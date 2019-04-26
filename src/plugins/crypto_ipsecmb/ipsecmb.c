/*
 * ipsecmb.c - Intel IPSec Multi-buffer library Crypto Engine
 *
 * Copyright (c) 2019 Cisco Systemss
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>

#include <intel-ipsec-mb.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/cpu.h>

#define HMAC_MAX_BLOCK_SIZE SHA_512_BLOCK_SIZE
#define EXPANDED_KEY_N_BYTES (16 * 15)

typedef struct
{
  MB_MGR *mgr;
  __m128i cbc_iv;
} ipsecmb_per_thread_data_t;

typedef struct
{
  u16 data_size;
  u8 block_size;
  aes_gcm_pre_t aes_gcm_pre;
  keyexp_t keyexp;
  hash_one_block_t hash_one_block;
  hash_fn_t hash_fn;
} ipsecmb_alg_data_t;

typedef struct ipsecmb_main_t_
{
  ipsecmb_per_thread_data_t *per_thread_data;
  ipsecmb_alg_data_t alg_data[VNET_CRYPTO_N_ALGS];
  void **key_data;
} ipsecmb_main_t;

typedef struct
{
  u8 enc_key_exp[EXPANDED_KEY_N_BYTES];
  u8 dec_key_exp[EXPANDED_KEY_N_BYTES];
} ipsecmb_aes_cbc_key_data_t;

static ipsecmb_main_t ipsecmb_main = { };

/*
 * (Alg, JOB_HASH_ALG, fn, block-size-bytes, hash-size-bytes, digest-size-bytes)
 */
#define foreach_ipsecmb_hmac_op                                \
  _(SHA1,   SHA1,    sha1,   64,  20, 20)                      \
  _(SHA224, SHA_224, sha224, 64,  32, 28)                      \
  _(SHA256, SHA_256, sha256, 64,  32, 32)                      \
  _(SHA384, SHA_384, sha384, 128, 64, 48)                      \
  _(SHA512, SHA_512, sha512, 128, 64, 64)

/*
 * (Alg, key-len-bits)
 */
#define foreach_ipsecmb_cbc_cipher_op                          \
  _(AES_128_CBC, 128)                                          \
  _(AES_192_CBC, 192)                                          \
  _(AES_256_CBC, 256)

/*
 * (Alg, key-len-bytes, iv-len-bytes)
 */
#define foreach_ipsecmb_gcm_cipher_op                          \
  _(AES_128_GCM, 128)                                          \
  _(AES_192_GCM, 192)                                          \
  _(AES_256_GCM, 256)

always_inline void
ipsecmb_retire_hmac_job (JOB_AES_HMAC * job, u32 * n_fail, u32 digest_size)
{
  vnet_crypto_op_t *op = job->user_data;
  u32 len = op->digest_len ? op->digest_len : digest_size;

  if (STS_COMPLETED != job->status)
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      *n_fail = *n_fail + 1;
      return;
    }

  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
    {
      if ((memcmp (op->digest, job->auth_tag_output, len)))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  return;
	}
    }
  else if (len == digest_size)
    clib_memcpy_fast (op->digest, job->auth_tag_output, digest_size);
  else
    clib_memcpy_fast (op->digest, job->auth_tag_output, len);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_hmac_inline (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			 u32 n_ops, u32 block_size, u32 hash_size,
			 u32 digest_size, JOB_HASH_ALG alg)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = vec_elt_at_index (imbm->per_thread_data,
						     vm->thread_index);
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][digest_size];

  /*
   * queue all the jobs first ...
   */
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u8 *kd = (u8 *) imbm->key_data[op->key_index];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->len;
      job->hash_alg = alg;
      job->auth_tag_output_len_in_bytes = digest_size;
      job->auth_tag_output = scratch[i];

      job->cipher_mode = NULL_CIPHER;
      job->cipher_direction = DECRYPT;
      job->chain_order = HASH_CIPHER;

      job->u.HMAC._hashed_auth_key_xor_ipad = kd;
      job->u.HMAC._hashed_auth_key_xor_opad = kd + hash_size;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_hmac_job (job, &n_fail, digest_size);
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    ipsecmb_retire_hmac_job (job, &n_fail, digest_size);

  return n_ops - n_fail;
}

#define _(a, b, c, d, e, f)                                             \
static_always_inline u32                                                \
ipsecmb_ops_hmac_##a (vlib_main_t * vm,                                 \
                      vnet_crypto_op_t * ops[],                         \
                      u32 n_ops)                                        \
{ return ipsecmb_ops_hmac_inline (vm, ops, n_ops, d, e, f, b); }        \

foreach_ipsecmb_hmac_op;
#undef _

always_inline void
ipsecmb_retire_cipher_job (JOB_AES_HMAC * job, u32 * n_fail)
{
  vnet_crypto_op_t *op = job->user_data;

  if (STS_COMPLETED != job->status)
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      *n_fail = *n_fail + 1;
    }
  else
    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_cbc_cipher_inline (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len,
			       JOB_CIPHER_DIRECTION direction)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = vec_elt_at_index (imbm->per_thread_data,
						     vm->thread_index);
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;

  for (i = 0; i < n_ops; i++)
    {
      ipsecmb_aes_cbc_key_data_t *kd;
      vnet_crypto_op_t *op = ops[i];
      kd = (ipsecmb_aes_cbc_key_data_t *) imbm->key_data[op->key_index];
      __m128i iv;

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = NULL_HASH;
      job->cipher_mode = CBC;
      job->cipher_direction = direction;
      job->chain_order = (direction == ENCRYPT ? CIPHER_HASH : HASH_CIPHER);

      if ((direction == ENCRYPT) && (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV))
	{
	  iv = ptd->cbc_iv;
	  _mm_storeu_si128 ((__m128i *) op->iv, iv);
	  ptd->cbc_iv = _mm_aesenc_si128 (iv, iv);
	}

      job->aes_key_len_in_bytes = key_len / 8;
      job->aes_enc_key_expanded = kd->enc_key_exp;
      job->aes_dec_key_expanded = kd->dec_key_exp;
      job->iv = op->iv;
      job->iv_len_in_bytes = AES_BLOCK_SIZE;

      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_cipher_job (job, &n_fail);
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    ipsecmb_retire_cipher_job (job, &n_fail);

  return n_ops - n_fail;
}

#define _(a, b)                                                              \
static_always_inline u32                                                     \
ipsecmb_ops_cbc_cipher_enc_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_cbc_cipher_inline (vm, ops, n_ops, b, ENCRYPT); }       \
                                                                             \
static_always_inline u32                                                     \
ipsecmb_ops_cbc_cipher_dec_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_cbc_cipher_inline (vm, ops, n_ops, b, DECRYPT); }       \

foreach_ipsecmb_cbc_cipher_op;
#undef _

always_inline void
ipsecmb_retire_gcm_cipher_job (JOB_AES_HMAC * job,
			       u32 * n_fail, JOB_CIPHER_DIRECTION direction)
{
  vnet_crypto_op_t *op = job->user_data;

  if (STS_COMPLETED != job->status)
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      *n_fail = *n_fail + 1;
      return;
    }
  else
    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (DECRYPT == direction)
    {
      if ((memcmp (op->tag, job->auth_tag_output, op->tag_len)))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	}
    }
}

static_always_inline u32
ipsecmb_ops_gcm_cipher_inline (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len,
			       JOB_CIPHER_DIRECTION direction)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = vec_elt_at_index (imbm->per_thread_data,
						     vm->thread_index);
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][64];

  /*
   * queue all the jobs first ...
   */
  for (i = 0; i < n_ops; i++)
    {
      struct gcm_key_data *kd;
      vnet_crypto_op_t *op = ops[i];
      kd = (struct gcm_key_data *) imbm->key_data[op->key_index];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = AES_GMAC;
      job->cipher_mode = GCM;
      job->cipher_direction = direction;
      job->chain_order = (direction == ENCRYPT ? CIPHER_HASH : HASH_CIPHER);

      job->iv = op->iv;
      job->aes_key_len_in_bytes = key_len / 8;
      job->aes_enc_key_expanded = kd;
      job->aes_dec_key_expanded = kd;
      job->iv_len_in_bytes = 12;

      job->u.GCM.aad = op->aad;
      job->u.GCM.aad_len_in_bytes = op->aad_len;
      job->auth_tag_output_len_in_bytes = op->tag_len;
      if (DECRYPT == direction)
	job->auth_tag_output = scratch[i];
      else
	job->auth_tag_output = op->tag;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_gcm_cipher_job (job, &n_fail, direction);
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    ipsecmb_retire_gcm_cipher_job (job, &n_fail, direction);

  return n_ops - n_fail;
}

#define _(a, b)                                                              \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_enc_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[],  \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_gcm_cipher_inline (vm, ops, n_ops, b, ENCRYPT); }       \
                                                                             \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_dec_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[],  \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_gcm_cipher_inline (vm, ops, n_ops, b, DECRYPT); }       \

foreach_ipsecmb_gcm_cipher_op;
#undef _

clib_error_t *
crypto_ipsecmb_iv_init (ipsecmb_main_t * imbm)
{
  ipsecmb_per_thread_data_t *ptd;
  clib_error_t *err = 0;
  int fd;

  if ((fd = open ("/dev/urandom", O_RDONLY)) < 0)
    return clib_error_return_unix (0, "failed to open '/dev/urandom'");

  vec_foreach (ptd, imbm->per_thread_data)
  {
    if (read (fd, &ptd->cbc_iv, sizeof (ptd->cbc_iv)) != sizeof (ptd->cbc_iv))
      {
	err = clib_error_return_unix (0, "'/dev/urandom' read failure");
	close (fd);
	return (err);
      }
  }

  close (fd);
  return (NULL);
}

static void
crypto_ipsecmb_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			    vnet_crypto_key_index_t idx)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  ipsecmb_alg_data_t *ad = imbm->alg_data + key->alg;
  u32 i;
  void *kd;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (imbm->key_data))
	return;

      if (imbm->key_data[idx] == 0)
	return;

      clib_memset_u8 (imbm->key_data[idx], 0,
		      clib_mem_size (imbm->key_data[idx]));
      clib_mem_free (imbm->key_data[idx]);
      imbm->key_data[idx] = 0;
      return;
    }

  if (ad->data_size == 0)
    return;

  vec_validate_aligned (imbm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && imbm->key_data[idx])
    {
      clib_memset_u8 (imbm->key_data[idx], 0,
		      clib_mem_size (imbm->key_data[idx]));
      clib_mem_free (imbm->key_data[idx]);
    }

  kd = imbm->key_data[idx] = clib_mem_alloc_aligned (ad->data_size,
						     CLIB_CACHE_LINE_BYTES);

  /* AES CBC key expansion */
  if (ad->keyexp)
    {
      ad->keyexp (key->data, ((ipsecmb_aes_cbc_key_data_t *) kd)->enc_key_exp,
		  ((ipsecmb_aes_cbc_key_data_t *) kd)->dec_key_exp);
      return;
    }

  /* AES GCM */
  if (ad->aes_gcm_pre)
    {
      ad->aes_gcm_pre (key->data, (struct gcm_key_data *) kd);
      return;
    }

  /* HMAC */
  if (ad->hash_one_block)
    {
      const int block_qw = HMAC_MAX_BLOCK_SIZE / sizeof (u64);
      u64 pad[block_qw], key_hash[block_qw];

      clib_memset_u8 (key_hash, 0, HMAC_MAX_BLOCK_SIZE);
      if (vec_len (key->data) <= ad->block_size)
	clib_memcpy_fast (key_hash, key->data, vec_len (key->data));
      else
	ad->hash_fn (key->data, vec_len (key->data), key_hash);

      for (i = 0; i < block_qw; i++)
	pad[i] = key_hash[i] ^ 0x3636363636363636;
      ad->hash_one_block (pad, kd);

      for (i = 0; i < block_qw; i++)
	pad[i] = key_hash[i] ^ 0x5c5c5c5c5c5c5c5c;
      ad->hash_one_block (pad, ((u8 *) kd) + (ad->data_size / 2));

      return;
    }
}

static clib_error_t *
crypto_ipsecmb_init (vlib_main_t * vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_alg_data_t *ad;
  ipsecmb_per_thread_data_t *ptd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
  MB_MGR *m = 0;
  u32 eidx;
  u8 *name;

  if ((error = vlib_call_init_function (vm, vnet_crypto_init)))
    return error;

  /*
   * A priority that is better than OpenSSL but worse than VPP natvie
   */
  name = format (0, "Intel(R) Multi-Buffer Crypto for IPsec Library %s%c",
		 IMB_VERSION_STR, 0);
  eidx = vnet_crypto_register_engine (vm, "ipsecmb", 80, (char *) name);

  vec_validate (imbm->per_thread_data, tm->n_vlib_mains - 1);

  /* *INDENT-OFF* */
  vec_foreach (ptd, imbm->per_thread_data)
    {
	ptd->mgr = alloc_mb_mgr (0);
        if (clib_cpu_supports_avx512f ())
	  init_mb_mgr_avx512 (ptd->mgr);
        else if (clib_cpu_supports_avx2 ())
	  init_mb_mgr_avx2 (ptd->mgr);
	else
	  init_mb_mgr_sse (ptd->mgr);

	if (ptd == imbm->per_thread_data)
	  m = ptd->mgr;
    }
  /* *INDENT-ON* */

  if (clib_cpu_supports_x86_aes () && (error = crypto_ipsecmb_iv_init (imbm)))
    return (error);

#define _(a, b, c, d, e, f)                                              \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
                                    ipsecmb_ops_hmac_##a);               \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_HMAC_##a;                        \
  ad->block_size = d;                                                    \
  ad->data_size = e * 2;                                                 \
  ad->hash_one_block = m-> c##_one_block;                                \
  ad->hash_fn = m-> c;                                                   \

  foreach_ipsecmb_hmac_op;
#undef _
#define _(a, b)                                                         \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_cbc_cipher_enc_##a);    \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_cbc_cipher_dec_##a);    \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_##a;                            \
  ad->data_size = sizeof (ipsecmb_aes_cbc_key_data_t);                  \
  ad->keyexp = m->keyexp_##b;                                           \

  foreach_ipsecmb_cbc_cipher_op;
#undef _
#define _(a, b)                                                         \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_gcm_cipher_enc_##a);    \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_gcm_cipher_dec_##a);    \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_##a;                            \
  ad->data_size = sizeof (struct gcm_key_data);                         \
  ad->aes_gcm_pre = m->gcm##b##_pre;                                    \

  foreach_ipsecmb_gcm_cipher_op;
#undef _

  vnet_crypto_register_key_handler (vm, eidx, crypto_ipsecmb_key_handler);
  return (NULL);
}

VLIB_INIT_FUNCTION (crypto_ipsecmb_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Intel IPSEC multi-buffer",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
