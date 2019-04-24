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

typedef struct
{
  MB_MGR *mgr;
  __m128i cbc_iv;
} ipsecmb_per_thread_data_t;

typedef void (*aes_gcm_pre_t) (const void *key, struct gcm_key_data * kd);

typedef struct ipsecmb_main_t_
{
  ipsecmb_per_thread_data_t *per_thread_data;
  void **key_data;
  aes_gcm_pre_t aes_gcm_pre_128;
  aes_gcm_pre_t aes_gcm_pre_192;
  aes_gcm_pre_t aes_gcm_pre_256;
} ipsecmb_main_t;

#define EXPANDED_KEY_N_BYTES (16 * 15)

typedef struct
{
  u8 enc_key_exp[EXPANDED_KEY_N_BYTES];
  u8 dec_key_exp[EXPANDED_KEY_N_BYTES];
} ipsecmb_aes_cbc_key_data_t;

#define INIT_IPSEC_MB_GCM_PRE(_arch)                             \
  ipsecmb_main.aes_gcm_pre_128 = aes_gcm_pre_128_##_arch;        \
  ipsecmb_main.aes_gcm_pre_192 = aes_gcm_pre_192_##_arch;        \
  ipsecmb_main.aes_gcm_pre_256 = aes_gcm_pre_256_##_arch;

static ipsecmb_main_t ipsecmb_main;

#define foreach_ipsecmb_hmac_op                                \
  _(SHA1, SHA1)                                                \
  _(SHA256, SHA_256)                                           \
  _(SHA384, SHA_384)                                           \
  _(SHA512, SHA_512)

/*
 * (Alg, key-len-bytes, iv-len-bytes)
 */
#define foreach_ipsecmb_cbc_cipher_op                          \
  _(AES_128_CBC, 16, 16)                                       \
  _(AES_192_CBC, 24, 16)                                       \
  _(AES_256_CBC, 32, 16)

/*
 * (Alg, key-len-bytes, iv-len-bytes)
 */
#define foreach_ipsecmb_gcm_cipher_op                          \
  _(AES_128_GCM, 16, 12)                                       \
  _(AES_192_GCM, 24, 12)                                       \
  _(AES_256_GCM, 32, 12)

always_inline void
ipsecmb_retire_hmac_job (JOB_AES_HMAC * job, u32 * n_fail)
{
  vnet_crypto_op_t *op = job->user_data;

  if (STS_COMPLETED != job->status)
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      *n_fail = *n_fail + 1;
    }
  else
    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
    {
      if ((memcmp (op->digest, job->auth_tag_output, op->digest_len)))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	}
    }
  else
    clib_memcpy_fast (op->digest, job->auth_tag_output, op->digest_len);
}

static_always_inline u32
ipsecmb_ops_hmac_inline (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			 u32 n_ops, u32 block_size, u32 digest_size,
			 JOB_HASH_ALG alg)
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
      vnet_crypto_op_t *op = ops[i];
      u8 *kd = (u8 *) imbm->key_data[op->key_index];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->len;
      job->hash_alg = alg;
      job->auth_tag_output_len_in_bytes = op->digest_len;
      job->auth_tag_output = scratch[i];

      job->cipher_mode = NULL_CIPHER;
      job->cipher_direction = DECRYPT;
      job->chain_order = HASH_CIPHER;

      job->u.HMAC._hashed_auth_key_xor_ipad = kd;
      job->u.HMAC._hashed_auth_key_xor_opad = kd + digest_size;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_hmac_job (job, &n_fail);
    }

  /*
   * .. then flush (i.e. complete) them
   *  We will have queued enough to satisfy the 'multi' buffer
   */
  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      ipsecmb_retire_hmac_job (job, &n_fail);
    }

  return n_ops - n_fail;
}

#define _(a, b)                                                         \
static_always_inline u32                                                \
ipsecmb_ops_hmac_##a (vlib_main_t * vm,                                 \
                      vnet_crypto_op_t * ops[],                         \
                      u32 n_ops)                                        \
{                                                                       \
  return ipsecmb_ops_hmac_inline (vm, ops, n_ops,                       \
                                  b##_BLOCK_SIZE,                       \
                                  a##_DIGEST_SIZE_IN_BYTES,             \
                                  b);                                   \
  }
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
ipsecmb_ops_cbc_cipher_inline (vlib_main_t * vm,
			       vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len, u32 iv_len,
			       JOB_CIPHER_DIRECTION direction)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = vec_elt_at_index (imbm->per_thread_data,
						     vm->thread_index);
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;

  /*
   * queue all the jobs first ...
   */
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

      job->aes_key_len_in_bytes = key_len;
      job->aes_enc_key_expanded = kd->enc_key_exp;
      job->aes_dec_key_expanded = kd->dec_key_exp;
      job->iv = op->iv;
      job->iv_len_in_bytes = iv_len;

      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_cipher_job (job, &n_fail);
    }

  /*
   * .. then flush (i.e. complete) them
   *  We will have queued enough to satisfy the 'multi' buffer
   */
  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      ipsecmb_retire_cipher_job (job, &n_fail);
    }

  return n_ops - n_fail;
}

#define _(a, b, c)                                                           \
static_always_inline u32                                                     \
ipsecmb_ops_cbc_cipher_enc_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_cbc_cipher_inline (vm, ops, n_ops, b, c, ENCRYPT); }    \

foreach_ipsecmb_cbc_cipher_op;
#undef _

#define _(a, b, c)                                                           \
static_always_inline u32                                                     \
ipsecmb_ops_cbc_cipher_dec_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_cbc_cipher_inline (vm, ops, n_ops, b, c, DECRYPT); }    \

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
ipsecmb_ops_gcm_cipher_inline (vlib_main_t * vm,
			       vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len, u32 iv_len,
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
      u32 nonce[3];
      __m128i iv;

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = AES_GMAC;
      job->cipher_mode = GCM;
      job->cipher_direction = direction;
      job->chain_order = (direction == ENCRYPT ? CIPHER_HASH : HASH_CIPHER);

      if (direction == ENCRYPT)
	{
	  if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	    {
	      iv = ptd->cbc_iv;
	      // only use 8 bytes of the IV
	      clib_memcpy_fast (op->iv, &iv, 8);
	      ptd->cbc_iv = _mm_aesenc_si128 (iv, iv);
	    }
	  nonce[0] = op->salt;
	  clib_memcpy_fast (nonce + 1, op->iv, 8);
	  job->iv = (u8 *) nonce;
	}
      else
	{
	  nonce[0] = op->salt;
	  clib_memcpy_fast (nonce + 1, op->iv, 8);
	  job->iv = op->iv;
	}

      job->aes_key_len_in_bytes = key_len;
      job->aes_enc_key_expanded = kd;
      job->aes_dec_key_expanded = kd;
      job->iv_len_in_bytes = iv_len;

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

  /*
   * .. then flush (i.e. complete) them
   *  We will have queued enough to satisfy the 'multi' buffer
   */
  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      ipsecmb_retire_gcm_cipher_job (job, &n_fail, direction);
    }

  return n_ops - n_fail;
}

#define _(a, b, c)                                                           \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_enc_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_gcm_cipher_inline (vm, ops, n_ops, b, c, ENCRYPT); }    \

foreach_ipsecmb_gcm_cipher_op;
#undef _

#define _(a, b, c)                                                           \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_dec_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{ return ipsecmb_ops_gcm_cipher_inline (vm, ops, n_ops, b, c, DECRYPT); }    \

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

#define HMAC_MAX_BLOCK_SIZE SHA_512_BLOCK_SIZE

static void
crypto_ipsecmb_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			    vnet_crypto_key_index_t idx)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  ipsecmb_per_thread_data_t *ptd;
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);
  MB_MGR *m = ptd->mgr;
  aes_gcm_pre_t aes_gcm_pre = 0;
  keyexp_t keyexp = 0;
  hash_one_block_t hash_one_block = 0;
  u32 i, data_size;
  u8 ipad[HMAC_MAX_BLOCK_SIZE], opad[HMAC_MAX_BLOCK_SIZE];
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
      return;
    }

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC:
      keyexp = m->keyexp_128;
      data_size = sizeof (ipsecmb_aes_cbc_key_data_t);
      break;
    case VNET_CRYPTO_ALG_AES_192_CBC:
      keyexp = m->keyexp_192;
      data_size = sizeof (ipsecmb_aes_cbc_key_data_t);
      break;
    case VNET_CRYPTO_ALG_AES_256_CBC:
      keyexp = m->keyexp_256;
      data_size = sizeof (ipsecmb_aes_cbc_key_data_t);
      break;
    case VNET_CRYPTO_ALG_AES_128_GCM:
      aes_gcm_pre = imbm->aes_gcm_pre_128;
      data_size = sizeof (struct gcm_key_data);
      break;
    case VNET_CRYPTO_ALG_AES_192_GCM:
      aes_gcm_pre = imbm->aes_gcm_pre_192;
      data_size = sizeof (struct gcm_key_data);
      break;
    case VNET_CRYPTO_ALG_AES_256_GCM:
      aes_gcm_pre = imbm->aes_gcm_pre_256;
      data_size = sizeof (struct gcm_key_data);
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA1:
      hash_one_block = m->sha1_one_block;
      data_size = 2 * SHA1_DIGEST_SIZE_IN_BYTES;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA256:
      hash_one_block = m->sha256_one_block;
      data_size = 2 * SHA256_DIGEST_SIZE_IN_BYTES;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA384:
      hash_one_block = m->sha384_one_block;
      data_size = 2 * SHA384_DIGEST_SIZE_IN_BYTES;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA512:
      hash_one_block = m->sha512_one_block;
      data_size = 2 * SHA512_DIGEST_SIZE_IN_BYTES;
      break;
    default:
      return;
      break;
    }

  vec_validate_aligned (imbm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && imbm->key_data[idx])
    {
      clib_memset_u8 (imbm->key_data[idx], 0,
		      clib_mem_size (imbm->key_data[idx]));
      clib_mem_free (imbm->key_data[idx]);
    }

  kd = imbm->key_data[idx] = clib_mem_alloc_aligned (data_size,
						     CLIB_CACHE_LINE_BYTES);

  if (keyexp)
    keyexp (key->data, ((ipsecmb_aes_cbc_key_data_t *) kd)->enc_key_exp,
	    ((ipsecmb_aes_cbc_key_data_t *) kd)->dec_key_exp);

  if (aes_gcm_pre)
    aes_gcm_pre (key->data, (struct gcm_key_data *) kd);

  if (hash_one_block)
    {
      u32 digest_size = data_size / 2;
      u8 *hashed_ipad = (u8 *) kd;
      u8 *hashed_opad = ipad + digest_size;

      clib_memset_u8 (ipad, 0x36, HMAC_MAX_BLOCK_SIZE);
      clib_memset_u8 (opad, 0x5c, HMAC_MAX_BLOCK_SIZE);

      for (i = 0; i < vec_len (key->data); i++)
	{
	  ipad[i] ^= key->data[i];
	  opad[i] ^= key->data[i];
	}
      hash_one_block (ipad, hashed_ipad);
      hash_one_block (opad, hashed_opad);
    }
}

static clib_error_t *
crypto_ipsecmb_init (vlib_main_t * vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
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

  if (clib_cpu_supports_avx512f ())
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx512 (ptd->mgr);
	INIT_IPSEC_MB_GCM_PRE (avx_gen4);
      }
    }
  else if (clib_cpu_supports_avx2 ())
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx2 (ptd->mgr);
	INIT_IPSEC_MB_GCM_PRE (avx_gen2);
      }
    }
  else
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_sse (ptd->mgr);
	INIT_IPSEC_MB_GCM_PRE (sse);
      }
    }

  if (clib_cpu_supports_x86_aes () && (error = crypto_ipsecmb_iv_init (imbm)))
    return (error);


#define _(a, b)                                                          \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
                                    ipsecmb_ops_hmac_##a);               \

  foreach_ipsecmb_hmac_op;
#undef _
#define _(a, b, c)                                                      \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_cbc_cipher_enc_##a);    \

  foreach_ipsecmb_cbc_cipher_op;
#undef _
#define _(a, b, c)                                                      \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_cbc_cipher_dec_##a);    \

  foreach_ipsecmb_cbc_cipher_op;
#undef _
#define _(a, b, c)                                                      \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_gcm_cipher_enc_##a);    \

  foreach_ipsecmb_gcm_cipher_op;
#undef _
#define _(a, b, c)                                                      \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_gcm_cipher_dec_##a);    \

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
