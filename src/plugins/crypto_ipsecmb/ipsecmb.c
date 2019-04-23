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

typedef struct ipsecmb_main_t_
{
  ipsecmb_per_thread_data_t *per_thread_data;
} ipsecmb_main_t;

/**
 * AES GCM key=expansion VFT
 */
typedef void (*ase_gcm_pre_t) (const void *key,
			       struct gcm_key_data * key_data);

typedef struct ipsecmb_gcm_pre_vft_t_
{
  ase_gcm_pre_t ase_gcm_pre_128;
  ase_gcm_pre_t ase_gcm_pre_192;
  ase_gcm_pre_t ase_gcm_pre_256;
} ipsecmb_gcm_pre_vft_t;

static ipsecmb_gcm_pre_vft_t ipsecmb_gcm_pre_vft;

#define INIT_IPSEC_MB_GCM_PRE(_arch)                                    \
  ipsecmb_gcm_pre_vft.ase_gcm_pre_128 = aes_gcm_pre_128_##_arch;        \
  ipsecmb_gcm_pre_vft.ase_gcm_pre_192 = aes_gcm_pre_192_##_arch;        \
  ipsecmb_gcm_pre_vft.ase_gcm_pre_256 = aes_gcm_pre_256_##_arch;

static ipsecmb_main_t ipsecmb_main;

#define foreach_ipsecmb_hmac_op                                \
  _(SHA1, SHA1, sha1)                                          \
  _(SHA256, SHA_256, sha256)                                   \
  _(SHA384, SHA_384, sha384)                                   \
  _(SHA512, SHA_512, sha512)

/*
 * (Alg, key-len-bits, key-len-bytes, iv-len-bytes)
 */
#define foreach_ipsecmb_cbc_cipher_op                          \
  _(AES_128_CBC, 128, 16, 16)                                  \
  _(AES_192_CBC, 192, 24, 16)                                  \
  _(AES_256_CBC, 256, 32, 16)

/*
 * (Alg, key-len-bits, key-len-bytes, iv-len-bytes)
 */
#define foreach_ipsecmb_gcm_cipher_op                          \
  _(AES_128_GCM, 128, 16, 12)                                  \
  _(AES_192_GCM, 192, 24, 12)                                  \
  _(AES_256_GCM, 256, 32, 12)

always_inline void
hash_expand_keys (const MB_MGR * mgr,
		  const u8 * key,
		  u32 length,
		  u8 block_size,
		  u8 ipad[256], u8 opad[256], hash_one_block_t fn)
{
  u8 buf[block_size];
  int i = 0;

  if (length > block_size)
    {
      return;
    }

  memset (buf, 0x36, sizeof (buf));
  for (i = 0; i < length; i++)
    {
      buf[i] ^= key[i];
    }
  fn (buf, ipad);

  memset (buf, 0x5c, sizeof (buf));

  for (i = 0; i < length; i++)
    {
      buf[i] ^= key[i];
    }
  fn (buf, opad);
}

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
ipsecmb_ops_hmac_inline (vlib_main_t * vm,
			 const ipsecmb_per_thread_data_t * ptd,
			 vnet_crypto_op_t * ops[],
			 u32 n_ops,
			 u32 block_size,
			 hash_one_block_t fn, JOB_HASH_ALG alg)
{
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][64];

  /*
   * queue all the jobs first ...
   */
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u8 ipad[256], opad[256];

      hash_expand_keys (ptd->mgr, op->key, op->key_len,
			block_size, ipad, opad, fn);

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

      job->aes_key_len_in_bytes = op->key_len;

      job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
      job->u.HMAC._hashed_auth_key_xor_opad = opad;
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

#define _(a, b, c)                                                      \
static_always_inline u32                                                \
ipsecmb_ops_hmac_##a (vlib_main_t * vm,                                 \
                      vnet_crypto_op_t * ops[],                         \
                      u32 n_ops)                                        \
{                                                                       \
  ipsecmb_per_thread_data_t *ptd;                                       \
  ipsecmb_main_t *imbm;                                                 \
                                                                        \
  imbm = &ipsecmb_main;                                                 \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);     \
                                                                        \
  return ipsecmb_ops_hmac_inline (vm, ptd, ops, n_ops,                  \
                                  b##_BLOCK_SIZE,                       \
                                  ptd->mgr->c##_one_block,              \
                                  b);                                   \
  }
foreach_ipsecmb_hmac_op;
#undef _

#define EXPANDED_KEY_N_BYTES (16 * 15)

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
			       ipsecmb_per_thread_data_t * ptd,
			       vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len, u32 iv_len,
			       keyexp_t fn, JOB_CIPHER_DIRECTION direction)
{
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;

  /*
   * queue all the jobs first ...
   */
  for (i = 0; i < n_ops; i++)
    {
      u8 aes_enc_key_expanded[EXPANDED_KEY_N_BYTES];
      u8 aes_dec_key_expanded[EXPANDED_KEY_N_BYTES];
      vnet_crypto_op_t *op = ops[i];
      __m128i iv;

      fn (op->key, aes_enc_key_expanded, aes_dec_key_expanded);

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
      job->aes_enc_key_expanded = aes_enc_key_expanded;
      job->aes_dec_key_expanded = aes_dec_key_expanded;
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

#define _(a, b, c, d)                                                   \
static_always_inline u32                                                \
ipsecmb_ops_cbc_cipher_enc_##a (vlib_main_t * vm,                       \
                                vnet_crypto_op_t * ops[],               \
                                u32 n_ops)                              \
{                                                                       \
  ipsecmb_per_thread_data_t *ptd;                                       \
  ipsecmb_main_t *imbm;                                                 \
                                                                        \
  imbm = &ipsecmb_main;                                                 \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);     \
                                                                        \
  return ipsecmb_ops_cbc_cipher_inline (vm, ptd, ops, n_ops, c, d,      \
                                        ptd->mgr->keyexp_##b,           \
                                        ENCRYPT);                       \
  }
foreach_ipsecmb_cbc_cipher_op;
#undef _

#define _(a, b, c, d)                                                   \
static_always_inline u32                                                \
ipsecmb_ops_cbc_cipher_dec_##a (vlib_main_t * vm,                       \
                                vnet_crypto_op_t * ops[],               \
                                u32 n_ops)                              \
{                                                                       \
  ipsecmb_per_thread_data_t *ptd;                                       \
  ipsecmb_main_t *imbm;                                                 \
                                                                        \
  imbm = &ipsecmb_main;                                                 \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);     \
                                                                        \
  return ipsecmb_ops_cbc_cipher_inline (vm, ptd, ops, n_ops, c, d,      \
                                        ptd->mgr->keyexp_##b,           \
                                        DECRYPT);                       \
  }
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
			       ipsecmb_per_thread_data_t * ptd,
			       vnet_crypto_op_t * ops[],
			       u32 n_ops, u32 key_len, u32 iv_len,
			       ase_gcm_pre_t fn,
			       JOB_CIPHER_DIRECTION direction)
{
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][64];

  /*
   * queue all the jobs first ...
   */
  for (i = 0; i < n_ops; i++)
    {
      struct gcm_key_data key_data;
      vnet_crypto_op_t *op = ops[i];
      u32 nonce[3];
      __m128i iv;

      fn (op->key, &key_data);

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
      job->aes_enc_key_expanded = &key_data;
      job->aes_dec_key_expanded = &key_data;
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

#define _(a, b, c, d)                                                        \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_enc_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{                                                                            \
  ipsecmb_per_thread_data_t *ptd;                                            \
  ipsecmb_main_t *imbm;                                                      \
                                                                             \
  imbm = &ipsecmb_main;                                                      \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);          \
                                                                             \
  return ipsecmb_ops_gcm_cipher_inline (vm, ptd, ops, n_ops, c, d,           \
                                        ipsecmb_gcm_pre_vft.ase_gcm_pre_##b, \
                                        ENCRYPT);                            \
  }
foreach_ipsecmb_gcm_cipher_op;
#undef _

#define _(a, b, c, d)                                                        \
static_always_inline u32                                                     \
ipsecmb_ops_gcm_cipher_dec_##a (vlib_main_t * vm,                            \
                                vnet_crypto_op_t * ops[],                    \
                                u32 n_ops)                                   \
{                                                                            \
  ipsecmb_per_thread_data_t *ptd;                                            \
  ipsecmb_main_t *imbm;                                                      \
                                                                             \
  imbm = &ipsecmb_main;                                                      \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);          \
                                                                             \
  return ipsecmb_ops_gcm_cipher_inline (vm, ptd, ops, n_ops, c, d,           \
                                        ipsecmb_gcm_pre_vft.ase_gcm_pre_##b, \
                                        DECRYPT);                            \
  }
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

static clib_error_t *
crypto_ipsecmb_init (vlib_main_t * vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
  u32 eidx;

  if ((error = vlib_call_init_function (vm, vnet_crypto_init)))
    return error;

  /*
   * A priority that is better than OpenSSL but worse than VPP natvie
   */
  eidx = vnet_crypto_register_engine (vm, "ipsecmb", 80,
				      "Intel IPSEC multi-buffer");

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


#define _(a, b, c)                                                       \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
                                    ipsecmb_ops_hmac_##a);               \

  foreach_ipsecmb_hmac_op;
#undef _
#define _(a, b, c, d)                                                   \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_cbc_cipher_enc_##a);    \

  foreach_ipsecmb_cbc_cipher_op;
#undef _
#define _(a, b, c, d)                                                   \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_cbc_cipher_dec_##a);    \

  foreach_ipsecmb_cbc_cipher_op;
#undef _
#define _(a, b, c, d)                                                   \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
                                    ipsecmb_ops_gcm_cipher_enc_##a);    \

  foreach_ipsecmb_gcm_cipher_op;
#undef _
#define _(a, b, c, d)                                                   \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
                                    ipsecmb_ops_gcm_cipher_dec_##a);    \

  foreach_ipsecmb_gcm_cipher_op;
#undef _

  return (NULL);
}

VLIB_INIT_FUNCTION (crypto_ipsecmb_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Intel IPSEC Multi-buffer Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
