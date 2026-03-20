/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024-2026 Cisco Systems, Inc.
 */

#include <fcntl.h>

#include <intel-ipsec-mb.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vppinfra/cpu.h>

#define HMAC_MAX_BLOCK_SIZE  IMB_SHA_512_BLOCK_SIZE
#define IPSECMB_HMAC_KEY_DATA_SIZE (2 * IMB_SHA512_DIGEST_SIZE_IN_BYTES)
#define EXPANDED_KEY_N_BYTES	   (16 * 15)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  IMB_MGR *mgr;
  IMB_JOB burst_jobs[IMB_MAX_BURST_SIZE];
} ipsecmb_per_thread_data_t;

typedef struct ipsecmb_main_t_
{
  IMB_MGR *mgr;
} ipsecmb_main_t;

typedef struct
{
  u8 enc_key_exp[EXPANDED_KEY_N_BYTES];
  u8 dec_key_exp[EXPANDED_KEY_N_BYTES];
} ipsecmb_aes_key_data_t;

typedef struct
{
  ipsecmb_aes_key_data_t cipher;
  u8 hmac[128];
} ipsecmb_combined_key_data_t;

static ipsecmb_main_t ipsecmb_main = {};
static __thread ipsecmb_per_thread_data_t ipsecmb_per_thread_data;

static_always_inline ipsecmb_per_thread_data_t *
ipsecmb_get_per_thread_data (void)
{
  ipsecmb_per_thread_data_t *ptd = &ipsecmb_per_thread_data;
  IMB_ARCH arch;

  if (PREDICT_TRUE (ptd->mgr != 0))
    return ptd;

  ptd->mgr = alloc_mb_mgr (0);
  if (ptd->mgr == 0)
    return 0;

  clib_memset_u8 (ptd->burst_jobs, 0, sizeof (IMB_JOB) * IMB_MAX_BURST_SIZE);

  init_mb_mgr_auto (ptd->mgr, &arch);
  if (imb_get_errno (ptd->mgr) != 0)
    {
      free_mb_mgr (ptd->mgr);
      ptd->mgr = 0;
      return 0;
    }

  if (!ptd->mgr->submit_hash_burst_nocheck)
    {
      free_mb_mgr (ptd->mgr);
      ptd->mgr = 0;
      return 0;
    }

  return ptd;
}

/*
 * (Alg, JOB_HASH_ALG, fn, block-size-bytes, hash-size-bytes, digest-size-bytes)
 */
#define foreach_ipsecmb_hmac_op                                                                    \
  _ (SHA1_160, SHA_1, sha1, 64, 20, 20)                                                            \
  _ (SHA2_224, SHA_224, sha224, 64, 32, 28)                                                        \
  _ (SHA2_256, SHA_256, sha256, 64, 32, 32)                                                        \
  _ (SHA2_384, SHA_384, sha384, 128, 64, 48)                                                       \
  _ (SHA2_512, SHA_512, sha512, 128, 64, 64)

/*
 * (Alg, key-len-bits, JOB_CIPHER_MODE)
 */
#define foreach_ipsecmb_cipher_op                                             \
  _ (AES_128_CBC, 128, CBC)                                                   \
  _ (AES_192_CBC, 192, CBC)                                                   \
  _ (AES_256_CBC, 256, CBC)                                                   \
  _ (AES_128_CTR, 128, CNTR)                                                  \
  _ (AES_192_CTR, 192, CNTR)                                                  \
  _ (AES_256_CTR, 256, CNTR)

/*
 * (Alg, key-len-bytes, iv-len-bytes, fixed, aad-len)
 */
#define foreach_ipsecmb_gcm_cipher_op                                                              \
  _ (AES_128_GCM, 128, 0, 0)                                                                       \
  _ (AES_128_GCM_ICV16_AAD8, 128, 1, 8)                                                            \
  _ (AES_128_GCM_ICV16_AAD12, 128, 1, 12)                                                          \
  _ (AES_192_GCM, 192, 0, 0)                                                                       \
  _ (AES_192_GCM_ICV16_AAD8, 192, 1, 8)                                                            \
  _ (AES_192_GCM_ICV16_AAD12, 192, 1, 12)                                                          \
  _ (AES_256_GCM, 256, 0, 0)                                                                       \
  _ (AES_256_GCM_ICV16_AAD8, 256, 1, 8)                                                            \
  _ (AES_256_GCM_ICV16_AAD12, 256, 1, 12)

#define foreach_ipsecmb_combined_cipher_op                                                         \
  _ (AES_128_CBC_SHA1_160, 128, CBC, CBC, SHA_1, SHA1_160, 64, 20, 20, 12)                         \
  _ (AES_192_CBC_SHA1_160, 192, CBC, CBC, SHA_1, SHA1_160, 64, 20, 20, 12)                         \
  _ (AES_256_CBC_SHA1_160, 256, CBC, CBC, SHA_1, SHA1_160, 64, 20, 20, 12)                         \
  _ (AES_128_CBC_SHA2_224, 128, CBC, CBC, SHA_224, SHA2_224, 64, 32, 28, 14)                       \
  _ (AES_192_CBC_SHA2_224, 192, CBC, CBC, SHA_224, SHA2_224, 64, 32, 28, 14)                       \
  _ (AES_256_CBC_SHA2_224, 256, CBC, CBC, SHA_224, SHA2_224, 64, 32, 28, 14)                       \
  _ (AES_128_CBC_SHA2_256, 128, CBC, CBC, SHA_256, SHA2_256, 64, 32, 32, 16)                       \
  _ (AES_192_CBC_SHA2_256, 192, CBC, CBC, SHA_256, SHA2_256, 64, 32, 32, 16)                       \
  _ (AES_256_CBC_SHA2_256, 256, CBC, CBC, SHA_256, SHA2_256, 64, 32, 32, 16)                       \
  _ (AES_128_CBC_SHA2_384, 128, CBC, CBC, SHA_384, SHA2_384, 128, 64, 48, 24)                      \
  _ (AES_192_CBC_SHA2_384, 192, CBC, CBC, SHA_384, SHA2_384, 128, 64, 48, 24)                      \
  _ (AES_256_CBC_SHA2_384, 256, CBC, CBC, SHA_384, SHA2_384, 128, 64, 48, 24)                      \
  _ (AES_128_CBC_SHA2_512, 128, CBC, CBC, SHA_512, SHA2_512, 128, 64, 64, 32)                      \
  _ (AES_192_CBC_SHA2_512, 192, CBC, CBC, SHA_512, SHA2_512, 128, 64, 64, 32)                      \
  _ (AES_256_CBC_SHA2_512, 256, CBC, CBC, SHA_512, SHA2_512, 128, 64, 64, 32)                      \
  _ (AES_128_CTR_SHA1_160, 128, CNTR, CTR, SHA_1, SHA1_160, 64, 20, 20, 12)                        \
  _ (AES_192_CTR_SHA1_160, 192, CNTR, CTR, SHA_1, SHA1_160, 64, 20, 20, 12)                        \
  _ (AES_256_CTR_SHA1_160, 256, CNTR, CTR, SHA_1, SHA1_160, 64, 20, 20, 12)                        \
  _ (AES_128_CTR_SHA2_256, 128, CNTR, CTR, SHA_256, SHA2_256, 64, 32, 32, 16)                      \
  _ (AES_192_CTR_SHA2_256, 192, CNTR, CTR, SHA_256, SHA2_256, 64, 32, 32, 16)                      \
  _ (AES_256_CTR_SHA2_256, 256, CNTR, CTR, SHA_256, SHA2_256, 64, 32, 32, 16)                      \
  _ (AES_128_CTR_SHA2_384, 128, CNTR, CTR, SHA_384, SHA2_384, 128, 64, 48, 24)                     \
  _ (AES_192_CTR_SHA2_384, 192, CNTR, CTR, SHA_384, SHA2_384, 128, 64, 48, 24)                     \
  _ (AES_256_CTR_SHA2_384, 256, CNTR, CTR, SHA_384, SHA2_384, 128, 64, 48, 24)                     \
  _ (AES_128_CTR_SHA2_512, 128, CNTR, CTR, SHA_512, SHA2_512, 128, 64, 64, 32)                     \
  _ (AES_192_CTR_SHA2_512, 192, CNTR, CTR, SHA_512, SHA2_512, 128, 64, 64, 32)                     \
  _ (AES_256_CTR_SHA2_512, 256, CNTR, CTR, SHA_512, SHA2_512, 128, 64, 64, 32)

#define foreach_chacha_poly_fixed_aad_lengths _ (0) _ (8) _ (12)

#define foreach_ipsecmb_combined_fixed_extra_op                                                    \
  _ (AES_128_CBC_SHA2_256, 12)                                                                     \
  _ (AES_192_CBC_SHA2_256, 12)                                                                     \
  _ (AES_256_CBC_SHA2_256, 12)                                                                     \
  _ (AES_128_CTR_SHA2_256, 12)                                                                     \
  _ (AES_192_CTR_SHA2_256, 12)                                                                     \
  _ (AES_256_CTR_SHA2_256, 12)

static_always_inline vnet_crypto_op_status_t
ipsecmb_status_job (IMB_STATUS status)
{
  switch (status)
    {
    case IMB_STATUS_COMPLETED:
      return VNET_CRYPTO_OP_STATUS_COMPLETED;
    case IMB_STATUS_BEING_PROCESSED:
    case IMB_STATUS_COMPLETED_CIPHER:
    case IMB_STATUS_COMPLETED_AUTH:
      return VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS;
    case IMB_STATUS_INVALID_ARGS:
    case IMB_STATUS_INTERNAL_ERROR:
    case IMB_STATUS_ERROR:
      return VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
    }
  ASSERT (0);
  return VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
}

always_inline void
ipsecmb_retire_hmac_job (IMB_JOB *job, u32 *n_fail, u32 digest_size)
{
  vnet_crypto_op_t *op = job->user_data;
  u32 len = op->auth_len ? op->auth_len : digest_size;

  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
    {
      op->status = ipsecmb_status_job (job->status);
      *n_fail = *n_fail + 1;
      return;
    }

  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
    {
      if ((memcmp (op->auth, job->auth_tag_output, len)))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  return;
	}
    }
  else if (len == digest_size)
    clib_memcpy_fast (op->auth, job->auth_tag_output, digest_size);
  else
    clib_memcpy_fast (op->auth, job->auth_tag_output, len);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_hmac_inline (vnet_crypto_op_t *ops[], u32 n_ops, u32 hash_size, u32 digest_size,
			 IMB_HASH_ALG alg, u32 key_data_offset)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  u8 scratch[IMB_MAX_BURST_SIZE][IMB_SHA512_DIGEST_SIZE_IN_BYTES];
  const u32 burst_sz =
    (n_ops > IMB_MAX_BURST_SIZE) ? IMB_MAX_BURST_SIZE : n_ops;

  if (ptd == 0)
    return 0;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;
      /*
       * configure all the jobs first ...
       */
      for (i = 0; i < n; i++, ops_index++)
	{
	  vnet_crypto_op_t *op = ops[ops_index];
	  const u8 *kd = vnet_crypto_get_simple_key_data (op->ctx) + key_data_offset;

	  job = &ptd->burst_jobs[i];

	  job->src = op->auth_src;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_hash_in_bytes = op->auth_src_len;
	  job->auth_tag_output_len_in_bytes = digest_size;
	  job->auth_tag_output = scratch[i];

	  job->u.HMAC._hashed_auth_key_xor_ipad = kd;
	  job->u.HMAC._hashed_auth_key_xor_opad = kd + hash_size;
	  job->user_data = op;
	}

      /*
       * submit all jobs to be processed and retire completed jobs
       */
      IMB_SUBMIT_HASH_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs, n, alg);

      for (i = 0; i < n; i++)
	{
	  job = &ptd->burst_jobs[i];
	  ipsecmb_retire_hmac_job (job, &n_fail, digest_size);
	}

      n_ops -= n;
    }

  return ops_index - n_fail;
}

#define _(a, b, c, d, e, f)                                                                        \
  static_always_inline u32 ipsecmb_ops_hmac_##a (vnet_crypto_op_t *ops[],                          \
						 vnet_crypto_op_chunk_t *chunks __clib_unused,     \
						 u32 n_ops, clib_thread_index_t thread_index)      \
  {                                                                                                \
    return ipsecmb_ops_hmac_inline (ops, n_ops, e, f, IMB_AUTH_HMAC_##b, 0);                       \
  }

foreach_ipsecmb_hmac_op;
#undef _

always_inline void
ipsecmb_retire_cipher_job (IMB_JOB *job, u32 *n_fail)
{
  vnet_crypto_op_t *op = job->user_data;

  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
    {
      op->status = ipsecmb_status_job (job->status);
      *n_fail = *n_fail + 1;
    }
  else
    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_aes_cipher_inline (vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
			       IMB_CIPHER_DIRECTION direction, IMB_CIPHER_MODE cipher_mode)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  const u32 burst_sz =
    (n_ops > IMB_MAX_BURST_SIZE) ? IMB_MAX_BURST_SIZE : n_ops;

  if (ptd == 0)
    return 0;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;

      for (i = 0; i < n; i++)
	{
	  ipsecmb_aes_key_data_t *kd;
	  vnet_crypto_op_t *op = ops[ops_index++];
	  kd = (ipsecmb_aes_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx);

	  job = &ptd->burst_jobs[i];

	  job->src = op->src;
	  job->dst = op->dst;
	  job->msg_len_to_cipher_in_bytes = op->len;
	  job->cipher_start_src_offset_in_bytes = 0;

	  job->hash_alg = IMB_AUTH_NULL;

	  job->enc_keys = kd->enc_key_exp;
	  job->dec_keys = kd->dec_key_exp;
	  job->iv = op->iv;
	  job->iv_len_in_bytes = IMB_AES_BLOCK_SIZE;

	  job->user_data = op;
	}

      IMB_SUBMIT_CIPHER_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs, n,
				       cipher_mode, direction, key_len / 8);
      for (i = 0; i < n; i++)
	{
	  job = &ptd->burst_jobs[i];
	  ipsecmb_retire_cipher_job (job, &n_fail);
	}

      n_ops -= n;
    }

  return ops_index - n_fail;
}

#define _(a, b, c)                                                                                 \
  static_always_inline u32 ipsecmb_ops_cipher_enc_##a (                                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_aes_cipher_inline (ops, n_ops, b, IMB_DIR_ENCRYPT, IMB_CIPHER_##c);         \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_cipher_dec_##a (                                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_aes_cipher_inline (ops, n_ops, b, IMB_DIR_DECRYPT, IMB_CIPHER_##c);         \
  }

foreach_ipsecmb_cipher_op;
#undef _

static_always_inline u32
ipsecmb_ops_combined_enc (vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
			  IMB_CIPHER_MODE cipher_mode, u32 hash_size, u32 digest_size,
			  IMB_HASH_ALG hash_alg)
{
  vnet_crypto_op_t *hmac_ops[n_ops];
  u32 i;
  u32 n_hmac_ops;
  u32 n_success;

  if (ipsecmb_ops_aes_cipher_inline (ops, n_ops, key_len, IMB_DIR_ENCRYPT, cipher_mode) == 0)
    return 0;

  n_hmac_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      if (ops[i]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	continue;
      hmac_ops[n_hmac_ops] = ops[i];
      n_hmac_ops++;
    }

  n_success = ipsecmb_ops_hmac_inline (hmac_ops, n_hmac_ops, hash_size, digest_size, hash_alg,
				       sizeof (ipsecmb_aes_key_data_t));

  return n_success;
}

static_always_inline u32
ipsecmb_ops_combined_dec (vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
			  IMB_CIPHER_MODE cipher_mode, u32 hash_size, u32 digest_size,
			  IMB_HASH_ALG hash_alg)
{
  vnet_crypto_op_t *cipher_ops[n_ops];
  vnet_crypto_op_t *hmac_ops[n_ops];
  u32 i;
  u32 n_cipher_ops;
  u32 n_hmac_ops;
  u32 n_success;

  n_hmac_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      hmac_ops[n_hmac_ops] = ops[i];
      n_hmac_ops++;
    }

  if (ipsecmb_ops_hmac_inline (hmac_ops, n_hmac_ops, hash_size, digest_size, hash_alg,
			       sizeof (ipsecmb_aes_key_data_t)) == 0)
    return 0;

  n_cipher_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      if (ops[i]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	continue;
      cipher_ops[n_cipher_ops] = ops[i];
      n_cipher_ops++;
    }

  n_success =
    ipsecmb_ops_aes_cipher_inline (cipher_ops, n_cipher_ops, key_len, IMB_DIR_DECRYPT, cipher_mode);

  return n_success;
}

#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  static_always_inline u32 ipsecmb_ops_combined_enc_##a (                                          \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_combined_enc (ops, n_ops, b, IMB_CIPHER_##c, g, h, IMB_AUTH_HMAC_##d);      \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_combined_dec_##a (                                          \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_combined_dec (ops, n_ops, b, IMB_CIPHER_##c, g, h, IMB_AUTH_HMAC_##d);      \
  }

foreach_ipsecmb_combined_cipher_op;
#undef _

  typedef struct
{
  aes_gcm_enc_dec_t enc_dec_fn;
  aes_gcm_init_t init_fn;
  aes_gcm_enc_dec_update_t upd_fn;
  aes_gcm_enc_dec_finalize_t finalize_fn;
  u32 is_dec;
  u32 chained;
  i32 aadlen;
  u32 taglen;
} ipsecmb_ops_gcm_args_t;

static_always_inline u32
ipsecmb_ops_gcm (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		 ipsecmb_ops_gcm_args_t a)
{
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_failed = 0;

  for (i = 0; i < n_ops; i++)
    {
      struct gcm_key_data *kd;
      struct gcm_context_data ctx;
      vnet_crypto_op_t *op = ops[i];
      u8 scratch[16], *tag = a.is_dec ? scratch : op->auth;
      u32 taglen = a.taglen ? a.taglen : op->auth_len;
      u32 aadlen = a.aadlen >= 0 ? a.aadlen : op->aad_len;

      kd = (struct gcm_key_data *) vnet_crypto_get_chained_key_data (op->ctx);
      if (!a.chained)
	kd = (struct gcm_key_data *) vnet_crypto_get_simple_key_data (op->ctx);
      if (a.chained)
	{
	  ASSERT (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS);
	  a.init_fn (kd, &ctx, op->iv, op->aad, aadlen);
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      a.upd_fn (kd, &ctx, chp->dst, chp->src, chp->len);
	      chp += 1;
	    }
	  a.finalize_fn (kd, &ctx, tag, taglen);
	}
      else
	{
	  a.enc_dec_fn (kd, &ctx, op->dst, op->src, op->len, op->iv, op->aad,
			aadlen, tag, taglen);
	}

      if (a.is_dec && (memcmp (op->auth, tag, taglen)))
	{
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  n_failed++;
	}
      else
	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops - n_failed;
}

static_always_inline IMB_MGR *
get_mgr (vlib_main_t *vm __clib_unused)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  if (ptd == 0)
    return 0;
  return ptd->mgr;
}

#define _(a, b, f, l)                                                                              \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_enc_##a (                                        \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index __clib_unused)                                                \
  {                                                                                                \
    return ipsecmb_ops_gcm (ops, 0, n_ops,                                                         \
			    (ipsecmb_ops_gcm_args_t){                                              \
			      .enc_dec_fn = get_mgr (vlib_get_main ())->gcm##b##_enc,              \
			      .aadlen = (f) ? (l) : -1,                                            \
			      .taglen = (f) ? 16 : 0,                                              \
			    });                                                                    \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_enc_##a##_chained (                              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index __clib_unused)                                                \
  {                                                                                                \
    IMB_MGR *m = get_mgr (vlib_get_main ());                                                       \
    return ipsecmb_ops_gcm (ops, chunks, n_ops,                                                    \
			    (ipsecmb_ops_gcm_args_t){                                              \
			      .init_fn = m->gcm##b##_init,                                         \
			      .upd_fn = m->gcm##b##_enc_update,                                    \
			      .finalize_fn = m->gcm##b##_enc_finalize,                             \
			      .chained = 1,                                                        \
			      .aadlen = (f) ? (l) : -1,                                            \
			      .taglen = (f) ? 16 : 0,                                              \
			    });                                                                    \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a (                                        \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index __clib_unused)                                                \
  {                                                                                                \
    return ipsecmb_ops_gcm (                                                                       \
      ops, 0, n_ops,                                                                               \
      (ipsecmb_ops_gcm_args_t){ .enc_dec_fn = get_mgr (vlib_get_main ())->gcm##b##_dec,            \
				.aadlen = (f) ? (l) : -1,                                          \
				.taglen = (f) ? 16 : 0,                                            \
				.is_dec = 1 });                                                    \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a##_chained (                              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index __clib_unused)                                                \
  {                                                                                                \
    IMB_MGR *m = get_mgr (vlib_get_main ());                                                       \
    return ipsecmb_ops_gcm (ops, chunks, n_ops,                                                    \
			    (ipsecmb_ops_gcm_args_t){ .init_fn = m->gcm##b##_init,                 \
						      .upd_fn = m->gcm##b##_dec_update,            \
						      .finalize_fn = m->gcm##b##_dec_finalize,     \
						      .chained = 1,                                \
						      .aadlen = (f) ? (l) : -1,                    \
						      .taglen = (f) ? 16 : 0,                      \
						      .is_dec = 1 });                              \
  }
foreach_ipsecmb_gcm_cipher_op;
#undef _

#ifdef HAVE_IPSECMB_CHACHA_POLY
always_inline void
ipsecmb_retire_aead_job (IMB_JOB *job, u32 *n_fail)
{
  vnet_crypto_op_t *op = job->user_data;
  u32 len = op->auth_len;

  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
    {
      op->status = ipsecmb_status_job (job->status);
      *n_fail = *n_fail + 1;
      return;
    }

  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
    {
      if (memcmp (op->auth, job->auth_tag_output, len))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  return;
	}
    }

  clib_memcpy_fast (op->auth, job->auth_tag_output, len);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_chacha_poly (vnet_crypto_op_t *ops[], u32 n_ops, IMB_CIPHER_DIRECTION dir, i32 aad_len,
			 u32 tag_len)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  struct IMB_JOB *job;
  IMB_MGR *m;
  u32 i, n, n_fail = 0, ops_index = 0;
  u8 scratch[IMB_MAX_BURST_SIZE][16];

  if (ptd == 0)
    return 0;
  m = ptd->mgr;

  while (n_ops)
    {
      n = n_ops > IMB_MAX_BURST_SIZE ? IMB_MAX_BURST_SIZE : n_ops;

      for (i = 0; i < n; i++, ops_index++)
	{
	  vnet_crypto_op_t *op = ops[ops_index];
	  u8 *key;

	  job = IMB_GET_NEXT_JOB (m);
	  key = vnet_crypto_get_simple_key_data (op->ctx);

	  job->cipher_direction = dir;
	  job->chain_order = IMB_ORDER_HASH_CIPHER;
	  job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
	  job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
	  job->enc_keys = job->dec_keys = key;
	  job->key_len_in_bytes = 32;

	  job->u.CHACHA20_POLY1305.aad = op->aad;
	  job->u.CHACHA20_POLY1305.aad_len_in_bytes = aad_len >= 0 ? aad_len : op->aad_len;
	  job->src = op->src;
	  job->dst = op->dst;

	  job->iv = op->iv;
	  job->iv_len_in_bytes = 12;
	  job->msg_len_to_cipher_in_bytes = job->msg_len_to_hash_in_bytes = op->len;
	  job->cipher_start_src_offset_in_bytes = job->hash_start_src_offset_in_bytes = 0;

	  job->auth_tag_output = dir == IMB_DIR_ENCRYPT ? op->auth : scratch[i];
	  job->auth_tag_output_len_in_bytes = tag_len ? tag_len : op->auth_len;

	  job->user_data = op;

	  job = IMB_SUBMIT_JOB_NOCHECK (ptd->mgr);
	  if (job)
	    ipsecmb_retire_aead_job (job, &n_fail);
	}

      while ((job = IMB_FLUSH_JOB (ptd->mgr)))
	ipsecmb_retire_aead_job (job, &n_fail);

      n_ops -= n;
    }

  return ops_index - n_fail;
}

static_always_inline u32
ipsecmb_ops_chacha_poly_enc (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused,
			     u32 n_ops, clib_thread_index_t thread_index)
{
  return ipsecmb_ops_chacha_poly (ops, n_ops, IMB_DIR_ENCRYPT, -1, 0);
}

static_always_inline u32
ipsecmb_ops_chacha_poly_dec (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused,
			     u32 n_ops, clib_thread_index_t thread_index)
{
  return ipsecmb_ops_chacha_poly (ops, n_ops, IMB_DIR_DECRYPT, -1, 0);
}

#define _(a)                                                                                       \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_enc (                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly (ops, n_ops, IMB_DIR_ENCRYPT, a, 16);                           \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_dec (                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly (ops, n_ops, IMB_DIR_DECRYPT, a, 16);                           \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _

  static_always_inline u32
  ipsecmb_ops_chacha_poly_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				   u32 n_ops, IMB_CIPHER_DIRECTION dir, i32 aad_len, u32 tag_len)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  IMB_MGR *m;
  u32 i, n_fail = 0;

  if (ptd == 0)
    return 0;
  m = ptd->mgr;

  if (dir == IMB_DIR_ENCRYPT)
    {
      for (i = 0; i < n_ops; i++)
	{
	  vnet_crypto_op_t *op = ops[i];
	  struct chacha20_poly1305_context_data ctx;
	  vnet_crypto_op_chunk_t *chp;
	  u32 j;

	  ASSERT (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS);

	  u8 *key = vnet_crypto_get_chained_key_data (op->ctx);

	  IMB_CHACHA20_POLY1305_INIT (m, key, &ctx, op->iv, op->aad,
				      aad_len >= 0 ? aad_len : op->aad_len);

	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      IMB_CHACHA20_POLY1305_ENC_UPDATE (m, key, &ctx, chp->dst,
						chp->src, chp->len);
	      chp += 1;
	    }

	  IMB_CHACHA20_POLY1305_ENC_FINALIZE (m, &ctx, op->auth, tag_len ? tag_len : op->auth_len);

	  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	}
    }
  else /* dir == IMB_DIR_DECRYPT */
    {
      for (i = 0; i < n_ops; i++)
	{
	  vnet_crypto_op_t *op = ops[i];
	  struct chacha20_poly1305_context_data ctx;
	  vnet_crypto_op_chunk_t *chp;
	  u8 scratch[16];
	  u32 j;

	  ASSERT (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS);

	  u8 *key = vnet_crypto_get_chained_key_data (op->ctx);

	  IMB_CHACHA20_POLY1305_INIT (m, key, &ctx, op->iv, op->aad,
				      aad_len >= 0 ? aad_len : op->aad_len);

	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      IMB_CHACHA20_POLY1305_DEC_UPDATE (m, key, &ctx, chp->dst,
						chp->src, chp->len);
	      chp += 1;
	    }

	  IMB_CHACHA20_POLY1305_DEC_FINALIZE (m, &ctx, scratch, tag_len ? tag_len : op->auth_len);

	  if (memcmp (op->auth, scratch, tag_len ? tag_len : op->auth_len))
	    {
	      n_fail = n_fail + 1;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	    }
	  else
	    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	}
    }

  return n_ops - n_fail;
}

static_always_inline u32
ipsec_mb_ops_chacha_poly_enc_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				      u32 n_ops, clib_thread_index_t thread_index)
{
  return ipsecmb_ops_chacha_poly_chained (ops, chunks, n_ops, IMB_DIR_ENCRYPT, -1, 0);
}

static_always_inline u32
ipsec_mb_ops_chacha_poly_dec_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				      u32 n_ops, clib_thread_index_t thread_index)
{
  return ipsecmb_ops_chacha_poly_chained (ops, chunks, n_ops, IMB_DIR_DECRYPT, -1, 0);
}

#define _(a)                                                                                       \
  static_always_inline u32 ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained (                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly_chained (ops, chunks, n_ops, IMB_DIR_ENCRYPT, a, 16);           \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained (                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly_chained (ops, chunks, n_ops, IMB_DIR_DECRYPT, a, 16);           \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

  static void
  crypto_ipsecmb_cipher_key_add_inline (vnet_crypto_ctx_t *ctx, u8 *key_data, keyexp_t keyexp)
{
  if (keyexp == 0)
    return;

  keyexp (vnet_crypto_get_cipher_key (ctx), ((ipsecmb_aes_key_data_t *) key_data)->enc_key_exp,
	  ((ipsecmb_aes_key_data_t *) key_data)->dec_key_exp);
}

#define _(a, b, c)                                                                                 \
  static void crypto_ipsecmb_cipher_key_change_##a (vnet_crypto_ctx_t *ctx,                        \
						    vnet_crypto_key_change_args_t *args)           \
  {                                                                                                \
    ipsecmb_main_t *imbm = &ipsecmb_main;                                                          \
    u8 *key_data;                                                                                  \
                                                                                                   \
    if (args->action != VNET_CRYPTO_KEY_DATA_ADD)                                                  \
      return;                                                                                      \
    key_data = args->key_data;                                                                     \
    if (imbm->mgr == 0)                                                                            \
      return;                                                                                      \
                                                                                                   \
    crypto_ipsecmb_cipher_key_add_inline (ctx, key_data, imbm->mgr->keyexp_##b);                   \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REGISTER_ALG_GROUP (ipsecmb_cipher_##a##_group) = {                                  \
    .max_key_data_sz = sizeof (ipsecmb_aes_key_data_t),                                            \
    .key_change_fn = crypto_ipsecmb_cipher_key_change_##a,                                         \
  };
foreach_ipsecmb_cipher_op
#undef _

  static void
  crypto_ipsecmb_gcm_key_add_inline (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_gcm_pre_t pre)
{
  if (pre == 0)
    return;

  pre (vnet_crypto_get_cipher_key (ctx), (struct gcm_key_data *) key_data);
}

#define _(a, b, f, l)                                                                              \
  static void crypto_ipsecmb_gcm_key_change_##a (vnet_crypto_ctx_t *ctx,                           \
						 vnet_crypto_key_change_args_t *args)              \
  {                                                                                                \
    ipsecmb_main_t *imbm = &ipsecmb_main;                                                          \
    u8 *key_data;                                                                                  \
                                                                                                   \
    if (args->action != VNET_CRYPTO_KEY_DATA_ADD &&                                                \
	args->action != VNET_CRYPTO_THREAD_KEY_DATA_ADD)                                           \
      return;                                                                                      \
    key_data = args->action == VNET_CRYPTO_KEY_DATA_ADD ? args->key_data : args->thread_key_data;  \
    if (imbm->mgr == 0)                                                                            \
      return;                                                                                      \
                                                                                                   \
    crypto_ipsecmb_gcm_key_add_inline (ctx, key_data, imbm->mgr->gcm##b##_pre);                    \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REGISTER_ALG_GROUP (ipsecmb_gcm_##a##_group) = {                                     \
    .max_key_data_sz = sizeof (struct gcm_key_data),                                               \
    .key_change_fn = crypto_ipsecmb_gcm_key_change_##a,                                            \
  };
foreach_ipsecmb_gcm_cipher_op
#undef _

  static void
  crypto_ipsecmb_hmac_key_add_inline (vnet_crypto_ctx_t *ctx, u8 *key_data,
				      hash_one_block_t hash_one_block, hash_fn_t hash_fn,
				      u32 block_size, u32 data_size)
{
  u32 i;

  {
    const int block_qw = HMAC_MAX_BLOCK_SIZE / sizeof (u64);
    u64 pad[block_qw], key_hash[block_qw];

    clib_memset_u8 (key_hash, 0, HMAC_MAX_BLOCK_SIZE);
    if (ctx->auth_key_sz <= block_size)
      clib_memcpy_fast (key_hash, vnet_crypto_get_auth_key (ctx), ctx->auth_key_sz);
    else
      hash_fn (vnet_crypto_get_auth_key (ctx), ctx->auth_key_sz, key_hash);

    for (i = 0; i < block_qw; i++)
      pad[i] = key_hash[i] ^ 0x3636363636363636;
    hash_one_block (pad, key_data);

    for (i = 0; i < block_qw; i++)
      pad[i] = key_hash[i] ^ 0x5c5c5c5c5c5c5c5c;
    hash_one_block (pad, ((u8 *) key_data) + (data_size / 2));
  }
}

#define _(a, b, c, d, e, f)                                                                        \
  static_always_inline void crypto_ipsecmb_hmac_key_add_internal_##a (vnet_crypto_ctx_t *ctx,      \
								      u8 *key_data)                \
  {                                                                                                \
    ipsecmb_main_t *imbm = &ipsecmb_main;                                                          \
                                                                                                   \
    if (imbm->mgr == 0)                                                                            \
      return;                                                                                      \
                                                                                                   \
    crypto_ipsecmb_hmac_key_add_inline (ctx, key_data, imbm->mgr->c##_one_block, imbm->mgr->c, d,  \
					e * 2);                                                    \
  }                                                                                                \
                                                                                                   \
  static void crypto_ipsecmb_hmac_key_change_##a (vnet_crypto_ctx_t *ctx,                          \
						  vnet_crypto_key_change_args_t *args)             \
  {                                                                                                \
    u8 *key_data;                                                                                  \
    if (args->action != VNET_CRYPTO_KEY_DATA_ADD)                                                  \
      return;                                                                                      \
    key_data = args->key_data;                                                                     \
    crypto_ipsecmb_hmac_key_add_internal_##a (ctx, key_data);                                      \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REGISTER_ALG_GROUP (ipsecmb_auth_##a##_group) = {                                    \
    .max_key_data_sz = IPSECMB_HMAC_KEY_DATA_SIZE,                                                 \
    .key_change_fn = crypto_ipsecmb_hmac_key_change_##a,                                           \
  };
foreach_ipsecmb_hmac_op
#undef _

  static void
  crypto_ipsecmb_chacha_poly_key_change (vnet_crypto_ctx_t *ctx,
					 vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;
  u32 sz = ctx->cipher_key_sz + ctx->auth_key_sz;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD && args->action != VNET_CRYPTO_THREAD_KEY_DATA_ADD)
    return;
  key_data = args->action == VNET_CRYPTO_KEY_DATA_ADD ? args->key_data : args->thread_key_data;
  if (sz > 32)
    sz = 32;
  clib_memcpy_fast (key_data, vnet_crypto_get_cipher_key (ctx), sz);
}

static void
crypto_ipsecmb_combined_key_add_inline (vnet_crypto_ctx_t *ctx, u8 *key_data, keyexp_t keyexp,
					void (*hmac_key_add_fn) (vnet_crypto_ctx_t *ctx,
								 u8 *key_data),
					vnet_crypto_alg_t cipher_alg, vnet_crypto_alg_t integ_alg)
{
  uword key_data_len = ctx->cipher_key_offset + ctx->cipher_key_sz;

  if (ctx->auth_key_sz)
    key_data_len = ctx->auth_key_offset + ctx->auth_key_sz;

  u8 key_buf[sizeof (vnet_crypto_ctx_t) + key_data_len];
  vnet_crypto_ctx_t *tmp_ctx = (vnet_crypto_ctx_t *) key_buf;

  clib_memcpy_fast (tmp_ctx, ctx, sizeof (vnet_crypto_ctx_t) + key_data_len);
  tmp_ctx->alg = cipher_alg;

  crypto_ipsecmb_cipher_key_add_inline (tmp_ctx, key_data, keyexp);
  tmp_ctx->alg = integ_alg;

  hmac_key_add_fn (tmp_ctx, key_data + sizeof (ipsecmb_aes_key_data_t));
}

#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  static void crypto_ipsecmb_combined_key_change_##a (vnet_crypto_ctx_t *ctx,                      \
						      vnet_crypto_key_change_args_t *args)         \
  {                                                                                                \
    ipsecmb_main_t *imbm = &ipsecmb_main;                                                          \
    u8 *key_data;                                                                                  \
                                                                                                   \
    if (args->action != VNET_CRYPTO_KEY_DATA_ADD)                                                  \
      return;                                                                                      \
    key_data = args->key_data;                                                                     \
    if (imbm->mgr == 0)                                                                            \
      return;                                                                                      \
                                                                                                   \
    crypto_ipsecmb_combined_key_add_inline (ctx, key_data, imbm->mgr->keyexp_##b,                  \
					    crypto_ipsecmb_hmac_key_add_internal_##e,              \
					    VNET_CRYPTO_ALG_AES_##b##_##j, VNET_CRYPTO_ALG_##e);   \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REGISTER_ALG_GROUP (ipsecmb_combined_##a##_group) = {                                \
    .max_key_data_sz = sizeof (ipsecmb_combined_key_data_t),                                       \
    .key_change_fn = crypto_ipsecmb_combined_key_change_##a,                                       \
  };
foreach_ipsecmb_combined_cipher_op
#undef _

  static char *
  crypto_ipsecmb_init (vnet_crypto_engine_registration_t *r __clib_unused)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd;

  if (!clib_cpu_supports_aes ())
    return "AES ISA not available on this CPU";

  ptd = ipsecmb_get_per_thread_data ();
  if (ptd == 0)
    return "failed to initialize thread-local ipsecmb context";

  imbm->mgr = ptd->mgr;
  return 0;
}

#ifdef HAVE_IPSECMB_CHACHA_POLY
VNET_CRYPTO_REGISTER_ALG_GROUP (ipsecmb_chacha_poly_group) = {
  .max_key_data_sz = IMB_CHACHA20_POLY1305_KEY_SIZE,
  .key_change_fn = crypto_ipsecmb_chacha_poly_key_change,
};
#endif

#define _(a, b, f, l)                                                                              \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_##a) = {                                                            \
    .group = &ipsecmb_gcm_##a##_group,                                                             \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_gcm_cipher_enc_##a,                                                    \
      .dec_fn = ipsecmb_ops_gcm_cipher_dec_##a,                                                    \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = ipsecmb_ops_gcm_cipher_enc_##a##_chained,                                          \
      .dec_fn = ipsecmb_ops_gcm_cipher_dec_##a##_chained,                                          \
    },                                                                                             \
  };
foreach_ipsecmb_gcm_cipher_op
#undef _

#define _(a, b, c, d, e, f)                                                                        \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_##a) = {                                                       \
    .group = &ipsecmb_auth_##a##_group,                                                            \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = { .hmac_fn = ipsecmb_ops_hmac_##a, },                                                \
  };
  foreach_ipsecmb_hmac_op
#undef _

VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_sha1_icv12) = {
  .group = &ipsecmb_auth_SHA1_160_group,
  .alg_id = VNET_CRYPTO_ALG_SHA1_160_ICV12,
  .simple = { .hmac_fn = ipsecmb_ops_hmac_SHA1_160, },
};

VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_sha256_icv12) = {
  .group = &ipsecmb_auth_SHA2_256_group,
  .alg_id = VNET_CRYPTO_ALG_SHA2_256_ICV12,
  .simple = { .hmac_fn = ipsecmb_ops_hmac_SHA2_256, },
};

VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_sha256_icv16) = {
  .group = &ipsecmb_auth_SHA2_256_group,
  .alg_id = VNET_CRYPTO_ALG_SHA2_256_ICV16,
  .simple = { .hmac_fn = ipsecmb_ops_hmac_SHA2_256, },
};

VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_sha384_icv24) = {
  .group = &ipsecmb_auth_SHA2_384_group,
  .alg_id = VNET_CRYPTO_ALG_SHA2_384_ICV24,
  .simple = { .hmac_fn = ipsecmb_ops_hmac_SHA2_384, },
};

VNET_CRYPTO_REGISTER_ALG (ipsecmb_hmac_sha512_icv32) = {
  .group = &ipsecmb_auth_SHA2_512_group,
  .alg_id = VNET_CRYPTO_ALG_SHA2_512_ICV32,
  .simple = { .hmac_fn = ipsecmb_ops_hmac_SHA2_512, },
};

#define _(a, b, c)                                                                                 \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_##a) = {                                                            \
    .group = &ipsecmb_cipher_##a##_group,                                                          \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_cipher_enc_##a,                                                        \
      .dec_fn = ipsecmb_ops_cipher_dec_##a,                                                        \
    },                                                                                             \
  };
foreach_ipsecmb_cipher_op
#undef _

#define _(a, b, c, j, d, e, f, g, h, i)                                                                   \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_##a) = {                                                            \
    .group = &ipsecmb_combined_##a##_group,                                                        \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_combined_enc_##a,                                                      \
      .dec_fn = ipsecmb_ops_combined_dec_##a,                                                      \
    },                                                                                             \
  }; \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_##a##_icv##i) = {                                                   \
    .group = &ipsecmb_combined_##a##_group,                                                        \
    .alg_id = VNET_CRYPTO_ALG_##a##_ICV##i,                                                        \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_combined_enc_##a,                                                      \
      .dec_fn = ipsecmb_ops_combined_dec_##a,                                                      \
    },                                                                                             \
  };
      foreach_ipsecmb_combined_cipher_op
#undef _

#define _(a, i)                                                                                    \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_##a##_icv##i##_extra) = {                                           \
    .group = &ipsecmb_combined_##a##_group,                                                        \
    .alg_id = VNET_CRYPTO_ALG_##a##_ICV##i,                                                        \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_combined_enc_##a,                                                      \
      .dec_fn = ipsecmb_ops_combined_dec_##a,                                                      \
    },                                                                                             \
  };
foreach_ipsecmb_combined_fixed_extra_op
#undef _

#ifdef HAVE_IPSECMB_CHACHA_POLY
	VNET_CRYPTO_REGISTER_ALG (ipsecmb_chacha20_poly1305) = {
	  .group = &ipsecmb_chacha_poly_group,
	  .alg_id = VNET_CRYPTO_ALG_CHACHA20_POLY1305,
	  .simple = {
	    .enc_fn = ipsecmb_ops_chacha_poly_enc,
	    .dec_fn = ipsecmb_ops_chacha_poly_dec,
	  },
	  .chained = {
	    .enc_fn = ipsec_mb_ops_chacha_poly_enc_chained,
	    .dec_fn = ipsec_mb_ops_chacha_poly_dec_chained,
	  },
	};

#define _(a)                                                                                       \
  VNET_CRYPTO_REGISTER_ALG (ipsecmb_chacha20_poly1305_tag16_aad##a) = {                                 \
    .group = &ipsecmb_chacha_poly_group,                                                           \
    .alg_id = VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD##a,                                      \
    .simple = {                                                                                    \
      .enc_fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_enc,                                        \
      .dec_fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_dec,                                        \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained,                               \
      .dec_fn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained,                               \
    },                                                                                             \
  };
foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

VNET_CRYPTO_REGISTER_ENGINE () = {
  .name = "ipsecmb",
  .desc = "Intel(R) Multi-Buffer Crypto for IPsec Library" IMB_VERSION_STR,
  .prio = 80,
  .init_fn = crypto_ipsecmb_init,
};
