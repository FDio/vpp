/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
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
#define EXPANDED_KEY_N_BYTES (16 * 15)

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
#define foreach_ipsecmb_hmac_op                                \
  _(SHA1,   SHA_1,   sha1,   64,  20, 20)                      \
  _(SHA224, SHA_224, sha224, 64,  32, 28)                      \
  _(SHA256, SHA_256, sha256, 64,  32, 32)                      \
  _(SHA384, SHA_384, sha384, 128, 64, 48)                      \
  _(SHA512, SHA_512, sha512, 128, 64, 64)

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
#define foreach_ipsecmb_gcm_cipher_op                                         \
  _ (AES_128_GCM, 128, 0, 0)                                                  \
  _ (AES_128_GCM_TAG16_AAD8, 128, 1, 8)                                       \
  _ (AES_128_GCM_TAG16_AAD12, 128, 1, 12)                                     \
  _ (AES_192_GCM, 192, 0, 0)                                                  \
  _ (AES_192_GCM_TAG16_AAD8, 192, 1, 8)                                       \
  _ (AES_192_GCM_TAG16_AAD12, 192, 1, 12)                                     \
  _ (AES_256_GCM, 256, 0, 0)                                                  \
  _ (AES_256_GCM_TAG16_AAD8, 256, 1, 8)                                       \
  _ (AES_256_GCM_TAG16_AAD12, 256, 1, 12)

#define foreach_ipsecmb_combined_cipher_op                                                         \
  _ (AES_128_CBC_SHA1, 128, CBC, CBC, SHA_1, SHA1, 64, 20, 20, 12)                                 \
  _ (AES_192_CBC_SHA1, 192, CBC, CBC, SHA_1, SHA1, 64, 20, 20, 12)                                 \
  _ (AES_256_CBC_SHA1, 256, CBC, CBC, SHA_1, SHA1, 64, 20, 20, 12)                                 \
  _ (AES_128_CBC_SHA224, 128, CBC, CBC, SHA_224, SHA224, 64, 32, 28, 14)                           \
  _ (AES_192_CBC_SHA224, 192, CBC, CBC, SHA_224, SHA224, 64, 32, 28, 14)                           \
  _ (AES_256_CBC_SHA224, 256, CBC, CBC, SHA_224, SHA224, 64, 32, 28, 14)                           \
  _ (AES_128_CBC_SHA256, 128, CBC, CBC, SHA_256, SHA256, 64, 32, 32, 16)                           \
  _ (AES_192_CBC_SHA256, 192, CBC, CBC, SHA_256, SHA256, 64, 32, 32, 16)                           \
  _ (AES_256_CBC_SHA256, 256, CBC, CBC, SHA_256, SHA256, 64, 32, 32, 16)                           \
  _ (AES_128_CBC_SHA384, 128, CBC, CBC, SHA_384, SHA384, 128, 64, 48, 24)                          \
  _ (AES_192_CBC_SHA384, 192, CBC, CBC, SHA_384, SHA384, 128, 64, 48, 24)                          \
  _ (AES_256_CBC_SHA384, 256, CBC, CBC, SHA_384, SHA384, 128, 64, 48, 24)                          \
  _ (AES_128_CBC_SHA512, 128, CBC, CBC, SHA_512, SHA512, 128, 64, 64, 32)                          \
  _ (AES_192_CBC_SHA512, 192, CBC, CBC, SHA_512, SHA512, 128, 64, 64, 32)                          \
  _ (AES_256_CBC_SHA512, 256, CBC, CBC, SHA_512, SHA512, 128, 64, 64, 32)                          \
  _ (AES_128_CTR_SHA1, 128, CNTR, CTR, SHA_1, SHA1, 64, 20, 20, 12)                                \
  _ (AES_192_CTR_SHA1, 192, CNTR, CTR, SHA_1, SHA1, 64, 20, 20, 12)                                \
  _ (AES_256_CTR_SHA1, 256, CNTR, CTR, SHA_1, SHA1, 64, 20, 20, 12)                                \
  _ (AES_128_CTR_SHA256, 128, CNTR, CTR, SHA_256, SHA256, 64, 32, 32, 16)                          \
  _ (AES_192_CTR_SHA256, 192, CNTR, CTR, SHA_256, SHA256, 64, 32, 32, 16)                          \
  _ (AES_256_CTR_SHA256, 256, CNTR, CTR, SHA_256, SHA256, 64, 32, 32, 16)                          \
  _ (AES_128_CTR_SHA384, 128, CNTR, CTR, SHA_384, SHA384, 128, 64, 48, 24)                         \
  _ (AES_192_CTR_SHA384, 192, CNTR, CTR, SHA_384, SHA384, 128, 64, 48, 24)                         \
  _ (AES_256_CTR_SHA384, 256, CNTR, CTR, SHA_384, SHA384, 128, 64, 48, 24)                         \
  _ (AES_128_CTR_SHA512, 128, CNTR, CTR, SHA_512, SHA512, 128, 64, 64, 32)                         \
  _ (AES_192_CTR_SHA512, 192, CNTR, CTR, SHA_512, SHA512, 128, 64, 64, 32)                         \
  _ (AES_256_CTR_SHA512, 256, CNTR, CTR, SHA_512, SHA512, 128, 64, 64, 32)

#define foreach_chacha_poly_fixed_aad_lengths _ (0) _ (8) _ (12)

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
  u32 len = op->digest_len ? op->digest_len : digest_size;

  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
    {
      op->status = ipsecmb_status_job (job->status);
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
ipsecmb_ops_hmac_inline (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			 u32 block_size, u32 hash_size, u32 digest_size, IMB_HASH_ALG alg)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  u8 scratch[n_ops][digest_size];
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
	  const u8 *kd = (u8 *) key_data[ops_index];

	  job = &ptd->burst_jobs[i];

	  job->src = op->integ_src;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_hash_in_bytes = op->integ_len;
	  job->auth_tag_output_len_in_bytes = digest_size;
	  job->auth_tag_output = scratch[ops_index];

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
						 vnet_crypto_key_data_t *key_data[], u32 n_ops)    \
  {                                                                                                \
    return ipsecmb_ops_hmac_inline (ops, key_data, n_ops, d, e, f, IMB_AUTH_HMAC_##b);             \
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
ipsecmb_ops_aes_cipher_inline (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[],
			       u32 n_ops, u32 key_len, IMB_CIPHER_DIRECTION direction,
			       IMB_CIPHER_MODE cipher_mode)
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
	  kd = (ipsecmb_aes_key_data_t *) key_data[ops_index - 1];

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
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_aes_cipher_inline (ops, key_data, n_ops, b, IMB_DIR_ENCRYPT,                \
					  IMB_CIPHER_##c);                                         \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_cipher_dec_##a (                                            \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_aes_cipher_inline (ops, key_data, n_ops, b, IMB_DIR_DECRYPT,                \
					  IMB_CIPHER_##c);                                         \
  }

foreach_ipsecmb_cipher_op;
#undef _

static_always_inline u32
ipsecmb_ops_combined_enc (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			  u32 key_len, IMB_CIPHER_MODE cipher_mode, u32 block_size, u32 hash_size,
			  u32 digest_size, IMB_HASH_ALG hash_alg)
{
  vnet_crypto_op_t *hmac_ops[n_ops];
  vnet_crypto_key_data_t *hmac_key_data[n_ops];
  u32 i;
  u32 n_hmac_ops;
  u32 n_success;

  if (ipsecmb_ops_aes_cipher_inline (ops, key_data, n_ops, key_len, IMB_DIR_ENCRYPT, cipher_mode) ==
      0)
    return 0;

  n_hmac_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      if (ops[i]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	continue;
      hmac_ops[n_hmac_ops] = ops[i];
      hmac_key_data[n_hmac_ops] =
	(vnet_crypto_key_data_t *) (((u8 *) key_data[i]) + sizeof (ipsecmb_aes_key_data_t));
      n_hmac_ops++;
    }

  n_success = ipsecmb_ops_hmac_inline (hmac_ops, hmac_key_data, n_hmac_ops, block_size, hash_size,
				       digest_size, hash_alg);

  return n_success;
}

static_always_inline u32
ipsecmb_ops_combined_dec (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			  u32 key_len, IMB_CIPHER_MODE cipher_mode, u32 block_size, u32 hash_size,
			  u32 digest_size, IMB_HASH_ALG hash_alg)
{
  vnet_crypto_op_t *cipher_ops[n_ops];
  vnet_crypto_key_data_t *cipher_key_data[n_ops];
  vnet_crypto_op_t *hmac_ops[n_ops];
  vnet_crypto_key_data_t *hmac_key_data[n_ops];
  u32 i;
  u32 n_cipher_ops;
  u32 n_hmac_ops;
  u32 n_success;

  n_hmac_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      hmac_ops[n_hmac_ops] = ops[i];
      hmac_key_data[n_hmac_ops] =
	(vnet_crypto_key_data_t *) (((u8 *) key_data[i]) + sizeof (ipsecmb_aes_key_data_t));
      n_hmac_ops++;
    }

  if (ipsecmb_ops_hmac_inline (hmac_ops, hmac_key_data, n_hmac_ops, block_size, hash_size,
			       digest_size, hash_alg) == 0)
    return 0;

  n_cipher_ops = 0;
  for (i = 0; i < n_ops; i++)
    {
      if (ops[i]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	continue;
      cipher_ops[n_cipher_ops] = ops[i];
      cipher_key_data[n_cipher_ops] = key_data[i];
      n_cipher_ops++;
    }

  n_success = ipsecmb_ops_aes_cipher_inline (cipher_ops, cipher_key_data, n_cipher_ops, key_len,
					     IMB_DIR_DECRYPT, cipher_mode);

  return n_success;
}

#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  static_always_inline u32 ipsecmb_ops_combined_enc_##a (                                          \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_combined_enc (ops, key_data, n_ops, b, IMB_CIPHER_##c, f, g, i,             \
				     IMB_AUTH_HMAC_##d);                                           \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_combined_dec_##a (                                          \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_combined_dec (ops, key_data, n_ops, b, IMB_CIPHER_##c, f, g, i,             \
				     IMB_AUTH_HMAC_##d);                                           \
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
  u32 fixed;
  u32 aadlen;
} ipsecmb_ops_gcm_args_t;

static_always_inline u32
ipsecmb_ops_gcm (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
		 vnet_crypto_key_data_t *key_data[], u32 n_ops, ipsecmb_ops_gcm_args_t a)
{
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_failed = 0;

  for (i = 0; i < n_ops; i++)
    {
      struct gcm_key_data *kd;
      struct gcm_context_data ctx;
      vnet_crypto_op_t *op = ops[i];
      u8 scratch[64], *tag = a.is_dec ? scratch : op->tag;
      u32 taglen = 16, aadlen = a.aadlen;

      if (!a.fixed)
	{
	  aadlen = op->aad_len;
	  taglen = op->tag_len;
	}

      kd = (struct gcm_key_data *) key_data[i];
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

      if (a.is_dec && (memcmp (op->tag, tag, taglen)))
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
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_gcm (                                                                       \
      ops, 0, key_data, n_ops,                                                                     \
      (ipsecmb_ops_gcm_args_t){                                                                    \
	.enc_dec_fn = get_mgr (vlib_get_main ())->gcm##b##_enc, .fixed = (f), .aadlen = (l) });    \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_enc_##a##_chained (                              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    IMB_MGR *m = get_mgr (vlib_get_main ());                                                       \
    return ipsecmb_ops_gcm (ops, chunks, key_data, n_ops,                                          \
			    (ipsecmb_ops_gcm_args_t){ .init_fn = m->gcm##b##_init,                 \
						      .upd_fn = m->gcm##b##_enc_update,            \
						      .finalize_fn = m->gcm##b##_enc_finalize,     \
						      .chained = 1,                                \
						      .fixed = (f),                                \
						      .aadlen = (l) });                            \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a (                                        \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_gcm (                                                                       \
      ops, 0, key_data, n_ops,                                                                     \
      (ipsecmb_ops_gcm_args_t){ .enc_dec_fn = get_mgr (vlib_get_main ())->gcm##b##_dec,            \
				.fixed = (f),                                                      \
				.aadlen = (l),                                                     \
				.is_dec = 1 });                                                    \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a##_chained (                              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    IMB_MGR *m = get_mgr (vlib_get_main ());                                                       \
    return ipsecmb_ops_gcm (ops, chunks, key_data, n_ops,                                          \
			    (ipsecmb_ops_gcm_args_t){ .init_fn = m->gcm##b##_init,                 \
						      .upd_fn = m->gcm##b##_dec_update,            \
						      .finalize_fn = m->gcm##b##_dec_finalize,     \
						      .chained = 1,                                \
						      .fixed = (f),                                \
						      .aadlen = (l),                               \
						      .is_dec = 1 });                              \
  }
foreach_ipsecmb_gcm_cipher_op;
#undef _

#ifdef HAVE_IPSECMB_CHACHA_POLY
  always_inline void
  ipsecmb_retire_aead_job (IMB_JOB *job, u32 *n_fail)
{
  vnet_crypto_op_t *op = job->user_data;
  u32 len = op->tag_len;

  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
    {
      op->status = ipsecmb_status_job (job->status);
      *n_fail = *n_fail + 1;
      return;
    }

  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
    {
      if (memcmp (op->tag, job->auth_tag_output, len))
	{
	  *n_fail = *n_fail + 1;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  return;
	}
    }

  clib_memcpy_fast (op->tag, job->auth_tag_output, len);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_chacha_poly (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			 IMB_CIPHER_DIRECTION dir, u32 fixed, u32 aad_len)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  struct IMB_JOB *job;
  IMB_MGR *m;
  u32 i, n_fail = 0;
  u8 scratch[VLIB_FRAME_SIZE][16];
  u8 *key;

  if (ptd == 0)
    return 0;
  m = ptd->mgr;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      job = IMB_GET_NEXT_JOB (m);
      key = (u8 *) key_data[i];

      job->cipher_direction = dir;
      job->chain_order = IMB_ORDER_HASH_CIPHER;
      job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
      job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
      job->enc_keys = job->dec_keys = key;
      job->key_len_in_bytes = 32;

      job->u.CHACHA20_POLY1305.aad = op->aad;
      job->u.CHACHA20_POLY1305.aad_len_in_bytes =
	fixed ? aad_len : op->aad_len;
      job->src = op->src;
      job->dst = op->dst;

      job->iv = op->iv;
      job->iv_len_in_bytes = 12;
      job->msg_len_to_cipher_in_bytes = job->msg_len_to_hash_in_bytes =
	op->len;
      job->cipher_start_src_offset_in_bytes =
	job->hash_start_src_offset_in_bytes = 0;

      job->auth_tag_output = scratch[i];
      job->auth_tag_output_len_in_bytes = 16;

      job->user_data = op;

      job = IMB_SUBMIT_JOB_NOCHECK (ptd->mgr);
      if (job)
	ipsecmb_retire_aead_job (job, &n_fail);

      op++;
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    ipsecmb_retire_aead_job (job, &n_fail);

  return n_ops - n_fail;
}

static_always_inline u32
ipsecmb_ops_chacha_poly_enc (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)
{
  return ipsecmb_ops_chacha_poly (ops, key_data, n_ops, IMB_DIR_ENCRYPT, 0, 0);
}

static_always_inline u32
ipsecmb_ops_chacha_poly_dec (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)
{
  return ipsecmb_ops_chacha_poly (ops, key_data, n_ops, IMB_DIR_DECRYPT, 0, 0);
}

#define _(a)                                                                                       \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_enc (                            \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly (ops, key_data, n_ops, IMB_DIR_ENCRYPT, 1, a);                  \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_dec (                            \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly (ops, key_data, n_ops, IMB_DIR_DECRYPT, 1, a);                  \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _

  static_always_inline u32
  ipsecmb_ops_chacha_poly_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				   vnet_crypto_key_data_t *key_data[], u32 n_ops,
				   IMB_CIPHER_DIRECTION dir, u32 fixed, u32 aad_len)
{
  ipsecmb_per_thread_data_t *ptd = ipsecmb_get_per_thread_data ();
  IMB_MGR *m;
  u32 i, n_fail = 0;
  u8 *key;

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

	  key = (u8 *) key_data[i];

	  IMB_CHACHA20_POLY1305_INIT (m, key, &ctx, op->iv, op->aad,
				      fixed ? aad_len : op->aad_len);

	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      IMB_CHACHA20_POLY1305_ENC_UPDATE (m, key, &ctx, chp->dst,
						chp->src, chp->len);
	      chp += 1;
	    }

	  IMB_CHACHA20_POLY1305_ENC_FINALIZE (m, &ctx, op->tag,
					      fixed ? 16 : op->tag_len);

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

	  key = (u8 *) key_data[i];

	  IMB_CHACHA20_POLY1305_INIT (m, key, &ctx, op->iv, op->aad,
				      fixed ? aad_len : op->aad_len);

	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      IMB_CHACHA20_POLY1305_DEC_UPDATE (m, key, &ctx, chp->dst,
						chp->src, chp->len);
	      chp += 1;
	    }

	  IMB_CHACHA20_POLY1305_DEC_FINALIZE (m, &ctx, scratch,
					      fixed ? 16 : op->tag_len);

	  if (memcmp (op->tag, scratch, fixed ? 16 : op->tag_len))
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
				      vnet_crypto_key_data_t *key_data[], u32 n_ops)
{
  return ipsecmb_ops_chacha_poly_chained (ops, chunks, key_data, n_ops, IMB_DIR_ENCRYPT, 0, 0);
}

static_always_inline u32
ipsec_mb_ops_chacha_poly_dec_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				      vnet_crypto_key_data_t *key_data[], u32 n_ops)
{
  return ipsecmb_ops_chacha_poly_chained (ops, chunks, key_data, n_ops, IMB_DIR_DECRYPT, 0, 0);
}

#define _(a)                                                                                       \
  static_always_inline u32 ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained (                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly_chained (ops, chunks, key_data, n_ops, IMB_DIR_ENCRYPT, 1, a);  \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained (                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    return ipsecmb_ops_chacha_poly_chained (ops, chunks, key_data, n_ops, IMB_DIR_DECRYPT, 1, a);  \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

  static void
  crypto_ipsecmb_cipher_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  keyexp_t keyexp = 0;

  if (imbm->mgr == 0)
    return;

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC:
    case VNET_CRYPTO_ALG_AES_128_CTR:
      keyexp = imbm->mgr->keyexp_128;
      break;
    case VNET_CRYPTO_ALG_AES_192_CBC:
    case VNET_CRYPTO_ALG_AES_192_CTR:
      keyexp = imbm->mgr->keyexp_192;
      break;
    case VNET_CRYPTO_ALG_AES_256_CBC:
    case VNET_CRYPTO_ALG_AES_256_CTR:
      keyexp = imbm->mgr->keyexp_256;
      break;
    default:
      return;
    }

  keyexp (vnet_crypto_get_cypher_key (key), ((ipsecmb_aes_key_data_t *) key_data)->enc_key_exp,
	  ((ipsecmb_aes_key_data_t *) key_data)->dec_key_exp);
}

static void
crypto_ipsecmb_gcm_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  aes_gcm_pre_t pre = 0;

  if (imbm->mgr == 0)
    return;

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_GCM:
    case VNET_CRYPTO_ALG_AES_128_GCM_TAG16_AAD8:
    case VNET_CRYPTO_ALG_AES_128_GCM_TAG16_AAD12:
      pre = imbm->mgr->gcm128_pre;
      break;
    case VNET_CRYPTO_ALG_AES_192_GCM:
    case VNET_CRYPTO_ALG_AES_192_GCM_TAG16_AAD8:
    case VNET_CRYPTO_ALG_AES_192_GCM_TAG16_AAD12:
      pre = imbm->mgr->gcm192_pre;
      break;
    case VNET_CRYPTO_ALG_AES_256_GCM:
    case VNET_CRYPTO_ALG_AES_256_GCM_TAG16_AAD8:
    case VNET_CRYPTO_ALG_AES_256_GCM_TAG16_AAD12:
      pre = imbm->mgr->gcm256_pre;
      break;
    default:
      return;
    }

  pre (vnet_crypto_get_cypher_key (key), (struct gcm_key_data *) key_data);
}

static void
crypto_ipsecmb_hmac_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  hash_one_block_t hash_one_block = 0;
  hash_fn_t hash_fn = 0;
  u32 block_size = 0;
  u32 data_size = 0;
  u32 i;

  if (imbm->mgr == 0)
    return;

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_HMAC_SHA1:
      block_size = 64;
      data_size = 20 * 2;
      hash_one_block = imbm->mgr->sha1_one_block;
      hash_fn = imbm->mgr->sha1;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA224:
      block_size = 64;
      data_size = 32 * 2;
      hash_one_block = imbm->mgr->sha224_one_block;
      hash_fn = imbm->mgr->sha224;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA256:
      block_size = 64;
      data_size = 32 * 2;
      hash_one_block = imbm->mgr->sha256_one_block;
      hash_fn = imbm->mgr->sha256;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA384:
      block_size = 128;
      data_size = 64 * 2;
      hash_one_block = imbm->mgr->sha384_one_block;
      hash_fn = imbm->mgr->sha384;
      break;
    case VNET_CRYPTO_ALG_HMAC_SHA512:
      block_size = 128;
      data_size = 64 * 2;
      hash_one_block = imbm->mgr->sha512_one_block;
      hash_fn = imbm->mgr->sha512;
      break;
    default:
      return;
    }

  {
    const int block_qw = HMAC_MAX_BLOCK_SIZE / sizeof (u64);
    u64 pad[block_qw], key_hash[block_qw];

    clib_memset_u8 (key_hash, 0, HMAC_MAX_BLOCK_SIZE);
    if (key->cipher_key_sz + key->integ_key_sz <= block_size)
      clib_memcpy_fast (key_hash, vnet_crypto_get_cypher_key (key),
			key->cipher_key_sz + key->integ_key_sz);
    else
      hash_fn (vnet_crypto_get_cypher_key (key), key->cipher_key_sz + key->integ_key_sz, key_hash);

    for (i = 0; i < block_qw; i++)
      pad[i] = key_hash[i] ^ 0x3636363636363636;
    hash_one_block (pad, key_data);

    for (i = 0; i < block_qw; i++)
      pad[i] = key_hash[i] ^ 0x5c5c5c5c5c5c5c5c;
    hash_one_block (pad, ((u8 *) key_data) + (data_size / 2));
  }
}

static void
crypto_ipsecmb_chacha_poly_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  u32 sz = key->cipher_key_sz + key->integ_key_sz;

  if (sz > 32)
    sz = 32;
  clib_memcpy_fast (key_data, vnet_crypto_get_cypher_key (key), sz);
}

static void
crypto_ipsecmb_key_del (vnet_crypto_key_t *key __clib_unused,
			vnet_crypto_key_data_t *key_data __clib_unused)
{
}

static void
crypto_ipsecmb_combined_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  vnet_crypto_key_t k;

  k = *key;

  switch (key->alg)
    {
#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  case VNET_CRYPTO_ALG_##a##_TAG##i:                                                               \
    k.alg = VNET_CRYPTO_ALG_AES_##b##_##j;                                                         \
    break;
      foreach_ipsecmb_combined_cipher_op
#undef _
	default : return;
    }

  crypto_ipsecmb_cipher_key_add (&k, key_data);

  switch (key->alg)
    {
#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  case VNET_CRYPTO_ALG_##a##_TAG##i:                                                               \
    k.alg = VNET_CRYPTO_ALG_HMAC_##e;                                                              \
    break;
      foreach_ipsecmb_combined_cipher_op
#undef _
	default : return;
    }

  crypto_ipsecmb_hmac_key_add (
    &k, (vnet_crypto_key_data_t *) (((u8 *) key_data) + sizeof (ipsecmb_aes_key_data_t)));
}

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

VNET_CRYPTO_REG_OP_GROUP (ipsecmb_cipher_group) = {
  .max_key_data_sz = sizeof (ipsecmb_aes_key_data_t),
  .key_add_fn = crypto_ipsecmb_cipher_key_add,
  .key_del_fn = crypto_ipsecmb_key_del,
};

VNET_CRYPTO_REG_OP_GROUP (ipsecmb_gcm_group) = {
  .max_key_data_sz = sizeof (struct gcm_key_data),
  .key_add_fn = crypto_ipsecmb_gcm_key_add,
  .key_del_fn = crypto_ipsecmb_key_del,
};

VNET_CRYPTO_REG_OP_GROUP (ipsecmb_auth_group) = {
  .max_key_data_sz = 128,
  .key_add_fn = crypto_ipsecmb_hmac_key_add,
  .key_del_fn = crypto_ipsecmb_key_del,
};

VNET_CRYPTO_REG_OP_GROUP (ipsecmb_combined_group) = {
  .max_key_data_sz = sizeof (ipsecmb_combined_key_data_t),
  .key_add_fn = crypto_ipsecmb_combined_key_add,
  .key_del_fn = crypto_ipsecmb_key_del,
};

#ifdef HAVE_IPSECMB_CHACHA_POLY
VNET_CRYPTO_REG_OP_GROUP (ipsecmb_chacha_poly_group) = {
  .max_key_data_sz = 32,
  .key_add_fn = crypto_ipsecmb_chacha_poly_key_add,
  .key_del_fn = crypto_ipsecmb_key_del,
};
#endif

#define _(a, b, f, l)                                                                              \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_enc) = {                                                       \
    .group = &ipsecmb_gcm_group,                                                                   \
    .op_id = VNET_CRYPTO_OP_##a##_ENC,                                                             \
    .fn = ipsecmb_ops_gcm_cipher_enc_##a,                                                          \
    .cfn = ipsecmb_ops_gcm_cipher_enc_##a##_chained,                                               \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_dec) = {                                                       \
    .group = &ipsecmb_gcm_group,                                                                   \
    .op_id = VNET_CRYPTO_OP_##a##_DEC,                                                             \
    .fn = ipsecmb_ops_gcm_cipher_dec_##a,                                                          \
    .cfn = ipsecmb_ops_gcm_cipher_dec_##a##_chained,                                               \
  };
foreach_ipsecmb_gcm_cipher_op
#undef _

#define _(a, b, c, d, e, f)                                                                        \
  VNET_CRYPTO_REG_OP (ipsecmb_hmac_##a) = {                                                        \
    .group = &ipsecmb_auth_group,                                                                  \
    .op_id = VNET_CRYPTO_OP_##a##_HMAC,                                                            \
    .fn = ipsecmb_ops_hmac_##a,                                                                    \
  };
  foreach_ipsecmb_hmac_op
#undef _

#define _(a, b, c)                                                                                 \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_enc) = {                                                       \
    .group = &ipsecmb_cipher_group,                                                                \
    .op_id = VNET_CRYPTO_OP_##a##_ENC,                                                             \
    .fn = ipsecmb_ops_cipher_enc_##a,                                                              \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_dec) = {                                                       \
    .group = &ipsecmb_cipher_group,                                                                \
    .op_id = VNET_CRYPTO_OP_##a##_DEC,                                                             \
    .fn = ipsecmb_ops_cipher_dec_##a,                                                              \
  };
    foreach_ipsecmb_cipher_op
#undef _

#define _(a, b, c, j, d, e, f, g, h, i)                                                            \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_tag##i##_enc) = {                                              \
    .group = &ipsecmb_combined_group,                                                              \
    .op_id = VNET_CRYPTO_OP_##a##_TAG##i##_ENC,                                                    \
    .fn = ipsecmb_ops_combined_enc_##a,                                                            \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (ipsecmb_##a##_tag##i##_dec) = {                                              \
    .group = &ipsecmb_combined_group,                                                              \
    .op_id = VNET_CRYPTO_OP_##a##_TAG##i##_DEC,                                                    \
    .fn = ipsecmb_ops_combined_dec_##a,                                                            \
  };
      foreach_ipsecmb_combined_cipher_op
#undef _

#ifdef HAVE_IPSECMB_CHACHA_POLY
	VNET_CRYPTO_REG_OP (ipsecmb_chacha20_poly1305_enc) = {
	  .group = &ipsecmb_chacha_poly_group,
	  .op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC,
	  .fn = ipsecmb_ops_chacha_poly_enc,
	  .cfn = ipsec_mb_ops_chacha_poly_enc_chained,
	};

VNET_CRYPTO_REG_OP (ipsecmb_chacha20_poly1305_dec) = {
  .group = &ipsecmb_chacha_poly_group,
  .op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC,
  .fn = ipsecmb_ops_chacha_poly_dec,
  .cfn = ipsec_mb_ops_chacha_poly_dec_chained,
};

#define _(a)                                                                                       \
  VNET_CRYPTO_REG_OP (ipsecmb_chacha20_poly1305_tag16_aad##a##_enc) = {                            \
    .group = &ipsecmb_chacha_poly_group,                                                           \
    .op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD##a##_ENC,                                  \
    .fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_enc,                                              \
    .cfn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained,                                    \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (ipsecmb_chacha20_poly1305_tag16_aad##a##_dec) = {                            \
    .group = &ipsecmb_chacha_poly_group,                                                           \
    .op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD##a##_DEC,                                  \
    .fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_dec,                                              \
    .cfn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained,                                    \
  };
foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

VNET_CRYPTO_REG_ENGINE () = {
  .name = "ipsecmb",
  .desc = "Intel(R) Multi-Buffer Crypto for IPsec Library" IMB_VERSION_STR,
  .prio = 80,
  .init_fn = crypto_ipsecmb_init,
};
