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
#define EXPANDED_MAX_HMAC_KEY_N_BYTES (64 * 2)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  IMB_MGR *mgr;
#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
  IMB_JOB burst_jobs[IMB_MAX_BURST_SIZE];
#endif
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
} ipsecmb_aes_key_data_t;

typedef struct
{
  ipsecmb_aes_key_data_t aes_key_data;
  ipsecmb_per_thread_data_t *ctx;
} ipsecmb_aes_key_ctx_data_t;

typedef struct
{
  u8 hmac_key_data[EXPANDED_MAX_HMAC_KEY_N_BYTES];
  ipsecmb_per_thread_data_t *ctx;
} ipsecmb_hmac_key_ctx_data_t;

typedef struct
{
  struct gcm_key_data gcm_key;
  IMB_MGR *mgr;
} ipsecmb_aes_gcm_key_ctx_data_t;

#ifdef HAVE_IPSECMB_CHACHA_POLY
typedef struct
{
  IMB_MGR *mgr;
  void *chacha_key_data;
} ipsecmb_aes_chacha_key_ctx_data_t;
#endif

static ipsecmb_main_t ipsecmb_main = { };

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

#define foreach_ipsecmb_linked_cipher_op                                      \
  _ (AES_128_CBC_SHA1, 128, CBC, SHA_1, 64, 20, 20, 12)                       \
  _ (AES_192_CBC_SHA1, 192, CBC, SHA_1, 64, 20, 20, 12)                       \
  _ (AES_256_CBC_SHA1, 256, CBC, SHA_1, 64, 20, 20, 12)                       \
  _ (AES_128_CBC_SHA224, 128, CBC, SHA_224, 64, 32, 28, 14)                   \
  _ (AES_192_CBC_SHA224, 192, CBC, SHA_224, 64, 32, 28, 14)                   \
  _ (AES_256_CBC_SHA224, 256, CBC, SHA_224, 64, 32, 28, 14)                   \
  _ (AES_128_CBC_SHA256, 128, CBC, SHA_256, 64, 32, 32, 16)                   \
  _ (AES_192_CBC_SHA256, 192, CBC, SHA_256, 64, 32, 32, 16)                   \
  _ (AES_256_CBC_SHA256, 256, CBC, SHA_256, 64, 32, 32, 16)                   \
  _ (AES_128_CBC_SHA384, 128, CBC, SHA_384, 128, 64, 48, 24)                  \
  _ (AES_192_CBC_SHA384, 192, CBC, SHA_384, 128, 64, 48, 24)                  \
  _ (AES_256_CBC_SHA384, 256, CBC, SHA_384, 128, 64, 48, 24)                  \
  _ (AES_128_CBC_SHA512, 128, CBC, SHA_512, 128, 64, 64, 32)                  \
  _ (AES_192_CBC_SHA512, 192, CBC, SHA_512, 128, 64, 64, 32)                  \
  _ (AES_256_CBC_SHA512, 256, CBC, SHA_512, 128, 64, 64, 32)                  \
  _ (AES_128_CTR_SHA1, 128, CNTR, SHA_1, 64, 20, 20, 12)                      \
  _ (AES_192_CTR_SHA1, 192, CNTR, SHA_1, 64, 20, 20, 12)                      \
  _ (AES_256_CTR_SHA1, 256, CNTR, SHA_1, 64, 20, 20, 12)                      \
  _ (AES_128_CTR_SHA256, 128, CNTR, SHA_256, 64, 32, 32, 16)                  \
  _ (AES_192_CTR_SHA256, 192, CNTR, SHA_256, 64, 32, 32, 16)                  \
  _ (AES_256_CTR_SHA256, 256, CNTR, SHA_256, 64, 32, 32, 16)                  \
  _ (AES_128_CTR_SHA384, 128, CNTR, SHA_384, 128, 64, 48, 24)                 \
  _ (AES_192_CTR_SHA384, 192, CNTR, SHA_384, 128, 64, 48, 24)                 \
  _ (AES_256_CTR_SHA384, 256, CNTR, SHA_384, 128, 64, 48, 24)                 \
  _ (AES_128_CTR_SHA512, 128, CNTR, SHA_512, 128, 64, 64, 32)                 \
  _ (AES_192_CTR_SHA512, 192, CNTR, SHA_512, 128, 64, 64, 32)                 \
  _ (AES_256_CTR_SHA512, 256, CNTR, SHA_512, 128, 64, 64, 32)

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

#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
static_always_inline u32
ipsecmb_ops_hmac_inline (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
			 u32 block_size, u32 hash_size, u32 digest_size,
			 IMB_HASH_ALG alg)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  u8 scratch[n_ops][digest_size];
  const u32 burst_sz =
    (n_ops > IMB_MAX_BURST_SIZE) ? IMB_MAX_BURST_SIZE : n_ops;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;
      /*
       * configure all the jobs first ...
       */
      for (i = 0; i < n; i++, ops_index++)
	{
	  vnet_crypto_op_t *op = ops[ops_index];
	  const u8 *kd = (u8 *) imbm->key_data[op->key_index];

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
#else
static_always_inline u32
ipsecmb_ops_hmac_inline (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
			 u32 block_size, u32 hash_size, u32 digest_size,
			 JOB_HASH_ALG alg)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
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

      job->src = op->integ_src;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->integ_len;
      job->hash_alg = alg;
      job->auth_tag_output_len_in_bytes = digest_size;
      job->auth_tag_output = scratch[i];

      job->cipher_mode = IMB_CIPHER_NULL;
      job->cipher_direction = IMB_DIR_DECRYPT;
      job->chain_order = IMB_ORDER_HASH_CIPHER;

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
#endif

#define _(a, b, c, d, e, f)                                             \
static_always_inline u32                                                \
ipsecmb_ops_hmac_##a (vlib_main_t * vm,                                 \
                      vnet_crypto_op_t * ops[],                         \
                      u32 n_ops)                                        \
{ return ipsecmb_ops_hmac_inline (vm, ops, n_ops, d, e, f,              \
		IMB_AUTH_HMAC_##b); }                                   \

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

#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
static_always_inline u32
ipsecmb_ops_aes_cipher_inline (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			       u32 n_ops, u32 key_len,
			       IMB_CIPHER_DIRECTION direction,
			       IMB_CIPHER_MODE cipher_mode)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  const u32 burst_sz =
    (n_ops > IMB_MAX_BURST_SIZE) ? IMB_MAX_BURST_SIZE : n_ops;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;

      for (i = 0; i < n; i++)
	{
	  ipsecmb_aes_key_data_t *kd;
	  vnet_crypto_op_t *op = ops[ops_index++];
	  kd = (ipsecmb_aes_key_data_t *) imbm->key_data[op->key_index];

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
#else
static_always_inline u32
ipsecmb_ops_aes_cipher_inline (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			       u32 n_ops, u32 key_len,
			       JOB_CIPHER_DIRECTION direction,
			       JOB_CIPHER_MODE cipher_mode)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0;

  for (i = 0; i < n_ops; i++)
    {
      ipsecmb_aes_key_data_t *kd;
      vnet_crypto_op_t *op = ops[i];
      kd = (ipsecmb_aes_key_data_t *) imbm->key_data[op->key_index];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = IMB_AUTH_NULL;
      job->cipher_mode = cipher_mode;
      job->cipher_direction = direction;
      job->chain_order =
	(direction == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH :
					      IMB_ORDER_HASH_CIPHER);

      job->aes_key_len_in_bytes = key_len / 8;
      job->enc_keys = kd->enc_key_exp;
      job->dec_keys = kd->dec_key_exp;
      job->iv = op->iv;
      job->iv_len_in_bytes = IMB_AES_BLOCK_SIZE;

      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_retire_cipher_job (job, &n_fail);
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    ipsecmb_retire_cipher_job (job, &n_fail);

  return n_ops - n_fail;
}
#endif

#define _(a, b, c)                                                            \
  static_always_inline u32 ipsecmb_ops_cipher_enc_##a (                       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_aes_cipher_inline (                                    \
                    vm, ops, n_ops, b, IMB_DIR_ENCRYPT, IMB_CIPHER_##c);      \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_cipher_dec_##a (                       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_aes_cipher_inline (                                    \
                   vm, ops, n_ops, b, IMB_DIR_DECRYPT, IMB_CIPHER_##c);       \
  }

foreach_ipsecmb_cipher_op;
#undef _

#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
static_always_inline u32
ipsecmb_ops_aes_enc_cipher_hmac_inline (
  vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
  IMB_CIPHER_DIRECTION direction, IMB_CIPHER_MODE cipher_mode,
  IMB_HASH_ALG alg, u32 block_size, u32 hash_size, u32 digest_size)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  u8 scratch[n_ops][digest_size];
  /* We reserve only half of IMB_MAX_BURST_SIZE here because the fused
   * linked cipher+HMAC path will enqueue two IMB jobs per crypto op
   * (first the cipher job, then the HMAC job). Dividing by 2 ensures we
   * never exceed the size of ptd->burst_jobs[] when processing a full
   * burst of linked operations. (If only single-operation jobs are used,
   * this still remains safe.) */
  const u32 burst_max_sz = IMB_MAX_BURST_SIZE / 2;
  const u32 burst_sz = (n_ops > burst_max_sz) ? burst_max_sz : n_ops;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;

      for (i = 0; i < n; i++, ops_index++)
	{
	  vnet_crypto_op_t *op = ops[ops_index];
	  vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
	  ipsecmb_aes_key_data_t *kd =
	    (ipsecmb_aes_key_data_t *) imbm->key_data[key->index_crypto];

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

	  const u8 *hkd = (u8 *) imbm->key_data[key->index_integ];

	  job = &ptd->burst_jobs[n + i];

	  job->src = op->integ_src;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_hash_in_bytes = op->integ_len;
	  job->auth_tag_output_len_in_bytes = digest_size;
	  job->auth_tag_output = scratch[ops_index];

	  job->u.HMAC._hashed_auth_key_xor_ipad = hkd;
	  job->u.HMAC._hashed_auth_key_xor_opad = hkd + hash_size;
	  job->user_data = op;
	}

      IMB_SUBMIT_CIPHER_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs, n,
				       cipher_mode, direction, key_len / 8);
      IMB_SUBMIT_HASH_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs + n, n, alg);
      for (i = 0; i < n; i++)
	{
	  job = &ptd->burst_jobs[i];
	  vnet_crypto_op_t *op = job->user_data;
	  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	    {
	      op->status = ipsecmb_status_job (job->status);
	      n_fail++;
	      continue;
	    }
	  job = &ptd->burst_jobs[n + i];

	  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	    {
	      op->status = ipsecmb_status_job (job->status);
	      n_fail++;
	      continue;
	    }

	  clib_memcpy_fast (op->digest, job->auth_tag_output, op->digest_len);

	  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	}

      n_ops -= n;
    }

  return ops_index - n_fail;
}

static_always_inline u32
ipsecmb_ops_aes_dec_cipher_hmac_inline (
  vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
  IMB_CIPHER_DIRECTION direction, IMB_CIPHER_MODE cipher_mode,
  IMB_HASH_ALG alg, u32 block_size, u32 hash_size, u32 digest_size)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0, ops_index = 0;
  u8 scratch[n_ops][digest_size];
  /* We reserve only half of IMB_MAX_BURST_SIZE here because the fused
   * linked cipher+HMAC path will enqueue two IMB jobs per crypto op
   * (first the cipher job, then the HMAC job). Dividing by 2 ensures we
   * never exceed the size of ptd->burst_jobs[] when processing a full
   * burst of linked operations. (If only single-operation jobs are used,
   * this still remains safe.) */
  const u32 burst_max_sz = IMB_MAX_BURST_SIZE / 2;
  const u32 burst_sz = (n_ops > burst_max_sz) ? burst_max_sz : n_ops;

  while (n_ops)
    {
      const u32 n = (n_ops > burst_sz) ? burst_sz : n_ops;

      for (i = 0; i < n; i++, ops_index++)
	{
	  vnet_crypto_op_t *op = ops[ops_index];
	  vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
	  const u8 *hkd = (u8 *) imbm->key_data[key->index_integ];

	  job = &ptd->burst_jobs[i];

	  job->src = op->integ_src;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_hash_in_bytes = op->integ_len;
	  job->auth_tag_output_len_in_bytes = digest_size;
	  job->auth_tag_output = scratch[ops_index];

	  job->u.HMAC._hashed_auth_key_xor_ipad = hkd;
	  job->u.HMAC._hashed_auth_key_xor_opad = hkd + hash_size;
	  job->user_data = op;

	  ipsecmb_aes_key_data_t *kd =
	    (ipsecmb_aes_key_data_t *) imbm->key_data[key->index_crypto];

	  job = &ptd->burst_jobs[n + i];

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
      IMB_SUBMIT_HASH_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs, n, alg);
      IMB_SUBMIT_CIPHER_BURST_NOCHECK (ptd->mgr, ptd->burst_jobs + n, n,
				       cipher_mode, direction, key_len / 8);
      for (i = 0; i < n; i++)
	{
	  job = &ptd->burst_jobs[i];
	  vnet_crypto_op_t *op = job->user_data;

	  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	    {
	      op->status = ipsecmb_status_job (job->status);
	      n_fail++;
	      continue;
	    }

	  if (memcmp (op->digest, job->auth_tag_output, op->digest_len))
	    {
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      n_fail++;
	      continue;
	    }

	  job = &ptd->burst_jobs[n + i];
	  if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	    {
	      op->status = ipsecmb_status_job (job->status);
	      n_fail++;
	      continue;
	    }

	  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	}

      n_ops -= n;
    }

  return ops_index - n_fail;
}
#else
static_always_inline u32
ipsecmb_ops_aes_enc_cipher_hmac_inline (
  vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
  IMB_CIPHER_DIRECTION direction, JOB_CIPHER_MODE cipher_mode,
  JOB_HASH_ALG alg, u32 block_size, u32 hash_size, u32 digest_size)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][digest_size];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      ipsecmb_aes_key_data_t *kd =
	(ipsecmb_aes_key_data_t *) imbm->key_data[key->index_crypto];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = IMB_AUTH_NULL;
      job->cipher_mode = cipher_mode;
      job->cipher_direction = direction;
      job->chain_order =
	(direction == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH :
					IMB_ORDER_HASH_CIPHER);

      job->aes_key_len_in_bytes = key_len / 8;
      job->enc_keys = kd->enc_key_exp;
      job->dec_keys = kd->dec_key_exp;
      job->iv = op->iv;
      job->iv_len_in_bytes = IMB_AES_BLOCK_SIZE;

      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job && PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}

      u8 *hkd = (u8 *) imbm->key_data[key->index_integ];
      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->integ_src;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->integ_len;
      job->hash_alg = alg;
      job->auth_tag_output_len_in_bytes = digest_size;
      job->auth_tag_output = scratch[i];

      job->cipher_mode = IMB_CIPHER_NULL;
      job->cipher_direction = IMB_DIR_DECRYPT;
      job->chain_order = IMB_ORDER_HASH_CIPHER;

      job->u.HMAC._hashed_auth_key_xor_ipad = hkd;
      job->u.HMAC._hashed_auth_key_xor_opad = hkd + hash_size;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job && PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}

      clib_memcpy_fast (op->digest, job->auth_tag_output, op->digest_len);

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      vnet_crypto_op_t *op = job->user_data;

      if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}
      else if (job->hash_alg != IMB_AUTH_NULL)
	{
	  clib_memcpy_fast (op->digest, job->auth_tag_output, op->digest_len);
	}
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops - n_fail;
}

static_always_inline u32
ipsecmb_ops_aes_dec_cipher_hmac_inline (
  vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops, u32 key_len,
  IMB_CIPHER_DIRECTION direction, JOB_CIPHER_MODE cipher_mode,
  JOB_HASH_ALG alg, u32 block_size, u32 hash_size, u32 digest_size)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_JOB *job;
  u32 i, n_fail = 0;
  u8 scratch[n_ops][digest_size];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);

      u8 *hkd = (u8 *) imbm->key_data[key->index_integ];
      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->integ_src;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->integ_len;
      job->hash_alg = alg;
      job->auth_tag_output_len_in_bytes = digest_size;
      job->auth_tag_output = scratch[i];

      job->cipher_mode = IMB_CIPHER_NULL;
      job->cipher_direction = IMB_DIR_DECRYPT;
      job->chain_order = IMB_ORDER_HASH_CIPHER;

      job->u.HMAC._hashed_auth_key_xor_ipad = hkd;
      job->u.HMAC._hashed_auth_key_xor_opad = hkd + hash_size;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job && PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}

      if (memcmp (op->digest, job->auth_tag_output, op->digest_len))
	{
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  n_fail++;
	  continue;
	}

      ipsecmb_aes_key_data_t *kd =
	(ipsecmb_aes_key_data_t *) imbm->key_data[key->index_crypto];

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->msg_len_to_cipher_in_bytes = op->len;
      job->cipher_start_src_offset_in_bytes = 0;

      job->hash_alg = IMB_AUTH_NULL;
      job->cipher_mode = cipher_mode;
      job->cipher_direction = direction;
      job->chain_order =
	(direction == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH :
					IMB_ORDER_HASH_CIPHER);

      job->aes_key_len_in_bytes = key_len / 8;
      job->enc_keys = kd->enc_key_exp;
      job->dec_keys = kd->dec_key_exp;
      job->iv = op->iv;
      job->iv_len_in_bytes = IMB_AES_BLOCK_SIZE;

      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job && PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      vnet_crypto_op_t *op = job->user_data;

      if (PREDICT_FALSE (IMB_STATUS_COMPLETED != job->status))
	{
	  op->status = ipsecmb_status_job (job->status);
	  n_fail++;
	  continue;
	}
      else if (job->hash_alg != IMB_AUTH_NULL)
	{
	  if (memcmp (op->digest, job->auth_tag_output, op->digest_len))
	    {
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      n_fail++;
	      continue;
	    }
	}
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops - n_fail;
}
#endif

#define _(a, b, c, d, e, f, g, h)                                             \
  static_always_inline u32 ipsecmb_ops_enc_##a (                              \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_aes_enc_cipher_hmac_inline (                           \
      vm, ops, n_ops, b, IMB_DIR_ENCRYPT, IMB_CIPHER_##c, IMB_AUTH_HMAC_##d,  \
      e, f, g);                                                               \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_dec_##a (                              \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_aes_dec_cipher_hmac_inline (                           \
      vm, ops, n_ops, b, IMB_DIR_DECRYPT, IMB_CIPHER_##c, IMB_AUTH_HMAC_##d,  \
      e, f, g);                                                               \
  }
foreach_ipsecmb_linked_cipher_op
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
		 u32 n_ops, ipsecmb_ops_gcm_args_t a)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
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

      kd = (struct gcm_key_data *) imbm->key_data[op->key_index];
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
get_mgr (vlib_main_t *vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  return ptd->mgr;
}

#define _(a, b, f, l)                                                         \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_enc_##a (                   \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_gcm (                                                  \
      ops, 0, n_ops,                                                          \
      (ipsecmb_ops_gcm_args_t){ .enc_dec_fn = get_mgr (vm)->gcm##b##_enc,     \
				.fixed = (f),                                 \
				.aadlen = (l) });                             \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_enc_##a##_chained (         \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    IMB_MGR *m = get_mgr (vm);                                                \
    return ipsecmb_ops_gcm (                                                  \
      ops, chunks, n_ops,                                                     \
      (ipsecmb_ops_gcm_args_t){ .init_fn = m->gcm##b##_init,                  \
				.upd_fn = m->gcm##b##_enc_update,             \
				.finalize_fn = m->gcm##b##_enc_finalize,      \
				.chained = 1,                                 \
				.fixed = (f),                                 \
				.aadlen = (l) });                             \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a (                   \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_gcm (                                                  \
      ops, 0, n_ops,                                                          \
      (ipsecmb_ops_gcm_args_t){ .enc_dec_fn = get_mgr (vm)->gcm##b##_dec,     \
				.fixed = (f),                                 \
				.aadlen = (l),                                \
				.is_dec = 1 });                               \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_gcm_cipher_dec_##a##_chained (         \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    IMB_MGR *m = get_mgr (vm);                                                \
    return ipsecmb_ops_gcm (                                                  \
      ops, chunks, n_ops,                                                     \
      (ipsecmb_ops_gcm_args_t){ .init_fn = m->gcm##b##_init,                  \
				.upd_fn = m->gcm##b##_dec_update,             \
				.finalize_fn = m->gcm##b##_dec_finalize,      \
				.chained = 1,                                 \
				.fixed = (f),                                 \
				.aadlen = (l),                                \
				.is_dec = 1 });                               \
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
ipsecmb_ops_chacha_poly (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
			 IMB_CIPHER_DIRECTION dir, u32 fixed, u32 aad_len)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  struct IMB_JOB *job;
  IMB_MGR *m = ptd->mgr;
  u32 i, n_fail = 0, last_key_index = ~0;
  u8 scratch[VLIB_FRAME_SIZE][16];
  u8 *key = 0;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      job = IMB_GET_NEXT_JOB (m);
      if (last_key_index != op->key_index)
	{
	  vnet_crypto_key_t *kd = vnet_crypto_get_key (op->key_index);

	  key = kd->data;
	  last_key_index = op->key_index;
	}

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
ipsecmb_ops_chacha_poly_enc (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			     u32 n_ops)
{
  return ipsecmb_ops_chacha_poly (vm, ops, n_ops, IMB_DIR_ENCRYPT, 0, 0);
}

static_always_inline u32
ipsecmb_ops_chacha_poly_dec (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			     u32 n_ops)
{
  return ipsecmb_ops_chacha_poly (vm, ops, n_ops, IMB_DIR_DECRYPT, 0, 0);
}

#define _(a)                                                                  \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_enc (       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_chacha_poly (vm, ops, n_ops, IMB_DIR_ENCRYPT, 1, a);   \
  }                                                                           \
                                                                              \
  static_always_inline u32 ipsecmb_ops_chacha_poly_tag16_aad##a##_dec (       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return ipsecmb_ops_chacha_poly (vm, ops, n_ops, IMB_DIR_DECRYPT, 1, a);   \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _

  static_always_inline u32
  ipsecmb_ops_chacha_poly_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				   vnet_crypto_op_chunk_t *chunks, u32 n_ops,
				   IMB_CIPHER_DIRECTION dir, u32 fixed,
				   u32 aad_len)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd = imbm->per_thread_data + vm->thread_index;
  IMB_MGR *m = ptd->mgr;
  u32 i, n_fail = 0, last_key_index = ~0;
  u8 *key = 0;

  if (dir == IMB_DIR_ENCRYPT)
    {
      for (i = 0; i < n_ops; i++)
	{
	  vnet_crypto_op_t *op = ops[i];
	  struct chacha20_poly1305_context_data ctx;
	  vnet_crypto_op_chunk_t *chp;
	  u32 j;

	  ASSERT (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS);

	  if (last_key_index != op->key_index)
	    {
	      vnet_crypto_key_t *kd = vnet_crypto_get_key (op->key_index);

	      key = kd->data;
	      last_key_index = op->key_index;
	    }

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

	  if (last_key_index != op->key_index)
	    {
	      vnet_crypto_key_t *kd = vnet_crypto_get_key (op->key_index);

	      key = kd->data;
	      last_key_index = op->key_index;
	    }

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
ipsec_mb_ops_chacha_poly_enc_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				      vnet_crypto_op_chunk_t *chunks,
				      u32 n_ops)
{
  return ipsecmb_ops_chacha_poly_chained (vm, ops, chunks, n_ops,
					  IMB_DIR_ENCRYPT, 0, 0);
}

static_always_inline u32
ipsec_mb_ops_chacha_poly_dec_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				      vnet_crypto_op_chunk_t *chunks,
				      u32 n_ops)
{
  return ipsecmb_ops_chacha_poly_chained (vm, ops, chunks, n_ops,
					  IMB_DIR_DECRYPT, 0, 0);
}

#define _(a)                                                                  \
  static_always_inline u32                                                    \
    ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained (                     \
      vlib_main_t *vm, vnet_crypto_op_t *ops[],                               \
      vnet_crypto_op_chunk_t *chunks, u32 n_ops)                              \
  {                                                                           \
    return ipsecmb_ops_chacha_poly_chained (vm, ops, chunks, n_ops,           \
					    IMB_DIR_ENCRYPT, 1, a);           \
  }                                                                           \
                                                                              \
  static_always_inline u32                                                    \
    ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained (                     \
      vlib_main_t *vm, vnet_crypto_op_t *ops[],                               \
      vnet_crypto_op_chunk_t *chunks, u32 n_ops)                              \
  {                                                                           \
    return ipsecmb_ops_chacha_poly_chained (vm, ops, chunks, n_ops,           \
					    IMB_DIR_DECRYPT, 1, a);           \
  }
foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

  static void
  crypto_ipsecmb_key_handler (vnet_crypto_key_op_t kop,
			      vnet_crypto_key_index_t idx)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  ipsecmb_alg_data_t *ad = imbm->alg_data + key->alg;
  u32 i;
  void *kd;

  /** TODO: add linked alg support **/
  if (key->is_link)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (imbm->key_data))
	return;

      if (imbm->key_data[idx] == 0)
	return;

      clib_mem_free_s (imbm->key_data[idx]);
      imbm->key_data[idx] = 0;
      return;
    }

  if (ad->data_size == 0)
    return;

  vec_validate_aligned (imbm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && imbm->key_data[idx])
    {
      clib_mem_free_s (imbm->key_data[idx]);
    }

  kd = imbm->key_data[idx] = clib_mem_alloc_aligned (ad->data_size,
						     CLIB_CACHE_LINE_BYTES);

  /* AES CBC key expansion */
  if (ad->keyexp)
    {
      ad->keyexp (key->data, ((ipsecmb_aes_key_data_t *) kd)->enc_key_exp,
		  ((ipsecmb_aes_key_data_t *) kd)->dec_key_exp);
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
      if (key->length <= ad->block_size)
	clib_memcpy_fast (key_hash, key->data, key->length);
      else
	ad->hash_fn (key->data, key->length, key_hash);

      for (i = 0; i < block_qw; i++)
	pad[i] = key_hash[i] ^ 0x3636363636363636;
      ad->hash_one_block (pad, kd);

      for (i = 0; i < block_qw; i++)
	pad[i] = key_hash[i] ^ 0x5c5c5c5c5c5c5c5c;
      ad->hash_one_block (pad, ((u8 *) kd) + (ad->data_size / 2));

      return;
    }
}

static char *
crypto_ipsecmb_init (vnet_crypto_engine_registration_t *r)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_alg_data_t *ad;
  u16 *kd;
  ipsecmb_per_thread_data_t *ptd;
  IMB_MGR *m = 0;
  IMB_ARCH arch;
  char *err = 0;
  u32 i;

  if (!clib_cpu_supports_aes ())
    return "AES ISA not available on this CPU";

  if (IMB_VERSION_NUM != imb_get_version ())
    return "incompatible IPsec Multi-Buffer Crypto library version";

  imbm->per_thread_data = r->per_thread_data;

  for (i = 0; i < r->num_threads; i++)
    {
      ptd = imbm->per_thread_data + i;
      ptd->mgr = alloc_mb_mgr (0);
      if (!ptd->mgr)
	{
	  err = "alloc_mb_mgr() failed";
	  goto err;
	}

#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
      clib_memset_u8 (ptd->burst_jobs, 0, sizeof (IMB_JOB) * IMB_MAX_BURST_SIZE);
#endif

      init_mb_mgr_auto (ptd->mgr, &arch);

      if (imb_get_errno (ptd->mgr) != 0)
	{
	  err = "init_mb_mgr_auto() failed";
	  goto err;
	}

#if IMB_VERSION_NUM >= IMB_VERSION(1, 3, 0)
      if (!ptd->mgr->submit_hash_burst_nocheck)
	{
	  err = "intel-ipsec-mb burst API not available";
	  goto err;
	}
#endif

      if (ptd == imbm->per_thread_data)
	m = ptd->mgr;
    }

#define _(a, b, c, d, e, f)                                                                        \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_HMAC_##a;                                                  \
  ad->block_size = d;                                                                              \
  ad->data_size = e * 2;                                                                           \
  ad->hash_one_block = m->c##_one_block;                                                           \
  ad->hash_fn = m->c;                                                                              \
  kd = r->key_data_sz + VNET_CRYPTO_ALG_HMAC_##a;                                                  \
  *kd = sizeof (ipsecmb_hmac_key_ctx_data_t);

  foreach_ipsecmb_hmac_op;
#undef _
#define _(a, b, c)                                                                                 \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_##a;                                                       \
  ad->data_size = sizeof (ipsecmb_aes_key_data_t);                                                 \
  ad->keyexp = m->keyexp_##b;                                                                      \
  kd = r->key_data_sz + VNET_CRYPTO_ALG_##a;                                                       \
  *kd = sizeof (ipsecmb_aes_key_ctx_data_t);

  foreach_ipsecmb_cipher_op;
#undef _
#define _(a, b, f, l)                                                                              \
  ad = imbm->alg_data + VNET_CRYPTO_ALG_##a;                                                       \
  ad->data_size = sizeof (struct gcm_key_data);                                                    \
  ad->aes_gcm_pre = m->gcm##b##_pre;                                                               \
  kd = r->key_data_sz + VNET_CRYPTO_ALG_##a;                                                       \
  *kd = sizeof (ipsecmb_aes_gcm_key_ctx_data_t);

  foreach_ipsecmb_gcm_cipher_op;
#undef _

#ifdef HAVE_IPSECMB_CHACHA_POLY
  ad = imbm->alg_data + VNET_CRYPTO_ALG_CHACHA20_POLY1305;
  ad->data_size = 0;
  kd = r->key_data_sz + VNET_CRYPTO_ALG_CHACHA20_POLY1305;
  *kd = sizeof (ipsecmb_aes_chacha_key_ctx_data_t);
#endif

  return 0;

err:
  do
    {
      ptd = imbm->per_thread_data + i;
      if (ptd->mgr)
	free_mb_mgr (ptd->mgr);
    }
  while (i--);
  return err;
}

vnet_crypto_engine_op_handlers_t op_handlers[] = {
#define _(a, b, f, l)                                                         \
  {                                                                           \
    .opt = VNET_CRYPTO_OP_##a##_ENC,                                          \
    .fn = ipsecmb_ops_gcm_cipher_enc_##a,                                     \
    .cfn = ipsecmb_ops_gcm_cipher_enc_##a##_chained,                          \
  },                                                                          \
    {                                                                         \
      .opt = VNET_CRYPTO_OP_##a##_DEC,                                        \
      .fn = ipsecmb_ops_gcm_cipher_dec_##a,                                   \
      .cfn = ipsecmb_ops_gcm_cipher_dec_##a##_chained,                        \
    },
  foreach_ipsecmb_gcm_cipher_op
#undef _
#define _(a, b, c, d, e, f)                                                   \
  { .opt = VNET_CRYPTO_OP_##a##_HMAC, .fn = ipsecmb_ops_hmac_##a },

    foreach_ipsecmb_hmac_op
#undef _
#define _(a, b, c)                                                            \
  { .opt = VNET_CRYPTO_OP_##a##_ENC, .fn = ipsecmb_ops_cipher_enc_##a },      \
    { .opt = VNET_CRYPTO_OP_##a##_DEC, .fn = ipsecmb_ops_cipher_dec_##a },

      foreach_ipsecmb_cipher_op
#undef _
#define _(a, b, c, d, e, f, g, h)                                             \
  { .opt = VNET_CRYPTO_OP_##a##_TAG##h##_ENC, .fn = ipsecmb_ops_enc_##a },    \
    { .opt = VNET_CRYPTO_OP_##a##_TAG##h##_DEC, .fn = ipsecmb_ops_dec_##a },

	foreach_ipsecmb_linked_cipher_op
#undef _
#ifdef HAVE_IPSECMB_CHACHA_POLY
  { .opt = VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC,
    .fn = ipsecmb_ops_chacha_poly_enc,
    .cfn = ipsec_mb_ops_chacha_poly_enc_chained },
  { .opt = VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC,
    .fn = ipsecmb_ops_chacha_poly_dec,
    .cfn = ipsec_mb_ops_chacha_poly_dec_chained },
#define _(a)                                                                  \
  {                                                                           \
    .opt = VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD##a##_ENC,               \
    .fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_enc,                         \
    .cfn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_enc_chained,               \
  },                                                                          \
    {                                                                         \
      .opt = VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD##a##_DEC,             \
      .fn = ipsecmb_ops_chacha_poly_tag16_aad##a##_dec,                       \
      .cfn = ipsec_mb_ops_chacha_poly_tag16_aad##a##_dec_chained,             \
    },
  foreach_chacha_poly_fixed_aad_lengths
#undef _
#endif

  {}
};

VNET_CRYPTO_ENGINE_REGISTRATION () = {
  .name = "ipsecmb",
  .desc = "Intel(R) Multi-Buffer Crypto for IPsec Library" IMB_VERSION_STR,
  .prio = 80,
  .per_thread_data_sz = sizeof (ipsecmb_per_thread_data_t),
  .init_fn = crypto_ipsecmb_init,
  .key_handler = crypto_ipsecmb_key_handler,
  .op_handlers = op_handlers,
};
