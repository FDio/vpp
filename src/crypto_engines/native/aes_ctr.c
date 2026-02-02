/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>
#include <vppinfra/crypto/aes_ctr.h>
#include <vppinfra/crypto/sha2.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

typedef struct aes_ctr_sha2_hmac_key_data
{
  clib_sha2_hmac_key_data_t hmac_key_data;
  aes_ctr_key_data_t ctr_key_data;
} aes_ctr_sha2_hmac_key_data_t;

static_always_inline u32
aes_ops_enc_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];
  aes_ctr_sha2_hmac_key_data_t *ctr_hmac_key_data;

next:
  {
    ctr_hmac_key_data = (aes_ctr_sha2_hmac_key_data_t *) op->key_data;
    clib_aes_ctr_init (&ctx, &ctr_hmac_key_data->ctr_key_data, op->iv, ks);
    clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &ctr_hmac_key_data->hmac_key_data);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, op->digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], u32 n_ops,
				  vnet_crypto_op_chunk_t *chunks, aes_key_size_t ks,
				  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];
  aes_ctr_sha2_hmac_key_data_t *ctr_hmac_key_data;

next:
  {
    ctr_hmac_key_data = (aes_ctr_sha2_hmac_key_data_t *) op->key_data;

    clib_aes_ctr_init (&ctx, &ctr_hmac_key_data->ctr_key_data, op->iv, ks);

    vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
    for (int j = 0; j < op->n_chunks; j++, chp++)
      clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &ctr_hmac_key_data->hmac_key_data);

    chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, op->digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];
  aes_ctr_sha2_hmac_key_data_t *ctr_hmac_key_data;
next:
  {
    ctr_hmac_key_data = (aes_ctr_sha2_hmac_key_data_t *) op->key_data;

    clib_sha2_hmac_init (&h_ctx, type, &ctr_hmac_key_data->hmac_key_data);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, op->digest_len)))
      {
	n_fail++;
	op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    else
      {
	clib_aes_ctr_init (&ctx, &ctr_hmac_key_data->ctr_key_data, op->iv, ks);
	clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      }
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], u32 n_ops,
				  vnet_crypto_op_chunk_t *chunks, aes_key_size_t ks,
				  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];
  aes_ctr_sha2_hmac_key_data_t *ctr_hmac_key_data;

next:
  {
    ctr_hmac_key_data = (aes_ctr_sha2_hmac_key_data_t *) op->key_data;

    clib_sha2_hmac_init (&h_ctx, type, &ctr_hmac_key_data->hmac_key_data);
    vnet_crypto_op_chunk_t *chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, op->digest_len)))
      {
	n_fail++;
	op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    else
      {
	clib_aes_ctr_init (&ctx, &ctr_hmac_key_data->ctr_key_data, op->iv, ks);

	vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
	for (int j = 0; j < op->n_chunks; j++, chp++)
	  clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      }
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_aes_ctr (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
		 aes_key_size_t ks, int maybe_chained)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  u32 n_left = n_ops;
  aes_ctr_key_data_t *key_data;

next:
  key_data = (aes_ctr_key_data_t *) op->key_data;

  clib_aes_ctr_init (&ctx, key_data, op->iv, ks);
  if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
      for (int j = 0; j < op->n_chunks; j++, chp++)
	clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);
    }
  else
    clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void
aes_ctr_key_exp (vnet_crypto_key_op_t kop, aes_ctr_key_data_t *key_data, const u8 *data,
		 aes_key_size_t ks)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_ctr_key_expand (key_data, data, ks);
    }
}

static_always_inline void
aes_ctr_hmac_key_exp (vnet_crypto_key_op_t kop, aes_ctr_sha2_hmac_key_data_t *key_data,
		      const u8 *data, u16 hmac_length, u16 ctr_length, aes_key_size_t ks,
		      clib_sha2_type_t type)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_ctr_key_expand (&key_data->ctr_key_data, data, ks);
      clib_sha2_hmac_key_data (type, data + ctr_length, hmac_length, &key_data->hmac_key_data);
    }
}

static int
probe ()
{
#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vaes () && clib_cpu_supports_avx512f ())
    return 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vaes ())
    return 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_avx512f ())
    return 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_avx2 ())
    return 20;
#elif __AES__
  if (clib_cpu_supports_aes ())
    return 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    return 10;
#endif
  return -1;
}

static int
aes_ctr_sha2_probe ()
{
  int r_ctr = -1, r_sha2 = -1;

#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vaes () && clib_cpu_supports_avx512f ())
    r_ctr = 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vaes ())
    r_ctr = 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_avx512f ())
    r_ctr = 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_avx2 ())
    r_ctr = 20;
#elif __AES__
  if (clib_cpu_supports_aes ())
    r_ctr = 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    r_ctr = 10;
#endif

#if defined(__x86_64__)
#if defined(__SHA__) && defined(__AVX512F__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx512f ())
    r_sha2 = 30;
#elif defined(__SHA__) && defined(__AVX2__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx2 ())
    r_sha2 = 20;
#elif defined(__SHA__)
  if (clib_cpu_supports_sha ())
    r_sha2 = 10;
#endif

#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA2)
  if (clib_cpu_supports_sha2 ())
    r_sha2 = 10;
#endif
#endif

  return clib_min (r_ctr, r_sha2);
}

#define _(b)                                                                                       \
  static u32 aes_ops_aes_ctr_##b (vnet_crypto_op_t *ops[], u32 n_ops)                              \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, 0, AES_KEY_##b, 0);                                        \
  }                                                                                                \
  static u32 aes_ops_aes_ctr_##b##_chained (vnet_crypto_op_t *ops[],                               \
					    vnet_crypto_op_chunk_t *chunks, u32 n_ops)             \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, chunks, AES_KEY_##b, 1);                                   \
  }                                                                                                \
  static void aes_ctr_key_exp_##b (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t arg)   \
  {                                                                                                \
    return aes_ctr_key_exp (kop, arg.per_thread_key_data, arg.key, AES_KEY_##b);                   \
  }                                                                                                \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_enc) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_ENC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_dec) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_DEC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
    .probe = probe,                                                                                \
  };                                                                                               \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##b##_ctr) = {                                                    \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_CTR,                                                       \
    .key_fn = aes_ctr_key_exp_##b,                                                                 \
    .probe = probe,                                                                                \
    .key_data_sz = sizeof (aes_ctr_key_data_t),                                                    \
  };

_ (128)
_ (192)
_ (256)

#undef _

#define _(a, b, c, d)                                                                              \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)  \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b);                      \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops)                            \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, n_ops, chunks, AES_KEY_##a, CLIB_SHA2_##b);      \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)  \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b);                      \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops)                            \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, n_ops, chunks, AES_KEY_##a, CLIB_SHA2_##b);      \
  }                                                                                                \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_ctr_hmac_sha##b##_enc) = {                                   \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_ENC,                                   \
    .fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,                              \
    .probe = aes_ctr_sha2_probe,                                                                   \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_ctr_hmac_sha##b##_dec) = {                                   \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_DEC,                                   \
    .fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,                              \
    .probe = aes_ctr_sha2_probe,                                                                   \
  };                                                                                               \
                                                                                                   \
  static void aes_ctr_key_exp_##a##_hmac_sha##b (vnet_crypto_key_op_t kop,                         \
						 vnet_crypto_key_handler_args_t arg)               \
  {                                                                                                \
    aes_ctr_hmac_key_exp (kop, arg.per_thread_key_data, arg.key, arg.key_length, d, AES_KEY_##a,   \
			  CLIB_SHA2_##b);                                                          \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##a##_ctr_hmac_sha##b) = {                                        \
    .alg_id = VNET_CRYPTO_ALG_AES_##a##_CTR_SHA##b##_TAG##c,                                       \
    .key_fn = aes_ctr_key_exp_##a##_hmac_sha##b,                                                   \
    .probe = aes_ctr_sha2_probe,                                                                   \
    .key_data_sz = sizeof (aes_ctr_sha2_hmac_key_data_t),                                          \
  };

_ (128, 256, 16, 16)
_ (192, 256, 16, 24)
_ (256, 256, 16, 32)

#undef _
