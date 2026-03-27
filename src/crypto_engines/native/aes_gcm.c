/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>
#include <vppinfra/crypto/aes_gcm.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_enc_aes_gcm (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks, i32 aad_len,
		     u32 auth_len)
{
  aes_gcm_key_data_t *kd;
  u32 i;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      kd = (aes_gcm_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx);
      aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->auth, op->len,
	       aad_len >= 0 ? aad_len : op->aad_len, auth_len ? auth_len : op->auth_len, kd,
	       AES_KEY_ROUNDS (ks), AES_GCM_OP_ENCRYPT);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_gcm (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks, i32 aad_len,
		     u32 auth_len)
{
  aes_gcm_key_data_t *kd;
  u32 i;
  u32 n_fail = 0;
  int rv;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      kd = (aes_gcm_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx);
      rv = aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->auth, op->len,
		    aad_len >= 0 ? aad_len : op->aad_len, auth_len ? auth_len : op->auth_len, kd,
		    AES_KEY_ROUNDS (ks), AES_GCM_OP_DECRYPT);

      if (rv)
	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      else
	{
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  n_fail++;
	}
    }

  return n_ops - n_fail;
}

static_always_inline void
aes_gcm_key_exp (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_key_size_t ks)
{
  clib_aes_gcm_key_expand ((aes_gcm_key_data_t *) key_data, vnet_crypto_get_cipher_key (ctx), ks);
}

#define foreach_aes_gcm_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                                       \
  static u32 aes_ops_dec_aes_gcm_##x (vnet_crypto_op_t *ops[],                                     \
				      vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,     \
				      clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, -1, 0);                                   \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x (vnet_crypto_op_t *ops[],                                     \
				      vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,     \
				      clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, -1, 0);                                   \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad8 (vnet_crypto_op_t *ops[],                        \
						   vnet_crypto_op_chunk_t *chunks __clib_unused,   \
						   u32 n_ops, clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 8, 16);                                   \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad8 (vnet_crypto_op_t *ops[],                        \
						   vnet_crypto_op_chunk_t *chunks __clib_unused,   \
						   u32 n_ops, clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 8, 16);                                   \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad12 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 12, 16);                                  \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad12 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 12, 16);                                  \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad20 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 20, 16);                                  \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad20 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 20, 16);                                  \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad28 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 28, 16);                                  \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad28 (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks __clib_unused,  \
						    u32 n_ops, clib_thread_index_t thread_index)   \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 28, 16);                                  \
  }

foreach_aes_gcm_handler_type;
#undef _

static int
probe ()
{
#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vpclmulqdq () && clib_cpu_supports_vaes () &&
      clib_cpu_supports_avx512f ())
    return 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vpclmulqdq () && clib_cpu_supports_vaes ())
    return 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_avx512f ())
    return 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_avx2 ())
    return 20;
#elif __AES__
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_aes ())
    return 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    return 10;
#endif
  return -1;
}

static_always_inline void
aes_gcm_key_add (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_key_size_t ks)
{
  aes_gcm_key_exp (ctx, key_data, ks);
}

static void
aes_gcm128_key_change (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_gcm_key_add (ctx, key_data, AES_KEY_128);
}

static void
aes_gcm192_key_change (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_gcm_key_add (ctx, key_data, AES_KEY_192);
}

static void
aes_gcm256_key_change (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_gcm_key_add (ctx, key_data, AES_KEY_256);
}

#define foreach_aes_gcm_bits _ (128) _ (192) _ (256)

VNET_CRYPTO_REGISTER_ALG_GROUP (native_gcm128_group) = {
  .name = "native_gcm128_group",
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_gcm_key_data_t),
  .key_change_fn = aes_gcm128_key_change,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_gcm192_group) = {
  .name = "native_gcm192_group",
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_gcm_key_data_t),
  .key_change_fn = aes_gcm192_key_change,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_gcm256_group) = {
  .name = "native_gcm256_group",
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_gcm_key_data_t),
  .key_change_fn = aes_gcm256_key_change,
};

#define _(b)                                                                                              \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_gcm) = {                                                          \
    .group = &native_gcm##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM,                                                       \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_enc_aes_gcm_##b,                                                           \
      .dec_fn = aes_ops_dec_aes_gcm_##b,                                                           \
    },                                                                                             \
  }; \
                                                                                                          \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_gcm_tag16_aad8) = {                                               \
    .group = &native_gcm##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM_ICV16_AAD8,                                            \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_enc_aes_gcm_##b##_tag16_aad8,                                              \
      .dec_fn = aes_ops_dec_aes_gcm_##b##_tag16_aad8,                                              \
    },                                                                                             \
  }; \
                                                                                                          \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_gcm_tag16_aad12) = {                                              \
    .group = &native_gcm##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM_ICV16_AAD12,                                           \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_enc_aes_gcm_##b##_tag16_aad12,                                             \
      .dec_fn = aes_ops_dec_aes_gcm_##b##_tag16_aad12,                                             \
    },                                                                                             \
  }; \
                                                                                                          \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_gcm_tag16_aad20) = {                                              \
    .group = &native_gcm##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM_ICV16_AAD20,                                           \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_enc_aes_gcm_##b##_tag16_aad20,                                             \
      .dec_fn = aes_ops_dec_aes_gcm_##b##_tag16_aad20,                                             \
    },                                                                                             \
  }; \
                                                                                                          \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_gcm_tag16_aad28) = {                                              \
    .group = &native_gcm##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM_ICV16_AAD28,                                           \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_enc_aes_gcm_##b##_tag16_aad28,                                             \
      .dec_fn = aes_ops_dec_aes_gcm_##b##_tag16_aad28,                                             \
    },                                                                                             \
  };

foreach_aes_gcm_bits
#undef _
