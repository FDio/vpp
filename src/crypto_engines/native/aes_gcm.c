/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>
#include <vppinfra/crypto/aes_gcm.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_enc_aes_gcm (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     u32 fixed, u32 aad_len)
{
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;

next:
  kd = (aes_gcm_key_data_t *) op->key_data;
  aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
	   fixed ? aad_len : op->aad_len, fixed ? 16 : op->tag_len, kd,
	   AES_KEY_ROUNDS (ks), AES_GCM_OP_ENCRYPT);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_gcm (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     u32 fixed, u32 aad_len)
{
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) op->key_data;
  rv = aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
		fixed ? aad_len : op->aad_len, fixed ? 16 : op->tag_len, kd,
		AES_KEY_ROUNDS (ks), AES_GCM_OP_DECRYPT);

  if (rv)
    {
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  else
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      n_ops--;
    }

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void
aes_gcm_key_exp (vnet_crypto_key_op_t kop, aes_gcm_key_data_t *key_data, const u8 *data,
		 aes_key_size_t ks)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_gcm_key_expand (key_data, data, ks);
    }
}

#define _(x)                                                                                       \
  static u32 aes_ops_dec_aes_gcm_##x (vnet_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 0, 0);                                    \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x (vnet_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 0, 0);                                    \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad8 (vnet_crypto_op_t *ops[], u32 n_ops)             \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 8);                                    \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad8 (vnet_crypto_op_t *ops[], u32 n_ops)             \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 8);                                    \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad12 (vnet_crypto_op_t *ops[], u32 n_ops)            \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 12);                                   \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad12 (vnet_crypto_op_t *ops[], u32 n_ops)            \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 12);                                   \
  }                                                                                                \
  static void aes_gcm_key_exp_##x (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t a)     \
  {                                                                                                \
    return aes_gcm_key_exp (kop, a.per_thread_key_data, a.key, AES_KEY_##x);                       \
  }

_ (128)
_ (192)
_ (256)

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

#define _(b)                                                                                       \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_enc) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_ENC,                                                     \
    .fn = aes_ops_enc_aes_gcm_##b,                                                                 \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_dec) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_DEC,                                                     \
    .fn = aes_ops_dec_aes_gcm_##b,                                                                 \
    .probe = probe,                                                                                \
  };                                                                                               \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_enc_tag16_aad8) = {                                      \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD8_ENC,                                          \
    .fn = aes_ops_enc_aes_gcm_##b##_tag16_aad8,                                                    \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_dec_tag16_aad8) = {                                      \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD8_DEC,                                          \
    .fn = aes_ops_dec_aes_gcm_##b##_tag16_aad8,                                                    \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_enc_tag16_aad12) = {                                     \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD12_ENC,                                         \
    .fn = aes_ops_enc_aes_gcm_##b##_tag16_aad12,                                                   \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_dec_tag16_aad12) = {                                     \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD12_DEC,                                         \
    .fn = aes_ops_dec_aes_gcm_##b##_tag16_aad12,                                                   \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##b##_gcm) = {                                                    \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM,                                                       \
    .key_fn = aes_gcm_key_exp_##b,                                                                 \
    .probe = probe,                                                                                \
    .key_data_sz = sizeof (aes_gcm_key_data_t),                                                    \
  };

_ (128) _ (192) _ (256)
#undef _
