/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <native/sha2.h>
#include <vppinfra/crypto/aes_cbc.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct aes_cbc_sha2_hmac_key_data
{
  clib_sha2_hmac_key_data_t hmac_key_data;
  aes_cbc_key_data_t cbc_key_data;
} aes_cbc_sha2_hmac_key_data_t;

#define CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE 256

static_always_inline u32
aes_ops_enc_aes_cbc_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type)
{
  u32 i, n_left = n_ops;
  aes_cbc_key_data_t *keys_data[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *plaintext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  uword oplen[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *iv[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *ciphertext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  clib_sha2_hmac_ctx_t ctx[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE];
  vnet_crypto_op_t *h_ops = ops[0];
  u8 buffer[64];
  aes_cbc_sha2_hmac_key_data_t *cbc_hmac_key_data;

  while (n_left)
    {
      i = 0;
      while (n_left && i < CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE)
	{
	  cbc_hmac_key_data = (aes_cbc_sha2_hmac_key_data_t *) ops[0]->key_data;
	  clib_sha2_hmac_init (&ctx[i], type, &cbc_hmac_key_data->hmac_key_data);
	  keys_data[i] = &cbc_hmac_key_data->cbc_key_data;
	  plaintext[i] = ops[0]->src;
	  ciphertext[i] = ops[0]->dst;
	  oplen[i] = ops[0]->len;
	  iv[i] = ops[0]->iv;
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

	  ops++;
	  n_left--;
	  i++;
	}
      clib_aes_cbc_encrypt_multi (keys_data, plaintext, oplen, iv, ks, ciphertext, i);

      for (u32 j = 0; j < i; j++, h_ops++)
	{
	  clib_sha2_hmac_update (&ctx[j], h_ops->integ_src, h_ops->integ_len);
	  clib_sha2_hmac_final (&ctx[j], buffer);
	  clib_memcpy_fast (h_ops->digest, buffer, h_ops->digest_len);
	}
    }
  return n_ops;
}

static_always_inline u32
aes_ops_hmac_dec_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type)
{
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_sha2_hmac_key_data_t *cbc_hmac_key_data = (aes_cbc_sha2_hmac_key_data_t *) op->key_data;
  aes_cbc_key_data_t *kd = &cbc_hmac_key_data->cbc_key_data;
  clib_sha2_hmac_ctx_t ctx;
  u8 buffer[64];
  u32 n_left = n_ops, n_fail = 0;

  ASSERT (n_ops >= 1);

decrypt:
  clib_sha2_hmac_init (&ctx, type, &cbc_hmac_key_data->hmac_key_data);
  clib_sha2_hmac_update (&ctx, op->integ_src, op->integ_len);
  clib_sha2_hmac_final (&ctx, buffer);

  if ((memcmp (op->digest, buffer, op->digest_len)))
    {
      n_fail++;
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
    }
  else
    {
#if defined(__VAES__) && defined(__AVX512F__)
      aes4_cbc_dec (kd->decrypt_key, (u8x64u *) op->src, (u8x64u *) op->dst,
		    (u8x16u *) op->iv, op->len, rounds);
#elif defined(__VAES__)
      aes2_cbc_dec (kd->decrypt_key, (u8x32u *) op->src, (u8x32u *) op->dst,
		    (u8x16u *) op->iv, op->len, rounds);
#else
      aes_cbc_dec (kd->decrypt_key, (u8x16u *) op->src, (u8x16u *) op->dst,
		   (u8x16u *) op->iv, op->len, rounds);
#endif
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  if (--n_left)
    {
      op += 1;
      cbc_hmac_key_data = (aes_cbc_sha2_hmac_key_data_t *) op->key_data;
      kd = &cbc_hmac_key_data->cbc_key_data;
      goto decrypt;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_enc_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks)
{
  u32 i, n_left = n_ops;
  aes_cbc_key_data_t *keys_data[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *plaintext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  uword oplen[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *iv[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *ciphertext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  aes_cbc_key_data_t *cbc_key_data;

  while (n_left)
    {
      i = 0;
      while (n_left && i < CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE)
	{
	  cbc_key_data = (aes_cbc_key_data_t *) ops[0]->key_data;
	  keys_data[i] = cbc_key_data;
	  plaintext[i] = ops[0]->src;
	  ciphertext[i] = ops[0]->dst;
	  oplen[i] = ops[0]->len;
	  iv[i] = ops[0]->iv;
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

	  ops++;
	  n_left--;
	  i++;
	}
      clib_aes_cbc_encrypt_multi (keys_data, plaintext, oplen, iv, ks, ciphertext, i);
    }
  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks)
{
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) op->key_data;
  u32 n_left = n_ops;

  ASSERT (n_ops >= 1);

decrypt:
#if defined(__VAES__) && defined(__AVX512F__)
  aes4_cbc_dec (kd->decrypt_key, (u8x64u *) op->src, (u8x64u *) op->dst,
		(u8x16u *) op->iv, op->len, rounds);
#elif defined(__VAES__)
  aes2_cbc_dec (kd->decrypt_key, (u8x32u *) op->src, (u8x32u *) op->dst,
		(u8x16u *) op->iv, op->len, rounds);
#else
  aes_cbc_dec (kd->decrypt_key, (u8x16u *) op->src, (u8x16u *) op->dst,
	       (u8x16u *) op->iv, op->len, rounds);
#endif
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      kd = (aes_cbc_key_data_t *) op->key_data;
      goto decrypt;
    }

  return n_ops;
}

static int
aes_cbc_cpu_probe ()
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
aes_cbc_sha2_probe ()
{
  int r_cbc = aes_cbc_cpu_probe ();
  int r_sha2 = sha2_probe ();
  return clib_min (r_cbc, r_sha2);
}

static void
aes_cbc_key_exp (vnet_crypto_key_op_t kop, aes_cbc_key_data_t *key_data, const u8 *data,
		 aes_key_size_t ks)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_cbc_key_expand (key_data, data, ks);
    }
}

static void
aes_cbc_hmac_key_exp (vnet_crypto_key_op_t kop, aes_cbc_sha2_hmac_key_data_t *key_data,
		      const u8 *data, u16 hmac_length, u16 cbc_length, aes_key_size_t ks,
		      clib_sha2_type_t type)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_cbc_key_expand (&key_data->cbc_key_data, data, ks);
      clib_sha2_hmac_key_data (type, data + cbc_length, hmac_length, &key_data->hmac_key_data);
    }
}

#define _(x)                                                                                       \
  static u32 aes_ops_enc_aes_cbc_##x (vnet_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_enc_aes_cbc (ops, n_ops, AES_KEY_##x);                                          \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##x##_cbc_enc) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_ENC,                                                     \
    .fn = aes_ops_enc_aes_cbc_##x,                                                                 \
    .probe = aes_cbc_cpu_probe,                                                                    \
  };                                                                                               \
                                                                                                   \
  static u32 aes_ops_dec_aes_cbc_##x (vnet_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_dec_aes_cbc (ops, n_ops, AES_KEY_##x);                                          \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##x##_cbc_dec) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_DEC,                                                     \
    .fn = aes_ops_dec_aes_cbc_##x,                                                                 \
    .probe = aes_cbc_cpu_probe,                                                                    \
  };                                                                                               \
                                                                                                   \
  static void aes_cbc_key_exp_##x (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t arg)   \
  {                                                                                                \
    aes_cbc_key_exp (kop, arg.per_thread_key_data, arg.key, AES_KEY_##x);                          \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##x##_cbc) = {                                                    \
    .alg_id = VNET_CRYPTO_ALG_AES_##x##_CBC,                                                       \
    .key_fn = aes_cbc_key_exp_##x,                                                                 \
    .probe = aes_cbc_cpu_probe,                                                                    \
    .key_data_sz = sizeof (aes_cbc_key_data_t),                                                    \
  };

_ (128)
_ (192)
_ (256)

#undef _

#define _(a, b, c, d)                                                                              \
  static u32 crypto_native_ops_enc_aes_cbc_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)  \
  {                                                                                                \
    return aes_ops_enc_aes_cbc_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b);                      \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_dec_aes_cbc_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)  \
  {                                                                                                \
    return aes_ops_hmac_dec_aes_cbc (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b);                      \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_cbc_hmac_sha##b##_enc) = {                                   \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_TAG##c##_ENC,                                   \
    .fn = crypto_native_ops_enc_aes_cbc_##a##_hmac_sha##b,                                         \
    .probe = aes_cbc_sha2_probe,                                                                   \
  };                                                                                               \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_cbc_hmac_sha##b##_dec) = {                                   \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_TAG##c##_DEC,                                   \
    .fn = crypto_native_ops_dec_aes_cbc_##a##_hmac_sha##b,                                         \
    .probe = aes_cbc_sha2_probe,                                                                   \
  };                                                                                               \
                                                                                                   \
  static void aes_cbc_key_exp_##a##_hmac_sha##b (vnet_crypto_key_op_t kop,                         \
						 vnet_crypto_key_handler_args_t arg)               \
  {                                                                                                \
    aes_cbc_hmac_key_exp (kop, arg.per_thread_key_data, arg.key, arg.key_length, d, AES_KEY_##a,   \
			  CLIB_SHA2_##b);                                                          \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##a##_cbc_hmac_sha##b) = {                                        \
    .alg_id = VNET_CRYPTO_ALG_AES_##a##_CBC_SHA##b##_TAG##c,                                       \
    .key_fn = aes_cbc_key_exp_##a##_hmac_sha##b,                                                   \
    .probe = aes_cbc_cpu_probe,                                                                    \
    .key_data_sz = sizeof (aes_cbc_sha2_hmac_key_data_t),                                          \
  };

_ (128, 224, 14, 16)
_ (192, 224, 14, 24)
_ (256, 224, 14, 32)
_ (128, 256, 16, 16)
_ (192, 256, 16, 24)
_ (256, 256, 16, 32)

#undef _