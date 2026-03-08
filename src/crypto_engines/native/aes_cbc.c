/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/crypto/aes_cbc.h>
#include <native/sha2.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

#define CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE 256

typedef struct
{
  aes_cbc_key_data_t crypto_key;
  clib_sha2_hmac_key_data_t integ_key;
} aes_cbc_hmac_key_data_t;

static_always_inline aes_cbc_key_data_t *
aes_cbc_get_key_data (vnet_crypto_op_t *op, clib_thread_index_t thread_index)
{
  return (aes_cbc_key_data_t *) vnet_crypto_get_simple_key_data (op->key);
}

static_always_inline aes_cbc_hmac_key_data_t *
aes_cbc_hmac_get_key_data (vnet_crypto_op_t *op, clib_thread_index_t thread_index)
{
  return (aes_cbc_hmac_key_data_t *) vnet_crypto_get_simple_key_data (op->key);
}

static_always_inline u32
aes_ops_enc_aes_cbc_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, clib_thread_index_t thread_index)
{
  u32 i, n_left = n_ops;
  uword key_indices[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  aes_cbc_key_data_t *keys[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *plaintext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  uword oplen[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *iv[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *ciphertext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  clib_sha2_hmac_ctx_t ctx[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE];
  vnet_crypto_op_t *h_ops = ops[0];
  u8 buffer[64];

  while (n_left)
    {
      i = 0;
      while (n_left && i < CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE)
	{
	  aes_cbc_hmac_key_data_t *kd = aes_cbc_hmac_get_key_data (ops[0], thread_index);
	  clib_sha2_hmac_init (&ctx[i], type, &kd->integ_key);
	  key_indices[i] = i;
	  keys[i] = &kd->crypto_key;
	  plaintext[i] = ops[0]->src;
	  ciphertext[i] = ops[0]->dst;
	  oplen[i] = ops[0]->len;
	  iv[i] = ops[0]->iv;
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

	  ops++;
	  n_left--;
	  i++;
	}
      clib_aes_cbc_encrypt_multi (keys, key_indices, plaintext, oplen, iv, ks, ciphertext, i);

      for (u32 j = 0; j < i; j++, h_ops++)
	{
	  u32 digest_len = vnet_crypto_get_op_data (h_ops->op)->digest_len;

	  if (digest_len == 0)
	    digest_len = h_ops->digest_len;

	  clib_sha2_hmac_update (&ctx[j], h_ops->integ_src, h_ops->integ_len);
	  clib_sha2_hmac_final (&ctx[j], buffer);
	  clib_memcpy_fast (h_ops->digest, buffer, digest_len);
	}
    }
  return n_ops;
}

static_always_inline u32
aes_ops_hmac_dec_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, clib_thread_index_t thread_index)
{
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_hmac_key_data_t *kd = aes_cbc_hmac_get_key_data (op, thread_index);
  clib_sha2_hmac_ctx_t ctx;
  u8 buffer[64];
  u32 digest_len;
  u32 n_left = n_ops, n_fail = 0;

  ASSERT (n_ops >= 1);

decrypt:
  digest_len = vnet_crypto_get_op_data (op->op)->digest_len;
  if (digest_len == 0)
    digest_len = op->digest_len;

  clib_sha2_hmac_init (&ctx, type, &kd->integ_key);
  clib_sha2_hmac_update (&ctx, op->integ_src, op->integ_len);
  clib_sha2_hmac_final (&ctx, buffer);

  if ((memcmp (op->digest, buffer, digest_len)))
    {
      n_fail++;
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
    }
  else
    {
#if defined(__VAES__) && defined(__AVX512F__)
      aes4_cbc_dec (kd->crypto_key.decrypt_key, (u8x64u *) op->src, (u8x64u *) op->dst,
		    (u8x16u *) op->iv, op->len, rounds);
#elif defined(__VAES__)
      aes2_cbc_dec (kd->crypto_key.decrypt_key, (u8x32u *) op->src, (u8x32u *) op->dst,
		    (u8x16u *) op->iv, op->len, rounds);
#else
      aes_cbc_dec (kd->crypto_key.decrypt_key, (u8x16u *) op->src, (u8x16u *) op->dst,
		   (u8x16u *) op->iv, op->len, rounds);
#endif
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  if (--n_left)
    {
      op += 1;
      kd = aes_cbc_hmac_get_key_data (op, thread_index);
      goto decrypt;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_enc_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     clib_thread_index_t thread_index)
{
  u32 i, n_left = n_ops;
  aes_cbc_key_data_t *keys[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  uword key_indices[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *plaintext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  uword oplen[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *iv[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};
  u8 *ciphertext[CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE] = {};

  while (n_left)
    {
      i = 0;
      while (n_left && i < CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE)
	{
	  key_indices[i] = i;
	  keys[i] = aes_cbc_get_key_data (ops[0], thread_index);
	  plaintext[i] = ops[0]->src;
	  ciphertext[i] = ops[0]->dst;
	  oplen[i] = ops[0]->len;
	  iv[i] = ops[0]->iv;
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	  ops++;
	  n_left--;
	  i++;
	}
      clib_aes_cbc_encrypt_multi (keys, key_indices, plaintext, oplen, iv, ks, ciphertext, i);
    }
  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_cbc (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     clib_thread_index_t thread_index)
{
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = aes_cbc_get_key_data (op, thread_index);
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
      kd = aes_cbc_get_key_data (op, thread_index);
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

static_always_inline void
aes_cbc_key_exp (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks)
{
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) key_data;
  if (ks == AES_KEY_128)
    clib_aes128_cbc_key_expand (kd, vnet_crypto_get_cipher_key (key));
  else if (ks == AES_KEY_192)
    clib_aes192_cbc_key_expand (kd, vnet_crypto_get_cipher_key (key));
  else
    clib_aes256_cbc_key_expand (kd, vnet_crypto_get_cipher_key (key));
}

static_always_inline void
aes_cbc_key_add_inline (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks)
{
  vnet_crypto_alg_t alg = VNET_CRYPTO_ALG_NONE;

  if (ks == AES_KEY_128)
    alg = VNET_CRYPTO_ALG_AES_128_CBC;
  else if (ks == AES_KEY_192)
    alg = VNET_CRYPTO_ALG_AES_192_CBC;
  else
    alg = VNET_CRYPTO_ALG_AES_256_CBC;

  if (key->alg != alg)
    return;

  aes_cbc_key_exp (key, key_data, ks);
}

static void
aes_cbc128_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_key_add_inline (key, key_data, AES_KEY_128);
}

static void
aes_cbc192_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_key_add_inline (key, key_data, AES_KEY_192);
}

static void
aes_cbc256_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_key_add_inline (key, key_data, AES_KEY_256);
}

static_always_inline void
aes_cbc_sha2_key_add_inline (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks,
			     clib_sha2_type_t type)
{
  aes_cbc_hmac_key_data_t *kd = (aes_cbc_hmac_key_data_t *) key_data;
  u16 crypto_len;
  u16 integ_len;

  if (ks == AES_KEY_128)
    crypto_len = 16;
  else if (ks == AES_KEY_192)
    crypto_len = 24;
  else
    crypto_len = 32;

  if (key->cipher_key_sz + key->integ_key_sz < crypto_len)
    return;

  integ_len = key->integ_key_sz;
  aes_cbc_key_exp (key, (u8 *) &kd->crypto_key, ks);
  clib_sha2_hmac_key_data (type, vnet_crypto_get_integ_key (key), integ_len, &kd->integ_key);
}

static void
aes_cbc128_sha224_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_128, CLIB_SHA2_224);
}

static void
aes_cbc192_sha224_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_192, CLIB_SHA2_224);
}

static void
aes_cbc256_sha224_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_256, CLIB_SHA2_224);
}

static void
aes_cbc128_sha256_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_128, CLIB_SHA2_256);
}

static void
aes_cbc192_sha256_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_192, CLIB_SHA2_256);
}

static void
aes_cbc256_sha256_key_change (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_cbc_sha2_key_add_inline (key, key_data, AES_KEY_256, CLIB_SHA2_256);
}

VNET_CRYPTO_REG_OP_GROUP (native_cbc128_group) = {
  .probe_fn = aes_cbc_cpu_probe,
  .max_key_data_sz = sizeof (aes_cbc_key_data_t),
  .key_change_fn = aes_cbc128_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc192_group) = {
  .probe_fn = aes_cbc_cpu_probe,
  .max_key_data_sz = sizeof (aes_cbc_key_data_t),
  .key_change_fn = aes_cbc192_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc256_group) = {
  .probe_fn = aes_cbc_cpu_probe,
  .max_key_data_sz = sizeof (aes_cbc_key_data_t),
  .key_change_fn = aes_cbc256_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc128_sha224_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc128_sha224_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc192_sha224_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc192_sha224_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc256_sha224_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc256_sha224_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc128_sha256_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc128_sha256_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc192_sha256_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc192_sha256_key_change,
};

VNET_CRYPTO_REG_OP_GROUP (native_cbc256_sha256_group) = {
  .probe_fn = aes_cbc_sha2_probe,
  .max_key_data_sz = sizeof (aes_cbc_hmac_key_data_t),
  .key_change_fn = aes_cbc256_sha256_key_change,
};

#define foreach_aes_cbc_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                                       \
  static u32 aes_ops_enc_aes_cbc_##x (vnet_crypto_op_t *ops[], u32 n_ops,                          \
				      clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return aes_ops_enc_aes_cbc (ops, n_ops, AES_KEY_##x, thread_index);                            \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##x##_cbc_enc) = {                                                       \
    .group = &native_cbc##x##_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_ENC,                                                     \
    .fn = aes_ops_enc_aes_cbc_##x,                                                                 \
  };                                                                                               \
                                                                                                   \
  static u32 aes_ops_dec_aes_cbc_##x (vnet_crypto_op_t *ops[], u32 n_ops,                          \
				      clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return aes_ops_dec_aes_cbc (ops, n_ops, AES_KEY_##x, thread_index);                            \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##x##_cbc_dec) = {                                                       \
    .group = &native_cbc##x##_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_DEC,                                                     \
    .fn = aes_ops_dec_aes_cbc_##x,                                                                 \
  };

foreach_aes_cbc_handler_type;
#undef _

#define _(a, b, c)                                                                                 \
  static u32 crypto_native_ops_enc_aes_cbc_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops,  \
							      clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_enc_aes_cbc_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, thread_index);        \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_dec_aes_cbc_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops,  \
							      clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_hmac_dec_aes_cbc (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, thread_index);        \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##a##_cbc_hmac_sha##b##_enc) = {                                         \
    .group = &native_cbc##a##_sha##b##_group,                                                      \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_ENC,                                            \
    .fn = crypto_native_ops_enc_aes_cbc_##a##_hmac_sha##b,                                         \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (aes_##a##_cbc_hmac_sha##b##_dec) = {                                         \
    .group = &native_cbc##a##_sha##b##_group,                                                      \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_DEC,                                            \
    .fn = crypto_native_ops_dec_aes_cbc_##a##_hmac_sha##b,                                         \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (aes_##a##_cbc_hmac_sha##b##_tag##c##_enc) = {                                \
    .group = &native_cbc##a##_sha##b##_group,                                                      \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_TAG##c##_ENC,                                   \
    .fn = crypto_native_ops_enc_aes_cbc_##a##_hmac_sha##b,                                         \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (aes_##a##_cbc_hmac_sha##b##_tag##c##_dec) = {                                \
    .group = &native_cbc##a##_sha##b##_group,                                                      \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CBC_SHA##b##_TAG##c##_DEC,                                   \
    .fn = crypto_native_ops_dec_aes_cbc_##a##_hmac_sha##b,                                         \
  };

_ (128, 224, 14)
_ (192, 224, 14)
_ (256, 224, 14)
_ (128, 256, 16)
_ (192, 256, 16)
_ (256, 256, 16)

#undef _
