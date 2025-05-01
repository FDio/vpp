/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/crypto/aes_cbc.h>
#include "sha2.h"

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

#define CRYPTO_NATIVE_AES_CBC_ENC_VEC_SIZE 256

static_always_inline u32
aes_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		     u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  u32 i, n_left = n_ops;
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
	  key_indices[i] = ops[0]->key_index;
	  plaintext[i] = ops[0]->src;
	  ciphertext[i] = ops[0]->dst;
	  oplen[i] = ops[0]->len;
	  iv[i] = ops[0]->iv;
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

	  ops++;
	  n_left--;
	  i++;
	}
      clib_aes_cbc_encrypt_multi ((aes_cbc_key_data_t **) cm->key_data,
				  key_indices, plaintext, oplen, iv, ks,
				  ciphertext, i);
    }
  return n_ops;
}


static_always_inline u32
aes_ops_dec_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		     u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
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
      kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
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

static void *
aes_cbc_key_exp_128 (vnet_crypto_key_t *key)
{
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  clib_aes128_cbc_key_expand (kd, key->data);
  return kd;
}

static void *
aes_cbc_key_exp_192 (vnet_crypto_key_t *key)
{
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  clib_aes192_cbc_key_expand (kd, key->data);
  return kd;
}

static void *
aes_cbc_key_exp_256 (vnet_crypto_key_t *key)
{
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  clib_aes256_cbc_key_expand (kd, key->data);
  return kd;
}

#define foreach_aes_cbc_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                  \
  static u32 aes_ops_enc_aes_cbc_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_enc_aes_cbc (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##x##_cbc_enc) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_ENC,                                \
    .fn = aes_ops_enc_aes_cbc_##x,                                            \
    .probe = aes_cbc_cpu_probe,                                               \
  };                                                                          \
                                                                              \
  static u32 aes_ops_dec_aes_cbc_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_dec_aes_cbc (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##x##_cbc_dec) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##x##_CBC_DEC,                                \
    .fn = aes_ops_dec_aes_cbc_##x,                                            \
    .probe = aes_cbc_cpu_probe,                                               \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##x##_cbc) = {                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##x##_CBC,                                  \
    .key_fn = aes_cbc_key_exp_##x,                                            \
    .probe = aes_cbc_cpu_probe,                                               \
  };

foreach_aes_cbc_handler_type;
#undef _

extern u32 crypto_native_ops_hmac_sha2 (vlib_main_t *vm,
					vnet_crypto_op_t *ops[], u32 n_ops,
					vnet_crypto_op_chunk_t *chunks,
					clib_sha2_type_t type);

#define foreach_crypto_native_cbc_hmac_op                                     \
  _ (128, 224, CLIB_SHA2_224, 14)                                             \
  _ (192, 224, CLIB_SHA2_224, 14)                                             \
  _ (256, 224, CLIB_SHA2_224, 14)                                             \
  _ (128, 256, CLIB_SHA2_256, 16)                                             \
  _ (192, 256, CLIB_SHA2_256, 16)                                             \
  _ (256, 256, CLIB_SHA2_256, 16)

#define _(k, b, clib_sha2, t)                                                 \
  static u32 crypto_native_ops_enc_aes_##k##_cbc_hmac_sha##b##_tag##t (       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    aes_ops_enc_aes_cbc (vm, ops, n_ops, AES_KEY_##k);                        \
    crypto_native_ops_hmac_sha2 (vm, ops, n_ops, 0, clib_sha2);               \
    return n_ops;                                                             \
  }                                                                           \
                                                                              \
  static u32 crypto_native_ops_dec_aes_##k##_cbc_hmac_sha##b##_tag##t (       \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    crypto_native_ops_hmac_sha2 (vm, ops, n_ops, 0, clib_sha2);               \
    aes_ops_dec_aes_cbc (vm, ops, n_ops, AES_KEY_##k);                        \
    return n_ops;                                                             \
  }                                                                           \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##k##_cbc_hmac_sha##b##_tag##t##_enc) = {     \
    .op_id = VNET_CRYPTO_OP_AES_##k##_CBC_SHA##b##_TAG##t##_ENC,              \
    .fn = crypto_native_ops_enc_aes_##k##_cbc_hmac_sha##b##_tag##t,           \
    .probe = aes_cbc_cpu_probe,                                               \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##k##_cbc_hmac_sha##b##_tag##t##_dec) = {     \
    .op_id = VNET_CRYPTO_OP_AES_##k##_CBC_SHA##b##_TAG##t##_DEC,              \
    .fn = crypto_native_ops_dec_aes_##k##_cbc_hmac_sha##b##_tag##t,           \
    .probe = aes_cbc_cpu_probe,                                               \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##k##_cbc_hmac_sha##b##_tag##t) = {          \
    .alg_id = VNET_CRYPTO_ALG_AES_##k##_CBC_SHA##b##_TAG##t,                  \
    .key_fn = aes_cbc_key_exp_##k,                                            \
    .probe = aes_cbc_cpu_probe,                                               \
  };

foreach_crypto_native_cbc_hmac_op
#undef _