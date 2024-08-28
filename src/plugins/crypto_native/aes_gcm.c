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
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>
#include <vppinfra/crypto/aes_gcm.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#endif

static_always_inline u32
aes_ops_enc_aes_gcm (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		     aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;

next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
	   op->aad_len, op->tag_len, kd, AES_KEY_ROUNDS (ks),
	   AES_GCM_OP_ENCRYPT);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_gcm (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		     aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  rv = aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
		op->aad_len, op->tag_len, kd, AES_KEY_ROUNDS (ks),
		AES_GCM_OP_DECRYPT);

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

static_always_inline void *
aes_gcm_key_exp (vnet_crypto_key_t *key, aes_key_size_t ks)
{
  aes_gcm_key_data_t *kd;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  clib_aes_gcm_key_expand (kd, key->data, ks);

  return kd;
}

#define foreach_aes_gcm_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                  \
  static u32 aes_ops_dec_aes_gcm_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_dec_aes_gcm (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
  static u32 aes_ops_enc_aes_gcm_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_enc_aes_gcm (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
  static void *aes_gcm_key_exp_##x (vnet_crypto_key_t *key)                   \
  {                                                                           \
    return aes_gcm_key_exp (key, AES_KEY_##x);                                \
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

#define _(b)                                                                  \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_enc) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_ENC,                                \
    .fn = aes_ops_enc_aes_gcm_##b,                                            \
    .probe = probe,                                                           \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_gcm_dec) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##b##_GCM_DEC,                                \
    .fn = aes_ops_dec_aes_gcm_##b,                                            \
    .probe = probe,                                                           \
  };                                                                          \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##b##_gcm) = {                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_GCM,                                  \
    .key_fn = aes_gcm_key_exp_##b,                                            \
    .probe = probe,                                                           \
  };

_ (128) _ (192) _ (256)
#undef _
