/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>
#include <vppinfra/crypto/aes_ctr.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_enc_aes_ctr (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		     aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_key_data_t *kd;
  u32 n_left = n_ops;

next:
  kd = (aes_ctr_key_data_t *) cm->key_data[op->key_index];
  aes_ctr (op->src, op->dst, (u8 *) op->iv, op->len, kd, AES_KEY_ROUNDS (ks));
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		     aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_key_data_t *kd;
  u32 n_left = n_ops;

next:
  kd = (aes_ctr_key_data_t *) cm->key_data[op->key_index];
  aes_ctr (op->src, op->dst, (u8 *) op->iv, op->len, kd, AES_KEY_ROUNDS (ks));
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void *
aes_ctr_key_exp (vnet_crypto_key_t *key, aes_key_size_t ks)
{
  aes_ctr_key_data_t *kd;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  clib_aes_ctr_key_expand (kd, key->data, ks);

  return kd;
}

#define foreach_aes_ctr_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                  \
  static u32 aes_ops_dec_aes_ctr_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_dec_aes_ctr (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
  static u32 aes_ops_enc_aes_ctr_##x (vlib_main_t *vm,                        \
				      vnet_crypto_op_t *ops[], u32 n_ops)     \
  {                                                                           \
    return aes_ops_enc_aes_ctr (vm, ops, n_ops, AES_KEY_##x);                 \
  }                                                                           \
  static void *aes_ctr_key_exp_##x (vnet_crypto_key_t *key)                   \
  {                                                                           \
    return aes_ctr_key_exp (key, AES_KEY_##x);                                \
  }

foreach_aes_ctr_handler_type;
#undef _

clib_error_t *
#if defined(__VAES__) && defined(__AVX512F__)
crypto_native_aes_ctr_init_icl (vlib_main_t *vm)
#elif defined(__VAES__)
crypto_native_aes_ctr_init_adl (vlib_main_t *vm)
#elif __AVX512F__
crypto_native_aes_ctr_init_skx (vlib_main_t *vm)
#elif __AVX2__
crypto_native_aes_ctr_init_hsw (vlib_main_t *vm)
#elif __aarch64__
crypto_native_aes_ctr_init_neon (vlib_main_t *vm)
#else
crypto_native_aes_ctr_init_slm (vlib_main_t *vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;

#define _(x)                                                                  \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index,              \
				    VNET_CRYPTO_OP_AES_##x##_CTR_ENC,         \
				    aes_ops_enc_aes_ctr_##x);                 \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index,              \
				    VNET_CRYPTO_OP_AES_##x##_CTR_DEC,         \
				    aes_ops_dec_aes_ctr_##x);                 \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_CTR] = aes_ctr_key_exp_##x;
  foreach_aes_ctr_handler_type;
#undef _
  return 0;
}
