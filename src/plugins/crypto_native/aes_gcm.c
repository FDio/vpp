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
#include <crypto_native/aes.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct
{
  /* pre-calculated hash key values */
  const u8x16 Hi[8];
  /* extracted AES key */
  const u8x16 Ke[15];
} aes_gcm_key_data_t;

#ifdef __x86_64__
static const u32x4 last_byte_one = { 0, 0, 0, 1 << 24 };

static const u8x16 bswap_mask = {
  15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

#include <crypto_native/ghash.h>
#include <crypto_native/aes_gcm_aesni.h>
#else
#include <crypto_native/aes_gcm_neon.h>
#endif

static_always_inline u32
aesni_ops_enc_aes_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;


next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  aes_gcm ((u8x16u *) op->src, (u8x16u *) op->dst, (u8x16u *) op->aad,
	   (u8x16u *) op->iv, (u8x16u *) op->tag, op->len, op->aad_len,
	   op->tag_len, kd, AES_KEY_ROUNDS (ks), /* is_encrypt */ 1);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aesni_ops_dec_aes_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  rv = aes_gcm ((u8x16u *) op->src, (u8x16u *) op->dst, (u8x16u *) op->aad,
		(u8x16u *) op->iv, (u8x16u *) op->tag, op->len,
		op->aad_len, op->tag_len, kd, AES_KEY_ROUNDS (ks),
		/* is_encrypt */ 0);

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
aesni_gcm_key_exp (vnet_crypto_key_t * key, aes_key_size_t ks)
{
  aes_gcm_key_data_t *kd;
  //u8x16 H;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  /* expand AES key */
  aes_key_expand ((u8x16 *) kd->Ke, key->data, ks);

  /* pre-calculate H */
  //H = aes_encrypt_block (u8x16_splat (0), kd->Ke, ks);
  //H = aesni_gcm_bswap (H);
  //ghash_precompute (H, (u8x16 *) kd->Hi, 8);
  return kd;
}

#define foreach_aesni_gcm_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)                      \
{ return aesni_ops_dec_aes_gcm (vm, ops, n_ops, AES_KEY_##x); }              \
static u32 aesni_ops_enc_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)                      \
{ return aesni_ops_enc_aes_gcm (vm, ops, n_ops, AES_KEY_##x); }              \
static void * aesni_gcm_key_exp_##x (vnet_crypto_key_t *key)                 \
{ return aesni_gcm_key_exp (key, AES_KEY_##x); }

foreach_aesni_gcm_handler_type;
#undef _

clib_error_t *
#ifdef __VAES__
crypto_native_aes_gcm_init_vaes (vlib_main_t * vm)
#elif __AVX512F__
crypto_native_aes_gcm_init_avx512 (vlib_main_t * vm)
#elif __AVX2__
crypto_native_aes_gcm_init_avx2 (vlib_main_t * vm)
#elif __aarch64__
crypto_native_aes_gcm_init_neon (vlib_main_t * vm)
#else
crypto_native_aes_gcm_init_sse42 (vlib_main_t * vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;

#define _(x) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_GCM_ENC, \
				    aesni_ops_enc_aes_gcm_##x); \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_GCM_DEC, \
				    aesni_ops_dec_aes_gcm_##x); \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_GCM] = aesni_gcm_key_exp_##x;
  foreach_aesni_gcm_handler_type;
#undef _
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
