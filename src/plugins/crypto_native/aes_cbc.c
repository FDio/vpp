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
#include <vppinfra/crypto/aes_cbc.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#endif

#if defined(__VAES__) && defined(__AVX512F__)
#define u8xN		  u8x64
#define u32xN		  u32x16
#define u32xN_min_scalar  u32x16_min_scalar
#define u32xN_is_all_zero u32x16_is_all_zero
#define u32xN_splat	  u32x16_splat
#elif defined(__VAES__)
#define u8xN		  u8x32
#define u32xN		  u32x8
#define u32xN_min_scalar  u32x8_min_scalar
#define u32xN_is_all_zero u32x8_is_all_zero
#define u32xN_splat	  u32x8_splat
#else
#define u8xN		  u8x16
#define u32xN		  u32x4
#define u32xN_min_scalar  u32x4_min_scalar
#define u32xN_is_all_zero u32x4_is_all_zero
#define u32xN_splat	  u32x4_splat
#endif

static_always_inline u32
aes_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		     u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  int rounds = AES_KEY_ROUNDS (ks);
  u8 placeholder[8192];
  u32 i, j, count, n_left = n_ops;
  u32xN placeholder_mask = { };
  u32xN len = { };
  vnet_crypto_key_index_t key_index[4 * N_AES_LANES];
  u8 *src[4 * N_AES_LANES] = {};
  u8 *dst[4 * N_AES_LANES] = {};
  u8xN r[4] = {};
  u8xN k[15][4] = {};

  for (i = 0; i < 4 * N_AES_LANES; i++)
    key_index[i] = ~0;

more:
  for (i = 0; i < 4 * N_AES_LANES; i++)
    if (len[i] == 0)
      {
	if (n_left == 0)
	  {
	    /* no more work to enqueue, so we are enqueueing placeholder buffer */
	    src[i] = dst[i] = placeholder;
	    len[i] = sizeof (placeholder);
	    placeholder_mask[i] = 0;
	  }
	else
	  {
	    u8x16 t = aes_block_load (ops[0]->iv);
	    ((u8x16 *) r)[i] = t;

	    src[i] = ops[0]->src;
	    dst[i] = ops[0]->dst;
	    len[i] = ops[0]->len;
	    placeholder_mask[i] = ~0;
	    if (key_index[i] != ops[0]->key_index)
	      {
		aes_cbc_key_data_t *kd;
		key_index[i] = ops[0]->key_index;
		kd = (aes_cbc_key_data_t *) cm->key_data[key_index[i]];
		for (j = 0; j < rounds + 1; j++)
		  ((u8x16 *) k[j])[i] = kd->encrypt_key[j];
	      }
	    ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	    n_left--;
	    ops++;
	  }
      }

  count = u32xN_min_scalar (len);

  ASSERT (count % 16 == 0);

  for (i = 0; i < count; i += 16)
    {
#if defined(__VAES__) && defined(__AVX512F__)
      r[0] = u8x64_xor3 (r[0], aes_block_load_x4 (src, i), k[0][0]);
      r[1] = u8x64_xor3 (r[1], aes_block_load_x4 (src + 4, i), k[0][1]);
      r[2] = u8x64_xor3 (r[2], aes_block_load_x4 (src + 8, i), k[0][2]);
      r[3] = u8x64_xor3 (r[3], aes_block_load_x4 (src + 12, i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x4 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x4 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x4 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x4 (r[3], k[j][3]);
	}
      r[0] = aes_enc_last_round_x4 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x4 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x4 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x4 (r[3], k[j][3]);

      aes_block_store_x4 (dst, i, r[0]);
      aes_block_store_x4 (dst + 4, i, r[1]);
      aes_block_store_x4 (dst + 8, i, r[2]);
      aes_block_store_x4 (dst + 12, i, r[3]);
#elif defined(__VAES__)
      r[0] = u8x32_xor3 (r[0], aes_block_load_x2 (src, i), k[0][0]);
      r[1] = u8x32_xor3 (r[1], aes_block_load_x2 (src + 2, i), k[0][1]);
      r[2] = u8x32_xor3 (r[2], aes_block_load_x2 (src + 4, i), k[0][2]);
      r[3] = u8x32_xor3 (r[3], aes_block_load_x2 (src + 6, i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x2 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x2 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x2 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x2 (r[3], k[j][3]);
	}
      r[0] = aes_enc_last_round_x2 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x2 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x2 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x2 (r[3], k[j][3]);

      aes_block_store_x2 (dst, i, r[0]);
      aes_block_store_x2 (dst + 2, i, r[1]);
      aes_block_store_x2 (dst + 4, i, r[2]);
      aes_block_store_x2 (dst + 6, i, r[3]);
#else
#if __x86_64__
      r[0] = u8x16_xor3 (r[0], aes_block_load (src[0] + i), k[0][0]);
      r[1] = u8x16_xor3 (r[1], aes_block_load (src[1] + i), k[0][1]);
      r[2] = u8x16_xor3 (r[2], aes_block_load (src[2] + i), k[0][2]);
      r[3] = u8x16_xor3 (r[3], aes_block_load (src[3] + i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x1 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x1 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x1 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x1 (r[3], k[j][3]);
	}

      r[0] = aes_enc_last_round_x1 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x1 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x1 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x1 (r[3], k[j][3]);

      aes_block_store (dst[0] + i, r[0]);
      aes_block_store (dst[1] + i, r[1]);
      aes_block_store (dst[2] + i, r[2]);
      aes_block_store (dst[3] + i, r[3]);
#else
      r[0] ^= aes_block_load (src[0] + i);
      r[1] ^= aes_block_load (src[1] + i);
      r[2] ^= aes_block_load (src[2] + i);
      r[3] ^= aes_block_load (src[3] + i);
      for (j = 0; j < rounds - 1; j++)
	{
	  r[0] = vaesmcq_u8 (vaeseq_u8 (r[0], k[j][0]));
	  r[1] = vaesmcq_u8 (vaeseq_u8 (r[1], k[j][1]));
	  r[2] = vaesmcq_u8 (vaeseq_u8 (r[2], k[j][2]));
	  r[3] = vaesmcq_u8 (vaeseq_u8 (r[3], k[j][3]));
	}
      r[0] = vaeseq_u8 (r[0], k[j][0]) ^ k[rounds][0];
      r[1] = vaeseq_u8 (r[1], k[j][1]) ^ k[rounds][1];
      r[2] = vaeseq_u8 (r[2], k[j][2]) ^ k[rounds][2];
      r[3] = vaeseq_u8 (r[3], k[j][3]) ^ k[rounds][3];
      aes_block_store (dst[0] + i, r[0]);
      aes_block_store (dst[1] + i, r[1]);
      aes_block_store (dst[2] + i, r[2]);
      aes_block_store (dst[3] + i, r[3]);
#endif
#endif
    }

  len -= u32xN_splat (count);

  for (i = 0; i < 4 * N_AES_LANES; i++)
    {
      src[i] += count;
      dst[i] += count;
    }

  if (n_left > 0)
    goto more;

  if (!u32xN_is_all_zero (len & placeholder_mask))
    goto more;

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

