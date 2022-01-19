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
  u8x16 encrypt_key[15];
#if __VAES__
  u8x64 decrypt_key[15];
#else
  u8x16 decrypt_key[15];
#endif
} aes_cbc_key_data_t;


static_always_inline void __clib_unused
aes_cbc_dec (u8x16 * k, u8x16u * src, u8x16u * dst, u8x16u * iv, int count,
	     int rounds)
{
  u8x16 r[4], c[4], f;

  f = iv[0];
  while (count >= 64)
    {
      clib_prefetch_load (src + 8);
      clib_prefetch_load (dst + 8);

      c[0] = r[0] = src[0];
      c[1] = r[1] = src[1];
      c[2] = r[2] = src[2];
      c[3] = r[3] = src[3];

#if __x86_64__
      r[0] ^= k[0];
      r[1] ^= k[0];
      r[2] ^= k[0];
      r[3] ^= k[0];

      for (int i = 1; i < rounds; i++)
	{
	  r[0] = aes_dec_round (r[0], k[i]);
	  r[1] = aes_dec_round (r[1], k[i]);
	  r[2] = aes_dec_round (r[2], k[i]);
	  r[3] = aes_dec_round (r[3], k[i]);
	}

      r[0] = aes_dec_last_round (r[0], k[rounds]);
      r[1] = aes_dec_last_round (r[1], k[rounds]);
      r[2] = aes_dec_last_round (r[2], k[rounds]);
      r[3] = aes_dec_last_round (r[3], k[rounds]);
#else
      for (int i = 0; i < rounds - 1; i++)
	{
	  r[0] = vaesimcq_u8 (vaesdq_u8 (r[0], k[i]));
	  r[1] = vaesimcq_u8 (vaesdq_u8 (r[1], k[i]));
	  r[2] = vaesimcq_u8 (vaesdq_u8 (r[2], k[i]));
	  r[3] = vaesimcq_u8 (vaesdq_u8 (r[3], k[i]));
	}
      r[0] = vaesdq_u8 (r[0], k[rounds - 1]) ^ k[rounds];
      r[1] = vaesdq_u8 (r[1], k[rounds - 1]) ^ k[rounds];
      r[2] = vaesdq_u8 (r[2], k[rounds - 1]) ^ k[rounds];
      r[3] = vaesdq_u8 (r[3], k[rounds - 1]) ^ k[rounds];
#endif
      dst[0] = r[0] ^ f;
      dst[1] = r[1] ^ c[0];
      dst[2] = r[2] ^ c[1];
      dst[3] = r[3] ^ c[2];
      f = c[3];

      count -= 64;
      src += 4;
      dst += 4;
    }

  while (count > 0)
    {
      c[0] = r[0] = src[0];
#if __x86_64__
      r[0] ^= k[0];
      for (int i = 1; i < rounds; i++)
	r[0] = aes_dec_round (r[0], k[i]);
      r[0] = aes_dec_last_round (r[0], k[rounds]);
#else
      c[0] = r[0] = src[0];
      for (int i = 0; i < rounds - 1; i++)
	r[0] = vaesimcq_u8 (vaesdq_u8 (r[0], k[i]));
      r[0] = vaesdq_u8 (r[0], k[rounds - 1]) ^ k[rounds];
#endif
      dst[0] = r[0] ^ f;
      f = c[0];

      count -= 16;
      src += 1;
      dst += 1;
    }
}

#if __x86_64__
#ifdef __VAES__

static_always_inline u8x64
aes_block_load_x4 (u8 * src[], int i)
{
  u8x64 r = { };
  r = u8x64_insert_u8x16 (r, aes_block_load (src[0] + i), 0);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[1] + i), 1);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[2] + i), 2);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[3] + i), 3);
  return r;
}

static_always_inline void
aes_block_store_x4 (u8 * dst[], int i, u8x64 r)
{
  aes_block_store (dst[0] + i, u8x64_extract_u8x16 (r, 0));
  aes_block_store (dst[1] + i, u8x64_extract_u8x16 (r, 1));
  aes_block_store (dst[2] + i, u8x64_extract_u8x16 (r, 2));
  aes_block_store (dst[3] + i, u8x64_extract_u8x16 (r, 3));
}

static_always_inline u8x64
aes_cbc_dec_permute (u8x64 a, u8x64 b)
{
  __m512i perm = { 6, 7, 8, 9, 10, 11, 12, 13 };
  return (u8x64) _mm512_permutex2var_epi64 ((__m512i) a, perm, (__m512i) b);
}

static_always_inline void
vaes_cbc_dec (u8x64 *k, u8x64u *src, u8x64u *dst, u8x16u *iv, int count,
	      aes_key_size_t rounds)
{
  u8x64 f, r[4], c[4] = { };
  __mmask8 m;
  int i, n_blocks = count >> 4;

  f = (u8x64) _mm512_mask_loadu_epi64 (_mm512_setzero_si512 (), 0xc0,
				       (__m512i *) (iv - 3));

  while (n_blocks >= 16)
    {
      c[0] = src[0];
      c[1] = src[1];
      c[2] = src[2];
      c[3] = src[3];

      r[0] = c[0] ^ k[0];
      r[1] = c[1] ^ k[0];
      r[2] = c[2] ^ k[0];
      r[3] = c[3] ^ k[0];

      for (i = 1; i < rounds; i++)
	{
	  r[0] = aes_dec_round_x4 (r[0], k[i]);
	  r[1] = aes_dec_round_x4 (r[1], k[i]);
	  r[2] = aes_dec_round_x4 (r[2], k[i]);
	  r[3] = aes_dec_round_x4 (r[3], k[i]);
	}

      r[0] = aes_dec_last_round_x4 (r[0], k[i]);
      r[1] = aes_dec_last_round_x4 (r[1], k[i]);
      r[2] = aes_dec_last_round_x4 (r[2], k[i]);
      r[3] = aes_dec_last_round_x4 (r[3], k[i]);

      dst[0] = r[0] ^= aes_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes_cbc_dec_permute (c[0], c[1]);
      dst[2] = r[2] ^= aes_cbc_dec_permute (c[1], c[2]);
      dst[4] = r[3] ^= aes_cbc_dec_permute (c[2], c[3]);
      f = c[3];

      n_blocks -= 16;
      src += 4;
      dst += 4;
    }

  while (n_blocks > 0)
    {
      m = (1 << (n_blocks * 2)) - 1;
      c[0] = (u8x64) _mm512_mask_loadu_epi64 ((__m512i) c[0], m,
					      (__m512i *) src);
      f = aes_cbc_dec_permute (f, c[0]);
      r[0] = c[0] ^ k[0];
      for (i = 1; i < rounds; i++)
	r[0] = aes_dec_round_x4 (r[0], k[i]);
      r[0] = aes_dec_last_round_x4 (r[0], k[i]);
      _mm512_mask_storeu_epi64 ((__m512i *) dst, m, (__m512i) (r[0] ^ f));
      f = c[0];
      n_blocks -= 4;
      src += 1;
      dst += 1;
    }
}
#endif
#endif

#ifdef __VAES__
#define N 16
#define u32xN u32x16
#define u32xN_min_scalar u32x16_min_scalar
#define u32xN_is_all_zero u32x16_is_all_zero
#define u32xN_splat u32x16_splat
#else
#define N 4
#define u32xN u32x4
#define u32xN_min_scalar u32x4_min_scalar
#define u32xN_is_all_zero u32x4_is_all_zero
#define u32xN_splat u32x4_splat
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
  vnet_crypto_key_index_t key_index[N];
  u8 *src[N] = { };
  u8 *dst[N] = { };
#if __VAES__
  u8x64 r[N / 4] = { };
  u8x64 k[15][N / 4] = { };
  u8x16 *kq, *rq = (u8x16 *) r;
#else
  u8x16 r[N] = { };
  u8x16 k[15][N] = { };
#endif

  for (i = 0; i < N; i++)
    key_index[i] = ~0;

more:
  for (i = 0; i < N; i++)
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
#if __VAES__
	    rq[i] = t;
#else
	    r[i] = t;
#endif

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
		  {
#if __VAES__
		    kq = (u8x16 *) k[j];
		    kq[i] = kd->encrypt_key[j];
#else
		    k[j][i] = kd->encrypt_key[j];
#endif
		  }
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
#ifdef __VAES__
      r[0] = u8x64_xor3 (r[0], aes_block_load_x4 (src, i), k[0][0]);
      r[1] = u8x64_xor3 (r[1], aes_block_load_x4 (src, i), k[0][1]);
      r[2] = u8x64_xor3 (r[2], aes_block_load_x4 (src, i), k[0][2]);
      r[3] = u8x64_xor3 (r[3], aes_block_load_x4 (src, i), k[0][3]);

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
#else
#if __x86_64__
      r[0] = u8x16_xor3 (r[0], aes_block_load (src[0] + i), k[0][0]);
      r[1] = u8x16_xor3 (r[1], aes_block_load (src[1] + i), k[0][1]);
      r[2] = u8x16_xor3 (r[2], aes_block_load (src[2] + i), k[0][2]);
      r[3] = u8x16_xor3 (r[3], aes_block_load (src[3] + i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round (r[0], k[j][0]);
	  r[1] = aes_enc_round (r[1], k[j][1]);
	  r[2] = aes_enc_round (r[2], k[j][2]);
	  r[3] = aes_enc_round (r[3], k[j][3]);
	}

      r[0] = aes_enc_last_round (r[0], k[j][0]);
      r[1] = aes_enc_last_round (r[1], k[j][1]);
      r[2] = aes_enc_last_round (r[2], k[j][2]);
      r[3] = aes_enc_last_round (r[3], k[j][3]);

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

  for (i = 0; i < N; i++)
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
#ifdef __VAES__
  vaes_cbc_dec (kd->decrypt_key, (u8x64u *) op->src, (u8x64u *) op->dst,
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

static_always_inline void *
aes_cbc_key_exp (vnet_crypto_key_t * key, aes_key_size_t ks)
{
  u8x16 e[15], d[15];
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  aes_key_expand (e, key->data, ks);
  aes_key_enc_to_dec (e, d, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    {
#if __VAES__
      kd->decrypt_key[i] = (u8x64) _mm512_broadcast_i64x2 ((__m128i) d[i]);
#else
      kd->decrypt_key[i] = d[i];
#endif
      kd->encrypt_key[i] = e[i];
    }
  return kd;
}

#define foreach_aes_cbc_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aes_ops_dec_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aes_ops_dec_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static u32 aes_ops_enc_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aes_ops_enc_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static void * aes_cbc_key_exp_##x (vnet_crypto_key_t *key) \
{ return aes_cbc_key_exp (key, AES_KEY_##x); }

foreach_aes_cbc_handler_type;
#undef _

#include <fcntl.h>

clib_error_t *
#ifdef __VAES__
crypto_native_aes_cbc_init_icl (vlib_main_t * vm)
#elif __AVX512F__
crypto_native_aes_cbc_init_skx (vlib_main_t * vm)
#elif __aarch64__
crypto_native_aes_cbc_init_neon (vlib_main_t * vm)
#elif __AVX2__
crypto_native_aes_cbc_init_hsw (vlib_main_t * vm)
#else
crypto_native_aes_cbc_init_slm (vlib_main_t * vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;

#define _(x) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_ENC, \
				    aes_ops_enc_aes_cbc_##x); \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_DEC, \
				    aes_ops_dec_aes_cbc_##x); \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_CBC] = aes_cbc_key_exp_##x;
  foreach_aes_cbc_handler_type;
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
