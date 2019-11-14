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
#include <x86intrin.h>
#include <crypto_ia32/crypto_ia32.h>
#include <crypto_ia32/aesni.h>
#include <crypto_ia32/ghash.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct
{
  /* pre-calculated hash key values */
  const __m128i Hi[8];
  /* extracted AES key */
  const __m128i Ke[15];
} aes_gcm_key_data_t;

static const __m128i last_byte_one = { 0, 1ULL << 56 };
static const __m128i zero = { 0, 0 };

static const u8x16 bswap_mask = {
  15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const u8x16 byte_mask_scale = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

static_always_inline __m128i
aesni_gcm_bswap (__m128i x)
{
  return _mm_shuffle_epi8 (x, (__m128i) bswap_mask);
}

static_always_inline __m128i
aesni_gcm_byte_mask (__m128i x, u8 n_bytes)
{
  u8x16 mask = u8x16_is_greater (u8x16_splat (n_bytes), byte_mask_scale);

  return _mm_blendv_epi8 (zero, x, (__m128i) mask);
}

static_always_inline __m128i
aesni_gcm_load_partial (__m128i * p, int n_bytes)
{
#ifdef __AVX512F__
  return _mm_mask_loadu_epi8 (zero, (1 << n_bytes) - 1, p);
#else
  return aesni_gcm_byte_mask (_mm_loadu_si128 (p), n_bytes);
#endif
}

static_always_inline void
aesni_gcm_store_partial (void *p, __m128i r, int n_bytes)
{
#ifdef __AVX512F__
  _mm_mask_storeu_epi8 (p, (1 << n_bytes) - 1, r);
#else
  u8x16 mask = u8x16_is_greater (u8x16_splat (n_bytes), byte_mask_scale);
  _mm_maskmoveu_si128 (r, (__m128i) mask, p);
#endif
}

static_always_inline void
aesni_gcm_load (__m128i * d, __m128i * inv, int n, int n_bytes)
{
  for (int i = 0; i < n - 1; i++)
    d[i] = _mm_loadu_si128 (inv + i);
  d[n - 1] = n_bytes ? aesni_gcm_load_partial (inv + n - 1, n_bytes) :
    _mm_loadu_si128 (inv + n - 1);
}

static_always_inline void
aesni_gcm_store (__m128i * d, __m128i * outv, int n, int n_bytes)
{
  for (int i = 0; i < n - 1; i++)
    _mm_storeu_si128 (outv + i, d[i]);
  if (n_bytes & 0xf)
    aesni_gcm_store_partial (outv + n - 1, d[n - 1], n_bytes);
  else
    _mm_storeu_si128 (outv + n - 1, d[n - 1]);
}

static_always_inline void
aesni_gcm_enc_first_round (__m128i * r, __m128i * Y, u32 * ctr, __m128i k,
			   int n_blocks)
{
  u32 i;

  if (PREDICT_TRUE ((u8) ctr[0] < (256 - n_blocks)))
    {
      for (i = 0; i < n_blocks; i++)
	{
	  Y[0] = _mm_add_epi32 (Y[0], last_byte_one);
	  r[i] = k ^ Y[0];
	}
      ctr[0] += n_blocks;
    }
  else
    {
      for (i = 0; i < n_blocks; i++)
	{
	  Y[0] = _mm_insert_epi32 (Y[0], clib_host_to_net_u32 (++ctr[0]), 3);
	  r[i] = k ^ Y[0];
	}
    }
}

static_always_inline void
aesni_gcm_enc_round (__m128i * r, __m128i k, int n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
    r[i] = _mm_aesenc_si128 (r[i], k);
}

static_always_inline void
aesni_gcm_enc_last_round (__m128i * r, __m128i * d, const __m128i * k,
			  int rounds, int n_blocks)
{

  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < rounds; i++)
    aesni_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
    d[i] ^= _mm_aesenclast_si128 (r[i], k[rounds]);
}

static_always_inline __m128i
aesni_gcm_ghash_blocks (__m128i T, aes_gcm_key_data_t * kd,
			const __m128i * in, int n_blocks)
{
  ghash_data_t _gd, *gd = &_gd;
  const __m128i *Hi = kd->Hi + n_blocks - 1;
  ghash_mul_first (gd, aesni_gcm_bswap (_mm_loadu_si128 (in)) ^ T, Hi[0]);
  for (int i = 1; i < n_blocks; i++)
    ghash_mul_next (gd, aesni_gcm_bswap (_mm_loadu_si128 (in + i)), Hi[-i]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}

static_always_inline __m128i
aesni_gcm_ghash (__m128i T, aes_gcm_key_data_t * kd, const __m128i * in,
		 u32 n_left)
{

  while (n_left >= 128)
    {
      T = aesni_gcm_ghash_blocks (T, kd, in, 8);
      n_left -= 128;
      in += 8;
    }

  if (n_left >= 64)
    {
      T = aesni_gcm_ghash_blocks (T, kd, in, 4);
      n_left -= 64;
      in += 4;
    }

  if (n_left >= 32)
    {
      T = aesni_gcm_ghash_blocks (T, kd, in, 2);
      n_left -= 32;
      in += 2;
    }

  if (n_left >= 16)
    {
      T = aesni_gcm_ghash_blocks (T, kd, in, 1);
      n_left -= 16;
      in += 1;
    }

  if (n_left)
    {
      __m128i r = aesni_gcm_load_partial ((__m128i *) in, n_left);
      T = ghash_mul (aesni_gcm_bswap (r) ^ T, kd->Hi[0]);
    }
  return T;
}

static_always_inline __m128i
aesni_gcm_calc (__m128i T, aes_gcm_key_data_t * kd, __m128i * d,
		__m128i * Y, u32 * ctr, __m128i * inv, __m128i * outv,
		int rounds, int n, int last_block_bytes, int with_ghash,
		int is_encrypt)
{
  __m128i r[n];
  ghash_data_t _gd = { }, *gd = &_gd;
  const __m128i *k = kd->Ke;
  int hidx = is_encrypt ? 4 : n, didx = 0;

  _mm_prefetch (inv + 4, _MM_HINT_T0);

  /* AES rounds 0 and 1 */
  aesni_gcm_enc_first_round (r, Y, ctr, k[0], n);
  aesni_gcm_enc_round (r, k[1], n);

  /* load data - decrypt round */
  if (is_encrypt == 0)
    aesni_gcm_load (d, inv, n, last_block_bytes);

  /* GHASH multiply block 1 */
  if (with_ghash)
    ghash_mul_first (gd, aesni_gcm_bswap (d[didx++]) ^ T, kd->Hi[--hidx]);

  /* AES rounds 2 and 3 */
  aesni_gcm_enc_round (r, k[2], n);
  aesni_gcm_enc_round (r, k[3], n);

  /* GHASH multiply block 2 */
  if (with_ghash && hidx)
    ghash_mul_next (gd, aesni_gcm_bswap (d[didx++]), kd->Hi[--hidx]);

  /* AES rounds 4 and 5 */
  aesni_gcm_enc_round (r, k[4], n);
  aesni_gcm_enc_round (r, k[5], n);

  /* GHASH multiply block 3 */
  if (with_ghash && hidx)
    ghash_mul_next (gd, aesni_gcm_bswap (d[didx++]), kd->Hi[--hidx]);

  /* AES rounds 6 and 7 */
  aesni_gcm_enc_round (r, k[6], n);
  aesni_gcm_enc_round (r, k[7], n);

  /* GHASH multiply block 4 */
  if (with_ghash && hidx)
    ghash_mul_next (gd, aesni_gcm_bswap (d[didx++]), kd->Hi[--hidx]);

  /* AES rounds 8 and 9 */
  aesni_gcm_enc_round (r, k[8], n);
  aesni_gcm_enc_round (r, k[9], n);

  /* GHASH reduce 1st step */
  if (with_ghash)
    ghash_reduce (gd);

  /* load data - encrypt round */
  if (is_encrypt)
    aesni_gcm_load (d, inv, n, last_block_bytes);

  /* GHASH reduce 2nd step */
  if (with_ghash)
    ghash_reduce2 (gd);

  /* AES last round(s) */
  aesni_gcm_enc_last_round (r, d, k, rounds, n);

  /* store data */
  aesni_gcm_store (d, outv, n, last_block_bytes);

  /* GHASH final step */
  if (with_ghash)
    T = ghash_final (gd);

  return T;
}

static_always_inline __m128i
aesni_gcm_calc_double (__m128i T, aes_gcm_key_data_t * kd, __m128i * d,
		       __m128i * Y, u32 * ctr, __m128i * inv, __m128i * outv,
		       int rounds, int is_encrypt)
{
  __m128i r[4];
  ghash_data_t _gd, *gd = &_gd;
  const __m128i *k = kd->Ke;

  /* AES rounds 0 and 1 */
  aesni_gcm_enc_first_round (r, Y, ctr, k[0], 4);
  aesni_gcm_enc_round (r, k[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (is_encrypt == 0)
    aesni_gcm_load (d, inv, 4, 0);

  /* GHASH multiply block 0 */
  ghash_mul_first (gd, aesni_gcm_bswap (d[0]) ^ T, kd->Hi[7]);

  /* AES rounds 2 and 3 */
  aesni_gcm_enc_round (r, k[2], 4);
  aesni_gcm_enc_round (r, k[3], 4);

  /* GHASH multiply block 1 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[1]), kd->Hi[6]);

  /* AES rounds 4 and 5 */
  aesni_gcm_enc_round (r, k[4], 4);
  aesni_gcm_enc_round (r, k[5], 4);

  /* GHASH multiply block 2 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[2]), kd->Hi[5]);

  /* AES rounds 6 and 7 */
  aesni_gcm_enc_round (r, k[6], 4);
  aesni_gcm_enc_round (r, k[7], 4);

  /* GHASH multiply block 3 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[3]), kd->Hi[4]);

  /* AES rounds 8 and 9 */
  aesni_gcm_enc_round (r, k[8], 4);
  aesni_gcm_enc_round (r, k[9], 4);

  /* load 4 blocks of data - encrypt round */
  if (is_encrypt)
    aesni_gcm_load (d, inv, 4, 0);

  /* AES last round(s) */
  aesni_gcm_enc_last_round (r, d, k, rounds, 4);

  /* store 4 blocks of data */
  aesni_gcm_store (d, outv, 4, 0);

  /* load next 4 blocks of data data - decrypt round */
  if (is_encrypt == 0)
    aesni_gcm_load (d, inv + 4, 4, 0);

  /* GHASH multiply block 4 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[0]), kd->Hi[3]);

  /* AES rounds 0, 1 and 2 */
  aesni_gcm_enc_first_round (r, Y, ctr, k[0], 4);
  aesni_gcm_enc_round (r, k[1], 4);
  aesni_gcm_enc_round (r, k[2], 4);

  /* GHASH multiply block 5 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[1]), kd->Hi[2]);

  /* AES rounds 3 and 4 */
  aesni_gcm_enc_round (r, k[3], 4);
  aesni_gcm_enc_round (r, k[4], 4);

  /* GHASH multiply block 6 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[2]), kd->Hi[1]);

  /* AES rounds 5 and 6 */
  aesni_gcm_enc_round (r, k[5], 4);
  aesni_gcm_enc_round (r, k[6], 4);

  /* GHASH multiply block 7 */
  ghash_mul_next (gd, aesni_gcm_bswap (d[3]), kd->Hi[0]);

  /* AES rounds 7 and 8 */
  aesni_gcm_enc_round (r, k[7], 4);
  aesni_gcm_enc_round (r, k[8], 4);

  /* GHASH reduce 1st step */
  ghash_reduce (gd);

  /* AES round 9 */
  aesni_gcm_enc_round (r, k[9], 4);

  /* load data - encrypt round */
  if (is_encrypt)
    aesni_gcm_load (d, inv + 4, 4, 0);

  /* GHASH reduce 2nd step */
  ghash_reduce2 (gd);

  /* AES last round(s) */
  aesni_gcm_enc_last_round (r, d, k, rounds, 4);

  /* store data */
  aesni_gcm_store (d, outv + 4, 4, 0);

  /* GHASH final step */
  return ghash_final (gd);
}

static_always_inline __m128i
aesni_gcm_ghash_last (__m128i T, aes_gcm_key_data_t * kd, __m128i * d,
		      int n_blocks, int n_bytes)
{
  ghash_data_t _gd, *gd = &_gd;

  if (n_bytes)
    d[n_blocks - 1] = aesni_gcm_byte_mask (d[n_blocks - 1], n_bytes);

  ghash_mul_first (gd, aesni_gcm_bswap (d[0]) ^ T, kd->Hi[n_blocks - 1]);
  if (n_blocks > 1)
    ghash_mul_next (gd, aesni_gcm_bswap (d[1]), kd->Hi[n_blocks - 2]);
  if (n_blocks > 2)
    ghash_mul_next (gd, aesni_gcm_bswap (d[2]), kd->Hi[n_blocks - 3]);
  if (n_blocks > 3)
    ghash_mul_next (gd, aesni_gcm_bswap (d[3]), kd->Hi[n_blocks - 4]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}


static_always_inline __m128i
aesni_gcm_enc (__m128i T, aes_gcm_key_data_t * kd, __m128i Y, const u8 * in,
	       const u8 * out, u32 n_left, int rounds)
{
  __m128i *inv = (__m128i *) in, *outv = (__m128i *) out;
  __m128i d[4];
  u32 ctr = 1;

  if (n_left == 0)
    return T;

  if (n_left < 64)
    {
      if (n_left > 48)
	{
	  n_left &= 0x0f;
	  aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4, n_left,
			  /* with_ghash */ 0, /* is_encrypt */ 1);
	  return aesni_gcm_ghash_last (T, kd, d, 4, n_left);
	}
      else if (n_left > 32)
	{
	  n_left &= 0x0f;
	  aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 3, n_left,
			  /* with_ghash */ 0, /* is_encrypt */ 1);
	  return aesni_gcm_ghash_last (T, kd, d, 3, n_left);
	}
      else if (n_left > 16)
	{
	  n_left &= 0x0f;
	  aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 2, n_left,
			  /* with_ghash */ 0, /* is_encrypt */ 1);
	  return aesni_gcm_ghash_last (T, kd, d, 2, n_left);
	}
      else
	{
	  n_left &= 0x0f;
	  aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 1, n_left,
			  /* with_ghash */ 0, /* is_encrypt */ 1);
	  return aesni_gcm_ghash_last (T, kd, d, 1, n_left);
	}
    }

  aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4, 0,
		  /* with_ghash */ 0, /* is_encrypt */ 1);

  /* next */
  n_left -= 64;
  outv += 4;
  inv += 4;

  while (n_left >= 128)
    {
      T = aesni_gcm_calc_double (T, kd, d, &Y, &ctr, inv, outv, rounds,
				 /* is_encrypt */ 1);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4, 0,
			  /* with_ghash */ 1, /* is_encrypt */ 1);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    return aesni_gcm_ghash_last (T, kd, d, 4, 0);

  if (n_left > 48)
    {
      n_left &= 0x0f;
      T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4, n_left,
			  /* with_ghash */ 1, /* is_encrypt */ 1);
      return aesni_gcm_ghash_last (T, kd, d, 4, n_left);
    }

  if (n_left > 32)
    {
      n_left &= 0x0f;
      T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 3, n_left,
			  /* with_ghash */ 1, /* is_encrypt */ 1);
      return aesni_gcm_ghash_last (T, kd, d, 3, n_left);
    }

  if (n_left > 16)
    {
      n_left &= 0x0f;
      T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 2, n_left,
			  /* with_ghash */ 1, /* is_encrypt */ 1);
      return aesni_gcm_ghash_last (T, kd, d, 2, n_left);
    }

  n_left &= 0x0f;
  T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 1, n_left,
		      /* with_ghash */ 1, /* is_encrypt */ 1);
  return aesni_gcm_ghash_last (T, kd, d, 1, n_left);
}

static_always_inline __m128i
aesni_gcm_dec (__m128i T, aes_gcm_key_data_t * kd, __m128i Y, const u8 * in,
	       const u8 * out, u32 n_left, int rounds)
{
  __m128i *inv = (__m128i *) in, *outv = (__m128i *) out;
  __m128i d[8];
  u32 ctr = 1;

  while (n_left >= 128)
    {
      T = aesni_gcm_calc_double (T, kd, d, &Y, &ctr, inv, outv, rounds,
				 /* is_encrypt */ 0);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      T = aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4, 0, 1, 0);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    return T;

  if (n_left > 48)
    return aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 4,
			   n_left - 48,
			   /* with_ghash */ 1, /* is_encrypt */ 0);

  if (n_left > 32)
    return aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 3,
			   n_left - 32,
			   /* with_ghash */ 1, /* is_encrypt */ 0);

  if (n_left > 16)
    return aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 2,
			   n_left - 16,
			   /* with_ghash */ 1, /* is_encrypt */ 0);

  return aesni_gcm_calc (T, kd, d, &Y, &ctr, inv, outv, rounds, 1, n_left,
			 /* with_ghash */ 1, /* is_encrypt */ 0);
}

static_always_inline int
aes_gcm (const u8 * in, u8 * out, const u8 * addt, const u8 * iv, u8 * tag,
	 u32 data_bytes, u32 aad_bytes, u8 tag_len, aes_gcm_key_data_t * kd,
	 int aes_rounds, int is_encrypt)
{
  int i;
  __m128i r, Y0, T = { };
  ghash_data_t _gd, *gd = &_gd;

  _mm_prefetch (iv, _MM_HINT_T0);
  _mm_prefetch (in, _MM_HINT_T0);
  _mm_prefetch (in + CLIB_CACHE_LINE_BYTES, _MM_HINT_T0);

  /* calculate ghash for AAD - optimized for ipsec common cases */
  if (aad_bytes == 8)
    T = aesni_gcm_ghash (T, kd, (__m128i *) addt, 8);
  else if (aad_bytes == 12)
    T = aesni_gcm_ghash (T, kd, (__m128i *) addt, 12);
  else
    T = aesni_gcm_ghash (T, kd, (__m128i *) addt, aad_bytes);

  /* initalize counter */
  Y0 = _mm_loadu_si128 ((__m128i *) iv);
  Y0 = _mm_insert_epi32 (Y0, clib_host_to_net_u32 (1), 3);

  /* ghash and encrypt/edcrypt  */
  if (is_encrypt)
    T = aesni_gcm_enc (T, kd, Y0, in, out, data_bytes, aes_rounds);
  else
    T = aesni_gcm_dec (T, kd, Y0, in, out, data_bytes, aes_rounds);

  _mm_prefetch (tag, _MM_HINT_T0);

  /* Finalize ghash */
  r[0] = data_bytes;
  r[1] = aad_bytes;

  /* bytes to bits */
  r <<= 3;

  /* interleaved computation of final ghash and E(Y0, k) */
  ghash_mul_first (gd, r ^ T, kd->Hi[0]);
  r = kd->Ke[0] ^ Y0;
  for (i = 1; i < 5; i += 1)
    r = _mm_aesenc_si128 (r, kd->Ke[i]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  for (; i < 9; i += 1)
    r = _mm_aesenc_si128 (r, kd->Ke[i]);
  T = ghash_final (gd);
  for (; i < aes_rounds; i += 1)
    r = _mm_aesenc_si128 (r, kd->Ke[i]);
  r = _mm_aesenclast_si128 (r, kd->Ke[aes_rounds]);
  T = aesni_gcm_bswap (T) ^ r;

  /* tag_len 16 -> 0 */
  tag_len &= 0xf;

  if (is_encrypt)
    {
      /* store tag */
      if (tag_len)
	aesni_gcm_store_partial ((__m128i *) tag, T, (1 << tag_len) - 1);
      else
	_mm_storeu_si128 ((__m128i *) tag, T);
    }
  else
    {
      /* check tag */
      u16 tag_mask = tag_len ? (1 << tag_len) - 1 : 0xffff;
      r = _mm_loadu_si128 ((__m128i *) tag);
      if (_mm_movemask_epi8 (r == T) != tag_mask)
	return 0;
    }
  return 1;
}

static_always_inline u32
aesni_ops_enc_aes_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aesni_key_size_t ks)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;


next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  aes_gcm (op->src, op->dst, op->aad, op->iv, op->tag, op->len, op->aad_len,
	   op->tag_len, kd, AESNI_KEY_ROUNDS (ks), /* is_encrypt */ 1);
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
		       u32 n_ops, aesni_key_size_t ks)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  rv = aes_gcm (op->src, op->dst, op->aad, op->iv, op->tag, op->len,
		op->aad_len, op->tag_len, kd, AESNI_KEY_ROUNDS (ks),
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
aesni_gcm_key_exp (vnet_crypto_key_t * key, aesni_key_size_t ks)
{
  aes_gcm_key_data_t *kd;
  __m128i H;
  int i;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  /* expand AES key */
  aes_key_expand ((__m128i *) kd->Ke, key->data, ks);

  /* pre-calculate H */
  H = kd->Ke[0];
  for (i = 1; i < AESNI_KEY_ROUNDS (ks); i += 1)
    H = _mm_aesenc_si128 (H, kd->Ke[i]);
  H = _mm_aesenclast_si128 (H, kd->Ke[i]);
  H = aesni_gcm_bswap (H);
  ghash_precompute (H, (__m128i *) kd->Hi, 8);
  return kd;
}

#define foreach_aesni_gcm_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[],                                 \
 vnet_crypto_op_chunk_t chunks[], u32 n_ops)                                 \
{ return aesni_ops_dec_aes_gcm (vm, ops, n_ops, AESNI_KEY_##x); }            \
static u32 aesni_ops_enc_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[],                                 \
  vnet_crypto_op_chunk_t chunks[], u32 n_ops)                                \
{ return aesni_ops_enc_aes_gcm (vm, ops, n_ops, AESNI_KEY_##x); }            \
static void * aesni_gcm_key_exp_##x (vnet_crypto_key_t *key)                 \
{ return aesni_gcm_key_exp (key, AESNI_KEY_##x); }

foreach_aesni_gcm_handler_type;
#undef _

clib_error_t *
#ifdef __AVX512F__
crypto_ia32_aesni_gcm_init_avx512 (vlib_main_t * vm)
#elif __AVX2__
crypto_ia32_aesni_gcm_init_avx2 (vlib_main_t * vm)
#else
crypto_ia32_aesni_gcm_init_sse42 (vlib_main_t * vm)
#endif
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;

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
