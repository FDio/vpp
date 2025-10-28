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

/*
 *------------------------------------------------------------------
 *  Copyright(c) 2018, Intel Corporation All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES * LOSS OF USE,
 *  DATA, OR PROFITS * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *------------------------------------------------------------------
 */

/*
 * Based on work by: Shay Gueron, Michael E. Kounavis, Erdinc Ozturk,
 *                   Vinodh Gopal, James Guilford, Tomasz Kantecki
 *
 * References:
 * [1] Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on
 *     Intel Architecture Processors. August, 2010
 * [2] Erdinc Ozturk et. al. Enabling High-Performance Galois-Counter-Mode on
 *     Intel Architecture Processors. October, 2012.
 * [3] intel-ipsec-mb library, https://github.com/01org/intel-ipsec-mb.git
 *
 * Definitions:
 *  GF    Galois Extension Field GF(2^128) - finite field where elements are
 *        represented as polynomials with coefficients in GF(2) with the
 *        highest degree of 127. Polynomials are represented as 128-bit binary
 *        numbers where each bit represents one coefficient.
 *        e.g. polynomial x^5 + x^3 + x + 1 is represented in binary 101011.
 *  H     hash key (128 bit)
 *  POLY  irreducible polynomial x^127 + x^7 + x^2 + x + 1
 *  RPOLY irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1
 *  +     addition in GF, which equals to XOR operation
 *  *     multiplication in GF
 *
 * GF multiplication consists of 2 steps:
 *  - carry-less multiplication of two 128-bit operands into 256-bit result
 *  - reduction of 256-bit result into 128-bit with modulo POLY
 *
 * GHash is calculated on 128-bit blocks of data according to the following
 * formula:
 *    GH = (GH + data) * hash_key
 *
 * To avoid bit-reflection of data, this code uses GF multipication
 * with reversed polynomial:
 *   a * b * x^-127 mod RPOLY
 *
 * To improve computation speed table Hi is precomputed with powers of H',
 * where H' is calculated as H<<1 mod RPOLY.
 * This allows us to improve performance by deferring reduction. For example
 * to caclulate ghash of 4 128-bit blocks of data (b0, b1, b2, b3), we can do:
 *
 * u8x16 Hi[4];
 * ghash_precompute (H, Hi, 4);
 *
 * ghash_ctx_t _gd, *gd = &_gd;
 * ghash_mul_first (gd, GH ^ b0, Hi[3]);
 * ghash_mul_next (gd, b1, Hi[2]);
 * ghash_mul_next (gd, b2, Hi[1]);
 * ghash_mul_next (gd, b3, Hi[0]);
 * ghash_reduce (gd);
 * ghash_reduce2 (gd);
 * GH = ghash_final (gd);
 *
 * Reduction step is split into 3 functions so it can be better interleaved
 * with other code, (i.e. with AES computation).
 */

#ifndef __ghash_h__
#define __ghash_h__

static_always_inline u8x16
gmul_lo_lo (u8x16 a, u8x16 b)
{
  return (u8x16) u64x2_clmul64 ((u64x2) a, 0, (u64x2) b, 0);
}

static_always_inline u8x16
gmul_hi_lo (u8x16 a, u8x16 b)
{
  return (u8x16) u64x2_clmul64 ((u64x2) a, 1, (u64x2) b, 0);
}

static_always_inline u8x16
gmul_lo_hi (u8x16 a, u8x16 b)
{
  return (u8x16) u64x2_clmul64 ((u64x2) a, 0, (u64x2) b, 1);
}

static_always_inline u8x16
gmul_hi_hi (u8x16 a, u8x16 b)
{
  return (u8x16) u64x2_clmul64 ((u64x2) a, 1, (u64x2) b, 1);
}

typedef struct
{
  u8x16 mid, hi, lo, tmp_lo, tmp_hi;
  u8x32 hi2, lo2, mid2, tmp_lo2, tmp_hi2;
  u8x64 hi4, lo4, mid4, tmp_lo4, tmp_hi4;
  int pending;
} ghash_ctx_t;

static const u8x16 ghash_poly = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
};

static const u8x16 ghash_poly2 = {
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
};

static_always_inline void
ghash_mul_first (ghash_ctx_t *gd, u8x16 a, u8x16 b)
{
  /* a1 * b1 */
  gd->hi = gmul_hi_hi (a, b);
  /* a0 * b0 */
  gd->lo = gmul_lo_lo (a, b);
  /* a0 * b1 ^ a1 * b0 */
  gd->mid = gmul_hi_lo (a, b) ^ gmul_lo_hi (a, b);

  /* set gd->pending to 0 so next invocation of ghash_mul_next(...) knows that
     there is no pending data in tmp_lo and tmp_hi */
  gd->pending = 0;
}

static_always_inline void
ghash_mul_next (ghash_ctx_t *gd, u8x16 a, u8x16 b)
{
  /* a1 * b1 */
  u8x16 hi = gmul_hi_hi (a, b);
  /* a0 * b0 */
  u8x16 lo = gmul_lo_lo (a, b);

  /* this branch will be optimized out by the compiler, and it allows us to
     reduce number of XOR operations by using ternary logic */
  if (gd->pending)
    {
      /* there is peding data from previous invocation so we can XOR */
      gd->hi = u8x16_xor3 (gd->hi, gd->tmp_hi, hi);
      gd->lo = u8x16_xor3 (gd->lo, gd->tmp_lo, lo);
      gd->pending = 0;
    }
  else
    {
      /* there is no peding data from previous invocation so we postpone XOR */
      gd->tmp_hi = hi;
      gd->tmp_lo = lo;
      gd->pending = 1;
    }

  /* gd->mid ^= a0 * b1 ^ a1 * b0  */
  gd->mid = u8x16_xor3 (gd->mid, gmul_hi_lo (a, b), gmul_lo_hi (a, b));
}

static_always_inline void
ghash_reduce (ghash_ctx_t *gd)
{
  u8x16 r;

  /* Final combination:
     gd->lo ^= gd->mid << 64
     gd->hi ^= gd->mid >> 64 */
  u8x16 midl = u8x16_word_shift_left (gd->mid, 8);
  u8x16 midr = u8x16_word_shift_right (gd->mid, 8);

  if (gd->pending)
    {
      gd->lo = u8x16_xor3 (gd->lo, gd->tmp_lo, midl);
      gd->hi = u8x16_xor3 (gd->hi, gd->tmp_hi, midr);
    }
  else
    {
      gd->lo ^= midl;
      gd->hi ^= midr;
    }
  r = gmul_hi_lo (ghash_poly2, gd->lo);
  gd->lo ^= u8x16_word_shift_left (r, 8);
}

static_always_inline void
ghash_reduce2 (ghash_ctx_t *gd)
{
  gd->tmp_lo = gmul_lo_lo (ghash_poly2, gd->lo);
  gd->tmp_hi = gmul_lo_hi (ghash_poly2, gd->lo);
}

static_always_inline u8x16
ghash_final (ghash_ctx_t *gd)
{
  return u8x16_xor3 (gd->hi, u8x16_word_shift_right (gd->tmp_lo, 4),
		     u8x16_word_shift_left (gd->tmp_hi, 4));
}

static_always_inline u8x16
ghash_mul (u8x16 a, u8x16 b)
{
  ghash_ctx_t _gd, *gd = &_gd;
  ghash_mul_first (gd, a, b);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}

#if defined(__VPCLMULQDQ__) && defined(__AVX512F__)

static const u8x64 ghash4_poly2 = {
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
};

static_always_inline u8x64
gmul4_lo_lo (u8x64 a, u8x64 b)
{
  return (u8x64) _mm512_clmulepi64_epi128 ((__m512i) a, (__m512i) b, 0x00);
}

static_always_inline u8x64
gmul4_hi_lo (u8x64 a, u8x64 b)
{
  return (u8x64) _mm512_clmulepi64_epi128 ((__m512i) a, (__m512i) b, 0x01);
}

static_always_inline u8x64
gmul4_lo_hi (u8x64 a, u8x64 b)
{
  return (u8x64) _mm512_clmulepi64_epi128 ((__m512i) a, (__m512i) b, 0x10);
}

static_always_inline u8x64
gmul4_hi_hi (u8x64 a, u8x64 b)
{
  return (u8x64) _mm512_clmulepi64_epi128 ((__m512i) a, (__m512i) b, 0x11);
}

static_always_inline void
ghash4_mul_first (ghash_ctx_t *gd, u8x64 a, u8x64 b)
{
  gd->hi4 = gmul4_hi_hi (a, b);
  gd->lo4 = gmul4_lo_lo (a, b);
  gd->mid4 = gmul4_hi_lo (a, b) ^ gmul4_lo_hi (a, b);
  gd->pending = 0;
}

static_always_inline void
ghash4_mul_next (ghash_ctx_t *gd, u8x64 a, u8x64 b)
{
  u8x64 hi = gmul4_hi_hi (a, b);
  u8x64 lo = gmul4_lo_lo (a, b);

  if (gd->pending)
    {
      /* there is peding data from previous invocation so we can XOR */
      gd->hi4 = u8x64_xor3 (gd->hi4, gd->tmp_hi4, hi);
      gd->lo4 = u8x64_xor3 (gd->lo4, gd->tmp_lo4, lo);
      gd->pending = 0;
    }
  else
    {
      /* there is no peding data from previous invocation so we postpone XOR */
      gd->tmp_hi4 = hi;
      gd->tmp_lo4 = lo;
      gd->pending = 1;
    }
  gd->mid4 = u8x64_xor3 (gd->mid4, gmul4_hi_lo (a, b), gmul4_lo_hi (a, b));
}

static_always_inline void
ghash4_reduce (ghash_ctx_t *gd)
{
  u8x64 r;

  /* Final combination:
     gd->lo4 ^= gd->mid4 << 64
     gd->hi4 ^= gd->mid4 >> 64 */

  u8x64 midl = u8x64_word_shift_left (gd->mid4, 8);
  u8x64 midr = u8x64_word_shift_right (gd->mid4, 8);

  if (gd->pending)
    {
      gd->lo4 = u8x64_xor3 (gd->lo4, gd->tmp_lo4, midl);
      gd->hi4 = u8x64_xor3 (gd->hi4, gd->tmp_hi4, midr);
    }
  else
    {
      gd->lo4 ^= midl;
      gd->hi4 ^= midr;
    }

  r = gmul4_hi_lo (ghash4_poly2, gd->lo4);
  gd->lo4 ^= u8x64_word_shift_left (r, 8);
}

static_always_inline void
ghash4_reduce2 (ghash_ctx_t *gd)
{
  gd->tmp_lo4 = gmul4_lo_lo (ghash4_poly2, gd->lo4);
  gd->tmp_hi4 = gmul4_lo_hi (ghash4_poly2, gd->lo4);
}

static_always_inline u8x16
ghash4_final (ghash_ctx_t *gd)
{
  u8x64 r;
  u8x32 t;

  r = u8x64_xor3 (gd->hi4, u8x64_word_shift_right (gd->tmp_lo4, 4),
		  u8x64_word_shift_left (gd->tmp_hi4, 4));

  /* horizontal XOR of 4 128-bit lanes */
  t = u8x64_extract_lo (r) ^ u8x64_extract_hi (r);
  return u8x32_extract_hi (t) ^ u8x32_extract_lo (t);
}
#endif

#if defined(__VPCLMULQDQ__)

static const u8x32 ghash2_poly2 = {
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xc2, 0x00, 0x00, 0x00, 0xc2, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
};

static_always_inline u8x32
gmul2_lo_lo (u8x32 a, u8x32 b)
{
  return (u8x32) _mm256_clmulepi64_epi128 ((__m256i) a, (__m256i) b, 0x00);
}

static_always_inline u8x32
gmul2_hi_lo (u8x32 a, u8x32 b)
{
  return (u8x32) _mm256_clmulepi64_epi128 ((__m256i) a, (__m256i) b, 0x01);
}

static_always_inline u8x32
gmul2_lo_hi (u8x32 a, u8x32 b)
{
  return (u8x32) _mm256_clmulepi64_epi128 ((__m256i) a, (__m256i) b, 0x10);
}

static_always_inline u8x32
gmul2_hi_hi (u8x32 a, u8x32 b)
{
  return (u8x32) _mm256_clmulepi64_epi128 ((__m256i) a, (__m256i) b, 0x11);
}

static_always_inline void
ghash2_mul_first (ghash_ctx_t *gd, u8x32 a, u8x32 b)
{
  gd->hi2 = gmul2_hi_hi (a, b);
  gd->lo2 = gmul2_lo_lo (a, b);
  gd->mid2 = gmul2_hi_lo (a, b) ^ gmul2_lo_hi (a, b);
  gd->pending = 0;
}

static_always_inline void
ghash2_mul_next (ghash_ctx_t *gd, u8x32 a, u8x32 b)
{
  u8x32 hi = gmul2_hi_hi (a, b);
  u8x32 lo = gmul2_lo_lo (a, b);

  if (gd->pending)
    {
      /* there is peding data from previous invocation so we can XOR */
      gd->hi2 = u8x32_xor3 (gd->hi2, gd->tmp_hi2, hi);
      gd->lo2 = u8x32_xor3 (gd->lo2, gd->tmp_lo2, lo);
      gd->pending = 0;
    }
  else
    {
      /* there is no peding data from previous invocation so we postpone XOR */
      gd->tmp_hi2 = hi;
      gd->tmp_lo2 = lo;
      gd->pending = 1;
    }
  gd->mid2 = u8x32_xor3 (gd->mid2, gmul2_hi_lo (a, b), gmul2_lo_hi (a, b));
}

static_always_inline void
ghash2_reduce (ghash_ctx_t *gd)
{
  u8x32 r;

  /* Final combination:
     gd->lo2 ^= gd->mid2 << 64
     gd->hi2 ^= gd->mid2 >> 64 */

  u8x32 midl = u8x32_word_shift_left (gd->mid2, 8);
  u8x32 midr = u8x32_word_shift_right (gd->mid2, 8);

  if (gd->pending)
    {
      gd->lo2 = u8x32_xor3 (gd->lo2, gd->tmp_lo2, midl);
      gd->hi2 = u8x32_xor3 (gd->hi2, gd->tmp_hi2, midr);
    }
  else
    {
      gd->lo2 ^= midl;
      gd->hi2 ^= midr;
    }

  r = gmul2_hi_lo (ghash2_poly2, gd->lo2);
  gd->lo2 ^= u8x32_word_shift_left (r, 8);
}

static_always_inline void
ghash2_reduce2 (ghash_ctx_t *gd)
{
  gd->tmp_lo2 = gmul2_lo_lo (ghash2_poly2, gd->lo2);
  gd->tmp_hi2 = gmul2_lo_hi (ghash2_poly2, gd->lo2);
}

static_always_inline u8x16
ghash2_final (ghash_ctx_t *gd)
{
  u8x32 r;

  r = u8x32_xor3 (gd->hi2, u8x32_word_shift_right (gd->tmp_lo2, 4),
		  u8x32_word_shift_left (gd->tmp_hi2, 4));

  /* horizontal XOR of 2 128-bit lanes */
  return u8x32_extract_hi (r) ^ u8x32_extract_lo (r);
}
#endif

static_always_inline void
ghash_precompute (u8x16 H, u8x16 * Hi, int n)
{
  u8x16 r8;
  u32x4 r32;
  /* calcullate H<<1 mod poly from the hash key */
  r8 = (u8x16) ((u64x2) H >> 63);
  H = (u8x16) ((u64x2) H << 1);
  H |= u8x16_word_shift_left (r8, 8);
  r32 = (u32x4) u8x16_word_shift_right (r8, 8);
#ifdef __SSE2__
  r32 = u32x4_shuffle (r32, 0, 1, 2, 0);
#else
  r32[3] = r32[0];
#endif
  r32 = r32 == (u32x4) {1, 0, 0, 1};
  Hi[n - 1] = H = H ^ ((u8x16) r32 & ghash_poly);

  /* calculate H^(i + 1) */
  for (int i = n - 2; i >= 0; i--)
    Hi[i] = ghash_mul (H, Hi[i + 1]);
}

#endif /* __ghash_h__ */

