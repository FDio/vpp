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
 * __i128 Hi[4];
 * ghash_precompute (H, Hi, 4);
 *
 * ghash_data_t _gd, *gd = &_gd;
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

/* on AVX-512 systems we can save a clock cycle by using ternary logic
   instruction to calculate a XOR b XOR c */
static_always_inline u8x16
ghash_xor3 (u8x16 a, u8x16 b, u8x16 c)
{
#if defined (__AVX512F__)
  return (u8x16) _mm_ternarylogic_epi32 ((__m128i) a, (__m128i) b,
					 (__m128i) c, 0x96);
#endif
  return a ^ b ^ c;
}

static_always_inline u8x16
gmul_lo_lo (u8x16 a, u8x16 b)
{
#if defined (__PCLMUL__)
  return (u8x16) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x00);
#elif defined (__ARM_FEATURE_CRYPTO)
  return (u8x16) vmull_p64 ((poly64_t) vget_low_p64 ((poly64x2_t) a),
			    (poly64_t) vget_low_p64 ((poly64x2_t) b));
#endif
}

static_always_inline u8x16
gmul_hi_lo (u8x16 a, u8x16 b)
{
#if defined (__PCLMUL__)
  return (u8x16) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x01);
#elif defined (__ARM_FEATURE_CRYPTO)
  return (u8x16) vmull_p64 ((poly64_t) vget_high_p64 ((poly64x2_t) a),
			    (poly64_t) vget_low_p64 ((poly64x2_t) b));
#endif
}

static_always_inline u8x16
gmul_lo_hi (u8x16 a, u8x16 b)
{
#if defined (__PCLMUL__)
  return (u8x16) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x10);
#elif defined (__ARM_FEATURE_CRYPTO)
  return (u8x16) vmull_p64 ((poly64_t) vget_low_p64 ((poly64x2_t) a),
			    (poly64_t) vget_high_p64 ((poly64x2_t) b));
#endif
}

static_always_inline u8x16
gmul_hi_hi (u8x16 a, u8x16 b)
{
#if defined (__PCLMUL__)
  return (u8x16) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x11);
#elif defined (__ARM_FEATURE_CRYPTO)
  return (u8x16) vmull_high_p64 ((poly64x2_t) a, (poly64x2_t) b);
#endif
}

typedef struct
{
  u8x16 mid, hi, lo, tmp_lo, tmp_hi;
  int pending;
} ghash_data_t;

static const u8x16 ghash_poly = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
};

static const u8x16 ghash_poly2 = {
  0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
};

static_always_inline void
ghash_mul_first (ghash_data_t * gd, u8x16 a, u8x16 b)
{
  /* a1 * b1 */
  gd->hi = gmul_hi_hi (a, b);
  /* a0 * b0 */
  gd->lo = gmul_lo_lo (a, b);
  /* a0 * b1 ^ a1 * b0 */
  gd->mid = (gmul_hi_lo (a, b) ^ gmul_lo_hi (a, b));

  /* set gd->pending to 0 so next invocation of ghash_mul_next(...) knows that
     there is no pending data in tmp_lo and tmp_hi */
  gd->pending = 0;
}

static_always_inline void
ghash_mul_next (ghash_data_t * gd, u8x16 a, u8x16 b)
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
      gd->hi = ghash_xor3 (gd->hi, gd->tmp_hi, hi);
      gd->lo = ghash_xor3 (gd->lo, gd->tmp_lo, lo);
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
  gd->mid = ghash_xor3 (gd->mid, gmul_hi_lo (a, b), gmul_lo_hi (a, b));
}

static_always_inline void
ghash_reduce (ghash_data_t * gd)
{
  u8x16 r;

  /* Final combination:
     gd->lo ^= gd->mid << 64
     gd->hi ^= gd->mid >> 64 */
  u8x16 midl = u8x16_word_shift_left (gd->mid, 8);
  u8x16 midr = u8x16_word_shift_right (gd->mid, 8);

  if (gd->pending)
    {
      gd->lo = ghash_xor3 (gd->lo, gd->tmp_lo, midl);
      gd->hi = ghash_xor3 (gd->hi, gd->tmp_hi, midr);
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
ghash_reduce2 (ghash_data_t * gd)
{
  gd->tmp_lo = gmul_lo_lo (ghash_poly2, gd->lo);
  gd->tmp_hi = gmul_lo_hi (ghash_poly2, gd->lo);
}

static_always_inline u8x16
ghash_final (ghash_data_t * gd)
{
  return ghash_xor3 (gd->hi, u8x16_word_shift_right (gd->tmp_lo, 4),
		     u8x16_word_shift_left (gd->tmp_hi, 4));
}

static_always_inline u8x16
ghash_mul (u8x16 a, u8x16 b)
{
  ghash_data_t _gd, *gd = &_gd;
  ghash_mul_first (gd, a, b);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}

static_always_inline void
ghash_precompute (u8x16 H, u8x16 * Hi, int count)
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
  /* *INDENT-OFF* */
  r32 = r32 == (u32x4) {1, 0, 0, 1};
  /* *INDENT-ON* */
  Hi[0] = H ^ ((u8x16) r32 & ghash_poly);

  /* calculate H^(i + 1) */
  for (int i = 1; i < count; i++)
    Hi[i] = ghash_mul (Hi[0], Hi[i - 1]);
}

#endif /* __ghash_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
