/*
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>

#if defined(CLIB_HAVE_VEC512)
#define u32xN		      u32x16
#define u32xNu		      u32x16u
#define u32xN_splat_u32x4     u32x16_splat_u32x4
#define u8xN		      u8x64
#define u8xN_load_partial     u8x64_load_partial
#define u8xN_store_partial    u8x64_store_partial
#define u32xN_bit_rotate_left u32x16_bit_rotate_left
#elif defined(CLIB_HAVE_VEC256)
#define u32xN		      u32x8
#define u32xNu		      u32x8u
#define u32xN_splat_u32x4     u32x8_splat_u32x4
#define u8xN		      u8x32
#define u8xN_load_partial     u8x32_load_partial
#define u8xN_store_partial    u8x32_store_partial
#define u32xN_bit_rotate_left u32x8_bit_rotate_left
#elif defined(CLIB_HAVE_VEC128)
#define u32xN		       u32x4
#define u32xNu		       u32x4u
#define u32xN_splat_u32x4(...) __VA_ARGS__
#define u8xN		       u8x16
#define u8xN_load_partial      u8x16_load_partial
#define u8xN_store_partial     u8x16_store_partial
#define u32xN_bit_rotate_left  u32x4_bit_rotate_left
#endif

#define CHACHA20_CONST_WORDS 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

static_always_inline void
clib_chacha20_rotate (u32xN *x1, u32xN *x2, u32xN *x3)
{
#if defined(CLIB_HAVE_VEC512)
  *x1 = u32x16_shuffle (*x1, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
  *x2 = u32x16_shuffle (*x2, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
  *x3 = u32x16_shuffle (*x3, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
#elif defined(CLIB_HAVE_VEC256)
  *x1 = u32x8_shuffle (*x1, 1, 2, 3, 0, 5, 6, 7, 4);
  *x2 = u32x8_shuffle (*x2, 2, 3, 0, 1, 6, 7, 4, 5);
  *x3 = u32x8_shuffle (*x3, 3, 0, 1, 2, 7, 4, 5, 6);
#else
  *x1 = u32x4_shuffle (*x1, 1, 2, 3, 0);
  *x2 = u32x4_shuffle (*x2, 2, 3, 0, 1);
  *x3 = u32x4_shuffle (*x3, 3, 0, 1, 2);
#endif
}

static_always_inline void
clib_chacha20_double_round (u32xN *x0, u32xN *x1, u32xN *x2, u32xN *x3)
{
  *x0 += *x1, *x3 ^= *x0, *x3 = u32xN_bit_rotate_left (*x3, 16);
  *x2 += *x3, *x1 ^= *x2, *x1 = u32xN_bit_rotate_left (*x1, 12);
  *x0 += *x1, *x3 ^= *x0, *x3 = u32xN_bit_rotate_left (*x3, 8);
  *x2 += *x3, *x1 ^= *x2, *x1 = u32xN_bit_rotate_left (*x1, 7);

  clib_chacha20_rotate (x1, x2, x3);

  *x0 += *x1, *x3 ^= *x0, *x3 = u32xN_bit_rotate_left (*x3, 16);
  *x2 += *x3, *x1 ^= *x2, *x1 = u32xN_bit_rotate_left (*x1, 12);
  *x0 += *x1, *x3 ^= *x0, *x3 = u32xN_bit_rotate_left (*x3, 8);
  *x2 += *x3, *x1 ^= *x2, *x1 = u32xN_bit_rotate_left (*x1, 7);

  clib_chacha20_rotate (x3, x2, x1);
}

static_always_inline void
clib_chacha20_load_store_partial (u32xN val, u32xNu *sv, u32xNu *dv, u64 length)
{
  if (length == sizeof (u32xNu))
    *dv = val ^ *sv;
  else
    {
      val ^= (u32xN) u8xN_load_partial ((u8 *) sv, length);
      u8xN_store_partial ((u8xN) val, (u8 *) dv, length);
    }
}

static_always_inline void
clib_chacha20_reorder_x4 (u32xN *x0, u32xN *x1, u32xN *x2, u32xN *x3)
{
#if defined(CLIB_HAVE_VEC512)
  u64x8 r0 = u64x8_shuffle2 ((u64x8) *x0, (u64x8) *x1, 0, 1, 8, 9, 4, 5, 12, 13);
  u64x8 r1 = u64x8_shuffle2 ((u64x8) *x0, (u64x8) *x1, 2, 3, 10, 11, 6, 7, 14, 15);
  u64x8 r2 = u64x8_shuffle2 ((u64x8) *x2, (u64x8) *x3, 0, 1, 8, 9, 4, 5, 12, 13);
  u64x8 r3 = u64x8_shuffle2 ((u64x8) *x2, (u64x8) *x3, 2, 3, 10, 11, 6, 7, 14, 15);

  *x0 = (u32xN) u64x8_shuffle2 (r0, r2, 0, 1, 2, 3, 8, 9, 10, 11);
  *x2 = (u32xN) u64x8_shuffle2 (r0, r2, 4, 5, 6, 7, 12, 13, 14, 15);
  *x1 = (u32xN) u64x8_shuffle2 (r1, r3, 0, 1, 2, 3, 8, 9, 10, 11);
  *x3 = (u32xN) u64x8_shuffle2 (r1, r3, 4, 5, 6, 7, 12, 13, 14, 15);
#elif defined(CLIB_HAVE_VEC256)
  u32xN r0 = u32x8_shuffle2 (*x0, *x1, 4, 5, 6, 7, 12, 13, 14, 15);
  u32xN r1 = u32x8_shuffle2 (*x2, *x3, 4, 5, 6, 7, 12, 13, 14, 15);
  *x0 = u32x8_shuffle2 (*x0, *x1, 0, 1, 2, 3, 8, 9, 10, 11);
  *x1 = u32x8_shuffle2 (*x2, *x3, 0, 1, 2, 3, 8, 9, 10, 11);
  *x2 = r0;
  *x3 = r1;
#endif
}

static_always_inline void
clib_chacha20_block_x16 (u32xNu *sv, u32xNu *dv, u32xN s0, u32xN s1, u32xN s2, u32xN s3)
{
  const u32 ctr_stride = sizeof (u32xN) / 16;
  u32xN s3l0, s3l1, s3l2, s3l3;
  u32xN a0, a1, a2, a3, b0, b1, b2, b3;
  u32xN c0, c1, c2, c3, d0, d1, d2, d3;

  s3l0 = s3;
  s3l1 = s3 + u32xN_splat_u32x4 ((u32x4){ ctr_stride });
  s3l2 = s3 + u32xN_splat_u32x4 ((u32x4){ 2 * ctr_stride });
  s3l3 = s3 + u32xN_splat_u32x4 ((u32x4){ 3 * ctr_stride });

  a0 = b0 = c0 = d0 = s0;
  a1 = b1 = c1 = d1 = s1;
  a2 = b2 = c2 = d2 = s2;

  a3 = s3l0, b3 = s3l1, c3 = s3l2, d3 = s3l3;

  for (u32 i = 20; i > 0; i -= 2)
    {
      clib_chacha20_double_round (&a0, &a1, &a2, &a3);
      clib_chacha20_double_round (&b0, &b1, &b2, &b3);
      clib_chacha20_double_round (&c0, &c1, &c2, &c3);
      clib_chacha20_double_round (&d0, &d1, &d2, &d3);
    }

  a0 += s0, a1 += s1, a2 += s2, a3 += s3l0;
  clib_chacha20_reorder_x4 (&a0, &a1, &a2, &a3);

  dv[0] = sv[0] ^ a0;
  dv[1] = sv[1] ^ a1;
  dv[2] = sv[2] ^ a2;
  dv[3] = sv[3] ^ a3;

  b0 += s0, b1 += s1, b2 += s2, b3 += s3l1;
  clib_chacha20_reorder_x4 (&b0, &b1, &b2, &b3);

  dv[4] = sv[4] ^ b0;
  dv[5] = sv[5] ^ b1;
  dv[6] = sv[6] ^ b2;
  dv[7] = sv[7] ^ b3;

  c0 += s0, c1 += s1, c2 += s2, c3 += s3l2;
  clib_chacha20_reorder_x4 (&c0, &c1, &c2, &c3);

  dv[8] = sv[8] ^ c0;
  dv[9] = sv[9] ^ c1;
  dv[10] = sv[10] ^ c2;
  dv[11] = sv[11] ^ c3;

  d0 += s0, d1 += s1, d2 += s2, d3 += s3l3;
  clib_chacha20_reorder_x4 (&d0, &d1, &d2, &d3);
  dv[12] = sv[12] ^ d0;
  dv[13] = sv[13] ^ d1;
  dv[14] = sv[14] ^ d2;
  dv[15] = sv[15] ^ d3;
}

static_always_inline void
clib_chacha20 (u8 *dst, u8 *src, u64 length, const u8 *key, const u8 *nonce, u32 init_ctr)
{
  const u32 n_lanes = sizeof (u32xN) / 16;
  const u32 n_bytes_x16 = 16 * sizeof (u32xN);
  const u32 ctr_blocks = n_bytes_x16 / 64;
  const u32xN s0 = u32xN_splat_u32x4 ((u32x4){ CHACHA20_CONST_WORDS });
  const u32xN s1 = u32xN_splat_u32x4 (*(u32x4u *) key);
  const u32xN s2 = u32xN_splat_u32x4 (*(u32x4u *) (key + 16));
  const u32xN ctr_inc_x4 = u32xN_splat_u32x4 ((u32x4){ n_lanes });
  const u32xN ctr_inc_x8 = u32xN_splat_u32x4 ((u32x4){ 2 * n_lanes });
  const u32xN ctr_inc_x12 = u32xN_splat_u32x4 ((u32x4){ 3 * n_lanes });
  const u32xN ctr_inc_x16 = u32xN_splat_u32x4 ((u32x4){ ctr_blocks });
  const u32u *nonce_u32 = (const u32u *) nonce;
  u32xNu *sv = (u32xNu *) src;
  u32xNu *dv = (u32xNu *) dst;
  u64 n_left = length;
  u32xN a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3;
  u32xN s3 = u32xN_splat_u32x4 ((u32x4){ init_ctr, nonce_u32[0], nonce_u32[1], nonce_u32[2] });

#if defined(CLIB_HAVE_VEC512)
  s3 += (u32xN){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 };
#elif defined(CLIB_HAVE_VEC256)
  s3 += (u32xN){ 0, 0, 0, 0, 1, 0, 0, 0 };
#endif

  for (; n_left >= n_bytes_x16; n_left -= n_bytes_x16, dv += 16, sv += 16)
    {
      clib_chacha20_block_x16 (sv, dv, s0, s1, s2, s3);
      s3 += ctr_inc_x16;
    }

  if (n_left == 0)
    return;

  if (n_left >= 12 * sizeof (u32xN))
    {
      a0 = s0, a1 = s1, a2 = s2, a3 = s3;
      b0 = s0, b1 = s1, b2 = s2, b3 = s3 + ctr_inc_x4;
      c0 = s0, c1 = s1, c2 = s2, c3 = s3 + ctr_inc_x8;

      for (int i = 20; i > 0; i -= 2)
	{
	  clib_chacha20_double_round (&a0, &a1, &a2, &a3);
	  clib_chacha20_double_round (&b0, &b1, &b2, &b3);
	  clib_chacha20_double_round (&c0, &c1, &c2, &c3);
	}

      a0 += s0, a1 += s1, a2 += s2, a3 += s3;
      b0 += s0, b1 += s1, b2 += s2, b3 += s3 + ctr_inc_x4;
      c0 += s0, c1 += s1, c2 += s2, c3 += s3 + ctr_inc_x8;

      clib_chacha20_reorder_x4 (&a0, &a1, &a2, &a3);
      clib_chacha20_reorder_x4 (&b0, &b1, &b2, &b3);
      clib_chacha20_reorder_x4 (&c0, &c1, &c2, &c3);

      dv[0] = a0 ^ sv[0];
      dv[1] = a1 ^ sv[1];
      dv[2] = a2 ^ sv[2];
      dv[3] = a3 ^ sv[3];
      dv[4] = b0 ^ sv[4];
      dv[5] = b1 ^ sv[5];
      dv[6] = b2 ^ sv[6];
      dv[7] = b3 ^ sv[7];
      dv[8] = c0 ^ sv[8];
      dv[9] = c1 ^ sv[9];
      dv[10] = c2 ^ sv[10];
      dv[11] = c3 ^ sv[11];
      n_left -= 12 * sizeof (u32xN);
      s3 += ctr_inc_x12;
      sv += 12;
      dv += 12;
    }
  else if (n_left >= 8 * sizeof (u32xN))
    {
      a0 = s0, a1 = s1, a2 = s2, a3 = s3;
      b0 = s0, b1 = s1, b2 = s2, b3 = s3 + ctr_inc_x4;

      for (int i = 20; i > 0; i -= 2)
	{
	  clib_chacha20_double_round (&a0, &a1, &a2, &a3);
	  clib_chacha20_double_round (&b0, &b1, &b2, &b3);
	}

      a0 += s0, a1 += s1, a2 += s2, a3 += s3;
      b0 += s0, b1 += s1, b2 += s2, b3 += s3 + ctr_inc_x4;

      clib_chacha20_reorder_x4 (&a0, &a1, &a2, &a3);
      clib_chacha20_reorder_x4 (&b0, &b1, &b2, &b3);

      dv[0] = a0 ^ sv[0];
      dv[1] = a1 ^ sv[1];
      dv[2] = a2 ^ sv[2];
      dv[3] = a3 ^ sv[3];
      dv[4] = b0 ^ sv[4];
      dv[5] = b1 ^ sv[5];
      dv[6] = b2 ^ sv[6];
      dv[7] = b3 ^ sv[7];
      n_left -= 8 * sizeof (u32xN);
      s3 += ctr_inc_x4 + ctr_inc_x4;
      sv += 8;
      dv += 8;
    }
  else if (n_left >= 4 * sizeof (u32xN))
    {
      a0 = s0, a1 = s1, a2 = s2, a3 = s3;

      for (int i = 20; i > 0; i -= 2)
	clib_chacha20_double_round (&a0, &a1, &a2, &a3);

      a0 += s0, a1 += s1, a2 += s2, a3 += s3;

      clib_chacha20_reorder_x4 (&a0, &a1, &a2, &a3);

      dv[0] = a0 ^ sv[0];
      dv[1] = a1 ^ sv[1];
      dv[2] = a2 ^ sv[2];
      dv[3] = a3 ^ sv[3];
      n_left -= 4 * sizeof (u32xN);
      s3 += ctr_inc_x4;
      sv += 4;
      dv += 4;
    }

  a0 = s0, a1 = s1, a2 = s2, a3 = s3;

  for (int i = 20; i > 0; i -= 2)
    clib_chacha20_double_round (&a0, &a1, &a2, &a3);

  a0 += s0, a1 += s1, a2 += s2, a3 += s3;

  clib_chacha20_reorder_x4 (&a0, &a1, &a2, &a3);

  if (n_left > 3 * sizeof (u32xNu))
    {
      dv[0] = a0 ^ sv[0];
      dv[1] = a1 ^ sv[1];
      dv[2] = a2 ^ sv[2];
      clib_chacha20_load_store_partial (a3, sv + 3, dv + 3, n_left - 3 * sizeof (u32xNu));
    }
  else if (n_left > 2 * sizeof (u32xNu))
    {
      dv[0] = a0 ^ sv[0];
      dv[1] = a1 ^ sv[1];
      clib_chacha20_load_store_partial (a2, sv + 2, dv + 2, n_left - 2 * sizeof (u32xNu));
    }
  else if (n_left > sizeof (u32xNu))
    {
      dv[0] = a0 ^ sv[0];
      clib_chacha20_load_store_partial (a1, sv + 1, dv + 1, n_left - sizeof (u32xNu));
    }
  else
    clib_chacha20_load_store_partial (a0, sv, dv, n_left);
}
