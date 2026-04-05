/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef __clib_poly1305_h__
#define __clib_poly1305_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>

/* implementation of DJB's poly1305 using 64-bit arithmetrics */

typedef struct
{
  u64 r[3], s[2];
  u64x8 r8[3];
  u64x8 r16[3];
  u64x8 r24[3];
  u64x8 r32[3];
} clib_poly1305_init_data_t;

typedef struct
{
  clib_poly1305_init_data_t d;
  u64 h[3];

  /* partial data */
  union
  {
    u8 as_u8[16];
    u64 as_u64[2];
  } partial;

  size_t n_partial_bytes;
} clib_poly1305_ctx_t;

static_always_inline void
clib_poly1305_precompute (clib_poly1305_init_data_t *kd, const u8 *key)
{
  const u64 m44 = 0xFFFFFFFFFFFULL;
  const u64 m42 = 0x3FFFFFFFFFFULL;
  u64u *k = (u64u *) key;
  u64 st[101] = {};
  u64 r0_44, r1_44, r2_44;
  int i;

  kd->r[0] = k[0] & 0x0ffffffc0fffffff;
  kd->r[1] = k[1] & 0x0ffffffc0ffffffc;
  kd->s[0] = k[2];
  kd->s[1] = k[3];
  kd->r[2] = kd->r[1] + (kd->r[1] >> 2);

  r0_44 = k[0] & 0x0ffc0fffffff;
  r1_44 = ((k[0] >> 44) | (k[1] << 20)) & 0x00fffffc0ffff;
  r2_44 = (k[1] >> 24) & 0x000ffffffc0f;
  st[2] = st[3] = st[4] = 0;
  st[5] = r0_44;
  st[6] = r1_44;
  st[7] = r2_44;

  for (i = 2; i <= 32; i++)
    {
      u32 o = 5 + (i - 1) * 3;
      u64 s1 = r1_44 * 20;
      u64 s2 = r2_44 * 20;
      u128 d0 = (u128) st[o - 3] * r0_44 + (u128) st[o - 2] * s2 + (u128) st[o - 1] * s1;
      u64 c0 = (u64) (d0 >> 44);
      u128 d1 = (u128) st[o - 3] * r1_44 + (u128) st[o - 2] * r0_44 + (u128) st[o - 1] * s2 + c0;
      u64 c1 = (u64) (d1 >> 44);
      u128 d2 = (u128) st[o - 3] * r2_44 + (u128) st[o - 2] * r1_44 + (u128) st[o - 1] * r0_44 + c1;
      u64 c2 = (u64) (d2 >> 42);

      st[o] = (u64) d0 & m44;
      st[o] += c2 * 5;
      st[o + 1] = ((u64) d1 & m44) + (st[o] >> 44);
      st[o] &= m44;
      st[o + 2] = (u64) d2 & m42;
    }

  kd->r8[0] = (u64x8){ st[26], st[23], st[20], st[17], st[14], st[11], st[8], st[5] };
  kd->r8[1] = (u64x8){ st[27], st[24], st[21], st[18], st[15], st[12], st[9], st[6] };
  kd->r8[2] = (u64x8){ st[28], st[25], st[22], st[19], st[16], st[13], st[10], st[7] };
  kd->r16[0] = (u64x8){ st[50], st[47], st[44], st[41], st[38], st[35], st[32], st[29] };
  kd->r16[1] = (u64x8){ st[51], st[48], st[45], st[42], st[39], st[36], st[33], st[30] };
  kd->r16[2] = (u64x8){ st[52], st[49], st[46], st[43], st[40], st[37], st[34], st[31] };
  kd->r24[0] = (u64x8){ st[74], st[71], st[68], st[65], st[62], st[59], st[56], st[53] };
  kd->r24[1] = (u64x8){ st[75], st[72], st[69], st[66], st[63], st[60], st[57], st[54] };
  kd->r24[2] = (u64x8){ st[76], st[73], st[70], st[67], st[64], st[61], st[58], st[55] };
  kd->r32[0] = (u64x8){ st[98], st[95], st[92], st[89], st[86], st[83], st[80], st[77] };
  kd->r32[1] = (u64x8){ st[99], st[96], st[93], st[90], st[87], st[84], st[81], st[78] };
  kd->r32[2] = (u64x8){ st[100], st[97], st[94], st[91], st[88], st[85], st[82], st[79] };
}

static_always_inline void
clib_poly1305_init (clib_poly1305_ctx_t *ctx, const clib_poly1305_init_data_t *kd)
{
  ctx->d = *kd;
  ctx->h[0] = ctx->h[1] = ctx->h[2] = 0;
  ctx->n_partial_bytes = 0;
}

static_always_inline void
_clib_poly1305_multiply_and_reduce (u64 h[3], const u64 r[3])
{
  union
  {
    struct
    {
      u64 lo, hi;
    };
    u128 n;
  } l0, l1, l2;
  u64 c;

  /*
		       h2       h1       h0
    x                           r1       r0
    ---------------------------------------
		  r0 x h2  r0 x h1  r0 × h0
    +    r1 x h2  r1 x h1  r1 x h0
    ---------------------------------------

    for p = 2^130-5, following applies:
    (r * 2^130) mod p == (r * 5) mod p

    bits above 130 can be shifted right (divided by 2^130)
    and multiplied by 5 per equation above

	     h2               h1                h0
    x                         r1                r0
    ----------------------------------------------
       r0 x h2           r0 x h1           r0 × h0
    +                    r1 x h0
    +           5x (r1 >>2) x h2  5x (r1 >>2) x h1
    ----------------------------------------------
       [0:l2.lo]   [l1.hi:l1.lo]     [l0.hi:l0.lo]
   */

  l0.n = l1.n = l2.n = 0;
  /* u64 x u64 = u128 multiplications */
  l0.n += (u128) h[0] * r[0];
  l0.n += (u128) h[1] * r[2]; /* r[2] holds precomputed (r[1] >> 2) * 5 */
  l1.n += (u128) h[0] * r[1];
  l1.n += (u128) h[1] * r[0];

  /* u64 x u64 = u64 multiplications, as h[2] may have only lower 2 bits set
   * and r[1] have clamped bits 60-63  */
  l1.n += (u128) (h[2] * r[2]);
  l2.n += (u128) (h[2] * r[0]);

  /* propagate upper 64 bits to higher limb */
  c = 0;
  l1.lo = u64_add_with_carry (&c, l1.lo, l0.hi);
  l2.lo = u64_add_with_carry (&c, l2.lo, l1.hi);

  l2.hi = l2.lo;
  /* keep bits [128:129] */
  l2.lo &= 3;

  /* bits 130 and above multiply with 5 and store to l2.hi */
  l2.hi -= l2.lo;
  l2.hi += l2.hi >> 2;

  /* add l2.hi to l0.lo with carry propagation and store result to h2:h1:h0 */
  c = 0;
  h[0] = u64_add_with_carry (&c, l0.lo, l2.hi);
  h[1] = u64_add_with_carry (&c, l1.lo, 0);
  h[2] = u64_add_with_carry (&c, l2.lo, 0);
}

static_always_inline u32
_clib_poly1305_add_blocks (clib_poly1305_ctx_t *ctx, const u8 *msg, uword n_bytes, const u32 bit17)
{
  u64 h[3];
  const u64 *r = ctx->d.r;

  for (int i = 0; i < 3; i++)
    h[i] = ctx->h[i];

  for (const u64u *m = (u64u *) msg; n_bytes >= 16; n_bytes -= 16, m += 2)
    {
      u64 c = 0;

      /* h += m */
      h[0] = u64_add_with_carry (&c, h[0], m[0]);
      h[1] = u64_add_with_carry (&c, h[1], m[1]);
      h[2] = u64_add_with_carry (&c, h[2], bit17 ? 1 : 0);

      /* h = (h * r) mod p */
      _clib_poly1305_multiply_and_reduce (h, r);
    }

  for (int i = 0; i < 3; i++)
    ctx->h[i] = h[i];

  return n_bytes;
}

static_always_inline void
_clib_poly1305_reduce_44 (u64 *h0, u64 *h1, u64 *h2, u64 sum0_lo, u64 sum0_hi, u64 sum1_lo,
			  u64 sum1_hi, u64 sum2_lo, u64 sum2_hi)
{
  const u64 poly1305_m44 = 0xFFFFFFFFFFFULL;
  const u64 poly1305_m42 = 0x3FFFFFFFFFFULL;
  u64 carry;

  *h0 = sum0_lo & poly1305_m44;
  sum1_lo += (sum0_lo >> 44) + (sum0_hi << 8);
  *h1 = sum1_lo & poly1305_m44;
  sum2_lo += (sum1_lo >> 44) + (sum1_hi << 8);
  *h2 = sum2_lo & poly1305_m42;

  carry = ((sum2_lo >> 42) + (sum2_hi << 10)) * 5;
  carry += *h0;
  *h0 = carry & poly1305_m44;
  carry >>= 44;
  carry += *h1;
  *h1 = carry & poly1305_m44;
  carry >>= 44;
  *h2 += carry;
}

static_always_inline size_t
_clib_poly1305_avx512_blocks (clib_poly1305_ctx_t *ctx, const u8 *m, size_t n_bytes)
{
#if defined(CLIB_HAVE_VEC512)
  const uword block_size = 16;
  const u64 poly1305_m44 = 0xFFFFFFFFFFFULL;
  const u64 poly1305_m42 = 0x3FFFFFFFFFFULL;
  u64 sum0_lo, sum0_hi, sum1_lo, sum1_hi, sum2_lo, sum2_hi;
  u64x8 d0, d1, t0, t1, u0, u1, m0, m1, m2, n0, n1, n2, r, zero = {};
  size_t original_bytes;
  u64 h0, h1, h2;
  u64x8u *mv = (u64x8u *) m;
  const clib_poly1305_init_data_t *d = &ctx->d;
  const u64x8 mask44 = u64x8_splat (poly1305_m44);
  const u64x8 mask42 = u64x8_splat (poly1305_m42);
  const u64x8 hibit = u64x8_splat (1ULL << 40);
  const u64x8 s8_0 = d->r8[1] * 20;
  const u64x8 s8_1 = d->r8[2] * 20;
  const u64x8 s16_0 = d->r16[1] * 20;
  const u64x8 s16_1 = d->r16[2] * 20;
  const u64x8 s24_0 = d->r24[1] * 20;
  const u64x8 s24_1 = d->r24[2] * 20;
  const u64x8 s32_0 = d->r32[1] * 20;
  const u64x8 s32_1 = d->r32[2] * 20;

  if (n_bytes < 8 * block_size)
    return 0;

  original_bytes = n_bytes;
  h0 = ctx->h[0] & poly1305_m44;
  h1 = ((ctx->h[0] >> 44) | (ctx->h[1] << 20)) & poly1305_m44;
  h2 = ((ctx->h[1] >> 24) | (ctx->h[2] << 40)) & poly1305_m42;

  for (; n_bytes >= 32 * block_size; mv += 8, n_bytes -= 32 * block_size)
    {
      u64x8 p0, p1, q0, q1;

      d0 = mv[0];
      d1 = mv[1];
      t0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      t1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      d0 = mv[2];
      d1 = mv[3];
      u0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      u1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      d0 = mv[4];
      d1 = mv[5];
      p0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      p1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      d0 = mv[6];
      d1 = mv[7];
      q0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      q1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);

      m0 = t0 & mask44;
      m1 = u64x8_shrdi (t0, t1, 44) & mask44;
      m2 = ((t1 >> 24) & mask42) | hibit;
      n0 = u0 & mask44;
      n1 = u64x8_shrdi (u0, u1, 44) & mask44;
      n2 = ((u1 >> 24) & mask42) | hibit;
      d0 = p0 & mask44;
      d1 = u64x8_shrdi (p0, p1, 44) & mask44;
      t0 = ((p1 >> 24) & mask42) | hibit;
      u0 = q0 & mask44;
      u1 = u64x8_shrdi (q0, q1, 44) & mask44;
      t1 = ((q1 >> 24) & mask42) | hibit;

      m0 = u64x8_mask_add (m0, 0x01, m0, u64x8_splat (h0));
      m1 = u64x8_mask_add (m1, 0x01, m1, u64x8_splat (h1));
      m2 = u64x8_mask_add (m2, 0x01, m2, u64x8_splat (h2));

      r = u64x8_muladd52_lo (zero, m0, d->r32[0]);
      r = u64x8_muladd52_lo (r, m1, s32_1);
      r = u64x8_muladd52_lo (r, m2, s32_0);
      r = u64x8_muladd52_lo (r, n0, d->r24[0]);
      r = u64x8_muladd52_lo (r, n1, s24_1);
      r = u64x8_muladd52_lo (r, n2, s24_0);
      r = u64x8_muladd52_lo (r, d0, d->r16[0]);
      r = u64x8_muladd52_lo (r, d1, s16_1);
      r = u64x8_muladd52_lo (r, t0, s16_0);
      r = u64x8_muladd52_lo (r, u0, d->r8[0]);
      r = u64x8_muladd52_lo (r, u1, s8_1);
      r = u64x8_muladd52_lo (r, t1, s8_0);
      sum0_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r32[0]);
      r = u64x8_muladd52_hi (r, m1, s32_1);
      r = u64x8_muladd52_hi (r, m2, s32_0);
      r = u64x8_muladd52_hi (r, n0, d->r24[0]);
      r = u64x8_muladd52_hi (r, n1, s24_1);
      r = u64x8_muladd52_hi (r, n2, s24_0);
      r = u64x8_muladd52_hi (r, d0, d->r16[0]);
      r = u64x8_muladd52_hi (r, d1, s16_1);
      r = u64x8_muladd52_hi (r, t0, s16_0);
      r = u64x8_muladd52_hi (r, u0, d->r8[0]);
      r = u64x8_muladd52_hi (r, u1, s8_1);
      r = u64x8_muladd52_hi (r, t1, s8_0);
      sum0_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r32[1]);
      r = u64x8_muladd52_lo (r, m1, d->r32[0]);
      r = u64x8_muladd52_lo (r, m2, s32_1);
      r = u64x8_muladd52_lo (r, n0, d->r24[1]);
      r = u64x8_muladd52_lo (r, n1, d->r24[0]);
      r = u64x8_muladd52_lo (r, n2, s24_1);
      r = u64x8_muladd52_lo (r, d0, d->r16[1]);
      r = u64x8_muladd52_lo (r, d1, d->r16[0]);
      r = u64x8_muladd52_lo (r, t0, s16_1);
      r = u64x8_muladd52_lo (r, u0, d->r8[1]);
      r = u64x8_muladd52_lo (r, u1, d->r8[0]);
      r = u64x8_muladd52_lo (r, t1, s8_1);
      sum1_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r32[1]);
      r = u64x8_muladd52_hi (r, m1, d->r32[0]);
      r = u64x8_muladd52_hi (r, m2, s32_1);
      r = u64x8_muladd52_hi (r, n0, d->r24[1]);
      r = u64x8_muladd52_hi (r, n1, d->r24[0]);
      r = u64x8_muladd52_hi (r, n2, s24_1);
      r = u64x8_muladd52_hi (r, d0, d->r16[1]);
      r = u64x8_muladd52_hi (r, d1, d->r16[0]);
      r = u64x8_muladd52_hi (r, t0, s16_1);
      r = u64x8_muladd52_hi (r, u0, d->r8[1]);
      r = u64x8_muladd52_hi (r, u1, d->r8[0]);
      r = u64x8_muladd52_hi (r, t1, s8_1);
      sum1_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r32[2]);
      r = u64x8_muladd52_lo (r, m1, d->r32[1]);
      r = u64x8_muladd52_lo (r, m2, d->r32[0]);
      r = u64x8_muladd52_lo (r, n0, d->r24[2]);
      r = u64x8_muladd52_lo (r, n1, d->r24[1]);
      r = u64x8_muladd52_lo (r, n2, d->r24[0]);
      r = u64x8_muladd52_lo (r, d0, d->r16[2]);
      r = u64x8_muladd52_lo (r, d1, d->r16[1]);
      r = u64x8_muladd52_lo (r, t0, d->r16[0]);
      r = u64x8_muladd52_lo (r, u0, d->r8[2]);
      r = u64x8_muladd52_lo (r, u1, d->r8[1]);
      r = u64x8_muladd52_lo (r, t1, d->r8[0]);
      sum2_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r32[2]);
      r = u64x8_muladd52_hi (r, m1, d->r32[1]);
      r = u64x8_muladd52_hi (r, m2, d->r32[0]);
      r = u64x8_muladd52_hi (r, n0, d->r24[2]);
      r = u64x8_muladd52_hi (r, n1, d->r24[1]);
      r = u64x8_muladd52_hi (r, n2, d->r24[0]);
      r = u64x8_muladd52_hi (r, d0, d->r16[2]);
      r = u64x8_muladd52_hi (r, d1, d->r16[1]);
      r = u64x8_muladd52_hi (r, t0, d->r16[0]);
      r = u64x8_muladd52_hi (r, u0, d->r8[2]);
      r = u64x8_muladd52_hi (r, u1, d->r8[1]);
      r = u64x8_muladd52_hi (r, t1, d->r8[0]);
      sum2_hi = u64x8_sum_elts (r);

      _clib_poly1305_reduce_44 (&h0, &h1, &h2, sum0_lo, sum0_hi, sum1_lo, sum1_hi, sum2_lo,
				sum2_hi);
    }

  if (n_bytes >= 16 * block_size)
    {
      d0 = mv[0];
      d1 = mv[1];
      t0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      t1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      d0 = mv[2];
      d1 = mv[3];
      u0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      u1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      m0 = t0 & mask44;
      m1 = u64x8_shrdi (t0, t1, 44) & mask44;
      m2 = ((t1 >> 24) & mask42) | hibit;
      n0 = u0 & mask44;
      n1 = u64x8_shrdi (u0, u1, 44) & mask44;
      n2 = ((u1 >> 24) & mask42) | hibit;

      m0 = u64x8_mask_add (m0, 0x01, m0, u64x8_splat (h0));
      m1 = u64x8_mask_add (m1, 0x01, m1, u64x8_splat (h1));
      m2 = u64x8_mask_add (m2, 0x01, m2, u64x8_splat (h2));

      r = u64x8_muladd52_lo (zero, m0, d->r16[0]);
      r = u64x8_muladd52_lo (r, m1, s16_1);
      r = u64x8_muladd52_lo (r, m2, s16_0);
      r = u64x8_muladd52_lo (r, n0, d->r8[0]);
      r = u64x8_muladd52_lo (r, n1, s8_1);
      r = u64x8_muladd52_lo (r, n2, s8_0);
      sum0_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r16[0]);
      r = u64x8_muladd52_hi (r, m1, s16_1);
      r = u64x8_muladd52_hi (r, m2, s16_0);
      r = u64x8_muladd52_hi (r, n0, d->r8[0]);
      r = u64x8_muladd52_hi (r, n1, s8_1);
      r = u64x8_muladd52_hi (r, n2, s8_0);
      sum0_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r16[1]);
      r = u64x8_muladd52_lo (r, m1, d->r16[0]);
      r = u64x8_muladd52_lo (r, m2, s16_1);
      r = u64x8_muladd52_lo (r, n0, d->r8[1]);
      r = u64x8_muladd52_lo (r, n1, d->r8[0]);
      r = u64x8_muladd52_lo (r, n2, s8_1);
      sum1_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r16[1]);
      r = u64x8_muladd52_hi (r, m1, d->r16[0]);
      r = u64x8_muladd52_hi (r, m2, s16_1);
      r = u64x8_muladd52_hi (r, n0, d->r8[1]);
      r = u64x8_muladd52_hi (r, n1, d->r8[0]);
      r = u64x8_muladd52_hi (r, n2, s8_1);
      sum1_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r16[2]);
      r = u64x8_muladd52_lo (r, m1, d->r16[1]);
      r = u64x8_muladd52_lo (r, m2, d->r16[0]);
      r = u64x8_muladd52_lo (r, n0, d->r8[2]);
      r = u64x8_muladd52_lo (r, n1, d->r8[1]);
      r = u64x8_muladd52_lo (r, n2, d->r8[0]);
      sum2_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r16[2]);
      r = u64x8_muladd52_hi (r, m1, d->r16[1]);
      r = u64x8_muladd52_hi (r, m2, d->r16[0]);
      r = u64x8_muladd52_hi (r, n0, d->r8[2]);
      r = u64x8_muladd52_hi (r, n1, d->r8[1]);
      r = u64x8_muladd52_hi (r, n2, d->r8[0]);
      sum2_hi = u64x8_sum_elts (r);

      _clib_poly1305_reduce_44 (&h0, &h1, &h2, sum0_lo, sum0_hi, sum1_lo, sum1_hi, sum2_lo,
				sum2_hi);
      mv += 4;
      n_bytes -= 16 * block_size;
    }

  if (n_bytes >= 8 * block_size)
    {
      d0 = mv[0];
      d1 = mv[1];
      t0 = u64x8_shuffle2 (d0, d1, 0, 2, 4, 6, 8, 10, 12, 14);
      t1 = u64x8_shuffle2 (d0, d1, 1, 3, 5, 7, 9, 11, 13, 15);
      m0 = t0 & mask44;
      m1 = u64x8_shrdi (t0, t1, 44) & mask44;
      m2 = ((t1 >> 24) & mask42) | hibit;

      m0 = u64x8_mask_add (m0, 0x01, m0, u64x8_splat (h0));
      m1 = u64x8_mask_add (m1, 0x01, m1, u64x8_splat (h1));
      m2 = u64x8_mask_add (m2, 0x01, m2, u64x8_splat (h2));

      r = u64x8_muladd52_lo (zero, m0, d->r8[0]);
      r = u64x8_muladd52_lo (r, m1, s8_1);
      r = u64x8_muladd52_lo (r, m2, s8_0);
      sum0_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r8[0]);
      r = u64x8_muladd52_hi (r, m1, s8_1);
      r = u64x8_muladd52_hi (r, m2, s8_0);
      sum0_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r8[1]);
      r = u64x8_muladd52_lo (r, m1, d->r8[0]);
      r = u64x8_muladd52_lo (r, m2, s8_1);
      sum1_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r8[1]);
      r = u64x8_muladd52_hi (r, m1, d->r8[0]);
      r = u64x8_muladd52_hi (r, m2, s8_1);
      sum1_hi = u64x8_sum_elts (r);

      r = u64x8_muladd52_lo (zero, m0, d->r8[2]);
      r = u64x8_muladd52_lo (r, m1, d->r8[1]);
      r = u64x8_muladd52_lo (r, m2, d->r8[0]);
      sum2_lo = u64x8_sum_elts (r);

      r = u64x8_muladd52_hi (zero, m0, d->r8[2]);
      r = u64x8_muladd52_hi (r, m1, d->r8[1]);
      r = u64x8_muladd52_hi (r, m2, d->r8[0]);
      sum2_hi = u64x8_sum_elts (r);

      _clib_poly1305_reduce_44 (&h0, &h1, &h2, sum0_lo, sum0_hi, sum1_lo, sum1_hi, sum2_lo,
				sum2_hi);
      mv += 2;
      n_bytes -= 8 * block_size;
    }

  ctx->h[0] = h0 | (h1 << 44);
  ctx->h[1] = (h1 >> 20) | (h2 << 24);
  ctx->h[2] = h2 >> 40;
  return original_bytes - n_bytes;
#else
  return 0;
#endif
}

static_always_inline void
clib_poly1305_update (clib_poly1305_ctx_t *ctx, const u8 *msg, uword len)
{
  const u32 block_size = 16;
  uword n_left = len;

  if (n_left == 0)
    return;

  if (ctx->n_partial_bytes)
    {
      u16 missing_bytes = 16 - ctx->n_partial_bytes;
      if (PREDICT_FALSE (n_left < missing_bytes))
	{
	  clib_memcpy_fast (ctx->partial.as_u8 + ctx->n_partial_bytes, msg,
			    n_left);
	  ctx->n_partial_bytes += n_left;
	  return;
	}

      clib_memcpy_fast (ctx->partial.as_u8 + ctx->n_partial_bytes, msg, missing_bytes);
      _clib_poly1305_add_blocks (ctx, ctx->partial.as_u8, 16, 1);
      ctx->n_partial_bytes = 0;
      n_left -= missing_bytes;
      msg += missing_bytes;
    }

  size_t consumed = _clib_poly1305_avx512_blocks (ctx, msg, n_left);

  msg += consumed;
  n_left -= consumed;

  if (n_left >= 4 * block_size)
    {
      _clib_poly1305_add_blocks (ctx, msg, 4 * block_size, 1);
      msg += 4 * block_size;
      n_left -= 4 * block_size;
    }

  uword n_before = n_left;
  n_left = _clib_poly1305_add_blocks (ctx, msg, n_left, 1);
  msg += n_before - n_left;

  if (n_left)
    {
      ctx->partial.as_u64[0] = ctx->partial.as_u64[1] = 0;
      clib_memcpy_fast (ctx->partial.as_u8, msg, n_left);
      ctx->n_partial_bytes = n_left;
    }
}

static_always_inline void
clib_poly1305_final (clib_poly1305_ctx_t *ctx, u8 *out)
{
  const u64 p[] = { 0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF, 3 }; /* 2^128-5 */
  const u64 *s = ctx->d.s;
  u64u *t = (u64u *) out;
  u64 h0, h1, t0, t1;
  u64 c;

  if (ctx->n_partial_bytes)
    {
      ctx->partial.as_u8[ctx->n_partial_bytes] = 1;
      _clib_poly1305_add_blocks (ctx, ctx->partial.as_u8, 16, 0);
    }

  h0 = ctx->h[0];
  h1 = ctx->h[1];

  /* h may not be fully reduced, try to subtract 2^128-5 */
  c = 0;
  t0 = u64_sub_with_borrow (&c, h0, p[0]);
  t1 = u64_sub_with_borrow (&c, h1, p[1]);
  u64_sub_with_borrow (&c, ctx->h[2], p[2]);

  if (!c)
    h0 = t0, h1 = t1;

  c = 0;
  t[0] = u64_add_with_carry (&c, h0, s[0]);
  t[1] = u64_add_with_carry (&c, h1, s[1]);
}

static_always_inline void
clib_poly1305 (const clib_poly1305_init_data_t *kd, const u8 *msg, uword len, u8 *out)
{
  clib_poly1305_ctx_t ctx = {};
  clib_poly1305_init (&ctx, kd);
  clib_poly1305_update (&ctx, msg, len);
  clib_poly1305_final (&ctx, out);
}

#endif /* __clib_poly1305_h__ */
