/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef __clib_poly1305_h__
#define __clib_poly1305_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>

#define CLIB_POLY1305_BLOCK_SIZE 16

/* implementation of DJB's poly1305 using 64-bit arithmetrics */

typedef struct
{
  u64 r[3], s[2];
  u64 h[3];

#if defined(CLIB_HAVE_VEC512)
  u64 r44[3];
  u64x8 r8[3];
  u64x8 s8[2];
#endif

  /* partial data */
  union
  {
    u8 as_u8[16];
    u64 as_u64[2];
  } partial;

  size_t n_partial_bytes;
} clib_poly1305_ctx;

#if defined(CLIB_HAVE_VEC512)
#define CLIB_POLY1305_M44	      0xFFFFFFFFFFFULL
#define CLIB_POLY1305_M42	      0x3FFFFFFFFFFULL
#define CLIB_POLY1305_HIBIT64	      (1ULL << 40)
#define CLIB_POLY1305_VEC_STATE_WORDS 29

static_always_inline void
_clib_poly1305_rh_to_44 (u64 out[3], const u64 h[3])
{
  out[0] = h[0] & CLIB_POLY1305_M44;
  out[1] = ((h[0] >> 44) | (h[1] << 20)) & CLIB_POLY1305_M44;
  out[2] = ((h[1] >> 24) | (h[2] << 40)) & CLIB_POLY1305_M42;
}

static_always_inline void
_clib_poly1305_44_to_rh (u64 h[3], const u64 in[3])
{
  h[0] = in[0] | (in[1] << 44);
  h[1] = (in[1] >> 20) | (in[2] << 24);
  h[2] = in[2] >> 40;
}

static_always_inline void
_clib_poly1305_mul_44 (u64 *h0, u64 *h1, u64 *h2, u64 a0, u64 a1, u64 a2, u64 b0, u64 b1, u64 b2)
{
  const u64 s1 = b1 * 20;
  const u64 s2 = b2 * 20;
  const u128 d0 = (u128) a0 * b0 + (u128) a1 * s2 + (u128) a2 * s1;
  const u64 c0 = (u64) (d0 >> 44);
  const u128 d1 = (u128) a0 * b1 + (u128) a1 * b0 + (u128) a2 * s2 + c0;
  const u64 c1 = (u64) (d1 >> 44);
  const u128 d2 = (u128) a0 * b2 + (u128) a1 * b1 + (u128) a2 * b0 + c1;
  const u64 c2 = (u64) (d2 >> 42);

  *h0 = (u64) d0 & CLIB_POLY1305_M44;
  *h0 += c2 * 5;
  *h1 = ((u64) d1 & CLIB_POLY1305_M44) + (*h0 >> 44);
  *h0 &= CLIB_POLY1305_M44;
  *h2 = (u64) d2 & CLIB_POLY1305_M42;
}

static_always_inline void
_clib_poly1305_precompute_r44 (u64 state[29], const u64 r44[3])
{
  u64 r0 = r44[0];
  u64 r1 = r44[1];
  u64 r2 = r44[2];
  int i;

  state[2] = state[3] = state[4] = 0;
  state[5] = r0;
  state[6] = r1;
  state[7] = r2;

  for (i = 2; i <= 8; i++)
    {
      u32 o = 5 + (i - 1) * 3;
      _clib_poly1305_mul_44 (&state[o], &state[o + 1], &state[o + 2], state[o - 3], state[o - 2],
			     state[o - 1], r0, r1, r2);
    }
}

static_always_inline void
_clib_poly1305_interleave_3x8 (u64x8 *r0, u64x8 *r1, u64x8 *r2)
{
  const u64x8 t0 = u64x8_shuffle2 (*r1, *r0, 7, 4, 1, 14, 11, 8, 5, 2);
  const u64x8 t1 = u64x8_shuffle2 (*r1, *r0, 5, 2, 15, 12, 9, 6, 3, 0);
  const u64x8 t2 = u64x8_shuffle2 (*r1, *r0, 6, 3, 0, 13, 10, 7, 4, 1);

  *r0 = u64x8_shuffle2 (*r2, t0, 5, 2, 8, 9, 10, 11, 12, 13);
  *r1 = u64x8_shuffle2 (*r2, t1, 6, 3, 0, 8, 9, 10, 11, 12);
  *r2 = u64x8_shuffle2 (*r2, t2, 7, 4, 1, 8, 9, 10, 11, 12);
}

static_always_inline size_t
_clib_poly1305_avx512_blocks (u64 h44[3], const clib_poly1305_ctx *ctx, const u8 *m, size_t blocks)
{
  size_t original_blocks;
  u64 h0, h1, h2;
  const u64x8 idx_lo = (u64x8){ 0, 2, 4, 6, 8, 10, 12, 14 };
  const u64x8 idx_hi = (u64x8){ 1, 3, 5, 7, 9, 11, 13, 15 };
  const u64x8 mask44 = u64x8_splat (CLIB_POLY1305_M44);
  const u64x8 mask42 = u64x8_splat (CLIB_POLY1305_M42);
  const u64x8 hibit = u64x8_splat (CLIB_POLY1305_HIBIT64);

  if (blocks < 8)
    return 0;

  original_blocks = blocks;
  h0 = h44[0];
  h1 = h44[1];
  h2 = h44[2];

  while (blocks >= 8)
    {
      const u64x8 data0 = *(u64x8u *) m;
      const u64x8 data1 = *(u64x8u *) (m + 64);
      const u64x8 t0 = u64x8_permute (data0, data1, idx_lo);
      const u64x8 t1 = u64x8_permute (data0, data1, idx_hi);
      u64x8 m0 = t0 & mask44;
      u64x8 m1 = u64x8_shrdi (t0, t1, 44) & mask44;
      u64x8 m2 = ((t1 >> 24) & mask42) | hibit;
      u64x8 d0_lo = {};
      u64x8 d0_hi = {};
      u64x8 d1_lo = {};
      u64x8 d1_hi = {};
      u64x8 d2_lo = {};
      u64x8 d2_hi = {};
      u64 sum0_lo, sum0_hi, sum1_lo, sum1_hi, sum2_lo, sum2_hi, carry;

      m0 = (u64x8) _mm512_mask_add_epi64 ((__m512i) m0, 0x01, (__m512i) m0,
					  (__m512i) u64x8_splat (h0));
      m1 = (u64x8) _mm512_mask_add_epi64 ((__m512i) m1, 0x01, (__m512i) m1,
					  (__m512i) u64x8_splat (h1));
      m2 = (u64x8) _mm512_mask_add_epi64 ((__m512i) m2, 0x01, (__m512i) m2,
					  (__m512i) u64x8_splat (h2));

      d0_lo = u64x8_madd52lo (d0_lo, m0, ctx->r8[0]);
      d0_lo = u64x8_madd52lo (d0_lo, m1, ctx->s8[1]);
      d0_lo = u64x8_madd52lo (d0_lo, m2, ctx->s8[0]);
      d0_hi = u64x8_madd52hi (d0_hi, m0, ctx->r8[0]);
      d0_hi = u64x8_madd52hi (d0_hi, m1, ctx->s8[1]);
      d0_hi = u64x8_madd52hi (d0_hi, m2, ctx->s8[0]);

      d1_lo = u64x8_madd52lo (d1_lo, m0, ctx->r8[1]);
      d1_lo = u64x8_madd52lo (d1_lo, m1, ctx->r8[0]);
      d1_lo = u64x8_madd52lo (d1_lo, m2, ctx->s8[1]);
      d1_hi = u64x8_madd52hi (d1_hi, m0, ctx->r8[1]);
      d1_hi = u64x8_madd52hi (d1_hi, m1, ctx->r8[0]);
      d1_hi = u64x8_madd52hi (d1_hi, m2, ctx->s8[1]);

      d2_lo = u64x8_madd52lo (d2_lo, m0, ctx->r8[2]);
      d2_lo = u64x8_madd52lo (d2_lo, m1, ctx->r8[1]);
      d2_lo = u64x8_madd52lo (d2_lo, m2, ctx->r8[0]);
      d2_hi = u64x8_madd52hi (d2_hi, m0, ctx->r8[2]);
      d2_hi = u64x8_madd52hi (d2_hi, m1, ctx->r8[1]);
      d2_hi = u64x8_madd52hi (d2_hi, m2, ctx->r8[0]);

      sum0_lo =
	d0_lo[0] + d0_lo[1] + d0_lo[2] + d0_lo[3] + d0_lo[4] + d0_lo[5] + d0_lo[6] + d0_lo[7];
      sum0_hi =
	d0_hi[0] + d0_hi[1] + d0_hi[2] + d0_hi[3] + d0_hi[4] + d0_hi[5] + d0_hi[6] + d0_hi[7];
      sum1_lo =
	d1_lo[0] + d1_lo[1] + d1_lo[2] + d1_lo[3] + d1_lo[4] + d1_lo[5] + d1_lo[6] + d1_lo[7];
      sum1_hi =
	d1_hi[0] + d1_hi[1] + d1_hi[2] + d1_hi[3] + d1_hi[4] + d1_hi[5] + d1_hi[6] + d1_hi[7];
      sum2_lo =
	d2_lo[0] + d2_lo[1] + d2_lo[2] + d2_lo[3] + d2_lo[4] + d2_lo[5] + d2_lo[6] + d2_lo[7];
      sum2_hi =
	d2_hi[0] + d2_hi[1] + d2_hi[2] + d2_hi[3] + d2_hi[4] + d2_hi[5] + d2_hi[6] + d2_hi[7];

      h0 = sum0_lo & CLIB_POLY1305_M44;
      sum1_lo += (sum0_lo >> 44) + (sum0_hi << 8);
      h1 = sum1_lo & CLIB_POLY1305_M44;
      sum2_lo += (sum1_lo >> 44) + (sum1_hi << 8);
      h2 = sum2_lo & CLIB_POLY1305_M42;

      carry = ((sum2_lo >> 42) + (sum2_hi << 10)) * 5;
      carry += h0;
      h0 = carry & CLIB_POLY1305_M44;
      carry >>= 44;
      carry += h1;
      h1 = carry & CLIB_POLY1305_M44;
      carry >>= 44;
      h2 += carry;

      m += 8 * 16;
      blocks -= 8;
    }

  h44[0] = h0;
  h44[1] = h1;
  h44[2] = h2;
  return original_blocks - blocks;
}
#endif

static_always_inline void
clib_poly1305_init (clib_poly1305_ctx *ctx, const u8 key[32])
{
  u64u *k = (u64u *) key;
  u64 *h = ctx->h;
  u64 *r = ctx->r;
  u64 *s = ctx->s;

  /* initialize accumulator */
  h[0] = h[1] = h[2] = 0;

  /* clamp 1st half of the key and store it into r[] */
  r[0] = k[0] & 0x0ffffffc0fffffff;
  r[1] = k[1] & 0x0ffffffc0ffffffc;
  s[0] = k[2];
  s[1] = k[3];

  /* precompute (r[1] >> 2) * 5 */
  r[2] = r[1] + (r[1] >> 2);

  ctx->n_partial_bytes = 0;

#if defined(CLIB_HAVE_VEC512)
  u64 state[29] = {};

  ctx->r44[0] = k[0] & 0x0ffc0fffffff;
  ctx->r44[1] = ((k[0] >> 44) | (k[1] << 20)) & 0x00fffffc0ffff;
  ctx->r44[2] = (k[1] >> 24) & 0x000ffffffc0f;
  _clib_poly1305_precompute_r44 (state, ctx->r44);
  ctx->r8[0] = *(u64x8u *) (state + 5);
  ctx->r8[1] = *(u64x8u *) (state + 13);
  ctx->r8[2] = *(u64x8u *) (state + 21);
  _clib_poly1305_interleave_3x8 (&ctx->r8[0], &ctx->r8[1], &ctx->r8[2]);
  ctx->s8[0] = ctx->r8[1] * 20;
  ctx->s8[1] = ctx->r8[2] * 20;
#endif
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
_clib_poly1305_add_blocks (clib_poly1305_ctx *ctx, const u8 *msg,
			   uword n_bytes, const u32 bit17)
{
  u64 r[3], h[3];

  for (int i = 0; i < 3; i++)
    {
      h[i] = ctx->h[i];
      r[i] = ctx->r[i];
    }

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
clib_poly1305_update (clib_poly1305_ctx *ctx, const u8 *msg, uword len)
{
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

#if defined(CLIB_HAVE_VEC512)
  if (n_left >= 8 * CLIB_POLY1305_BLOCK_SIZE)
    {
      size_t blocks = n_left / CLIB_POLY1305_BLOCK_SIZE;
      u64 h44[3];

      _clib_poly1305_rh_to_44 (h44, ctx->h);

      if (blocks >= 8)
	{
	  size_t consumed = _clib_poly1305_avx512_blocks (h44, ctx, msg, blocks);
	  msg += consumed * CLIB_POLY1305_BLOCK_SIZE;
	  n_left -= consumed * CLIB_POLY1305_BLOCK_SIZE;
	  blocks -= consumed;
	}

      _clib_poly1305_44_to_rh (ctx->h, h44);
    }
#endif

  {
    uword n_before = n_left;
    n_left = _clib_poly1305_add_blocks (ctx, msg, n_left, 1);
    msg += n_before - n_left;
  }

  if (n_left)
    {
      ctx->partial.as_u64[0] = ctx->partial.as_u64[1] = 0;
      clib_memcpy_fast (ctx->partial.as_u8, msg, n_left);
      ctx->n_partial_bytes = n_left;
    }
}

static_always_inline void
clib_poly1305_final (clib_poly1305_ctx *ctx, u8 *out)
{
  const u64 p[] = { 0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF, 3 }; /* 2^128-5 */
  const u64 *s = ctx->s;
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
    {
      h0 = t0;
      h1 = t1;
    }

  c = 0;
  t[0] = u64_add_with_carry (&c, h0, s[0]);
  t[1] = u64_add_with_carry (&c, h1, s[1]);
}

static_always_inline void
clib_poly1305 (const u8 *key, const u8 *msg, uword len, u8 *out)
{
  clib_poly1305_ctx ctx = {};
  clib_poly1305_init (&ctx, key);
  clib_poly1305_update (&ctx, msg, len);
  clib_poly1305_final (&ctx, out);
}

#endif /* __clib_poly1305_h__ */
