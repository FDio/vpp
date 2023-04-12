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
  const u64 r[3], s[2];
  u64 h[3];

  /* partial data */
  union
  {
    u8 as_u8[16];
    u64 as_u64[2];
  } partial;

  size_t n_partial_bytes;
} clib_poly1305_ctx;

static_always_inline void
clib_poly1305_init (clib_poly1305_ctx *ctx, const u8 key[32])
{
  u64u *k = (u64u *) key;
  u64 *h = (u64 *) ctx->h;
  u64 *r = (u64 *) ctx->r;
  u64 *s = (u64 *) ctx->s;

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

      clib_memcpy_fast (ctx->partial.as_u8 + ctx->n_partial_bytes, msg,
			missing_bytes);
      _clib_poly1305_add_blocks (ctx, ctx->partial.as_u8, 16, 1);
      ctx->n_partial_bytes = 0;
      n_left -= missing_bytes;
      msg += missing_bytes;
    }

  n_left = _clib_poly1305_add_blocks (ctx, msg, n_left, 1);

  if (n_left)
    {
      ctx->partial.as_u64[0] = ctx->partial.as_u64[1] = 0;
      clib_memcpy_fast (ctx->partial.as_u8, msg + len - n_left, n_left);
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
  clib_poly1305_ctx ctx;
  clib_poly1305_init (&ctx, key);
  clib_poly1305_update (&ctx, msg, len);
  clib_poly1305_final (&ctx, out);
}

#endif /* __clib_poly1305_h__ */
