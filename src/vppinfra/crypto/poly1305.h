/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef __clib_poly1305_h__
#define __clib_poly1305_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>

typedef struct
{
  /* accumulator */
  u32 h[5];

  /* key split into r and s */
  const u32 r[4];
  const u32 s[4];

  /* precomputed */
  const u32 f[5];

  /* partial data */
  u8 partial[16];
  size_t n_partial_bytes;
} clib_poly1305_ctx;

static_always_inline void
clib_poly1305_init (clib_poly1305_ctx *ctx, const u8 key[32])
{
  u32u *k = (u32 *) key;
  u32 *r = (u32 *) ctx->r;
  u32 *s = (u32 *) ctx->s;
  u32 *f = (u32 *) ctx->f;
  u32 *h = (u32 *) ctx->h;

  ctx->n_partial_bytes = 0;

  /* initialize accumulator */
  h[0] = h[1] = h[2] = h[3] = h[4] = 0;

  /* store 2nd half of the key  */
  s[0] = k[4];
  s[1] = k[5];
  s[2] = k[6];
  s[3] = k[7];

  /* clamp 1st half of the key and store it into r[] */
  r[0] = k[0] & 0x0fffffff;
  r[1] = k[1] & 0x0ffffffc;
  r[2] = k[2] & 0x0ffffffc;
  r[3] = k[3] & 0x0ffffffc;

  /* precompute r * 5, lowest 2 bits of r[0] are stored in f[4] */
  f[0] = (r[0] >> 2) * 5;
  f[1] = (r[1] >> 2) + r[1];
  f[2] = (r[2] >> 2) + r[2];
  f[3] = (r[3] >> 2) + r[3];
  f[4] = r[0] & 3;
}

static_always_inline void
poly1305_one_block (u32 h[5], const u32 *r, const u32 *f, u32u *m,
		    const u32 final_one)
{
  u64 s[5], a[6], b[6];
  /* sum of message and accumulator (h += m), no carry propagated */
  s[0] = (u64) h[0] + m[0];
  s[1] = (u64) h[1] + m[1];
  s[2] = (u64) h[2] + m[2];
  s[3] = (u64) h[3] + m[3];
  s[4] = h[4] + (final_one ? 1 : 0);

  /* multiply h and r modulo p (h = (h * p) mod p, no carry propagated */
  a[0] = s[0] * r[0] + s[1] * f[3] + s[2] * f[2] + s[3] * f[1] + s[4] * f[0];
  a[1] = s[0] * r[1] + s[1] * r[0] + s[2] * f[3] + s[3] * f[2] + s[4] * f[1];
  a[2] = s[0] * r[2] + s[1] * r[1] + s[2] * r[0] + s[3] * f[3] + s[4] * f[2];
  a[3] = s[0] * r[3] + s[1] * r[2] + s[2] * r[1] + s[3] * r[0] + s[4] * f[3];
  a[4] = s[4] * f[4];

  /* partial carry propagation */
  b[0] = (u32) a[0];
  b[1] = (u32) a[1] + (a[0] >> 32);
  b[2] = (u32) a[2] + (a[1] >> 32);
  b[3] = (u32) a[3] + (a[2] >> 32);
  b[4] = a[4] + (a[3] >> 32);

  b[0] += (b[4] >> 2) * 5;
  b[4] &= 3;

  b[1] += b[0] >> 32;
  b[2] += b[1] >> 32;
  b[3] += b[2] >> 32;
  b[4] += b[3] >> 32;

  /* store accumulator */
  h[0] = b[0];
  h[1] = b[1];
  h[2] = b[2];
  h[3] = b[3];
  h[4] = b[4];
}

static_always_inline void
clib_poly1305_update (clib_poly1305_ctx *ctx, const u8 *msg, uword len)
{
  if (len == 0)
    return;

  if (ctx->n_partial_bytes)
    {
      uword n = 16 - ctx->n_partial_bytes;
      if (PREDICT_FALSE (len < n))
	{
	  clib_memcpy (ctx->partial + ctx->n_partial_bytes, msg, len);
	  ctx->n_partial_bytes += len;
	  return;
	}

      clib_memcpy (ctx->partial + ctx->n_partial_bytes, msg, n);
      poly1305_one_block (ctx->h, ctx->r, ctx->f, (u32u *) ctx->partial, 0);
      ctx->n_partial_bytes = 0;
      len -= n;
      msg += n;
    }

  u32 h[5];
  for (int i = 0; i < ARRAY_LEN (h); i++)
    h[i] = ctx->h[i];

  for (; len >= 16; len -= 16, msg += 16)
    poly1305_one_block (h, ctx->r, ctx->f, (u32u *) msg, 1);

  for (int i = 0; i < ARRAY_LEN (h); i++)
    ctx->h[i] = h[i];

  if (len > 0)
    {
      clib_memset_u8 (ctx->partial, 0, 16);
      clib_memcpy (ctx->partial, msg + len - len, len);
      ctx->n_partial_bytes = len;
    }
}

static_always_inline void
clib_poly1305_final (clib_poly1305_ctx *ctx, u8 tag[16])
{
  u32u *t = (u32u *) tag;
  u32 *h = (u32 *) ctx->h;
  const u32 *s = (u32 *) ctx->s;

  if (ctx->n_partial_bytes)
    {
      ctx->partial[ctx->n_partial_bytes] = 1;
      poly1305_one_block (ctx->h, ctx->r, ctx->f, (u32u *) ctx->partial, 0);
    }

  /* check if we should subtract 2^130-5 by performing the corresponding carry
   * propagation. */
  u64 c = 5;
  c = (c + h[0]) >> 32;
  c = (c + h[1]) >> 32;
  c = (c + h[2]) >> 32;
  c = (c + h[3]) >> 32;
  c += h[4];

  c = (c >> 2) * 5; /* shift the carry back to the beginning  */

  /*c now indicates how many times we should subtract 2^130-5 (0 or 1) */

  t[0] = c = c + h[0] + s[0];
  t[1] = c = (c >> 32) + h[1] + s[1];
  t[2] = c = (c >> 32) + h[2] + s[2];
  t[3] = c = (c >> 32) + h[3] + s[3];
}

static_always_inline void
clib_poly1305 (const u8 key[32], const u8 *msg, uword len, u8 tag[16])
{
  clib_poly1305_ctx ctx;
  clib_poly1305_init (&ctx, key);
  clib_poly1305_update (&ctx, msg, len);
  clib_poly1305_final (&ctx, tag);
}

#endif /* __clib_poly1305_h__ */
