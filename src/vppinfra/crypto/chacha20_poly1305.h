/*
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/string.h>
#include <vppinfra/crypto/poly1305.h>

#if defined(CLIB_HAVE_VEC512) || defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)
#include <vppinfra/crypto/chacha20.h>

static_always_inline void
clib_chacha20_poly1305_update_padded (clib_poly1305_ctx_t *ctx, const u8 *data, uword n_bytes)
{
  u8 zero[16] = {};

  if (n_bytes)
    clib_poly1305_update (ctx, data, n_bytes);

  if (n_bytes & 0xf)
    clib_poly1305_update (ctx, zero, 16 - (n_bytes & 0xf));
}

static_always_inline int
clib_chacha20_poly1305_enc (const u8 *src, u8 *dst, const u8 *aad, const u8 *iv, u8 *tag,
			    u32 data_bytes, u32 aad_bytes, const u8 *key)
{
  clib_poly1305_ctx_t poly_ctx = {};
  clib_poly1305_init_data_t poly_kd = {};
  u64u lengths[2];
  u8 otk[64] = {};

  clib_chacha20 (otk, otk, sizeof (otk), key, iv, 0);
  clib_poly1305_precompute (&poly_kd, otk);
  clib_poly1305_init (&poly_ctx, &poly_kd);

  clib_chacha20_poly1305_update_padded (&poly_ctx, aad, aad_bytes);

  if (data_bytes)
    clib_chacha20 (dst, (u8 *) src, data_bytes, key, iv, 1);
  clib_chacha20_poly1305_update_padded (&poly_ctx, dst, data_bytes);

  lengths[0] = aad_bytes;
  lengths[1] = data_bytes;
  clib_poly1305_update (&poly_ctx, (u8 *) lengths, sizeof (lengths));
  clib_poly1305_final (&poly_ctx, tag);

  return 1;
}

static_always_inline int
clib_chacha20_poly1305_dec (const u8 *src, u8 *dst, const u8 *aad, const u8 *iv, const u8 *tag,
			    u32 data_bytes, u32 aad_bytes, const u8 *key)
{
  clib_poly1305_ctx_t poly_ctx = {};
  clib_poly1305_init_data_t poly_kd = {};
  u64u lengths[2];
  u8 tag_calc[16];
  u8 otk[64] = {};

  clib_chacha20 (otk, otk, sizeof (otk), key, iv, 0);
  clib_poly1305_precompute (&poly_kd, otk);
  clib_poly1305_init (&poly_ctx, &poly_kd);

  clib_chacha20_poly1305_update_padded (&poly_ctx, aad, aad_bytes);
  clib_chacha20_poly1305_update_padded (&poly_ctx, src, data_bytes);

  lengths[0] = aad_bytes;
  lengths[1] = data_bytes;
  clib_poly1305_update (&poly_ctx, (u8 *) lengths, sizeof (lengths));
  clib_poly1305_final (&poly_ctx, tag_calc);

  if (clib_memcmp (tag_calc, tag, sizeof (tag_calc)) != 0)
    return 0;
  if (data_bytes)
    clib_chacha20 (dst, (u8 *) src, data_bytes, key, iv, 1);
  return 1;
}

#endif
