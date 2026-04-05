/*
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/string.h>
#include <vppinfra/crypto/poly1305.h>

#if defined(CLIB_HAVE_VEC512) || defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)
#include <vppinfra/crypto/chacha20.h>

typedef enum
{
  CLIB_CHACHA20_POLY1305_OP_ENCRYPT,
  CLIB_CHACHA20_POLY1305_OP_DECRYPT,
} clib_chacha20_poly1305_op_t;

static_always_inline void
clib_chacha20_poly1305_update_padded (clib_poly1305_ctx *ctx, const u8 *data, uword n_bytes)
{
  u8 zero[16] = {};

  if (n_bytes)
    clib_poly1305_update (ctx, data, n_bytes);

  if (n_bytes & 0xf)
    clib_poly1305_update (ctx, zero, 16 - (n_bytes & 0xf));
}

static_always_inline int
clib_chacha20_poly1305 (const u8 *src, u8 *dst, const u8 *aad, const u8 *iv, u8 *tag,
			u32 data_bytes, u32 aad_bytes, const u8 *key,
			clib_chacha20_poly1305_op_t op)
{
  clib_poly1305_ctx poly_ctx = {};
  u64u lengths[2];
  u8 tag_calc[16];
  u8 otk[64] = {};

  clib_chacha20 (otk, otk, sizeof (otk), key, iv, 0);
  clib_poly1305_init (&poly_ctx, otk);

  clib_chacha20_poly1305_update_padded (&poly_ctx, aad, aad_bytes);

  if (op == CLIB_CHACHA20_POLY1305_OP_ENCRYPT)
    {
      if (data_bytes)
	clib_chacha20 (dst, (u8 *) src, data_bytes, key, iv, 1);
      clib_chacha20_poly1305_update_padded (&poly_ctx, dst, data_bytes);
    }
  else
    {
      clib_chacha20_poly1305_update_padded (&poly_ctx, src, data_bytes);
    }

  lengths[0] = aad_bytes;
  lengths[1] = data_bytes;
  clib_poly1305_update (&poly_ctx, (u8 *) lengths, sizeof (lengths));
  clib_poly1305_final (&poly_ctx, tag_calc);

  if (op == CLIB_CHACHA20_POLY1305_OP_DECRYPT)
    {
      if (clib_memcmp (tag_calc, tag, sizeof (tag_calc)) != 0)
	return 0;
      if (data_bytes)
	clib_chacha20 (dst, (u8 *) src, data_bytes, key, iv, 1);
      return 1;
    }

  clib_memcpy_fast (tag, tag_calc, sizeof (tag_calc));
  return 1;
}

#endif
