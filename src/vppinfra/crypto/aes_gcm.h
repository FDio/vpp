/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef __crypto_aes_gcm_h__
#define __crypto_aes_gcm_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>
#include <vppinfra/crypto/aes.h>
#include <vppinfra/crypto/ghash.h>

#define NUM_HI 32

typedef struct
{
  /* pre-calculated hash key values */
  const u8x16 Hi[NUM_HI];
  /* extracted AES key */
  const u8x16 Ke[AES_KEY_ROUNDS (AES_KEY_256) + 1];
#if defined(__VAES__) && defined(__AVX512F__)
  const u8x64 Ke4[AES_KEY_ROUNDS (AES_KEY_256) + 1];
#endif
} aes_gcm_key_data_t;

typedef struct
{
  int is_encrypt;
  int last;
  u8 rounds;
  u8x16 T;

  /* expaded keys */
  const u8x16 *Hi;
  const u8x16 *Ke;
#if defined(__VAES__) && defined(__AVX512F__)
  const u8x64 *Ke4;
#endif

  /* counter */
  u32 counter;
  union
  {
    u32x4 Y;
    u32x16 Y4;
  };
} aes_gcm_ctx_t;

static const u32x4 ctr_inv_1 = { 0, 0, 0, 1 << 24 };

static_always_inline void
aes_gcm_enc_first_round (u8x16 *r, aes_gcm_ctx_t *ctx, int n_blocks)
{
  u8x16 k = ctx->Ke[0];
  int i = 0;

  if (PREDICT_TRUE ((u8) ctx->counter < 0xfe) || n_blocks < 3)
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x16) ctx->Y;
	  ctx->Y += ctr_inv_1;
	}
      ctx->counter += n_blocks;
    }
  else
    {
      r[i++] = k ^ (u8x16) ctx->Y;
      ctx->Y += ctr_inv_1;
      ctx->counter += 1;

      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x16) ctx->Y;
	  ctx->counter++;
	  ctx->Y[3] = clib_host_to_net_u32 (ctx->counter);
	}
    }
}

static_always_inline void
aes_gcm_enc_round (u8x16 *r, u8x16 k, int n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
    r[i] = aes_enc_round (r[i], k);
}

static_always_inline void
aes_gcm_enc_last_round (aes_gcm_ctx_t *ctx, u8x16 *r, u8x16 *d, u8x16 const *k,
			int n_blocks)
{

  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < ctx->rounds; i++)
    aes_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
    d[i] ^= aes_enc_last_round (r[i], k[ctx->rounds]);
}

static_always_inline void
aes_gcm_ghash (aes_gcm_ctx_t *ctx, u8 *data, u32 n_left)
{
  uword i;
#if defined(__VAES__) && defined(__AVX512F__)
  u8x64u *Hi4, *d = (u8x64u *) data;
  ghash4_data_t _gd = {}, *gd = &_gd;
  u8x64 r = {}, tag4 = {};

  for (; n_left >= 512; n_left -= 512, d += 8)
    {
      Hi4 = (u8x64u *) (ctx->Hi + NUM_HI - 32);
      tag4 = u8x64_insert_u8x16 (tag4, ctx->T, 0);

      ghash4_mul_first (gd, u8x64_reflect_u8x16 (d[0]) ^ tag4, Hi4[0]);
      for (i = 1; i < 8; i++)
	ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[i]), Hi4[i]);
      ghash4_reduce (gd);
      ghash4_reduce2 (gd);
      ctx->T = ghash4_final (gd);
    }

  if (n_left > 0)
    {
      Hi4 = (u8x64u *) (ctx->Hi + NUM_HI - ((n_left + 15) / 16));
      tag4 = u8x64_insert_u8x16 (tag4, ctx->T, 0);

      if (n_left < 64)
	{
	  clib_memcpy_fast (&r, d, n_left);
	  ghash4_mul_first (gd, u8x64_reflect_u8x16 (r) ^ tag4, Hi4[0]);
	  ghash4_reduce (gd);
	}
      else
	{
	  ghash4_mul_first (gd, u8x64_reflect_u8x16 (d[0]) ^ tag4, Hi4[0]);
	  n_left -= 64;
	  i = 1;

	  if (n_left >= 256)
	    {
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i])), Hi4[i]);
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i + 1])),
			       Hi4[i + 1]);
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i + 2])),
			       Hi4[i + 2]);
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i + 3])),
			       Hi4[i + 3]);
	      n_left -= 256;
	      i += 4;
	    }

	  if (n_left >= 128)
	    {
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i])), Hi4[i]);
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i + 1])),
			       Hi4[i + 1]);
	      n_left -= 128;
	      i += 2;
	    }

	  if (n_left >= 64)
	    {
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 ((d[i])), Hi4[i]);
	      n_left -= 64;
	      i += 1;
	    }

	  if (n_left)
	    {
	      clib_memcpy_fast (&r, d + i, n_left);
	      ghash4_mul_next (gd, u8x64_reflect_u8x16 (r), Hi4[i]);
	    }

	  ghash4_reduce (gd);
	}
      ghash4_reduce2 (gd);
      ctx->T = ghash4_final (gd);
    }
#elif defined(__VAES__)
  u8x32u *Hi2, *d = (u8x32u *) data;
  ghash2_data_t _gd = {}, *gd = &_gd;
  u8x32 r = {}, tag2 = {};

  for (; n_left >= 256; n_left -= 256, d += 8)
    {
      Hi2 = (u8x32u *) (ctx->Hi + NUM_HI - 16);
      tag2 = u8x32_insert_lo (tag2, ctx->T);

      ghash2_mul_first (gd, u8x32_reflect_u8x16 (d[0]) ^ tag2, Hi2[0]);
      for (i = 1; i < 8; i++)
	ghash2_mul_next (gd, u8x32_reflect_u8x16 (d[i]), Hi2[i]);
      ghash2_reduce (gd);
      ghash2_reduce2 (gd);
      ctx->T = ghash2_final (gd);
    }

  if (n_left > 0)
    {
      Hi2 = (u8x32u *) (ctx->Hi + NUM_HI - (n_left + 15) / 16);
      tag2 = u8x32_insert_lo (tag2, ctx->T);

      if (n_left < 32)
	{
	  clib_memcpy_fast (&r, d, n_left);
	  ghash2_mul_first (gd, u8x32_reflect_u8x16 (r) ^ tag2, Hi2[0]);
	  ghash2_reduce (gd);
	}
      else
	{
	  ghash2_mul_first (gd, u8x32_reflect_u8x16 (d[0]) ^ tag2, Hi2[0]);
	  n_left -= 32;
	  i = 1;

	  if (n_left >= 128)
	    {
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i])), Hi2[i]);
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i + 1])),
			       Hi2[i + 1]);
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i + 2])),
			       Hi2[i + 2]);
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i + 3])),
			       Hi2[i + 3]);
	      n_left -= 128;
	      i += 4;
	    }

	  if (n_left >= 64)
	    {
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i])), Hi2[i]);
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i + 1])),
			       Hi2[i + 1]);
	      n_left -= 64;
	      i += 2;
	    }

	  if (n_left >= 32)
	    {
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 ((d[i])), Hi2[i]);
	      n_left -= 32;
	      i += 1;
	    }

	  if (n_left > 0)
	    {
	      clib_memcpy_fast (&r, d + i, n_left);
	      ghash2_mul_next (gd, u8x32_reflect_u8x16 (r), Hi2[i]);
	    }

	  ghash2_reduce (gd);
	}
      ghash2_reduce2 (gd);
      ctx->T = ghash2_final (gd);
    }
#else
  ghash_data_t _gd, *gd = &_gd;
  u8x16 *Hi, r = {};
  u8x16u *d = (u8x16u *) data;

  for (; n_left >= 128; n_left -= 128, d += 8)
    {
      Hi = (u8x16 *) (ctx->Hi + NUM_HI - 8);
      ghash_mul_first (gd, u8x16_reflect (d[0]) ^ ctx->T, Hi[0]);
      for (i = 1; i < 8; i++)
	ghash_mul_next (gd, u8x16_reflect ((d[i])), Hi[i]);
      ghash_reduce (gd);
      ghash_reduce2 (gd);
      ctx->T = ghash_final (gd);
    }

  if (n_left)
    {

      if (n_left < 16)
	{
	  clib_memcpy_fast (&r, d, n_left);
	  ghash_mul_first (gd, u8x16_reflect (r) ^ ctx->T,
			   ctx->Hi[NUM_HI - 1]);
	  ghash_reduce (gd);
	}
      else
	{

	  Hi = (u8x16 *) (ctx->Hi + NUM_HI - ((n_left + 15) / 16));
	  ghash_mul_first (gd, u8x16_reflect (d[0]) ^ ctx->T, Hi[0]);
	  n_left -= 16;
	  i = 1;

	  if (n_left >= 64)
	    {
	      ghash_mul_next (gd, u8x16_reflect ((d[i])), Hi[i]);
	      ghash_mul_next (gd, u8x16_reflect ((d[i + 1])), Hi[i + 1]);
	      ghash_mul_next (gd, u8x16_reflect ((d[i + 2])), Hi[i + 2]);
	      ghash_mul_next (gd, u8x16_reflect ((d[i + 3])), Hi[i + 3]);
	      n_left -= 64;
	      i += 4;
	    }

	  if (n_left >= 32)
	    {
	      ghash_mul_next (gd, u8x16_reflect ((d[i])), Hi[i]);
	      ghash_mul_next (gd, u8x16_reflect ((d[i + 1])), Hi[i + 1]);
	      n_left -= 32;
	      i += 2;
	    }

	  if (n_left >= 16)
	    {
	      ghash_mul_next (gd, u8x16_reflect ((d[i])), Hi[i]);
	      n_left -= 16;
	      i += 1;
	    }

	  if (n_left)
	    {
	      u8x16 r = {};
	      clib_memcpy_fast (&r, d + i, n_left);
	      ghash_mul_next (gd, u8x16_reflect (r), Hi[i]);
	    }

	  ghash_reduce (gd);
	}
      ghash_reduce2 (gd);
      ctx->T = ghash_final (gd);
    }
#endif
}

static_always_inline __clib_unused void
aes_gcm_calc (aes_gcm_ctx_t *ctx, u8x16 *d, u8x16u *inv, u8x16u *outv, int n,
	      int last_block_bytes, int with_ghash)
{
  u8x16 r[n];
  ghash_data_t _gd = {}, *gd = &_gd;
  const u8x16 *rk = (u8x16 *) ctx->Ke;
  int ghash_blocks = (ctx->is_encrypt) ? 4 : n, gc = 1;
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - ghash_blocks;

  clib_prefetch_load (inv + 4);

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (r, ctx, n);
  aes_gcm_enc_round (r, rk[1], n);

  /* load data - decrypt round */
  if (!ctx->is_encrypt)
    {
      for (int i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[n - 1] = aes_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH multiply block 1 */
  if (with_ghash)
    ghash_mul_first (gd, u8x16_reflect (d[0]) ^ ctx->T, Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, rk[2], n);
  aes_gcm_enc_round (r, rk[3], n);

  /* GHASH multiply block 2 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, rk[4], n);
  aes_gcm_enc_round (r, rk[5], n);

  /* GHASH multiply block 3 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, rk[6], n);
  aes_gcm_enc_round (r, rk[7], n);

  /* GHASH multiply block 4 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[3]);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, rk[8], n);
  aes_gcm_enc_round (r, rk[9], n);

  /* GHASH reduce 1st step */
  if (with_ghash)
    ghash_reduce (gd);

  /* load data - encrypt round */
  if (ctx->is_encrypt)
    {
      for (int i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[n - 1] = aes_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH reduce 2nd step */
  if (with_ghash)
    ghash_reduce2 (gd);

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, rk, n);

  /* store data */
  for (int i = 0; i < n - ctx->last; i++)
    outv[i] = d[i];

  if (ctx->last)
    aes_store_partial (outv + n - 1, d[n - 1], last_block_bytes);

  /* GHASH final step */
  if (with_ghash)
    ctx->T = ghash_final (gd);
}

static_always_inline __clib_unused void
aes_gcm_calc_double (aes_gcm_ctx_t *ctx, u8x16 *d, u8x16u *inv, u8x16u *outv,
		     int with_ghash)
{
  u8x16 r[4];
  ghash_data_t _gd, *gd = &_gd;
  const u8x16 *rk = (u8x16 *) ctx->Ke;
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - 8;

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (r, ctx, 4);
  aes_gcm_enc_round (r, rk[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (!ctx->is_encrypt)
    {
      d[0] = inv[0];
      d[1] = inv[1];
      d[2] = inv[2];
      d[3] = inv[3];
    }

  /* GHASH multiply block 0 */
  ghash_mul_first (gd, u8x16_reflect (d[0]) ^ ctx->T, Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, rk[2], 4);
  aes_gcm_enc_round (r, rk[3], 4);

  /* GHASH multiply block 1 */
  ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, rk[4], 4);
  aes_gcm_enc_round (r, rk[5], 4);

  /* GHASH multiply block 2 */
  ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, rk[6], 4);
  aes_gcm_enc_round (r, rk[7], 4);

  /* GHASH multiply block 3 */
  ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[3]);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, rk[8], 4);
  aes_gcm_enc_round (r, rk[9], 4);

  /* load 4 blocks of data - encrypt round */
  if (ctx->is_encrypt)
    {
      d[0] = inv[0];
      d[1] = inv[1];
      d[2] = inv[2];
      d[3] = inv[3];
    }

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, rk, 4);

  /* store 4 blocks of data */
  outv[0] = d[0];
  outv[1] = d[1];
  outv[2] = d[2];
  outv[3] = d[3];

  /* load next 4 blocks of data data - decrypt round */
  if (!ctx->is_encrypt)
    {
      d[0] = inv[4];
      d[1] = inv[5];
      d[2] = inv[6];
      d[3] = inv[7];
    }

  /* GHASH multiply block 4 */
  ghash_mul_next (gd, u8x16_reflect (d[0]), Hi[4]);

  /* AES rounds 0, 1 and 2 */
  aes_gcm_enc_first_round (r, ctx, 4);
  aes_gcm_enc_round (r, rk[1], 4);
  aes_gcm_enc_round (r, rk[2], 4);

  /* GHASH multiply block 5 */
  ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[5]);

  /* AES rounds 3 and 4 */
  aes_gcm_enc_round (r, rk[3], 4);
  aes_gcm_enc_round (r, rk[4], 4);

  /* GHASH multiply block 6 */
  ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[6]);

  /* AES rounds 5 and 6 */
  aes_gcm_enc_round (r, rk[5], 4);
  aes_gcm_enc_round (r, rk[6], 4);

  /* GHASH multiply block 7 */
  ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[7]);

  /* AES rounds 7 and 8 */
  aes_gcm_enc_round (r, rk[7], 4);
  aes_gcm_enc_round (r, rk[8], 4);

  /* GHASH reduce 1st step */
  ghash_reduce (gd);

  /* AES round 9 */
  aes_gcm_enc_round (r, rk[9], 4);

  /* load data - encrypt round */
  if (ctx->is_encrypt)
    {
      d[0] = inv[4];
      d[1] = inv[5];
      d[2] = inv[6];
      d[3] = inv[7];
    }

  /* GHASH reduce 2nd step */
  ghash_reduce2 (gd);

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, rk, 4);

  /* store data */
  outv[4] = d[0];
  outv[5] = d[1];
  outv[6] = d[2];
  outv[7] = d[3];

  /* GHASH final step */
  ctx->T = ghash_final (gd);
}

static_always_inline __clib_unused void
aes_gcm_ghash_last (aes_gcm_ctx_t *ctx, u8x16 *d, int n_blocks, int n_bytes)
{
  ghash_data_t _gd, *gd = &_gd;
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - n_blocks;

  if (n_bytes)
    d[n_blocks - 1] = aes_byte_mask (d[n_blocks - 1], n_bytes);

  ghash_mul_first (gd, u8x16_reflect (d[0]) ^ ctx->T, Hi[0]);
  if (n_blocks > 1)
    ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[1]);
  if (n_blocks > 2)
    ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[2]);
  if (n_blocks > 3)
    ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[3]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  ctx->T = ghash_final (gd);
}

#if defined(__VAES__) && defined(__AVX512F__)
static const u32x16 ctr_inv_1234 = {
  0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24, 0, 0, 0, 3 << 24, 0, 0, 0, 4 << 24,
};

static const u32x16 ctr_inv_4444 = { 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24,
				     0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24 };

static const u32x16 ctr_1234 = {
  1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
};
static const u32x16 ctr_4444 = {
  4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0,
};

static_always_inline void
aes4_gcm_enc_first_round (u8x64 *r, aes_gcm_ctx_t *ctx, int n)
{
  u8x64 k = ctx->Ke4[0];
  int i = 0;

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 512-blocks in parallel except the
     last round, overflow can happen only when n == 4 */

  if (n == 4)
    for (; i < 2; i++)
      {
	r[i] = k ^ (u8x64) ctx->Y4;
	ctx->Y4 += ctr_inv_4444;
      }

  if (n == 4 && PREDICT_FALSE ((u8) ctx->counter == 242))
    {
      u32x16 Yr = (u32x16) u8x64_reflect_u8x16 ((u8x64) ctx->Y4);

      for (; i < n; i++)
	{
	  r[i] = k ^ (u8x64) ctx->Y4;
	  Yr += ctr_4444;
	  ctx->Y4 = (u32x16) u8x64_reflect_u8x16 ((u8x64) Yr);
	}
    }
  else
    {
      for (; i < n; i++)
	{
	  r[i] = k ^ (u8x64) ctx->Y4;
	  ctx->Y4 += ctr_inv_4444;
	}
    }
  ctx->counter += n * 4;
}

static_always_inline void
aes4_gcm_enc_round (u8x64 *r, u8x64 k, int n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
    r[i] = aes_enc_round_x4 (r[i], k);
}

static_always_inline void
aes4_gcm_enc_last_round (aes_gcm_ctx_t *ctx, u8x64 *r, u8x64 *d,
			 u8x64 const *k, int n_blocks)
{

  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < ctx->rounds; i++)
    aes4_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
    d[i] ^= aes_enc_last_round_x4 (r[i], k[ctx->rounds]);
}

static_always_inline void
aes4_gcm_calc (aes_gcm_ctx_t *ctx, u8x64 *d, u8x16u *in, u8x16u *out, int n,
	       int last_4block_bytes, int with_ghash)
{
  ghash4_data_t _gd, *gd = &_gd;
  const u8x64 *rk = (u8x64 *) ctx->Ke4;
  int i, ghash_blocks, gc = 1;
  u8x64u *Hi4, *inv = (u8x64u *) in, *outv = (u8x64u *) out;
  u8x64 r[4];
  u64 byte_mask = _bextr_u64 (-1LL, 0, last_4block_bytes);

  if (ctx->is_encrypt)
    {
      /* during encryption we either hash four 512-bit blocks from previous
	 round or we don't hash at all */
      ghash_blocks = 4;
      Hi4 = (u8x64u *) (ctx->Hi + NUM_HI - ghash_blocks * 4);
    }
  else
    {
      /* during deccryption we hash 1..4 512-bit blocks from current round */
      ghash_blocks = n;
      int n_128bit_blocks = n * 4;
      /* if this is last round of decryption, we may have less than 4
	 128-bit blocks in the last 512-bit data block, so we need to adjust
	 Hi4 pointer accordingly */
      if (ctx->last)
	n_128bit_blocks += ((last_4block_bytes + 15) >> 4) - 4;
      Hi4 = (u8x64u *) (ctx->Hi + NUM_HI - n_128bit_blocks);
    }

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctx, n);
  aes4_gcm_enc_round (r, rk[1], n);

  /* load 4 blocks of data - decrypt round */
  if (!ctx->is_encrypt)
    {
      for (i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[i] = u8x64_mask_load (u8x64_splat (0), inv + i, byte_mask);
    }

  /* GHASH multiply block 0 */
  if (with_ghash)
    ghash4_mul_first (gd,
		      u8x64_reflect_u8x16 (d[0]) ^
			u8x64_insert_u8x16 (u8x64_zero (), ctx->T, 0),
		      Hi4[0]);

  /* AES rounds 2 and 3 */
  aes4_gcm_enc_round (r, rk[2], n);
  aes4_gcm_enc_round (r, rk[3], n);

  /* GHASH multiply block 1 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[1]);

  /* AES rounds 4 and 5 */
  aes4_gcm_enc_round (r, rk[4], n);
  aes4_gcm_enc_round (r, rk[5], n);

  /* GHASH multiply block 2 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[2]);

  /* AES rounds 6 and 7 */
  aes4_gcm_enc_round (r, rk[6], n);
  aes4_gcm_enc_round (r, rk[7], n);

  /* GHASH multiply block 3 */
  if (with_ghash && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[3]);

  /* load 4 blocks of data - decrypt round */
  if (ctx->is_encrypt)
    {
      for (i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[i] = u8x64_mask_load (u8x64_zero (), inv + i, byte_mask);
    }

  /* AES rounds 8 and 9 */
  aes4_gcm_enc_round (r, rk[8], n);
  aes4_gcm_enc_round (r, rk[9], n);

  /* AES last round(s) */
  aes4_gcm_enc_last_round (ctx, r, d, rk, n);

  /* store 4 blocks of data */
  for (i = 0; i < n - ctx->last; i++)
    outv[i] = d[i];

  if (ctx->last)
    u8x64_mask_store (d[i], outv + i, byte_mask);

  /* GHASH reduce 1st step */
  ghash4_reduce (gd);

  /* GHASH reduce 2nd step */
  ghash4_reduce2 (gd);

  /* GHASH final step */
  if (with_ghash)
    ctx->T = ghash4_final (gd);
}

static_always_inline void
aes4_gcm_calc_double (aes_gcm_ctx_t *ctx, u8x64 *d, u8x16u *in, u8x16u *out,
		      int with_ghash)
{
  u8x64 r[4];
  ghash4_data_t _gd, *gd = &_gd;
  const u8x64 *rk = (u8x64 *) ctx->Ke4;
  u8x64 *Hi4 = (u8x64 *) (ctx->Hi + NUM_HI - 32);
  u8x64u *inv = (u8x64u *) in, *outv = (u8x64u *) out;

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctx, 4);
  aes4_gcm_enc_round (r, rk[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (!ctx->is_encrypt)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i];

  /* GHASH multiply block 0 */
  ghash4_mul_first (gd,
		    u8x64_reflect_u8x16 (d[0]) ^
		      u8x64_insert_u8x16 (u8x64_zero (), ctx->T, 0),
		    Hi4[0]);

  /* AES rounds 2 and 3 */
  aes4_gcm_enc_round (r, rk[2], 4);
  aes4_gcm_enc_round (r, rk[3], 4);

  /* GHASH multiply block 1 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[1]);

  /* AES rounds 4 and 5 */
  aes4_gcm_enc_round (r, rk[4], 4);
  aes4_gcm_enc_round (r, rk[5], 4);

  /* GHASH multiply block 2 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[2]);

  /* AES rounds 6 and 7 */
  aes4_gcm_enc_round (r, rk[6], 4);
  aes4_gcm_enc_round (r, rk[7], 4);

  /* GHASH multiply block 3 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[3]);

  /* AES rounds 8 and 9 */
  aes4_gcm_enc_round (r, rk[8], 4);
  aes4_gcm_enc_round (r, rk[9], 4);

  /* load 4 blocks of data - encrypt round */
  if (ctx->is_encrypt)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i];

  /* AES last round(s) */
  aes4_gcm_enc_last_round (ctx, r, d, rk, 4);

  /* store 4 blocks of data */
  for (int i = 0; i < 4; i++)
    outv[i] = d[i];

  /* load 4 blocks of data - decrypt round */
  if (!ctx->is_encrypt)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i + 4];

  /* GHASH multiply block 3 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[0]), Hi4[4]);

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctx, 4);
  aes4_gcm_enc_round (r, rk[1], 4);

  /* GHASH multiply block 5 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[5]);

  /* AES rounds 2 and 3 */
  aes4_gcm_enc_round (r, rk[2], 4);
  aes4_gcm_enc_round (r, rk[3], 4);

  /* GHASH multiply block 6 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[6]);

  /* AES rounds 4 and 5 */
  aes4_gcm_enc_round (r, rk[4], 4);
  aes4_gcm_enc_round (r, rk[5], 4);

  /* GHASH multiply block 7 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[7]);

  /* AES rounds 6 and 7 */
  aes4_gcm_enc_round (r, rk[6], 4);
  aes4_gcm_enc_round (r, rk[7], 4);

  /* GHASH reduce 1st step */
  ghash4_reduce (gd);

  /* AES rounds 8 and 9 */
  aes4_gcm_enc_round (r, rk[8], 4);
  aes4_gcm_enc_round (r, rk[9], 4);

  /* GHASH reduce 2nd step */
  ghash4_reduce2 (gd);

  /* load 4 blocks of data - encrypt round */
  if (ctx->is_encrypt)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i + 4];

  /* AES last round(s) */
  aes4_gcm_enc_last_round (ctx, r, d, rk, 4);

  /* store 4 blocks of data */
  for (int i = 0; i < 4; i++)
    outv[i + 4] = d[i];

  /* GHASH final step */
  ctx->T = ghash4_final (gd);
}

static_always_inline void
aes4_gcm_ghash_last (aes_gcm_ctx_t *ctx, u8x64 *d, int n,
		     int last_4block_bytes)
{
  ghash4_data_t _gd, *gd = &_gd;
  u8x64u *Hi4;
  int n_128bit_blocks;
  u64 byte_mask = _bextr_u64 (-1LL, 0, last_4block_bytes);
  n_128bit_blocks = (n - 1) * 4 + ((last_4block_bytes + 15) >> 4);
  Hi4 = (u8x64u *) (ctx->Hi + NUM_HI - n_128bit_blocks);

  d[n - 1] = u8x64_mask_blend (u8x64_zero (), d[n - 1], byte_mask);
  ghash4_mul_first (gd,
		    u8x64_reflect_u8x16 (d[0]) ^
		      u8x64_insert_u8x16 (u8x64_zero (), ctx->T, 0),
		    Hi4[0]);
  if (n > 1)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[1]);
  if (n > 2)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[2]);
  if (n > 3)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[3]);
  ghash4_reduce (gd);
  ghash4_reduce2 (gd);
  ctx->T = ghash4_final (gd);
}
#endif

static_always_inline void
aes_gcm_enc (aes_gcm_ctx_t *ctx, u8x16u *inv, u8x16u *outv, u32 n_left)
{
  if (n_left == 0)
    return;

#if defined(__VAES__) && defined(__AVX512F__)
  u8x64 d4[4];
  if (n_left < 256)
    {
      ctx->last = 1;
      if (n_left > 192)
	{
	  n_left -= 192;
	  aes4_gcm_calc (ctx, d4, inv, outv, 4, n_left, /* with_ghash */ 0);
	  aes4_gcm_ghash_last (ctx, d4, 4, n_left);
	}
      else if (n_left > 128)
	{
	  n_left -= 128;
	  aes4_gcm_calc (ctx, d4, inv, outv, 3, n_left, /* with_ghash */ 0);
	  aes4_gcm_ghash_last (ctx, d4, 3, n_left);
	}
      else if (n_left > 64)
	{
	  n_left -= 64;
	  aes4_gcm_calc (ctx, d4, inv, outv, 2, n_left, /* with_ghash */ 0);
	  aes4_gcm_ghash_last (ctx, d4, 2, n_left);
	}
      else
	{
	  aes4_gcm_calc (ctx, d4, inv, outv, 1, n_left, /* with_ghash */ 0);
	  aes4_gcm_ghash_last (ctx, d4, 1, n_left);
	}
      return;
    }

  aes4_gcm_calc (ctx, d4, inv, outv, 4, 0, /* with_ghash */ 0);

  /* next */
  n_left -= 256;
  outv += 16;
  inv += 16;

  while (n_left >= 512)
    {
      aes4_gcm_calc_double (ctx, d4, inv, outv, /* with_ghash */ 1);

      /* next */
      n_left -= 512;
      outv += 32;
      inv += 32;
    }

  if (n_left >= 256)
    {
      aes4_gcm_calc (ctx, d4, inv, outv, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 256;
      outv += 16;
      inv += 16;
    }

  if (n_left == 0)
    {
      aes4_gcm_ghash_last (ctx, d4, 4, 64);
      return;
    }

  ctx->last = 1;
  if (n_left > 192)
    {
      n_left -= 192;
      aes4_gcm_calc (ctx, d4, inv, outv, 4, n_left, /* with_ghash */ 1);
      aes4_gcm_ghash_last (ctx, d4, 4, n_left);
    }
  else if (n_left > 128)
    {
      n_left -= 128;
      aes4_gcm_calc (ctx, d4, inv, outv, 3, n_left, /* with_ghash */ 1);
      aes4_gcm_ghash_last (ctx, d4, 3, n_left);
    }
  else if (n_left > 64)
    {
      n_left -= 64;
      aes4_gcm_calc (ctx, d4, inv, outv, 2, n_left, /* with_ghash */ 1);
      aes4_gcm_ghash_last (ctx, d4, 2, n_left);
    }
  else
    {
      aes4_gcm_calc (ctx, d4, inv, outv, 1, n_left, /* with_ghash */ 1);
      aes4_gcm_ghash_last (ctx, d4, 1, n_left);
    }
  return;
#else
  u8x16 d[4];
  if (n_left < 64)
    {
      ctx->last = 1;
      if (n_left > 48)
	{
	  n_left -= 48;
	  aes_gcm_calc (ctx, d, inv, outv, 4, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 4, n_left);
	}
      else if (n_left > 32)
	{
	  n_left -= 32;
	  aes_gcm_calc (ctx, d, inv, outv, 3, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 3, n_left);
	}
      else if (n_left > 16)
	{
	  n_left -= 16;
	  aes_gcm_calc (ctx, d, inv, outv, 2, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 2, n_left);
	}
      else
	{
	  aes_gcm_calc (ctx, d, inv, outv, 1, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 1, n_left);
	}
      return;
    }

  aes_gcm_calc (ctx, d, inv, outv, 4, 0, /* with_ghash */ 0);

  /* next */
  n_left -= 64;
  outv += 4;
  inv += 4;

  while (n_left >= 128)
    {
      aes_gcm_calc_double (ctx, d, inv, outv, /* with_ghash */ 1);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      aes_gcm_calc (ctx, d, inv, outv, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    {
      aes_gcm_ghash_last (ctx, d, 4, 0);
      return;
    }

  ctx->last = 1;

  if (n_left > 48)
    {
      n_left -= 48;
      aes_gcm_calc (ctx, d, inv, outv, 4, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 4, n_left);
      return;
    }

  if (n_left > 32)
    {
      n_left -= 32;
      aes_gcm_calc (ctx, d, inv, outv, 3, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 3, n_left);
      return;
    }

  if (n_left > 16)
    {
      n_left -= 16;
      aes_gcm_calc (ctx, d, inv, outv, 2, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 2, n_left);
      return;
    }

  aes_gcm_calc (ctx, d, inv, outv, 1, n_left, /* with_ghash */ 1);
  aes_gcm_ghash_last (ctx, d, 1, n_left);
#endif
}

static_always_inline void
aes_gcm_dec (aes_gcm_ctx_t *ctx, u8x16u *inv, u8x16u *outv, u32 n_left)
{
#if defined(__VAES__) && defined(__AVX512F__)
  u8x64 d4[4] = {};

  for (; n_left >= 512; n_left -= 512, outv += 32, inv += 32)
    aes4_gcm_calc_double (ctx, d4, inv, outv, /* with_ghash */ 1);

  if (n_left >= 256)
    {
      aes4_gcm_calc (ctx, d4, inv, outv, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 256;
      outv += 16;
      inv += 16;
    }

  if (n_left == 0)
    return;

  ctx->last = 1;

  if (n_left > 192)
    aes4_gcm_calc (ctx, d4, inv, outv, 4, n_left - 192, /* with_ghash */ 1);
  else if (n_left > 128)
    aes4_gcm_calc (ctx, d4, inv, outv, 3, n_left - 128, /* with_ghash */ 1);
  else if (n_left > 64)
    aes4_gcm_calc (ctx, d4, inv, outv, 2, n_left - 64, /* with_ghash */ 1);
  else
    aes4_gcm_calc (ctx, d4, inv, outv, 1, n_left, /* with_ghash */ 1);
  return;
#else
  u8x16 d[4] = {};
  while (n_left >= 128)
    {
      aes_gcm_calc_double (ctx, d, inv, outv, /* with_ghash */ 1);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      aes_gcm_calc (ctx, d, inv, outv, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    return;

  ctx->last = 1;

  if (n_left > 48)
    aes_gcm_calc (ctx, d, inv, outv, 4, n_left - 48, /* with_ghash */ 1);
  else if (n_left > 32)
    aes_gcm_calc (ctx, d, inv, outv, 3, n_left - 32, /* with_ghash */ 1);
  else if (n_left > 16)
    aes_gcm_calc (ctx, d, inv, outv, 2, n_left - 16, /* with_ghash */ 1);
  else
    aes_gcm_calc (ctx, d, inv, outv, 1, n_left, /* with_ghash */ 1);
#endif
}

static_always_inline int
aes_gcm (const u8 *src, u8x16u *out, const u8 *aad, u8 *ivp, u8x16u *tag,
	 u32 data_bytes, u32 aad_bytes, u8 tag_len,
	 const aes_gcm_key_data_t *kd, int aes_rounds, int is_encrypt)
{
  int i;
  u8x16 r, EY0;
  u8x16u *in = (u8x16u *) src;
  u8 *addt = (u8 *) aad;
  vec128_t Y0 = {};
  ghash_data_t __clib_unused _gd, *gd = &_gd;

  aes_gcm_ctx_t _ctx = {
    .counter = 2,
    .rounds = aes_rounds,
    .is_encrypt = is_encrypt,
    .Ke = kd->Ke,
#if defined(__VAES__) && defined(__AVX512F__)
    .Ke4 = kd->Ke4,
#endif
    .Hi = kd->Hi
  }, *ctx = &_ctx;

  /* initalize counter */
  Y0.as_u64x2[0] = *(u64u *) ivp;
  Y0.as_u32x4[2] = *(u32u *) (ivp + 8);
  Y0.as_u32x4 += ctr_inv_1;
#if defined(__VAES__) && defined(__AVX512F__)
  ctx->Y4 = u32x16_splat_u32x4 (Y0.as_u32x4) + ctr_inv_1234;
#else
  ctx->Y = Y0.as_u32x4 + ctr_inv_1;
#endif

  /* encrypt counter 0 E(Y0, k) */
  EY0 = ctx->Ke[0] ^ Y0.as_u8x16;
  for (i = 1; i < aes_rounds; i += 1)
    EY0 = aes_enc_round (EY0, ctx->Ke[i]);
  EY0 = aes_enc_last_round (EY0, ctx->Ke[aes_rounds]);

  /* calculate ghash for AAD */
  aes_gcm_ghash (ctx, addt, aad_bytes);

  clib_prefetch_load (tag);

  /* ghash and encrypt/edcrypt  */
  if (is_encrypt)
    aes_gcm_enc (ctx, in, out, data_bytes);
  else
    aes_gcm_dec (ctx, in, out, data_bytes);

  /* Finalize ghash - data bytes and aad bytes converted to bits */
  r = (u8x16) ((u64x2){ data_bytes, aad_bytes } << 3);
  ctx->T = ghash_mul (r ^ ctx->T, kd->Hi[NUM_HI - 1]);

  /* final tag is */
  ctx->T = u8x16_reflect (ctx->T) ^ EY0;

  /* tag_len 16 -> 0 */
  tag_len &= 0xf;

  if (is_encrypt)
    {
      /* store tag */
      if (tag_len)
	aes_store_partial (tag, ctx->T, tag_len);
      else
	tag[0] = ctx->T;
    }
  else
    {
      /* check tag */
      u16 tag_mask = tag_len ? (1 << tag_len) - 1 : 0xffff;
      if ((u8x16_msb_mask (tag[0] == ctx->T) & tag_mask) != tag_mask)
	return 0;
    }
  return 1;
}

static_always_inline void
clib_aes_gcm_key_expand (aes_gcm_key_data_t *kd, const u8 *key,
			 aes_key_size_t ks)
{
  u8x16 H;

  /* expand AES key */
  aes_key_expand ((u8x16 *) kd->Ke, key, ks);

  /* pre-calculate H */
  H = aes_encrypt_block (u8x16_zero (), kd->Ke, ks);
  H = u8x16_reflect (H);
  ghash_precompute (H, (u8x16 *) kd->Hi, ARRAY_LEN (kd->Hi));
#if defined(__VAES__) && defined(__AVX512F__)
  u8x64 *Ke4 = (u8x64 *) kd->Ke4;
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    Ke4[i] = u8x64_splat_u8x16 (kd->Ke[i]);
#endif
}

static_always_inline void
clib_aes128_gcm_enc (const aes_gcm_key_data_t *kd, const u8 *plaintext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, u32 tag_bytes, u8 *cyphertext, u8 *tag)
{
  aes_gcm (plaintext, (u8x16u *) cyphertext, aad, (u8 *) iv, (u8x16u *) tag,
	   data_bytes, aad_bytes, tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_128),
	   /* is_encrypt */ 1);
}

static_always_inline void
clib_aes256_gcm_enc (const aes_gcm_key_data_t *kd, const u8 *plaintext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, u32 tag_bytes, u8 *cyphertext, u8 *tag)
{
  aes_gcm (plaintext, (u8x16u *) cyphertext, aad, (u8 *) iv, (u8x16u *) tag,
	   data_bytes, aad_bytes, tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_256),
	   /* is_encrypt */ 1);
}

static_always_inline int
clib_aes128_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, (u8x16u *) plaintext, aad, (u8 *) iv,
		  (u8x16u *) tag, data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_128), /* is_encrypt */ 0);
}

static_always_inline int
clib_aes256_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, (u8x16u *) plaintext, aad, (u8 *) iv,
		  (u8x16u *) tag, data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_256), /* is_encrypt */ 0);
}

static_always_inline void
clib_aes128_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, (u8x16u *) tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_128), /* is_encrypt */ 1);
}

static_always_inline void
clib_aes256_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, (u8x16u *) tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_256), /* is_encrypt */ 1);
}

#endif /* __crypto_aes_gcm_h__ */
