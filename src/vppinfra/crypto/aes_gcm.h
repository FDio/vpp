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
#if defined(__VAES__) && defined(__AVX512F__)
#define N 64
typedef u8x64 aes_data_t;
typedef u8x64u aes_ghash_t;
typedef u8x64u aes_datau_t;
typedef u32x16 aes_gcm_counter_t;
#define aes_gcm_load_partial(p, n)     u8x64_load_partial ((u8 *) (p), n)
#define aes_gcm_store_partial(v, p, n) u8x64_store_partial (v, (u8 *) (p), n)
#elif defined(__VxAES__)
#define N			       32
typedef u8x32 aes_data_t;
typedef u8x32u aes_ghash_t;
typedef u8x32u aes_datau_t;
typedef u32x8 aes_gcm_counter_t;
#define aes_gcm_load_partial(p, n)     u8x32_load_partial ((u8 *) (p), n)
#define aes_gcm_store_partial(v, p, n) u8x32_store_partial (v, (u8 *) (p), n)
#else
#define N			       16
typedef u8x16 aes_data_t;
typedef u8x16 aes_ghash_t;
typedef u8x16u aes_datau_t;
typedef u32x4 aes_gcm_counter_t;
#define aes_gcm_load_partial(p, n)     u8x16_load_partial ((u8 *) (p), n)
#define aes_gcm_store_partial(v, p, n) u8x16_store_partial (v, (u8 *) (p), n)
#endif

typedef struct
{
  /* pre-calculated hash key values */
  const u8x16 Hi[NUM_HI];
  /* extracted AES key */
  const u8x16 Ke[AES_KEY_ROUNDS (AES_KEY_256) + 1];
#if defined(__VAES__) && defined(__AVX512F__)
  const u8x64 Ke4[AES_KEY_ROUNDS (AES_KEY_256) + 1];
#elif defined(__VAES__)
  const u8x32 Ke2[AES_KEY_ROUNDS (AES_KEY_256) + 1];
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
  const aes_data_t *Ke;

  /* counter */
  u32 counter;
  aes_gcm_counter_t Y;

  /* ghash */
  ghash_data_t gd;
} aes_gcm_ctx_t;

static_always_inline void
aes_gcm_ghash_mul_first (aes_gcm_ctx_t *ctx, aes_data_t data, aes_ghash_t H)
{
#if N == 64
  u8x64 tag4 = {};
  tag4 = u8x64_insert_u8x16 (tag4, ctx->T, 0);
  ghash4_mul_first (&ctx->gd, u8x64_reflect_u8x16 (data) ^ tag4, H);
#elif N == 32
  u8x32 tag2 = {};
  tag2 = u8x32_insert_lo (tag2, ctx->T);
  ghash2_mul_first (&ctx->gd, u8x32_reflect_u8x16 (data) ^ tag2, H);
#else
  ghash_mul_first (&ctx->gd, u8x16_reflect (data) ^ ctx->T, H);
#endif
}
static_always_inline void
aes_gcm_ghash_mul_next (aes_gcm_ctx_t *ctx, aes_data_t data, aes_ghash_t H)
{
#if N == 64
  ghash4_mul_next (&ctx->gd, u8x64_reflect_u8x16 (data), H);
#elif N == 32
  ghash2_mul_next (&ctx->gd, u8x32_reflect_u8x16 (data), H);
#else
  ghash_mul_next (&ctx->gd, u8x16_reflect (data), H);
#endif
}
static_always_inline void
aes_gcm_ghash_reduce (aes_gcm_ctx_t *ctx)
{
#if N == 64
  ghash4_reduce (&ctx->gd);
#elif N == 32
  ghash2_reduce (&ctx->gd);
#else
  ghash_reduce (&ctx->gd);
#endif
}
static_always_inline void
aes_gcm_ghash_reduce2 (aes_gcm_ctx_t *ctx)
{
#if N == 64
  ghash4_reduce2 (&ctx->gd);
#elif N == 32
  ghash2_reduce2 (&ctx->gd);
#else
  ghash_reduce2 (&ctx->gd);
#endif
}
static_always_inline void
aes_gcm_ghash_final (aes_gcm_ctx_t *ctx)
{
#if N == 64
  ctx->T = ghash4_final (&ctx->gd);
#elif N == 32
  ctx->T = ghash2_final (&ctx->gd);
#else
  ctx->T = ghash_final (&ctx->gd);
#endif
}

static_always_inline void
aes_gcm_ghash (aes_gcm_ctx_t *ctx, u8 *data, u32 n_left)
{
  uword i;
  aes_data_t r = {};
  const aes_ghash_t *Hi;
  const aes_datau_t *d = (aes_datau_t *) data;

  for (; n_left >= 8 * N; n_left -= 8 * N, d += 8)
    {
      Hi = (typeof (Hi)) (ctx->Hi + NUM_HI - N / 2);
      aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);
      for (i = 1; i < 8; i++)
	aes_gcm_ghash_mul_next (ctx, ((d[i])), Hi[i]);
      aes_gcm_ghash_reduce (ctx);
      aes_gcm_ghash_reduce2 (ctx);
      aes_gcm_ghash_final (ctx);
    }

  if (n_left > 0)
    {
#if N == 64
      Hi = (u8x64u *) (ctx->Hi + NUM_HI - ((n_left + 15) / 16));
#elif N == 32
      Hi = (u8x32u *) (ctx->Hi + NUM_HI - (n_left + 15) / 16);
#else
      Hi = (u8x16 *) (ctx->Hi + NUM_HI - 1);
#endif

      if (n_left < N)
	{
	  clib_memcpy_fast (&r, d, n_left);
	  aes_gcm_ghash_mul_first (ctx, r, Hi[0]);
	  aes_gcm_ghash_reduce (ctx);
	}
      else
	{
#if N == 16
	  Hi = (u8x16 *) (ctx->Hi + NUM_HI - ((n_left + 15) / 16));
#endif
	  aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);
	  n_left -= N;
	  i = 1;

	  if (n_left >= 4 * N)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i], Hi[i]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 1], Hi[i + 1]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 2], Hi[i + 2]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 3], Hi[i + 3]);
	      n_left -= 4 * N;
	      i += 4;
	    }
	  if (n_left >= 2 * N)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i], Hi[i]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 1], Hi[i + 1]);
	      n_left -= 2 * N;
	      i += 2;
	    }

	  if (n_left >= N)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i], Hi[i]);
	      n_left -= N;
	      i += 1;
	    }

	  if (n_left)
	    {
	      clib_memcpy_fast (&r, d + i, n_left);
	      aes_gcm_ghash_mul_next (ctx, r, Hi[i]);
	    }

	  aes_gcm_ghash_reduce (ctx);
	}

      aes_gcm_ghash_reduce2 (ctx);
      aes_gcm_ghash_final (ctx);
    }
}

static_always_inline void
aes_gcm_enc_first_round (aes_gcm_ctx_t *ctx, aes_data_t *r, uword n_blocks)
{
  const __clib_unused aes_data_t k = ctx->Ke[0];
  int __clib_unused i = 0;

#if N == 64
  const u32x16 ctr_inv_4444 = { 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24,
				0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24 };

  const u32x16 ctr_4444 = {
    4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0,
  };

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 512-blocks in parallel except the
     last round, overflow can happen only when n == 4 */

  if (n_blocks == 4)
    for (; i < 2; i++)
      {
	r[i] = k ^ (u8x64) ctx->Y;
	ctx->Y += ctr_inv_4444;
      }

  if (n_blocks == 4 && PREDICT_FALSE ((u8) ctx->counter == 242))
    {
      u32x16 Yr = (u32x16) u8x64_reflect_u8x16 ((u8x64) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x64) ctx->Y;
	  Yr += ctr_4444;
	  ctx->Y = (u32x16) u8x64_reflect_u8x16 ((u8x64) Yr);
	}
    }
  else
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x64) ctx->Y;
	  ctx->Y += ctr_inv_4444;
	}
    }
  ctx->counter += n_blocks * 4;
#elif N == 32
  const u32x8 ctr_inv_44 = { 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24 };
  const u32x8 ctr_44 = { 4, 0, 0, 0, 4, 0, 0, 0 };

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 512-blocks in parallel except the
     last round, overflow can happen only when n == 4 */

  if (n_blocks == 4)
    for (; i < 2; i++)
      {
	r[i] = k ^ (u8x32) ctx->Y;
	ctx->Y += ctr_inv_44;
      }

  if (n_blocks == 4 && PREDICT_FALSE ((u8) ctx->counter == 242))
    {
      u32x8 Yr = (u32x8) u8x32_reflect_u8x16 ((u8x32) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x32) ctx->Y;
	  Yr += ctr_44;
	  ctx->Y = (u32x8) u8x32_reflect_u8x16 ((u8x32) Yr);
	}
    }
  else
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x32) ctx->Y;
	  ctx->Y += ctr_inv_44;
	}
    }
  ctx->counter += n_blocks * 2;
#else
  const u32x4 ctr_inv_1 = { 0, 0, 0, 1 << 24 };

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
#endif
}

static_always_inline void
aes_gcm_enc_round (aes_data_t *r, aes_data_t k, uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N == 64
    r[i] = aes_enc_round_x4 (r[i], k);
#elif N == 32
    r[i] = aes_enc_round_x2 (r[i], k);
#else
    r[i] = aes_enc_round (r[i], k);
#endif
}

static_always_inline void
aes_gcm_enc_last_round (aes_gcm_ctx_t *ctx, aes_data_t *r, aes_data_t *d,
			const aes_data_t *k, uword n_blocks)
{
  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < ctx->rounds; i++)
    aes_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
#if N == 64
    d[i] ^= aes_enc_last_round_x4 (r[i], k[ctx->rounds]);
#elif N == 32
    d[i] ^= aes_enc_last_round_x2 (r[i], k[ctx->rounds]);
#else
    d[i] ^= aes_enc_last_round (r[i], k[ctx->rounds]);
#endif
}

static_always_inline void
aes_gcm_calc (aes_gcm_ctx_t *ctx, aes_data_t *d, const u8 *in, u8 *out,
	      uword n, uword last_block_bytes, int with_ghash)
{
  const aes_data_t *k = ctx->Ke;
#if N == 64
  uword i, ghash_blocks, gc = 1;
  u8x64u *Hi, *inv = (u8x64u *) in, *outv = (u8x64u *) out;
  u8x64 r[4];
  u64 byte_mask = _bextr_u64 (-1LL, 0, last_block_bytes);
#elif N == 32
  u8x32 r[4];
  u8x32u *inv = (u8x32u *) in, *outv = (u8x32u *) out;
  int ghash_blocks = (ctx->is_encrypt) ? 4 : n, gc = 1;
  u8x32 *Hi = (u8x32 *) ctx->Hi + NUM_HI - ghash_blocks;
#else
  u8x16 r[n];
  int ghash_blocks = (ctx->is_encrypt) ? 4 : n, gc = 1;
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - ghash_blocks;
  u8x16u *inv = (u8x16u *) in, *outv = (u8x16u *) out;
#endif

#if N == 64
  if (ctx->is_encrypt)
    {
      /* during encryption we either hash four 512-bit blocks from previous
	 round or we don't hash at all */
      ghash_blocks = 4;
      Hi = (u8x64u *) (ctx->Hi + NUM_HI - ghash_blocks * 4);
    }
  else
    {
      /* during deccryption we hash 1..4 512-bit blocks from current round */
      ghash_blocks = n;
      uword n_128bit_blocks = n * 4;
      /* if this is last round of decryption, we may have less than 4
	 128-bit blocks in the last 512-bit data block, so we need to adjust
	 Hi pointer accordingly */
      if (ctx->last)
	n_128bit_blocks += ((last_block_bytes + 15) >> 4) - 4;
      Hi = (u8x64u *) (ctx->Hi + NUM_HI - n_128bit_blocks);
    }
#endif

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, n);
  aes_gcm_enc_round (r, k[1], n);

#if N == 64
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
    aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, k[2], n);
  aes_gcm_enc_round (r, k[3], n);

  /* GHASH multiply block 1 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, k[4], n);
  aes_gcm_enc_round (r, k[5], n);

  /* GHASH multiply block 2 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, k[6], n);
  aes_gcm_enc_round (r, k[7], n);

  /* GHASH multiply block 3 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[3]), Hi[3]);

  /* load 4 blocks of data - decrypt round */
  if (ctx->is_encrypt)
    {
      for (i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[i] = u8x64_mask_load (u8x64_zero (), inv + i, byte_mask);
    }

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, k[8], n);
  aes_gcm_enc_round (r, k[9], n);

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, n);

  /* store 4 blocks of data */
  for (i = 0; i < n - ctx->last; i++)
    outv[i] = d[i];

  if (ctx->last)
    u8x64_mask_store (d[i], outv + i, byte_mask);

  /* GHASH reduce 1st step */
  aes_gcm_ghash_reduce (ctx);

  /* GHASH reduce 2nd step */
  aes_gcm_ghash_reduce2 (ctx);

#else
  /* load data - decrypt round */
  if (!ctx->is_encrypt)
    {
      for (int i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[n - 1] = aes_gcm_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH multiply block 1 */
  if (with_ghash)
    aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, k[2], n);
  aes_gcm_enc_round (r, k[3], n);

  /* GHASH multiply block 2 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, k[4], n);
  aes_gcm_enc_round (r, k[5], n);

  /* GHASH multiply block 3 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, k[6], n);
  aes_gcm_enc_round (r, k[7], n);

  /* GHASH multiply block 4 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[3]), Hi[3]);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, k[8], n);
  aes_gcm_enc_round (r, k[9], n);

  /* GHASH reduce 1st step */
  if (with_ghash)
    aes_gcm_ghash_reduce (ctx);

  /* load data - encrypt round */
  if (ctx->is_encrypt)
    {
      for (int i = 0; i < n - ctx->last; i++)
	d[i] = inv[i];

      if (ctx->last)
	d[n - 1] = aes_gcm_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH reduce 2nd step */
  if (with_ghash)
    aes_gcm_ghash_reduce2 (ctx);

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, n);

  /* store data */
  for (int i = 0; i < n - ctx->last; i++)
    outv[i] = d[i];

  if (ctx->last)
    aes_gcm_store_partial (d[n - 1], outv + n - 1, last_block_bytes);
#endif

  /* GHASH final step */
  if (with_ghash)
    aes_gcm_ghash_final (ctx);
}

static_always_inline void
aes_gcm_calc_double (aes_gcm_ctx_t *ctx, aes_data_t *d, const u8 *src, u8 *dst,
		     int with_ghash)
{
  aes_data_t r[4];
  const aes_data_t *k = ctx->Ke;
#if N == 64
  u8x64 *Hi = (u8x64 *) (ctx->Hi + NUM_HI - 32);
  u8x64u *sv = (u8x64u *) src, *dv = (u8x64u *) dst;
#elif N == 32
  u8x32 *Hi = (u8x32 *) ctx->Hi + NUM_HI - 16;
  u8x32u *sv = (u8x32u *) src;
  u8x32u *dv = (u8x32u *) dst;
#else
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - 8;
  u8x16u *sv = (u8x16u *) src;
  u8x16u *dv = (u8x16u *) dst;
#endif

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, 4);
  aes_gcm_enc_round (r, k[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (!ctx->is_encrypt)
    {
      d[0] = sv[0];
      d[1] = sv[1];
      d[2] = sv[2];
      d[3] = sv[3];
    }

  /* GHASH multiply block 0 */
  aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, k[2], 4);
  aes_gcm_enc_round (r, k[3], 4);

  /* GHASH multiply block 1 */
  aes_gcm_ghash_mul_next (ctx, (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, k[4], 4);
  aes_gcm_enc_round (r, k[5], 4);

  /* GHASH multiply block 2 */
  aes_gcm_ghash_mul_next (ctx, (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, k[6], 4);
  aes_gcm_enc_round (r, k[7], 4);

  /* GHASH multiply block 3 */
  aes_gcm_ghash_mul_next (ctx, (d[3]), Hi[3]);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, k[8], 4);
  aes_gcm_enc_round (r, k[9], 4);

  /* load 4 blocks of data - encrypt round */
  if (ctx->is_encrypt)
    {
      d[0] = sv[0];
      d[1] = sv[1];
      d[2] = sv[2];
      d[3] = sv[3];
    }

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, 4);

  /* store 4 blocks of data */
  dv[0] = d[0];
  dv[1] = d[1];
  dv[2] = d[2];
  dv[3] = d[3];

  /* load next 4 blocks of data data - decrypt round */
  if (!ctx->is_encrypt)
    {
      d[0] = sv[4];
      d[1] = sv[5];
      d[2] = sv[6];
      d[3] = sv[7];
    }

#if N == 64

  /* GHASH multiply block 3 */
  aes_gcm_ghash_mul_next (ctx, (d[0]), Hi[4]);

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, 4);
  aes_gcm_enc_round (r, k[1], 4);

  /* GHASH multiply block 5 */
  aes_gcm_ghash_mul_next (ctx, (d[1]), Hi[5]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, k[2], 4);
  aes_gcm_enc_round (r, k[3], 4);

  /* GHASH multiply block 6 */
  aes_gcm_ghash_mul_next (ctx, (d[2]), Hi[6]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, k[4], 4);
  aes_gcm_enc_round (r, k[5], 4);

  /* GHASH multiply block 7 */
  aes_gcm_ghash_mul_next (ctx, (d[3]), Hi[7]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, k[6], 4);
  aes_gcm_enc_round (r, k[7], 4);

  /* GHASH reduce 1st step */
  aes_gcm_ghash_reduce (ctx);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, k[8], 4);
  aes_gcm_enc_round (r, k[9], 4);

  /* GHASH reduce 2nd step */
  aes_gcm_ghash_reduce2 (ctx);

  /* load 4 blocks of data - encrypt round */
  if (ctx->is_encrypt)
    for (int i = 0; i < 4; i++)
      d[i] = sv[i + 4];

#else

  /* GHASH multiply block 4 */
  aes_gcm_ghash_mul_next (ctx, (d[0]), Hi[4]);

  /* AES rounds 0, 1 and 2 */
  aes_gcm_enc_first_round (ctx, r, 4);
  aes_gcm_enc_round (r, k[1], 4);
  aes_gcm_enc_round (r, k[2], 4);

  /* GHASH multiply block 5 */
  aes_gcm_ghash_mul_next (ctx, (d[1]), Hi[5]);

  /* AES rounds 3 and 4 */
  aes_gcm_enc_round (r, k[3], 4);
  aes_gcm_enc_round (r, k[4], 4);

  /* GHASH multiply block 6 */
  aes_gcm_ghash_mul_next (ctx, (d[2]), Hi[6]);

  /* AES rounds 5 and 6 */
  aes_gcm_enc_round (r, k[5], 4);
  aes_gcm_enc_round (r, k[6], 4);

  /* GHASH multiply block 7 */
  aes_gcm_ghash_mul_next (ctx, (d[3]), Hi[7]);

  /* AES rounds 7 and 8 */
  aes_gcm_enc_round (r, k[7], 4);
  aes_gcm_enc_round (r, k[8], 4);

  /* GHASH reduce 1st step */
  aes_gcm_ghash_reduce (ctx);

  /* AES round 9 */
  aes_gcm_enc_round (r, k[9], 4);

  /* load data - encrypt round */
  if (ctx->is_encrypt)
    {
      d[0] = sv[4];
      d[1] = sv[5];
      d[2] = sv[6];
      d[3] = sv[7];
    }

  /* GHASH reduce 2nd step */
  aes_gcm_ghash_reduce2 (ctx);

#endif
  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, 4);

  /* store data */
  dv[4] = d[0];
  dv[5] = d[1];
  dv[6] = d[2];
  dv[7] = d[3];

  /* GHASH final step */
#if N == 64
  aes_gcm_ghash_final (ctx);
#else
  aes_gcm_ghash_final (ctx);
#endif
}

static_always_inline void
aes_gcm_ghash_last (aes_gcm_ctx_t *ctx, aes_data_t *d, int n_blocks,
		    uword n_bytes)
{
#if N == 64
  int n_128bit_blocks;
  u64 byte_mask = _bextr_u64 (-1LL, 0, n_bytes);
  n_128bit_blocks = (n_blocks - 1) * 4 + ((n_bytes + 15) >> 4);
  u8x64u *Hi = (u8x64u *) (ctx->Hi + NUM_HI - n_128bit_blocks);

  d[n_blocks - 1] =
    u8x64_mask_blend (u8x64_zero (), d[n_blocks - 1], byte_mask);
#elif N == 32
  u8x32u *Hi = (u8x32u *) ctx->Hi + NUM_HI - n_blocks;
#else
  u8x16 *Hi = (u8x16 *) ctx->Hi + NUM_HI - n_blocks;

  if (n_bytes)
    d[n_blocks - 1] = aes_byte_mask (d[n_blocks - 1], n_bytes);
#endif

  aes_gcm_ghash_mul_first (ctx, d[0], Hi[0]);
  if (n_blocks > 1)
    aes_gcm_ghash_mul_next (ctx, d[1], Hi[1]);
  if (n_blocks > 2)
    aes_gcm_ghash_mul_next (ctx, d[2], Hi[2]);
  if (n_blocks > 3)
    aes_gcm_ghash_mul_next (ctx, d[3], Hi[3]);
  aes_gcm_ghash_reduce (ctx);
  aes_gcm_ghash_reduce2 (ctx);
  aes_gcm_ghash_final (ctx);
}

static_always_inline void
aes_gcm_enc (aes_gcm_ctx_t *ctx, const u8 *src, u8 *dst, u32 n_left)
{
  aes_data_t d[4];
  if (n_left == 0)
    return;

  if (n_left < 4 * N)
    {
      ctx->last = 1;
      if (n_left > 3 * N)
	{
	  n_left -= 3 * N;
	  aes_gcm_calc (ctx, d, src, dst, 4, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 4, n_left);
	}
      else if (n_left > 2 * N)
	{
	  n_left -= 2 * N;
	  aes_gcm_calc (ctx, d, src, dst, 3, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 3, n_left);
	}
      else if (n_left > N)
	{
	  n_left -= N;
	  aes_gcm_calc (ctx, d, src, dst, 2, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 2, n_left);
	}
      else
	{
	  aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 0);
	  aes_gcm_ghash_last (ctx, d, 1, n_left);
	}
      return;
    }
  aes_gcm_calc (ctx, d, src, dst, 4, 0, /* with_ghash */ 0);

  /* next */
  n_left -= 4 * N;
  dst += 4 * N;
  src += 4 * N;

  for (; n_left >= 8 * N; n_left -= 8 * N, src += 8 * N, dst += 8 * N)
    aes_gcm_calc_double (ctx, d, src, dst, /* with_ghash */ 1);

  if (n_left >= 4 * N)
    {
      aes_gcm_calc (ctx, d, src, dst, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 4 * N;
      dst += 4 * N;
      src += 4 * N;
    }

  if (n_left == 0)
    {
#if N == 64
      aes_gcm_ghash_last (ctx, d, 4, 64);
#else
      aes_gcm_ghash_last (ctx, d, 4, 0);
#endif
      return;
    }

  ctx->last = 1;

  if (n_left > 3 * N)
    {
      n_left -= 3 * N;
      aes_gcm_calc (ctx, d, src, dst, 4, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 4, n_left);
    }
  else if (n_left > 2 * N)
    {
      n_left -= 2 * N;
      aes_gcm_calc (ctx, d, src, dst, 3, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 3, n_left);
    }
  else if (n_left > N)
    {
      n_left -= N;
      aes_gcm_calc (ctx, d, src, dst, 2, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 2, n_left);
    }
  else
    {
      aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 1);
      aes_gcm_ghash_last (ctx, d, 1, n_left);
    }
}

static_always_inline void
aes_gcm_dec (aes_gcm_ctx_t *ctx, const u8 *src, u8 *dst, uword n_left)
{
  aes_data_t d[4] = {};
  for (; n_left >= 8 * N; n_left -= 8 * N, dst += 8 * N, src += 8 * N)
    aes_gcm_calc_double (ctx, d, src, dst, /* with_ghash */ 1);

  if (n_left >= 4 * N)
    {
      aes_gcm_calc (ctx, d, src, dst, 4, 0, /* with_ghash */ 1);

      /* next */
      n_left -= 4 * N;
      dst += N * 4;
      src += N * 4;
    }

  if (n_left == 0)
    return;

  ctx->last = 1;

  if (n_left > 3 * N)
    aes_gcm_calc (ctx, d, src, dst, 4, n_left - 3 * N, /* with_ghash */ 1);
  else if (n_left > 2 * N)
    aes_gcm_calc (ctx, d, src, dst, 3, n_left - 2 * N, /* with_ghash */ 1);
  else if (n_left > N)
    aes_gcm_calc (ctx, d, src, dst, 2, n_left - N, /* with_ghash */ 1);
  else
    aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 1);
}

static_always_inline int
aes_gcm (const u8 *src, u8 *dst, const u8 *aad, u8 *ivp, u8 *tag,
	 u32 data_bytes, u32 aad_bytes, u8 tag_len,
	 const aes_gcm_key_data_t *kd, int aes_rounds, int is_encrypt)
{
  int i;
  u8x16 r, EY0;
  u8 *addt = (u8 *) aad;
  vec128_t Y0 = {};

  aes_gcm_ctx_t _ctx = { .counter = 2,
			 .rounds = aes_rounds,
			 .is_encrypt = is_encrypt,
			 .Hi = kd->Hi },
		*ctx = &_ctx;

  /* initalize counter */
  Y0.as_u64x2[0] = *(u64u *) ivp;
  Y0.as_u32x4[2] = *(u32u *) (ivp + 8);
  Y0.as_u32x4[3] = 1 << 24;
#if N == 64
  ctx->Ke = kd->Ke4;
  ctx->Y = u32x16_splat_u32x4 (Y0.as_u32x4) + (u32x16){
    0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24, 0, 0, 0, 3 << 24, 0, 0, 0, 4 << 24,
  };
#elif N == 32
  ctx->Ke = kd->Ke2;
  ctx->Y = u32x8_insert_lo (ctx->Y, Y0.as_u32x4);
  ctx->Y = u32x8_insert_hi (ctx->Y, Y0.as_u32x4);
  ctx->Y += (u32x8){ 0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24 };
#else
  ctx->Ke = kd->Ke;
  ctx->Y = Y0.as_u32x4 + (u32x4){ 0, 0, 0, 1 << 24 };
#endif

  /* encrypt counter 0 E(Y0, k) */
  EY0 = kd->Ke[0] ^ Y0.as_u8x16;
  for (i = 1; i < aes_rounds; i += 1)
    EY0 = aes_enc_round (EY0, kd->Ke[i]);
  EY0 = aes_enc_last_round (EY0, kd->Ke[aes_rounds]);

  /* calculate ghash for AAD */
  aes_gcm_ghash (ctx, addt, aad_bytes);

  clib_prefetch_load (tag);

  /* ghash and encrypt/edcrypt  */
  if (is_encrypt)
    aes_gcm_enc (ctx, src, dst, data_bytes);
  else
    aes_gcm_dec (ctx, src, dst, data_bytes);

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
	u8x16_store_partial (ctx->T, tag, tag_len);
      else
	((u8x16u *) tag)[0] = ctx->T;
    }
  else
    {
      /* check tag */
      if (tag_len)
	{
	  u16 mask = pow2_mask (tag_len);
	  u8x16 expected = u8x16_load_partial (tag, tag_len);
	  if ((u8x16_msb_mask (expected == ctx->T) & mask) == mask)
	    return 1;
	}
      else
	{
	  if (u8x16_is_equal (ctx->T, *(u8x16u *) tag))
	    return 1;
	}
    }
  return 0;
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
  aes_gcm (plaintext, cyphertext, aad, (u8 *) iv, tag, data_bytes, aad_bytes,
	   tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_128),
	   /* is_encrypt */ 1);
}

static_always_inline void
clib_aes256_gcm_enc (const aes_gcm_key_data_t *kd, const u8 *plaintext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, u32 tag_bytes, u8 *cyphertext, u8 *tag)
{
  aes_gcm (plaintext, cyphertext, aad, (u8 *) iv, tag, data_bytes, aad_bytes,
	   tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_256),
	   /* is_encrypt */ 1);
}

static_always_inline int
clib_aes128_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, plaintext, aad, (u8 *) iv, (u8 *) tag,
		  data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_128), /* is_encrypt */ 0);
}

static_always_inline int
clib_aes256_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, plaintext, aad, (u8 *) iv, (u8 *) tag,
		  data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_256), /* is_encrypt */ 0);
}

static_always_inline void
clib_aes128_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_128), /* is_encrypt */ 1);
}

static_always_inline void
clib_aes256_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_256), /* is_encrypt */ 1);
}

#endif /* __crypto_aes_gcm_h__ */
