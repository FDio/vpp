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

#define NUM_HI 36
#if N_AES_LANES == 4
typedef u8x64u aes_ghash_t;
#define aes_gcm_splat(v)	       u8x64_splat (v)
#define aes_gcm_ghash_reduce(c)	       ghash4_reduce (&(c)->gd)
#define aes_gcm_ghash_reduce2(c)       ghash4_reduce2 (&(c)->gd)
#define aes_gcm_ghash_final(c)	       (c)->T = ghash4_final (&(c)->gd)
#elif N_AES_LANES == 2
typedef u8x32u aes_ghash_t;
#define aes_gcm_splat(v)	       u8x32_splat (v)
#define aes_gcm_ghash_reduce(c)	       ghash2_reduce (&(c)->gd)
#define aes_gcm_ghash_reduce2(c)       ghash2_reduce2 (&(c)->gd)
#define aes_gcm_ghash_final(c)	       (c)->T = ghash2_final (&(c)->gd)
#else
typedef u8x16 aes_ghash_t;
#define aes_gcm_splat(v)	       u8x16_splat (v)
#define aes_gcm_ghash_reduce(c)	       ghash_reduce (&(c)->gd)
#define aes_gcm_ghash_reduce2(c)       ghash_reduce2 (&(c)->gd)
#define aes_gcm_ghash_final(c)	       (c)->T = ghash_final (&(c)->gd)
#endif

typedef enum
{
  AES_GCM_OP_UNKNONW = 0,
  AES_GCM_OP_ENCRYPT,
  AES_GCM_OP_DECRYPT,
  AES_GCM_OP_GMAC
} aes_gcm_op_t;

typedef struct
{
  /* pre-calculated hash key values */
  const u8x16 Hi[NUM_HI];
  /* extracted AES key */
  const aes_expaned_key_t Ke[AES_KEY_ROUNDS (AES_KEY_256) + 1];
} aes_gcm_key_data_t;

typedef struct
{
  aes_gcm_op_t operation;
  int last;
  u8 rounds;
  uword data_bytes;
  uword aad_bytes;

  u8x16 T;

  /* hash */
  const u8x16 *Hi;
  const aes_ghash_t *next_Hi;

  /* expaded keys */
  const aes_expaned_key_t *Ke;

  /* counter */
  u32 counter;
  u8x16 EY0;
  aes_counter_t Y;

  /* ghash */
  ghash_ctx_t gd;
} aes_gcm_ctx_t;

static_always_inline u8x16
aes_gcm_final_block (aes_gcm_ctx_t *ctx)
{
  return (u8x16) ((u64x2){ ctx->data_bytes, ctx->aad_bytes } << 3);
}

static_always_inline void
aes_gcm_ghash_mul_first (aes_gcm_ctx_t *ctx, aes_data_t data, u32 n_lanes)
{
  uword hash_offset = NUM_HI - n_lanes;
  ctx->next_Hi = (aes_ghash_t *) (ctx->Hi + hash_offset);
#if N_AES_LANES == 4
  u8x64 tag4 = {};
  tag4 = u8x64_insert_u8x16 (tag4, ctx->T, 0);
  ghash4_mul_first (&ctx->gd, aes_reflect (data) ^ tag4, *ctx->next_Hi++);
#elif N_AES_LANES == 2
  u8x32 tag2 = {};
  tag2 = u8x32_insert_lo (tag2, ctx->T);
  ghash2_mul_first (&ctx->gd, aes_reflect (data) ^ tag2, *ctx->next_Hi++);
#else
  ghash_mul_first (&ctx->gd, aes_reflect (data) ^ ctx->T, *ctx->next_Hi++);
#endif
}

static_always_inline void
aes_gcm_ghash_mul_next (aes_gcm_ctx_t *ctx, aes_data_t data)
{
#if N_AES_LANES == 4
  ghash4_mul_next (&ctx->gd, aes_reflect (data), *ctx->next_Hi++);
#elif N_AES_LANES == 2
  ghash2_mul_next (&ctx->gd, aes_reflect (data), *ctx->next_Hi++);
#else
  ghash_mul_next (&ctx->gd, aes_reflect (data), *ctx->next_Hi++);
#endif
}

static_always_inline void
aes_gcm_ghash_mul_final_block (aes_gcm_ctx_t *ctx)
{
#if N_AES_LANES == 4
  u8x64 h = u8x64_insert_u8x16 (u8x64_zero (), ctx->Hi[NUM_HI - 1], 0);
  u8x64 r4 = u8x64_insert_u8x16 (u8x64_zero (), aes_gcm_final_block (ctx), 0);
  ghash4_mul_next (&ctx->gd, r4, h);
#elif N_AES_LANES == 2
  u8x32 h = u8x32_insert_lo (u8x32_zero (), ctx->Hi[NUM_HI - 1]);
  u8x32 r2 = u8x32_insert_lo (u8x32_zero (), aes_gcm_final_block (ctx));
  ghash2_mul_next (&ctx->gd, r2, h);
#else
  ghash_mul_next (&ctx->gd, aes_gcm_final_block (ctx), ctx->Hi[NUM_HI - 1]);
#endif
}

static_always_inline void
aes_gcm_enc_ctr0_round (aes_gcm_ctx_t *ctx, int aes_round)
{
  if (aes_round == 0)
    ctx->EY0 ^= ctx->Ke[0].x1;
  else if (aes_round == ctx->rounds)
    ctx->EY0 = aes_enc_last_round_x1 (ctx->EY0, ctx->Ke[aes_round].x1);
  else
    ctx->EY0 = aes_enc_round_x1 (ctx->EY0, ctx->Ke[aes_round].x1);
}

static_always_inline void
aes_gcm_ghash (aes_gcm_ctx_t *ctx, u8 *data, u32 n_left)
{
  uword i;
  aes_data_t r = {};
  const aes_mem_t *d = (aes_mem_t *) data;

  for (int n = 8 * N_AES_BYTES; n_left >= n; n_left -= n, d += 8)
    {
      if (ctx->operation == AES_GCM_OP_GMAC && n_left == n)
	{
	  aes_gcm_ghash_mul_first (ctx, d[0], 8 * N_AES_LANES + 1);
	  for (i = 1; i < 8; i++)
	    aes_gcm_ghash_mul_next (ctx, d[i]);
	  aes_gcm_ghash_mul_final_block (ctx);
	  aes_gcm_ghash_reduce (ctx);
	  aes_gcm_ghash_reduce2 (ctx);
	  aes_gcm_ghash_final (ctx);
	  goto done;
	}

      aes_gcm_ghash_mul_first (ctx, d[0], 8 * N_AES_LANES);
      for (i = 1; i < 8; i++)
	aes_gcm_ghash_mul_next (ctx, d[i]);
      aes_gcm_ghash_reduce (ctx);
      aes_gcm_ghash_reduce2 (ctx);
      aes_gcm_ghash_final (ctx);
    }

  if (n_left > 0)
    {
      int n_lanes = (n_left + 15) / 16;

      if (ctx->operation == AES_GCM_OP_GMAC)
	n_lanes++;

      if (n_left < N_AES_BYTES)
	{
	  clib_memcpy_fast (&r, d, n_left);
	  aes_gcm_ghash_mul_first (ctx, r, n_lanes);
	}
      else
	{
	  aes_gcm_ghash_mul_first (ctx, d[0], n_lanes);
	  n_left -= N_AES_BYTES;
	  i = 1;

	  if (n_left >= 4 * N_AES_BYTES)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 1]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 2]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 3]);
	      n_left -= 4 * N_AES_BYTES;
	      i += 4;
	    }
	  if (n_left >= 2 * N_AES_BYTES)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i]);
	      aes_gcm_ghash_mul_next (ctx, d[i + 1]);
	      n_left -= 2 * N_AES_BYTES;
	      i += 2;
	    }

	  if (n_left >= N_AES_BYTES)
	    {
	      aes_gcm_ghash_mul_next (ctx, d[i]);
	      n_left -= N_AES_BYTES;
	      i += 1;
	    }

	  if (n_left)
	    {
	      clib_memcpy_fast (&r, d + i, n_left);
	      aes_gcm_ghash_mul_next (ctx, r);
	    }
	}

      if (ctx->operation == AES_GCM_OP_GMAC)
	aes_gcm_ghash_mul_final_block (ctx);
      aes_gcm_ghash_reduce (ctx);
      aes_gcm_ghash_reduce2 (ctx);
      aes_gcm_ghash_final (ctx);
    }
  else if (ctx->operation == AES_GCM_OP_GMAC)
    ctx->T =
      ghash_mul (aes_gcm_final_block (ctx) ^ ctx->T, ctx->Hi[NUM_HI - 1]);

done:
  /* encrypt counter 0 E(Y0, k) */
  if (ctx->operation == AES_GCM_OP_GMAC)
    for (int i = 0; i < ctx->rounds + 1; i += 1)
      aes_gcm_enc_ctr0_round (ctx, i);
}

static_always_inline void
aes_gcm_enc_first_round (aes_gcm_ctx_t *ctx, aes_data_t *r, uword n_blocks)
{
  const aes_expaned_key_t Ke0 = ctx->Ke[0];
  uword i = 0;

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 128, 256 or 512-blocks in parallel
     except the last round, overflow can happen only when n_blocks == 4 */

#if N_AES_LANES == 4
  const u32x16 ctr_inv_4444 = { 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24,
				0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24 };

  const u32x16 ctr_4444 = {
    4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0,
  };

  if (n_blocks == 4)
    for (; i < 2; i++)
      {
	r[i] = Ke0.x4 ^ (u8x64) ctx->Y; /* Initial AES round */
	ctx->Y += ctr_inv_4444;
      }

  if (n_blocks == 4 && PREDICT_FALSE ((u8) ctx->counter == 242))
    {
      u32x16 Yr = (u32x16) aes_reflect ((u8x64) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x4 ^ (u8x64) ctx->Y; /* Initial AES round */
	  Yr += ctr_4444;
	  ctx->Y = (u32x16) aes_reflect ((u8x64) Yr);
	}
    }
  else
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x4 ^ (u8x64) ctx->Y; /* Initial AES round */
	  ctx->Y += ctr_inv_4444;
	}
    }
  ctx->counter += n_blocks * 4;
#elif N_AES_LANES == 2
  const u32x8 ctr_inv_22 = { 0, 0, 0, 2 << 24, 0, 0, 0, 2 << 24 };
  const u32x8 ctr_22 = { 2, 0, 0, 0, 2, 0, 0, 0 };

  if (n_blocks == 4)
    for (; i < 2; i++)
      {
	r[i] = Ke0.x2 ^ (u8x32) ctx->Y; /* Initial AES round */
	ctx->Y += ctr_inv_22;
      }

  if (n_blocks == 4 && PREDICT_FALSE ((u8) ctx->counter == 250))
    {
      u32x8 Yr = (u32x8) aes_reflect ((u8x32) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x2 ^ (u8x32) ctx->Y; /* Initial AES round */
	  Yr += ctr_22;
	  ctx->Y = (u32x8) aes_reflect ((u8x32) Yr);
	}
    }
  else
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x2 ^ (u8x32) ctx->Y; /* Initial AES round */
	  ctx->Y += ctr_inv_22;
	}
    }
  ctx->counter += n_blocks * 2;
#else
  const u32x4 ctr_inv_1 = { 0, 0, 0, 1 << 24 };

  if (PREDICT_TRUE ((u8) ctx->counter < 0xfe) || n_blocks < 3)
    {
      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x1 ^ (u8x16) ctx->Y; /* Initial AES round */
	  ctx->Y += ctr_inv_1;
	}
      ctx->counter += n_blocks;
    }
  else
    {
      r[i++] = Ke0.x1 ^ (u8x16) ctx->Y; /* Initial AES round */
      ctx->Y += ctr_inv_1;
      ctx->counter += 1;

      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x1 ^ (u8x16) ctx->Y; /* Initial AES round */
	  ctx->counter++;
	  ctx->Y[3] = clib_host_to_net_u32 (ctx->counter);
	}
    }
#endif
}

static_always_inline void
aes_gcm_enc_last_round (aes_gcm_ctx_t *ctx, aes_data_t *r, aes_data_t *d,
			const aes_expaned_key_t *Ke, uword n_blocks)
{
  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < ctx->rounds; i++)
    aes_enc_round (r, Ke + i, n_blocks);

  aes_enc_last_round (r, d, Ke + ctx->rounds, n_blocks);
}

static_always_inline void
aes_gcm_calc (aes_gcm_ctx_t *ctx, aes_data_t *d, const u8 *src, u8 *dst, u32 n,
	      u32 n_bytes, int with_ghash)
{
  const aes_expaned_key_t *k = ctx->Ke;
  const aes_mem_t *sv = (aes_mem_t *) src;
  aes_mem_t *dv = (aes_mem_t *) dst;
  uword ghash_blocks, gc = 1;
  aes_data_t r[4];
  u32 i, n_lanes;

  if (ctx->operation == AES_GCM_OP_ENCRYPT)
    {
      ghash_blocks = 4;
      n_lanes = N_AES_LANES * 4;
    }
  else
    {
      ghash_blocks = n;
      n_lanes = n * N_AES_LANES;
#if N_AES_LANES != 1
      if (ctx->last)
	n_lanes = (n_bytes + 15) / 16;
#endif
    }

  n_bytes -= (n - 1) * N_AES_BYTES;

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, n);
  aes_enc_round (r, k + 1, n);

  /* load data - decrypt round */
  if (ctx->operation == AES_GCM_OP_DECRYPT)
    {
      for (i = 0; i < n - ctx->last; i++)
	d[i] = sv[i];

      if (ctx->last)
	d[n - 1] = aes_load_partial ((u8 *) (sv + n - 1), n_bytes);
    }

  /* GHASH multiply block 0 */
  if (with_ghash)
    aes_gcm_ghash_mul_first (ctx, d[0], n_lanes);

  /* AES rounds 2 and 3 */
  aes_enc_round (r, k + 2, n);
  aes_enc_round (r, k + 3, n);

  /* GHASH multiply block 1 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[1]));

  /* AES rounds 4 and 5 */
  aes_enc_round (r, k + 4, n);
  aes_enc_round (r, k + 5, n);

  /* GHASH multiply block 2 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[2]));

  /* AES rounds 6 and 7 */
  aes_enc_round (r, k + 6, n);
  aes_enc_round (r, k + 7, n);

  /* GHASH multiply block 3 */
  if (with_ghash && gc++ < ghash_blocks)
    aes_gcm_ghash_mul_next (ctx, (d[3]));

  /* load 4 blocks of data - decrypt round */
  if (ctx->operation == AES_GCM_OP_ENCRYPT)
    {
      for (i = 0; i < n - ctx->last; i++)
	d[i] = sv[i];

      if (ctx->last)
	d[n - 1] = aes_load_partial (sv + n - 1, n_bytes);
    }

  /* AES rounds 8 and 9 */
  aes_enc_round (r, k + 8, n);
  aes_enc_round (r, k + 9, n);

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, n);

  /* store data */
  for (i = 0; i < n - ctx->last; i++)
    dv[i] = d[i];

  if (ctx->last)
    aes_store_partial (d[n - 1], dv + n - 1, n_bytes);

  /* GHASH reduce 1st step */
  aes_gcm_ghash_reduce (ctx);

  /* GHASH reduce 2nd step */
  if (with_ghash)
    aes_gcm_ghash_reduce2 (ctx);

  /* GHASH final step */
  if (with_ghash)
    aes_gcm_ghash_final (ctx);
}

static_always_inline void
aes_gcm_calc_double (aes_gcm_ctx_t *ctx, aes_data_t *d, const u8 *src, u8 *dst)
{
  const aes_expaned_key_t *k = ctx->Ke;
  const aes_mem_t *sv = (aes_mem_t *) src;
  aes_mem_t *dv = (aes_mem_t *) dst;
  aes_data_t r[4];

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, 4);
  aes_enc_round (r, k + 1, 4);

  /* load 4 blocks of data - decrypt round */
  if (ctx->operation == AES_GCM_OP_DECRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = sv[i];

  /* GHASH multiply block 0 */
  aes_gcm_ghash_mul_first (ctx, d[0], N_AES_LANES * 8);

  /* AES rounds 2 and 3 */
  aes_enc_round (r, k + 2, 4);
  aes_enc_round (r, k + 3, 4);

  /* GHASH multiply block 1 */
  aes_gcm_ghash_mul_next (ctx, (d[1]));

  /* AES rounds 4 and 5 */
  aes_enc_round (r, k + 4, 4);
  aes_enc_round (r, k + 5, 4);

  /* GHASH multiply block 2 */
  aes_gcm_ghash_mul_next (ctx, (d[2]));

  /* AES rounds 6 and 7 */
  aes_enc_round (r, k + 6, 4);
  aes_enc_round (r, k + 7, 4);

  /* GHASH multiply block 3 */
  aes_gcm_ghash_mul_next (ctx, (d[3]));

  /* AES rounds 8 and 9 */
  aes_enc_round (r, k + 8, 4);
  aes_enc_round (r, k + 9, 4);

  /* load 4 blocks of data - encrypt round */
  if (ctx->operation == AES_GCM_OP_ENCRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = sv[i];

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, 4);

  /* store 4 blocks of data */
  for (int i = 0; i < 4; i++)
    dv[i] = d[i];

  /* load next 4 blocks of data data - decrypt round */
  if (ctx->operation == AES_GCM_OP_DECRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = sv[i + 4];

  /* GHASH multiply block 4 */
  aes_gcm_ghash_mul_next (ctx, (d[0]));

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (ctx, r, 4);
  aes_enc_round (r, k + 1, 4);

  /* GHASH multiply block 5 */
  aes_gcm_ghash_mul_next (ctx, (d[1]));

  /* AES rounds 2 and 3 */
  aes_enc_round (r, k + 2, 4);
  aes_enc_round (r, k + 3, 4);

  /* GHASH multiply block 6 */
  aes_gcm_ghash_mul_next (ctx, (d[2]));

  /* AES rounds 4 and 5 */
  aes_enc_round (r, k + 4, 4);
  aes_enc_round (r, k + 5, 4);

  /* GHASH multiply block 7 */
  aes_gcm_ghash_mul_next (ctx, (d[3]));

  /* AES rounds 6 and 7 */
  aes_enc_round (r, k + 6, 4);
  aes_enc_round (r, k + 7, 4);

  /* GHASH reduce 1st step */
  aes_gcm_ghash_reduce (ctx);

  /* AES rounds 8 and 9 */
  aes_enc_round (r, k + 8, 4);
  aes_enc_round (r, k + 9, 4);

  /* GHASH reduce 2nd step */
  aes_gcm_ghash_reduce2 (ctx);

  /* load 4 blocks of data - encrypt round */
  if (ctx->operation == AES_GCM_OP_ENCRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = sv[i + 4];

  /* AES last round(s) */
  aes_gcm_enc_last_round (ctx, r, d, k, 4);

  /* store data */
  for (int i = 0; i < 4; i++)
    dv[i + 4] = d[i];

  /* GHASH final step */
  aes_gcm_ghash_final (ctx);
}

static_always_inline void
aes_gcm_mask_bytes (aes_data_t *d, uword n_bytes)
{
  const union
  {
    u8 b[64];
    aes_data_t r;
  } scale = {
    .b = { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
	   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	   32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	   48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63 },
  };

  d[0] &= (aes_gcm_splat (n_bytes) > scale.r);
}

static_always_inline void
aes_gcm_calc_last (aes_gcm_ctx_t *ctx, aes_data_t *d, int n_blocks,
		   u32 n_bytes)
{
  int n_lanes = (N_AES_LANES == 1 ? n_blocks : (n_bytes + 15) / 16) + 1;
  n_bytes -= (n_blocks - 1) * N_AES_BYTES;
  int i;

  aes_gcm_enc_ctr0_round (ctx, 0);
  aes_gcm_enc_ctr0_round (ctx, 1);

  if (n_bytes != N_AES_BYTES)
    aes_gcm_mask_bytes (d + n_blocks - 1, n_bytes);

  aes_gcm_ghash_mul_first (ctx, d[0], n_lanes);

  aes_gcm_enc_ctr0_round (ctx, 2);
  aes_gcm_enc_ctr0_round (ctx, 3);

  if (n_blocks > 1)
    aes_gcm_ghash_mul_next (ctx, d[1]);

  aes_gcm_enc_ctr0_round (ctx, 4);
  aes_gcm_enc_ctr0_round (ctx, 5);

  if (n_blocks > 2)
    aes_gcm_ghash_mul_next (ctx, d[2]);

  aes_gcm_enc_ctr0_round (ctx, 6);
  aes_gcm_enc_ctr0_round (ctx, 7);

  if (n_blocks > 3)
    aes_gcm_ghash_mul_next (ctx, d[3]);

  aes_gcm_enc_ctr0_round (ctx, 8);
  aes_gcm_enc_ctr0_round (ctx, 9);

  aes_gcm_ghash_mul_final_block (ctx);
  aes_gcm_ghash_reduce (ctx);

  for (i = 10; i < ctx->rounds; i++)
    aes_gcm_enc_ctr0_round (ctx, i);

  aes_gcm_ghash_reduce2 (ctx);

  aes_gcm_ghash_final (ctx);

  aes_gcm_enc_ctr0_round (ctx, i);
}

static_always_inline void
aes_gcm_enc (aes_gcm_ctx_t *ctx, const u8 *src, u8 *dst, u32 n_left)
{
  aes_data_t d[4];

  if (PREDICT_FALSE (n_left == 0))
    {
      int i;
      for (i = 0; i < ctx->rounds + 1; i++)
	aes_gcm_enc_ctr0_round (ctx, i);
      return;
    }

  if (n_left < 4 * N_AES_BYTES)
    {
      ctx->last = 1;
      if (n_left > 3 * N_AES_BYTES)
	{
	  aes_gcm_calc (ctx, d, src, dst, 4, n_left, /* with_ghash */ 0);
	  aes_gcm_calc_last (ctx, d, 4, n_left);
	}
      else if (n_left > 2 * N_AES_BYTES)
	{
	  aes_gcm_calc (ctx, d, src, dst, 3, n_left, /* with_ghash */ 0);
	  aes_gcm_calc_last (ctx, d, 3, n_left);
	}
      else if (n_left > N_AES_BYTES)
	{
	  aes_gcm_calc (ctx, d, src, dst, 2, n_left, /* with_ghash */ 0);
	  aes_gcm_calc_last (ctx, d, 2, n_left);
	}
      else
	{
	  aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 0);
	  aes_gcm_calc_last (ctx, d, 1, n_left);
	}
      return;
    }

  aes_gcm_calc (ctx, d, src, dst, 4, 4 * N_AES_BYTES, /* with_ghash */ 0);

  /* next */
  n_left -= 4 * N_AES_BYTES;
  dst += 4 * N_AES_BYTES;
  src += 4 * N_AES_BYTES;

  for (int n = 8 * N_AES_BYTES; n_left >= n; n_left -= n, src += n, dst += n)
    aes_gcm_calc_double (ctx, d, src, dst);

  if (n_left >= 4 * N_AES_BYTES)
    {
      aes_gcm_calc (ctx, d, src, dst, 4, 4 * N_AES_BYTES, /* with_ghash */ 1);

      /* next */
      n_left -= 4 * N_AES_BYTES;
      dst += 4 * N_AES_BYTES;
      src += 4 * N_AES_BYTES;
    }

  if (n_left == 0)
    {
      aes_gcm_calc_last (ctx, d, 4, 4 * N_AES_BYTES);
      return;
    }

  ctx->last = 1;

  if (n_left > 3 * N_AES_BYTES)
    {
      aes_gcm_calc (ctx, d, src, dst, 4, n_left, /* with_ghash */ 1);
      aes_gcm_calc_last (ctx, d, 4, n_left);
    }
  else if (n_left > 2 * N_AES_BYTES)
    {
      aes_gcm_calc (ctx, d, src, dst, 3, n_left, /* with_ghash */ 1);
      aes_gcm_calc_last (ctx, d, 3, n_left);
    }
  else if (n_left > N_AES_BYTES)
    {
      aes_gcm_calc (ctx, d, src, dst, 2, n_left, /* with_ghash */ 1);
      aes_gcm_calc_last (ctx, d, 2, n_left);
    }
  else
    {
      aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 1);
      aes_gcm_calc_last (ctx, d, 1, n_left);
    }
}

static_always_inline void
aes_gcm_dec (aes_gcm_ctx_t *ctx, const u8 *src, u8 *dst, uword n_left)
{
  aes_data_t d[4] = {};
  ghash_ctx_t gd;

  /* main encryption loop */
  for (int n = 8 * N_AES_BYTES; n_left >= n; n_left -= n, dst += n, src += n)
    aes_gcm_calc_double (ctx, d, src, dst);

  if (n_left >= 4 * N_AES_BYTES)
    {
      aes_gcm_calc (ctx, d, src, dst, 4, 4 * N_AES_BYTES, /* with_ghash */ 1);

      /* next */
      n_left -= 4 * N_AES_BYTES;
      dst += N_AES_BYTES * 4;
      src += N_AES_BYTES * 4;
    }

  if (n_left)
    {
      ctx->last = 1;

      if (n_left > 3 * N_AES_BYTES)
	aes_gcm_calc (ctx, d, src, dst, 4, n_left, /* with_ghash */ 1);
      else if (n_left > 2 * N_AES_BYTES)
	aes_gcm_calc (ctx, d, src, dst, 3, n_left, /* with_ghash */ 1);
      else if (n_left > N_AES_BYTES)
	aes_gcm_calc (ctx, d, src, dst, 2, n_left, /* with_ghash */ 1);
      else
	aes_gcm_calc (ctx, d, src, dst, 1, n_left, /* with_ghash */ 1);
    }

  /* interleaved counter 0 encryption E(Y0, k) and ghash of final GCM
   * (bit length) block */

  aes_gcm_enc_ctr0_round (ctx, 0);
  aes_gcm_enc_ctr0_round (ctx, 1);

  ghash_mul_first (&gd, aes_gcm_final_block (ctx) ^ ctx->T,
		   ctx->Hi[NUM_HI - 1]);

  aes_gcm_enc_ctr0_round (ctx, 2);
  aes_gcm_enc_ctr0_round (ctx, 3);

  ghash_reduce (&gd);

  aes_gcm_enc_ctr0_round (ctx, 4);
  aes_gcm_enc_ctr0_round (ctx, 5);

  ghash_reduce2 (&gd);

  aes_gcm_enc_ctr0_round (ctx, 6);
  aes_gcm_enc_ctr0_round (ctx, 7);

  ctx->T = ghash_final (&gd);

  aes_gcm_enc_ctr0_round (ctx, 8);
  aes_gcm_enc_ctr0_round (ctx, 9);

  for (int i = 10; i < ctx->rounds + 1; i += 1)
    aes_gcm_enc_ctr0_round (ctx, i);
}

static_always_inline int
aes_gcm (const u8 *src, u8 *dst, const u8 *aad, u8 *ivp, u8 *tag,
	 u32 data_bytes, u32 aad_bytes, u8 tag_len,
	 const aes_gcm_key_data_t *kd, int aes_rounds, aes_gcm_op_t op)
{
  u8 *addt = (u8 *) aad;
  u32x4 Y0;

  aes_gcm_ctx_t _ctx = { .counter = 2,
			 .rounds = aes_rounds,
			 .operation = op,
			 .data_bytes = data_bytes,
			 .aad_bytes = aad_bytes,
			 .Ke = kd->Ke,
			 .Hi = kd->Hi },
		*ctx = &_ctx;

  /* initalize counter */
  Y0 = (u32x4) (u64x2){ *(u64u *) ivp, 0 };
  Y0[2] = *(u32u *) (ivp + 8);
  Y0[3] = 1 << 24;
  ctx->EY0 = (u8x16) Y0;

#if N_AES_LANES == 4
  ctx->Y = u32x16_splat_u32x4 (Y0) + (u32x16){
    0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24, 0, 0, 0, 3 << 24, 0, 0, 0, 4 << 24,
  };
#elif N_AES_LANES == 2
  ctx->Y =
    u32x8_splat_u32x4 (Y0) + (u32x8){ 0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24 };
#else
  ctx->Y = Y0 + (u32x4){ 0, 0, 0, 1 << 24 };
#endif

  /* calculate ghash for AAD */
  aes_gcm_ghash (ctx, addt, aad_bytes);

  /* ghash and encrypt/edcrypt  */
  if (op == AES_GCM_OP_ENCRYPT)
    aes_gcm_enc (ctx, src, dst, data_bytes);
  else if (op == AES_GCM_OP_DECRYPT)
    aes_gcm_dec (ctx, src, dst, data_bytes);

  /* final tag is */
  ctx->T = u8x16_reflect (ctx->T) ^ ctx->EY0;

  /* tag_len 16 -> 0 */
  tag_len &= 0xf;

  if (op == AES_GCM_OP_ENCRYPT || op == AES_GCM_OP_GMAC)
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
  u8x16 ek[AES_KEY_ROUNDS (AES_KEY_256) + 1];
  aes_expaned_key_t *Ke = (aes_expaned_key_t *) kd->Ke;

  /* expand AES key */
  aes_key_expand (ek, key, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    Ke[i].lanes[0] = Ke[i].lanes[1] = Ke[i].lanes[2] = Ke[i].lanes[3] = ek[i];

  /* pre-calculate H */
  H = aes_encrypt_block (u8x16_zero (), ek, ks);
  H = u8x16_reflect (H);
  ghash_precompute (H, (u8x16 *) kd->Hi, ARRAY_LEN (kd->Hi));
}

static_always_inline void
clib_aes128_gcm_enc (const aes_gcm_key_data_t *kd, const u8 *plaintext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, u32 tag_bytes, u8 *cyphertext, u8 *tag)
{
  aes_gcm (plaintext, cyphertext, aad, (u8 *) iv, tag, data_bytes, aad_bytes,
	   tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_128), AES_GCM_OP_ENCRYPT);
}

static_always_inline void
clib_aes256_gcm_enc (const aes_gcm_key_data_t *kd, const u8 *plaintext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, u32 tag_bytes, u8 *cyphertext, u8 *tag)
{
  aes_gcm (plaintext, cyphertext, aad, (u8 *) iv, tag, data_bytes, aad_bytes,
	   tag_bytes, kd, AES_KEY_ROUNDS (AES_KEY_256), AES_GCM_OP_ENCRYPT);
}

static_always_inline int
clib_aes128_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, plaintext, aad, (u8 *) iv, (u8 *) tag,
		  data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_128), AES_GCM_OP_DECRYPT);
}

static_always_inline int
clib_aes256_gcm_dec (const aes_gcm_key_data_t *kd, const u8 *cyphertext,
		     u32 data_bytes, const u8 *aad, u32 aad_bytes,
		     const u8 *iv, const u8 *tag, u32 tag_bytes, u8 *plaintext)
{
  return aes_gcm (cyphertext, plaintext, aad, (u8 *) iv, (u8 *) tag,
		  data_bytes, aad_bytes, tag_bytes, kd,
		  AES_KEY_ROUNDS (AES_KEY_256), AES_GCM_OP_DECRYPT);
}

static_always_inline void
clib_aes128_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_128), AES_GCM_OP_GMAC);
}

static_always_inline void
clib_aes256_gmac (const aes_gcm_key_data_t *kd, const u8 *data, u32 data_bytes,
		  const u8 *iv, u32 tag_bytes, u8 *tag)
{
  aes_gcm (0, 0, data, (u8 *) iv, tag, 0, data_bytes, tag_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_256), AES_GCM_OP_GMAC);
}

#endif /* __crypto_aes_gcm_h__ */
