/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef __crypto_aes_ctr_h__
#define __crypto_aes_ctr_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>
#include <vppinfra/crypto/aes.h>

#if defined(__VAES__) && defined(__AVX512F__)
typedef u8x64 aes_data_t;
typedef u8x64u aes_mem_t;
typedef u32x16 aes_ctr_counter_t;
#define N			       64
#define aes_ctr_load_partial(p, n)     u8x64_load_partial ((u8 *) (p), n)
#define aes_ctr_store_partial(v, p, n) u8x64_store_partial (v, (u8 *) (p), n)
#define aes_ctr_reflect(r)	       u8x64_reflect_u8x16 (r)
#elif defined(__VAES__)
typedef u8x32 aes_data_t;
typedef u8x32u aes_mem_t;
typedef u32x8 aes_ctr_counter_t;
#define N			       32
#define aes_ctr_load_partial(p, n)     u8x32_load_partial ((u8 *) (p), n)
#define aes_ctr_store_partial(v, p, n) u8x32_store_partial (v, (u8 *) (p), n)
#define aes_ctr_reflect(r)	       u8x32_reflect_u8x16 (r)
#else
typedef u8x16 aes_data_t;
typedef u8x16u aes_mem_t;
typedef u32x4 aes_ctr_counter_t;
#define N			       16
#define aes_ctr_load_partial(p, n)     u8x16_load_partial ((u8 *) (p), n)
#define aes_ctr_store_partial(v, p, n) u8x16_store_partial (v, (u8 *) (p), n)
#define aes_ctr_reflect(r)	       u8x16_reflect (r)
#endif
#define N_LANES (N / 16)

typedef union
{
  u8x16 x1;
  u8x32 x2;
  u8x64 x4;
  u8x16 lanes[4];
} __clib_aligned (64)
aes_ctr_expaned_key_t;

typedef struct
{
  /* extracted AES key */
  const aes_ctr_expaned_key_t Ke[AES_KEY_ROUNDS (AES_KEY_256) + 1];
} aes_ctr_key_data_t;

typedef struct
{
  int last;
  u8 rounds;

  /* expaded keys */
  const aes_ctr_expaned_key_t *Ke;

  /* counter */
  u32 counter;
  aes_ctr_counter_t Y;

} aes_ctr_ctx_t;

static_always_inline void
aes_ctr_enc_first_round (aes_ctr_ctx_t *ctx, aes_data_t *r, uword n_blocks)
{
  const aes_ctr_expaned_key_t Ke0 = ctx->Ke[0];
  uword i = 0;

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 128, 256 or 512-blocks in parallel
     except the last round, overflow can happen only when n_blocks == 4 */

#if N_LANES == 4
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
      u32x16 Yr = (u32x16) aes_ctr_reflect ((u8x64) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x4 ^ (u8x64) ctx->Y; /* Initial AES round */
	  Yr += ctr_4444;
	  ctx->Y = (u32x16) aes_ctr_reflect ((u8x64) Yr);
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
#elif N_LANES == 2
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
      u32x8 Yr = (u32x8) aes_ctr_reflect ((u8x32) ctx->Y);

      for (; i < n_blocks; i++)
	{
	  r[i] = Ke0.x2 ^ (u8x32) ctx->Y; /* Initial AES round */
	  Yr += ctr_22;
	  ctx->Y = (u32x8) aes_ctr_reflect ((u8x32) Yr);
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
aes_ctr_enc_round (aes_data_t *r, const aes_ctr_expaned_key_t *Ke,
		   uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N_LANES == 4
    r[i] = aes_enc_round_x4 (r[i], Ke->x4);
#elif N_LANES == 2
    r[i] = aes_enc_round_x2 (r[i], Ke->x2);
#else
    r[i] = aes_enc_round (r[i], Ke->x1);
#endif
}

static_always_inline void
aes_ctr_enc_last_round (aes_ctr_ctx_t *ctx, aes_data_t *r, aes_data_t *d,
			const aes_ctr_expaned_key_t *Ke, uword n_blocks)
{
  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < ctx->rounds; i++)
    aes_ctr_enc_round (r, Ke + i, n_blocks);

  for (int i = 0; i < n_blocks; i++)
#if N_LANES == 4
    d[i] ^= aes_enc_last_round_x4 (r[i], Ke[ctx->rounds].x4);
#elif N_LANES == 2
    d[i] ^= aes_enc_last_round_x2 (r[i], Ke[ctx->rounds].x2);
#else
    d[i] ^= aes_enc_last_round (r[i], Ke[ctx->rounds].x1);
#endif
}

static_always_inline void
aes_ctr_calc (aes_ctr_ctx_t *ctx, aes_data_t *d, const u8 *src, u8 *dst, u32 n,
	      u32 n_bytes)
{
  const aes_ctr_expaned_key_t *k = ctx->Ke;
  const aes_mem_t *sv = (aes_mem_t *) src;
  aes_mem_t *dv = (aes_mem_t *) dst;
  aes_data_t r[4];
  u32 i;

  n_bytes -= (n - 1) * N;

  /* AES rounds 0 and 1 */
  aes_ctr_enc_first_round (ctx, r, n);
  aes_ctr_enc_round (r, k + 1, n);

  /* load data */
  for (i = 0; i < n - ctx->last; i++)
    d[i] = sv[i];

  if (ctx->last)
    d[n - 1] = aes_ctr_load_partial ((u8 *) (sv + n - 1), n_bytes);

  aes_ctr_enc_round (r, k + 2, n);
  aes_ctr_enc_round (r, k + 3, n);
  aes_ctr_enc_round (r, k + 4, n);
  aes_ctr_enc_round (r, k + 5, n);
  aes_ctr_enc_round (r, k + 6, n);
  aes_ctr_enc_round (r, k + 7, n);
  aes_ctr_enc_round (r, k + 8, n);
  aes_ctr_enc_round (r, k + 9, n);
  aes_ctr_enc_last_round (ctx, r, d, k, n);

  /* store data */
  for (i = 0; i < n - ctx->last; i++)
    dv[i] = d[i];

  if (ctx->last)
    aes_ctr_store_partial (d[n - 1], dv + n - 1, n_bytes);
}

static_always_inline void
aes_ctr (const u8 *src, u8 *dst, const u8 *iv, u32 n_bytes,
	 const aes_ctr_key_data_t *kd, int aes_rounds)
{
  u32x4 Y;
  aes_data_t d[4] = {};
  uword n_left = n_bytes;

  aes_ctr_ctx_t _ctx = { .counter = 1,
			 .rounds = aes_rounds,
			 .Ke = kd->Ke,
			 },
		*ctx = &_ctx;

  /* initalize counter */
  Y = *(u32x4u *) iv;

#if N_LANES == 4
  ctx->Y = u32x16_splat_u32x4 (Y) + (u32x16){
    0, 0, 0, 0, 0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24, 0, 0, 0, 3 << 24,
  };
#elif N_LANES == 2
  ctx->Y = u32x8_splat_u32x4 (Y) + (u32x8){ 0, 0, 0, 0, 0, 0, 0, 1 << 24 };
#else
  ctx->Y = Y;
#endif

  /* main loop */
  for (; n_left >= 4 * N; n_left -= 4 * N, dst += 4 * N, src += 4 * N)
    aes_ctr_calc (ctx, d, src, dst, 4, 4 * N);

  if (n_left)
    {
      ctx->last = 1;

      if (n_left > 3 * N)
	aes_ctr_calc (ctx, d, src, dst, 4, n_left);
      else if (n_left > 2 * N)
	aes_ctr_calc (ctx, d, src, dst, 3, n_left);
      else if (n_left > N)
	aes_ctr_calc (ctx, d, src, dst, 2, n_left);
      else
	aes_ctr_calc (ctx, d, src, dst, 1, n_left);
    }
}

static_always_inline void
clib_aes_ctr_key_expand (aes_ctr_key_data_t *kd, const u8 *key,
			 aes_key_size_t ks)
{
  u8x16 ek[AES_KEY_ROUNDS (AES_KEY_256) + 1];
  aes_ctr_expaned_key_t *Ke = (aes_ctr_expaned_key_t *) kd->Ke;

  /* expand AES key */
  aes_key_expand (ek, key, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    Ke[i].lanes[0] = Ke[i].lanes[1] = Ke[i].lanes[2] = Ke[i].lanes[3] = ek[i];
}

static_always_inline void
clib_aes128_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr (plaintext, cyphertext, iv, n_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_128));
}

static_always_inline void
clib_aes192_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr (plaintext, cyphertext, iv, n_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_192));
}

static_always_inline void
clib_aes256_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr (plaintext, cyphertext, iv, n_bytes, kd,
	   AES_KEY_ROUNDS (AES_KEY_256));
}

#endif /* __crypto_aes_ctr_h__ */
