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
#define aes_ctr_reflect(r)	       ((u32x16) u8x64_reflect_u8x16 (r))
#elif defined(__VAES__)
typedef u8x32 aes_data_t;
typedef u8x32u aes_mem_t;
typedef u32x8 aes_ctr_counter_t;
#define N			       32
#define aes_ctr_load_partial(p, n)     u8x32_load_partial ((u8 *) (p), n)
#define aes_ctr_store_partial(v, p, n) u8x32_store_partial (v, (u8 *) (p), n)
#define aes_ctr_reflect(r)	       ((u32x8) u8x32_reflect_u8x16 (r))
#else
typedef u8x16 aes_data_t;
typedef u8x16u aes_mem_t;
typedef u32x4 aes_ctr_counter_t;
#define N			       16
#define aes_ctr_load_partial(p, n)     u8x16_load_partial ((u8 *) (p), n)
#define aes_ctr_store_partial(v, p, n) u8x16_store_partial (v, (u8 *) (p), n)
#define aes_ctr_reflect(r)	       ((u32x4) u8x16_reflect (r))
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
  const aes_ctr_expaned_key_t exp_key[AES_KEY_ROUNDS (AES_KEY_256) + 1];
} aes_ctr_key_data_t;

typedef struct
{
  u8 rounds;				/* number of AES rounds */
  const aes_ctr_expaned_key_t *exp_key; /* expaded keys */
  aes_ctr_counter_t ctr;		/* counter (reflected) */
} aes_ctr_ctx_t;

static_always_inline void
aes_ctr_first_round (aes_ctr_ctx_t *ctx, aes_data_t *r, uword n_blocks)
{
  const aes_ctr_expaned_key_t k0 = ctx->exp_key[0];

  for (int i = 0; i < n_blocks; i++)
    {
#if N_LANES == 4
      r[i] = k0.x4 ^ (u8x64) aes_ctr_reflect ((u8x64) ctx->ctr);
      ctx->ctr += (u32x16){ 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0 };
#elif N_LANES == 2
      r[i] = k0.x2 ^ (u8x32) aes_ctr_reflect ((u8x32) ctx->ctr);
      ctx->ctr += (u32x8){ 2, 0, 0, 0, 2, 0, 0, 0 };
#else
      r[i] = k0.x1 ^ (u8x16) aes_ctr_reflect ((u8x16) ctx->ctr);
      ctx->ctr += (u32x4){ 1, 0, 0, 0 };
#endif
    }
}

static_always_inline void
aes_ctr_round (aes_data_t *r, const aes_ctr_expaned_key_t *k, uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N_LANES == 4
    r[i] = aes_enc_round_x4 (r[i], k->x4);
#elif N_LANES == 2
    r[i] = aes_enc_round_x2 (r[i], k->x2);
#else
    r[i] = aes_enc_round (r[i], k->x1);
#endif
}

static_always_inline void
aes_ctr_enc_last_round (aes_ctr_ctx_t *ctx, aes_data_t *r, aes_data_t *d,
			const aes_ctr_expaned_key_t *k, uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N_LANES == 4
    d[i] ^= aes_enc_last_round_x4 (r[i], k[ctx->rounds].x4);
#elif N_LANES == 2
    d[i] ^= aes_enc_last_round_x2 (r[i], k[ctx->rounds].x2);
#else
    d[i] ^= aes_enc_last_round (r[i], k[ctx->rounds].x1);
#endif
}

static_always_inline void
aes_ctr_calc (aes_ctr_ctx_t *ctx, aes_data_t *d, const u8 *src, u8 *dst, u32 n,
	      u32 n_bytes, int last)
{
  const aes_ctr_expaned_key_t *k = ctx->exp_key;
  const aes_mem_t *sv = (aes_mem_t *) src;
  aes_mem_t *dv = (aes_mem_t *) dst;
  aes_data_t r[4];

  n_bytes -= (n - 1) * N;

  aes_ctr_first_round (ctx, r, n);

  /* load data */
  for (int i = 0; i < n - last; i++)
    d[i] = sv[i];

  if (last)
    d[n - 1] = aes_ctr_load_partial ((u8 *) (sv + n - 1), n_bytes);

  for (int i = 1; i < ctx->rounds; i++)
    aes_ctr_round (r, k + i, n);

  aes_ctr_enc_last_round (ctx, r, d, k, n);

  /* store data */
  for (int i = 0; i < n - last; i++)
    dv[i] = d[i];

  if (last)
    aes_ctr_store_partial (d[n - 1], dv + n - 1, n_bytes);
}

static_always_inline void
aes_ctr (aes_ctr_ctx_t *ctx, const u8 *src, u8 *dst, const u8 *iv, u32 n_bytes)
{
  aes_data_t d[4] = {};
  uword n_left = n_bytes;
  u32x4 ctr = *(u32x4u *) iv;

#if N_LANES == 4
  ctx->ctr = aes_ctr_reflect (u32x16_splat_u32x4 (ctr)) +
	     (u32x16){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 };
#elif N_LANES == 2
  ctx->ctr = aes_ctr_reflect (u32x8_splat_u32x4 (ctr)) +
	     (u32x8){ 0, 0, 0, 0, 1, 0, 0, 0 };
#else
  ctx->ctr = aes_ctr_reflect (ctr);
#endif

  /* main loop */
  for (; n_left >= 4 * N; n_left -= 4 * N, dst += 4 * N, src += 4 * N)
    aes_ctr_calc (ctx, d, src, dst, 4, 4 * N, 0);

  if (n_left)
    {
      if (n_left > 3 * N)
	aes_ctr_calc (ctx, d, src, dst, 4, n_left, 1);
      else if (n_left > 2 * N)
	aes_ctr_calc (ctx, d, src, dst, 3, n_left, 1);
      else if (n_left > N)
	aes_ctr_calc (ctx, d, src, dst, 2, n_left, 1);
      else
	aes_ctr_calc (ctx, d, src, dst, 1, n_left, 1);
    }
}

static_always_inline void
clib_aes_ctr_key_expand (aes_ctr_key_data_t *kd, const u8 *key,
			 aes_key_size_t ks)
{
  u8x16 ek[AES_KEY_ROUNDS (AES_KEY_256) + 1];
  aes_ctr_expaned_key_t *k = (aes_ctr_expaned_key_t *) kd->exp_key;

  /* expand AES key */
  aes_key_expand (ek, key, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    k[i].lanes[0] = k[i].lanes[1] = k[i].lanes[2] = k[i].lanes[3] = ek[i];
}

static_always_inline void
clib_aes128_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr_ctx_t ctx = { .rounds = AES_KEY_ROUNDS (AES_KEY_128),
			.exp_key = kd->exp_key };
  aes_ctr (&ctx, plaintext, cyphertext, iv, n_bytes);
}

static_always_inline void
clib_aes192_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr_ctx_t ctx = { .rounds = AES_KEY_ROUNDS (AES_KEY_192),
			.exp_key = kd->exp_key };
  aes_ctr (&ctx, plaintext, cyphertext, iv, n_bytes);
}

static_always_inline void
clib_aes256_ctr_enc (const aes_ctr_key_data_t *kd, const u8 *plaintext,
		     u32 n_bytes, const u8 *iv, u8 *cyphertext)
{
  aes_ctr_ctx_t ctx = { .rounds = AES_KEY_ROUNDS (AES_KEY_256),
			.exp_key = kd->exp_key };
  aes_ctr (&ctx, plaintext, cyphertext, iv, n_bytes);
}

#endif /* __crypto_aes_ctr_h__ */
