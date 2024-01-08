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

typedef struct
{
  const aes_expaned_key_t exp_key[AES_KEY_ROUNDS (AES_KEY_256) + 1];
} aes_ctr_key_data_t;

typedef struct
{
  const aes_expaned_key_t exp_key[AES_KEY_ROUNDS (AES_KEY_256) + 1];
  aes_counter_t ctr;		   /* counter (reflected) */
  u8 keystream_bytes[N_AES_BYTES]; /* keystream leftovers */
  u32 n_keystream_bytes;	   /* number of keystream leftovers */
} aes_ctr_ctx_t;

static_always_inline aes_counter_t
aes_ctr_one_block (aes_ctr_ctx_t *ctx, aes_counter_t ctr, const u8 *src,
		   u8 *dst, u32 n_parallel, u32 n_bytes, int rounds, int last)
{
  u32 __clib_aligned (N_AES_BYTES)
  inc[] = { N_AES_LANES, 0, 0, 0, N_AES_LANES, 0, 0, 0,
	    N_AES_LANES, 0, 0, 0, N_AES_LANES, 0, 0, 0 };
  const aes_expaned_key_t *k = ctx->exp_key;
  const aes_mem_t *sv = (aes_mem_t *) src;
  aes_mem_t *dv = (aes_mem_t *) dst;
  aes_data_t d[4], t[4];
  u32 r;

  n_bytes -= (n_parallel - 1) * N_AES_BYTES;

  /* AES First Round */
  for (int i = 0; i < n_parallel; i++)
    {
#if N_AES_LANES == 4
      t[i] = k[0].x4 ^ (u8x64) aes_reflect ((u8x64) ctr);
#elif N_AES_LANES == 2
      t[i] = k[0].x2 ^ (u8x32) aes_reflect ((u8x32) ctr);
#else
      t[i] = k[0].x1 ^ (u8x16) aes_reflect ((u8x16) ctr);
#endif
      ctr += *(aes_counter_t *) inc;
    }

  /* Load Data */
  for (int i = 0; i < n_parallel - last; i++)
    d[i] = sv[i];

  if (last)
    d[n_parallel - 1] =
      aes_load_partial ((u8 *) (sv + n_parallel - 1), n_bytes);

  /* AES Intermediate Rounds */
  for (r = 1; r < rounds; r++)
    aes_enc_round (t, k + r, n_parallel);

  /* AES Last Round */
  aes_enc_last_round (t, d, k + r, n_parallel);

  /* Store Data */
  for (int i = 0; i < n_parallel - last; i++)
    dv[i] = d[i];

  if (last)
    {
      aes_store_partial (d[n_parallel - 1], dv + n_parallel - 1, n_bytes);
      *(aes_data_t *) ctx->keystream_bytes = t[n_parallel - 1];
      ctx->n_keystream_bytes = N_AES_BYTES - n_bytes;
    }

  return ctr;
}

static_always_inline void
clib_aes_ctr_init (aes_ctr_ctx_t *ctx, const aes_ctr_key_data_t *kd,
		   const u8 *iv, aes_key_size_t ks)
{
  u32x4 ctr = (u32x4) u8x16_reflect (*(u8x16u *) iv);
#if N_AES_LANES == 4
  ctx->ctr = (aes_counter_t) u32x16_splat_u32x4 (ctr) +
	     (u32x16){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0 };
#elif N_AES_LANES == 2
  ctx->ctr = (aes_counter_t) u32x8_splat_u32x4 (ctr) +
	     (u32x8){ 0, 0, 0, 0, 1, 0, 0, 0 };
#else
  ctx->ctr = ctr;
#endif
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    ((aes_expaned_key_t *) ctx->exp_key)[i] = kd->exp_key[i];
  ctx->n_keystream_bytes = 0;
}

static_always_inline void
clib_aes_ctr_transform (aes_ctr_ctx_t *ctx, const u8 *src, u8 *dst,
			u32 n_bytes, aes_key_size_t ks)
{
  int r = AES_KEY_ROUNDS (ks);
  aes_counter_t ctr = ctx->ctr;

  if (ctx->n_keystream_bytes)
    {
      u8 *ks = ctx->keystream_bytes + N_AES_BYTES - ctx->n_keystream_bytes;

      if (ctx->n_keystream_bytes >= n_bytes)
	{
	  for (int i = 0; i < n_bytes; i++)
	    dst[i] = src[i] ^ ks[i];
	  ctx->n_keystream_bytes -= n_bytes;
	  return;
	}

      for (int i = 0; i < ctx->n_keystream_bytes; i++)
	dst++[0] = src++[0] ^ ks[i];

      n_bytes -= ctx->n_keystream_bytes;
      ctx->n_keystream_bytes = 0;
    }

  /* main loop */
  for (int n = 4 * N_AES_BYTES; n_bytes >= n; n_bytes -= n, dst += n, src += n)
    ctr = aes_ctr_one_block (ctx, ctr, src, dst, 4, n, r, 0);

  if (n_bytes)
    {
      if (n_bytes > 3 * N_AES_BYTES)
	ctr = aes_ctr_one_block (ctx, ctr, src, dst, 4, n_bytes, r, 1);
      else if (n_bytes > 2 * N_AES_BYTES)
	ctr = aes_ctr_one_block (ctx, ctr, src, dst, 3, n_bytes, r, 1);
      else if (n_bytes > N_AES_BYTES)
	ctr = aes_ctr_one_block (ctx, ctr, src, dst, 2, n_bytes, r, 1);
      else
	ctr = aes_ctr_one_block (ctx, ctr, src, dst, 1, n_bytes, r, 1);
    }
  else
    ctx->n_keystream_bytes = 0;

  ctx->ctr = ctr;
}

static_always_inline void
clib_aes_ctr_key_expand (aes_ctr_key_data_t *kd, const u8 *key,
			 aes_key_size_t ks)
{
  u8x16 ek[AES_KEY_ROUNDS (AES_KEY_256) + 1];
  aes_expaned_key_t *k = (aes_expaned_key_t *) kd->exp_key;

  /* expand AES key */
  aes_key_expand (ek, key, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    k[i].lanes[0] = k[i].lanes[1] = k[i].lanes[2] = k[i].lanes[3] = ek[i];
}

static_always_inline void
clib_aes128_ctr (const aes_ctr_key_data_t *kd, const u8 *src, u32 n_bytes,
		 const u8 *iv, u8 *dst)
{
  aes_ctr_ctx_t ctx;
  clib_aes_ctr_init (&ctx, kd, iv, AES_KEY_128);
  clib_aes_ctr_transform (&ctx, src, dst, n_bytes, AES_KEY_128);
}

static_always_inline void
clib_aes192_ctr (const aes_ctr_key_data_t *kd, const u8 *src, u32 n_bytes,
		 const u8 *iv, u8 *dst)
{
  aes_ctr_ctx_t ctx;
  clib_aes_ctr_init (&ctx, kd, iv, AES_KEY_192);
  clib_aes_ctr_transform (&ctx, src, dst, n_bytes, AES_KEY_192);
}

static_always_inline void
clib_aes256_ctr (const aes_ctr_key_data_t *kd, const u8 *src, u32 n_bytes,
		 const u8 *iv, u8 *dst)
{
  aes_ctr_ctx_t ctx;
  clib_aes_ctr_init (&ctx, kd, iv, AES_KEY_256);
  clib_aes_ctr_transform (&ctx, src, dst, n_bytes, AES_KEY_256);
}

#endif /* __crypto_aes_ctr_h__ */
