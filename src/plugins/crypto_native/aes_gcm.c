/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>
#include <crypto_native/aes.h>
#include <crypto_native/ghash.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

#ifdef __VAES__
#define NUM_HI 32
#else
#define NUM_HI 8
#endif

typedef struct
{
  /* pre-calculated hash key values */
  const u8x16 Hi[NUM_HI];
  /* extracted AES key */
  const u8x16 Ke[15];
#ifdef __VAES__
  const u8x64 Ke4[15];
#endif
} aes_gcm_key_data_t;

typedef struct
{
  u32 counter;
  union
  {
    u32x4 Y;
    u32x16 Y4;
  };
} aes_gcm_counter_t;

typedef enum
{
  AES_GCM_F_WITH_GHASH = (1 << 0),
  AES_GCM_F_LAST_ROUND = (1 << 1),
  AES_GCM_F_ENCRYPT = (1 << 2),
  AES_GCM_F_DECRYPT = (1 << 3),
} aes_gcm_flags_t;

static const u32x4 ctr_inv_1 = { 0, 0, 0, 1 << 24 };

static_always_inline void
aes_gcm_enc_first_round (u8x16 * r, aes_gcm_counter_t * ctr, u8x16 k,
			 int n_blocks)
{
  if (PREDICT_TRUE ((u8) ctr->counter < (256 - 2 * n_blocks)))
    {
      for (int i = 0; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x16) ctr->Y;
	  ctr->Y += ctr_inv_1;
	}
      ctr->counter += n_blocks;
    }
  else
    {
      for (int i = 0; i < n_blocks; i++)
	{
	  r[i] = k ^ (u8x16) ctr->Y;
	  ctr->counter++;
	  ctr->Y[3] = clib_host_to_net_u32 (ctr->counter + 1);
	}
    }
}

static_always_inline void
aes_gcm_enc_round (u8x16 * r, u8x16 k, int n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
    r[i] = aes_enc_round (r[i], k);
}

static_always_inline void
aes_gcm_enc_last_round (u8x16 * r, u8x16 * d, u8x16 const *k,
			int rounds, int n_blocks)
{

  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < rounds; i++)
    aes_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
    d[i] ^= aes_enc_last_round (r[i], k[rounds]);
}

static_always_inline u8x16
aes_gcm_ghash_blocks (u8x16 T, aes_gcm_key_data_t * kd,
		      u8x16u * in, int n_blocks)
{
  ghash_data_t _gd, *gd = &_gd;
  u8x16 *Hi = (u8x16 *) kd->Hi + NUM_HI - n_blocks;
  ghash_mul_first (gd, u8x16_reflect (in[0]) ^ T, Hi[0]);
  for (int i = 1; i < n_blocks; i++)
    ghash_mul_next (gd, u8x16_reflect ((in[i])), Hi[i]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}

static_always_inline u8x16
aes_gcm_ghash (u8x16 T, aes_gcm_key_data_t * kd, u8x16u * in, u32 n_left)
{

  while (n_left >= 128)
    {
      T = aes_gcm_ghash_blocks (T, kd, in, 8);
      n_left -= 128;
      in += 8;
    }

  if (n_left >= 64)
    {
      T = aes_gcm_ghash_blocks (T, kd, in, 4);
      n_left -= 64;
      in += 4;
    }

  if (n_left >= 32)
    {
      T = aes_gcm_ghash_blocks (T, kd, in, 2);
      n_left -= 32;
      in += 2;
    }

  if (n_left >= 16)
    {
      T = aes_gcm_ghash_blocks (T, kd, in, 1);
      n_left -= 16;
      in += 1;
    }

  if (n_left)
    {
      u8x16 r = aes_load_partial (in, n_left);
      T = ghash_mul (u8x16_reflect (r) ^ T, kd->Hi[NUM_HI - 1]);
    }
  return T;
}

static_always_inline u8x16
aes_gcm_calc (u8x16 T, aes_gcm_key_data_t * kd, u8x16 * d,
	      aes_gcm_counter_t * ctr, u8x16u * inv, u8x16u * outv,
	      int rounds, int n, int last_block_bytes, aes_gcm_flags_t f)
{
  u8x16 r[n];
  ghash_data_t _gd = { }, *gd = &_gd;
  const u8x16 *rk = (u8x16 *) kd->Ke;
  int ghash_blocks = (f & AES_GCM_F_ENCRYPT) ? 4 : n, gc = 1;
  u8x16 *Hi = (u8x16 *) kd->Hi + NUM_HI - ghash_blocks;

  clib_prefetch_load (inv + 4);

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (r, ctr, rk[0], n);
  aes_gcm_enc_round (r, rk[1], n);

  /* load data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    {
      for (int i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
	d[i] = inv[i];

      if (f & AES_GCM_F_LAST_ROUND)
	d[n - 1] = aes_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH multiply block 1 */
  if (f & AES_GCM_F_WITH_GHASH)
    ghash_mul_first (gd, u8x16_reflect (d[0]) ^ T, Hi[0]);

  /* AES rounds 2 and 3 */
  aes_gcm_enc_round (r, rk[2], n);
  aes_gcm_enc_round (r, rk[3], n);

  /* GHASH multiply block 2 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[1]);

  /* AES rounds 4 and 5 */
  aes_gcm_enc_round (r, rk[4], n);
  aes_gcm_enc_round (r, rk[5], n);

  /* GHASH multiply block 3 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[2]);

  /* AES rounds 6 and 7 */
  aes_gcm_enc_round (r, rk[6], n);
  aes_gcm_enc_round (r, rk[7], n);

  /* GHASH multiply block 4 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[3]);

  /* AES rounds 8 and 9 */
  aes_gcm_enc_round (r, rk[8], n);
  aes_gcm_enc_round (r, rk[9], n);

  /* GHASH reduce 1st step */
  if (f & AES_GCM_F_WITH_GHASH)
    ghash_reduce (gd);

  /* load data - encrypt round */
  if (f & AES_GCM_F_ENCRYPT)
    {
      for (int i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
	d[i] = inv[i];

      if (f & AES_GCM_F_LAST_ROUND)
	d[n - 1] = aes_load_partial (inv + n - 1, last_block_bytes);
    }

  /* GHASH reduce 2nd step */
  if (f & AES_GCM_F_WITH_GHASH)
    ghash_reduce2 (gd);

  /* AES last round(s) */
  aes_gcm_enc_last_round (r, d, rk, rounds, n);

  /* store data */
  for (int i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
    outv[i] = d[i];

  if (f & AES_GCM_F_LAST_ROUND)
    aes_store_partial (outv + n - 1, d[n - 1], last_block_bytes);

  /* GHASH final step */
  if (f & AES_GCM_F_WITH_GHASH)
    T = ghash_final (gd);

  return T;
}

static_always_inline u8x16
aes_gcm_calc_double (u8x16 T, aes_gcm_key_data_t * kd, u8x16 * d,
		     aes_gcm_counter_t * ctr, u8x16u * inv, u8x16u * outv,
		     int rounds, aes_gcm_flags_t f)
{
  u8x16 r[4];
  ghash_data_t _gd, *gd = &_gd;
  const u8x16 *rk = (u8x16 *) kd->Ke;
  u8x16 *Hi = (u8x16 *) kd->Hi + NUM_HI - 8;

  /* AES rounds 0 and 1 */
  aes_gcm_enc_first_round (r, ctr, rk[0], 4);
  aes_gcm_enc_round (r, rk[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    {
      d[0] = inv[0];
      d[1] = inv[1];
      d[2] = inv[2];
      d[3] = inv[3];
    }

  /* GHASH multiply block 0 */
  ghash_mul_first (gd, u8x16_reflect (d[0]) ^ T, Hi[0]);

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
  if (f & AES_GCM_F_ENCRYPT)
    {
      d[0] = inv[0];
      d[1] = inv[1];
      d[2] = inv[2];
      d[3] = inv[3];
    }

  /* AES last round(s) */
  aes_gcm_enc_last_round (r, d, rk, rounds, 4);

  /* store 4 blocks of data */
  outv[0] = d[0];
  outv[1] = d[1];
  outv[2] = d[2];
  outv[3] = d[3];

  /* load next 4 blocks of data data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    {
      d[0] = inv[4];
      d[1] = inv[5];
      d[2] = inv[6];
      d[3] = inv[7];
    }

  /* GHASH multiply block 4 */
  ghash_mul_next (gd, u8x16_reflect (d[0]), Hi[4]);

  /* AES rounds 0, 1 and 2 */
  aes_gcm_enc_first_round (r, ctr, rk[0], 4);
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
  if (f & AES_GCM_F_ENCRYPT)
    {
      d[0] = inv[4];
      d[1] = inv[5];
      d[2] = inv[6];
      d[3] = inv[7];
    }

  /* GHASH reduce 2nd step */
  ghash_reduce2 (gd);

  /* AES last round(s) */
  aes_gcm_enc_last_round (r, d, rk, rounds, 4);

  /* store data */
  outv[4] = d[0];
  outv[5] = d[1];
  outv[6] = d[2];
  outv[7] = d[3];

  /* GHASH final step */
  return ghash_final (gd);
}

static_always_inline u8x16
aes_gcm_ghash_last (u8x16 T, aes_gcm_key_data_t * kd, u8x16 * d,
		    int n_blocks, int n_bytes)
{
  ghash_data_t _gd, *gd = &_gd;
  u8x16 *Hi = (u8x16 *) kd->Hi + NUM_HI - n_blocks;

  if (n_bytes)
    d[n_blocks - 1] = aes_byte_mask (d[n_blocks - 1], n_bytes);

  ghash_mul_first (gd, u8x16_reflect (d[0]) ^ T, Hi[0]);
  if (n_blocks > 1)
    ghash_mul_next (gd, u8x16_reflect (d[1]), Hi[1]);
  if (n_blocks > 2)
    ghash_mul_next (gd, u8x16_reflect (d[2]), Hi[2]);
  if (n_blocks > 3)
    ghash_mul_next (gd, u8x16_reflect (d[3]), Hi[3]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  return ghash_final (gd);
}

#ifdef __VAES__
static const u32x16 ctr_inv_1234 = {
  0, 0, 0, 1 << 24, 0, 0, 0, 2 << 24, 0, 0, 0, 3 << 24, 0, 0, 0, 4 << 24,
};

static const u32x16 ctr_inv_4444 = {
  0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24, 0, 0, 0, 4 << 24
};

static const u32x16 ctr_1234 = {
  1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
};

static_always_inline void
aes4_gcm_enc_first_round (u8x64 * r, aes_gcm_counter_t * ctr, u8x64 k, int n)
{
  u8 last_byte = (u8) ctr->counter;
  int i = 0;

  /* As counter is stored in network byte order for performance reasons we
     are incrementing least significant byte only except in case where we
     overlow. As we are processing four 512-blocks in parallel except the
     last round, overflow can happen only when n == 4 */

  if (n == 4)
    for (; i < 2; i++)
      {
	r[i] = k ^ (u8x64) ctr->Y4;
	ctr->Y4 += ctr_inv_4444;
      }

  if (n == 4 && PREDICT_TRUE (last_byte == 241))
    {
      u32x16 Yc, Yr = (u32x16) u8x64_reflect_u8x16 ((u8x64) ctr->Y4);

      for (; i < n; i++)
	{
	  r[i] = k ^ (u8x64) ctr->Y4;
	  Yc = u32x16_splat (ctr->counter + 4 * (i + 1)) + ctr_1234;
	  Yr = (u32x16) u32x16_mask_blend (Yr, Yc, 0x1111);
	  ctr->Y4 = (u32x16) u8x64_reflect_u8x16 ((u8x64) Yr);
	}
    }
  else
    {
      for (; i < n; i++)
	{
	  r[i] = k ^ (u8x64) ctr->Y4;
	  ctr->Y4 += ctr_inv_4444;
	}
    }
  ctr->counter += n * 4;
}

static_always_inline void
aes4_gcm_enc_round (u8x64 * r, u8x64 k, int n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
    r[i] = aes_enc_round_x4 (r[i], k);
}

static_always_inline void
aes4_gcm_enc_last_round (u8x64 * r, u8x64 * d, u8x64 const *k,
			 int rounds, int n_blocks)
{

  /* additional ronuds for AES-192 and AES-256 */
  for (int i = 10; i < rounds; i++)
    aes4_gcm_enc_round (r, k[i], n_blocks);

  for (int i = 0; i < n_blocks; i++)
    d[i] ^= aes_enc_last_round_x4 (r[i], k[rounds]);
}

static_always_inline u8x16
aes4_gcm_calc (u8x16 T, aes_gcm_key_data_t * kd, u8x64 * d,
	       aes_gcm_counter_t * ctr, u8x16u * in, u8x16u * out,
	       int rounds, int n, int last_4block_bytes, aes_gcm_flags_t f)
{
  ghash4_data_t _gd, *gd = &_gd;
  const u8x64 *rk = (u8x64 *) kd->Ke4;
  int i, ghash_blocks, gc = 1;
  u8x64u *Hi4, *inv = (u8x64u *) in, *outv = (u8x64u *) out;
  u8x64 r[4];
  u64 byte_mask = _bextr_u64 (-1LL, 0, last_4block_bytes);

  if (f & AES_GCM_F_ENCRYPT)
    {
      /* during encryption we either hash four 512-bit blocks from previous
         round or we don't hash at all */
      ghash_blocks = 4;
      Hi4 = (u8x64u *) (kd->Hi + NUM_HI - ghash_blocks * 4);
    }
  else
    {
      /* during deccryption we hash 1..4 512-bit blocks from current round */
      ghash_blocks = n;
      int n_128bit_blocks = n * 4;
      /* if this is last round of decryption, we may have less than 4
         128-bit blocks in the last 512-bit data block, so we need to adjust
         Hi4 pointer accordingly */
      if (f & AES_GCM_F_LAST_ROUND)
	n_128bit_blocks += ((last_4block_bytes + 15) >> 4) - 4;
      Hi4 = (u8x64u *) (kd->Hi + NUM_HI - n_128bit_blocks);
    }

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctr, rk[0], n);
  aes4_gcm_enc_round (r, rk[1], n);

  /* load 4 blocks of data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    {
      for (i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
	d[i] = inv[i];

      if (f & AES_GCM_F_LAST_ROUND)
	d[i] = u8x64_mask_load (u8x64_splat (0), inv + i, byte_mask);
    }

  /* GHASH multiply block 0 */
  if (f & AES_GCM_F_WITH_GHASH)
    ghash4_mul_first (gd, u8x64_reflect_u8x16 (d[0]) ^
		      u8x64_insert_u8x16 (u8x64_splat (0), T, 0), Hi4[0]);

  /* AES rounds 2 and 3 */
  aes4_gcm_enc_round (r, rk[2], n);
  aes4_gcm_enc_round (r, rk[3], n);

  /* GHASH multiply block 1 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[1]);

  /* AES rounds 4 and 5 */
  aes4_gcm_enc_round (r, rk[4], n);
  aes4_gcm_enc_round (r, rk[5], n);

  /* GHASH multiply block 2 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[2]);

  /* AES rounds 6 and 7 */
  aes4_gcm_enc_round (r, rk[6], n);
  aes4_gcm_enc_round (r, rk[7], n);

  /* GHASH multiply block 3 */
  if ((f & AES_GCM_F_WITH_GHASH) && gc++ < ghash_blocks)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[3]);

  /* load 4 blocks of data - decrypt round */
  if (f & AES_GCM_F_ENCRYPT)
    {
      for (i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
	d[i] = inv[i];

      if (f & AES_GCM_F_LAST_ROUND)
	d[i] = u8x64_mask_load (u8x64_splat (0), inv + i, byte_mask);
    }

  /* AES rounds 8 and 9 */
  aes4_gcm_enc_round (r, rk[8], n);
  aes4_gcm_enc_round (r, rk[9], n);

  /* AES last round(s) */
  aes4_gcm_enc_last_round (r, d, rk, rounds, n);

  /* store 4 blocks of data */
  for (i = 0; i < n - ((f & AES_GCM_F_LAST_ROUND) != 0); i++)
    outv[i] = d[i];

  if (f & AES_GCM_F_LAST_ROUND)
    u8x64_mask_store (d[i], outv + i, byte_mask);

  /* GHASH reduce 1st step */
  ghash4_reduce (gd);

  /* GHASH reduce 2nd step */
  ghash4_reduce2 (gd);

  /* GHASH final step */
  return ghash4_final (gd);
}

static_always_inline u8x16
aes4_gcm_calc_double (u8x16 T, aes_gcm_key_data_t * kd, u8x64 * d,
		      aes_gcm_counter_t * ctr, u8x16u * in, u8x16u * out,
		      int rounds, aes_gcm_flags_t f)
{
  u8x64 r[4];
  ghash4_data_t _gd, *gd = &_gd;
  const u8x64 *rk = (u8x64 *) kd->Ke4;
  u8x64 *Hi4 = (u8x64 *) (kd->Hi + NUM_HI - 32);
  u8x64u *inv = (u8x64u *) in, *outv = (u8x64u *) out;

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctr, rk[0], 4);
  aes4_gcm_enc_round (r, rk[1], 4);

  /* load 4 blocks of data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i];

  /* GHASH multiply block 0 */
  ghash4_mul_first (gd, u8x64_reflect_u8x16 (d[0]) ^
		    u8x64_insert_u8x16 (u8x64_splat (0), T, 0), Hi4[0]);

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
  if (f & AES_GCM_F_ENCRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i];

  /* AES last round(s) */
  aes4_gcm_enc_last_round (r, d, rk, rounds, 4);

  /* store 4 blocks of data */
  for (int i = 0; i < 4; i++)
    outv[i] = d[i];

  /* load 4 blocks of data - decrypt round */
  if (f & AES_GCM_F_DECRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i + 4];

  /* GHASH multiply block 3 */
  ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[0]), Hi4[4]);

  /* AES rounds 0 and 1 */
  aes4_gcm_enc_first_round (r, ctr, rk[0], 4);
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
  if (f & AES_GCM_F_ENCRYPT)
    for (int i = 0; i < 4; i++)
      d[i] = inv[i + 4];

  /* AES last round(s) */
  aes4_gcm_enc_last_round (r, d, rk, rounds, 4);

  /* store 4 blocks of data */
  for (int i = 0; i < 4; i++)
    outv[i + 4] = d[i];

  /* GHASH final step */
  return ghash4_final (gd);
}

static_always_inline u8x16
aes4_gcm_ghash_last (u8x16 T, aes_gcm_key_data_t * kd, u8x64 * d,
		     int n, int last_4block_bytes)
{
  ghash4_data_t _gd, *gd = &_gd;
  u8x64u *Hi4;
  int n_128bit_blocks;
  u64 byte_mask = _bextr_u64 (-1LL, 0, last_4block_bytes);
  n_128bit_blocks = (n - 1) * 4 + ((last_4block_bytes + 15) >> 4);
  Hi4 = (u8x64u *) (kd->Hi + NUM_HI - n_128bit_blocks);

  d[n - 1] = u8x64_mask_blend (u8x64_splat (0), d[n - 1], byte_mask);
  ghash4_mul_first (gd, u8x64_reflect_u8x16 (d[0]) ^
		    u8x64_insert_u8x16 (u8x64_splat (0), T, 0), Hi4[0]);
  if (n > 1)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[1]), Hi4[1]);
  if (n > 2)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[2]), Hi4[2]);
  if (n > 3)
    ghash4_mul_next (gd, u8x64_reflect_u8x16 (d[3]), Hi4[3]);
  ghash4_reduce (gd);
  ghash4_reduce2 (gd);
  return ghash4_final (gd);
}
#endif

static_always_inline u8x16
aes_gcm_enc (u8x16 T, aes_gcm_key_data_t * kd, aes_gcm_counter_t * ctr,
	     u8x16u * inv, u8x16u * outv, u32 n_left, int rounds)
{
  u8x16 d[4];
  aes_gcm_flags_t f = AES_GCM_F_ENCRYPT;

  if (n_left == 0)
    return T;

#if __VAES__
  u8x64 d4[4];
  if (n_left < 256)
    {
      f |= AES_GCM_F_LAST_ROUND;
      if (n_left > 192)
	{
	  n_left -= 192;
	  aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4, n_left, f);
	  return aes4_gcm_ghash_last (T, kd, d4, 4, n_left);
	}
      else if (n_left > 128)
	{
	  n_left -= 128;
	  aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 3, n_left, f);
	  return aes4_gcm_ghash_last (T, kd, d4, 3, n_left);
	}
      else if (n_left > 64)
	{
	  n_left -= 64;
	  aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 2, n_left, f);
	  return aes4_gcm_ghash_last (T, kd, d4, 2, n_left);
	}
      else
	{
	  aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 1, n_left, f);
	  return aes4_gcm_ghash_last (T, kd, d4, 1, n_left);
	}
    }

  aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4, 0, f);

  /* next */
  n_left -= 256;
  outv += 16;
  inv += 16;

  f |= AES_GCM_F_WITH_GHASH;

  while (n_left >= 512)
    {
      T = aes4_gcm_calc_double (T, kd, d4, ctr, inv, outv, rounds, f);

      /* next */
      n_left -= 512;
      outv += 32;
      inv += 32;
    }

  while (n_left >= 256)
    {
      T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4, 0, f);

      /* next */
      n_left -= 256;
      outv += 16;
      inv += 16;
    }

  if (n_left == 0)
    return aes4_gcm_ghash_last (T, kd, d4, 4, 64);

  f |= AES_GCM_F_LAST_ROUND;

  if (n_left > 192)
    {
      n_left -= 192;
      T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4, n_left, f);
      return aes4_gcm_ghash_last (T, kd, d4, 4, n_left);
    }

  if (n_left > 128)
    {
      n_left -= 128;
      T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 3, n_left, f);
      return aes4_gcm_ghash_last (T, kd, d4, 3, n_left);
    }

  if (n_left > 64)
    {
      n_left -= 64;
      T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 2, n_left, f);
      return aes4_gcm_ghash_last (T, kd, d4, 2, n_left);
    }

  T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 1, n_left, f);
  return aes4_gcm_ghash_last (T, kd, d4, 1, n_left);
#endif

  if (n_left < 64)
    {
      f |= AES_GCM_F_LAST_ROUND;
      if (n_left > 48)
	{
	  n_left -= 48;
	  aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, n_left, f);
	  return aes_gcm_ghash_last (T, kd, d, 4, n_left);
	}
      else if (n_left > 32)
	{
	  n_left -= 32;
	  aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 3, n_left, f);
	  return aes_gcm_ghash_last (T, kd, d, 3, n_left);
	}
      else if (n_left > 16)
	{
	  n_left -= 16;
	  aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 2, n_left, f);
	  return aes_gcm_ghash_last (T, kd, d, 2, n_left);
	}
      else
	{
	  aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 1, n_left, f);
	  return aes_gcm_ghash_last (T, kd, d, 1, n_left);
	}
    }

  aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, 0, f);

  /* next */
  n_left -= 64;
  outv += 4;
  inv += 4;

  f |= AES_GCM_F_WITH_GHASH;

  while (n_left >= 128)
    {
      T = aes_gcm_calc_double (T, kd, d, ctr, inv, outv, rounds, f);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, 0, f);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    return aes_gcm_ghash_last (T, kd, d, 4, 0);

  f |= AES_GCM_F_LAST_ROUND;

  if (n_left > 48)
    {
      n_left -= 48;
      T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, n_left, f);
      return aes_gcm_ghash_last (T, kd, d, 4, n_left);
    }

  if (n_left > 32)
    {
      n_left -= 32;
      T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 3, n_left, f);
      return aes_gcm_ghash_last (T, kd, d, 3, n_left);
    }

  if (n_left > 16)
    {
      n_left -= 16;
      T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 2, n_left, f);
      return aes_gcm_ghash_last (T, kd, d, 2, n_left);
    }

  T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 1, n_left, f);
  return aes_gcm_ghash_last (T, kd, d, 1, n_left);
}

static_always_inline u8x16
aes_gcm_dec (u8x16 T, aes_gcm_key_data_t * kd, aes_gcm_counter_t * ctr,
	     u8x16u * inv, u8x16u * outv, u32 n_left, int rounds)
{
  aes_gcm_flags_t f = AES_GCM_F_WITH_GHASH | AES_GCM_F_DECRYPT;
#ifdef __VAES__
  u8x64 d4[4] = { };

  while (n_left >= 512)
    {
      T = aes4_gcm_calc_double (T, kd, d4, ctr, inv, outv, rounds, f);

      /* next */
      n_left -= 512;
      outv += 32;
      inv += 32;
    }

  while (n_left >= 256)
    {
      T = aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4, 0, f);

      /* next */
      n_left -= 256;
      outv += 16;
      inv += 16;
    }

  if (n_left == 0)
    return T;

  f |= AES_GCM_F_LAST_ROUND;

  if (n_left > 192)
    return aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 4,
			  n_left - 192, f);
  if (n_left > 128)
    return aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 3,
			  n_left - 128, f);
  if (n_left > 64)
    return aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 2,
			  n_left - 64, f);
  return aes4_gcm_calc (T, kd, d4, ctr, inv, outv, rounds, 1, n_left, f);
#else
  u8x16 d[4];
  while (n_left >= 128)
    {
      T = aes_gcm_calc_double (T, kd, d, ctr, inv, outv, rounds, f);

      /* next */
      n_left -= 128;
      outv += 8;
      inv += 8;
    }

  if (n_left >= 64)
    {
      T = aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, 0, f);

      /* next */
      n_left -= 64;
      outv += 4;
      inv += 4;
    }

  if (n_left == 0)
    return T;

  f |= AES_GCM_F_LAST_ROUND;

  if (n_left > 48)
    return aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 4, n_left - 48, f);

  if (n_left > 32)
    return aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 3, n_left - 32, f);

  if (n_left > 16)
    return aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 2, n_left - 16, f);

  return aes_gcm_calc (T, kd, d, ctr, inv, outv, rounds, 1, n_left, f);
#endif
}

static_always_inline int
aes_gcm (u8x16u * in, u8x16u * out, u8x16u * addt, u8x16u * iv, u8x16u * tag,
	 u32 data_bytes, u32 aad_bytes, u8 tag_len, aes_gcm_key_data_t * kd,
	 int aes_rounds, int is_encrypt)
{
  int i;
  u8x16 r, T = { };
  u32x4 Y0;
  ghash_data_t _gd, *gd = &_gd;
  aes_gcm_counter_t _ctr, *ctr = &_ctr;

  clib_prefetch_load (iv);
  clib_prefetch_load (in);
  clib_prefetch_load (in + 4);

  /* calculate ghash for AAD - optimized for ipsec common cases */
  if (aad_bytes == 8)
    T = aes_gcm_ghash (T, kd, addt, 8);
  else if (aad_bytes == 12)
    T = aes_gcm_ghash (T, kd, addt, 12);
  else
    T = aes_gcm_ghash (T, kd, addt, aad_bytes);

  /* initalize counter */
  ctr->counter = 1;
  Y0 = (u32x4) aes_load_partial (iv, 12) + ctr_inv_1;
#ifdef __VAES__
  ctr->Y4 = u32x16_splat_u32x4 (Y0) + ctr_inv_1234;
#else
  ctr->Y = Y0 + ctr_inv_1;
#endif

  /* ghash and encrypt/edcrypt  */
  if (is_encrypt)
    T = aes_gcm_enc (T, kd, ctr, in, out, data_bytes, aes_rounds);
  else
    T = aes_gcm_dec (T, kd, ctr, in, out, data_bytes, aes_rounds);

  clib_prefetch_load (tag);

  /* Finalize ghash  - data bytes and aad bytes converted to bits */
  /* *INDENT-OFF* */
  r = (u8x16) ((u64x2) {data_bytes, aad_bytes} << 3);
  /* *INDENT-ON* */

  /* interleaved computation of final ghash and E(Y0, k) */
  ghash_mul_first (gd, r ^ T, kd->Hi[NUM_HI - 1]);
  r = kd->Ke[0] ^ (u8x16) Y0;
  for (i = 1; i < 5; i += 1)
    r = aes_enc_round (r, kd->Ke[i]);
  ghash_reduce (gd);
  ghash_reduce2 (gd);
  for (; i < 9; i += 1)
    r = aes_enc_round (r, kd->Ke[i]);
  T = ghash_final (gd);
  for (; i < aes_rounds; i += 1)
    r = aes_enc_round (r, kd->Ke[i]);
  r = aes_enc_last_round (r, kd->Ke[aes_rounds]);
  T = u8x16_reflect (T) ^ r;

  /* tag_len 16 -> 0 */
  tag_len &= 0xf;

  if (is_encrypt)
    {
      /* store tag */
      if (tag_len)
	aes_store_partial (tag, T, tag_len);
      else
	tag[0] = T;
    }
  else
    {
      /* check tag */
      u16 tag_mask = tag_len ? (1 << tag_len) - 1 : 0xffff;
      if ((u8x16_msb_mask (tag[0] == T) & tag_mask) != tag_mask)
	return 0;
    }
  return 1;
}

static_always_inline u32
aes_ops_enc_aes_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		     u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;


next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  aes_gcm ((u8x16u *) op->src, (u8x16u *) op->dst, (u8x16u *) op->aad,
	   (u8x16u *) op->iv, (u8x16u *) op->tag, op->len, op->aad_len,
	   op->tag_len, kd, AES_KEY_ROUNDS (ks), /* is_encrypt */ 1);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) cm->key_data[op->key_index];
  rv = aes_gcm ((u8x16u *) op->src, (u8x16u *) op->dst, (u8x16u *) op->aad,
		(u8x16u *) op->iv, (u8x16u *) op->tag, op->len,
		op->aad_len, op->tag_len, kd, AES_KEY_ROUNDS (ks),
		/* is_encrypt */ 0);

  if (rv)
    {
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  else
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      n_ops--;
    }

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void *
aes_gcm_key_exp (vnet_crypto_key_t * key, aes_key_size_t ks)
{
  aes_gcm_key_data_t *kd;
  u8x16 H;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  /* expand AES key */
  aes_key_expand ((u8x16 *) kd->Ke, key->data, ks);

  /* pre-calculate H */
  H = aes_encrypt_block (u8x16_splat (0), kd->Ke, ks);
  H = u8x16_reflect (H);
  ghash_precompute (H, (u8x16 *) kd->Hi, NUM_HI);
#ifdef __VAES__
  u8x64 *Ke4 = (u8x64 *) kd->Ke4;
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    Ke4[i] = u8x64_splat_u8x16 (kd->Ke[i]);
#endif
  return kd;
}

static int
crypto_native_frame_enqueue (vlib_main_t * vm,
			     vnet_crypto_async_frame_t * frame)
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd =
    vec_elt_at_index (cm->per_thread_data,
		      vm->thread_index);
  crypto_native_queue_t *q = ptd->queues[frame->op];
  u64 head = q->head;

  /* job is not taken from the queue if pointer is still set */
  if (q->jobs[head & CRYPTO_NATIVE_QUEUE_MASK])
    {
      u32 n_elts = frame->n_elts, i;
      for (i = 0; i < n_elts; i++)
	frame->elts[i].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
      return -1;
    }

  frame->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
  q->jobs[head & CRYPTO_NATIVE_QUEUE_MASK] = frame;
  head += 1;
  CLIB_MEMORY_STORE_BARRIER ();
  q->head = head;

  return 0;
}

static_always_inline vnet_crypto_async_frame_t *
crypto_native_get_pending_frame (crypto_native_queue_t * q)
{
  vnet_crypto_async_frame_t *f;
  u32 i;
  u32 tail = q->tail;
  u32 head = q->head;

  for (i = tail; i < head; i++)
    {
      f = q->jobs[i & CRYPTO_NATIVE_QUEUE_MASK];
      if (!f)
	continue;
      if (clib_atomic_bool_cmp_and_swap
	  (&f->state, VNET_CRYPTO_FRAME_STATE_PENDING,
	   VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS))
	{
	  return f;
	}
    }
  return NULL;
}

static_always_inline vnet_crypto_async_frame_t *
crypto_native_get_completed_frame (crypto_native_queue_t * q)
{
  vnet_crypto_async_frame_t *f = 0;
  if (q->jobs[q->tail & CRYPTO_NATIVE_QUEUE_MASK]
      && q->jobs[q->tail & CRYPTO_NATIVE_QUEUE_MASK]->state
      >= VNET_CRYPTO_FRAME_STATE_SUCCESS)
    {
      u32 tail = q->tail;
      CLIB_MEMORY_STORE_BARRIER ();
      q->tail++;
      f = q->jobs[tail & CRYPTO_NATIVE_QUEUE_MASK];
      q->jobs[tail & CRYPTO_NATIVE_QUEUE_MASK] = 0;
    }
  return f;
}

static vnet_crypto_async_frame_t *
crypto_native_frame_dequeue (vlib_main_t * vm, vnet_crypto_async_op_id_t opt,
			     aes_key_size_t ks, u8 tag_len, u8 aad_len,
			     u8 is_encrypt)
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd = 0;
  crypto_native_queue_t *q = 0;
  vnet_crypto_async_frame_t *f = 0;
  vnet_crypto_async_frame_elt_t *fe;
  aes_gcm_key_data_t *kd;
  int rv;
  u32 n_elts;
  u32 *bi;
  u8 state = VNET_CRYPTO_FRAME_STATE_SUCCESS;

  /* *INDENT-OFF* */
  vec_foreach (ptd, cm->per_thread_data)
    {
      q = ptd->queues[opt];
      f = crypto_native_get_pending_frame (q);
      if (f)
	break;
    }
  /* *INDENT-ON* */

  if (f)
    {
      n_elts = f->n_elts;
      bi = f->buffer_indices;
      fe = f->elts;

      while (n_elts)
	{
	  /* native engine doesn't support chaining buffers yet */
	  if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	    {
	      fe->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	      state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
	    }
	  else
	    {
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
	      u8x16u *src = (u8x16u *) (b->data + fe->crypto_start_offset);
	      kd = (aes_gcm_key_data_t *) cm->key_data[fe->key_index];

	      rv = aes_gcm (src, src, (u8x16u *) fe->aad, (u8x16u *) fe->iv,
			    (u8x16u *) fe->tag, fe->crypto_total_length,
			    aad_len, tag_len, kd, AES_KEY_ROUNDS (ks),
			    is_encrypt);

	      fe->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

	      if (PREDICT_FALSE (rv < 1))
		{
		  fe->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
		  state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
		}

	    }
	  bi++;
	  fe++;
	  n_elts--;
	}
      f->state = state;
    }

  return
    crypto_native_get_completed_frame (vec_elt_at_index
				       (cm->per_thread_data,
					vm->thread_index)->queues[opt]);
}


/* *INDENT-OFF* */
#define _(n, s, k, t, a) 							\
static vnet_crypto_async_frame_t* 						\
crypto_native_frame_dequeue_GCM_##n##_TAG_##t##_AAD_##a##_enc			\
(vlib_main_t *vm)								\
{ return crypto_native_frame_dequeue(vm,					\
    VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC, AES_ASYNC_KEY_##k, t, a, 1); }	\
static vnet_crypto_async_frame_t* 						\
crypto_native_frame_dequeue_GCM_##n##_TAG_##t##_AAD_##a##_dec			\
(vlib_main_t *vm)								\
{ return crypto_native_frame_dequeue(vm, 					\
    VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC, AES_ASYNC_KEY_##k, t, a, 0); }
foreach_crypto_aead_async_alg
#undef _

#define foreach_aes_gcm_handler_type _(128) _(192) _(256)
#define _(x) \
static u32 aes_ops_dec_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)                      \
{ return aes_ops_dec_aes_gcm (vm, ops, n_ops, AES_KEY_##x); }              \
static u32 aes_ops_enc_aes_gcm_##x                                         \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)                      \
{ return aes_ops_enc_aes_gcm (vm, ops, n_ops, AES_KEY_##x); }              \
static void * aes_gcm_key_exp_##x (vnet_crypto_key_t *key)                 \
{ return aes_gcm_key_exp (key, AES_KEY_##x); }

foreach_aes_gcm_handler_type;
#undef _
/* *INDENT-ON* */

clib_error_t *
#ifdef __VAES__
crypto_native_aes_gcm_init_icl (vlib_main_t * vm)
#elif __AVX512F__
crypto_native_aes_gcm_init_skx (vlib_main_t * vm)
#elif __AVX2__
crypto_native_aes_gcm_init_hsw (vlib_main_t * vm)
#elif __aarch64__
crypto_native_aes_gcm_init_neon (vlib_main_t * vm)
#else
crypto_native_aes_gcm_init_slm (vlib_main_t * vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd;

  u32 queue_size = CRYPTO_NATIVE_QUEUE_SIZE * sizeof (void *)
    + sizeof (crypto_native_queue_t);


#define _(x) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_GCM_ENC, \
				    aes_ops_enc_aes_gcm_##x); \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_GCM_DEC, \
				    aes_ops_dec_aes_gcm_##x); \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_GCM] = aes_gcm_key_exp_##x;
  foreach_aes_gcm_handler_type;
#undef _

#define _(n, s, k, t, a) 										\
  vnet_crypto_register_async_handler (vm, cm->crypto_engine_index,					\
				      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,			\
				      crypto_native_frame_enqueue,					\
				      crypto_native_frame_dequeue_GCM_##n##_TAG_##t##_AAD_##a##_enc);	\
  vnet_crypto_register_async_handler (vm, cm->crypto_engine_index,					\
				      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,			\
				      crypto_native_frame_enqueue,					\
				      crypto_native_frame_dequeue_GCM_##n##_TAG_##t##_AAD_##a##_dec);
  foreach_crypto_aead_async_alg
#undef _
    vec_foreach (ptd, cm->per_thread_data)
  {
    u32 i;
    for (i = 0; i < VNET_CRYPTO_ASYNC_OP_N_IDS; i++)
      {
	crypto_native_queue_t *q = clib_mem_alloc_aligned (queue_size,
							   CLIB_CACHE_LINE_BYTES);
	ASSERT (q != 0);
	ptd->queues[i] = q;
	clib_memset_u8 (q, 0, queue_size);
      }
  }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
