/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __aes_h__
#define __aes_h__

typedef enum
{
  AES_KEY_128 = 0,
  AES_KEY_192 = 1,
  AES_KEY_256 = 2,
} aes_key_size_t;

#define AES_KEY_ROUNDS(x)		(10 + x * 2)
#define AES_KEY_BYTES(x)		(16 + x * 8)

static_always_inline u8x16
aes_block_load (u8 * p)
{
  return *(u8x16u *) p;
}

static_always_inline u8x16
aes_enc_round_x1 (u8x16 a, u8x16 k)
{
#if defined (__AES__)
  return (u8x16) _mm_aesenc_si128 ((__m128i) a, (__m128i) k);
#elif defined (__ARM_FEATURE_CRYPTO)
  return vaesmcq_u8 (vaeseq_u8 (a, u8x16_splat (0))) ^ k;
#endif
}

#if defined(__VAES__) && defined(__AVX512F__)
static_always_inline u8x64
aes_enc_round_x4 (u8x64 a, u8x64 k)
{
  return (u8x64) _mm512_aesenc_epi128 ((__m512i) a, (__m512i) k);
}

static_always_inline u8x64
aes_enc_last_round_x4 (u8x64 a, u8x64 k)
{
  return (u8x64) _mm512_aesenclast_epi128 ((__m512i) a, (__m512i) k);
}

static_always_inline u8x64
aes_dec_round_x4 (u8x64 a, u8x64 k)
{
  return (u8x64) _mm512_aesdec_epi128 ((__m512i) a, (__m512i) k);
}

static_always_inline u8x64
aes_dec_last_round_x4 (u8x64 a, u8x64 k)
{
  return (u8x64) _mm512_aesdeclast_epi128 ((__m512i) a, (__m512i) k);
}
#endif

#ifdef __VAES__
static_always_inline u8x32
aes_enc_round_x2 (u8x32 a, u8x32 k)
{
  return (u8x32) _mm256_aesenc_epi128 ((__m256i) a, (__m256i) k);
}

static_always_inline u8x32
aes_enc_last_round_x2 (u8x32 a, u8x32 k)
{
  return (u8x32) _mm256_aesenclast_epi128 ((__m256i) a, (__m256i) k);
}

static_always_inline u8x32
aes_dec_round_x2 (u8x32 a, u8x32 k)
{
  return (u8x32) _mm256_aesdec_epi128 ((__m256i) a, (__m256i) k);
}

static_always_inline u8x32
aes_dec_last_round_x2 (u8x32 a, u8x32 k)
{
  return (u8x32) _mm256_aesdeclast_epi128 ((__m256i) a, (__m256i) k);
}
#endif

static_always_inline u8x16
aes_enc_last_round_x1 (u8x16 a, u8x16 k)
{
#if defined (__AES__)
  return (u8x16) _mm_aesenclast_si128 ((__m128i) a, (__m128i) k);
#elif defined (__ARM_FEATURE_CRYPTO)
  return vaeseq_u8 (a, u8x16_splat (0)) ^ k;
#endif
}

#ifdef __x86_64__

static_always_inline u8x16
aes_dec_round_x1 (u8x16 a, u8x16 k)
{
  return (u8x16) _mm_aesdec_si128 ((__m128i) a, (__m128i) k);
}

static_always_inline u8x16
aes_dec_last_round_x1 (u8x16 a, u8x16 k)
{
  return (u8x16) _mm_aesdeclast_si128 ((__m128i) a, (__m128i) k);
}
#endif

static_always_inline void
aes_block_store (u8 * p, u8x16 r)
{
  *(u8x16u *) p = r;
}

static_always_inline u8x16
aes_encrypt_block (u8x16 block, const u8x16 * round_keys, aes_key_size_t ks)
{
  int rounds = AES_KEY_ROUNDS (ks);
  block ^= round_keys[0];
  for (int i = 1; i < rounds; i += 1)
    block = aes_enc_round_x1 (block, round_keys[i]);
  return aes_enc_last_round_x1 (block, round_keys[rounds]);
}

static_always_inline u8x16
aes_inv_mix_column (u8x16 a)
{
#if defined (__AES__)
  return (u8x16) _mm_aesimc_si128 ((__m128i) a);
#elif defined (__ARM_FEATURE_CRYPTO)
  return vaesimcq_u8 (a);
#endif
}

#ifdef __x86_64__
#define aes_keygen_assist(a, b) \
  (u8x16) _mm_aeskeygenassist_si128((__m128i) a, b)

/* AES-NI based AES key expansion based on code samples from
   Intel(r) Advanced Encryption Standard (AES) New Instructions White Paper
   (323641-001) */

static_always_inline void
aes128_key_assist (u8x16 * rk, u8x16 r)
{
  u8x16 t = rk[-1];
  t ^= u8x16_word_shift_left (t, 4);
  t ^= u8x16_word_shift_left (t, 4);
  t ^= u8x16_word_shift_left (t, 4);
  rk[0] = t ^ (u8x16) u32x4_shuffle ((u32x4) r, 3, 3, 3, 3);
}

static_always_inline void
aes128_key_expand (u8x16 *rk, u8x16u const *k)
{
  rk[0] = k[0];
  aes128_key_assist (rk + 1, aes_keygen_assist (rk[0], 0x01));
  aes128_key_assist (rk + 2, aes_keygen_assist (rk[1], 0x02));
  aes128_key_assist (rk + 3, aes_keygen_assist (rk[2], 0x04));
  aes128_key_assist (rk + 4, aes_keygen_assist (rk[3], 0x08));
  aes128_key_assist (rk + 5, aes_keygen_assist (rk[4], 0x10));
  aes128_key_assist (rk + 6, aes_keygen_assist (rk[5], 0x20));
  aes128_key_assist (rk + 7, aes_keygen_assist (rk[6], 0x40));
  aes128_key_assist (rk + 8, aes_keygen_assist (rk[7], 0x80));
  aes128_key_assist (rk + 9, aes_keygen_assist (rk[8], 0x1b));
  aes128_key_assist (rk + 10, aes_keygen_assist (rk[9], 0x36));
}

static_always_inline void
aes192_key_assist (u8x16 * r1, u8x16 * r2, u8x16 key_assist)
{
  u8x16 t;
  r1[0] ^= t = u8x16_word_shift_left (r1[0], 4);
  r1[0] ^= t = u8x16_word_shift_left (t, 4);
  r1[0] ^= u8x16_word_shift_left (t, 4);
  r1[0] ^= (u8x16) _mm_shuffle_epi32 ((__m128i) key_assist, 0x55);
  r2[0] ^= u8x16_word_shift_left (r2[0], 4);
  r2[0] ^= (u8x16) _mm_shuffle_epi32 ((__m128i) r1[0], 0xff);
}

static_always_inline void
aes192_key_expand (u8x16 * rk, u8x16u const *k)
{
  u8x16 r1, r2;

  rk[0] = r1 = k[0];
  rk[1] = r2 = (u8x16) (u64x2) { *(u64 *) (k + 1), 0 };

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x1));
  rk[1] = (u8x16) _mm_shuffle_pd ((__m128d) rk[1], (__m128d) r1, 0);
  rk[2] = (u8x16) _mm_shuffle_pd ((__m128d) r1, (__m128d) r2, 1);

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x2));
  rk[3] = r1;
  rk[4] = r2;

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x4));
  rk[4] = (u8x16) _mm_shuffle_pd ((__m128d) rk[4], (__m128d) r1, 0);
  rk[5] = (u8x16) _mm_shuffle_pd ((__m128d) r1, (__m128d) r2, 1);

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x8));
  rk[6] = r1;
  rk[7] = r2;

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x10));
  rk[7] = (u8x16) _mm_shuffle_pd ((__m128d) rk[7], (__m128d) r1, 0);
  rk[8] = (u8x16) _mm_shuffle_pd ((__m128d) r1, (__m128d) r2, 1);

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x20));
  rk[9] = r1;
  rk[10] = r2;

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x40));
  rk[10] = (u8x16) _mm_shuffle_pd ((__m128d) rk[10], (__m128d) r1, 0);
  rk[11] = (u8x16) _mm_shuffle_pd ((__m128d) r1, (__m128d) r2, 1);

  aes192_key_assist (&r1, &r2, aes_keygen_assist (r2, 0x80));
  rk[12] = r1;
}

static_always_inline void
aes256_key_assist (u8x16 * rk, int i, u8x16 key_assist)
{
  u8x16 r, t;
  rk += i;
  r = rk[-2];
  r ^= t = u8x16_word_shift_left (r, 4);
  r ^= t = u8x16_word_shift_left (t, 4);
  r ^= u8x16_word_shift_left (t, 4);
  r ^= (u8x16) u32x4_shuffle ((u32x4) key_assist, 3, 3, 3, 3);
  rk[0] = r;

  if (i >= 14)
    return;

  key_assist = aes_keygen_assist (rk[0], 0x0);
  r = rk[-1];
  r ^= t = u8x16_word_shift_left (r, 4);
  r ^= t = u8x16_word_shift_left (t, 4);
  r ^= u8x16_word_shift_left (t, 4);
  r ^= (u8x16) u32x4_shuffle ((u32x4) key_assist, 2, 2, 2, 2);
  rk[1] = r;
}

static_always_inline void
aes256_key_expand (u8x16 * rk, u8x16u const *k)
{
  rk[0] = k[0];
  rk[1] = k[1];
  aes256_key_assist (rk, 2, aes_keygen_assist (rk[1], 0x01));
  aes256_key_assist (rk, 4, aes_keygen_assist (rk[3], 0x02));
  aes256_key_assist (rk, 6, aes_keygen_assist (rk[5], 0x04));
  aes256_key_assist (rk, 8, aes_keygen_assist (rk[7], 0x08));
  aes256_key_assist (rk, 10, aes_keygen_assist (rk[9], 0x10));
  aes256_key_assist (rk, 12, aes_keygen_assist (rk[11], 0x20));
  aes256_key_assist (rk, 14, aes_keygen_assist (rk[13], 0x40));
}
#endif

#ifdef __aarch64__

static const u8x16 aese_prep_mask1 =
  { 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12 };
static const u8x16 aese_prep_mask2 =
  { 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15 };

static_always_inline void
aes128_key_expand_round_neon (u8x16 * rk, u32 rcon)
{
  u8x16 r, t, last_round = rk[-1], z = { };
  r = vqtbl1q_u8 (last_round, aese_prep_mask1);
  r = vaeseq_u8 (r, z);
  r ^= (u8x16) vdupq_n_u32 (rcon);
  r ^= last_round;
  r ^= t = vextq_u8 (z, last_round, 12);
  r ^= t = vextq_u8 (z, t, 12);
  r ^= vextq_u8 (z, t, 12);
  rk[0] = r;
}

static_always_inline void
aes128_key_expand (u8x16 *rk, u8x16u const *k)
{
  rk[0] = k[0];
  aes128_key_expand_round_neon (rk + 1, 0x01);
  aes128_key_expand_round_neon (rk + 2, 0x02);
  aes128_key_expand_round_neon (rk + 3, 0x04);
  aes128_key_expand_round_neon (rk + 4, 0x08);
  aes128_key_expand_round_neon (rk + 5, 0x10);
  aes128_key_expand_round_neon (rk + 6, 0x20);
  aes128_key_expand_round_neon (rk + 7, 0x40);
  aes128_key_expand_round_neon (rk + 8, 0x80);
  aes128_key_expand_round_neon (rk + 9, 0x1b);
  aes128_key_expand_round_neon (rk + 10, 0x36);
}

static_always_inline void
aes192_key_expand_round_neon (u8x8 * rk, u32 rcon)
{
  u8x8 r, last_round = rk[-1], z = { };
  u8x16 r2, z2 = { };

  r2 = (u8x16) vdupq_lane_u64 ((uint64x1_t) last_round, 0);
  r2 = vqtbl1q_u8 (r2, aese_prep_mask1);
  r2 = vaeseq_u8 (r2, z2);
  r2 ^= (u8x16) vdupq_n_u32 (rcon);

  r = (u8x8) vdup_laneq_u64 ((u64x2) r2, 0);
  r ^= rk[-3];
  r ^= vext_u8 (z, rk[-3], 4);
  rk[0] = r;

  r = rk[-2] ^ vext_u8 (r, z, 4);
  r ^= vext_u8 (z, r, 4);
  rk[1] = r;

  if (rcon == 0x80)
    return;

  r = rk[-1] ^ vext_u8 (r, z, 4);
  r ^= vext_u8 (z, r, 4);
  rk[2] = r;
}

static_always_inline void
aes192_key_expand (u8x16 * ek, const u8x16u * k)
{
  u8x8 *rk = (u8x8 *) ek;
  ek[0] = k[0];
  rk[2] = *(u8x8u *) (k + 1);
  aes192_key_expand_round_neon (rk + 3, 0x01);
  aes192_key_expand_round_neon (rk + 6, 0x02);
  aes192_key_expand_round_neon (rk + 9, 0x04);
  aes192_key_expand_round_neon (rk + 12, 0x08);
  aes192_key_expand_round_neon (rk + 15, 0x10);
  aes192_key_expand_round_neon (rk + 18, 0x20);
  aes192_key_expand_round_neon (rk + 21, 0x40);
  aes192_key_expand_round_neon (rk + 24, 0x80);
}


static_always_inline void
aes256_key_expand_round_neon (u8x16 * rk, u32 rcon)
{
  u8x16 r, t, z = { };

  r = vqtbl1q_u8 (rk[-1], rcon ? aese_prep_mask1 : aese_prep_mask2);
  r = vaeseq_u8 (r, z);
  if (rcon)
    r ^= (u8x16) vdupq_n_u32 (rcon);
  r ^= rk[-2];
  r ^= t = vextq_u8 (z, rk[-2], 12);
  r ^= t = vextq_u8 (z, t, 12);
  r ^= vextq_u8 (z, t, 12);
  rk[0] = r;
}

static_always_inline void
aes256_key_expand (u8x16 *rk, u8x16u const *k)
{
  rk[0] = k[0];
  rk[1] = k[1];
  aes256_key_expand_round_neon (rk + 2, 0x01);
  aes256_key_expand_round_neon (rk + 3, 0);
  aes256_key_expand_round_neon (rk + 4, 0x02);
  aes256_key_expand_round_neon (rk + 5, 0);
  aes256_key_expand_round_neon (rk + 6, 0x04);
  aes256_key_expand_round_neon (rk + 7, 0);
  aes256_key_expand_round_neon (rk + 8, 0x08);
  aes256_key_expand_round_neon (rk + 9, 0);
  aes256_key_expand_round_neon (rk + 10, 0x10);
  aes256_key_expand_round_neon (rk + 11, 0);
  aes256_key_expand_round_neon (rk + 12, 0x20);
  aes256_key_expand_round_neon (rk + 13, 0);
  aes256_key_expand_round_neon (rk + 14, 0x40);
}

#endif

static_always_inline void
aes_key_expand (u8x16 * key_schedule, u8 const *key, aes_key_size_t ks)
{
  switch (ks)
    {
    case AES_KEY_128:
      aes128_key_expand (key_schedule, (u8x16u const *) key);
      break;
    case AES_KEY_192:
      aes192_key_expand (key_schedule, (u8x16u const *) key);
      break;
    case AES_KEY_256:
      aes256_key_expand (key_schedule, (u8x16u const *) key);
      break;
    }
}

static_always_inline void
aes_key_enc_to_dec (u8x16 * ke, u8x16 * kd, aes_key_size_t ks)
{
  int rounds = AES_KEY_ROUNDS (ks);

  kd[rounds] = ke[0];
  kd[0] = ke[rounds];

  for (int i = 1; i < (rounds / 2); i++)
    {
      kd[rounds - i] = aes_inv_mix_column (ke[i]);
      kd[i] = aes_inv_mix_column (ke[rounds - i]);
    }

  kd[rounds / 2] = aes_inv_mix_column (ke[rounds / 2]);
}
#if defined(__VAES__) && defined(__AVX512F__)
#define N_AES_LANES		   4
#define aes_load_partial(p, n)	   u8x64_load_partial ((u8 *) (p), n)
#define aes_store_partial(v, p, n) u8x64_store_partial (v, (u8 *) (p), n)
#define aes_reflect(r)		   u8x64_reflect_u8x16 (r)
typedef u8x64 aes_data_t;
typedef u8x64u aes_mem_t;
typedef u32x16 aes_counter_t;
#elif defined(__VAES__)
#define N_AES_LANES		   2
#define aes_load_partial(p, n)	   u8x32_load_partial ((u8 *) (p), n)
#define aes_store_partial(v, p, n) u8x32_store_partial (v, (u8 *) (p), n)
#define aes_reflect(r)		   u8x32_reflect_u8x16 (r)
typedef u8x32 aes_data_t;
typedef u8x32u aes_mem_t;
typedef u32x8 aes_counter_t;
#else
#define N_AES_LANES		   1
#define aes_load_partial(p, n)	   u8x16_load_partial ((u8 *) (p), n)
#define aes_store_partial(v, p, n) u8x16_store_partial (v, (u8 *) (p), n)
#define aes_reflect(r)		   u8x16_reflect (r)
typedef u8x16 aes_data_t;
typedef u8x16u aes_mem_t;
typedef u32x4 aes_counter_t;
#endif

#define N_AES_BYTES (N_AES_LANES * 16)

typedef union
{
  u8x16 x1;
  u8x32 x2;
  u8x64 x4;
  u8x16 lanes[4];
} aes_expaned_key_t;

static_always_inline void
aes_enc_round (aes_data_t *r, const aes_expaned_key_t *ek, uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N_AES_LANES == 4
    r[i] = aes_enc_round_x4 (r[i], ek->x4);
#elif N_AES_LANES == 2
    r[i] = aes_enc_round_x2 (r[i], ek->x2);
#else
    r[i] = aes_enc_round_x1 (r[i], ek->x1);
#endif
}

static_always_inline void
aes_enc_last_round (aes_data_t *r, aes_data_t *d, const aes_expaned_key_t *ek,
		    uword n_blocks)
{
  for (int i = 0; i < n_blocks; i++)
#if N_AES_LANES == 4
    d[i] ^= r[i] = aes_enc_last_round_x4 (r[i], ek->x4);
#elif N_AES_LANES == 2
    d[i] ^= r[i] = aes_enc_last_round_x2 (r[i], ek->x2);
#else
    d[i] ^= r[i] = aes_enc_last_round_x1 (r[i], ek->x1);
#endif
}

#endif /* __aes_h__ */
