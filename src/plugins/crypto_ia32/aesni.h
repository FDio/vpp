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

#ifndef __aesni_h__
#define __aesni_h__


typedef struct
{
  __m128i encrypt_key[15];
  __m128i decrypt_key[15];
} aesni_key_data_t;

typedef enum
{
  AESNI_KEY_128 = 0,
  AESNI_KEY_192 = 1,
  AESNI_KEY_256 = 2,
} aesni_key_size_t;

#define AESNI_KEY_ROUNDS(x)		(10 + x *2)
#define AESNI_KEY_BYTES(x)		(16 + x * 8)


/* AES-NI based AES key expansion based on code samples from
   Intel(r) Advanced Encryption Standard (AES) New Instructions White Paper
   (323641-001) */

static_always_inline __m128i
aes128_key_assist (__m128i r1, __m128i r2)
{
  r1 ^= _mm_slli_si128 (r1, 4);
  r1 ^= _mm_slli_si128 (r1, 4);
  r1 ^= _mm_slli_si128 (r1, 4);
  return r1 ^ _mm_shuffle_epi32 (r2, 0xff);
}

static_always_inline void
aes128_key_expand (__m128i * k, u8 * key)
{
  k[0] = _mm_loadu_si128 ((const __m128i *) key);
  k[1] = aes128_key_assist (k[0], _mm_aeskeygenassist_si128 (k[0], 0x01));
  k[2] = aes128_key_assist (k[1], _mm_aeskeygenassist_si128 (k[1], 0x02));
  k[3] = aes128_key_assist (k[2], _mm_aeskeygenassist_si128 (k[2], 0x04));
  k[4] = aes128_key_assist (k[3], _mm_aeskeygenassist_si128 (k[3], 0x08));
  k[5] = aes128_key_assist (k[4], _mm_aeskeygenassist_si128 (k[4], 0x10));
  k[6] = aes128_key_assist (k[5], _mm_aeskeygenassist_si128 (k[5], 0x20));
  k[7] = aes128_key_assist (k[6], _mm_aeskeygenassist_si128 (k[6], 0x40));
  k[8] = aes128_key_assist (k[7], _mm_aeskeygenassist_si128 (k[7], 0x80));
  k[9] = aes128_key_assist (k[8], _mm_aeskeygenassist_si128 (k[8], 0x1b));
  k[10] = aes128_key_assist (k[9], _mm_aeskeygenassist_si128 (k[9], 0x36));
}

static_always_inline void
aes192_key_assist (__m128i * r1, __m128i * r2, __m128i * r3)
{
  __m128i r;
  *r1 ^= r = _mm_slli_si128 (*r1, 0x4);
  *r1 ^= r = _mm_slli_si128 (r, 0x4);
  *r1 ^= _mm_slli_si128 (r, 0x4);
  *r1 ^= _mm_shuffle_epi32 (*r2, 0x55);
  *r3 ^= _mm_slli_si128 (*r3, 0x4);
  *r3 ^= *r2 = _mm_shuffle_epi32 (*r1, 0xff);
}

static_always_inline void
aes192_key_expand (__m128i * k, u8 * key)
{
  __m128i r1, r2, r3;

  k[0] = r1 = _mm_loadu_si128 ((__m128i *) key);
  r3 = _mm_loadu_si128 ((__m128i *) (key + 16));

  k[1] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x1);
  aes192_key_assist (&r1, &r2, &r3);
  k[1] = (__m128i) _mm_shuffle_pd ((__m128d) k[1], (__m128d) r1, 0);
  k[2] = (__m128i) _mm_shuffle_pd ((__m128d) r1, (__m128d) r3, 1);
  r2 = _mm_aeskeygenassist_si128 (r3, 0x2);
  aes192_key_assist (&r1, &r2, &r3);
  k[3] = r1;

  k[4] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x4);
  aes192_key_assist (&r1, &r2, &r3);
  k[4] = (__m128i) _mm_shuffle_pd ((__m128d) k[4], (__m128d) r1, 0);
  k[5] = (__m128i) _mm_shuffle_pd ((__m128d) r1, (__m128d) r3, 1);
  r2 = _mm_aeskeygenassist_si128 (r3, 0x8);
  aes192_key_assist (&r1, &r2, &r3);
  k[6] = r1;

  k[7] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x10);
  aes192_key_assist (&r1, &r2, &r3);
  k[7] = (__m128i) _mm_shuffle_pd ((__m128d) k[7], (__m128d) r1, 0);
  k[8] = (__m128i) _mm_shuffle_pd ((__m128d) r1, (__m128d) r3, 1);
  r2 = _mm_aeskeygenassist_si128 (r3, 0x20);
  aes192_key_assist (&r1, &r2, &r3);
  k[9] = r1;

  k[10] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x40);
  aes192_key_assist (&r1, &r2, &r3);
  k[10] = (__m128i) _mm_shuffle_pd ((__m128d) k[10], (__m128d) r1, 0);
  k[11] = (__m128i) _mm_shuffle_pd ((__m128d) r1, (__m128d) r3, 1);
  r2 = _mm_aeskeygenassist_si128 (r3, 0x80);
  aes192_key_assist (&r1, &r2, &r3);
  k[12] = r1;
}

static_always_inline void
aes256_key_assist1 (__m128i * r1, __m128i * r2)
{
  __m128i r;
  *r1 ^= r = _mm_slli_si128 (*r1, 0x4);
  *r1 ^= r = _mm_slli_si128 (r, 0x4);
  *r1 ^= _mm_slli_si128 (r, 0x4);
  *r1 ^= *r2 = _mm_shuffle_epi32 (*r2, 0xff);
}

static_always_inline void
aes256_key_assist2 (__m128i r1, __m128i * r3)
{
  __m128i r;
  *r3 ^= r = _mm_slli_si128 (*r3, 0x4);
  *r3 ^= r = _mm_slli_si128 (r, 0x4);
  *r3 ^= _mm_slli_si128 (r, 0x4);
  *r3 ^= _mm_shuffle_epi32 (_mm_aeskeygenassist_si128 (r1, 0x0), 0xaa);
}

static_always_inline void
aes256_key_expand (__m128i * k, u8 * key)
{
  __m128i r1, r2, r3;
  k[0] = r1 = _mm_loadu_si128 ((__m128i *) key);
  k[1] = r3 = _mm_loadu_si128 ((__m128i *) (key + 16));
  r2 = _mm_aeskeygenassist_si128 (k[1], 0x01);
  aes256_key_assist1 (&r1, &r2);
  k[2] = r1;
  aes256_key_assist2 (r1, &r3);
  k[3] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x02);
  aes256_key_assist1 (&r1, &r2);
  k[4] = r1;
  aes256_key_assist2 (r1, &r3);
  k[5] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x04);
  aes256_key_assist1 (&r1, &r2);
  k[6] = r1;
  aes256_key_assist2 (r1, &r3);
  k[7] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x08);
  aes256_key_assist1 (&r1, &r2);
  k[8] = r1;
  aes256_key_assist2 (r1, &r3);
  k[9] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x10);
  aes256_key_assist1 (&r1, &r2);
  k[10] = r1;
  aes256_key_assist2 (r1, &r3);
  k[11] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x20);
  aes256_key_assist1 (&r1, &r2);
  k[12] = r1;
  aes256_key_assist2 (r1, &r3);
  k[13] = r3;
  r2 = _mm_aeskeygenassist_si128 (r3, 0x40);
  aes256_key_assist1 (&r1, &r2);
  k[14] = r1;
}

static_always_inline void
aes_key_expand (__m128i * k, u8 * key, aesni_key_size_t ks)
{
  switch (ks)
    {
    case AESNI_KEY_128:
      aes128_key_expand (k, key);
      break;
    case AESNI_KEY_192:
      aes192_key_expand (k, key);
      break;
    case AESNI_KEY_256:
      aes256_key_expand (k, key);
      break;
    }
}


static_always_inline void
aes_key_enc_to_dec (__m128i * k, aesni_key_size_t ks)
{
  int rounds = AESNI_KEY_ROUNDS (ks);
  __m128i r;

  r = k[rounds];
  k[rounds] = k[0];
  k[0] = r;

  for (int i = 1; i < (rounds / 2); i++)
    {
      r = k[rounds - i];
      k[rounds - i] = _mm_aesimc_si128 (k[i]);
      k[i] = _mm_aesimc_si128 (r);
    }

  k[rounds / 2] = _mm_aesimc_si128 (k[rounds / 2]);
}

#endif /* __aesni_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
