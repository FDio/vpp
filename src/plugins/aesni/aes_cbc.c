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

#pragma GCC target("aes,sse4.2")

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <x86intrin.h>
#include <aesni/aesni.h>

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
aes_key_enc_to_dec (__m128i * k, int rounds)
{
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

static_always_inline void
aes_cbc_enc (__m128i * k, u8 * src, u8 * dst, u8 * iv, int count, int rounds)
{
  __m128i r = _mm_loadu_si128 ((__m128i *) iv);
  while (count > 0)
    {
      int i;
      r ^= _mm_loadu_si128 ((__m128i *) src) ^ k[0];
      for (i = 1; i < rounds; i++)
	r = _mm_aesenc_si128 (r, k[i]);
      r = _mm_aesenclast_si128 (r, k[i]);
      _mm_storeu_si128 ((__m128i *) dst, r);
      count -= 16;
      src += 16;
      dst += 16;
    }
}

static_always_inline void
aes_cbc_dec (__m128i * k, u8 * src, u8 * dst, u8 * iv, int count, int rounds)
{
  __m128i r, l, f;
  f = _mm_loadu_si128 ((__m128i *) iv);

  while (count > 0)
    {
      int i;
      r = l = _mm_loadu_si128 (((__m128i *) src));
      r ^= k[0];
      for (i = 1; i < rounds; i++)
	r = _mm_aesdec_si128 (r, k[i]);
      r = _mm_aesdeclast_si128 (r, k[i]);
      _mm_storeu_si128 ((__m128i *) dst, r ^ f);
      f = l;
      count -= 16;
      src += 16;
      dst += 16;
    }
}

u32
aesni_enc_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  if ((vnet_crypto_dequeue_one_job (q)))
    {
      clib_warning ("got one on thread %u", vm->thread_index);
      return 1;
    }

#if 0
  __m128i k[11];

  while (n_jobs)
    {
      vnet_crypto_job_t *j = *jobs;

      ASSERT (j->alg == VNET_CRYPTO_ALG_AES_128_CBC);
      ASSERT (j->op == VNET_CRYPTO_OP_ENCRYPT);
      aes128_key_expand (k, j->key);
      aes_cbc_enc (k, j->src, j->dst, j->iv, j->len, 10);
      jobs++;
      n_jobs--;
    }
#endif
  return 0;
}

u32
aesni_dec_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  if ((vnet_crypto_dequeue_one_job (q)))
    {
      clib_warning ("got one on thread %u", vm->thread_index);
      return 1;
    }

#if 0
  __m128i k[11];
  while (n_jobs)
    {
      vnet_crypto_job_t *j = *jobs;

      ASSERT (j->alg == VNET_CRYPTO_ALG_AES_128_CBC);
      ASSERT (j->op == VNET_CRYPTO_OP_DECRYPT);
      aes128_key_expand (k, j->key);
      aes_key_enc_to_dec (k, 10);
      aes_cbc_dec (k, j->src, j->dst, j->iv, j->len, 10);
      jobs++;
      n_jobs--;
    }
#endif
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
