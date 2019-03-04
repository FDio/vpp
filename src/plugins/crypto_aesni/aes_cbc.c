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
#include <crypto_aesni/crypto_aesni.h>

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
aes_key_expand (__m128i * k, u8 * key, int rounds)
{
  switch (rounds)
    {
    case 10:
      aes128_key_expand (k, key);
      break;
    case 12:
      aes192_key_expand (k, key);
      break;
    case 14:
      aes256_key_expand (k, key);
      break;
    }
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

static_always_inline u32
aesni_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, int rounds)
{
  u32 i;
  __m128i k[rounds + 1];
  vnet_crypto_key_t *key;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      key = vnet_crypto_get_key (op->key_index);
      aes_key_expand (k, key->data, rounds);
      aes_cbc_enc (k, op->src, op->dst, op->iv, op->len, rounds);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
aesni_ops_dec_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, int rounds)
{
  u32 i;
  __m128i k[rounds + 1];
  vnet_crypto_key_t *key;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      key = vnet_crypto_get_key (op->key_index);
      aes_key_expand (k, key->data, rounds);
      aes_key_enc_to_dec (k, rounds);
      aes_cbc_dec (k, op->src, op->dst, op->iv, op->len, rounds);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

u32
aesni_ops_enc_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_enc_aes_cbc (vm, ops, n_ops, 10);
}

u32
aesni_ops_enc_aes_cbc_192 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_enc_aes_cbc (vm, ops, n_ops, 12);
}

u32
aesni_ops_enc_aes_cbc_256 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_enc_aes_cbc (vm, ops, n_ops, 14);
}

u32
aesni_ops_dec_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_dec_aes_cbc (vm, ops, n_ops, 10);
}

u32
aesni_ops_dec_aes_cbc_192 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_dec_aes_cbc (vm, ops, n_ops, 12);
}

u32
aesni_ops_dec_aes_cbc_256 (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			   u32 n_ops)
{
  return aesni_ops_dec_aes_cbc (vm, ops, n_ops, 14);
}

vnet_async_crypto_op_t *
aesni_queue_enc_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  vnet_async_crypto_op_t * aj, *j;
  if ((aj = vnet_crypto_dequeue_one_job (q)))
    {
      __m128i k[11];

      j = aj;
      while (j)
        {
          vnet_crypto_op_t *sj = &j->data;

          ASSERT (sj->op == VNET_CRYPTO_OP_AES_128_CBC_ENC);
          vnet_crypto_key_t *key = vnet_crypto_get_key(sj->key_index);
          aes128_key_expand (k, key->data);
          aes_cbc_enc (k, sj->src, sj->dst, sj->iv, sj->len, 10);
          sj->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
          j = j->next;
        }
      return aj;
    }

  return 0;
}

vnet_async_crypto_op_t *
aesni_queue_dec_aes_cbc_128 (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  vnet_async_crypto_op_t *j;
  if ((j = vnet_crypto_dequeue_one_job (q)))
    {
      clib_warning ("got one on thread %u", vm->thread_index);
      return j;
    }

#if 0
  __m128i k[11];
  while (n_jobs)
    {
      vnet_crypto_op_t *j = *jobs;

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
