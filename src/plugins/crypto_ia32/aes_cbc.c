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
#include <x86intrin.h>
#include <crypto_ia32/crypto_ia32.h>
#include <crypto_ia32/aesni.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct
{
#if __VAES__
  __m128i encrypt_key[15];
  __m512i decrypt_key4[15];
#else
  __m128i encrypt_key[15];
  __m128i decrypt_key[15];
#endif
} aes_cbc_key_data_t;

static_always_inline __m128i
aes_block_load (u8 * p)
{
  return _mm_loadu_si128 ((__m128i *) p);
}

static_always_inline void
aes_block_store (u8 * p, __m128i r)
{
  _mm_store_si128 ((__m128i *) p, r);
}

static_always_inline void __clib_unused
aes_cbc_dec (__m128i * k, u8 * src, u8 * dst, u8 * iv, int count,
	     aesni_key_size_t rounds)
{
  __m128i r0, r1, r2, r3, c0, c1, c2, c3, f;
  int i;

  f = aes_block_load (iv);

  while (count >= 64)
    {
      _mm_prefetch (src + 128, _MM_HINT_T0);
      _mm_prefetch (dst + 128, _MM_HINT_T0);

      c0 = aes_block_load (src);
      c1 = aes_block_load (src + 16);
      c2 = aes_block_load (src + 32);
      c3 = aes_block_load (src + 48);

      r0 = c0 ^ k[0];
      r1 = c1 ^ k[0];
      r2 = c2 ^ k[0];
      r3 = c3 ^ k[0];

      for (i = 1; i < rounds; i++)
	{
	  r0 = _mm_aesdec_si128 (r0, k[i]);
	  r1 = _mm_aesdec_si128 (r1, k[i]);
	  r2 = _mm_aesdec_si128 (r2, k[i]);
	  r3 = _mm_aesdec_si128 (r3, k[i]);
	}

      r0 = _mm_aesdeclast_si128 (r0, k[i]);
      r1 = _mm_aesdeclast_si128 (r1, k[i]);
      r2 = _mm_aesdeclast_si128 (r2, k[i]);
      r3 = _mm_aesdeclast_si128 (r3, k[i]);

      aes_block_store (dst, r0 ^ f);
      aes_block_store (dst + 16, r1 ^ c0);
      aes_block_store (dst + 32, r2 ^ c1);
      aes_block_store (dst + 48, r3 ^ c2);

      f = c3;

      count -= 64;
      src += 64;
      dst += 64;
    }

  while (count > 0)
    {
      c0 = aes_block_load (src);
      r0 = c0 ^ k[0];
      for (i = 1; i < rounds; i++)
	r0 = _mm_aesdec_si128 (r0, k[i]);
      r0 = _mm_aesdeclast_si128 (r0, k[i]);
      aes_block_store (dst, r0 ^ f);
      f = c0;
      count -= 16;
      src += 16;
      dst += 16;
    }
}

static_always_inline void __clib_unused
vaes_cbc_dec (__m512i * k, u8 * src, u8 * dst, u8 * iv, int count,
	      aesni_key_size_t rounds)
{
  __m512i permute = { 6, 7, 8, 9, 10, 11, 12, 13 };
  __m512i r0, r1, r2, r3, c0, c1, c2, c3, f = { };
  __mmask8 m;
  int i, n_blocks = count >> 4;

  f = _mm512_mask_loadu_epi64 (f, 0xc0, (__m512i *) (iv - 48));

  while (n_blocks >= 16)
    {
      c0 = _mm512_loadu_si512 ((__m512i *) src);
      c1 = _mm512_loadu_si512 ((__m512i *) (src + 64));
      c2 = _mm512_loadu_si512 ((__m512i *) (src + 128));
      c3 = _mm512_loadu_si512 ((__m512i *) (src + 192));

      r0 = c0 ^ k[0];
      r1 = c1 ^ k[0];
      r2 = c2 ^ k[0];
      r3 = c3 ^ k[0];

      for (i = 1; i < rounds; i++)
	{
	  r0 = _mm512_aesdec_epi128 (r0, k[i]);
	  r1 = _mm512_aesdec_epi128 (r1, k[i]);
	  r2 = _mm512_aesdec_epi128 (r2, k[i]);
	  r3 = _mm512_aesdec_epi128 (r3, k[i]);
	}

      r0 = _mm512_aesdeclast_epi128 (r0, k[i]);
      r1 = _mm512_aesdeclast_epi128 (r1, k[i]);
      r2 = _mm512_aesdeclast_epi128 (r2, k[i]);
      r3 = _mm512_aesdeclast_epi128 (r3, k[i]);

      r0 ^= _mm512_permutex2var_epi64 (f, permute, c0);
      _mm512_storeu_si512 ((__m512i *) dst, r0);

      r1 ^= _mm512_permutex2var_epi64 (c0, permute, c1);
      _mm512_storeu_si512 ((__m512i *) (dst + 64), r1);

      r2 ^= _mm512_permutex2var_epi64 (c1, permute, c2);
      _mm512_storeu_si512 ((__m512i *) (dst + 128), r2);

      r3 ^= _mm512_permutex2var_epi64 (c2, permute, c3);
      _mm512_storeu_si512 ((__m512i *) (dst + 192), r3);
      f = c3;

      n_blocks -= 16;
      src += 256;
      dst += 256;
    }

  while (n_blocks > 0)
    {
      m = (1 << (n_blocks * 2)) - 1;
      c0 = _mm512_mask_loadu_epi64 (c0, m, (__m512i *) src);
      f = _mm512_permutex2var_epi64 (f, permute, c0);
      r0 = c0 ^ k[0];
      for (i = 1; i < rounds; i++)
	r0 = _mm512_aesdec_epi128 (r0, k[i]);
      r0 = _mm512_aesdeclast_epi128 (r0, k[i]);
      _mm512_mask_storeu_epi64 ((__m512i *) dst, m, r0 ^ f);
      f = c0;
      n_blocks -= 4;
      src += 64;
      dst += 64;
    }
}

static_always_inline u32
aesni_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aesni_key_size_t ks)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  crypto_ia32_per_thread_data_t *ptd = vec_elt_at_index (cm->per_thread_data,
							 vm->thread_index);
  int rounds = AESNI_KEY_ROUNDS (ks);
  u8 dummy[8192];
  u8 *src[4] = { };
  u8 *dst[4] = { };
  vnet_crypto_key_index_t key_index[4] = { ~0, ~0, ~0, ~0 };
  u32x4 dummy_mask = { };
  u32x4 len = { };
  u32 i, j, count, n_left = n_ops;
  __m128i t;
#ifdef __VAES__
  __m512i k4[rounds + 1];
  __m512i r4 = { 0 };
  __m512i t4 = { 0 };
#else
  __m128i r[4] = { }, k[4][rounds + 1];
#endif

more:
  for (i = 0; i < 4; i++)
    if (len[i] == 0)
      {
	if (n_left == 0)
	  {
	    /* no more work to enqueue, so we are enqueueing dummy buffer */
	    src[i] = dst[i] = dummy;
	    len[i] = sizeof (dummy);
	    dummy_mask[i] = 0;
	  }
	else
	  {
	    if (ops[0]->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	      {
		t = ptd->cbc_iv[i];
		aes_block_store (ops[0]->iv, t);
		ptd->cbc_iv[i] = _mm_aesenc_si128 (t, t);
	      }
	    else
	      t = aes_block_load (ops[0]->iv);
#ifdef __VAES__
	    r4[2 * i] = t[0];
	    r4[2 * i + 1] = t[1];
#else
	    r[i] = t;
#endif
	    src[i] = ops[0]->src;
	    dst[i] = ops[0]->dst;
	    len[i] = ops[0]->len;
	    dummy_mask[i] = ~0;
	    if (key_index[i] != ops[0]->key_index)
	      {
		aes_cbc_key_data_t *kd;
		key_index[i] = ops[0]->key_index;
		kd = (aes_cbc_key_data_t *) cm->key_data[key_index[i]];
		for (j = 0; j < rounds + 1; j++)
		  {
#ifdef __VAES__
		    k4[j][2 * i] = kd->encrypt_key[j][0];
		    k4[j][2 * i + 1] = kd->encrypt_key[j][1];
#else
		    k[i][j] = kd->encrypt_key[j];
#endif
		  }
	      }
	    ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	    n_left--;
	    ops++;
	  }
      }

  count = u32x4_min_scalar (len);

  ASSERT (count % 16 == 0);

  for (i = 0; i < count; i += 16)
    {
#ifdef __VAES__
      t4 = _mm512_inserti64x2 (t4, aes_block_load (src[0] + i), 0);
      t4 = _mm512_inserti64x2 (t4, aes_block_load (src[1] + i), 1);
      t4 = _mm512_inserti64x2 (t4, aes_block_load (src[2] + i), 2);
      t4 = _mm512_inserti64x2 (t4, aes_block_load (src[3] + i), 3);

      r4 ^= t4 ^ k4[0];
      for (j = 1; j < rounds; j++)
	r4 = _mm512_aesenc_epi128 (r4, k4[j]);
      r4 = _mm512_aesenclast_epi128 (r4, k4[j]);

      aes_block_store (dst[0] + i, _mm512_extracti64x2_epi64 (r4, 0));
      aes_block_store (dst[1] + i, _mm512_extracti64x2_epi64 (r4, 1));
      aes_block_store (dst[2] + i, _mm512_extracti64x2_epi64 (r4, 2));
      aes_block_store (dst[3] + i, _mm512_extracti64x2_epi64 (r4, 3));
#else
      r[0] ^= aes_block_load (src[0] + i) ^ k[0][0];
      r[1] ^= aes_block_load (src[1] + i) ^ k[1][0];
      r[2] ^= aes_block_load (src[2] + i) ^ k[2][0];
      r[3] ^= aes_block_load (src[3] + i) ^ k[3][0];

      for (j = 1; j < rounds; j++)
	{
	  r[0] = _mm_aesenc_si128 (r[0], k[0][j]);
	  r[1] = _mm_aesenc_si128 (r[1], k[1][j]);
	  r[2] = _mm_aesenc_si128 (r[2], k[2][j]);
	  r[3] = _mm_aesenc_si128 (r[3], k[3][j]);
	}

      r[0] = _mm_aesenclast_si128 (r[0], k[0][j]);
      r[1] = _mm_aesenclast_si128 (r[1], k[1][j]);
      r[2] = _mm_aesenclast_si128 (r[2], k[2][j]);
      r[3] = _mm_aesenclast_si128 (r[3], k[3][j]);

      aes_block_store (dst[0] + i, r[0]);
      aes_block_store (dst[1] + i, r[1]);
      aes_block_store (dst[2] + i, r[2]);
      aes_block_store (dst[3] + i, r[3]);
#endif
    }

  for (i = 0; i < 4; i++)
    {
      src[i] += count;
      dst[i] += count;
      len[i] -= count;
    }

  if (n_left > 0)
    goto more;

  if (!u32x4_is_all_zero (len & dummy_mask))
    goto more;

  return n_ops;
}

static_always_inline u32
aesni_ops_dec_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aesni_key_size_t ks)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  int rounds = AESNI_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
  u32 n_left = n_ops;

  ASSERT (n_ops >= 1);

decrypt:
#ifdef __VAES__
  vaes_cbc_dec (kd->decrypt_key4, op->src, op->dst, op->iv, op->len, rounds);
#else
  aes_cbc_dec (kd->decrypt_key, op->src, op->dst, op->iv, op->len, rounds);
#endif
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
      goto decrypt;
    }

  return n_ops;
}

static_always_inline void *
aesni_cbc_key_exp (vnet_crypto_key_t * key, aesni_key_size_t ks)
{
  __m128i e[15], d[15];
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  aes_key_expand (e, key->data, ks);
  aes_key_expand (d, key->data, ks);
  aes_key_enc_to_dec (d, ks);
  for (int i = 0; i < AESNI_KEY_ROUNDS (ks) + 1; i++)
    {
#if __VAES__
      kd->decrypt_key4[i] = _mm512_broadcast_i64x2 (d[i]);
      kd->encrypt_key[i] = e[i];
#else
      kd->decrypt_key[i] = d[i];
      kd->encrypt_key[i] = e[i];
#endif
    }
  return kd;
}

#define foreach_aesni_cbc_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_dec_aes_cbc (vm, ops, n_ops, AESNI_KEY_##x); } \
static u32 aesni_ops_enc_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_enc_aes_cbc (vm, ops, n_ops, AESNI_KEY_##x); } \
static void * aesni_cbc_key_exp_##x (vnet_crypto_key_t *key) \
{ return aesni_cbc_key_exp (key, AESNI_KEY_##x); }

foreach_aesni_cbc_handler_type;
#undef _

#include <fcntl.h>

clib_error_t *
#ifdef __VAES__
crypto_ia32_aesni_cbc_init_vaes (vlib_main_t * vm)
#elif __AVX512F__
crypto_ia32_aesni_cbc_init_avx512 (vlib_main_t * vm)
#elif __AVX2__
crypto_ia32_aesni_cbc_init_avx2 (vlib_main_t * vm)
#else
crypto_ia32_aesni_cbc_init_sse42 (vlib_main_t * vm)
#endif
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  crypto_ia32_per_thread_data_t *ptd;
  clib_error_t *err = 0;
  int fd;

  if ((fd = open ("/dev/urandom", O_RDONLY)) < 0)
    return clib_error_return_unix (0, "failed to open '/dev/urandom'");

  /* *INDENT-OFF* */
  vec_foreach (ptd, cm->per_thread_data)
    {
      for (int i = 0; i < 4; i++)
	{
	  if (read(fd, ptd->cbc_iv, sizeof (ptd->cbc_iv)) !=
	      sizeof (ptd->cbc_iv))
	    {
	      err = clib_error_return_unix (0, "'/dev/urandom' read failure");
	      goto error;
	    }
	}
    }
  /* *INDENT-ON* */

#define _(x) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_ENC, \
				    aesni_ops_enc_aes_cbc_##x); \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_AES_##x##_CBC_DEC, \
				    aesni_ops_dec_aes_cbc_##x); \
  cm->key_fn[VNET_CRYPTO_ALG_AES_##x##_CBC] = aesni_cbc_key_exp_##x;
  foreach_aesni_cbc_handler_type;
#undef _

error:
  close (fd);
  return err;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
