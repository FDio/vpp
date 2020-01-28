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
#include <crypto_native/crypto_native.h>
#include <crypto_native/aes.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

typedef struct
{
  __m128i encrypt_key[15];
#if __VAES__
  __m512i decrypt_key[15];
#else
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
  _mm_storeu_si128 ((__m128i *) p, r);
}

static_always_inline __m128i __clib_unused
xor3 (__m128i a, __m128i b, __m128i c)
{
#if __AVX512F__
  return _mm_ternarylogic_epi32 (a, b, c, 0x96);
#endif
  return a ^ b ^ c;
}

#if __VAES__
static_always_inline __m512i
xor3_x4 (__m512i a, __m512i b, __m512i c)
{
  return _mm512_ternarylogic_epi32 (a, b, c, 0x96);
}

static_always_inline __m512i
aes_block_load_x4 (u8 * src[], int i)
{
  __m512i r = { };
  r = _mm512_inserti64x2 (r, aes_block_load (src[0] + i), 0);
  r = _mm512_inserti64x2 (r, aes_block_load (src[1] + i), 1);
  r = _mm512_inserti64x2 (r, aes_block_load (src[2] + i), 2);
  r = _mm512_inserti64x2 (r, aes_block_load (src[3] + i), 3);
  return r;
}

static_always_inline void
aes_block_store_x4 (u8 * dst[], int i, __m512i r)
{
  aes_block_store (dst[0] + i, _mm512_extracti64x2_epi64 (r, 0));
  aes_block_store (dst[1] + i, _mm512_extracti64x2_epi64 (r, 1));
  aes_block_store (dst[2] + i, _mm512_extracti64x2_epi64 (r, 2));
  aes_block_store (dst[3] + i, _mm512_extracti64x2_epi64 (r, 3));
}
#endif

static_always_inline void __clib_unused
aes_cbc_dec (__m128i * k, u8 * src, u8 * dst, u8 * iv, int count,
	     aes_key_size_t rounds)
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

#ifdef __VAES__
static_always_inline void
vaes_cbc_dec (__m512i * k, u8 * src, u8 * dst, u8 * iv, int count,
	      aes_key_size_t rounds)
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
#endif

#ifdef __VAES__
#define N 16
#define u32xN u32x16
#define u32xN_min_scalar u32x16_min_scalar
#define u32xN_is_all_zero u32x16_is_all_zero
#else
#define N 4
#define u32xN u32x4
#define u32xN_min_scalar u32x4_min_scalar
#define u32xN_is_all_zero u32x4_is_all_zero
#endif

static_always_inline u32
aesni_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd =
    vec_elt_at_index (cm->per_thread_data, vm->thread_index);
  int rounds = AES_KEY_ROUNDS (ks);
  u8 dummy[8192];
  u32 i, j, count, n_left = n_ops;
  u32xN dummy_mask = { };
  u32xN len = { };
  vnet_crypto_key_index_t key_index[N];
  u8 *src[N] = { };
  u8 *dst[N] = { };
  /* *INDENT-OFF* */
  union
  {
    __m128i x1[N];
    __m512i x4[N / 4];
  } r = { }, k[15] = { };
  /* *INDENT-ON* */

  for (i = 0; i < N; i++)
    key_index[i] = ~0;

more:
  for (i = 0; i < N; i++)
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
		r.x1[i] = ptd->cbc_iv[i];
		aes_block_store (ops[0]->iv, r.x1[i]);
		ptd->cbc_iv[i] = _mm_aesenc_si128 (r.x1[i], r.x1[i]);
	      }
	    else
	      r.x1[i] = aes_block_load (ops[0]->iv);

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
		  k[j].x1[i] = kd->encrypt_key[j];
	      }
	    ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	    n_left--;
	    ops++;
	  }
      }

  count = u32xN_min_scalar (len);

  ASSERT (count % 16 == 0);

  for (i = 0; i < count; i += 16)
    {
#ifdef __VAES__
      r.x4[0] = xor3_x4 (r.x4[0], aes_block_load_x4 (src, i), k[0].x4[0]);
      r.x4[1] = xor3_x4 (r.x4[1], aes_block_load_x4 (src, i), k[0].x4[1]);
      r.x4[2] = xor3_x4 (r.x4[2], aes_block_load_x4 (src, i), k[0].x4[2]);
      r.x4[3] = xor3_x4 (r.x4[3], aes_block_load_x4 (src, i), k[0].x4[3]);

      for (j = 1; j < rounds; j++)
	{
	  r.x4[0] = _mm512_aesenc_epi128 (r.x4[0], k[j].x4[0]);
	  r.x4[1] = _mm512_aesenc_epi128 (r.x4[1], k[j].x4[1]);
	  r.x4[2] = _mm512_aesenc_epi128 (r.x4[2], k[j].x4[2]);
	  r.x4[3] = _mm512_aesenc_epi128 (r.x4[3], k[j].x4[3]);
	}
      r.x4[0] = _mm512_aesenclast_epi128 (r.x4[0], k[j].x4[0]);
      r.x4[1] = _mm512_aesenclast_epi128 (r.x4[1], k[j].x4[1]);
      r.x4[2] = _mm512_aesenclast_epi128 (r.x4[2], k[j].x4[2]);
      r.x4[3] = _mm512_aesenclast_epi128 (r.x4[3], k[j].x4[3]);

      aes_block_store_x4 (dst, i, r.x4[0]);
      aes_block_store_x4 (dst + 4, i, r.x4[1]);
      aes_block_store_x4 (dst + 8, i, r.x4[2]);
      aes_block_store_x4 (dst + 12, i, r.x4[3]);
#else
      r.x1[0] = xor3 (r.x1[0], aes_block_load (src[0] + i), k[0].x1[0]);
      r.x1[1] = xor3 (r.x1[1], aes_block_load (src[1] + i), k[0].x1[1]);
      r.x1[2] = xor3 (r.x1[2], aes_block_load (src[2] + i), k[0].x1[2]);
      r.x1[3] = xor3 (r.x1[3], aes_block_load (src[3] + i), k[0].x1[3]);

      for (j = 1; j < rounds; j++)
	{
	  r.x1[0] = _mm_aesenc_si128 (r.x1[0], k[j].x1[0]);
	  r.x1[1] = _mm_aesenc_si128 (r.x1[1], k[j].x1[1]);
	  r.x1[2] = _mm_aesenc_si128 (r.x1[2], k[j].x1[2]);
	  r.x1[3] = _mm_aesenc_si128 (r.x1[3], k[j].x1[3]);
	}

      r.x1[0] = _mm_aesenclast_si128 (r.x1[0], k[j].x1[0]);
      r.x1[1] = _mm_aesenclast_si128 (r.x1[1], k[j].x1[1]);
      r.x1[2] = _mm_aesenclast_si128 (r.x1[2], k[j].x1[2]);
      r.x1[3] = _mm_aesenclast_si128 (r.x1[3], k[j].x1[3]);

      aes_block_store (dst[0] + i, r.x1[0]);
      aes_block_store (dst[1] + i, r.x1[1]);
      aes_block_store (dst[2] + i, r.x1[2]);
      aes_block_store (dst[3] + i, r.x1[3]);
#endif
    }

  for (i = 0; i < N; i++)
    {
      src[i] += count;
      dst[i] += count;
      len[i] -= count;
    }

  if (n_left > 0)
    goto more;

  if (!u32xN_is_all_zero (len & dummy_mask))
    goto more;

  return n_ops;
}

static_always_inline u32
aesni_ops_dec_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
  u32 n_left = n_ops;

  ASSERT (n_ops >= 1);

decrypt:
#ifdef __VAES__
  vaes_cbc_dec (kd->decrypt_key, op->src, op->dst, op->iv, op->len, rounds);
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
aesni_cbc_key_exp (vnet_crypto_key_t * key, aes_key_size_t ks)
{
  __m128i e[15], d[15];
  aes_cbc_key_data_t *kd;
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);
  aes_key_expand (e, key->data, ks);
  aes_key_expand (d, key->data, ks);
  aes_key_enc_to_dec (d, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    {
#if __VAES__
      kd->decrypt_key[i] = _mm512_broadcast_i64x2 (d[i]);
#else
      kd->decrypt_key[i] = d[i];
#endif
      kd->encrypt_key[i] = e[i];
    }
  return kd;
}

#define foreach_aesni_cbc_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_dec_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static u32 aesni_ops_enc_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_enc_aes_cbc (vm, ops, n_ops, AES_KEY_##x); } \
static void * aesni_cbc_key_exp_##x (vnet_crypto_key_t *key) \
{ return aesni_cbc_key_exp (key, AES_KEY_##x); }

foreach_aesni_cbc_handler_type;
#undef _

#include <fcntl.h>

clib_error_t *
#ifdef __VAES__
crypto_native_aes_cbc_init_vaes (vlib_main_t * vm)
#elif __AVX512F__
crypto_native_aes_cbc_init_avx512 (vlib_main_t * vm)
#elif __AVX2__
crypto_native_aes_cbc_init_avx2 (vlib_main_t * vm)
#else
crypto_native_aes_cbc_init_sse42 (vlib_main_t * vm)
#endif
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd;
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
