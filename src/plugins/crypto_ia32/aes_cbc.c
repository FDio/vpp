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

static_always_inline void
aes_cbc_dec (__m128i * k, u8 * src, u8 * dst, u8 * iv, int count,
	     aesni_key_size_t rounds)
{
  __m128i r0, r1, r2, r3, c0, c1, c2, c3, f;
  int i;

  f = _mm_loadu_si128 ((__m128i *) iv);

  while (count >= 64)
    {
      _mm_prefetch (src + 128, _MM_HINT_T0);
      _mm_prefetch (dst + 128, _MM_HINT_T0);

      c0 = _mm_loadu_si128 (((__m128i *) src + 0));
      c1 = _mm_loadu_si128 (((__m128i *) src + 1));
      c2 = _mm_loadu_si128 (((__m128i *) src + 2));
      c3 = _mm_loadu_si128 (((__m128i *) src + 3));

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

      _mm_storeu_si128 ((__m128i *) dst + 0, r0 ^ f);
      _mm_storeu_si128 ((__m128i *) dst + 1, r1 ^ c0);
      _mm_storeu_si128 ((__m128i *) dst + 2, r2 ^ c1);
      _mm_storeu_si128 ((__m128i *) dst + 3, r3 ^ c2);

      f = c3;

      count -= 64;
      src += 64;
      dst += 64;
    }

  while (count > 0)
    {
      c0 = _mm_loadu_si128 (((__m128i *) src));
      r0 = c0 ^ k[0];
      for (i = 1; i < rounds; i++)
	r0 = _mm_aesdec_si128 (r0, k[i]);
      r0 = _mm_aesdeclast_si128 (r0, k[i]);
      _mm_storeu_si128 ((__m128i *) dst, r0 ^ f);
      f = c0;
      count -= 16;
      src += 16;
      dst += 16;
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
  u32x4 dummy_mask, len = { };
  u32 i, j, count, n_left = n_ops;
  __m128i r[4] = { }, k[4][rounds + 1];

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
		r[i] = ptd->cbc_iv[i];
		_mm_storeu_si128 ((__m128i *) ops[0]->iv, r[i]);
		ptd->cbc_iv[i] = _mm_aesenc_si128 (r[i], r[i]);
	      }
	    else
	      r[i] = _mm_loadu_si128 ((__m128i *) ops[0]->iv);
	    src[i] = ops[0]->src;
	    dst[i] = ops[0]->dst;
	    len[i] = ops[0]->len;
	    dummy_mask[i] = ~0;
	    if (key_index[i] != ops[0]->key_index)
	      {
		aesni_key_data_t *kd;
		key_index[i] = ops[0]->key_index;
		kd = (aesni_key_data_t *) cm->key_data[key_index[i]];
		clib_memcpy_fast (k[i], kd->encrypt_key,
				  (rounds + 1) * sizeof (__m128i));
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
      r[0] ^= _mm_loadu_si128 ((__m128i *) (src[0] + i)) ^ k[0][0];
      r[1] ^= _mm_loadu_si128 ((__m128i *) (src[1] + i)) ^ k[1][0];
      r[2] ^= _mm_loadu_si128 ((__m128i *) (src[2] + i)) ^ k[2][0];
      r[3] ^= _mm_loadu_si128 ((__m128i *) (src[3] + i)) ^ k[3][0];

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

      _mm_storeu_si128 ((__m128i *) (dst[0] + i), r[0]);
      _mm_storeu_si128 ((__m128i *) (dst[1] + i), r[1]);
      _mm_storeu_si128 ((__m128i *) (dst[2] + i), r[2]);
      _mm_storeu_si128 ((__m128i *) (dst[3] + i), r[3]);
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
  aesni_key_data_t *kd = (aesni_key_data_t *) cm->key_data[op->key_index];
  u32 n_left = n_ops;

  ASSERT (n_ops >= 1);

decrypt:
  aes_cbc_dec (kd->decrypt_key, op->src, op->dst, op->iv, op->len, rounds);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      kd = (aesni_key_data_t *) cm->key_data[op->key_index];
      goto decrypt;
    }

  return n_ops;
}

#define foreach_aesni_cbc_handler_type _(128) _(192) _(256)

#define _(x) \
static u32 aesni_ops_dec_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_dec_aes_cbc (vm, ops, n_ops, AESNI_KEY_##x); } \
static u32 aesni_ops_enc_aes_cbc_##x \
(vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return aesni_ops_enc_aes_cbc (vm, ops, n_ops, AESNI_KEY_##x); } \

foreach_aesni_cbc_handler_type;
#undef _

#include <fcntl.h>

clib_error_t *
crypto_ia32_aesni_cbc_init (vlib_main_t * vm)
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
				    aesni_ops_dec_aes_cbc_##x);
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
