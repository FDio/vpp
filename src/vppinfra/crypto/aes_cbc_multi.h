/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef __crypto_aes_cbc_multi_h__
#define __crypto_aes_cbc_multi_h__

#include <vppinfra/crypto/aes_cbc.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

#if defined(__VAES__) && defined(__AVX512F__)
#define u8xN		  u8x64
#define u32xN		  u32x16
#define u32xN_min_scalar  u32x16_min_scalar
#define u32xN_is_all_zero u32x16_is_all_zero
#define u32xN_splat	  u32x16_splat
#elif defined(__VAES__)
#define u8xN		  u8x32
#define u32xN		  u32x8
#define u32xN_min_scalar  u32x8_min_scalar
#define u32xN_is_all_zero u32x8_is_all_zero
#define u32xN_splat	  u32x8_splat
#else
#define u8xN		  u8x16
#define u32xN		  u32x4
#define u32xN_min_scalar  u32x4_min_scalar
#define u32xN_is_all_zero u32x4_is_all_zero
#define u32xN_splat	  u32x4_splat
#endif

static_always_inline u32
clib_aes_cbc_encrypt_multi (aes_cbc_key_data_t **key_data,
			    const uword *key_indices, u8 **plaintext,
			    const uword *oplen, u8 **iv, aes_key_size_t ks,
			    u8 **ciphertext, uword n_ops)
{
  int rounds = AES_KEY_ROUNDS (ks);
  u8 placeholder[8192];
  u32 i, j, count, n_left = n_ops;
  u32xN placeholder_mask = {};
  u32xN len = {};
  u32 key_index[4 * N_AES_LANES];
  u8 *src[4 * N_AES_LANES] = {};
  u8 *dst[4 * N_AES_LANES] = {};
  u8xN r[4] = {};
  u8xN k[15][4] = {};

  for (i = 0; i < 4 * N_AES_LANES; i++)
    key_index[i] = ~0;

more:
  for (i = 0; i < 4 * N_AES_LANES; i++)
    if (len[i] == 0)
      {
	if (n_left == 0)
	  {
	    /* no more work to enqueue, so we are enqueueing placeholder buffer
	     */
	    src[i] = dst[i] = placeholder;
	    len[i] = sizeof (placeholder);
	    placeholder_mask[i] = 0;
	  }
	else
	  {
	    u8x16 t = aes_block_load (iv[0]);
	    ((u8x16 *) r)[i] = t;

	    src[i] = plaintext[0];
	    dst[i] = ciphertext[0];
	    len[i] = oplen[0];
	    placeholder_mask[i] = ~0;
	    if (key_index[i] != key_indices[0])
	      {
		aes_cbc_key_data_t *kd;
		key_index[i] = key_indices[0];
		kd = key_data[key_index[i]];
		for (j = 0; j < rounds + 1; j++)
		  ((u8x16 *) k[j])[i] = kd->encrypt_key[j];
	      }
	    n_left--;
	    iv++;
	    ciphertext++;
	    plaintext++;
	    key_indices++;
	    oplen++;
	  }
      }

  count = u32xN_min_scalar (len);

  ASSERT (count % 16 == 0);

  for (i = 0; i < count; i += 16)
    {
#if defined(__VAES__) && defined(__AVX512F__)
      r[0] = u8x64_xor3 (r[0], aes_block_load_x4 (src, i), k[0][0]);
      r[1] = u8x64_xor3 (r[1], aes_block_load_x4 (src + 4, i), k[0][1]);
      r[2] = u8x64_xor3 (r[2], aes_block_load_x4 (src + 8, i), k[0][2]);
      r[3] = u8x64_xor3 (r[3], aes_block_load_x4 (src + 12, i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x4 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x4 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x4 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x4 (r[3], k[j][3]);
	}
      r[0] = aes_enc_last_round_x4 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x4 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x4 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x4 (r[3], k[j][3]);

      aes_block_store_x4 (dst, i, r[0]);
      aes_block_store_x4 (dst + 4, i, r[1]);
      aes_block_store_x4 (dst + 8, i, r[2]);
      aes_block_store_x4 (dst + 12, i, r[3]);
#elif defined(__VAES__)
      r[0] = u8x32_xor3 (r[0], aes_block_load_x2 (src, i), k[0][0]);
      r[1] = u8x32_xor3 (r[1], aes_block_load_x2 (src + 2, i), k[0][1]);
      r[2] = u8x32_xor3 (r[2], aes_block_load_x2 (src + 4, i), k[0][2]);
      r[3] = u8x32_xor3 (r[3], aes_block_load_x2 (src + 6, i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x2 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x2 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x2 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x2 (r[3], k[j][3]);
	}
      r[0] = aes_enc_last_round_x2 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x2 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x2 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x2 (r[3], k[j][3]);

      aes_block_store_x2 (dst, i, r[0]);
      aes_block_store_x2 (dst + 2, i, r[1]);
      aes_block_store_x2 (dst + 4, i, r[2]);
      aes_block_store_x2 (dst + 6, i, r[3]);
#else
#if __x86_64__
      r[0] = u8x16_xor3 (r[0], aes_block_load (src[0] + i), k[0][0]);
      r[1] = u8x16_xor3 (r[1], aes_block_load (src[1] + i), k[0][1]);
      r[2] = u8x16_xor3 (r[2], aes_block_load (src[2] + i), k[0][2]);
      r[3] = u8x16_xor3 (r[3], aes_block_load (src[3] + i), k[0][3]);

      for (j = 1; j < rounds; j++)
	{
	  r[0] = aes_enc_round_x1 (r[0], k[j][0]);
	  r[1] = aes_enc_round_x1 (r[1], k[j][1]);
	  r[2] = aes_enc_round_x1 (r[2], k[j][2]);
	  r[3] = aes_enc_round_x1 (r[3], k[j][3]);
	}

      r[0] = aes_enc_last_round_x1 (r[0], k[j][0]);
      r[1] = aes_enc_last_round_x1 (r[1], k[j][1]);
      r[2] = aes_enc_last_round_x1 (r[2], k[j][2]);
      r[3] = aes_enc_last_round_x1 (r[3], k[j][3]);

      aes_block_store (dst[0] + i, r[0]);
      aes_block_store (dst[1] + i, r[1]);
      aes_block_store (dst[2] + i, r[2]);
      aes_block_store (dst[3] + i, r[3]);
#else
      r[0] ^= aes_block_load (src[0] + i);
      r[1] ^= aes_block_load (src[1] + i);
      r[2] ^= aes_block_load (src[2] + i);
      r[3] ^= aes_block_load (src[3] + i);
      for (j = 0; j < rounds - 1; j++)
	{
	  r[0] = vaesmcq_u8 (vaeseq_u8 (r[0], k[j][0]));
	  r[1] = vaesmcq_u8 (vaeseq_u8 (r[1], k[j][1]));
	  r[2] = vaesmcq_u8 (vaeseq_u8 (r[2], k[j][2]));
	  r[3] = vaesmcq_u8 (vaeseq_u8 (r[3], k[j][3]));
	}
      r[0] = vaeseq_u8 (r[0], k[j][0]) ^ k[rounds][0];
      r[1] = vaeseq_u8 (r[1], k[j][1]) ^ k[rounds][1];
      r[2] = vaeseq_u8 (r[2], k[j][2]) ^ k[rounds][2];
      r[3] = vaeseq_u8 (r[3], k[j][3]) ^ k[rounds][3];
      aes_block_store (dst[0] + i, r[0]);
      aes_block_store (dst[1] + i, r[1]);
      aes_block_store (dst[2] + i, r[2]);
      aes_block_store (dst[3] + i, r[3]);
#endif
#endif
    }

  len -= u32xN_splat (count);

  for (i = 0; i < 4 * N_AES_LANES; i++)
    {
      src[i] += count;
      dst[i] += count;
    }

  if (n_left > 0)
    goto more;

  if (!u32xN_is_all_zero (len & placeholder_mask))
    goto more;

  return n_ops;
}

#undef u8xN
#undef u32xN
#undef u32xN_min_scalar
#undef u32xN_is_all_zero
#undef u32xN_splat
#endif /* __crypto_aes_cbc_multi_h__ */