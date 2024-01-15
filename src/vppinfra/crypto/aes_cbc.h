/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef __crypto_aes_cbc_h__
#define __crypto_aes_cbc_h__

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/crypto/aes.h>

typedef struct
{
  const u8x16 encrypt_key[15];
  const u8x16 decrypt_key[15];
} aes_cbc_key_data_t;

static_always_inline void
clib_aes_cbc_encrypt (const aes_cbc_key_data_t *kd, const u8 *src, uword len,
		      const u8 *iv, aes_key_size_t ks, u8 *dst)
{
  int rounds = AES_KEY_ROUNDS (ks);
  u8x16 r, *k = (u8x16 *) kd->encrypt_key;

  r = *(u8x16u *) iv;

  for (int i = 0; i < len; i += 16)
    {
      int j;
      r = u8x16_xor3 (r, *(u8x16u *) (src + i), k[0]);
      for (j = 1; j < rounds; j++)
	r = aes_enc_round_x1 (r, k[j]);
      r = aes_enc_last_round_x1 (r, k[rounds]);
      *(u8x16u *) (dst + i) = r;
    }
}

static_always_inline void
clib_aes128_cbc_encrypt (const aes_cbc_key_data_t *kd, const u8 *plaintext,
			 uword len, const u8 *iv, u8 *ciphertext)
{
  clib_aes_cbc_encrypt (kd, plaintext, len, iv, AES_KEY_128, ciphertext);
}

static_always_inline void
clib_aes192_cbc_encrypt (const aes_cbc_key_data_t *kd, const u8 *plaintext,
			 uword len, const u8 *iv, u8 *ciphertext)
{
  clib_aes_cbc_encrypt (kd, plaintext, len, iv, AES_KEY_192, ciphertext);
}

static_always_inline void
clib_aes256_cbc_encrypt (const aes_cbc_key_data_t *kd, const u8 *plaintext,
			 uword len, const u8 *iv, u8 *ciphertext)
{
  clib_aes_cbc_encrypt (kd, plaintext, len, iv, AES_KEY_256, ciphertext);
}

static_always_inline void __clib_unused
aes_cbc_dec (const u8x16 *k, u8x16u *src, u8x16u *dst, u8x16u *iv, int count,
	     int rounds)
{
  u8x16 r[4], c[4], f;

  f = iv[0];
  while (count >= 64)
    {
      c[0] = r[0] = src[0];
      c[1] = r[1] = src[1];
      c[2] = r[2] = src[2];
      c[3] = r[3] = src[3];

#if __x86_64__
      r[0] ^= k[0];
      r[1] ^= k[0];
      r[2] ^= k[0];
      r[3] ^= k[0];

      for (int i = 1; i < rounds; i++)
	{
	  r[0] = aes_dec_round_x1 (r[0], k[i]);
	  r[1] = aes_dec_round_x1 (r[1], k[i]);
	  r[2] = aes_dec_round_x1 (r[2], k[i]);
	  r[3] = aes_dec_round_x1 (r[3], k[i]);
	}

      r[0] = aes_dec_last_round_x1 (r[0], k[rounds]);
      r[1] = aes_dec_last_round_x1 (r[1], k[rounds]);
      r[2] = aes_dec_last_round_x1 (r[2], k[rounds]);
      r[3] = aes_dec_last_round_x1 (r[3], k[rounds]);
#else
      for (int i = 0; i < rounds - 1; i++)
	{
	  r[0] = vaesimcq_u8 (vaesdq_u8 (r[0], k[i]));
	  r[1] = vaesimcq_u8 (vaesdq_u8 (r[1], k[i]));
	  r[2] = vaesimcq_u8 (vaesdq_u8 (r[2], k[i]));
	  r[3] = vaesimcq_u8 (vaesdq_u8 (r[3], k[i]));
	}
      r[0] = vaesdq_u8 (r[0], k[rounds - 1]) ^ k[rounds];
      r[1] = vaesdq_u8 (r[1], k[rounds - 1]) ^ k[rounds];
      r[2] = vaesdq_u8 (r[2], k[rounds - 1]) ^ k[rounds];
      r[3] = vaesdq_u8 (r[3], k[rounds - 1]) ^ k[rounds];
#endif
      dst[0] = r[0] ^ f;
      dst[1] = r[1] ^ c[0];
      dst[2] = r[2] ^ c[1];
      dst[3] = r[3] ^ c[2];
      f = c[3];

      count -= 64;
      src += 4;
      dst += 4;
    }

  while (count > 0)
    {
      c[0] = r[0] = src[0];
#if __x86_64__
      r[0] ^= k[0];
      for (int i = 1; i < rounds; i++)
	r[0] = aes_dec_round_x1 (r[0], k[i]);
      r[0] = aes_dec_last_round_x1 (r[0], k[rounds]);
#else
      c[0] = r[0] = src[0];
      for (int i = 0; i < rounds - 1; i++)
	r[0] = vaesimcq_u8 (vaesdq_u8 (r[0], k[i]));
      r[0] = vaesdq_u8 (r[0], k[rounds - 1]) ^ k[rounds];
#endif
      dst[0] = r[0] ^ f;
      f = c[0];

      count -= 16;
      src += 1;
      dst += 1;
    }
}

#if __x86_64__
#if defined(__VAES__) && defined(__AVX512F__)

static_always_inline u8x64
aes_block_load_x4 (u8 *src[], int i)
{
  u8x64 r = {};
  r = u8x64_insert_u8x16 (r, aes_block_load (src[0] + i), 0);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[1] + i), 1);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[2] + i), 2);
  r = u8x64_insert_u8x16 (r, aes_block_load (src[3] + i), 3);
  return r;
}

static_always_inline void
aes_block_store_x4 (u8 *dst[], int i, u8x64 r)
{
  aes_block_store (dst[0] + i, u8x64_extract_u8x16 (r, 0));
  aes_block_store (dst[1] + i, u8x64_extract_u8x16 (r, 1));
  aes_block_store (dst[2] + i, u8x64_extract_u8x16 (r, 2));
  aes_block_store (dst[3] + i, u8x64_extract_u8x16 (r, 3));
}

static_always_inline u8x64
aes4_cbc_dec_permute (u8x64 a, u8x64 b)
{
  return (u8x64) u64x8_shuffle2 (a, b, 6, 7, 8, 9, 10, 11, 12, 13);
}

static_always_inline void
aes4_cbc_dec (const u8x16 *k, u8x64u *src, u8x64u *dst, u8x16u *iv, int count,
	      aes_key_size_t rounds)
{
  u8x64 f, k4, r[4], c[4] = {};
  __mmask8 m;
  int i, n_blocks = count >> 4;

  f = u8x64_insert_u8x16 (u8x64_zero (), *iv, 3);

  while (n_blocks >= 16)
    {
      k4 = u8x64_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];
      c[2] = src[2];
      c[3] = src[3];

      r[0] = c[0] ^ k4;
      r[1] = c[1] ^ k4;
      r[2] = c[2] ^ k4;
      r[3] = c[3] ^ k4;

      for (i = 1; i < rounds; i++)
	{
	  k4 = u8x64_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x4 (r[0], k4);
	  r[1] = aes_dec_round_x4 (r[1], k4);
	  r[2] = aes_dec_round_x4 (r[2], k4);
	  r[3] = aes_dec_round_x4 (r[3], k4);
	}

      k4 = u8x64_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x4 (r[0], k4);
      r[1] = aes_dec_last_round_x4 (r[1], k4);
      r[2] = aes_dec_last_round_x4 (r[2], k4);
      r[3] = aes_dec_last_round_x4 (r[3], k4);

      dst[0] = r[0] ^= aes4_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes4_cbc_dec_permute (c[0], c[1]);
      dst[2] = r[2] ^= aes4_cbc_dec_permute (c[1], c[2]);
      dst[3] = r[3] ^= aes4_cbc_dec_permute (c[2], c[3]);
      f = c[3];

      n_blocks -= 16;
      src += 4;
      dst += 4;
    }

  if (n_blocks >= 12)
    {
      k4 = u8x64_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];
      c[2] = src[2];

      r[0] = c[0] ^ k4;
      r[1] = c[1] ^ k4;
      r[2] = c[2] ^ k4;

      for (i = 1; i < rounds; i++)
	{
	  k4 = u8x64_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x4 (r[0], k4);
	  r[1] = aes_dec_round_x4 (r[1], k4);
	  r[2] = aes_dec_round_x4 (r[2], k4);
	}

      k4 = u8x64_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x4 (r[0], k4);
      r[1] = aes_dec_last_round_x4 (r[1], k4);
      r[2] = aes_dec_last_round_x4 (r[2], k4);

      dst[0] = r[0] ^= aes4_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes4_cbc_dec_permute (c[0], c[1]);
      dst[2] = r[2] ^= aes4_cbc_dec_permute (c[1], c[2]);
      f = c[2];

      n_blocks -= 12;
      src += 3;
      dst += 3;
    }
  else if (n_blocks >= 8)
    {
      k4 = u8x64_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];

      r[0] = c[0] ^ k4;
      r[1] = c[1] ^ k4;

      for (i = 1; i < rounds; i++)
	{
	  k4 = u8x64_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x4 (r[0], k4);
	  r[1] = aes_dec_round_x4 (r[1], k4);
	}

      k4 = u8x64_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x4 (r[0], k4);
      r[1] = aes_dec_last_round_x4 (r[1], k4);

      dst[0] = r[0] ^= aes4_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes4_cbc_dec_permute (c[0], c[1]);
      f = c[1];

      n_blocks -= 8;
      src += 2;
      dst += 2;
    }
  else if (n_blocks >= 4)
    {
      c[0] = src[0];

      r[0] = c[0] ^ u8x64_splat_u8x16 (k[0]);

      for (i = 1; i < rounds; i++)
	r[0] = aes_dec_round_x4 (r[0], u8x64_splat_u8x16 (k[i]));

      r[0] = aes_dec_last_round_x4 (r[0], u8x64_splat_u8x16 (k[i]));

      dst[0] = r[0] ^= aes4_cbc_dec_permute (f, c[0]);
      f = c[0];

      n_blocks -= 4;
      src += 1;
      dst += 1;
    }

  if (n_blocks > 0)
    {
      k4 = u8x64_splat_u8x16 (k[0]);
      m = (1 << (n_blocks * 2)) - 1;
      c[0] =
	(u8x64) _mm512_mask_loadu_epi64 ((__m512i) c[0], m, (__m512i *) src);
      f = aes4_cbc_dec_permute (f, c[0]);
      r[0] = c[0] ^ k4;
      for (i = 1; i < rounds; i++)
	r[0] = aes_dec_round_x4 (r[0], u8x64_splat_u8x16 (k[i]));
      r[0] = aes_dec_last_round_x4 (r[0], u8x64_splat_u8x16 (k[i]));
      _mm512_mask_storeu_epi64 ((__m512i *) dst, m, (__m512i) (r[0] ^ f));
    }
}
#elif defined(__VAES__)

static_always_inline u8x32
aes_block_load_x2 (u8 *src[], int i)
{
  u8x32 r = {};
  r = u8x32_insert_lo (r, aes_block_load (src[0] + i));
  r = u8x32_insert_hi (r, aes_block_load (src[1] + i));
  return r;
}

static_always_inline void
aes_block_store_x2 (u8 *dst[], int i, u8x32 r)
{
  aes_block_store (dst[0] + i, u8x32_extract_lo (r));
  aes_block_store (dst[1] + i, u8x32_extract_hi (r));
}

static_always_inline u8x32
aes2_cbc_dec_permute (u8x32 a, u8x32 b)
{
  return (u8x32) u64x4_shuffle2 ((u64x4) a, (u64x4) b, 2, 3, 4, 5);
}

static_always_inline void
aes2_cbc_dec (const u8x16 *k, u8x32u *src, u8x32u *dst, u8x16u *iv, int count,
	      aes_key_size_t rounds)
{
  u8x32 k2, f = {}, r[4], c[4] = {};
  int i, n_blocks = count >> 4;

  f = u8x32_insert_hi (f, *iv);

  while (n_blocks >= 8)
    {
      k2 = u8x32_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];
      c[2] = src[2];
      c[3] = src[3];

      r[0] = c[0] ^ k2;
      r[1] = c[1] ^ k2;
      r[2] = c[2] ^ k2;
      r[3] = c[3] ^ k2;

      for (i = 1; i < rounds; i++)
	{
	  k2 = u8x32_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x2 (r[0], k2);
	  r[1] = aes_dec_round_x2 (r[1], k2);
	  r[2] = aes_dec_round_x2 (r[2], k2);
	  r[3] = aes_dec_round_x2 (r[3], k2);
	}

      k2 = u8x32_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x2 (r[0], k2);
      r[1] = aes_dec_last_round_x2 (r[1], k2);
      r[2] = aes_dec_last_round_x2 (r[2], k2);
      r[3] = aes_dec_last_round_x2 (r[3], k2);

      dst[0] = r[0] ^= aes2_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes2_cbc_dec_permute (c[0], c[1]);
      dst[2] = r[2] ^= aes2_cbc_dec_permute (c[1], c[2]);
      dst[3] = r[3] ^= aes2_cbc_dec_permute (c[2], c[3]);
      f = c[3];

      n_blocks -= 8;
      src += 4;
      dst += 4;
    }

  if (n_blocks >= 6)
    {
      k2 = u8x32_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];
      c[2] = src[2];

      r[0] = c[0] ^ k2;
      r[1] = c[1] ^ k2;
      r[2] = c[2] ^ k2;

      for (i = 1; i < rounds; i++)
	{
	  k2 = u8x32_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x2 (r[0], k2);
	  r[1] = aes_dec_round_x2 (r[1], k2);
	  r[2] = aes_dec_round_x2 (r[2], k2);
	}

      k2 = u8x32_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x2 (r[0], k2);
      r[1] = aes_dec_last_round_x2 (r[1], k2);
      r[2] = aes_dec_last_round_x2 (r[2], k2);

      dst[0] = r[0] ^= aes2_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes2_cbc_dec_permute (c[0], c[1]);
      dst[2] = r[2] ^= aes2_cbc_dec_permute (c[1], c[2]);
      f = c[2];

      n_blocks -= 6;
      src += 3;
      dst += 3;
    }
  else if (n_blocks >= 4)
    {
      k2 = u8x32_splat_u8x16 (k[0]);
      c[0] = src[0];
      c[1] = src[1];

      r[0] = c[0] ^ k2;
      r[1] = c[1] ^ k2;

      for (i = 1; i < rounds; i++)
	{
	  k2 = u8x32_splat_u8x16 (k[i]);
	  r[0] = aes_dec_round_x2 (r[0], k2);
	  r[1] = aes_dec_round_x2 (r[1], k2);
	}

      k2 = u8x32_splat_u8x16 (k[i]);
      r[0] = aes_dec_last_round_x2 (r[0], k2);
      r[1] = aes_dec_last_round_x2 (r[1], k2);

      dst[0] = r[0] ^= aes2_cbc_dec_permute (f, c[0]);
      dst[1] = r[1] ^= aes2_cbc_dec_permute (c[0], c[1]);
      f = c[1];

      n_blocks -= 4;
      src += 2;
      dst += 2;
    }
  else if (n_blocks >= 2)
    {
      k2 = u8x32_splat_u8x16 (k[0]);
      c[0] = src[0];
      r[0] = c[0] ^ k2;

      for (i = 1; i < rounds; i++)
	r[0] = aes_dec_round_x2 (r[0], u8x32_splat_u8x16 (k[i]));

      r[0] = aes_dec_last_round_x2 (r[0], u8x32_splat_u8x16 (k[i]));
      dst[0] = r[0] ^= aes2_cbc_dec_permute (f, c[0]);
      f = c[0];

      n_blocks -= 2;
      src += 1;
      dst += 1;
    }

  if (n_blocks > 0)
    {
      u8x16 rl = *(u8x16u *) src ^ k[0];
      for (i = 1; i < rounds; i++)
	rl = aes_dec_round_x1 (rl, k[i]);
      rl = aes_dec_last_round_x1 (rl, k[i]);
      *(u8x16u *) dst = rl ^ u8x32_extract_hi (f);
    }
}
#endif
#endif

static_always_inline void
clib_aes_cbc_key_expand (aes_cbc_key_data_t *kd, const u8 *key,
			 aes_key_size_t ks)
{
  u8x16 e[15], d[15];
  aes_key_expand (e, key, ks);
  aes_key_enc_to_dec (e, d, ks);
  for (int i = 0; i < AES_KEY_ROUNDS (ks) + 1; i++)
    {
      ((u8x16 *) kd->decrypt_key)[i] = d[i];
      ((u8x16 *) kd->encrypt_key)[i] = e[i];
    }
}

static_always_inline void
clib_aes128_cbc_key_expand (aes_cbc_key_data_t *kd, const u8 *key)
{
  clib_aes_cbc_key_expand (kd, key, AES_KEY_128);
}
static_always_inline void
clib_aes192_cbc_key_expand (aes_cbc_key_data_t *kd, const u8 *key)
{
  clib_aes_cbc_key_expand (kd, key, AES_KEY_192);
}
static_always_inline void
clib_aes256_cbc_key_expand (aes_cbc_key_data_t *kd, const u8 *key)
{
  clib_aes_cbc_key_expand (kd, key, AES_KEY_256);
}

static_always_inline void
clib_aes_cbc_decrypt (const aes_cbc_key_data_t *kd, const u8 *ciphertext,
		      uword len, const u8 *iv, aes_key_size_t ks,
		      u8 *plaintext)
{
  int rounds = AES_KEY_ROUNDS (ks);
#if defined(__VAES__) && defined(__AVX512F__)
  aes4_cbc_dec (kd->decrypt_key, (u8x64u *) ciphertext, (u8x64u *) plaintext,
		(u8x16u *) iv, (int) len, rounds);
#elif defined(__VAES__)
  aes2_cbc_dec (kd->decrypt_key, (u8x32u *) ciphertext, (u8x32u *) plaintext,
		(u8x16u *) iv, (int) len, rounds);
#else
  aes_cbc_dec (kd->decrypt_key, (u8x16u *) ciphertext, (u8x16u *) plaintext,
	       (u8x16u *) iv, (int) len, rounds);
#endif
}

static_always_inline void
clib_aes128_cbc_decrypt (const aes_cbc_key_data_t *kd, const u8 *ciphertext,
			 uword len, const u8 *iv, u8 *plaintext)
{
  clib_aes_cbc_decrypt (kd, ciphertext, len, iv, AES_KEY_128, plaintext);
}

static_always_inline void
clib_aes192_cbc_decrypt (const aes_cbc_key_data_t *kd, const u8 *ciphertext,
			 uword len, const u8 *iv, u8 *plaintext)
{
  clib_aes_cbc_decrypt (kd, ciphertext, len, iv, AES_KEY_192, plaintext);
}

static_always_inline void
clib_aes256_cbc_decrypt (const aes_cbc_key_data_t *kd, const u8 *ciphertext,
			 uword len, const u8 *iv, u8 *plaintext)
{
  clib_aes_cbc_decrypt (kd, ciphertext, len, iv, AES_KEY_256, plaintext);
}

#endif /* __crypto_aes_cbc_h__ */
