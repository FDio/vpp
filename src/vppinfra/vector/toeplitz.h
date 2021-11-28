/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_toeplitz_h
#define included_vector_toeplitz_h
#include <vppinfra/clib.h>

typedef struct
{
  u16 key_length;
  u16 gfni_offset;
  u8 data[];
} clib_toeplitz_hash_key_t;

clib_toeplitz_hash_key_t *clib_toeplitz_hash_key_init (u8 *key, u32 keylen);
void clib_toeplitz_hash_key_free (clib_toeplitz_hash_key_t *k);

#if defined(__GFNI__) && defined(__AVX512F__)

#define u64x8_gf2p8_affine(d, m, imm)                                         \
  (u64x8) _mm512_gf2p8affine_epi64_epi8 ((__m512i) (d), (__m512i) (m), imm)

#endif

#ifdef CLIB_HAVE_VEC256
static_always_inline u32x8
toeplitz_hash_one_x8 (u32x8 hash, u64x4 v4, u8 data, u8 off)
{
  u32x8 v8 = u32x8_shuffle2 (v4 << (off * 8), v4 << (off * 8 + 4),
			     /*uppper 32 bits of each u64 in reverse order */
			     15, 13, 11, 9, 7, 5, 3, 1);

#ifdef CLIB_HAVE_VEC256_MASK_BITWISE_OPS
  return u32x8_mask_xor (hash, v8, data);
#else
  static const u32x8 bits = { 1, 2, 4, 8, 16, 32, 64, 128 };
  return hash ^ (((u32x8_splat (data) & bits) != u32x8_zero ()) & v8);
#endif
}
#endif

static_always_inline u32
clib_toeplitz_hash (clib_toeplitz_hash_key_t *k, u8 *data, int n_bytes)
{
  u8 *key = k->data;
  /* key must be 4 bytes longer than data */
  ASSERT (k->key_length - n_bytes >= 4);

#if defined(__GFNI__) && defined(__AVX512F__)
  u8x64 a, b, dv;
  u64x8 xor_sum_x8 = {};
  u64x8u *m = (u64x8u *) ((u8 *) k + k->gfni_offset);

  u8x64 idx = { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x05,
		0x02, 0x03, 0x04, 0x05, 0x03, 0x04, 0x05, 0x06, 0x03, 0x04,
		0x05, 0x06, 0x04, 0x05, 0x06, 0x07, 0x04, 0x05, 0x06, 0x07,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x06, 0x07,
		0x08, 0x09, 0x06, 0x07, 0x08, 0x09, 0x07, 0x08, 0x09, 0x0a,
		0x07, 0x08, 0x09, 0x0a };

  /* move data ptr backwards for 3 byte so mask load "prepends" three zeros */
  data -= 3;
  n_bytes += 3;

  if (n_bytes < 64)
    {
      dv = u8x64_mask_load_zero ((u8 *) data, pow2_mask (n_bytes - 3) << 3);
      goto last8;
    }

  dv = u8x64_mask_load_zero ((u8 *) data, -1ULL << 3);
next56:
  a = u8x64_permute (idx, dv);
  b = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 1));
  xor_sum_x8 = u64x8_xor3 (xor_sum_x8, u64x8_gf2p8_affine (a, m[0], 0),
			   u64x8_gf2p8_affine (b, m[1], 0));

  a = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 2));
  b = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 3));
  xor_sum_x8 = u64x8_xor3 (xor_sum_x8, u64x8_gf2p8_affine (a, m[2], 0),
			   u64x8_gf2p8_affine (b, m[3], 0));

  a = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 4));
  b = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 5));
  xor_sum_x8 = u64x8_xor3 (xor_sum_x8, u64x8_gf2p8_affine (a, m[4], 0),
			   u64x8_gf2p8_affine (b, m[5], 0));

  a = u8x64_permute (idx, (u8x64) u64x8_align_right (dv, dv, 6));
  xor_sum_x8 ^= u64x8_gf2p8_affine (a, m[6], 0);
  n_bytes -= 56;
  data += 56;
  m += 7;

  if (n_bytes >= 64)
    {
      dv = *(u8x64u *) data;
      goto next56;
    }

  if (n_bytes == 0)
    goto done;

  dv = u8x64_mask_load_zero ((u8 *) data, pow2_mask (n_bytes));
last8:
  a = u8x64_permute (idx, dv);
  xor_sum_x8 ^= u64x8_gf2p8_affine (a, m[0], 0);
  n_bytes -= 8;

  if (n_bytes > 0)
    {
      m += 1;
      dv = (u8x64) u64x8_align_right (u64x8_zero (), dv, 1);
      goto last8;
    }

done:
  /* horizontal xor */
  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 4);
  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 2);
  return xor_sum_x8[0] ^ xor_sum_x8[1];
#elif defined(CLIB_HAVE_VEC256)
  u64x4 v4, shift = { 0, 1, 2, 3 };
  u32x8 hash8 = {};
  u32x4 hash4;

  while (n_bytes >= 4)
    {
      v4 = u64x4_splat (clib_net_to_host_u64 (*(u64u *) key)) << shift;

      hash8 = toeplitz_hash_one_x8 (hash8, v4, data[0], 0);
      hash8 = toeplitz_hash_one_x8 (hash8, v4, data[1], 1);
      hash8 = toeplitz_hash_one_x8 (hash8, v4, data[2], 2);
      hash8 = toeplitz_hash_one_x8 (hash8, v4, data[3], 3);

      data += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      u64 v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;

      if (n_bytes == 3)
	{
	  v |= (u64) key[5] << 16;
	  v |= (u64) key[6] << 8;
	  v4 = u64x4_splat (v) << shift;
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[0], 0);
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[1], 1);
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[2], 2);
	}
      else if (n_bytes == 2)
	{
	  v |= (u64) key[5] << 16;
	  v4 = u64x4_splat (v) << shift;
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[0], 0);
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[1], 1);
	}
      else
	{
	  v4 = u64x4_splat (v) << shift;
	  hash8 = toeplitz_hash_one_x8 (hash8, v4, data[0], 0);
	}
    }

  hash4 = u32x8_extract_lo (hash8) ^ u32x8_extract_hi (hash8);
  hash4 ^= (u32x4) u8x16_align_right (hash4, hash4, 8);
  hash4 ^= (u32x4) u8x16_align_right (hash4, hash4, 4);
  return hash4[0];

#endif
  u64 v, hash = 0;

  while (n_bytes >= 4)
    {
      v = clib_net_to_host_u64 (*(u64u *) key);

      for (u8 bit = 1 << 7, byte = data[0]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[1]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[2]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[3]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;

      data += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;
      for (u8 bit = 1 << 7, byte = data[0]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      if (n_bytes > 1)
	{
	  v |= (u64) key[5] << 24;
	  for (u8 bit = 1 << 7, byte = data[1]; bit; bit >>= 1, v <<= 1)
	    hash ^= byte & bit ? v : 0;
	}
      if (n_bytes > 2)
	{
	  v |= (u64) key[6] << 24;
	  for (u8 bit = 1 << 7, byte = data[2]; bit; bit >>= 1, v <<= 1)
	    hash ^= byte & bit ? v : 0;
	}
    }
  return hash >> 32;
}

#endif
