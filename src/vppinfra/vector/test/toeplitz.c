/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>

/* secret key and test cases taken from:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/verifying-the-rss-hash-calculation
 */
static u8 secret_key[] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67,
  0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb,
  0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
  0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

typedef struct
{
  u32 sip;
  u32 dip;
  u16 sport;
  u16 dport;
} __clib_packed ip4_key_t;

typedef struct
{
  ip4_key_t key;
  u32 hash_2t;
  u32 hash_4t;
} ip4_test_t;

#define _IP4(a, b, c, d) ((d) << 24 | (c) << 16 | (b) << 8 | (a))
#define _PORT(a)	 ((a) >> 8 | (((a) &0xff) << 8))

static ip4_test_t ip4_tests[] = {
  {
    .key.dip = _IP4 (161, 142, 100, 80),
    .key.dport = _PORT (1766),
    .key.sip = _IP4 (66, 9, 149, 187),
    .key.sport = _PORT (2794),
    .hash_2t = 0x323e8fc2,
    .hash_4t = 0x51ccc178,
  },
};

#ifdef CLIB_HAVE_VEC256
static_always_inline u32x8
toeplitz_hash_one_x8 (u32x8 hash, u64x4 v4, u8 data, u8 off)
{
  u32x8 v8 = u32x8_shuffle (v4 << (off * 8), v4 << (off * 8 + 4),
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
clib_toeplitz_hash (u8 *key, u32 keylen, u8 *data, u32 n_bytes)
{
  /* key must be 4 bytes longer than data */
  ASSERT (keylen - n_bytes >= 4);

#ifdef CLIB_HAVE_VEC256
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
  ASSERT (n_bytes == 0);
  return hash >> 32;
}

static clib_error_t *
test_clib_toeplitz_hash (clib_error_t *err)
{
  for (int i = 0; i < ARRAY_LEN (ip4_tests); i++)
    {
      u32 r;
      r = clib_toeplitz_hash (secret_key, sizeof (secret_key),
			      (u8 *) &ip4_tests[i].key, 8);
      if (ip4_tests[i].hash_2t != r)
	return clib_error_return (err,
				  "wrong 2 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_2t, r);

      r = clib_toeplitz_hash (secret_key, sizeof (secret_key),
			      (u8 *) &ip4_tests[i].key, 12);
      if (ip4_tests[i].hash_4t != r)
	return clib_error_return (err,
				  "wrong 4 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_4t, r);
    }

  return err;
}

REGISTER_TEST (clib_toeplitz_hash) = {
  .name = "clib_toeplitz_hash",
  .fn = test_clib_toeplitz_hash,
};
