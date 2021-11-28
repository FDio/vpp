/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>

/* secret key and test cases taken from:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/verifying-the-rss-hash-calculation
 */
static u8 sec_key[] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67,
  0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb,
  0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
  0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

typedef struct
{
  u32 sip, dip;
  u16 sport, dport;
} __clib_packed ip4_key_t;

typedef struct
{
  ip4_key_t key;
  u32 hash_2t, hash_4t;
} ip4_test_t;

typedef struct
{
  u16 sip[8], dip[8];
  u16 sport, dport;
} __clib_packed ip6_key_t;

typedef struct
{
  ip6_key_t key;
  u32 hash_2t, hash_4t;
} ip6_test_t;

#define N_IP4_TESTS    5
#define N_IP6_TESTS    3
#define N_LENGTH_TESTS 240

#ifndef CLIB_MARCH_VARIANT
#define _IP4(a, b, c, d) ((d) << 24 | (c) << 16 | (b) << 8 | (a))
#define _IP6(a, b, c, d, e, f, g, h)                                          \
  {                                                                           \
    (u16) ((a) << 8) | (u8) ((a) >> 8), (u16) ((b) << 8) | (u8) ((b) >> 8),   \
      (u16) ((c) << 8) | (u8) ((c) >> 8), (u16) ((d) << 8) | (u8) ((d) >> 8), \
      (u16) ((e) << 8) | (u8) ((e) >> 8), (u16) ((f) << 8) | (u8) ((f) >> 8), \
      (u16) ((g) << 8) | (u8) ((g) >> 8), (u16) ((h) << 8) | (u8) ((h) >> 8), \
  }
#define _PORT(a) ((a) >> 8 | (((a) &0xff) << 8))

const ip4_test_t ip4_tests[N_IP4_TESTS] = {
  /* ipv4 tests */
  {
    .key.sip = _IP4 (66, 9, 149, 187),
    .key.dip = _IP4 (161, 142, 100, 80),
    .key.sport = _PORT (2794),
    .key.dport = _PORT (1766),
    .hash_2t = 0x323e8fc2,
    .hash_4t = 0x51ccc178,
  },
  {
    .key.sip = _IP4 (199, 92, 111, 2),
    .key.dip = _IP4 (65, 69, 140, 83),
    .key.sport = _PORT (14230),
    .key.dport = _PORT (4739),
    .hash_2t = 0xd718262a,
    .hash_4t = 0xc626b0ea,
  },
  {
    .key.sip = _IP4 (24, 19, 198, 95),
    .key.dip = _IP4 (12, 22, 207, 184),
    .key.sport = _PORT (12898),
    .key.dport = _PORT (38024),
    .hash_2t = 0xd2d0a5de,
    .hash_4t = 0x5c2b394a,
  },
  {
    .key.sip = _IP4 (38, 27, 205, 30),
    .key.dip = _IP4 (209, 142, 163, 6),
    .key.sport = _PORT (48228),
    .key.dport = _PORT (2217),
    .hash_2t = 0x82989176,
    .hash_4t = 0xafc7327f,
  },
  {
    .key.sip = _IP4 (153, 39, 163, 191),
    .key.dip = _IP4 (202, 188, 127, 2),
    .key.sport = _PORT (44251),
    .key.dport = _PORT (1303),
    .hash_2t = 0x5d1809c5,
    .hash_4t = 0x10e828a2,
  }
};

const ip6_test_t ip6_tests[N_IP6_TESTS] = {
  {
    .key.sip = _IP6 (0x3ffe, 0x2501, 0x200, 0x1fff, 0, 0, 0, 7),
    .key.dip = _IP6 (0x3ffe, 0x2501, 0x200, 3, 0, 0, 0, 1),
    .key.sport = _PORT (2794),
    .key.dport = _PORT (1766),
    .hash_2t = 0x2cc18cd5,
    .hash_4t = 0x40207d3d,
  },
  {
    .key.sip = _IP6 (0x3ffe, 0x501, 8, 0, 0x260, 0x97ff, 0xfe40, 0xefab),
    .key.dip = _IP6 (0xff02, 0, 0, 0, 0, 0, 0, 1),
    .key.sport = _PORT (14230),
    .key.dport = _PORT (4739),
    .hash_2t = 0x0f0c461c,
    .hash_4t = 0xdde51bbf,
  },
  {
    .key.sip = _IP6 (0x3ffe, 0x1900, 0x4545, 3, 0x200, 0xf8ff, 0xfe21, 0x67cf),
    .key.dip = _IP6 (0xfe80, 0, 0, 0, 0x200, 0xf8ff, 0xfe21, 0x67cf),
    .key.sport = _PORT (44251),
    .key.dport = _PORT (38024),
    .hash_2t = 0x4b61e985,
    .hash_4t = 0x02d1feef,
  }
};

const u32 length_test_hashes[N_LENGTH_TESTS] = {
  0x00000000, 0x00000000, 0x2b6d12ad, 0x9de4446e, 0x061f00bf, 0xad7ed8f7,
  0x4bc7b068, 0x231fc545, 0xdbd97a33, 0xcdab29e7, 0x2d665c0c, 0x31e28ed7,
  0x14e19218, 0x5aa89f0f, 0xd47de07f, 0x355ec712, 0x7e1cbfc0, 0xf84de19d,
  0xbcf66bd3, 0x104086c6, 0x71900b34, 0xcd2f9819, 0xeae68ebb, 0x54d63b4c,
  0x5f865a2c, 0x9d6ded08, 0xe00b0912, 0x3fcf07a6, 0x3bd9ca93, 0x3f4f3bbb,
  0xd0b82624, 0xa28a08e1, 0xa585969f, 0x0c8f4a71, 0x5dce7bdd, 0x4fcf2a6d,
  0x91c89ae9, 0xbef8a24d, 0x8e3d30fe, 0xc8027848, 0xc1e7e513, 0xa12bd3d9,
  0x46700bb4, 0xc6339dab, 0x970805ad, 0xfcb50ac8, 0xc6db4f44, 0x792e2987,
  0xacfb7836, 0xa25ec529, 0x957d7beb, 0x6732809a, 0x891836ed, 0xeefb83b2,
  0xca96b40b, 0x93fd5abd, 0x9076f922, 0x59adb4eb, 0x9705aafb, 0x282719b1,
  0xdda9cb8a, 0x3f499131, 0x47491130, 0x30ef0759, 0xad1cf855, 0x428aa312,
  0x4200240a, 0x71a72857, 0x16b30c36, 0x10cca9a3, 0x166f091e, 0x30e00560,
  0x8acd20ba, 0xfa633d76, 0x0fe32eb7, 0xdcc0122f, 0x20aa8ab0, 0x62b2a9af,
  0x7a6c80a6, 0x27e87268, 0x95b797a8, 0x25d18ccd, 0x68a7fb00, 0xc54bcdad,
  0x3bd0e717, 0xf0df54c9, 0x780daadf, 0x7b435605, 0x150c1e10, 0x8a892e54,
  0x9d27cb25, 0xe23383a5, 0x57aac408, 0x83b8abf8, 0x560f33af, 0xd5cb3307,
  0x79ae8edc, 0x9b127665, 0x320f18bd, 0x385d636b, 0xbd1b2dbf, 0x97679888,
  0x738894a4, 0xeba2afb0, 0xfa7c2d50, 0xb6741aa1, 0x28922bba, 0x7783242b,
  0xa694cca2, 0xa32781c0, 0x696cd670, 0xa714d72f, 0xea34d35a, 0xc5aed81e,
  0x0438433a, 0xc1939ab2, 0xb51c123a, 0x121426b9, 0x1add93ba, 0x50c56b6a,
  0x7e90902a, 0xae3abd85, 0x2f7a0088, 0xb45cf6f9, 0x80070094, 0x8bd46467,
  0xdfd1b762, 0x0bb25856, 0x48eefe84, 0x0989dbb9, 0xfc32472b, 0x965fec6b,
  0x5a256bd0, 0x6df7127a, 0x7856d0d6, 0xedc82bd3, 0x1b563b96, 0xc73eace7,
  0xba4c0a93, 0xdfd6dd97, 0x923c41db, 0x14926ca6, 0x22e52ab1, 0x22852a66,
  0x79606b9c, 0xb0f22b23, 0xb46354ba, 0x9c3cd931, 0x03a92bd6, 0x84000834,
  0x5425df65, 0xf4dd3fc9, 0x391cc873, 0xa560b52e, 0x828037d9, 0x31323dd5,
  0x5c6e3147, 0x28e21f85, 0xa431eb51, 0xf468c4a3, 0x9bea1d2e, 0x43d9109c,
  0x5bb9b081, 0xe0825675, 0xc9c92591, 0xd29fc812, 0x03136bc9, 0x5e005a1f,
  0x6d821ed8, 0x3f0bfcc4, 0x24774162, 0x893bde94, 0x6475efea, 0x6711538e,
  0xc4755f6d, 0x9425ebe2, 0xacf471b4, 0xb947ab0c, 0x1f78c455, 0x372b3ed7,
  0xb3ec24d7, 0x18c4459f, 0xa8ff3695, 0xe4aa2b85, 0x8a52ad7e, 0xe05e8177,
  0x7aa348ed, 0x3e4ac6aa, 0x17dcf8a5, 0x93b933b0, 0x8f7413ec, 0xc77bfe61,
  0xfdb72874, 0x4370f138, 0xdf3462ad, 0xc8970a59, 0xb4a9fed8, 0xa2ddc39b,
  0xd61db62a, 0x95c5fc1b, 0x7b22e6e0, 0x1969702c, 0x7992aebb, 0x59d7c225,
  0x0e16db0b, 0x9f2afc21, 0x246cf66b, 0xb3d6569d, 0x29c532d7, 0xe155747a,
  0xe38d7872, 0xea704969, 0xb69095b0, 0x1b198efd, 0x55daab76, 0xa2a377b6,
  0xb31aa2fa, 0x48b73c41, 0xf0cc501a, 0x9c9ca831, 0x1b591b99, 0xb2d8d22f,
  0xab4b5f69, 0x4fe00e71, 0xdf5480bd, 0x982540d7, 0x7f34ea4f, 0xd7be66e1,
  0x9d2ab1ba, 0x1ba62e12, 0xee3fb36c, 0xf28d7c5a, 0x756311eb, 0xc68567f2,
  0x7b6ea177, 0xc398d9f3
};

#else
extern const ip4_test_t ip4_tests[N_IP4_TESTS];
extern const ip6_test_t ip6_tests[N_IP6_TESTS];
extern const u32 length_test_hashes[N_LENGTH_TESTS];
#endif

#ifdef __GFNI__

static_always_inline __clib_unused u64x8
u64x8_byte_swap (u64x8 v)
{
  u8x64 swap = {
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
  };
  return (u64x8) _mm512_shuffle_epi8 ((__m512i) v, (__m512i) swap);
}

#define u64x8_shuffle(v1, v2, ...)                                            \
  (u64x8) __builtin_shufflevector ((u64x8) (v1), (u64x8) (v2), __VA_ARGS__)
#define u32x16_shuffle(v1, v2, ...)                                           \
  (u32x16) __builtin_shufflevector ((u32x16) (v1), (u32x16) (v2), __VA_ARGS__)
#define u8x64_shuffle(v1, v2, ...)                                            \
  (u8x64) __builtin_shufflevector ((u8x64) (v1), (u8x64) (v2), __VA_ARGS__)

static_always_inline void
clib_toeplitz_hash_key_expand_8 (u8x16 kv, u64x8u *m)
{
  u64x8 kv4, a, b, shift = { 0, 1, 2, 3, 4, 5, 6, 7 };

  kv4 = u8x64_splat_u8x16 (kv);

  /* clang-format off */
  /* create 8 byte-swapped copies of the bytes 0 - 7 */
  a = (u64x8) u8x64_shuffle (kv4, kv4,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0);
  /* create 8 byte-swapped copies of the bytes 4 - 11 */
  b = (u64x8) u8x64_shuffle (kv4, kv4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4,
    0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4);
  /* clang-format on */

  /* shift each 64-bit element for 0 - 7 bits */
  a <<= shift;
  b <<= shift;

  /* clang-format off */
  /* construct eight 8x8 bit matrix used by gf2p8affine */
  * m = (u64x8) u8x64_shuffle (a, b,
    0x07, 0x0f, 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f,
    0x06, 0x0e, 0x16, 0x1e, 0x26, 0x2e, 0x36, 0x3e,
    0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d,
    0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c,
    0x47, 0x4f, 0x57, 0x5f, 0x67, 0x6f, 0x77, 0x7f,
    0x46, 0x4e, 0x56, 0x5e, 0x66, 0x6e, 0x76, 0x7e,
    0x45, 0x4d, 0x55, 0x5d, 0x65, 0x6d, 0x75, 0x7d,
    0x44, 0x4c, 0x54, 0x5c, 0x64, 0x6c, 0x74, 0x7c);
  /* clang-format on */
}

#ifdef __GFNI__
void __clib_section (".foo")
foo (u8 *p, u64 *m)
{
  u8x16 kv = *(u8x16u *) p;
  clib_toeplitz_hash_key_expand_8 (kv, (u64x8u *) m);
  kv = *(u8x16u *) p + 8;
  clib_toeplitz_hash_key_expand_8 (kv, (u64x8u *) (m + 64));
  kv = *(u8x16u *) p + 16;
  clib_toeplitz_hash_key_expand_8 (kv, (u64x8u *) (m + 128));
  kv = *(u8x16u *) p + 24;
  clib_toeplitz_hash_key_expand_8 (kv, (u64x8u *) (m + 192));
}
#endif

void
clib_toeplitz_hash_key_expand (u64 *matrixes, u8 *key, int size)
{
  u64x8u *m = (u64x8u *) matrixes;
  u8x16 kv;

  while (size >= 16)
    {
      clib_toeplitz_hash_key_expand_8 (*(u64x2u *) key, m);
      key += 8;
      m++;
      size -= 8;
    }

  kv = u8x16_mask_load_zero (key, pow2_mask (size));
  clib_toeplitz_hash_key_expand_8 (kv, m);
  clib_toeplitz_hash_key_expand_8 (u8x16_align_right (kv, kv, 8), m + 1);
}

always_inline u8x64
u8x64_permute (u8x64 v, u8x64 idx)
{
  return (u8x64) _mm512_permutexvar_epi8 ((__m512i) v, (__m512i) idx);
}

static inline u32
clib_toeplitz_hash_gfni (const u64 *mm, const u8 *data, int len)
{
  u8x64 perm, dv;
  u64x8 xor_sum_x8 = {};
  u64x8u *m = (u64x8u *) mm;

  u8x64 idx = { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x05,
		0x02, 0x03, 0x04, 0x05, 0x03, 0x04, 0x05, 0x06, 0x03, 0x04,
		0x05, 0x06, 0x04, 0x05, 0x06, 0x07, 0x04, 0x05, 0x06, 0x07,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x06, 0x07,
		0x08, 0x09, 0x06, 0x07, 0x08, 0x09, 0x07, 0x08, 0x09, 0x0a,
		0x07, 0x08, 0x09, 0x0a };

  /* move data ptr backwards for 3 byte so mask load "prepends" three zeros */
  data -= 3;
  len += 3;

  if (len < 64)
    {
      dv = u8x64_mask_load_zero ((u8 *) data, pow2_mask (len - 3) << 3);
      goto last8;
    }

  dv = u8x64_mask_load_zero ((u8 *) data, -1ULL << 3);
next56:
  perm = u8x64_permute (idx, dv);
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[0], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 1));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[1], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 2));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[2], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 3));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[3], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 4));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[4], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 5));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[5], 0);
  perm = u8x64_permute (idx, u64x8_align_right (dv, dv, 6));
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[6], 0);
  data += 56;
  len -= 56;
  m += 7;

  if (len >= 64)
    {
      dv = *(u8x64u *) data;
      goto next56;
    }

  if (len == 0)
    goto done;

  dv = u8x64_mask_load_zero ((u8 *) data, pow2_mask (len));
last8:
  perm = u8x64_permute (idx, dv);
  xor_sum_x8 ^= _mm512_gf2p8affine_epi64_epi8 (perm, m[0], 0);
  len -= 8;

  if (len > 0)
    {
      m += 1;
      dv = u64x8_align_right (u64x8_zero (), dv, 1);
      goto last8;
    }

done:
  /* horizontal xor */
  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 4);
  xor_sum_x8 ^= u64x8_align_right (xor_sum_x8, xor_sum_x8, 2);
  return xor_sum_x8[0] ^ xor_sum_x8[1];
}

#endif

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

#ifdef __GFNI__
  u64 m[256];
  clib_toeplitz_hash_key_expand (m, key, keylen + 4);
  return clib_toeplitz_hash_gfni (m, data, n_bytes);
#endif

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

__clib_test_fn u32
wrapper (u8 *key, u32 keylen, u8 *data, u32 n_bytes)
{
  return clib_toeplitz_hash (key, keylen, data, n_bytes);
}

static clib_error_t *
test_clib_toeplitz_hash (clib_error_t *err)
{
  u32 r;
  int n_key_copies, bigkey_len, bigdata_len;
  u8 *bigkey, *bigdata;

  for (int i = 0; i < N_IP4_TESTS; i++)
    {
      r = wrapper (sec_key, sizeof (sec_key), (u8 *) &ip4_tests[i].key, 8);
      if (ip4_tests[i].hash_2t != r)
	return clib_error_return (err,
				  "wrong IPv4 2 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_2t, r);

      r = wrapper (sec_key, sizeof (sec_key), (u8 *) &ip4_tests[i].key, 12);
      if (ip4_tests[i].hash_4t != r)
	return clib_error_return (err,
				  "wrong IPv4 4 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_4t, r);
    }

  for (int i = 0; i < N_IP6_TESTS; i++)
    {
      r = wrapper (sec_key, sizeof (sec_key), (u8 *) &ip6_tests[i].key, 32);
      if (ip6_tests[i].hash_2t != r)
	return clib_error_return (err,
				  "wrong IPv6 2 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip6_tests[i].hash_2t, r);

      r = wrapper (sec_key, sizeof (sec_key), (u8 *) &ip6_tests[i].key, 36);
      if (ip6_tests[i].hash_4t != r)
	return clib_error_return (err,
				  "wrong IPv6 4 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip6_tests[i].hash_4t, r);
    }

  n_key_copies = 6;
  bigkey_len = sizeof (sec_key) * n_key_copies;
  bigdata_len = bigkey_len - 4;
  bigkey = clib_mem_alloc (bigkey_len);
  bigdata = clib_mem_alloc (bigdata_len);

  for (int i = 0; i < n_key_copies; i++)
    clib_memcpy (bigkey + i * sizeof (sec_key), sec_key, sizeof (sec_key));

  for (int i = 0; i < bigdata_len; i++)
    bigdata[i] = (u8) i;

  for (int i = 0; i < N_LENGTH_TESTS - 4; i++)
    {
      r = wrapper (bigkey, i + 4, bigdata, i);
      if (length_test_hashes[i] != r)
	{
	  err = clib_error_return (err,
				   "wrong length test hash for length %u, "
				   "calculated 0x%08x expected 0x%08x "
				   "xor 0x%08x",
				   i, r, length_test_hashes[i],
				   r ^ length_test_hashes[i]);
	  goto done;
	}
    }

done:
  clib_mem_free (bigkey);
  clib_mem_free (bigdata);
  return err;
}

REGISTER_TEST (clib_toeplitz_hash) = {
  .name = "clib_toeplitz_hash",
  .fn = test_clib_toeplitz_hash,
};
