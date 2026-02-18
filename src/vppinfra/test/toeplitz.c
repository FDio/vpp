/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/toeplitz.h>

/* secret key and test cases taken from:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/verifying-the-rss-hash-calculation
 */

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

__test_funct_fn u32
wrapper (clib_toeplitz_hash_key_t *k, u8 *data, u32 n_bytes)
{
  return clib_toeplitz_hash (k, data, n_bytes);
}

__test_funct_fn void
wrapper_x4 (clib_toeplitz_hash_key_t *k, u8 *d0, u8 *d1, u8 *d2, u8 *d3,
	    u32 *h0, u32 *h1, u32 *h2, u32 *h3, u32 n_bytes)
{
  clib_toeplitz_hash_x4 (k, d0, d1, d2, d3, h0, h1, h2, h3, n_bytes);
}

static clib_error_t *
test_clib_toeplitz_hash (clib_error_t *err)
{
  u32 r;
  int n_key_copies, bigkey_len, bigdata_len;
  u8 *bigkey, *bigdata;
  clib_toeplitz_hash_key_t *k;

  k = clib_toeplitz_hash_key_init (0, 0);

  for (int i = 0; i < N_IP4_TESTS; i++)
    {
      r = wrapper (k, (u8 *) &ip4_tests[i].key, 8);
      if (ip4_tests[i].hash_2t != r)
	return clib_error_return (err,
				  "wrong IPv4 2 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_2t, r);

      r = wrapper (k, (u8 *) &ip4_tests[i].key, 12);
      if (ip4_tests[i].hash_4t != r)
	return clib_error_return (err,
				  "wrong IPv4 4 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip4_tests[i].hash_4t, r);
    }

  for (int i = 0; i < N_IP6_TESTS; i++)
    {
      r = wrapper (k, (u8 *) &ip6_tests[i].key, 32);
      if (ip6_tests[i].hash_2t != r)
	return clib_error_return (err,
				  "wrong IPv6 2 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip6_tests[i].hash_2t, r);

      r = wrapper (k, (u8 *) &ip6_tests[i].key, 36);
      if (ip6_tests[i].hash_4t != r)
	return clib_error_return (err,
				  "wrong IPv6 4 tuple hash for test %u, "
				  "calculated 0x%08x expected 0x%08x",
				  i, ip6_tests[i].hash_4t, r);
    }

  n_key_copies = 6;
  bigkey_len = k->key_length * n_key_copies;
  bigdata_len = bigkey_len - 4;
  bigkey = test_mem_alloc_and_splat (k->key_length, n_key_copies, k->data);
  bigdata = test_mem_alloc_and_fill_inc_u8 (bigdata_len, 0, 0);
  u32 key_len = k->key_length;

  clib_toeplitz_hash_key_free (k);
  k = clib_toeplitz_hash_key_init (bigkey, n_key_copies * key_len);

  for (int i = 0; i < N_LENGTH_TESTS - 4; i++)
    {
      r = wrapper (k, bigdata, i);
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
  clib_toeplitz_hash_key_free (k);
  return err;
}

void __test_perf_fn
perftest_fixed_12byte (test_perf_t *tp)
{
  u32 n = tp->n_ops;
  u8 *data = test_mem_alloc_and_splat (12, n, (void *) &ip4_tests[0].key);
  u8 *res = test_mem_alloc (4 * n);
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    ((u32 *) res)[i] = clib_toeplitz_hash (k, data + i * 12, 12);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

void __test_perf_fn
perftest_fixed_36byte (test_perf_t *tp)
{
  u32 n = tp->n_ops;
  u8 *data = test_mem_alloc_and_splat (36, n, (void *) &ip6_tests[0].key);
  u8 *res = test_mem_alloc (4 * n);
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    ((u32 *) res)[i] = clib_toeplitz_hash (k, data + i * 36, 36);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

void __test_perf_fn
perftest_variable_size (test_perf_t *tp)
{
  u32 key_len, n_keys, n = tp->n_ops;
  u8 *key, *data = test_mem_alloc (n);
  u32 *res = test_mem_alloc (sizeof (u32));
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  k = clib_toeplitz_hash_key_init (0, 0);
  key_len = k->key_length;
  n_keys = ((n + 4) / k->key_length) + 1;
  key = test_mem_alloc_and_splat (n_keys, key_len, k->data);
  clib_toeplitz_hash_key_free (k);
  k = clib_toeplitz_hash_key_init (key, key_len * n_keys);

  test_perf_event_enable (tp);
  res[0] = clib_toeplitz_hash (k, data, n);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

REGISTER_TEST (clib_toeplitz_hash) = {
  .name = "clib_toeplitz_hash",
  .fn = test_clib_toeplitz_hash,
  .perf_tests = PERF_TESTS ({ .name = "fixed (per 12 byte tuple)",
			      .n_ops = 1024,
			      .fn = perftest_fixed_12byte },
			    { .name = "fixed (per 36 byte tuple)",
			      .n_ops = 1024,
			      .fn = perftest_fixed_36byte },
			    { .name = "variable size (per byte)",
			      .n_ops = 16384,
			      .fn = perftest_variable_size }),
};

static clib_error_t *
test_clib_toeplitz_hash_x4 (clib_error_t *err)
{
  u32 r[4];
  int n_key_copies, bigkey_len, bigdata_len;
  u8 *bigkey, *bigdata0, *bigdata1, *bigdata2, *bigdata3;
  clib_toeplitz_hash_key_t *k;

  k = clib_toeplitz_hash_key_init (0, 0);

  wrapper_x4 (k, (u8 *) &ip4_tests[0].key, (u8 *) &ip4_tests[1].key,
	      (u8 *) &ip4_tests[2].key, (u8 *) &ip4_tests[3].key, r, r + 1,
	      r + 2, r + 3, 8);

  if (ip4_tests[0].hash_2t != r[0] || ip4_tests[1].hash_2t != r[1] ||
      ip4_tests[2].hash_2t != r[2] || ip4_tests[3].hash_2t != r[3])
    return clib_error_return (err,
			      "wrong IPv4 2 tuple x4 hash "
			      "calculated { 0x%08x, 0x%08x, 0x%08x, 0x%08x } "
			      "expected { 0x%08x, 0x%08x, 0x%08x, 0x%08x }",
			      ip4_tests[0].hash_2t, ip4_tests[1].hash_2t,
			      ip4_tests[2].hash_2t, ip4_tests[3].hash_2t, r[0],
			      r[1], r[2], r[3]);

  wrapper_x4 (k, (u8 *) &ip4_tests[0].key, (u8 *) &ip4_tests[1].key,
	      (u8 *) &ip4_tests[2].key, (u8 *) &ip4_tests[3].key, r, r + 1,
	      r + 2, r + 3, 12);

  if (ip4_tests[0].hash_4t != r[0] || ip4_tests[1].hash_4t != r[1] ||
      ip4_tests[2].hash_4t != r[2] || ip4_tests[3].hash_4t != r[3])
    return clib_error_return (err,
			      "wrong IPv4 4 tuple x4 hash "
			      "calculated { 0x%08x, 0x%08x, 0x%08x, 0x%08x } "
			      "expected { 0x%08x, 0x%08x, 0x%08x, 0x%08x }",
			      ip4_tests[0].hash_4t, ip4_tests[1].hash_4t,
			      ip4_tests[2].hash_4t, ip4_tests[3].hash_4t, r[0],
			      r[1], r[2], r[3]);

  wrapper_x4 (k, (u8 *) &ip6_tests[0].key, (u8 *) &ip6_tests[1].key,
	      (u8 *) &ip6_tests[2].key, (u8 *) &ip6_tests[0].key, r, r + 1,
	      r + 2, r + 3, 32);

  if (ip6_tests[0].hash_2t != r[0] || ip6_tests[1].hash_2t != r[1] ||
      ip6_tests[2].hash_2t != r[2] || ip6_tests[0].hash_2t != r[3])
    return clib_error_return (err,
			      "wrong IPv6 2 tuple x4 hash "
			      "calculated { 0x%08x, 0x%08x, 0x%08x, 0x%08x } "
			      "expected { 0x%08x, 0x%08x, 0x%08x, 0x%08x }",
			      ip6_tests[0].hash_2t, ip6_tests[1].hash_2t,
			      ip6_tests[2].hash_2t, ip6_tests[0].hash_2t, r[0],
			      r[1], r[2], r[3]);

  wrapper_x4 (k, (u8 *) &ip6_tests[0].key, (u8 *) &ip6_tests[1].key,
	      (u8 *) &ip6_tests[2].key, (u8 *) &ip6_tests[0].key, r, r + 1,
	      r + 2, r + 3, 36);

  if (ip6_tests[0].hash_4t != r[0] || ip6_tests[1].hash_4t != r[1] ||
      ip6_tests[2].hash_4t != r[2] || ip6_tests[0].hash_4t != r[3])
    return clib_error_return (err,
			      "wrong IPv6 4 tuple x4 hash "
			      "calculated { 0x%08x, 0x%08x, 0x%08x, 0x%08x } "
			      "expected { 0x%08x, 0x%08x, 0x%08x, 0x%08x }",
			      ip6_tests[0].hash_4t, ip6_tests[1].hash_4t,
			      ip6_tests[2].hash_4t, ip6_tests[0].hash_4t, r[0],
			      r[1], r[2], r[3]);

  n_key_copies = 6;
  bigkey_len = k->key_length * n_key_copies;
  bigdata_len = bigkey_len - 4;
  bigkey = test_mem_alloc_and_splat (k->key_length, n_key_copies, k->data);
  bigdata0 = test_mem_alloc_and_fill_inc_u8 (bigdata_len, 0, 0);
  bigdata1 = test_mem_alloc_and_fill_inc_u8 (bigdata_len, 0, 0);
  bigdata2 = test_mem_alloc_and_fill_inc_u8 (bigdata_len, 0, 0);
  bigdata3 = test_mem_alloc_and_fill_inc_u8 (bigdata_len, 0, 0);
  u32 key_len = k->key_length;

  clib_toeplitz_hash_key_free (k);
  k = clib_toeplitz_hash_key_init (bigkey, n_key_copies * key_len);

  for (int i = 0; i < N_LENGTH_TESTS - 4; i++)
    {
      wrapper_x4 (k, bigdata0, bigdata1, bigdata2, bigdata3, r, r + 1, r + 2,
		  r + 3, i);
      if (length_test_hashes[i] != r[0] || length_test_hashes[i] != r[1] ||
	  length_test_hashes[i] != r[2] || length_test_hashes[i] != r[3])
	{
	  err = clib_error_return (
	    err,
	    "wrong length test hash x4 for length %u, "
	    "calculated { 0x%08x, 0x%08x, 0x%08x, 0x%08x }, expected 0x%08x",
	    i, r[0], r[1], r[2], r[3], length_test_hashes[i]);
	  goto done;
	}
    }

done:
  clib_toeplitz_hash_key_free (k);
  return err;
}

void __test_perf_fn
perftest_fixed_12byte_x4 (test_perf_t *tp)
{
  u32 n = tp->n_ops / 4;
  u8 *d0 = test_mem_alloc_and_splat (12, n, (void *) &ip4_tests[0].key);
  u8 *d1 = test_mem_alloc_and_splat (12, n, (void *) &ip4_tests[1].key);
  u8 *d2 = test_mem_alloc_and_splat (12, n, (void *) &ip4_tests[2].key);
  u8 *d3 = test_mem_alloc_and_splat (12, n, (void *) &ip4_tests[3].key);
  u32 *h0 = test_mem_alloc (4 * n);
  u32 *h1 = test_mem_alloc (4 * n);
  u32 *h2 = test_mem_alloc (4 * n);
  u32 *h3 = test_mem_alloc (4 * n);
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    clib_toeplitz_hash_x4 (k, d0 + i * 12, d1 + i * 12, d2 + i * 12,
			   d3 + i * 12, h0 + i, h1 + i, h2 + i, h3 + i, 12);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

void __test_perf_fn
perftest_fixed_36byte_x4 (test_perf_t *tp)
{
  u32 n = tp->n_ops / 4;
  u8 *d0 = test_mem_alloc_and_splat (36, n, (void *) &ip6_tests[0].key);
  u8 *d1 = test_mem_alloc_and_splat (36, n, (void *) &ip6_tests[1].key);
  u8 *d2 = test_mem_alloc_and_splat (36, n, (void *) &ip6_tests[2].key);
  u8 *d3 = test_mem_alloc_and_splat (36, n, (void *) &ip6_tests[0].key);
  u32 *h0 = test_mem_alloc (4 * n);
  u32 *h1 = test_mem_alloc (4 * n);
  u32 *h2 = test_mem_alloc (4 * n);
  u32 *h3 = test_mem_alloc (4 * n);
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    clib_toeplitz_hash_x4 (k, d0 + i * 36, d1 + i * 36, d2 + i * 36,
			   d3 + i * 36, h0 + i, h1 + i, h2 + i, h3 + i, 36);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

void __test_perf_fn
perftest_variable_size_x4 (test_perf_t *tp)
{
  u32 key_len, n_keys, n = tp->n_ops / 4;
  u8 *key;
  u8 *d0 = test_mem_alloc (n);
  u8 *d1 = test_mem_alloc (n);
  u8 *d2 = test_mem_alloc (n);
  u8 *d3 = test_mem_alloc (n);
  u32 *h0 = test_mem_alloc (sizeof (u32));
  u32 *h1 = test_mem_alloc (sizeof (u32));
  u32 *h2 = test_mem_alloc (sizeof (u32));
  u32 *h3 = test_mem_alloc (sizeof (u32));
  clib_toeplitz_hash_key_t *k = clib_toeplitz_hash_key_init (0, 0);

  k = clib_toeplitz_hash_key_init (0, 0);
  key_len = k->key_length;
  n_keys = ((n + 4) / k->key_length) + 1;
  key = test_mem_alloc_and_splat (n_keys, key_len, k->data);
  clib_toeplitz_hash_key_free (k);
  k = clib_toeplitz_hash_key_init (key, key_len * n_keys);

  test_perf_event_enable (tp);
  clib_toeplitz_hash_x4 (k, d0, d1, d2, d3, h0, h1, h2, h3, n);
  test_perf_event_disable (tp);

  clib_toeplitz_hash_key_free (k);
}

REGISTER_TEST (clib_toeplitz_hash_x4) = {
  .name = "clib_toeplitz_hash_x4",
  .fn = test_clib_toeplitz_hash_x4,
  .perf_tests = PERF_TESTS ({ .name = "fixed (per 12 byte tuple)",
			      .n_ops = 1024,
			      .fn = perftest_fixed_12byte_x4 },
			    { .name = "fixed (per 36 byte tuple)",
			      .n_ops = 1024,
			      .fn = perftest_fixed_36byte_x4 },
			    { .name = "variable size (per byte)",
			      .n_ops = 16384,
			      .fn = perftest_variable_size_x4 }),
};
