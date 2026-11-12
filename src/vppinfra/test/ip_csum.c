/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/byte_order.h>
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/ip_csum.h>

typedef struct
{
  struct
  {
    u8 *src;
    u32 count;
  } chunk[5];
  u16 result;
} ip_csum_test_t;

static u8 test1[] = { 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40,
		      0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
		      0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0x00 };
#define TEST_LEN(x) (ARRAY_LEN (x) - 1)

static ip_csum_test_t tests[] = { {
				    .chunk[0].src = test1,
				    .chunk[0].count = TEST_LEN (test1),
				    .result = 0x61b8,
				  },
				  {
				    .chunk[0].src = test1,
				    .chunk[0].count = 1,
				    .chunk[1].src = test1 + 1,
				    .chunk[1].count = 2,
				    .chunk[2].src = test1 + 3,
				    .chunk[2].count = 3,
				    .chunk[3].src = test1 + 6,
				    .chunk[3].count = 4,
				    .chunk[4].src = test1 + 10,
				    .chunk[4].count = TEST_LEN (test1) - 10,
				    .result = 0x61b8,
				  },
				  {
				    .chunk[0].count = 1,
				    .result = 0xff0f,
				  },
				  {
				    .chunk[0].count = 2,
				    .result = 0x080f,
				  },
				  {
				    .chunk[0].count = 3,
				    .result = 0x0711,
				  },
				  {
				    .chunk[0].count = 4,
				    .result = 0x1210,
				  },
				  {
				    .chunk[0].count = 63,
				    .result = 0xda01,
				  },
				  {
				    .chunk[0].count = 64,
				    .result = 0xe100,
				  },
				  {
				    .chunk[0].count = 65,
				    .result = 0xe010,
				  },
				  {
				    .chunk[0].count = 65535,
				    .result = 0xfc84,
				  },
				  {
				    .chunk[0].count = 65536,
				    .result = 0xffff,
				  } };

static clib_error_t *
test_clib_ip_csum (clib_error_t *err)
{
  u8 *buf;
  buf = test_mem_alloc (65536);
  for (int i = 0; i < 65536; i++)
    buf[i] = 0xf0 + ((i * 7) & 0xf);

  for (int i = 0; i < ARRAY_LEN (tests); i++)
    {
      clib_ip_csum_t c = {};
      ip_csum_test_t *t = tests + i;
      u16 rv;

      for (int j = 0; j < ARRAY_LEN (((ip_csum_test_t *) 0)->chunk); j++)
	if (t->chunk[j].count > 0)
	  {
	    if (t->chunk[j].src == 0)
	      clib_ip_csum_chunk (&c, buf, t->chunk[j].count);
	    else
	      clib_ip_csum_chunk (&c, t->chunk[j].src, t->chunk[j].count);
	  }
      rv = clib_ip_csum_fold (&c);

      if (rv != tests[i].result)
	{
	  err = clib_error_return (err,
				   "bad checksum in test case %u (expected "
				   "0x%04x, calculated 0x%04x)",
				   i, tests[i].result, rv);
	  goto done;
	}
    }
done:
  return err;
}

static u16
ip_csum_reference (u8 *src, u32 count)
{
  u32 sum = 0;

  for (u32 i = 0; i < count; i += 2)
    sum += ((u16) src[i] << 8) + (i + 1 < count ? src[i + 1] : 0);
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return clib_host_to_net_u16 (~sum);
}

static clib_error_t *
test_clib_ip_csum_empty_chunk (clib_error_t *err)
{
  for (u8 odd = 0; odd < 2; odd++)
    {
      clib_ip_csum_t c = { .sum = 0x123456789abcdef0, .odd = odd };

      clib_ip_csum_chunk (&c, 0, 0);
      if (c.sum != 0x123456789abcdef0 || c.odd != odd)
	return clib_error_return (err, "empty checksum chunk modifies state (odd %u)", odd);
      clib_ip_csum_and_copy_chunk (&c, 0, 0, 0);
      if (c.sum != 0x123456789abcdef0 || c.odd != odd)
	return clib_error_return (err, "empty copy chunk modifies state (odd %u)", odd);
    }
  return err;
}

REGISTER_TEST (clib_ip_csum_empty_chunk) = {
  .name = "clib_ip_csum_empty_chunk",
  .fn = test_clib_ip_csum_empty_chunk,
};

static clib_error_t *
validate_ip_csum_and_copy (clib_error_t *err, u8 *src, u8 *dst, u32 count, u32 split, u32 offset)
{
  clib_ip_csum_t c = {};
  u16 expected = ip_csum_reference (src, count), actual;

  clib_memset_u8 (dst - 64, 0xff, count + 4096 + 64);
  if (split)
    {
      clib_ip_csum_and_copy_chunk (&c, src, dst, split);
      clib_ip_csum_and_copy_chunk (&c, 0, 0, 0);
      clib_ip_csum_and_copy_chunk (&c, src + split, dst + split, count - split);
      clib_ip_csum_and_copy_chunk (&c, 0, 0, 0);
      actual = clib_ip_csum_fold (&c);
    }
  else
    actual = clib_ip_csum_and_copy (dst, src, count);

  if (actual != expected)
    return clib_error_return (err,
			      "bad copy checksum (count %u, split %u, offset %u, "
			      "expected 0x%04x, calculated 0x%04x)",
			      count, split, offset, expected, actual);
  for (u32 i = 0; i < count; i++)
    if (dst[i] != src[i])
      return clib_error_return (err,
				"bad copy at byte %u (count %u, split %u, "
				"offset %u, expected 0x%02x, found 0x%02x)",
				i, count, split, offset, src[i], dst[i]);
  for (int i = -64; i < (int) count + 4096; i++)
    if ((i < 0 || i >= (int) count) && dst[i] != 0xff)
      return clib_error_return (err,
				"copy guard overwritten at byte %d (count %u, "
				"split %u, offset %u, found 0x%02x)",
				i, count, split, offset, dst[i]);
  return err;
}

static clib_error_t *
test_clib_ip_csum_and_copy (clib_error_t *err)
{
  static const u16 lengths[] = {
    255,  256,	257,  511,  512,  513,	1023, 1024, 1025, 1447, 1448, 1449,  1459,
    1460, 1461, 1981, 1982, 1983, 2047, 2048, 2049, 4095, 4096, 4097, 65534, 65535,
  };
  static const u16 splits[] = { 0,  1,	2,  3,	 15,  16,  17,	31,  32,  33,
				63, 64, 65, 127, 128, 129, 511, 512, 513, 1447 };
  u8 *src = test_mem_alloc (65536 + 64);
  u8 *dst = test_mem_alloc (65536 + 4096 + 128);

  for (u32 i = 0; i < 65536 + 64; i++)
    src[i] = (i * 131 + (i >> 3) * 17 + 31) % 255;
  for (u32 offset = 0; offset < 4; offset++)
    for (u32 i = 0; i < 130 + ARRAY_LEN (lengths); i++)
      {
	u32 count = i < 130 ? i : lengths[i - 130];

	for (u32 j = 0; j < ARRAY_LEN (splits); j++)
	  {
	    u32 split = splits[j];

	    if (split && split >= count)
	      continue;
	    err = validate_ip_csum_and_copy (err, src + offset, dst + 64 + 3 - offset, count, split,
					     offset);
	    if (err)
	      return err;
	  }
      }
  return err;
}

REGISTER_TEST (clib_ip_csum_and_copy) = {
  .name = "clib_ip_csum_and_copy",
  .fn = test_clib_ip_csum_and_copy,
};

void __test_perf_fn
perftest_ip4_hdr (test_perf_t *tp)
{
  u32 n = tp->n_ops;
  u8 *data = test_mem_alloc_and_splat (20, n, (void *) &test1);
  u16 *res = test_mem_alloc (n * sizeof (u16));

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    res[i] = clib_ip_csum (data + i * 20, 20);
  test_perf_event_disable (tp);
}

void __test_perf_fn
perftest_tcp_payload (test_perf_t *tp)
{
  u32 n = tp->n_ops;
  volatile uword *lenp = &tp->arg0;
  u8 *data = test_mem_alloc_and_splat (20, n, (void *) &test1);
  u16 *res = test_mem_alloc (n * sizeof (u16));

  test_perf_event_enable (tp);
  for (int i = 0; i < n; i++)
    res[i] = clib_ip_csum (data + i * lenp[0], lenp[0]);
  test_perf_event_disable (tp);
}

void __test_perf_fn
perftest_byte (test_perf_t *tp)
{
  volatile uword *np = &tp->n_ops;
  u8 *data = test_mem_alloc_and_fill_inc_u8 (*np, 0, 0);
  u16 *res = test_mem_alloc (sizeof (u16));

  test_perf_event_enable (tp);
  res[0] = clib_ip_csum (data, np[0]);
  test_perf_event_disable (tp);
}

REGISTER_TEST (clib_ip_csum) = {
  .name = "clib_ip_csum",
  .fn = test_clib_ip_csum,
  .perf_tests = PERF_TESTS (
    { .name = "fixed size (per IPv4 Header)",
      .n_ops = 1024,
      .fn = perftest_ip4_hdr },
    { .name = "fixed size (per 1460 byte block)",
      .n_ops = 16,
      .arg0 = 1460,
      .fn = perftest_tcp_payload },
    { .name = "variable size (per byte)", .n_ops = 16384, .fn = perftest_byte }

    ),
};
