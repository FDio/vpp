/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

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
  test_mem_free (buf);
  return err;
}

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

  test_mem_free (data);
  test_mem_free (res);
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

  test_mem_free (data);
  test_mem_free (res);
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

  test_mem_free (data);
  test_mem_free (res);
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
