/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <unistd.h>
#include <vperf/builtin/vperf_stats.h>
#include <vperf/vcl/vperf.h>

static u8 *cli_output;

void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  cli_output = va_format (cli_output, fmt, &va);
  va_end (va);
  vec_add1 (cli_output, '\n');
}

static int
expect (const char *output, const char *text)
{
  if (strstr (output, text))
    return 0;
  fprintf (stderr, "Missing '%s' in:\n%s\n", text, output);
  return 1;
}

static int
test_builtin_stats (void)
{
  const struct
  {
    u64 bytes;
    f64 seconds;
    const char *rate;
  } cases[] = {
    { 0, 1, "0" },
    { 1, 2, "1" },
    { 2147483647ULL, 8, "268435456" },
    { 2147483648ULL, 8, "268435456" },
    { 4294967295ULL, 8, "536870912" },
    { 4294967296ULL, 8, "536870912" },
    { 4294967297ULL, 8, "536870912" },
    { 9223372036854775808ULL, 1099511627776., "8388608" },
    { UINT64_MAX, 1099511627776., "16777216" },
#if uword_bits == 64
    { 2147483647ULL, 1, "2147483647" },
    { 2147483648ULL, 1, "2147483648" },
    { 2147483649ULL, 1, "2147483649" },
    { 4294967295ULL, 1, "4294967295" },
    { 4294967296ULL, 1, "4294967296" },
    { 4294967297ULL, 1, "4294967297" },
    { 12500000000ULL, 1, "12500000000" },
#endif
  };
  vp_test_worker_t *wrks = 0;
  int failed = 0;

  vec_validate (wrks, 1);
  for (u32 i = 0; i < ARRAY_LEN (cases); i++)
    for (u8 mode = 0; mode < 4; mode++)
      {
	vp_test_cfg_t cfg = {
	  .proto = VP_PROTO_TLS,
	  .is_server = mode & 1,
	  .echo_bytes = (mode >> 1),
	};
	vp_stats_t stats = { 0 };
	char expected[128];

	clib_memset (wrks, 0, vec_len (wrks) * sizeof (*wrks));
	if (cfg.is_server == cfg.echo_bytes)
	  {
	    wrks[0].bytes_sent = cases[i].bytes / 3;
	    wrks[1].bytes_sent = cases[i].bytes - wrks[0].bytes_sent;
	    wrks[0].bytes_received = 17;
	    wrks[1].bytes_received = 23;
	  }
	else
	  {
	    wrks[0].bytes_received = cases[i].bytes / 3;
	    wrks[1].bytes_received = cases[i].bytes - wrks[0].bytes_received;
	    wrks[0].bytes_sent = 17;
	    wrks[1].bytes_sent = 23;
	  }
	vec_reset_length (cli_output);
	vec_add1 (cli_output, '\n');
	vp_print_final_stats (0, cases[i].seconds, &cfg, &stats, wrks);
	vec_add1 (cli_output, 0);
	snprintf (expected, sizeof (expected), "\n%" PRIu64 " bytes (", (uint64_t) cases[i].bytes);
	failed |= expect ((char *) cli_output, expected);
	snprintf (expected, sizeof (expected), "\n%s bytes/second %s-duplex\n", cases[i].rate,
		  cfg.echo_bytes ? "full" : "half");
	failed |= expect ((char *) cli_output, expected);
	if (cases[i].bytes == 12500000000ULL)
	  failed |= expect ((char *) cli_output, "\n12.50GB/s ");
      }
  vec_free (wrks);
  vec_free (cli_output);
  return failed;
}

static int
test_vcl_stats (void)
{
  vperf_session_t ts = { .fd = 7 };
  vperf_stats_t *s = &ts.stats;
  FILE *capture = tmpfile ();
  int saved_stdout, failed = 0;
  char output[8192];
  size_t n;

  if (!capture)
    return 1;
  fflush (stdout);
  saved_stdout = dup (STDOUT_FILENO);
  if (saved_stdout < 0 || dup2 (fileno (capture), STDOUT_FILENO) < 0)
    {
      if (saved_stdout >= 0)
	close (saved_stdout);
      fclose (capture);
      return 1;
    }
  s->tx_bytes = UINT64_MAX - 4294967297ULL;
  s->rx_bytes = 4294967297ULL;
  s->tx_xacts = 4294967296ULL;
  s->rx_xacts = 4294967298ULL;
  s->tx_eagain = UINT32_MAX;
  s->rx_eagain = UINT32_MAX - 1;
  s->tx_incomp = UINT32_MAX - 2;
  s->rx_incomp = UINT32_MAX - 3;
  s->stop.tv_sec = 1;
  vperf_stats_dump ("VCL", s, 1, 1, 0);
  ts.cfg.rxbuf_size = 4294967299ULL;
  ts.cfg.txbuf_size = 4294967300ULL;
  ts.cfg.num_writes = 9223372036854775808ULL;
  ts.cfg.total_bytes = UINT64_MAX;
  vperf_cfg_dump (&ts.cfg, 1);
  s->rx_bytes = s->tx_bytes = 4294967297000000ULL;
  vperf_stats_dump_inc (&ts, 0);
  vperf_stats_dump_inc (&ts, 1);
  s->tx_bytes = 999999999999999999ULL;
  vperf_stats_dump_inc (&ts, 0);
  fflush (stdout);
  if (dup2 (saved_stdout, STDOUT_FILENO) < 0)
    failed = 1;
  close (saved_stdout);
  rewind (capture);
  n = fread (output, 1, sizeof (output) - 1, capture);
  output[n] = 0;
  fclose (capture);

  failed |= expect (output, "Streamed 18446744073709551615 bytes");
  failed |= expect (output, "writes:  4294967296 (0x100000000)");
  failed |= expect (output, "reads:  4294967298 (0x100000002)");
  failed |= expect (output, "tx bytes:  18446744069414584318 (0xfffffffefffffffe)");
  failed |= expect (output, "rx bytes:  4294967297 (0x100000001)");
  failed |= expect (output, "tx eagain:  4294967295 (0xffffffff)");
  failed |= expect (output, "rx eagain:  4294967294 (0xfffffffe)");
  failed |= expect (output, "tx incomplete:  4294967293 (0xfffffffd)");
  failed |= expect (output, "rx incomplete:  4294967292 (0xfffffffc)");
  failed |= expect (output, "rxbuf size:  4294967299 (0x100000003)");
  failed |= expect (output, "txbuf size:  4294967300 (0x100000004)");
  failed |= expect (output, "num writes:  9223372036854775808 (0x8000000000000000)");
  failed |= expect (output, "client tx bytes:  18446744073709551615 (0xffffffffffffffff)");
  failed |= expect (output, "7: Sent 4294967297 Mbytes in 1.00 seconds");
  failed |= expect (output, "7: Received 4294967297 Mbytes in 1.00 seconds");
  failed |= expect (output, "7: Sent 999999999999 Mbytes in 1.00 seconds");
  return failed;
}

static int
test_builtin_datagrams (void)
{
  vp_test_proto_t protos[] = { VP_PROTO_UDP, VP_PROTO_HTTP_CONNECT_UDP, VP_PROTO_UDP_USO };
  vp_test_worker_t *wrks = 0;
  int failed = 0;

  vec_validate (wrks, 1);
  wrks[0].dgrams_sent = 6000000000ULL;
  wrks[1].dgrams_sent = 4000000000ULL;
  wrks[0].dgrams_received = 3000000000ULL;
  wrks[1].dgrams_received = 2000000000ULL;
  for (u32 p = 0; p < ARRAY_LEN (protos); p++)
    for (u8 mode = 0; mode < 4; mode++)
      {
	vp_test_cfg_t cfg = {
	  .proto = protos[p],
	  .is_server = mode & 1,
	  .echo_bytes = mode >> 1,
	};
	vp_stats_t stats = { .peer_dgrams_received = 5000000000ULL };
	stats.rtt_stats.n_sum = 1;
	stats.rtt_stats.min_rtt = .000125;
	vec_reset_length (cli_output);
	vp_print_final_stats (0, 1, &cfg, &stats, wrks);
	vec_add1 (cli_output, 0);
	if (cfg.is_server)
	  failed |= expect ((char *) cli_output, cfg.echo_bytes ?
						   "received total 5000000000 datagrams, sent "
						   "total 10000000000 datagrams\n" :
						   "received total 5000000000 datagrams\n");
	else
	  failed |=
	    expect ((char *) cli_output,
		    cfg.echo_bytes ? "sent total 10000000000 datagrams, received total 5000000000 "
				     "datagrams, lost 5000000000 datagrams (50.00%)\n" :
				     "sent total 10000000000 datagrams, lost 5000000000 datagrams "
				     "(50.00%)\n");
      }
  vec_free (wrks);
  vec_free (cli_output);
  return failed;
}

#if uword_bits == 64
static int
test_builtin_periodic (void)
{
  vp_test_proto_t protos[] = { VP_PROTO_TLS, VP_PROTO_TCP, VP_PROTO_UDP };
  vp_test_worker_t *wrks = 0;
  vp_test_session_t *sess;
  int failed = 0;

  vec_validate (wrks, 1);
  for (u32 i = 0; i < 2; i++)
    {
      pool_get_zero (wrks[i].sessions, sess);
      sess->vpp_session_handle = ~0ULL;
      sess->bytes_sent = i ? 4000000000ULL : 6000000000ULL;
      sess->bytes_received = i ? 2000000000ULL : 3000000000ULL;
      sess->dgrams_sent = i ? 3 : 4294967416ULL;
      sess->dgrams_received = i ? 10 : 4294967386ULL;
      sess->rtt = .01;
      sess->jitter = i ? 2.75 : 1.25;
    }
  for (u32 p = 0; p < ARRAY_LEN (protos); p++)
    for (u8 total = 0; total < 2; total++)
      for (u8 jitter = 0; jitter < 2; jitter++)
	{
	  /* Use time_offset as a fixed clock. */
	  vlib_main_t vm = {
	    .time_offset = 10,
	    .clib_time = { .log2_clocks_per_frequency_verify = 63 },
	  };
	  vp_test_cfg_t cfg = {
	    .proto = protos[p],
	    .report_interval_total = total,
	    .report_interval_jitter = jitter,
	  };
	  vp_stats_t stats = {
	    .last_print_time = 9,
	    .last_total_tx_bytes = 2000000000ULL,
	    .last_total_rx_bytes = 500000000ULL,
	    .last_total_tx_dgrams = 17,
	    .last_total_rx_dgrams = 9,
	  };
	  vec_reset_length (cli_output);
	  clib_spinlock_init (&stats.rtt_stats.w_lock);
	  vp_print_periodic_stats (&vm, 1, &cfg, &stats, wrks);
	  clib_spinlock_free (&stats.rtt_stats.w_lock);
	  vec_add1 (cli_output, 0);
	  failed |= expect ((char *) cli_output, total ? "Run time (s)" : "Interval (s)");
	  failed |= expect ((char *) cli_output,
			    total && cfg.proto != VP_PROTO_UDP ? "12.00Gb/s" : "100.00Gb/s");
	  failed |= expect ((char *) cli_output, total ? "10.00G" : "8.00G");
	  failed |= expect ((char *) cli_output, total ? "5.00G" : "4.50G");
	  if (cfg.proto == VP_PROTO_UDP)
	    {
	      failed |= expect ((char *) cli_output,
				total ? "4294967419/4294967396\n" : "4294967402/4294967387\n");
	      if (jitter)
		failed |= expect ((char *) cli_output, "2.000ms");
	      if (stats.last_total_tx_dgrams != 4294967419ULL ||
		  stats.last_total_rx_dgrams != 4294967396ULL)
		failed = 1;
	    }
	  if (stats.last_print_time != 10 || stats.last_total_tx_bytes != 10000000000ULL ||
	      stats.last_total_rx_bytes != 5000000000ULL)
	    failed = 1;
	}
  {
    vlib_main_t vm = { .time_offset = 1, .clib_time = { .log2_clocks_per_frequency_verify = 63 } };
    vp_test_cfg_t cfg = { .proto = VP_PROTO_TLS };
    vp_stats_t stats = { 0 };
    for (u32 i = 0; i < 2; i++)
      {
	sess = pool_elt_at_index (wrks[i].sessions, 0);
	sess->bytes_sent = i ? 0 : 1ULL << 60;
	sess->bytes_received = 0;
      }
    vec_reset_length (cli_output);
    vp_print_periodic_stats (&vm, 0, &cfg, &stats, wrks);
    vec_add1 (cli_output, 0);
    failed |= expect ((char *) cli_output, "b/s");
  }
  for (u32 i = 0; i < 2; i++)
    pool_free (wrks[i].sessions);
  vec_free (wrks);
  vec_free (cli_output);
  return failed;
}
#endif

int
main (void)
{
  clib_mem_init (0, 64 << 20);
  int failed = test_builtin_stats () | test_vcl_stats () | test_builtin_datagrams ();
#if uword_bits == 64
  failed |= test_builtin_periodic ();
#endif
  return failed;
}
