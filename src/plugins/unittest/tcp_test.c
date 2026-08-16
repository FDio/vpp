/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/tcp/tcp_timer.h>
#include <svm/fifo_segment.h>
#include <unittest/session/test_session_helpers.h>
#include <unittest/tcp/tcp_tamper.h>
#include <unittest/tcp/tcp_e2e_helpers.h>

#define TCP_TEST_I(_cond, _comment, _args...)			\
({								\
  int _evald = (_cond);						\
  if (!(_evald)) {						\
    fformat(stderr, "FAIL:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  } else {							\
    fformat(stderr, "PASS:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  }								\
  _evald;							\
})

#define TCP_TEST(_cond, _comment, _args...)			\
{								\
    if (!TCP_TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

/* Production creates one rate sample per ACK. Keep direct scoreboard tests
 * faithful to that ownership model when they reuse a local sample. */
static_always_inline void
tcp_test_rcv_sacks (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs)
{
  clib_memset (rs, 0, sizeof (*rs));
  tcp_rcv_sacks (tc, ack, rs);
}

typedef enum
{
  TCP_TEST_SACK_BACKEND_SCOREBOARD,
  TCP_TEST_SACK_BACKEND_BT,
  TCP_TEST_N_SACK_BACKENDS,
} tcp_test_sack_backend_t;

static const char *tcp_test_sack_backend_names[] = {
  [TCP_TEST_SACK_BACKEND_SCOREBOARD] = "scoreboard",
  [TCP_TEST_SACK_BACKEND_BT] = "byte tracker",
};

static void
tcp_test_sack_backend_init (tcp_connection_t *tc, tcp_test_sack_backend_t backend)
{
  u32 snd_nxt = tc->snd_nxt;

  scoreboard_init (&tc->sack_sb);
  if (backend != TCP_TEST_SACK_BACKEND_BT)
    return;

  tcp_bt_init (tc);
  tc->snd_nxt = tc->snd_una;
  if (seq_gt (snd_nxt, tc->snd_una))
    tcp_bt_track_tx (tc, snd_nxt - tc->snd_una);
  tc->snd_nxt = snd_nxt;
}

static void
tcp_test_sack_backend_cleanup (tcp_connection_t *tc, tcp_test_sack_backend_t backend)
{
  scoreboard_clear (&tc->sack_sb);
  pool_free (tc->sack_sb.holes);
  vec_free (tc->rcv_opts.sacks);
  if (backend == TCP_TEST_SACK_BACKEND_BT)
    tcp_bt_cleanup (tc);
}

static_always_inline void
tcp_test_sack_backend_track_rxt (tcp_connection_t *tc, tcp_test_sack_backend_t backend, u32 start,
				 u32 end)
{
  if (backend == TCP_TEST_SACK_BACKEND_BT)
    tcp_bt_track_rxt (tc, start, end);
}

scoreboard_trace_elt_t sb_trace[] = {};

static int
tcp_test_scoreboard_replay (vlib_main_t * vm, unformat_input_t * input)
{
  int verbose = 0;
  tcp_connection_t _tc, *tc = &_tc;
  u8 *s = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detail"))
	verbose = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

#if TCP_SCOREBOARD_TRACE
  tc->sack_sb.trace = sb_trace;
#endif
  s = tcp_scoreboard_replay (s, tc, verbose);
  vlib_cli_output (vm, "%v", s);
  return 0;
}

typedef enum
{
  TCP_TEST_REORDER_OOO,
  TCP_TEST_REORDER_RECOVERY,
  TCP_TEST_REORDER_RXT,
  TCP_TEST_REORDER_RESCUE,
} tcp_test_reorder_mode_t;

typedef struct
{
  const char *name;
  tcp_test_reorder_mode_t mode;
  u16 snd_mss;
  u32 snd_nxt;
  u32 frontier_start;
  u32 delayed_start;
  u32 delayed_end;
  u32 initial_reorder;
  u32 expected_reorder;
} tcp_test_reorder_case_t;

static const tcp_test_reorder_case_t tcp_test_reorder_cases[] = {
  { "round fractional mss up", TCP_TEST_REORDER_OOO, 150, 3000, 2850, 2549, 2699,
    TCP_DUPACK_THRESHOLD, 4 },
  { "keep exact mss distance exact", TCP_TEST_REORDER_OOO, 150, 3000, 2850, 2400, 2550,
    TCP_DUPACK_THRESHOLD, 4 },
  { "clamp to maximum", TCP_TEST_REORDER_OOO, 150, 60000, 59850, 1, 151, TCP_DUPACK_THRESHOLD,
    TCP_MAX_SACK_REORDER },
  { "preserve a larger learned estimate", TCP_TEST_REORDER_OOO, 150, 3000, 2850, 2400, 2550, 20,
    20 },
  { "learn unretransmitted data in recovery", TCP_TEST_REORDER_RECOVERY, 150, 3000, 2400, 300, 450,
    TCP_DUPACK_THRESHOLD, 18 },
  { "ignore retransmitted data", TCP_TEST_REORDER_RXT, 150, 3000, 2400, 300, 450,
    TCP_DUPACK_THRESHOLD, TCP_DUPACK_THRESHOLD },
  { "ignore rescue retransmits", TCP_TEST_REORDER_RESCUE, 150, 3000, 2400, 300, 450,
    TCP_DUPACK_THRESHOLD, TCP_DUPACK_THRESHOLD },
};

static int
tcp_test_sack_reordering (tcp_test_sack_backend_t backend)
{
  tcp_connection_t _tc, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t block;
  u32 i;

  for (i = 0; i < ARRAY_LEN (tcp_test_reorder_cases); i++)
    {
      const tcp_test_reorder_case_t *t = &tcp_test_reorder_cases[i];
      int ok;

      clib_memset (tc, 0, sizeof (*tc));
      tc->snd_nxt = t->snd_nxt;
      tc->snd_mss = t->snd_mss;
      tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK;
      tcp_test_sack_backend_init (tc, backend);
      sb->reorder = t->initial_reorder;
      sb->rescue_rxt = tc->snd_una - 1;

      if (t->mode != TCP_TEST_REORDER_OOO)
	tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
      if (t->mode == TCP_TEST_REORDER_RECOVERY)
	sb->high_rxt = t->delayed_start;
      else if (t->mode == TCP_TEST_REORDER_RXT)
	{
	  sb->high_rxt = t->delayed_end;
	  tcp_test_sack_backend_track_rxt (tc, backend, t->delayed_start, t->delayed_end);
	}
      else if (t->mode == TCP_TEST_REORDER_RESCUE)
	{
	  tc->snd_congestion = tc->snd_nxt;
	  sb->rescue_rxt = tc->snd_congestion;
	  tcp_test_sack_backend_track_rxt (tc, backend, t->delayed_start, t->delayed_end);
	}

      block.start = t->frontier_start;
      block.end = tc->snd_nxt;
      vec_add1 (tc->rcv_opts.sacks, block);
      tc->rcv_opts.n_sack_blocks = 1;
      tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
      ok = TCP_TEST_I (
	(sb->reorder == t->initial_reorder), "%s sack reorder %s: frontier keeps %u, got %u",
	tcp_test_sack_backend_names[backend], t->name, t->initial_reorder, sb->reorder);

      if (ok)
	{
	  vec_reset_length (tc->rcv_opts.sacks);
	  block.start = t->delayed_start;
	  block.end = t->delayed_end;
	  vec_add1 (tc->rcv_opts.sacks, block);
	  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
	  ok = TCP_TEST_I (
	    (sb->reorder == t->expected_reorder), "%s sack reorder %s: expected %u, got %u",
	    tcp_test_sack_backend_names[backend], t->name, t->expected_reorder, sb->reorder);
	}

      tcp_test_sack_backend_cleanup (tc, backend);
      if (!ok)
	return 1;
    }

  return 0;
}

/* Drive one out-of-order reorder observation and return the learned estimate.
 * Establishes the sack frontier at snd_nxt, then sacks a single delayed mss
 * whose start is 'distance' bytes below the frontier. */
static u32
tcp_test_reorder_observe (tcp_connection_t *tc, tcp_test_sack_backend_t backend, u16 mss,
			  u32 snd_nxt, u32 distance, u32 initial_reorder)
{
  tcp_rate_sample_t rs = {};
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t block;
  u32 reorder;

  clib_memset (tc, 0, sizeof (*tc));
  tc->snd_nxt = snd_nxt;
  tc->snd_mss = mss;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK;
  tcp_test_sack_backend_init (tc, backend);
  sb->reorder = initial_reorder;
  sb->rescue_rxt = tc->snd_una - 1;

  /* Establish the frontier at snd_nxt. */
  block.start = snd_nxt - mss;
  block.end = snd_nxt;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);

  /* Sack a delayed segment 'distance' bytes below the frontier. */
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = snd_nxt - distance;
  block.end = block.start + mss;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);

  reorder = sb->reorder;

  tcp_test_sack_backend_cleanup (tc, backend);
  return reorder;
}

/* The reorder estimate must equal ceil(reordering_distance / mss) exactly,
 * neither under- nor over-estimating, and must track the maximum observed
 * distance rather than summing successive observations. */
static int
tcp_test_sack_reorder_accuracy (tcp_test_sack_backend_t backend)
{
  tcp_connection_t _tc, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t block;
  const u16 mss = 150;
  const u32 snd_nxt = 60000;
  u32 dist_mss;
  int ok = 1;

  /* Accuracy sweep: for each whole-segment distance, test an exact multiple,
   * one byte over (must round the partial segment up) and one byte under (must
   * not round an almost-full extra segment up). Start above the floor
   * (TCP_DUPACK_THRESHOLD) so every point exercises the ceil rounding rather
   * than the clamp, and keep every distance >= mss so the delayed segment is a
   * valid block below the frontier (end <= snd_nxt). */
  for (dist_mss = TCP_DUPACK_THRESHOLD + 1; dist_mss <= 40 && ok; dist_mss++)
    {
      u32 s;
      const int offs[] = { 0, 1, -1 };

      for (s = 0; s < ARRAY_LEN (offs) && ok; s++)
	{
	  u32 distance = dist_mss * mss + offs[s];
	  u32 expected = (distance + mss - 1) / mss;
	  u32 got =
	    tcp_test_reorder_observe (tc, backend, mss, snd_nxt, distance, TCP_DUPACK_THRESHOLD);

	  ok = TCP_TEST_I ((got == expected),
			   "%s reorder accuracy: distance %u (mss %u) expected %u, got %u",
			   tcp_test_sack_backend_names[backend], distance, mss, expected, got);
	}
    }
  if (!ok)
    return 1;

  /* Floor: a reordering shorter than the dupack threshold must clamp to
   * TCP_DUPACK_THRESHOLD, not report the (smaller) measured distance. Distances
   * stay >= mss so the block is still a valid observation below the frontier. */
  {
    u32 floor_dists[] = { mss + 1, 2 * mss };

    for (dist_mss = 0; dist_mss < ARRAY_LEN (floor_dists) && ok; dist_mss++)
      {
	u32 distance = floor_dists[dist_mss];
	u32 got =
	  tcp_test_reorder_observe (tc, backend, mss, snd_nxt, distance, TCP_DUPACK_THRESHOLD);

	ok = TCP_TEST_I ((got == TCP_DUPACK_THRESHOLD),
			 "%s reorder floor: distance %u clamps to %u, got %u",
			 tcp_test_sack_backend_names[backend], distance, TCP_DUPACK_THRESHOLD, got);
      }
  }
  if (!ok)
    return 1;

  /* Max-semantics: a larger observation raises the estimate; a subsequent
   * smaller one neither lowers it (under-estimate) nor adds to it
   * (over-estimate). */
  {
    u32 big = 10, small = 4, got;

    clib_memset (tc, 0, sizeof (*tc));
    tc->snd_nxt = snd_nxt;
    tc->snd_mss = mss;
    tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK;
    tcp_test_sack_backend_init (tc, backend);
    sb->rescue_rxt = tc->snd_una - 1;

    block.start = snd_nxt - mss;
    block.end = snd_nxt;
    vec_add1 (tc->rcv_opts.sacks, block);
    tc->rcv_opts.n_sack_blocks = 1;
    tcp_test_rcv_sacks (tc, tc->snd_una, &rs);

    /* Large reorder first. */
    vec_reset_length (tc->rcv_opts.sacks);
    block.start = snd_nxt - big * mss;
    block.end = block.start + mss;
    vec_add1 (tc->rcv_opts.sacks, block);
    tc->rcv_opts.n_sack_blocks = 1;
    tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
    ok = TCP_TEST_I ((sb->reorder == big), "%s reorder max: large observation sets %u, got %u",
		     tcp_test_sack_backend_names[backend], big, sb->reorder);

    /* Smaller reorder after: must stay at big, not drop to small, not sum. */
    if (ok)
      {
	vec_reset_length (tc->rcv_opts.sacks);
	block.start = snd_nxt - small * mss;
	block.end = block.start + mss;
	vec_add1 (tc->rcv_opts.sacks, block);
	tc->rcv_opts.n_sack_blocks = 1;
	tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
	ok =
	  TCP_TEST_I ((sb->reorder == big), "%s reorder max: smaller observation keeps %u, got %u",
		      tcp_test_sack_backend_names[backend], big, sb->reorder);
      }

    tcp_test_sack_backend_cleanup (tc, backend);
    if (!ok)
      return 1;

    /* Reverse order grows the estimate to the larger observation. */
    got = tcp_test_reorder_observe (tc, backend, mss, snd_nxt, big * mss, small);
    ok =
      TCP_TEST_I ((got == big), "%s reorder max: grows past a smaller prior estimate to %u, got %u",
		  tcp_test_sack_backend_names[backend], big, got);
    if (!ok)
      return 1;
  }

  return 0;
}

static int
tcp_test_sack_rx (vlib_main_t * vm, unformat_input_t * input)
{
  tcp_connection_t _tc, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *sacks = 0, block;
  sack_scoreboard_hole_t *hole;
  int i, verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "replay"))
	return tcp_test_scoreboard_replay (vm, input);
    }

  if (tcp_test_sack_reordering (TCP_TEST_SACK_BACKEND_SCOREBOARD) ||
      tcp_test_sack_reordering (TCP_TEST_SACK_BACKEND_BT))
    return 1;

  if (tcp_test_sack_reorder_accuracy (TCP_TEST_SACK_BACKEND_SCOREBOARD) ||
      tcp_test_sack_reorder_accuracy (TCP_TEST_SACK_BACKEND_BT))
    return 1;

  clib_memset (tc, 0, sizeof (*tc));

  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 1000;
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->snd_mss = 150;
  scoreboard_init (&tc->sack_sb);

  for (i = 0; i < 1000 / 100; i++)
    {
      block.start = i * 100;
      block.end = (i + 1) * 100;
      vec_add1 (sacks, block);
    }

  /*
   * Inject even blocks
   */

  for (i = 0; i < 1000 / 200; i++)
    {
      vec_add1 (tc->rcv_opts.sacks, sacks[i * 2]);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);

  if (verbose)
    vlib_cli_output (vm, "sb after even blocks (mss %u):\n%U",
		     tc->snd_mss, format_tcp_scoreboard, sb, tc);

  TCP_TEST ((pool_elts (sb->holes) == 5),
	    "scoreboard has %d elements", pool_elts (sb->holes));

  /* First SACK block should be rejected */
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 0 && hole->end == 200), "first hole start %u end %u", hole->start,
	    hole->end);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->start == 900 && hole->end == 1000), "last hole start %u end %u", hole->start,
	    hole->end);
  TCP_TEST ((sb->sacked_bytes == 400), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((rs.last_sacked_bytes == 400), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->high_sacked == 900), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((rs.last_lost == 300), "last lost bytes %u", rs.last_lost);

  /*
   * Inject odd blocks except the last
   *
   */

  vec_reset_length (tc->rcv_opts.sacks);
  for (i = 0; i < 800 / 200; i++)
    {
      vec_add1 (tc->rcv_opts.sacks, sacks[i * 2 + 1]);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nsb after odd blocks:\n%U", format_tcp_scoreboard,
		     sb, tc);

  hole = scoreboard_first_hole (sb);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  TCP_TEST ((hole->start == 0 && hole->end == 100), "first hole start %u end %u", hole->start,
	    hole->end);
  TCP_TEST ((sb->sacked_bytes == 800), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->high_sacked == 900), "high sacked %u", sb->high_sacked);
  TCP_TEST ((rs.last_sacked_bytes == 400), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((rs.last_lost == 0), "last lost bytes %u", rs.last_lost);

  /*
   *  Ack until byte 100 - this is reneging because we should ack until 900
   */
  tcp_test_rcv_sacks (tc, 100, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nack until byte 100:\n%U", format_tcp_scoreboard,
		     sb, tc);

  TCP_TEST ((pool_elts (sb->holes) == 1), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->is_reneging), "is reneging");

  /*
   * Make sure we accept duplicate acks while reneging.
   */
  tc->snd_una = 100;
  sb->high_rxt = 950;

  block.start = 900;
  block.end = 950;
  vec_add1 (tc->rcv_opts.sacks, block);

  tcp_test_rcv_sacks (tc, 100, &rs);
  TCP_TEST ((pool_elts (sb->holes) == 1), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((rs.last_sacked_bytes == 50), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.rxt_sacked == 50), "last rxt sacked bytes %d", rs.rxt_sacked);

  /*
   * Sack all up to 950
   */
  tcp_test_rcv_sacks (tc, 950, &rs);
  TCP_TEST ((sb->high_sacked == 950), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Sack [960 970] [980 990]
   */
  sb->high_rxt = 985;

  tc->snd_una = 950;
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 960;
  block.end = 970;
  vec_add1 (tc->rcv_opts.sacks, block);

  block.start = 980;
  block.end = 990;
  vec_add1 (tc->rcv_opts.sacks, block);

  tcp_test_rcv_sacks (tc, 950, &rs);
  TCP_TEST ((sb->high_sacked == 990), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 20), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 20), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((rs.rxt_sacked == 15), "last rxt sacked bytes %d", rs.rxt_sacked);

  /*
   * Ack up to 960 (reneging) + [961 971]
   */
  tc->rcv_opts.sacks[0].start = 961;
  tc->rcv_opts.sacks[0].end = 971;

  tcp_test_rcv_sacks (tc, 960, &rs);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 21), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 1), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.rxt_sacked == 11), "last rxt sacked bytes %d", rs.rxt_sacked);
  TCP_TEST ((rs.last_bytes_delivered == 0), "last bytes delivered %d", rs.last_bytes_delivered);

  /*
   * Ack up to 960 (reneging) + [961 990]
   */
  tc->snd_una = 960;
  tc->rcv_opts.sacks[0].start = 961;
  tc->rcv_opts.sacks[0].end = 990;

  tcp_test_rcv_sacks (tc, 960, &rs);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 30), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 9), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.rxt_sacked == 9), "last rxt sacked bytes %d", rs.rxt_sacked);

  /*
   * Sack remaining bytes [990 1000]
   */
  tc->rcv_opts.sacks[0].start = 990;
  tc->rcv_opts.sacks[0].end = 1000;

  tcp_test_rcv_sacks (tc, 960, &rs);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 40), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 10), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.rxt_sacked == 0), "last rxt sacked bytes %d", rs.rxt_sacked);
  TCP_TEST (pool_elts (sb->holes) == 0, "no holes left");

  /*
   * Ack up to 970 no sack blocks
   */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tcp_test_rcv_sacks (tc, 970, &rs);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 30), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.rxt_sacked == 0), "last rxt sacked bytes %d", rs.rxt_sacked);

  /*
   * Ack all up to 1000
   */
  tc->snd_una = 970;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  TCP_TEST ((sb->high_sacked == 1000), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST (rs.last_bytes_delivered == 30, "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Add new block
   */
  tc->flags = 0;
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  vec_reset_length (tc->rcv_opts.sacks);

  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);

  tc->snd_una = 1000;
  tc->snd_nxt = 1500;
  tcp_test_rcv_sacks (tc, 1000, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nadd [1200, 1300] snd_una_max 1500, snd_una 1000:"
		     " \n%U", format_tcp_scoreboard, sb, tc);

  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 1000 && hole->end == 1200), "first hole start %u end %u", hole->start,
	    hole->end);
  TCP_TEST ((sb->high_sacked == 1300), "max sacked byte %u", sb->high_sacked);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->start == 1300 && hole->end == 1500), "last hole start %u end %u", hole->start,
	    hole->end);
  TCP_TEST ((sb->sacked_bytes == 100), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);

  /*
   * Ack first hole
   */

  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 0;
  /* Ack up to 1300 to avoid reneging */
  tcp_test_rcv_sacks (tc, 1300, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nsb ack up to byte 1300:\n%U",
		     format_tcp_scoreboard, sb, tc);

  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((rs.last_bytes_delivered == 100), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->head != TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail != TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Add some more blocks and then remove all
   */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->snd_una = 1300;
  tc->snd_nxt = 1900;
  for (i = 0; i < 5; i++)
    {
      block.start = i * 100 + 1200;
      block.end = (i + 1) * 100 + 1200;
      vec_add1 (tc->rcv_opts.sacks, block);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 1900, &rs);

  scoreboard_clear (sb);
  if (verbose)
    vlib_cli_output (vm, "\nsb cleared all:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "number of holes %d", pool_elts (sb->holes));
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * Re-inject odd blocks and ack them all
   */

  tc->snd_una = 0;
  tc->snd_nxt = 1000;
  vec_reset_length (tc->rcv_opts.sacks);
  for (i = 0; i < 5; i++)
    {
      vec_add1 (tc->rcv_opts.sacks, sacks[i * 2 + 1]);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nsb added odd blocks snd_una 0 snd_una_max 1000:"
		     "\n%U", format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 5),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->end == 900), "last hole end %u", hole->end);
  TCP_TEST ((sb->high_sacked == 1000), "high sacked %u", sb->high_sacked);

  /*
   * Renege bytes from 950 to 1000
   */
  tcp_test_rcv_sacks (tc, 950, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nack [0, 950]:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 0), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 50), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->high_sacked == 1000), "high sacked %u", sb->high_sacked);

  scoreboard_clear (sb);

  /*
   * Inject one block, ack it and overlap hole
   */

  tc->snd_una = 0;
  tc->snd_nxt = 1000;

  block.start = 100;
  block.end = 500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);

  tcp_test_rcv_sacks (tc, 0, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nsb added [100, 500] snd_una 0 snd_una_max 1000:"
		     "\n%U", format_tcp_scoreboard, sb, tc);

  tcp_test_rcv_sacks (tc, 800, &rs);

  if (verbose)
    vlib_cli_output (vm, "\nsb ack [0, 800]:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 400), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->head != TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail != TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * One hole close to head, patch head, split in two and start acking
   * the lowest part
   */
  scoreboard_clear (sb);
  /* scoreboard_clear does not floor reorder (path property) */
  sb->reorder = TCP_DUPACK_THRESHOLD;
  tc->snd_una = 0;
  tc->snd_nxt = 1000;

  block.start = 500;
  block.end = 1000;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);

  tcp_test_rcv_sacks (tc, 0, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nsb added [500, 1000]:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((sb->sacked_bytes == 500), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 500), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 500), "lost bytes %u", sb->lost_bytes);

  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 400;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 100, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nsb added [0, 100] [300, 400]:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 100), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 0), "last bytes delivered %d", rs.last_bytes_delivered);
  /* Hole should be split in 2 lost holes that add up to 300 */
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->reorder == 7), "reorder %u", sb->reorder);

  /*
   * Ack [100 300] in two steps
   *
   * Step 1. Ack [100 200] which delivers 100 of the bytes lost
   */
  tc->snd_una = 100;
  tcp_test_rcv_sacks (tc, 200, &rs);
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 0), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 200), "lost bytes %u", sb->lost_bytes);

  /*
   * Step 2. Ack up to 300, although 300 400 is sacked, so this is interpreted
   * as reneging.
   */
  tc->snd_una = 200;
  tcp_test_rcv_sacks (tc, 300, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nacked [100, 300] in two steps:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 0), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((sb->is_reneging), "is reneging");

  /*
   * Ack [300 500]. Delivers reneged segment [300 400] and reneges bytes
   * above 500
   */
  tc->snd_una = 300;
  tcp_test_rcv_sacks (tc, 500, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nacked [400, 500]:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 500), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 100), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * Ack up to 1000 to deliver all bytes
   */
  tc->snd_una = 500;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nAck high sacked:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((rs.last_sacked_bytes == 0), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 500), "last bytes delivered %d", rs.last_bytes_delivered);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Add [1200, 1500] and test that [1000, 1200] is lost (bytes condition)
   * snd_una = 1000 and snd_una_max = 1600
   */
  tc->snd_una = 1000;
  tc->snd_nxt = 1600;
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 1200;
  block.end = 1500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 1000, &rs);
  if (verbose)
    vlib_cli_output (vm, "\nacked [1200, 1500] test first hole is lost:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 2), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 300), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 300), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((rs.last_bytes_delivered == 0), "last bytes delivered %d", rs.last_bytes_delivered);
  /* No bytes lost because of reorder */
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->reorder == 7), "reorder %u", sb->reorder);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Restart
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);

  /*
   * Inject [100 500]
   */

  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 1000;
  sb->high_rxt = 0;

  block.start = 100;
  block.end = 500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);

  tcp_test_rcv_sacks (tc, 0, &rs);

  TCP_TEST ((sb->sacked_bytes == 400), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 400), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Renege, sack all of the remaining bytes and cover some rxt bytes
   */
  sb->high_rxt = 700;
  tc->rcv_opts.sacks[0].start = 500;
  tc->rcv_opts.sacks[0].end = 1000;

  tcp_test_rcv_sacks (tc, 100, &rs);

  TCP_TEST ((sb->sacked_bytes == 900), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 500), "last sacked bytes %d", rs.last_sacked_bytes);
  TCP_TEST (sb->is_reneging, "is reneging");
  TCP_TEST ((rs.rxt_sacked == 300), "last rxt sacked bytes %d", rs.rxt_sacked);

  /*
   * Reorder estimate must keep learning during congestion recovery. A segment
   * that was never retransmitted (start at/above high_rxt) but arrives out of
   * order below the sack frontier is unambiguous reordering, so it should grow
   * sb->reorder even though has_rxt (in recovery) is set. Without this the
   * estimate stays pinned at the dupack floor and the connection re-enters
   * spurious fast recoveries on a reordering path.
   */
  scoreboard_clear (sb);
  sb->reorder = TCP_DUPACK_THRESHOLD;
  vec_reset_length (tc->rcv_opts.sacks);
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 3000;
  sb->high_rxt = 0;
  /* scoreboard_init_rxt sentinel: no rescue retransmit fired this episode */
  sb->rescue_rxt = tc->snd_una - 1;
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder at floor %u", sb->reorder);

  /* Establish a high sack frontier first (extends it, does not grow reorder) */
  block.start = 2400;
  block.end = 3000;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->high_sacked == 3000), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder still floor %u", sb->reorder);

  /* A never-retransmitted low block arrives out of order below the frontier:
   * reord = ceil((3000 - 300) / 150) = 18 */
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->reorder == 18), "reorder grew in recovery %u", sb->reorder);

  /*
   * A sack below high_rxt during recovery is ambiguous (it could be a
   * retransmit arriving rather than the original delayed segment) and must not
   * grow the reorder estimate.
   */
  scoreboard_clear (sb);
  sb->reorder = TCP_DUPACK_THRESHOLD;
  vec_reset_length (tc->rcv_opts.sacks);
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 3000;
  sb->high_rxt = 0;
  sb->rescue_rxt = tc->snd_una - 1;

  block.start = 2400;
  block.end = 3000;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder floor %u", sb->reorder);

  /* Everything below the frontier has now been retransmitted */
  sb->high_rxt = 2400;
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder unchanged below high_rxt %u",
	    sb->reorder);

  /*
   * After a rescue retransmit (RFC 6675) the re-sent segment sits at/above
   * high_rxt but is NOT reordering. rescue_rxt advanced to snd_congestion marks
   * it, so a later out-of-order sack at/above high_rxt must NOT grow reorder
   * (else a delayed rescue + advancing frontier would inflate it toward 300 and
   * strand real loss until rto).
   */
  scoreboard_clear (sb);
  sb->reorder = TCP_DUPACK_THRESHOLD;
  vec_reset_length (tc->rcv_opts.sacks);
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 3000;
  tc->snd_congestion = 3000;
  sb->high_rxt = 0;
  /* A rescue fired: rescue_rxt was set to snd_congestion (>= snd_una) */
  sb->rescue_rxt = tc->snd_congestion;

  block.start = 2400;
  block.end = 3000;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->high_sacked == 3000), "high sacked %u", sb->high_sacked);

  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder unchanged after rescue rxt %u",
	    sb->reorder);

  /*
   * Restart
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);
  tc->snd_congestion = 0;

  /*
   * Broken sacks:
   * block.start > snd_nxt
   * && block.start < blk.end
   * && block.end <= snd_nxt
   */
  tc->flags = 0;
  block.start = 2147483647;
  block.end = 4294967295;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->snd_una = tc->snd_nxt = 1969067947;

  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);

  /*
   * Exercise nested received SACK blocks:
   * snd_una=100
   *   |----- lost hole -----|
   *                         35300                 102700
   *                         |<------ outer sack ------>|
   *                           35700            36700
   *                           |---- inner sack ----|
   *
   * The scoreboard starts with:
   * - one lost hole [100, 35300]
   * - stale high_sacked = 36700
   * - pre-existing sacked_bytes = 67000
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);

  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_FINPNDG;
  tc->snd_una = 100;
  tc->snd_nxt = 102700;
  sb->reorder = 3;
  sb->high_sacked = 36700;
  block.start = 35300;
  block.end = 102700;
  vec_add1 (tc->rcv_opts.sacks, block);
  block.start = 35700;
  block.end = 36700;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  pool_get (sb->holes, hole);
  clib_memset (hole, 0, sizeof (*hole));
  hole->start = tc->snd_una;
  hole->end = 35300;
  hole->next = TCP_INVALID_SACK_HOLE_INDEX;
  hole->prev = TCP_INVALID_SACK_HOLE_INDEX;
  hole->is_lost = 1;
  sb->head = sb->tail = scoreboard_hole_index (sb, hole);
  sb->lost_bytes = scoreboard_hole_bytes (hole);
  sb->cur_rxt_hole = sb->head;
  sb->high_rxt = 35300;
  sb->rescue_rxt = tc->snd_nxt;
  sb->sacked_bytes = 67000;

  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);

  TCP_TEST ((sb->high_sacked == 102700), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 67400), "sacked bytes %u", sb->sacked_bytes);
  TCP_TEST ((rs.last_sacked_bytes == 400), "last sacked bytes %u", rs.last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 35200), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Reclassify an rto-forced loss using only SACK evidence. With no SACKed
   * data, the rto mark must be removed without discarding the hole.
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);
  tc->flags = TCP_CONN_RECOVERY;
  tc->snd_una = 0;
  tc->snd_nxt = 1000;
  tc->snd_mss = 100;
  tcp_sack_rxt_mark_lost (tc);
  TCP_TEST ((sb->lost_bytes == 1000), "rto marks bytes lost %u", sb->lost_bytes);

  tcp_sack_recompute_loss (tc);
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((sb->lost_bytes == 0), "rto-only loss removed %u", sb->lost_bytes);
  TCP_TEST ((hole && !hole->is_lost), "rto-only hole is no longer lost");

  /* SACK-derived loss must survive the same reclassification. */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);
  tc->flags = TCP_CONN_FAST_RECOVERY;
  block.start = 300;
  block.end = 600;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST ((sb->lost_bytes == 300), "SACK marks bytes lost %u", sb->lost_bytes);

  tcp_sack_recompute_loss (tc);
  TCP_TEST ((sb->lost_bytes == 300), "SACK-derived loss preserved %u", sb->lost_bytes);

  /* A clean scoreboard does not track cumulative ACK progress. Recovery undo
   * may reclassify loss after snd_una advances, so a stale high_sacked below
   * the ACK must still describe zero SACKed bytes. */
  scoreboard_clear (sb);
  sb->high_sacked = tc->snd_una;
  tc->snd_una += tc->snd_mss;
  tcp_sack_recompute_loss (tc);
  TCP_TEST ((sb->sacked_bytes == 0), "empty scoreboard has no sacked bytes %u", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "empty scoreboard has no lost bytes %u", sb->lost_bytes);

  /*
   * Clear
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);

  return 0;
}

static u32
tcp_test_dsack_rxt_count (tcp_connection_t *tc)
{
  return (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) ? pool_elts (tc->dsack_rxt) - 1 : 0;
}

static tcp_dsack_rxt_t *
tcp_test_dsack_rxt_at (tcp_connection_t *tc, u32 position)
{
  u32 index;

  ASSERT (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE);
  index = tc->dsack_rxt[0].head;
  while (position--)
    {
      ASSERT (index != TCP_DSACK_RXT_INVALID_INDEX);
      index = pool_elt_at_index (tc->dsack_rxt, index)->next;
    }
  ASSERT (index != TCP_DSACK_RXT_INVALID_INDEX);
  return pool_elt_at_index (tc->dsack_rxt, index);
}

static int
tcp_test_dsack_rx (vlib_main_t *vm)
{
  tcp_connection_t _tc, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_block_t block;

#define DSACK_RX_INIT()                                                                            \
  do                                                                                               \
    {                                                                                              \
      clib_memset (tc, 0, sizeof (*tc));                                                           \
      tc->snd_mss = 100;                                                                           \
      tc->snd_una = 1000;                                                                          \
      tc->snd_nxt = 2000;                                                                          \
      tc->snd_wnd_max = 1000;                                                                      \
      tc->snd_congestion = 1600;                                                                   \
      tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;                      \
      rs.ack_flags = 0;                                                                            \
      scoreboard_init (&tc->sack_sb);                                                              \
    }                                                                                              \
  while (0)

#define DSACK_RX_RESET()                                                                           \
  do                                                                                               \
    {                                                                                              \
      scoreboard_clear (&tc->sack_sb);                                                             \
      pool_free (tc->sack_sb.holes);                                                               \
      vec_free (tc->rcv_opts.sacks);                                                               \
      tcp_dsack_cleanup (tc);                                                                      \
      DSACK_RX_INIT ();                                                                            \
    }                                                                                              \
  while (0)

  DSACK_RX_INIT ();

  /* RFC 2883 requires comparison with the ACK in this packet, not the
   * connection's newer snd_una. */
  tc->flags = TCP_CONN_RECOVERY;
  block.start = 800;
  block.end = 900;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 700, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK),
	    "D-SACK classification uses packet ACK instead of snd_una");

  /* Old ACKs outside recovery process D-SACK evidence without touching the
   * ordinary SACK scoreboard. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tc->snd_una = 1300;
  tc->snd_congestion = 1200;
  tcp_cong_recovery_off (tc);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_rcv_dsack (tc, 1200, &rs);
  TCP_TEST ((rs.ack_flags & (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS)) ==
	      (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS),
	    "old ACK D-SACK proves retained retransmission spurious");
  TCP_TEST (tc->sack_sb.head == TCP_INVALID_SACK_HOLE_INDEX && !tc->sack_sb.sacked_bytes,
	    "old ACK D-SACK leaves scoreboard unchanged");

  DSACK_RX_RESET ();
  block.start = 800;
  block.end = 900;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_DSACK, "detect D-SACK below cumulative ACK");
  TCP_TEST (tc->dsack_flags & TCP_DSACK_UNDO_DISABLED,
	    "D-SACK for untracked data disables congestion undo");
  TCP_TEST (vec_len (tc->rcv_opts.sacks) == 0,
	    "remove below-ACK D-SACK before scoreboard processing");

  DSACK_RX_RESET ();
  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);
  block.start = 1100;
  block.end = 1500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 2;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_DSACK, "detect above-ACK D-SACK contained by second block");
  TCP_TEST (vec_len (tc->rcv_opts.sacks) == 1 && tc->rcv_opts.sacks[0].start == 1100 &&
	      tc->rcv_opts.sacks[0].end == 1500,
	    "preserve containing SACK block for scoreboard processing");

  DSACK_RX_RESET ();
  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);
  block.start = 1350;
  block.end = 1500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 2;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK),
	    "do not classify uncontained above-ACK block as D-SACK");

  DSACK_RX_RESET ();
  tc->snd_wnd_max = 100;
  block.start = 800;
  block.end = 1000;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 1000, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK),
	    "ignore dubious D-SACK larger than maximum advertised window");

  /* One retransmission, acknowledged through the recovery point and reported
   * duplicate, is sufficient evidence for undo. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST ((rs.ack_flags & (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS)) ==
	      (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS),
	    "D-SACK proves single retransmission episode spurious");

  /* D-SACK can prove the current reduction spurious before the cumulative ACK
   * reaches the recovery point. Congestion control exits the old episode and
   * re-enters if the scoreboard still identifies other loss. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tc->snd_una = 1200;
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (seq_lt (tc->snd_una, tc->snd_congestion) && (rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "non-advancing D-SACK proves recovery spurious before the recovery point");

  /* Every retransmitted range must be D-SACKed; one spurious retransmission
   * cannot hide a real loss elsewhere in the episode. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1200, 1300);
  TCP_TEST (tcp_test_dsack_rxt_count (tc) == 1 && tcp_test_dsack_rxt_at (tc, 0)->start == 1100 &&
	      tcp_test_dsack_rxt_at (tc, 0)->end == 1300,
	    "coalesce adjacent retransmissions without losing byte coverage");
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_congestion, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "advancing D-SACK does not discard another retransmission's history");
  TCP_TEST (tc->dsack_pending_bytes == 100 && !(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE),
	    "first D-SACK leaves aggregate evidence for one retransmission");
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  vec_reset_length (tc->rcv_opts.sacks);
  rs.ack_flags = 0;
  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una + 100, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS,
	    "all retransmissions D-SACKed makes episode undo eligible");
  TCP_TEST (!tc->dsack_pending_bytes && !(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE),
	    "D-SACKed retransmissions need no retained exact ranges");

  /* ACKed retransmissions retire to aggregate state. A later retransmission
   * starts a new exact active range without restoring retired ranges. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1200, 1300);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 1300, &rs);
  TCP_TEST (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tc->dsack_pending_bytes == 100,
	    "cumulative ACK retires exact D-SACK ranges to aggregate state");
  tc->snd_una = 1300;
  tcp_dsack_track_retransmit (tc, 1300, 1400);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tcp_test_dsack_rxt_count (tc) == 1 &&
	      tcp_test_dsack_rxt_at (tc, 0)->start == 1300 &&
	      tcp_test_dsack_rxt_at (tc, 0)->end == 1400 && tc->dsack_pending_bytes == 200,
	    "new retransmission retains only active exact coverage");

  /* Cumulative ACKs retire exact history as snd_una advances. Partial
   * retirement trims only the active prefix. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1300);
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  tcp_test_rcv_sacks (tc, 1200, &rs);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tcp_test_dsack_rxt_count (tc) == 1 &&
	      tcp_test_dsack_rxt_at (tc, 0)->start == 1200 &&
	      tcp_test_dsack_rxt_at (tc, 0)->end == 1300 && tc->dsack_pending_bytes == 200,
	    "clean ACK trims acknowledged exact D-SACK history");
  tc->snd_una = 1200;
  tcp_test_rcv_sacks (tc, 1300, &rs);
  TCP_TEST (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tcp_dsack_has_history (tc) &&
	      tc->dsack_pending_bytes == 200,
	    "clean ACK frees fully acknowledged exact D-SACK history");

  /* Prefix retirement returns nodes to the pool for later retransmissions. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1300, 1400);
  TCP_TEST (pool_len (tc->dsack_rxt) == 3, "pool contains metadata and two ranges");
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  tcp_test_rcv_sacks (tc, 1200, &rs);
  tc->snd_una = 1200;
  tcp_dsack_track_retransmit (tc, 1500, 1600);
  TCP_TEST (
    pool_len (tc->dsack_rxt) == 3 && tcp_test_dsack_rxt_count (tc) == 2 &&
      tcp_test_dsack_rxt_at (tc, 0)->start == 1300 && tcp_test_dsack_rxt_at (tc, 0)->end == 1400 &&
      tcp_test_dsack_rxt_at (tc, 1)->start == 1500 && tcp_test_dsack_rxt_at (tc, 1)->end == 1600,
    "retired D-SACK range pool slot is reused");

  /* Clearing one episode preserves active retransmissions so the next
   * recovery can seed its aggregate accounting from them. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_recovery_clear (tc);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && !tcp_dsack_has_history (tc) &&
	      !tc->dsack_pending_bytes,
	    "episode clear preserves active retransmission ranges");
  tcp_dsack_recovery_init (tc);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tcp_dsack_has_history (tc) &&
	      tc->dsack_pending_bytes == 100,
	    "new recovery seeds aggregate D-SACK accounting from active ranges");

  /* Per-segment D-SACKs for one contiguous retransmit run must not rebuild
   * enough redundant marked ranges to overflow bounded history. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tc->snd_nxt = 1100 + (TCP_MAX_DSACK_RXT_RANGES + 1) * tc->snd_mss;
  for (u32 i = 0; i < TCP_MAX_DSACK_RXT_RANGES + 1; i++)
    tcp_dsack_track_retransmit (tc, 1100 + i * tc->snd_mss, 1100 + (i + 1) * tc->snd_mss);
  TCP_TEST (tcp_test_dsack_rxt_count (tc) == 1, "coalesce a long contiguous retransmit run");
  for (u32 i = 0; i < TCP_MAX_DSACK_RXT_RANGES + 1; i++)
    {
      u32 seg = TCP_MAX_DSACK_RXT_RANGES - i;

      vec_reset_length (tc->rcv_opts.sacks);
      block.start = 1100 + seg * tc->snd_mss;
      block.end = block.start + tc->snd_mss;
      vec_add1 (tc->rcv_opts.sacks, block);
      tc->rcv_opts.n_sack_blocks = 1;
      clib_memset (&rs, 0, sizeof (rs));
      tcp_rcv_dsack (tc, tc->snd_nxt, &rs);
    }
  TCP_TEST (!(tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW) && tcp_test_dsack_rxt_count (tc) == 1 &&
	      (rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "per-segment D-SACKs retain compact history beyond the range limit");

  /* A fragmented recovery can retain at most a bounded number of ranges.
   * Overflow abandons undo for this episode without permanently disabling
   * D-SACK undo on the connection. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  for (u32 i = 0; i < TCP_MAX_DSACK_RXT_RANGES; i++)
    tcp_dsack_track_retransmit (tc, 1000 + 200 * i, 1100 + 200 * i);
  TCP_TEST (tcp_test_dsack_rxt_count (tc) == TCP_MAX_DSACK_RXT_RANGES &&
	      !(tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW),
	    "retain D-SACK retransmit ranges up to the limit");
  tcp_dsack_track_retransmit (tc, 1000 + 200 * TCP_MAX_DSACK_RXT_RANGES,
			      1100 + 200 * TCP_MAX_DSACK_RXT_RANGES);
  TCP_TEST (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && (tc->dsack_flags & TCP_DSACK_INELIGIBLE) &&
	      (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED),
	    "range overflow abandons only the current D-SACK undo episode");
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 800;
  block.end = 900;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_rcv_dsack (tc, tc->snd_una, &rs);
  TCP_TEST ((rs.ack_flags & TCP_ACK_F_DSACK) && !(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED),
	    "delayed D-SACK after overflow does not disable future undo");
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  rs.ack_flags = 0;
  tcp_test_rcv_sacks (tc, tc->snd_una + 100, &rs);
  TCP_TEST (tcp_dsack_has_history (tc) && (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW),
	    "ACK progress retains the overflowed recovery episode");
  tcp_dsack_recovery_init (tc);
  TCP_TEST (!tcp_dsack_has_history (tc) &&
	      !(tc->dsack_flags & (TCP_DSACK_INELIGIBLE | TCP_DSACK_RXT_OVERFLOW)),
	    "next recovery retires the overflowed recovery episode");

  /* D-SACK matching updates only aggregate state and never splits active
   * retransmit ranges. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  for (u32 i = 0; i < TCP_MAX_DSACK_RXT_RANGES; i++)
    tcp_dsack_track_retransmit (tc, 1100 + 200 * i, 1200 + 200 * i);
  block.start = 1100;
  block.end = 1150;
  vec_add1 (tc->rcv_opts.sacks, block);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 2;
  tcp_rcv_dsack (tc, tc->snd_una, &rs);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) &&
	      !(tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW) &&
	      tcp_test_dsack_rxt_count (tc) == TCP_MAX_DSACK_RXT_RANGES &&
	      tc->dsack_pending_bytes == TCP_MAX_DSACK_RXT_RANGES * 100 - 50,
	    "D-SACK matching preserves compact active history");

  /* Repeated retransmissions and D-SACKs use aggregate copy accounting, but
   * the ambiguous retransmit path remains ineligible for undo. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_congestion, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS) && tc->dsack_pending_bytes == 100 &&
	      (tc->dsack_flags & TCP_DSACK_INELIGIBLE),
	    "one D-SACK accounts one ambiguous retransmission copy");
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  vec_reset_length (tc->rcv_opts.sacks);
  rs.ack_flags = 0;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) && !tc->dsack_pending_bytes,
	    "repeated D-SACK accounts the second copy without enabling undo");

  /* A D-SACK range containing bytes that were not retransmitted is network
   * duplication evidence, even if its total retransmitted overlap matches
   * the episode's retransmitted byte count. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1300, 1400);
  block.start = 1100;
  block.end = 1400;
  vec_add1 (tc->rcv_opts.sacks, block);
  block.start = 1100;
  block.end = 1500;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 2;
  tcp_rcv_dsack (tc, tc->snd_una, &rs);
  TCP_TEST (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) &&
	      (tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) &&
	      !(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "active D-SACK gap disables undo and discards history");

  /* Overlapping D-SACK evidence cannot credit more bytes than remain
   * pending for the episode. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1300);
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "partial D-SACK does not prove the whole retransmission duplicate");
  vec_reset_length (tc->rcv_opts.sacks);
  rs.ack_flags = 0;
  block.start = 1150;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS) &&
	      (tc->dsack_flags & TCP_DSACK_INELIGIBLE) && tc->dsack_pending_bytes == 100,
	    "overlapping D-SACK cannot exceed pending retransmit evidence");

  /* Rescue, repeated-RTO and reneging paths make an episode ineligible
   * before an ambiguous retransmission can be used for undo. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
  tcp_dsack_track_retransmit (tc, 1150, 1250);
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 1200;
  block.end = 1250;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_INELIGIBLE) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) &&
	      !(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "ambiguous retransmit path is ineligible but remains recognized");

  /* Union deletion must preserve the sorted range invariant. Otherwise an
   * early break while matching a later D-SACK can miss retained history. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tcp_dsack_track_retransmit (tc, 1250, 1400);
  tcp_dsack_track_retransmit (tc, 1600, 1700);
  tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
  tcp_dsack_track_retransmit (tc, 1100, 1300);
  TCP_TEST (tcp_test_dsack_rxt_count (tc) == 2 && tcp_test_dsack_rxt_at (tc, 0)->start == 1100 &&
	      tcp_test_dsack_rxt_at (tc, 0)->end == 1400 &&
	      tcp_test_dsack_rxt_at (tc, 1)->start == 1600 &&
	      tcp_test_dsack_rxt_at (tc, 1)->end == 1700,
	    "union of multiple retransmissions remains sorted and disjoint");
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 1300;
  block.end = 1400;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_INELIGIBLE) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) &&
	      !(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "D-SACK after a multi-range union matches retained history");

  /* Eifel may undo first and retain an ineligible history solely to recognize
   * the later D-SACK. Matching that history is not network duplication and
   * must not disable D-SACK on the connection. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
  tc->snd_una = tc->snd_congestion;
  tcp_cong_recovery_off (tc);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS) &&
	      !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED),
	    "late D-SACK matching Eifel history neither re-undoes nor disables");
  vec_reset_length (tc->rcv_opts.sacks);
  rs.ack_flags = 0;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  tcp_test_rcv_sacks (tc, tc->snd_una + 100, &rs);
  TCP_TEST (tcp_dsack_has_history (tc), "ordinary ACK progress retains incomplete D-SACK history");
  tcp_dsack_recovery_init (tc);
  TCP_TEST (!tcp_dsack_has_history (tc), "next recovery retires incomplete D-SACK history");

  /* RFC 3708 A.1 applies to the SACK history at ACK arrival. Processing the
   * cumulative ACK may drain that history before D-SACK eligibility is
   * finalized. */
  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_congestion = 1200;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1000, 1100);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_una, &rs);
  TCP_TEST (tc->sack_sb.sacked_bytes == 100, "retain prior SACK history");
  vec_reset_length (tc->rcv_opts.sacks);
  rs.ack_flags = 0;
  block.start = 1000;
  block.end = 1100;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 1200, &rs);
  TCP_TEST (!tc->sack_sb.sacked_bytes && (rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "use pre-processing SACK history when cumulative ACK drains scoreboard");

  DSACK_RX_RESET ();
  tc->flags |= TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_una = 1100;
  tcp_dsack_recovery_clear (tc);
  tcp_dsack_track_retransmit (tc, 1100, 1200);
  block.start = 1100;
  block.end = 1200;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, tc->snd_congestion, &rs);
  TCP_TEST ((tc->dsack_flags & TCP_DSACK_INELIGIBLE) && !(rs.ack_flags & TCP_ACK_F_DSACK_SPURIOUS),
	    "empty SACK history at snd_una keeps whole-ACK-loss reduction");

  if (vm)
    vlib_cli_output (vm, "D-SACK receive/undo tests passed");

  scoreboard_clear (&tc->sack_sb);
  pool_free (tc->sack_sb.holes);
  vec_free (tc->rcv_opts.sacks);
  tcp_dsack_cleanup (tc);

#undef DSACK_RX_RESET
#undef DSACK_RX_INIT
  return 0;
}

static int
tcp_test_sack_tx (vlib_main_t * vm, unformat_input_t * input)
{
  tcp_connection_t _tc, *tc = &_tc;
  sack_block_t *sacks;
  int i, verbose = 0, expected;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  clib_memset (tc, 0, sizeof (*tc));

  /*
   * Add odd sack block pairs
   */
  for (i = 1; i < 10; i += 2)
    {
      tcp_update_sack_list (tc, i * 100, (i + 1) * 100);
    }

  TCP_TEST ((vec_len (tc->snd_sacks) == 5), "sack blocks %d expected %d",
	    vec_len (tc->snd_sacks), 5);
  TCP_TEST ((tc->snd_sacks[0].start = 900),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    900);

  /*
   * Try to add one extra
   */
  sacks = vec_dup (tc->snd_sacks);

  tcp_update_sack_list (tc, 1100, 1200);
  if (verbose)
    vlib_cli_output (vm, "add new segment [1100, 1200]\n%U",
		     format_tcp_sacks, tc);
  expected = 5 < TCP_MAX_SACK_BLOCKS ? 6 : 5;
  TCP_TEST ((vec_len (tc->snd_sacks) == expected),
	    "sack blocks %d expected %d", vec_len (tc->snd_sacks), expected);
  TCP_TEST ((tc->snd_sacks[0].start == 1100),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    1100);

  /* restore */
  vec_free (tc->snd_sacks);
  tc->snd_sacks = sacks;

  /*
   * Overlap first 2 segment
   */
  tc->rcv_nxt = 300;
  tcp_update_sack_list (tc, 300, 300);
  if (verbose)
    vlib_cli_output (vm, "overlap first 2 segments:\n%U",
		     format_tcp_sacks, tc);
  TCP_TEST ((vec_len (tc->snd_sacks) == 3), "sack blocks %d expected %d",
	    vec_len (tc->snd_sacks), 3);
  TCP_TEST ((tc->snd_sacks[0].start == 900),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    500);

  /*
   * Add a new segment
   */
  tcp_update_sack_list (tc, 1100, 1200);
  if (verbose)
    vlib_cli_output (vm, "add new segment [1100, 1200]\n%U",
		     format_tcp_sacks, tc);
  TCP_TEST ((vec_len (tc->snd_sacks) == 4), "sack blocks %d expected %d",
	    vec_len (tc->snd_sacks), 4);
  TCP_TEST ((tc->snd_sacks[0].start == 1100),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    1100);

  /*
   * Join middle segments
   */
  tcp_update_sack_list (tc, 800, 900);
  if (verbose)
    vlib_cli_output (vm, "join middle segments [800, 900]\n%U",
		     format_tcp_sacks, tc);

  TCP_TEST ((vec_len (tc->snd_sacks) == 3), "sack blocks %d expected %d",
	    vec_len (tc->snd_sacks), 3);
  TCP_TEST ((tc->snd_sacks[0].start == 700),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    1100);

  /*
   * Advance rcv_nxt to overlap all
   */
  tc->rcv_nxt = 1200;
  tcp_update_sack_list (tc, 1200, 1200);
  if (verbose)
    vlib_cli_output (vm, "advance rcv_nxt to 1200\n%U", format_tcp_sacks, tc);
  TCP_TEST ((vec_len (tc->snd_sacks) == 0), "sack blocks %d expected %d",
	    vec_len (tc->snd_sacks), 0);


  /*
   * Add 2 blocks, overwrite first and update rcv_nxt to also remove it
   */

  vec_reset_length (tc->snd_sacks);
  tc->rcv_nxt = 0;

  tcp_update_sack_list (tc, 100, 200);
  tcp_update_sack_list (tc, 300, 400);

  if (verbose)
    vlib_cli_output (vm, "add [100, 200] [300, 400]\n%U",
		     format_tcp_sacks, tc);
  TCP_TEST ((vec_len (tc->snd_sacks) == 2),
	    "sack blocks %d expected %d", vec_len (tc->snd_sacks), 2);
  TCP_TEST ((tc->snd_sacks[0].start == 300),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    300);

  tc->rcv_nxt = 100;
  tcp_update_sack_list (tc, 100, 100);
  if (verbose)
    vlib_cli_output (vm, "add [100, 200] rcv_nxt = 100\n%U",
		     format_tcp_sacks, tc);
  TCP_TEST ((vec_len (tc->snd_sacks) == 1),
	    "sack blocks %d expected %d", vec_len (tc->snd_sacks), 1);
  TCP_TEST ((tc->snd_sacks[0].start == 300),
	    "first sack block start %u expected %u", tc->snd_sacks[0].start,
	    300);
  return 0;
}

static int
tcp_test_snd_wnd_max (void)
{
  tcp_connection_t _tc, *tc = &_tc;

  clib_memset (tc, 0, sizeof (*tc));

  tc->snd_wnd_max = 1000;
  tc->snd_una = 1000;
  tc->snd_nxt = 1500;
  tc->bytes_out = 800;
  tc->bytes_retrans = 100;
  TCP_TEST (tcp_old_ack_wnd (tc) == 200, "bound old ACK history by cumulatively acknowledged data");

  tc->bytes_out = (1ULL << 32) + 2000;
  TCP_TEST (tcp_old_ack_wnd (tc) == tc->snd_wnd_max,
	    "retain maximum send-window bound across sequence wrap");

  return 0;
}

static int
tcp_test_sack (vlib_main_t * vm, unformat_input_t * input)
{
  int res = 0;

  /* Run all tests */
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    {
      if (tcp_test_sack_tx (vm, input))
	{
	  return -1;
	}

      if (tcp_test_sack_rx (vm, input))
	{
	  return -1;
	}

      if (tcp_test_dsack_rx (vm))
	{
	  return -1;
	}

      if (tcp_test_snd_wnd_max ())
	{
	  return -1;
	}
    }
  else
    {
      if (unformat (input, "tx"))
	{
	  res = tcp_test_sack_tx (vm, input);
	}
      else if (unformat (input, "rx"))
	{
	  res = tcp_test_sack_rx (vm, input);
	  if (!res)
	    res = tcp_test_dsack_rx (vm);
	}
    }

  return res;
}

static int
tcp_test_lookup (vlib_main_t * vm, unformat_input_t * input)
{
  session_main_t *smm = &session_main;
  transport_connection_t _tc1, *tc1 = &_tc1, _tc2, *tc2 = &_tc2, *tconn;
  tcp_connection_t *tc;
  session_t *s, *s1;
  u8 cmp = 0, is_filtered = 0;
  u32 sidx;

  /*
   * Allocate fake session and connection 1
   */
  pool_get (smm->wrk[0].sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->session_index = sidx = s - smm->wrk[0].sessions;

  tc = tcp_connection_alloc (0);
  tc->connection.s_index = s->session_index;
  s->connection_index = tc->connection.c_index;

  tc->connection.lcl_ip.ip4.as_u32 = clib_host_to_net_u32 (0x06000101);
  tc->connection.rmt_ip.ip4.as_u32 = clib_host_to_net_u32 (0x06000103);
  tc->connection.lcl_port = 35051;
  tc->connection.rmt_port = 53764;
  tc->connection.proto = TRANSPORT_PROTO_TCP;
  tc->connection.is_ip4 = 1;
  clib_memcpy_fast (tc1, &tc->connection, sizeof (*tc1));

  /*
   * Allocate fake session and connection 2
   */
  pool_get (smm->wrk[0].sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->session_index = s - smm->wrk[0].sessions;

  tc = tcp_connection_alloc (0);
  tc->connection.s_index = s->session_index;
  s->connection_index = tc->connection.c_index;

  tc->connection.lcl_ip.ip4.as_u32 = clib_host_to_net_u32 (0x06000101);
  tc->connection.rmt_ip.ip4.as_u32 = clib_host_to_net_u32 (0x06000102);
  tc->connection.lcl_port = 38225;
  tc->connection.rmt_port = 53764;
  tc->connection.proto = TRANSPORT_PROTO_TCP;
  tc->connection.is_ip4 = 1;
  clib_memcpy_fast (tc2, &tc->connection, sizeof (*tc2));

  /*
   * Confirm that connection lookup works
   */

  s1 = pool_elt_at_index (smm->wrk[0].sessions, sidx);
  session_lookup_add_connection (tc1, session_handle (s1));
  tconn = session_lookup_connection_wt4 (0, &tc1->lcl_ip.ip4,
					 &tc1->rmt_ip.ip4,
					 tc1->lcl_port, tc1->rmt_port,
					 tc1->proto, 0, &is_filtered);

  TCP_TEST ((tconn != 0), "connection exists");
  cmp = (memcmp (&tconn->rmt_ip, &tc1->rmt_ip, sizeof (tc1->rmt_ip)) == 0);
  TCP_TEST ((cmp), "rmt ip is identical %d", cmp);
  TCP_TEST ((tconn->lcl_port == tc1->lcl_port),
	    "rmt port is identical %d", tconn->lcl_port == tc1->lcl_port);

  /*
   * Non-existing connection lookup should not work
   */

  tconn = session_lookup_connection_wt4 (0, &tc2->lcl_ip.ip4,
					 &tc2->rmt_ip.ip4,
					 tc2->lcl_port, tc2->rmt_port,
					 tc2->proto, 0, &is_filtered);
  TCP_TEST ((tconn == 0), "lookup result should be null");

  /*
   * Delete and lookup again
   */
  session_lookup_del_connection (tc1);
  tconn = session_lookup_connection_wt4 (0, &tc1->lcl_ip.ip4,
					 &tc1->rmt_ip.ip4,
					 tc1->lcl_port, tc1->rmt_port,
					 tc1->proto, 0, &is_filtered);
  TCP_TEST ((tconn == 0), "lookup result should be null");
  tconn = session_lookup_connection_wt4 (0, &tc2->lcl_ip.ip4,
					 &tc2->rmt_ip.ip4,
					 tc2->lcl_port, tc2->rmt_port,
					 tc2->proto, 0, &is_filtered);
  TCP_TEST ((tconn == 0), "lookup result should be null");

  /*
   * Re-add and lookup tc2
   */
  session_lookup_add_connection (tc1, tc1->s_index);
  tconn = session_lookup_connection_wt4 (0, &tc2->lcl_ip.ip4,
					 &tc2->rmt_ip.ip4,
					 tc2->lcl_port, tc2->rmt_port,
					 tc2->proto, 0, &is_filtered);
  TCP_TEST ((tconn == 0), "lookup result should be null");

  return 0;
}

static int
tcp_test_session (vlib_main_t * vm, unformat_input_t * input)
{
  int rv = 0;
  tcp_connection_t *tc0;
  ip4_address_t local, remote;
  u16 local_port, remote_port;
  int is_add = 1;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else
	break;
    }

  if (is_add)
    {
      local.as_u32 = clib_host_to_net_u32 (0x06000101);
      remote.as_u32 = clib_host_to_net_u32 (0x06000102);
      local_port = clib_host_to_net_u16 (1234);
      remote_port = clib_host_to_net_u16 (11234);

      tc0 = tcp_connection_alloc (0);

      tc0->state = TCP_STATE_ESTABLISHED;
      tc0->rcv_las = 1;
      tc0->c_lcl_port = local_port;
      tc0->c_rmt_port = remote_port;
      tc0->c_is_ip4 = 1;
      tc0->c_thread_index = 0;
      tc0->c_lcl_ip4.as_u32 = local.as_u32;
      tc0->c_rmt_ip4.as_u32 = remote.as_u32;
      tc0->rcv_opts.mss = 1450;
      tcp_connection_init_vars (tc0);

      TCP_EVT (TCP_EVT_OPEN, tc0);

      if (session_stream_accept (&tc0->connection, 0 /* listener index */ ,
				 0 /* thread index */ , 0 /* notify */ ))
	clib_warning ("stream_session_accept failed");

      session_stream_accept_notify (&tc0->connection);
    }
  else
    {
      tc0 = tcp_connection_get (0 /* connection index */ , 0 /* thread */ );
      tc0->state = TCP_STATE_CLOSED;
      session_transport_closing_notify (&tc0->connection);
    }

  return rv;
}

static inline int
tbt_seq_lt (u32 a, u32 b)
{
  return seq_lt (a, b);
}

static void
tcp_test_set_time (clib_thread_index_t thread_index, u32 val)
{
  session_main.wrk[thread_index].last_vlib_time = val;
  tcp_set_time_now (&tcp_main.wrk[thread_index], val);
}

/* Build a deterministic CUBIC avoidance epoch through the registered
 * callbacks.  This deliberately avoids depending on cubic_data_t's private
 * layout. */
static void
tcp_test_cubic_init_epoch (tcp_connection_t *tc, clib_thread_index_t thread_index, u32 snd_mss,
			   u32 w_max_segs)
{
  clib_memset (tc, 0, sizeof (*tc));
  tc->c_thread_index = thread_index;
  tc->snd_mss = snd_mss;
  tc->tx_fifo_size = 1 << 30;
  tc->mrtt_us = 0.1;
  tc->srtt = 0.1 / TCP_TICK;
  tc->cc_algo = tcp_cc_algo_get (TCP_CC_CUBIC);
  tc->cc_algo->init (tc);

  tc->cwnd = w_max_segs * snd_mss;
  tc->ssthresh = tc->cwnd;
  tc->cc_algo->congestion (tc);
  tc->cc_algo->recovered (tc);
}

/* Compare the congestion-window and accumulator trajectories of two CUBIC
 * avoidance epochs. */
static int
tcp_test_cubic_compare_growth (tcp_connection_t *tc, tcp_connection_t *ref, u32 n_acks)
{
  tcp_rate_sample_t rs = { .bytes_acked = tc->snd_mss, .acked_and_sacked = tc->snd_mss };
  u32 i;

  for (i = 0; i < n_acks; i++)
    {
      tc->snd_una += rs.bytes_acked;
      ref->snd_una += rs.bytes_acked;
      tc->cwnd_limited_seq = tc->snd_una;
      ref->cwnd_limited_seq = ref->snd_una;
      tc->cc_algo->rcv_ack (tc, &rs);
      ref->cc_algo->rcv_ack (ref, &rs);
      if (tc->cwnd != ref->cwnd || tc->cwnd_acc_bytes != ref->cwnd_acc_bytes)
	{
	  fformat (stderr,
		   "FAIL:%d: cubic growth diverged at ack %u: cwnd %u expected %u, "
		   "accumulator %u expected %u\n",
		   __LINE__, i, tc->cwnd, ref->cwnd, tc->cwnd_acc_bytes, ref->cwnd_acc_bytes);
	  return 1;
	}
    }
  return 0;
}

static int
tcp_test_cwnd_limited_marking (void)
{
  const u32 snd_mss = 1000, cwnd = 10 * snd_mss;
  tcp_connection_t _tc, *tc = &_tc;

  clib_memset (tc, 0, sizeof (*tc));
  tc->snd_mss = snd_mss;
  tc->snd_una = 100 * snd_mss;
  tc->cwnd = cwnd;
  tc->ssthresh = 2 * cwnd;
  tc->cwnd_limited_seq = tc->snd_una;

  /* A smaller receive window, not cwnd, limits this flight even when slow
   * start's half-window usage threshold is exceeded. */
  tc->snd_wnd = 3 * cwnd / 4;
  tc->snd_nxt = tc->snd_una + tc->snd_wnd;
  tcp_cc_update_cwnd_limited (tc, tc->snd_wnd);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_una),
	    "rwnd-limited flight is not marked cwnd-limited");

  /* A full congestion window is positive evidence of cwnd limitation. */
  tc->snd_wnd = cwnd;
  tc->snd_nxt = tc->snd_una + cwnd;
  tcp_cc_update_cwnd_limited (tc, cwnd);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_nxt), "full flight is marked cwnd-limited");

  /* Exactly half of cwnd does not satisfy the strict slow-start usage
   * threshold. */
  tc->cwnd_limited_seq = tc->snd_una;
  tc->snd_nxt = tc->snd_una + cwnd / 2;
  tcp_cc_update_cwnd_limited (tc, cwnd / 2);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_una),
	    "half-window slow-start flight is not eligible for growth");

  /* More than half of cwnd validates standard slow-start growth. */
  tc->snd_nxt++;
  tcp_cc_update_cwnd_limited (tc, cwnd / 2 + 1);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_nxt),
	    "over-half-window slow-start flight is eligible for growth");

  /* The half-window heuristic applies only during slow start. */
  tc->ssthresh = cwnd / 2;

  /* Headroom with no unsent data is application limited. */
  tc->cwnd_limited_seq = tc->snd_una;
  tc->snd_nxt = tc->snd_una + cwnd - 2 * snd_mss;
  tcp_cc_update_cwnd_limited (tc, cwnd - 2 * snd_mss);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_una),
	    "application-limited flight is not marked cwnd-limited");

  /* More queued data, but not enough to fill cwnd, is still application
   * limited. */
  tcp_cc_update_cwnd_limited (tc, cwnd - snd_mss);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_una),
	    "short queued flight is not marked cwnd-limited");

  /* Enough data to fill cwnd is not application limited merely because
   * pacing or output scheduling ended this burst early. */
  tcp_cc_update_cwnd_limited (tc, cwnd);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_nxt), "backlogged flight is marked cwnd-limited");

  /* Sub-MSS headroom cannot be used for another full segment. */
  tc->cwnd_limited_seq = tc->snd_una;
  tc->snd_nxt = tc->snd_una + cwnd - snd_mss / 2;
  tcp_cc_update_cwnd_limited (tc, cwnd - snd_mss / 2 + 1);
  TCP_TEST ((tc->cwnd_limited_seq == tc->snd_nxt),
	    "queued flight with sub-mss headroom is marked cwnd-limited");

  /* An ACK that starts before the marker covers data from a cwnd-limited
   * flight even if it cumulatively acknowledges data beyond the marker. */
  {
    tcp_rate_sample_t rs = { .bytes_acked = 3 * snd_mss };

    tc->snd_una = 200 * snd_mss;
    tc->cwnd_limited_seq = tc->snd_una - 2 * snd_mss;
    TCP_TEST (tcp_cc_is_cwnd_limited (tc, &rs), "cumulative ACK crossing marker is cwnd-limited");

    rs.bytes_acked = snd_mss;
    TCP_TEST (!tcp_cc_is_cwnd_limited (tc, &rs),
	      "cumulative ACK starting past marker is not cwnd-limited");
  }

  return 0;
}

static int
tcp_test_cwnd_limited_growth (void)
{
  const tcp_cc_algorithm_type_e cc_types[] = { TCP_CC_NEWRENO, TCP_CC_CUBIC };
  const char *cc_names[] = { "newreno", "cubic" };
  const u32 snd_mss = 1000, initial_cwnd = 10 * snd_mss, n_app_limited_acks = 128;
  tcp_rate_sample_t rs = { .bytes_acked = snd_mss, .acked_and_sacked = snd_mss };
  tcp_connection_t _tc, *tc = &_tc;
  u32 i, j;

  for (i = 0; i < ARRAY_LEN (cc_types); i++)
    {
      clib_memset (tc, 0, sizeof (*tc));
      tc->cc_algo = tcp_cc_algo_get (cc_types[i]);
      tc->snd_mss = snd_mss;
      tc->snd_una = 2 * snd_mss;
      tc->cwnd = initial_cwnd;
      tc->ssthresh = 1 << 30;
      tc->tx_fifo_size = 1 << 30;

      /* None of these ACKs cover data from a cwnd-limited flight. */
      tc->cwnd_limited_seq = tc->snd_una - rs.bytes_acked;
      for (j = 0; j < n_app_limited_acks; j++)
	{
	  tc->cc_algo->rcv_ack (tc, &rs);
	  tc->snd_una += rs.bytes_acked;
	}
      TCP_TEST ((tc->cwnd == initial_cwnd), "%s does not grow over %u app-limited ACKs",
		cc_names[i], n_app_limited_acks);

      /* Extending the marker through the ACK permits normal slow-start
       * growth. */
      tc->cwnd_limited_seq = tc->snd_una;
      tc->cc_algo->rcv_ack (tc, &rs);
      TCP_TEST ((tc->cwnd == initial_cwnd + snd_mss), "%s grows when cwnd-limited", cc_names[i]);

      /* Once cumulative ACKs pass the marker, growth stops again. */
      tc->snd_una += rs.bytes_acked;
      tc->cc_algo->rcv_ack (tc, &rs);
      TCP_TEST ((tc->cwnd == initial_cwnd + snd_mss), "%s expires cwnd-limited marker",
		cc_names[i]);

      /* The next send-side update ages the expired marker. */
      tc->snd_wnd = 0;
      tc->snd_nxt = tc->snd_una;
      tcp_cc_update_cwnd_limited (tc, 0);
      TCP_TEST ((tc->cwnd_limited_seq == tc->snd_una),
		"%s ages expired cwnd-limited marker on send", cc_names[i]);
    }

  return 0;
}

/* RFC 9438 excludes continuously application-limited time from the CUBIC
 * epoch even when the flight never drains and START_TX is not generated. */
static int
tcp_test_cubic_app_limited (void)
{
  const clib_thread_index_t thread_index = 0;
  const u32 snd_mss = 1000;
  tcp_rate_sample_t rs = { .bytes_acked = snd_mss, .acked_and_sacked = snd_mss };
  tcp_connection_t _tc, *tc = &_tc, _ref, *ref = &_ref;
  u32 initial_cwnd;

  tcp_test_set_time (thread_index, 1);
  tcp_test_cubic_init_epoch (tc, thread_index, snd_mss, 100);
  initial_cwnd = tc->cwnd;

  /* The ACK at time 2 belongs to a flight that did not exhaust cwnd. */
  tcp_test_set_time (thread_index, 2);
  tc->snd_una = 2 * snd_mss;
  tc->cwnd_limited_seq = tc->snd_una - rs.bytes_acked;
  tc->cc_algo->rcv_ack (tc, &rs);
  TCP_TEST ((tc->cwnd == initial_cwnd), "cubic pauses on an app-limited ACK");

  /* At time 10 the sender becomes cwnd-limited without first draining the
   * flight.  Its frozen one-second epoch must match an epoch started at 9. */
  tcp_test_set_time (thread_index, 9);
  tcp_test_cubic_init_epoch (ref, thread_index, snd_mss, 100);
  tcp_test_set_time (thread_index, 10);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 1) == 0),
	    "cubic excludes a continuous app-limited interval");
  tcp_test_set_time (thread_index, 11);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 64) == 0),
	    "cubic preserves its curve after continuous app limitation");

  /* A paused epoch stays frozen across restarted app-limited flights.  If
   * START_TX resumed it, every short flight would add roughly one RTT. */
  tcp_test_set_time (thread_index, 20);
  tcp_test_cubic_init_epoch (tc, thread_index, snd_mss, 100);
  tcp_test_set_time (thread_index, 21);
  tc->snd_una = 2 * snd_mss;
  tc->cwnd_limited_seq = tc->snd_una - rs.bytes_acked;
  tc->cc_algo->rcv_ack (tc, &rs);
  tc->delivered_time = tcp_time_now_us (thread_index);

  tcp_test_set_time (thread_index, 30);
  tc->cc_algo->event (tc, TCP_CC_EVT_START_TX);
  tcp_test_set_time (thread_index, 31);
  tc->snd_una += rs.bytes_acked;
  tc->cwnd_limited_seq = tc->snd_una - rs.bytes_acked;
  tc->cc_algo->rcv_ack (tc, &rs);
  tc->delivered_time = tcp_time_now_us (thread_index);

  tcp_test_set_time (thread_index, 40);
  tc->cc_algo->event (tc, TCP_CC_EVT_START_TX);
  tcp_test_set_time (thread_index, 41);
  tc->snd_una += rs.bytes_acked;
  tc->cwnd_limited_seq = tc->snd_una - rs.bytes_acked;
  tc->cc_algo->rcv_ack (tc, &rs);
  tc->delivered_time = tcp_time_now_us (thread_index);

  /* When bulk transmission resumes, the first cwnd-limited ACK resumes the
   * original one-second epoch. */
  tcp_test_set_time (thread_index, 50);
  tc->cc_algo->event (tc, TCP_CC_EVT_START_TX);
  tcp_test_cubic_init_epoch (ref, thread_index, snd_mss, 100);
  tcp_test_set_time (thread_index, 51);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 1) == 0),
	    "cubic excludes repeated app-limited flights");
  tcp_test_set_time (thread_index, 52);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 64) == 0),
	    "cubic preserves its curve after repeated app limitation");

  return 0;
}

static int
tcp_test_cubic_undo (vlib_main_t *vm)
{
  const clib_thread_index_t thread_index = 0;
  const u32 snd_mss = 1000, restored_cwnd = 60 * snd_mss;
  const u32 restored_ssthresh = 50 * snd_mss;
  tcp_connection_t _tc, *tc = &_tc, _ref, *ref = &_ref;
  tcp_cc_algorithm_t *cubic = tcp_cc_algo_get (TCP_CC_CUBIC);
  u32 i;

  TCP_TEST ((cubic->undo_recovery != 0), "cubic has undo recovery callback");

  /* Undo after fast recovery reconstructs an avoidance epoch at the restored
   * window and pre-event w_max. */
  tcp_test_set_time (thread_index, 1);
  tcp_test_cubic_init_epoch (tc, thread_index, snd_mss, 100);
  clib_memcpy_fast (ref, tc, sizeof (*ref));
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;
  tc->cc_algo->congestion (tc);
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 2);
  tc->cc_algo->undo_recovery (tc);
  TCP_TEST ((tc->cwnd == restored_cwnd && tc->ssthresh == restored_ssthresh),
	    "cubic fast undo leaves restored generic state unchanged");
  ref->ssthresh = restored_cwnd;
  ref->cc_algo->recovered (ref);
  ref->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 3);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 96) == 0),
	    "cubic fast recovery undo restores coherent growth");
  TCP_TEST ((tc->cwnd > restored_cwnd), "cubic fast recovery undo resumes growth (%u > %u)",
	    tc->cwnd, restored_cwnd);

  /* Repeated loss notifications in one RTO recovery event retain the entry
   * state needed to reconstruct the epoch on undo. */
  tcp_test_set_time (thread_index, 10);
  tcp_test_cubic_init_epoch (tc, thread_index, snd_mss, 100);
  clib_memcpy_fast (ref, tc, sizeof (*ref));
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;
  tc->cc_algo->congestion (tc);
  for (i = 0; i < 3; i++)
    tc->cc_algo->loss (tc);
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 11);
  tc->cc_algo->undo_recovery (tc);
  TCP_TEST ((tc->cwnd == restored_cwnd && tc->ssthresh == restored_ssthresh),
	    "cubic rto undo leaves restored generic state unchanged");
  ref->ssthresh = restored_cwnd;
  ref->cc_algo->recovered (ref);
  ref->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 12);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 96) == 0),
	    "cubic rto undo restores coherent growth after repeated loss callbacks");
  TCP_TEST ((tc->cwnd > restored_cwnd), "cubic rto undo resumes growth (%u > %u)", tc->cwnd,
	    restored_cwnd);

  /* A restored window at or above w_max starts a convex epoch with K = 0. */
  tcp_test_set_time (thread_index, 20);
  tcp_test_cubic_init_epoch (tc, thread_index, snd_mss, 50);
  clib_memcpy_fast (ref, tc, sizeof (*ref));
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;
  tc->cc_algo->congestion (tc);
  tc->cwnd = restored_cwnd;
  tc->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 21);
  tc->cc_algo->undo_recovery (tc);
  TCP_TEST ((tc->cwnd == restored_cwnd && tc->ssthresh == restored_ssthresh),
	    "cubic K=0 undo leaves restored generic state unchanged");
  ref->ssthresh = restored_ssthresh;
  ref->cc_algo->loss (ref);
  ref->cwnd = restored_cwnd;
  ref->ssthresh = restored_ssthresh;

  tcp_test_set_time (thread_index, 22);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 32) == 0),
	    "cubic undo handles restored window at or above w_max");
  TCP_TEST ((tc->cwnd <= restored_cwnd + snd_mss), "cubic K=0 epoch does not jump cwnd (%u)",
	    tc->cwnd);

  return 0;
}

/* CUBIC shifts its epoch by the local sender's idle interval, recorded when
 * the flight drains.  Receive-side PAWS state advances independently and must
 * not affect that interval. */
static int
tcp_test_cubic_idle (vlib_main_t *vm)
{
  const clib_thread_index_t thread_index = 0;
  tcp_connection_t _tc, *tc = &_tc, _ref, *ref = &_ref;

  tcp_test_set_time (thread_index, 1);
  tcp_test_cubic_init_epoch (tc, thread_index, 1000, 100);

  /* The flight drains at time 2 and starts the local sender's idle interval. */
  tcp_test_set_time (thread_index, 2);
  tc->delivered_time = tcp_time_now_us (thread_index);
  tc->tsval_recent_age = tcp_time_tstamp (thread_index);

  /* Receive-side PAWS state may advance while the local sender remains idle.
   * The expected epoch starts at time 9: the original time 1 epoch shifted by
   * the eight time units since the flight drained. */
  tcp_test_set_time (thread_index, 9);
  tc->tsval_recent_age = tcp_time_tstamp (thread_index);
  tcp_test_cubic_init_epoch (ref, thread_index, 1000, 100);

  tcp_test_set_time (thread_index, 10);
  tc->cc_algo->event (tc, TCP_CC_EVT_START_TX);
  /* Byte tracking starts a new delivery-rate interval after congestion
   * control consumes the drain time.  That reset must not affect CUBIC. */
  tc->delivered_time = tcp_time_now_us (thread_index);

  tcp_test_set_time (thread_index, 11);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 64) == 0),
	    "cubic sender idle shifts the epoch by the local idle time");

  /* Before the first delivered flight there is no delivery-rate baseline.
   * Starting transmission must begin a fresh epoch at the current time. */
  tcp_test_set_time (thread_index, 20);
  tcp_test_cubic_init_epoch (tc, thread_index, 1000, 100);
  tcp_test_set_time (thread_index, 30);
  tc->cc_algo->event (tc, TCP_CC_EVT_START_TX);
  tcp_test_cubic_init_epoch (ref, thread_index, 1000, 100);
  tcp_test_set_time (thread_index, 31);
  TCP_TEST ((tcp_test_cubic_compare_growth (tc, ref, 32) == 0),
	    "cubic first transmission starts a fresh epoch");
  return 0;
}

static int
tcp_test_cubic (vlib_main_t *vm, unformat_input_t *input)
{
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vlib_cli_output (vm, "parse error: '%U'", format_unformat_error, input);
      return -1;
    }

  if ((rv = tcp_test_cwnd_limited_marking ()))
    return rv;

  if ((rv = tcp_test_cwnd_limited_growth ()))
    return rv;

  if ((rv = tcp_test_cubic_app_limited ()))
    return rv;

  if ((rv = tcp_test_cubic_undo (vm)))
    return rv;

  return tcp_test_cubic_idle (vm);
}

static int
tcp_test_persist_e2e (vlib_main_t *vm, unformat_input_t *input)
{
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  session_handle_t listen_handle = SESSION_INVALID_HANDLE;
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 2234;
  u32 client_index = ~0, server_index = ~0, sw_if_index[2] = { ~0, ~0 };
  u32 client_vrf = 0, server_vrf = 2, server_bytes_drained = 0, tries = 0;
  u32 total_bytes = 16 << 10, server_fifo_size = 4 << 10;
  u32 client_fifo_size = 32 << 10, i;
  u16 placeholder_server_port = 2235, placeholder_client_port = 6679;
  ip4_address_t intf_addr[2];
  session_t *client_s = 0, *server_s = 0;
  session_worker_t *swrk;
  tcp_connection_t *client_tc = 0;
  tcp_worker_ctx_t *client_wrk;
  tcp_header_t *th;
  transport_connection_t *tc;
  vlib_buffer_t *b;
  u8 *appns_id = 0, *data = 0;
  u32 bi = ~0, old_rto, old_snd_nxt;
  u32 pending_bufs_len, pending_nexts_len;
  int error, rv = 0, routes_added = 0, ns_added = 0, sessions_cleaned;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vlib_cli_output (vm, "parse error: '%U'", format_unformat_error, input);
      return -1;
    }

  session_test_reset_placeholder_state ();

  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x03030301);
  if (session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]))
    return 1;

  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x04040401);
  if (session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]))
    {
      rv = 1;
      goto cleanup;
    }

  session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
					     1 /* is_add */);
  session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
					     1 /* is_add */);
  routes_added = 1;

  appns_id = format (0, "appns_persist_server");
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = appns_id,
    .secret = placeholder_secret,
    .sw_if_index = sw_if_index[1],
    .is_add = 1,
  };
  error = vnet_app_namespace_add_del (&ns_args);
  if (!TCP_TEST_I ((error == 0), "app ns insertion should succeed: %d", error))
    {
      rv = 1;
      goto cleanup;
    }
  ns_added = 1;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_RX_FIFO_SIZE] = 4 << 10;
  options[APP_OPTIONS_TX_FIFO_SIZE] = client_fifo_size;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "tcp_test_persist_client"),
  };

  error = vnet_application_attach (&attach_args);
  if (!TCP_TEST_I ((error == 0), "client app attached"))
    {
      vec_free (attach_args.name);
      rv = 1;
      goto cleanup;
    }
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  options[APP_OPTIONS_RX_FIFO_SIZE] = server_fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = 4 << 10;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;

  attach_args.name = format (0, "tcp_test_persist_server");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  if (!TCP_TEST_I ((error == 0), "server app attached"))
    {
      vec_free (attach_args.name);
      rv = 1;
      goto cleanup;
    }
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  if (!TCP_TEST_I ((error == 0), "server bind should work"))
    {
      rv = 1;
      goto cleanup;
    }
  listen_handle = bind_args.handle;

  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };
  error = vnet_connect (&connect_args);
  if (!TCP_TEST_I ((error == 0), "connect should work"))
    {
      rv = 1;
      goto cleanup;
    }

  tries = 0;
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  if (!TCP_TEST_I ((connected_session_index != ~0), "client session should exist"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((accepted_session_index != ~0), "server session should exist"))
    {
      rv = 1;
      goto cleanup;
    }

  client_s = session_get (connected_session_index, connected_session_thread);
  server_s = session_get (accepted_session_index, accepted_session_thread);
  tc = session_get_transport (client_s);
  if (!TCP_TEST_I ((tc != 0), "client transport should exist"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = (tcp_connection_t *) tc;
  swrk = session_main_get_worker (client_tc->c_thread_index);
  client_wrk = tcp_get_worker (client_tc->c_thread_index);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < total_bytes; i++)
    data[i] = i & 0xff;

  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }

  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  tries = 0;
  while ((!tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST) ||
	  svm_fifo_max_dequeue_cons (server_s->rx_fifo) == 0) &&
	 ++tries < 200)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  if (!TCP_TEST_I (tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST), "client entered persist"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((client_tc->snd_wnd < client_tc->snd_mss),
		   "client send window is effectively zero"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((svm_fifo_max_dequeue_cons (server_s->rx_fifo) > 0),
		   "server rx fifo has unread data"))
    {
      rv = 1;
      goto cleanup;
    }

  for (i = 0; i < 2; i++)
    {
      pending_bufs_len = vec_len (swrk->pending_tx_buffers);
      pending_nexts_len = vec_len (swrk->pending_tx_nexts);
      old_snd_nxt = client_tc->snd_nxt;
      old_rto = client_tc->rto;

      tcp_timer_reset (&client_wrk->timer_wheel, client_tc, TCP_TIMER_PERSIST);
      tcp_timer_persist_handler (client_tc);

      if (!TCP_TEST_I ((vec_len (swrk->pending_tx_buffers) == pending_bufs_len + 1),
		       "persist pop %u queues one probe", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((vec_len (swrk->pending_tx_nexts) == pending_nexts_len + 1),
		       "persist pop %u queues one next index", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((client_tc->snd_nxt == old_snd_nxt),
		       "persist pop %u does not advance snd_nxt", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((client_tc->rto_boff == i + 1), "persist pop %u backs off rto", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((client_tc->rto == clib_min (old_rto << 1, TCP_RTO_MAX)),
		       "persist pop %u doubles rto", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I (tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST),
		       "persist rearmed after pop %u", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I (!tcp_timer_is_active (client_tc, TCP_TIMER_RETRANSMIT),
		       "persist pop %u does not arm retransmit", i + 1))
	{
	  rv = 1;
	  goto cleanup;
	}

      if (i != 0)
	continue;

      bi = swrk->pending_tx_buffers[pending_bufs_len];
      b = vlib_get_buffer (vm, bi);
      th = vlib_buffer_get_current (b);

      if (!TCP_TEST_I ((b->current_length == (tcp_doff (th) << 2)),
		       "first persist probe carries no payload"))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((th->flags == TCP_FLAG_ACK), "first persist probe is an ack"))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((clib_net_to_host_u32 (th->seq_number) == client_tc->snd_una - 1),
		       "first persist probe seq is snd_una - 1"))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((clib_net_to_host_u32 (th->ack_number) == client_tc->rcv_nxt),
		       "first persist probe ack is rcv_nxt"))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I (
	    (clib_net_to_host_u16 (th->window) == (client_tc->rcv_wnd >> client_tc->rcv_wscale)),
	    "first persist probe advertises current receive window"))
	{
	  rv = 1;
	  goto cleanup;
	}
      if (!TCP_TEST_I ((vnet_buffer (b)->tcp.connection_index == client_tc->c_c_index),
		       "first persist probe carries connection index"))
	{
	  rv = 1;
	  goto cleanup;
	}
    }

  /* The empty-flight transition records the local delivery baseline even
   * when delivery-rate sampling is disabled. */
  client_tc->cfg_flags &= ~TCP_CFG_F_BYTE_TRACKER;
  client_tc->delivered_time = 0;
  server_bytes_drained += session_test_drain_rx_fifo (server_s);

  tries = 0;
  while (++tries < 200)
    {
      server_bytes_drained += session_test_drain_rx_fifo (server_s);

      if (!tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST) &&
	  client_tc->snd_una == client_tc->snd_nxt && server_bytes_drained == total_bytes)
	break;

      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  if (!TCP_TEST_I (!tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST),
		   "window open turns off persist"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((client_tc->rto_boff == 0), "window open clears persist backoff"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((client_tc->snd_una == client_tc->snd_nxt),
		   "client drained all outstanding data"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((client_tc->delivered_time > 0), "flight drain records delivery time"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((server_bytes_drained == total_bytes), "server received all queued bytes"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc->snd_wnd = client_tc->snd_mss - 1;
  tcp_retransmit_timer_update (&client_wrk->timer_wheel, client_tc);
  if (!TCP_TEST_I (!tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST),
		   "sub-mss window does not arm persist"))
    {
      rv = 1;
      goto cleanup;
    }
  tcp_timer_persist_handler (client_tc);
  if (!TCP_TEST_I (!tcp_timer_is_active (client_tc, TCP_TIMER_PERSIST),
		   "sub-mss window keeps persist off"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((app_session_error == 0), "no app session errors"))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  sessions_cleaned = tcp_e2e_force_session_cleanup (vm);

  if (listen_handle != SESSION_INVALID_HANDLE)
    {
      vnet_unlisten_args_t unbind_args = {
	.handle = listen_handle,
	.app_index = server_index,
      };
      (void) vnet_unlisten (&unbind_args);
    }

  if (server_index != ~0)
    {
      vnet_app_detach_args_t detach_args = {
	.app_index = server_index,
	.api_client_index = ~0,
      };
      vnet_application_detach (&detach_args);
    }
  if (client_index != ~0)
    {
      vnet_app_detach_args_t detach_args = {
	.app_index = client_index,
	.api_client_index = ~0,
      };
      vnet_application_detach (&detach_args);
    }

  if (ns_added)
    {
      ns_args.is_add = 0;
      (void) vnet_app_namespace_add_del (&ns_args);
    }

  vlib_process_suspend (vm, 10e-3);

  if (routes_added)
    {
      session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
						 0 /* is_add */);
      session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
						 0 /* is_add */);
    }

  /* Stop the loopbacks and drain referencing graph frames before deletion. */
  for (int j = 0; j < 2; j++)
    {
      if (sw_if_index[j] == ~0)
	continue;
      (void) ip4_add_del_interface_address (vm, sw_if_index[j], &intf_addr[j], 24, 1 /* is_del */);
      vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index[j], 0);
    }
  if (sessions_cleaned && tcp_e2e_drain_graph_frames (vm))
    {
      for (int j = 0; j < 2; j++)
	if (sw_if_index[j] != ~0)
	  (void) vnet_delete_loopback_interface (sw_if_index[j]);
    }
  else
    clib_warning ("graph frames did not quiesce; preserving test loopbacks");

  vec_free (data);
  vec_free (appns_id);

  return rv;
}

static int
tcp_test_persist (vlib_main_t *vm, unformat_input_t *input)
{
  return tcp_test_persist_e2e (vm, input);
}

/* Run the RTO sequence on the connection owner and record its outcomes. */
typedef struct
{
  tcp_connection_t *tc;
  session_t *s;
  u8 *data;
  u32 total_bytes;
  /* Recorded outcomes. */
  u8 first_in_recovery;
  u8 first_cwnd_growth_enabled;
  u32 first_tr_occurences;
  u32 first_rto_boff;
  u32 cwnd_after_first;
  u32 flight_after_first;
  u32 cc_space_after_first;
  u32 snd_rxt_after_first;
  u32 rxt_delivered_after_first;
  u32 prev_cwnd_after_first;
  u32 ssthresh_after_first;
  u8 dsack_history_after_first;
  u8 dsack_ineligible_after_first;
  u8 second_still_in_recovery;
  u32 cwnd_after_second;
  u32 flight_after_second;
  u32 cc_space_after_second;
  u32 snd_rxt_after_second;
  u32 rxt_delivered_after_second;
  u32 rxt_flight_after_reneging;
  u32 snd_rxt_after_reneging;
  u32 rxt_delivered_after_reneging;
  u32 second_ssthresh;
  u32 second_prev_cwnd;
  u8 dsack_ineligible_after_second;
  u32 mss;
  u8 fr_in_fastrecovery;
  u32 fr_prev_cwnd_sentinel;
  u32 fr_prev_cwnd_after;
  u32 fr_cwnd_sentinel;
  u32 fr_cwnd_after;
  volatile u8 done;
  volatile u8 in_flight; /**< set while a callback is queued/running */
} tcp_test_rto_rpc_args_t;

static tcp_test_rto_rpc_args_t tcp_test_rto_rpc_args;

static void
tcp_test_rto_rpc (void *argp)
{
  tcp_test_rto_rpc_args_t *a = argp;
  tcp_connection_t *tc = a->tc;
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  /* First rto: starts the congestion event, enters rto recovery. */
  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
  scoreboard_clear (&tc->sack_sb);
  tcp_sack_init_rxt (tc, tc->snd_una);
  tc->snd_rxt_bytes = 0;
  tc->rxt_delivered = 0;
  tc->tr_occurences = 0;
  tc->rto_boff = 0;
  /* Model a flight that did not exhaust the pre-timeout cwnd. */
  tc->cwnd_limited_seq = tc->snd_una;
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
  a->mss = tc->snd_mss;
  tcp_timer_retransmit_handler (tc);

  a->first_in_recovery = tcp_in_recovery (tc);
  a->first_cwnd_growth_enabled = tc->cwnd_limited_seq == tc->snd_nxt;
  a->first_tr_occurences = tc->tr_occurences;
  a->first_rto_boff = tc->rto_boff;
  a->cwnd_after_first = tc->cwnd;
  a->flight_after_first = tcp_flight_size (tc);
  a->cc_space_after_first = tcp_available_cc_snd_space (tc);
  a->snd_rxt_after_first = tc->snd_rxt_bytes;
  a->rxt_delivered_after_first = tc->rxt_delivered;
  a->prev_cwnd_after_first = tc->prev_cwnd;
  a->ssthresh_after_first = tc->ssthresh;
  a->dsack_history_after_first = tcp_dsack_has_history (tc);
  a->dsack_ineligible_after_first = (tc->dsack_flags & TCP_DSACK_INELIGIBLE) != 0;

  /* Emulate ACK progress without ending recovery, then fire a second RTO. */
  tc->rto_boff = 0;
  a->second_still_in_recovery = tcp_in_recovery (tc);

  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
  tcp_timer_retransmit_handler (tc);
  a->cwnd_after_second = tc->cwnd;
  a->flight_after_second = tcp_flight_size (tc);
  a->cc_space_after_second = tcp_available_cc_snd_space (tc);
  a->snd_rxt_after_second = tc->snd_rxt_bytes;
  a->rxt_delivered_after_second = tc->rxt_delivered;
  a->second_ssthresh = tc->ssthresh;
  a->second_prev_cwnd = tc->prev_cwnd;
  a->dsack_ineligible_after_second = (tc->dsack_flags & TCP_DSACK_INELIGIBLE) != 0;

  /* A retransmitted range may be counted delivered and later reneged. In
   * that case high_rxt still covers the head but no retransmitted bytes are
   * left to retire before sending its replacement. */
  tc->rxt_delivered = tc->snd_rxt_bytes;
  tc->sack_sb.is_reneging = 1;
  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
  tcp_timer_retransmit_handler (tc);
  a->rxt_flight_after_reneging = tc->snd_rxt_bytes - tc->rxt_delivered;
  a->snd_rxt_after_reneging = tc->snd_rxt_bytes;
  a->rxt_delivered_after_reneging = tc->rxt_delivered;

  /* Fire an RTO during fast recovery and preserve its entry snapshot. */
  tcp_recovery_off (tc);
  tcp_fastrecovery_off (tc);
  tc->rto_boff = 0;
  tc->snd_una = tc->snd_nxt;
  (void) svm_fifo_enqueue (a->s->tx_fifo, a->total_bytes, a->data);
  tc->snd_wnd = a->total_bytes;
  tc->snd_nxt = tc->snd_una + a->total_bytes;
  tc->snd_congestion = tc->snd_nxt;
  tc->rcv_dupacks = 0;

  tcp_fastrecovery_on (tc);
  a->fr_in_fastrecovery = tcp_in_fastrecovery (tc) && !tcp_in_recovery (tc);

  /* Use sentinels to verify snapshot preservation and loss-window reduction. */
  a->fr_prev_cwnd_sentinel = tc->cwnd + 12345;
  tc->prev_cwnd = a->fr_prev_cwnd_sentinel;
  a->fr_cwnd_sentinel = 0x40000000;
  tc->cwnd = a->fr_cwnd_sentinel;

  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
  tc->rto_boff = 0;
  tcp_timer_retransmit_handler (tc);
  a->fr_prev_cwnd_after = tc->prev_cwnd;
  a->fr_cwnd_after = tc->cwnd;

  a->done = 1;
  a->in_flight = 0;
}

/* Set up SACK head-retry state and schedule TX on the connection owner. */
typedef struct
{
  tcp_connection_t *tc;
  session_t *s;
  u8 *data;
  u32 mss;
  transport_connection_flags_t saved_flags;
  u8 budget_ok; /**< tcp_available_cc_snd_space == mss after setup */
  u64 old_bytes_retrans;
  volatile u8 done;
  volatile u8 in_flight; /**< set while a callback is queued/running */
} tcp_test_headrtx_rpc_args_t;

static tcp_test_headrtx_rpc_args_t tcp_test_headrtx_rpc_args;

static void
tcp_test_headrtx_setup_rpc (void *argp)
{
  tcp_test_headrtx_rpc_args_t *a = argp;
  tcp_connection_t *tc = a->tc;
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_scoreboard_hole_t *hole;
  u32 mss = a->mss;

  a->saved_flags = tc->connection.flags;

  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
  scoreboard_clear (sb);

  /* Build an isolated four-MSS flight with no pending custom TX work. */
  svm_fifo_dequeue_drop_all (a->s->tx_fifo);
  tc->flags &= ~TCP_CONN_RXT_PENDING;
  a->s->flags &= ~SESSION_F_CUSTOM_TX;
  (void) svm_fifo_enqueue (a->s->tx_fifo, 4 * mss, a->data);

  tc->connection.flags &= ~TRANSPORT_CONNECTION_F_IS_TX_PACED;
  tc->flags |= TCP_CONN_RECOVERY | TCP_CONN_FRXT_FIRST | TCP_CONN_RXT_PENDING;
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->snd_nxt = tc->snd_una + 4 * mss;
  tc->snd_congestion = tc->snd_nxt - mss;
  tc->snd_rxt_bytes = 0;
  tc->rxt_delivered = 0;
  tc->prr_delivered = 0;

  pool_get (sb->holes, hole);
  clib_memset (hole, 0, sizeof (*hole));
  hole->start = tc->snd_una;
  hole->end = tc->snd_una + 2 * mss;
  hole->next = TCP_INVALID_SACK_HOLE_INDEX;
  hole->prev = TCP_INVALID_SACK_HOLE_INDEX;
  hole->is_lost = 1;
  sb->head = sb->tail = scoreboard_hole_index (sb, hole);
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
  sb->high_rxt = tc->snd_una;
  sb->high_sacked = tc->snd_nxt;
  sb->rescue_rxt = tc->snd_una - 1;
  sb->lost_bytes = scoreboard_hole_bytes (hole);

  /* Leave exactly one MSS of congestion-control send space. */
  tc->cwnd = tcp_flight_size (tc) + mss;
  tc->snd_wnd = tc->cwnd;
  a->budget_ok = (tcp_available_cc_snd_space (tc) == mss);

  a->old_bytes_retrans = tc->bytes_retrans;
  a->s->flags |= SESSION_F_CUSTOM_TX;
  (void) session_program_tx_io_evt (a->s->handle, SESSION_IO_EVT_TX);

  a->done = 1;
  a->in_flight = 0;
}

/*
 * Regression test for "reduce loss window once per rto congestion event".
 *
 * On each rto tcp_cc_rxt_timeout re-sets the loss cwnd, but the once-per-event
 * reduction (ssthresh via tcp_cc_congestion, the prev_cwnd/prev_ssthresh undo
 * snapshot, and the snd_rxt_ts Eifel reference) must run only for the rto that
 * starts the event. It must NOT re-run for a subsequent rto of the same,
 * still-unrecovered event even though rto_boff can be cleared to 0
 * mid-recovery by tcp_update_rtt on an ack that makes progress.
 */
static int
tcp_test_rto_reduce_once_e2e (vlib_main_t *vm, unformat_input_t *input)
{
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  session_handle_t listen_handle = SESSION_INVALID_HANDLE;
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 2236;
  u32 client_index = ~0, server_index = ~0, sw_if_index[2] = { ~0, ~0 };
  u32 client_vrf = 0, server_vrf = 2, tries = 0;
  u32 total_bytes = 16 << 10;
  u32 client_fifo_size = 32 << 10, i;
  /* Use an ephemeral client port. */
  u16 placeholder_server_port = 2237, placeholder_client_port = 0;
  ip4_address_t intf_addr[2];
  session_t *client_s = 0;
  tcp_connection_t *client_tc = 0;
  transport_connection_t *tc;
  u8 *appns_id = 0, *data = 0;
  int error, rv = 0, routes_added = 0, ns_added = 0, sessions_cleaned;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vlib_cli_output (vm, "parse error: '%U'", format_unformat_error, input);
      return -1;
    }

  session_test_reset_placeholder_state ();

  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x08080801);
  if (session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]))
    return 1;

  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x09090901);
  if (session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]))
    {
      rv = 1;
      goto cleanup;
    }

  session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
					     1 /* is_add */);
  session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
					     1 /* is_add */);
  routes_added = 1;

  appns_id = format (0, "appns_rto_once_server");
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = appns_id,
    .secret = placeholder_secret,
    .sw_if_index = sw_if_index[1],
    .is_add = 1,
  };
  error = vnet_app_namespace_add_del (&ns_args);
  if (!TCP_TEST_I ((error == 0), "app ns insertion should succeed: %d", error))
    {
      rv = 1;
      goto cleanup;
    }
  ns_added = 1;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_RX_FIFO_SIZE] = 4 << 10;
  options[APP_OPTIONS_TX_FIFO_SIZE] = client_fifo_size;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "tcp_test_rto_once_client"),
  };

  error = vnet_application_attach (&attach_args);
  if (!TCP_TEST_I ((error == 0), "client app attached"))
    {
      vec_free (attach_args.name);
      rv = 1;
      goto cleanup;
    }
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  options[APP_OPTIONS_RX_FIFO_SIZE] = 4 << 10;
  options[APP_OPTIONS_TX_FIFO_SIZE] = 4 << 10;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;

  attach_args.name = format (0, "tcp_test_rto_once_server");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  if (!TCP_TEST_I ((error == 0), "server app attached"))
    {
      vec_free (attach_args.name);
      rv = 1;
      goto cleanup;
    }
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  if (!TCP_TEST_I ((error == 0), "server bind should work"))
    {
      rv = 1;
      goto cleanup;
    }
  listen_handle = bind_args.handle;

  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };
  error = vnet_connect (&connect_args);
  if (!TCP_TEST_I ((error == 0), "connect should work"))
    {
      rv = 1;
      goto cleanup;
    }

  tries = 0;
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  if (!TCP_TEST_I ((connected_session_index != ~0), "client session should exist"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((accepted_session_index != ~0), "server session should exist"))
    {
      rv = 1;
      goto cleanup;
    }

  client_s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (client_s);
  if (!TCP_TEST_I ((tc != 0), "client transport should exist"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = (tcp_connection_t *) tc;

  /*
   * Build a deterministic flight of unacked data to time out on, without
   * depending on peer ack timing (over loopback the peer would ack instantly).
   * Queue data in the tx fifo and mark it as sent-but-unacked by advancing
   * snd_nxt past snd_una; snd_congestion is the recovery point. The rto handler
   * retransmits from the fifo at snd_una.
   */
  vec_validate (data, total_bytes - 1);
  for (i = 0; i < total_bytes; i++)
    data[i] = i & 0xff;

  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }

  /* Freeze the peer window wide and mark the queued data as in flight. */
  client_tc->snd_wnd = total_bytes;
  client_tc->snd_nxt = client_tc->snd_una + total_bytes;
  client_tc->snd_congestion = client_tc->snd_nxt;
  client_tc->rcv_dupacks = 0;

  if (!TCP_TEST_I ((client_tc->snd_nxt != client_tc->snd_una), "client has data in flight"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Run connection mutations on the owning thread. Static arguments keep the
   * RPC state valid until completion. */
  {
    tcp_test_rto_rpc_args_t *a = &tcp_test_rto_rpc_args;

    /* Allow only one RPC to reference the static arguments. */
    if (!TCP_TEST_I ((a->in_flight == 0), "rto rpc slot available"))
      return 1;

    clib_memset (a, 0, sizeof (*a));
    a->tc = client_tc;
    a->s = client_s;
    a->data = data;
    a->total_bytes = total_bytes;
    a->in_flight = 1;

    session_send_rpc_evt_to_thread (client_tc->c_thread_index, tcp_test_rto_rpc, a);

    /* Wait for the owning thread to finish mutating the connection. */
    tries = 0;
    while (!a->done && ++tries < 2000)
      tcp_e2e_pump (vm, 1e-3);
    if (!TCP_TEST_I ((a->done != 0), "rto sequence ran on the connection thread"))
      {
	rv = 1;
	/* Keep referenced state alive until the callback completes. */
	for (tries = 0; a->in_flight && tries < 2000; tries++)
	  tcp_e2e_pump (vm, 1e-3);
	if (a->in_flight)
	  return 1;
	goto cleanup;
      }

    /* First rto: enters recovery, counts once, backs off. */
    if (!TCP_TEST_I ((a->first_in_recovery != 0), "first rto enters recovery"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->first_cwnd_growth_enabled != 0),
		     "first rto restores standard cwnd growth for an app-limited flight"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->first_tr_occurences == 1),
		     "first rto counts as one timeout (tr_occurences %u)", a->first_tr_occurences))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->first_rto_boff >= 1), "first rto backed off"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->cwnd_after_first == a->mss && a->flight_after_first == a->mss &&
		      a->cc_space_after_first == 0),
		     "first rto leaves one mss in flight with no send space "
		     "(cwnd %u flight %u space %u mss %u)",
		     a->cwnd_after_first, a->flight_after_first, a->cc_space_after_first, a->mss))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->snd_rxt_after_first == a->mss && a->rxt_delivered_after_first == 0),
		     "first rto accounts one live retransmission (sent %u delivered %u)",
		     a->snd_rxt_after_first, a->rxt_delivered_after_first))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->dsack_history_after_first && !a->dsack_ineligible_after_first),
		     "first rto starts eligible D-SACK history"))
      {
	rv = 1;
	goto cleanup;
      }

    /* A repeated RTO in one recovery event preserves ssthresh and prev_cwnd. */
    if (!TCP_TEST_I ((a->second_still_in_recovery != 0), "still in recovery before second rto"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->second_ssthresh == a->ssthresh_after_first),
		     "second rto does not re-reduce ssthresh (%u -> %u)", a->ssthresh_after_first,
		     a->second_ssthresh))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->second_prev_cwnd == a->prev_cwnd_after_first),
		     "second rto does not re-snapshot prev_cwnd (%u -> %u)",
		     a->prev_cwnd_after_first, a->second_prev_cwnd))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->cwnd_after_second == a->mss && a->flight_after_second == a->mss &&
		      a->cc_space_after_second == 0),
		     "second rto replaces the timed-out copy without opening send space "
		     "(cwnd %u flight %u space %u mss %u)",
		     a->cwnd_after_second, a->flight_after_second, a->cc_space_after_second,
		     a->mss))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I (
	  (a->snd_rxt_after_second == 2 * a->mss && a->rxt_delivered_after_second == a->mss),
	  "second rto retires the prior retransmission (sent %u delivered %u)",
	  a->snd_rxt_after_second, a->rxt_delivered_after_second))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I (a->dsack_ineligible_after_second, "second rto makes D-SACK undo ineligible"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->snd_rxt_after_reneging == 3 * a->mss &&
		      a->rxt_delivered_after_reneging == 2 * a->mss &&
		      a->rxt_flight_after_reneging == a->mss),
		     "rto after reneging leaves its replacement in flight "
		     "(sent %u delivered %u rxt flight %u mss %u)",
		     a->snd_rxt_after_reneging, a->rxt_delivered_after_reneging,
		     a->rxt_flight_after_reneging, a->mss))
      {
	rv = 1;
	goto cleanup;
      }

    /* An RTO during fast recovery reduces cwnd and preserves prev_cwnd. */
    if (!TCP_TEST_I ((a->fr_in_fastrecovery != 0), "in fast recovery, not rto recovery"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->fr_prev_cwnd_after == a->fr_prev_cwnd_sentinel),
		     "rto during fast recovery preserves the entry undo snapshot "
		     "(prev_cwnd %u, expected %u)",
		     a->fr_prev_cwnd_after, a->fr_prev_cwnd_sentinel))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((a->fr_cwnd_after < a->fr_cwnd_sentinel),
		     "rto during fast recovery sets loss cwnd (%u, was sentinel %u)",
		     a->fr_cwnd_after, a->fr_cwnd_sentinel))
      {
	rv = 1;
	goto cleanup;
      }
  }

  /*
   * Spurious-retransmit detection predicate (RFC 3522 Sec. 3.2 Eifel),
   * tcp_cc_is_spurious_retransmit: on a cumulative ack in recovery, decides
   * whether the window reduction was spurious (reordered/delayed data, not real
   * loss) and should be undone. Base state below is spurious; each case flips
   * one term. Spurious requires: retransmit stamped, part of the flight still
   * outstanding (snd_una < snd_congestion), timestamp option present, and tsecr
   * older than the first retransmit. Other outstanding loss is handled as a
   * separate recovery event.
   */
  {
    tcp_connection_t _stc, *stc = &_stc;
    tcp_rate_sample_t _srs, *srs = &_srs;
    u32 mss = 1460;

#define ARM_SPURIOUS()                                                                             \
  do                                                                                               \
    {                                                                                              \
      clib_memset (stc, 0, sizeof (*stc));                                                         \
      clib_memset (srs, 0, sizeof (*srs));                                                         \
      stc->snd_mss = mss;                                                                          \
      stc->flags |= TCP_CONN_FAST_RECOVERY;                                                        \
      srs->bytes_acked = 2 * mss;                                                                  \
      stc->snd_una = 10000;                                                                        \
      stc->snd_congestion = stc->snd_una + 10 * mss;                                               \
      stc->snd_rxt_ts = 1000;                                                                      \
      stc->sack_sb.lost_bytes = 0;                                                                 \
      stc->rcv_opts.flags = TCP_OPTS_FLAG_TSTAMP;                                                  \
      stc->rcv_opts.tsecr = stc->snd_rxt_ts - 1;                                                   \
    }                                                                                              \
  while (0)

    /* Base: all conditions met -> spurious. */
    ARM_SPURIOUS ();
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: spurious on partial cumulative ack, tsecr < snd_rxt_ts, "
		     "no loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Also valid for rto recovery (TCP_CONN_RECOVERY), not just fast recovery. */
    ARM_SPURIOUS ();
    stc->flags = TCP_CONN_RECOVERY;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: also fires for rto recovery"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Detection is independent of other outstanding loss. Rto recovery may
     * carry speculative loss marks. */
    ARM_SPURIOUS ();
    stc->flags = TCP_CONN_RECOVERY;
    stc->sack_sb.lost_bytes = mss;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: rto retransmit spurious despite outstanding loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: no retransmit stamped (snd_rxt_ts == 0), nothing to undo. */
    ARM_SPURIOUS ();
    stc->snd_rxt_ts = 0;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: not spurious without a retransmit timestamp"))
      {
	rv = 1;
	goto cleanup;
      }

    /* The initiating fast retransmit can be spurious while another SACK-derived
     * loss remains outstanding. The response handles that as a fresh event. */
    ARM_SPURIOUS ();
    stc->sack_sb.lost_bytes = mss;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: fast retransmit spurious despite other outstanding loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: full-flight ack (snd_una reached snd_congestion). Ambiguous per
     * RFC 3522 Sec. 3.2 (e.g. rto from losing all acks) -> keep the reduction. */
    ARM_SPURIOUS ();
    stc->snd_una = stc->snd_congestion;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: not spurious on a full-flight ack"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: echoed tsecr not older than snd_rxt_ts (ack post-dates the
     * retransmit -> the retransmit was needed). */
    ARM_SPURIOUS ();
    stc->rcv_opts.tsecr = stc->snd_rxt_ts;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: not spurious when tsecr >= snd_rxt_ts"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: no timestamp option -> Eifel not applicable. */
    ARM_SPURIOUS ();
    stc->rcv_opts.flags = 0;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc, srs)),
		     "eifel: not spurious without the timestamp option"))
      {
	rv = 1;
	goto cleanup;
      }
#undef ARM_SPURIOUS
  }

  /*
   * When SACK advances beyond the recovery point, retransmitting snd_una
   * consumes the same congestion-control send budget as every other
   * retransmission. Leave one MSS of send space and a two-MSS lost hole; only
   * the head segment may be emitted.
   */
  {
    tcp_test_headrtx_rpc_args_t *h = &tcp_test_headrtx_rpc_args;
    u32 rxt_tries;

    /* Allow only one RPC to reference the static arguments. */
    if (!TCP_TEST_I ((h->in_flight == 0), "head-retry rpc slot available"))
      return 1;

    clib_memset (h, 0, sizeof (*h));
    h->tc = client_tc;
    h->s = client_s;
    h->data = data;
    h->mss = client_tc->snd_mss;
    h->in_flight = 1;

    session_send_rpc_evt_to_thread (client_tc->c_thread_index, tcp_test_headrtx_setup_rpc, h);
    /* Wait for the owning thread to complete setup. */
    tries = 0;
    while (!h->done && ++tries < 2000)
      tcp_e2e_pump (vm, 1e-3);
    if (!TCP_TEST_I ((h->done != 0), "sack head retry setup ran on the connection thread"))
      {
	rv = 1;
	for (tries = 0; h->in_flight && tries < 2000; tries++)
	  tcp_e2e_pump (vm, 1e-3);
	if (h->in_flight)
	  return 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((h->budget_ok != 0), "sack head retry starts with one mss send budget"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Wait for the worker to dispatch the programmed tx event. */
    for (rxt_tries = 0; (client_tc->flags & TCP_CONN_RXT_PENDING) && rxt_tries < 100; rxt_tries++)
      tcp_e2e_pump (vm, 1e-3);

    client_tc->connection.flags = h->saved_flags;
    if (!TCP_TEST_I (!(client_tc->flags & TCP_CONN_RXT_PENDING),
		     "sack head retry tx event dispatched"))
      {
	rv = 1;
	goto cleanup;
      }
    if (!TCP_TEST_I ((client_tc->bytes_retrans == h->old_bytes_retrans + h->mss),
		     "sack head retry consumes one mss, retransmitted %llu bytes",
		     client_tc->bytes_retrans - h->old_bytes_retrans))
      {
	rv = 1;
	goto cleanup;
      }
  }

cleanup:
  sessions_cleaned = tcp_e2e_force_session_cleanup (vm);

  if (listen_handle != SESSION_INVALID_HANDLE)
    {
      vnet_unlisten_args_t unbind_args = {
	.handle = listen_handle,
	.app_index = server_index,
      };
      (void) vnet_unlisten (&unbind_args);
    }

  if (server_index != ~0)
    {
      vnet_app_detach_args_t detach_args = {
	.app_index = server_index,
	.api_client_index = ~0,
      };
      vnet_application_detach (&detach_args);
    }
  if (client_index != ~0)
    {
      vnet_app_detach_args_t detach_args = {
	.app_index = client_index,
	.api_client_index = ~0,
      };
      vnet_application_detach (&detach_args);
    }

  if (ns_added)
    {
      ns_args.is_add = 0;
      (void) vnet_app_namespace_add_del (&ns_args);
    }

  vlib_process_suspend (vm, 10e-3);

  if (routes_added)
    {
      session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
						 0 /* is_add */);
      session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
						 0 /* is_add */);
    }

  /* Stop the loopbacks and drain referencing graph frames before deletion. */
  for (int j = 0; j < 2; j++)
    {
      if (sw_if_index[j] == ~0)
	continue;
      (void) ip4_add_del_interface_address (vm, sw_if_index[j], &intf_addr[j], 24, 1 /* is_del */);
      vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index[j], 0);
    }
  if (sessions_cleaned && tcp_e2e_drain_graph_frames (vm))
    {
      for (int j = 0; j < 2; j++)
	if (sw_if_index[j] != ~0)
	  (void) vnet_delete_loopback_interface (sw_if_index[j]);
    }
  else
    clib_warning ("graph frames did not quiesce; preserving test loopbacks");

  vec_free (data);
  vec_free (appns_id);

  return rv;
}

static int
tcp_test_rto (vlib_main_t *vm, unformat_input_t *input)
{
  return tcp_test_rto_reduce_once_e2e (vm, input);
}

/*
 * Tampering-based end-to-end cases. Each drives a real connection through the
 * test tampering node and asserts the connection tolerates a specific dropped
 * segment. Sub-cases are selected with "test tcp tamper <name>"; no argument
 * (or "all") runs them all.
 */

/* Drop the client's first FIN and confirm the connection still tears down: the
 * FIN is retransmitted and acknowledged (snd_una reaches snd_nxt). */
static int
tcp_test_tamper_lost_fin (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "lost_fin",
    .client_addr = 0x0a0a0a01,
    .server_addr = 0x0b0b0b01,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2239,
    .client_port = 0, /* ephemeral */
    .secret = 2238,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *fin_rule;
  u64 to_before;
  u32 tries;
  int rv = 0;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "lost_fin: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;

  if (!TCP_TEST_I ((client_tc->state == TCP_STATE_ESTABLISHED),
		   "lost_fin: client established before close (state %U)", format_tcp_state,
		   client_tc->state))
    {
      rv = 1;
      goto cleanup;
    }

  /* Arm the drop, route the client's egress through the tamper node, close. */
  to_before = tcp_e2e_teardown_timeouts ();
  fin_rule = tcp_tamper_drop_fin (client_tc, 1);
  tcp_tamper_enable (client_tc);
  session_close (ctx->client_s);

  tries = 0;
  while (fin_rule->n_dropped == 0 && ++tries < 100)
    tcp_e2e_pump (vm, 10e-3);
  if (!TCP_TEST_I ((fin_rule->n_dropped == 1),
		   "lost_fin: tamper node dropped the first FIN (dropped %u, matched %u)",
		   fin_rule->n_dropped, fin_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for the FIN retransmission using an RTO-derived deadline. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    tries = 0;
    while (connected_session_index != ~0 && fin_rule->n_matched < 2 && ++tries < max_iters)
      tcp_e2e_pump (vm, 10e-3);
  }
  if (!TCP_TEST_I ((fin_rule->n_matched >= 2),
		   "lost_fin: FIN retransmitted after the drop (matched %u)", fin_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((fin_rule->n_dropped == 1),
		   "lost_fin: only the first FIN was dropped (dropped %u of %u)",
		   fin_rule->n_dropped, fin_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for FIN acknowledgment, reacquiring the transport each iteration. */
  {
    u32 csi = connected_session_index, cst = connected_session_thread;
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    u8 advanced = 0;

    for (tries = 0; tries < max_iters; tries++)
      {
	session_t *s = session_get_if_valid (csi, cst);
	tcp_connection_t *cur;

	if (connected_session_index == ~0 || !s)
	  {
	    advanced = 1; /* fully closed and cleaned up */
	    break;
	  }
	cur = (tcp_connection_t *) session_get_transport (s);
	/* FIN acknowledgment advances snd_una to snd_nxt. */
	if (!cur || cur->snd_una == cur->snd_nxt)
	  {
	    advanced = 1; /* retransmitted FIN acknowledged */
	    break;
	  }
	tcp_e2e_pump (vm, 10e-3);
      }
    if (!TCP_TEST_I ((advanced != 0),
		     "lost_fin: retransmitted FIN acknowledged (snd_una reached snd_nxt)"))
      {
	rv = 1;
	goto cleanup;
      }
  }

  /* Require protocol-driven teardown. */
  if (!TCP_TEST_I ((tcp_e2e_teardown_timeouts () == to_before),
		   "lost_fin: teardown was protocol-driven, no waitclose timeout"))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop the client's ACK of the server's FIN and confirm the teardown still
 * completes: the server stays in LAST_ACK, retransmits its FIN, the client
 * (in TIME_WAIT) re-acks it, and the server leaves LAST_ACK. */
static int
tcp_test_tamper_lost_final_ack (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "lost_ack",
    .client_addr = 0x0c0c0c01,
    .server_addr = 0x0d0d0d01,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2241,
    .client_port = 0, /* ephemeral */
    .secret = 2240,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc, *server_tc;
  tcp_tamper_rule_t *ack_rule;
  session_t *server_s;
  u64 to_before;
  u32 tries, server_si, server_st;
  u8 advanced = 0;
  int rv = 0;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "lost_ack: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;

  server_si = accepted_session_index;
  server_st = accepted_session_thread;
  server_s = session_get_if_valid (server_si, server_st);
  if (!TCP_TEST_I ((server_s != 0), "lost_ack: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  server_tc = (tcp_connection_t *) session_get_transport (server_s);

  /* Drop the client's ACK of the server's FIN. */
  to_before = tcp_e2e_teardown_timeouts ();
  ack_rule = tcp_tamper_drop_pure_ack (client_tc, 1);
  tcp_tamper_enable (client_tc);
  session_close (ctx->client_s);

  tries = 0;
  while (ack_rule->n_dropped == 0 && ++tries < 200)
    tcp_e2e_pump (vm, 10e-3);
  if (!TCP_TEST_I ((ack_rule->n_dropped == 1),
		   "lost_ack: tamper node dropped the client's final ack (dropped %u)",
		   ack_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }

  /* Confirm the server waits in LAST_ACK. */
  if (!TCP_TEST_I ((server_tc->state == TCP_STATE_LAST_ACK),
		   "lost_ack: server is in LAST_ACK after its ack was dropped (state %U)",
		   format_tcp_state, server_tc->state))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for the client to re-ACK the FIN and the server to leave LAST_ACK. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (server_tc, 10e-3);
    for (tries = 0; tries < max_iters; tries++)
      {
	session_t *s = session_get_if_valid (server_si, server_st);
	tcp_connection_t *cur;

	if (accepted_session_index == ~0 || !s)
	  {
	    advanced = 1; /* server closed and cleaned up */
	    break;
	  }
	cur = (tcp_connection_t *) session_get_transport (s);
	if ((!cur || cur->state != TCP_STATE_LAST_ACK) && ack_rule->n_matched >= 2)
	  {
	    advanced = 1; /* left LAST_ACK after the client re-acked */
	    break;
	  }
	tcp_e2e_pump (vm, 10e-3);
      }
  }
  if (!TCP_TEST_I ((ack_rule->n_matched >= 2),
		   "lost_ack: client re-acked the retransmitted FIN (matched %u)",
		   ack_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((advanced != 0),
		   "lost_ack: server leaves LAST_ACK after retransmitting its FIN"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((ack_rule->n_dropped == 1),
		   "lost_ack: only the first ack was dropped (dropped %u of %u)",
		   ack_rule->n_dropped, ack_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  /* Require protocol-driven recovery from the lost ACK. */
  if (!TCP_TEST_I ((tcp_e2e_teardown_timeouts () == to_before),
		   "lost_ack: teardown was protocol-driven, no waitclose timeout"))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop the server's first FIN and verify retransmission and acknowledgment. */
static int
tcp_test_tamper_peer_fin_first (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "peer_fin",
    .client_addr = 0x0e0e0e01,
    .server_addr = 0x0f0f0f01,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2243,
    .client_port = 0, /* ephemeral */
    .secret = 2242,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc, *server_tc;
  tcp_tamper_rule_t *fin_rule;
  session_t *server_s;
  u64 to_before;
  u32 tries, server_si, server_st;
  u8 advanced = 0;
  int rv = 0;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "peer_fin: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;

  server_si = accepted_session_index;
  server_st = accepted_session_thread;
  server_s = session_get_if_valid (server_si, server_st);
  if (!TCP_TEST_I ((server_s != 0), "peer_fin: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  server_tc = (tcp_connection_t *) session_get_transport (server_s);

  /* Drop the server's first FIN while it closes first. */
  to_before = tcp_e2e_teardown_timeouts ();
  fin_rule = tcp_tamper_drop_fin (server_tc, 1);
  tcp_tamper_enable (server_tc);
  session_close (server_s);

  tries = 0;
  while (fin_rule->n_dropped == 0 && ++tries < 200)
    tcp_e2e_pump (vm, 10e-3);
  if (!TCP_TEST_I ((fin_rule->n_dropped == 1),
		   "peer_fin: tamper node dropped the server's first FIN (dropped %u)",
		   fin_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for the client to leave ESTABLISHED and acknowledge the server's FIN. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (server_tc, 10e-3);
    u8 client_done = 0, server_done = 0;

    for (tries = 0; tries < max_iters; tries++)
      {
	session_t *cs = session_get_if_valid (connected_session_index, connected_session_thread);
	session_t *ss = session_get_if_valid (server_si, server_st);
	tcp_connection_t *cc, *sc;

	if (connected_session_index == ~0 || !cs)
	  client_done = 1;
	else
	  {
	    cc = (tcp_connection_t *) session_get_transport (cs);
	    if (!cc || cc->state != TCP_STATE_ESTABLISHED)
	      client_done = 1;
	  }

	/* FIN acknowledgment advances snd_una to snd_nxt. */
	if (accepted_session_index == ~0 || !ss)
	  server_done = 1;
	else
	  {
	    sc = (tcp_connection_t *) session_get_transport (ss);
	    if (!sc || sc->snd_una == sc->snd_nxt)
	      server_done = 1;
	  }

	if (client_done && server_done && fin_rule->n_matched >= 2)
	  {
	    advanced = 1;
	    break;
	  }
	tcp_e2e_pump (vm, 10e-3);
      }
  }
  if (!TCP_TEST_I ((fin_rule->n_matched >= 2),
		   "peer_fin: server retransmitted its FIN (matched %u)", fin_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((advanced != 0),
		   "peer_fin: client left ESTABLISHED and server FIN acknowledged after "
		   "the retransmitted FIN"))
    {
      rv = 1;
      goto cleanup;
    }
  /* Require protocol-driven teardown. */
  if (!TCP_TEST_I ((tcp_e2e_teardown_timeouts () == to_before),
		   "peer_fin: teardown was protocol-driven, no waitclose timeout"))
    {
      rv = 1;
      goto cleanup;
    }
  (void) client_tc;

cleanup:
  tcp_tamper_reset ();
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop a mid-stream segment and verify retransmission and delivery. */
static int
tcp_test_tamper_chained_rxt (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "chain_rxt",
    .client_addr = 0x10101001,
    .server_addr = 0x11111101,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2245,
    .client_port = 0, /* ephemeral */
    .secret = 2244,
    .rx_fifo_size = 128 << 10,
    .tx_fifo_size = 128 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *seg_rule;
  session_t *client_s, *server_s;
  u32 tries, drop_seq, total_bytes = 32 << 10, drained = 0;
  u8 *data = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "chain_rxt: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "chain_rxt: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Target a segment a few MSS into the stream so it is genuinely mid-stream
   * (not the first or last segment). snd_una is the initial send sequence. */
  drop_seq = client_tc->snd_una + 3 * client_tc->snd_mss;
  seg_rule = tcp_tamper_drop_seq (client_tc, drop_seq, 1);
  tcp_tamper_enable (client_tc);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;

  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "chain_rxt: client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "chain_rxt: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Drain the server while the transfer progresses. */
  for (tries = 0; drained < total_bytes && tries < 600; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 10e-3);
    }

  if (!TCP_TEST_I ((seg_rule->n_dropped == 1),
		   "chain_rxt: tamper node dropped the target segment (dropped %u)",
		   seg_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((seg_rule->n_matched >= 2),
		   "chain_rxt: dropped segment was retransmitted (matched %u)",
		   seg_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((drained == total_bytes),
		   "chain_rxt: all %u bytes delivered despite the drop (got %u)", total_bytes,
		   drained))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop a FIN deferred behind queued data and verify clean delivery and close. */
static int
tcp_test_tamper_queued_fin (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "queued_fin",
    .client_addr = 0x12121201,
    .server_addr = 0x13131301,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2247,
    .client_port = 0, /* ephemeral */
    .secret = 2246,
    /* Bound the peer window to keep the FIN pending during transfer. */
    .rx_fifo_size = 4 << 10,
    .tx_fifo_size = 128 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *fin_rule;
  session_t *client_s, *server_s;
  u64 to_before;
  u32 tries, total_bytes = 32 << 10, drained = 0;
  u8 *data = 0, saw_finpndg = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "queued_fin: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "queued_fin: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Drop the client's first FIN, route egress through the tamper node. */
  to_before = tcp_e2e_teardown_timeouts ();
  fin_rule = tcp_tamper_drop_fin (client_tc, 1);
  tcp_tamper_enable (client_tc);

  /* Queue data before closing to defer the FIN. */
  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "queued_fin: client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }

  /* Close before starting TX so the FIN remains pending behind the data. */
  session_close (client_s);
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "queued_fin: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Drain the server and observe the pending FIN. */
  for (tries = 0; drained < total_bytes && tries < 600; tries++)
    {
      if (client_tc->flags & TCP_CONN_FINPNDG)
	saw_finpndg = 1;
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 10e-3);
    }
  if (!TCP_TEST_I ((saw_finpndg != 0), "queued_fin: FIN is pending behind queued data (FINPNDG)"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((drained == total_bytes),
		   "queued_fin: all %u bytes delivered before the FIN (got %u)", total_bytes,
		   drained))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for the deferred FIN retransmission and acknowledgment. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    u8 done = 0;

    for (tries = 0; tries < max_iters; tries++)
      {
	session_t *s = session_get_if_valid (connected_session_index, connected_session_thread);
	tcp_connection_t *cur;

	if (connected_session_index == ~0 || !s)
	  {
	    done = 1;
	    break;
	  }
	cur = (tcp_connection_t *) session_get_transport (s);
	/* Require the deferred FIN to be sent and acknowledged. */
	if (fin_rule->n_matched >= 2 && cur && !(cur->flags & TCP_CONN_FINPNDG) &&
	    cur->snd_una == cur->snd_nxt)
	  {
	    done = 1;
	    break;
	  }
	tcp_e2e_pump (vm, 10e-3);
      }
    if (!TCP_TEST_I ((done != 0),
		     "queued_fin: deferred FIN acknowledged (snd_una reached snd_nxt)"))
      {
	rv = 1;
	goto cleanup;
      }
  }
  if (!TCP_TEST_I ((fin_rule->n_dropped == 1),
		   "queued_fin: tamper node dropped the deferred FIN (dropped %u)",
		   fin_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((fin_rule->n_matched >= 2),
		   "queued_fin: deferred FIN was retransmitted (matched %u)", fin_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  /* Require protocol-driven teardown. */
  if (!TCP_TEST_I ((tcp_e2e_teardown_timeouts () == to_before),
		   "queued_fin: teardown was protocol-driven, no waitclose timeout"))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop data while a FIN is pending, then verify delivery and clean close. */
static int
tcp_test_tamper_queued_data_loss_mode (vlib_main_t *vm, u8 bt_mode)
{
  tcp_e2e_params_t params = {
    .name = bt_mode ? "queued_dl_bt" : "queued_dl",
    .client_addr = 0x16161601,
    .server_addr = 0x17171701,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = bt_mode ? 2261 : 2251,
    .client_port = 0, /* ephemeral */
    .secret = bt_mode ? 2260 : 2250,
    /* Bound the peer window to keep the FIN pending during recovery. */
    .rx_fifo_size = 4 << 10,
    .tx_fifo_size = 128 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *seg_rule;
  session_t *client_s, *server_s;
  transport_endpt_attr_t attr = {
    .type = TRANSPORT_ENDPT_ATTR_FLAGS,
  };
  u64 to_before;
  u32 tries, mss, drop_seq, total_bytes = 32 << 10, drained = 0;
  u8 *data = 0, saw_finpndg = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "queued_dl: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "queued_dl: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  mss = client_tc->snd_mss;

  if (bt_mode)
    {
      error = session_transport_attribute (client_s, 1 /* is_get */, &attr);
      attr.flags |= TRANSPORT_ENDPT_ATTR_F_RATE_SAMPLING;
      error |= session_transport_attribute (client_s, 0 /* is_get */, &attr);
      if (!TCP_TEST_I (error == 0 && client_tc->bt != 0,
		       "queued_dl_bt: byte tracker enabled on an empty flight"))
	{
	  rv = 1;
	  goto cleanup;
	}
    }

  /* Drop a mid-stream data segment. */
  to_before = tcp_e2e_teardown_timeouts ();
  drop_seq = client_tc->snd_una + 3 * mss;
  seg_rule = tcp_tamper_drop_seq (client_tc, drop_seq, 1);
  tcp_tamper_enable (client_tc);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "queued_dl: client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }

  /* Close with data queued so the FIN is deferred, then start the transfer. */
  session_close (client_s);
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "queued_dl: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Drain the server and observe the pending FIN. */
  for (tries = 0; drained < total_bytes && tries < 800; tries++)
    {
      if (client_tc->flags & TCP_CONN_FINPNDG)
	saw_finpndg = 1;
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 10e-3);
    }

  if (!TCP_TEST_I ((saw_finpndg != 0), "queued_dl: FIN was pending behind queued data (FINPNDG)"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I (
	(seg_rule->n_dropped == 1 && seg_rule->n_matched >= 2),
	"queued_dl: data segment dropped once and retransmitted (dropped %u, matched %u)",
	seg_rule->n_dropped, seg_rule->n_matched))
    {
      rv = 1;
      goto cleanup;
    }
  if (bt_mode && !TCP_TEST_I (client_tc->bt != 0 && pool_elts (client_tc->sack_sb.holes) == 0,
			      "queued_dl_bt: loss recovery used no scoreboard holes"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((drained == total_bytes),
		   "queued_dl: all %u bytes delivered despite the data loss (got %u)", total_bytes,
		   drained))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for the deferred FIN to be sent and acknowledged. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    u8 done = 0;

    for (tries = 0; tries < max_iters; tries++)
      {
	session_t *s = session_get_if_valid (connected_session_index, connected_session_thread);
	tcp_connection_t *cur;

	if (connected_session_index == ~0 || !s)
	  {
	    done = 1;
	    break;
	  }
	cur = (tcp_connection_t *) session_get_transport (s);
	if (cur && !(cur->flags & TCP_CONN_FINPNDG) && cur->snd_una == cur->snd_nxt)
	  {
	    done = 1;
	    break;
	  }
	tcp_e2e_pump (vm, 10e-3);
      }
    if (!TCP_TEST_I ((done != 0), "queued_dl: deferred FIN acknowledged (snd_una reached snd_nxt)"))
      {
	rv = 1;
	goto cleanup;
      }
  }
  if (!TCP_TEST_I ((tcp_e2e_teardown_timeouts () == to_before),
		   "queued_dl: teardown was protocol-driven, no waitclose timeout"))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

static int
tcp_test_tamper_queued_data_loss (vlib_main_t *vm)
{
  return tcp_test_tamper_queued_data_loss_mode (vm, 0 /* bt_mode */);
}

static int
tcp_test_tamper_queued_data_loss_bt (vlib_main_t *vm)
{
  return tcp_test_tamper_queued_data_loss_mode (vm, 1 /* bt_mode */);
}

/* Lose data above the recovery point and verify recovery exit and re-entry. */
static int
tcp_test_tamper_recovery_point (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "recov_pt",
    .client_addr = 0x14141401,
    .server_addr = 0x15151501,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2249,
    .client_port = 0, /* ephemeral */
    .secret = 2248,
    /* Keep a wide flight outstanding during recovery. */
    .rx_fifo_size = 256 << 10,
    .tx_fifo_size = 256 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *r1, *r2;
  session_t *client_s, *server_s;
  u32 tries, mss, seq1, total_bytes = 256 << 10, drained = 0;
  u32 fr_before;
  u64 tr_before;
  u8 *data = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "recov_pt: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "recov_pt: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  mss = client_tc->snd_mss;
  fr_before = client_tc->fr_occurences;
  tr_before = client_tc->tr_occurences;

  /* Drop an early segment and its first retransmission, then drop fresh data
   * above the recovery point during the same recovery episode. */
  seq1 = client_tc->snd_una + 4 * mss;
  tcp_tamper_drop_seq (client_tc, seq1, 2);
  tcp_tamper_drop_above_rp (client_tc, 1);
  r1 = &tcp_tamper_main.rules[0];
  r2 = &tcp_tamper_main.rules[1];
  tcp_tamper_enable (client_tc);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "recov_pt: client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "recov_pt: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  for (tries = 0; drained < total_bytes && tries < 2000; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 5e-3);
    }

  if (!TCP_TEST_I ((r1->n_dropped == 2 && r2->n_dropped == 1),
		   "recov_pt: early segment + its retransmit dropped (%u) and one segment "
		   "above the recovery point dropped (%u)",
		   r1->n_dropped, r2->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  /* Confirm the second loss occurred before the first recovery point. */
  if (!TCP_TEST_I ((r2->drop_in_recovery && seq_lt (r2->drop_snd_una, r2->drop_snd_congestion)),
		   "recov_pt: second loss dropped during the first recovery "
		   "(snd_una %u < recovery point %u)",
		   r2->drop_snd_una - client_tc->iss, r2->drop_snd_congestion - client_tc->iss))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((drained == total_bytes),
		   "recov_pt: all %u bytes delivered despite two losses (got %u)", total_bytes,
		   drained))
    {
      rv = 1;
      goto cleanup;
    }
  /* The first loss enters fast recovery. The early segment whose retransmit was
   * also dropped is a lost retransmit that NextSeg (RFC6675) cannot resend once
   * high_rxt has advanced past it, so it is recovered by the rto -- the exact
   * episode/mechanism split is not asserted, only that recovery makes progress
   * (>=1 fast-recovery episode) and, together with the all-data-delivered check
   * above, that both losses are ultimately recovered. */
  if (!TCP_TEST_I (((client_tc->fr_occurences - fr_before) >= 1),
		   "recov_pt: recovery entered for the losses (fr delta %u, tr delta %llu)",
		   client_tc->fr_occurences - fr_before, client_tc->tr_occurences - tr_before))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Suppress ACKs until the sender spuriously retransmits the first segment,
 * while genuinely losing a later segment. The retransmission reaches a
 * receiver that already has the first segment. Add that duplicate range to the
 * receiver's next ACK (VPP does not yet generate D-SACKs) alongside its real
 * SACK evidence above the hole. Verify that the ACK exits timeout recovery
 * before its recovery point and immediately enters a fresh fast-recovery
 * episode for the residual loss. */
static int
tcp_test_tamper_dsack_early_undo (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "dsack_early",
    .client_addr = 0x1a1a1a01,
    .server_addr = 0x1b1b1b01,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2255,
    .client_port = 0, /* ephemeral */
    .secret = 2254,
    .rx_fifo_size = 128 << 10,
    .tx_fifo_size = 128 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc, *server_tc;
  tcp_tamper_rule_t *ack_rule, *loss_rule, *release_rule;
  tcp_rate_sample_t seed_rs = { 0 };
  sack_block_t seed_sack, dsack;
  session_t *client_s, *server_s;
  const u32 n_segments = 8;
  u32 tries, max_iters, mss, spurious_seq, loss_seq;
  u32 total_bytes, drained = 0, fr_before, tr_before, ack_matches_before;
  u32 fresh_snd_una = 0, fresh_snd_nxt = 0, fresh_snd_congestion = 0;
  u32 fresh_cwnd = 0, fresh_prev_cwnd = 0, fresh_lost = 0;
  u8 *data = 0;
  u8 saw_reentry = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "dsack_early: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "dsack_early: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  server_tc = (tcp_connection_t *) session_get_transport (server_s);

  client_tc->cfg_flags |= TCP_CFG_F_NO_TSO;
  client_tc->cfg_flags &= ~TCP_CFG_F_TSO;

  mss = client_tc->snd_mss;
  spurious_seq = client_tc->snd_una;
  loss_seq = spurious_seq + mss;
  total_bytes = n_segments * mss;
  fr_before = client_tc->fr_occurences;
  tr_before = client_tc->tr_occurences;
  client_tc->rto = TCP_RTO_MIN;
  client_tc->cwnd = clib_max (client_tc->cwnd, total_bytes);
  client_tc->snd_wnd = clib_max (client_tc->snd_wnd, total_bytes);

  /* Drop all receiver ACKs until the original head is retransmitted. Drop a
   * later segment and its first retransmission so the fresh recovery remains
   * observable after the D-SACK ACK is processed. */
  tcp_tamper_drop_pure_ack (server_tc, ~0u);
  tcp_tamper_drop_seq (client_tc, loss_seq, 2);
  tcp_tamper_drop_seq (client_tc, spurious_seq, 0);
  ack_rule = &tcp_tamper_main.rules[0];
  loss_rule = &tcp_tamper_main.rules[1];
  release_rule = &tcp_tamper_main.rules[2];
  loss_rule->data_only = 1;
  release_rule->data_only = 1;
  tcp_tamper_enable (client_tc);
  tcp_tamper_enable (server_tc);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  for (i = 0; i < (int) n_segments; i++)
    {
      error = svm_fifo_enqueue (client_s->tx_fifo, mss, data + i * mss);
      if (!TCP_TEST_I ((error == (int) mss), "dsack_early: client queued segment %u", i))
	{
	  rv = 1;
	  goto cleanup;
	}
      error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
      if (!TCP_TEST_I ((error == 0), "dsack_early: segment %u tx event programmed", i))
	{
	  rv = 1;
	  goto cleanup;
	}
      tcp_e2e_pump (vm, 1e-3);
    }

  if (!TCP_TEST_I ((server_tc->rcv_nxt == loss_seq),
		   "dsack_early: receiver stopped at residual loss "
		   "(rcv_nxt %u, expected %u)",
		   server_tc->rcv_nxt - client_tc->iss, loss_seq - client_tc->iss))
    {
      rv = 1;
      goto cleanup;
    }

  /* Model the SACK history that precedes a spurious retransmission caused by
   * reordering: the sender has seen one block above two apparent holes, but
   * the receiver already has the head segment. The real loopback ACKs remain
   * suppressed so the timeout, D-SACK reception, recovery exit, and immediate
   * residual-loss re-entry all run through the normal input/CC path. */
  seed_sack.start = loss_seq + mss;
  seed_sack.end = seed_sack.start + mss;
  vec_add1 (client_tc->rcv_opts.sacks, seed_sack);
  client_tc->rcv_opts.n_sack_blocks = 1;
  client_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tcp_rcv_sacks (client_tc, spurious_seq, &seed_rs);
  if (!TCP_TEST_I ((client_tc->sack_sb.sacked_bytes != 0),
		   "dsack_early: prior SACK history seeded "
		   "(una %u, nxt %u, block %u-%u, sacked %u, last %u)",
		   client_tc->snd_una - client_tc->iss, client_tc->snd_nxt - client_tc->iss,
		   seed_sack.start - client_tc->iss, seed_sack.end - client_tc->iss,
		   client_tc->sack_sb.sacked_bytes, seed_rs.last_sacked_bytes))
    {
      rv = 1;
      goto cleanup;
    }

  /* Let the spurious timeout retransmission reach the receiver while its ACK
   * is still suppressed. Then explicitly make the receiver's next ACK a
   * D-SACK ACK. This preserves the full sender input and CC path while keeping
   * sender-side D-SACK generation outside this receiver-only feature. */
  max_iters = tcp_e2e_rxt_wait_iters (client_tc, 2e-3);
  for (tries = 0; tries < max_iters; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (release_rule->n_matched >= 2)
	break;
      tcp_e2e_pump (vm, 2e-3);
    }

  if (!TCP_TEST_I ((release_rule->n_matched >= 2 && ack_rule->n_dropped > 0),
		   "dsack_early: head retransmitted (%u matches) after %u suppressed ACKs",
		   release_rule->n_matched, ack_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  dsack.start = spurious_seq;
  dsack.end = spurious_seq + mss;
  vec_insert_elts (server_tc->snd_sacks, &dsack, 1, 0);
  server_tc->snd_sack_pos = 0;
  client_tc->snd_rxt_ts = 0;
  ack_matches_before = ack_rule->n_matched;
  ack_rule->n_drop = 0;
  tcp_program_ack (server_tc);

  for (tries = 0; tries < 50 && client_tc->snd_una == spurious_seq; tries++)
    tcp_e2e_pump (vm, 1e-3);
  if (!TCP_TEST_I ((seq_gt (client_tc->snd_una, spurious_seq)),
		   "dsack_early: synthetic D-SACK ACK reached sender "
		   "(ack matches %u->%u, server sacks %u, tr %u, fr %u, flags 0x%x, "
		   "dsack flags 0x%x, rxt ranges %u)",
		   ack_matches_before, ack_rule->n_matched, vec_len (server_tc->snd_sacks),
		   client_tc->tr_occurences - tr_before, client_tc->fr_occurences - fr_before,
		   client_tc->flags, client_tc->dsack_flags, tcp_test_dsack_rxt_count (client_tc)))
    {
      rv = 1;
      goto cleanup;
    }

  max_iters = tcp_e2e_rxt_wait_iters (client_tc, 2e-3);
  for (tries = 0; tries < max_iters; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (client_tc->tr_occurences - tr_before == 1 && client_tc->fr_occurences - fr_before == 1 &&
	  tcp_in_fastrecovery (client_tc) && !tcp_in_recovery (client_tc) &&
	  client_tc->sack_sb.lost_bytes && loss_rule->n_dropped == 2)
	{
	  fresh_snd_una = client_tc->snd_una;
	  fresh_snd_nxt = client_tc->snd_nxt;
	  fresh_snd_congestion = client_tc->snd_congestion;
	  fresh_cwnd = client_tc->cwnd;
	  fresh_prev_cwnd = client_tc->prev_cwnd;
	  fresh_lost = client_tc->sack_sb.lost_bytes;
	  saw_reentry = 1;
	  break;
	}
      tcp_e2e_pump (vm, 2e-3);
    }
  if (!TCP_TEST_I ((saw_reentry),
		   "dsack_early: D-SACK exited timeout recovery and re-entered fast recovery "
		   "(tr delta %u, fr delta %u, flags 0x%x, lost %u, "
		   "loss matches %u drops %u, una %u, nxt %u, dsack flags 0x%x, "
		   "rxt ranges %u)",
		   client_tc->tr_occurences - tr_before, client_tc->fr_occurences - fr_before,
		   client_tc->flags, client_tc->sack_sb.lost_bytes, loss_rule->n_matched,
		   loss_rule->n_dropped, client_tc->snd_una - client_tc->iss,
		   client_tc->snd_nxt - client_tc->iss, client_tc->dsack_flags,
		   tcp_test_dsack_rxt_count (client_tc)))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I (
	(seq_lt (fresh_snd_una, fresh_snd_congestion) && fresh_snd_congestion == fresh_snd_nxt),
	"dsack_early: fresh recovery point reset before old point was ACKed "
	"(una %u, congestion %u, nxt %u)",
	fresh_snd_una - client_tc->iss, fresh_snd_congestion - client_tc->iss,
	fresh_snd_nxt - client_tc->iss))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((fresh_lost > 0 && fresh_cwnd < fresh_prev_cwnd),
		   "dsack_early: residual loss received a fresh reduction "
		   "(lost %u, cwnd %u, previous %u)",
		   fresh_lost, fresh_cwnd, fresh_prev_cwnd))
    {
      rv = 1;
      goto cleanup;
    }

  /* The residual retransmission rule is exhausted. Let its RTO complete the
   * transfer so the case also verifies that recovery remains live. */
  max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
  for (tries = 0; drained < total_bytes && tries < max_iters; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 10e-3);
    }
  if (!TCP_TEST_I ((drained == total_bytes),
		   "dsack_early: all %u bytes delivered after residual loss (got %u)", total_bytes,
		   drained))
    rv = 1;

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Stranded lost retransmit. Build one large lost run below high_rxt: drop a run
 * of consecutive original segments (so they become one contiguous hole) and
 * also drop the coalesced retransmit of that run, which advances high_rxt past
 * the whole hole. NextSeg (RFC6675) then skips it (end <= high_rxt), so the main
 * retransmit loop cannot resend it -- a lost retransmit that only the rto can
 * recover. This is the regression anchor for the removal of the "lost head
 * retransmit" heuristic (which used to dribble the head 1 seg/RTT and starve the
 * rto): with the heuristic gone the run is recovered by the rto and the transfer
 * still completes. Assert the drops landed and all data is delivered. */
static int
tcp_test_tamper_stranded_head (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "strand_head",
    .client_addr = 0x16161601,
    .server_addr = 0x17171701,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2251,
    .client_port = 0, /* ephemeral */
    .secret = 2250,
    /* Wide flight so the frontier can run far ahead of the stuck run. */
    .rx_fifo_size = 256 << 10,
    .tx_fifo_size = 256 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  session_t *client_s, *server_s;
  const u32 n_holes = 8;
  tcp_tamper_rule_t *orig_rule, *rxt_rule;
  u32 tries, mss, seq0, total_bytes = 256 << 10, drained = 0;
  u64 tr_before;
  u8 *data = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "strand_head: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "strand_head: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }
  mss = client_tc->snd_mss;
  tr_before = client_tc->tr_occurences;

  /* Build one large stranded hole, then keep it stranded:
   *  - drop the n_holes ORIGINAL mss segments at/above seq0 (they are mss-
   *    aligned, so exact seqs match) -> one contiguous lost run [seq0, seq0+N).
   *  - drop the COALESCED retransmit of that run, which the main loop sends as
   *    one segment starting at high_rxt == seq0. That send advances high_rxt
   *    past the whole run, so NextSeg now skips it (end <= high_rxt) -- the run
   *    is stranded and recovered only by the rto. */
  seq0 = client_tc->snd_una + 4 * mss;
  tcp_tamper_drop_from_seq (client_tc, seq0, n_holes);
  tcp_tamper_drop_seq (client_tc, seq0, 1);
  /* Reference by index: tcp_tamper_add_rule may realloc the rule vector, so
   * pointers returned by the constructors above can be stale after the 2nd add. */
  orig_rule = &tcp_tamper_main.rules[0];
  rxt_rule = &tcp_tamper_main.rules[1];
  tcp_tamper_enable (client_tc);

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "strand_head: client queued %u bytes",
		   total_bytes))
    {
      rv = 1;
      goto cleanup;
    }
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "strand_head: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  for (tries = 0; drained < total_bytes && tries < 8000; tries++)
    {
      drained += session_test_drain_rx_fifo (server_s);
      if (drained >= total_bytes)
	break;
      tcp_e2e_pump (vm, 5e-3);
    }

  if (!TCP_TEST_I ((orig_rule->n_dropped == n_holes && rxt_rule->n_dropped == 1),
		   "strand_head: %u originals dropped (%u) and coalesced retransmit dropped (%u)",
		   n_holes, orig_rule->n_dropped, rxt_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  /* Surface how the stranded run drained. With the head-retry heuristic removed
   * the run is drained by the rto, so tr rises. Informational. */
  vlib_cli_output (vm, "strand_head: tr delta %llu (rto drains) over %u stranded segs",
		   client_tc->tr_occurences - tr_before, n_holes);
  if (!TCP_TEST_I ((drained == total_bytes),
		   "strand_head: all %u bytes delivered despite the stranded run (got %u)",
		   total_bytes, drained))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

/* Drop the only in-flight segment and verify recovery through one RTO. */
static int
tcp_test_tamper_rto (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "rto",
    .client_addr = 0x18181801,
    .server_addr = 0x19191901,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2253,
    .client_port = 0, /* ephemeral */
    .secret = 2252,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *seg_rule;
  session_t *client_s, *server_s;
  u32 tries, tr_before, drained = 0, total_bytes;
  u8 *data = 0;
  int error, rv = 0, i;

  tcp_tamper_reset ();

  if (!TCP_TEST_I ((tcp_e2e_setup (vm, ctx, &params) == 0), "rto: e2e setup"))
    {
      rv = 1;
      goto cleanup;
    }
  client_tc = ctx->client_tc;
  client_s = ctx->client_s;
  server_s = session_get_if_valid (accepted_session_index, accepted_session_thread);
  if (!TCP_TEST_I ((server_s != 0), "rto: server session resolvable"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Drop the only in-flight segment so recovery requires an RTO. */
  total_bytes = client_tc->snd_mss;
  tr_before = client_tc->tr_occurences;
  client_tc->cwnd = clib_max (client_tc->cwnd, 4 * client_tc->snd_mss);
  client_tc->snd_wnd = clib_max (client_tc->snd_wnd, client_tc->cwnd);
  client_tc->cwnd_limited_seq = client_tc->snd_una;
  seg_rule = tcp_tamper_drop_seq (client_tc, client_tc->snd_una, 1);
  tcp_tamper_enable (client_tc);
  client_tc->rto = TCP_RTO_MIN;

  vec_validate (data, total_bytes - 1);
  for (i = 0; i < (int) total_bytes; i++)
    data[i] = i & 0xff;
  error = svm_fifo_enqueue (client_s->tx_fifo, total_bytes, data);
  if (!TCP_TEST_I ((error == (int) total_bytes), "rto: client queued %u bytes", total_bytes))
    {
      rv = 1;
      goto cleanup;
    }
  error = session_program_tx_io_evt (client_s->handle, SESSION_IO_EVT_TX);
  if (!TCP_TEST_I ((error == 0), "rto: client tx event programmed"))
    {
      rv = 1;
      goto cleanup;
    }

  /* Wait for delivery with an RTO-derived deadline. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    for (tries = 0; drained < total_bytes && tries < max_iters; tries++)
      {
	drained += session_test_drain_rx_fifo (server_s);
	if (drained >= total_bytes)
	  break;
	tcp_e2e_pump (vm, 10e-3);
      }
  }

  /* Delivery reaches the peer before its ACK necessarily reaches the sender.
   * Wait for timer recovery to finish before checking the loss window. */
  {
    u32 max_iters = tcp_e2e_rxt_wait_iters (client_tc, 10e-3);
    for (tries = 0; (tcp_in_recovery (client_tc) || client_tc->snd_una != client_tc->snd_nxt) &&
		    tries < max_iters;
	 tries++)
      tcp_e2e_pump (vm, 10e-3);
  }

  if (!TCP_TEST_I ((seg_rule->n_dropped == 1), "rto: the lone segment was dropped (dropped %u)",
		   seg_rule->n_dropped))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I (((client_tc->tr_occurences - tr_before) == 1),
		   "rto: recovered via a single retransmit timeout (tr delta %u)",
		   client_tc->tr_occurences - tr_before))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((drained == total_bytes), "rto: data delivered after the timeout (got %u of %u)",
		   drained, total_bytes))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((!tcp_in_recovery (client_tc) && client_tc->snd_una == client_tc->snd_nxt),
		   "rto: retransmitted app-limited flight was acknowledged"))
    {
      rv = 1;
      goto cleanup;
    }
  if (!TCP_TEST_I ((client_tc->cwnd > client_tc->snd_mss),
		   "rto: ACK resumes standard cwnd growth (cwnd %u, mss %u)", client_tc->cwnd,
		   client_tc->snd_mss))
    {
      rv = 1;
      goto cleanup;
    }

cleanup:
  tcp_tamper_reset ();
  vec_free (data);
  tcp_e2e_teardown (vm, ctx);
  return rv;
}

static int
tcp_test_tamper (vlib_main_t *vm, unformat_input_t *input)
{
  struct
  {
    const char *name;
    int (*fn) (vlib_main_t *);
  } cases[] = {
    { "fin", tcp_test_tamper_lost_fin },
    { "lost-ack", tcp_test_tamper_lost_final_ack },
    { "peer-fin", tcp_test_tamper_peer_fin_first },
    { "chain-rxt", tcp_test_tamper_chained_rxt },
    { "queued-fin", tcp_test_tamper_queued_fin },
    { "queued-data-loss", tcp_test_tamper_queued_data_loss },
    { "queued-data-loss-bt", tcp_test_tamper_queued_data_loss_bt },
    { "recov-pt", tcp_test_tamper_recovery_point },
    { "dsack-early", tcp_test_tamper_dsack_early_undo },
    { "strand-head", tcp_test_tamper_stranded_head },
    { "rto", tcp_test_tamper_rto },
  };
  int res = 0, i;

  /* No argument: run every case. */
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    {
      for (i = 0; i < ARRAY_LEN (cases); i++)
	if ((res = cases[i].fn (vm)))
	  return res;
      return 0;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u8 matched = 0;

      if (unformat (input, "all"))
	{
	  for (i = 0; i < ARRAY_LEN (cases); i++)
	    if ((res = cases[i].fn (vm)))
	      return res;
	  continue;
	}
      for (i = 0; i < ARRAY_LEN (cases); i++)
	{
	  if (unformat (input, cases[i].name))
	    {
	      matched = 1;
	      if ((res = cases[i].fn (vm)))
		return res;
	      break;
	    }
	}
      if (!matched)
	{
	  vlib_cli_output (vm, "unknown tamper case: '%U'", format_unformat_error, input);
	  return -1;
	}
    }
  return res;
}

static int
tcp_test_delivery (vlib_main_t * vm, unformat_input_t * input)
{
  clib_thread_index_t thread_index = 0, snd_una, *min_seqs = 0;
  tcp_rate_sample_t _rs = { 0 }, *rs = &_rs;
  tcp_connection_t _tc, *tc = &_tc;
  int __clib_unused verbose = 0, i;
  u64 rate = 1000, burst = 100;
  sack_block_t block;
  tcp_byte_tracker_t *bt;
  rb_node_t *root, *rbn;
  tcp_bt_sample_t *bts;
  u32 ack;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  /* Init data structures */
  memset (tc, 0, sizeof (*tc));
  tc->snd_mss = burst;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  scoreboard_init (&tc->sack_sb);
  tcp_test_set_time (thread_index, 1);
  transport_connection_tx_pacer_update (&tc->connection, rate, 1e6);

  tcp_bt_init (tc);
  bt = tc->bt;

  TCP_TEST (bt->last_ooo == TCP_BTS_INVALID_INDEX,
	    "last out-of-order sample should be invalid after init");

  /*
   * Track simple bursts without rxt
   */

  /* 1) track first burst a time 1 */
  tcp_bt_track_tx (tc, burst);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 1, "should have 1 sample");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->next == TCP_BTS_INVALID_INDEX, "next should be invalid");
  TCP_TEST (bts->prev == TCP_BTS_INVALID_INDEX, "prev should be invalid");
  TCP_TEST (bts->delivered_time == 1, "delivered time should be 1");
  TCP_TEST (bts->delivered == 0, "delivered should be 0");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_RXT), "not retransmitted");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_APP_LIMITED), "not app limited");

  /* 2) check delivery rate at time 2 */
  tcp_test_set_time (thread_index, 2);
  tc->snd_una = tc->snd_nxt = burst;
  rs->bytes_acked = burst;

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "sample should've been consumed");
  TCP_TEST (tc->delivered_time == 2, "delivered time should be 2");
  TCP_TEST (tc->delivered == burst, "delivered should be 100");
  TCP_TEST (rs->interval_time == 1, "ack time should be 1");
  TCP_TEST (rs->delivered == burst, "delivered should be 100");
  TCP_TEST (rs->prior_delivered == 0, "sample delivered should be 0");
  TCP_TEST (!(rs->flags & TCP_BTS_IS_RXT), "not retransmitted");
  TCP_TEST (tc->first_tx_time == 1, "first_tx_time %u", tc->first_tx_time);

  /* 3) track second burst at time 2 */
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  /* 4) track second burst at time 3 */
  tcp_test_set_time (thread_index, 3);
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  TCP_TEST (pool_elts (bt->samples) == 2, "should have 2 samples");

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->next == bt->tail, "next should tail");

  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST (bts->min_seq == tc->snd_nxt - burst,
	    "min seq should be snd_nxt prior to burst");
  TCP_TEST (bts->prev == bt->head, "prev should be head");

  /* 5) check delivery rate at time 4 */
  tcp_test_set_time (thread_index, 4);
  tc->snd_una = tc->snd_nxt;
  rs->bytes_acked = 2 * burst;

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "sample should've been consumed");
  TCP_TEST (tc->delivered_time == 4, "delivered time should be 4");
  TCP_TEST (tc->delivered == 3 * burst, "delivered should be 300 is %u",
	    tc->delivered);
  TCP_TEST (rs->interval_time == 2, "ack time should be 2");
  TCP_TEST (rs->delivered == 2 * burst, "delivered should be 200");
  TCP_TEST (rs->prior_delivered == burst, "delivered should be 100");
  TCP_TEST (!(rs->flags & TCP_BTS_IS_RXT), "not retransmitted");
  TCP_TEST (tc->first_tx_time == 2, "first_tx_time %u", tc->first_tx_time);

  /*
   * Track retransmissions
   *
   * snd_una should be 300 at this point
   */

  snd_una = tc->snd_una;

  /* 1) track first burst at time 4 */
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  /* 2) track second burst at time 5 */
  tcp_test_set_time (thread_index, 5);
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  /* 3) track third burst at time 6 */
  tcp_test_set_time (thread_index, 6);
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  /* 4) track fourth burst at time 7 */
  tcp_test_set_time (thread_index, 7);
  /* Limited until last burst is acked */
  tc->app_limited = snd_una + 4 * burst - 1;
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  /* 5) check delivery rate at time 8
   *
   * tc->snd_una = snd_una + 10
   * sacks:
   * [snd_una + burst, snd_una + burst + 10]
   * [snd_una + 2 * burst + 10, snd_una + 2 * burst + 20]
   */
  tcp_test_set_time (thread_index, 8);
  ack = snd_una + 10;

  TCP_TEST (pool_elts (bt->samples) == 4, "there should be 4 samples");

  block = (sack_block_t) { .start = snd_una + burst, .end = snd_una + burst + 10 };
  vec_add1 (tc->rcv_opts.sacks, block);
  block = (sack_block_t) { .start = snd_una + 2 * burst + 10, .end = snd_una + 2 * burst + 20 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, ack, rs);
  rs->bytes_acked = ack - tc->snd_una;
  tc->snd_una = ack;

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 7, "there should be 7 samples %u",
	    pool_elts (bt->samples));
  TCP_TEST (tc->delivered_time == 8, "delivered time should be 8");
  TCP_TEST (tc->delivered == 3 * burst + 30, "delivered should be %u is %u",
	    3 * burst + 30, tc->delivered);
  /* All 3 samples have the same delivered number of bytes. So the first is
   * the reference for delivery estimate. */
  TCP_TEST (rs->interval_time == 4, "ack time should be 4 is %.2f",
	    rs->interval_time);
  TCP_TEST (rs->delivered == 30, "delivered should be 30");
  TCP_TEST (rs->prior_delivered == 3 * burst,
	    "sample delivered should be %u", 3 * burst);
  TCP_TEST (!(rs->flags & TCP_BTS_IS_RXT), "not retransmitted");
  TCP_TEST (!(rs->flags & TCP_BTS_IS_APP_LIMITED), "not app limited");
  /* All 3 samples have the same delivered number of bytes. The first
   * sets the first tx time */
  TCP_TEST (tc->first_tx_time == 4, "first_tx_time %u", tc->first_tx_time);

  /* 6) Retransmit and track at time 9
   *
   * delivered = 3 * burst + 30
   * delivered_time = 8 (last ack)
   *
   * segments:
   * [snd_una + 10, snd_una + burst]
   * [snd_una + burst + 10, snd_una + 2 * burst + 10]
   * [snd_una + 2 * burst + 20, snd_una + 4 * burst]
   */
  tcp_test_set_time (thread_index, 9);

  tcp_bt_track_rxt (tc, snd_una + 10, snd_una + burst);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  /* The retransmit covers everything left from first burst */
  TCP_TEST (pool_elts (bt->samples) == 7, "there should be 7 samples %u",
	    pool_elts (bt->samples));

  tcp_bt_track_rxt (tc, snd_una + burst + 10, snd_una + 2 * burst + 10);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 6, "there should be 6 samples %u",
	    pool_elts (bt->samples));

  /* Retransmit covers last sample entirely so it should be removed */
  tcp_bt_track_rxt (tc, snd_una + 2 * burst + 20, snd_una + 4 * burst);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 5, "there should be 5 samples %u",
	    pool_elts (bt->samples));
  TCP_TEST (bt->last_ooo != TCP_BTS_INVALID_INDEX, "last retransmit sample should be cached");

  vec_validate (min_seqs, 4);
  min_seqs[0] = snd_una + 10;
  min_seqs[1] = snd_una + burst;
  min_seqs[2] = snd_una + burst + 10;
  min_seqs[3] = snd_una + 2 * burst + 10;
  min_seqs[4] = snd_una + 2 * burst + 20;

  root = bt->sample_lookup.nodes + rb_tree_root (&bt->sample_lookup);
  bts = bt->samples + bt->head;
  for (i = 0; i < vec_len (min_seqs); i++)
    {
      if (bts->min_seq != min_seqs[i])
	TCP_TEST (0, "should be %u is %u", min_seqs[i], bts->min_seq);
      rbn = rb_tree_search_subtree_custom (&bt->sample_lookup, root,
					   bts->min_seq, tbt_seq_lt);
      if (rbn->opaque != bts - bt->samples)
	TCP_TEST (0, "lookup should work");
      bts = bt->samples + bts->next;
    }

  /* 7) check delivery rate at time 10
   *
   * tc->snd_una = snd_una + 2 * burst
   * sacks:
   * [snd_una + 2 * burst + 20, snd_una + 2 * burst + 30]
   * [snd_una + 2 * burst + 50, snd_una + 2 * burst + 60]
   */
  tcp_test_set_time (thread_index, 10);
  ack = snd_una + 2 * burst;
  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = snd_una + 2 * burst + 20, .end = snd_una + 2 * burst + 30 };
  vec_add1 (tc->rcv_opts.sacks, block);
  block = (sack_block_t) { .start = snd_una + 2 * burst + 50, .end = snd_una + 2 * burst + 60 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_test_rcv_sacks (tc, ack, rs);
  rs->bytes_acked = ack - tc->snd_una;
  tc->snd_una = ack;

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 6, "num samples should be 6 is %u", pool_elts (bt->samples));
  TCP_TEST (tc->delivered_time == 10, "delivered time should be 10");
  TCP_TEST (tc->delivered == 5 * burst + 30, "delivered should be %u is %u", 5 * burst + 30,
	    tc->delivered);
  /* A rxt was acked and delivered time for it is 8 (last ack time) so
   * ack_time is 2 (8 - 10). However, first_tx_time for rxt was 4 and rxt
   * time 9. Therefore snd_time is 5 (9 - 4)*/
  TCP_TEST (rs->interval_time == 5, "ack time should be 5 is %.2f",
	    rs->interval_time);
  /* delivered_now - delivered_rxt ~ 5 * burst + 30 - 3 * burst - 30 */
  TCP_TEST (rs->delivered == 2 * burst, "delivered should be 200 is %u", rs->delivered);
  TCP_TEST (rs->prior_delivered == 3 * burst + 30,
	    "sample delivered should be %u", 3 * burst + 30);
  TCP_TEST (rs->flags & TCP_BTS_IS_RXT, "is retransmitted");
  /* Sample is app limited because of the retransmits */
  TCP_TEST (rs->flags & TCP_BTS_IS_APP_LIMITED, "is app limited");
  TCP_TEST (tc->app_limited, "app limited should be set");
  TCP_TEST (tc->first_tx_time == 9, "first_tx_time %u", tc->first_tx_time);


  /*
   * 8) check delivery rate at time 11
   */
  tcp_test_set_time (thread_index, 11);
  ack = tc->snd_nxt;
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 0;
  tcp_test_rcv_sacks (tc, ack, rs);
  rs->bytes_acked = ack - tc->snd_una;
  tc->snd_una = ack;
  TCP_TEST (rs->last_bytes_delivered == 30,
	    "cumulative ACK recognizes 30 previously delivered bytes is %u",
	    rs->last_bytes_delivered);

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "num samples should be 0 is %u",
	    pool_elts (bt->samples));
  TCP_TEST (bt->head == TCP_BTS_INVALID_INDEX && bt->tail == TCP_BTS_INVALID_INDEX &&
	      bt->last_ooo == TCP_BTS_INVALID_INDEX,
	    "sample indices should be invalid after freeing cached sample");
  TCP_TEST (tc->delivered_time == 11, "delivered time should be 11");
  TCP_TEST (tc->delivered == 7 * burst, "delivered should be %u is %u",
	    7 * burst, tc->delivered);
  /* Delivered time at retransmit was 8 so ack_time is 11 - 8 = 3. However,
   * first_tx_time for rxt was 4 and rxt time was 9. Therefore snd_time
   * is 9 - 4 = 5 */
  TCP_TEST (rs->interval_time == 5, "ack time should be 5 is %.2f",
	    rs->interval_time);
  /* delivered_now - delivered_rxt ~ 7 * burst - 3 * burst - 30.
   * That's because we didn't retransmit any new segment. */
  TCP_TEST (rs->delivered == 4 * burst - 30, "delivered should be 370 is %u", rs->delivered);
  TCP_TEST (rs->prior_delivered == 3 * burst + 30,
	    "sample delivered should be %u", 3 * burst + 30);
  TCP_TEST (rs->flags & TCP_BTS_IS_RXT, "is retransmitted");
  TCP_TEST (rs->flags & TCP_BTS_IS_APP_LIMITED, "is app limited");
  TCP_TEST (tc->app_limited == 0, "app limited should be cleared");
  TCP_TEST (tc->first_tx_time == 9, "first_tx_time %u", tc->first_tx_time);

  /*
   * 9) test flush
   */

  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  tcp_test_set_time (thread_index, 12);
  tcp_bt_track_tx (tc, burst);
  tc->snd_nxt += burst;

  tcp_bt_flush_samples (tc);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after flush");
  TCP_TEST (pool_elts (bt->samples) == 0, "flush should free all samples");
  TCP_TEST (bt->head == TCP_BTS_INVALID_INDEX && bt->tail == TCP_BTS_INVALID_INDEX &&
	      bt->last_ooo == TCP_BTS_INVALID_INDEX,
	    "sample indices should be invalid after flush");

  /*
   * Cleanup
   */
  scoreboard_clear (&tc->sack_sb);
  pool_free (tc->sack_sb.holes);
  vec_free (tc->rcv_opts.sacks);
  vec_free (min_seqs);
  tcp_bt_cleanup (tc);
  return 0;
}

typedef struct
{
  u32 sacked_bytes;
  u32 lost_bytes;
  u32 high_sacked;
  u32 reorder;
  u32 last_sacked_bytes;
  u32 last_bytes_delivered;
  u32 rxt_sacked;
  u32 last_lost;
  u8 is_reneging;
} tcp_test_sack_snapshot_t;

static int
tcp_test_sack_backend_trace (tcp_test_sack_backend_t backend, tcp_test_sack_snapshot_t *snapshots)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs;
  sack_block_t blocks[3];
  u32 acks[] = { 0, 100, 100, 450 };
  u32 n_blocks[] = { 3, 3, 1, 2 };
  u32 i, j;

  tc->snd_mss = 100;
  tc->snd_nxt = 1000;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  tcp_test_sack_backend_init (tc, backend);

  for (i = 0; i < ARRAY_LEN (acks); i++)
    {
      vec_reset_length (tc->rcv_opts.sacks);

      if (i < 2)
	{
	  blocks[0] = (sack_block_t) { .start = 300, .end = 400 };
	  blocks[1] = (sack_block_t) { .start = 500, .end = 600 };
	  blocks[2] = (sack_block_t) { .start = 700, .end = 800 };
	}
      else if (i == 2)
	blocks[0] = (sack_block_t) { .start = 200, .end = 300 };
      else
	{
	  blocks[0] = (sack_block_t) { .start = 500, .end = 600 };
	  blocks[1] = (sack_block_t) { .start = 700, .end = 800 };
	}

      for (j = 0; j < n_blocks[i]; j++)
	vec_add1 (tc->rcv_opts.sacks, blocks[j]);
      tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);

      tcp_test_rcv_sacks (tc, acks[i], &rs);
      snapshots[i] = (tcp_test_sack_snapshot_t) {
	.sacked_bytes = tc->sack_sb.sacked_bytes,
	.lost_bytes = tc->sack_sb.lost_bytes,
	.high_sacked = tc->sack_sb.high_sacked,
	.reorder = tc->sack_sb.reorder,
	.last_sacked_bytes = rs.last_sacked_bytes,
	.last_bytes_delivered = rs.last_bytes_delivered,
	.rxt_sacked = rs.rxt_sacked,
	.last_lost = rs.last_lost,
	.is_reneging = tc->sack_sb.is_reneging,
      };

      if (backend == TCP_TEST_SACK_BACKEND_BT)
	{
	  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT range store sane at step %u", i);
	  TCP_TEST (tc->sack_sb.head == TCP_INVALID_SACK_HOLE_INDEX &&
		      pool_elts (tc->sack_sb.holes) == 0,
		    "BT mode does not allocate scoreboard holes at step %u", i);
	}

      rs.bytes_acked = acks[i] - tc->snd_una;
      tc->snd_una = acks[i];
      if (backend == TCP_TEST_SACK_BACKEND_BT)
	tcp_bt_sample_delivery_rate (tc, &rs);
    }

  tcp_test_sack_backend_cleanup (tc, backend);
  return 0;
}

static int
tcp_test_sack_backends (void)
{
  tcp_test_sack_snapshot_t snapshots[TCP_TEST_N_SACK_BACKENDS][4];
  tcp_test_sack_snapshot_t *sb, *bt;
  u32 i;

  if (tcp_test_sack_backend_trace (TCP_TEST_SACK_BACKEND_SCOREBOARD,
				   snapshots[TCP_TEST_SACK_BACKEND_SCOREBOARD]) ||
      tcp_test_sack_backend_trace (TCP_TEST_SACK_BACKEND_BT, snapshots[TCP_TEST_SACK_BACKEND_BT]))
    return 1;

  for (i = 0; i < ARRAY_LEN (snapshots[0]); i++)
    {
      sb = &snapshots[TCP_TEST_SACK_BACKEND_SCOREBOARD][i];
      bt = &snapshots[TCP_TEST_SACK_BACKEND_BT][i];
      TCP_TEST (sb->sacked_bytes == bt->sacked_bytes,
		"BT sacked bytes match default at step %u: %u", i, bt->sacked_bytes);
      TCP_TEST (sb->lost_bytes == bt->lost_bytes, "BT lost bytes match default at step %u: %u", i,
		bt->lost_bytes);
      TCP_TEST (sb->high_sacked == bt->high_sacked, "BT high_sacked matches default at step %u: %u",
		i, bt->high_sacked);
      TCP_TEST (sb->reorder == bt->reorder, "BT reorder matches default at step %u: %u", i,
		bt->reorder);
      TCP_TEST (sb->last_sacked_bytes == bt->last_sacked_bytes,
		"BT newly sacked bytes match default at step %u: %u", i, bt->last_sacked_bytes);
      TCP_TEST (sb->last_bytes_delivered == bt->last_bytes_delivered,
		"BT cumulatively delivered SACK bytes match at step %u: %u", i,
		bt->last_bytes_delivered);
      TCP_TEST (sb->rxt_sacked == bt->rxt_sacked,
		"BT retransmitted SACK bytes match default at step %u: %u", i, bt->rxt_sacked);
      TCP_TEST (sb->last_lost == bt->last_lost, "BT newly lost bytes match default at step %u: %u",
		i, bt->last_lost);
      TCP_TEST (sb->is_reneging == bt->is_reneging, "BT reneging matches default at step %u: %u", i,
		bt->is_reneging);
    }

  return 0;
}

typedef enum
{
  TCP_TEST_BT_SB_OPEN,
  TCP_TEST_BT_SB_RECOVERY,
  TCP_TEST_BT_SB_RESCUE,
} tcp_test_bt_sb_mode_t;

static int
tcp_test_bt_scoreboard_random (u32 base, u32 seed, tcp_test_bt_sb_mode_t mode)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  tcp_rate_sample_t default_rs, bt_rs;
  sack_block_t block;
  u32 ack, end, flight = 8192, high_rxt, i, j, n_blocks, offset, span;
  u8 rescue_active = 0, same;

  default_tc->snd_mss = bt_tc->snd_mss = 128;
  default_tc->snd_una = bt_tc->snd_una = base;
  default_tc->snd_nxt = base + flight;
  default_tc->rcv_opts.flags = bt_tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  bt_tc->snd_nxt = base;
  tcp_bt_track_tx (bt_tc, flight);
  bt_tc->snd_nxt = base + flight;

  if (mode != TCP_TEST_BT_SB_OPEN)
    {
      default_tc->flags = bt_tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
      default_tc->snd_congestion = bt_tc->snd_congestion = base + flight;
      tcp_sack_init_rxt (default_tc, base);
      tcp_sack_init_rxt (bt_tc, base);

      /* HighRxt only identifies a retransmission frontier for the
       * scoreboard. BT must additionally mark the retransmitted samples.
       * Mark the full flight so random SACK blocks cannot straddle HighRxt;
       * BT intentionally accounts such mixed blocks more precisely than the
       * hole scoreboard, so they are not strict equivalence cases. */
      high_rxt = base + flight;
      tcp_bt_track_rxt (bt_tc, base, high_rxt);
      default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = high_rxt;
    }

  for (i = 0; i < 96 && default_tc->snd_una != default_tc->snd_nxt; i++)
    {
      seed = 1664525 * seed + 1013904223;
      span = default_tc->snd_nxt - default_tc->snd_una;
      ack = default_tc->snd_una + clib_min (seed % 97, span);
      n_blocks = (seed >> 16) & 3;

      /* Retransmit the head from time to time. Once sacked samples are shorter
       * than mss this covers bytes the peer already sacked, which must not
       * disturb either aggregate. Both backends still agree because neither
       * reclassifies sacked bytes. */
      if (mode != TCP_TEST_BT_SB_OPEN && (seed & 0x300) &&
	  seq_lt (default_tc->snd_una, default_tc->snd_nxt))
	{
	  u32 rxt_end = default_tc->snd_una + clib_min (default_tc->snd_mss, span);
	  tcp_bt_track_rxt (bt_tc, bt_tc->snd_una, rxt_end);
	  TCP_TEST (tcp_bt_is_sane (bt_tc->bt) && tcp_bt_is_sane_post_recovery (bt_tc),
		    "random BT head retransmit keeps aggregates in step at step %u "
		    "(base 0x%x mode %u, sacked %u lost %u)",
		    i, base, mode, bt_tc->sack_sb.sacked_bytes, bt_tc->sack_sb.lost_bytes);
	}

      vec_reset_length (default_tc->rcv_opts.sacks);
      vec_reset_length (bt_tc->rcv_opts.sacks);

      for (j = 0; j < n_blocks && seq_lt (ack + 1, default_tc->snd_nxt); j++)
	{
	  seed = 1664525 * seed + 1013904223;
	  span = default_tc->snd_nxt - ack - 1;
	  offset = seed % span;
	  block.start = ack + 1 + offset;
	  seed = 1664525 * seed + 1013904223;
	  end = block.start + 1 + seed % (default_tc->snd_nxt - block.start);
	  block.end = end;
	  vec_add1 (default_tc->rcv_opts.sacks, block);
	  vec_add1 (bt_tc->rcv_opts.sacks, block);
	}

      default_tc->rcv_opts.n_sack_blocks = vec_len (default_tc->rcv_opts.sacks);
      bt_tc->rcv_opts.n_sack_blocks = vec_len (bt_tc->rcv_opts.sacks);
      if (vec_len (default_tc->rcv_opts.sacks))
	{
	  default_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
	  bt_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
	}
      else
	{
	  default_tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
	  bt_tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
	}

      clib_memset (&default_rs, 0, sizeof (default_rs));
      clib_memset (&bt_rs, 0, sizeof (bt_rs));
      tcp_rcv_sacks (default_tc, ack, &default_rs);
      tcp_rcv_sacks (bt_tc, ack, &bt_rs);

      /* Production completes deferred BT cumulative-ACK accounting after
       * snd_una and bytes_acked are updated. Compare backends after that full
       * per-ACK sequence rather than halfway through it. */
      default_rs.bytes_acked = bt_rs.bytes_acked = ack - default_tc->snd_una;
      default_tc->snd_una = bt_tc->snd_una = ack;
      tcp_bt_sample_delivery_rate (bt_tc, &bt_rs);

      same = default_tc->sack_sb.sacked_bytes == bt_tc->sack_sb.sacked_bytes &&
	     default_tc->sack_sb.lost_bytes == bt_tc->sack_sb.lost_bytes &&
	     default_tc->sack_sb.high_sacked == bt_tc->sack_sb.high_sacked &&
	     default_tc->sack_sb.reorder == bt_tc->sack_sb.reorder &&
	     default_tc->sack_sb.is_reneging == bt_tc->sack_sb.is_reneging &&
	     default_rs.last_sacked_bytes == bt_rs.last_sacked_bytes &&
	     default_rs.last_bytes_delivered == bt_rs.last_bytes_delivered &&
	     default_rs.rxt_sacked == bt_rs.rxt_sacked && default_rs.last_lost == bt_rs.last_lost &&
	     tcp_bt_is_sane (bt_tc->bt) && bt_tc->sack_sb.head == TCP_INVALID_SACK_HOLE_INDEX;
      TCP_TEST (same,
		"random BT scoreboard trace matches default at step %u "
		"(base 0x%x mode %u, sacked %u/%u lost %u/%u "
		"high %u/%u reorder %u/%u rxt %u/%u newly-lost %u/%u)",
		i, base, mode, default_tc->sack_sb.sacked_bytes, bt_tc->sack_sb.sacked_bytes,
		default_tc->sack_sb.lost_bytes, bt_tc->sack_sb.lost_bytes,
		default_tc->sack_sb.high_sacked, bt_tc->sack_sb.high_sacked,
		default_tc->sack_sb.reorder, bt_tc->sack_sb.reorder, default_rs.rxt_sacked,
		bt_rs.rxt_sacked, default_rs.last_lost, bt_rs.last_lost);

      /* Rescue is only valid after SACK processing has established an
       * outstanding range from which the rescue retransmit was selected. */
      if (mode == TCP_TEST_BT_SB_RESCUE && !rescue_active && default_tc->sack_sb.sacked_bytes)
	{
	  default_tc->sack_sb.rescue_rxt = bt_tc->sack_sb.rescue_rxt = default_tc->snd_congestion;
	  rescue_active = 1;
	}
    }

  TCP_TEST (mode != TCP_TEST_BT_SB_RESCUE || rescue_active,
	    "random BT scoreboard trace activated rescue mode");

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  vec_free (default_tc->rcv_opts.sacks);
  vec_free (bt_tc->rcv_opts.sacks);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

static int
tcp_test_bt_reorder (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_block_t block;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 3000);
  tc->snd_nxt = tc->snd_congestion = 3000;
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;

  /* A retransmission from an earlier recovery remains RTT/reorder ambiguous
   * after the current recovery resets HighRxt below it. */
  tcp_bt_track_rxt (tc, 300, 400);
  tcp_dsack_recovery_clear (tc);
  tc->sack_sb.high_rxt = 0;
  tc->sack_sb.rescue_rxt = tc->snd_una - 1;

  block = (sack_block_t) { .start = 2400, .end = 3000 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);

  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 300, .end = 400 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.reorder == TCP_DUPACK_THRESHOLD,
	    "BT old retransmit does not grow reorder above floor: %u", tc->sack_sb.reorder);
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT remains sane after old retransmit sack");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  clib_memset (tc, 0, sizeof (*tc));

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 3000);
  tc->snd_nxt = tc->snd_congestion = 3000;
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;

  block = (sack_block_t) { .start = 2400, .end = 3000 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);

  /* Rescue retransmits the highest outstanding range without advancing
   * HighRxt. It must not suppress learning from unrelated original data. */
  tcp_bt_track_rxt (tc, 2300, 2400);
  tc->sack_sb.rescue_rxt = tc->snd_congestion;
  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 300, .end = 400 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.reorder == 27, "BT original data grows reorder after rescue: %u",
	    tc->sack_sb.reorder);

  /* The rescued range itself remains ambiguous. Reset the learned value so a
   * mistaken update from this range is observable. */
  tc->sack_sb.reorder = TCP_DUPACK_THRESHOLD;
  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 2300, .end = 2400 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.reorder == TCP_DUPACK_THRESHOLD,
	    "BT rescue retransmit does not grow reorder above floor: %u", tc->sack_sb.reorder);
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT remains sane after rescue reorder checks");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

static int
tcp_test_bt_retransmit_ranges (void)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  tcp_rate_sample_t default_rs = {}, bt_rs = {};
  sack_scoreboard_hole_t *hole;
  tcp_rxt_range_t range;
  sack_block_t blocks[] = {
    { .start = 300, .end = 400 },
    { .start = 500, .end = 600 },
    { .start = 700, .end = 800 },
  };
  u8 default_rescue, bt_rescue, default_limited, bt_limited;
  u32 i, n_bytes;

  default_tc->snd_mss = bt_tc->snd_mss = 100;
  default_tc->snd_nxt = 1000;
  default_tc->rcv_opts.flags = bt_tc->rcv_opts.flags =
    TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  tcp_bt_track_tx (bt_tc, 1000);
  bt_tc->snd_nxt = 1000;

  for (i = 0; i < ARRAY_LEN (blocks); i++)
    {
      vec_add1 (default_tc->rcv_opts.sacks, blocks[i]);
      vec_add1 (bt_tc->rcv_opts.sacks, blocks[i]);
    }
  default_tc->rcv_opts.n_sack_blocks = ARRAY_LEN (blocks);
  bt_tc->rcv_opts.n_sack_blocks = ARRAY_LEN (blocks);
  tcp_rcv_sacks (default_tc, 0, &default_rs);
  tcp_rcv_sacks (bt_tc, 0, &bt_rs);
  tcp_sack_init_rxt (default_tc, 0);
  tcp_sack_init_rxt (bt_tc, 0);
  hole = scoreboard_get_hole (&default_tc->sack_sb, default_tc->sack_sb.cur_rxt_hole);

  for (i = 0; i < 16; i++)
    {
      default_rescue = bt_rescue = 0;
      default_limited = bt_limited = 0;
      hole = scoreboard_next_rxt_hole (&default_tc->sack_sb, hole, 0 /* have_unsent */,
				       &default_rescue, &default_limited);
      u8 have_range =
	tcp_bt_next_rxt_range (bt_tc, 0 /* have_unsent */, &bt_rescue, &bt_limited, &range);

      TCP_TEST (!!hole == have_range, "BT retransmit selection matches default at step %u", i);
      TCP_TEST (default_rescue == bt_rescue, "BT rescue decision matches default at step %u", i);
      TCP_TEST (default_limited == bt_limited, "BT send-limit decision matches default at step %u",
		i);

      if (!hole)
	break;

      TCP_TEST (range.start == default_tc->sack_sb.high_rxt && range.end == hole->end,
		"BT retransmit range matches default at step %u: [%u,%u)", i, range.start,
		range.end);
      n_bytes = clib_min (100, range.end - range.start);
      default_tc->sack_sb.high_rxt += n_bytes;
      bt_tc->sack_sb.high_rxt += n_bytes;
    }

  TCP_TEST (i < 16, "BT retransmit walk terminates");

  default_tc->flags = bt_tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  default_tc->snd_congestion = bt_tc->snd_congestion = 1000;
  default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = 500;
  tcp_dsack_recovery_clear (bt_tc);
  tcp_bt_track_rxt (bt_tc, 0, 300);
  tcp_bt_track_rxt (bt_tc, 400, 500);
  vec_reset_length (default_tc->rcv_opts.sacks);
  vec_reset_length (bt_tc->rcv_opts.sacks);
  blocks[0] = (sack_block_t) { .start = 400, .end = 500 };
  vec_add1 (default_tc->rcv_opts.sacks, blocks[0]);
  vec_add1 (bt_tc->rcv_opts.sacks, blocks[0]);
  default_tc->rcv_opts.n_sack_blocks = 1;
  bt_tc->rcv_opts.n_sack_blocks = 1;
  clib_memset (&default_rs, 0, sizeof (default_rs));
  clib_memset (&bt_rs, 0, sizeof (bt_rs));
  tcp_rcv_sacks (default_tc, 100, &default_rs);
  tcp_rcv_sacks (bt_tc, 100, &bt_rs);
  TCP_TEST (default_rs.rxt_sacked == bt_rs.rxt_sacked && bt_rs.rxt_sacked == 200,
	    "BT retransmission delivery accounting matches default: %u", bt_rs.rxt_sacked);
  TCP_TEST (default_tc->sack_sb.sacked_bytes == bt_tc->sack_sb.sacked_bytes &&
	      default_tc->sack_sb.lost_bytes == bt_tc->sack_sb.lost_bytes,
	    "BT recovery ACK/SACK aggregates match default");
  TCP_TEST (tcp_bt_is_sane (bt_tc->bt), "BT range store sane after recovery ACK/SACK");

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  vec_free (default_tc->rcv_opts.sacks);
  vec_free (bt_tc->rcv_opts.sacks);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

/* A cumulative-only ACK on a SACK-enabled byte tracker still owns the recovery
 * scoreboard accounting. */
static int
tcp_test_bt_cumulative_ack (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  tcp_bt_sample_t *head;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 300);
  tc->snd_nxt = 300;

  /* A clean cumulative ACK has no SACK block and therefore bypasses the
   * generic SACK preparation path. Delivery sampling must retire its prefix
   * and advance the byte tracker's scoreboard boundaries. */
  tcp_test_rcv_sacks (tc, 100, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_BT_PROCESSED),
	    "clean BT cumulative ACK is deferred to delivery sampling");
  TCP_TEST (pool_elts (tc->bt->samples) == 1,
	    "SACK preparation leaves a clean BT cumulative ACK untouched");
  rs.bytes_acked = 100;
  tc->snd_una = 100;
  tcp_bt_sample_delivery_rate (tc, &rs);

  head = pool_elt_at_index (tc->bt->samples, tc->bt->head);
  TCP_TEST (head->min_seq == 100 && tc->delivered == 100,
	    "BT delivery sampling retires a clean cumulative ACK");
  TCP_TEST (tc->sack_sb.high_sacked == 100 && tc->bt->sack_loss_high == 100,
	    "clean cumulative ACK advances BT scoreboard boundaries");

  /* With SACK negotiated, the byte tracker is also the recovery scoreboard.
   * A cumulative ACK without a SACK option must therefore retire loss and
   * retransmission state, not just generate a delivery-rate sample. */
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_congestion = tc->snd_nxt;
  tcp_sack_rxt_mark_lost (tc);
  tcp_bt_track_rxt (tc, 100, 200);
  tc->sack_sb.high_rxt = 200;

  tcp_test_rcv_sacks (tc, 200, &rs);
  TCP_TEST (!(rs.ack_flags & TCP_ACK_F_BT_PROCESSED),
	    "recovery cumulative ACK is deferred to one accounted tracker walk");
  rs.bytes_acked = 100;
  tc->snd_una = 200;
  tcp_bt_sample_delivery_rate (tc, &rs);

  TCP_TEST (tc->sack_sb.lost_bytes == 100,
	    "BT cumulative ACK retires lost bytes during recovery: %u", tc->sack_sb.lost_bytes);
  TCP_TEST (rs.rxt_sacked == 100, "BT cumulative ACK accounts retransmitted delivery: %u",
	    rs.rxt_sacked);
  TCP_TEST (tc->sack_sb.high_sacked == 200 && tc->bt->sack_loss_high == 200,
	    "recovery cumulative ACK advances BT scoreboard boundaries");
  TCP_TEST (tcp_bt_is_sane (tc->bt) && tcp_bt_is_sane_post_recovery (tc),
	    "BT remains sane after cumulative-only recovery ACK");

  tcp_bt_cleanup (tc);
  return 0;
}

/* A range reported as delivered by SACK remains delivered if the receiver
 * later reneges. Its cumulative ACK must retire the sample without crediting
 * the same bytes to the delivery-rate estimator a second time. */
static int
tcp_test_bt_reneging_delivery (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  tcp_bt_sample_t *bts;
  sack_block_t block;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 300);
  tc->snd_nxt = 300;

  block = (sack_block_t) { .start = 100, .end = 200 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_BT_PROCESSED, "BT SACK processing records its tracker walk");
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tc->delivered == 100, "BT credits the initial SACK once: %u", tc->delivered);

  /* Cumulative ACK of the prefix leaves the formerly SACKed range at the
   * tracker head, which is the reneging signal consumed on RTO. */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 0;
  tcp_test_rcv_sacks (tc, 100, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_BT_PROCESSED,
	    "BT cumulative ACK after SACK history records its tracker walk");
  rs.bytes_acked = 100;
  tc->snd_una = 100;
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tc->sack_sb.is_reneging, "BT detects SACK reneging at the tracker head");
  TCP_TEST (tc->delivered == 200, "BT credits only the new cumulative ACK: %u", tc->delivered);

  TCP_TEST (tcp_sack_handle_reneging (tc), "BT handles the pending SACK reneging");
  bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
  TCP_TEST ((bts->flags & (TCP_BTS_IS_DELIVERED | TCP_BTS_IS_LOST)) ==
		(TCP_BTS_IS_DELIVERED | TCP_BTS_IS_LOST) &&
	      !(bts->flags & TCP_BTS_IS_SACKED),
	    "reneged sample remains delivered but is no longer SACKed");

  tcp_bt_track_rxt (tc, 100, 200);
  tc->sack_sb.high_rxt = 200;
  tcp_test_rcv_sacks (tc, 200, &rs);
  rs.bytes_acked = 100;
  tc->snd_una = 200;
  tcp_bt_sample_delivery_rate (tc, &rs);

  TCP_TEST (rs.last_bytes_delivered == 100,
	    "reneged range is recognized as previously delivered: %u", rs.last_bytes_delivered);
  TCP_TEST (tc->delivered == 200 && rs.acked_and_sacked == 0,
	    "reneged range is not credited twice: delivered %u acked-and-sacked %u", tc->delivered,
	    rs.acked_and_sacked);
  TCP_TEST (rs.prior_delivered == 0 && tcp_bt_is_sane (tc->bt),
	    "reneged range does not create an unanchored rate sample");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  clib_memset (tc, 0, sizeof (*tc));

  /* Re-SACKing data whose delivery was recorded before reneging restores
   * current SACK state, but must not credit the delivery estimator again. */
  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 300);
  tc->snd_nxt = 300;

  block = (sack_block_t) { .start = 100, .end = 200 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  tcp_bt_sample_delivery_rate (tc, &rs);

  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 0;
  tcp_test_rcv_sacks (tc, 100, &rs);
  rs.bytes_acked = 100;
  tc->snd_una = 100;
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tcp_sack_handle_reneging (tc), "BT handles reneging before re-SACK");

  block = (sack_block_t) { .start = 150, .end = 200 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 100, &rs);
  tcp_bt_sample_delivery_rate (tc, &rs);

  TCP_TEST (rs.last_sacked_bytes == 50 && rs.last_bytes_delivered == 50,
	    "re-SACK identifies 50 previously delivered bytes: %u/%u", rs.last_sacked_bytes,
	    rs.last_bytes_delivered);
  TCP_TEST (tc->delivered == 200 && rs.acked_and_sacked == 0,
	    "re-SACK does not credit delivery twice: delivered %u acked-and-sacked %u",
	    tc->delivered, rs.acked_and_sacked);
  TCP_TEST (tc->sack_sb.sacked_bytes == 50 && tcp_bt_is_sane_post_recovery (tc),
	    "re-SACK restores current SACK state without aggregate drift");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* Repeated SACK blocks can begin inside a range that is already fully SACKed.
 * They must not fragment that range or change any per-ACK accounting. */
static int
tcp_test_bt_repeat_sack (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_block_t block;
  u32 i, n_samples;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 1000);
  tc->snd_nxt = 1000;

  block = (sack_block_t) { .start = 100, .end = 900 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);

  n_samples = pool_elts (tc->bt->samples);
  TCP_TEST (rs.last_sacked_bytes == 800 && tc->sack_sb.sacked_bytes == 800,
	    "initial SACK accounts 800 bytes: %u/%u", rs.last_sacked_bytes,
	    tc->sack_sb.sacked_bytes);
  TCP_TEST (n_samples == 3, "initial SACK creates three ranges: %u", n_samples);

  for (i = 2; i < 9; i++)
    {
      tc->rcv_opts.sacks[0].start = i * 100;
      tcp_test_rcv_sacks (tc, 0, &rs);

      TCP_TEST (rs.last_sacked_bytes == 0 && rs.last_lost == 0,
		"repeat SACK has no accounting delta at step %u: %u/%u", i, rs.last_sacked_bytes,
		rs.last_lost);
      TCP_TEST (pool_elts (tc->bt->samples) == n_samples,
		"repeat SACK does not fragment samples at step %u: %u", i,
		pool_elts (tc->bt->samples));
    }

  /* Skipping the already SACKed prefix must still find new coverage after it. */
  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 200, .end = 950 };
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (rs.last_sacked_bytes == 50 && tc->sack_sb.sacked_bytes == 850,
	    "overlap accounts only its new suffix: %u/%u", rs.last_sacked_bytes,
	    tc->sack_sb.sacked_bytes);
  TCP_TEST (pool_elts (tc->bt->samples) == n_samples && tcp_bt_is_sane (tc->bt) &&
	      tcp_bt_is_sane_post_recovery (tc),
	    "overlap preserves compact, sane BT state");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* Filling the gap between two compatible SACKed samples must coalesce the
 * complete range. Exercise it together with cumulative ACK advancement so
 * the synthetic cumulative block is ignored after its prefix was retired. */
static int
tcp_test_bt_sack_bridge (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  tcp_bt_sample_t *bts;
  sack_block_t block;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 400);
  tc->snd_nxt = 400;

  block = (sack_block_t) { .start = 100, .end = 200 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);

  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 300, .end = 400 };
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (pool_elts (tc->bt->samples) == 4,
	    "separate SACK islands retain the intervening sample: %u", pool_elts (tc->bt->samples));

  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 200, .end = 300 };
  tcp_test_rcv_sacks (tc, 50, &rs);

  bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
  bts = pool_elt_at_index (tc->bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 100 && bts->max_seq == 400 && (bts->flags & TCP_BTS_IS_SACKED),
	    "bridging SACK coalesces both neighboring islands: [%u,%u)", bts->min_seq,
	    bts->max_seq);
  TCP_TEST (pool_elts (tc->bt->samples) == 2 && tcp_bt_is_sane (tc->bt) &&
	      tcp_bt_is_sane_post_recovery (tc),
	    "bridging SACK leaves compact, sane BT state: %u", pool_elts (tc->bt->samples));

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* New SACK evidence advances a monotonic loss boundary. Cumulative ACKs
 * retire exact aggregate state and move the boundary past the retired prefix;
 * they do not require loss to be rediscovered over the remaining samples. */
static int
tcp_test_bt_incremental_sack_loss (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  sack_block_t block;
  u32 i;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  for (i = 0; i < 10; i++)
    {
      tcp_test_set_time (tc->c_thread_index, i + 1);
      tcp_bt_track_tx (tc, 100);
      tc->snd_nxt += 100;
    }

  block = (sack_block_t) { .start = 700, .end = 800 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.lost_bytes == 0 && tc->bt->sack_loss_high == 0,
	    "one SACK block does not advance loss boundary: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);

  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 500, .end = 600 };
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.lost_bytes == 0 && tc->bt->sack_loss_high == 0,
	    "two SACK blocks do not advance loss boundary: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);

  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 900, .end = 1000 };
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (rs.last_lost == 500 && tc->sack_sb.lost_bytes == 500 && tc->bt->sack_loss_high == 500,
	    "third SACK block marks initial loss prefix: %u/%u/%u", rs.last_lost,
	    tc->sack_sb.lost_bytes, tc->bt->sack_loss_high);

  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 800, .end = 900 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (rs.last_lost == 100 && tc->sack_sb.lost_bytes == 600 && tc->bt->sack_loss_high == 700,
	    "new SACK marks only newly exposed loss interval: lost %u/%u high %u "
	    "sacked %u/%u scoreboard-high %u reorder %u",
	    rs.last_lost, tc->sack_sb.lost_bytes, tc->bt->sack_loss_high, rs.last_sacked_bytes,
	    tc->sack_sb.sacked_bytes, tc->sack_sb.high_sacked, tc->sack_sb.reorder);

  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 0;
  tcp_test_rcv_sacks (tc, 800, &rs);
  rs.bytes_acked = 800;
  tc->snd_una = 800;
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tc->sack_sb.lost_bytes == 0 && tc->sack_sb.sacked_bytes == 200 &&
	      tc->bt->sack_loss_high == 800,
	    "cumulative ACK retires aggregates and advances loss boundary: %u/%u/%u",
	    tc->sack_sb.lost_bytes, tc->sack_sb.sacked_bytes, tc->bt->sack_loss_high);

  TCP_TEST (tcp_bt_is_sane (tc->bt) && tcp_bt_is_sane_post_recovery (tc),
	    "incremental loss update keeps BT aggregates exact");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);

  /* RTO loss is deliberately outside the SACK boundary. A full recompute
   * removes it, then rebuilds the same boundary once enough SACK evidence is
   * present. */
  clib_memset (tc, 0, sizeof (*tc));
  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 1000);
  tc->snd_nxt = 1000;

  block = (sack_block_t) { .start = 300, .end = 400 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  tcp_bt_rxt_mark_lost (tc);
  TCP_TEST (tc->sack_sb.lost_bytes == 300 && tc->bt->sack_loss_high == 0,
	    "RTO loss does not advance SACK boundary: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);

  tcp_bt_recompute_sack_loss (tc);
  TCP_TEST (tc->sack_sb.lost_bytes == 0 && tc->bt->sack_loss_high == 0,
	    "full recompute removes RTO-only loss: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);

  tc->rcv_opts.sacks[0] = (sack_block_t) { .start = 400, .end = 600 };
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.lost_bytes == 300 && tc->bt->sack_loss_high == 300,
	    "new evidence establishes SACK loss boundary: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);
  tcp_bt_recompute_sack_loss (tc);
  TCP_TEST (tc->sack_sb.lost_bytes == 300 && tc->bt->sack_loss_high == 300 &&
	      tcp_bt_is_sane_post_recovery (tc),
	    "full recompute preserves SACK-derived boundary: %u/%u", tc->sack_sb.lost_bytes,
	    tc->bt->sack_loss_high);

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* Retransmit selection caches the end of a fragmented logical range. A clean
 * cumulative ACK must preserve it, while a new SACK must invalidate it before
 * splitting that range. */
static int
tcp_test_bt_retransmit_range_cache (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs = {};
  tcp_rxt_range_t range;
  sack_block_t block;
  u8 can_rescue = 0, snd_limited = 0;
  u32 i;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);

  for (i = 0; i < 4; i++)
    {
      tcp_test_set_time (tc->c_thread_index, i + 1);
      tcp_bt_track_tx (tc, 100);
      tc->snd_nxt += 100;
    }

  tcp_bt_rxt_mark_lost (tc);
  tc->sack_sb.high_sacked = tc->snd_nxt;
  tcp_bt_init_rxt (tc, tc->snd_una);
  TCP_TEST (tcp_bt_next_rxt_range (tc, 0, &can_rescue, &snd_limited, &range),
	    "BT finds the fragmented retransmit range");
  TCP_TEST (range.start == 0 && range.end == 400 && tc->bt->cur_rxt_end == 400,
	    "BT caches the fragmented range end: [%u,%u)", range.start, range.end);

  /* Model one partial retransmission and an ACK below HighRxt. There is no SACK
   * state to recompute, so the ACK-only fast path keeps the range-end cache. */
  tc->sack_sb.high_rxt = 50;
  tcp_test_rcv_sacks (tc, 25, &rs);
  rs.bytes_acked = 25;
  tc->snd_una = 25;
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tc->bt->cur_rxt != TCP_BTS_INVALID_INDEX && tc->bt->cur_rxt_end == 400,
	    "clean ACK preserves the active retransmit range cache");
  TCP_TEST (tc->sack_sb.lost_bytes == 375 && tcp_bt_is_sane_post_recovery (tc),
	    "clean ACK updates only the cumulatively acknowledged loss: %u",
	    tc->sack_sb.lost_bytes);

  /* A new SACK in the cached range must invalidate the old end. The next
   * selection stops at the new SACKed island instead of using the stale 400. */
  block = (sack_block_t) { .start = 200, .end = 300 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 25, &rs);
  TCP_TEST (tc->bt->cur_rxt_end == tc->sack_sb.high_rxt,
	    "new SACK invalidates the retransmit range cache");

  can_rescue = snd_limited = 0;
  TCP_TEST (tcp_bt_next_rxt_range (tc, 0, &can_rescue, &snd_limited, &range),
	    "BT rebuilds the retransmit range after SACK");
  TCP_TEST (range.start == 50 && range.end == 200,
	    "rebuilt retransmit range stops at SACKed island: [%u,%u)", range.start, range.end);
  TCP_TEST (tcp_bt_is_sane (tc->bt) && tcp_bt_is_sane_post_recovery (tc),
	    "BT remains sane after retransmit cache invalidation");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* Range discovery may skip a SACKed island before finding the next lost
 * range. Cache the range's first sample, not the island, so a partial send
 * still selects the remaining lost bytes ahead of unsent data. */
static int
tcp_test_bt_retransmit_range_cache_skip_sacked (void)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  tcp_rate_sample_t default_rs = {}, bt_rs = {};
  sack_scoreboard_hole_t *hole;
  tcp_rxt_range_t range;
  sack_block_t blocks[] = {
    { .start = 100, .end = 200 },
    { .start = 500, .end = 800 },
  };
  u8 default_rescue, bt_rescue, default_limited, bt_limited, have_range;
  u32 i;

  default_tc->snd_mss = bt_tc->snd_mss = 100;
  default_tc->snd_nxt = 1000;
  default_tc->rcv_opts.flags = bt_tc->rcv_opts.flags =
    TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  tcp_bt_track_tx (bt_tc, 1000);
  bt_tc->snd_nxt = 1000;

  for (i = 0; i < ARRAY_LEN (blocks); i++)
    {
      vec_add1 (default_tc->rcv_opts.sacks, blocks[i]);
      vec_add1 (bt_tc->rcv_opts.sacks, blocks[i]);
    }
  default_tc->rcv_opts.n_sack_blocks = bt_tc->rcv_opts.n_sack_blocks = ARRAY_LEN (blocks);
  tcp_rcv_sacks (default_tc, 0, &default_rs);
  tcp_rcv_sacks (bt_tc, 0, &bt_rs);

  default_tc->flags = bt_tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  default_tc->snd_congestion = bt_tc->snd_congestion = 1000;
  tcp_sack_init_rxt (default_tc, 0);
  tcp_sack_init_rxt (bt_tc, 0);
  hole = scoreboard_get_hole (&default_tc->sack_sb, default_tc->sack_sb.cur_rxt_hole);

  /* Consume the first lost range, [0,100). The next lookup must skip the
   * SACKed [100,200) island to reach the multi-MSS lost [200,500) range. */
  default_rescue = bt_rescue = default_limited = bt_limited = 0;
  hole = scoreboard_next_rxt_hole (&default_tc->sack_sb, hole, 1 /* have_unsent */, &default_rescue,
				   &default_limited);
  have_range = tcp_bt_next_rxt_range (bt_tc, 1 /* have_unsent */, &bt_rescue, &bt_limited, &range);
  TCP_TEST (hole && have_range && range.start == 0 && range.end == 100,
	    "BT and scoreboard select the first lost range: [%u,%u)", range.start, range.end);

  tcp_bt_track_rxt (bt_tc, 0, 100);
  default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = 100;

  default_rescue = bt_rescue = default_limited = bt_limited = 0;
  hole = scoreboard_next_rxt_hole (&default_tc->sack_sb, hole, 1 /* have_unsent */, &default_rescue,
				   &default_limited);
  have_range = tcp_bt_next_rxt_range (bt_tc, 1 /* have_unsent */, &bt_rescue, &bt_limited, &range);
  TCP_TEST (hole && have_range && range.start == 200 && range.end == 500,
	    "BT skips the SACKed island and selects lost range: [%u,%u)", range.start, range.end);

  /* Model one MSS sent from the selected range. With unsent data available,
   * the cached classification must still make RFC 6675 Rule 1 win. */
  tcp_bt_track_rxt (bt_tc, 200, 300);
  default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = 300;

  default_rescue = bt_rescue = default_limited = bt_limited = 0;
  hole = scoreboard_next_rxt_hole (&default_tc->sack_sb, hole, 1 /* have_unsent */, &default_rescue,
				   &default_limited);
  have_range = tcp_bt_next_rxt_range (bt_tc, 1 /* have_unsent */, &bt_rescue, &bt_limited, &range);
  TCP_TEST (hole && have_range && range.start == 300 && range.end == 500,
	    "BT continues the partially retransmitted lost range: [%u,%u)", range.start, range.end);
  TCP_TEST (default_rescue == bt_rescue && default_limited == bt_limited,
	    "BT cached range retains scoreboard rescue and limiting decisions");
  TCP_TEST (tcp_bt_is_sane (bt_tc->bt) && tcp_bt_is_sane_post_recovery (bt_tc),
	    "BT remains sane after cached lost-range selection");

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  vec_free (default_tc->rcv_opts.sacks);
  vec_free (bt_tc->rcv_opts.sacks);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

static int
tcp_test_bt_rescue_range (void)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  sack_scoreboard_hole_t *hole;
  tcp_rxt_range_t range;
  u8 default_rescue = 0, bt_rescue = 0, default_limited = 0, bt_limited = 0;
  u32 n_bytes, offset;

  default_tc->snd_mss = bt_tc->snd_mss = 100;
  default_tc->snd_una = bt_tc->snd_una = 100;
  default_tc->snd_nxt = 1000;
  default_tc->sack_sb.high_sacked = bt_tc->sack_sb.high_sacked = 100;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  bt_tc->snd_nxt = 100;
  tcp_bt_track_tx (bt_tc, 900);
  bt_tc->snd_nxt = 1000;

  tcp_sack_rxt_mark_lost (default_tc);
  tcp_sack_rxt_mark_lost (bt_tc);
  tcp_sack_init_rxt (default_tc, 100);
  tcp_sack_init_rxt (bt_tc, 100);

  hole = scoreboard_get_hole (&default_tc->sack_sb, default_tc->sack_sb.cur_rxt_hole);
  hole = scoreboard_next_rxt_hole (&default_tc->sack_sb, hole, 0 /* have_unsent */, &default_rescue,
				   &default_limited);
  u8 have_range =
    tcp_bt_next_rxt_range (bt_tc, 0 /* have_unsent */, &bt_rescue, &bt_limited, &range);
  TCP_TEST (!hole && !have_range, "ordinary BT and scoreboard retransmit ranges are exhausted");
  TCP_TEST (default_rescue && bt_rescue, "BT and scoreboard request a rescue retransmit");
  TCP_TEST (default_limited && bt_limited, "BT and scoreboard report rescue send limiting");

  hole = scoreboard_last_hole (&default_tc->sack_sb);
  have_range = tcp_bt_last_rxt_range (bt_tc, &range);
  TCP_TEST (hole && have_range, "BT and scoreboard retain a rescue retransmit range");
  TCP_TEST (range.start == hole->start && range.end == hole->end && range.is_lost == hole->is_lost,
	    "BT rescue range matches default: [%u,%u)", range.start, range.end);

  n_bytes = clib_min (bt_tc->snd_mss, range.end - range.start);
  TCP_TEST (seq_geq (range.end, bt_tc->snd_una + n_bytes),
	    "BT rescue range produces a valid retransmit offset");
  offset = range.end - bt_tc->snd_una - n_bytes;
  TCP_TEST (offset == 800, "BT rescue retransmit offset is %u", offset);

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

/* Before the first SACK, HighACK must follow snd_una instead of retaining the
 * zeroed scoreboard value. Otherwise serial arithmetic can select Rule 3 for
 * upper-half initial sequence numbers instead of requesting Rule 4 rescue. */
static int
tcp_test_bt_initial_high_sacked (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rxt_range_t range;
  const u32 base = 0x80001000;
  u8 can_rescue = 0, snd_limited = 0;

  tc->snd_mss = 100;
  tc->snd_una = tc->snd_nxt = base;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  TCP_TEST (tc->sack_sb.high_sacked == base, "BT initializes HighACK to snd_una: 0x%x",
	    tc->sack_sb.high_sacked);

  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;
  tcp_bt_init_rxt (tc, tc->snd_una);
  TCP_TEST (!tcp_bt_next_rxt_range (tc, 0, &can_rescue, &snd_limited, &range) && can_rescue &&
	      snd_limited,
	    "BT applies Rule 4 before SACK state at upper-half sequence base");

  tcp_bt_cleanup (tc);
  return 0;
}

/* An rto head retransmit always covers a full mss, so it spans bytes the peer
 * already sacked as soon as the first outstanding sample is shorter than mss.
 * Those bytes must keep their sacked classification and both aggregates must
 * stay in step with the samples, exactly as the hole scoreboard keeps them:
 * there sacked ranges are the gaps between holes, so a retransmit can never
 * rewrite them. */
static int
tcp_test_bt_rxt_over_sacked (void)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  tcp_rate_sample_t default_rs, bt_rs;
  sack_block_t block;

  default_tc->snd_mss = bt_tc->snd_mss = 100;
  default_tc->snd_nxt = 1000;
  default_tc->rcv_opts.flags = bt_tc->rcv_opts.flags =
    TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  tcp_bt_track_tx (bt_tc, 1000);
  bt_tc->snd_nxt = 1000;

  /*
   * Sack a block that starts mid-segment so the head sample is under mss
   */
  block = (sack_block_t) { .start = 50, .end = 200 };
  vec_add1 (default_tc->rcv_opts.sacks, block);
  vec_add1 (bt_tc->rcv_opts.sacks, block);
  default_tc->rcv_opts.n_sack_blocks = bt_tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (default_tc, 0, &default_rs);
  tcp_test_rcv_sacks (bt_tc, 0, &bt_rs);

  TCP_TEST (bt_tc->sack_sb.sacked_bytes == default_tc->sack_sb.sacked_bytes &&
	      bt_tc->sack_sb.sacked_bytes == 150,
	    "BT sacked bytes match default before rto: %u", bt_tc->sack_sb.sacked_bytes);

  /*
   * Rto marks the head lost and rewinds the retransmit frontier
   */
  default_tc->flags = bt_tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  default_tc->snd_congestion = bt_tc->snd_congestion = 1000;
  tcp_sack_rxt_mark_lost (default_tc);
  tcp_sack_rxt_mark_lost (bt_tc);
  tcp_sack_init_rxt (default_tc, 0);
  tcp_sack_init_rxt (bt_tc, 0);

  TCP_TEST (bt_tc->sack_sb.lost_bytes == default_tc->sack_sb.lost_bytes &&
	      bt_tc->sack_sb.lost_bytes == 50,
	    "BT lost bytes match default after rto: %u", bt_tc->sack_sb.lost_bytes);

  /*
   * Head retransmit of one mss. It spans the sacked block, so BT may only
   * relabel the 50 bytes below it.
   */
  tcp_bt_track_rxt (bt_tc, 0, 100);
  default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = 100;

  TCP_TEST (bt_tc->sack_sb.sacked_bytes == default_tc->sack_sb.sacked_bytes &&
	      bt_tc->sack_sb.sacked_bytes == 150,
	    "BT retains sacked bytes a head retransmit spans: %u", bt_tc->sack_sb.sacked_bytes);
  TCP_TEST (bt_tc->sack_sb.lost_bytes == default_tc->sack_sb.lost_bytes &&
	      bt_tc->sack_sb.lost_bytes == 50,
	    "BT lost bytes match default after head retransmit: %u", bt_tc->sack_sb.lost_bytes);
  TCP_TEST (tcp_bt_is_sane (bt_tc->bt), "BT range store sane after head retransmit");
  TCP_TEST (tcp_bt_is_sane_post_recovery (bt_tc),
	    "BT aggregates match samples after head retransmit");

  /*
   * Next ack. Drift in either aggregate shows up here as a mismatch against
   * the samples the byte tracker walks.
   */
  vec_reset_length (default_tc->rcv_opts.sacks);
  vec_reset_length (bt_tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 300, .end = 400 };
  vec_add1 (default_tc->rcv_opts.sacks, block);
  vec_add1 (bt_tc->rcv_opts.sacks, block);
  default_tc->rcv_opts.n_sack_blocks = bt_tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (default_tc, 0, &default_rs);
  tcp_test_rcv_sacks (bt_tc, 0, &bt_rs);

  TCP_TEST (bt_tc->sack_sb.sacked_bytes == default_tc->sack_sb.sacked_bytes &&
	      bt_tc->sack_sb.sacked_bytes == 250,
	    "BT sacked bytes match default on next ack: %u", bt_tc->sack_sb.sacked_bytes);
  TCP_TEST (bt_tc->sack_sb.lost_bytes == default_tc->sack_sb.lost_bytes &&
	      bt_tc->sack_sb.lost_bytes == 50,
	    "BT lost bytes match default on next ack: %u", bt_tc->sack_sb.lost_bytes);
  TCP_TEST (bt_rs.last_sacked_bytes == default_rs.last_sacked_bytes &&
	      bt_rs.last_lost == default_rs.last_lost,
	    "BT per-ack deltas match default on next ack");
  TCP_TEST (tcp_bt_is_sane_post_recovery (bt_tc), "BT aggregates match samples on next ack");

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  vec_free (default_tc->rcv_opts.sacks);
  vec_free (bt_tc->rcv_opts.sacks);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

/* Same invariant on the path that extends the previous retransmit sample
 * instead of allocating a new one. */
static int
tcp_test_bt_rxt_merge_over_sacked (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_rate_sample_t rs;
  sack_block_t block;

  tc->snd_mss = 100;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 1000);
  tc->snd_nxt = 1000;

  block = (sack_block_t) { .start = 200, .end = 300 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (tc, 0, &rs);
  TCP_TEST (tc->sack_sb.sacked_bytes == 100, "sacked bytes are %u", tc->sack_sb.sacked_bytes);

  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->snd_congestion = 1000;
  tcp_sack_rxt_mark_lost (tc);
  tcp_sack_init_rxt (tc, 0);
  TCP_TEST (tc->sack_sb.lost_bytes == 200, "lost bytes are %u", tc->sack_sb.lost_bytes);

  /* Retransmit the head, then a contiguous range that runs into the sacked
   * block. The second call extends the sample the first one allocated. */
  tcp_bt_track_rxt (tc, 0, 50);
  tcp_bt_track_rxt (tc, 50, 250);

  TCP_TEST (tc->sack_sb.sacked_bytes == 100,
	    "BT retains sacked bytes a merged retransmit spans: %u", tc->sack_sb.sacked_bytes);
  TCP_TEST (tc->sack_sb.lost_bytes == 200, "BT lost bytes survive a merged retransmit: %u",
	    tc->sack_sb.lost_bytes);
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT range store sane after merged retransmit");
  TCP_TEST (tcp_bt_is_sane_post_recovery (tc),
	    "BT aggregates match samples after merged retransmit");

  /* Retransmitting only sacked bytes must be a no-op for the aggregates */
  tcp_bt_track_rxt (tc, 200, 300);
  TCP_TEST (tc->sack_sb.sacked_bytes == 100 && tc->sack_sb.lost_bytes == 200,
	    "BT aggregates unchanged by a fully sacked retransmit: %u/%u", tc->sack_sb.sacked_bytes,
	    tc->sack_sb.lost_bytes);
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT range store sane after fully sacked retransmit");
  TCP_TEST (tcp_bt_is_sane_post_recovery (tc),
	    "BT aggregates match samples after fully sacked retransmit");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

/* Contiguous retransmits may coalesce within a loss class, but must preserve a
 * boundary between lost and not-lost source samples. */
static int
tcp_test_bt_rxt_merge_loss_boundary (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_bt_sample_t *bts, *next;
  u32 i, now;

  for (i = 0; i < 2; i++)
    {
      clib_memset (tc, 0, sizeof (*tc));
      tc->snd_mss = 100;
      scoreboard_init (&tc->sack_sb);
      tcp_bt_init (tc);

      now = 1 + 3 * i;
      tcp_test_set_time (tc->c_thread_index, now);
      tcp_bt_track_tx (tc, 50);
      tc->snd_nxt = 50;
      tcp_test_set_time (tc->c_thread_index, now + 1);
      tcp_bt_track_tx (tc, 50);
      tc->snd_nxt = 100;

      bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
      if (i)
	bts = pool_elt_at_index (tc->bt->samples, bts->next);
      bts->flags |= TCP_BTS_IS_LOST;
      tc->sack_sb.lost_bytes = 50;

      tcp_test_set_time (tc->c_thread_index, now + 2);
      tcp_bt_track_rxt (tc, 0, 25);
      tcp_bt_track_rxt (tc, 25, 100);

      bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
      next = pool_elt_at_index (tc->bt->samples, bts->next);
      TCP_TEST (bts->min_seq == 0 && bts->max_seq == 50 && (bts->flags & TCP_BTS_IS_RXT) &&
		  !!(bts->flags & TCP_BTS_IS_LOST) == !i,
		"BT preserves first loss class across merged retransmits");
      TCP_TEST (next->min_seq == 50 && next->max_seq == 100 && (next->flags & TCP_BTS_IS_RXT) &&
		  !!(next->flags & TCP_BTS_IS_LOST) == !!i,
		"BT preserves second loss class across merged retransmits");
      TCP_TEST (tc->sack_sb.lost_bytes == 50 && pool_elts (tc->bt->samples) == 2,
		"BT preserves the loss boundary and aggregate: %u", tc->sack_sb.lost_bytes);
      TCP_TEST (tcp_bt_is_sane (tc->bt) && tcp_bt_is_sane_post_recovery (tc),
		"BT aggregates match retransmit samples across a loss boundary");

      tcp_bt_cleanup (tc);
    }
  return 0;
}

/* A retransmit crossing a SACKed island must also relabel the unsacked suffix
 * that went on the wire. Otherwise its delivery is not counted as a
 * retransmission and its original RTT sample remains eligible. */
static int
tcp_test_bt_rxt_across_sacked_island (void)
{
  tcp_connection_t _default_tc = {}, _bt_tc = {};
  tcp_connection_t *default_tc = &_default_tc, *bt_tc = &_bt_tc;
  tcp_rate_sample_t default_rs, bt_rs;
  tcp_bt_sample_t *bts;
  sack_block_t block;

  default_tc->snd_mss = bt_tc->snd_mss = 100;
  default_tc->snd_nxt = 200;
  default_tc->rcv_opts.flags = bt_tc->rcv_opts.flags =
    TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&default_tc->sack_sb);
  scoreboard_init (&bt_tc->sack_sb);
  tcp_bt_init (bt_tc);
  tcp_bt_track_tx (bt_tc, 200);
  bt_tc->snd_nxt = 200;

  block = (sack_block_t) { .start = 40, .end = 60 };
  vec_add1 (default_tc->rcv_opts.sacks, block);
  vec_add1 (bt_tc->rcv_opts.sacks, block);
  default_tc->rcv_opts.n_sack_blocks = bt_tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (default_tc, 0, &default_rs);
  tcp_test_rcv_sacks (bt_tc, 0, &bt_rs);

  default_tc->flags = bt_tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  default_tc->snd_congestion = bt_tc->snd_congestion = 200;
  tcp_sack_rxt_mark_lost (default_tc);
  tcp_sack_rxt_mark_lost (bt_tc);
  tcp_sack_init_rxt (default_tc, 0);
  tcp_sack_init_rxt (bt_tc, 0);

  /* The RTO segment covers unsacked bytes on both sides of the SACKed island. */
  tcp_bt_track_rxt (bt_tc, 0, 100);
  default_tc->sack_sb.high_rxt = bt_tc->sack_sb.high_rxt = 100;

  bts = pool_elt_at_index (bt_tc->bt->samples, bt_tc->bt->head);
  TCP_TEST (bts->min_seq == 0 && bts->max_seq == 40 && (bts->flags & TCP_BTS_IS_RXT),
	    "BT tracks retransmitted prefix [0,40)");
  bts = pool_elt_at_index (bt_tc->bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 40 && bts->max_seq == 60 && (bts->flags & TCP_BTS_IS_SACKED),
	    "BT preserves SACKed island [40,60)");
  bts = pool_elt_at_index (bt_tc->bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 60 && bts->max_seq == 100 && (bts->flags & TCP_BTS_IS_RXT),
	    "BT tracks retransmitted suffix [60,100)");

  vec_reset_length (default_tc->rcv_opts.sacks);
  vec_reset_length (bt_tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 60, .end = 100 };
  vec_add1 (default_tc->rcv_opts.sacks, block);
  vec_add1 (bt_tc->rcv_opts.sacks, block);
  default_tc->rcv_opts.n_sack_blocks = bt_tc->rcv_opts.n_sack_blocks = 1;
  tcp_test_rcv_sacks (default_tc, 0, &default_rs);
  tcp_test_rcv_sacks (bt_tc, 0, &bt_rs);

  TCP_TEST (bt_rs.rxt_sacked == default_rs.rxt_sacked && bt_rs.rxt_sacked == 40,
	    "BT counts retransmitted suffix delivery: %u", bt_rs.rxt_sacked);
  TCP_TEST (bt_rs.flags & TCP_BTS_IS_RXT, "BT marks the suffix rate sample as RTT-ambiguous");
  TCP_TEST (tcp_bt_is_sane (bt_tc->bt) && tcp_bt_is_sane_post_recovery (bt_tc),
	    "BT remains sane after SACKing retransmitted suffix");

  scoreboard_clear (&default_tc->sack_sb);
  pool_free (default_tc->sack_sb.holes);
  vec_free (default_tc->rcv_opts.sacks);
  vec_free (bt_tc->rcv_opts.sacks);
  tcp_bt_cleanup (bt_tc);
  return 0;
}

static int
tcp_test_bt_rxt_merge_flags (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_bt_sample_t *bts;

  tcp_bt_init (tc);
  tcp_test_set_time (tc->c_thread_index, 1);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt = 100;

  /* Contiguous retransmits at the same timestamp may only be coalesced when
   * the resulting samples carry identical delivery-rate metadata. */
  tcp_test_set_time (tc->c_thread_index, 2);
  tcp_bt_track_rxt (tc, 0, 50);
  tc->app_limited = 1;
  tcp_bt_track_rxt (tc, 50, 100);

  bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
  TCP_TEST (bts->min_seq == 0 && bts->max_seq == 50 && (bts->flags & TCP_BTS_IS_RXT) &&
	      !(bts->flags & TCP_BTS_IS_APP_LIMITED),
	    "BT retains non-app-limited retransmit [0:50]");
  bts = pool_elt_at_index (tc->bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 50 && bts->max_seq == 100 &&
	      (bts->flags & (TCP_BTS_IS_RXT | TCP_BTS_IS_APP_LIMITED)) ==
		(TCP_BTS_IS_RXT | TCP_BTS_IS_APP_LIMITED),
	    "BT retains app-limited retransmit [50:100]");
  TCP_TEST (pool_elts (tc->bt->samples) == 2 && tcp_bt_is_sane (tc->bt),
	    "BT keeps incompatible retransmit samples separate");

  tcp_bt_cleanup (tc);
  return 0;
}

static int
tcp_test_bt_dsack (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;
  tcp_bt_sample_t *bts;
  tcp_rate_sample_t rs = {};
  sack_block_t block;
  u32 matched, samples;

  tc->snd_mss = 100;
  tc->snd_una = tc->snd_nxt = 1000;
  tc->snd_wnd_max = 1000;
  tc->snd_congestion = 1600;
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_SACK;
  scoreboard_init (&tc->sack_sb);
  tcp_bt_init (tc);
  tcp_bt_track_tx (tc, 600);
  tc->snd_nxt = 1600;

  tc->flags = 0;
  tcp_bt_track_rxt (tc, 1100, 1200);
  TCP_TEST (!tcp_dsack_has_history (tc),
	    "BT does not account retransmission outside congestion recovery");
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_dsack_recovery_init (tc);
  TCP_TEST (tc->dsack_pending_bytes == 100 && tc->dsack_history_start == 1000 &&
	      (tc->dsack_flags & TCP_DSACK_HISTORY),
	    "BT seeds D-SACK accounting from an active retransmission");

  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tcp_rcv_sacks (tc, 1300, &rs);
  rs.bytes_acked = 300;
  tc->snd_una = 1300;
  tcp_bt_sample_delivery_rate (tc, &rs);
  bts = pool_elt_at_index (tc->bt->samples, tc->bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una && tc->dsack_pending_bytes == 100,
	    "BT frees ACKed samples and keeps aggregate D-SACK history");
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT range store sane after ACKed samples are freed");

  tc->snd_congestion = 1200;
  tcp_cong_recovery_off (tc);
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK_PERMITTED;
  clib_memset (&rs, 0, sizeof (rs));
  tcp_rcv_sacks (tc, 1400, &rs);
  rs.bytes_acked = 100;
  tc->snd_una = 1400;
  tcp_bt_sample_delivery_rate (tc, &rs);
  TCP_TEST (tcp_dsack_has_history (tc) && tc->dsack_pending_bytes == 100,
	    "BT retains D-SACK history across ordinary post-recovery ACKs");

  tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;
  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 1100, .end = 1200 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  clib_memset (&rs, 0, sizeof (rs));
  tcp_rcv_dsack (tc, 1200, &rs);
  TCP_TEST (rs.ack_flags & TCP_ACK_F_DSACK, "BT recognizes D-SACK against ACKed history");
  TCP_TEST (!tc->dsack_pending_bytes, "BT accounts D-SACK evidence for ACKed samples");
  TCP_TEST (!(tc->dsack_flags & (TCP_DSACK_INELIGIBLE | TCP_DSACK_UNDO_DISABLED)),
	    "BT D-SACK history remains undo eligible: 0x%x", tc->dsack_flags);
  TCP_TEST ((rs.ack_flags & (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS)) ==
	      (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS),
	    "BT aggregate history proves a retransmission spurious");

  tcp_bt_dsack_recovery_clear (tc);
  tc->snd_una = 1400;
  tc->snd_nxt = 1600;
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_bt_track_rxt (tc, 1400, 1600);
  block = (sack_block_t) { .start = 1400, .end = 1500 };
  samples = pool_elts (tc->bt->samples);
  matched = tcp_bt_dsack_mark_duplicate (tc, block.start, block.end);
  TCP_TEST (matched == 100 && tc->dsack_pending_bytes == 200 &&
	      pool_elts (tc->bt->samples) == samples,
	    "BT D-SACK matcher reports coverage without updating aggregate state");
  block = (sack_block_t) { .start = 1500, .end = 1600 };
  matched = tcp_bt_dsack_mark_duplicate (tc, block.start, block.end);
  TCP_TEST (matched == 100 && tc->dsack_pending_bytes == 200,
	    "BT D-SACK matcher leaves byte accounting to the common path");
  TCP_TEST (tcp_bt_is_sane (tc->bt), "BT range store sane after D-SACK matching");

  tcp_bt_dsack_recovery_clear (tc);
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_bt_track_rxt (tc, 1400, 1500);
  tcp_bt_track_rxt (tc, 1400, 1500);
  block = (sack_block_t) { .start = 1400, .end = 1500 };
  matched = tcp_bt_dsack_mark_duplicate (tc, block.start, block.end);
  TCP_TEST (matched == 100 && tc->dsack_pending_bytes == 200,
	    "BT D-SACK matcher does not consume repeated retransmit credit");

  tcp_bt_dsack_recovery_clear (tc);
  tc->snd_una = 1400;
  tc->snd_nxt = 1600;
  tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
  tcp_bt_track_rxt (tc, 1450, 1500);
  vec_reset_length (tc->rcv_opts.sacks);
  block = (sack_block_t) { .start = 1450, .end = 1500 };
  vec_add1 (tc->rcv_opts.sacks, block);
  block = (sack_block_t) { .start = 1501, .end = 1600 };
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 2;
  clib_memset (&rs, 0, sizeof (rs));
  tcp_rcv_sacks (tc, 1500, &rs);
  TCP_TEST ((rs.ack_flags & (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS)) ==
	      (TCP_ACK_F_DSACK | TCP_ACK_F_DSACK_SPURIOUS),
	    "BT processes D-SACK evidence before ACK and SACK sample retirement");
  TCP_TEST (!tc->dsack_pending_bytes && tcp_bt_is_sane (tc->bt),
	    "BT keeps aggregate state sane after combined D-SACK processing");

  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  return 0;
}

static int
tcp_test_bt_toggle (void)
{
  tcp_connection_t _tc = {}, *tc = &_tc;

  tc->snd_una = 100;
  tc->snd_nxt = 200;
  TCP_TEST (tcp_bt_enable (tc, 0) == 0 && tc->bt == 0,
	    "disabled byte tracker is a no-op with data in flight");
  TCP_TEST (tcp_bt_enable (tc, 1) == -1 && tc->bt == 0,
	    "cannot enable byte tracker with data in flight");

  tc->snd_nxt = tc->snd_una;
  TCP_TEST (tcp_bt_enable (tc, 1) == 0 && tc->bt != 0,
	    "can enable byte tracker with an empty flight");

  tc->snd_nxt = 200;
  TCP_TEST (tcp_bt_enable (tc, 1) == 0 && tc->bt != 0,
	    "enabled byte tracker is a no-op with data in flight");
  TCP_TEST (tcp_bt_enable (tc, 0) == -1 && tc->bt != 0,
	    "cannot disable byte tracker with data in flight");

  tc->snd_una = tc->snd_nxt;
  TCP_TEST (tcp_bt_enable (tc, 0) == 0 && tc->bt == 0,
	    "can disable byte tracker with an empty flight");
  return 0;
}

static int
tcp_test_bt (vlib_main_t * vm, unformat_input_t * input)
{
  clib_thread_index_t thread_index = 0;
  tcp_rate_sample_t _rs = { 0 }, *rs = &_rs;
  tcp_connection_t _tc, *tc = &_tc;
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  int __clib_unused verbose = 0, i, rv;
  fifo_segment_t *fs;
  tcp_byte_tracker_t *bt;
  session_t *s;
  tcp_bt_sample_t *bts;
  u32 head;
  u8 *bt_fmt = 0;

  if (tcp_test_bt_toggle ())
    return 1;
  if (tcp_test_sack_backends ())
    return 1;
  if (tcp_test_bt_scoreboard_random (0, 0x12345678, TCP_TEST_BT_SB_OPEN) ||
      tcp_test_bt_scoreboard_random (0xfffff000, 0x87654321, TCP_TEST_BT_SB_OPEN) ||
      tcp_test_bt_scoreboard_random (0, 0x31415926, TCP_TEST_BT_SB_RECOVERY) ||
      tcp_test_bt_scoreboard_random (0xfffff000, 0x27182818, TCP_TEST_BT_SB_RECOVERY) ||
      tcp_test_bt_scoreboard_random (0, 0x31415926, TCP_TEST_BT_SB_RESCUE))
    return 1;
  if (tcp_test_bt_retransmit_ranges ())
    return 1;
  if (tcp_test_bt_cumulative_ack () || tcp_test_bt_reneging_delivery () ||
      tcp_test_bt_repeat_sack () || tcp_test_bt_sack_bridge () ||
      tcp_test_bt_incremental_sack_loss () || tcp_test_bt_retransmit_range_cache () ||
      tcp_test_bt_retransmit_range_cache_skip_sacked ())
    return 1;
  if (tcp_test_bt_reorder ())
    return 1;
  if (tcp_test_bt_rescue_range () || tcp_test_bt_initial_high_sacked ())
    return 1;
  if (tcp_test_bt_rxt_over_sacked () || tcp_test_bt_rxt_merge_over_sacked () ||
      tcp_test_bt_rxt_merge_loss_boundary () || tcp_test_bt_rxt_across_sacked_island ())
    return 1;
  if (tcp_test_bt_rxt_merge_flags ())
    return 1;
  if (tcp_test_bt_dsack ())
    return 1;

  /* Init data structures */
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;

  /* 1) track first burst at time 1 */
  /* [] --> [0:100] */
  tcp_test_set_time (thread_index, 1);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 1, "should have 1 sample");
  bts = pool_elt_at_index (bt->samples, bt->head);
  head = bt->head;
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->next == TCP_BTS_INVALID_INDEX, "next should be invalid");
  TCP_TEST (bts->prev == TCP_BTS_INVALID_INDEX, "prev should be invalid");
  TCP_TEST (bts->tx_time == 1, "tx time should be 1");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_RXT), "not retransmitted");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");

  /* 2) track second butst at time 2 */
  /* --> [0:100][100:200] */
  tcp_test_set_time (thread_index, 2);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 2, "should have 2 samples");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (head == bt->head, "head is not updated");
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 1, "tx time of head should be 1");

  /* 3) acked partially at time 3 */
  /* ACK:150 */
  /* --> [150:200] */
  tcp_test_set_time (thread_index, 3);
  tc->snd_una = 150;
  rs->bytes_acked = 150;
  rs->last_sacked_bytes = 0;
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 1, "should have 1 sample");
  TCP_TEST (head != bt->head, "head is updated");
  head = bt->head;
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 2, "tx time should be 2");

  /* 4) track another burst at time 4 */
  /* --> [150:200][200:300] */
  tcp_test_set_time (thread_index, 4);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 2, "should have 2 samples");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (head == bt->head, "head is not updated");
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 2, "tx time of head should be 2");

  /* 5) track another burst at time 5 */
  /* --> [150:200][200:300][300:400] */
  tcp_test_set_time (thread_index, 5);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 3, "should have 3 samples");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (head == bt->head, "head is not updated");
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 2, "tx time of head should be 2");

  /*
   * 6) same timestamp tx coalesces with tail
   */
  tcp_bt_cleanup (tc);
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;

  tcp_test_set_time (thread_index, 11);
  tcp_bt_track_tx (tc, 50);
  tc->snd_nxt += 50;
  tcp_bt_track_tx (tc, 75);
  tc->snd_nxt += 75;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after tx merge");
  TCP_TEST (pool_elts (bt->samples) == 1, "same time tx should coalesce");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == 0 && bts->max_seq == 125, "coalesced sample should cover [0:125]");

  tc->app_limited = 1;
  tcp_bt_track_tx (tc, 25);
  tc->snd_nxt += 25;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after app-limited transition");
  TCP_TEST (pool_elts (bt->samples) == 2,
	    "samples with different app-limited state should not coalesce");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (!(bts->flags & TCP_BTS_IS_APP_LIMITED) && bts->min_seq == 0 && bts->max_seq == 125,
	    "first sample should remain non-app-limited [0:125]");
  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST ((bts->flags & TCP_BTS_IS_APP_LIMITED) && bts->min_seq == 125 && bts->max_seq == 150,
	    "second sample should be app-limited [125:150]");

  bt_fmt = format (0, "%U", format_tcp_bt, tc);
  TCP_TEST (vec_len (bt_fmt) > 0, "bt format should produce output");
  vec_free (bt_fmt);

  /*
   * 7) contiguous retransmits extend last out-of-order sample and split tail
   */
  tcp_bt_cleanup (tc);
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;
  memset (rs, 0, sizeof (*rs));

  for (i = 0; i < 3; i++)
    {
      tcp_test_set_time (thread_index, 20 + i);
      tcp_bt_track_tx (tc, 100);
      tc->snd_nxt += 100;
    }

  tcp_test_set_time (thread_index, 30);
  tcp_bt_track_rxt (tc, 0, 100);
  tcp_bt_track_rxt (tc, 100, 200);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after rxt merge");
  TCP_TEST (pool_elts (bt->samples) == 2, "contiguous rxt should merge");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == 0 && bts->max_seq == 200, "merged rxt should cover [0:200]");
  TCP_TEST ((bts->flags & TCP_BTS_IS_RXT), "merged rxt should be marked");

  tcp_bt_track_rxt (tc, 250, 275);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after rxt split");
  TCP_TEST (pool_elts (bt->samples) == 4, "rxt in middle should split sample");
  bts = pool_elt_at_index (bt->samples, bt->head);
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 200 && bts->max_seq == 250, "split head should cover [200:250]");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 250 && bts->max_seq == 275, "split rxt should cover [250:275]");
  TCP_TEST ((bts->flags & TCP_BTS_IS_RXT), "split rxt should be marked");

  tcp_bt_track_rxt (tc, 275, 300);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after tail rxt merge");
  TCP_TEST (pool_elts (bt->samples) == 3, "tail rxt should merge with previous");
  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST (bts->min_seq == 250 && bts->max_seq == 300, "tail rxt merge should cover [250:300]");
  TCP_TEST ((bts->flags & TCP_BTS_IS_RXT), "tail rxt should be marked");

  /*
   * 8) a mid-sample retransmit preserves the original tx metadata on the
   * unretransmitted remainder, and re-retransmitting a retransmit marks it
   * as a lost retransmit.
   */
  vec_free (tc->rcv_opts.sacks);
  tcp_bt_cleanup (tc);
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;
  memset (rs, 0, sizeof (*rs));

  /* One 300-byte burst at time 40, delivered baseline set by the tx. */
  tcp_test_set_time (thread_index, 40);
  tcp_bt_track_tx (tc, 300);
  tc->snd_nxt += 300;
  {
    tcp_bt_sample_t *rem, *mid;

    /* Retransmit the middle [100:200] at time 41, splitting into three. */
    tcp_test_set_time (thread_index, 41);
    tcp_bt_track_rxt (tc, 100, 200);
    TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after mid rxt");
    TCP_TEST (pool_elts (bt->samples) == 3, "mid rxt should split into 3 is %u",
	      pool_elts (bt->samples));

    /* head [0:100] keeps the original tx time */
    bts = pool_elt_at_index (bt->samples, bt->head);
    TCP_TEST (bts->min_seq == 0 && bts->max_seq == 100, "split head [0:100]");
    TCP_TEST (bts->tx_time == 40 && !(bts->flags & TCP_BTS_IS_RXT),
	      "split head keeps original tx time and is not rxt");

    /* middle [100:200] is the retransmit at time 41 */
    mid = pool_elt_at_index (bt->samples, bts->next);
    TCP_TEST (mid->min_seq == 100 && mid->max_seq == 200, "split middle [100:200]");
    TCP_TEST (mid->tx_time == 41 && (mid->flags & TCP_BTS_IS_RXT),
	      "split middle carries the rxt time and rxt flag");
    TCP_TEST (!(mid->flags & TCP_BTS_IS_RXT_LOST), "first rxt of the middle is not yet a lost rxt");

    /* remainder [200:300] must keep the ORIGINAL tx metadata, not the rxt's */
    rem = pool_elt_at_index (bt->samples, mid->next);
    TCP_TEST (rem->min_seq == 200 && rem->max_seq == 300, "split remainder [200:300]");
    TCP_TEST (rem->tx_time == 40 && rem->first_tx_time == mid->first_tx_time,
	      "remainder preserves original tx time %.0f is %.0f", 40.0, rem->tx_time);
    TCP_TEST (!(rem->flags & TCP_BTS_IS_RXT), "remainder is not a retransmit");

    /* Retransmit the middle again at time 42: an already-rxt sample being
     * retransmitted must be flagged as a lost retransmit. */
    tcp_test_set_time (thread_index, 42);
    tcp_bt_track_rxt (tc, 100, 200);
    TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after re-rxt");
    bts = pool_elt_at_index (bt->samples, bt->head);
    mid = pool_elt_at_index (bt->samples, bts->next);
    TCP_TEST (mid->min_seq == 100 && mid->max_seq == 200, "re-rxt middle still [100:200]");
    TCP_TEST (mid->tx_time == 42 && (mid->flags & TCP_BTS_IS_RXT),
	      "re-rxt carries the newer rxt time");
    TCP_TEST ((mid->flags & TCP_BTS_IS_RXT_LOST),
	      "re-retransmitted sample is marked as a lost retransmit");
  }

  /*
   * 9) app-limited detection uses the session tx fifo and in-flight data
   */
  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "tcp-bt-app-limited";
  a->segment_size = 256 << 10;
  a->segment_type = SSVM_SEGMENT_PRIVATE;
  rv = fifo_segment_create (fsm, a);
  TCP_TEST (!rv, "fifo segment create returned %d", rv);
  fs = fifo_segment_get_segment (fsm, a->new_segment_indices[0]);
  TCP_TEST (fs != 0, "fifo segment should be allocated");

  s = session_alloc (thread_index);
  s->tx_fifo = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_TX_FIFO);
  TCP_TEST (s->tx_fifo != 0, "tx fifo should be allocated");
  tc->connection.s_index = s->session_index;
  tc->connection.thread_index = thread_index;
  tc->snd_una = 1000;
  tc->snd_nxt = 1200;
  tc->snd_mss = 100;
  tc->cwnd = 1000;
  tc->delivered = 300;
  tc->snd_rxt_bytes = 0;
  tc->sack_sb.lost_bytes = 0;
  tc->app_limited = 0;

  tcp_bt_check_app_limited (tc);
  TCP_TEST (tc->app_limited == 500, "app limited should include delivered and flight bytes");

  fifo_segment_free_fifo (fs, s->tx_fifo);
  session_free (s);
  vec_free (a->new_segment_indices);
  fifo_segment_delete (fsm, fs);
  tcp_bt_cleanup (tc);

  /* Delivery sampling continues after FIN and excludes the FIN sequence. */
  memset (tc, 0, sizeof (*tc));
  memset (rs, 0, sizeof (*rs));
  tcp_bt_init (tc);
  tcp_test_set_time (thread_index, 50);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt = 101;
  tc->flags |= TCP_CONN_FINSNT;
  tc->snd_una = 100;
  rs->bytes_acked = 100;
  tcp_test_set_time (thread_index, 51);
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tc->delivered == 100 && rs->acked_and_sacked == 100,
	    "data delivery remains sampled after FIN is sent");
  tc->snd_una = 101;
  memset (rs, 0, sizeof (*rs));
  rs->bytes_acked = 1;
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tc->delivered == 100 && rs->acked_and_sacked == 0,
	    "FIN acknowledgment is excluded from delivered bytes");
  tcp_bt_cleanup (tc);

  return 0;
}

static clib_error_t *
tcp_test (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };

  vnet_session_enable_disable (vm, &args);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sack"))
	{
	  res = tcp_test_sack (vm, input);
	}
      else if (unformat (input, "session"))
	{
	  res = tcp_test_session (vm, input);
	}
      else if (unformat (input, "lookup"))
	{
	  res = tcp_test_lookup (vm, input);
	}
      else if (unformat (input, "delivery"))
	{
	  res = tcp_test_delivery (vm, input);
	}
      else if (unformat (input, "persist"))
	{
	  res = tcp_test_persist (vm, input);
	}
      else if (unformat (input, "rto"))
	{
	  res = tcp_test_rto (vm, input);
	}
      else if (unformat (input, "cubic"))
	{
	  res = tcp_test_cubic (vm, input);
	}
      else if (unformat (input, "bt"))
	{
	  res = tcp_test_bt (vm, input);
	}
      else if (unformat (input, "tamper"))
	{
	  res = tcp_test_tamper (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = tcp_test_sack (vm, input)))
	    goto done;
	  if ((res = tcp_test_lookup (vm, input)))
	    goto done;
	  if ((res = tcp_test_delivery (vm, input)))
	    goto done;
	  if ((res = tcp_test_persist (vm, input)))
	    goto done;
	  if ((res = tcp_test_rto (vm, input)))
	    goto done;
	  if ((res = tcp_test_cubic (vm, input)))
	    goto done;
	  if ((res = tcp_test_bt (vm, input)))
	    goto done;
	  if ((res = tcp_test_tamper (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "TCP unit test failed");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (tcp_test_command, static) = {
  .path = "test tcp",
  .short_help = "internal tcp unit tests",
  .function = tcp_test,
};
