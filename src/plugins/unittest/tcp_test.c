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
tcp_test_sack_reordering (void)
{
  tcp_connection_t _tc, *tc = &_tc;
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
      scoreboard_init (sb);
      sb->reorder = t->initial_reorder;
      sb->rescue_rxt = tc->snd_una - 1;

      if (t->mode != TCP_TEST_REORDER_OOO)
	tc->flags = TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY;
      if (t->mode == TCP_TEST_REORDER_RECOVERY)
	sb->high_rxt = t->delayed_start;
      else if (t->mode == TCP_TEST_REORDER_RXT)
	sb->high_rxt = t->delayed_end;
      else if (t->mode == TCP_TEST_REORDER_RESCUE)
	{
	  tc->snd_congestion = tc->snd_nxt;
	  sb->rescue_rxt = tc->snd_congestion;
	}

      block.start = t->frontier_start;
      block.end = tc->snd_nxt;
      vec_add1 (tc->rcv_opts.sacks, block);
      tc->rcv_opts.n_sack_blocks = 1;
      tcp_rcv_sacks (tc, tc->snd_una);
      ok = TCP_TEST_I ((sb->reorder == t->initial_reorder),
		       "sack reorder %s: frontier keeps %u, got %u", t->name, t->initial_reorder,
		       sb->reorder);

      if (ok)
	{
	  vec_reset_length (tc->rcv_opts.sacks);
	  block.start = t->delayed_start;
	  block.end = t->delayed_end;
	  vec_add1 (tc->rcv_opts.sacks, block);
	  tcp_rcv_sacks (tc, tc->snd_una);
	  ok = TCP_TEST_I ((sb->reorder == t->expected_reorder),
			   "sack reorder %s: expected %u, got %u", t->name, t->expected_reorder,
			   sb->reorder);
	}

      scoreboard_clear (sb);
      pool_free (sb->holes);
      vec_free (tc->rcv_opts.sacks);
      if (!ok)
	return 1;
    }

  return 0;
}

/* Drive one out-of-order reorder observation and return the learned estimate.
 * Establishes the sack frontier at snd_nxt, then sacks a single delayed mss
 * whose start is 'distance' bytes below the frontier. */
static u32
tcp_test_reorder_observe (tcp_connection_t *tc, u16 mss, u32 snd_nxt, u32 distance,
			  u32 initial_reorder)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t block;
  u32 reorder;

  clib_memset (tc, 0, sizeof (*tc));
  tc->snd_nxt = snd_nxt;
  tc->snd_mss = mss;
  tc->rcv_opts.flags = TCP_OPTS_FLAG_SACK;
  scoreboard_init (sb);
  sb->reorder = initial_reorder;
  sb->rescue_rxt = tc->snd_una - 1;

  /* Establish the frontier at snd_nxt. */
  block.start = snd_nxt - mss;
  block.end = snd_nxt;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_rcv_sacks (tc, tc->snd_una);

  /* Sack a delayed segment 'distance' bytes below the frontier. */
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = snd_nxt - distance;
  block.end = block.start + mss;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = 1;
  tcp_rcv_sacks (tc, tc->snd_una);

  reorder = sb->reorder;

  scoreboard_clear (sb);
  pool_free (sb->holes);
  vec_free (tc->rcv_opts.sacks);
  return reorder;
}

/* The reorder estimate must equal ceil(reordering_distance / mss) exactly,
 * neither under- nor over-estimating, and must track the maximum observed
 * distance rather than summing successive observations. */
static int
tcp_test_sack_reorder_accuracy (void)
{
  tcp_connection_t _tc, *tc = &_tc;
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
	  u32 got = tcp_test_reorder_observe (tc, mss, snd_nxt, distance, TCP_DUPACK_THRESHOLD);

	  ok = TCP_TEST_I ((got == expected),
			   "reorder accuracy: distance %u (mss %u) expected %u, got %u", distance,
			   mss, expected, got);
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
	u32 got = tcp_test_reorder_observe (tc, mss, snd_nxt, distance, TCP_DUPACK_THRESHOLD);

	ok = TCP_TEST_I ((got == TCP_DUPACK_THRESHOLD),
			 "reorder floor: distance %u clamps to %u, got %u", distance,
			 TCP_DUPACK_THRESHOLD, got);
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
    scoreboard_init (sb);
    sb->rescue_rxt = tc->snd_una - 1;

    block.start = snd_nxt - mss;
    block.end = snd_nxt;
    vec_add1 (tc->rcv_opts.sacks, block);
    tc->rcv_opts.n_sack_blocks = 1;
    tcp_rcv_sacks (tc, tc->snd_una);

    /* Large reorder first. */
    vec_reset_length (tc->rcv_opts.sacks);
    block.start = snd_nxt - big * mss;
    block.end = block.start + mss;
    vec_add1 (tc->rcv_opts.sacks, block);
    tc->rcv_opts.n_sack_blocks = 1;
    tcp_rcv_sacks (tc, tc->snd_una);
    ok = TCP_TEST_I ((sb->reorder == big), "reorder max: large observation sets %u, got %u", big,
		     sb->reorder);

    /* Smaller reorder after: must stay at big, not drop to small, not sum. */
    if (ok)
      {
	vec_reset_length (tc->rcv_opts.sacks);
	block.start = snd_nxt - small * mss;
	block.end = block.start + mss;
	vec_add1 (tc->rcv_opts.sacks, block);
	tc->rcv_opts.n_sack_blocks = 1;
	tcp_rcv_sacks (tc, tc->snd_una);
	ok = TCP_TEST_I ((sb->reorder == big), "reorder max: smaller observation keeps %u, got %u",
			 big, sb->reorder);
      }

    scoreboard_clear (sb);
    pool_free (sb->holes);
    vec_free (tc->rcv_opts.sacks);
    if (!ok)
      return 1;

    /* Reverse order grows the estimate to the larger observation. */
    got = tcp_test_reorder_observe (tc, mss, snd_nxt, big * mss, small);
    ok = TCP_TEST_I ((got == big), "reorder max: grows past a smaller prior estimate to %u, got %u",
		     big, got);
    if (!ok)
      return 1;
  }

  return 0;
}

static int
tcp_test_sack_rx (vlib_main_t * vm, unformat_input_t * input)
{
  tcp_connection_t _tc, *tc = &_tc;
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

  if (tcp_test_sack_reordering ())
    return 1;

  if (tcp_test_sack_reorder_accuracy ())
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
  tcp_rcv_sacks (tc, 0);

  if (verbose)
    vlib_cli_output (vm, "sb after even blocks (mss %u):\n%U",
		     tc->snd_mss, format_tcp_scoreboard, sb, tc);

  TCP_TEST ((pool_elts (sb->holes) == 5),
	    "scoreboard has %d elements", pool_elts (sb->holes));

  /* First SACK block should be rejected */
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 0 && hole->end == 200),
	    "first hole start %u end %u", hole->start, hole->end);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->start == 900 && hole->end == 1000),
	    "last hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 400), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->last_sacked_bytes == 400),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->high_sacked == 900), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);

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
  tcp_rcv_sacks (tc, 0);

  if (verbose)
    vlib_cli_output (vm, "\nsb after odd blocks:\n%U", format_tcp_scoreboard,
		     sb, tc);

  hole = scoreboard_first_hole (sb);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  TCP_TEST ((hole->start == 0 && hole->end == 100),
	    "first hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 800), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->high_sacked == 900), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->last_sacked_bytes == 400),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);

  /*
   *  Ack until byte 100 - this is reneging because we should ack until 900
   */
  tcp_rcv_sacks (tc, 100);
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

  tcp_rcv_sacks (tc, 100);
  TCP_TEST ((pool_elts (sb->holes) == 1), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->last_sacked_bytes == 50), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->rxt_sacked == 50), "last rxt sacked bytes %d",
	    sb->rxt_sacked);

  /*
   * Sack all up to 950
   */
  tcp_rcv_sacks (tc, 950);
  TCP_TEST ((sb->high_sacked == 950), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);
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

  tcp_rcv_sacks (tc, 950);
  TCP_TEST ((sb->high_sacked == 990), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 20), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 20),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->rxt_sacked == 15), "last rxt sacked bytes %d",
	    sb->rxt_sacked);

  /*
   * Ack up to 960 (reneging) + [961 971]
   */
  tc->rcv_opts.sacks[0].start = 961;
  tc->rcv_opts.sacks[0].end = 971;

  tcp_rcv_sacks (tc, 960);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 21), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 1),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->rxt_sacked == 11), "last rxt sacked bytes %d",
	    sb->rxt_sacked);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);

  /*
   * Ack up to 960 (reneging) + [961 990]
   */
  tc->snd_una = 960;
  tc->rcv_opts.sacks[0].start = 961;
  tc->rcv_opts.sacks[0].end = 990;

  tcp_rcv_sacks (tc, 960);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 30), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 9),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->rxt_sacked == 9), "last rxt sacked bytes %d",
	    sb->rxt_sacked);

  /*
   * Sack remaining bytes [990 1000]
   */
  tc->rcv_opts.sacks[0].start = 990;
  tc->rcv_opts.sacks[0].end = 1000;

  tcp_rcv_sacks (tc, 960);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 40), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 10),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->rxt_sacked == 0), "last rxt sacked bytes %d",
	    sb->rxt_sacked);
  TCP_TEST (pool_elts (sb->holes) == 0, "no holes left");

  /*
   * Ack up to 970 no sack blocks
   */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->rcv_opts.flags &= ~TCP_OPTS_FLAG_SACK;
  tcp_rcv_sacks (tc, 970);

  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 30), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->rxt_sacked == 0), "last rxt sacked bytes %d",
	    sb->rxt_sacked);

  /*
   * Ack all up to 1000
   */
  tc->snd_una = 970;
  tcp_rcv_sacks (tc, 1000);
  TCP_TEST ((sb->high_sacked == 1000), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST (sb->last_bytes_delivered == 30, "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);
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
  tcp_rcv_sacks (tc, 1000);

  if (verbose)
    vlib_cli_output (vm, "\nadd [1200, 1300] snd_una_max 1500, snd_una 1000:"
		     " \n%U", format_tcp_scoreboard, sb, tc);

  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 1000 && hole->end == 1200),
	    "first hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->high_sacked == 1300), "max sacked byte %u", sb->high_sacked);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->start == 1300 && hole->end == 1500),
	    "last hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 100), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);

  /*
   * Ack first hole
   */

  vec_reset_length (tc->rcv_opts.sacks);
  /* Ack up to 1300 to avoid reneging */
  tcp_rcv_sacks (tc, 1300);

  if (verbose)
    vlib_cli_output (vm, "\nsb ack up to byte 1300:\n%U",
		     format_tcp_scoreboard, sb, tc);

  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->last_bytes_delivered == 100), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->head != TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail != TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Add some more blocks and then remove all
   */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->snd_una = 1300;
  tc->snd_nxt = 1900;
  for (i = 0; i < 5; i++)
    {
      block.start = i * 100 + 1200;
      block.end = (i + 1) * 100 + 1200;
      vec_add1 (tc->rcv_opts.sacks, block);
    }
  tcp_rcv_sacks (tc, 1900);

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
  tcp_rcv_sacks (tc, 0);
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
  tcp_rcv_sacks (tc, 950);

  if (verbose)
    vlib_cli_output (vm, "\nack [0, 950]:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 0), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->sacked_bytes == 50), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
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

  tcp_rcv_sacks (tc, 0);

  if (verbose)
    vlib_cli_output (vm, "\nsb added [100, 500] snd_una 0 snd_una_max 1000:"
		     "\n%U", format_tcp_scoreboard, sb, tc);

  tcp_rcv_sacks (tc, 800);

  if (verbose)
    vlib_cli_output (vm, "\nsb ack [0, 800]:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((!sb->is_reneging), "is not reneging");
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 400),
	    "last bytes delivered %d", sb->last_bytes_delivered);
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

  tcp_rcv_sacks (tc, 0);
  if (verbose)
    vlib_cli_output (vm, "\nsb added [500, 1000]:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((sb->sacked_bytes == 500), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 500), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 500), "lost bytes %u", sb->lost_bytes);

  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 400;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 100);
  if (verbose)
    vlib_cli_output (vm, "\nsb added [0, 100] [300, 400]:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 100), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  /* Hole should be split in 2 lost holes that add up to 300 */
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->reorder == 7), "reorder %u", sb->reorder);

  /*
   * Ack [100 300] in two steps
   *
   * Step 1. Ack [100 200] which delivers 100 of the bytes lost
   */
  tc->snd_una = 100;
  tcp_rcv_sacks (tc, 200);
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 200), "lost bytes %u", sb->lost_bytes);

  /*
   * Step 2. Ack up to 300, although 300 400 is sacked, so this is interpreted
   * as reneging.
   */
  tc->snd_una = 200;
  tcp_rcv_sacks (tc, 300);
  if (verbose)
    vlib_cli_output (vm, "\nacked [100, 300] in two steps:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((sb->sacked_bytes == 600), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->is_reneging), "is reneging");

  /*
   * Ack [300 500]. Delivers reneged segment [300 400] and reneges bytes
   * above 500
   */
  tc->snd_una = 300;
  tcp_rcv_sacks (tc, 500);
  if (verbose)
    vlib_cli_output (vm, "\nacked [400, 500]:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 500), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 100), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->is_reneging), "is reneging");
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * Ack up to 1000 to deliver all bytes
   */
  tc->snd_una = 500;
  tcp_rcv_sacks (tc, 1000);
  if (verbose)
    vlib_cli_output (vm, "\nAck high sacked:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 500), "last bytes delivered %d",
	    sb->last_bytes_delivered);
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
  tcp_rcv_sacks (tc, 1000);
  if (verbose)
    vlib_cli_output (vm, "\nacked [1200, 1500] test first hole is lost:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 2), "scoreboard has %d elements",
	    pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 300), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 300), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);
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

  tcp_rcv_sacks (tc, 0);

  TCP_TEST ((sb->sacked_bytes == 400), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 400), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((!sb->is_reneging), "is not reneging");

  /*
   * Renege, sack all of the remaining bytes and cover some rxt bytes
   */
  sb->high_rxt = 700;
  tc->rcv_opts.sacks[0].start = 500;
  tc->rcv_opts.sacks[0].end = 1000;

  tcp_rcv_sacks (tc, 100);

  TCP_TEST ((sb->sacked_bytes == 900), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 500), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST (sb->is_reneging, "is reneging");
  TCP_TEST ((sb->rxt_sacked == 300), "last rxt sacked bytes %d",
	    sb->rxt_sacked);

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
  tcp_rcv_sacks (tc, 0);
  TCP_TEST ((sb->high_sacked == 3000), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder still floor %u", sb->reorder);

  /* A never-retransmitted low block arrives out of order below the frontier:
   * reord = ceil((3000 - 300) / 150) = 18 */
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 0);
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
  tcp_rcv_sacks (tc, 0);
  TCP_TEST ((sb->reorder == TCP_DUPACK_THRESHOLD), "reorder floor %u", sb->reorder);

  /* Everything below the frontier has now been retransmitted */
  sb->high_rxt = 2400;
  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 0);
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
  tcp_rcv_sacks (tc, 0);
  TCP_TEST ((sb->high_sacked == 3000), "high sacked %u", sb->high_sacked);

  vec_reset_length (tc->rcv_opts.sacks);
  block.start = 300;
  block.end = 450;
  vec_add1 (tc->rcv_opts.sacks, block);
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 0);
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

  tcp_rcv_sacks (tc, tc->snd_una);

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

  tcp_rcv_sacks (tc, tc->snd_una);

  TCP_TEST ((sb->high_sacked == 102700), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 67400), "sacked bytes %u", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 400), "last sacked bytes %u", sb->last_sacked_bytes);
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
  scoreboard_rxt_mark_lost (sb, tc->snd_una, tc->snd_nxt);
  TCP_TEST ((sb->lost_bytes == 1000), "rto marks bytes lost %u", sb->lost_bytes);

  scoreboard_recompute_sack_loss (sb, tc->snd_una, tc->snd_mss);
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
  tcp_rcv_sacks (tc, tc->snd_una);
  TCP_TEST ((sb->lost_bytes == 300), "SACK marks bytes lost %u", sb->lost_bytes);

  scoreboard_recompute_sack_loss (sb, tc->snd_una, tc->snd_mss);
  TCP_TEST ((sb->lost_bytes == 300), "SACK-derived loss preserved %u", sb->lost_bytes);

  /* A clean scoreboard does not track cumulative ACK progress. Recovery undo
   * may reclassify loss after snd_una advances, so a stale high_sacked below
   * the ACK must still describe zero SACKed bytes. */
  scoreboard_clear (sb);
  sb->high_sacked = tc->snd_una;
  tc->snd_una += tc->snd_mss;
  scoreboard_recompute_sack_loss (sb, tc->snd_una, tc->snd_mss);
  TCP_TEST ((sb->sacked_bytes == 0), "empty scoreboard has no sacked bytes %u", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "empty scoreboard has no lost bytes %u", sb->lost_bytes);

  /*
   * Clear
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);

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
  tcp_rate_sample_t rs = { .acked_and_sacked = tc->snd_mss };
  u32 i;

  for (i = 0; i < n_acks; i++)
    {
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
  int error, rv = 0, routes_added = 0, ns_added = 0;

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
  client_tc->cfg_flags &= ~TCP_CFG_F_RATE_SAMPLE;
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
  if (accepted_session_index != ~0)
    {
      vnet_disconnect_args_t disconnect_args = {
	.handle = session_make_handle (accepted_session_index, accepted_session_thread),
	.app_index = server_index,
      };
      (void) vnet_disconnect_session (&disconnect_args);
    }
  else if (connected_session_index != ~0)
    {
      vnet_disconnect_args_t disconnect_args = {
	.handle = session_make_handle (connected_session_index, connected_session_thread),
	.app_index = client_index,
      };
      (void) vnet_disconnect_session (&disconnect_args);
    }

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
  for (int j = 0; j < 5; j++)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 1e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  for (int j = 0; j < 2; j++)
    if (sw_if_index[j] != ~0)
      (void) vnet_delete_loopback_interface (sw_if_index[j]);

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
  u32 first_tr_occurences;
  u32 first_rto_boff;
  u32 cwnd_after_first;
  u32 flight_after_first;
  u32 cc_space_after_first;
  u32 snd_rxt_after_first;
  u32 rxt_delivered_after_first;
  u32 prev_cwnd_after_first;
  u32 ssthresh_after_first;
  u8 second_still_in_recovery;
  u32 cwnd_after_second;
  u32 flight_after_second;
  u32 cc_space_after_second;
  u32 snd_rxt_after_second;
  u32 rxt_delivered_after_second;
  u32 second_ssthresh;
  u32 second_prev_cwnd;
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
  scoreboard_init_rxt (&tc->sack_sb, tc->snd_una);
  tc->snd_rxt_bytes = 0;
  tc->rxt_delivered = 0;
  tc->tr_occurences = 0;
  tc->rto_boff = 0;
  a->mss = tc->snd_mss;
  tcp_timer_retransmit_handler (tc);

  a->first_in_recovery = tcp_in_recovery (tc);
  a->first_tr_occurences = tc->tr_occurences;
  a->first_rto_boff = tc->rto_boff;
  a->cwnd_after_first = tc->cwnd;
  a->flight_after_first = tcp_flight_size (tc);
  a->cc_space_after_first = tcp_available_cc_snd_space (tc);
  a->snd_rxt_after_first = tc->snd_rxt_bytes;
  a->rxt_delivered_after_first = tc->rxt_delivered;
  a->prev_cwnd_after_first = tc->prev_cwnd;
  a->ssthresh_after_first = tc->ssthresh;

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
  int error, rv = 0, routes_added = 0, ns_added = 0;

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
    u32 mss = 1460;

#define ARM_SPURIOUS()                                                                             \
  do                                                                                               \
    {                                                                                              \
      clib_memset (stc, 0, sizeof (*stc));                                                         \
      stc->snd_mss = mss;                                                                          \
      stc->flags |= TCP_CONN_FAST_RECOVERY;                                                        \
      stc->bytes_acked = 2 * mss;                                                                  \
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
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: spurious on partial cumulative ack, tsecr < snd_rxt_ts, "
		     "no loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Also valid for rto recovery (TCP_CONN_RECOVERY), not just fast recovery. */
    ARM_SPURIOUS ();
    stc->flags = TCP_CONN_RECOVERY;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc)), "eifel: also fires for rto recovery"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Detection is independent of other outstanding loss. Rto recovery may
     * carry speculative loss marks. */
    ARM_SPURIOUS ();
    stc->flags = TCP_CONN_RECOVERY;
    stc->sack_sb.lost_bytes = mss;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: rto retransmit spurious despite outstanding loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: no retransmit stamped (snd_rxt_ts == 0), nothing to undo. */
    ARM_SPURIOUS ();
    stc->snd_rxt_ts = 0;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: not spurious without a retransmit timestamp"))
      {
	rv = 1;
	goto cleanup;
      }

    /* The initiating fast retransmit can be spurious while another SACK-derived
     * loss remains outstanding. The response handles that as a fresh event. */
    ARM_SPURIOUS ();
    stc->sack_sb.lost_bytes = mss;
    if (!TCP_TEST_I ((tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: fast retransmit spurious despite other outstanding loss"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: full-flight ack (snd_una reached snd_congestion). Ambiguous per
     * RFC 3522 Sec. 3.2 (e.g. rto from losing all acks) -> keep the reduction. */
    ARM_SPURIOUS ();
    stc->snd_una = stc->snd_congestion;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: not spurious on a full-flight ack"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: echoed tsecr not older than snd_rxt_ts (ack post-dates the
     * retransmit -> the retransmit was needed). */
    ARM_SPURIOUS ();
    stc->rcv_opts.tsecr = stc->snd_rxt_ts;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc)),
		     "eifel: not spurious when tsecr >= snd_rxt_ts"))
      {
	rv = 1;
	goto cleanup;
      }

    /* Negative: no timestamp option -> Eifel not applicable. */
    ARM_SPURIOUS ();
    stc->rcv_opts.flags = 0;
    if (!TCP_TEST_I ((!tcp_cc_is_spurious_retransmit (stc)),
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
  if (accepted_session_index != ~0)
    {
      vnet_disconnect_args_t disconnect_args = {
	.handle = session_make_handle (accepted_session_index, accepted_session_thread),
	.app_index = server_index,
      };
      (void) vnet_disconnect_session (&disconnect_args);
    }
  else if (connected_session_index != ~0)
    {
      vnet_disconnect_args_t disconnect_args = {
	.handle = session_make_handle (connected_session_index, connected_session_thread),
	.app_index = client_index,
      };
      (void) vnet_disconnect_session (&disconnect_args);
    }

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
  for (int j = 0; j < 5; j++)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 1e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  for (int j = 0; j < 2; j++)
    if (sw_if_index[j] != ~0)
      (void) vnet_delete_loopback_interface (sw_if_index[j]);

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
tcp_test_tamper_queued_data_loss (vlib_main_t *vm)
{
  tcp_e2e_params_t params = {
    .name = "queued_dl",
    .client_addr = 0x16161601,
    .server_addr = 0x17171701,
    .client_vrf = 0,
    .server_vrf = 2,
    .server_port = 2251,
    .client_port = 0, /* ephemeral */
    .secret = 2250,
    /* Bound the peer window to keep the FIN pending during recovery. */
    .rx_fifo_size = 4 << 10,
    .tx_fifo_size = 128 << 10,
  };
  tcp_e2e_ctx_t _ctx, *ctx = &_ctx;
  tcp_connection_t *client_tc;
  tcp_tamper_rule_t *seg_rule;
  session_t *client_s, *server_s;
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
    { "recov-pt", tcp_test_tamper_recovery_point },
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
  sack_scoreboard_t *sb = &tc->sack_sb;
  int __clib_unused verbose = 0, i;
  u64 rate = 1000, burst = 100;
  sack_block_t *sacks = 0;
  tcp_byte_tracker_t *bt;
  rb_node_t *root, *rbn;
  tcp_bt_sample_t *bts;

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
  tcp_test_set_time (thread_index, 1);
  transport_connection_tx_pacer_update (&tc->connection, rate, 1e6);

  tcp_bt_init (tc);
  bt = tc->bt;

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
  tc->bytes_acked = burst;

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
  tc->bytes_acked = 2 * burst;

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
  tc->snd_una += 10;
  tc->bytes_acked = 10;
  sb->last_sacked_bytes = 20;

  TCP_TEST (pool_elts (bt->samples) == 4, "there should be 4 samples");

  vec_validate (sacks, 1);
  sacks[0].start = snd_una + burst;
  sacks[0].end = snd_una + burst + 10;
  sacks[1].start = snd_una + 2 * burst + 10;
  sacks[1].end = snd_una + 2 * burst + 20;
  tc->rcv_opts.sacks = sacks;

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
  tc->snd_una = snd_una + 2 * burst;
  tc->bytes_acked = 2 * burst - 10;
  sb->last_sacked_bytes = 20;

  sacks[0].start = snd_una + 2 * burst + 20;
  sacks[0].end = snd_una + 2 * burst + 30;
  sacks[1].start = snd_una + 2 * burst + 50;
  sacks[1].end = snd_una + 2 * burst + 60;

  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 5, "num samples should be 5 is %u",
	    pool_elts (bt->samples));
  TCP_TEST (tc->delivered_time == 10, "delivered time should be 10");
  TCP_TEST (tc->delivered == 5 * burst + 40, "delivered should be %u is %u",
	    5 * burst + 40, tc->delivered);
  /* A rxt was acked and delivered time for it is 8 (last ack time) so
   * ack_time is 2 (8 - 10). However, first_tx_time for rxt was 4 and rxt
   * time 9. Therefore snd_time is 5 (9 - 4)*/
  TCP_TEST (rs->interval_time == 5, "ack time should be 5 is %.2f",
	    rs->interval_time);
  /* delivered_now - delivered_rxt ~ 5 * burst + 40 - 3 * burst - 30 */
  TCP_TEST (rs->delivered == 2 * burst + 10, "delivered should be 210 is %u",
	    rs->delivered);
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
  tc->snd_una = tc->snd_nxt;
  tc->bytes_acked = 2 * burst;
  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 40;

  memset (rs, 0, sizeof (*rs));
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "num samples should be 0 is %u",
	    pool_elts (bt->samples));
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
  TCP_TEST (rs->delivered == 4 * burst - 30, "delivered should be 160 is %u",
	    rs->delivered);
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

  /*
   * Cleanup
   */
  vec_free (sacks);
  vec_free (min_seqs);
  tcp_bt_cleanup (tc);
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
  sack_block_t *blk;

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
  tc->bytes_acked = 150;
  tc->sack_sb.last_sacked_bytes = 0;
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

  /* 6) acked with SACK option at time 6 */
  /* ACK:250 + SACK[350:400] */
  /* --> [250:300][300:350][350:400/sacked] */
  tcp_test_set_time (thread_index, 6);
  tc->snd_una = 250;
  tc->bytes_acked = 100;
  tc->sack_sb.last_sacked_bytes = 50;
  vec_add2 (tc->rcv_opts.sacks, blk, 1);
  blk->start = 350;
  blk->end = 400;
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 3, "should have 3 samples");
  TCP_TEST (head != bt->head, "head is updated");
  head = bt->head;
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 4, "tx time of head should be 4");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->tx_time == 5, "tx time of next should be 5");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST (bts->tx_time == 5, "tx time of tail should be 5");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "sacked");

  /* 7) track another burst at time 7 */
  /* --> [250:300][300:350][350:400/sacked][400-500] */
  tcp_test_set_time (thread_index, 7);
  tcp_bt_track_tx (tc, 100);
  tc->snd_nxt += 100;

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 4, "should have 4 samples");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (head == bt->head, "head is not updated");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 4, "tx time of head should be 4");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->tx_time == 5, "tx time of next should be 5");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->tx_time == 5, "tx time of next should be 5");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "sacked");
  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST (bts->tx_time == 7, "tx time of tail should be 7");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");

  /* 8) retransmit lost one at time 8 */
  /* retransmit [250:300] */
  /* --> [250:300][300:350][350:400/sacked][400-500] */
  tcp_test_set_time (thread_index, 8);
  tcp_bt_track_rxt (tc, 250, 300);
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 4, "should have 4 samples");
  TCP_TEST (head == bt->head, "head is not updated");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->tx_time == 8, "tx time of head should be 8");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->tx_time == 5, "tx time of next should be 5");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->tx_time == 5, "tx time of next should be 5");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "sacked");
  bts = pool_elt_at_index (bt->samples, bt->tail);
  TCP_TEST (bts->tx_time == 7, "tx time of tail should be 7");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");

  /* 9) acked with SACK option at time 9 */
  /* ACK:350 + SACK[420:450] */
  /* --> [400:420][420:450/sacked][450:400] */
  tcp_test_set_time (thread_index, 9);
  tc->snd_una = 400;
  tc->bytes_acked = 150;
  tc->sack_sb.last_sacked_bytes = 30;
  vec_add2 (tc->rcv_opts.sacks, blk, 1);
  blk->start = 420;
  blk->end = 450;
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 3, "should have 3 samples");
  TCP_TEST (head != bt->head, "head is updated");
  head = bt->head;
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == tc->snd_una, "min seq should be snd_una");
  TCP_TEST (bts->min_seq == 400 && bts->max_seq == 420, "bts [400:420]");
  TCP_TEST (bts->tx_time == 7, "tx time of head should be 7");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 420 && bts->max_seq == 450, "bts [420:450]");
  TCP_TEST (bts->tx_time == 7, "tx time of head should be 7");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "sacked");
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 450 && bts->max_seq == 500, "bts [450:500]");
  TCP_TEST (bts->tx_time == 7, "tx time of head should be 7");
  TCP_TEST (!(bts->flags & TCP_BTS_IS_SACKED), "not sacked");

  /* 10) acked partially at time 10 */
  /* ACK:500 */
  /* --> [] */
  tcp_test_set_time (thread_index, 10);
  tc->snd_una = 500;
  tc->bytes_acked = 100;
  tc->sack_sb.last_sacked_bytes = 0;
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "should have 0 samples");
  TCP_TEST (bt->head == TCP_BTS_INVALID_INDEX, "bt->head is invalidated");
  TCP_TEST (tc->snd_una == tc->snd_nxt, "snd_una == snd_nxt");

  /*
   * 11) same timestamp tx coalesces with tail
   */
  vec_free (tc->rcv_opts.sacks);
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

  bt_fmt = format (0, "%U", format_tcp_bt, tc);
  TCP_TEST (vec_len (bt_fmt) > 0, "bt format should produce output");
  vec_free (bt_fmt);

  /*
   * 12) adjacent SACKed samples merge with previous and next samples
   */
  tcp_bt_cleanup (tc);
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;
  memset (rs, 0, sizeof (*rs));

  for (i = 0; i < 3; i++)
    {
      tcp_test_set_time (thread_index, 12 + i);
      tcp_bt_track_tx (tc, 100);
      tc->snd_nxt += 100;
    }

  vec_validate (tc->rcv_opts.sacks, 0);
  tc->sack_sb.last_sacked_bytes = 100;
  tc->rcv_opts.sacks[0].start = 100;
  tc->rcv_opts.sacks[0].end = 200;
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after first sack");
  TCP_TEST (pool_elts (bt->samples) == 3, "first sack should not merge");

  tc->sack_sb.last_sacked_bytes = 100;
  tc->rcv_opts.sacks[0].start = 200;
  tc->rcv_opts.sacks[0].end = 300;
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after merge with prev");
  TCP_TEST (pool_elts (bt->samples) == 2, "adjacent sack should merge with previous");
  bts = pool_elt_at_index (bt->samples, bt->head);
  bts = pool_elt_at_index (bt->samples, bts->next);
  TCP_TEST (bts->min_seq == 100 && bts->max_seq == 300,
	    "merged previous sack should cover [100:300]");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "merged previous sack should be marked");

  tc->sack_sb.last_sacked_bytes = 100;
  tc->rcv_opts.sacks[0].start = 0;
  tc->rcv_opts.sacks[0].end = 100;
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane after merge with next");
  TCP_TEST (pool_elts (bt->samples) == 1, "adjacent sack should merge with next");
  bts = pool_elt_at_index (bt->samples, bt->head);
  TCP_TEST (bts->min_seq == 0 && bts->max_seq == 300, "merged sacks should cover [0:300]");
  TCP_TEST ((bts->flags & TCP_BTS_IS_SACKED), "merged sacks should be marked");

  /*
   * 13) contiguous retransmits extend last out-of-order sample and split tail
   */
  vec_free (tc->rcv_opts.sacks);
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
   * 15) a mid-sample retransmit preserves the original tx metadata on the
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
   * 14) app-limited detection uses the session tx fifo and in-flight data
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
  tc->bytes_acked = 100;
  tcp_test_set_time (thread_index, 51);
  tcp_bt_sample_delivery_rate (tc, rs);
  TCP_TEST (tc->delivered == 100 && rs->acked_and_sacked == 100,
	    "data delivery remains sampled after FIN is sent");
  tc->snd_una = 101;
  tc->bytes_acked = 1;
  memset (rs, 0, sizeof (*rs));
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
