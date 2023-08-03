/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

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

/* *INDENT-OFF* */
scoreboard_trace_elt_t sb_trace[] = {};
/* *INDENT-ON* */

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
   * Restart
   */
  scoreboard_clear (sb);
  vec_reset_length (tc->rcv_opts.sacks);

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
  session_lookup_add_connection (tc1, s1->session_handle.as_u64);
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
tcp_test_set_time (u32 thread_index, u32 val)
{
  session_main.wrk[thread_index].last_vlib_time = val;
  tcp_set_time_now (&tcp_main.wrk_ctx[thread_index], val);
}

static int
tcp_test_delivery (vlib_main_t * vm, unformat_input_t * input)
{
  u32 thread_index = 0, snd_una, *min_seqs = 0;
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

  root = bt->sample_lookup.nodes + bt->sample_lookup.root;
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
  u32 thread_index = 0;
  tcp_rate_sample_t _rs = { 0 }, *rs = &_rs;
  tcp_connection_t _tc, *tc = &_tc;
  int __clib_unused verbose = 0, i;
  tcp_byte_tracker_t *bt;
  tcp_bt_sample_t *bts;
  u32 head;
  sack_block_t *blk;

  /* Init data structures */
  memset (tc, 0, sizeof (*tc));
  tcp_bt_init (tc);
  bt = tc->bt;

  /* 1) track first burst at time 1 */
  /* [] --> [0:100] */
  session_main.wrk[thread_index].last_vlib_time = 1;
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
  session_main.wrk[thread_index].last_vlib_time = 2;
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
  session_main.wrk[thread_index].last_vlib_time = 3;
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
  session_main.wrk[thread_index].last_vlib_time = 4;
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
  session_main.wrk[thread_index].last_vlib_time = 5;
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
  session_main.wrk[thread_index].last_vlib_time = 6;
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
  session_main.wrk[thread_index].last_vlib_time = 7;
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
  session_main.wrk[thread_index].last_vlib_time = 8;
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
  session_main.wrk[thread_index].last_vlib_time = 6;
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
  session_main.wrk[thread_index].last_vlib_time = 3;
  tc->snd_una = 500;
  tc->bytes_acked = 100;
  tc->sack_sb.last_sacked_bytes = 0;
  tcp_bt_sample_delivery_rate (tc, rs);

  TCP_TEST (tcp_bt_is_sane (bt), "tracker should be sane");
  TCP_TEST (pool_elts (bt->samples) == 0, "should have 0 samples");
  TCP_TEST (bt->head == TCP_BTS_INVALID_INDEX, "bt->head is invalidated");
  TCP_TEST (tc->snd_una == tc->snd_nxt, "snd_una == snd_nxt");

  return 0;
}

static clib_error_t *
tcp_test (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  vnet_session_enable_disable (vm, 1);

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
      else if (unformat (input, "bt"))
	{
	  res = tcp_test_bt (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = tcp_test_sack (vm, input)))
	    goto done;
	  if ((res = tcp_test_lookup (vm, input)))
	    goto done;
	  if ((res = tcp_test_delivery (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "TCP unit test failed");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_test_command, static) =
{
  .path = "test tcp",
  .short_help = "internal tcp unit tests",
  .function = tcp_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
