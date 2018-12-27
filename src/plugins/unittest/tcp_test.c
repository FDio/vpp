/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

  tc->snd_una = 0;
  tc->snd_una_max = 1000;
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
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->last_sacked_bytes == 400),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->high_sacked == 900), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);

  /*
   * Inject odd blocks
   */

  vec_reset_length (tc->rcv_opts.sacks);
  for (i = 0; i < 1000 / 200; i++)
    {
      vec_add1 (tc->rcv_opts.sacks, sacks[i * 2 + 1]);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 0);

  if (verbose)
    vlib_cli_output (vm, "\nsb after odd blocks:\n%U", format_tcp_scoreboard,
		     sb, tc);

  hole = scoreboard_first_hole (sb);
  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  TCP_TEST ((hole->start == 0 && hole->end == 100),
	    "first hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 900), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->high_sacked == 1000), "high sacked %u", sb->high_sacked);
  TCP_TEST ((sb->last_sacked_bytes == 500),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);

  /*
   *  Ack until byte 100, all bytes are now acked + sacked
   */
  tcp_rcv_sacks (tc, 100);
  if (verbose)
    vlib_cli_output (vm, "\nack until byte 100:\n%U", format_tcp_scoreboard,
		     sb, tc);

  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->snd_una_adv == 900),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((sb->high_sacked == 1000), "max sacked byte %u", sb->high_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);

  /*
   * Add new block
   */

  vec_reset_length (tc->rcv_opts.sacks);

  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->rcv_opts.sacks, block);

  tc->snd_una_max = 1500;
  tc->snd_una = 1000;
  tc->snd_nxt = 1500;
  tcp_rcv_sacks (tc, 1000);

  if (verbose)
    vlib_cli_output (vm, "\nadd [1200, 1300] snd_una_max 1500, snd_una 1000:"
		     " \n%U", format_tcp_scoreboard, sb, tc);

  TCP_TEST ((sb->snd_una_adv == 0),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 1000 && hole->end == 1200),
	    "first hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->snd_una_adv == 0),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
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
  tcp_rcv_sacks (tc, 1200);

  if (verbose)
    vlib_cli_output (vm, "\nsb ack up to byte 1200:\n%U",
		     format_tcp_scoreboard, sb, tc);

  TCP_TEST ((sb->snd_una_adv == 100),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->last_bytes_delivered == 100), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * Add some more blocks and then remove all
   */
  vec_reset_length (tc->rcv_opts.sacks);
  tc->snd_una += sb->snd_una_adv;
  tc->snd_una_max = 1900;
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
  tc->snd_una_max = 1000;
  tc->snd_nxt = 1000;
  for (i = 0; i < 5; i++)
    {
      vec_add1 (tc->rcv_opts.sacks, sacks[i * 2 + 1]);
    }
  tc->rcv_opts.n_sack_blocks = vec_len (tc->rcv_opts.sacks);
  tcp_rcv_sacks (tc, 0);
  if (verbose)
    vlib_cli_output (vm, "\nsb added odd blocks snd_una 0 snd_una_max 1500:"
		     "\n%U", format_tcp_scoreboard, sb, tc);
  TCP_TEST ((pool_elts (sb->holes) == 5),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);

  tcp_rcv_sacks (tc, 950);

  if (verbose)
    vlib_cli_output (vm, "\nack [0, 950]:\n%U", format_tcp_scoreboard, sb,
		     tc);

  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->snd_una_adv == 50), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);

  /*
   * Inject one block, ack it and overlap hole
   */

  tc->snd_una = 0;
  tc->snd_una_max = 1000;
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

  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 400),
	    "last bytes delivered %d", sb->last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * One hole close to head, patch head, split in two and start acking
   * the lowest part
   */
  scoreboard_clear (sb);
  tc->snd_una = 0;
  tc->snd_una_max = 1000;
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
  TCP_TEST ((sb->lost_bytes == 300), "lost bytes %u", sb->lost_bytes);

  tc->snd_una = 100;
  tcp_rcv_sacks (tc, 200);
  tc->snd_una = 200;
  tcp_rcv_sacks (tc, 300);
  if (verbose)
    vlib_cli_output (vm, "\nacked [0, 300] in two steps:\n%U",
		     format_tcp_scoreboard, sb, tc);
  TCP_TEST ((sb->sacked_bytes == 500), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->lost_bytes == 100), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 100), "last bytes delivered %d",
	    sb->last_bytes_delivered);

  tc->snd_una = 400;
  tcp_rcv_sacks (tc, 500);
  if (verbose)
    vlib_cli_output (vm, "\nacked [400, 500]:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0), "last sacked bytes %d",
	    sb->last_sacked_bytes);
  TCP_TEST ((sb->last_bytes_delivered == 500), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->lost_bytes == 0), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->snd_una_adv == 500), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->head == TCP_INVALID_SACK_HOLE_INDEX), "head %u", sb->head);
  TCP_TEST ((sb->tail == TCP_INVALID_SACK_HOLE_INDEX), "tail %u", sb->tail);

  /*
   * Re-ack high sacked, to make sure last_bytes_delivered and
   * snd_una_adv are 0-ed
   */
  tcp_rcv_sacks (tc, 1000);
  if (verbose)
    vlib_cli_output (vm, "\nAck high sacked:\n%U", format_tcp_scoreboard, sb,
		     tc);
  TCP_TEST ((sb->last_bytes_delivered == 0), "last bytes delivered %d",
	    sb->last_bytes_delivered);
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);

  /*
   * Add [1200, 1500] and test that [1000, 1200] is lost (bytes condition)
   * snd_una = 1000 and snd_una_max = 1600
   */
  tc->snd_una = 1000;
  tc->snd_una_max = 1600;
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
  TCP_TEST ((sb->lost_bytes == 200), "lost bytes %u", sb->lost_bytes);
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);

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


typedef struct
{
  u32 offset;
  u32 len;
} test_pattern_t;

/* *INDENT-OFF* */
test_pattern_t test_pattern[] = {
  {380, 8}, {768, 8}, {1156, 8}, {1544, 8}, {1932, 8}, {2320, 8}, {2708, 8},
  {2992, 8}, {372, 8}, {760, 8}, {1148, 8}, {1536, 8}, {1924, 8}, {2312, 8},
  {2700, 8}, {2984, 8}, {364, 8}, {752, 8}, {1140, 8}, {1528, 8}, {1916, 8},
  {2304, 8}, {2692, 8}, {2976, 8}, {356, 8}, {744, 8}, {1132, 8}, {1520, 8},
  {1908, 8}, {2296, 8}, {2684, 8}, {2968, 8}, {348, 8}, {736, 8}, {1124, 8},
  {1512, 8}, {1900, 8}, {2288, 8}, {2676, 8}, {2960, 8}, {340, 8}, {728, 8},
  {1116, 8}, {1504, 8}, {1892, 8}, {2280, 8}, {2668, 8}, {2952, 8}, {332, 8},
  {720, 8}, {1108, 8}, {1496, 8}, {1884, 8}, {2272, 8}, {2660, 8}, {2944, 8},
  {324, 8}, {712, 8}, {1100, 8}, {1488, 8}, {1876, 8}, {2264, 8}, {2652, 8},
  {2936, 8}, {316, 8}, {704, 8}, {1092, 8}, {1480, 8}, {1868, 8}, {2256, 8},
  {2644, 8}, {2928, 8}, {308, 8}, {696, 8}, {1084, 8}, {1472, 8}, {1860, 8},
  {2248, 8}, {2636, 8}, {2920, 8}, {300, 8}, {688, 8}, {1076, 8}, {1464, 8},
  {1852, 8}, {2240, 8}, {2628, 8}, {2912, 8}, {292, 8}, {680, 8}, {1068, 8},
  {1456, 8}, {1844, 8}, {2232, 8}, {2620, 8}, {2904, 8}, {284, 8}, {672, 8},
  {1060, 8}, {1448, 8}, {1836, 8}, {2224, 8}, {2612, 8}, {2896, 8}, {276, 8},
  {664, 8}, {1052, 8}, {1440, 8}, {1828, 8},  {2216, 8}, {2604, 8}, {2888, 8},
  {268, 8}, {656, 8}, {1044, 8}, {1432, 8}, {1820, 8}, {2208, 8}, {2596, 8},
  {2880, 8}, {260, 8}, {648, 8}, {1036, 8}, {1424, 8}, {1812, 8}, {2200, 8},
  {2588, 8}, {2872, 8}, {252, 8}, {640, 8}, {1028, 8}, {1416, 8}, {1804, 8},
  {2192, 8}, {2580, 8}, {2864, 8}, {244, 8}, {632, 8}, {1020, 8}, {1408, 8},
  {1796, 8}, {2184, 8}, {2572, 8}, {2856, 8}, {236, 8}, {624, 8}, {1012, 8},
  {1400, 8}, {1788, 8}, {2176, 8}, {2564, 8}, {2848, 8}, {228, 8}, {616, 8},
  {1004, 8}, {1392, 8}, {1780, 8}, {2168, 8}, {2556, 8}, {2840, 8}, {220, 8},
  {608, 8}, {996, 8}, {1384, 8}, {1772, 8}, {2160, 8}, {2548, 8}, {2832, 8},
  {212, 8}, {600, 8}, {988, 8}, {1376, 8}, {1764, 8}, {2152, 8}, {2540, 8},
  {2824, 8}, {204, 8}, {592, 8}, {980, 8}, {1368, 8}, {1756, 8}, {2144, 8},
  {2532, 8}, {2816, 8}, {196, 8}, {584, 8}, {972, 8}, {1360, 8}, {1748, 8},
  {2136, 8}, {2524, 8}, {2808, 8}, {188, 8}, {576, 8}, {964, 8}, {1352, 8},
  {1740, 8}, {2128, 8}, {2516, 8}, {2800, 8}, {180, 8}, {568, 8}, {956, 8},
  {1344, 8}, {1732, 8}, {2120, 8}, {2508, 8}, {2792, 8}, {172, 8}, {560, 8},
  {948, 8}, {1336, 8}, {1724, 8}, {2112, 8}, {2500, 8}, {2784, 8}, {164, 8},
  {552, 8}, {940, 8}, {1328, 8}, {1716, 8}, {2104, 8}, {2492, 8}, {2776, 8},
  {156, 8}, {544, 8}, {932, 8}, {1320, 8}, {1708, 8}, {2096, 8}, {2484, 8},
  {2768, 8}, {148, 8}, {536, 8}, {924, 8}, {1312, 8}, {1700, 8}, {2088, 8},
  {2476, 8}, {2760, 8}, {140, 8}, {528, 8}, {916, 8}, {1304, 8}, {1692, 8},
  {2080, 8}, {2468, 8}, {2752, 8}, {132, 8}, {520, 8}, {908, 8}, {1296, 8},
  {1684, 8}, {2072, 8}, {2460, 8}, {2744, 8}, {124, 8}, {512, 8}, {900, 8},
  {1288, 8}, {1676, 8}, {2064, 8}, {2452, 8}, {2736, 8}, {116, 8}, {504, 8},
  {892, 8}, {1280, 8}, {1668, 8}, {2056, 8}, {2444, 8}, {2728, 8}, {108, 8},
  {496, 8}, {884, 8}, {1272, 8}, {1660, 8}, {2048, 8}, {2436, 8}, {2720, 8},
  {100, 8}, {488, 8}, {876, 8}, {1264, 8}, {1652, 8}, {2040, 8}, {2428, 8},
  {2716, 4}, {92, 8}, {480, 8}, {868, 8}, {1256, 8}, {1644, 8}, {2032, 8},
  {2420, 8}, {84, 8}, {472, 8}, {860, 8}, {1248, 8}, {1636, 8}, {2024, 8},
  {2412, 8}, {76, 8}, {464, 8}, {852, 8}, {1240, 8}, {1628, 8}, {2016, 8},
  {2404, 8}, {68, 8}, {456, 8}, {844, 8}, {1232, 8}, {1620, 8}, {2008, 8},
  {2396, 8}, {60, 8}, {448, 8}, {836, 8}, {1224, 8}, {1612, 8}, {2000, 8},
  {2388, 8}, {52, 8}, {440, 8}, {828, 8}, {1216, 8}, {1604, 8}, {1992, 8},
  {2380, 8}, {44, 8}, {432, 8}, {820, 8}, {1208, 8}, {1596, 8}, {1984, 8},
  {2372, 8}, {36, 8}, {424, 8}, {812, 8}, {1200, 8}, {1588, 8}, {1976, 8},
  {2364, 8}, {28, 8}, {416, 8}, {804, 8}, {1192, 8}, {1580, 8}, {1968, 8},
  {2356, 8}, {20, 8}, {408, 8}, {796, 8}, {1184, 8}, {1572, 8}, {1960, 8},
  {2348, 8}, {12, 8}, {400, 8}, {788, 8}, {1176, 8}, {1564, 8}, {1952, 8},
  {2340, 8}, {4, 8}, {392, 8}, {780, 8}, {1168, 8}, {1556, 8}, {1944, 8},
  {2332, 8},
  /* missing from original data set */
  {388, 4}, {776, 4}, {1164, 4}, {1552, 4}, {1940, 4}, {2328, 4},
};
/* *INDENT-ON* */

int
pattern_cmp (const void *arg1, const void *arg2)
{
  test_pattern_t *a1 = (test_pattern_t *) arg1;
  test_pattern_t *a2 = (test_pattern_t *) arg2;

  if (a1->offset < a2->offset)
    return -1;
  else if (a1->offset > a2->offset)
    return 1;
  return 0;
}

static u8
fifo_validate_pattern (vlib_main_t * vm, test_pattern_t * pattern,
		       u32 pattern_length)
{
  test_pattern_t *tp = pattern;
  int i;

  /* Go through the pattern and make 100% sure it's sane */
  for (i = 0; i < pattern_length - 1; i++)
    {
      if (tp->offset + tp->len != (tp + 1)->offset)
	{
	  vlib_cli_output (vm, "[%d] missing {%d, %d}", i,
			   (tp->offset + tp->len),
			   (tp + 1)->offset - (tp->offset + tp->len));
	  return 0;
	}
      tp++;
    }
  return 1;
}

static test_pattern_t *
fifo_get_validate_pattern (vlib_main_t * vm, test_pattern_t * test_data,
			   u32 test_data_len)
{
  test_pattern_t *validate_pattern = 0;

  /* Validate, and try segments in order... */
  vec_validate (validate_pattern, test_data_len - 1);
  memcpy (validate_pattern, test_data,
	  test_data_len * sizeof (test_pattern_t));
  qsort ((u8 *) validate_pattern, test_data_len, sizeof (test_pattern_t),
	 pattern_cmp);

  if (fifo_validate_pattern (vm, validate_pattern, test_data_len) == 0)
    return 0;

  return validate_pattern;
}

static svm_fifo_t *
fifo_prepare (u32 fifo_size)
{
  svm_fifo_t *f;
  f = svm_fifo_create (fifo_size);

  /* Paint fifo data vector with -1's */
  clib_memset (f->data, 0xFF, fifo_size);

  return f;
}

static int
compare_data (u8 * data1, u8 * data2, u32 start, u32 len, u32 * index)
{
  int i;

  for (i = start; i < len; i++)
    {
      if (data1[i] != data2[i])
	{
	  *index = i;
	  return 1;
	}
    }
  return 0;
}

int
tcp_test_fifo1 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 1 << 20;
  u32 *test_data = 0;
  u32 offset;
  int i, rv, verbose = 0;
  u32 data_word, test_data_len, j;
  ooo_segment_t *ooo_seg;
  u8 *data, *s, *data_buf = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
    }

  test_data_len = fifo_size / sizeof (u32);
  vec_validate (test_data, test_data_len - 1);

  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  f = fifo_prepare (fifo_size);

  /*
   * Enqueue an initial (un-dequeued) chunk
   */
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) test_data);
  TCP_TEST ((rv == sizeof (u32)), "enqueued %d", rv);
  TCP_TEST ((f->tail == 4), "fifo tail %u", f->tail);

  /*
   * Create 3 chunks in the future. The offsets are relative
   * to the current fifo tail
   */
  for (i = 0; i < 3; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      if (i == 0)
	{
	  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), data);
	  rv = rv > 0 ? 0 : rv;
	}
      else
	rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after odd segs: %U", format_svm_fifo, f, 1);

  TCP_TEST ((f->tail == 8), "fifo tail %u", f->tail);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Try adding a completely overlapped segment
   */
  offset = 3 * sizeof (u32) - f->tail;
  data = (u8 *) (test_data + 3);
  rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
  if (rv)
    {
      clib_warning ("enqueue returned %d", rv);
      goto err;
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after overlap seg: %U", format_svm_fifo, f, 1);

  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Make sure format functions are not buggy
   */
  s = format (0, "%U", format_svm_fifo, f, 2);
  vec_free (s);

  /*
   * Paint some of missing data backwards
   */
  for (i = 3; i > 1; i--)
    {
      offset = (2 * i + 0) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 0));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo before missing link: %U", format_svm_fifo, f,
		     1);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == 12),
	    "first ooo seg position %u", ooo_seg->start);
  TCP_TEST ((ooo_seg->length == 16),
	    "first ooo seg length %u", ooo_seg->length);

  /*
   * Enqueue the missing u32
   */
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) (test_data + 2));
  if (verbose)
    vlib_cli_output (vm, "fifo after missing link: %U", format_svm_fifo, f,
		     1);
  TCP_TEST ((rv == 20), "bytes to be enqueued %u", rv);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Collect results
   */
  for (i = 0; i < 7; i++)
    {
      rv = svm_fifo_dequeue_nowait (f, sizeof (u32), (u8 *) & data_word);
      if (rv != sizeof (u32))
	{
	  clib_warning ("bytes dequeues %u", rv);
	  goto err;
	}
      if (data_word != test_data[i])
	{
	  clib_warning ("recovered [%d] %d not %d", i, data_word,
			test_data[i]);
	  goto err;
	}
    }

  /*
   * Test segment overlaps: last ooo segment overlaps all
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  for (i = 0; i < 4; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  rv = svm_fifo_enqueue_with_offset (f, 8 - f->tail, 21, data);
  TCP_TEST ((rv == 0), "ooo enqueued %u", rv);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, vec_len (data));
  svm_fifo_peek (f, 0, vec_len (data), data_buf);
  if (compare_data (data_buf, data, 8, vec_len (data), &j))
    {
      TCP_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j], data[j]);
    }
  vec_reset_length (data_buf);

  /*
   * Test segment overlaps: enqueue and overlap ooo segments
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  for (i = 0; i < 4; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after enqueue: %U", format_svm_fifo, f, 1);

  rv = svm_fifo_enqueue_nowait (f, 29, data);
  if (verbose)
    vlib_cli_output (vm, "fifo after enqueueing 29: %U", format_svm_fifo, f,
		     1);
  TCP_TEST ((rv == 32), "ooo enqueued %u", rv);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, vec_len (data));
  svm_fifo_peek (f, 0, vec_len (data), data_buf);
  if (compare_data (data_buf, data, 0, vec_len (data), &j))
    {
      TCP_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j], data[j]);
    }

  /* Try to peek beyond the data */
  rv = svm_fifo_peek (f, svm_fifo_max_dequeue (f), vec_len (data), data_buf);
  TCP_TEST ((rv == 0), "peeked %u expected 0", rv);

  vec_free (data_buf);
  svm_fifo_free (f);
  vec_free (test_data);

  return 0;

err:
  svm_fifo_free (f);
  vec_free (test_data);
  return -1;
}

static int
tcp_test_fifo2 (vlib_main_t * vm)
{
  svm_fifo_t *f;
  u32 fifo_size = 1 << 20;
  int i, rv, test_data_len;
  u64 data64;
  test_pattern_t *tp, *vp, *test_data;
  ooo_segment_t *ooo_seg;

  test_data = test_pattern;
  test_data_len = ARRAY_LEN (test_pattern);

  vp = fifo_get_validate_pattern (vm, test_data, test_data_len);

  /* Create a fifo */
  f = fifo_prepare (fifo_size);

  /*
   * Try with sorted data
   */
  for (i = 0; i < test_data_len; i++)
    {
      tp = vp + i;
      data64 = tp->offset;
      svm_fifo_enqueue_with_offset (f, tp->offset - f->tail, tp->len,
				    (u8 *) & data64);
    }

  /* Expected result: one big fat chunk at offset 4 */
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == 4),
	    "first ooo seg position %u", ooo_seg->start);
  TCP_TEST ((ooo_seg->length == 2996),
	    "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) & data64);
  TCP_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  svm_fifo_free (f);
  vec_free (vp);

  /*
   * Now try it again w/ unsorted data...
   */

  f = fifo_prepare (fifo_size);

  for (i = 0; i < test_data_len; i++)
    {
      tp = &test_data[i];
      data64 = tp->offset;
      rv = svm_fifo_enqueue_with_offset (f, tp->offset - f->tail, tp->len,
					 (u8 *) & data64);
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	}
    }

  /* Expecting the same result: one big fat chunk at offset 4 */
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == 4),
	    "first ooo seg position %u", ooo_seg->start);
  TCP_TEST ((ooo_seg->length == 2996),
	    "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) & data64);

  TCP_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  svm_fifo_free (f);

  return 0;
}

static int
tcp_test_fifo3 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 4 << 10;
  u32 fifo_initial_offset = 0;
  u32 total_size = 2 << 10;
  int overlap = 0, verbose = 0, randomize = 1, drop = 0, in_seq_all = 0;
  u8 *data_pattern = 0, *data_buf = 0;
  test_pattern_t *tp, *generate = 0;
  u32 nsegs = 2, seg_size, length_so_far;
  u32 current_offset, offset_increment, len_this_chunk;
  u32 seed = 0xdeaddabe, j;
  int i, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fifo-size %d", &fifo_size))
	;
      else if (unformat (input, "total-size %d", &total_size))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "overlap"))
	overlap = 1;
      else if (unformat (input, "initial-offset %d", &fifo_initial_offset))
	;
      else if (unformat (input, "seed %d", &seed))
	;
      else if (unformat (input, "nsegs %d", &nsegs))
	;
      else if (unformat (input, "no-randomize"))
	randomize = 0;
      else if (unformat (input, "in-seq-all"))
	in_seq_all = 1;
      else if (unformat (input, "drop"))
	drop = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  if (total_size > fifo_size)
    {
      clib_warning ("total_size %d greater than fifo size %d", total_size,
		    fifo_size);
      return -1;
    }
  if (overlap && randomize == 0)
    {
      clib_warning ("Can't enqueue in-order with overlap");
      return -1;
    }

  /*
   * Generate data
   */
  vec_validate (data_pattern, total_size - 1);
  for (i = 0; i < vec_len (data_pattern); i++)
    data_pattern[i] = i & 0xff;

  /*
   * Generate segments
   */
  seg_size = total_size / nsegs;
  length_so_far = 0;
  current_offset = randomize;
  while (length_so_far < total_size)
    {
      vec_add2 (generate, tp, 1);
      len_this_chunk = clib_min (seg_size, total_size - length_so_far);
      tp->offset = current_offset;
      tp->len = len_this_chunk;

      if (overlap && (len_this_chunk == seg_size))
	do
	  {
	    offset_increment = len_this_chunk
	      % (1 + (random_u32 (&seed) % len_this_chunk));
	  }
	while (offset_increment == 0);
      else
	offset_increment = len_this_chunk;

      current_offset += offset_increment;
      length_so_far = tp->offset + tp->len;
    }

  /*
   * Validate segment list. Only valid for non-overlap cases.
   */
  if (overlap == 0)
    fifo_validate_pattern (vm, generate, vec_len (generate));

  if (verbose)
    {
      vlib_cli_output (vm, "raw data pattern:");
      for (i = 0; i < vec_len (generate); i++)
	{
	  vlib_cli_output (vm, "[%d] offset %u len %u", i,
			   generate[i].offset, generate[i].len);
	}
    }

  /* Randomize data pattern */
  if (randomize)
    {
      for (i = 0; i < vec_len (generate) / 2; i++)
	{
	  u32 src_index, dst_index;
	  test_pattern_t _tmp, *tmp = &_tmp;

	  src_index = random_u32 (&seed) % vec_len (generate);
	  dst_index = random_u32 (&seed) % vec_len (generate);

	  tmp[0] = generate[dst_index];
	  generate[dst_index] = generate[src_index];
	  generate[src_index] = tmp[0];
	}
      if (verbose)
	{
	  vlib_cli_output (vm, "randomized data pattern:");
	  for (i = 0; i < vec_len (generate); i++)
	    {
	      vlib_cli_output (vm, "[%d] offset %u len %u", i,
			       generate[i].offset, generate[i].len);
	    }
	}
    }

  /*
   * Create a fifo and add segments
   */
  f = fifo_prepare (fifo_size);

  /* manually set head and tail pointers to validate modular arithmetic */
  fifo_initial_offset = fifo_initial_offset % fifo_size;
  f->head = fifo_initial_offset;
  f->tail = fifo_initial_offset;

  for (i = !randomize; i < vec_len (generate); i++)
    {
      tp = generate + i;
      svm_fifo_enqueue_with_offset (f,
				    fifo_initial_offset + tp->offset -
				    f->tail, tp->len,
				    (u8 *) data_pattern + tp->offset);
    }

  /* Add the first segment in order for non random data */
  if (!randomize)
    svm_fifo_enqueue_nowait (f, generate[0].len, (u8 *) data_pattern);

  /*
   * Expected result: one big fat chunk at offset 1 if randomize == 1
   */

  if (verbose)
    vlib_cli_output (vm, "fifo before missing link: %U",
		     format_svm_fifo, f, 1 /* verbose */ );

  /*
   * Add the missing byte if segments were randomized
   */
  if (randomize)
    {
      u32 bytes_to_enq = 1;
      if (in_seq_all)
	bytes_to_enq = total_size;
      rv = svm_fifo_enqueue_nowait (f, bytes_to_enq, data_pattern + 0);

      if (verbose)
	vlib_cli_output (vm, "in-order enqueue returned %d", rv);

      TCP_TEST ((rv == total_size), "enqueued %u expected %u", rv,
		total_size);

    }

  TCP_TEST ((svm_fifo_has_ooo_data (f) == 0), "number of ooo segments %u",
	    svm_fifo_number_ooo_segments (f));

  /*
   * Test if peeked data is the same as original data
   */
  vec_validate (data_buf, vec_len (data_pattern));
  svm_fifo_peek (f, 0, vec_len (data_pattern), data_buf);
  if (compare_data (data_buf, data_pattern, 0, vec_len (data_pattern), &j))
    {
      TCP_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j],
		data_pattern[j]);
    }
  vec_reset_length (data_buf);

  /*
   * Dequeue or drop all data
   */
  if (drop)
    {
      svm_fifo_dequeue_drop (f, vec_len (data_pattern));
    }
  else
    {
      svm_fifo_dequeue_nowait (f, vec_len (data_pattern), data_buf);
      if (compare_data
	  (data_buf, data_pattern, 0, vec_len (data_pattern), &j))
	{
	  TCP_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		    data_pattern[j]);
	}
    }

  TCP_TEST ((svm_fifo_max_dequeue (f) == 0), "fifo has %d bytes",
	    svm_fifo_max_dequeue (f));

  svm_fifo_free (f);
  vec_free (data_pattern);
  vec_free (data_buf);

  return 0;
}

static int
tcp_test_fifo4 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 6 << 10;
  u32 fifo_initial_offset = 1000000000;
  u32 test_n_bytes = 5000, j;
  u8 *test_data = 0, *data_buf = 0;
  int i, rv, verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  /*
   * Create a fifo and add segments
   */
  f = fifo_prepare (fifo_size);

  /* Set head and tail pointers */
  fifo_initial_offset = fifo_initial_offset % fifo_size;
  svm_fifo_init_pointers (f, fifo_initial_offset);

  vec_validate (test_data, test_n_bytes - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  for (i = test_n_bytes - 1; i > 0; i--)
    {
      rv = svm_fifo_enqueue_with_offset (f, fifo_initial_offset + i - f->tail,
					 sizeof (u8), &test_data[i]);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", i, i, i + sizeof (u8));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  svm_fifo_free (f);
	  vec_free (test_data);
	  return -1;
	}
    }

  svm_fifo_enqueue_nowait (f, sizeof (u8), &test_data[0]);

  vec_validate (data_buf, vec_len (test_data));

  svm_fifo_dequeue_nowait (f, vec_len (test_data), data_buf);
  rv = compare_data (data_buf, test_data, 0, vec_len (test_data), &j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  TCP_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  svm_fifo_free (f);
  vec_free (test_data);
  return 0;
}

static u32
fifo_pos (svm_fifo_t * f, u32 pos)
{
  return pos % f->nitems;
}

static int
tcp_test_fifo5 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 400, j = 0, offset = 200;
  int i, rv, verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  ooo_segment_t *ooo_seg;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  f = fifo_prepare (fifo_size);
  svm_fifo_init_pointers (f, offset);

  vec_validate (test_data, 399);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Start with [100, 200] and [300, 400]
   */
  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 300, 100, &test_data[300]);

  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  TCP_TEST ((f->ooos_newest == 1), "newest %u", f->ooos_newest);
  if (verbose)
    vlib_cli_output (vm, "fifo after [100, 200] and [300, 400] : %U",
		     format_svm_fifo, f, 2 /* verbose */ );

  /*
   * Add [225, 275]
   */

  rv = svm_fifo_enqueue_with_offset (f, 225, 50, &test_data[200]);
  if (verbose)
    vlib_cli_output (vm, "fifo after [225, 275] : %U",
		     format_svm_fifo, f, 2 /* verbose */ );
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 3),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == fifo_pos (f, 100 + offset)),
	    "first seg start %u expected %u", ooo_seg->start,
	    fifo_pos (f, 100 + offset));
  TCP_TEST ((ooo_seg->length == 100), "first seg length %u expected %u",
	    ooo_seg->length, 100);
  ooo_seg = ooo_segment_next (f, ooo_seg);
  TCP_TEST ((ooo_seg->start == fifo_pos (f, 225 + offset)),
	    "second seg start %u expected %u",
	    ooo_seg->start, fifo_pos (f, 225 + offset));
  TCP_TEST ((ooo_seg->length == 50), "second seg length %u expected %u",
	    ooo_seg->length, 50);
  ooo_seg = ooo_segment_next (f, ooo_seg);
  TCP_TEST ((ooo_seg->start == fifo_pos (f, 300 + offset)),
	    "third seg start %u expected %u",
	    ooo_seg->start, fifo_pos (f, 300 + offset));
  TCP_TEST ((ooo_seg->length == 100), "third seg length %u expected %u",
	    ooo_seg->length, 100);
  TCP_TEST ((f->ooos_newest == 2), "newest %u", f->ooos_newest);
  /*
   * Add [190, 310]
   */
  rv = svm_fifo_enqueue_with_offset (f, 190, 120, &test_data[190]);
  if (verbose)
    vlib_cli_output (vm, "fifo after [190, 310] : %U",
		     format_svm_fifo, f, 1 /* verbose */ );
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == fifo_pos (f, offset + 100)),
	    "first seg start %u expected %u",
	    ooo_seg->start, fifo_pos (f, offset + 100));
  TCP_TEST ((ooo_seg->length == 300), "first seg length %u expected %u",
	    ooo_seg->length, 300);

  /*
   * Add [0, 150]
   */
  rv = svm_fifo_enqueue_nowait (f, 150, test_data);

  if (verbose)
    vlib_cli_output (vm, "fifo after [0 150] : %U", format_svm_fifo, f,
		     2 /* verbose */ );

  TCP_TEST ((rv == 400), "managed to enqueue %u expected %u", rv, 400);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, 399);
  svm_fifo_peek (f, 0, 400, data_buf);
  if (compare_data (data_buf, test_data, 0, 400, &j))
    {
      TCP_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j],
		test_data[j]);
    }

  /*
   * Add [100 200] and overlap it with [50 250]
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 50, 200, &test_data[50]);
  TCP_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	    "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  TCP_TEST ((ooo_seg->start == 50), "first seg start %u expected %u",
	    ooo_seg->start, 50);
  TCP_TEST ((ooo_seg->length == 200), "first seg length %u expected %u",
	    ooo_seg->length, 200);

  svm_fifo_free (f);
  vec_free (test_data);
  return 0;
}

/* *INDENT-OFF* */
svm_fifo_trace_elem_t fifo_trace[] = {};
/* *INDENT-ON* */

static int
tcp_test_fifo_replay (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t f;
  int verbose = 0;
  u8 no_read = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "no-read"))
	no_read = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

#if SVMF_FIFO_TRACE
  f.trace = fifo_trace;
#endif

  str = svm_fifo_replay (str, &f, no_read, verbose);
  vlib_cli_output (vm, "%v", str);
  return 0;
}

static int
tcp_test_fifo (vlib_main_t * vm, unformat_input_t * input)
{
  int res = 0;
  char *str;

  /* Run all tests */
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    {
      res = tcp_test_fifo1 (vm, input);
      if (res)
	return res;

      res = tcp_test_fifo2 (vm);
      if (res)
	return res;

      /*
       * Run a number of fifo3 configs
       */
      str = "nsegs 10 overlap seed 123";
      unformat_init_cstring (input, str);
      if (tcp_test_fifo3 (vm, input))
	return -1;
      unformat_free (input);

      str = "nsegs 10 overlap seed 123 in-seq-all";
      unformat_init_cstring (input, str);
      if (tcp_test_fifo3 (vm, input))
	return -1;
      unformat_free (input);

      str = "nsegs 10 overlap seed 123 initial-offset 3917";
      unformat_init_cstring (input, str);
      if (tcp_test_fifo3 (vm, input))
	return -1;
      unformat_free (input);

      str = "nsegs 10 overlap seed 123 initial-offset 3917 drop";
      unformat_init_cstring (input, str);
      if (tcp_test_fifo3 (vm, input))
	return -1;
      unformat_free (input);

      str = "nsegs 10 seed 123 initial-offset 3917 drop no-randomize";
      unformat_init_cstring (input, str);
      if (tcp_test_fifo3 (vm, input))
	return -1;
      unformat_free (input);

      res = tcp_test_fifo4 (vm, input);
      if (res)
	return res;

      res = tcp_test_fifo5 (vm, input);
      if (res)
	return res;
    }
  else
    {
      if (unformat (input, "fifo3"))
	{
	  res = tcp_test_fifo3 (vm, input);
	}
      else if (unformat (input, "fifo2"))
	{
	  res = tcp_test_fifo2 (vm);
	}
      else if (unformat (input, "fifo1"))
	{
	  res = tcp_test_fifo1 (vm, input);
	}
      else if (unformat (input, "fifo4"))
	{
	  res = tcp_test_fifo4 (vm, input);
	}
      else if (unformat (input, "fifo5"))
	{
	  res = tcp_test_fifo5 (vm, input);
	}
      else if (unformat (input, "replay"))
	{
	  res = tcp_test_fifo_replay (vm, input);
	}
    }

  return res;
}

static int
tcp_test_lookup (vlib_main_t * vm, unformat_input_t * input)
{
  session_manager_main_t *smm = &session_manager_main;
  tcp_main_t *tm = &tcp_main;
  transport_connection_t _tc1, *tc1 = &_tc1, _tc2, *tc2 = &_tc2, *tconn;
  tcp_connection_t *tc;
  stream_session_t *s, *s1;
  u8 cmp = 0, is_filtered = 0;
  u32 sidx;

  /*
   * Allocate fake session and connection 1
   */
  pool_get (smm->wrk[0].sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->session_index = sidx = s - smm->wrk[0].sessions;

  pool_get (tm->connections[0], tc);
  clib_memset (tc, 0, sizeof (*tc));
  tc->connection.c_index = tc - tm->connections[0];
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

  pool_get (tm->connections[0], tc);
  clib_memset (tc, 0, sizeof (*tc));
  tc->connection.c_index = tc - tm->connections[0];
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
  tcp_main_t *tm = vnet_get_tcp_main ();
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

      pool_get (tm->connections[0], tc0);
      clib_memset (tc0, 0, sizeof (*tc0));

      tc0->state = TCP_STATE_ESTABLISHED;
      tc0->rcv_las = 1;
      tc0->c_c_index = tc0 - tm->connections[0];
      tc0->c_lcl_port = local_port;
      tc0->c_rmt_port = remote_port;
      tc0->c_is_ip4 = 1;
      tc0->c_thread_index = 0;
      tc0->c_lcl_ip4.as_u32 = local.as_u32;
      tc0->c_rmt_ip4.as_u32 = remote.as_u32;
      tc0->rcv_opts.mss = 1450;
      tcp_connection_init_vars (tc0);

      TCP_EVT_DBG (TCP_EVT_OPEN, tc0);

      if (stream_session_accept (&tc0->connection, 0 /* listener index */ ,
				 0 /* notify */ ))
	clib_warning ("stream_session_accept failed");

      stream_session_accept_notify (&tc0->connection);
    }
  else
    {
      tc0 = tcp_connection_get (0 /* connection index */ , 0 /* thread */ );
      tc0->state = TCP_STATE_CLOSED;
      session_transport_closing_notify (&tc0->connection);
    }

  return rv;
}

static clib_error_t *
tcp_test (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sack"))
	{
	  res = tcp_test_sack (vm, input);
	}
      else if (unformat (input, "fifo"))
	{
	  res = tcp_test_fifo (vm, input);
	}
      else if (unformat (input, "session"))
	{
	  res = tcp_test_session (vm, input);
	}
      else if (unformat (input, "lookup"))
	{
	  res = tcp_test_lookup (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = tcp_test_sack (vm, input)))
	    goto done;
	  if ((res = tcp_test_fifo (vm, input)))
	    goto done;
	  if ((res = tcp_test_lookup (vm, input)))
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
