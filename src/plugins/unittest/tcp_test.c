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
  tc->snd_nxt = tc->snd_una_max = 1900;
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
  tc->snd_nxt = tc->snd_una_max = 1600;
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

static int
tcp_test_lookup (vlib_main_t * vm, unformat_input_t * input)
{
  session_main_t *smm = &session_main;
  tcp_main_t *tm = &tcp_main;
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

      if (session_stream_accept (&tc0->connection, 0 /* listener index */ ,
				 0 /* notify */ ))
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
