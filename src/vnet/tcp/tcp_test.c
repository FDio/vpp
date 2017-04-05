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

static int
tcp_test_sack ()
{
  tcp_connection_t _tc, *tc = &_tc;
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *sacks = 0, block;
  sack_scoreboard_hole_t *hole;
  int i;

  memset (tc, 0, sizeof (*tc));

  tc->snd_una = 0;
  tc->snd_una_max = 1000;
  tc->snd_nxt = 1000;
  tc->opt.flags |= TCP_OPTS_FLAG_SACK;
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
      vec_add1 (tc->opt.sacks, sacks[i * 2]);
    }
  tc->opt.n_sack_blocks = vec_len (tc->opt.sacks);
  tcp_rcv_sacks (tc, 0);

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

  /*
   * Inject odd blocks
   */

  vec_reset_length (tc->opt.sacks);
  for (i = 0; i < 1000 / 200; i++)
    {
      vec_add1 (tc->opt.sacks, sacks[i * 2 + 1]);
    }
  tc->opt.n_sack_blocks = vec_len (tc->opt.sacks);
  tcp_rcv_sacks (tc, 0);

  hole = scoreboard_first_hole (sb);
  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  TCP_TEST ((hole->start == 0 && hole->end == 100),
	    "first hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 900), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->snd_una_adv == 0), "snd_una_adv %u", sb->snd_una_adv);
  TCP_TEST ((sb->max_byte_sacked == 1000),
	    "max sacked byte %u", sb->max_byte_sacked);
  TCP_TEST ((sb->last_sacked_bytes == 500),
	    "last sacked bytes %d", sb->last_sacked_bytes);

  /*
   *  Ack until byte 100, all bytes are now acked + sacked
   */
  tcp_rcv_sacks (tc, 100);

  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "scoreboard has %d elements", pool_elts (sb->holes));
  TCP_TEST ((sb->snd_una_adv == 900),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((sb->max_byte_sacked == 1000),
	    "max sacked byte %u", sb->max_byte_sacked);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((sb->last_sacked_bytes == 0),
	    "last sacked bytes %d", sb->last_sacked_bytes);

  /*
   * Add new block
   */

  vec_reset_length (tc->opt.sacks);

  block.start = 1200;
  block.end = 1300;
  vec_add1 (tc->opt.sacks, block);

  tc->snd_una_max = 1500;
  tc->snd_una = 1000;
  tc->snd_nxt = 1500;
  tcp_rcv_sacks (tc, 1000);

  TCP_TEST ((sb->snd_una_adv == 0),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((pool_elts (sb->holes) == 2),
	    "scoreboard has %d holes", pool_elts (sb->holes));
  hole = scoreboard_first_hole (sb);
  TCP_TEST ((hole->start == 1000 && hole->end == 1200),
	    "first hole start %u end %u", hole->start, hole->end);
  hole = scoreboard_last_hole (sb);
  TCP_TEST ((hole->start == 1300 && hole->end == 1500),
	    "last hole start %u end %u", hole->start, hole->end);
  TCP_TEST ((sb->sacked_bytes == 100), "sacked bytes %d", sb->sacked_bytes);

  /*
   * Ack first hole
   */

  vec_reset_length (tc->opt.sacks);
  tcp_rcv_sacks (tc, 1200);

  TCP_TEST ((sb->snd_una_adv == 100),
	    "snd_una_adv after ack %u", sb->snd_una_adv);
  TCP_TEST ((sb->sacked_bytes == 0), "sacked bytes %d", sb->sacked_bytes);
  TCP_TEST ((pool_elts (sb->holes) == 1),
	    "scoreboard has %d elements", pool_elts (sb->holes));

  /*
   * Remove all
   */

  scoreboard_clear (sb);
  TCP_TEST ((pool_elts (sb->holes) == 0),
	    "number of holes %d", pool_elts (sb->holes));
  return 0;
}

static int
tcp_test_fifo (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 1 << 20;
  u32 *test_data = 0;
  u32 offset;
  int i, rv;
  u32 data_word, test_data_len;

  /* $$$ parse args */
  test_data_len = fifo_size / sizeof (u32);
  vec_validate (test_data, test_data_len - 1);

  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  f = svm_fifo_create (fifo_size);

  /* Paint fifo data vector with -1's */
  memset (f->data, 0xFF, test_data_len);

  /* Enqueue an initial (un-dequeued) chunk */
  rv = svm_fifo_enqueue_nowait (f, 0 /* pid */ ,
				sizeof (u32), (u8 *) test_data);

  if (rv != sizeof (u32))
    {
      clib_warning ("enqueue returned %d", rv);
      goto out;
    }

  /*
   * Create 3 chunks in the future. The offsets are relative
   * to the current fifo tail
   */
  for (i = 0; i < 3; i++)
    {
      offset = (2 * i + 1) * sizeof (u32);
      vlib_cli_output (vm, "add offset %d", offset);

      rv = svm_fifo_enqueue_with_offset
	(f, 0 /* pid */ , offset, sizeof (u32),
	 (u8 *) (test_data + ((offset + sizeof (u32)) / sizeof (u32))));

      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto out;
	}
    }

  /* Paint missing data backwards */
  for (i = 3; i > 0; i--)
    {
      offset = (2 * i + 0) * sizeof (u32);

      vlib_cli_output (vm, "add offset %d", offset);

      rv = svm_fifo_enqueue_with_offset
	(f, 0 /* pid */ , offset, sizeof (u32),
	 (u8 *) (test_data + ((offset + sizeof (u32)) / sizeof (u32))));

      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto out;
	}
    }

  vlib_cli_output (vm, "fifo before missing link: %U",
		   format_svm_fifo, f, 1 /* verbose */ );

  /* Enqueue the missing u32 */
  rv = svm_fifo_enqueue_nowait (f, 0 /* pid */ ,
				sizeof (u32), (u8 *) (test_data + 1));
  if (rv != 7 * sizeof (u32))
    {
      clib_warning ("enqueue returned %d", rv);
      goto out;
    }

  vlib_cli_output (vm, "fifo after missing link: %U",
		   format_svm_fifo, f, 1 /* verbose */ );

  /* Collect results */
  for (i = 0; i < 7; i++)
    {
      rv = svm_fifo_dequeue_nowait (f, 0 /* pid */ , sizeof (u32),
				    (u8 *) & data_word);
      if (rv != sizeof (u32))
	{
	  clib_warning ("dequeue returned %d", rv);
	  goto out;
	}
      if (data_word != test_data[i])
	{
	  clib_warning ("recovered data %d not %d", data_word, test_data[i]);
	  goto out;
	}
    }

  clib_warning ("test complete...");

out:
  svm_fifo_free (f);
  vec_free (test_data);
  return 0;
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
	  res = tcp_test_sack ();
	}
      else if (unformat (input, "fifo"))
	{
	  res = tcp_test_fifo (vm, input);
	}
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  if (res)
    {
      return clib_error_return (0, "TCP unit test failed");
    }
  else
    {
      return 0;
    }
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
