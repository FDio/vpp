/*
 * node.c - packet data fuzzer
 *
 * Copyright (c) 2019 by Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pfuzz/pfuzz.h>

#include <string.h>
#include <unistd.h>

#define AFL_LOOP_ITERATIONS 1000000000
#define MAX_PACKET_SIZE 9000
/* set TESTING_STABILITY to 1 for running for some number of iterations
   then exiting. */
#define TESTING_STABILITY 0	/* TODO better use an env variable */
#define TEST_STABILITY_ITERATIONS 1
/* Whether to XOR the packet with AFL's input, or to overwrite it */
#define USE_XOR 0		/* TODO better use an env variable */
/* Maximum number of stacked mutations per iteration for blackbox fuzzing */
#define BLACKBOX_MAX_MUTS 16

/* Necessary for some experiments where VPP is interrupted abruptly without
   calling exit handlers. In this case, we need to flush the output of gcov
   regularly. */
void __gcov_flush ();
/* At around 25000 loops/s, this flushes about every minute */
#define FLUSH_EVERY 1500000

static u8 afl_buf[MAX_PACKET_SIZE];

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} pfuzz_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pfuzz_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pfuzz_trace_t *t = va_arg (*args, pfuzz_trace_t *);

  s =
    format (s,
	    "PFUZZ: sw_if_index %d, next index %d",
	    t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t pfuzz_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pfuzz_error \
_(FUZZED, "Packets fuzzed")

typedef enum
{
#define _(sym,str) PFUZZ_ERROR_##sym,
  foreach_pfuzz_error
#undef _
    PFUZZ_N_ERROR,
} pfuzz_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pfuzz_error_strings[] = {
#define _(sym,string) string,
  foreach_pfuzz_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PFUZZ_NEXT_DROP,
  PFUZZ_N_NEXT,
} pfuzz_next_t;


always_inline uword
pfuzz_inline (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame, int is_trace)
{
  pfuzz_main_t *pm = &pfuzz_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_buffer_t *b0;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 next0;
  u8 *target;
  ssize_t nread;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  if (pm->mode == PFUZZ_MODE_FUZZ)
    {
      if (TESTING_STABILITY)
	{
	  static int iter = 0;
	  if (iter == TEST_STABILITY_ITERATIONS)
	    exit (0);
	  iter++;
	}
      else
	{
#ifdef __AFL_COMPILER
	  /* go on AFL_LOOP_ITERATIONS times before exiting */
	  if (!__AFL_LOOP (AFL_LOOP_ITERATIONS))
	    exit (0);
#else /* __AFL_COMPILER */
	  /* if the compiler doesn't understand __AFL_LOOP, run only once
	     except if pm->use_blackbox (in which case run blackbox fuzzing) */
	  /* TODO factorize with TESTING_STABILITY? */
	  if (!pm->use_blackbox)
	    {
	      static int first_time = 1;
	      if (!first_time)
		exit (0);
	      first_time = 0;
	    }
#endif /* __AFL_COMPILER */
	}
    }

  if ((pm->mode == PFUZZ_MODE_FUZZ && !pm->use_blackbox)
      || pm->replay_fd != 0)
    {
      /* Read up to MAX_PACKET_SIZE bytes from replay_fd
         (which is stdin in PFUZZ_MODE_FUZZ). Further bytes are ignored. */
      nread = read (pm->replay_fd, afl_buf, MAX_PACKET_SIZE);
      if (nread == -1)
	clib_unix_warning ("failed reading from replay_fd");
      if (pm->mode == PFUZZ_MODE_REPLAY)
	{
	  /* rewind the replay file */
	  if (lseek (pm->replay_fd, 0, SEEK_SET) == -1)
	    clib_unix_warning ("lseek() failed");
	}
    }

  while (n_left_from > 0)
    {
      b0 = b[0];
      vnet_feature_next (&next0, b0);
      next[0] = next0;

      target = vlib_buffer_get_current (b0);

      if (!pm->use_blackbox)
	{			/* greybox fuzzing; also works for replay mode */
	  if (USE_XOR)
	    {
	      /* XOR afl_buf with current data */
	      for (int i = 0; i < clib_min (nread, b0->current_length); i++)
		{
		  target[i] ^= afl_buf[i];
		}
	    }
	  else
	    {
	      /* Overwrite current data with afl_buf.
	         If nread is too small, finish with zeroes */
	      memcpy (target, afl_buf, clib_min (nread, b0->current_length));
	      if (b0->current_length > nread)
		memset (target + nread, 0, b0->current_length - nread);
	    }

	}
      else
	{			/* blackbox fuzzing or associated "replay mode" in which nothing
				   is done */
	  static u32 iter = 0;
	  if (iter == FLUSH_EVERY)
	    {
	      __gcov_flush ();
	      iter = 0;
	    }
	  iter++;
	  if (pm->mode == PFUZZ_MODE_FUZZ)
	    {
	      /* Select a random number n_mut from 1 to BLACKBOX_MAX_MUTS,
	         and stack n_mut mutations (replacements of a random byte
	         with a random value) */
	      u32 n_mut = random_u32 (&pm->seed) % BLACKBOX_MAX_MUTS + 1;
	      for (int i = 0; i < n_mut; i++)
		{
		  u32 loc = random_u32 (&pm->seed) % b0->current_length;
		  u8 new = random_u32 (&pm->seed) % 256;
		  target[loc] = new;
		}
	    }
	}
      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      pfuzz_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PFUZZ_ERROR_FUZZED, frame->n_vectors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (pfuzz_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return pfuzz_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return pfuzz_inline (vm, node, frame, 0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pfuzz_node) =
{
  .name = "pfuzz",
  .vector_size = sizeof (u32),
  .format_trace = format_pfuzz_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pfuzz_error_strings),
  .error_strings = pfuzz_error_strings,

  .n_next_nodes = PFUZZ_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [PFUZZ_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
