/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vlib/punt.h>

#define foreach_punt_error                     \
  _(DISPATCHED, "dispatched")                  \
  _(NO_REASON, "No such punt reason")          \
  _(NO_REG, "No registrations")                \
  _(REP_FAIL, "Replication Faliure")

typedef enum punt_error_t_
{
#define _(v,s) PUNT_ERROR_##v,
  foreach_punt_error
#undef _
    PUNT_N_ERRORS,
} punt_error_t;

static char *punt_error_strings[] = {
#define _(v,s) [PUNT_ERROR_##v] = s,
  foreach_punt_error
#undef _
};

typedef enum punt_next_t_
{
  PUNT_NEXT_DROP,
  PUNT_N_NEXT,
} punt_next_t;

typedef struct punt_trace_t_
{
  vlib_punt_reason_t pt_reason;
} punt_trace_t;

/**
 * Per-thread clone vectors
 */
#ifndef CLIB_MARCH_VARIANT
u32 **punt_clones;
#else
extern u32 **punt_clones;
#endif

static u8 *
format_punt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  punt_trace_t *t = va_arg (*args, punt_trace_t *);

  s = format (s, "reason: %U", format_vlib_punt_reason, t->pt_reason);

  return s;
}

always_inline u32
punt_replicate (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		u32 thread_index,
		vlib_buffer_t * b0,
		u32 bi0,
		vlib_punt_reason_t pr0,
		u32 * next_index,
		u32 * n_left_to_next, u32 ** to_next, u32 * n_dispatched)
{
  /* multiple clients => replicate a copy to each */
  u16 n_clones0, n_cloned0, clone0;
  u32 ci0, next0;

  n_clones0 = vec_len (punt_dp_db[pr0]);
  vec_validate (punt_clones[thread_index], n_clones0);

  n_cloned0 = vlib_buffer_clone (vm, bi0,
				 punt_clones[thread_index],
				 n_clones0, 2 * CLIB_CACHE_LINE_BYTES);

  if (PREDICT_FALSE (n_cloned0 != n_clones0))
    {
      b0->error = node->errors[PUNT_ERROR_REP_FAIL];
    }

  for (clone0 = 1; clone0 < n_cloned0; clone0++)
    {
      ci0 = punt_clones[thread_index][clone0];

      *to_next[0] = ci0;
      *to_next += 1;
      *n_left_to_next -= 1;

      next0 = punt_dp_db[pr0][clone0];

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vlib_buffer_t *c0;
	  punt_trace_t *t;

	  c0 = vlib_get_buffer (vm, ci0);

	  if (c0 != b0)
	    vlib_buffer_copy_trace_flag (vm, b0, ci0);

	  t = vlib_add_trace (vm, node, c0, sizeof (*t));
	  t->pt_reason = pr0;
	}

      vlib_validate_buffer_enqueue_x1 (vm, node, *next_index,
				       *to_next, *n_left_to_next, ci0, next0);

      /* replications here always go to different next-nodes
       * so there's no need to check if the to_next frame
       * is full */
    }
  *n_dispatched = *n_dispatched + n_clones0;

  /* The original buffer is the first clone */
  next0 = punt_dp_db[pr0][0];
  *to_next[0] = bi0;
  return next0;
}

always_inline u32
punt_dispatch_one (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_combined_counter_main_t * cm,
		   u32 thread_index,
		   u32 bi0,
		   u32 * next_index,
		   u32 * n_left_to_next, u32 ** to_next, u32 * n_dispatched)
{
  vlib_punt_reason_t pr0;
  vlib_buffer_t *b0;
  u32 next0;

  b0 = vlib_get_buffer (vm, bi0);
  pr0 = b0->punt_reason;

  if (PREDICT_FALSE (pr0 >= vec_len (punt_dp_db)))
    {
      b0->error = node->errors[PUNT_ERROR_NO_REASON];
      next0 = PUNT_NEXT_DROP;
    }
  else
    {
      vlib_increment_combined_counter
	(cm, thread_index, pr0, 1, vlib_buffer_length_in_chain (vm, b0));

      if (PREDICT_TRUE (1 == vec_len (punt_dp_db[pr0])))
	{
	  /*
	   * one registered client => give it the packet
	   * This is the most likely outcome.
	   */
	  next0 = punt_dp_db[pr0][0];
	  *n_dispatched = *n_dispatched + 1;
	}
      else if (0 == vec_len (punt_dp_db[pr0]))
	{
	  /* no registered clients => drop */
	  next0 = PUNT_NEXT_DROP;
	  b0->error = node->errors[PUNT_ERROR_NO_REG];
	}
      else
	{
	  /*
	   * multiple registered clients => replicate
	   */
	  next0 = punt_replicate (vm, node, thread_index, b0, bi0, pr0,
				  next_index, n_left_to_next, to_next,
				  n_dispatched);
	}
    }

  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      punt_trace_t *t;

      t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->pt_reason = pr0;
    }

  return (next0);
}

VLIB_NODE_FN (punt_dispatch_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index;
  vlib_combined_counter_main_t *cm;
  u32 n_dispatched;

  cm = &punt_counters;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  thread_index = vlib_get_thread_index ();
  n_dispatched = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 4 && n_left_to_next > 2)
	{
	  punt_next_t next0, next1;
	  u32 bi0, bi1;

	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, LOAD);
	    vlib_prefetch_buffer_header (b3, LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;

	  next0 = punt_dispatch_one (vm, node, cm, thread_index, bi0,
				     &next_index, &n_left_to_next,
				     &to_next, &n_dispatched);
	  next1 = punt_dispatch_one (vm, node, cm, thread_index, bi1,
				     &next_index, &n_left_to_next,
				     &to_next, &n_dispatched);

	  to_next += 2;
	  n_left_to_next -= 2;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  punt_next_t next0;
	  u32 bi0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = punt_dispatch_one (vm, node, cm, thread_index, bi0,
				     &next_index, &n_left_to_next,
				     &to_next, &n_dispatched);

	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PUNT_ERROR_DISPATCHED, n_dispatched);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (punt_dispatch_node) = {
  .name = "punt-dispatch",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_trace,
  .n_errors = PUNT_N_ERRORS,
  .error_strings = punt_error_strings,
  .n_next_nodes = PUNT_N_NEXT,
  .next_nodes = {
    [PUNT_NEXT_DROP] = "drop",
  },
};

/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
punt_node_init (vlib_main_t * vm)
{
  vec_validate (punt_clones, vlib_num_workers ());

  return NULL;
}

VLIB_INIT_FUNCTION (punt_node_init);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
