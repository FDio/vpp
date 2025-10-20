/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/error.h>
#include <vnet/buffer.h>
#include <vnet/feature/feature.h>
#include <soft-rss/soft_rss.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} soft_rss_trace_t;

static u8 *
format_soft_rss_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  soft_rss_trace_t *t = va_arg (*args, soft_rss_trace_t *);

  s = format (s, "soft-rss: sw_if_index %u, next %u", t->sw_if_index,
	      t->next_index);
  return s;
}

#define foreach_soft_rss_error _ (PROCESSED, "Packets processed by soft-rss")

typedef enum
{
#define _(sym, str) SOFT_RSS_ERROR_##sym,
  foreach_soft_rss_error
#undef _
    SOFT_RSS_N_ERROR,
} soft_rss_error_t;

static char *soft_rss_error_strings[] = {
#define _(sym, str) str,
  foreach_soft_rss_error
#undef _
};

static_always_inline uword
soft_rss_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, int trace)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  u32 packets_processed = 0;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 *to_next;
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  u32 next0 = next_index;

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  /* TODO: add software RSS steering or other per-packet logic here. */

	  vnet_feature_next (&next0, b0);

	  if (trace && PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      soft_rss_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  packets_processed++;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (packets_processed)
    vlib_node_increment_counter (vm, node->node_index,
				 SOFT_RSS_ERROR_PROCESSED, packets_processed);

  return frame->n_vectors;
}

VLIB_NODE_FN (soft_rss_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return soft_rss_node_inline (vm, node, frame, 1);

  return soft_rss_node_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (soft_rss_node) = {
  .name = "soft-rss",
  .vector_size = sizeof (u32),
  .format_trace = format_soft_rss_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (soft_rss_error_strings),
  .error_strings = soft_rss_error_strings,
};
