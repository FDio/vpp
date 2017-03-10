/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>

#include <vnet/span/span.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t span_node;

/* packet trace format function */
u8 *
format_span_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  span_trace_t *t = va_arg (*args, span_trace_t *);

  vnet_main_t *vnm = &vnet_main;
  s = format (s, "SPAN: mirrored %U -> %U",
	      format_vnet_sw_if_index_name, vnm, t->src_sw_if_index,
	      format_vnet_sw_if_index_name, vnm, t->mirror_sw_if_index);

  return s;
}

#define foreach_span_error                      \
_(HITS, "SPAN incomming packets processed")

typedef enum
{
#define _(sym,str) SPAN_ERROR_##sym,
  foreach_span_error
#undef _
    SPAN_N_ERROR,
} span_error_t;

static char *span_error_strings[] = {
#define _(sym,string) string,
  foreach_span_error
#undef _
};

static_always_inline void
span_mirror (vlib_main_t * vm, vlib_node_runtime_t * node, u32 sw_if_index0,
	     vlib_buffer_t * b0, vlib_frame_t ** mirror_frames, int is_rx)
{
  vlib_buffer_t *c0;
  span_main_t *sm = &span_main;
  vnet_main_t *vnm = &vnet_main;
  span_interface_t *si0 = 0;
  u32 *to_mirror_next = 0;
  u32 i;

  si0 = vec_elt_at_index (sm->interfaces, sw_if_index0);

  if (is_rx != 0 && si0->num_rx_mirror_ports == 0)
    return;

  if (is_rx == 0 && si0->num_tx_mirror_ports == 0)
    return;

  /* Don't do it again */
  if (PREDICT_FALSE (b0->flags & VNET_BUFFER_SPAN_CLONE))
    return;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, is_rx ? si0->rx_mirror_ports : si0->tx_mirror_ports, (
    {
      if (mirror_frames[i] == 0)
	mirror_frames[i] = vnet_get_frame_to_sw_interface (vnm, i);
      to_mirror_next = vlib_frame_vector_args (mirror_frames[i]);
      to_mirror_next += mirror_frames[i]->n_vectors;
      /* This can fail */
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE(c0 != 0))
        {
          vnet_buffer (c0)->sw_if_index[VLIB_TX] = i;
          c0->flags |= VNET_BUFFER_SPAN_CLONE;
          to_mirror_next[0] = vlib_get_buffer_index (vm, c0);
          mirror_frames[i]->n_vectors++;
          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->src_sw_if_index = sw_if_index0;
              t->mirror_sw_if_index = i;
            }
        }
    }));
  /* *INDENT-ON* */
}

static_always_inline uword
span_node_inline_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame, int is_rx)
{
  span_main_t *sm = &span_main;
  vnet_main_t *vnm = &vnet_main;
  u32 n_left_from, *from, *to_next;
  u32 n_span_packets = 0;
  u32 next_index;
  u32 sw_if_index;
  static __thread vlib_frame_t **mirror_frames = 0;
  vlib_rx_or_tx_t rxtx = is_rx ? VLIB_RX : VLIB_TX;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vec_validate_aligned (mirror_frames, sm->max_sw_if_index,
			CLIB_CACHE_LINE_BYTES);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0;
	  u32 bi1;
	  vlib_buffer_t *b0;
	  vlib_buffer_t *b1;
	  u32 sw_if_index0;
	  u32 next0 = 0;
	  u32 sw_if_index1;
	  u32 next1 = 0;

	  /* speculatively enqueue b0, b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next += 2;
	  n_left_to_next -= 2;
	  from += 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[rxtx];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[rxtx];

	  span_mirror (vm, node, sw_if_index0, b0, mirror_frames, is_rx);
	  span_mirror (vm, node, sw_if_index1, b1, mirror_frames, is_rx);

	  vnet_feature_next (sw_if_index0, &next0, b0);
	  vnet_feature_next (sw_if_index1, &next1, b1);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  u32 next0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[rxtx];

	  span_mirror (vm, node, sw_if_index0, b0, mirror_frames, is_rx);

	  vnet_feature_next (sw_if_index0, &next0, b0);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }


  for (sw_if_index = 0; sw_if_index < vec_len (mirror_frames); sw_if_index++)
    {
      if (mirror_frames[sw_if_index] == 0)
	continue;

      vnet_put_frame_to_sw_interface (vnm, sw_if_index,
				      mirror_frames[sw_if_index]);
      mirror_frames[sw_if_index] = 0;
    }
  vlib_node_increment_counter (vm, span_node.index, SPAN_ERROR_HITS,
			       n_span_packets);

  return frame->n_vectors;
}

static uword
span_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, 1);
}

static uword
span_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (span_input_node) = {
  .function = span_input_node_fn,
  .name = "span-input",
  .vector_size = sizeof (u32),
  .format_trace = format_span_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(span_error_strings),
  .error_strings = span_error_strings,

  .n_next_nodes = 0,

  /* edit / add dispositions here */
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (span_input_node, span_input_node_fn)

VLIB_REGISTER_NODE (span_output_node) = {
  .function = span_output_node_fn,
  .name = "span-output",
  .vector_size = sizeof (u32),
  .format_trace = format_span_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(span_error_strings),
  .error_strings = span_error_strings,

  .n_next_nodes = 0,

  /* edit / add dispositions here */
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (span_output_node, span_output_node_fn)

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
