/*
 * node.c: p2p ethernet vpp node
 *
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

#include <vnet/ethernet/p2p_ethernet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t p2p_ethernet_input_node;

/* packet trace format function */
u8 *
format_p2p_ethernet_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  p2p_ethernet_trace_t *t = va_arg (*args, p2p_ethernet_trace_t *);

  vnet_main_t *vnm = &vnet_main;
  s = format (s, "P2P ethernet: %U -> %U",
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      format_vnet_sw_if_index_name, vnm, t->p2pe_sw_if_index);

  return s;
}

#define foreach_p2p_ethernet_error                      \
_(HITS, "P2P ethernet incoming packets processed")

typedef enum
{
#define _(sym,str) P2PE_ERROR_##sym,
  foreach_p2p_ethernet_error
#undef _
    P2PE_N_ERROR,
} p2p_ethernet_error_t;

static char *p2p_ethernet_error_strings[] = {
#define _(sym,string) string,
  foreach_p2p_ethernet_error
#undef _
};

static uword
p2p_ethernet_input_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 thread_index = vlib_get_thread_index ();
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 n_p2p_ethernet_packets = 0;
  vlib_combined_counter_main_t *cm =
    vnet_get_main ()->interface_main.combined_sw_if_counters;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0 = 0, next1 = 0;
	  u32 sw_if_index0, sw_if_index1;
	  ethernet_header_t *en0, *en1;
	  u32 rx0, rx1;

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  en0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  en1 = vlib_buffer_get_current (b1);
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  vnet_feature_next (sw_if_index0, &next0, b0);
	  vnet_feature_next (sw_if_index1, &next1, b1);

	  rx0 = p2p_ethernet_lookup (sw_if_index0, en0->src_address);
	  rx1 = p2p_ethernet_lookup (sw_if_index1, en1->src_address);

	  if (rx0 != ~0)
	    {
	      /* Send pkt to p2p_ethernet RX interface */
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = rx0;
	      n_p2p_ethernet_packets += 1;

	      if (PREDICT_FALSE (n_trace > 0))
		{
		  p2p_ethernet_trace_t *t0;
		  vlib_trace_buffer (vm, node, next_index, b0,
				     1 /* follow_chain */ );
		  vlib_set_trace_count (vm, node, --n_trace);
		  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
		  t0->sw_if_index = sw_if_index0;
		  t0->p2pe_sw_if_index = rx0;
		}

	      vlib_increment_combined_counter (cm, thread_index, rx0, 1,
					       vlib_buffer_length_in_chain
					       (vm, b0));
	    }
	  if (rx1 != ~0)
	    {
	      /* Send pkt to p2p_ethernet RX interface */
	      vnet_buffer (b1)->sw_if_index[VLIB_RX] = rx1;
	      n_p2p_ethernet_packets += 1;

	      if (PREDICT_FALSE (n_trace > 0))
		{
		  p2p_ethernet_trace_t *t1;
		  vlib_trace_buffer (vm, node, next_index, b1,
				     1 /* follow_chain */ );
		  vlib_set_trace_count (vm, node, --n_trace);
		  t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
		  t1->sw_if_index = sw_if_index1;
		  t1->p2pe_sw_if_index = rx1;
		}

	      vlib_increment_combined_counter (cm, thread_index, rx1, 1,
					       vlib_buffer_length_in_chain
					       (vm, b1));
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi1, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = 0;
	  u32 sw_if_index0;
	  ethernet_header_t *en0;
	  u32 rx0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  en0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  vnet_feature_next (sw_if_index0, &next0, b0);

	  rx0 = p2p_ethernet_lookup (sw_if_index0, en0->src_address);
	  if (rx0 != ~0)
	    {
	      /* Send pkt to p2p_ethernet RX interface */
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = rx0;
	      n_p2p_ethernet_packets += 1;

	      if (PREDICT_FALSE (n_trace > 0))
		{
		  p2p_ethernet_trace_t *t0;
		  vlib_trace_buffer (vm, node, next_index, b0,
				     1 /* follow_chain */ );
		  vlib_set_trace_count (vm, node, --n_trace);
		  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
		  t0->sw_if_index = sw_if_index0;
		  t0->p2pe_sw_if_index = rx0;
		}

	      vlib_increment_combined_counter (cm, thread_index, rx0, 1,
					       vlib_buffer_length_in_chain
					       (vm, b0));
	    }
	  else
	    {
	      if (PREDICT_FALSE (n_trace > 0))
		{
		  node->flags |= VLIB_NODE_FLAG_TRACE;
		}
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, p2p_ethernet_input_node.index,
			       P2PE_ERROR_HITS, n_p2p_ethernet_packets);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (p2p_ethernet_input_node) = {
  .function = p2p_ethernet_input_node_fn,
  .name = "p2p-ethernet-input",
  .vector_size = sizeof (u32),
  .format_trace = format_p2p_ethernet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(p2p_ethernet_error_strings),
  .error_strings = p2p_ethernet_error_strings,

  .n_next_nodes = 1,

  /* edit / add dispositions here */
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (p2p_ethernet_input_node,
			      p2p_ethernet_input_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
