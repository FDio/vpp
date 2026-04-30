/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppp/packet.h>
#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppox/pppd/pppd.h>

static char *pppox_error_strings[] = {
#define pppox_error(n, s) s,
#include <pppoeclient/pppox/pppox_error.def>
#undef pppox_error
};

typedef struct
{
  u32 sw_if_index;
  u32 error;
} pppox_rx_trace_t;

static u8 *
format_pppox_rx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppox_rx_trace_t *t = va_arg (*args, pppox_rx_trace_t *);

  s = format (s, "PPPoX sw_if_index %u error %u", t->sw_if_index, t->error);
  return s;
}

static uword
pppox_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 pppox_pkts = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = PPPOX_INPUT_NEXT_DROP;
	  u32 error0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  pppox_pkts++;

	  /* Consume the control packet locally via pppd shim. */
	  if (consume_pppox_ctrl_pkt (bi0, b0) != 0)
	    error0 = PPPOX_ERROR_CONTROL_PLANE_DISABLED;

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppox_rx_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->error = error0;
	    }

	  /* Route consumed buffer to error-drop so VPP graph frees it safely. */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, pppox_input_node.index, PPPOX_ERROR_TOTAL_RX_CTRL_PKTS,
			       pppox_pkts);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppox_input_node) = {
  .function = pppox_input,
  .name = "pppox-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOX_N_ERROR,
  .error_strings = pppox_error_strings,

  .n_next_nodes = PPPOX_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [PPPOX_INPUT_NEXT_##s] = n,
    foreach_pppox_input_next
#undef _
  },

  .format_trace = format_pppox_rx_trace,
};

typedef struct
{
  u32 sw_if_index;
  u32 error;
} pppox_tx_trace_t;

static u8 *
format_pppox_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppox_tx_trace_t *t = va_arg (*args, pppox_tx_trace_t *);

  s = format (s, "PPPoX sw_if_index %u error %u", t->sw_if_index, t->error);
  return s;
}

static u32 pppoeclient_output_next_index = ~0;

static_always_inline u32
pppox_get_output_next_index (vlib_main_t *vm)
{
  if (PREDICT_TRUE (pppoeclient_output_next_index != ~0))
    return pppoeclient_output_next_index;

  /* vlib_node_add_next() must run on the main thread; worker threads can
   * observe the cached result but should never try to extend the graph. */
  if (PREDICT_FALSE (vlib_get_thread_index () != 0))
    return PPPOX_OUTPUT_NEXT_DROP;

  vlib_node_t *next = vlib_get_node_by_name (vm, (u8 *) "pppoeclient-session-output");
  if (next)
    pppoeclient_output_next_index = vlib_node_add_next (vm, pppox_output_node.index, next->index);
  else
    pppoeclient_output_next_index = PPPOX_OUTPUT_NEXT_DROP;

  return pppoeclient_output_next_index;
}

static uword
pppox_output (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  pppox_main_t *pom = &pppox_main;
  vnet_main_t *vnm = pom->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 pkts_encapsulated = 0;
  u32 thread_index = vlib_get_thread_index ();
  u32 stats_pppox_sw_if_index, stats_n_packets, stats_n_bytes;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = pppox_get_output_next_index (vm);
  stats_pppox_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 pppox_sw_if_index0, pppox_sw_if_index1, len0, len1;

	  next0 = next1 = pppox_get_output_next_index (vm);

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

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

	  /* 1-wide cache? */
	  pppox_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  pppox_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  pkts_encapsulated += 2;
	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  stats_n_packets += 2;
	  stats_n_bytes += len0 + len1;

	  if (PREDICT_FALSE ((pppox_sw_if_index0 != stats_pppox_sw_if_index) ||
			     (pppox_sw_if_index1 != stats_pppox_sw_if_index)))
	    {
	      stats_n_packets -= 2;
	      stats_n_bytes -= len0 + len1;
	      if (pppox_sw_if_index0 == pppox_sw_if_index1)
		{
		  if (stats_n_packets)
		    vlib_increment_combined_counter (
		      im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX, thread_index,
		      stats_pppox_sw_if_index, stats_n_packets, stats_n_bytes);
		  stats_pppox_sw_if_index = pppox_sw_if_index0;
		  stats_n_packets = 2;
		  stats_n_bytes = len0 + len1;
		}
	      else
		{
		  vlib_increment_combined_counter (im->combined_sw_if_counters +
						     VNET_INTERFACE_COUNTER_TX,
						   thread_index, pppox_sw_if_index0, 1, len0);
		  vlib_increment_combined_counter (im->combined_sw_if_counters +
						     VNET_INTERFACE_COUNTER_TX,
						   thread_index, pppox_sw_if_index1, 1, len1);
		}
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppox_tx_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->sw_if_index = pppox_sw_if_index0;
	      tr->error = 0;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppox_tx_trace_t *tr = vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->sw_if_index = pppox_sw_if_index1;
	      tr->error = 0;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = pppox_get_output_next_index (vm);
	  u32 pppox_sw_if_index0, len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* 1-wide cache? */
	  pppox_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  pkts_encapsulated++;
	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  if (PREDICT_FALSE (pppox_sw_if_index0 != stats_pppox_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (
		  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX, thread_index,
		  stats_pppox_sw_if_index, stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_pppox_sw_if_index = pppox_sw_if_index0;
	    }
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppox_tx_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->sw_if_index = pppox_sw_if_index0;
	      tr->error = 0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, PPPOX_ERROR_TOTAL_TX_PKTS, pkts_encapsulated);
  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
				       thread_index, stats_pppox_sw_if_index, stats_n_packets,
				       stats_n_bytes);
      node->runtime_data[0] = stats_pppox_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppox_output_node) = {
  .function = pppox_output,
  .name = "pppox-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pppox_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pppox_error_strings),
  .error_strings = pppox_error_strings,

  .n_next_nodes = PPPOX_OUTPUT_N_NEXT,

  .next_nodes = {
#define _(s, n) [PPPOX_OUTPUT_NEXT_##s] = n,
    foreach_pppox_output_next
#undef _
  },
};

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
