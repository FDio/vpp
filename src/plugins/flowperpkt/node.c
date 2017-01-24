/*
 * node.c - ipfix-per-packet graph node
 *
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <flowperpkt/flowperpkt.h>

/**
 * @file flow record generator graph node
 */

typedef struct
{
  /** interface handle */
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  /** packet timestamp */
  u64 timestamp;
  /** size of the buffer */
  u16 buffer_size;
  flowperpkt_variant_t which;
} flowperpkt_trace_t;

/* packet trace format function */
static u8 *
format_flowperpkt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowperpkt_trace_t *t = va_arg (*args, flowperpkt_trace_t *);
  s = format (s,
	      "FLOWPERPKT (%d): rx_sw_if_index %d, tx_sw_if_index %d, "
	      "timestamp %lld, size %d", t->which,
	      t->rx_sw_if_index, t->tx_sw_if_index,
	      t->timestamp, t->buffer_size);
  return s;
}

vlib_node_registration_t flowperpkt_ip4_node;
vlib_node_registration_t flowperpkt_ip6_node;
vlib_node_registration_t flowperpkt_l2_node;

/* No counters at the moment */
#define foreach_flowperpkt_error

typedef enum
{
#define _(sym,str) FLOWPERPKT_ERROR_##sym,
  foreach_flowperpkt_error
#undef _
    FLOWPERPKT_N_ERROR,
} flowperpkt_error_t;

static char *flowperpkt_error_strings[] = {
#define _(sym,string) string,
  foreach_flowperpkt_error
#undef _
};

typedef enum
{
  FLOWPERPKT_NEXT_DROP,
  FLOWPERPKT_NEXT_IP4_LOOKUP,
  FLOWPERPKT_N_NEXT,
} flowperpkt_next_t;

#define FLOWPERPKT_NEXT_NODES {					\
    [FLOWPERPKT_NEXT_DROP] = "error-drop",			\
    [FLOWPERPKT_NEXT_IP4_LOOKUP] = "ip4-lookup",		\
}

static inline flowperpkt_variant_t
flowperpkt_get_variant (flowperpkt_variant_t which,
			flowperpkt_record_t flags, u16 ethertype)
{
  if (which == FLOW_VARIANT_L2 && flags & FLOW_RECORD_L3)
    return ethertype == ETHERNET_TYPE_IP6 ?
      FLOW_VARIANT_L2_IP6 : ethertype == ETHERNET_TYPE_IP4 ?
      FLOW_VARIANT_L2_IP4 : FLOW_VARIANT_L2;
  return which;
}

uword
flowperpkt_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame,
		    flowperpkt_variant_t which)
{
  u32 n_left_from, *from, *to_next;
  flowperpkt_next_t next_index;
  flowperpkt_main_t *fm = &flowperpkt_main;
  u64 now;

  now = (u64) ((vlib_time_now (vm) - fm->vlib_time_0) * 1e9);
  now += fm->nanosecond_time_0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = FLOWPERPKT_NEXT_DROP;
	  u32 next1 = FLOWPERPKT_NEXT_DROP;
	  u16 len0, len1;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_TX],
			     &next0, b0);
	  vnet_feature_next (vnet_buffer (b1)->sw_if_index[VLIB_TX],
			     &next1, b1);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b0, now, len0, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype0));

	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);

	  if (PREDICT_TRUE ((b1->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b1, now, len1, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype1));

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  flowperpkt_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
		  t->tx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
		  t->timestamp = now;
		  t->buffer_size = len0;
		  t->which = which;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  flowperpkt_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->rx_sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
		  t->tx_sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
		  t->timestamp = now;
		  t->buffer_size = len1;
		  t->which = which;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = FLOWPERPKT_NEXT_DROP;
	  u16 len0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_TX],
			     &next0, b0);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_FLOW_REPORT) == 0))
	    add_to_flow_record (vm, node, fm, b0, now, len0, 0 /* flush */ ,
				flowperpkt_get_variant
				(which, fm->context[which].flags,
				 ethertype0));

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      flowperpkt_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->tx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->timestamp = now;
	      t->buffer_size = len0;
	      t->which = which;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
flowperpkt_ip4_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_IP4);
}

static uword
flowperpkt_ip6_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_IP6);
}

static uword
flowperpkt_l2_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return flowperpkt_node_fn (vm, node, frame, FLOW_VARIANT_L2);
}

void
flowperpkt_flush_callback_ip4 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_ip4_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_IP4);
}

void
flowperpkt_flush_callback_ip6 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_ip6_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_IP6);
}

void
flowperpkt_flush_callback_l2 (void)
{
  vlib_main_t *vm = vlib_get_main ();
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_node_runtime_t *node;
  node = vlib_node_get_runtime (vm, flowperpkt_l2_node.index);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2_IP4);

  add_to_flow_record (vm, node, fm, 0 /* data_b */ ,
		      0ULL /* timestamp */ ,
		      0 /* length */ ,
		      1 /* do_flush */ ,
		      FLOW_VARIANT_L2_IP6);

}

/**
 * @brief IPFIX ip4 flow-per-packet graph node
 * @node flowperpkt-ip4
 *
 * This is the IPFIX flow-record-per-packet node.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * <em>Uses:</em>
 * - <code>vnet_buffer(b)->ip.save_rewrite_length</code>
 *     - tells the node the length of the rewrite which was applied in
 *       ip4/6_rewrite_inline, allows the code to find the IP header without
 *       having to parse L2 headers, or make stupid assumptions about their
 *       length.
 * - <code>vnet_buffer(b)->flags & VLIB_BUFFER_FLOW_REPORT</code>
 *     - Used to suppress flow record generation for flow record packets.
 *
 * <em>Sets:</em>
 * - <code>vnet_buffer(b)->flags & VLIB_BUFFER_FLOW_REPORT</code>
 *     - To suppress flow record generation for flow record packets
 *
 * <em>Next Index:</em>
 * - Next configured output feature on the interface, usually
 *   "interface-output." Generated flow records head for ip4-lookup
 */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowperpkt_ip4_node) = {
  .function = flowperpkt_ip4_node_fn,
  .name = "flowperpkt-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowperpkt_ip6_node) = {
  .function = flowperpkt_ip6_node_fn,
  .name = "flowperpkt-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
VLIB_REGISTER_NODE (flowperpkt_l2_node) = {
  .function = flowperpkt_l2_node_fn,
  .name = "flowperpkt-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_flowperpkt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowperpkt_error_strings),
  .error_strings = flowperpkt_error_strings,
  .n_next_nodes = FLOWPERPKT_N_NEXT,
  .next_nodes = FLOWPERPKT_NEXT_NODES,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
