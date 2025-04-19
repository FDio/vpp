/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vnet/udp/udp.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

#define udp_node_index(node_id, is_ip4)                                       \
  ((is_ip4) ? udp4_##node_id##_node.index : udp6_##node_id##_node.index)

typedef enum udp_output_next_
{
  UDP_OUTPUT_NEXT_DROP,
  UDP_OUTPUT_NEXT_IP_LOOKUP,
  UDP_OUTPUT_N_NEXT
} udp_output_next_t;

#define foreach_udp4_output_next                                              \
  _ (DROP, "error-drop")                                                      \
  _ (IP_LOOKUP, "ip4-lookup")

#define foreach_udp6_output_next                                              \
  _ (DROP, "error-drop")                                                      \
  _ (IP_LOOKUP, "ip6-lookup")

static vlib_error_desc_t udp_output_error_counters[] = {
#define udp_error(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
#include <vnet/udp/udp_error.def>
#undef udp_error
};

typedef struct udp_tx_trace_
{
  udp_header_t udp_header;
  udp_connection_t udp_connection;
} udp_tx_trace_t;

static u8 *
format_udp_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_tx_trace_t *t = va_arg (*args, udp_tx_trace_t *);
  udp_connection_t *uc = &t->udp_connection;
  u32 indent = format_get_indent (s);

  s = format (s, "%U\n%U%U", format_udp_connection, uc, 1, format_white_space,
	      indent, format_udp_header, &t->udp_header, 128);

  return s;
}

always_inline udp_connection_t *
udp_output_get_connection (vlib_buffer_t *b, clib_thread_index_t thread_index)
{
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.flags & UDP_CONN_F_LISTEN))
    return udp_listener_get (vnet_buffer (b)->tcp.connection_index);

  return udp_connection_get (vnet_buffer (b)->tcp.connection_index,
			     thread_index);
}

static void
udp46_output_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
			  u32 *to_next, u32 n_bufs)
{
  udp_connection_t *uc;
  udp_tx_trace_t *t;
  vlib_buffer_t *b;
  udp_header_t *uh;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      b = vlib_get_buffer (vm, to_next[i]);
      if (!(b->flags & VLIB_BUFFER_IS_TRACED))
	continue;
      uh = vlib_buffer_get_current (b);
      uc = udp_output_get_connection (b, vm->thread_index);
      t = vlib_add_trace (vm, node, b, sizeof (*t));
      clib_memcpy_fast (&t->udp_header, uh, sizeof (t->udp_header));
      clib_memcpy_fast (&t->udp_connection, uc, sizeof (t->udp_connection));
    }
}

always_inline void
udp_output_handle_packet (udp_connection_t *uc0, vlib_buffer_t *b0,
			  vlib_node_runtime_t *error_node, u16 *next0,
			  u8 is_ip4)
{
  /* If next_index is not drop use it */
  if (uc0->next_node_index)
    {
      *next0 = uc0->next_node_index;
      vnet_buffer (b0)->tcp.next_node_opaque = uc0->next_node_opaque;
    }
  else
    {
      *next0 = UDP_OUTPUT_NEXT_IP_LOOKUP;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = uc0->c_fib_index;
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = uc0->sw_if_index;
}

always_inline uword
udp46_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, int is_ip4)
{
  u32 n_left_from, *from, thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    udp46_output_trace_frame (vm, node, from, n_left_from);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      udp_connection_t *uc0, *uc1;

      vlib_prefetch_buffer_header (b[2], STORE);
      CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

      vlib_prefetch_buffer_header (b[3], STORE);
      CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

      uc0 = udp_output_get_connection (b[0], thread_index);
      uc1 = udp_output_get_connection (b[1], thread_index);

      if (PREDICT_TRUE (!uc0 + !uc1 == 0))
	{
	  udp_output_handle_packet (uc0, b[0], node, &next[0], is_ip4);
	  udp_output_handle_packet (uc1, b[1], node, &next[1], is_ip4);
	}
      else
	{
	  if (uc0 != 0)
	    {
	      udp_output_handle_packet (uc0, b[0], node, &next[0], is_ip4);
	    }
	  else
	    {
	      b[0]->error = node->errors[UDP_ERROR_INVALID_CONNECTION];
	      next[0] = UDP_OUTPUT_NEXT_DROP;
	    }
	  if (uc1 != 0)
	    {
	      udp_output_handle_packet (uc1, b[1], node, &next[1], is_ip4);
	    }
	  else
	    {
	      b[1]->error = node->errors[UDP_ERROR_INVALID_CONNECTION];
	      next[1] = UDP_OUTPUT_NEXT_DROP;
	    }
	}

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      udp_connection_t *uc0;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	}

      uc0 = udp_output_get_connection (b[0], thread_index);

      if (PREDICT_TRUE (uc0 != 0))
	{
	  udp_output_handle_packet (uc0, b[0], node, &next[0], is_ip4);
	}
      else
	{
	  b[0]->error = node->errors[UDP_ERROR_INVALID_CONNECTION];
	  next[0] = UDP_OUTPUT_NEXT_DROP;
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, udp_node_index (output, is_ip4),
			       UDP_ERROR_PKTS_SENT, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (udp4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return udp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

VLIB_NODE_FN (udp6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return udp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (udp4_output_node) =
{
  .name = "udp4-output",
  .vector_size = sizeof (u32),
  .n_errors = UDP_N_ERROR,
  .protocol_hint = VLIB_NODE_PROTO_HINT_UDP,
  .error_counters = udp_output_error_counters,
  .n_next_nodes = UDP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_OUTPUT_NEXT_##s] = n,
    foreach_udp4_output_next
#undef _
  },
  .format_buffer = format_udp_header,
  .format_trace = format_udp_tx_trace,
};

VLIB_REGISTER_NODE (udp6_output_node) =
{
  .name = "udp6-output",
  .vector_size = sizeof (u32),
  .n_errors = UDP_N_ERROR,
  .protocol_hint = VLIB_NODE_PROTO_HINT_UDP,
  .error_counters = udp_output_error_counters,
  .n_next_nodes = UDP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_OUTPUT_NEXT_##s] = n,
    foreach_udp6_output_next
#undef _
  },
  .format_buffer = format_udp_header,
  .format_trace = format_udp_tx_trace,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
