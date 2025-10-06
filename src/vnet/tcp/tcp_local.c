
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/tcp/tcp_local.h>

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u8 bound;
} tcp_local_rx_trace_t;

static vlib_error_desc_t tcp_error_counters[] = {
#define tcp_error(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
#include "tcp_error.def"
#undef tcp_error
};

#ifndef CLIB_MARCH_VARIANT
u8 *
format_tcp_rx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  tcp_local_rx_trace_t *t = va_arg (*args, tcp_local_rx_trace_t *);

  s = format (
    s, "TCP: src-port %d dst-port %d%s", clib_net_to_host_u16 (t->src_port),
    clib_net_to_host_u16 (t->dst_port), t->bound ? "" : " (no listener)");
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

always_inline void
tcp_dispatch_error (vlib_node_runtime_t *node, vlib_buffer_t *b, u8 is_ip4,
		    u16 *next)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u8 punt_unknown = is_ip4 ? tm->punt_unknown4 : tm->punt_unknown6;

  if (PREDICT_FALSE (punt_unknown))
    {
      b->error = node->errors[TCP_ERROR_PUNT];
      *next = TCP_LOCAL_NEXT_PUNT;
    }
  else
    {
      *next = TCP_LOCAL_NEXT_RESET;
      b->error = node->errors[TCP_ERROR_NO_LISTENER];
    }
}

always_inline uword
tcp46_local_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, int is_ip4)
{
  u32 n_left_from, *from;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u16 *next_by_dst_port =
    (is_ip4 ? tm->next_by_dst_port4 : tm->next_by_dst_port6);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      tcp_header_t *tcp0 = 0;
      u32 i0;
      int n_advance_bytes;
      int n_data_bytes;

#define LENGTH_ERROR_CHECK(condition)                                         \
  if (PREDICT_FALSE (condition))                                              \
    {                                                                         \
      b0->error = node->errors[TCP_ERROR_LENGTH];                             \
      next[0] = TCP_LOCAL_NEXT_DROP;                                          \
      goto trace_x1;                                                          \
    }

      if (is_ip4)
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	  int ip_hdr_bytes = ip4_header_bytes (ip4);
	  LENGTH_ERROR_CHECK (b0->current_length <
			      ip_hdr_bytes + sizeof (*tcp0));

	  tcp0 = ip4_next_header (ip4);
	  vnet_buffer (b0)->tcp.hdr_offset = (u8 *) tcp0 - (u8 *) ip4;
	  n_advance_bytes = (ip_hdr_bytes + tcp_header_bytes (tcp0));
	  n_data_bytes = clib_net_to_host_u16 (ip4->length) - n_advance_bytes;

	  /* Length check. Checksum computed by ipx_local no need to compute
	   * again */
	  LENGTH_ERROR_CHECK (n_data_bytes < 0);
	}
      else
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	  LENGTH_ERROR_CHECK (b0->current_data <
			      sizeof (*ip6) + sizeof (*tcp0));

	  tcp0 = ip6_next_header (ip6);
	  vnet_buffer (b0)->tcp.hdr_offset = (u8 *) tcp0 - (u8 *) ip6;
	  n_advance_bytes = tcp_header_bytes (tcp0);
	  n_data_bytes =
	    clib_net_to_host_u16 (ip6->payload_length) - n_advance_bytes;
	  n_advance_bytes += sizeof (ip6[0]);

	  LENGTH_ERROR_CHECK (n_data_bytes < 0);
	}

#undef LENGTH_ERROR_CHECK

      vnet_buffer (b0)->tcp.seq_number =
	clib_net_to_host_u32 (tcp0->seq_number);
      vnet_buffer (b0)->tcp.ack_number =
	clib_net_to_host_u32 (tcp0->ack_number);
      vnet_buffer (b0)->tcp.data_offset = n_advance_bytes;
      vnet_buffer (b0)->tcp.data_len = n_data_bytes;
      vnet_buffer (b0)->tcp.seq_end =
	vnet_buffer (b0)->tcp.seq_number + n_data_bytes;

      i0 = sparse_vec_index (next_by_dst_port, tcp0->dst_port);
      next[0] = vec_elt (next_by_dst_port, i0);

      if (PREDICT_FALSE ((i0 == SPARSE_VEC_INVALID_INDEX) ||
			 next[0] == TCP_NO_NODE_SET))
	tcp_dispatch_error (node, b0, is_ip4, next);
      else
	b0->error = node->errors[TCP_ERROR_NONE];

    trace_x1:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  tcp_local_rx_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  if (b0->error != node->errors[TCP_ERROR_LENGTH])
	    {
	      tr->src_port = tcp0->src_port;
	      tr->dst_port = tcp0->dst_port;
	      tr->bound = (next[0] != TCP_LOCAL_NEXT_RESET);
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (tcp4_local_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return tcp46_local_inline (vm, node, from_frame, 1 /* is_ip4 */);
}

VLIB_NODE_FN (tcp6_local_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return tcp46_local_inline (vm, node, from_frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (tcp4_local_node) = {
  .name = "ip4-tcp-lookup",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_counters = tcp_error_counters,

  .n_next_nodes = TCP_LOCAL_N_NEXT,
  .next_nodes = {
    [TCP_LOCAL_NEXT_DROP]= "ip4-drop",
    [TCP_LOCAL_NEXT_PUNT]= "ip4-punt",
    [TCP_LOCAL_NEXT_RESET]= "tcp4-reset",
    [TCP_LOCAL_NEXT_INPUT]= "tcp4-input",
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

VLIB_REGISTER_NODE (tcp6_local_node) = {
  .name = "ip6-tcp-lookup",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = TCP_N_ERROR,
  .error_counters = tcp_error_counters,

  .n_next_nodes = TCP_LOCAL_N_NEXT,
  .next_nodes = {
    [TCP_LOCAL_NEXT_DROP]= "ip6-drop",
    [TCP_LOCAL_NEXT_PUNT]= "ip6-punt",
    [TCP_LOCAL_NEXT_RESET]= "tcp6-reset",
    [TCP_LOCAL_NEXT_INPUT]= "tcp6-input",
  },

  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};

void
tcp_register_dst_port (vlib_main_t *vm, u16 dst_port, u32 node_index,
		       u8 is_ip4)
{
  tcp_main_t *um = vnet_get_tcp_main ();
  u16 *n;

  /* Setup tcp protocol -> next index sparse vector mapping. */
  if (is_ip4)
    n = sparse_vec_validate (um->next_by_dst_port4,
			     clib_host_to_net_u16 (dst_port));
  else
    n = sparse_vec_validate (um->next_by_dst_port6,
			     clib_host_to_net_u16 (dst_port));

  n[0] = vlib_node_add_next (
    vm, is_ip4 ? tcp4_local_node.index : tcp6_local_node.index, node_index);
}

void
tcp_unregister_dst_port (vlib_main_t *vm, u16 dst_port, u8 is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u16 *n;

  if (is_ip4)
    n = sparse_vec_validate (tm->next_by_dst_port4,
			     clib_host_to_net_u16 (dst_port));
  else
    n = sparse_vec_validate (tm->next_by_dst_port6,
			     clib_host_to_net_u16 (dst_port));

  n[0] = TCP_NO_NODE_SET;
}

u8
tcp_is_valid_dst_port (u16 dst_port, u8 is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u16 *next_by_dst_port =
    is_ip4 ? tm->next_by_dst_port4 : tm->next_by_dst_port6;
  uword index =
    sparse_vec_index (next_by_dst_port, clib_host_to_net_u16 (dst_port));
  return (index != SPARSE_VEC_INVALID_INDEX &&
	  vec_elt (next_by_dst_port, index) != TCP_NO_NODE_SET);
}

void
tcp_punt_unknown (vlib_main_t *vm, u8 is_ip4, u8 is_add)
{
  tcp_main_t *um = vnet_get_tcp_main ();

  if (is_ip4)
    um->punt_unknown4 = is_add;
  else
    um->punt_unknown6 = is_add;
}

clib_error_t *
tcp_local_init (vlib_main_t *vm)
{
  tcp_main_t *tm = vnet_get_tcp_main ();

  tm->punt_unknown4 = 0;
  tm->punt_unknown6 = 0;

  tm->next_by_dst_port4 =
    sparse_vec_new (/* elt bytes */ sizeof (tm->next_by_dst_port4[0]),
		    /* bits in index */ BITS (((tcp_header_t *) 0)->dst_port));

  tm->next_by_dst_port6 =
    sparse_vec_new (/* elt bytes */ sizeof (tm->next_by_dst_port6[0]),
		    /* bits in index */ BITS (((tcp_header_t *) 0)->dst_port));

  ip4_register_protocol (IP_PROTOCOL_TCP, tcp4_local_node.index);
  ip6_register_protocol (IP_PROTOCOL_TCP, tcp6_local_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (tcp_local_init) = {
  .runs_after = VLIB_INITS ("tcp-init"),
};
