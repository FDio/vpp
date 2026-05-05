/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <hsi/hsi.h>
#include <hsi/hsi_tracker.h>
#include <vnet/tcp/tcp_types.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/udp/udp.h>

hsi_main_t hsi_main;

static inline u8
hsi_intercept_proto_flag (transport_proto_t proto, u8 is_ip4)
{
  /* This leverages the fact that TCP is 0 and UDP is 1 */
  return (1 << (proto << 1 | is_ip4));
}

static inline u8
hsi_have_intercept_proto (transport_proto_t proto, u8 is_ip4)
{
  return (hsi_main.intercept_type & hsi_intercept_proto_flag (proto, is_ip4));
}

char *hsi_error_strings[] = {
#define hsi_error(n, s) s,
#include <hsi/hsi_error.def>
#undef hsi_error
};

typedef enum hsi_input_next_
{
  HSI_INPUT_NEXT_UDP_INPUT,
  HSI_INPUT_NEXT_UDP_INPUT_NOLOOKUP,
  HSI_INPUT_NEXT_TCP_INPUT,
  HSI_INPUT_NEXT_TCP_INPUT_NOLOOKUP,
  HSI_INPUT_NEXT_TCP_LISTEN,
  HSI_INPUT_NEXT_IP_LOOKUP,
  HSI_INPUT_NEXT_DROP,
  HSI_INPUT_N_NEXT
} hsi_input_next_t;

typedef enum hsi_lookup_result_
{
  HSI_LOOKUP_RESULT_PASS,
  HSI_LOOKUP_RESULT_INTERCEPT,
  HSI_LOOKUP_RESULT_TRACK,
  HSI_LOOKUP_RESULT_HELD,
} hsi_lookup_result_t;

always_inline hsi_lookup_result_t
hsi_tracked_action_to_lookup_result (hsi_tracked_action_t action, u32 *next)
{
  switch (action)
    {
    case HSI_TRACKED_ACTION_FORWARD:
      *next = HSI_INPUT_NEXT_IP_LOOKUP;
      return HSI_LOOKUP_RESULT_TRACK;
    case HSI_TRACKED_ACTION_DROP:
      *next = HSI_INPUT_NEXT_DROP;
      return HSI_LOOKUP_RESULT_INTERCEPT;
    case HSI_TRACKED_ACTION_HELD:
      return HSI_LOOKUP_RESULT_HELD;
    }

  ASSERT (0);
  *next = HSI_INPUT_NEXT_DROP;
  return HSI_LOOKUP_RESULT_INTERCEPT;
}

always_inline hsi_lookup_result_t
hsi_drain_cache_action_to_lookup_result (hsi_tracked_action_t action, u32 *next)
{
  switch (action)
    {
    case HSI_TRACKED_ACTION_HELD:
      return HSI_LOOKUP_RESULT_HELD;
    case HSI_TRACKED_ACTION_DROP:
      *next = HSI_INPUT_NEXT_DROP;
      return HSI_LOOKUP_RESULT_INTERCEPT;
    default:
      ASSERT (0);
      *next = HSI_INPUT_NEXT_DROP;
      return HSI_LOOKUP_RESULT_INTERCEPT;
    }
}

#define foreach_hsi4_input_next                                                                    \
  _ (UDP_INPUT, "udp4-input")                                                                      \
  _ (UDP_INPUT_NOLOOKUP, "udp4-input-nolookup")                                                    \
  _ (TCP_INPUT, "tcp4-input")                                                                      \
  _ (TCP_INPUT_NOLOOKUP, "tcp4-input-nolookup")                                                    \
  _ (TCP_LISTEN, "tcp4-listen")                                                                    \
  _ (IP_LOOKUP, "ip4-lookup")                                                                      \
  _ (DROP, "error-drop")

#define foreach_hsi6_input_next                                                                    \
  _ (UDP_INPUT, "udp6-input")                                                                      \
  _ (UDP_INPUT_NOLOOKUP, "udp6-input-nolookup")                                                    \
  _ (TCP_INPUT, "tcp6-input")                                                                      \
  _ (TCP_INPUT_NOLOOKUP, "tcp6-input-nolookup")                                                    \
  _ (TCP_LISTEN, "tcp6-listen")                                                                    \
  _ (IP_LOOKUP, "ip6-lookup")                                                                      \
  _ (DROP, "error-drop")

typedef struct
{
  u32 next_node;
} hsi_trace_t;

static u8 *
format_hsi_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  hsi_trace_t *t = va_arg (*args, hsi_trace_t *);
  vlib_node_t *nn;

  nn = vlib_get_next_node (vm, node->index, t->next_node);
  s = format (s, "session %sfound, next node: %v", t->next_node < HSI_INPUT_N_NEXT ? "" : "not ",
	      nn->name);
  return s;
}

always_inline session_t *
hsi_udp_lookup (vlib_buffer_t *b, void *ip_hdr, udp_header_t **rhdr, u8 is_ip4)
{
  udp_header_t *hdr;
  session_t *s;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
      *rhdr = hdr = ip4_next_header (ip4);
      s = session_lookup_safe4 (vnet_buffer (b)->ip.fib_index, &ip4->dst_address, &ip4->src_address,
				hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_UDP);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      *rhdr = hdr = ip6_next_header (ip6);
      s = session_lookup_safe6 (vnet_buffer (b)->ip.fib_index, &ip6->dst_address, &ip6->src_address,
				hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_UDP);
    }

  return s;
}

always_inline transport_connection_t *
hsi_tcp_lookup (vlib_main_t *vm, vlib_buffer_t *b, void *ip_hdr, tcp_header_t **rhdr, u8 is_ip4)
{
  transport_connection_t *tc;
  tcp_header_t *hdr;
  u8 result = 0;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
      *rhdr = hdr = ip4_next_header (ip4);
      tc = session_lookup_connection_wt4 (vnet_buffer (b)->ip.fib_index, &ip4->dst_address,
					  &ip4->src_address, hdr->dst_port, hdr->src_port,
					  TRANSPORT_PROTO_TCP, vm->thread_index, &result);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      *rhdr = hdr = ip6_next_header (ip6);
      tc = session_lookup_connection_wt6 (vnet_buffer (b)->ip.fib_index, &ip6->dst_address,
					  &ip6->src_address, hdr->dst_port, hdr->src_port,
					  TRANSPORT_PROTO_TCP, vm->thread_index, &result);
    }

  return result == 0 ? tc : 0;
}

always_inline hsi_lookup_result_t
hsi_tcp_lookup_handler (vlib_main_t *vm, vlib_buffer_t *b, void *ip_hdr, u32 *next, u8 is_ip4,
			u8 is_input)
{
  tcp_header_t *tcp_hdr = 0;
  tcp_connection_t *tc;
  tcp_state_t state;

  tc = (tcp_connection_t *) hsi_tcp_lookup (vm, b, ip_hdr, &tcp_hdr, is_ip4);
  if (!tc)
    {
      u32 error = 0;

      if (!hsi_have_intercept_proto (TRANSPORT_PROTO_TCP, is_ip4) || !tcp_syn (tcp_hdr))
	{
	  vnet_feature_next (next, b);
	  return HSI_LOOKUP_RESULT_PASS;
	}

      /* force parsing of buffer in preparation for tcp-listen */
      tcp_input_lookup_buffer (b, vm->thread_index, &error, is_ip4, 1 /* is_nolookup*/);
      if (error)
	{
	  vnet_feature_next (next, b);
	  return HSI_LOOKUP_RESULT_PASS;
	}

      vnet_buffer (b)->tcp.connection_index =
	hsi_main.intercept_listeners[!is_ip4][TRANSPORT_PROTO_TCP];
      vnet_buffer (b)->tcp.flags = TCP_STATE_LISTEN;

      *next = HSI_INPUT_NEXT_TCP_LISTEN;
      return HSI_LOOKUP_RESULT_INTERCEPT;
    }

  state = tc->state;
  if (state == TCP_STATE_LISTEN)
    {
      /* Avoid processing non syn packets that match listener */
      if (!tcp_syn (tcp_hdr))
	{
	  vnet_feature_next (next, b);
	  return HSI_LOOKUP_RESULT_PASS;
	}
      *next = HSI_INPUT_NEXT_TCP_INPUT;
    }
  else if (state == TCP_STATE_SYN_SENT)
    {
      *next = HSI_INPUT_NEXT_TCP_INPUT;
    }
  else
    {
      if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_TRACKED))
	{
	  hsi_tcp_tracked_action_t action;

	  if (!is_input && tc->state != TCP_STATE_CLOSED)
	    {
	      vnet_feature_next (next, b);
	      return HSI_LOOKUP_RESULT_PASS;
	    }

	  action = hsi_tcp_tracked_connection_action (vm, b, tc, ip_hdr, tcp_hdr, is_ip4);
	  return hsi_tracked_action_to_lookup_result (action, next);
	}
      /* Lookup already done, use result */
      *next = HSI_INPUT_NEXT_TCP_INPUT_NOLOOKUP;
      vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
    }

  return HSI_LOOKUP_RESULT_INTERCEPT;
}

always_inline hsi_lookup_result_t
hsi_udp_tracked_lookup_handler (vlib_main_t *vm, vlib_buffer_t *b, session_t *s,
				udp_connection_t *uc, void *ip_hdr, udp_header_t *udp_hdr,
				u32 *next, u8 is_ip4, u8 is_input)
{
  hsi_udp_tracked_action_t action;

  if (uc->c_thread_index != vm->thread_index)
    {
      if (hsi_udp_connection_is_draining (uc))
	{
	  if (!is_input)
	    {
	      vnet_feature_next (next, b);
	      return HSI_LOOKUP_RESULT_PASS;
	    }

	  action = hsi_udp_drain_cache_buffer_remote (vm, b, s, uc, ip_hdr, udp_hdr, is_ip4);
	  return hsi_drain_cache_action_to_lookup_result (action, next);
	}

      uc = hsi_udp_migrate_tracked_connection (&s, uc);
      if (!uc)
	{
	  *next = HSI_INPUT_NEXT_DROP;
	  return HSI_LOOKUP_RESULT_INTERCEPT;
	}
    }

  if (!is_input && hsi_udp_connection_is_draining (uc))
    {
      vnet_feature_next (next, b);
      return HSI_LOOKUP_RESULT_PASS;
    }

  action = hsi_udp_tracked_connection_action (vm, b, uc, ip_hdr, udp_hdr, is_ip4);
  return hsi_tracked_action_to_lookup_result (action, next);
}

always_inline hsi_lookup_result_t
hsi_udp_lookup_handler (vlib_main_t *vm, vlib_buffer_t *b, void *ip_hdr, u32 *next, u8 is_ip4,
			u8 is_input)
{
  udp_header_t *udp_hdr = 0;
  udp_connection_t *uc;
  u32 advance;
  session_t *s;

  s = hsi_udp_lookup (b, ip_hdr, &udp_hdr, is_ip4);
  if (s)
    {
      uc = udp_connection_get (s->connection_index, s->thread_index);
      if (uc && (uc->cfg_flags & UDP_CFG_F_TRACKED))
	return hsi_udp_tracked_lookup_handler (vm, b, s, uc, ip_hdr, udp_hdr, next, is_ip4,
					       is_input);
    }
  else
    {
      if (!hsi_have_intercept_proto (TRANSPORT_PROTO_UDP, is_ip4))
	{
	  vnet_feature_next (next, b);
	  return HSI_LOOKUP_RESULT_PASS;
	}
      s = session_get_from_handle (hsi_main.intercept_listeners[!is_ip4][TRANSPORT_PROTO_UDP]);
    }
  *next = HSI_INPUT_NEXT_UDP_INPUT_NOLOOKUP;
  /* Emulate udp-local and consume headers up to udp payload */
  advance = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  advance += sizeof (udp_header_t);
  vlib_buffer_advance (b, advance);
  vnet_buffer (b)->udp.session_handle = s->handle;

  return HSI_LOOKUP_RESULT_INTERCEPT;
}

always_inline u8
hsi_lookup_and_update (vlib_main_t *vm, vlib_buffer_t *b, u32 *next, u8 is_ip4, u8 is_input)
{
  u32 l3_offset = 0;
  hsi_lookup_result_t result;
  void *ip_hdr;
  u8 proto;

  /*
   * HSI tracker offload expects TCP/UDP to be directly reachable after the IP
   * header at this point. Fragmented packets and IPv6 extension-header chains
   * must be resolved by earlier features before they can be tracked.
   */
  if (is_input)
    {
      ip_hdr = vlib_buffer_get_current (b);
      if (is_ip4)
	ip_lookup_set_buffer_fib_index (ip4_main.fib_index_by_sw_if_index, b);
      else
	ip_lookup_set_buffer_fib_index (ip6_main.fib_index_by_sw_if_index, b);
    }
  else
    {
      l3_offset = vnet_buffer (b)->ip.save_rewrite_length;
      ip_hdr = vlib_buffer_get_current (b) + l3_offset;
    }

  if (is_ip4)
    proto = ((ip4_header_t *) ip_hdr)->protocol;
  else
    proto = ((ip6_header_t *) ip_hdr)->protocol;

  if (PREDICT_FALSE (proto != IP_PROTOCOL_TCP && proto != IP_PROTOCOL_UDP))
    {
      vnet_feature_next (next, b);
      return 1;
    }

  if (!is_input)
    {
      vlib_buffer_advance (b, l3_offset);
      ip_hdr = vlib_buffer_get_current (b);
    }

  if (proto == IP_PROTOCOL_TCP)
    result = hsi_tcp_lookup_handler (vm, b, ip_hdr, next, is_ip4, is_input);
  else
    result = hsi_udp_lookup_handler (vm, b, ip_hdr, next, is_ip4, is_input);

  if (!is_input)
    {
      if (result == HSI_LOOKUP_RESULT_PASS)
	vlib_buffer_advance (b, -(word) l3_offset);
    }

  /* Return 0 when HSI holds the buffer and this node must not enqueue it. */
  return result != HSI_LOOKUP_RESULT_HELD;
}

static void
hsi_input_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffer_indices, u16 *nexts,
		       u32 n_bufs, u8 is_ip4)
{
  vlib_buffer_t *b;
  hsi_trace_t *t;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      b = vlib_get_buffer (vm, buffer_indices[i]);
      if (!(b->flags & VLIB_BUFFER_IS_TRACED))
	continue;
      t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->next_node = nexts[i];
    }
}

always_inline void
hsi_enqueue_if_owned (u32 **to_next, u16 **next, u32 *n_to_next, u32 bi, u32 next_index, u8 enqueue)
{
  (*to_next)[0] = bi;
  (*next)[0] = next_index;
  *to_next += enqueue;
  *next += enqueue;
  *n_to_next += enqueue;
}

always_inline uword
hsi46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_ip4,
		    u8 is_input)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 to_nexts[VLIB_FRAME_SIZE], *to_next;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from, *from;
  u32 n_to_next = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  to_next = to_nexts;
  next = nexts;

  while (n_left_from >= 4)
    {
      u32 next0 = 0, next1 = 0;
      u8 enqueue0, enqueue1;

      vlib_prefetch_buffer_header (b[2], LOAD);
      CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

      vlib_prefetch_buffer_header (b[3], LOAD);
      CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

      enqueue0 = hsi_lookup_and_update (vm, b[0], &next0, is_ip4, is_input);
      hsi_enqueue_if_owned (&to_next, &next, &n_to_next, from[0], next0, enqueue0);

      enqueue1 = hsi_lookup_and_update (vm, b[1], &next1, is_ip4, is_input);
      hsi_enqueue_if_owned (&to_next, &next, &n_to_next, from[1], next1, enqueue1);

      b += 2;
      from += 2;
      n_left_from -= 2;
    }

  while (n_left_from)
    {
      u32 next0 = 0;
      u8 enqueue0;

      enqueue0 = hsi_lookup_and_update (vm, b[0], &next0, is_ip4, is_input);
      hsi_enqueue_if_owned (&to_next, &next, &n_to_next, from[0], next0, enqueue0);

      b += 1;
      from += 1;
      n_left_from -= 1;
    }

  if (n_to_next)
    vlib_buffer_enqueue_to_next (vm, node, to_nexts, nexts, n_to_next);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    hsi_input_trace_frame (vm, node, to_nexts, nexts, n_to_next, is_ip4);

  return frame->n_vectors;
}

VLIB_NODE_FN (hsi4_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 1 /* is_ip4 */, 1 /* is_input */);
}

VLIB_REGISTER_NODE (hsi4_in_node) = {
  .name = "hsi4-in",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi4_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi4_in_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "hsi4-in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = VNET_FEATURES ("ip4-full-reassembly-feature"),
};

VLIB_NODE_FN (hsi4_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 1 /* is_ip4 */, 0 /* is_input */);
}

VLIB_REGISTER_NODE (hsi4_out_node) = {
  .name = "hsi4-out",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi4_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi4_out_feature, static) = {
  .arc_name = "ip4-output",
  .node_name = "hsi4-out",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VLIB_NODE_FN (hsi6_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 0 /* is_ip4 */, 1 /* is_input */);
}

VLIB_REGISTER_NODE (hsi6_in_node) = {
  .name = "hsi6-in",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi6_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi6_in_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "hsi6-in",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-full-reassembly-feature"),
};

VLIB_NODE_FN (hsi6_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 0 /* is_ip4 */, 0 /* is_input */);
}

VLIB_REGISTER_NODE (hsi6_out_node) = {
  .name = "hsi6-out",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi6_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi6_out_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "hsi6-out",
  .runs_before = VNET_FEATURES ("interface-output"),
};

void
hsi_intercept_proto (transport_proto_t proto, u8 is_ip4, u8 is_enable)
{
  hsi_main_t *hm = &hsi_main;
  session_endpoint_t sep = { .transport_proto = proto, .is_ip4 = is_ip4 };
  session_t *ls;

  ls = session_lookup_listener_wildcard (0, &sep);
  if (!ls)
    return;

  if (is_enable)
    {
      if (proto == TRANSPORT_PROTO_TCP)
	hm->intercept_listeners[!is_ip4][proto] = ls->connection_index;
      else
	hm->intercept_listeners[!is_ip4][proto] = ls->handle;
      hm->intercept_type |= hsi_intercept_proto_flag (proto, is_ip4);
    }
  else
    {
      hm->intercept_listeners[!is_ip4][proto] = SESSION_INVALID_HANDLE;
      hm->intercept_type &= ~hsi_intercept_proto_flag (proto, is_ip4);
    }
}

static clib_error_t *
hsi_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  hsi_main_t *hm = &hsi_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 is_enable = 1;
  u32 max_packets;
  f64 timeout;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	{
	  is_enable = 0;
	}
      else if (unformat (line_input, "intercept tcp"))
	{
	  hsi_intercept_proto (TRANSPORT_PROTO_TCP, 1 /* is_ip4 */, is_enable);
	  hsi_intercept_proto (TRANSPORT_PROTO_TCP, 0 /* is_ip4 */, is_enable);
	}
      else if (unformat (line_input, "intercept udp"))
	{
	  hsi_intercept_proto (TRANSPORT_PROTO_UDP, 1 /* is_ip4 */, is_enable);
	  hsi_intercept_proto (TRANSPORT_PROTO_UDP, 0 /* is_ip4 */, is_enable);
	}
      else if (unformat (line_input, "intercept all"))
	{
	  hsi_intercept_proto (TRANSPORT_PROTO_TCP, 1 /* is_ip4 */, is_enable);
	  hsi_intercept_proto (TRANSPORT_PROTO_TCP, 0 /* is_ip4 */, is_enable);
	  hsi_intercept_proto (TRANSPORT_PROTO_UDP, 1 /* is_ip4 */, is_enable);
	  hsi_intercept_proto (TRANSPORT_PROTO_UDP, 0 /* is_ip4 */, is_enable);
	}
      else if (unformat (line_input, "tcp drain-cache max-packets %u", &max_packets))
	{
	  if (!max_packets)
	    {
	      error = clib_error_return (0, "max-packets must be non-zero");
	      goto done;
	    }
	  hm->tcp_drain_cache_max_packets = max_packets;
	}
      else if (unformat (line_input, "tcp drain-timeout %f", &timeout))
	{
	  if (timeout <= 0)
	    {
	      error = clib_error_return (0, "timeout must be positive");
	      goto done;
	    }
	  hm->tcp_drain_no_progress_timeout = timeout;
	}
      else if (unformat (line_input, "udp drain-cache max-packets %u", &max_packets))
	{
	  if (!max_packets)
	    {
	      error = clib_error_return (0, "max-packets must be non-zero");
	      goto done;
	    }
	  hm->udp_drain_cache_max_packets = max_packets;
	}
      else if (unformat (line_input, "udp drain-timeout %f", &timeout))
	{
	  if (timeout <= 0)
	    {
	      error = clib_error_return (0, "timeout must be positive");
	      goto done;
	    }
	  hm->udp_drain_no_progress_timeout = timeout;
	}
      else if (unformat (line_input, "udp idle-timeout %f", &timeout))
	{
	  if (timeout < 0)
	    {
	      error = clib_error_return (0, "timeout must be non-negative");
	      goto done;
	    }
	  hm->udp_idle_timeout = timeout;
	  hsi_udp_idle_timeout_update ();
	}
      else if (unformat (line_input, "tcp fin-wait-timeout %f", &timeout))
	{
	  if (timeout <= 0)
	    {
	      error = clib_error_return (0, "timeout must be positive");
	      goto done;
	    }
	  hm->tcp_fin_wait_timeout = timeout;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (hsi_command, static) = {
  .path = "hsi",
  .short_help = "hsi [intercept [tcp | udp | all]] "
		"[tcp drain-cache max-packets <n>] [tcp drain-timeout <sec>] "
		"[udp drain-cache max-packets <n>] [udp drain-timeout <sec>] "
		"[udp idle-timeout <sec>] [tcp fin-wait-timeout <sec>]",
  .function = hsi_command_fn,
};

static clib_error_t *
hsi_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  hsi_main_t *hm = &hsi_main;
  hsi_worker_t *wrk;
  u32 i;

  vlib_cli_output (vm, "tcp drain-cache max-packets %u", hm->tcp_drain_cache_max_packets);
  vlib_cli_output (vm, "tcp drain-timeout %.3f", hm->tcp_drain_no_progress_timeout);
  vlib_cli_output (vm, "udp drain-cache max-packets %u", hm->udp_drain_cache_max_packets);
  vlib_cli_output (vm, "udp drain-timeout %.3f", hm->udp_drain_no_progress_timeout);
  vlib_cli_output (vm, "udp idle-timeout %.3f", hm->udp_idle_timeout);
  vlib_cli_output (vm, "tcp fin-wait-timeout %.3f", hm->tcp_fin_wait_timeout);

  vec_foreach_index (i, hm->wrk)
    {
      wrk = vec_elt_at_index (hm->wrk, i);
#define _(name, type, str) vlib_cli_output (vm, "thread %u %s %lu", i, str, wrk->stats.name);
      foreach_hsi_wrk_stat
#undef _
    }

  hsi_tracker_show (vm);

  return 0;
}

VLIB_CLI_COMMAND (hsi_show_command, static) = {
  .path = "show hsi",
  .short_help = "show hsi",
  .function = hsi_show_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Host Stack Intercept (HSI)",
  .default_disabled = 0,
};

static void
hsi_workers_init (void)
{
  hsi_main_t *hm = &hsi_main;

  vec_validate (hm->wrk, vlib_get_n_threads () - 1);
}

static clib_error_t *
hsi_workers_num_workers_change (vlib_main_t *vm)
{
  hsi_workers_init ();
  return 0;
}

VLIB_NUM_WORKERS_CHANGE_FN (hsi_workers_num_workers_change);

clib_error_t *
hsi_init (vlib_main_t *vm)
{
  hsi_main_t *hm = &hsi_main;

  hm->intercept_type = 0;
  hm->tcp_drain_cache_max_packets = HSI_TCP_DRAIN_CACHE_DEFAULT_PACKETS;
  hm->tcp_drain_no_progress_timeout = HSI_TCP_DRAIN_NO_PROGRESS_DEFAULT_TIMEOUT;
  hm->udp_drain_cache_max_packets = HSI_UDP_DRAIN_CACHE_DEFAULT_PACKETS;
  hm->udp_drain_no_progress_timeout = HSI_UDP_DRAIN_NO_PROGRESS_DEFAULT_TIMEOUT;
  hm->udp_idle_timeout = HSI_UDP_IDLE_DEFAULT_TIMEOUT;
  hm->tcp_fin_wait_timeout = HSI_TCP_FIN_WAIT_DEFAULT_TIMEOUT;
  hsi_workers_init ();

  return 0;
}

VLIB_INIT_FUNCTION (hsi_init);
