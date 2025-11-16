/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <hsi/hsi.h>
#include <vnet/tcp/tcp_types.h>
#include <vnet/tcp/tcp_inlines.h>

typedef struct hsi_main_
{
  u8 intercept_type;

  /* ipv4 and ipv6 for tcp and udp */
  session_handle_t intercept_listeners[2][2];
} hsi_main_t;

static hsi_main_t hsi_main;

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
  HSI_INPUT_N_NEXT
} hsi_input_next_t;

#define foreach_hsi4_input_next                                               \
  _ (UDP_INPUT, "udp4-input")                                                 \
  _ (UDP_INPUT_NOLOOKUP, "udp4-input-nolookup")                               \
  _ (TCP_INPUT, "tcp4-input")                                                 \
  _ (TCP_INPUT_NOLOOKUP, "tcp4-input-nolookup")                               \
  _ (TCP_LISTEN, "tcp4-listen")

#define foreach_hsi6_input_next                                               \
  _ (UDP_INPUT, "udp6-input")                                                 \
  _ (UDP_INPUT_NOLOOKUP, "udp6-input-nolookup")                               \
  _ (TCP_INPUT, "tcp6-input")                                                 \
  _ (TCP_INPUT_NOLOOKUP, "tcp6-input-nolookup")                               \
  _ (TCP_LISTEN, "tcp6-listen")

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
  s = format (s, "session %sfound, next node: %v",
	      t->next_node < HSI_INPUT_N_NEXT ? "" : "not ", nn->name);
  return s;
}

always_inline session_t *
hsi_udp_lookup (vlib_buffer_t *b, void *ip_hdr, u8 is_ip4)
{
  udp_header_t *hdr;
  session_t *s;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
      hdr = ip4_next_header (ip4);
      s = session_lookup_safe4 (
	vnet_buffer (b)->ip.fib_index, &ip4->dst_address, &ip4->src_address,
	hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_UDP);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      hdr = ip6_next_header (ip6);
      s = session_lookup_safe6 (
	vnet_buffer (b)->ip.fib_index, &ip6->dst_address, &ip6->src_address,
	hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_UDP);
    }

  return s;
}

always_inline transport_connection_t *
hsi_tcp_lookup (vlib_buffer_t *b, void *ip_hdr, tcp_header_t **rhdr, u8 is_ip4)
{
  transport_connection_t *tc;
  tcp_header_t *hdr;
  u8 result = 0;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
      *rhdr = hdr = ip4_next_header (ip4);
      tc = session_lookup_connection_wt4 (
	vnet_buffer (b)->ip.fib_index, &ip4->dst_address, &ip4->src_address,
	hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_TCP,
	vlib_get_thread_index (), &result);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      *rhdr = hdr = ip6_next_header (ip6);
      tc = session_lookup_connection_wt6 (
	vnet_buffer (b)->ip.fib_index, &ip6->dst_address, &ip6->src_address,
	hdr->dst_port, hdr->src_port, TRANSPORT_PROTO_TCP,
	vlib_get_thread_index (), &result);
    }

  return result == 0 ? tc : 0;
}

always_inline void
hsi_lookup_and_update (vlib_buffer_t *b, u32 *next, u8 is_ip4, u8 is_input)
{
  u8 proto, state;
  tcp_header_t *tcp_hdr = 0;
  tcp_connection_t *tc;
  u32 rw_len = 0;
  session_t *s;
  void *ip_hdr;

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
      rw_len = vnet_buffer (b)->ip.save_rewrite_length;
      ip_hdr = vlib_buffer_get_current (b) + rw_len;
    }

  if (is_ip4)
    proto = ((ip4_header_t *) ip_hdr)->protocol;
  else
    proto = ((ip6_header_t *) ip_hdr)->protocol;

  switch (proto)
    {
    case IP_PROTOCOL_TCP:
      tc = (tcp_connection_t *) hsi_tcp_lookup (b, ip_hdr, &tcp_hdr, is_ip4);
      if (tc)
	{
	  state = tc->state;
	  if (state == TCP_STATE_LISTEN)
	    {
	      /* Avoid processing non syn packets that match listener */
	      if (!tcp_syn (tcp_hdr))
		{
		  vnet_feature_next (next, b);
		  break;
		}
	      *next = HSI_INPUT_NEXT_TCP_INPUT;
	    }
	  else if (state == TCP_STATE_SYN_SENT)
	    {
	      *next = HSI_INPUT_NEXT_TCP_INPUT;
	    }
	  else
	    {
	      /* Lookup already done, use result */
	      *next = HSI_INPUT_NEXT_TCP_INPUT_NOLOOKUP;
	      vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
	    }
	  vlib_buffer_advance (b, rw_len);
	}
      else
	{
	  u32 error = 0;

	  if (!hsi_have_intercept_proto (TRANSPORT_PROTO_TCP, is_ip4) ||
	      !tcp_syn (tcp_hdr))
	    {
	      vnet_feature_next (next, b);
	      break;
	    }

	  /* force parsing of buffer in preparation for tcp-listen */
	  tcp_input_lookup_buffer (b, vlib_get_thread_index (), &error, is_ip4,
				   1 /* is_nolookup*/);
	  if (error)
	    {
	      vnet_feature_next (next, b);
	      break;
	    }

	  vnet_buffer (b)->tcp.connection_index =
	    hsi_main.intercept_listeners[!is_ip4][TRANSPORT_PROTO_TCP];
	  vnet_buffer (b)->tcp.flags = TCP_STATE_LISTEN;

	  *next = HSI_INPUT_NEXT_TCP_LISTEN;
	}
      break;
    case IP_PROTOCOL_UDP:
      s = hsi_udp_lookup (b, ip_hdr, is_ip4);
      if (!s)
	{
	  if (!hsi_have_intercept_proto (TRANSPORT_PROTO_UDP, is_ip4))
	    {
	      vnet_feature_next (next, b);
	      break;
	    }
	  s = session_get_from_handle (
	    hsi_main.intercept_listeners[!is_ip4][TRANSPORT_PROTO_UDP]);
	}
      *next = HSI_INPUT_NEXT_UDP_INPUT_NOLOOKUP;
      /* Emulate udp-local and consume headers up to udp payload */
      rw_len += is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
      rw_len += sizeof (udp_header_t);
      vlib_buffer_advance (b, rw_len);
      vnet_buffer (b)->udp.session_handle = s->handle;
      break;
    default:
      vnet_feature_next (next, b);
      break;
    }
}

static void
hsi_input_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_buffer_t **bufs, u16 *nexts, u32 n_bufs, u8 is_ip4)
{
  vlib_buffer_t *b;
  hsi_trace_t *t;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      b = bufs[i];
      if (!(b->flags & VLIB_BUFFER_IS_TRACED))
	continue;
      t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->next_node = nexts[i];
    }
}

always_inline uword
hsi46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u8 is_ip4, u8 is_input)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      u32 next0, next1;

      vlib_prefetch_buffer_header (b[2], LOAD);
      CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

      vlib_prefetch_buffer_header (b[3], LOAD);
      CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

      hsi_lookup_and_update (b[0], &next0, is_ip4, is_input);
      hsi_lookup_and_update (b[1], &next1, is_ip4, is_input);

      next[0] = next0;
      next[1] = next1;

      b += 2;
      next += 2;
      n_left_from -= 2;
    }

  while (n_left_from)
    {
      u32 next0;

      hsi_lookup_and_update (b[0], &next0, is_ip4, is_input);

      next[0] = next0;

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    hsi_input_trace_frame (vm, node, bufs, nexts, frame->n_vectors, is_ip4);

  return frame->n_vectors;
}

VLIB_NODE_FN (hsi4_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 1 /* is_ip4 */,
			     1 /* is_input */);
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
  return hsi46_input_inline (vm, node, frame, 1 /* is_ip4 */,
			     0 /* is_input */);
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
  return hsi46_input_inline (vm, node, frame, 0 /* is_ip4 */,
			     1 /* is_input */);
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
  return hsi46_input_inline (vm, node, frame, 0 /* is_ip4 */,
			     0 /* is_input */);
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
hsi_command_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 is_enable = 1;

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
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (hsi_command, static) = {
  .path = "hsi",
  .short_help = "hsi [intercept [tcp | udp | all]]",
  .function = hsi_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Host Stack Intercept (HSI)",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
