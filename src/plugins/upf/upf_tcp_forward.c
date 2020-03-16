/*
 * Copyright (c) 2020 Travelping GmbH
 *
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

typedef enum
{
  UPF_TCP_FORWARD_NEXT_DROP,
  UPF_TCP_FORWARD_NEXT_FORWARD,
  UPF_TCP_FORWARD_N_NEXT,
} upf_tcp_forward_next_t;

/* Statistics (not all errors) */
#define foreach_upf_tcp_forward_error			\
  _(PROCESS, "good packets process")			\
  _(INVALID_FLOW, "flow entry not found")		\
  _(NO_SESSION, "session not found")

static char *upf_tcp_forward_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_tcp_forward_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_TCP_FORWARD_ERROR_##sym,
  foreach_upf_tcp_forward_error
#undef _
    UPF_TCP_FORWARD_N_ERROR,
} upf_tcp_forward_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 flow_id;
  u32 pdr_idx;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_tcp_forward_trace_t;

static u8 *
format_upf_tcp_forward_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_tcp_forward_trace_t *t = va_arg (*args, upf_tcp_forward_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 " Flow %u PDR Idx %u\n"
	      "%U%U",
	      t->session_index, t->cp_seid, t->flow_id, t->pdr_idx,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static_always_inline void
net_add (u32 * data, u32 add)
{
  add += clib_net_to_host_u32 (*data);
  *data = clib_host_to_net_u32 (add);
}

static_always_inline void
net_sub (u32 * data, u32 sub)
{
  sub = clib_net_to_host_u32 (*data) - sub;
  *data = clib_host_to_net_u32 (sub);
}

static_always_inline int
upf_tcp_tstamp_mod (tcp_header_t * th, flow_direction_t direction,
		    flow_entry_t * flow)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j, blocks;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  /* broken options */
	  if (opts_len < 2)
	    return -1;
	  opt_len = data[1];

	  /* weird option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    return -1;
	}

      /* Parse options */
      switch (kind)
	{
	case TCP_OPTION_TIMESTAMP:
	  if (opt_len == TCP_OPTION_LEN_TIMESTAMP)
	    {
	      /* tsval */
	      net_sub ((u32 *) (data + 2), flow_tsval_offs (flow, direction));

	      if (tcp_ack (th))
		/* tsecr */
		net_add ((u32 *) (data + 6),
			 flow_tsval_offs (flow, FT_REVERSE ^ direction));
	    }
	  break;

	case TCP_OPTION_SACK_BLOCK:
	  /* If a SYN, break */
	  if (tcp_syn (th))
	    break;

	  /* If too short or not correctly formatted, break */
	  if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	    break;

	  blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
	  for (j = 0; j < blocks; j++)
	    {
	      if (direction == FT_ORIGIN)
		{
		  net_add ((u32 *) (data + 2 + 8 * j),
			   flow_seq_offs (flow, FT_REVERSE));
		  net_add ((u32 *) (data + 6 + 8 * j),
			   flow_seq_offs (flow, FT_REVERSE));
		}
	      else
		{
		  net_sub ((u32 *) (data + 2 + 8 * j),
			   flow_seq_offs (flow, FT_ORIGIN));
		  net_sub ((u32 *) (data + 6 + 8 * j),
			   flow_seq_offs (flow, FT_ORIGIN));
		}
	    }
	  break;

	default:
	  break;
	}
    }

  return 0;
}

static uword
upf_tcp_forward (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, flow_direction_t direction,
		 int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  u32 len;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 error;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  flow_direction_t direction;
	  flow_entry_t *flow = NULL;
	  ip4_header_t *ip4;
	  ip6_header_t *ip6;
	  tcp_header_t *th;
	  u32 seq, ack;
	  u32 flow_id;

	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  error = 0;
	  next = UPF_TCP_FORWARD_NEXT_FORWARD;

	  flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
	  ASSERT (flow_id != ~0);
	  if (flow_id == ~0 || pool_is_free_index (fm->flows, flow_id))
	    {
	      next = UPF_TCP_FORWARD_NEXT_DROP;
	      error = UPF_TCP_FORWARD_ERROR_INVALID_FLOW;
	      goto stats;
	    }

	  flow = pool_elt_at_index (fm->flows, flow_id);
	  direction =
	    (flow->is_reverse ==
	     upf_buffer_opaque (b)->gtpu.is_reverse) ? FT_ORIGIN : FT_REVERSE;

	  /* mostly borrowed from vnet/interface_output.c calc_checksums */
	  if (is_ip4)
	    {
	      ip4 = (ip4_header_t *) vlib_buffer_get_current (b);
	      th = (tcp_header_t *) ip4_next_header (ip4);
	    }
	  else
	    {
	      ip6 = (ip6_header_t *) vlib_buffer_get_current (b);
	      th = (tcp_header_t *) ip6_next_header (ip6);
	    }

	  seq = clib_net_to_host_u32 (th->seq_number);
	  ack = clib_net_to_host_u32 (th->ack_number);

	  if (direction == FT_ORIGIN)
	    {
	      seq += flow_seq_offs (flow, FT_ORIGIN);
	      ack += flow_seq_offs (flow, FT_REVERSE);
	    }
	  else
	    {
	      seq -= flow_seq_offs (flow, FT_REVERSE);
	      ack -= flow_seq_offs (flow, FT_ORIGIN);
	    }

	  th->seq_number = clib_host_to_net_u32 (seq);
	  th->ack_number = clib_host_to_net_u32 (ack);

	  upf_tcp_tstamp_mod (th, direction, flow);

	  /* calculate new header checksums */
	  if (is_ip4)
	    {
	      ip4->checksum = ip4_header_checksum (ip4);
	      th->checksum = 0;
	      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	    }
	  else
	    {
	      int bogus;

	      th->checksum = 0;
	      th->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	    }

	  b->flags &= ~VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
	  b->flags &= ~VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
	  b->flags &= ~VNET_BUFFER_F_OFFLOAD_IP_CKSUM;

	stats:
	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	  b->error = error ? node->errors[error] : 0;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_session_t *sess = NULL;
	      u32 sidx = 0;
	      upf_tcp_forward_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));

	      /* Get next node index and adj index from tunnel next_dpo */
	      sidx = upf_buffer_opaque (b)->gtpu.session_index;
	      sess = pool_elt_at_index (gtm->sessions, sidx);
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
	      tr->pdr_idx = upf_buffer_opaque (b)->gtpu.pdr_idx;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_tcp4_forward_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return upf_tcp_forward (vm, node, from_frame, FT_REVERSE, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_tcp6_forward_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return upf_tcp_forward (vm, node, from_frame, FT_REVERSE, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_tcp4_forward_node) = {
  .name = "upf-tcp4-forward",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tcp_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_tcp_forward_error_strings),
  .error_strings = upf_tcp_forward_error_strings,
  .n_next_nodes = UPF_TCP_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_TCP_FORWARD_NEXT_DROP]    = "error-drop",
    [UPF_TCP_FORWARD_NEXT_FORWARD] = "upf-ip4-forward",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_tcp6_forward_node) = {
  .name = "upf-tcp6-forward",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tcp_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_tcp_forward_error_strings),
  .error_strings = upf_tcp_forward_error_strings,
  .n_next_nodes = UPF_TCP_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_TCP_FORWARD_NEXT_DROP]    = "error-drop",
    [UPF_TCP_FORWARD_NEXT_FORWARD] = "upf-ip6-forward",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
