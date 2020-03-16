/*
 * Copyright (c) 2018 Travelping GmbH
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
  UPF_PROXY_INPUT_NEXT_DROP,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP,
  UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT,
  UPF_PROXY_INPUT_N_NEXT,
} upf_proxy_input_next_t;

/* Statistics (not all errors) */
#define foreach_upf_proxy_input_error				\
  _(LENGTH, "inconsistent ip/tcp lengths")			\
  _(NO_LISTENER, "no redirect server available")		\
  _(PROCESS, "good packets process")				\
  _(OPTIONS, "Could not parse options")				\
  _(CREATE_SESSION_FAIL, "Sessions couldn't be allocated")

static char *upf_proxy_input_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_proxy_input_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_PROXY_INPUT_ERROR_##sym,
  foreach_upf_proxy_input_error
#undef _
    UPF_PROXY_INPUT_N_ERROR,
} upf_proxy_input_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_proxy_input_trace_t;

static u8 *
format_upf_proxy_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_input_trace_t *t = va_arg (*args, upf_proxy_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 "\n%U%U",
	      t->session_index, t->cp_seid,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static_always_inline void
upf_vnet_buffer_l3_hdr_offset_is_current (vlib_buffer_t * b)
{
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
}

static uword
upf_proxy_input (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, int is_ip4)
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
	  upf_session_t *sess = NULL;
	  flow_direction_t direction;
	  flow_entry_t *flow = NULL;
	  upf_pdr_t *pdr = NULL;
	  upf_far_t *far = NULL;
	  struct rules *active;
	  flow_tc_t *ftc;

	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  error = 0;
	  next = UPF_FORWARD_NEXT_DROP;

	  ASSERT (upf_buffer_opaque (b)->gtpu.flow_id);

	  /* Outer Header Removal */
	  switch (upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK)
	    {
	    case BUFFER_GTP_UDP_IP4:	/* GTP-U/UDP/IPv4 */
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case BUFFER_GTP_UDP_IP6:	/* GTP-U/UDP/IPv6 */
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case BUFFER_UDP_IP4:	/* UDP/IPv4 */
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip4_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case BUFFER_UDP_IP6:	/* UDP/IPv6 */
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip6_header_t) +
				   sizeof (udp_header_t));
	      break;

	    default:
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;
	    }

	  upf_debug ("flow: %p (0x%08x): %U\n",
		     fm->flows + upf_buffer_opaque (b)->gtpu.flow_id,
		     upf_buffer_opaque (b)->gtpu.flow_id,
		     format_flow_key,
		     &(fm->flows + upf_buffer_opaque (b)->gtpu.flow_id)->key);

	  flow =
	    pool_elt_at_index (fm->flows,
			       upf_buffer_opaque (b)->gtpu.flow_id);
	  ASSERT (flow);

	  direction =
	    (flow->is_reverse ==
	     upf_buffer_opaque (b)->gtpu.is_reverse) ? FT_ORIGIN : FT_REVERSE;

	  upf_debug ("direction: %u, buffer: %u, flow: %u", direction,
		     upf_buffer_opaque (b)->gtpu.is_reverse,
		     flow->is_reverse);

	  ftc = &flow_tc (flow, direction);
	  upf_debug ("ftc conn_index %u", ftc->conn_index);

	  if (ftc->conn_index != ~0)
	    {
	      ASSERT (ftc->thread_index == thread_index);

	      upf_debug ("existing connection 0x%08x", ftc->conn_index);
	      vnet_buffer (b)->tcp.connection_index = ftc->conn_index;

	      /* transport connection already setup */
	      next = UPF_PROXY_INPUT_NEXT_TCP_INPUT;
	    }
	  else if (direction == FT_ORIGIN)
	    {
	      upf_debug ("PROXY_ACCEPT");
	      next = UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT;
	    }
	  else if (direction == FT_REVERSE && ftc->conn_index == ~0)
	    {
	      upf_debug ("INPUT_LOOKUP");
	      next = UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP;
	    }
	  else
	    goto stats;

	  /* Get next node index and adj index from tunnel next_dpo */
	  sess = pool_elt_at_index (gtm->sessions, flow->session_index);
	  active = pfcp_get_rules (sess, PFCP_ACTIVE);
	  pdr = pfcp_get_pdr_by_id (active, flow_pdr_id (flow, direction));
	  far = pdr ? pfcp_get_far_by_id (active, pdr->far_id) : NULL;

	  if (PREDICT_FALSE (!pdr) || PREDICT_FALSE (!far))
	    {
	      next = UPF_FORWARD_NEXT_DROP;
	      goto stats;
	    }


#define IS_DL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	  upf_debug ("pdr: %d, far: %d\n", pdr->id, far->id);
	  next = process_qers (vm, sess, active, pdr, b,
			       IS_DL (pdr, far), IS_UL (pdr, far), next);
	  next = process_urrs (vm, sess, active, pdr, b,
			       IS_DL (pdr, far), IS_UL (pdr, far), next);

#undef IS_DL
#undef IS_UL

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
	      upf_proxy_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));

	      /* Get next node index and adj index from tunnel next_dpo */
	      sidx = upf_buffer_opaque (b)->gtpu.session_index;
	      sess = pool_elt_at_index (gtm->sessions, sidx);
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
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

VLIB_NODE_FN (upf_ip4_proxy_input_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return upf_proxy_input (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_input_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return upf_proxy_input (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_proxy_input_node) = {
  .name = "upf-ip4-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]          = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]     = "tcp4-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP]     = "tcp4-input",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]  = "upf-ip4-proxy-accept",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_proxy_input_node) = {
  .name = "upf-ip6-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]          = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]     = "tcp6-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP]     = "tcp6-input",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]  = "upf-ip6-proxy-accept",
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
