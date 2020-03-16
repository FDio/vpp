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
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_process_error				\
  _(LENGTH, "inconsistent ip/tcp lengths")			\
  _(NO_LISTENER, "no redirect server available")		\
  _(PROCESS, "good packets process")				\
  _(OPTIONS, "Could not parse options")				\
  _(CREATE_SESSION_FAIL, "Sessions couldn't be allocated")

static char *upf_process_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_process_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_PROCESS_ERROR_##sym,
  foreach_upf_process_error
#undef _
    UPF_PROCESS_N_ERROR,
} upf_process_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 pdr_id;
  u32 far_id;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_process_trace_t;

static u8 *
format_upf_process_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_process_trace_t *t = va_arg (*args, upf_process_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 " pdr %d far %d\n%U%U",
	      t->session_index, t->cp_seid, t->pdr_id, t->far_id,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
static int
proxy_session_stream_accept (transport_connection_t * tc, u32 flow_id,
			     u8 notify)
{
  upf_proxy_main_t *pm = &upf_proxy_main;
  app_worker_t *app_wrk;
  application_t *app;
  session_t *s;
  int rv;

  app = application_get_if_valid (pm->server_app_index);
  if (!app)
    return -1;

  app_wrk = application_get_worker (app, 0 /* default wrk only */ );

  /* Make sure we have a segment manager for connects */
  app_worker_alloc_connects_segment_manager (app_wrk);

  s = session_alloc_for_connection (tc);
  s->session_state = SESSION_STATE_CREATED;
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = flow_id;

  clib_warning ("proxy session @ %p, app %p, wrk %p (idx %u), flow: 0x%08x",
		s, app, app_wrk, app_wrk->wrk_index, flow_id);

  if ((rv = app_worker_init_connected (app_wrk, s)))
    return rv;

  session_lookup_add_connection (tc, session_handle (s));

  /* Shoulder-tap the server */
  if (notify)
    {
      return app_worker_accept_notify (app_wrk, s);
    }

  clib_warning ("proxy session flow: 0x%08x", s->opaque);
  return 0;
}

static_always_inline u32
upf_to_proxy (vlib_main_t * vm, vlib_buffer_t * b,
	      int is_ip4, u32 sidx, u32 far_idx,
	      flow_tc_t * ftc, u32 fib_index, u32 * error)
{
  u32 thread_index = vm->thread_index;
  int n_advance_bytes, n_data_bytes;
  tcp_connection_t *child;
  tcp_header_t *tcp;
  u32 flow_id;

  if (ftc->conn_index != ~0)
    {
      ASSERT (ftc->thread_index == thread_index);

      vnet_buffer (b)->tcp.connection_index = ftc->conn_index;

      /* transport connection already setup */
      return UPF_PROCESS_NEXT_TCP_INPUT;
    }

  flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
  if (upf_buffer_opaque (b)->gtpu.is_reverse)
    flow_id |= 0x80000000;

  if (is_ip4)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      int ip_hdr_bytes = ip4_header_bytes (ip4);
      if (PREDICT_FALSE (b->current_length < ip_hdr_bytes + sizeof (*tcp)))
	{
	  *error = UPF_PROCESS_ERROR_LENGTH;
	  return UPF_PROCESS_NEXT_DROP;
	}
      tcp = ip4_next_header (ip4);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip4;
      n_advance_bytes = (ip_hdr_bytes + tcp_header_bytes (tcp));
      n_data_bytes = clib_net_to_host_u16 (ip4->length) - n_advance_bytes;

      /* Length check. Checksum computed by ipx_local no need to compute again */
      if (PREDICT_FALSE (n_data_bytes < 0))
	{
	  *error = TCP_ERROR_LENGTH;
	  return UPF_PROCESS_NEXT_DROP;
	}
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (PREDICT_FALSE (b->current_length < sizeof (*ip6) + sizeof (*tcp)))
	{
	  *error = UPF_PROCESS_ERROR_LENGTH;
	  return UPF_PROCESS_NEXT_DROP;
	}
      tcp = ip6_next_header (ip6);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip6;
      n_advance_bytes = tcp_header_bytes (tcp);
      n_data_bytes = clib_net_to_host_u16 (ip6->payload_length)
	- n_advance_bytes;
      n_advance_bytes += sizeof (ip6[0]);

      if (PREDICT_FALSE (n_data_bytes < 0))
	{
	  *error = TCP_ERROR_LENGTH;
	  return UPF_PROCESS_NEXT_DROP;
	}
    }

  if (PREDICT_FALSE (!tcp_syn (tcp)))
    {
      clib_warning ("UPF proxy, no connection and not SYN\n");
      *error = UPF_PROCESS_ERROR_NO_LISTENER;
      return UPF_PROCESS_NEXT_DROP;
    }

  vnet_buffer (b)->tcp.seq_number = clib_net_to_host_u32 (tcp->seq_number);
  vnet_buffer (b)->tcp.ack_number = clib_net_to_host_u32 (tcp->ack_number);
  vnet_buffer (b)->tcp.data_offset = n_advance_bytes;
  vnet_buffer (b)->tcp.data_len = n_data_bytes;
  vnet_buffer (b)->tcp.seq_end = vnet_buffer (b)->tcp.seq_number
    + n_data_bytes;
  vnet_buffer (b)->tcp.flags = 0;

  if (~0 == fib_index)
    {
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      fib_index = is_ip4 ?
	ip4_fib_table_get_index_for_sw_if_index (sw_if_index)
	: ip6_fib_table_get_index_for_sw_if_index (sw_if_index);
      clib_warning ("SwIfIdx: %u", sw_if_index);
    }

  clib_warning ("FIB: %u", fib_index);

  /* Create child session and send SYN-ACK */
  child = tcp_connection_alloc (thread_index);

  if (tcp_options_parse (tcp, &child->rcv_opts, 1))
    {
      *error = UPF_PROCESS_ERROR_OPTIONS;
      tcp_connection_free (child);
      return UPF_PROCESS_NEXT_DROP;
    }

  tcp_init_w_buffer (child, b, is_ip4);

  child->state = TCP_STATE_SYN_RCVD;
  child->c_fib_index = fib_index;
  child->cc_algo = tcp_cc_algo_get (TCP_CC_NEWRENO);
  tcp_connection_init_vars (child);
  child->rto = TCP_RTO_MIN;

  if (proxy_session_stream_accept
      (&child->connection, flow_id, 0 /* notify */ ))
    {
      tcp_connection_cleanup (child);
      *error = UPF_PROCESS_ERROR_CREATE_SESSION_FAIL;
      return UPF_PROCESS_NEXT_DROP;
    }

  vnet_buffer (b)->tcp.connection_index = child->c_c_index;
  ftc->conn_index = child->c_c_index;
  ftc->thread_index = thread_index;

  child->tx_fifo_size = transport_tx_fifo_size (&child->connection);

  tcp_send_synack (child);

  TCP_EVT (TCP_EVT_SYN_RCVD, child, 1);

  return UPF_PROCESS_NEXT_DROP;
}

static_always_inline void
upf_vnet_buffer_l3_hdr_offset_is_current (vlib_buffer_t * b)
{
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
}

static uword
upf_process (vlib_main_t * vm, vlib_node_runtime_t * node,
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
  upf_session_t *sess = NULL;
  u32 sidx = 0;
  u32 len;
  struct rules *active;

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
	  flow_entry_t *flow = NULL;
	  upf_pdr_t *pdr = NULL;
	  upf_far_t *far = NULL;

	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sidx = upf_buffer_opaque (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);

	  error = 0;
	  next = UPF_PROCESS_NEXT_DROP;
	  active = pfcp_get_rules (sess, PFCP_ACTIVE);

	  if (PREDICT_TRUE (upf_buffer_opaque (b)->gtpu.pdr_idx != ~0))
	    {
	      pdr = active->pdr + upf_buffer_opaque (b)->gtpu.pdr_idx;
	      far = pfcp_get_far_by_id (active, pdr->far_id);
	    }

	  if (PREDICT_FALSE (!pdr) || PREDICT_FALSE (!far))
	    goto stats;

	  /* Outer Header Removal */
	  switch (pdr->outer_header_removal)
	    {
	    case OUTER_HEADER_REMOVAL_GTP_IP4:	/* GTP-U/UDP/IPv4 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_GTP_UDP_IP4))
		{
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case OUTER_HEADER_REMOVAL_GTP_IP6:	/* GTP-U/UDP/IPv6 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_GTP_UDP_IP6))
		{
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case OUTER_HEADER_REMOVAL_UDP_IP4:	/* UDP/IPv4 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_UDP_IP4))
		{
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip4_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case OUTER_HEADER_REMOVAL_UDP_IP6:	/* UDP/IPv6 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_UDP_IP6))
		{
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip6_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case OUTER_HEADER_REMOVAL_GTP:	/* GTP-U/UDP/IP */
	      switch (upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK)
		{
		case BUFFER_GTP_UDP_IP4:
		case BUFFER_GTP_UDP_IP6:
		  vlib_buffer_advance (b,
				       upf_buffer_opaque (b)->
				       gtpu.data_offset);
		  upf_vnet_buffer_l3_hdr_offset_is_current (b);
		  break;

		default:
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      break;

	    default:
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;
	    }

	  if (~0 != upf_buffer_opaque (b)->gtpu.flow_id)
	    {
	      gtp_debug ("flow: %p (0x%08x): %U\n",
			 fm->flows + upf_buffer_opaque (b)->gtpu.flow_id,
			 upf_buffer_opaque (b)->gtpu.flow_id,
			 format_flow_key,
			 &(fm->flows +
			   upf_buffer_opaque (b)->gtpu.flow_id)->key);

	      flow =
		pool_elt_at_index (fm->flows,
				   upf_buffer_opaque (b)->gtpu.flow_id);
	    }

	  if (flow && flow->is_l3_proxy)
	    {
	      next = upf_to_proxy (vm, b, is_ip4, sidx, ~0,
				   &flow->tc[upf_buffer_opaque (b)->
					     gtpu.is_reverse], ~0, &error);
	      goto process;
	    }

	  if (PREDICT_TRUE (far->apply_action & FAR_FORWARD))
	    {
	      if (far->forward.flags & FAR_F_OUTER_HEADER_CREATION)
		{
		  if (far->forward.outer_header_creation.description
		      & OUTER_HEADER_CREATION_GTP_IP4)
		    {
		      next = UPF_PROCESS_NEXT_GTP_IP4_ENCAP;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_GTP_IP6)
		    {
		      next = UPF_PROCESS_NEXT_GTP_IP6_ENCAP;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_UDP_IP4)
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_NOT_YET;
		      goto trace;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_UDP_IP6)
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_NOT_YET;
		      goto trace;
		    }
		}
	      else if (far->forward.flags & FAR_F_REDIRECT_INFORMATION)
		{
		  u32 fib_index;

		  if (!flow)
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_NO_FLOW;
		      goto trace;
		    }

		  fib_index =
		    upf_nwi_fib_index (is_ip4 ? FIB_PROTOCOL_IP4 :
				       FIB_PROTOCOL_IP6,
				       far->forward.nwi_index);
		  next =
		    upf_to_proxy (vm, b, is_ip4, sidx, far - active->far,
				  &flow->tc[upf_buffer_opaque (b)->
					    gtpu.is_reverse], fib_index,
				  &error);
		}
	      else
		{
		  if (is_ip4)
		    {
		      b->flags &= ~(VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
				    VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
				    VNET_BUFFER_F_OFFLOAD_IP_CKSUM);
		      vnet_buffer (b)->sw_if_index[VLIB_TX] =
			upf_nwi_fib_index (FIB_PROTOCOL_IP4,
					   far->forward.nwi_index);
		    }
		  else
		    {
		      b->flags &= ~(VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
				    VNET_BUFFER_F_OFFLOAD_UDP_CKSUM);
		      vnet_buffer (b)->sw_if_index[VLIB_TX] =
			upf_nwi_fib_index (FIB_PROTOCOL_IP6,
					   far->forward.nwi_index);
		    }
		  next = UPF_PROCESS_NEXT_IP_INPUT;
		}
	    }
	  else if (far->apply_action & FAR_BUFFER)
	    {
	      next = UPF_PROCESS_NEXT_DROP;
	      // error = UPF_PROCESS_ERROR_NOT_YET;
	    }
	  else
	    {
	      next = UPF_PROCESS_NEXT_DROP;
	    }

	process:

#define IS_DL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	  gtp_debug ("pdr: %d, far: %d\n", pdr->id, far->id);
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

	trace:
	  b->error = error ? node->errors[error] : 0;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_process_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_id = pdr ? pdr->id : ~0;
	      tr->far_id = far ? far->id : ~0;
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

VLIB_NODE_FN (upf_ip4_process_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return upf_process (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_process_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return upf_process (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_process_node) = {
  .name = "upf-ip4-process",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_process_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_process_error_strings),
  .error_strings = upf_process_error_strings,
  .n_next_nodes = UPF_PROCESS_N_NEXT,
  .next_nodes = {
    [UPF_PROCESS_NEXT_DROP]          = "error-drop",
    [UPF_PROCESS_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_PROCESS_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_PROCESS_NEXT_IP_INPUT]      = "ip4-input",
    [UPF_PROCESS_NEXT_TCP_INPUT]     = "tcp4-input-nolookup",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_process_node) = {
  .name = "upf-ip6-process",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_process_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_process_error_strings),
  .error_strings = upf_process_error_strings,
  .n_next_nodes = UPF_PROCESS_N_NEXT,
  .next_nodes = {
    [UPF_PROCESS_NEXT_DROP]          = "error-drop",
    [UPF_PROCESS_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_PROCESS_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_PROCESS_NEXT_IP_INPUT]      = "ip6-input",
    [UPF_PROCESS_NEXT_TCP_INPUT]     = "tcp6-input-nolookup",
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
