/*
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

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <ioam/encap/ip6_ioam_trace.h>
#include <ioam/encap/ip6_ioam_e2e.h>
#include <ioam/udp-ping/udp_ping_packet.h>
#include <ioam/udp-ping/udp_ping.h>
#include <ioam/udp-ping/udp_ping_util.h>
#include <vnet/srv6/sr_packet.h>

typedef enum
{
  UDP_PING_NEXT_DROP,
  UDP_PING_NEXT_PUNT,
  UDP_PING_NEXT_UDP_LOOKUP,
  UDP_PING_NEXT_ICMP,
  UDP_PING_NEXT_IP6_LOOKUP,
  UDP_PING_NEXT_IP6_DROP,
  UDP_PING_N_NEXT,
} udp_ping_next_t;

udp_ping_main_t udp_ping_main;

uword
udp_ping_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt, vlib_frame_t * f);

extern int
ip6_hbh_ioam_trace_data_list_handler (vlib_buffer_t * b, ip6_header_t * ip,
				      ip6_hop_by_hop_option_t * opt);

typedef struct
{
  ip6_address_t src;
  ip6_address_t dst;
  u16 src_port;
  u16 dst_port;
  u16 handle;
  u16 next_index;
  u8 msg_type;
} udp_ping_trace_t;

/* packet trace format function */
static u8 *
format_udp_ping_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_ping_trace_t *t = va_arg (*args, udp_ping_trace_t *);

  s = format (s, "udp-ping-local: src %U, dst %U, src_port %u, dst_port %u "
	      "handle %u, next_index %u, msg_type %u",
	      format_ip6_address, &t->src,
	      format_ip6_address, &t->dst,
	      t->src_port, t->dst_port,
	      t->handle, t->next_index, t->msg_type);
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp_ping_node, static) =
{
  .function = udp_ping_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "udp-ping-process",
};
/* *INDENT-ON* */

void
udp_ping_calculate_timer_interval (void)
{
  int i;
  ip46_udp_ping_flow *flow = NULL;
  u16 min_interval = 0x1e9;

  for (i = 0; i < vec_len (udp_ping_main.ip46_flow); i++)
    {
      if (pool_is_free_index (udp_ping_main.ip46_flow, i))
	continue;

      flow = pool_elt_at_index (udp_ping_main.ip46_flow, i);

      if (min_interval > flow->udp_data.interval)
	min_interval = flow->udp_data.interval;
    }

  if (udp_ping_main.timer_interval != min_interval)
    {
      udp_ping_main.timer_interval = min_interval;
      vlib_process_signal_event (udp_ping_main.vlib_main,
				 udp_ping_node.index, EVENT_SIG_RECHECK, 0);
    }
}

void
ip46_udp_ping_set_flow (ip46_address_t src, ip46_address_t dst,
			u16 start_src_port, u16 end_src_port,
			u16 start_dst_port, u16 end_dst_port,
			u16 interval, u8 fault_det, u8 is_disable)
{
  u8 found = 0;
  ip46_udp_ping_flow *flow = NULL;
  int i;

  for (i = 0; i < vec_len (udp_ping_main.ip46_flow); i++)
    {
      if (pool_is_free_index (udp_ping_main.ip46_flow, i))
	continue;

      flow = pool_elt_at_index (udp_ping_main.ip46_flow, i);
      if ((0 == udp_ping_compare_flow (src, dst,
				       start_src_port, end_src_port,
				       start_dst_port, end_dst_port, flow)))
	{
	  found = 1;
	  break;
	}
    }

  if (found)
    {
      u16 cur_interval;
      if (is_disable)
	{
	  cur_interval = flow->udp_data.interval;
	  udp_ping_free_flow_data (flow);
	  pool_put_index (udp_ping_main.ip46_flow, i);
	  if (udp_ping_main.timer_interval == interval)
	    udp_ping_calculate_timer_interval ();
	  return;
	}

      cur_interval = flow->udp_data.interval;
      flow->udp_data.interval = interval;
      if (udp_ping_main.timer_interval > interval)
	{
	  udp_ping_main.timer_interval = interval;
	  vlib_process_signal_event (udp_ping_main.vlib_main,
				     udp_ping_node.index,
				     EVENT_SIG_RECHECK, 0);
	}
      else if (udp_ping_main.timer_interval == cur_interval)
	udp_ping_calculate_timer_interval ();

      return;
    }

  /* Delete operation and item not found */
  if (is_disable)
    return;

  /* Alloc new session */
  pool_get_aligned (udp_ping_main.ip46_flow, flow, CLIB_CACHE_LINE_BYTES);
  udp_ping_populate_flow (src, dst,
			  start_src_port, end_src_port,
			  start_dst_port, end_dst_port,
			  interval, fault_det, flow);

  udp_ping_create_rewrite (flow, (flow - udp_ping_main.ip46_flow));

  if (udp_ping_main.timer_interval > interval)
    {
      udp_ping_main.timer_interval = interval;
      vlib_process_signal_event (udp_ping_main.vlib_main,
				 udp_ping_node.index, EVENT_SIG_RECHECK, 0);
    }
  return;
}

uword
unformat_port_range (unformat_input_t * input, va_list * args)
{
  u16 *start_port, *end_port;
  uword c;
  u8 colon_present = 0;

  start_port = va_arg (*args, u16 *);
  end_port = va_arg (*args, u16 *);

  *start_port = *end_port = 0;
  /* Get start port */
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case '0' ... '9':
	  *start_port = ((*start_port) * 10) + (c - '0');
	  break;

	case ':':
	  colon_present = 1;
	  break;

	default:
	  return 0;
	}

      if (colon_present)
	break;
    }

  if (!colon_present)
    return 0;

  /* Get end port */
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case '0' ... '9':
	  *end_port = ((*end_port) * 10) + (c - '0');
	  break;

	default:
	  return 1;
	}
    }

  if (end_port < start_port)
    return 0;

  return 1;
}

static clib_error_t *
set_udp_ping_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_address_t dst, src;
  u16 start_src_port, end_src_port;
  u16 start_dst_port, end_dst_port;
  u32 interval;
  u8 is_disable = 0;
  u8 fault_det = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "src %U", unformat_ip46_address, &src, IP46_TYPE_ANY))
	;
      else if (unformat (input, "src-port-range %U",
			 unformat_port_range, &start_src_port, &end_src_port))
	;
      else
	if (unformat
	    (input, "dst %U", unformat_ip46_address, &dst, IP46_TYPE_ANY))
	;
      else if (unformat (input, "dst-port-range %U",
			 unformat_port_range, &start_dst_port, &end_dst_port))
	;
      else if (unformat (input, "interval %d", &interval))
	;
      else if (unformat (input, "fault-detect"))
	fault_det = 1;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	break;
    }

  ip46_udp_ping_set_flow (src, dst, start_src_port, end_src_port,
			  start_dst_port, end_dst_port, (u16) interval,
			  fault_det, is_disable);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_udp_ping_command, static) =
{
  .path = "set udp-ping",
  .short_help =
      "set udp-ping src <local IPv6 address>  src-port-range <local port range> \
      dst <remote IPv6 address> dst-port-range <destination port range> \
      interval <time interval in sec for which ping packet will be sent> \
      [disable]",
  .function = set_udp_ping_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_udp_ping_summary_cmd_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  u8 *s = 0;
  int i, j;
  ip46_udp_ping_flow *ip46_flow;
  u16 src_port, dst_port;
  udp_ping_flow_data *stats;

  s = format (s, "UDP-Ping data:\n");

  for (i = 0; i < vec_len (udp_ping_main.ip46_flow); i++)
    {
      if (pool_is_free_index (udp_ping_main.ip46_flow, i))
	continue;

      ip46_flow = pool_elt_at_index (udp_ping_main.ip46_flow, i);
      s = format (s, "Src: %U, Dst: %U\n",
		  format_ip46_address, &ip46_flow->src, IP46_TYPE_ANY,
		  format_ip46_address, &ip46_flow->dst, IP46_TYPE_ANY);

      s = format (s, "Start src port: %u, End src port: %u\n",
		  ip46_flow->udp_data.start_src_port,
		  ip46_flow->udp_data.end_src_port);
      s = format (s, "Start dst port: %u, End dst port: %u\n",
		  ip46_flow->udp_data.start_dst_port,
		  ip46_flow->udp_data.end_dst_port);
      s = format (s, "Interval: %u\n", ip46_flow->udp_data.interval);

      j = 0;
      for (src_port = ip46_flow->udp_data.start_src_port;
	   src_port <= ip46_flow->udp_data.end_src_port; src_port++)
	{
	  for (dst_port = ip46_flow->udp_data.start_dst_port;
	       dst_port <= ip46_flow->udp_data.end_dst_port; dst_port++)
	    {
	      stats = ip46_flow->udp_data.stats + j;
	      s =
		format (s, "\nSrc Port - %u, Dst Port - %u, Flow CTX - %u\n",
			src_port, dst_port, stats->flow_ctx);
	      s =
		format (s, "Path State - %s\n",
			(stats->retry > MAX_PING_RETRIES) ? "Down" : "Up");
	      s = format (s, "Path Data:\n");
	      s = print_analyse_flow (s,
				      &ip46_flow->udp_data.
				      stats[j].analyse_data);
	      j++;
	    }
	}
      s = format (s, "\n\n");
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_udp_ping_cmd, static) =
{
  .path = "show udp-ping summary",
  .short_help = "Summary of udp-ping",
  .function = show_udp_ping_summary_cmd_fn,
};
/* *INDENT-ON* */

/**
 * @brief UDP-Ping Process node.
 * @node udp-ping-process
 *
 * This is process node which wakes up when periodically to send
 * out udp probe packets for all configured sessions.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 */
uword
udp_ping_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  f64 now;
  uword *event_data = 0;
  int i;
  ip46_udp_ping_flow *ip46_flow;

  while (1)
    {
      vec_reset_length (event_data);
      vlib_process_wait_for_event_or_clock (vm, udp_ping_main.timer_interval);
      (void) vlib_process_get_events (vm, &event_data);
      now = vlib_time_now (vm);

      for (i = 0; i < vec_len (udp_ping_main.ip46_flow); i++)
	{
	  if (pool_is_free_index (udp_ping_main.ip46_flow, i))
	    continue;

	  ip46_flow = pool_elt_at_index (udp_ping_main.ip46_flow, i);
	  if (ip46_flow->udp_data.next_send_time < now)
	    udp_ping_send_ip6_pak (udp_ping_main.vlib_main, ip46_flow);
	}
    }
  return 0;
}

/**
 * @brief HopByHop analyse function for udp-ping response.
 *
 * Walks through all hbh options present in udp-ping response
 * and uses analyser library for the analysis.
 *
 */
void
udp_ping_analyse_hbh (vlib_buffer_t * b0,
		      u32 flow_id,
		      u16 src_port,
		      u16 dst_port,
		      ip6_hop_by_hop_option_t * opt0,
		      ip6_hop_by_hop_option_t * limit0, u16 len)
{
  u8 type0;
  ip46_udp_ping_flow *ip46_flow;
  u16 flow_index;
  ioam_analyser_data_t *data;
  ioam_e2e_option_t *e2e;
  ioam_trace_option_t *trace;

  /* If the packet doesnt match UDP session then return */
  if (PREDICT_FALSE (pool_is_free_index (udp_ping_main.ip46_flow, flow_id)))
    return;

  ip46_flow = udp_ping_main.ip46_flow + flow_id;
  /* Check port is within range */
  if (PREDICT_FALSE ((src_port < ip46_flow->udp_data.start_src_port) ||
		     (src_port > ip46_flow->udp_data.end_src_port) ||
		     (dst_port < ip46_flow->udp_data.start_dst_port) ||
		     (dst_port > ip46_flow->udp_data.end_dst_port)))
    return;

  flow_index = (src_port - ip46_flow->udp_data.start_src_port) *
    (ip46_flow->udp_data.end_dst_port - ip46_flow->udp_data.start_dst_port +
     1);
  flow_index += (dst_port - ip46_flow->udp_data.start_dst_port);
  data = &(ip46_flow->udp_data.stats[flow_index].analyse_data);

  data->pkt_counter++;
  data->bytes_counter += len;

  vnet_buffer (b0)->l2_classify.opaque_index =
    ip46_flow->udp_data.stats[flow_index].flow_ctx;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST:
	  /* Add trace for here as it hasnt been done yet */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
	  trace = (ioam_trace_option_t *) opt0;
	  if (PREDICT_FALSE
	      (trace->trace_hdr.ioam_trace_type & BIT_LOOPBACK_REPLY))
	    {
	      ip6_ioam_analyse_hbh_trace_loopback (data, &trace->trace_hdr,
						   (trace->hdr.length - 2));
	      return;
	    }
	  ip6_hbh_ioam_trace_data_list_handler (b0,
						vlib_buffer_get_current (b0),
						opt0);
	  (void) ip6_ioam_analyse_hbh_trace (data, &trace->trace_hdr, len,
					     (trace->hdr.length - 2));
	  break;
	case HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE:
	  e2e = (ioam_e2e_option_t *) opt0;
	  (void) ip6_ioam_analyse_hbh_e2e (data, &e2e->e2e_hdr, len);
	  break;
	case 0:		/* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  break;
	}
      opt0 = (ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
					  sizeof (ip6_hop_by_hop_option_t));
    }
  ip46_flow->udp_data.stats[flow_index].retry = 0;
}

/**
 * @brief UDP-Ping request/response handler function.
 *
 * Checks udp-ping packet type - request/response and handles them.
 * If not udp-ping packet then, strips off hbh options and enques
 * packet to protocol registered node to enable next protocol processing.
 *
 */
void
udp_ping_local_analyse (vlib_buffer_t * b0,
			ip6_header_t * ip0,
			ip6_hop_by_hop_header_t * hbh0, u16 * next0)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  *next0 = UDP_PING_NEXT_IP6_DROP;

  if (PREDICT_TRUE (hbh0->protocol == IP_PROTOCOL_UDP))
    {
      ip6_hop_by_hop_option_t *opt0;
      ip6_hop_by_hop_option_t *limit0;
      u16 p_len0;
      udp_ping_t *udp0;

      /* Check for udp ping packet */
      udp0 = (udp_ping_t *) ((u8 *) hbh0 + ((hbh0->length + 1) << 3));
      opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
      if ((udp0->ping_data.probe_marker1 ==
	   clib_host_to_net_u32 (UDP_PING_PROBE_MARKER1)) &&
	  (udp0->ping_data.probe_marker2 ==
	   clib_host_to_net_u32 (UDP_PING_PROBE_MARKER2)))
	{
	  if (udp0->ping_data.msg_type == UDP_PING_PROBE)
	    {
	      udp_ping_create_reply_from_probe_ip6 (ip0, hbh0, udp0);
	      /* Skip e2e processing */
	      vnet_buffer (b0)->l2_classify.opaque_index = 0x7FFFFFFF;
	      *next0 = UDP_PING_NEXT_IP6_LOOKUP;
	      return;
	    }

	  /* Reply */
	  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
	  limit0 = (ip6_hop_by_hop_option_t *)
	    ((u8 *) hbh0 + ((hbh0->length + 1) << 3));
	  p_len0 = clib_net_to_host_u16 (ip0->payload_length);
	  udp_ping_analyse_hbh (b0,
				clib_net_to_host_u16 (udp0->
						      ping_data.sender_handle),
				clib_net_to_host_u16 (udp0->udp.dst_port),
				clib_net_to_host_u16 (udp0->udp.src_port),
				opt0, limit0, p_len0);

	  /* UDP Ping packet, so return */
	  return;
	}
    }

  /* If next header is SR, then destination may get overwritten to
   * remote address. So pass it to SR processing as it may be local packet
   * afterall
   */
  if (PREDICT_FALSE (hbh0->protocol == IPPROTO_IPV6_ROUTE))
    goto end;

  /* Other case remove hbh-ioam headers */
  u64 *copy_dst0, *copy_src0;
  u16 new_l0;

  vlib_buffer_advance (b0, (hbh0->length + 1) << 3);

  new_l0 = clib_net_to_host_u16 (ip0->payload_length) -
    ((hbh0->length + 1) << 3);

  ip0->payload_length = clib_host_to_net_u16 (new_l0);

  ip0->protocol = hbh0->protocol;

  copy_src0 = (u64 *) ip0;
  copy_dst0 = copy_src0 + (hbh0->length + 1);
  copy_dst0[4] = copy_src0[4];
  copy_dst0[3] = copy_src0[3];
  copy_dst0[2] = copy_src0[2];
  copy_dst0[1] = copy_src0[1];
  copy_dst0[0] = copy_src0[0];

end:
  *next0 = lm->local_next_by_ip_protocol[hbh0->protocol];
  return;
}

/**
 * @brief udp ping request/response packet receive node.
 * @node udp-ping-local
 *
 * This function receives udp ping request/response packets and process them.
 * For request packets, response is created and sent.
 * For response packets, they are analysed and results stored.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer, next index usage
 *
 * <em>Uses:</em>
 * - <code>udp_ping_local_analyse(p0, ip0, hbh0, &next0)</code>
 *     - Checks packet type - request/respnse and process them.
 *
 * <em>Next Index:</em>
 * - Dispatches the packet to ip6-lookup/ip6-drop depending on type of packet.
 */
static uword
udp_ping_local_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  udp_ping_next_t next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  ip6_hop_by_hop_header_t *hbh0, *hbh1;
	  u16 next0, next1;
	  u32 pi0, pi1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    /* Prefetch 3 cache lines as we need to look deep into packet */
	    CLIB_PREFETCH (p2->data, 3 * CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, 3 * CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);

	  udp_ping_local_analyse (p0, ip0, hbh0, &next0);
	  udp_ping_local_analyse (p1, ip1, hbh1, &next1);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  udp_ping_trace_t *t0 =
		    vlib_add_trace (vm, node, p0, sizeof (*t0));
		  udp_ping_t *udp0;

		  /* Check for udp ping packet */
		  udp0 =
		    (udp_ping_t *) ((u8 *) hbh0 + ((hbh0->length + 1) << 3));
		  t0->src = ip0->src_address;
		  t0->dst = ip0->dst_address;
		  t0->src_port = clib_net_to_host_u16 (udp0->udp.src_port);
		  t0->dst_port = clib_net_to_host_u16 (udp0->udp.dst_port);
		  t0->handle =
		    clib_net_to_host_u16 (udp0->ping_data.sender_handle);
		  t0->msg_type = udp0->ping_data.msg_type;
		  t0->next_index = next0;
		}
	      if (p1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  udp_ping_trace_t *t1 =
		    vlib_add_trace (vm, node, p1, sizeof (*t1));
		  udp_ping_t *udp1;

		  /* Check for udp ping packet */
		  udp1 =
		    (udp_ping_t *) ((u8 *) hbh1 + ((hbh1->length + 1) << 3));
		  t1->src = ip1->src_address;
		  t1->dst = ip1->dst_address;
		  t1->src_port = clib_net_to_host_u16 (udp1->udp.src_port);
		  t1->dst_port = clib_net_to_host_u16 (udp1->udp.dst_port);
		  t1->handle =
		    clib_net_to_host_u16 (udp1->ping_data.sender_handle);
		  t1->msg_type = udp1->ping_data.msg_type;
		  t1->next_index = next1;
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0;
	  u16 next0;
	  u32 pi0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);
	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);

	  udp_ping_local_analyse (p0, ip0, hbh0, &next0);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  udp_ping_trace_t *t0 =
		    vlib_add_trace (vm, node, p0, sizeof (*t0));
		  udp_ping_t *udp0;

		  /* Check for udp ping packet */
		  udp0 =
		    (udp_ping_t *) ((u8 *) hbh0 + ((hbh0->length + 1) << 3));
		  t0->src = ip0->src_address;
		  t0->dst = ip0->dst_address;
		  t0->src_port = clib_net_to_host_u16 (udp0->udp.src_port);
		  t0->dst_port = clib_net_to_host_u16 (udp0->udp.dst_port);
		  t0->handle =
		    clib_net_to_host_u16 (udp0->ping_data.sender_handle);
		  t0->msg_type = udp0->ping_data.msg_type;
		  t0->next_index = next0;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
/*
 * Node for udp-ping-local
 */
VLIB_REGISTER_NODE (udp_ping_local, static) =
{
  .function = udp_ping_local_node_fn,
  .name = "udp-ping-local",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_ping_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = UDP_PING_N_NEXT,
  .next_nodes =
    {
      [UDP_PING_NEXT_DROP] = "error-drop",
      [UDP_PING_NEXT_PUNT] = "error-punt",
      [UDP_PING_NEXT_UDP_LOOKUP] = "ip6-udp-lookup",
      [UDP_PING_NEXT_ICMP] = "ip6-icmp-input",
      [UDP_PING_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [UDP_PING_NEXT_IP6_DROP] = "ip6-drop",
    },
};
/* *INDENT-ON* */

static clib_error_t *
udp_ping_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  udp_ping_main.vlib_main = vm;
  udp_ping_main.vnet_main = vnet_get_main ();
  udp_ping_main.timer_interval = 1e9;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return (error);

  ip6_register_protocol (IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
			 udp_ping_local.index);
  return 0;
}

VLIB_INIT_FUNCTION (udp_ping_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
