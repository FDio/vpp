/*
 * dhcp6_proxy_node.c: dhcpv6 proxy node processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/fib/fib.h>

static char *dhcpv6_proxy_error_strings[] = {
#define dhcpv6_proxy_error(n,s) s,
#include <vnet/dhcp/dhcp6_proxy_error.def>
#undef dhcpv6_proxy_error
};

#define foreach_dhcpv6_proxy_to_server_input_next \
  _ (DROP, "error-drop")			\
  _ (LOOKUP, "ip6-lookup")                      \
  _ (SEND_TO_CLIENT, "dhcpv6-proxy-to-client")


typedef enum
{
#define _(s,n) DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_##s,
  foreach_dhcpv6_proxy_to_server_input_next
#undef _
    DHCPV6_PROXY_TO_SERVER_INPUT_N_NEXT,
} dhcpv6_proxy_to_server_input_next_t;

typedef struct
{
  /* 0 => to server, 1 => to client */
  int which;
  u8 packet_data[64];
  u32 error;
  u32 sw_if_index;
  u32 original_sw_if_index;
} dhcpv6_proxy_trace_t;

static vlib_node_registration_t dhcpv6_proxy_to_server_node;
static vlib_node_registration_t dhcpv6_proxy_to_client_node;

/* all DHCP servers address */
static ip6_address_t all_dhcpv6_server_address;
static ip6_address_t all_dhcpv6_server_relay_agent_address;

static u8 *
format_dhcpv6_proxy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dhcpv6_proxy_trace_t *t = va_arg (*args, dhcpv6_proxy_trace_t *);

  if (t->which == 0)
    s = format (s, "DHCPV6 proxy: sent to server %U",
		format_ip6_address, &t->packet_data, sizeof (ip6_address_t));
  else
    s = format (s, "DHCPV6 proxy: sent to client from %U",
		format_ip6_address, &t->packet_data, sizeof (ip6_address_t));
  if (t->error != (u32) ~ 0)
    s = format (s, " error: %s\n", dhcpv6_proxy_error_strings[t->error]);

  s = format (s, "  original_sw_if_index: %d, sw_if_index: %d\n",
	      t->original_sw_if_index, t->sw_if_index);

  return s;
}

static u8 *
format_dhcpv6_proxy_header_with_length (u8 * s, va_list * args)
{
  dhcpv6_header_t *h = va_arg (*args, dhcpv6_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "dhcpv6 header truncated");

  s = format (s, "DHCPV6 Proxy");

  return s;
}

/* get first interface address */
static ip6_address_t *
ip6_interface_first_global_or_site_address (ip6_main_t * im, u32 sw_if_index)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip6_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip6_address_t * a = ip_interface_address_get_address (lm, ia);
    if ((a->as_u8[0] & 0xe0) == 0x20 ||
        (a->as_u8[0] & 0xfe) == 0xfc)  {
        result = a;
        break;
    }
  }));
  /* *INDENT-ON* */
  return result;
}

static inline void
copy_ip6_address (ip6_address_t * dst, ip6_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

static uword
dhcpv6_proxy_to_server_input (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  dhcp_proxy_main_t *dpm = &dhcp_proxy_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 pkts_to_server = 0, pkts_to_client = 0, pkts_no_server = 0;
  u32 pkts_no_interface_address = 0, pkts_no_exceeding_max_hop = 0;
  u32 pkts_no_src_address = 0;
  u32 pkts_wrong_msg_type = 0;
  u32 pkts_too_big = 0;
  ip6_main_t *im = &ip6_main;
  ip6_address_t *src;
  int bogus_length;
  dhcp_proxy_t *proxy;
  dhcp_server_t *server;
  u32 rx_fib_idx = 0, server_fib_idx = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  u32 sw_if_index = 0;
	  u32 rx_sw_if_index = 0;
	  vnet_sw_interface_t *swif;
	  u32 bi0;
	  vlib_buffer_t *b0;
	  udp_header_t *u0, *u1;
	  dhcpv6_header_t *h0;	// client msg hdr
	  ip6_header_t *ip0, *ip1;
	  ip6_address_t _ia0, *ia0 = &_ia0;
	  u32 next0;
	  u32 error0 = (u32) ~ 0;
	  dhcpv6_option_t *fwd_opt;
	  dhcpv6_relay_hdr_t *r1;
	  u16 len;
	  dhcpv6_int_id_t *id1;
	  dhcpv6_vss_t *vss1;
	  dhcpv6_client_mac_t *cmac;	// client mac
	  ethernet_header_t *e_h0;
	  u8 client_src_mac[6];
	  dhcp_vss_t *vss;
	  u8 is_solicit = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  h0 = vlib_buffer_get_current (b0);

	  /*
	   * udp_local hands us the DHCPV6 header.
	   */
	  u0 = (void *) h0 - (sizeof (*u0));
	  ip0 = (void *) u0 - (sizeof (*ip0));
	  e_h0 = (void *) ip0 - ethernet_buffer_header_size (b0);

	  clib_memcpy (client_src_mac, e_h0->src_address, 6);

	  switch (h0->msg_type)
	    {
	    case DHCPV6_MSG_SOLICIT:
	    case DHCPV6_MSG_REQUEST:
	    case DHCPV6_MSG_CONFIRM:
	    case DHCPV6_MSG_RENEW:
	    case DHCPV6_MSG_REBIND:
	    case DHCPV6_MSG_RELEASE:
	    case DHCPV6_MSG_DECLINE:
	    case DHCPV6_MSG_INFORMATION_REQUEST:
	    case DHCPV6_MSG_RELAY_FORW:
	      /* send to server */
	      break;
	    case DHCPV6_MSG_RELAY_REPL:
	      /* send to client */
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_SEND_TO_CLIENT;
	      error0 = 0;
	      pkts_to_client++;
	      goto do_enqueue;
	    default:
	      /* drop the packet */
	      pkts_wrong_msg_type++;
	      error0 = DHCPV6_PROXY_ERROR_WRONG_MESSAGE_TYPE;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      goto do_trace;

	    }

	  /* Send to DHCPV6 server via the configured FIB */
	  rx_sw_if_index = sw_if_index =
	    vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_idx = im->mfib_index_by_sw_if_index[rx_sw_if_index];
	  proxy = dhcp_get_proxy (dpm, rx_fib_idx, FIB_PROTOCOL_IP6);

	  if (PREDICT_FALSE (NULL == proxy))
	    {
	      error0 = DHCPV6_PROXY_ERROR_NO_SERVER;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_no_server++;
	      goto do_trace;
	    }

	  server = &proxy->dhcp_servers[0];
	  server_fib_idx = server->server_fib_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = server_fib_idx;


	  /* relay-option header pointer */
	  vlib_buffer_advance (b0, -(sizeof (*fwd_opt)));
	  fwd_opt = vlib_buffer_get_current (b0);
	  /* relay message header pointer */
	  vlib_buffer_advance (b0, -(sizeof (*r1)));
	  r1 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, -(sizeof (*u1)));
	  u1 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, -(sizeof (*ip1)));
	  ip1 = vlib_buffer_get_current (b0);

	  /* fill in all that rubbish... */
	  len = clib_net_to_host_u16 (u0->length) - sizeof (udp_header_t);
	  copy_ip6_address (&r1->peer_addr, &ip0->src_address);

	  r1->msg_type = DHCPV6_MSG_RELAY_FORW;
	  fwd_opt->length = clib_host_to_net_u16 (len);
	  fwd_opt->option = clib_host_to_net_u16 (DHCPV6_OPTION_RELAY_MSG);

	  r1->hop_count++;
	  r1->hop_count =
	    (h0->msg_type != DHCPV6_MSG_RELAY_FORW) ? 0 : r1->hop_count;

	  if (PREDICT_FALSE (r1->hop_count >= HOP_COUNT_LIMIT))
	    {
	      error0 = DHCPV6_RELAY_PKT_DROP_MAX_HOPS;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_no_exceeding_max_hop++;
	      goto do_trace;
	    }


	  /* If relay-fwd and src address is site or global unicast address  */
	  if (h0->msg_type == DHCPV6_MSG_RELAY_FORW &&
	      ((ip0->src_address.as_u8[0] & 0xe0) == 0x20 ||
	       (ip0->src_address.as_u8[0] & 0xfe) == 0xfc))
	    {
	      /* Set link address to zero */
	      r1->link_addr.as_u64[0] = 0;
	      r1->link_addr.as_u64[1] = 0;
	      goto link_address_set;
	    }

	  /* if receiving interface is unnumbered, use receiving interface
	   * IP address as link address, otherwise use the loopback interface
	   * IP address as link address.
	   */

	  swif = vnet_get_sw_interface (vnm, rx_sw_if_index);
	  if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	    sw_if_index = swif->unnumbered_sw_if_index;

	  ia0 =
	    ip6_interface_first_global_or_site_address (&ip6_main,
							sw_if_index);
	  if (ia0 == 0)
	    {
	      error0 = DHCPV6_PROXY_ERROR_NO_INTERFACE_ADDRESS;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_no_interface_address++;
	      goto do_trace;
	    }

	  copy_ip6_address (&r1->link_addr, ia0);

	link_address_set:

	  if ((b0->current_length + sizeof (*id1) + sizeof (*vss1) +
	       sizeof (*cmac)) > VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES)
	    {
	      error0 = DHCPV6_PROXY_ERROR_PKT_TOO_BIG;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_too_big++;
	      goto do_trace;
	    }

	  id1 = (dhcpv6_int_id_t *) (((uword) ip1) + b0->current_length);
	  b0->current_length += (sizeof (*id1));

	  id1->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_INTERFACE_ID);
	  id1->opt.length = clib_host_to_net_u16 (sizeof (rx_sw_if_index));
	  id1->int_idx = clib_host_to_net_u32 (rx_sw_if_index);

	  u1->length = 0;
	  if (h0->msg_type != DHCPV6_MSG_RELAY_FORW)
	    {
	      cmac =
		(dhcpv6_client_mac_t *) (((uword) ip1) + b0->current_length);
	      b0->current_length += (sizeof (*cmac));
	      cmac->opt.length = clib_host_to_net_u16 (sizeof (*cmac) -
						       sizeof (cmac->opt));
	      cmac->opt.option =
		clib_host_to_net_u16
		(DHCPV6_OPTION_CLIENT_LINK_LAYER_ADDRESS);
	      cmac->link_type = clib_host_to_net_u16 (1);	/* ethernet */
	      clib_memcpy (cmac->data, client_src_mac, 6);
	      u1->length += sizeof (*cmac);
	    }

	  vss = dhcp_get_vss_info (dpm, rx_fib_idx, FIB_PROTOCOL_IP6);

	  if (vss)
	    {
	      u16 id_len;	/* length of VPN ID */
	      u16 type_len = sizeof (vss1->vss_type);

	      vss1 = (dhcpv6_vss_t *) (((uword) ip1) + b0->current_length);
	      vss1->vss_type = vss->vss_type;
	      if (vss->vss_type == VSS_TYPE_VPN_ID)
		{
		  id_len = sizeof (vss->vpn_id);	/* vpn_id is 7 bytes */
		  memcpy (vss1->data, vss->vpn_id, id_len);
		}
	      else if (vss->vss_type == VSS_TYPE_ASCII)
		{
		  id_len = vec_len (vss->vpn_ascii_id);
		  memcpy (vss1->data, vss->vpn_ascii_id, id_len);
		}
	      else		/* must be VSS_TYPE_DEFAULT, no VPN ID */
		id_len = 0;

	      vss1->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_VSS);
	      vss1->opt.length = clib_host_to_net_u16 (type_len + id_len);
	      u1->length += type_len + id_len + sizeof (vss1->opt);
	      b0->current_length += type_len + id_len + sizeof (vss1->opt);
	    }

	  pkts_to_server++;
	  u1->checksum = 0;
	  u1->src_port = clib_host_to_net_u16 (UDP_DST_PORT_dhcpv6_to_client);
	  u1->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_dhcpv6_to_server);

	  u1->length =
	    clib_host_to_net_u16 (clib_net_to_host_u16 (fwd_opt->length) +
				  sizeof (*r1) + sizeof (*fwd_opt) +
				  sizeof (*u1) + sizeof (*id1) + u1->length);

	  clib_memset (ip1, 0, sizeof (*ip1));
	  ip1->ip_version_traffic_class_and_flow_label = 0x60;
	  ip1->payload_length = u1->length;
	  ip1->protocol = PROTO_UDP;
	  ip1->hop_limit = HOP_COUNT_LIMIT;
	  src = ((server->dhcp_server.ip6.as_u64[0] ||
		  server->dhcp_server.ip6.as_u64[1]) ?
		 &server->dhcp_server.ip6 : &all_dhcpv6_server_address);
	  copy_ip6_address (&ip1->dst_address, src);


	  ia0 = ip6_interface_first_global_or_site_address
	    (&ip6_main, vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	  src = (proxy->dhcp_src_address.ip6.as_u64[0] ||
		 proxy->dhcp_src_address.ip6.as_u64[1]) ?
	    &proxy->dhcp_src_address.ip6 : ia0;
	  if (ia0 == 0)
	    {
	      error0 = DHCPV6_PROXY_ERROR_NO_SRC_ADDRESS;
	      next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_no_src_address++;
	      goto do_trace;
	    }

	  copy_ip6_address (&ip1->src_address, src);


	  u1->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip1,
							    &bogus_length);
	  ASSERT (bogus_length == 0);

	  next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP;

	  is_solicit = (DHCPV6_MSG_SOLICIT == h0->msg_type);

	  /*
	   * If we have multiple servers configured and this is the
	   * client's discover message, then send copies to each of
	   * those servers
	   */
	  if (is_solicit && vec_len (proxy->dhcp_servers) > 1)
	    {
	      u32 ii;

	      for (ii = 1; ii < vec_len (proxy->dhcp_servers); ii++)
		{
		  vlib_buffer_t *c0;
		  u32 ci0;

		  c0 = vlib_buffer_copy (vm, b0);
		  vlib_buffer_copy_trace_flag (vm, c0, bi0);
		  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);
		  ci0 = vlib_get_buffer_index (vm, c0);
		  server = &proxy->dhcp_servers[ii];

		  ip0 = vlib_buffer_get_current (c0);

		  src = ((server->dhcp_server.ip6.as_u64[0] ||
			  server->dhcp_server.ip6.as_u64[1]) ?
			 &server->dhcp_server.ip6 :
			 &all_dhcpv6_server_address);
		  copy_ip6_address (&ip1->dst_address, src);

		  to_next[0] = ci0;
		  to_next += 1;
		  n_left_to_next -= 1;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   ci0, next0);

		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      dhcpv6_proxy_trace_t *tr;

		      tr = vlib_add_trace (vm, node, c0, sizeof (*tr));
		      tr->which = 0;	/* to server */
		      tr->error = error0;
		      tr->original_sw_if_index = rx_sw_if_index;
		      tr->sw_if_index = sw_if_index;
		      if (next0 == DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP)
			copy_ip6_address ((ip6_address_t *) &
					  tr->packet_data[0],
					  &server->dhcp_server.ip6);
		    }

		  if (PREDICT_FALSE (0 == n_left_to_next))
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      vlib_get_next_frame (vm, node, next_index,
					   to_next, n_left_to_next);
		    }
		}
	    }

	do_trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcpv6_proxy_trace_t *tr = vlib_add_trace (vm, node,
							 b0, sizeof (*tr));
	      tr->which = 0;	/* to server */
	      tr->error = error0;
	      tr->original_sw_if_index = rx_sw_if_index;
	      tr->sw_if_index = sw_if_index;
	      if (DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP == next0)
		copy_ip6_address ((ip6_address_t *) & tr->packet_data[0],
				  &server->dhcp_server.ip6);
	    }

	do_enqueue:
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_RELAY_TO_CLIENT,
			       pkts_to_client);
  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_RELAY_TO_SERVER,
			       pkts_to_server);
  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_NO_INTERFACE_ADDRESS,
			       pkts_no_interface_address);
  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_WRONG_MESSAGE_TYPE,
			       pkts_wrong_msg_type);
  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_NO_SRC_ADDRESS,
			       pkts_no_src_address);
  vlib_node_increment_counter (vm, dhcpv6_proxy_to_server_node.index,
			       DHCPV6_PROXY_ERROR_PKT_TOO_BIG, pkts_too_big);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcpv6_proxy_to_server_node, static) = {
  .function = dhcpv6_proxy_to_server_input,
  .name = "dhcpv6-proxy-to-server",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = DHCPV6_PROXY_N_ERROR,
  .error_strings = dhcpv6_proxy_error_strings,

  .n_next_nodes = DHCPV6_PROXY_TO_SERVER_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_##s] = n,
    foreach_dhcpv6_proxy_to_server_input_next
#undef _
  },

  .format_buffer = format_dhcpv6_proxy_header_with_length,
  .format_trace = format_dhcpv6_proxy_trace,
#if 0
  .unformat_buffer = unformat_dhcpv6_proxy_header,
#endif
};
/* *INDENT-ON* */

static uword
dhcpv6_proxy_to_client_input (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{

  u32 n_left_from, *from;
  ethernet_main_t *em = vnet_get_ethernet_main ();
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  dhcp_proxy_t *proxy;
  dhcp_server_t *server;
  vnet_main_t *vnm = vnet_get_main ();
  int bogus_length;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      udp_header_t *u0, *u1 = 0;
      dhcpv6_relay_hdr_t *h0;
      ip6_header_t *ip1 = 0, *ip0;
      ip6_address_t _ia0, *ia0 = &_ia0;
      ip6_address_t client_address;
      ethernet_interface_t *ei0;
      ethernet_header_t *mac0;
      vnet_hw_interface_t *hi0;
      vlib_frame_t *f0;
      u32 *to_next0;
      u32 sw_if_index = ~0;
      u32 original_sw_if_index = ~0;
      vnet_sw_interface_t *si0;
      u32 error0 = (u32) ~ 0;
      vnet_sw_interface_t *swif;
      dhcpv6_option_t *r0 = 0, *o;
      u16 len = 0;
      u8 interface_opt_flag = 0;
      u8 relay_msg_opt_flag = 0;
      ip6_main_t *im = &ip6_main;
      u32 server_fib_idx, client_fib_idx;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0);

      if (DHCPV6_MSG_RELAY_REPL != h0->msg_type)
	{
	  error0 = DHCPV6_PROXY_ERROR_WRONG_MESSAGE_TYPE;

	drop_packet:
	  vlib_node_increment_counter (vm, dhcpv6_proxy_to_client_node.index,
				       error0, 1);

	  f0 = vlib_get_frame_to_node (vm, dm->error_drop_node_index);
	  to_next0 = vlib_frame_vector_args (f0);
	  to_next0[0] = bi0;
	  f0->n_vectors = 1;
	  vlib_put_frame_to_node (vm, dm->error_drop_node_index, f0);
	  goto do_trace;
	}
      /* hop count seems not need to be checked */
      if (HOP_COUNT_LIMIT < h0->hop_count)
	{
	  error0 = DHCPV6_RELAY_PKT_DROP_MAX_HOPS;
	  goto drop_packet;
	}
      u0 = (void *) h0 - (sizeof (*u0));
      ip0 = (void *) u0 - (sizeof (*ip0));

      vlib_buffer_advance (b0, sizeof (*h0));
      o = vlib_buffer_get_current (b0);

      /* Parse through TLVs looking for option 18 (DHCPV6_OPTION_INTERFACE_ID)
         _and_ option 9 (DHCPV6_OPTION_RELAY_MSG) option which must be there.
         Currently assuming no other options need to be processed
         The interface-ID is the FIB number we need
         to track down the client-facing interface */

      while ((u8 *) o < (b0->data + b0->current_data + b0->current_length))
	{
	  if (DHCPV6_OPTION_INTERFACE_ID == clib_net_to_host_u16 (o->option))
	    {
	      interface_opt_flag = 1;
	      if (clib_net_to_host_u16 (o->length) == sizeof (sw_if_index))
		sw_if_index =
		  clib_net_to_host_u32 (((dhcpv6_int_id_t *) o)->int_idx);
	      if (sw_if_index >= vec_len (im->fib_index_by_sw_if_index))
		{
		  error0 = DHCPV6_PROXY_ERROR_WRONG_INTERFACE_ID_OPTION;
		  goto drop_packet;
		}
	    }
	  if (DHCPV6_OPTION_RELAY_MSG == clib_net_to_host_u16 (o->option))
	    {
	      relay_msg_opt_flag = 1;
	      r0 = vlib_buffer_get_current (b0);
	    }
	  if ((relay_msg_opt_flag == 1) && (interface_opt_flag == 1))
	    break;
	  vlib_buffer_advance (b0,
			       sizeof (*o) +
			       clib_net_to_host_u16 (o->length));
	  o =
	    (dhcpv6_option_t *) (((uword) o) +
				 clib_net_to_host_u16 (o->length) +
				 sizeof (*o));
	}

      if ((relay_msg_opt_flag == 0) || (r0 == 0))
	{
	  error0 = DHCPV6_PROXY_ERROR_NO_RELAY_MESSAGE_OPTION;
	  goto drop_packet;
	}

      if ((u32) ~ 0 == sw_if_index)
	{
	  error0 = DHCPV6_PROXY_ERROR_NO_CIRCUIT_ID_OPTION;
	  goto drop_packet;
	}

      //Advance buffer to start of encapsulated DHCPv6 message
      vlib_buffer_advance (b0, sizeof (*r0));

      client_fib_idx = im->mfib_index_by_sw_if_index[sw_if_index];
      proxy = dhcp_get_proxy (dm, client_fib_idx, FIB_PROTOCOL_IP6);

      if (NULL == proxy)
	{
	  error0 = DHCPV6_PROXY_ERROR_NO_SERVER;
	  goto drop_packet;
	}

      server_fib_idx = im->fib_index_by_sw_if_index
	[vnet_buffer (b0)->sw_if_index[VLIB_RX]];

      vec_foreach (server, proxy->dhcp_servers)
      {
	if (server_fib_idx == server->server_fib_index &&
	    ip0->src_address.as_u64[0] == server->dhcp_server.ip6.as_u64[0] &&
	    ip0->src_address.as_u64[1] == server->dhcp_server.ip6.as_u64[1])
	  {
	    goto server_found;
	  }
      }

      //drop packet if not from server with configured address or FIB
      error0 = DHCPV6_PROXY_ERROR_BAD_SVR_FIB_OR_ADDRESS;
      goto drop_packet;

    server_found:
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = original_sw_if_index
	= sw_if_index;

      swif = vnet_get_sw_interface (vnm, original_sw_if_index);
      if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	sw_if_index = swif->unnumbered_sw_if_index;


      /*
       * udp_local hands us the DHCPV6 header, need udp hdr,
       * ip hdr to relay to client
       */
      vlib_buffer_advance (b0, -(sizeof (*u1)));
      u1 = vlib_buffer_get_current (b0);

      vlib_buffer_advance (b0, -(sizeof (*ip1)));
      ip1 = vlib_buffer_get_current (b0);

      copy_ip6_address (&client_address, &h0->peer_addr);

      ia0 = ip6_interface_first_address (&ip6_main, sw_if_index);
      if (ia0 == 0)
	{
	  error0 = DHCPV6_PROXY_ERROR_NO_INTERFACE_ADDRESS;
	  goto drop_packet;
	}

      len = clib_net_to_host_u16 (r0->length);
      clib_memset (ip1, 0, sizeof (*ip1));
      copy_ip6_address (&ip1->dst_address, &client_address);
      u1->checksum = 0;
      u1->src_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcpv6_to_server);
      u1->dst_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcpv6_to_client);
      u1->length = clib_host_to_net_u16 (len + sizeof (udp_header_t));

      ip1->ip_version_traffic_class_and_flow_label =
	ip0->ip_version_traffic_class_and_flow_label & 0x00000fff;
      ip1->payload_length = u1->length;
      ip1->protocol = PROTO_UDP;
      ip1->hop_limit = HOP_COUNT_LIMIT;
      copy_ip6_address (&ip1->src_address, ia0);

      u1->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip1,
							&bogus_length);
      ASSERT (bogus_length == 0);

      vlib_buffer_advance (b0, -(sizeof (ethernet_header_t)));
      si0 = vnet_get_sw_interface (vnm, original_sw_if_index);
      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	vlib_buffer_advance (b0, -4 /* space for VLAN tag */ );

      mac0 = vlib_buffer_get_current (b0);

      hi0 = vnet_get_sup_hw_interface (vnm, original_sw_if_index);
      ei0 = pool_elt_at_index (em->interfaces, hi0->hw_instance);
      clib_memcpy (mac0->src_address, ei0->address, sizeof (ei0->address));
      clib_memset (&mac0->dst_address, 0xff, sizeof (mac0->dst_address));
      mac0->type = (si0->type == VNET_SW_INTERFACE_TYPE_SUB) ?
	clib_net_to_host_u16 (0x8100) : clib_net_to_host_u16 (0x86dd);

      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	{
	  u32 *vlan_tag = (u32 *) (mac0 + 1);
	  u32 tmp;
	  tmp = (si0->sub.id << 16) | 0x0800;
	  *vlan_tag = clib_host_to_net_u32 (tmp);
	}

      /* $$$ consider adding a dynamic next to the graph node, for performance */
      f0 = vlib_get_frame_to_node (vm, hi0->output_node_index);
      to_next0 = vlib_frame_vector_args (f0);
      to_next0[0] = bi0;
      f0->n_vectors = 1;
      vlib_put_frame_to_node (vm, hi0->output_node_index, f0);

    do_trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  dhcpv6_proxy_trace_t *tr = vlib_add_trace (vm, node,
						     b0, sizeof (*tr));
	  tr->which = 1;	/* to client */
	  if (ia0)
	    copy_ip6_address ((ip6_address_t *) tr->packet_data, ia0);
	  tr->error = error0;
	  tr->original_sw_if_index = original_sw_if_index;
	  tr->sw_if_index = sw_if_index;
	}
    }
  return from_frame->n_vectors;

}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcpv6_proxy_to_client_node, static) = {
  .function = dhcpv6_proxy_to_client_input,
  .name = "dhcpv6-proxy-to-client",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = DHCPV6_PROXY_N_ERROR,
  .error_strings = dhcpv6_proxy_error_strings,
  .format_buffer = format_dhcpv6_proxy_header_with_length,
  .format_trace = format_dhcpv6_proxy_trace,
#if 0
  .unformat_buffer = unformat_dhcpv6_proxy_header,
#endif
};
/* *INDENT-ON* */

static clib_error_t *
dhcp6_proxy_init (vlib_main_t * vm)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  vlib_node_t *error_drop_node;

  error_drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  dm->error_drop_node_index = error_drop_node->index;

  /* RFC says this is the dhcpv6 server address  */
  all_dhcpv6_server_address.as_u64[0] =
    clib_host_to_net_u64 (0xFF05000000000000);
  all_dhcpv6_server_address.as_u64[1] = clib_host_to_net_u64 (0x00010003);

  /* RFC says this is the server and agent address */
  all_dhcpv6_server_relay_agent_address.as_u64[0] =
    clib_host_to_net_u64 (0xFF02000000000000);
  all_dhcpv6_server_relay_agent_address.as_u64[1] =
    clib_host_to_net_u64 (0x00010002);

  return 0;
}

VLIB_INIT_FUNCTION (dhcp6_proxy_init);

int
dhcp6_proxy_set_server (ip46_address_t * addr,
			ip46_address_t * src_addr,
			u32 rx_table_id, u32 server_table_id, int is_del)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 rx_fib_index = 0;
  int rc = 0;

  const mfib_prefix_t all_dhcp_servers = {
    .fp_len = 128,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_grp_addr = {
		    .ip6 = all_dhcpv6_server_relay_agent_address,
		    }
  };

  if (ip46_address_is_zero (addr))
    return VNET_API_ERROR_INVALID_DST_ADDRESS;

  if (ip46_address_is_zero (src_addr))
    return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  rx_fib_index = mfib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6,
						     rx_table_id,
						     MFIB_SOURCE_DHCP);

  if (is_del)
    {
      if (dhcp_proxy_server_del (FIB_PROTOCOL_IP6, rx_fib_index,
				 addr, server_table_id))
	{
	  mfib_table_entry_delete (rx_fib_index,
				   &all_dhcp_servers, MFIB_SOURCE_DHCP);
	  mfib_table_unlock (rx_fib_index, FIB_PROTOCOL_IP6,
			     MFIB_SOURCE_DHCP);

	  udp_unregister_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
				   0 /* is_ip6 */ );
	  udp_unregister_dst_port (vm, UDP_DST_PORT_dhcpv6_to_server,
				   0 /* is_ip6 */ );
	}
    }
  else
    {
      const fib_route_path_t path_for_us = {
	.frp_proto = DPO_PROTO_IP6,
	.frp_addr = zero_addr,
	.frp_sw_if_index = 0xffffffff,
	.frp_fib_index = ~0,
	.frp_weight = 0,
	.frp_flags = FIB_ROUTE_PATH_LOCAL,
      };
      if (dhcp_proxy_server_add (FIB_PROTOCOL_IP6, addr, src_addr,
				 rx_fib_index, server_table_id))
	{
	  mfib_table_entry_path_update (rx_fib_index,
					&all_dhcp_servers,
					MFIB_SOURCE_DHCP,
					&path_for_us, MFIB_ITF_FLAG_FORWARD);
	  /*
	   * Each interface that is enabled in this table, needs to be added
	   * as an accepting interface, but this is not easily doable in VPP.
	   * So we cheat. Add a flag to the entry that indicates accept form
	   * any interface.
	   * We will still only accept on v6 enabled interfaces, since the
	   * input feature ensures this.
	   */
	  mfib_table_entry_update (rx_fib_index,
				   &all_dhcp_servers,
				   MFIB_SOURCE_DHCP,
				   MFIB_RPF_ID_NONE,
				   MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);
	  mfib_table_lock (rx_fib_index, FIB_PROTOCOL_IP6, MFIB_SOURCE_DHCP);

	  udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
				 dhcpv6_proxy_to_client_node.index,
				 0 /* is_ip6 */ );
	  udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_server,
				 dhcpv6_proxy_to_server_node.index,
				 0 /* is_ip6 */ );
	}
    }

  mfib_table_unlock (rx_fib_index, FIB_PROTOCOL_IP6, MFIB_SOURCE_DHCP);

  return (rc);
}

static clib_error_t *
dhcpv6_proxy_set_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ip46_address_t addr, src_addr;
  int set_server = 0, set_src_address = 0;
  u32 rx_table_id = 0, server_table_id = 0;
  int is_del = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server %U", unformat_ip6_address, &addr.ip6))
	set_server = 1;
      else if (unformat (input, "src-address %U",
			 unformat_ip6_address, &src_addr.ip6))
	set_src_address = 1;
      else if (unformat (input, "server-fib-id %d", &server_table_id))
	;
      else if (unformat (input, "rx-fib-id %d", &rx_table_id))
	;
      else if (unformat (input, "delete") || unformat (input, "del"))
	is_del = 1;
      else
	break;
    }

  if (is_del || (set_server && set_src_address))
    {
      int rv;

      rv = dhcp6_proxy_set_server (&addr, &src_addr, rx_table_id,
				   server_table_id, is_del);

      //TODO: Complete the errors
      switch (rv)
	{
	case 0:
	  return 0;

	case VNET_API_ERROR_INVALID_DST_ADDRESS:
	  return clib_error_return (0, "Invalid server address");

	case VNET_API_ERROR_INVALID_SRC_ADDRESS:
	  return clib_error_return (0, "Invalid src address");

	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  return clib_error_return
	    (0, "Fib id %d: no per-fib DHCP server configured", rx_table_id);

	default:
	  return clib_error_return (0, "BUG: rv %d", rv);
	}
    }
  else
    return clib_error_return (0, "parse error`%U'",
			      format_unformat_error, input);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcpv6_proxy_set_command, static) = {
  .path = "set dhcpv6 proxy",
  .short_help = "set dhcpv6 proxy [del] server <ipv6-addr> src-address <ipv6-addr> "
		  "[server-fib-id <fib-id>] [rx-fib-id <fib-id>] ",
  .function = dhcpv6_proxy_set_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_dhcp6_proxy_server (u8 * s, va_list * args)
{
  dhcp_proxy_t *proxy = va_arg (*args, dhcp_proxy_t *);
  fib_table_t *server_fib;
  dhcp_server_t *server;
  ip6_mfib_t *rx_fib;

  if (proxy == 0)
    {
      s = format (s, "%=14s%=16s%s", "RX FIB", "Src Address",
		  "Servers FIB,Address");
      return s;
    }

  rx_fib = ip6_mfib_get (proxy->rx_fib_index);

  s = format (s, "%=14u%=16U",
	      rx_fib->table_id,
	      format_ip46_address, &proxy->dhcp_src_address, IP46_TYPE_ANY);

  vec_foreach (server, proxy->dhcp_servers)
  {
    server_fib = fib_table_get (server->server_fib_index, FIB_PROTOCOL_IP6);
    s = format (s, "%u,%U  ",
		server_fib->ft_table_id,
		format_ip46_address, &server->dhcp_server, IP46_TYPE_ANY);
  }

  return s;
}

static int
dhcp6_proxy_show_walk (dhcp_proxy_t * proxy, void *ctx)
{
  vlib_main_t *vm = ctx;

  vlib_cli_output (vm, "%U", format_dhcp6_proxy_server, proxy);

  return (1);
}

static clib_error_t *
dhcpv6_proxy_show_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_dhcp6_proxy_server,
		   NULL /* header line */ );

  dhcp_proxy_walk (FIB_PROTOCOL_IP6, dhcp6_proxy_show_walk, vm);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcpv6_proxy_show_command, static) = {
  .path = "show dhcpv6 proxy",
  .short_help = "Display dhcpv6 proxy info",
  .function = dhcpv6_proxy_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcpv6_vss_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 is_del = 0, vss_type = VSS_TYPE_DEFAULT;
  u8 *vpn_ascii_id = 0;
  u32 oui = 0, fib_id = 0, tbl_id = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &tbl_id))
	;
      else if (unformat (input, "oui %d", &oui))
	vss_type = VSS_TYPE_VPN_ID;
      else if (unformat (input, "vpn-id %d", &fib_id))
	vss_type = VSS_TYPE_VPN_ID;
      else if (unformat (input, "vpn-ascii-id %s", &vpn_ascii_id))
	vss_type = VSS_TYPE_ASCII;
      else if (unformat (input, "delete") || unformat (input, "del"))
	is_del = 1;
      else
	break;
    }

  if (tbl_id == ~0)
    return clib_error_return (0, "no table ID specified.");

  int rv = dhcp_proxy_set_vss (FIB_PROTOCOL_IP6, tbl_id, vss_type,
			       vpn_ascii_id, oui, fib_id, is_del);
  switch (rv)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "vss for table %d not found in pool.",
				tbl_id);
    default:
      return clib_error_return (0, "BUG: rv %d", rv);
    }
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcpv6_proxy_vss_command, static) = {
  .path = "set dhcpv6 vss",
  .short_help = "set dhcpv6 vss table <table-id> [oui <n> vpn-id <n> | vpn-ascii-id <text>]",
  .function = dhcpv6_vss_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcpv6_vss_show_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  dhcp_vss_walk (FIB_PROTOCOL_IP6, dhcp_vss_show_walk, vm);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcpv6_proxy_vss_show_command, static) = {
  .path = "show dhcpv6 vss",
  .short_help = "show dhcpv6 VSS",
  .function = dhcpv6_vss_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcpv6_link_address_show_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index0 = 0, sw_if_index;
  vnet_sw_interface_t *swif;
  ip6_address_t *ia0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index0))
	{
	  swif = vnet_get_sw_interface (vnm, sw_if_index0);
	  sw_if_index = (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED) ?
	    swif->unnumbered_sw_if_index : sw_if_index0;
	  ia0 = ip6_interface_first_address (&ip6_main, sw_if_index);
	  if (ia0)
	    {
	      vlib_cli_output (vm, "%=20s%=48s", "interface", "link-address");

	      vlib_cli_output (vm, "%=20U%=48U",
			       format_vnet_sw_if_index_name, vnm,
			       sw_if_index0, format_ip6_address, ia0);
	    }
	  else
	    vlib_cli_output (vm, "%=34s%=20U",
			     "No IPv6 address configured on",
			     format_vnet_sw_if_index_name, vnm, sw_if_index);
	}
      else
	break;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcpv6_proxy_address_show_command, static) = {
  .path = "show dhcpv6 link-address interface",
  .short_help = "show dhcpv6 link-address interface <interface>",
  .function = dhcpv6_link_address_show_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
