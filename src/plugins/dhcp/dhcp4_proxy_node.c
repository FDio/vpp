/*
 * proxy_node.c: dhcp proxy node processing
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
#include <dhcp/dhcp_proxy.h>
#include <dhcp/client.h>
#include <vnet/fib/ip4_fib.h>

static char *dhcp_proxy_error_strings[] = {
#define dhcp_proxy_error(n,s) s,
#include <dhcp/dhcp4_proxy_error.def>
#undef dhcp_proxy_error
};

#define foreach_dhcp_proxy_to_server_input_next \
  _ (DROP, "error-drop")			\
  _ (LOOKUP, "ip4-lookup")			\
  _ (SEND_TO_CLIENT, "dhcp-proxy-to-client")

typedef enum
{
#define _(s,n) DHCP_PROXY_TO_SERVER_INPUT_NEXT_##s,
  foreach_dhcp_proxy_to_server_input_next
#undef _
    DHCP_PROXY_TO_SERVER_INPUT_N_NEXT,
} dhcp_proxy_to_server_input_next_t;

typedef struct
{
  /* 0 => to server, 1 => to client */
  int which;
  ip4_address_t trace_ip4_address;
  u32 error;
  u32 sw_if_index;
  u32 original_sw_if_index;

  /* enough space for the DHCP header plus some options */
  u8 packet_data[2 * sizeof (dhcp_header_t)];
}
dhcp_proxy_trace_t;

#define VPP_DHCP_OPTION82_SUB1_SIZE   6
#define VPP_DHCP_OPTION82_SUB5_SIZE   6
#define VPP_DHCP_OPTION82_VSS_SIZE    12
#define VPP_DHCP_OPTION82_SIZE (VPP_DHCP_OPTION82_SUB1_SIZE + \
                                VPP_DHCP_OPTION82_SUB5_SIZE + \
                                VPP_DHCP_OPTION82_VSS_SIZE +3)

static vlib_node_registration_t dhcp_proxy_to_server_node;
static vlib_node_registration_t dhcp_proxy_to_client_node;

static u8 *
format_dhcp_proxy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dhcp_proxy_trace_t *t = va_arg (*args, dhcp_proxy_trace_t *);

  if (t->which == 0)
    s = format (s, "DHCP proxy: sent to server %U\n",
		format_ip4_address, &t->trace_ip4_address, t->error);
  else
    s = format (s, "DHCP proxy: broadcast to client from %U\n",
		format_ip4_address, &t->trace_ip4_address);

  if (t->error != (u32) ~ 0)
    s = format (s, "  error: %s\n", dhcp_proxy_error_strings[t->error]);

  s = format (s, "  original_sw_if_index: %d, sw_if_index: %d\n",
	      t->original_sw_if_index, t->sw_if_index);
  s = format (s, "  %U",
	      format_dhcp_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

static u8 *
format_dhcp_proxy_header_with_length (u8 * s, va_list * args)
{
  dhcp_header_t *h = va_arg (*args, dhcp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "dhcp header truncated");

  s = format (s, "DHCP Proxy");

  return s;
}

static uword
dhcp_proxy_to_server_input (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  dhcp_proxy_main_t *dpm = &dhcp_proxy_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 pkts_to_server = 0, pkts_to_client = 0, pkts_no_server = 0;
  u32 pkts_no_interface_address = 0;
  u32 pkts_too_big = 0;
  ip4_main_t *im = &ip4_main;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  udp_header_t *u0;
	  dhcp_header_t *h0;
	  ip4_header_t *ip0;
	  u32 next0;
	  u32 old0, new0;
	  ip_csum_t sum0;
	  u32 error0 = (u32) ~ 0;
	  u32 sw_if_index = 0;
	  u32 original_sw_if_index = 0;
	  u32 fib_index;
	  dhcp_proxy_t *proxy;
	  dhcp_server_t *server;
	  u32 rx_sw_if_index;
	  dhcp_option_t *o, *end;
	  u32 len = 0;
	  u8 is_discover = 0;
	  int space_left;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  h0 = vlib_buffer_get_current (b0);

	  /*
	   * udp_local hands us the DHCP header, need udp hdr,
	   * ip hdr to relay to server
	   */
	  vlib_buffer_advance (b0, -(sizeof (*u0)));
	  u0 = vlib_buffer_get_current (b0);

	  /* This blows. Return traffic has src_port = 67, dst_port = 67 */
	  if (u0->src_port ==
	      clib_net_to_host_u16 (UDP_DST_PORT_dhcp_to_server))
	    {
	      vlib_buffer_advance (b0, sizeof (*u0));
	      next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_SEND_TO_CLIENT;
	      error0 = 0;
	      pkts_to_client++;
	      goto do_enqueue;
	    }

	  rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index = im->fib_index_by_sw_if_index[rx_sw_if_index];
	  proxy = dhcp_get_proxy (dpm, fib_index, FIB_PROTOCOL_IP4);

	  if (PREDICT_FALSE (NULL == proxy))
	    {
	      error0 = DHCP_PROXY_ERROR_NO_SERVER;
	      next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_no_server++;
	      goto do_trace;
	    }

	  if (!vlib_buffer_chain_linearize (vm, b0))
	    {
	      error0 = DHCP_PROXY_ERROR_PKT_TOO_BIG;
	      next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_too_big++;
	      goto do_trace;
	    }
	  space_left = vlib_buffer_space_left_at_end (vm, b0);
	  /* cant parse chains...
	   * and we need some space for option 82*/
	  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) != 0 ||
	      space_left < VPP_DHCP_OPTION82_SIZE)
	    {
	      error0 = DHCP_PROXY_ERROR_PKT_TOO_BIG;
	      next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
	      pkts_too_big++;
	      goto do_trace;
	    }

	  server = &proxy->dhcp_servers[0];
	  vlib_buffer_advance (b0, -(sizeof (*ip0)));
	  ip0 = vlib_buffer_get_current (b0);

	  /* disable UDP checksum */
	  u0->checksum = 0;
	  sum0 = ip0->checksum;
	  old0 = ip0->dst_address.as_u32;
	  new0 = server->dhcp_server.ip4.as_u32;
	  ip0->dst_address.as_u32 = server->dhcp_server.ip4.as_u32;
	  sum0 = ip_csum_update (sum0, old0, new0,
				 ip4_header_t /* structure */ ,
				 dst_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  sum0 = ip0->checksum;
	  old0 = ip0->src_address.as_u32;
	  new0 = proxy->dhcp_src_address.ip4.as_u32;
	  ip0->src_address.as_u32 = new0;
	  sum0 = ip_csum_update (sum0, old0, new0,
				 ip4_header_t /* structure */ ,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  /* Send to DHCP server via the configured FIB */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = server->server_fib_index;

	  h0->gateway_ip_address = proxy->dhcp_src_address.ip4;
	  pkts_to_server++;

	  o = h0->options;
	  end = (void *) vlib_buffer_get_tail (b0);

	  /* TLVs are not performance-friendly... */
	  while (o->option != DHCP_PACKET_OPTION_END && o < end)
	    {
	      if (DHCP_PACKET_OPTION_MSG_TYPE == o->option)
		{
		  if (DHCP_PACKET_DISCOVER == o->data[0])
		    {
		      is_discover = 1;
		    }
		}
	      o = (dhcp_option_t *) (o->data + o->length);
	    }

	  if (o->option == DHCP_PACKET_OPTION_END && o <= end)
	    {
	      vnet_main_t *vnm = vnet_get_main ();
	      u16 old_l0, new_l0;
	      ip4_address_t _ia0, *ia0 = &_ia0;
	      dhcp_vss_t *vss;
	      vnet_sw_interface_t *swif;

	      original_sw_if_index = sw_if_index =
		vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      swif = vnet_get_sw_interface (vnm, sw_if_index);
	      if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
		sw_if_index = swif->unnumbered_sw_if_index;

	      /*
	       * Get the first ip4 address on the [client-side]
	       * RX interface, if not unnumbered. otherwise use
	       * the loopback interface's ip address.
	       */
	      ia0 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);

	      if (ia0 == 0)
		{
		  error0 = DHCP_PROXY_ERROR_NO_INTERFACE_ADDRESS;
		  next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
		  pkts_no_interface_address++;
		  goto do_trace;
		}

	      /* Add option 82 */
	      o->option = 82;	/* option 82 */
	      o->length = 12;	/* 12 octets to follow */
	      o->data[0] = 1;	/* suboption 1, circuit ID (=FIB id) */
	      o->data[1] = 4;	/* length of suboption */
	      u32 *o_ifid = (u32 *) & o->data[2];
	      *o_ifid = clib_host_to_net_u32 (original_sw_if_index);
	      o->data[6] = 5;	/* suboption 5 (client RX intfc address) */
	      o->data[7] = 4;	/* length 4 */
	      u32 *o_addr = (u32 *) & o->data[8];
	      *o_addr = ia0->as_u32;
	      o->data[12] = DHCP_PACKET_OPTION_END;

	      vss = dhcp_get_vss_info (dpm, fib_index, FIB_PROTOCOL_IP4);
	      if (vss)
		{
		  u32 id_len;	/* length of VPN ID */

		  if (vss->vss_type == VSS_TYPE_VPN_ID)
		    {
		      id_len = sizeof (vss->vpn_id);	/* vpn_id is 7 bytes */
		      memcpy (&o->data[15], vss->vpn_id, id_len);
		    }
		  else if (vss->vss_type == VSS_TYPE_ASCII)
		    {
		      id_len = vec_len (vss->vpn_ascii_id);
		      memcpy (&o->data[15], vss->vpn_ascii_id, id_len);
		    }
		  else		/* must be VSS_TYPE_DEFAULT, no VPN ID */
		    id_len = 0;

		  o->data[12] = 151;	/* vss suboption */
		  o->data[13] = id_len + 1;	/* length: vss_type + id_len */
		  o->data[14] = vss->vss_type;	/* vss option type */
		  o->data[15 + id_len] = 152;	/* vss control suboption */
		  o->data[16 + id_len] = 0;	/* length */
		  o->data[17 + id_len] = DHCP_PACKET_OPTION_END;	/* "end-of-options" (0xFF) */
		  /* 5 bytes for suboption headers 151+len, 152+len and 0xFF */
		  o->length += id_len + 5;
		}

	      len = o->length + 3;
	      b0->current_length += len;
	      /* Fix IP header length and checksum */
	      old_l0 = ip0->length;
	      new_l0 = clib_net_to_host_u16 (old_l0);
	      new_l0 += len;
	      new_l0 = clib_host_to_net_u16 (new_l0);
	      ip0->length = new_l0;
	      sum0 = ip0->checksum;
	      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
				     length /* changed member */ );
	      ip0->checksum = ip_csum_fold (sum0);

	      /* Fix UDP length */
	      new_l0 = clib_net_to_host_u16 (u0->length);
	      new_l0 += len;
	      u0->length = clib_host_to_net_u16 (new_l0);
	    }
	  else
	    {
	      vlib_node_increment_counter
		(vm, dhcp_proxy_to_server_node.index,
		 DHCP_PROXY_ERROR_OPTION_82_ERROR, 1);
	    }

	  next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP;

	  /*
	   * If we have multiple servers configured and this is the
	   * client's discover message, then send copies to each of
	   * those servers
	   */
	  if (is_discover && vec_len (proxy->dhcp_servers) > 1)
	    {
	      u32 ii;

	      for (ii = 1; ii < vec_len (proxy->dhcp_servers); ii++)
		{
		  vlib_buffer_t *c0;
		  u32 ci0;

		  c0 = vlib_buffer_copy (vm, b0);
		  if (c0 == NULL)
		    {
		      vlib_node_increment_counter
			(vm, dhcp_proxy_to_server_node.index,
			 DHCP_PROXY_ERROR_ALLOC_FAIL, 1);
		      continue;
		    }
		  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);
		  ci0 = vlib_get_buffer_index (vm, c0);
		  server = &proxy->dhcp_servers[ii];

		  ip0 = vlib_buffer_get_current (c0);

		  sum0 = ip0->checksum;
		  old0 = ip0->dst_address.as_u32;
		  new0 = server->dhcp_server.ip4.as_u32;
		  ip0->dst_address.as_u32 = server->dhcp_server.ip4.as_u32;
		  sum0 = ip_csum_update (sum0, old0, new0,
					 ip4_header_t /* structure */ ,
					 dst_address /* changed member */ );
		  ip0->checksum = ip_csum_fold (sum0);

		  to_next[0] = ci0;
		  to_next += 1;
		  n_left_to_next -= 1;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   ci0, next0);

		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      dhcp_proxy_trace_t *tr;

		      tr = vlib_add_trace (vm, node, c0, sizeof (*tr));
		      tr->which = 0;	/* to server */
		      tr->error = error0;
		      tr->original_sw_if_index = original_sw_if_index;
		      tr->sw_if_index = sw_if_index;
		      if (next0 == DHCP_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP)
			tr->trace_ip4_address.as_u32 =
			  server->dhcp_server.ip4.as_u32;

		      clib_memcpy_fast (tr->packet_data, h0,
					sizeof (tr->packet_data));

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
	      dhcp_proxy_trace_t *tr = vlib_add_trace (vm, node,
						       b0, sizeof (*tr));
	      tr->which = 0;	/* to server */
	      tr->error = error0;
	      tr->original_sw_if_index = original_sw_if_index;
	      tr->sw_if_index = sw_if_index;
	      if (next0 == DHCP_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP)
		tr->trace_ip4_address.as_u32 =
		  proxy->dhcp_servers[0].dhcp_server.ip4.as_u32;
	      clib_memcpy_fast (tr->packet_data, h0,
				sizeof (tr->packet_data));
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
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
			       DHCP_PROXY_ERROR_RELAY_TO_CLIENT,
			       pkts_to_client);
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
			       DHCP_PROXY_ERROR_RELAY_TO_SERVER,
			       pkts_to_server);
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
			       DHCP_PROXY_ERROR_NO_SERVER, pkts_no_server);
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
			       DHCP_PROXY_ERROR_NO_INTERFACE_ADDRESS,
			       pkts_no_interface_address);
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
			       DHCP_PROXY_ERROR_PKT_TOO_BIG, pkts_too_big);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp_proxy_to_server_node, static) = {
  .function = dhcp_proxy_to_server_input,
  .name = "dhcp-proxy-to-server",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = DHCP_PROXY_N_ERROR,
  .error_strings = dhcp_proxy_error_strings,

  .n_next_nodes = DHCP_PROXY_TO_SERVER_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DHCP_PROXY_TO_SERVER_INPUT_NEXT_##s] = n,
    foreach_dhcp_proxy_to_server_input_next
#undef _
  },

  .format_buffer = format_dhcp_proxy_header_with_length,
  .format_trace = format_dhcp_proxy_trace,
#if 0
  .unformat_buffer = unformat_dhcp_proxy_header,
#endif
};
/* *INDENT-ON* */

typedef enum
{
  DHCP4_PROXY_NEXT_DROP,
  DHCP4_PROXY_NEXT_TX,
  DHCP4_PROXY_N_NEXT,
} dhcp4_next_t;

static uword
dhcp_proxy_to_client_input (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  ethernet_main_t *em = vnet_get_ethernet_main ();
  dhcp_proxy_main_t *dpm = &dhcp_proxy_main;
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  u32 next_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  udp_header_t *u0;
	  dhcp_header_t *h0;
	  ip4_header_t *ip0 = 0;
	  ip4_address_t *ia0 = 0;
	  u32 old0, new0;
	  ip_csum_t sum0;
	  ethernet_interface_t *ei0;
	  ethernet_header_t *mac0;
	  vnet_hw_interface_t *hi0;
	  u32 sw_if_index = ~0;
	  vnet_sw_interface_t *si0;
	  u32 inner_vlan = (u32) ~ 0;
	  u32 outer_vlan = (u32) ~ 0;
	  u32 error0 = (u32) ~ 0;
	  vnet_sw_interface_t *swif;
	  u32 fib_index;
	  dhcp_proxy_t *proxy;
	  dhcp_server_t *server;
	  u32 original_sw_if_index = (u32) ~ 0;
	  dhcp4_next_t next0 = DHCP4_PROXY_NEXT_TX;
	  ip4_address_t relay_addr = {
	    .as_u32 = 0,
	  };

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);

	  /*
	   * udp_local hands us the DHCP header, need udp hdr,
	   * ip hdr to relay to client
	   */
	  vlib_buffer_advance (b0, -(sizeof (*u0)));
	  u0 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, -(sizeof (*ip0)));
	  ip0 = vlib_buffer_get_current (b0);

	  /* Consumed by dhcp client code? */
	  if (dhcp_client_for_us (bi0, b0, ip0, u0, h0))
	    {
	      error0 = DHCP_PROXY_ERROR_FOR_US;
	      goto drop_packet;
	    }

	  // if (1 /* dpm->insert_option_82 */ )
	  /* linearize needed to "unclone" and scan options */
	  int rv = vlib_buffer_chain_linearize (vm, b0);
	  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) != 0 || !rv)
	    {
	      error0 = DHCP_PROXY_ERROR_PKT_TOO_BIG;
	      goto drop_packet;
	    }

	  dhcp_option_t *o = h0->options, *end =
	    (void *) vlib_buffer_get_tail (b0);

	  /* Parse through TLVs looking for option 82.
	     The circuit-ID is the FIB number we need
	     to track down the client-facing interface */

	  while (o->option != DHCP_PACKET_OPTION_END && o < end)
	    {
	      if (o->option == 82)
		{
		  u32 vss_exist = 0;
		  u32 vss_ctrl = 0;
		  dhcp_option_t *sub = (dhcp_option_t *) & o->data[0];
		  dhcp_option_t *subend =
		    (dhcp_option_t *) (o->data + o->length);
		  while (sub->option != DHCP_PACKET_OPTION_END
			 && sub < subend)
		    {
		      /* If this is one of ours, it will have
		         total length 12, circuit-id suboption type,
		         and the sw_if_index */
		      if (sub->option == 1 && sub->length == 4)
			{
			  sw_if_index = ((sub->data[0] << 24) |
					 (sub->data[1] << 16) |
					 (sub->data[2] << 8) |
					 (sub->data[3]));
			}
		      else if (sub->option == 5 && sub->length == 4)
			{
			  relay_addr.as_u8[0] = sub->data[0];
			  relay_addr.as_u8[1] = sub->data[1];
			  relay_addr.as_u8[2] = sub->data[2];
			  relay_addr.as_u8[3] = sub->data[3];
			}
		      else if (sub->option == 151 &&
			       sub->length == 7 && sub->data[0] == 1)
			vss_exist = 1;
		      else if (sub->option == 152 && sub->length == 0)
			vss_ctrl = 1;
		      sub = (dhcp_option_t *) (sub->data + sub->length);
		    }
		  if (vss_ctrl && vss_exist)
		    vlib_node_increment_counter
		      (vm, dhcp_proxy_to_client_node.index,
		       DHCP_PROXY_ERROR_OPTION_82_VSS_NOT_PROCESSED, 1);

		}
	      o = (dhcp_option_t *) (o->data + o->length);
	    }

	  if (sw_if_index == (u32) ~ 0)
	    {
	      error0 = DHCP_PROXY_ERROR_NO_OPTION_82;

	    drop_packet:
	      vlib_node_increment_counter (vm,
					   dhcp_proxy_to_client_node.index,
					   error0, 1);
	      b0->error = node->errors[error0];
	      next0 = DHCP4_PROXY_NEXT_DROP;
	      goto do_trace;
	    }

	  if (relay_addr.as_u32 == 0)
	    {
	      error0 = DHCP_PROXY_ERROR_BAD_OPTION_82_ADDR;
	      goto drop_packet;
	    }

	  if (sw_if_index >= vec_len (im->fib_index_by_sw_if_index))
	    {
	      error0 = DHCP_PROXY_ERROR_BAD_OPTION_82_ITF;
	      goto drop_packet;
	    }

	  fib_index = im->fib_index_by_sw_if_index[sw_if_index];
	  proxy = dhcp_get_proxy (dpm, fib_index, FIB_PROTOCOL_IP4);

	  if (PREDICT_FALSE (NULL == proxy))
	    {
	      error0 = DHCP_PROXY_ERROR_NO_SERVER;
	      goto drop_packet;
	    }

	  vec_foreach (server, proxy->dhcp_servers)
	  {
	    if (ip0->src_address.as_u32 == server->dhcp_server.ip4.as_u32)
	      {
		goto server_found;
	      }
	  }

	  error0 = DHCP_PROXY_ERROR_BAD_SVR_FIB_OR_ADDRESS;
	  goto drop_packet;

	server_found:
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index;

	  swif = vnet_get_sw_interface (vnm, sw_if_index);
	  original_sw_if_index = sw_if_index;
	  if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	    sw_if_index = swif->unnumbered_sw_if_index;

	  ia0 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
	  if (ia0 == 0)
	    {
	      error0 = DHCP_PROXY_ERROR_NO_INTERFACE_ADDRESS;
	      goto drop_packet;
	    }

	  if (relay_addr.as_u32 != ia0->as_u32)
	    {
	      error0 = DHCP_PROXY_ERROR_BAD_YIADDR;
	      goto drop_packet;
	    }

	  u0->checksum = 0;
	  u0->dst_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcp_to_client);
	  sum0 = ip0->checksum;
	  old0 = ip0->dst_address.as_u32;
	  new0 = 0xFFFFFFFF;
	  ip0->dst_address.as_u32 = new0;
	  sum0 =
	    ip_csum_update (sum0, old0, new0, ip4_header_t /* structure */ ,
			    dst_address /* offset of changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  sum0 = ip0->checksum;
	  old0 = ip0->src_address.as_u32;
	  new0 = ia0->as_u32;
	  ip0->src_address.as_u32 = new0;
	  sum0 =
	    ip_csum_update (sum0, old0, new0, ip4_header_t /* structure */ ,
			    src_address /* offset of changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  vlib_buffer_advance (b0, -(sizeof (ethernet_header_t)));
	  si0 = vnet_get_sw_interface (vnm, original_sw_if_index);
	  if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	    {
	      if (si0->sub.eth.flags.one_tag == 1)
		{
		  vlib_buffer_advance (b0, -4 /* space for 1 VLAN tag */ );
		  outer_vlan = (si0->sub.eth.outer_vlan_id << 16) | 0x0800;
		}
	      else if (si0->sub.eth.flags.two_tags == 1)
		{
		  vlib_buffer_advance (b0, -8 /* space for 2 VLAN tag */ );
		  outer_vlan = (si0->sub.eth.outer_vlan_id << 16) | 0x8100;
		  inner_vlan = (si0->sub.eth.inner_vlan_id << 16) | 0x0800;
		}
	    }

	  mac0 = vlib_buffer_get_current (b0);

	  hi0 = vnet_get_sup_hw_interface (vnm, original_sw_if_index);
	  ei0 = pool_elt_at_index (em->interfaces, hi0->hw_instance);
	  clib_memcpy (mac0->src_address, &ei0->address,
		       sizeof (mac0->src_address));
	  clib_memset (mac0->dst_address, 0xff, sizeof (mac0->dst_address));

	  if (si0->type == VNET_SW_INTERFACE_TYPE_SUB
	      && outer_vlan != (u32) ~ 0)
	    {
	      mac0->type = (si0->sub.eth.flags.dot1ad == 1) ?
		clib_net_to_host_u16 (0x88a8) : clib_net_to_host_u16 (0x8100);
	      u32 *vlan_tag = (u32 *) (mac0 + 1);
	      *vlan_tag = clib_host_to_net_u32 (outer_vlan);
	      if (inner_vlan != (u32) ~ 0)
		{
		  u32 *inner_vlan_tag = (u32 *) (vlan_tag + 1);
		  *inner_vlan_tag = clib_host_to_net_u32 (inner_vlan);
		}
	    }
	  else
	    {
	      mac0->type = clib_net_to_host_u16 (0x0800);
	    }

	do_trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_proxy_trace_t *tr = vlib_add_trace (vm, node,
						       b0, sizeof (*tr));
	      tr->which = 1;	/* to client */
	      tr->trace_ip4_address.as_u32 = ia0 ? ia0->as_u32 : 0;
	      tr->error = error0;
	      tr->original_sw_if_index = original_sw_if_index;
	      tr->sw_if_index = sw_if_index;
	      clib_memcpy_fast (tr->packet_data, h0,
				sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp_proxy_to_client_node, static) = {
  .function = dhcp_proxy_to_client_input,
  .name = "dhcp-proxy-to-client",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = DHCP_PROXY_N_ERROR,
  .error_strings = dhcp_proxy_error_strings,
  .format_buffer = format_dhcp_proxy_header_with_length,
  .format_trace = format_dhcp_proxy_trace,
#if 0
  .unformat_buffer = unformat_dhcp_proxy_header,
#endif
  .n_next_nodes = DHCP4_PROXY_N_NEXT,
  .next_nodes = {
    [DHCP4_PROXY_NEXT_DROP] = "error-drop",
    [DHCP4_PROXY_NEXT_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

void
dhcp_maybe_register_udp_ports (dhcp_port_reg_flags_t ports)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  vlib_main_t *vm = dm->vlib_main;
  int port_regs_diff = dm->udp_ports_registered ^ ports;

  if (!port_regs_diff)
    return;

  if ((port_regs_diff & DHCP_PORT_REG_CLIENT) & ports)
    udp_register_dst_port (vm, UDP_DST_PORT_dhcp_to_client,
			   dhcp_proxy_to_client_node.index, 1 /* is_ip4 */ );

  if ((port_regs_diff & DHCP_PORT_REG_SERVER) & ports)
    udp_register_dst_port (vm, UDP_DST_PORT_dhcp_to_server,
			   dhcp_proxy_to_server_node.index, 1 /* is_ip4 */ );

  dm->udp_ports_registered |= ports;
}

static clib_error_t *
dhcp4_proxy_init (vlib_main_t * vm)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  vlib_node_t *error_drop_node;

  error_drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  dm->error_drop_node_index = error_drop_node->index;
  dm->vlib_main = vm;

  return 0;
}


VLIB_INIT_FUNCTION (dhcp4_proxy_init);

int
dhcp4_proxy_set_server (ip46_address_t * addr,
			ip46_address_t * src_addr,
			u32 rx_table_id, u32 server_table_id, int is_del)
{
  u32 rx_fib_index = 0;
  int rc = 0;

  const fib_prefix_t all_1s = {
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = 0xffffffff,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  if (ip46_address_is_zero (addr))
    return VNET_API_ERROR_INVALID_DST_ADDRESS;

  if (ip46_address_is_zero (src_addr))
    return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  dhcp_maybe_register_udp_ports (DHCP_PORT_REG_CLIENT | DHCP_PORT_REG_SERVER);

  rx_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
						    rx_table_id,
						    FIB_SOURCE_DHCP);

  if (is_del)
    {
      if (dhcp_proxy_server_del (FIB_PROTOCOL_IP4, rx_fib_index,
				 addr, server_table_id))
	{
	  fib_table_entry_special_remove (rx_fib_index,
					  &all_1s, FIB_SOURCE_DHCP);
	  fib_table_unlock (rx_fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_DHCP);
	}
    }
  else
    {
      if (dhcp_proxy_server_add (FIB_PROTOCOL_IP4,
				 addr, src_addr,
				 rx_fib_index, server_table_id))
	{
	  fib_table_entry_special_add (rx_fib_index,
				       &all_1s,
				       FIB_SOURCE_DHCP, FIB_ENTRY_FLAG_LOCAL);
	  fib_table_lock (rx_fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_DHCP);
	}
    }
  fib_table_unlock (rx_fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_DHCP);

  return (rc);
}

static clib_error_t *
dhcp4_proxy_set_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  ip46_address_t server_addr, src_addr;
  u32 server_table_id = 0, rx_table_id = 0;
  int is_del = 0;
  int set_src = 0, set_server = 0;

  clib_memset (&server_addr, 0, sizeof (server_addr));
  clib_memset (&src_addr, 0, sizeof (src_addr));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server %U",
		    unformat_ip4_address, &server_addr.ip4))
	set_server = 1;
      else if (unformat (input, "server-fib-id %d", &server_table_id))
	;
      else if (unformat (input, "rx-fib-id %d", &rx_table_id))
	;
      else if (unformat (input, "src-address %U",
			 unformat_ip4_address, &src_addr.ip4))
	set_src = 1;
      else if (unformat (input, "delete") || unformat (input, "del"))
	is_del = 1;
      else
	break;
    }

  if (is_del || (set_server && set_src))
    {
      int rv;

      rv = dhcp4_proxy_set_server (&server_addr, &src_addr, rx_table_id,
				   server_table_id, is_del);
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
  return clib_error_return (0, "BUG2: should not be reached?");
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_proxy_set_command, static) = {
  .path = "set dhcp proxy",
  .short_help = "set dhcp proxy [del] server <ip-addr> src-address <ip-addr> [server-fib-id <n>] [rx-fib-id <n>]",
  .function = dhcp4_proxy_set_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_dhcp4_proxy_server (u8 * s, va_list * args)
{
  dhcp_proxy_t *proxy = va_arg (*args, dhcp_proxy_t *);
  ip4_fib_t *rx_fib, *server_fib;
  dhcp_server_t *server;

  if (proxy == 0)
    {
      s = format (s, "%=14s%=16s%s", "RX FIB", "Src Address",
		  "Servers FIB,Address");
      return s;
    }

  rx_fib = ip4_fib_get (proxy->rx_fib_index);

  s = format (s, "%=14u%=16U",
	      rx_fib->table_id,
	      format_ip46_address, &proxy->dhcp_src_address, IP46_TYPE_ANY);

  vec_foreach (server, proxy->dhcp_servers)
  {
    server_fib = ip4_fib_get (server->server_fib_index);
    s = format (s, "%u,%U  ",
		server_fib->table_id,
		format_ip46_address, &server->dhcp_server, IP46_TYPE_ANY);
  }
  return s;
}

static int
dhcp4_proxy_show_walk (dhcp_proxy_t * server, void *ctx)
{
  vlib_main_t *vm = ctx;

  vlib_cli_output (vm, "%U", format_dhcp4_proxy_server, server);

  return (1);
}

static clib_error_t *
dhcp4_proxy_show_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_dhcp4_proxy_server,
		   NULL /* header line */ );

  dhcp_proxy_walk (FIB_PROTOCOL_IP4, dhcp4_proxy_show_walk, vm);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_proxy_show_command, static) = {
  .path = "show dhcp proxy",
  .short_help = "Display dhcp proxy server info",
  .function = dhcp4_proxy_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp_option_82_vss_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 is_del = 0, vss_type = VSS_TYPE_DEFAULT;
  u32 oui = 0, fib_id = 0, tbl_id = ~0;
  u8 *vpn_ascii_id = 0;

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

  int rv = dhcp_proxy_set_vss (FIB_PROTOCOL_IP4, tbl_id, vss_type,
			       vpn_ascii_id, oui, fib_id, is_del);
  switch (rv)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0,
				"option 82 vss for table %d not found in in pool.",
				tbl_id);
    default:
      return clib_error_return (0, "BUG: rv %d", rv);

    }
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_proxy_vss_command,static) = {
  .path = "set dhcp option-82 vss",
  .short_help = "set dhcp option-82 vss [del] table <table id> [oui <n> vpn-id <n> | vpn-ascii-id <text>]",
  .function = dhcp_option_82_vss_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp_vss_show_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dhcp_vss_walk (FIB_PROTOCOL_IP4, dhcp_vss_show_walk, vm);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_proxy_vss_show_command, static) = {
  .path = "show dhcp vss",
  .short_help = "show dhcp VSS",
  .function = dhcp_vss_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp_option_82_address_show_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index0 = 0, sw_if_index;
  vnet_sw_interface_t *swif;
  ip4_address_t *ia0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index0))
	{
	  swif = vnet_get_sw_interface (vnm, sw_if_index0);
	  sw_if_index = (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED) ?
	    swif->unnumbered_sw_if_index : sw_if_index0;
	  ia0 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
	  if (ia0)
	    {
	      vlib_cli_output (vm, "%=20s%=20s", "interface",
			       "source IP address");

	      vlib_cli_output (vm, "%=20U%=20U",
			       format_vnet_sw_if_index_name,
			       vnm, sw_if_index0, format_ip4_address, ia0);
	    }
	  else
	    vlib_cli_output (vm, "%=34s %=20U",
			     "No IPv4 address configured on",
			     format_vnet_sw_if_index_name, vnm, sw_if_index);
	}
      else
	break;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_proxy_address_show_command,static) = {
  .path = "show dhcp option-82-address interface",
  .short_help = "show dhcp option-82-address interface <interface>",
  .function = dhcp_option_82_address_show_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
