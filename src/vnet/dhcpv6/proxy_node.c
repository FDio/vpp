/*
 * proxy_node.c: dhcpv6 proxy node processing
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
#include <vnet/dhcpv6/proxy.h>
#include <vnet/fib/ip6_fib.h>

static char * dhcpv6_proxy_error_strings[] = {
#define dhcpv6_proxy_error(n,s) s,
#include "proxy_error.def"
#undef dhcpv6_proxy_error
};

#define foreach_dhcpv6_proxy_to_server_input_next \
  _ (DROP, "error-drop")			\
  _ (LOOKUP, "ip6-lookup")                      \
  _ (SEND_TO_CLIENT, "dhcpv6-proxy-to-client")


typedef enum {
#define _(s,n) DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_##s,
  foreach_dhcpv6_proxy_to_server_input_next
#undef _
  DHCPV6_PROXY_TO_SERVER_INPUT_N_NEXT,
} dhcpv6_proxy_to_server_input_next_t;

typedef struct {
  /* 0 => to server, 1 => to client */
  int which;
  u8 packet_data[64];
  u32 error;
  u32 sw_if_index;
  u32 original_sw_if_index;
} dhcpv6_proxy_trace_t;

vlib_node_registration_t dhcpv6_proxy_to_server_node;
vlib_node_registration_t dhcpv6_proxy_to_client_node;


u8 * format_dhcpv6_proxy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dhcpv6_proxy_trace_t * t = va_arg (*args, dhcpv6_proxy_trace_t *);

  if (t->which == 0)
    s = format (s, "DHCPV6 proxy: sent to server %U",
                format_ip6_address, &t->packet_data, sizeof (ip6_address_t));
  else
    s = format (s, "DHCPV6 proxy: sent to client from %U",
                format_ip6_address, &t->packet_data, sizeof (ip6_address_t));
  if (t->error != (u32)~0)
    s = format (s, " error: %s\n", dhcpv6_proxy_error_strings[t->error]);

  s = format (s, "  original_sw_if_index: %d, sw_if_index: %d\n",
              t->original_sw_if_index, t->sw_if_index);

  return s;
}

u8 * format_dhcpv6_proxy_header_with_length (u8 * s, va_list * args)
{
  dhcpv6_header_t * h = va_arg (*args, dhcpv6_header_t *);
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
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia = 0;
  ip6_address_t * result = 0;

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
  return result;
}

/* get first interface address */
static ip6_address_t *
ip6_interface_first_address (ip6_main_t * im, u32 sw_if_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia = 0;
  ip6_address_t * result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip6_address_t * a = ip_interface_address_get_address (lm, ia);
    result = a;
    break;
  }));
  return result;
}

static inline void copy_ip6_address (ip6_address_t *dst, ip6_address_t *src) 
{

  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
} 

static uword
dhcpv6_proxy_to_server_input (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  dhcpv6_proxy_main_t * dpm = &dhcpv6_proxy_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 pkts_to_server=0, pkts_to_client=0, pkts_no_server=0;
  u32 pkts_no_interface_address=0, pkts_no_exceeding_max_hop=0;
  u32 pkts_no_src_address=0;
  u32 pkts_wrong_msg_type=0;
  u32 pkts_too_big=0;
  ip6_main_t * im = &ip6_main;
  ip6_fib_t * fib;
  ip6_address_t * src;
  int bogus_length;
  dhcpv6_server_t * server;
  u32  rx_fib_idx = 0, server_fib_idx = 0;
  u32 server_idx;
  u32 fib_id1 = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          vnet_main_t *vnm = vnet_get_main();
          u32 sw_if_index = 0;
          u32 rx_sw_if_index = 0;
          vnet_sw_interface_t *swif;
 	  u32 bi0;
	  vlib_buffer_t * b0;
          udp_header_t * u0, *u1;
	  dhcpv6_header_t * h0;  // client msg hdr
          ip6_header_t * ip0, *ip1;
          ip6_address_t _ia0, *ia0=&_ia0;
	  u32 next0;
          u32 error0 = (u32) ~0;
          dhcpv6_option_t *fwd_opt;
          dhcpv6_relay_hdr_t *r1;
          u16 len;
          dhcpv6_int_id_t *id1;
          dhcpv6_vss_t *vss1;
          dhcpv6_client_mac_t *cmac; // client mac
          ethernet_header_t * e_h0;
          u8 client_src_mac[6];
          vlib_buffer_free_list_t *fl;

          uword *p_vss;
          u32  oui1=0;
          dhcpv6_vss_info *vss;


	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          h0 = vlib_buffer_get_current (b0);

          /*
           * udp_local hands us the DHCPV6 header.
           */
          u0 = (void *)h0 -(sizeof(*u0));
          ip0 = (void *)u0 -(sizeof(*ip0));
          e_h0 = (void *)ip0 - ethernet_buffer_header_size(b0);

          clib_memcpy(client_src_mac, e_h0->src_address, 6);

          switch (h0->u.msg_type) {
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
          rx_sw_if_index = sw_if_index =  vnet_buffer(b0)->sw_if_index[VLIB_RX];
          rx_fib_idx = im->fib_index_by_sw_if_index [rx_sw_if_index];

	  if (vec_len(dpm->dhcp6_server_index_by_rx_fib_index) <= rx_fib_idx)
	    goto no_server;

	  server_idx = dpm->dhcp6_server_index_by_rx_fib_index[rx_fib_idx];

          if (PREDICT_FALSE (pool_is_free_index (dpm->dhcp6_servers,
                                                          server_idx)))
                     {
                     no_server:
                       error0 = DHCPV6_PROXY_ERROR_NO_SERVER;
                       next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
                       pkts_no_server++;
                       goto do_trace;
                     }

          server = pool_elt_at_index(dpm->dhcp6_servers, server_idx);
          if (server->valid == 0)
            goto no_server;

          server_fib_idx = server->server_fib6_index;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = server_fib_idx;


          /* relay-option header pointer */
          vlib_buffer_advance(b0, -(sizeof(*fwd_opt)));
          fwd_opt = vlib_buffer_get_current(b0);
          /* relay message header pointer */
          vlib_buffer_advance(b0, -(sizeof(*r1)));
          r1 = vlib_buffer_get_current(b0);

          vlib_buffer_advance(b0, -(sizeof(*u1)));
          u1 = vlib_buffer_get_current(b0);

          vlib_buffer_advance(b0, -(sizeof(*ip1)));
          ip1 = vlib_buffer_get_current(b0);

          /* fill in all that rubbish... */
          len = clib_net_to_host_u16(u0->length) - sizeof(udp_header_t);
          copy_ip6_address(&r1->peer_addr, &ip0->src_address);

          r1->msg_type = DHCPV6_MSG_RELAY_FORW;
          fwd_opt->length = clib_host_to_net_u16(len);
          fwd_opt->option = clib_host_to_net_u16(DHCPV6_OPTION_RELAY_MSG);

          r1->hop_count++;
          r1->hop_count = (h0->u.msg_type != DHCPV6_MSG_RELAY_FORW) ? 0 : r1->hop_count;

          if (PREDICT_FALSE(r1->hop_count >= HOP_COUNT_LIMIT))
            {
              error0 =  DHCPV6_RELAY_PKT_DROP_MAX_HOPS;
              next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
              pkts_no_exceeding_max_hop++;
              goto do_trace;
            }


          /* If relay-fwd and src address is site or global unicast address  */
          if (h0->u.msg_type == DHCPV6_MSG_RELAY_FORW &&
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

          ia0 = ip6_interface_first_global_or_site_address(&ip6_main, sw_if_index);
          if (ia0 == 0)
            {
              error0 = DHCPV6_PROXY_ERROR_NO_INTERFACE_ADDRESS;
              next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
              pkts_no_interface_address++;
              goto do_trace;
            }

          copy_ip6_address(&r1->link_addr, ia0);

        link_address_set:
          fl = vlib_buffer_get_free_list (vm, b0->free_list_index);

          if ((b0->current_length+sizeof(*id1)+sizeof(*vss1)+sizeof(*cmac))
              > fl->n_data_bytes)
            {
              error0 = DHCPV6_PROXY_ERROR_PKT_TOO_BIG;
              next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
              pkts_too_big++;
              goto do_trace;
            }

          id1 = (dhcpv6_int_id_t *) (((uword) ip1) + b0->current_length);
          b0->current_length += (sizeof (*id1));


          fib = ip6_fib_get (rx_fib_idx);

          //TODO: Revisit if hash makes sense here
          p_vss = hash_get (dpm->vss_index_by_vrf_id,
                            fib->table_id);
          if (p_vss)
            {
              vss = pool_elt_at_index (dpm->vss, p_vss[0]);
              oui1 =  vss->vpn_id.oui;
              fib_id1 =  vss->vpn_id.fib_id;
            }

          id1->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_INTERFACE_ID);
          id1->opt.length = clib_host_to_net_u16(sizeof(rx_sw_if_index));
          id1->int_idx = clib_host_to_net_u32(rx_sw_if_index);

          u1->length =0;
          if (h0->u.msg_type != DHCPV6_MSG_RELAY_FORW)
            {
               cmac = (dhcpv6_client_mac_t *) (((uword) ip1) + b0->current_length);
               b0->current_length += (sizeof (*cmac));
               cmac->opt.length =clib_host_to_net_u16(sizeof(*cmac) -
                                                      sizeof(cmac->opt));
               cmac->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_CLIENT_LINK_LAYER_ADDRESS);
               cmac->link_type = clib_host_to_net_u16(1); // ethernet
               clib_memcpy(cmac->data, client_src_mac, 6);
               u1->length += sizeof(*cmac);
            }
          if (server->insert_vss !=0 ) {
              vss1 = (dhcpv6_vss_t *) (((uword) ip1) + b0->current_length);
              b0->current_length += (sizeof (*vss1));
              vss1->opt.length =clib_host_to_net_u16(sizeof(*vss1) -
						     sizeof(vss1->opt));
              vss1->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_VSS);
              vss1->data[0] = 1;   // type
              vss1->data[1] = oui1>>16 & 0xff;
              vss1->data[2] = oui1>>8  & 0xff;
              vss1->data[3] = oui1 & 0xff;
              vss1->data[4] = fib_id1>>24 & 0xff;
              vss1->data[5] = fib_id1>>16 & 0xff;
              vss1->data[6] = fib_id1>>8 & 0xff;
              vss1->data[7] = fib_id1 & 0xff;
              u1->length += sizeof(*vss1);
          }

          pkts_to_server++;
          u1->checksum = 0;
          u1->src_port = clib_host_to_net_u16(UDP_DST_PORT_dhcpv6_to_client);
          u1->dst_port = clib_host_to_net_u16(UDP_DST_PORT_dhcpv6_to_server);

          u1->length =
              clib_host_to_net_u16( clib_net_to_host_u16(fwd_opt->length) +
                                    sizeof(*r1) + sizeof(*fwd_opt) +
                                    sizeof(*u1) + sizeof(*id1) + u1->length);

          memset(ip1, 0, sizeof(*ip1));
          ip1->ip_version_traffic_class_and_flow_label = 0x60;
          ip1->payload_length =  u1->length;
          ip1->protocol = PROTO_UDP;
          ip1->hop_limit = HOP_COUNT_LIMIT;
	      src = (server->dhcp6_server.as_u64[0] || server->dhcp6_server.as_u64[1]) ?
	        &server->dhcp6_server : &dpm->all_dhcpv6_server_address;
          copy_ip6_address(&ip1->dst_address, src);


          ia0 = ip6_interface_first_global_or_site_address
              (&ip6_main, vnet_buffer(b0)->sw_if_index[VLIB_RX]);

	      src = (server->dhcp6_src_address.as_u64[0] || server->dhcp6_src_address.as_u64[1]) ?
	        &server->dhcp6_src_address : ia0;
          if (ia0 == 0)
            {
              error0 = DHCPV6_PROXY_ERROR_NO_SRC_ADDRESS;
              next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_DROP;
              pkts_no_src_address++;
              goto do_trace;
            }

	  copy_ip6_address (&ip1->src_address, src);


          u1->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b0, ip1,
                                                           &bogus_length);
          ASSERT(bogus_length == 0);

          next0 = DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP;

        do_trace:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
               dhcpv6_proxy_trace_t *tr = vlib_add_trace (vm, node,
                                                          b0, sizeof (*tr));
               tr->which = 0; /* to server */
               tr->error = error0;
               tr->original_sw_if_index = rx_sw_if_index;
               tr->sw_if_index = sw_if_index;
               if (DHCPV6_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP == next0)
                 copy_ip6_address((ip6_address_t *)&tr->packet_data[0], &server->dhcp6_server);
            }

        do_enqueue:
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
                               DHCPV6_PROXY_ERROR_PKT_TOO_BIG,
                               pkts_too_big);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (dhcpv6_proxy_to_server_node) = {
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

static uword
dhcpv6_proxy_to_client_input (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * from_frame)
{

  u32 n_left_from, * from;
  ethernet_main_t *em = ethernet_get_main (vm);
  dhcpv6_proxy_main_t * dm = &dhcpv6_proxy_main;
  dhcpv6_server_t * server;
  vnet_main_t * vnm = vnet_get_main();
  int bogus_length;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      udp_header_t * u0, *u1=0;
      dhcpv6_relay_hdr_t * h0;
      ip6_header_t * ip1 = 0, *ip0;
      ip6_address_t _ia0, * ia0 = &_ia0;
      ip6_address_t client_address;
      ethernet_interface_t *ei0;
      ethernet_header_t *mac0;
      vnet_hw_interface_t *hi0;
      vlib_frame_t *f0;
      u32 * to_next0;
      u32 sw_if_index = ~0;
      u32 original_sw_if_index = ~0;
      vnet_sw_interface_t *si0;
      u32 error0 = (u32)~0;
      vnet_sw_interface_t *swif;
      dhcpv6_option_t *r0 = 0, *o;
      u16 len = 0;
      u8 interface_opt_flag = 0;
      u8 relay_msg_opt_flag = 0;
      ip6_fib_t * svr_fib;
      ip6_main_t * im = &ip6_main;
      u32 server_fib_idx, svr_fib_id, client_fib_idx, server_idx;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0);

      if (DHCPV6_MSG_RELAY_REPL != h0->msg_type)
        {
          error0 =  DHCPV6_PROXY_ERROR_WRONG_MESSAGE_TYPE;

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
          error0 =  DHCPV6_RELAY_PKT_DROP_MAX_HOPS;
          goto drop_packet;
        }
      u0 = (void *)h0 -(sizeof(*u0));
      ip0 = (void *)u0 -(sizeof(*ip0));

      vlib_buffer_advance (b0, sizeof(*h0));
      o = vlib_buffer_get_current (b0);

      /* Parse through TLVs looking for option 18 (DHCPV6_OPTION_INTERFACE_ID)
         _and_ option 9 (DHCPV6_OPTION_RELAY_MSG) option which must be there.
         Currently assuming no other options need to be processed
         The interface-ID is the FIB number we need
         to track down the client-facing interface */

      while ((u8 *) o < (b0->data + b0->current_data + b0->current_length))
        {
           if (DHCPV6_OPTION_INTERFACE_ID == clib_net_to_host_u16(o->option))
             {
                interface_opt_flag = 1;
                if (clib_net_to_host_u16(o->length) == sizeof(sw_if_index))
                    sw_if_index = clib_net_to_host_u32(((dhcpv6_int_id_t*)o)->int_idx);
                if (sw_if_index >= vec_len (im->fib_index_by_sw_if_index))
                  {
                    error0 = DHCPV6_PROXY_ERROR_WRONG_INTERFACE_ID_OPTION;
                    goto drop_packet;
                  }
             }
           if (DHCPV6_OPTION_RELAY_MSG == clib_net_to_host_u16(o->option))
             {
                relay_msg_opt_flag = 1;
                r0 = vlib_buffer_get_current (b0);
             }
           if ((relay_msg_opt_flag == 1) && (interface_opt_flag == 1))
             break;
           vlib_buffer_advance (b0, sizeof(*o) + clib_net_to_host_u16(o->length));
           o = (dhcpv6_option_t *) (((uword) o) + clib_net_to_host_u16(o->length) + sizeof(*o));
        }

      if ((relay_msg_opt_flag == 0) || (r0 == 0))
        {
    	  error0 = DHCPV6_PROXY_ERROR_NO_RELAY_MESSAGE_OPTION;
    	  goto drop_packet;
        }

      if ((u32)~0 == sw_if_index)
        {
          error0 = DHCPV6_PROXY_ERROR_NO_CIRCUIT_ID_OPTION;
          goto drop_packet;
        }

      //Advance buffer to start of encapsulated DHCPv6 message
      vlib_buffer_advance (b0, sizeof(*r0));

      client_fib_idx = im->fib_index_by_sw_if_index[sw_if_index];
      if (client_fib_idx < vec_len(dm->dhcp6_server_index_by_rx_fib_index))
    	  server_idx = dm->dhcp6_server_index_by_rx_fib_index[client_fib_idx];
      else
    	  server_idx = 0;

      if (PREDICT_FALSE (pool_is_free_index (dm->dhcp6_servers, server_idx)))
        {
          error0 = DHCPV6_PROXY_ERROR_WRONG_INTERFACE_ID_OPTION;
          goto drop_packet;
        }

      server = pool_elt_at_index (dm->dhcp6_servers, server_idx);
      if (server->valid == 0)
      {
    	  error0 = DHCPV6_PROXY_ERROR_NO_SERVER;
          goto drop_packet;
      }


      server_fib_idx = im->fib_index_by_sw_if_index
          [vnet_buffer(b0)->sw_if_index[VLIB_RX]];
      svr_fib = ip6_fib_get (server_fib_idx);
      svr_fib_id = svr_fib->table_id;

      if (svr_fib_id != server->server_fib6_index ||
          ip0->src_address.as_u64[0] != server->dhcp6_server.as_u64[0] ||
          ip0->src_address.as_u64[1] != server->dhcp6_server.as_u64[1])
        {
          //drop packet if not from server with configured address or FIB
          error0 = DHCPV6_PROXY_ERROR_BAD_SVR_FIB_OR_ADDRESS;
          goto drop_packet;
        }

      vnet_buffer (b0)->sw_if_index[VLIB_TX] = original_sw_if_index
          = sw_if_index;

      swif = vnet_get_sw_interface (vnm, original_sw_if_index);
      if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
          sw_if_index = swif->unnumbered_sw_if_index;


      /*
       * udp_local hands us the DHCPV6 header, need udp hdr,
       * ip hdr to relay to client
       */
      vlib_buffer_advance (b0, -(sizeof(*u1)));
      u1 = vlib_buffer_get_current (b0);

      vlib_buffer_advance (b0, -(sizeof(*ip1)));
      ip1 = vlib_buffer_get_current (b0);

      copy_ip6_address(&client_address, &h0->peer_addr);

      ia0 = ip6_interface_first_address (&ip6_main, sw_if_index);
      if (ia0 == 0)
        {
          error0 = DHCPV6_PROXY_ERROR_NO_INTERFACE_ADDRESS;
          goto drop_packet;
        }

      len =  clib_net_to_host_u16(r0->length);
      memset(ip1, 0, sizeof(*ip1));
      copy_ip6_address(&ip1->dst_address, &client_address);
      u1->checksum = 0;
      u1->src_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcpv6_to_server);
      u1->dst_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcpv6_to_client);
      u1->length = clib_host_to_net_u16 (len + sizeof(udp_header_t));

      ip1->ip_version_traffic_class_and_flow_label =
          ip0->ip_version_traffic_class_and_flow_label &
          0x00000fff;
      ip1->payload_length =  u1->length;
      ip1->protocol = PROTO_UDP;
      ip1->hop_limit = HOP_COUNT_LIMIT;
      copy_ip6_address(&ip1->src_address, ia0);

      u1->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b0, ip1,
                                                       &bogus_length);
      ASSERT(bogus_length == 0);

      vlib_buffer_advance (b0, -(sizeof(ethernet_header_t)));
      si0 = vnet_get_sw_interface (vnm, original_sw_if_index);
      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	  vlib_buffer_advance (b0, -4 /* space for VLAN tag */);

      mac0 = vlib_buffer_get_current (b0);

      hi0 = vnet_get_sup_hw_interface (vnm, original_sw_if_index);
      ei0 = pool_elt_at_index (em->interfaces, hi0->hw_instance);
      clib_memcpy (mac0->src_address, ei0->address, sizeof (ei0->address));
      memset (&mac0->dst_address, 0xff, sizeof (mac0->dst_address));
      mac0->type = (si0->type == VNET_SW_INTERFACE_TYPE_SUB) ?
	clib_net_to_host_u16(0x8100) : clib_net_to_host_u16 (0x86dd);

      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	{
	  u32 * vlan_tag = (u32 *)(mac0+1);
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
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
        {
          dhcpv6_proxy_trace_t *tr = vlib_add_trace (vm, node,
                                                     b0, sizeof (*tr));
          tr->which = 1; /* to client */
          if (ia0)
              copy_ip6_address((ip6_address_t*)tr->packet_data, ia0);
          tr->error = error0;
          tr->original_sw_if_index = original_sw_if_index;
          tr->sw_if_index = sw_if_index;
        }
    }
  return from_frame->n_vectors;

}

VLIB_REGISTER_NODE (dhcpv6_proxy_to_client_node) = {
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

clib_error_t * dhcpv6_proxy_init (vlib_main_t * vm)
{
  dhcpv6_proxy_main_t * dm = &dhcpv6_proxy_main;
  vlib_node_t * error_drop_node;
  dhcpv6_server_t * server;

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main();
  error_drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  dm->error_drop_node_index = error_drop_node->index;

  dm->vss_index_by_vrf_id = hash_create (0, sizeof (uword));

  /* RFC says this is the dhcpv6 server address  */
  dm->all_dhcpv6_server_address.as_u64[0] = clib_host_to_net_u64 (0xFF05000000000000);
  dm->all_dhcpv6_server_address.as_u64[1] = clib_host_to_net_u64 (0x00010003);

  /* RFC says this is the server and agent address */
  dm->all_dhcpv6_server_relay_agent_address.as_u64[0] = clib_host_to_net_u64 (0xFF02000000000000);
  dm->all_dhcpv6_server_relay_agent_address.as_u64[1] = clib_host_to_net_u64 (0x00010002);

  udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
                         dhcpv6_proxy_to_client_node.index, 0 /* is_ip6 */);

  udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_server,
                         dhcpv6_proxy_to_server_node.index, 0 /* is_ip6 */);

  /* Create the default server, don't mark it valid */
  pool_get (dm->dhcp6_servers, server);
  memset (server, 0, sizeof (*server));

  return 0;
}

VLIB_INIT_FUNCTION (dhcpv6_proxy_init);

/* Old API, manipulates a single server (only) shared by all Rx VRFs */
int dhcpv6_proxy_set_server (ip6_address_t *addr, ip6_address_t *src_address,
                             u32 fib_id, int insert_vss, int is_del)
{
	return dhcpv6_proxy_set_server_2 (addr, src_address,
			0, fib_id,
			insert_vss, is_del);
}

int dhcpv6_proxy_set_server_2 (ip6_address_t *addr, ip6_address_t *src_address,
                             u32 rx_fib_id, u32 server_fib_id,
							 int insert_vss, int is_del)
{
  dhcpv6_proxy_main_t * dm = &dhcpv6_proxy_main;
  dhcpv6_server_t * server = 0;
  u32 server_fib_index = 0;
  u32 rx_fib_index = 0;

  rx_fib_index = ip6_fib_table_find_or_create_and_lock(rx_fib_id);
  server_fib_index = ip6_fib_table_find_or_create_and_lock(server_fib_id);

  if (is_del)
      {

	  if (rx_fib_index >= vec_len(dm->dhcp6_server_index_by_rx_fib_index))
		  return VNET_API_ERROR_NO_SUCH_ENTRY;

	  server_fib_index = dm->dhcp6_server_index_by_rx_fib_index[rx_fib_index];

	  dm->dhcp6_server_index_by_rx_fib_index[rx_fib_index] = 0;
	  server = pool_elt_at_index (dm->dhcp6_servers, server_fib_index);
	  memset (server, 0, sizeof (*server));
	  pool_put (dm->dhcp6_servers, server);
	  return 0;
      }

  if (addr->as_u64[0] == 0 &&
        addr->as_u64[1] == 0 )
      return VNET_API_ERROR_INVALID_DST_ADDRESS;

    if (src_address->as_u64[0] == 0 &&
        src_address->as_u64[1] == 0)
      return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  if (rx_fib_id == 0)
    {
      server = pool_elt_at_index (dm->dhcp6_servers, 0);

      goto initialize_it;
    }

  if (rx_fib_index < vec_len(dm->dhcp6_server_index_by_rx_fib_index))
    {
      server_fib_index = dm->dhcp6_server_index_by_rx_fib_index[rx_fib_index];
      if (server_fib_index != 0)
        {
          server = pool_elt_at_index (dm->dhcp6_servers, server_fib_index);
          goto initialize_it;
        }
    }

  /*Allocate a new server*/
  pool_get (dm->dhcp6_servers, server);

  initialize_it:

  copy_ip6_address(&server->dhcp6_server, addr);
  copy_ip6_address(&server->dhcp6_src_address, src_address);
  server->server_fib6_index = server_fib_index;
  server->valid = 1;
  server->insert_vss = insert_vss;

  vec_validate (dm->dhcp6_server_index_by_rx_fib_index, rx_fib_index);
  dm->dhcp6_server_index_by_rx_fib_index[rx_fib_index] =
		  server - dm->dhcp6_servers;

  return 0;
}

static clib_error_t *
dhcpv6_proxy_set_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  ip6_address_t addr, src_addr;
  int set_server = 0, set_src_address = 0;
  u32 rx_fib_id = 0, server_fib_id = 0;
  int is_del = 0, add_vss = 0;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server %U",
                    unformat_ip6_address, &addr))
	 set_server = 1;
      else if (unformat(input, "src-address %U",
			unformat_ip6_address, &src_addr))
	  set_src_address =1;
       else if (unformat (input, "server-fib-id %d", &server_fib_id))
        ;
       else if (unformat (input, "rx-fib-id %d", &rx_fib_id))
         ;
       else if (unformat (input, "add-vss-option")
               || unformat (input, "insert-option"))
          add_vss = 1;
       else if (unformat (input, "delete") ||
                unformat (input, "del"))
           is_del = 1;
      else
        break;
    }

  if (is_del || (set_server && set_src_address))
  {
      int rv;

      rv = dhcpv6_proxy_set_server_2 (&addr, &src_addr, rx_fib_id,
    		  server_fib_id, add_vss, is_del);

      //TODO: Complete the errors
      switch (rv)
        {
        case 0:
          return 0;

        case -1:
          return clib_error_return (0, "FIB id %d does not exist", server_fib_id);

        default:
          return clib_error_return (0, "BUG: rv %d", rv);
        }
  }
  else
    return clib_error_return (0, "parse error`%U'",
                              format_unformat_error, input);
}

VLIB_CLI_COMMAND (dhcpv6_proxy_set_command, static) = {
  .path = "set dhcpv6 proxy",
  .short_help = "set dhcpv6 proxy [del] server <ipv6-addr> src-address <ipv6-addr> "
		  "[add-vss-option] [server-fib-id <fib-id>] [rx-fib-id <fib-id>] ",
  .function = dhcpv6_proxy_set_command_fn,
};

u8 * format_dhcpv6_proxy_server (u8 * s, va_list * args)
{
  dhcpv6_proxy_main_t * dm = va_arg (*args, dhcpv6_proxy_main_t *);
  dhcpv6_server_t * server = va_arg (*args, dhcpv6_server_t *);
  u32 rx_fib_index = va_arg (*args, u32);
  ip6_fib_t * rx_fib, * server_fib;
  u32 server_fib_id = (u32)~0, rx_fib_id = ~0;

  if (dm == 0)
    {
      s = format (s, "%=40s%=40s%=14s%=14s%=20s", "Server Address", "Source Address",
                  "Server FIB", "RX FIB", "Insert VSS Option");
      return s;
    }

  server_fib = ip6_fib_get(server->server_fib6_index);
  if (server_fib)
	  server_fib_id= server_fib->table_id;

  rx_fib= ip6_fib_get(rx_fib_index);

  if (rx_fib)
	  rx_fib_id = rx_fib->table_id;

  s = format (s, "%=40U%=40U%=14u%=14u%=20s",
              format_ip6_address, &server->dhcp6_server,
              format_ip6_address, &server->dhcp6_src_address,
			  server_fib_id, rx_fib_id,
			                server->insert_vss ? "yes" : "no");
  return s;
}

static clib_error_t *
dhcpv6_proxy_show_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  dhcpv6_proxy_main_t * dm = &dhcpv6_proxy_main;
  ip6_main_t * im = &ip6_main;
  int i;
  u32 server_index;
  dhcpv6_server_t * server;

  vlib_cli_output (vm, "%U", format_dhcpv6_proxy_server, 0 /* header line */,
		  0, 0);
  for (i = 0; i < vec_len (im->fibs); i++)
      {
        if (i < vec_len(dm->dhcp6_server_index_by_rx_fib_index))
          server_index = dm->dhcp6_server_index_by_rx_fib_index[i];
        else
          server_index = 0;
        server = pool_elt_at_index (dm->dhcp6_servers, server_index);
        if (server->valid)
          vlib_cli_output (vm, "%U", format_dhcpv6_proxy_server, dm,
		  server, i);
      }
  return 0;
}

VLIB_CLI_COMMAND (dhcpv6_proxy_show_command, static) = {
  .path = "show dhcpv6 proxy",
  .short_help = "Display dhcpv6 proxy info",
  .function = dhcpv6_proxy_show_command_fn,
};

int dhcpv6_proxy_set_vss(u32 tbl_id,
                         u32 oui,
                         u32 fib_id,
                         int is_del)
{
  dhcpv6_proxy_main_t *dm = &dhcpv6_proxy_main;
  u32 old_oui, old_fib_id;
  uword *p;
  dhcpv6_vss_info *v;

  p = hash_get (dm->vss_index_by_vrf_id, tbl_id);

  if (p) {
      v = pool_elt_at_index (dm->vss, p[0]);
      if (!v)
        return VNET_API_ERROR_NO_SUCH_FIB;

      old_oui = v->vpn_id.oui;
      old_fib_id = v->vpn_id.fib_id;

      if (is_del)
      {
          if (old_oui == oui &&
              old_fib_id == fib_id )
          {
              pool_put(dm->vss, v);
              hash_unset (dm->vss_index_by_vrf_id, tbl_id);
              return 0;
          }
          else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
      }

      pool_put(dm->vss, v);
      hash_unset (dm->vss_index_by_vrf_id, tbl_id);
  } else if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_get (dm->vss, v);
  memset (v, ~0, sizeof (*v));
  v->vpn_id.fib_id = fib_id;
  v->vpn_id.oui = oui;
  hash_set (dm->vss_index_by_vrf_id, tbl_id, v - dm->vss);

  return 0;
}


static clib_error_t *
dhcpv6_vss_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  int is_del = 0, got_new_vss=0;
  u32 oui=0;
  u32 fib_id=0, tbl_id=~0;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "oui %d", &oui))
          got_new_vss = 1;
      else if (unformat (input, "vpn-id %d", &fib_id))
          got_new_vss = 1;
      else if (unformat (input, "table %d", &tbl_id))
          got_new_vss = 1;
      else if (unformat(input, "delete") || unformat(input, "del"))
          is_del = 1;
      else
          break;
    }

  if (tbl_id ==~0)
      return clib_error_return (0, "no table ID specified.");

  if (is_del || got_new_vss)
    {
      int rv;

      rv = dhcpv6_proxy_set_vss(tbl_id, oui, fib_id, is_del);
      switch (rv)
        {
        case 0:
          return 0;

        case VNET_API_ERROR_NO_SUCH_FIB:
            return clib_error_return (0, "vss info (oui:%d, vpn-id:%d)  not found in table %d.",
                                      oui, fib_id, tbl_id);

        case VNET_API_ERROR_NO_SUCH_ENTRY:
            return clib_error_return (0, "vss for table %d not found in pool.",
                                      tbl_id);

        default:
          return clib_error_return (0, "BUG: rv %d", rv);
        }
    }
  else
      return clib_error_return (0, "parse error`%U'",
                                format_unformat_error, input);

}

VLIB_CLI_COMMAND (dhcpv6_proxy_vss_command, static) = {
  .path = "set dhcpv6 vss",
  .short_help = "set dhcpv6 vss table <table-id> oui <oui> vpn-idx <vpn-idx>",
  .function = dhcpv6_vss_command_fn,
};

static clib_error_t *
dhcpv6_vss_show_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)

{
  dhcpv6_proxy_main_t * dm = &dhcpv6_proxy_main;
  dhcpv6_vss_info *v;
  u32 oui;
  u32 fib_id;
  u32 tbl_id;
  uword index;

  vlib_cli_output (vm, "%=6s%=6s%=12s","Table", "OUI", "VPN ID");
  hash_foreach (tbl_id, index, dm->vss_index_by_vrf_id,
  ({
     v = pool_elt_at_index (dm->vss, index);
     oui = v->vpn_id.oui;
     fib_id = v->vpn_id.fib_id;
     vlib_cli_output (vm, "%=6d%=6d%=12d",
                      tbl_id, oui, fib_id);
  }));

  return 0;
}

VLIB_CLI_COMMAND (dhcpv6_proxy_vss_show_command, static) = {
  .path = "show dhcpv6 vss",
  .short_help = "show dhcpv6 VSS",
  .function = dhcpv6_vss_show_command_fn,
};

static clib_error_t *
dhcpv6_link_address_show_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)

{
  dhcpv6_proxy_main_t *dm = &dhcpv6_proxy_main;
  vnet_main_t *vnm = vnet_get_main();
  u32 sw_if_index0=0, sw_if_index;
  ip6_address_t *ia0;
  vnet_sw_interface_t *swif;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat(input, "%U",
                   unformat_vnet_sw_interface, dm->vnet_main, &sw_if_index0))
        {
            swif = vnet_get_sw_interface (vnm, sw_if_index0);
            sw_if_index = (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED) ?
                swif->unnumbered_sw_if_index : sw_if_index0;
            ia0 = ip6_interface_first_address(&ip6_main, sw_if_index);
            if (ia0)
              {
                  vlib_cli_output (vm, "%=20s%=48s", "interface", "link-address");

                  vlib_cli_output (vm, "%=20U%=48U",
                                   format_vnet_sw_if_index_name, dm->vnet_main, sw_if_index0,
                                   format_ip6_address, ia0);
              } else
                vlib_cli_output (vm, "%=34s%=20U", "No IPv6 address configured on",
                                 format_vnet_sw_if_index_name, dm->vnet_main, sw_if_index);
        } else
          break;
    }

  return 0;
}

VLIB_CLI_COMMAND (dhcpv6_proxy_address_show_command, static) = {
  .path = "show dhcpv6 link-address interface",
  .short_help = "show dhcpv6 link-address interface <interface>",
  .function = dhcpv6_link_address_show_command_fn,
};
