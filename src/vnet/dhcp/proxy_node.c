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
#include <vnet/pg/pg.h>
#include <vnet/dhcp/proxy.h>
#include <vnet/fib/ip4_fib.h>

static char * dhcp_proxy_error_strings[] = {
#define dhcp_proxy_error(n,s) s,
#include "proxy_error.def"
#undef dhcp_proxy_error
};

#define foreach_dhcp_proxy_to_server_input_next \
  _ (DROP, "error-drop")			\
  _ (LOOKUP, "ip4-lookup")			\
  _ (SEND_TO_CLIENT, "dhcp-proxy-to-client")

typedef enum {
#define _(s,n) DHCP_PROXY_TO_SERVER_INPUT_NEXT_##s,
  foreach_dhcp_proxy_to_server_input_next
#undef _
  DHCP_PROXY_TO_SERVER_INPUT_N_NEXT,
} dhcp_proxy_to_server_input_next_t;

typedef struct {
  /* 0 => to server, 1 => to client */
  int which; 
  ip4_address_t trace_ip4_address;
  u32 error;
  u32 sw_if_index;
  u32 original_sw_if_index;
} dhcp_proxy_trace_t;

#define VPP_DHCP_OPTION82_SUB1_SIZE   6
#define VPP_DHCP_OPTION82_SUB5_SIZE   6
#define VPP_DHCP_OPTION82_VSS_SIZE    12
#define VPP_DHCP_OPTION82_SIZE (VPP_DHCP_OPTION82_SUB1_SIZE + \
                                VPP_DHCP_OPTION82_SUB5_SIZE + \
                                VPP_DHCP_OPTION82_VSS_SIZE +3)

vlib_node_registration_t dhcp_proxy_to_server_node;
vlib_node_registration_t dhcp_proxy_to_client_node;

u8 * format_dhcp_proxy_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dhcp_proxy_trace_t * t = va_arg (*args, dhcp_proxy_trace_t *);
    
  if (t->which == 0)
    s = format (s, "DHCP proxy: sent to server %U\n",
                format_ip4_address, &t->trace_ip4_address, t->error);
  else
    s = format (s, "DHCP proxy: broadcast to client from %U\n",
                format_ip4_address, &t->trace_ip4_address);
      
  if (t->error != (u32)~0)
    s = format (s, "  error: %s\n", dhcp_proxy_error_strings[t->error]);

  s = format (s, "  original_sw_if_index: %d, sw_if_index: %d\n",
              t->original_sw_if_index, t->sw_if_index);
  
  return s;
}

u8 * format_dhcp_proxy_header_with_length (u8 * s, va_list * args)
{
  dhcp_header_t * h = va_arg (*args, dhcp_header_t *);
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
  u32 n_left_from, next_index, * from, * to_next;
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 pkts_to_server=0, pkts_to_client=0, pkts_no_server=0;
  u32 pkts_no_interface_address=0;
  u32 pkts_too_big=0;
  ip4_main_t * im = &ip4_main;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
          udp_header_t * u0;
	  dhcp_header_t * h0;
          ip4_header_t * ip0;
	  u32 next0;
          u32 old0, new0;
          ip_csum_t sum0;
          u32 error0 = (u32) ~0;
          u32 sw_if_index = 0;
          u32 original_sw_if_index = 0;
          u8  *end = NULL;
          u32 fib_index, server_index;
          dhcp_server_t * server;
          u32 rx_sw_if_index;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          h0 = vlib_buffer_get_current (b0);

          /* 
           * udp_local hands us the DHCP header, need udp hdr, 
           * ip hdr to relay to server
           */
          vlib_buffer_advance (b0, -(sizeof(*u0)));
	  u0 = vlib_buffer_get_current (b0);

          /* This blows. Return traffic has src_port = 67, dst_port = 67 */
          if (u0->src_port == clib_net_to_host_u16(UDP_DST_PORT_dhcp_to_server))
            {
              vlib_buffer_advance (b0, sizeof(*u0));
              next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_SEND_TO_CLIENT;
              error0 = 0;
              pkts_to_client++;
              goto do_enqueue;
            }

          rx_sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          fib_index = im->fib_index_by_sw_if_index [rx_sw_if_index];

          if (fib_index < vec_len(dpm->dhcp_server_index_by_rx_fib_index))
            server_index = dpm->dhcp_server_index_by_rx_fib_index[fib_index];
          else
            server_index = 0;
          
          if (PREDICT_FALSE (pool_is_free_index (dpm->dhcp_servers, 
                                                 server_index)))
            {
            no_server:
              error0 = DHCP_PROXY_ERROR_NO_SERVER;
              next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
              pkts_no_server++;
              goto do_trace;
            }
          
          server = pool_elt_at_index (dpm->dhcp_servers, server_index);
          if (server->valid == 0)
            goto no_server;

          vlib_buffer_advance (b0, -(sizeof(*ip0)));
          ip0 = vlib_buffer_get_current (b0);

          /* disable UDP checksum */
          u0->checksum = 0;
          sum0 = ip0->checksum;
          old0 = ip0->dst_address.as_u32;
          new0 = server->dhcp_server.as_u32;
          ip0->dst_address.as_u32 = server->dhcp_server.as_u32;
          sum0 = ip_csum_update (sum0, old0, new0, 
                                ip4_header_t /* structure */, 
                                dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          sum0 = ip0->checksum;
          old0 = ip0->src_address.as_u32;
          new0 = server->dhcp_src_address.as_u32;
          ip0->src_address.as_u32 = new0;
          sum0 = ip_csum_update (sum0, old0, new0, 
                                ip4_header_t /* structure */, 
                                src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          /* Send to DHCP server via the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] =
            server->server_fib_index;

          h0->gateway_ip_address.as_u32 = server->dhcp_src_address.as_u32;
          pkts_to_server++;

          if (server->insert_option_82) 
            {
              u32 fib_index, fib_id, opt82_fib_id=0, opt82_oui=0;
	      ip4_fib_t * fib;
              dhcp_option_t *o = (dhcp_option_t *) h0->options;
              u32 len = 0;
              vlib_buffer_free_list_t *fl;
              
              fib_index = im->fib_index_by_sw_if_index 
                [vnet_buffer(b0)->sw_if_index[VLIB_RX]];
	      fib = ip4_fib_get (fib_index);
	      fib_id = fib->table_id;

              end = b0->data + b0->current_data + b0->current_length;
              /* TLVs are not performance-friendly... */
              while  (o->option != 0xFF /* end of options */ && (u8 *)o < end) 
                  o = (dhcp_option_t *) (((uword) o) + (o->length + 2));

              fl = vlib_buffer_get_free_list (vm, b0->free_list_index);
              // start write at (option*)o, some packets have padding
              if (((u8 *)o - (u8 *)b0->data + VPP_DHCP_OPTION82_SIZE) > fl->n_data_bytes)
                {
                  next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
                  pkts_too_big++;
                  goto do_trace;
                }

              if ((o->option == 0xFF)  && ((u8 *)o <= end))
                {  
                  vnet_main_t *vnm = vnet_get_main();   
                  u16 old_l0, new_l0;
                  ip4_address_t _ia0, * ia0 = &_ia0;
                  uword  *p_vss;
                  vss_info *vss;
                  vnet_sw_interface_t *swif;
                  sw_if_index = 0;
                  original_sw_if_index = 0;
                  
                  original_sw_if_index = sw_if_index = 
                      vnet_buffer(b0)->sw_if_index[VLIB_RX];
                  swif = vnet_get_sw_interface (vnm, sw_if_index);
                  if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
                      sw_if_index = swif->unnumbered_sw_if_index;
                  
                  p_vss = hash_get (dpm->opt82vss_index_by_vrf_id,
                                    fib_id);
                  if (p_vss) 
                    {
                      vss = pool_elt_at_index (dpm->opt82vss, p_vss[0]);
                      opt82_oui =  vss->vpn_id.oui;
                      opt82_fib_id =  vss->vpn_id.fib_id;
                    }
                  /* 
                   * Get the first ip4 address on the [client-side] 
                   * RX interface, if not unnumbered. otherwise use
                   * the loopback interface's ip address.
                   */
                  ia0 = ip4_interface_first_address(&ip4_main, sw_if_index, 0);
                  
                  if (ia0 == 0)
                    {
                      error0 = DHCP_PROXY_ERROR_NO_INTERFACE_ADDRESS;
                      next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_DROP;
                      pkts_no_interface_address++;
                      goto do_trace;
                    }

                  /* Add option 82 */
                  o->option = 82;   /* option 82 */
                  o->length = 12;   /* 12 octets to follow */
                  o->data[0] = 1;   /* suboption 1, circuit ID (=FIB id) */
                  o->data[1] = 4;   /* length of suboption */
                  o->data[2] = (original_sw_if_index >> 24) & 0xFF;
                  o->data[3] = (original_sw_if_index >> 16) & 0xFF;
                  o->data[4] = (original_sw_if_index >> 8)  & 0xFF;
                  o->data[5] = (original_sw_if_index >> 0)  & 0xFF;
		  o->data[6] = 5; /* suboption 5 (client RX intfc address) */
		  o->data[7] = 4; /* length 4 */
		  o->data[8] = ia0->as_u8[0];
		  o->data[9] = ia0->as_u8[1];
		  o->data[10] = ia0->as_u8[2];
		  o->data[11] = ia0->as_u8[3];
                  o->data[12] = 0xFF;
                  if (opt82_oui !=0 || opt82_fib_id != 0)
                    {
                      o->data[12] = 151; /* vss suboption */
                      if (255 == opt82_fib_id) {
                          o->data[13] = 1;   /* length */
                          o->data[14] = 255;   /* vss option type */
                          o->data[15] = 152; /* vss control suboption */
                          o->data[16] = 0;   /* length */
                          /* and a new "end-of-options" option (0xff) */
                          o->data[17] = 0xFF;
                          o->length += 5;
                      } else {
                          o->data[13] = 8;   /* length */
                          o->data[14] = 1;   /* vss option type */
                          o->data[15] = (opt82_oui >> 16) & 0xff;
                          o->data[16] = (opt82_oui >> 8) & 0xff;
                          o->data[17] = (opt82_oui ) & 0xff;
                          o->data[18] = (opt82_fib_id >> 24) & 0xff;
                          o->data[19] = (opt82_fib_id >> 16) & 0xff;
                          o->data[20] = (opt82_fib_id >> 8) & 0xff;
                          o->data[21] = (opt82_fib_id) & 0xff;
                          o->data[22] = 152; /* vss control suboption */
                          o->data[23] = 0;   /* length */
                          
                          /* and a new "end-of-options" option (0xff) */
                          o->data[24] = 0xFF;
                          o->length += 12;
                      }
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
                                         length /* changed member */);
                  ip0->checksum = ip_csum_fold (sum0);

                  /* Fix UDP length */
                  new_l0 = clib_net_to_host_u16 (u0->length);
                  new_l0 += len;
                  u0->length = clib_host_to_net_u16 (new_l0);
                } else {
                  vlib_node_increment_counter 
                      (vm, dhcp_proxy_to_server_node.index,
                       DHCP_PROXY_ERROR_OPTION_82_ERROR, 1);
                }
            }
          
          next0 = DHCP_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP;

        do_trace:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
               dhcp_proxy_trace_t *tr = vlib_add_trace (vm, node, 
                                                        b0, sizeof (*tr));
               tr->which = 0; /* to server */
               tr->error = error0;
               tr->original_sw_if_index = original_sw_if_index;
               tr->sw_if_index = sw_if_index;
               if (next0 == DHCP_PROXY_TO_SERVER_INPUT_NEXT_LOOKUP)
                 tr->trace_ip4_address.as_u32 = server->dhcp_server.as_u32;
            }

        do_enqueue:
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
                               DHCP_PROXY_ERROR_NO_SERVER,
                               pkts_no_server);
  vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
                               DHCP_PROXY_ERROR_NO_INTERFACE_ADDRESS,
                               pkts_no_interface_address);
 vlib_node_increment_counter (vm, dhcp_proxy_to_server_node.index,
                              DHCP_PROXY_ERROR_PKT_TOO_BIG,
                              pkts_too_big);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (dhcp_proxy_to_server_node) = {
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

static uword
dhcp_proxy_to_client_input (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * from_frame)
{
  u32 n_left_from, * from;
  ethernet_main_t *em = ethernet_get_main (vm);
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      udp_header_t * u0;
      dhcp_header_t * h0;
      ip4_header_t * ip0 = 0;
      ip4_address_t * ia0 = 0;
      u32 old0, new0;
      ip_csum_t sum0;
      ethernet_interface_t *ei0;
      ethernet_header_t *mac0;
      vnet_hw_interface_t *hi0;
      vlib_frame_t *f0;
      u32 * to_next0;
      u32 sw_if_index = ~0;
      vnet_sw_interface_t *si0;
      u32 error0 = (u32)~0;
      vnet_sw_interface_t *swif;
      u32 server_index;
      u32 fib_index;
      dhcp_server_t * server;
      u32 original_sw_if_index = (u32) ~0;
          
      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0);

      /* 
       * udp_local hands us the DHCP header, need udp hdr, 
       * ip hdr to relay to client
       */
      vlib_buffer_advance (b0, -(sizeof(*u0)));
      u0 = vlib_buffer_get_current (b0);

      vlib_buffer_advance (b0, -(sizeof(*ip0)));
      ip0 = vlib_buffer_get_current (b0);

      /* Consumed by dhcp client code? */
      if (dhcp_client_for_us (bi0, b0, ip0, u0, h0))
          continue;

      if (1 /* dpm->insert_option_82 */)
        {
          dhcp_option_t *o = (dhcp_option_t *) h0->options;
          dhcp_option_t *sub;
              
          /* Parse through TLVs looking for option 82.
             The circuit-ID is the FIB number we need
             to track down the client-facing interface */

          while (o->option != 0xFF /* end of options */ &&
                 (u8 *) o < (b0->data + b0->current_data + b0->current_length))
            {
              if (o->option == 82)
                {
                    u32 vss_exist = 0;
                    u32 vss_ctrl = 0;
                    sub = (dhcp_option_t *) &o->data[0];
                    while (sub->option != 0xFF /* end of options */ &&
                           (u8 *) sub < (u8 *)(o + o->length)) {
                        /* If this is one of ours, it will have
                           total length 12, circuit-id suboption type,
                           and the sw_if_index */
                        if (sub->option == 1 && sub->length == 4)
                          {
                            sw_if_index = (o->data[2] << 24)
                                | (o->data[3] << 16)
                                | (o->data[4] << 8)
                                | (o->data[5]);
                          } else if (sub->option == 151 &&
                                     sub->length == 7 &&
                                     sub->data[0] == 1)
                            vss_exist = 1;
                        else if (sub->option == 152 && sub->length == 0)
                            vss_ctrl = 1;
                        sub = (dhcp_option_t *) 
                          (((uword) sub) + (sub->length + 2));
                    }
                    if (vss_ctrl && vss_exist)
                      vlib_node_increment_counter 
                        (vm, dhcp_proxy_to_client_node.index,
                         DHCP_PROXY_ERROR_OPTION_82_VSS_NOT_PROCESSED, 1);

                }
              o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
            }
        }

      if (sw_if_index == (u32)~0)
        {
          error0 = DHCP_PROXY_ERROR_NO_OPTION_82;
          
        drop_packet:
          vlib_node_increment_counter (vm, dhcp_proxy_to_client_node.index,
                                       error0, 1);
          f0 = vlib_get_frame_to_node (vm, dpm->error_drop_node_index);
          to_next0 = vlib_frame_vector_args (f0);
          to_next0[0] = bi0;
          f0->n_vectors = 1;
          vlib_put_frame_to_node (vm, dpm->error_drop_node_index, f0);
          goto do_trace;
        }
      

      if (sw_if_index >= vec_len (im->fib_index_by_sw_if_index))
        {
          error0 = DHCP_PROXY_ERROR_BAD_OPTION_82;
          goto drop_packet;
        }

      fib_index = im->fib_index_by_sw_if_index [sw_if_index];

      if (fib_index < vec_len(dpm->dhcp_server_index_by_rx_fib_index))
        server_index = dpm->dhcp_server_index_by_rx_fib_index[fib_index];
      else
        server_index = 0;

      if (PREDICT_FALSE (pool_is_free_index (dpm->dhcp_servers, 
                                             server_index)))
        {
          error0 = DHCP_PROXY_ERROR_BAD_OPTION_82;
          goto drop_packet;
        }
      
      server = pool_elt_at_index (dpm->dhcp_servers, server_index);
      if (server->valid == 0)
        {
          error0 = DHCP_PROXY_ERROR_NO_SERVER;
          goto drop_packet;
        }

      if (ip0->src_address.as_u32 != server->dhcp_server.as_u32)
        {             
          error0 = DHCP_PROXY_ERROR_BAD_SVR_FIB_OR_ADDRESS;
          goto drop_packet;
        }

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

      u0->checksum = 0;
      u0->dst_port = clib_net_to_host_u16 (UDP_DST_PORT_dhcp_to_client);
      sum0 = ip0->checksum;
      old0 = ip0->dst_address.as_u32;
      new0 = 0xFFFFFFFF;
      ip0->dst_address.as_u32 = new0;
      sum0 = ip_csum_update (sum0, old0, new0, 
                            ip4_header_t /* structure */, 
                            dst_address /* offset of changed member */);
      ip0->checksum = ip_csum_fold (sum0);

      sum0 = ip0->checksum;
      old0 = ip0->src_address.as_u32;
      new0 = ia0->as_u32;
      ip0->src_address.as_u32 = new0;
      sum0 = ip_csum_update (sum0, old0, new0, 
                            ip4_header_t /* structure */, 
                            src_address /* offset of changed member */);
      ip0->checksum = ip_csum_fold (sum0);

      vlib_buffer_advance (b0, -(sizeof(ethernet_header_t)));
      si0 = vnet_get_sw_interface (vnm, original_sw_if_index);
      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	  vlib_buffer_advance (b0, -4 /* space for VLAN tag */);

      mac0 = vlib_buffer_get_current (b0);

      hi0 = vnet_get_sup_hw_interface (vnm, original_sw_if_index);
      ei0 = pool_elt_at_index (em->interfaces, hi0->hw_instance);
      clib_memcpy (mac0->src_address, ei0->address, sizeof (ei0->address));
      memset (mac0->dst_address, 0xff, sizeof (mac0->dst_address));
      mac0->type = (si0->type == VNET_SW_INTERFACE_TYPE_SUB) ?
	clib_net_to_host_u16(0x8100) : clib_net_to_host_u16 (0x0800);

      if (si0->type == VNET_SW_INTERFACE_TYPE_SUB)
	{
	  u32 * vlan_tag = (u32 *)(mac0+1);
	  u32 tmp;
	  tmp = (si0->sub.id << 16) | 0x0800;
	  *vlan_tag = clib_host_to_net_u32 (tmp);
	}

      /* $$$ This needs to be rewritten, for sure */
      f0 = vlib_get_frame_to_node (vm, hi0->output_node_index);
      to_next0 = vlib_frame_vector_args (f0);
      to_next0[0] = bi0;
      f0->n_vectors = 1;
      vlib_put_frame_to_node (vm, hi0->output_node_index, f0);

    do_trace:
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          dhcp_proxy_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
          tr->which = 1; /* to client */
          tr->trace_ip4_address.as_u32 = ia0 ? ia0->as_u32 : 0;
          tr->error = error0;
          tr->original_sw_if_index = original_sw_if_index;
          tr->sw_if_index = sw_if_index;
        }
    }
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (dhcp_proxy_to_client_node) = {
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
};

clib_error_t * dhcp_proxy_init (vlib_main_t * vm)
{
  dhcp_proxy_main_t * dm = &dhcp_proxy_main;
  vlib_node_t * error_drop_node;
  dhcp_server_t * server;

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main();
  error_drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  dm->error_drop_node_index = error_drop_node->index;

  dm->opt82vss_index_by_vrf_id = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm, UDP_DST_PORT_dhcp_to_client, 
                         dhcp_proxy_to_client_node.index, 1 /* is_ip4 */);

  udp_register_dst_port (vm, UDP_DST_PORT_dhcp_to_server, 
                         dhcp_proxy_to_server_node.index, 1 /* is_ip4 */);

  /* Create the default server, don't mark it valid */
  pool_get (dm->dhcp_servers, server);
  memset (server, 0, sizeof (*server));

  return 0;
}

VLIB_INIT_FUNCTION (dhcp_proxy_init);

int dhcp_proxy_set_server_2 (ip4_address_t *addr, ip4_address_t *src_address,
                             u32 rx_fib_id,
                             u32 server_fib_id, 
                             int insert_option_82, int is_del)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_server_t * server = 0;
  u32 server_index = 0;
  u32 rx_fib_index = 0;

  if (addr->as_u32 == 0)
    return VNET_API_ERROR_INVALID_DST_ADDRESS;
  
  if (src_address->as_u32 == 0)
    return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  rx_fib_index = fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4,
                                                   rx_fib_id);

  if (rx_fib_id == 0)
    {
      server = pool_elt_at_index (dpm->dhcp_servers, 0);
      
      if (is_del)
        {
          memset (server, 0, sizeof (*server));
          return 0;
        }
      goto initialize_it;
    }

  if (is_del)
    {
      if (rx_fib_index >= vec_len(dpm->dhcp_server_index_by_rx_fib_index))
        return VNET_API_ERROR_NO_SUCH_ENTRY;
      
      server_index = dpm->dhcp_server_index_by_rx_fib_index[rx_fib_index];
      ASSERT(server_index > 0);

      /* Use the default server again.  */
      dpm->dhcp_server_index_by_rx_fib_index[rx_fib_index] = 0;
      server = pool_elt_at_index (dpm->dhcp_servers, server_index);
      memset (server, 0, sizeof (*server));
      pool_put (dpm->dhcp_servers, server);
      return 0;
    }

  if (rx_fib_index < vec_len(dpm->dhcp_server_index_by_rx_fib_index))
    {
      server_index = dpm->dhcp_server_index_by_rx_fib_index[rx_fib_index];
      if (server_index != 0)
        {
          server = pool_elt_at_index (dpm->dhcp_servers, server_index);
          goto initialize_it;
        }
    }

  pool_get (dpm->dhcp_servers, server);
  
 initialize_it:

  server->dhcp_server.as_u32 = addr->as_u32;
  server->server_fib_index = 
      fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4,
	  				server_fib_id);
  server->dhcp_src_address.as_u32 = src_address->as_u32;
  server->insert_option_82 = insert_option_82;
  server->valid = 1;
  if (rx_fib_index)
    {
      vec_validate (dpm->dhcp_server_index_by_rx_fib_index, rx_fib_index);
      dpm->dhcp_server_index_by_rx_fib_index[rx_fib_index] = 
        server - dpm->dhcp_servers;
    }

  return 0;
}

/* Old API, manipulates the default server (only) */
int dhcp_proxy_set_server (ip4_address_t *addr, ip4_address_t *src_address,
                           u32 fib_id, int insert_option_82, int is_del)
{
  return dhcp_proxy_set_server_2 (addr, src_address, 0 /* rx_fib_id */,
                                  fib_id /* server_fib_id */, 
                                  insert_option_82, is_del);
}


static clib_error_t *
dhcp_proxy_set_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  ip4_address_t server_addr, src_addr;
  u32 server_fib_id = 0, rx_fib_id = 0;
  int is_del = 0;
  int add_option_82 = 0;
  int set_src = 0, set_server = 0;
  
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "server %U", 
                    unformat_ip4_address, &server_addr)) 
        set_server = 1;
      else if (unformat (input, "server-fib-id %d", &server_fib_id))
        ;
      else if (unformat (input, "rx-fib-id %d", &rx_fib_id))
        ;
      else if (unformat(input, "src-address %U", 
			unformat_ip4_address, &src_addr))
        set_src = 1;
      else if (unformat (input, "add-option-82")
               || unformat (input, "insert-option-82"))
        add_option_82 = 1;
      else if (unformat (input, "delete") ||
               unformat (input, "del"))
        is_del = 1;
      else
        break;
    }

  if (is_del || (set_server && set_src))
    {
      int rv;

      rv = dhcp_proxy_set_server_2 (&server_addr, &src_addr, rx_fib_id, 
                                    server_fib_id, add_option_82, is_del);
      switch (rv)
        {
        case 0:
          return 0;

        case VNET_API_ERROR_INVALID_DST_ADDRESS:
          return clib_error_return (0, "Invalid server address");
          
        case VNET_API_ERROR_INVALID_SRC_ADDRESS:
          return clib_error_return (0, "Invalid src address");
          
        case VNET_API_ERROR_NO_SUCH_INNER_FIB:
          return clib_error_return (0, "No such rx fib id %d", rx_fib_id);
          
        case VNET_API_ERROR_NO_SUCH_FIB:
          return clib_error_return (0, "No such server fib id %d", 
                                    server_fib_id);

        case VNET_API_ERROR_NO_SUCH_ENTRY:
          return clib_error_return 
            (0, "Fib id %d: no per-fib DHCP server configured", rx_fib_id);

        default:
          return clib_error_return (0, "BUG: rv %d", rv);
        }
    }
  else
    return clib_error_return (0, "parse error`%U'",
                              format_unformat_error, input);
}

VLIB_CLI_COMMAND (dhcp_proxy_set_command, static) = {
  .path = "set dhcp proxy",
  .short_help = "set dhcp proxy [del] server <ip-addr> src-address <ip-addr> [add-option-82] [server-fib-id <n>] [rx-fib-id <n>]",
  .function = dhcp_proxy_set_command_fn,
};

u8 * format_dhcp_proxy_server (u8 * s, va_list * args)
{
  dhcp_proxy_main_t * dm = va_arg (*args, dhcp_proxy_main_t *);
  dhcp_server_t * server = va_arg (*args, dhcp_server_t *);
  u32 rx_fib_index = va_arg (*args, u32);
  ip4_fib_t * rx_fib, * server_fib;
  u32 server_fib_id = ~0, rx_fib_id = ~0;

  if (dm == 0)
    {
      s = format (s, "%=16s%=16s%=14s%=14s%=20s", "Server", "Src Address", 
                  "Server FIB", "RX FIB", "Insert Option 82");
      return s;
    }

  server_fib = ip4_fib_get(server->server_fib_index);

  if (server_fib)
    server_fib_id = server_fib->table_id;

  rx_fib = ip4_fib_get(rx_fib_index);

  if (rx_fib)
    rx_fib_id = rx_fib->table_id;

  s = format (s, "%=16U%=16U%=14u%=14u%=20s",
              format_ip4_address, &server->dhcp_server,
              format_ip4_address, &server->dhcp_src_address,
              server_fib_id, rx_fib_id,
              server->insert_option_82 ? "yes" : "no");
  return s;
}

static clib_error_t *
dhcp_proxy_show_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  ip4_main_t * im = &ip4_main;
  dhcp_server_t * server;
  u32 server_index;
  int i;

  vlib_cli_output (vm, "%U", format_dhcp_proxy_server, 0 /* header line */,
                   0, 0);

  for (i = 0; i < vec_len (im->fibs); i++)
    {
      if (i < vec_len(dpm->dhcp_server_index_by_rx_fib_index))
        server_index = dpm->dhcp_server_index_by_rx_fib_index[i];
      else
        server_index = 0;
      server = pool_elt_at_index (dpm->dhcp_servers, server_index);
      if (server->valid)
        vlib_cli_output (vm, "%U", format_dhcp_proxy_server, dpm, 
                         server, i);
    }

  return 0;
}

VLIB_CLI_COMMAND (dhcp_proxy_show_command, static) = {
  .path = "show dhcp proxy",
  .short_help = "Display dhcp proxy server info",
  .function = dhcp_proxy_show_command_fn,
};


int dhcp_proxy_set_option82_vss(  u32 vrf_id,
                                  u32 oui,
                                  u32 fib_id, 
                                  int is_del)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  uword *p;
  vss_info *a;
  u32 old_oui=0, old_fib_id=0;
  
  p = hash_get (dm->opt82vss_index_by_vrf_id, vrf_id);

  if (p) 
    {
      a = pool_elt_at_index (dm->opt82vss, p[0]);
      if (!a) 
        return VNET_API_ERROR_NO_SUCH_FIB;
      old_oui = a->vpn_id.oui;
      old_fib_id = a->vpn_id.fib_id;
          
      if (is_del)
        {
          if (old_oui == oui &&
              old_fib_id == fib_id)
            {
              pool_put(dm->opt82vss, a);
              hash_unset (dm->opt82vss_index_by_vrf_id, vrf_id);
              return 0;
            }
          else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
        }
      pool_put(dm->opt82vss, a);
      hash_unset (dm->opt82vss_index_by_vrf_id, vrf_id);
  } else if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pool_get (dm->opt82vss, a);
  memset (a, ~0, sizeof (a[0]));
  a->vpn_id.oui = oui;
  a->vpn_id.fib_id = fib_id;
  hash_set (dm->opt82vss_index_by_vrf_id, vrf_id, a - dm->opt82vss);
  
  return 0;
}

static clib_error_t *
dhcp_option_82_vss_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  int is_del = 0, got_new_vpn_id=0;
  u32 oui=0, fib_id=0, tbl_id=~0;
 

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) 
    {

      if (unformat(input, "delete") || unformat(input, "del"))
          is_del = 1;    
      else if (unformat (input, "oui %d", &oui))
          got_new_vpn_id = 1;
      else if (unformat (input, "vpn-id %d", &fib_id))
          got_new_vpn_id = 1;
      else if (unformat (input, "table %d", &tbl_id))
          got_new_vpn_id = 1;
      else
          break;
  }
  if (tbl_id == ~0)
      return clib_error_return (0, "no table ID specified.");
  
  if (is_del || got_new_vpn_id)
    {
      int rv;
      rv = dhcp_proxy_set_option82_vss(tbl_id, oui, fib_id, is_del);
      switch (rv)
        {
        case 0:
            return 0;
            
        case VNET_API_ERROR_NO_SUCH_FIB:
            return clib_error_return (0, "option 82 vss(oui:%d, vpn-id:%d) not found in table %d",
                                      oui, fib_id, tbl_id);
            
        case VNET_API_ERROR_NO_SUCH_ENTRY:
            return clib_error_return (0, "option 82 vss for table %d not found in in pool.",
                                      tbl_id);
        default:
          return clib_error_return (0, "BUG: rv %d", rv);
        }
    }
  else
      return clib_error_return (0, "parse error`%U'",
                                format_unformat_error, input);
}

VLIB_CLI_COMMAND (dhcp_proxy_vss_command,static) = {
  .path = "set dhcp option-82 vss",
  .short_help = "set dhcp option-82 vss [del] table <table id> oui <oui> vpn-id <vpn-id>",
  .function = dhcp_option_82_vss_fn,
};


static clib_error_t *
dhcp_vss_show_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
  
{
  dhcp_proxy_main_t * dm = &dhcp_proxy_main;
  vss_info *v;
  u32 oui;
  u32 fib_id;
  u32 tbl_id;
  uword index;
  
  vlib_cli_output (vm, "%=9s%=11s%=12s","Table", "OUI", "VPN-ID");
  hash_foreach (tbl_id, index, dm->opt82vss_index_by_vrf_id,
  ({
     v = pool_elt_at_index (dm->opt82vss, index);
     oui = v->vpn_id.oui;
     fib_id = v->vpn_id.fib_id;
     vlib_cli_output (vm, "%=9d 0x%08x%=12d",
                      tbl_id, oui, fib_id);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (dhcp_proxy_vss_show_command, static) = {
  .path = "show dhcp vss",
  .short_help = "show dhcp VSS",
  .function = dhcp_vss_show_command_fn,
};

static clib_error_t *
dhcp_option_82_address_show_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
  
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  vnet_main_t *vnm = vnet_get_main();                                     
  u32 sw_if_index0=0, sw_if_index;
  ip4_address_t *ia0;
  vnet_sw_interface_t *swif;
  
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) 
    {
      
      if (unformat(input, "%U",
                   unformat_vnet_sw_interface, dm->vnet_main, &sw_if_index0))
        {
          swif = vnet_get_sw_interface (vnm, sw_if_index0);
          sw_if_index = (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED) ?
            swif->unnumbered_sw_if_index : sw_if_index0;
          ia0 = ip4_interface_first_address(&ip4_main, sw_if_index, 0);
          if (ia0)
            {
              vlib_cli_output (vm, "%=20s%=20s", "interface", 
                               "source IP address");
              
              vlib_cli_output (vm, "%=20U%=20U",
                               format_vnet_sw_if_index_name, 
                               dm->vnet_main, sw_if_index0,
                               format_ip4_address, ia0);
            }
          else
            vlib_cli_output (vm, "%=34s %=20U", 
                             "No IPv4 address configured on",
                             format_vnet_sw_if_index_name, 
                             dm->vnet_main, sw_if_index);
        }
      else
        break;
    }
  
  return 0;
}

VLIB_CLI_COMMAND (dhcp_proxy_address_show_command,static) = {
  .path = "show dhcp option-82-address interface",
  .short_help = "show dhcp option-82-address interface <interface>",
  .function = dhcp_option_82_address_show_command_fn,
};
