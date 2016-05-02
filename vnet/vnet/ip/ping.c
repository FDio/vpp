/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ip/ping.h>


/*
 * Process ICMPv6 echo replies
 * Expect 1 packet / frame
 */
static uword
ip6_icmp_echo_reply_node_fn (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * frame)
{
  ping_main_t *pm = &ping_main;
  u32 n_left_from, * from;

  from = vlib_frame_vector_args (frame); /* array of buffer indices */
  n_left_from = frame->n_vectors;        /* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      u32 next0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      /* Signal to the CLI process that a reply has arrived,
         find the process by ICMP ID from the packet */
      {
        icmp6_echo_request_header_t *h0 = vlib_buffer_get_current(b0);
        uword *h = hash_get(pm->cli_proc_by_icmp_id, clib_net_to_host_u16(h0->icmp_echo.id));
        if (h) {
          vlib_process_signal_event (vm, h[0], PING_RESPONSE_IP6, b0->flags);
        }
      }

      /* push this pkt to the next graph node, always error-drop */
      next0 = ICMP6_ECHO_REPLY_NEXT_NORMAL;
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_icmp_echo_reply_node,static) = {
  .function = ip6_icmp_echo_reply_node_fn,
  .name = "ip6-icmp-echo-reply",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP6_ECHO_REPLY_NEXT_NORMAL] = "error-drop",
  },
};

char *ip6_lookup_next_nodes[] = IP6_LOOKUP_NEXT_NODES;

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


static void
send_ip6_ping (vlib_main_t *vm, ip6_main_t *im, ip6_address_t *pa6, u32 sw_if_index, 
               u16 seq_host, u16 id_host, u16 data_len, u8 verbose)
{
  ping_main_t *pm = &ping_main;
  icmp6_echo_request_header_t * h0;
  u32 bi0 = 0;
  u32 sw_if_index0;
  ip_lookup_main_t * lm = &im->lookup_main;
  int bogus_length = 0;
  u32 adj_index0;
  ip_adjacency_t * adj0;
  vlib_buffer_t * p0;
  vlib_frame_t * f;
  u32 * to_next;
  u32 fib_index0;


  h0 = vlib_packet_template_get_packet
         (vm, &pm->icmp6_echo_request_packet_template, &bi0);

  p0 = vlib_get_buffer (vm, bi0);

  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  vnet_buffer(p0)->sw_if_index[VLIB_TX] = ~0; /* use interface VRF */

  /* Enqueue the packet right now */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;



  h0->ip.dst_address = *pa6;
  h0->ip.src_address = *pa6;

  fib_index0 = 0; // vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p0)->sw_if_index[VLIB_TX]);
  adj_index0 = ip6_fib_lookup_with_table(im, fib_index0, &h0->ip.dst_address);
  
  adj0 = ip_get_adjacency (lm, adj_index0);
  sw_if_index0 = adj0->rewrite_header.sw_if_index;
  if (verbose) {
    clib_warning("IPv6 adjacency index: %u, sw_if_index: %u\n", adj_index0, sw_if_index0);
    clib_warning("Adj: %s\n", ip6_lookup_next_nodes[adj0->lookup_next_index]);
    clib_warning("Intf: %d\n", adj0->if_address_index);
  }
  if ((~0 == sw_if_index0) && (~0 == sw_if_index)) {
    clib_warning("Can not set the source interface (next adj: %s)", ip6_lookup_next_nodes[adj0->lookup_next_index]);
    vlib_buffer_free(vm, &bi0, 1);
    return;
  }
  {
    if (~0 != sw_if_index) {
      sw_if_index0 = sw_if_index;
      if (verbose) {
        clib_warning("Setting source interface: %d\n", sw_if_index0);
      }
    }
    ip6_address_t * a = ip6_interface_first_address(im, sw_if_index0);
    h0->ip.src_address = a[0];
  }

  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
  vnet_buffer(p0)->sw_if_index[VLIB_RX] = sw_if_index0; 


  h0->icmp_echo.seq = clib_host_to_net_u16(seq_host);
  h0->icmp_echo.id = clib_host_to_net_u16(id_host);

  h0->ip.payload_length = clib_host_to_net_u16 (data_len + sizeof(icmp46_header_t)); 

  p0->current_length = clib_net_to_host_u16(h0->ip.payload_length) + 
                         STRUCT_OFFSET_OF (icmp6_echo_request_header_t, icmp);

  h0->icmp.checksum = 0;
  h0->icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip, &bogus_length);
}


static clib_error_t *
ping_ip_address (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  ping_main_t *pm = &ping_main;
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t * error = 0;
  u32 ping_repeat = 5;
  u8 ping_ip4, ping_ip6;
  vnet_main_t *vnm = vnet_get_main();
  u32 data_len = 64;
  u32 verbose = 0;

  ping_ip4 = ping_ip6 = 0;
  
  u32 sw_if_index;

  sw_if_index = ~0;


  if (unformat (input, "%U", unformat_ip4_address, &a4)) {
    ping_ip4 = 1;
  } else if (unformat (input, "%U", unformat_ip6_address, &a6)) {
    ping_ip6 = 1;
  }
  else {
    error = clib_error_return (0, "expected IP4/IP6 address `%U'",
				 format_unformat_error, input);
      goto done;
  }

  while(!unformat_eof(input, NULL)) {
    if (unformat (input, "source")) {
      if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index)) {
	error = clib_error_return (0, "unknown interface `%U'",
				   format_unformat_error, input);
	goto done;
      }
    } else if (unformat(input, "size")) {
      if (! unformat(input, "%u", &data_len) ) {
	error = clib_error_return (0, "expecting size but got `%U'",
				   format_unformat_error, input);
	goto done;
      }
    } else if (unformat(input, "repeat")) {
      if (! unformat(input, "%u", &ping_repeat) ) {
	error = clib_error_return (0, "expecting repeat count but got `%U'",
				   format_unformat_error, input);
	goto done;
      }
    } else if (unformat(input, "verbose")) {
      verbose = 1;
    }
    else {
      error = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
      goto done;
    }
  }

  if (ping_ip4 || ping_ip6) {
    int i;
    uword curr_proc = vlib_current_process(vm);
    uword event_type, * event_data = 0;
    u32 n_replies = 0;
    u32 n_requests = 0;
    u16 icmp_id = rand();
    while (hash_get(pm->cli_proc_by_icmp_id, icmp_id)) {
      clib_warning("ICMP ID collision at %d, incrementing", icmp_id);
      icmp_id++;
    }
    hash_set(pm->cli_proc_by_icmp_id, icmp_id, curr_proc);
    
    for(i=0; i<ping_repeat; i++) {
      if (ping_ip6) {
         send_ip6_ping(vm, ping_main.ip6_main, &a6, sw_if_index, i, icmp_id,  data_len, verbose);
         n_requests++;
      }
      if (ping_ip4) {
         clib_warning("IPv4 ping TBD.");
      }
      vlib_process_wait_for_event_or_clock(vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) {
      case ~0:                /* no events => timeout */
          os_puts((u8*)".", 1, 0 /* is_error */);
          break;

      case PING_RESPONSE_IP6:
          os_puts((u8*)"!", 1, 0 /* is_error */);
          n_replies++;
          break;

      default:
          /* someone pressed a key, abort */
          clib_warning ("Aborted.");
          i = ping_repeat;
          break;
      }
    }
    os_puts((u8*)"\n", 1, 0);
    { 
      float loss = (0 == n_requests) ? 0 : 100.0 * ((float)n_requests - (float)n_replies)/(float)n_requests;
      clib_warning("Statistics: %u sent, %u received, %f%% packet loss\n", n_requests, n_replies, loss);
      hash_unset(pm->cli_proc_by_icmp_id, icmp_id);
    }
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (ping_command, static) = {
  .path = "ping",
  .function = ping_ip_address,
  .short_help = "Ping IP4/IP6 address from interface",
};

static clib_error_t * ping_cli_init (vlib_main_t * vm)
{ 
  icmp6_echo_request_header_t p;
  ping_main_t *pm = &ping_main;
  u16 i;

  memset (&p, 0, sizeof (p));

  pm->ip6_main = &ip6_main;

  p.ip.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
  p.ip.payload_length = clib_host_to_net_u16 (sizeof (p)
                                      - STRUCT_OFFSET_OF (icmp6_echo_request_header_t, icmp));
  p.ip.protocol = IP_PROTOCOL_ICMP6;
  p.ip.hop_limit = 255;
  p.icmp.type = ICMP6_echo_request;
  for(i=0; i<sizeof(p.icmp_echo.data); i++) {
    p.icmp_echo.data[i] = i % 256;
  }

  vlib_packet_template_init (vm,
			     &pm->icmp6_echo_request_packet_template,
			     &p, sizeof(p),
			     /* alloc chunk size */ 8,
			     "ip6 icmp echo request");


  icmp6_register_type (vm, ICMP6_echo_reply, ip6_icmp_echo_reply_node.index);
  return 0; 
}


VLIB_INIT_FUNCTION (ping_cli_init);
