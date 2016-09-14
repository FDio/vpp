/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

u8 *
format_icmp4_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp4_input_trace_t *t = va_arg (*va, icmp4_input_trace_t *);

  s = format (s, "%U",
              format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

/*
 * If we can find the ping run by an ICMP ID, then we send the signal
 * to the CLI process referenced by that ping run, alongside with
 * a freshly made copy of the packet.
 * I opted for a packet copy to keep the main packet processing path
 * the same as for all the other nodes.
 *
 */

static void
signal_ip46_icmp_reply_event (vlib_main_t * vm,
                              u8 event_type, vlib_buffer_t * b0)
{
  ping_main_t *pm = &ping_main;
  u16 net_icmp_id = 0;
  u32 bi0_copy = 0;

  switch (event_type)
    {
    case PING_RESPONSE_IP4:
      {
        icmp4_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
        net_icmp_id = h0->icmp_echo.id;
      }
      break;
    case PING_RESPONSE_IP6:
      {
        icmp6_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
        net_icmp_id = h0->icmp_echo.id;
      }
      break;
    default:
      return;
    }

  uword *p = hash_get (pm->ping_run_by_icmp_id,
                       clib_net_to_host_u16 (net_icmp_id));
  if (!p)
    return;

  ping_run_t *pr = vec_elt_at_index (pm->ping_runs, p[0]);
  if (vlib_buffer_alloc (vm, &bi0_copy, 1) == 1)
    {
      void *dst = vlib_buffer_get_current (vlib_get_buffer (vm, bi0_copy));
      clib_memcpy (dst, vlib_buffer_get_current (b0), b0->current_length);
    }
  /* If buffer_alloc failed, bi0_copy == 0 - just signaling an event. */

  vlib_process_signal_event (vm, pr->cli_process_id, event_type, bi0_copy);
}

/*
 * Process ICMPv6 echo replies
 */
static uword
ip6_icmp_echo_reply_node_fn (vlib_main_t * vm,
                             vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);        /* array of buffer indices */
  n_left_from = frame->n_vectors;       /* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      signal_ip46_icmp_reply_event (vm, PING_RESPONSE_IP6, b0);

      /* push this pkt to the next graph node, always error-drop */
      next0 = ICMP6_ECHO_REPLY_NEXT_NORMAL;
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_echo_reply_node, static) =
{
  .function = ip6_icmp_echo_reply_node_fn,
  .name = "ip6-icmp-echo-reply",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp6_input_trace,
  .n_next_nodes = ICMP6_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP6_ECHO_REPLY_NEXT_NORMAL] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * Process ICMPv4 echo replies
 */
static uword
ip4_icmp_echo_reply_node_fn (vlib_main_t * vm,
                             vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);        /* array of buffer indices */
  n_left_from = frame->n_vectors;       /* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      /* push this pkt to the next graph node, always error-drop */
      signal_ip46_icmp_reply_event (vm, PING_RESPONSE_IP4, b0);

      next0 = ICMP4_ECHO_REPLY_NEXT_NORMAL;
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_icmp_echo_reply_node, static) =
{
  .function = ip4_icmp_echo_reply_node_fn,
  .name = "ip4-icmp-echo-reply",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp4_input_trace,
  .n_next_nodes = ICMP4_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP4_ECHO_REPLY_NEXT_NORMAL] = "error-drop",
  },
};
/* *INDENT-ON* */

char *ip6_lookup_next_nodes[] = IP6_LOOKUP_NEXT_NODES;
char *ip4_lookup_next_nodes[] = IP4_LOOKUP_NEXT_NODES;

/* get first interface address */
static ip6_address_t *
ip6_interface_first_address (ip6_main_t * im, u32 sw_if_index)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip6_address_t *result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */ ,
                                (
                                  {
                                  ip6_address_t * a =
                                  ip_interface_address_get_address (lm, ia);
                                  result = a;
                                  break;
                                  }
                                ));
  return result;
}

/* Fill in the ICMP ECHO structure, return the safety-checked and possibly shrunk data_len */
static u16
init_icmp46_echo_request (icmp46_echo_request_t * icmp46_echo,
                          u16 seq_host, u16 id_host, u16 data_len)
{
  int i;
  icmp46_echo->seq = clib_host_to_net_u16 (seq_host);
  icmp46_echo->id = clib_host_to_net_u16 (id_host);

  for (i = 0; i < sizeof (icmp46_echo->data); i++)
    {
      icmp46_echo->data[i] = i % 256;
    }

  if (data_len > sizeof (icmp46_echo_request_t))
    {
      data_len = sizeof (icmp46_echo_request_t);
    }
  return data_len;
}

/*
 * Given adj index, return sw_if_index, possibly overwritten
 * by a parameter. There is mostly debug outputs here,
 * but it turned out handy to have these.
 */

static u32
adj_index_to_sw_if_index (vlib_main_t * vm, ip_lookup_main_t * lm,
                          char *lookup_next_nodes[], u32 adj_index0,
                          u32 sw_if_index, u8 verbose)
{
  ip_adjacency_t *adj0 = ip_get_adjacency (lm, adj_index0);
  u32 sw_if_index0 = adj0->rewrite_header.sw_if_index;
  if (verbose)
    {
      vlib_cli_output (vm, "Adjacency index: %u, sw_if_index: %u\n",
                       adj_index0, sw_if_index0);
      vlib_cli_output (vm, "Adj: %s\n",
                       lookup_next_nodes[adj0->lookup_next_index]);
      vlib_cli_output (vm, "Adj Interface: %d\n", adj0->if_address_index);
    }

  if (~0 != sw_if_index)
    {
      sw_if_index0 = sw_if_index;
      if (verbose)
        {
          vlib_cli_output (vm, "Forced set interface: %d\n", sw_if_index0);
        }
    }
  return sw_if_index0;
}

static send_ip46_ping_result_t
send_ip6_ping (vlib_main_t * vm, ip6_main_t * im, ip6_address_t * pa6,
               u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
               u8 verbose)
{
  icmp6_echo_request_header_t *h0;
  u32 bi0 = 0;
  u32 sw_if_index0;
  ip_lookup_main_t *lm = &im->lookup_main;
  int bogus_length = 0;
  u32 adj_index0;
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 fib_index0;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return SEND_PING_ALLOC_FAIL;

  p0 = vlib_get_buffer (vm, bi0);

  /* Determine sw_if_index0 of source intf, may be force-set via sw_if_index. */
  vnet_buffer (p0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = ~0;  /* use interface VRF */
  fib_index0 = 0;
  adj_index0 = ip6_fib_lookup_with_table (im, fib_index0, pa6);
  sw_if_index0 =
    adj_index_to_sw_if_index (vm, lm, ip6_lookup_next_nodes, adj_index0,
                              sw_if_index, verbose);
  if ((~0 == sw_if_index0) && (~0 == sw_if_index))
    {
      vlib_buffer_free (vm, &bi0, 1);
      return SEND_PING_NO_INTERFACE;
    }
  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index0;

  h0 = vlib_buffer_get_current (p0);

  /* Fill in ip6 header fields */
  h0->ip6.ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  h0->ip6.payload_length = 0;   /* Set below */
  h0->ip6.protocol = IP_PROTOCOL_ICMP6;
  h0->ip6.hop_limit = 255;
  h0->ip6.dst_address = *pa6;
  h0->ip6.src_address = *pa6;

  /* Fill in the correct source now */
  ip6_address_t *a = ip6_interface_first_address (im, sw_if_index0);
  h0->ip6.src_address = a[0];

  /* Fill in icmp fields */
  h0->icmp.type = ICMP6_echo_request;
  h0->icmp.code = 0;
  h0->icmp.checksum = 0;

  data_len =
    init_icmp46_echo_request (&h0->icmp_echo, seq_host, id_host, data_len);
  h0->icmp_echo.time_sent = vlib_time_now (vm);

  /* Fix up the lengths */
  h0->ip6.payload_length =
    clib_host_to_net_u16 (data_len + sizeof (icmp46_header_t));

  p0->current_length = clib_net_to_host_u16 (h0->ip6.payload_length) +
    STRUCT_OFFSET_OF (icmp6_echo_request_header_t, icmp);

  /* Calculate the ICMP checksum */
  h0->icmp.checksum = 0;
  h0->icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip6, &bogus_length);

  /* Enqueue the packet right now */
  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);

  return SEND_PING_OK;
}

static send_ip46_ping_result_t
send_ip4_ping (vlib_main_t * vm,
               ip4_main_t * im,
               ip4_address_t * pa4,
               u32 sw_if_index,
               u16 seq_host, u16 id_host, u16 data_len, u8 verbose)
{
  icmp4_echo_request_header_t *h0;
  u32 bi0 = 0;
  u32 sw_if_index0;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 adj_index0;
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 fib_index0;
  u32 if_add_index0;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return SEND_PING_ALLOC_FAIL;

  p0 = vlib_get_buffer (vm, bi0);

  /* Determine sw_if_index0 of the source intf, may be force-set via sw_if_index.  */
  vnet_buffer (p0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = ~0;  /* use interface VRF */
  fib_index0 = 0;
  adj_index0 = ip4_fib_lookup_with_table (im, fib_index0, pa4, 0);
  sw_if_index0 =
    adj_index_to_sw_if_index (vm, lm, ip4_lookup_next_nodes, adj_index0,
                              sw_if_index, verbose);
  if ((~0 == sw_if_index0) && (~0 == sw_if_index))
    {
      vlib_buffer_free (vm, &bi0, 1);
      return SEND_PING_NO_INTERFACE;
    }
  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index0;

  h0 = vlib_buffer_get_current (p0);

  /* Fill in ip4 header fields */
  h0->ip4.checksum = 0;
  h0->ip4.ip_version_and_header_length = 0x45;
  h0->ip4.tos = 0;
  h0->ip4.length = 0;           /* Set below */
  h0->ip4.fragment_id = 0;
  h0->ip4.flags_and_fragment_offset = 0;
  h0->ip4.ttl = 0xff;
  h0->ip4.protocol = IP_PROTOCOL_ICMP;
  h0->ip4.dst_address = *pa4;
  h0->ip4.src_address = *pa4;

  /* Fill in the correct source now */
  if_add_index0 = lm->if_address_pool_index_by_sw_if_index[sw_if_index0];
  if (PREDICT_TRUE (if_add_index0 != ~0))
    {
      ip_interface_address_t *if_add =
        pool_elt_at_index (lm->if_address_pool, if_add_index0);
      ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);
      h0->ip4.src_address = *if_ip;
      if (verbose)
        {
          vlib_cli_output (vm, "Source address: %U",
                           format_ip4_address, &h0->ip4.src_address);
        }
    }

  /* Fill in icmp fields */
  h0->icmp.type = ICMP4_echo_request;
  h0->icmp.code = 0;
  h0->icmp.checksum = 0;

  data_len =
    init_icmp46_echo_request (&h0->icmp_echo, seq_host, id_host, data_len);
  h0->icmp_echo.time_sent = vlib_time_now (vm);

  /* Fix up the lengths */
  h0->ip4.length =
    clib_host_to_net_u16 (data_len + sizeof (icmp46_header_t) +
                          sizeof (ip4_header_t));

  p0->current_length = clib_net_to_host_u16 (h0->ip4.length);

  /* Calculate the IP and ICMP checksums */
  h0->ip4.checksum = ip4_header_checksum (&(h0->ip4));
  h0->icmp.checksum =
    ~ip_csum_fold (ip_incremental_checksum (0, &(h0->icmp),
                    p0->current_length - sizeof (ip4_header_t)));

  /* Enqueue the packet right now */
  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  return SEND_PING_OK;
}


static void
print_ip6_icmp_reply (vlib_main_t * vm, u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm,
                                       bi0);
  icmp6_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
  f64 rtt = vlib_time_now (vm) - h0->icmp_echo.time_sent;

  vlib_cli_output (vm,
                   "%d bytes from %U: icmp_seq=%d ttl=%d time=%.4f ms",
                   clib_host_to_net_u16 (h0->ip6.payload_length),
                   format_ip6_address,
                   &h0->ip6.src_address,
                   clib_host_to_net_u16 (h0->icmp_echo.seq),
                   h0->ip6.hop_limit, rtt * 1000.0);
}

static void
print_ip4_icmp_reply (vlib_main_t * vm, u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm,
                                       bi0);
  icmp4_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
  f64 rtt = vlib_time_now (vm) - h0->icmp_echo.time_sent;
  u32 rcvd_icmp_len =
    clib_host_to_net_u16 (h0->ip4.length) -
    (4 * (0xF & h0->ip4.ip_version_and_header_length));

  vlib_cli_output (vm,
                   "%d bytes from %U: icmp_seq=%d ttl=%d time=%.4f ms",
                   rcvd_icmp_len,
                   format_ip4_address,
                   &h0->ip4.src_address,
                   clib_host_to_net_u16 (h0->icmp_echo.seq),
                   h0->ip4.ttl, rtt * 1000.0);
}


/*
 * Perform the ping run with the given parameters in the current CLI process.
 * Depending on whether pa4 or pa6 is set, runs IPv4 or IPv6 ping.
 * The amusing side effect is of course if both are set, then both pings are sent.
 * This behavior can be used to ping a dualstack host over IPv4 and IPv6 at once.
 */

static void
run_ping_ip46_address (vlib_main_t * vm, ip4_address_t * pa4,
                       ip6_address_t * pa6, u32 sw_if_index,
                       f64 ping_interval, u32 ping_repeat, u32 data_len,
                       u32 verbose)
{
  int i;
  ping_main_t *pm = &ping_main;
  uword curr_proc = vlib_current_process (vm);
  u32 n_replies = 0;
  u32 n_requests = 0;
  ping_run_t *pr = 0;
  u32 ping_run_index = 0;
  u16 icmp_id;

  static u32 rand_seed = 0;

  if (PREDICT_FALSE(!rand_seed))
      rand_seed = random_default_seed();

  icmp_id = random_u32(&rand_seed) & 0xffff;

  while (hash_get (pm->ping_run_by_icmp_id, icmp_id))
    {
      vlib_cli_output (vm, "ICMP ID collision at %d, incrementing", icmp_id);
      icmp_id++;
    }
  pool_get (pm->ping_runs, pr);
  ping_run_index = pr - pm->ping_runs;
  pr->cli_process_id = curr_proc;
  pr->icmp_id = icmp_id;
  hash_set (pm->ping_run_by_icmp_id, icmp_id, ping_run_index);
  for (i = 1; i <= ping_repeat; i++)
    {
      f64 sleep_interval;
      f64 time_ping_sent = vlib_time_now (vm);
      /* Reset pr: running ping in other process could have changed pm->ping_runs */
      pr = vec_elt_at_index (pm->ping_runs, ping_run_index);
      pr->curr_seq = i;
      if (pa6 &&
          (SEND_PING_OK == send_ip6_ping (vm, ping_main.ip6_main, pa6,
                                          sw_if_index, i, icmp_id, data_len,
                                          verbose)))
        {
          n_requests++;
        }
      if (pa4 &&
          (SEND_PING_OK == send_ip4_ping (vm, ping_main.ip4_main, pa4,
                                          sw_if_index, i, icmp_id, data_len,
                                          verbose)))
        {
          n_requests++;
        }
      while ((i <= ping_repeat)
             &&
             ((sleep_interval =
               time_ping_sent + ping_interval - vlib_time_now (vm)) > 0.0))
        {
          uword event_type, *event_data = 0;
          vlib_process_wait_for_event_or_clock (vm, sleep_interval);
          event_type = vlib_process_get_events (vm, &event_data);
          switch (event_type)
            {
            case ~0:           /* no events => timeout */
              break;
            case PING_RESPONSE_IP6:
              {
                int i;
                for (i = 0; i < vec_len (event_data); i++)
                  {
                    u32 bi0 = event_data[0];
                    print_ip6_icmp_reply (vm, bi0);
                    n_replies++;
                    if (0 != bi0)
                      {
                        vlib_buffer_free (vm, &bi0, 1);
                      }
                  }
              }
              break;
            case PING_RESPONSE_IP4:
              {
                int i;
                for (i = 0; i < vec_len (event_data); i++)
                  {
                    u32 bi0 = event_data[0];
                    print_ip4_icmp_reply (vm, bi0);
                    n_replies++;
                    if (0 != bi0)
                      {
                        vlib_buffer_free (vm, &bi0, 1);
                      }
                  }
              }
              break;
            default:
              /* someone pressed a key, abort */
              vlib_cli_output (vm, "Aborted due to a keypress.");
              i = 1 + ping_repeat;
              break;
            }
        }
    }
  vlib_cli_output (vm, "\n");
  {
    float loss =
      (0 ==
       n_requests) ? 0 : 100.0 * ((float) n_requests -
                                  (float) n_replies) / (float) n_requests;
    vlib_cli_output (vm,
                     "Statistics: %u sent, %u received, %f%% packet loss\n",
                     n_requests, n_replies, loss);
    /* Reset pr: running ping in other process could have changed pm->ping_runs */
    pr = vec_elt_at_index (pm->ping_runs, ping_run_index);
    hash_unset (pm->ping_run_by_icmp_id, icmp_id);
    pool_put (pm->ping_runs, pr);
  }
}





static clib_error_t *
ping_ip_address (vlib_main_t * vm,
                 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t *error = 0;
  u32 ping_repeat = 5;
  u8 ping_ip4, ping_ip6;
  vnet_main_t *vnm = vnet_get_main ();
  u32 data_len = PING_DEFAULT_DATA_LEN;
  u32 verbose = 0;
  f64 ping_interval = PING_DEFAULT_INTERVAL;
  ping_ip4 = ping_ip6 = 0;
  u32 sw_if_index;
  sw_if_index = ~0;
  if (unformat (input, "%U", unformat_ip4_address, &a4))
    {
      ping_ip4 = 1;
    }
  else if (unformat (input, "%U", unformat_ip6_address, &a6))
    {
      ping_ip6 = 1;
    }
  else if (unformat (input, "ipv4"))
    {
      if (unformat (input, "%U", unformat_ip4_address, &a4))
        {
          ping_ip4 = 1;
        }
      else
        {
          error =
            clib_error_return (0,
                               "expecting IPv4 address but got `%U'",
                               format_unformat_error, input);
        }
    }
  else if (unformat (input, "ipv6"))
    {
      if (unformat (input, "%U", unformat_ip6_address, &a6))
        {
          ping_ip6 = 1;
        }
      else
        {
          error =
            clib_error_return (0,
                               "expecting IPv6 address but got `%U'",
                               format_unformat_error, input);
        }
    }
  else
    {
      error =
        clib_error_return (0,
                           "expecting IP4/IP6 address `%U'. Usage: ping <addr> [source <intf>] [size <datasz>] [repeat <count>] [verbose]",
                           format_unformat_error, input);
      goto done;
    }

  /* allow for the second AF in the same ping */
  if (!ping_ip4 && (unformat (input, "ipv4")))
    {
      if (unformat (input, "%U", unformat_ip4_address, &a4))
        {
          ping_ip4 = 1;
        }
    }
  else if (!ping_ip6 && (unformat (input, "ipv6")))
    {
      if (unformat (input, "%U", unformat_ip6_address, &a6))
        {
          ping_ip6 = 1;
        }
    }

  /* parse the rest of the parameters  in a cycle */
  while (!unformat_eof (input, NULL))
    {
      if (unformat (input, "source"))
        {
          if (!unformat_user
              (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
            {
              error =
                clib_error_return (0,
                                   "unknown interface `%U'",
                                   format_unformat_error, input);
              goto done;
            }
        }
      else if (unformat (input, "size"))
        {
          if (!unformat (input, "%u", &data_len))
            {
              error =
                clib_error_return (0,
                                   "expecting size but got `%U'",
                                   format_unformat_error, input);
              goto done;
            }
        }
      else if (unformat (input, "interval"))
        {
          if (!unformat (input, "%f", &ping_interval))
            {
              error =
                clib_error_return (0,
                                   "expecting interval (floating point number) got `%U'",
                                   format_unformat_error, input);
              goto done;
            }
        }
      else if (unformat (input, "repeat"))
        {
          if (!unformat (input, "%u", &ping_repeat))
            {
              error =
                clib_error_return (0,
                                   "expecting repeat count but got `%U'",
                                   format_unformat_error, input);
              goto done;
            }
        }
      else if (unformat (input, "verbose"))
        {
          verbose = 1;
        }
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
          goto done;
        }
    }

  run_ping_ip46_address (vm, ping_ip4 ? &a4 : NULL, ping_ip6 ? &a6 : NULL,
                         sw_if_index, ping_interval, ping_repeat, data_len,
                         verbose);
done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ping_command, static) =
{
  .path = "ping",
  .function = ping_ip_address,
  .short_help = "Ping IP4/IP6 address from interface",
  .long_help =
  "Ping IPv4/IPv6 address (or both at the same time)\n"
  "\n"
  "Arguments:\n"
  "\n"
  "ADDRESS              target (IPv4/IPv6)\n"
  "ipv4 ADDRESS         target IPv4 address\n"
  "ipv6 ADDRESS         target IPv6 address\n"
  "interface STRING     interface for the source address\n"
  "size NUMBER          size to send\n"
  "repeat NUMBER        how many echo requests to send\n"
  "interval NUMBER      interval between echo requests, in seconds (integer or fractional)\n"
  "verbose              print various low-level information\n"
};
/* *INDENT-ON* */

static clib_error_t *
ping_cli_init (vlib_main_t * vm)
{
  ping_main_t *pm = &ping_main;
  pm->ip6_main = &ip6_main;
  pm->ip4_main = &ip4_main;
  icmp6_register_type (vm, ICMP6_echo_reply, ip6_icmp_echo_reply_node.index);
  ip4_icmp_register_type (vm, ICMP4_echo_reply,
                          ip4_icmp_echo_reply_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (ping_cli_init);
