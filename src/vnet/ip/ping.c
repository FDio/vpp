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

#include <stddef.h>
#include <vnet/ip/ping.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vlib/vlib.h>

ping_main_t ping_main;

/**
 * @file
 * @brief IPv4 and IPv6 ICMP Ping.
 *
 * This file contains code to suppport IPv4 or IPv6 ICMP ECHO_REQUEST to
 * network hosts.
 *
 */


u8 *
format_icmp_echo_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_echo_trace_t *t = va_arg (*va, icmp_echo_trace_t *);

  s = format (s, "ICMP echo id %d seq %d%s",
	      clib_net_to_host_u16 (t->id),
	      clib_net_to_host_u16 (t->seq), t->bound ? "" : " (unknown)");

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

static int
signal_ip46_icmp_reply_event (u8 event_type, vlib_buffer_t * b0)
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
      return 0;
    }

  uword *p = hash_get (pm->ping_run_by_icmp_id,
		       clib_net_to_host_u16 (net_icmp_id));
  if (!p)
    return 0;

  ping_run_t *pr = vec_elt_at_index (pm->ping_runs, p[0]);
  vlib_main_t *vm = vlib_mains[pr->cli_thread_index];
  if (vlib_buffer_alloc (vm, &bi0_copy, 1) == 1)
    {
      void *dst = vlib_buffer_get_current (vlib_get_buffer (vm,
							    bi0_copy));
      clib_memcpy (dst, vlib_buffer_get_current (b0), b0->current_length);
    }
  /* If buffer_alloc failed, bi0_copy == 0 - just signaling an event. */
  f64 nowts = vlib_time_now (vm);
  /* Pass the timestamp to the cli_process thanks to the vnet_buffer unused metadata field */
  clib_memcpy (vnet_buffer
	       (vlib_get_buffer
		(vm, bi0_copy))->unused, &nowts, sizeof (nowts));
  vlib_process_signal_event_mt (vm, pr->cli_process_id, event_type, bi0_copy);
  return 1;
}

/*
 * Process ICMPv6 echo replies
 */
static uword
ip6_icmp_echo_reply_node_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);	/* array of buffer indices */
  n_left_from = frame->n_vectors;	/* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      next0 = signal_ip46_icmp_reply_event (PING_RESPONSE_IP6, b0) ?
	ICMP6_ECHO_REPLY_NEXT_DROP : ICMP6_ECHO_REPLY_NEXT_PUNT;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  icmp6_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
	  icmp_echo_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->id = h0->icmp_echo.id;
	  tr->seq = h0->icmp_echo.seq;
	  tr->bound = (next0 == ICMP6_ECHO_REPLY_NEXT_DROP);
	}

      /* push this pkt to the next graph node */
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
  .format_trace = format_icmp_echo_trace,
  .n_next_nodes = ICMP6_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP6_ECHO_REPLY_NEXT_DROP] = "error-drop",
    [ICMP6_ECHO_REPLY_NEXT_PUNT] = "error-punt",
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

  from = vlib_frame_vector_args (frame);	/* array of buffer indices */
  n_left_from = frame->n_vectors;	/* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      next0 = signal_ip46_icmp_reply_event (PING_RESPONSE_IP4, b0) ?
	ICMP4_ECHO_REPLY_NEXT_DROP : ICMP4_ECHO_REPLY_NEXT_PUNT;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  icmp4_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
	  icmp_echo_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->id = h0->icmp_echo.id;
	  tr->seq = h0->icmp_echo.seq;
	  tr->bound = (next0 == ICMP4_ECHO_REPLY_NEXT_DROP);
	}

      /* push this pkt to the next graph node */
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
  .format_trace = format_icmp_echo_trace,
  .n_next_nodes = ICMP4_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP4_ECHO_REPLY_NEXT_DROP] = "error-drop",
    [ICMP4_ECHO_REPLY_NEXT_PUNT] = "error-punt",
  },
};
/* *INDENT-ON* */

char *ip6_lookup_next_nodes[] = IP6_LOOKUP_NEXT_NODES;
char *ip4_lookup_next_nodes[] = IP4_LOOKUP_NEXT_NODES;

/* Fill in the ICMP ECHO structure, return the safety-checked and possibly shrunk data_len */
static u16
init_icmp46_echo_request (icmp46_echo_request_t * icmp46_echo,
			  u16 seq_host, u16 id_host, u16 data_len)
{
  int i;
  icmp46_echo->seq = clib_host_to_net_u16 (seq_host);
  icmp46_echo->id = clib_host_to_net_u16 (id_host);

  if (data_len > PING_MAXIMUM_DATA_SIZE)
    data_len = PING_MAXIMUM_DATA_SIZE;
  for (i = 0; i < data_len; i++)
    icmp46_echo->data[i] = i % 256;
  return data_len;
}

static send_ip46_ping_result_t
send_ip6_ping (vlib_main_t * vm, ip6_main_t * im,
	       u32 table_id, ip6_address_t * pa6,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose)
{
  icmp6_echo_request_header_t *h0;
  u32 bi0 = 0;
  int bogus_length = 0;
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  vlib_buffer_free_list_t *fl;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return SEND_PING_ALLOC_FAIL;

  p0 = vlib_get_buffer (vm, bi0);
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (p0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (p0);

  /*
   * if the user did not provide a source interface, use the any interface
   * that the destination resolves via.
   */
  if (~0 == sw_if_index)
    {
      fib_node_index_t fib_entry_index;
      u32 fib_index;

      fib_index = ip6_fib_index_from_table_id (table_id);

      if (~0 == fib_index)
	{
	  vlib_buffer_free (vm, &bi0, 1);
	  return SEND_PING_NO_TABLE;
	}

      fib_entry_index = ip6_fib_table_lookup (fib_index, pa6, 128);
      sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
      /*
       * Set the TX interface to force ip-lookup to use its table ID
       */
      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index;
    }
  else
    {
      /*
       * force an IP lookup in the table bound to the user's chosen
       * source interface.
       */
      vnet_buffer (p0)->sw_if_index[VLIB_TX] =
	ip6_fib_table_get_index_for_sw_if_index (sw_if_index);
    }

  if (~0 == sw_if_index)
    {
      vlib_buffer_free (vm, &bi0, 1);
      return SEND_PING_NO_INTERFACE;
    }

  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index;

  h0 = vlib_buffer_get_current (p0);

  /* Fill in ip6 header fields */
  h0->ip6.ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  h0->ip6.payload_length = 0;	/* Set below */
  h0->ip6.protocol = IP_PROTOCOL_ICMP6;
  h0->ip6.hop_limit = 255;
  h0->ip6.dst_address = *pa6;
  h0->ip6.src_address = *pa6;

  /* Fill in the correct source now */
  ip6_address_t *a = ip6_interface_first_address (im, sw_if_index);
  if (!a)
    {
      vlib_buffer_free (vm, &bi0, 1);
      return SEND_PING_NO_SRC_ADDRESS;
    }
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

  ASSERT (burst <= VLIB_FRAME_SIZE);
  f->n_vectors = burst;
  while (--burst)
    {
      vlib_buffer_t *c0 = vlib_buffer_copy (vm, p0);
      to_next++;
      to_next[0] = vlib_get_buffer_index (vm, c0);
    }
  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);

  return SEND_PING_OK;
}

static send_ip46_ping_result_t
send_ip4_ping (vlib_main_t * vm,
	       ip4_main_t * im,
	       u32 table_id,
	       ip4_address_t * pa4,
	       u32 sw_if_index,
	       u16 seq_host, u16 id_host, u16 data_len, u32 burst, u8 verbose)
{
  icmp4_echo_request_header_t *h0;
  u32 bi0 = 0;
  ip_lookup_main_t *lm = &im->lookup_main;
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 if_add_index0;
  vlib_buffer_free_list_t *fl;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return SEND_PING_ALLOC_FAIL;

  p0 = vlib_get_buffer (vm, bi0);
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (p0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (p0);

  /*
   * if the user did not provide a source interface, use the any interface
   * that the destination resolves via.
   */
  if (~0 == sw_if_index)
    {
      fib_node_index_t fib_entry_index;
      u32 fib_index;

      fib_index = ip4_fib_index_from_table_id (table_id);

      if (~0 == fib_index)
	{
	  vlib_buffer_free (vm, &bi0, 1);
	  return SEND_PING_NO_TABLE;
	}

      fib_entry_index =
	ip4_fib_table_lookup (ip4_fib_get (fib_index), pa4, 32);
      sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
      /*
       * Set the TX interface to force ip-lookup to use the user's table ID
       */
      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index;
    }
  else
    {
      /*
       * force an IP lookup in the table bound to the user's chosen
       * source interface.
       */
      vnet_buffer (p0)->sw_if_index[VLIB_TX] =
	ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
    }

  if (~0 == sw_if_index)
    {
      vlib_buffer_free (vm, &bi0, 1);
      return SEND_PING_NO_INTERFACE;
    }

  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index;

  h0 = vlib_buffer_get_current (p0);

  /* Fill in ip4 header fields */
  h0->ip4.checksum = 0;
  h0->ip4.ip_version_and_header_length = 0x45;
  h0->ip4.tos = 0;
  h0->ip4.length = 0;		/* Set below */
  h0->ip4.fragment_id = 0;
  h0->ip4.flags_and_fragment_offset = 0;
  h0->ip4.ttl = 0xff;
  h0->ip4.protocol = IP_PROTOCOL_ICMP;
  h0->ip4.dst_address = *pa4;
  h0->ip4.src_address = *pa4;

  /* Fill in the correct source now */
  if_add_index0 = lm->if_address_pool_index_by_sw_if_index[sw_if_index];
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
					    p0->current_length -
					    sizeof (ip4_header_t)));

  /* Enqueue the packet right now */
  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;

  ASSERT (burst <= VLIB_FRAME_SIZE);
  f->n_vectors = burst;
  while (--burst)
    {
      vlib_buffer_t *c0 = vlib_buffer_copy (vm, p0);
      to_next++;
      to_next[0] = vlib_get_buffer_index (vm, c0);
    }
  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  return SEND_PING_OK;
}


static void
print_ip6_icmp_reply (vlib_main_t * vm, u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  icmp6_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
  f64 rtt = 0;
  clib_memcpy (&rtt, vnet_buffer (b0)->unused, sizeof (rtt));
  rtt -= h0->icmp_echo.time_sent;
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
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  icmp4_echo_request_header_t *h0 = vlib_buffer_get_current (b0);
  f64 rtt = 0;
  clib_memcpy (&rtt, vnet_buffer (b0)->unused, sizeof (rtt));
  rtt -= h0->icmp_echo.time_sent;
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
run_ping_ip46_address (vlib_main_t * vm, u32 table_id, ip4_address_t * pa4,
		       ip6_address_t * pa6, u32 sw_if_index,
		       f64 ping_interval, u32 ping_repeat, u32 data_len,
		       u32 ping_burst, u32 verbose)
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

  if (PREDICT_FALSE (!rand_seed))
    rand_seed = random_default_seed ();

  icmp_id = random_u32 (&rand_seed) & 0xffff;

  while (hash_get (pm->ping_run_by_icmp_id, icmp_id))
    {
      vlib_cli_output (vm, "ICMP ID collision at %d, incrementing", icmp_id);
      icmp_id++;
    }
  pool_get (pm->ping_runs, pr);
  ping_run_index = pr - pm->ping_runs;
  pr->cli_process_id = curr_proc;
  pr->cli_thread_index = vlib_get_thread_index ();
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
	  (SEND_PING_OK ==
	   send_ip6_ping (vm, ping_main.ip6_main, table_id, pa6, sw_if_index,
			  i, icmp_id, data_len, ping_burst, verbose)))
	{
	  n_requests += ping_burst;
	}
      if (pa4 &&
	  (SEND_PING_OK ==
	   send_ip4_ping (vm, ping_main.ip4_main, table_id, pa4, sw_if_index,
			  i, icmp_id, data_len, ping_burst, verbose)))
	{
	  n_requests += ping_burst;
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
	    case ~0:		/* no events => timeout */
	      break;
	    case PING_RESPONSE_IP6:
	      {
		int i;
		for (i = 0; i < vec_len (event_data); i++)
		  {
		    u32 bi0 = event_data[i];
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
		    u32 bi0 = event_data[i];
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
	  vec_free (event_data);
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
  u32 ping_burst = 1;
  u8 ping_ip4, ping_ip6;
  vnet_main_t *vnm = vnet_get_main ();
  u32 data_len = PING_DEFAULT_DATA_LEN;
  u32 verbose = 0;
  f64 ping_interval = PING_DEFAULT_INTERVAL;
  u32 sw_if_index, table_id;

  table_id = 0;
  ping_ip4 = ping_ip6 = 0;
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
	  if (data_len > PING_MAXIMUM_DATA_SIZE)
	    {
	      error =
		clib_error_return (0,
				   "%d is bigger than maximum allowed payload size %d",
				   data_len, PING_MAXIMUM_DATA_SIZE);
	      goto done;
	    }
	}
      else if (unformat (input, "table-id"))
	{
	  if (!unformat (input, "%u", &table_id))
	    {
	      error =
		clib_error_return (0,
				   "expecting table-id but got `%U'",
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
      else if (unformat (input, "burst"))
	{
	  if (!unformat (input, "%u", &ping_burst))
	    {
	      error =
		clib_error_return (0,
				   "expecting burst count but got `%U'",
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

  if (ping_burst < 1 || ping_burst > VLIB_FRAME_SIZE)
    return clib_error_return (0, "burst size must be between 1 and %u",
			      VLIB_FRAME_SIZE);

  run_ping_ip46_address (vm, table_id, ping_ip4 ? &a4 : NULL,
			 ping_ip6 ? &a6 : NULL, sw_if_index, ping_interval,
			 ping_repeat, data_len, ping_burst, verbose);
done:
  return error;
}

/*?
 * This command sends an ICMP ECHO_REQUEST to network hosts. The address
 * can be an IPv4 or IPv6 address (or both at the same time).
 *
 * @cliexpar
 * @parblock
 * Example of how ping an IPv4 address:
 * @cliexstart{ping 172.16.1.2 source GigabitEthernet2/0/0 repeat 2}
 * 64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1090 ms
 * 64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0914 ms
 *
 * Statistics: 2 sent, 2 received, 0% packet loss
 * @cliexend
 *
 * Example of how ping both an IPv4 address and IPv6 address at the same time:
 * @cliexstart{ping 172.16.1.2 ipv6 fe80::24a5:f6ff:fe9c:3a36 source GigabitEthernet2/0/0 repeat 2 verbose}
 * Adjacency index: 10, sw_if_index: 1
 * Adj: ip6-discover-neighbor
 * Adj Interface: 0
 * Forced set interface: 1
 * Adjacency index: 0, sw_if_index: 4294967295
 * Adj: ip4-miss
 * Adj Interface: 0
 * Forced set interface: 1
 * Source address: 172.16.1.1
 * 64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1899 ms
 * Adjacency index: 10, sw_if_index: 1
 * Adj: ip6-discover-neighbor
 * Adj Interface: 0
 * Forced set interface: 1
 * Adjacency index: 0, sw_if_index: 4294967295
 * Adj: ip4-miss
 * Adj Interface: 0
 * Forced set interface: 1
 * Source address: 172.16.1.1
 * 64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0910 ms
 *
 * Statistics: 4 sent, 2 received, 50% packet loss
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ping_command, static) =
{
  .path = "ping",
  .function = ping_ip_address,
  .short_help = "ping {<ip-addr> | ipv4 <ip4-addr> | ipv6 <ip6-addr>}"
  " [ipv4 <ip4-addr> | ipv6 <ip6-addr>] [source <interface>]"
  " [size <pktsize>] [interval <sec>] [repeat <cnt>] [table-id <id>]"
  " [verbose]",
  .is_mp_safe = 1,
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
