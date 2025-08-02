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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <ping/ping.h>

/**
 * @file
 * @brief IPv4 and IPv6 ICMP Ping.
 *
 * This file contains code to support IPv4 or IPv6 ICMP ECHO_REQUEST to
 * network hosts.
 *
 */

static u8 *
format_ip46_ping_result (u8 *s, va_list *args)
{
  send_ip46_ping_result_t res = va_arg (*args, send_ip46_ping_result_t);

  switch (res)
    {
#define _(v, n)                                                               \
  case SEND_PING_##v:                                                         \
    s = format (s, "%s", n);                                                  \
    break;
      foreach_ip46_ping_result
#undef _
    }

  return (s);
}

static uword
ip4_icmp_echo_request (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next;
  ip4_main_t *i4m = &ip4_main;
  u16 *fragment_ids, *fid;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp_input_trace_t));

  /* Get random fragment IDs for replies. */
  fid = fragment_ids = clib_random_buffer_get_data (
    &vm->random_buffer, n_packets * sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 2 && n_left_to_next > 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  icmp46_header_t *icmp0, *icmp1;
	  u32 bi0, src0, dst0;
	  u32 bi1, src1, dst1;
	  ip_csum_t sum0, sum1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, bi0);
	  p1 = vlib_get_buffer (vm, bi1);
	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  icmp0 = ip4_next_header (ip0);
	  icmp1 = ip4_next_header (ip1);

	  vnet_buffer (p0)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;
	  vnet_buffer (p1)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;

	  /* Update ICMP checksum. */
	  sum0 = icmp0->checksum;
	  sum1 = icmp1->checksum;

	  ASSERT (icmp0->type == ICMP4_echo_request);
	  ASSERT (icmp1->type == ICMP4_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  sum1 = ip_csum_update (sum1, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  icmp0->type = ICMP4_echo_reply;
	  icmp1->type = ICMP4_echo_reply;

	  icmp0->checksum = ip_csum_fold (sum0);
	  icmp1->checksum = ip_csum_fold (sum1);

	  src0 = ip0->src_address.data_u32;
	  src1 = ip1->src_address.data_u32;
	  dst0 = ip0->dst_address.data_u32;
	  dst1 = ip1->dst_address.data_u32;

	  /* Swap source and destination address.
	     Does not change checksum. */
	  ip0->src_address.data_u32 = dst0;
	  ip1->src_address.data_u32 = dst1;
	  ip0->dst_address.data_u32 = src0;
	  ip1->dst_address.data_u32 = src1;

	  /* Update IP checksum. */
	  sum0 = ip0->checksum;
	  sum1 = ip1->checksum;

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  sum1 = ip_csum_update (sum1, ip1->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  ip0->ttl = host_config_ttl;
	  ip1->ttl = host_config_ttl;

	  /* New fragment id. */
	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0], ip4_header_t,
				 fragment_id);
	  sum1 = ip_csum_update (sum1, ip1->fragment_id, fid[1], ip4_header_t,
				 fragment_id);
	  ip0->fragment_id = fid[0];
	  ip1->fragment_id = fid[1];
	  fid += 2;

	  ip0->checksum = ip_csum_fold (sum0);
	  ip1->checksum = ip_csum_fold (sum1);

	  ASSERT (ip4_header_checksum_is_valid (ip0));
	  ASSERT (ip4_header_checksum_is_valid (ip1));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  p1->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  icmp46_header_t *icmp0;
	  u32 bi0, src0, dst0;
	  ip_csum_t sum0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  icmp0 = ip4_next_header (ip0);

	  vnet_buffer (p0)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;

	  /* Update ICMP checksum. */
	  sum0 = icmp0->checksum;

	  ASSERT (icmp0->type == ICMP4_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  icmp0->type = ICMP4_echo_reply;
	  icmp0->checksum = ip_csum_fold (sum0);

	  src0 = ip0->src_address.data_u32;
	  dst0 = ip0->dst_address.data_u32;
	  ip0->src_address.data_u32 = dst0;
	  ip0->dst_address.data_u32 = src0;

	  /* Update IP checksum. */
	  sum0 = ip0->checksum;

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  ip0->ttl = host_config_ttl;

	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0], ip4_header_t,
				 fragment_id);
	  ip0->fragment_id = fid[0];
	  fid += 1;

	  ip0->checksum = ip_csum_fold (sum0);

	  ASSERT (ip4_header_checksum_is_valid (ip0));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  vlib_error_count (vm, ip4_icmp_input_node.index,
		    ICMP4_ERROR_ECHO_REPLIES_SENT, frame->n_vectors);

  return frame->n_vectors;
}

static u8 *
format_icmp_input_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_input_trace_t *t = va_arg (*va, icmp_input_trace_t *);

  s = format (s, "%U", format_ip4_header, t->packet_data,
	      sizeof (t->packet_data));

  return s;
}

VLIB_REGISTER_NODE (ip4_icmp_echo_request_node,static) = {
  .function = ip4_icmp_echo_request,
  .name = "ip4-icmp-echo-request",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-load-balance",
  },
};

typedef enum
{
  ICMP6_ECHO_REQUEST_NEXT_LOOKUP,
  ICMP6_ECHO_REQUEST_NEXT_OUTPUT,
  ICMP6_ECHO_REQUEST_N_NEXT,
} icmp6_echo_request_next_t;

static uword
ip6_icmp_echo_request (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  ip6_main_t *im = &ip6_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 2 && n_left_to_next > 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  icmp46_header_t *icmp0, *icmp1;
	  ip6_address_t tmp0, tmp1;
	  ip_csum_t sum0, sum1;
	  u32 bi0, bi1;
	  u32 fib_index0, fib_index1;
	  u32 next0 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;
	  u32 next1 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, bi0);
	  p1 = vlib_get_buffer (vm, bi1);
	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  icmp0 = ip6_next_header (ip0);
	  icmp1 = ip6_next_header (ip1);

	  /* Check icmp type to echo reply and update icmp checksum. */
	  sum0 = icmp0->checksum;
	  sum1 = icmp1->checksum;

	  ASSERT (icmp0->type == ICMP6_echo_request);
	  ASSERT (icmp1->type == ICMP6_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);
	  sum1 = ip_csum_update (sum1, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);

	  icmp0->checksum = ip_csum_fold (sum0);
	  icmp1->checksum = ip_csum_fold (sum1);

	  icmp0->type = ICMP6_echo_reply;
	  icmp1->type = ICMP6_echo_reply;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  tmp1 = ip1->src_address;

	  ip0->src_address = ip0->dst_address;
	  ip1->src_address = ip1->dst_address;

	  ip0->dst_address = tmp0;
	  ip1->dst_address = tmp1;

	  /* New hop count. */
	  ip0->hop_limit = im->host_config.ttl;
	  ip1->hop_limit = im->host_config.ttl;

	  if (ip6_address_is_link_local_unicast (&ip0->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip0->dst_address))
	    {
	      fib_index0 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;
	    }
	  if (ip6_address_is_link_local_unicast (&ip1->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip1->dst_address))
	    {
	      fib_index1 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p1)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p1)->sw_if_index[VLIB_TX] = fib_index1;
	    }
	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  p1->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done
	   */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  icmp46_header_t *icmp0;
	  u32 bi0;
	  ip6_address_t tmp0;
	  ip_csum_t sum0;
	  u32 fib_index0;
	  u32 next0 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  icmp0 = ip6_next_header (ip0);

	  /* Check icmp type to echo reply and update icmp checksum. */
	  sum0 = icmp0->checksum;

	  ASSERT (icmp0->type == ICMP6_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);

	  icmp0->checksum = ip_csum_fold (sum0);

	  icmp0->type = ICMP6_echo_reply;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  ip0->src_address = ip0->dst_address;
	  ip0->dst_address = tmp0;

	  ip0->hop_limit = im->host_config.ttl;

	  if (ip6_address_is_link_local_unicast (&ip0->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip0->dst_address))
	    {
	      /* if original packet was to the link local, then the
	       * fib index is that of the LL table, we can't use that
	       * to foward the response if the new destination
	       * is global, so reset to the fib index of the link.
	       * In other case, the fib index we need has been written
	       * to the buffer already. */
	      fib_index0 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;
	    }
	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, ip6_icmp_input_node.index,
		    ICMP6_ERROR_ECHO_REPLIES_SENT, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_icmp_echo_request_node,static) = {
  .function = ip6_icmp_echo_request,
  .name = "ip6-icmp-echo-request",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_ECHO_REQUEST_N_NEXT,
  .next_nodes = {
    [ICMP6_ECHO_REQUEST_NEXT_LOOKUP] = "ip6-lookup",
    [ICMP6_ECHO_REQUEST_NEXT_OUTPUT] = "interface-output",
  },
};

/*
 * An address-family agnostic ping send function.
 */

static send_ip46_ping_result_t
send_ip46_ping (vlib_main_t *vm, u32 table_id, ip46_address_t *pa46,
		u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
		u32 burst, u8 verbose, int is_ip6)
{
  int err = SEND_PING_OK;
  u32 bi0 = 0;
  int n_buf0 = 0;
  vlib_buffer_t *b0;
  u8 l4_proto = is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP;

  n_buf0 = vlib_buffer_alloc (vm, &bi0, 1);
  if (n_buf0 < 1)
    ERROR_OUT (SEND_PING_ALLOC_FAIL);

  b0 = vlib_get_buffer (vm, bi0);

  /*
   * if the user did not provide a source interface,
   * perform a resolution and use an interface
   * via which it succeeds.
   */
  u32 fib_index;
  if (~0 == sw_if_index)
    {
      fib_index = ip46_fib_index_from_table_id (table_id, is_ip6);
      sw_if_index = ip46_get_resolving_interface (fib_index, pa46, is_ip6);
    }
  else
    fib_index =
      ip46_fib_table_get_index_for_sw_if_index (sw_if_index, is_ip6, pa46);

  if (~0 == fib_index)
    ERROR_OUT (SEND_PING_NO_TABLE);
  if (~0 == sw_if_index)
    ERROR_OUT (SEND_PING_NO_INTERFACE);

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;

  int l4_header_offset = ip46_fill_l3_header (pa46, b0, l4_proto, 255, is_ip6);

  /* set the src address in the buffer */
  if (!ip46_set_src_address (sw_if_index, b0, is_ip6))
    ERROR_OUT (SEND_PING_NO_SRC_ADDRESS);
  if (verbose)
    ip46_print_buffer_src_address (vm, b0, is_ip6);

  u16 payload_len = ip46_fill_icmp_request_at (
    vm, b0, l4_header_offset, seq_host, id_host, data_len, is_ip6);

  ip46_fix_len_and_csum (vm, b0, l4_header_offset, l4_proto, payload_len,
			 is_ip6);

  u32 node_index = ip6_lookup_node.index;
  if (is_ip6)
    {
      if (pa46->ip6.as_u32[0] == clib_host_to_net_u32 (0xff020000))
	{
	  node_index = ip6_rewrite_mcast_node.index;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	    ip6_link_get_mcast_adj (sw_if_index);
	}
    }
  else
    {
      node_index = ip4_lookup_node.index;
    }
  int n_sent = ip46_enqueue_packet (vm, b0, burst, node_index);
  if (n_sent < burst)
    err = SEND_PING_NO_BUFFERS;

done:
  if (err != SEND_PING_OK)
    {
      if (n_buf0 > 0)
	vlib_buffer_free (vm, &bi0, 1);
    }
  return err;
}

send_ip46_ping_result_t
send_ip6_ping (vlib_main_t *vm, u32 table_id, ip6_address_t *pa6,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose)
{
  ip46_address_t target;
  target.ip6 = *pa6;
  return send_ip46_ping (vm, table_id, &target, sw_if_index, seq_host, id_host,
			 data_len, burst, verbose, 1 /* is_ip6 */);
}

send_ip46_ping_result_t
send_ip4_ping (vlib_main_t *vm, u32 table_id, ip4_address_t *pa4,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose)
{
  ip46_address_t target;
  ip46_address_set_ip4 (&target, pa4);
  return send_ip46_ping (vm, table_id, &target, sw_if_index, seq_host, id_host,
			 data_len, burst, verbose, 0 /* is_ip6 */);
}

static void
print_ip46_icmp_reply (vlib_main_t *vm, u32 bi0, int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  int l4_offset;
  void *paddr;
  void *format_addr_func;
  u16 payload_length;
  u8 ttl;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      paddr = (void *) &ip6->src_address;
      format_addr_func = (void *) format_ip6_address;
      ttl = ip6->hop_limit;
      l4_offset = sizeof (ip6_header_t); // FIXME - EH processing ?
      payload_length = clib_net_to_host_u16 (ip6->payload_length);
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      paddr = (void *) &ip4->src_address;
      format_addr_func = (void *) format_ip4_address;
      ttl = ip4->ttl;
      l4_offset = ip4_header_bytes (ip4);
      payload_length =
	clib_net_to_host_u16 (ip4->length) + ip4_header_bytes (ip4);
    }
  icmp46_header_t *icmp = vlib_buffer_get_current (b0) + l4_offset;
  icmp46_echo_request_t *icmp_echo = (icmp46_echo_request_t *) (icmp + 1);
  u64 *dataplane_ts = (u64 *) &vnet_buffer (b0)->unused[0];

  f64 clocks_per_second = ((f64) vm->clib_time.clocks_per_second);
  f64 rtt = ((f64) (*dataplane_ts - icmp_echo->time_sent)) / clocks_per_second;

  vlib_cli_output (vm, "%d bytes from %U: icmp_seq=%d ttl=%d time=%.4f ms",
		   payload_length, format_addr_func, paddr,
		   clib_host_to_net_u16 (icmp_echo->seq), ttl, rtt * 1000.0);
}

/*
 * Perform the ping run with the given parameters in the current CLI process.
 * Depending on whether pa4 or pa6 is set, runs IPv4 or IPv6 ping.
 * The amusing side effect is of course if both are set, then both pings are
 * sent. This behavior can be used to ping a dualstack host over IPv4 and IPv6
 * at once.
 */

static void
run_ping_ip46_address (vlib_main_t *vm, u32 table_id, ip4_address_t *pa4,
		       ip6_address_t *pa6, u32 sw_if_index, f64 ping_interval,
		       u32 ping_repeat, u32 data_len, u32 ping_burst,
		       u32 verbose)
{
  int i;
  uword curr_proc = vlib_current_process (vm);
  u32 n_replies = 0;
  u32 n_requests = 0;
  u16 icmp_id;

  static u32 rand_seed = 0;

  if (PREDICT_FALSE (!rand_seed))
    rand_seed = random_default_seed ();

  icmp_id = random_u32 (&rand_seed) & 0xffff;

  while (get_cli_process_id_by_run_id (vm, icmp_id) != CLI_UNKNOWN_NODE)
    {
      vlib_cli_output (vm, "ICMP ID collision at %d, incrementing", icmp_id);
      icmp_id++;
    }

  set_cli_process_id_by_run_id (vm, icmp_id, curr_proc);

  for (i = 1; i <= ping_repeat; i++)
    {
      send_ip46_ping_result_t res = SEND_PING_OK;
      f64 sleep_interval;
      f64 time_ping_sent = vlib_time_now (vm);
      if (pa6)
	{
	  res = send_ip6_ping (vm, table_id, pa6, sw_if_index, i, icmp_id,
			       data_len, ping_burst, verbose);
	  if (SEND_PING_OK == res)
	    n_requests += ping_burst;
	  else
	    vlib_cli_output (vm, "Failed: %U", format_ip46_ping_result, res);
	}
      if (pa4)
	{
	  res = send_ip4_ping (vm, table_id, pa4, sw_if_index, i, icmp_id,
			       data_len, ping_burst, verbose);
	  if (SEND_PING_OK == res)
	    n_requests += ping_burst;
	  else
	    vlib_cli_output (vm, "Failed: %U", format_ip46_ping_result, res);
	}

      /* Collect and print the responses until it is time to send a next ping
       */

      while ((i <= ping_repeat) &&
	     ((sleep_interval =
		 time_ping_sent + ping_interval - vlib_time_now (vm)) > 0.0))
	{
	  uword event_type, *event_data = 0;
	  vlib_process_wait_for_event_or_clock (vm, sleep_interval);
	  event_type = vlib_process_get_events (vm, &event_data);
	  switch (event_type)
	    {
	    case ~0: /* no events => timeout */
	      break;
	    case RESPONSE_IP6:
	      /* fall-through */
	    case RESPONSE_IP4:
	      {
		int ii;
		int is_ip6 = (event_type == RESPONSE_IP6);
		for (ii = 0; ii < vec_len (event_data); ii++)
		  {
		    u32 bi0 = event_data[ii];
		    print_ip46_icmp_reply (vm, bi0, is_ip6);
		    n_replies++;
		    if (0 != bi0)
		      vlib_buffer_free (vm, &bi0, 1);
		  }
	      }
	      break;
	    case UNIX_CLI_PROCESS_EVENT_READ_READY:
	    case UNIX_CLI_PROCESS_EVENT_QUIT:
	      /* someone pressed a key, abort */
	      vlib_cli_output (vm, "Aborted due to a keypress.");
	      goto double_break;
	    }
	  vec_free (event_data);
	}
    }
double_break:
  vlib_cli_output (vm, "\n");
  {
    float loss =
      (0 == n_requests) ?
	0 :
	100.0 * ((float) n_requests - (float) n_replies) / (float) n_requests;
    vlib_cli_output (vm,
		     "Statistics: %u sent, %u received, %f%% packet loss\n",
		     n_requests, n_replies, loss);
    clear_cli_process_id_by_run_id (vm, icmp_id);
  }
}

static clib_error_t *
ping_ip_address (vlib_main_t *vm, unformat_input_t *input,
		 vlib_cli_command_t *cmd)
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
	  error = clib_error_return (0, "expecting IPv4 address but got `%U'",
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
	  error = clib_error_return (0, "expecting IPv6 address but got `%U'",
				     format_unformat_error, input);
	}
    }
  else
    {
      error = clib_error_return (
	0,
	"expecting IP4/IP6 address `%U'. Usage: ping <addr> [source <intf>] "
	"[size <datasz>] [repeat <count>] [verbose]",
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
	  if (!unformat_user (input, unformat_vnet_sw_interface, vnm,
			      &sw_if_index))
	    {
	      error = clib_error_return (0, "unknown interface `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "size"))
	{
	  if (!unformat (input, "%u", &data_len))
	    {
	      error = clib_error_return (0, "expecting size but got `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  if (data_len > PING_MAXIMUM_DATA_SIZE)
	    {
	      error = clib_error_return (
		0, "%d is bigger than maximum allowed payload size %d",
		data_len, PING_MAXIMUM_DATA_SIZE);
	      goto done;
	    }
	}
      else if (unformat (input, "table-id"))
	{
	  if (!unformat (input, "%u", &table_id))
	    {
	      error = clib_error_return (0, "expecting table-id but got `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "interval"))
	{
	  if (!unformat (input, "%f", &ping_interval))
	    {
	      error = clib_error_return (
		0, "expecting interval (floating point number) got `%U'",
		format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "repeat"))
	{
	  if (!unformat (input, "%u", &ping_repeat))
	    {
	      error =
		clib_error_return (0, "expecting repeat count but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "burst"))
	{
	  if (!unformat (input, "%u", &ping_burst))
	    {
	      error =
		clib_error_return (0, "expecting burst count but got `%U'",
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

    /*
     * Operationally, one won't (and shouldn't) need to send more than a frame
     * worth of pings. But it may be handy during the debugging.
     */

#ifdef CLIB_DEBUG
#define MAX_PING_BURST (10 * VLIB_FRAME_SIZE)
#else
#define MAX_PING_BURST (VLIB_FRAME_SIZE)
#endif

  if (ping_burst < 1 || ping_burst > MAX_PING_BURST)
    return clib_error_return (0, "burst size must be between 1 and %u",
			      MAX_PING_BURST);

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
 * @cliexstart{ping 172.16.1.2 ipv6 fe80::24a5:f6ff:fe9c:3a36 source
GigabitEthernet2/0/0 repeat 2 verbose}
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
VLIB_CLI_COMMAND (ping_command, static) = {
  .path = "ping",
  .function = ping_ip_address,
  .short_help = "ping {<ip-addr> | ipv4 <ip4-addr> | ipv6 <ip6-addr>}"
		" [ipv4 <ip4-addr> | ipv6 <ip6-addr>] [source <interface>]"
		" [size <pktsize:60>] [interval <sec:1>] [repeat <cnt:5>] "
		"[table-id <id:0>]"
		" [burst <count:1>] [verbose]",
  .is_mp_safe = 1,
};

static clib_error_t *
ping_init (vlib_main_t *vm)
{
  ip4_icmp_register_type (vm, ICMP4_echo_request,
			  ip4_icmp_echo_request_node.index);
  icmp6_register_type (vm, ICMP6_echo_request,
		       ip6_icmp_echo_request_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (ping_init) = {
  .runs_after = VLIB_INITS ("ping_traceroute_common_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
