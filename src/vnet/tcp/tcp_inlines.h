/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_TCP_TCP_INLINES_H_
#define SRC_VNET_TCP_TCP_INLINES_H_

#include <vnet/tcp/tcp.h>

always_inline tcp_header_t *
tcp_buffer_hdr (vlib_buffer_t * b)
{
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return (tcp_header_t *) (b->data + b->current_data
			   + vnet_buffer (b)->tcp.hdr_offset);
}

always_inline tcp_connection_t *
tcp_connection_get (u32 conn_index, u32 thread_index)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  if (PREDICT_FALSE (pool_is_free_index (wrk->connections, conn_index)))
    return 0;
  return pool_elt_at_index (wrk->connections, conn_index);
}

always_inline tcp_connection_t *
tcp_connection_get_if_valid (u32 conn_index, u32 thread_index)
{
  tcp_worker_ctx_t *wrk;
  if (thread_index >= vec_len (tcp_main.wrk_ctx))
    return 0;
  wrk = tcp_get_worker (thread_index);
  if (pool_is_free_index (wrk->connections, conn_index))
    return 0;
  return pool_elt_at_index (wrk->connections, conn_index);
}

always_inline void
tcp_connection_set_state (tcp_connection_t * tc, tcp_state_t state)
{
  tc->state = state;
  TCP_EVT (TCP_EVT_STATE_CHANGE, tc);
}

always_inline tcp_connection_t *
tcp_listener_get (u32 tli)
{
  tcp_connection_t *tc = 0;
  if (!pool_is_free_index (tcp_main.listener_pool, tli))
    tc = pool_elt_at_index (tcp_main.listener_pool, tli);
  return tc;
}

always_inline tcp_connection_t *
tcp_half_open_connection_get (u32 conn_index)
{
  return tcp_connection_get (conn_index, transport_cl_thread ());
}

/**
 * Our estimate of the number of bytes that have left the network
 */
always_inline u32
tcp_bytes_out (const tcp_connection_t * tc)
{
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    return tc->sack_sb.sacked_bytes + tc->sack_sb.lost_bytes;
  else
    return clib_min (tc->rcv_dupacks * tc->snd_mss,
		     tc->snd_nxt - tc->snd_una);
}

/**
 * Our estimate of the number of bytes in flight (pipe size)
 */
always_inline u32
tcp_flight_size (const tcp_connection_t * tc)
{
  int flight_size;

  flight_size = (int) (tc->snd_nxt - tc->snd_una) - tcp_bytes_out (tc)
    + tc->snd_rxt_bytes - tc->rxt_delivered;

  ASSERT (flight_size >= 0);

  return flight_size;
}

/**
 * Initial cwnd as per RFC5681
 */
always_inline u32
tcp_initial_cwnd (const tcp_connection_t * tc)
{
  if (tcp_cfg.initial_cwnd_multiplier > 0)
    return tcp_cfg.initial_cwnd_multiplier * tc->snd_mss;

  if (tc->snd_mss > 2190)
    return 2 * tc->snd_mss;
  else if (tc->snd_mss > 1095)
    return 3 * tc->snd_mss;
  else
    return 4 * tc->snd_mss;
}

/*
 * Accumulate acked bytes for cwnd increase
 *
 * Once threshold bytes are accumulated, snd_mss bytes are added
 * to the cwnd.
 */
always_inline void
tcp_cwnd_accumulate (tcp_connection_t * tc, u32 thresh, u32 bytes)
{
  tc->cwnd_acc_bytes += bytes;
  if (tc->cwnd_acc_bytes >= thresh)
    {
      u32 inc = tc->cwnd_acc_bytes / thresh;
      tc->cwnd_acc_bytes -= inc * thresh;
      tc->cwnd += inc * tc->snd_mss;
      tc->cwnd = clib_min (tc->cwnd, tc->tx_fifo_size);
    }
}

always_inline u32
tcp_loss_wnd (const tcp_connection_t * tc)
{
  /* Whatever we have in flight + the packet we're about to send */
  return tcp_flight_size (tc) + tc->snd_mss;
}

always_inline u32
tcp_available_snd_wnd (const tcp_connection_t * tc)
{
  return clib_min (tc->cwnd, tc->snd_wnd);
}

always_inline u32
tcp_available_output_snd_space (const tcp_connection_t * tc)
{
  u32 available_wnd = tcp_available_snd_wnd (tc);
  int flight_size = (int) (tc->snd_nxt - tc->snd_una);

  if (available_wnd <= flight_size)
    return 0;

  return available_wnd - flight_size;
}

/**
 * Estimate of how many bytes we can still push into the network
 */
always_inline u32
tcp_available_cc_snd_space (const tcp_connection_t * tc)
{
  u32 available_wnd = tcp_available_snd_wnd (tc);
  u32 flight_size = tcp_flight_size (tc);

  if (available_wnd <= flight_size)
    return 0;

  return available_wnd - flight_size;
}

always_inline u8
tcp_is_lost_fin (tcp_connection_t * tc)
{
  if ((tc->flags & TCP_CONN_FINSNT) && (tc->snd_nxt - tc->snd_una == 1))
    return 1;
  return 0;
}

/**
 * Time used to generate timestamps, not the timestamp
 */
always_inline u32
tcp_time_tstamp (u32 thread_index)
{
  return tcp_main.wrk_ctx[thread_index].time_tstamp;
}

/**
 * Generate timestamp for tcp connection
 */
always_inline u32
tcp_tstamp (tcp_connection_t * tc)
{
  return (tcp_main.wrk_ctx[tc->c_thread_index].time_tstamp -
	  tc->timestamp_delta);
}

always_inline f64
tcp_time_now_us (u32 thread_index)
{
  return tcp_main.wrk_ctx[thread_index].time_us;
}

always_inline void
tcp_set_time_now (tcp_worker_ctx_t *wrk, f64 now)
{
  /* TCP internal cache of time reference. Could use @ref transport_time_now
   * but because @ref tcp_time_now_us is used per packet, caching might
   * slightly improve efficiency. */
  wrk->time_us = now;
  wrk->time_tstamp = (u64) (now * TCP_TSTP_HZ);
}

always_inline void
tcp_update_time_now (tcp_worker_ctx_t *wrk)
{
  f64 now = vlib_time_now (wrk->vm);

  /* Both pacer and tcp us time need to be updated */
  transport_update_pacer_time (wrk->vm->thread_index, now);
  tcp_set_time_now (wrk, now);
}

always_inline tcp_connection_t *
tcp_input_lookup_buffer (vlib_buffer_t * b, u8 thread_index, u32 * error,
			 u8 is_ip4, u8 is_nolookup)
{
  u32 fib_index = vnet_buffer (b)->ip.fib_index;
  int n_advance_bytes, n_data_bytes;
  transport_connection_t *tc;
  tcp_header_t *tcp;
  u8 result = 0;

  if (is_ip4)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      int ip_hdr_bytes = ip4_header_bytes (ip4);
      if (PREDICT_FALSE (b->current_length < ip_hdr_bytes + sizeof (*tcp)))
	{
	  *error = TCP_ERROR_LENGTH;
	  return 0;
	}
      tcp = ip4_next_header (ip4);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip4;
      n_advance_bytes = (ip_hdr_bytes + tcp_header_bytes (tcp));
      n_data_bytes = clib_net_to_host_u16 (ip4->length) - n_advance_bytes;

      /* Length check. Checksum computed by ipx_local no need to compute again */
      if (PREDICT_FALSE (n_data_bytes < 0))
	{
	  *error = TCP_ERROR_LENGTH;
	  return 0;
	}

      if (!is_nolookup)
	tc = session_lookup_connection_wt4 (fib_index, &ip4->dst_address,
					    &ip4->src_address, tcp->dst_port,
					    tcp->src_port,
					    TRANSPORT_PROTO_TCP, thread_index,
					    &result);
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (PREDICT_FALSE (b->current_length < sizeof (*ip6) + sizeof (*tcp)))
	{
	  *error = TCP_ERROR_LENGTH;
	  return 0;
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
	  return 0;
	}

      if (!is_nolookup)
	{
	  if (PREDICT_FALSE
	      (ip6_address_is_link_local_unicast (&ip6->dst_address)))
	    {
	      ip6_main_t *im = &ip6_main;
	      fib_index = vec_elt (im->fib_index_by_sw_if_index,
				   vnet_buffer (b)->ip.rx_sw_if_index);
	    }

	  tc = session_lookup_connection_wt6 (fib_index, &ip6->dst_address,
					      &ip6->src_address,
					      tcp->dst_port, tcp->src_port,
					      TRANSPORT_PROTO_TCP,
					      thread_index, &result);
	}
    }

  /* Set the sw_if_index[VLIB_RX] to the interface we received
   * the connection on (the local interface) */
  vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer (b)->ip.rx_sw_if_index;

  if (is_nolookup)
    tc =
      (transport_connection_t *) tcp_connection_get (vnet_buffer (b)->
						     tcp.connection_index,
						     thread_index);

  vnet_buffer (b)->tcp.seq_number = clib_net_to_host_u32 (tcp->seq_number);
  vnet_buffer (b)->tcp.ack_number = clib_net_to_host_u32 (tcp->ack_number);
  vnet_buffer (b)->tcp.data_offset = n_advance_bytes;
  vnet_buffer (b)->tcp.data_len = n_data_bytes;
  vnet_buffer (b)->tcp.seq_end = vnet_buffer (b)->tcp.seq_number
    + n_data_bytes;

  *error = result ? TCP_ERROR_NONE + result : *error;

  return tcp_get_connection_from_transport (tc);
}

/**
 * Initialize connection by gleaning network and rcv params from buffer
 *
 * @param tc		connection to initialize
 * @param b		buffer whose current data is pointing at ip
 * @param is_ip4	flag set to 1 if using ip4
 */
always_inline void
tcp_init_w_buffer (tcp_connection_t * tc, vlib_buffer_t * b, u8 is_ip4)
{
  tcp_header_t *th = tcp_buffer_hdr (b);

  tc->c_lcl_port = th->dst_port;
  tc->c_rmt_port = th->src_port;
  tc->c_is_ip4 = is_ip4;

  if (is_ip4)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      tc->c_lcl_ip4.as_u32 = ip4->dst_address.as_u32;
      tc->c_rmt_ip4.as_u32 = ip4->src_address.as_u32;
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      clib_memcpy_fast (&tc->c_lcl_ip6, &ip6->dst_address,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&tc->c_rmt_ip6, &ip6->src_address,
			sizeof (ip6_address_t));
    }

  tc->irs = vnet_buffer (b)->tcp.seq_number;
  tc->rcv_nxt = vnet_buffer (b)->tcp.seq_number + 1;
  tc->rcv_las = tc->rcv_nxt;
  tc->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  tc->snd_wl1 = vnet_buffer (b)->tcp.seq_number;
  tc->snd_wl2 = vnet_buffer (b)->tcp.ack_number;

  /* RFC1323: TSval timestamps sent on {SYN} and {SYN,ACK}
   * segments are used to initialize PAWS. */
  if (tcp_opts_tstamp (&tc->rcv_opts))
    {
      tc->tsval_recent = tc->rcv_opts.tsval;
      tc->tsval_recent_age = tcp_time_tstamp (tc->c_thread_index);
    }

  if (tcp_opts_wscale (&tc->rcv_opts))
    tc->snd_wscale = tc->rcv_opts.wscale;

  tc->snd_wnd = clib_net_to_host_u16 (th->window) << tc->snd_wscale;
}

always_inline void
tcp_update_rto (tcp_connection_t * tc)
{
  tc->rto = clib_min (tc->srtt + (tc->rttvar << 2), TCP_RTO_MAX);
  tc->rto = clib_max (tc->rto, TCP_RTO_MIN);
}

always_inline u8
tcp_is_descheduled (tcp_connection_t * tc)
{
  return (transport_connection_is_descheduled (&tc->connection) ? 1 : 0);
}

/**
 * Push TCP header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param seq - sequence number net order
 * @param ack - ack number net order
 * @param tcp_hdr_opts_len - header and options length in bytes
 * @param flags - header flags
 * @param wnd - window size
 *
 * @return - pointer to start of TCP header
 */
always_inline void *
vlib_buffer_push_tcp_net_order (vlib_buffer_t * b, u16 sp, u16 dp, u32 seq,
				u32 ack, u8 tcp_hdr_opts_len, u8 flags,
				u16 wnd)
{
  tcp_header_t *th;

  th = vlib_buffer_push_uninit (b, tcp_hdr_opts_len);

  th->src_port = sp;
  th->dst_port = dp;
  th->seq_number = seq;
  th->ack_number = ack;
  th->data_offset_and_reserved = (tcp_hdr_opts_len >> 2) << 4;
  th->flags = flags;
  th->window = wnd;
  th->checksum = 0;
  th->urgent_pointer = 0;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) th - b->data;
  b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  return th;
}

/**
 * Push TCP header to buffer
 *
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param seq - sequence number host order
 * @param ack - ack number host order
 * @param tcp_hdr_opts_len - header and options length in bytes
 * @param flags - header flags
 * @param wnd - window size
 *
 * @return - pointer to start of TCP header
 */
always_inline void *
vlib_buffer_push_tcp (vlib_buffer_t * b, u16 sp_net, u16 dp_net, u32 seq,
		      u32 ack, u8 tcp_hdr_opts_len, u8 flags, u16 wnd)
{
  return vlib_buffer_push_tcp_net_order (b, sp_net, dp_net,
					 clib_host_to_net_u32 (seq),
					 clib_host_to_net_u32 (ack),
					 tcp_hdr_opts_len, flags,
					 clib_host_to_net_u16 (wnd));
}

#endif /* SRC_VNET_TCP_TCP_INLINES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
