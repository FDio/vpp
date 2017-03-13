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

#include <vnet/tcp/tcp.h>
#include <vnet/lisp-cp/packets.h>

vlib_node_registration_t tcp4_output_node;
vlib_node_registration_t tcp6_output_node;

typedef enum _tcp_output_nect
{
  TCP_OUTPUT_NEXT_DROP,
  TCP_OUTPUT_NEXT_IP_LOOKUP,
  TCP_OUTPUT_N_NEXT
} tcp_output_next_t;

#define foreach_tcp4_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip4-lookup")

#define foreach_tcp6_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip6-lookup")

static char *tcp_error_strings[] = {
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u8 state;
} tcp_tx_trace_t;

u16 dummy_mtu = 400;

u8 *
format_tcp_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "TBD\n");

  return s;
}

void
tcp_set_snd_mss (tcp_connection_t * tc)
{
  u16 snd_mss;

  /* TODO find our iface MTU */
  snd_mss = dummy_mtu;

  /* TODO cache mss and consider PMTU discovery */
  snd_mss = tc->opt.mss < snd_mss ? tc->opt.mss : snd_mss;

  tc->snd_mss = snd_mss;

  if (tc->snd_mss == 0)
    {
      clib_warning ("snd mss is 0");
      tc->snd_mss = dummy_mtu;
    }
}

static u8
tcp_window_compute_scale (u32 available_space)
{
  u8 wnd_scale = 0;
  while (wnd_scale < TCP_MAX_WND_SCALE
	 && (available_space >> wnd_scale) > TCP_WND_MAX)
    wnd_scale++;
  return wnd_scale;
}

/**
 * TCP's IW as recommended by RFC6928
 */
always_inline u32
tcp_initial_wnd_unscaled (tcp_connection_t * tc)
{
  return TCP_IW_N_SEGMENTS * dummy_mtu;
}

/**
 * Compute initial window and scale factor. As per RFC1323, window field in
 * SYN and SYN-ACK segments is never scaled.
 */
u32
tcp_initial_window_to_advertise (tcp_connection_t * tc)
{
  u32 max_fifo;

  /* Initial wnd for SYN. Fifos are not allocated yet.
   * Use some predefined value. For SYN-ACK we still want the
   * scale to be computed in the same way */
  max_fifo = TCP_MAX_RX_FIFO_SIZE;

  tc->rcv_wscale = tcp_window_compute_scale (max_fifo);
  tc->rcv_wnd = tcp_initial_wnd_unscaled (tc);

  return clib_min (tc->rcv_wnd, TCP_WND_MAX);
}

/**
 * Compute and return window to advertise, scaled as per RFC1323
 */
u32
tcp_window_to_advertise (tcp_connection_t * tc, tcp_state_t state)
{
  u32 available_space, max_fifo, observed_wnd;

  if (state < TCP_STATE_ESTABLISHED)
    return tcp_initial_window_to_advertise (tc);

  /*
   * Figure out how much space we have available
   */
  available_space = stream_session_max_enqueue (&tc->connection);
  max_fifo = stream_session_fifo_size (&tc->connection);

  ASSERT (tc->opt.mss < max_fifo);

  if (available_space < tc->opt.mss && available_space < max_fifo / 8)
    available_space = 0;

  /*
   * Use the above and what we know about what we've previously advertised
   * to compute the new window
   */
  observed_wnd = tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);

  /* Bad. Thou shalt not shrink */
  if (available_space < observed_wnd)
    {
      if (available_space == 0)
	clib_warning ("Didn't shrink rcv window despite not having space");
    }

  tc->rcv_wnd = clib_min (available_space, TCP_WND_MAX << tc->rcv_wscale);

  if (tc->rcv_wnd == 0)
    {
      tc->flags |= TCP_CONN_SENT_RCV_WND0;
    }

  return tc->rcv_wnd >> tc->rcv_wscale;
}

/**
 * Write TCP options to segment.
 */
u32
tcp_options_write (u8 * data, tcp_options_t * opts)
{
  u32 opts_len = 0;
  u32 buf, seq_len = 4;

  if (tcp_opts_mss (opts))
    {
      *data++ = TCP_OPTION_MSS;
      *data++ = TCP_OPTION_LEN_MSS;
      buf = clib_host_to_net_u16 (opts->mss);
      clib_memcpy (data, &buf, sizeof (opts->mss));
      data += sizeof (opts->mss);
      opts_len += TCP_OPTION_LEN_MSS;
    }

  if (tcp_opts_wscale (opts))
    {
      *data++ = TCP_OPTION_WINDOW_SCALE;
      *data++ = TCP_OPTION_LEN_WINDOW_SCALE;
      *data++ = opts->wscale;
      opts_len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_sack_permitted (opts))
    {
      *data++ = TCP_OPTION_SACK_PERMITTED;
      *data++ = TCP_OPTION_LEN_SACK_PERMITTED;
      opts_len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  if (tcp_opts_tstamp (opts))
    {
      *data++ = TCP_OPTION_TIMESTAMP;
      *data++ = TCP_OPTION_LEN_TIMESTAMP;
      buf = clib_host_to_net_u32 (opts->tsval);
      clib_memcpy (data, &buf, sizeof (opts->tsval));
      data += sizeof (opts->tsval);
      buf = clib_host_to_net_u32 (opts->tsecr);
      clib_memcpy (data, &buf, sizeof (opts->tsecr));
      data += sizeof (opts->tsecr);
      opts_len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack (opts))
    {
      int i;
      u32 n_sack_blocks = clib_min (vec_len (opts->sacks),
				    TCP_OPTS_MAX_SACK_BLOCKS);

      if (n_sack_blocks != 0)
	{
	  *data++ = TCP_OPTION_SACK_BLOCK;
	  *data++ = 2 + n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
	  for (i = 0; i < n_sack_blocks; i++)
	    {
	      buf = clib_host_to_net_u32 (opts->sacks[i].start);
	      clib_memcpy (data, &buf, seq_len);
	      data += seq_len;
	      buf = clib_host_to_net_u32 (opts->sacks[i].end);
	      clib_memcpy (data, &buf, seq_len);
	      data += seq_len;
	    }
	  opts_len += 2 + n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
	}
    }

  /* Terminate TCP options */
  if (opts_len % 4)
    {
      *data++ = TCP_OPTION_EOL;
      opts_len += TCP_OPTION_LEN_EOL;
    }

  /* Pad with zeroes to a u32 boundary */
  while (opts_len % 4)
    {
      *data++ = TCP_OPTION_NOOP;
      opts_len += TCP_OPTION_LEN_NOOP;
    }
  return opts_len;
}

always_inline int
tcp_make_syn_options (tcp_options_t * opts, u8 wnd_scale)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = dummy_mtu;	/*XXX discover that */
  len += TCP_OPTION_LEN_MSS;

  opts->flags |= TCP_OPTS_FLAG_WSCALE;
  opts->wscale = wnd_scale;
  len += TCP_OPTION_LEN_WINDOW_SCALE;

  opts->flags |= TCP_OPTS_FLAG_TSTAMP;
  opts->tsval = tcp_time_now ();
  opts->tsecr = 0;
  len += TCP_OPTION_LEN_TIMESTAMP;

  opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
  len += TCP_OPTION_LEN_SACK_PERMITTED;

  /* Align to needed boundary */
  len += (TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  return len;
}

always_inline int
tcp_make_synack_options (tcp_connection_t * tc, tcp_options_t * opts)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = dummy_mtu;	/*XXX discover that */
  len += TCP_OPTION_LEN_MSS;

  if (tcp_opts_wscale (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_WSCALE;
      opts->wscale = tc->rcv_wscale;
      len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_tstamp (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_time_now ();
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack_permitted (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
      len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  /* Align to needed boundary */
  len += (TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  return len;
}

always_inline int
tcp_make_established_options (tcp_connection_t * tc, tcp_options_t * opts)
{
  u8 len = 0;

  opts->flags = 0;

  if (tcp_opts_tstamp (&tc->opt))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_time_now ();
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }
  if (tcp_opts_sack_permitted (&tc->opt))
    {
      if (vec_len (tc->snd_sacks))
	{
	  opts->flags |= TCP_OPTS_FLAG_SACK;
	  opts->sacks = tc->snd_sacks;
	  opts->n_sack_blocks = vec_len (tc->snd_sacks);
	  len += 2 + TCP_OPTION_LEN_SACK_BLOCK * opts->n_sack_blocks;
	}
    }

  /* Align to needed boundary */
  len += (TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  return len;
}

always_inline int
tcp_make_options (tcp_connection_t * tc, tcp_options_t * opts,
		  tcp_state_t state)
{
  switch (state)
    {
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT_1:
      return tcp_make_established_options (tc, opts);
    case TCP_STATE_SYN_RCVD:
      return tcp_make_synack_options (tc, opts);
    case TCP_STATE_SYN_SENT:
      return tcp_make_syn_options (opts, tc->rcv_wscale);
    default:
      clib_warning ("Not handled!");
      return 0;
    }
}

#define tcp_get_free_buffer_index(tm, bidx)                             \
do {                                                                    \
  u32 *my_tx_buffers, n_free_buffers;                                   \
  u32 cpu_index = tm->vlib_main->cpu_index;                             \
  my_tx_buffers = tm->tx_buffers[cpu_index];                            \
  if (PREDICT_FALSE(vec_len (my_tx_buffers) == 0))                      \
    {                                                                   \
      n_free_buffers = 32;      /* TODO config or macro */              \
      vec_validate (my_tx_buffers, n_free_buffers - 1);                 \
      _vec_len(my_tx_buffers) = vlib_buffer_alloc_from_free_list (      \
          tm->vlib_main, my_tx_buffers, n_free_buffers,                 \
          VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);                         \
      tm->tx_buffers[cpu_index] = my_tx_buffers;                        \
    }                                                                   \
  /* buffer shortage */                                                 \
  if (PREDICT_FALSE (vec_len (my_tx_buffers) == 0))                     \
    return;                                                             \
  *bidx = my_tx_buffers[_vec_len (my_tx_buffers)-1];                    \
  _vec_len (my_tx_buffers) -= 1;                                        \
} while (0)

always_inline void
tcp_reuse_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_t *it = b;
  do
    {
      it->current_data = 0;
      it->current_length = 0;
      it->total_length_not_including_first_buffer = 0;
    }
  while ((it->flags & VLIB_BUFFER_NEXT_PRESENT)
	 && (it = vlib_get_buffer (vm, it->next_buffer)));

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
  vnet_buffer (b)->tcp.flags = 0;
}

/**
 * Prepare ACK
 */
void
tcp_make_ack_i (tcp_connection_t * tc, vlib_buffer_t * b, tcp_state_t state,
		u8 flags)
{
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 wnd;

  wnd = tcp_window_to_advertise (tc, state);

  /* Make and write options */
  tcp_opts_len = tcp_make_established_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
			     tc->rcv_nxt, tcp_hdr_opts_len, flags, wnd);

  tcp_options_write ((u8 *) (th + 1), snd_opts);

  /* Mark as ACK */
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
}

/**
 * Convert buffer to ACK
 */
void
tcp_make_ack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;

  tcp_reuse_buffer (vm, b);
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, TCP_FLAG_ACK);
  vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_ACK;
}

/**
 * Convert buffer to FIN-ACK
 */
void
tcp_make_fin (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u8 flags = 0;

  tcp_reuse_buffer (vm, b);

  flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, flags);

  /* Reset flags, make sure ack is sent */
  vnet_buffer (b)->tcp.flags &= ~TCP_BUF_FLAG_DUPACK;

  tc->snd_nxt += 1;
}

/**
 * Convert buffer to SYN-ACK
 */
void
tcp_make_synack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 initial_wnd;
  u32 time_now;

  memset (snd_opts, 0, sizeof (*snd_opts));

  tcp_reuse_buffer (vm, b);

  /* Set random initial sequence */
  time_now = tcp_time_now ();

  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;
  tc->snd_una_max = tc->snd_nxt;

  initial_wnd = tcp_initial_window_to_advertise (tc);

  /* Make and write options */
  tcp_opts_len = tcp_make_synack_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len,
			     TCP_FLAG_SYN | TCP_FLAG_ACK, initial_wnd);

  tcp_options_write ((u8 *) (th + 1), snd_opts);

  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_ACK;

  /* Init retransmit timer */
  tcp_retransmit_timer_set (tc);
}

always_inline void
tcp_enqueue_to_ip_lookup (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			  u8 is_ip4)
{
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Default FIB for now */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;

  /* Send to IP lookup */
  next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

int
tcp_make_reset_in_place (vlib_main_t * vm, vlib_buffer_t * b0,
			 tcp_state_t state, u32 my_thread_index, u8 is_ip4)
{
  u8 tcp_hdr_len = sizeof (tcp_header_t);
  ip4_header_t *ih4;
  ip6_header_t *ih6;
  tcp_header_t *th0;
  ip4_address_t src_ip40;
  ip6_address_t src_ip60;
  u16 src_port0;
  u32 tmp;

  /* Find IP and TCP headers */
  if (is_ip4)
    {
      ih4 = vlib_buffer_get_current (b0);
      th0 = ip4_next_header (ih4);
    }
  else
    {
      ih6 = vlib_buffer_get_current (b0);
      th0 = ip6_next_header (ih6);
    }

  /* Swap src and dst ip */
  if (is_ip4)
    {
      ASSERT ((ih4->ip_version_and_header_length & 0xF0) == 0x40);
      src_ip40.as_u32 = ih4->src_address.as_u32;
      ih4->src_address.as_u32 = ih4->dst_address.as_u32;
      ih4->dst_address.as_u32 = src_ip40.as_u32;

      /* Chop the end of the pkt */
      b0->current_length += ip4_header_bytes (ih4) + tcp_hdr_len;
    }
  else
    {
      ASSERT ((ih6->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60);
      clib_memcpy (&src_ip60, &ih6->src_address, sizeof (ip6_address_t));
      clib_memcpy (&ih6->src_address, &ih6->dst_address,
		   sizeof (ip6_address_t));
      clib_memcpy (&ih6->dst_address, &src_ip60, sizeof (ip6_address_t));

      /* Chop the end of the pkt */
      b0->current_length += sizeof (ip6_header_t) + tcp_hdr_len;
    }

  /* Try to determine what/why we're actually resetting and swap
   * src and dst ports */
  if (state == TCP_STATE_CLOSED)
    {
      if (!tcp_syn (th0))
	return -1;

      tmp = clib_net_to_host_u32 (th0->seq_number);

      /* Got a SYN for no listener. */
      th0->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
      th0->ack_number = clib_host_to_net_u32 (tmp + 1);
      th0->seq_number = 0;

    }
  else if (state >= TCP_STATE_SYN_SENT)
    {
      th0->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
      th0->seq_number = th0->ack_number;
      th0->ack_number = 0;
    }

  src_port0 = th0->src_port;
  th0->src_port = th0->dst_port;
  th0->dst_port = src_port0;
  th0->window = 0;
  th0->data_offset_and_reserved = (tcp_hdr_len >> 2) << 4;
  th0->urgent_pointer = 0;

  /* Compute checksum */
  if (is_ip4)
    {
      th0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ih4);
    }
  else
    {
      int bogus = ~0;
      th0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ih6, &bogus);
      ASSERT (!bogus);
    }

  return 0;
}

/**
 *  Send reset without reusing existing buffer
 */
void
tcp_send_reset (vlib_buffer_t * pkt, u8 is_ip4)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u8 tcp_hdr_len, flags = 0;
  tcp_header_t *th, *pkt_th;
  u32 seq, ack;
  ip4_header_t *ih4, *pkt_ih4;
  ip6_header_t *ih6, *pkt_ih6;

  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Make and write options */
  tcp_hdr_len = sizeof (tcp_header_t);

  if (is_ip4)
    {
      pkt_ih4 = vlib_buffer_get_current (pkt);
      pkt_th = ip4_next_header (pkt_ih4);
    }
  else
    {
      pkt_ih6 = vlib_buffer_get_current (pkt);
      pkt_th = ip6_next_header (pkt_ih6);
    }

  if (tcp_ack (pkt_th))
    {
      flags = TCP_FLAG_RST;
      seq = pkt_th->ack_number;
      ack = 0;
    }
  else
    {
      flags = TCP_FLAG_RST | TCP_FLAG_ACK;
      seq = 0;
      ack = clib_host_to_net_u32 (vnet_buffer (pkt)->tcp.seq_end);
    }

  th = vlib_buffer_push_tcp_net_order (b, pkt_th->dst_port, pkt_th->src_port,
				       seq, ack, tcp_hdr_len, flags, 0);

  /* Swap src and dst ip */
  if (is_ip4)
    {
      ASSERT ((pkt_ih4->ip_version_and_header_length & 0xF0) == 0x40);
      ih4 = vlib_buffer_push_ip4 (vm, b, &pkt_ih4->dst_address,
				  &pkt_ih4->src_address, IP_PROTOCOL_TCP);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih4);
    }
  else
    {
      int bogus = ~0;
      pkt_ih6 = (ip6_header_t *) (pkt_th - 1);
      ASSERT ((pkt_ih6->ip_version_traffic_class_and_flow_label & 0xF0) ==
	      0x60);
      ih6 =
	vlib_buffer_push_ip6 (vm, b, &pkt_ih6->dst_address,
			      &pkt_ih6->src_address, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih6, &bogus);
      ASSERT (!bogus);
    }

  tcp_enqueue_to_ip_lookup (vm, b, bi, is_ip4);
}

void
tcp_push_ip_hdr (tcp_main_t * tm, tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_header_t *th = vlib_buffer_get_current (b);

  if (tc->c_is_ip4)
    {
      ip4_header_t *ih;
      ih = vlib_buffer_push_ip4 (tm->vlib_main, b, &tc->c_lcl_ip4,
				 &tc->c_rmt_ip4, IP_PROTOCOL_TCP);
      th->checksum = ip4_tcp_udp_compute_checksum (tm->vlib_main, b, ih);
    }
  else
    {
      ip6_header_t *ih;
      int bogus = ~0;

      ih = vlib_buffer_push_ip6 (tm->vlib_main, b, &tc->c_lcl_ip6,
				 &tc->c_rmt_ip6, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (tm->vlib_main, b, ih,
							&bogus);
      ASSERT (!bogus);
    }
}

/**
 *  Send SYN
 *
 *  Builds a SYN packet for a half-open connection and sends it to ipx_lookup.
 *  The packet is not forwarded through tcpx_output to avoid doing lookups
 *  in the half_open pool.
 */
void
tcp_send_syn (tcp_connection_t * tc)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u8 tcp_hdr_opts_len, tcp_opts_len;
  tcp_header_t *th;
  u32 time_now;
  u16 initial_wnd;
  tcp_options_t snd_opts;

  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  /* Set random initial sequence */
  time_now = tcp_time_now ();

  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_una_max = tc->snd_nxt = tc->iss + 1;

  initial_wnd = tcp_initial_window_to_advertise (tc);

  /* Make and write options */
  memset (&snd_opts, 0, sizeof (snd_opts));
  tcp_opts_len = tcp_make_syn_options (&snd_opts, tc->rcv_wscale);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN,
			     initial_wnd);

  tcp_options_write ((u8 *) (th + 1), &snd_opts);

  /* Measure RTT with this */
  tc->rtt_ts = tcp_time_now ();
  tc->rtt_seq = tc->snd_nxt;

  /* Start retransmit trimer  */
  tcp_timer_set (tc, TCP_TIMER_RETRANSMIT_SYN, tc->rto * TCP_TO_TIMER_TICK);
  tc->rto_boff = 0;

  /* Set the connection establishment timer */
  tcp_timer_set (tc, TCP_TIMER_ESTABLISH, TCP_ESTABLISH_TIME);

  tcp_push_ip_hdr (tm, tc, b);
  tcp_enqueue_to_ip_lookup (vm, b, bi, tc->c_is_ip4);
}

always_inline void
tcp_enqueue_to_output (vlib_main_t * vm, vlib_buffer_t * b, u32 bi, u8 is_ip4)
{
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Decide where to send the packet */
  next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

/**
 *  Send FIN
 */
void
tcp_send_fin (tcp_connection_t * tc)
{
  vlib_buffer_t *b;
  u32 bi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;

  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Leave enough space for headers */
  vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

  tcp_make_fin (tc, b);
  tcp_enqueue_to_output (vm, b, bi, tc->c_is_ip4);
  tc->flags |= TCP_CONN_FINSNT;
  TCP_EVT_DBG (TCP_EVT_FIN_SENT, tc);
}

always_inline u8
tcp_make_state_flags (tcp_state_t next_state)
{
  switch (next_state)
    {
    case TCP_STATE_ESTABLISHED:
      return TCP_FLAG_ACK;
    case TCP_STATE_SYN_RCVD:
      return TCP_FLAG_SYN | TCP_FLAG_ACK;
    case TCP_STATE_SYN_SENT:
      return TCP_FLAG_SYN;
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_FIN_WAIT_1:
      return TCP_FLAG_FIN;
    default:
      clib_warning ("Shouldn't be here!");
    }
  return 0;
}

/**
 * Push TCP header and update connection variables
 */
static void
tcp_push_hdr_i (tcp_connection_t * tc, vlib_buffer_t * b,
		tcp_state_t next_state)
{
  u32 advertise_wnd, data_len;
  u8 tcp_opts_len, tcp_hdr_opts_len, opts_write_len, flags;
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  tcp_header_t *th;

  data_len = b->current_length;
  vnet_buffer (b)->tcp.flags = 0;

  /* Make and write options */
  memset (snd_opts, 0, sizeof (*snd_opts));
  tcp_opts_len = tcp_make_options (tc, snd_opts, next_state);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  /* Get rcv window to advertise */
  advertise_wnd = tcp_window_to_advertise (tc, next_state);
  flags = tcp_make_state_flags (next_state);

  /* Push header and options */
  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
			     tc->rcv_nxt, tcp_hdr_opts_len, flags,
			     advertise_wnd);

  opts_write_len = tcp_options_write ((u8 *) (th + 1), snd_opts);

  ASSERT (opts_write_len == tcp_opts_len);

  /* Tag the buffer with the connection index  */
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;

  tc->snd_nxt += data_len;
  TCP_EVT_DBG (TCP_EVT_PKTIZE, tc);
}

/* Send delayed ACK when timer expires */
void
tcp_timer_delack_handler (u32 index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 thread_index = os_get_cpu_number ();
  tcp_connection_t *tc;
  vlib_buffer_t *b;
  u32 bi;

  tc = tcp_connection_get (index, thread_index);

  /* Get buffer */
  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  /* Fill in the ACK */
  tcp_make_ack (tc, b);

  tc->timers[TCP_TIMER_DELACK] = TCP_TIMER_HANDLE_INVALID;
  tc->flags &= ~TCP_CONN_DELACK;

  tcp_enqueue_to_output (vm, b, bi, tc->c_is_ip4);
}

/** Build a retransmit segment
 *
 * @return the number of bytes in the segment or 0 if there's nothing to
 *         retransmit
 * */
u32
tcp_prepare_retransmit_segment (tcp_connection_t * tc, vlib_buffer_t * b,
				u32 max_bytes)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 n_bytes, offset = 0;
  sack_scoreboard_hole_t *hole;
  u32 hole_size;

  tcp_reuse_buffer (vm, b);

  ASSERT (tc->state >= TCP_STATE_ESTABLISHED);
  ASSERT (max_bytes != 0);

  if (tcp_opts_sack_permitted (&tc->opt))
    {
      /* XXX get first hole not retransmitted yet  */
      hole = scoreboard_first_hole (&tc->sack_sb);
      if (!hole)
	return 0;

      offset = hole->start - tc->snd_una;
      hole_size = hole->end - hole->start;

      ASSERT (hole_size);

      if (hole_size < max_bytes)
	max_bytes = hole_size;
    }
  else
    {
      if (seq_geq (tc->snd_nxt, tc->snd_una_max))
	return 0;
    }

  n_bytes = stream_session_peek_bytes (&tc->connection,
				       vlib_buffer_get_current (b), offset,
				       max_bytes);
  ASSERT (n_bytes != 0);

  tcp_push_hdr_i (tc, b, tc->state);

  return n_bytes;
}

static void
tcp_timer_retransmit_handler_i (u32 index, u8 is_syn)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = tm->vlib_main;
  u32 thread_index = os_get_cpu_number ();
  tcp_connection_t *tc;
  vlib_buffer_t *b;
  u32 bi, max_bytes, snd_space;

  if (is_syn)
    {
      tc = tcp_half_open_connection_get (index);
    }
  else
    {
      tc = tcp_connection_get (index, thread_index);
    }

  /* Make sure timer handle is set to invalid */
  tc->timers[TCP_TIMER_RETRANSMIT] = TCP_TIMER_HANDLE_INVALID;

  /* Increment RTO backoff (also equal to number of retries) */
  tc->rto_boff += 1;

  /* Go back to first un-acked byte */
  tc->snd_nxt = tc->snd_una;

  /* Get buffer */
  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (vm, bi);

  if (tc->state >= TCP_STATE_ESTABLISHED)
    {
      tcp_fastrecovery_off (tc);

      /* Exponential backoff */
      tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

      /* Figure out what and how many bytes we can send */
      snd_space = tcp_available_snd_space (tc);
      max_bytes = clib_min (tc->snd_mss, snd_space);

      if (max_bytes == 0)
	{
	  clib_warning ("no wnd to retransmit");
	  return;
	}
      tcp_prepare_retransmit_segment (tc, b, max_bytes);

      tc->rtx_bytes += max_bytes;

      /* No fancy recovery for now! */
      scoreboard_clear (&tc->sack_sb);
    }
  else
    {
      /* Retransmit for SYN/SYNACK */
      ASSERT (tc->state == TCP_STATE_SYN_RCVD
	      || tc->state == TCP_STATE_SYN_SENT);

      /* Try without increasing RTO a number of times. If this fails,
       * start growing RTO exponentially */
      if (tc->rto_boff > TCP_RTO_SYN_RETRIES)
	tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

      vlib_buffer_make_headroom (b, MAX_HDRS_LEN);

      tcp_push_hdr_i (tc, b, tc->state);

      /* Account for the SYN */
      tc->snd_nxt += 1;
    }

  if (!is_syn)
    {
      tcp_enqueue_to_output (vm, b, bi, tc->c_is_ip4);

      /* Re-enable retransmit timer */
      tcp_retransmit_timer_set (tc);
    }
  else
    {
      ASSERT (tc->state == TCP_STATE_SYN_SENT);

      /* This goes straight to ipx_lookup */
      tcp_push_ip_hdr (tm, tc, b);
      tcp_enqueue_to_ip_lookup (vm, b, bi, tc->c_is_ip4);

      /* Re-enable retransmit timer */
      tcp_timer_set (tc, TCP_TIMER_RETRANSMIT_SYN,
		     tc->rto * TCP_TO_TIMER_TICK);
    }
}

void
tcp_timer_retransmit_handler (u32 index)
{
  tcp_timer_retransmit_handler_i (index, 0);
}

void
tcp_timer_retransmit_syn_handler (u32 index)
{
  tcp_timer_retransmit_handler_i (index, 1);
}

/**
 * Retansmit first unacked segment */
void
tcp_retransmit_first_unacked (tcp_connection_t * tc)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 snd_nxt = tc->snd_nxt;
  vlib_buffer_t *b;
  u32 bi;

  tc->snd_nxt = tc->snd_una;

  /* Get buffer */
  tcp_get_free_buffer_index (tm, &bi);
  b = vlib_get_buffer (tm->vlib_main, bi);

  tcp_prepare_retransmit_segment (tc, b, tc->snd_mss);
  tcp_enqueue_to_output (tm->vlib_main, b, bi, tc->c_is_ip4);

  tc->snd_nxt = snd_nxt;
  tc->rtx_bytes += tc->snd_mss;
}

void
tcp_fast_retransmit (tcp_connection_t * tc)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 snd_space, max_bytes, n_bytes, bi;
  vlib_buffer_t *b;

  ASSERT (tcp_in_fastrecovery (tc));

  clib_warning ("fast retransmit!");

  /* Start resending from first un-acked segment */
  tc->snd_nxt = tc->snd_una;

  snd_space = tcp_available_snd_space (tc);

  while (snd_space)
    {
      tcp_get_free_buffer_index (tm, &bi);
      b = vlib_get_buffer (tm->vlib_main, bi);

      max_bytes = clib_min (tc->snd_mss, snd_space);
      n_bytes = tcp_prepare_retransmit_segment (tc, b, max_bytes);

      /* Nothing left to retransmit */
      if (n_bytes == 0)
	return;

      tcp_enqueue_to_output (tm->vlib_main, b, bi, tc->c_is_ip4);

      snd_space -= n_bytes;
    }

  /* If window allows, send new data */
  tc->snd_nxt = tc->snd_una_max;
}

always_inline u32
tcp_session_has_ooo_data (tcp_connection_t * tc)
{
  stream_session_t *s =
    stream_session_get (tc->c_s_index, tc->c_thread_index);
  return svm_fifo_has_ooo_data (s->server_rx_fifo);
}

always_inline uword
tcp46_output_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->cpu_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  tcp_connection_t *tc0;
	  tcp_header_t *th0;
	  u32 error0 = TCP_ERROR_PKTS_SENT, next0 = TCP_OUTPUT_NEXT_IP_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				    my_thread_index);
	  if (PREDICT_FALSE (tc0 == 0 || tc0->state == TCP_STATE_CLOSED))
	    {
	      error0 = TCP_ERROR_INVALID_CONNECTION;
	      next0 = TCP_OUTPUT_NEXT_DROP;
	      goto done;
	    }

	  th0 = vlib_buffer_get_current (b0);
	  TCP_EVT_DBG (TCP_EVT_OUTPUT, tc0, th0->flags, b0->current_length);

	  if (is_ip4)
	    {
	      ip4_header_t *ih0;
	      ih0 = vlib_buffer_push_ip4 (vm, b0, &tc0->c_lcl_ip4,
					  &tc0->c_rmt_ip4, IP_PROTOCOL_TCP);
	      th0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ih0);
	    }
	  else
	    {
	      ip6_header_t *ih0;
	      int bogus = ~0;

	      ih0 = vlib_buffer_push_ip6 (vm, b0, &tc0->c_lcl_ip6,
					  &tc0->c_rmt_ip6, IP_PROTOCOL_TCP);
	      th0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ih0,
								 &bogus);
	      ASSERT (!bogus);
	    }

	  /* Filter out DUPACKs if there are no OOO segments left */
	  if (PREDICT_FALSE
	      (vnet_buffer (b0)->tcp.flags & TCP_BUF_FLAG_DUPACK))
	    {
	      ASSERT (tc0->snt_dupacks > 0);
	      tc0->snt_dupacks--;
	      if (!tcp_session_has_ooo_data (tc0))
		{
		  error0 = TCP_ERROR_FILTERED_DUPACKS;
		  next0 = TCP_OUTPUT_NEXT_DROP;
		  goto done;
		}
	    }

	  /* Retransmitted SYNs do reach this but it should be harmless */
	  tc0->rcv_las = tc0->rcv_nxt;

	  /* Stop DELACK timer and fix flags */
	  tc0->flags &=
	    ~(TCP_CONN_SNDACK | TCP_CONN_DELACK | TCP_CONN_BURSTACK);
	  if (tcp_timer_is_active (tc0, TCP_TIMER_DELACK))
	    {
	      tcp_timer_reset (tc0, TCP_TIMER_DELACK);
	    }

	  /* If not retransmitting
	   * 1) update snd_una_max (SYN, SYNACK, new data, FIN)
	   * 2) If we're not tracking an ACK, start tracking */
	  if (seq_lt (tc0->snd_una_max, tc0->snd_nxt))
	    {
	      tc0->snd_una_max = tc0->snd_nxt;
	      if (tc0->rtt_ts == 0)
		{
		  tc0->rtt_ts = tcp_time_now ();
		  tc0->rtt_seq = tc0->snd_nxt;
		}
	    }

	  /* Set the retransmit timer if not set already and not
	   * doing a pure ACK */
	  if (!tcp_timer_is_active (tc0, TCP_TIMER_RETRANSMIT)
	      && tc0->snd_nxt != tc0->snd_una)
	    {
	      tcp_retransmit_timer_set (tc0);
	      tc0->rto_boff = 0;
	    }

	  /* set fib index to default and lookup node */
	  /* XXX network virtualization (vrf/vni) */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  b0->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
	done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {

	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
tcp4_output (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_output (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_output_node) =
{
  .function = tcp4_output,.name = "tcp4-output",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),
    .n_errors = TCP_N_ERROR,
    .error_strings = tcp_error_strings,
    .n_next_nodes = TCP_OUTPUT_N_NEXT,
    .next_nodes = {
#define _(s,n) [TCP_OUTPUT_NEXT_##s] = n,
    foreach_tcp4_output_next
#undef _
    },
    .format_buffer = format_tcp_header,
    .format_trace = format_tcp_tx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_output_node, tcp4_output);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_output_node) =
{
  .function = tcp6_output,
  .name = "tcp6-output",
    /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_OUTPUT_NEXT_##s] = n,
    foreach_tcp6_output_next
#undef _
  },
  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_tx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_output_node, tcp6_output);

u32
tcp_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  tcp_connection_t *tc;

  tc = (tcp_connection_t *) tconn;
  tcp_push_hdr_i (tc, b, TCP_STATE_ESTABLISHED);
  return 0;
}

typedef enum _tcp_reset_next
{
  TCP_RESET_NEXT_DROP,
  TCP_RESET_NEXT_IP_LOOKUP,
  TCP_RESET_N_NEXT
} tcp_reset_next_t;

#define foreach_tcp4_reset_next        	\
  _(DROP, "error-drop")                 \
  _(IP_LOOKUP, "ip4-lookup")

#define foreach_tcp6_reset_next        	\
  _(DROP, "error-drop")                 \
  _(IP_LOOKUP, "ip6-lookup")

static uword
tcp46_send_reset_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->cpu_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 error0 = TCP_ERROR_RST_SENT, next0 = TCP_RESET_NEXT_IP_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (tcp_make_reset_in_place (vm, b0, vnet_buffer (b0)->tcp.flags,
				       my_thread_index, is_ip4))
	    {
	      error0 = TCP_ERROR_LOOKUP_DROPS;
	      next0 = TCP_RESET_NEXT_DROP;
	      goto done;
	    }

	  /* Prepare to send to IP lookup */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;
	  next0 = TCP_RESET_NEXT_IP_LOOKUP;

	done:
	  b0->error = node->errors[error0];
	  b0->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {

	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
tcp4_send_reset (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame)
{
  return tcp46_send_reset_inline (vm, node, from_frame, 1);
}

static uword
tcp6_send_reset (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame)
{
  return tcp46_send_reset_inline (vm, node, from_frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_reset_node) = {
  .function = tcp4_send_reset,
  .name = "tcp4-reset",
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RESET_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RESET_NEXT_##s] = n,
    foreach_tcp4_reset_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_reset_node, tcp4_send_reset);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_reset_node) = {
  .function = tcp6_send_reset,
  .name = "tcp6-reset",
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RESET_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RESET_NEXT_##s] = n,
    foreach_tcp6_reset_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_reset_node, tcp6_send_reset);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
