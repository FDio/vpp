/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
#include <vnet/tcp/tcp_inlines.h>
#include <math.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

typedef enum _tcp_output_next
{
  TCP_OUTPUT_NEXT_DROP,
  TCP_OUTPUT_NEXT_IP_LOOKUP,
  TCP_OUTPUT_NEXT_IP_REWRITE,
  TCP_OUTPUT_NEXT_IP_ARP,
  TCP_OUTPUT_N_NEXT
} tcp_output_next_t;

#define foreach_tcp4_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip4-lookup")			\
  _ (IP_REWRITE, "ip4-rewrite")			\
  _ (IP_ARP, "ip4-arp")

#define foreach_tcp6_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip6-lookup")			\
  _ (IP_REWRITE, "ip6-rewrite")			\
  _ (IP_ARP, "ip6-discover-neighbor")

static vlib_error_desc_t tcp_output_error_counters[] = {
#define tcp_error(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

typedef struct
{
  tcp_header_t tcp_header;
  tcp_connection_t tcp_connection;
} tcp_tx_trace_t;

static u8 *
format_tcp_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_tx_trace_t *t = va_arg (*args, tcp_tx_trace_t *);
  tcp_connection_t *tc = &t->tcp_connection;
  u32 indent = format_get_indent (s);

  s = format (s, "%U state %U\n%U%U", format_tcp_connection_id, tc,
	      format_tcp_state, tc->state, format_white_space, indent,
	      format_tcp_header, &t->tcp_header, 128);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
static u8
tcp_window_compute_scale (u32 window)
{
  u8 wnd_scale = 0;
  while (wnd_scale < TCP_MAX_WND_SCALE && (window >> wnd_scale) > TCP_WND_MAX)
    wnd_scale++;
  return wnd_scale;
}

/**
 * TCP's initial window
 */
always_inline u32
tcp_initial_wnd_unscaled (tcp_connection_t * tc)
{
  /* RFC 6928 recommends the value lower. However at the time our connections
   * are initialized, fifos may not be allocated. Therefore, advertise the
   * smallest possible unscaled window size and update once fifos are
   * assigned to the session.
   */
  /*
     tcp_update_rcv_mss (tc);
     TCP_IW_N_SEGMENTS * tc->mss;
   */
  return tcp_cfg.min_rx_fifo;
}

/**
 * Compute initial window and scale factor. As per RFC1323, window field in
 * SYN and SYN-ACK segments is never scaled.
 */
u32
tcp_initial_window_to_advertise (tcp_connection_t * tc)
{
  /* Compute rcv wscale only if peer advertised support for it */
  if (tc->state != TCP_STATE_SYN_RCVD || tcp_opts_wscale (&tc->rcv_opts))
    tc->rcv_wscale = tcp_window_compute_scale (tcp_cfg.max_rx_fifo);

  tc->rcv_wnd = tcp_initial_wnd_unscaled (tc);

  return clib_min (tc->rcv_wnd, TCP_WND_MAX);
}

static inline void
tcp_update_rcv_wnd (tcp_connection_t * tc)
{
  u32 available_space, wnd;
  i32 observed_wnd;

  /*
   * Figure out how much space we have available
   */
  available_space = transport_max_rx_enqueue (&tc->connection);

  /*
   * Use the above and what we know about what we've previously advertised
   * to compute the new window
   */
  observed_wnd = (i32) tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);

  /* Check if we are about to retract the window. Do the comparison before
   * rounding to avoid errors. Per RFC7323 sec. 2.4 we could remove this */
  if (PREDICT_FALSE ((i32) available_space < observed_wnd))
    {
      wnd = round_down_pow2 (clib_max (observed_wnd, 0), 1 << tc->rcv_wscale);
      TCP_EVT (TCP_EVT_RCV_WND_SHRUNK, tc, observed_wnd, available_space);
    }
  else
    {
      /* Make sure we have a multiple of 1 << rcv_wscale. We round down to
       * avoid advertising a window larger than what can be buffered */
      wnd = round_down_pow2 (available_space, 1 << tc->rcv_wscale);
    }

  if (PREDICT_FALSE (wnd < tc->rcv_opts.mss))
    wnd = 0;

  tc->rcv_wnd = clib_min (wnd, TCP_WND_MAX << tc->rcv_wscale);
}

/**
 * Compute and return window to advertise, scaled as per RFC1323
 */
static inline u32
tcp_window_to_advertise (tcp_connection_t * tc, tcp_state_t state)
{
  if (state < TCP_STATE_ESTABLISHED)
    return tcp_initial_window_to_advertise (tc);

  tcp_update_rcv_wnd (tc);
  return tc->rcv_wnd >> tc->rcv_wscale;
}

static int
tcp_make_syn_options (tcp_connection_t * tc, tcp_options_t * opts)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = tc->mss;
  len += TCP_OPTION_LEN_MSS;

  opts->flags |= TCP_OPTS_FLAG_WSCALE;
  opts->wscale = tc->rcv_wscale;
  len += TCP_OPTION_LEN_WINDOW_SCALE;

  opts->flags |= TCP_OPTS_FLAG_TSTAMP;
  opts->tsval = tcp_time_tstamp (tc->c_thread_index);
  opts->tsecr = 0;
  len += TCP_OPTION_LEN_TIMESTAMP;

  if (TCP_USE_SACKS)
    {
      opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
      len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  /* Align to needed boundary */
  len += (TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  return len;
}

static int
tcp_make_synack_options (tcp_connection_t * tc, tcp_options_t * opts)
{
  u8 len = 0;

  opts->flags |= TCP_OPTS_FLAG_MSS;
  opts->mss = tc->mss;
  len += TCP_OPTION_LEN_MSS;

  if (tcp_opts_wscale (&tc->rcv_opts))
    {
      opts->flags |= TCP_OPTS_FLAG_WSCALE;
      opts->wscale = tc->rcv_wscale;
      len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_tstamp (&tc->rcv_opts))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_time_tstamp (tc->c_thread_index);
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      opts->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
      len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  /* Align to needed boundary */
  len += (TCP_OPTS_ALIGN - len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  return len;
}

static int
tcp_make_established_options (tcp_connection_t * tc, tcp_options_t * opts)
{
  u8 len = 0;

  opts->flags = 0;

  if (tcp_opts_tstamp (&tc->rcv_opts))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = tcp_tstamp (tc);
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      if (vec_len (tc->snd_sacks))
	{
	  opts->flags |= TCP_OPTS_FLAG_SACK;
	  if (tc->snd_sack_pos >= vec_len (tc->snd_sacks))
	    tc->snd_sack_pos = 0;
	  opts->sacks = &tc->snd_sacks[tc->snd_sack_pos];
	  opts->n_sack_blocks = vec_len (tc->snd_sacks) - tc->snd_sack_pos;
	  opts->n_sack_blocks = clib_min (opts->n_sack_blocks,
					  TCP_OPTS_MAX_SACK_BLOCKS);
	  tc->snd_sack_pos += opts->n_sack_blocks;
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
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_CLOSING:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_TIME_WAIT:
    case TCP_STATE_CLOSED:
      return tcp_make_established_options (tc, opts);
    case TCP_STATE_SYN_RCVD:
      return tcp_make_synack_options (tc, opts);
    case TCP_STATE_SYN_SENT:
      return tcp_make_syn_options (tc, opts);
    default:
      clib_warning ("State not handled! %d", state);
      return 0;
    }
}

/**
 * Update burst send vars
 *
 * - Updates snd_mss to reflect the effective segment size that we can send
 * by taking into account all TCP options, including SACKs.
 * - Cache 'on the wire' options for reuse
 * - Updates receive window which can be reused for a burst.
 *
 * This should *only* be called when doing bursts
 */
void
tcp_update_burst_snd_vars (tcp_connection_t * tc)
{
  tcp_main_t *tm = &tcp_main;

  /* Compute options to be used for connection. These may be reused when
   * sending data or to compute the effective mss (snd_mss) */
  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts,
				       TCP_STATE_ESTABLISHED);

  /* XXX check if MTU has been updated */
  tc->snd_mss = clib_min (tc->mss, tc->rcv_opts.mss) - tc->snd_opts_len;
  ASSERT (tc->snd_mss > 0);

  tcp_options_write (tm->wrk_ctx[tc->c_thread_index].cached_opts,
		     &tc->snd_opts);

  tcp_update_rcv_wnd (tc);

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_check_app_limited (tc);

  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_cc_event (tc, TCP_CC_EVT_START_TX);
    }

  if (tc->flags & TCP_CONN_PSH_PENDING)
    {
      u32 max_deq = transport_max_tx_dequeue (&tc->connection);
      /* Last byte marked for push */
      tc->psh_seq = tc->snd_una + max_deq - 1;
    }
}

static void *
tcp_init_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  b->current_data = 0;
  vnet_buffer (b)->tcp.flags = 0;
  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);
}

/* Compute TCP checksum in software when offloading is disabled for a connection */
u16
ip6_tcp_compute_checksum_custom (vlib_main_t * vm, vlib_buffer_t * p0,
				 ip46_address_t * src, ip46_address_t * dst)
{
  ip_csum_t sum0;
  u16 payload_length_host_byte_order;
  u32 i;

  /* Initialize checksum with ip header. */
  sum0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0)) +
    clib_host_to_net_u16 (IP_PROTOCOL_TCP);
  payload_length_host_byte_order = vlib_buffer_length_in_chain (vm, p0);

  for (i = 0; i < ARRAY_LEN (src->ip6.as_uword); i++)
    {
      sum0 = ip_csum_with_carry
	(sum0, clib_mem_unaligned (&src->ip6.as_uword[i], uword));
      sum0 = ip_csum_with_carry
	(sum0, clib_mem_unaligned (&dst->ip6.as_uword[i], uword));
    }

  return ip_calculate_l4_checksum (vm, p0, sum0,
				   payload_length_host_byte_order, NULL, 0,
				   NULL);
}

u16
ip4_tcp_compute_checksum_custom (vlib_main_t * vm, vlib_buffer_t * p0,
				 ip46_address_t * src, ip46_address_t * dst)
{
  ip_csum_t sum0;
  u32 payload_length_host_byte_order;

  payload_length_host_byte_order = vlib_buffer_length_in_chain (vm, p0);
  sum0 =
    clib_host_to_net_u32 (payload_length_host_byte_order +
			  (IP_PROTOCOL_TCP << 16));

  sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&src->ip4, u32));
  sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&dst->ip4, u32));

  return ip_calculate_l4_checksum (vm, p0, sum0,
				   payload_length_host_byte_order, NULL, 0,
				   NULL);
}

static inline u16
tcp_compute_checksum (tcp_connection_t * tc, vlib_buffer_t * b)
{
  u16 checksum = 0;
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_NO_CSUM_OFFLOAD))
    {
      tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
      vlib_main_t *vm = wrk->vm;

      if (tc->c_is_ip4)
	checksum = ip4_tcp_compute_checksum_custom
	  (vm, b, &tc->c_lcl_ip, &tc->c_rmt_ip);
      else
	checksum = ip6_tcp_compute_checksum_custom
	  (vm, b, &tc->c_lcl_ip, &tc->c_rmt_ip);
    }
  else
    {
      vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }
  return checksum;
}

/**
 * Prepare ACK
 */
static inline void
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

  th->checksum = tcp_compute_checksum (tc, b);

  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;

  if (wnd == 0)
    {
      transport_rx_fifo_req_deq_ntf (&tc->connection);
      tcp_zero_rwnd_sent_on (tc);
    }
  else
    tcp_zero_rwnd_sent_off (tc);
}

/**
 * Convert buffer to ACK
 */
static inline void
tcp_make_ack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, TCP_FLAG_ACK);
  TCP_EVT (TCP_EVT_ACK_SENT, tc);
  tc->rcv_las = tc->rcv_nxt;
}

/**
 * Convert buffer to FIN-ACK
 */
static void
tcp_make_fin (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_ACK);
}

/**
 * Convert buffer to SYN
 */
void
tcp_make_syn (tcp_connection_t * tc, vlib_buffer_t * b)
{
  u8 tcp_hdr_opts_len, tcp_opts_len;
  tcp_header_t *th;
  u16 initial_wnd;
  tcp_options_t snd_opts;

  initial_wnd = tcp_initial_window_to_advertise (tc);

  /* Make and write options */
  clib_memset (&snd_opts, 0, sizeof (snd_opts));
  tcp_opts_len = tcp_make_syn_options (tc, &snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN,
			     initial_wnd);
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  tcp_options_write ((u8 *) (th + 1), &snd_opts);
  th->checksum = tcp_compute_checksum (tc, b);
}

/**
 * Convert buffer to SYN-ACK
 */
static void
tcp_make_synack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 initial_wnd;

  clib_memset (snd_opts, 0, sizeof (*snd_opts));
  initial_wnd = tcp_initial_window_to_advertise (tc);
  tcp_opts_len = tcp_make_synack_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len,
			     TCP_FLAG_SYN | TCP_FLAG_ACK, initial_wnd);
  tcp_options_write ((u8 *) (th + 1), snd_opts);

  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  th->checksum = tcp_compute_checksum (tc, b);
}

static void
tcp_enqueue_half_open (tcp_worker_ctx_t *wrk, tcp_connection_t *tc,
		       vlib_buffer_t *b, u32 bi)
{
  vlib_main_t *vm = wrk->vm;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  session_add_pending_tx_buffer (vm->thread_index, bi,
				 wrk->tco_next_node[!tc->c_is_ip4]);

  if (vm->thread_index == 0 && vlib_num_workers ())
    session_queue_run_on_main_thread (vm);
}

static void
tcp_enqueue_to_output (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
		       u8 is_ip4)
{
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  session_add_pending_tx_buffer (wrk->vm->thread_index, bi,
				 wrk->tco_next_node[!is_ip4]);
}

int
tcp_buffer_make_reset (vlib_main_t *vm, vlib_buffer_t *b, u8 is_ip4)
{
  ip4_address_t src_ip4 = {}, dst_ip4 = {};
  ip6_address_t src_ip6, dst_ip6;
  u16 src_port, dst_port;
  u32 tmp, len, seq, ack;
  ip4_header_t *ih4;
  ip6_header_t *ih6;
  tcp_header_t *th;
  u8 flags;

  /*
   * Find IP and TCP headers and glean information from them. Assumes
   * buffer was parsed by something like @ref tcp_input_lookup_buffer
   */
  th = tcp_buffer_hdr (b);

  if (is_ip4)
    {
      ih4 = vlib_buffer_get_current (b);
      ASSERT ((ih4->ip_version_and_header_length & 0xF0) == 0x40);
      src_ip4.as_u32 = ih4->src_address.as_u32;
      dst_ip4.as_u32 = ih4->dst_address.as_u32;
    }
  else
    {
      ih6 = vlib_buffer_get_current (b);
      ASSERT ((ih6->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60);
      clib_memcpy_fast (&src_ip6, &ih6->src_address, sizeof (ip6_address_t));
      clib_memcpy_fast (&dst_ip6, &ih6->dst_address, sizeof (ip6_address_t));
    }

  src_port = th->src_port;
  dst_port = th->dst_port;
  flags = TCP_FLAG_RST;

  /*
   * RFC 793. If the ACK bit is off, sequence number zero is used,
   *   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
   * If the ACK bit is on,
   *   <SEQ=SEG.ACK><CTL=RST>
   */
  if (tcp_ack (th))
    {
      seq = th->ack_number;
      ack = 0;
    }
  else
    {
      flags |= TCP_FLAG_ACK;
      tmp = clib_net_to_host_u32 (th->seq_number);
      len = vnet_buffer (b)->tcp.data_len + tcp_is_syn (th) + tcp_is_fin (th);
      ack = clib_host_to_net_u32 (tmp + len);
      seq = 0;
    }

  /*
   * Clear and reuse current buffer for reset
   */
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    vlib_buffer_free_one (vm, b->next_buffer);

  /* Zero all flags but free list index and trace flag */
  b->flags &= VLIB_BUFFER_NEXT_PRESENT - 1;
  /* Make sure new tcp header comes after current ip */
  b->current_data = ((u8 *) th - b->data) + sizeof (tcp_header_t);
  b->current_length = 0;
  b->total_length_not_including_first_buffer = 0;
  vnet_buffer (b)->tcp.flags = 0;

  /*
   * Add TCP and IP headers
   */
  th = vlib_buffer_push_tcp_net_order (b, dst_port, src_port, seq, ack,
				       sizeof (tcp_header_t), flags, 0);

  if (is_ip4)
    {
      ih4 = vlib_buffer_push_ip4 (vm, b, &dst_ip4, &src_ip4,
				  IP_PROTOCOL_TCP, 1);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih4);
    }
  else
    {
      int bogus = ~0;
      ih6 = vlib_buffer_push_ip6 (vm, b, &dst_ip6, &src_ip6, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih6, &bogus);
      ASSERT (!bogus);
    }

  return 0;
}

/**
 *  Send reset without reusing existing buffer
 *
 *  It extracts connection info out of original packet
 */
void
tcp_send_reset_w_pkt (tcp_connection_t * tc, vlib_buffer_t * pkt,
		      u32 thread_index, u8 is_ip4)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u8 tcp_hdr_len, flags = 0;
  tcp_header_t *th, *pkt_th;
  u32 seq, ack, bi;
  ip4_header_t *ih4, *pkt_ih4;
  ip6_header_t *ih6, *pkt_ih6;

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);

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
      ack = (tc->state >= TCP_STATE_SYN_RCVD) ? tc->rcv_nxt : 0;
      ack = clib_host_to_net_u32 (ack);
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
				  &pkt_ih4->src_address, IP_PROTOCOL_TCP,
				  tcp_csum_offload (tc));
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih4);
    }
  else
    {
      int bogus = ~0;
      ASSERT ((pkt_ih6->ip_version_traffic_class_and_flow_label & 0xF0) ==
	      0x60);
      ih6 = vlib_buffer_push_ip6_custom (vm, b, &pkt_ih6->dst_address,
					 &pkt_ih6->src_address,
					 IP_PROTOCOL_TCP,
					 tc->ipv6_flow_label);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih6, &bogus);
      ASSERT (!bogus);
    }

  tcp_enqueue_half_open (wrk, tc, b, bi);
  TCP_EVT (TCP_EVT_RST_SENT, tc);
  vlib_node_increment_counter (vm, tcp_node_index (output, tc->c_is_ip4),
			       TCP_ERROR_RST_SENT, 1);
}

/**
 * Build and set reset packet for connection
 */
void
tcp_send_reset (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;
  tcp_header_t *th;
  u16 tcp_hdr_opts_len, advertise_wnd, opts_write_len;
  u8 flags;

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);

  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);
  tcp_hdr_opts_len = tc->snd_opts_len + sizeof (tcp_header_t);
  advertise_wnd = tc->rcv_wnd >> tc->rcv_wscale;
  flags = TCP_FLAG_RST | TCP_FLAG_ACK;
  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
			     tc->rcv_nxt, tcp_hdr_opts_len, flags,
			     advertise_wnd);
  opts_write_len = tcp_options_write ((u8 *) (th + 1), &tc->snd_opts);
  th->checksum = tcp_compute_checksum (tc, b);
  ASSERT (opts_write_len == tc->snd_opts_len);
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
  TCP_EVT (TCP_EVT_RST_SENT, tc);
  vlib_node_increment_counter (vm, tcp_node_index (output, tc->c_is_ip4),
			       TCP_ERROR_RST_SENT, 1);
}

/**
 *  Send SYN
 *
 *  Builds a SYN packet for a half-open connection and sends it to tcp-output.
 *  The packet is handled by main thread and because half-open and established
 *  connections use the same pool the connection can be retrieved without
 *  additional logic.
 */
void
tcp_send_syn (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  /*
   * Setup retransmit and establish timers before requesting buffer
   * such that we can return if we've ran out.
   */
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN,
		    (u32) tc->rto * TCP_TO_TIMER_TICK);

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN,
			tcp_cfg.alloc_err_timeout);
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_syn (tc, b);

  /* Measure RTT with this */
  tc->rtt_ts = tcp_time_now_us (vlib_num_workers ()? 1 : 0);
  tc->rtt_seq = tc->snd_nxt;
  tc->rto_boff = 0;

  tcp_enqueue_half_open (wrk, tc, b, bi);
  TCP_EVT (TCP_EVT_SYN_SENT, tc);
}

void
tcp_send_synack (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  ASSERT (tc->snd_una != tc->snd_nxt);
  tcp_retransmit_timer_update (&wrk->timer_wheel, tc);

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT,
			tcp_cfg.alloc_err_timeout);
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  tc->rtt_ts = tcp_time_now_us (tc->c_thread_index);
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_synack (tc, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
  TCP_EVT (TCP_EVT_SYNACK_SENT, tc);
}

/**
 *  Send FIN
 */
void
tcp_send_fin (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;
  u8 fin_snt = 0;

  fin_snt = tc->flags & TCP_CONN_FINSNT;
  if (fin_snt)
    tc->snd_nxt -= 1;

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      /* Out of buffers so program fin retransmit ASAP */
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT,
			tcp_cfg.alloc_err_timeout);
      if (fin_snt)
	tc->snd_nxt += 1;
      else
	/* Make sure retransmit retries a fin not data */
	tc->flags |= TCP_CONN_FINSNT;
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  /* If we have non-dupacks programmed, no need to send them */
  if ((tc->flags & TCP_CONN_SNDACK) && !tc->pending_dupacks)
    tc->flags &= ~TCP_CONN_SNDACK;

  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_fin (tc, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
  TCP_EVT (TCP_EVT_FIN_SENT, tc);
  /* Account for the FIN */
  tc->snd_nxt += 1;
  tcp_retransmit_timer_update (&wrk->timer_wheel, tc);
  if (!fin_snt)
    {
      tc->flags |= TCP_CONN_FINSNT;
      tc->flags &= ~TCP_CONN_FINPNDG;
    }
}

/**
 * Push TCP header and update connection variables. Should only be called
 * for segments with data, not for 'control' packets.
 */
always_inline void
tcp_push_hdr_i (tcp_connection_t * tc, vlib_buffer_t * b, u32 snd_nxt,
		u8 compute_opts, u8 maybe_burst, u8 update_snd_nxt)
{
  u8 tcp_hdr_opts_len, flags = TCP_FLAG_ACK;
  u32 advertise_wnd, data_len;
  tcp_main_t *tm = &tcp_main;
  tcp_header_t *th;

  data_len = b->current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    data_len += b->total_length_not_including_first_buffer;

  vnet_buffer (b)->tcp.flags = 0;
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;

  if (compute_opts)
    tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);

  tcp_hdr_opts_len = tc->snd_opts_len + sizeof (tcp_header_t);

  if (maybe_burst)
    advertise_wnd = tc->rcv_wnd >> tc->rcv_wscale;
  else
    advertise_wnd = tcp_window_to_advertise (tc, TCP_STATE_ESTABLISHED);

  if (PREDICT_FALSE (tc->flags & TCP_CONN_PSH_PENDING))
    {
      if (seq_geq (tc->psh_seq, snd_nxt)
	  && seq_lt (tc->psh_seq, snd_nxt + data_len))
	flags |= TCP_FLAG_PSH;
    }
  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, snd_nxt,
			     tc->rcv_nxt, tcp_hdr_opts_len, flags,
			     advertise_wnd);

  if (maybe_burst)
    {
      clib_memcpy_fast ((u8 *) (th + 1),
			tm->wrk_ctx[tc->c_thread_index].cached_opts,
			tc->snd_opts_len);
    }
  else
    {
      u8 len = tcp_options_write ((u8 *) (th + 1), &tc->snd_opts);
      ASSERT (len == tc->snd_opts_len);
    }

  /*
   * Update connection variables
   */

  if (update_snd_nxt)
    tc->snd_nxt += data_len;
  tc->rcv_las = tc->rcv_nxt;

  tc->bytes_out += data_len;
  tc->data_segs_out += 1;

  th->checksum = tcp_compute_checksum (tc, b);

  TCP_EVT (TCP_EVT_PKTIZE, tc);
}

always_inline u32
tcp_buffer_len (vlib_buffer_t * b)
{
  u32 data_len = b->current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    data_len += b->total_length_not_including_first_buffer;
  return data_len;
}

always_inline u32
tcp_push_one_header (tcp_connection_t *tc, vlib_buffer_t *b)
{
  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_track_tx (tc, tcp_buffer_len (b));

  tcp_push_hdr_i (tc, b, tc->snd_nxt, /* compute opts */ 0, /* burst */ 1,
		  /* update_snd_nxt */ 1);

  tcp_validate_txf_size (tc, tc->snd_nxt - tc->snd_una);
  return 0;
}

u32
tcp_session_push_header (transport_connection_t *tconn, vlib_buffer_t **bs,
			 u32 n_bufs)
{
  tcp_connection_t *tc = (tcp_connection_t *) tconn;

  while (n_bufs >= 4)
    {
      vlib_prefetch_buffer_header (bs[2], STORE);
      vlib_prefetch_buffer_header (bs[3], STORE);

      tcp_push_one_header (tc, bs[0]);
      tcp_push_one_header (tc, bs[1]);

      n_bufs -= 2;
      bs += 2;
    }
  while (n_bufs)
    {
      if (n_bufs > 1)
	vlib_prefetch_buffer_header (bs[1], STORE);

      tcp_push_one_header (tc, bs[0]);

      n_bufs -= 1;
      bs += 1;
    }

  /* If not tracking an ACK, start tracking */
  if (tc->rtt_ts == 0 && !tcp_in_cong_recovery (tc))
    {
      tc->rtt_ts = tcp_time_now_us (tc->c_thread_index);
      tc->rtt_seq = tc->snd_nxt;
    }
  if (PREDICT_FALSE (!tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT)))
    {
      tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
      tcp_retransmit_timer_set (&wrk->timer_wheel, tc);
      tc->rto_boff = 0;
    }
  return 0;
}

void
tcp_send_ack (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_update_rcv_wnd (tc);
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_ack (tc, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
}

void
tcp_program_ack (tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_SNDACK))
    {
      session_add_self_custom_tx_evt (&tc->connection, 1);
      tc->flags |= TCP_CONN_SNDACK;
    }
}

void
tcp_program_dupack (tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_SNDACK))
    {
      session_add_self_custom_tx_evt (&tc->connection, 1);
      tc->flags |= TCP_CONN_SNDACK;
    }
  if (tc->pending_dupacks < 255)
    tc->pending_dupacks += 1;
}

void
tcp_program_retransmit (tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_RXT_PENDING))
    {
      session_add_self_custom_tx_evt (&tc->connection, 0);
      tc->flags |= TCP_CONN_RXT_PENDING;
    }
}

/**
 * Send window update ack
 *
 * Ensures that it will be sent only once, after a zero rwnd has been
 * advertised in a previous ack, and only if rwnd has grown beyond a
 * configurable value.
 */
void
tcp_send_window_update_ack (tcp_connection_t * tc)
{
  if (tcp_zero_rwnd_sent (tc))
    {
      tcp_update_rcv_wnd (tc);
      if (tc->rcv_wnd >= tcp_cfg.rwnd_min_update_ack * tc->snd_mss)
	{
	  tcp_zero_rwnd_sent_off (tc);
	  tcp_program_ack (tc);
	}
    }
}

/**
 * Allocate a new buffer and build a new tcp segment
 *
 * @param wrk		tcp worker
 * @param tc		connection for which the segment will be allocated
 * @param offset	offset of the first byte in the tx fifo
 * @param max_deq_byte	segment size
 * @param[out] b	pointer to buffer allocated
 *
 * @return 	the number of bytes in the segment or 0 if buffer cannot be
 * 		allocated or no data available
 */
static int
tcp_prepare_segment (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		     u32 offset, u32 max_deq_bytes, vlib_buffer_t ** b)
{
  u32 bytes_per_buffer = vnet_get_tcp_main ()->bytes_per_buffer;
  vlib_main_t *vm = wrk->vm;
  u32 bi, seg_size;
  int n_bytes = 0;
  u8 *data;

  seg_size = max_deq_bytes + TRANSPORT_MAX_HDRS_LEN;

  /*
   * Prepare options
   */
  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);

  /*
   * Allocate and fill in buffer(s)
   */

  /* Easy case, buffer size greater than mss */
  if (PREDICT_TRUE (seg_size <= bytes_per_buffer))
    {
      if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
	{
	  tcp_worker_stats_inc (wrk, no_buffer, 1);
	  return 0;
	}
      *b = vlib_get_buffer (vm, bi);
      data = tcp_init_buffer (vm, *b);
      n_bytes = session_tx_fifo_peek_bytes (&tc->connection, data, offset,
					    max_deq_bytes);
      ASSERT (n_bytes == max_deq_bytes);
      b[0]->current_length = n_bytes;
      tcp_push_hdr_i (tc, *b, tc->snd_una + offset, /* compute opts */ 0,
		      /* burst */ 0, /* update_snd_nxt */ 0);
    }
  /* Split mss into multiple buffers */
  else
    {
      u32 chain_bi = ~0, n_bufs_per_seg, n_bufs;
      u16 n_peeked, len_to_deq;
      vlib_buffer_t *chain_b, *prev_b;
      int i;

      /* Make sure we have enough buffers */
      n_bufs_per_seg = ceil ((double) seg_size / bytes_per_buffer);
      vec_validate_aligned (wrk->tx_buffers, n_bufs_per_seg - 1,
			    CLIB_CACHE_LINE_BYTES);
      n_bufs = vlib_buffer_alloc (vm, wrk->tx_buffers, n_bufs_per_seg);
      if (PREDICT_FALSE (n_bufs != n_bufs_per_seg))
	{
	  if (n_bufs)
	    vlib_buffer_free (vm, wrk->tx_buffers, n_bufs);
	  tcp_worker_stats_inc (wrk, no_buffer, 1);
	  return 0;
	}

      *b = vlib_get_buffer (vm, wrk->tx_buffers[--n_bufs]);
      data = tcp_init_buffer (vm, *b);
      n_bytes = session_tx_fifo_peek_bytes (&tc->connection, data, offset,
					    bytes_per_buffer -
					    TRANSPORT_MAX_HDRS_LEN);
      b[0]->current_length = n_bytes;
      b[0]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      b[0]->total_length_not_including_first_buffer = 0;
      max_deq_bytes -= n_bytes;

      chain_b = *b;
      for (i = 1; i < n_bufs_per_seg; i++)
	{
	  prev_b = chain_b;
	  len_to_deq = clib_min (max_deq_bytes, bytes_per_buffer);
	  chain_bi = wrk->tx_buffers[--n_bufs];
	  chain_b = vlib_get_buffer (vm, chain_bi);
	  chain_b->current_data = 0;
	  data = vlib_buffer_get_current (chain_b);
	  n_peeked = session_tx_fifo_peek_bytes (&tc->connection, data,
						 offset + n_bytes,
						 len_to_deq);
	  ASSERT (n_peeked == len_to_deq);
	  n_bytes += n_peeked;
	  chain_b->current_length = n_peeked;
	  chain_b->next_buffer = 0;

	  /* update previous buffer */
	  prev_b->next_buffer = chain_bi;
	  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

	  max_deq_bytes -= n_peeked;
	  b[0]->total_length_not_including_first_buffer += n_peeked;
	}

      tcp_push_hdr_i (tc, *b, tc->snd_una + offset, /* compute opts */ 0,
		      /* burst */ 0, /* update_snd_nxt */ 0);

      if (PREDICT_FALSE (n_bufs))
	{
	  clib_warning ("not all buffers consumed");
	  vlib_buffer_free (vm, wrk->tx_buffers, n_bufs);
	}
    }

  ASSERT (n_bytes > 0);
  ASSERT (((*b)->current_data + (*b)->current_length) <= bytes_per_buffer);

  return n_bytes;
}

/**
 * Build a retransmit segment
 *
 * @return the number of bytes in the segment or 0 if there's nothing to
 *         retransmit
 */
static u32
tcp_prepare_retransmit_segment (tcp_worker_ctx_t * wrk,
				tcp_connection_t * tc, u32 offset,
				u32 max_deq_bytes, vlib_buffer_t ** b)
{
  u32 start, available_bytes;
  int n_bytes = 0;

  ASSERT (tc->state >= TCP_STATE_ESTABLISHED);
  ASSERT (max_deq_bytes != 0);

  /*
   * Make sure we can retransmit something
   */
  available_bytes = transport_max_tx_dequeue (&tc->connection);
  ASSERT (available_bytes >= offset);
  available_bytes -= offset;
  if (!available_bytes)
    return 0;

  max_deq_bytes = clib_min (tc->snd_mss, max_deq_bytes);
  max_deq_bytes = clib_min (available_bytes, max_deq_bytes);

  start = tc->snd_una + offset;
  ASSERT (seq_leq (start + max_deq_bytes, tc->snd_nxt));

  n_bytes = tcp_prepare_segment (wrk, tc, offset, max_deq_bytes, b);
  if (!n_bytes)
    return 0;

  tc->snd_rxt_bytes += n_bytes;

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_track_rxt (tc, start, start + n_bytes);

  tc->bytes_retrans += n_bytes;
  tc->segs_retrans += 1;
  tcp_worker_stats_inc (wrk, rxt_segs, 1);
  TCP_EVT (TCP_EVT_CC_RTX, tc, offset, n_bytes);

  return n_bytes;
}

static void
tcp_check_sack_reneging (tcp_connection_t * tc)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_scoreboard_hole_t *hole;

  hole = scoreboard_first_hole (sb);
  if (!sb->is_reneging && (!hole || hole->start == tc->snd_una))
    return;

  scoreboard_clear_reneging (sb, tc->snd_una, tc->snd_nxt);
}

/**
 * Reset congestion control, switch cwnd to loss window and try again.
 */
static void
tcp_cc_init_rxt_timeout (tcp_connection_t * tc)
{
  TCP_EVT (TCP_EVT_CC_EVT, tc, 6);

  tc->prev_ssthresh = tc->ssthresh;
  tc->prev_cwnd = tc->cwnd;

  /* If we entrered loss without fast recovery, notify cc algo of the
   * congestion event such that it can update ssthresh and its state */
  if (!tcp_in_fastrecovery (tc))
    tcp_cc_congestion (tc);

  /* Let cc algo decide loss cwnd and ssthresh post unrecovered loss */
  tcp_cc_loss (tc);

  tc->rtt_ts = 0;
  tc->cwnd_acc_bytes = 0;
  tc->tr_occurences += 1;
  tc->sack_sb.reorder = TCP_DUPACK_THRESHOLD;
  tcp_recovery_on (tc);
}

void
tcp_timer_retransmit_handler (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;
  u32 bi, n_bytes;

  tcp_worker_stats_inc (wrk, tr_events, 1);

  /* Should be handled by a different handler */
  if (PREDICT_FALSE (tc->state == TCP_STATE_SYN_SENT))
    return;

  /* Wait-close and retransmit could pop at the same time */
  if (tc->state == TCP_STATE_CLOSED)
    return;

  if (tc->state >= TCP_STATE_ESTABLISHED)
    {
      TCP_EVT (TCP_EVT_CC_EVT, tc, 2);

      /* Lost FIN, retransmit and return */
      if (tc->flags & TCP_CONN_FINSNT)
	{
	  tcp_send_fin (tc);
	  tc->rto_boff += 1;
	  tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);
	  return;
	}

      /* Shouldn't be here */
      if (tc->snd_una == tc->snd_nxt)
	{
	  ASSERT (!tcp_in_recovery (tc));
	  tc->rto_boff = 0;
	  return;
	}

      /* We're not in recovery so make sure rto_boff is 0. Can be non 0 due
       * to persist timer timeout */
      if (!tcp_in_recovery (tc) && tc->rto_boff > 0)
	{
	  tc->rto_boff = 0;
	  tcp_update_rto (tc);
	}

      /* Peer is dead or network connectivity is lost. Close connection.
       * RFC 1122 section 4.2.3.5 recommends a value of at least 100s. For
       * a min rto of 0.2s we need to retry about 8 times. */
      if (tc->rto_boff >= TCP_RTO_BOFF_MAX)
	{
	  tcp_send_reset (tc);
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  session_transport_closing_notify (&tc->connection);
	  session_transport_closed_notify (&tc->connection);
	  tcp_connection_timers_reset (tc);
	  tcp_program_cleanup (wrk, tc);
	  tcp_worker_stats_inc (wrk, tr_abort, 1);
	  return;
	}

      if (tcp_opts_sack_permitted (&tc->rcv_opts))
	{
	  tcp_check_sack_reneging (tc);
	  scoreboard_rxt_mark_lost (&tc->sack_sb, tc->snd_una, tc->snd_nxt);
	}

      /* Update send congestion to make sure that rxt has data to send */
      tc->snd_congestion = tc->snd_nxt;

      /* Send the first unacked segment. If we're short on buffers, return
       * as soon as possible */
      n_bytes = clib_min (tc->snd_mss, tc->snd_nxt - tc->snd_una);
      n_bytes = tcp_prepare_retransmit_segment (wrk, tc, 0, n_bytes, &b);
      if (!n_bytes)
	{
	  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT,
			    tcp_cfg.alloc_err_timeout);
	  return;
	}

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

      tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);

      tc->rto_boff += 1;
      if (tc->rto_boff == 1)
	{
	  tcp_cc_init_rxt_timeout (tc);
	  /* Record timestamp. Eifel detection algorithm RFC3522 */
	  tc->snd_rxt_ts = tcp_tstamp (tc);
	}

      if (tcp_opts_sack_permitted (&tc->rcv_opts))
	scoreboard_init_rxt (&tc->sack_sb, tc->snd_una + n_bytes);

      tcp_program_retransmit (tc);
    }
  /* Retransmit SYN-ACK */
  else if (tc->state == TCP_STATE_SYN_RCVD)
    {
      TCP_EVT (TCP_EVT_CC_EVT, tc, 2);

      tc->rtt_ts = 0;

      /* Passive open establish timeout */
      if (tc->rto > TCP_ESTABLISH_TIME >> 1)
	{
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  tcp_connection_timers_reset (tc);
	  tcp_program_cleanup (wrk, tc);
	  tcp_worker_stats_inc (wrk, tr_abort, 1);
	  return;
	}

      if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
	{
	  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT,
			    tcp_cfg.alloc_err_timeout);
	  tcp_worker_stats_inc (wrk, no_buffer, 1);
	  return;
	}

      tc->rto_boff += 1;
      if (tc->rto_boff > TCP_RTO_SYN_RETRIES)
	tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

      ASSERT (tc->snd_una != tc->snd_nxt);
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);

      b = vlib_get_buffer (vm, bi);
      tcp_init_buffer (vm, b);
      tcp_make_synack (tc, b);
      TCP_EVT (TCP_EVT_SYN_RXT, tc, 1);

      /* Retransmit timer already updated, just enqueue to output */
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
    }
  else
    {
      ASSERT (tc->state == TCP_STATE_CLOSED);
      return;
    }
}

/**
 * SYN retransmit timer handler. Active open only.
 */
void
tcp_timer_retransmit_syn_handler (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;
  u32 bi;

  /* Note: the connection may have transitioned to ESTABLISHED... */
  if (PREDICT_FALSE (tc->state != TCP_STATE_SYN_SENT))
    return;

  /* Half-open connection actually moved to established but we were
   * waiting for syn retransmit to pop to call cleanup from the right
   * thread. */
  if (tc->flags & TCP_CONN_HALF_OPEN_DONE)
    {
      if (tcp_half_open_connection_cleanup (tc))
	TCP_DBG ("could not remove half-open connection");
      return;
    }

  TCP_EVT (TCP_EVT_CC_EVT, tc, 2);
  tc->rtt_ts = 0;

  /* Active open establish timeout */
  if (tc->rto >= TCP_ESTABLISH_TIME >> 1)
    {
      session_stream_connect_notify (&tc->connection, SESSION_E_TIMEDOUT);
      tcp_connection_cleanup (tc);
      return;
    }

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN,
			tcp_cfg.alloc_err_timeout);
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  /* Try without increasing RTO a number of times. If this fails,
   * start growing RTO exponentially */
  tc->rto_boff += 1;
  if (tc->rto_boff > TCP_RTO_SYN_RETRIES)
    tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_syn (tc, b);

  TCP_EVT (TCP_EVT_SYN_RXT, tc, 0);

  tcp_enqueue_half_open (wrk, tc, b, bi);

  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN,
		    (u32) tc->rto * TCP_TO_TIMER_TICK);
}

/**
 * Got 0 snd_wnd from peer, try to do something about it.
 *
 */
void
tcp_timer_persist_handler (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  u32 bi, max_snd_bytes, available_bytes, offset;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  int n_bytes = 0;
  u8 *data;

  /* Problem already solved or worse */
  if (tc->state == TCP_STATE_CLOSED || tc->snd_wnd > tc->snd_mss
      || (tc->flags & TCP_CONN_FINSNT))
    goto update_scheduler;

  available_bytes = transport_max_tx_dequeue (&tc->connection);
  offset = tc->snd_nxt - tc->snd_una;

  /* Reprogram persist if no new bytes available to send. We may have data
   * next time */
  if (!available_bytes)
    {
      tcp_persist_timer_set (&wrk->timer_wheel, tc);
      return;
    }

  if (available_bytes <= offset)
    goto update_scheduler;

  /* Increment RTO backoff */
  tc->rto_boff += 1;
  tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

  /*
   * Try to force the first unsent segment (or buffer)
   */
  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      tcp_persist_timer_set (&wrk->timer_wheel, tc);
      tcp_worker_stats_inc (wrk, no_buffer, 1);
      return;
    }

  b = vlib_get_buffer (vm, bi);
  data = tcp_init_buffer (vm, b);

  tcp_validate_txf_size (tc, offset);
  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);
  max_snd_bytes = clib_min (tc->snd_mss,
			    tm->bytes_per_buffer - TRANSPORT_MAX_HDRS_LEN);
  n_bytes = session_tx_fifo_peek_bytes (&tc->connection, data, offset,
					max_snd_bytes);
  b->current_length = n_bytes;
  ASSERT (n_bytes != 0 && (tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT)
			   || tc->snd_una == tc->snd_nxt
			   || tc->rto_boff > 1));

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    {
      tcp_bt_check_app_limited (tc);
      tcp_bt_track_tx (tc, n_bytes);
    }

  tcp_push_hdr_i (tc, b, tc->snd_nxt, /* compute opts */ 0,
		  /* burst */ 0, /* update_snd_nxt */ 1);
  tcp_validate_txf_size (tc, tc->snd_nxt - tc->snd_una);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

  /* Just sent new data, enable retransmit */
  tcp_retransmit_timer_update (&wrk->timer_wheel, tc);

  return;

update_scheduler:

  if (tcp_is_descheduled (tc))
    transport_connection_reschedule (&tc->connection);
}

/**
 * Retransmit first unacked segment
 */
int
tcp_retransmit_first_unacked (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi, n_bytes;

  TCP_EVT (TCP_EVT_CC_EVT, tc, 1);

  n_bytes = tcp_prepare_retransmit_segment (wrk, tc, 0, tc->snd_mss, &b);
  if (!n_bytes)
    return -1;

  bi = vlib_get_buffer_index (vm, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

  return 0;
}

static int
tcp_transmit_unsent (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		     u32 burst_size)
{
  u32 offset, n_segs = 0, n_written, bi, available_wnd;
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;

  offset = tc->snd_nxt - tc->snd_una;
  available_wnd = tc->snd_wnd - offset;
  burst_size = clib_min (burst_size, available_wnd / tc->snd_mss);

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_check_app_limited (tc);

  while (n_segs < burst_size)
    {
      n_written = tcp_prepare_segment (wrk, tc, offset, tc->snd_mss, &b);
      if (!n_written)
	goto done;

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
      offset += n_written;
      n_segs += 1;

      if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
	tcp_bt_track_tx (tc, n_written);

      tc->snd_nxt += n_written;
    }

done:
  return n_segs;
}

/**
 * Estimate send space using proportional rate reduction (RFC6937)
 */
int
tcp_fastrecovery_prr_snd_space (tcp_connection_t * tc)
{
  u32 pipe, prr_out;
  int space;

  pipe = tcp_flight_size (tc);
  prr_out = tc->snd_rxt_bytes + (tc->snd_nxt - tc->snd_congestion);

  if (pipe > tc->ssthresh)
    {
      space = ((int) tc->prr_delivered * ((f64) tc->ssthresh / tc->prev_cwnd))
	- prr_out;
    }
  else
    {
      int limit;
      limit = clib_max ((int) (tc->prr_delivered - prr_out), 0) + tc->snd_mss;
      space = clib_min (tc->ssthresh - pipe, limit);
    }
  space = clib_max (space, prr_out ? 0 : tc->snd_mss);
  return space;
}

static inline u8
tcp_retransmit_should_retry_head (tcp_connection_t * tc,
				  sack_scoreboard_t * sb)
{
  u32 tx_adv_sack = sb->high_sacked - tc->snd_congestion;
  f64 rr = (f64) tc->ssthresh / tc->prev_cwnd;

  if (tcp_fastrecovery_first (tc))
    return 1;

  return (tx_adv_sack > (tc->snd_una - tc->prr_start) * rr);
}

static inline u8
tcp_max_tx_deq (tcp_connection_t * tc)
{
  return (transport_max_tx_dequeue (&tc->connection)
	  - (tc->snd_nxt - tc->snd_una));
}

#define scoreboard_rescue_rxt_valid(_sb, _tc)			\
    (seq_geq (_sb->rescue_rxt, _tc->snd_una) 			\
	&& seq_leq (_sb->rescue_rxt, _tc->snd_congestion))

/**
 * Do retransmit with SACKs
 */
static int
tcp_retransmit_sack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		     u32 burst_size)
{
  u32 n_written = 0, offset, max_bytes, n_segs = 0;
  u8 snd_limited = 0, can_rescue = 0;
  u32 bi, max_deq, burst_bytes;
  sack_scoreboard_hole_t *hole;
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;
  sack_scoreboard_t *sb;
  int snd_space;

  ASSERT (tcp_in_cong_recovery (tc));

  burst_bytes = transport_connection_tx_pacer_burst (&tc->connection);
  burst_size = clib_min (burst_size, burst_bytes / tc->snd_mss);
  if (!burst_size)
    {
      tcp_program_retransmit (tc);
      return 0;
    }

  if (tcp_in_recovery (tc))
    snd_space = tcp_available_cc_snd_space (tc);
  else
    snd_space = tcp_fastrecovery_prr_snd_space (tc);

  if (snd_space < tc->snd_mss)
    goto done;

  sb = &tc->sack_sb;

  /* Check if snd_una is a lost retransmit */
  if (pool_elts (sb->holes)
      && seq_gt (sb->high_sacked, tc->snd_congestion)
      && tc->rxt_head != tc->snd_una
      && tcp_retransmit_should_retry_head (tc, sb))
    {
      max_bytes = clib_min (tc->snd_mss, tc->snd_congestion - tc->snd_una);
      n_written = tcp_prepare_retransmit_segment (wrk, tc, 0, max_bytes, &b);
      if (!n_written)
	{
	  tcp_program_retransmit (tc);
	  goto done;
	}
      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
      n_segs = 1;

      tc->rxt_head = tc->snd_una;
      tc->rxt_delivered += n_written;
      tc->prr_delivered += n_written;
      ASSERT (tc->rxt_delivered <= tc->snd_rxt_bytes);
    }

  tcp_fastrecovery_first_off (tc);

  TCP_EVT (TCP_EVT_CC_EVT, tc, 0);
  hole = scoreboard_get_hole (sb, sb->cur_rxt_hole);

  max_deq = transport_max_tx_dequeue (&tc->connection);
  max_deq -= tc->snd_nxt - tc->snd_una;

  while (snd_space > 0 && n_segs < burst_size)
    {
      hole = scoreboard_next_rxt_hole (sb, hole, max_deq != 0, &can_rescue,
				       &snd_limited);
      if (!hole)
	{
	  /* We are out of lost holes to retransmit so send some new data. */
	  if (max_deq > tc->snd_mss)
	    {
	      u32 n_segs_new;
	      int av_wnd;

	      /* Make sure we don't exceed available window and leave space
	       * for one more packet, to avoid zero window acks */
	      av_wnd = (int) tc->snd_wnd - (tc->snd_nxt - tc->snd_una);
	      av_wnd = clib_max (av_wnd - tc->snd_mss, 0);
	      snd_space = clib_min (snd_space, av_wnd);
	      snd_space = clib_min (max_deq, snd_space);
	      burst_size = clib_min (burst_size - n_segs,
				     snd_space / tc->snd_mss);
	      burst_size = clib_min (burst_size, TCP_RXT_MAX_BURST);
	      n_segs_new = tcp_transmit_unsent (wrk, tc, burst_size);
	      if (max_deq > n_segs_new * tc->snd_mss)
		tcp_program_retransmit (tc);

	      n_segs += n_segs_new;
	      goto done;
	    }

	  if (tcp_in_recovery (tc) || !can_rescue
	      || scoreboard_rescue_rxt_valid (sb, tc))
	    break;

	  /* If rescue rxt undefined or less than snd_una then one segment of
	   * up to SMSS octets that MUST include the highest outstanding
	   * unSACKed sequence number SHOULD be returned, and RescueRxt set to
	   * RecoveryPoint. HighRxt MUST NOT be updated.
	   */
	  hole = scoreboard_last_hole (sb);
	  max_bytes = clib_min (tc->snd_mss, hole->end - hole->start);
	  max_bytes = clib_min (max_bytes, snd_space);
	  offset = hole->end - tc->snd_una - max_bytes;
	  n_written = tcp_prepare_retransmit_segment (wrk, tc, offset,
						      max_bytes, &b);
	  if (!n_written)
	    goto done;

	  sb->rescue_rxt = tc->snd_congestion;
	  bi = vlib_get_buffer_index (vm, b);
	  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
	  n_segs += 1;
	  break;
	}

      max_bytes = clib_min (hole->end - sb->high_rxt, snd_space);
      max_bytes = snd_limited ? clib_min (max_bytes, tc->snd_mss) : max_bytes;
      if (max_bytes == 0)
	break;

      offset = sb->high_rxt - tc->snd_una;
      n_written = tcp_prepare_retransmit_segment (wrk, tc, offset, max_bytes,
						  &b);
      ASSERT (n_written <= snd_space);

      /* Nothing left to retransmit */
      if (n_written == 0)
	break;

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

      sb->high_rxt += n_written;
      ASSERT (seq_leq (sb->high_rxt, tc->snd_nxt));

      snd_space -= n_written;
      n_segs += 1;
    }

  if (hole)
    tcp_program_retransmit (tc);

done:

  transport_connection_tx_pacer_reset_bucket (&tc->connection, 0);
  return n_segs;
}

/**
 * Fast retransmit without SACK info
 */
static int
tcp_retransmit_no_sack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
			u32 burst_size)
{
  u32 n_written = 0, offset = 0, bi, max_deq, n_segs_now, max_bytes;
  u32 burst_bytes, sent_bytes;
  vlib_main_t *vm = wrk->vm;
  int snd_space, n_segs = 0;
  u8 cc_limited = 0;
  vlib_buffer_t *b;

  ASSERT (tcp_in_cong_recovery (tc));
  TCP_EVT (TCP_EVT_CC_EVT, tc, 0);

  burst_bytes = transport_connection_tx_pacer_burst (&tc->connection);
  burst_size = clib_min (burst_size, burst_bytes / tc->snd_mss);
  if (!burst_size)
    {
      tcp_program_retransmit (tc);
      return 0;
    }

  snd_space = tcp_available_cc_snd_space (tc);
  cc_limited = snd_space < burst_bytes;

  if (!tcp_fastrecovery_first (tc))
    goto send_unsent;

  /* RFC 6582: [If a partial ack], retransmit the first unacknowledged
   * segment. */
  while (snd_space > 0 && n_segs < burst_size)
    {
      max_bytes = clib_min (tc->snd_mss,
			    tc->snd_congestion - tc->snd_una - offset);
      if (!max_bytes)
	break;
      n_written = tcp_prepare_retransmit_segment (wrk, tc, offset, max_bytes,
						  &b);

      /* Nothing left to retransmit */
      if (n_written == 0)
	break;

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
      snd_space -= n_written;
      offset += n_written;
      n_segs += 1;
    }

  if (n_segs == burst_size)
    goto done;

send_unsent:

  /* RFC 6582: Send a new segment if permitted by the new value of cwnd. */
  if (snd_space < tc->snd_mss || tc->snd_mss == 0)
    goto done;

  max_deq = transport_max_tx_dequeue (&tc->connection);
  max_deq -= tc->snd_nxt - tc->snd_una;
  if (max_deq)
    {
      snd_space = clib_min (max_deq, snd_space);
      burst_size = clib_min (burst_size - n_segs, snd_space / tc->snd_mss);
      n_segs_now = tcp_transmit_unsent (wrk, tc, burst_size);
      if (n_segs_now && max_deq > n_segs_now * tc->snd_mss)
	tcp_program_retransmit (tc);
      n_segs += n_segs_now;
    }

done:
  tcp_fastrecovery_first_off (tc);

  sent_bytes = clib_min (n_segs * tc->snd_mss, burst_bytes);
  sent_bytes = cc_limited ? burst_bytes : sent_bytes;
  transport_connection_tx_pacer_update_bytes (&tc->connection, sent_bytes);

  return n_segs;
}

static int
tcp_send_acks (tcp_connection_t * tc, u32 max_burst_size)
{
  int j, n_acks;

  if (!tc->pending_dupacks)
    {
      if (tcp_in_cong_recovery (tc) || !tcp_max_tx_deq (tc)
	  || tc->state != TCP_STATE_ESTABLISHED)
	{
	  tcp_send_ack (tc);
	  return 1;
	}
      return 0;
    }

  /* If we're supposed to send dupacks but have no ooo data
   * send only one ack */
  if (!vec_len (tc->snd_sacks))
    {
      tcp_send_ack (tc);
      tc->dupacks_out += 1;
      tc->pending_dupacks = 0;
      return 1;
    }

  /* Start with first sack block */
  tc->snd_sack_pos = 0;

  /* Generate enough dupacks to cover all sack blocks. Do not generate
   * more sacks than the number of packets received. But do generate at
   * least 3, i.e., the number needed to signal congestion, if needed. */
  n_acks = vec_len (tc->snd_sacks) / TCP_OPTS_MAX_SACK_BLOCKS;
  n_acks = clib_min (n_acks, tc->pending_dupacks);
  n_acks = clib_max (n_acks, clib_min (tc->pending_dupacks, 3));
  for (j = 0; j < clib_min (n_acks, max_burst_size); j++)
    tcp_send_ack (tc);

  if (n_acks < max_burst_size)
    {
      tc->pending_dupacks = 0;
      tc->snd_sack_pos = 0;
      tc->dupacks_out += n_acks;
      return n_acks;
    }
  else
    {
      TCP_DBG ("constrained by burst size");
      tc->pending_dupacks = n_acks - max_burst_size;
      tc->dupacks_out += max_burst_size;
      tcp_program_dupack (tc);
      return max_burst_size;
    }
}

static int
tcp_do_retransmit (tcp_connection_t * tc, u32 max_burst_size)
{
  tcp_worker_ctx_t *wrk;
  u32 n_segs;

  if (PREDICT_FALSE (tc->state == TCP_STATE_CLOSED))
    return 0;

  wrk = tcp_get_worker (tc->c_thread_index);

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    n_segs = tcp_retransmit_sack (wrk, tc, max_burst_size);
  else
    n_segs = tcp_retransmit_no_sack (wrk, tc, max_burst_size);

  return n_segs;
}

int
tcp_session_custom_tx (void *conn, transport_send_params_t * sp)
{
  tcp_connection_t *tc = (tcp_connection_t *) conn;
  u32 n_segs = 0;

  if (tcp_in_cong_recovery (tc) && (tc->flags & TCP_CONN_RXT_PENDING))
    {
      tc->flags &= ~TCP_CONN_RXT_PENDING;
      n_segs = tcp_do_retransmit (tc, sp->max_burst_size);
    }

  if (!(tc->flags & TCP_CONN_SNDACK))
    return n_segs;

  tc->flags &= ~TCP_CONN_SNDACK;

  /* We have retransmitted packets and no dupack */
  if (n_segs && !tc->pending_dupacks)
    return n_segs;

  if (sp->max_burst_size <= n_segs)
    {
      tcp_program_ack (tc);
      return n_segs;
    }

  n_segs += tcp_send_acks (tc, sp->max_burst_size - n_segs);

  return n_segs;
}
#endif /* CLIB_MARCH_VARIANT */

static void
tcp_output_handle_link_local (tcp_connection_t * tc0, vlib_buffer_t * b0,
			      u16 * next0, u32 * error0)
{
  ip_adjacency_t *adj;
  adj_index_t ai;

  /* Not thread safe but as long as the connection exists the adj should
   * not be removed */
  ai = adj_nbr_find (FIB_PROTOCOL_IP6, VNET_LINK_IP6, &tc0->c_rmt_ip,
		     tc0->sw_if_index);
  if (ai == ADJ_INDEX_INVALID)
    {
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
      *next0 = TCP_OUTPUT_NEXT_DROP;
      *error0 = TCP_ERROR_LINK_LOCAL_RW;
      return;
    }

  adj = adj_get (ai);
  if (PREDICT_TRUE (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE))
    *next0 = TCP_OUTPUT_NEXT_IP_REWRITE;
  else if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
    *next0 = TCP_OUTPUT_NEXT_IP_ARP;
  else
    {
      *next0 = TCP_OUTPUT_NEXT_DROP;
      *error0 = TCP_ERROR_LINK_LOCAL_RW;
    }
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ai;
}

static void
tcp46_output_trace_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
			  u32 * to_next, u32 n_bufs)
{
  tcp_connection_t *tc;
  tcp_tx_trace_t *t;
  vlib_buffer_t *b;
  tcp_header_t *th;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      b = vlib_get_buffer (vm, to_next[i]);
      if (!(b->flags & VLIB_BUFFER_IS_TRACED))
	continue;
      th = vlib_buffer_get_current (b);
      tc = tcp_connection_get (vnet_buffer (b)->tcp.connection_index,
			       vm->thread_index);
      t = vlib_add_trace (vm, node, b, sizeof (*t));
      clib_memcpy_fast (&t->tcp_header, th, sizeof (t->tcp_header));
      clib_memcpy_fast (&t->tcp_connection, tc, sizeof (t->tcp_connection));
    }
}

always_inline void
tcp_output_push_ip (vlib_main_t * vm, vlib_buffer_t * b0,
		    tcp_connection_t * tc0, u8 is_ip4)
{
  TCP_EVT (TCP_EVT_OUTPUT, tc0,
	   ((tcp_header_t *) vlib_buffer_get_current (b0))->flags,
	   b0->current_length);

  if (is_ip4)
    vlib_buffer_push_ip4 (vm, b0, &tc0->c_lcl_ip4, &tc0->c_rmt_ip4,
			  IP_PROTOCOL_TCP, tcp_csum_offload (tc0));
  else
    vlib_buffer_push_ip6_custom (vm, b0, &tc0->c_lcl_ip6, &tc0->c_rmt_ip6,
				 IP_PROTOCOL_TCP, tc0->ipv6_flow_label);
}

always_inline void
tcp_check_if_gso (tcp_connection_t * tc, vlib_buffer_t * b)
{
  if (PREDICT_TRUE (!(tc->cfg_flags & TCP_CFG_F_TSO)))
    return;

  u16 data_len = b->current_length - sizeof (tcp_header_t) - tc->snd_opts_len;

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    data_len += b->total_length_not_including_first_buffer;

  if (PREDICT_TRUE (data_len <= tc->snd_mss))
    return;
  else
    {
      ASSERT ((b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID) != 0);
      ASSERT ((b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID) != 0);
      b->flags |= VNET_BUFFER_F_GSO;
      vnet_buffer2 (b)->gso_l4_hdr_sz =
	sizeof (tcp_header_t) + tc->snd_opts_len;
      vnet_buffer2 (b)->gso_size = tc->snd_mss;
    }
}

always_inline void
tcp_output_handle_packet (tcp_connection_t * tc0, vlib_buffer_t * b0,
			  vlib_node_runtime_t * error_node, u16 * next0,
			  u8 is_ip4)
{
  /* If next_index is not drop use it */
  if (tc0->next_node_index)
    {
      *next0 = tc0->next_node_index;
      vnet_buffer (b0)->tcp.next_node_opaque = tc0->next_node_opaque;
    }
  else
    {
      *next0 = TCP_OUTPUT_NEXT_IP_LOOKUP;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = tc0->c_fib_index;
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = tc0->sw_if_index;

  if (!is_ip4)
    {
      u32 error0 = 0;

      if (PREDICT_FALSE (ip6_address_is_link_local_unicast (&tc0->c_rmt_ip6)))
	tcp_output_handle_link_local (tc0, b0, next0, &error0);

      if (PREDICT_FALSE (error0))
	{
	  b0->error = error_node->errors[error0];
	  return;
	}
    }

  tc0->segs_out += 1;
}

always_inline uword
tcp46_output_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame, int is_ip4)
{
  u32 n_left_from, *from, thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  tcp_update_time_now (tcp_get_worker (thread_index));

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    tcp46_output_trace_frame (vm, node, from, n_left_from);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      tcp_connection_t *tc0, *tc1;

      {
	vlib_prefetch_buffer_header (b[2], STORE);
	CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[3], STORE);
	CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
      }

      tc0 = tcp_connection_get (vnet_buffer (b[0])->tcp.connection_index,
				thread_index);
      tc1 = tcp_connection_get (vnet_buffer (b[1])->tcp.connection_index,
				thread_index);

      if (PREDICT_TRUE (!tc0 + !tc1 == 0))
	{
	  tcp_output_push_ip (vm, b[0], tc0, is_ip4);
	  tcp_output_push_ip (vm, b[1], tc1, is_ip4);

	  tcp_check_if_gso (tc0, b[0]);
	  tcp_check_if_gso (tc1, b[1]);

	  tcp_output_handle_packet (tc0, b[0], node, &next[0], is_ip4);
	  tcp_output_handle_packet (tc1, b[1], node, &next[1], is_ip4);
	}
      else
	{
	  if (tc0 != 0)
	    {
	      tcp_output_push_ip (vm, b[0], tc0, is_ip4);
	      tcp_check_if_gso (tc0, b[0]);
	      tcp_output_handle_packet (tc0, b[0], node, &next[0], is_ip4);
	    }
	  else
	    {
	      b[0]->error = node->errors[TCP_ERROR_INVALID_CONNECTION];
	      next[0] = TCP_OUTPUT_NEXT_DROP;
	    }
	  if (tc1 != 0)
	    {
	      tcp_output_push_ip (vm, b[1], tc1, is_ip4);
	      tcp_check_if_gso (tc1, b[1]);
	      tcp_output_handle_packet (tc1, b[1], node, &next[1], is_ip4);
	    }
	  else
	    {
	      b[1]->error = node->errors[TCP_ERROR_INVALID_CONNECTION];
	      next[1] = TCP_OUTPUT_NEXT_DROP;
	    }
	}

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      tcp_connection_t *tc0;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	}

      tc0 = tcp_connection_get (vnet_buffer (b[0])->tcp.connection_index,
				thread_index);

      if (PREDICT_TRUE (tc0 != 0))
	{
	  tcp_output_push_ip (vm, b[0], tc0, is_ip4);
	  tcp_check_if_gso (tc0, b[0]);
	  tcp_output_handle_packet (tc0, b[0], node, &next[0], is_ip4);
	}
      else
	{
	  b[0]->error = node->errors[TCP_ERROR_INVALID_CONNECTION];
	  next[0] = TCP_OUTPUT_NEXT_DROP;
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, tcp_node_index (output, is_ip4),
			       TCP_ERROR_PKTS_SENT, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (tcp4_output_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (tcp6_output_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return tcp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_output_node) =
{
  .name = "tcp4-output",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .protocol_hint = VLIB_NODE_PROTO_HINT_TCP,
  .error_counters = tcp_output_error_counters,
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_output_node) =
{
  .name = "tcp6-output",
    /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .protocol_hint = VLIB_NODE_PROTO_HINT_TCP,
  .error_counters = tcp_output_error_counters,
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

static void
tcp_reset_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_buffer_t **bs, u32 n_bufs, u8 is_ip4)
{
  tcp_header_t *tcp;
  tcp_tx_trace_t *t;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      if (bs[i]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  tcp = vlib_buffer_get_current (bs[i]);
	  t = vlib_add_trace (vm, node, bs[i], sizeof (*t));

	  if (is_ip4)
	    {
	      ip4_header_t *ih4 = vlib_buffer_get_current (bs[i]);
	      tcp = ip4_next_header (ih4);
	      t->tcp_connection.c_lcl_ip.ip4 = ih4->dst_address;
	      t->tcp_connection.c_rmt_ip.ip4 = ih4->src_address;
	      t->tcp_connection.c_is_ip4 = 1;
	    }
	  else
	    {
	      ip6_header_t *ih6 = vlib_buffer_get_current (bs[i]);
	      tcp = ip6_next_header (ih6);
	      t->tcp_connection.c_lcl_ip.ip6 = ih6->dst_address;
	      t->tcp_connection.c_rmt_ip.ip6 = ih6->src_address;
	    }
	  t->tcp_connection.c_lcl_port = tcp->dst_port;
	  t->tcp_connection.c_rmt_port = tcp->src_port;
	  t->tcp_connection.c_proto = TRANSPORT_PROTO_TCP;
	  clib_memcpy_fast (&t->tcp_header, tcp, sizeof (t->tcp_header));
	}
    }
}

static uword
tcp46_reset_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u8 is_ip4)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      tcp_buffer_make_reset (vm, b[0], is_ip4);

      /* IP lookup in fib where it was received. Previous value
       * was overwritten by tcp-input */
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	vec_elt (ip4_main.fib_index_by_sw_if_index,
		 vnet_buffer (b[0])->sw_if_index[VLIB_RX]);

      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      next[0] = TCP_RESET_NEXT_IP_LOOKUP;

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    tcp_reset_trace_frame (vm, node, bufs, frame->n_vectors, is_ip4);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index, TCP_ERROR_RST_SENT,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (tcp4_reset_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  return tcp46_reset_inline (vm, node, from_frame, 1);
}

VLIB_NODE_FN (tcp6_reset_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  return tcp46_reset_inline (vm, node, from_frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_reset_node) = {
  .name = "tcp4-reset",
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_counters = tcp_output_error_counters,
  .n_next_nodes = TCP_RESET_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RESET_NEXT_##s] = n,
    foreach_tcp4_reset_next
#undef _
  },
  .format_trace = format_tcp_tx_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_reset_node) = {
  .name = "tcp6-reset",
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_counters = tcp_output_error_counters,
  .n_next_nodes = TCP_RESET_N_NEXT,
  .next_nodes = {
#define _(s,n) [TCP_RESET_NEXT_##s] = n,
    foreach_tcp6_reset_next
#undef _
  },
  .format_trace = format_tcp_tx_trace,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
