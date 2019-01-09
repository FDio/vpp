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
#include <math.h>

vlib_node_registration_t tcp4_output_node;
vlib_node_registration_t tcp6_output_node;

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

static char *tcp_error_strings[] = {
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

typedef struct
{
  tcp_header_t tcp_header;
  tcp_connection_t tcp_connection;
} tcp_tx_trace_t;

u16 dummy_mtu = 1460;

u8 *
format_tcp_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_tx_trace_t *t = va_arg (*args, tcp_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U\n%U%U",
	      format_tcp_header, &t->tcp_header, 128,
	      format_white_space, indent,
	      format_tcp_connection, &t->tcp_connection, 1);

  return s;
}

static u8
tcp_window_compute_scale (u32 window)
{
  u8 wnd_scale = 0;
  while (wnd_scale < TCP_MAX_WND_SCALE && (window >> wnd_scale) > TCP_WND_MAX)
    wnd_scale++;
  return wnd_scale;
}

/**
 * Update max segment size we're able to process.
 *
 * The value is constrained by our interface's MTU and IP options. It is
 * also what we advertise to our peer.
 */
void
tcp_update_rcv_mss (tcp_connection_t * tc)
{
  /* TODO find our iface MTU */
  tc->mss = dummy_mtu - sizeof (tcp_header_t);
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
  return TCP_MIN_RX_FIFO_SIZE;
}

/**
 * Compute initial window and scale factor. As per RFC1323, window field in
 * SYN and SYN-ACK segments is never scaled.
 */
u32
tcp_initial_window_to_advertise (tcp_connection_t * tc)
{
  tcp_main_t *tm = &tcp_main;
  u32 max_fifo;

  /* Initial wnd for SYN. Fifos are not allocated yet.
   * Use some predefined value. For SYN-ACK we still want the
   * scale to be computed in the same way */
  max_fifo = tm->max_rx_fifo ? tm->max_rx_fifo : TCP_MAX_RX_FIFO_SIZE;

  /* Compute rcv wscale only if peer advertised support for it */
  if (tc->state != TCP_STATE_SYN_RCVD || tcp_opts_wscale (&tc->rcv_opts))
    tc->rcv_wscale = tcp_window_compute_scale (max_fifo);

  tc->rcv_wnd = tcp_initial_wnd_unscaled (tc);

  return clib_min (tc->rcv_wnd, TCP_WND_MAX);
}

static void
tcp_update_rcv_wnd (tcp_connection_t * tc)
{
  i32 observed_wnd;
  u32 available_space, max_fifo, wnd;

  /*
   * Figure out how much space we have available
   */
  available_space = transport_max_rx_enqueue (&tc->connection);
  max_fifo = transport_rx_fifo_size (&tc->connection);

  ASSERT (tc->rcv_opts.mss < max_fifo);
  if (available_space < tc->rcv_opts.mss && available_space < max_fifo >> 3)
    available_space = 0;

  /*
   * Use the above and what we know about what we've previously advertised
   * to compute the new window
   */
  observed_wnd = (i32) tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);
  if (observed_wnd < 0)
    observed_wnd = 0;

  /* Bad. Thou shalt not shrink */
  if (available_space < observed_wnd)
    {
      wnd = observed_wnd;
      TCP_EVT_DBG (TCP_EVT_RCV_WND_SHRUNK, tc, observed_wnd, available_space);
    }
  else
    {
      wnd = available_space;
    }

  /* Make sure we have a multiple of rcv_wscale */
  if (wnd && tc->rcv_wscale)
    {
      wnd &= ~(1 << tc->rcv_wscale);
      if (wnd == 0)
	wnd = 1 << tc->rcv_wscale;
    }

  tc->rcv_wnd = clib_min (wnd, TCP_WND_MAX << tc->rcv_wscale);
}

/**
 * Compute and return window to advertise, scaled as per RFC1323
 */
static u32
tcp_window_to_advertise (tcp_connection_t * tc, tcp_state_t state)
{
  if (state < TCP_STATE_ESTABLISHED)
    return tcp_initial_window_to_advertise (tc);

  tcp_update_rcv_wnd (tc);

  if (tc->rcv_wnd == 0)
    {
      tc->flags |= TCP_CONN_SENT_RCV_WND0;
    }
  else
    {
      tc->flags &= ~TCP_CONN_SENT_RCV_WND0;
    }

  return tc->rcv_wnd >> tc->rcv_wscale;
}

/**
 * Write TCP options to segment.
 */
static u32
tcp_options_write (u8 * data, tcp_options_t * opts)
{
  u32 opts_len = 0;
  u32 buf, seq_len = 4;

  if (tcp_opts_mss (opts))
    {
      *data++ = TCP_OPTION_MSS;
      *data++ = TCP_OPTION_LEN_MSS;
      buf = clib_host_to_net_u16 (opts->mss);
      clib_memcpy_fast (data, &buf, sizeof (opts->mss));
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
      clib_memcpy_fast (data, &buf, sizeof (opts->tsval));
      data += sizeof (opts->tsval);
      buf = clib_host_to_net_u32 (opts->tsecr);
      clib_memcpy_fast (data, &buf, sizeof (opts->tsecr));
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
	      clib_memcpy_fast (data, &buf, seq_len);
	      data += seq_len;
	      buf = clib_host_to_net_u32 (opts->sacks[i].end);
	      clib_memcpy_fast (data, &buf, seq_len);
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

static int
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
      opts->tsval = tcp_time_now ();
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
      opts->tsval = tcp_time_now_w_thread (tc->c_thread_index);
      opts->tsecr = tc->tsval_recent;
      len += TCP_OPTION_LEN_TIMESTAMP;
    }
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      if (vec_len (tc->snd_sacks))
	{
	  opts->flags |= TCP_OPTS_FLAG_SACK;
	  opts->sacks = tc->snd_sacks;
	  opts->n_sack_blocks = clib_min (vec_len (tc->snd_sacks),
					  TCP_OPTS_MAX_SACK_BLOCKS);
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
      return tcp_make_syn_options (opts, tc->rcv_wscale);
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
}

void
tcp_init_mss (tcp_connection_t * tc)
{
  u16 default_min_mss = 536;
  tcp_update_rcv_mss (tc);

  /* TODO cache mss and consider PMTU discovery */
  tc->snd_mss = clib_min (tc->rcv_opts.mss, tc->mss);

  if (tc->snd_mss < 45)
    {
      /* Assume that at least the min default mss works */
      tc->snd_mss = default_min_mss;
      tc->rcv_opts.mss = default_min_mss;
    }

  /* We should have enough space for 40 bytes of options */
  ASSERT (tc->snd_mss > 45);

  /* If we use timestamp option, account for it */
  if (tcp_opts_tstamp (&tc->rcv_opts))
    tc->snd_mss -= TCP_OPTION_LEN_TIMESTAMP;
}

static int
tcp_alloc_tx_buffers (tcp_worker_ctx_t * wrk, u16 * n_bufs, u32 wanted)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 n_alloc;

  ASSERT (wanted > *n_bufs);
  vec_validate_aligned (wrk->tx_buffers, wanted - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, &wrk->tx_buffers[*n_bufs],
			       wanted - *n_bufs);
  *n_bufs += n_alloc;
  _vec_len (wrk->tx_buffers) = *n_bufs;
  return n_alloc;
}

always_inline int
tcp_get_free_buffer_index (tcp_worker_ctx_t * wrk, u32 * bidx)
{
  u16 n_bufs = vec_len (wrk->tx_buffers);

  TCP_DBG_BUFFER_ALLOC_MAYBE_FAIL (wrk->vm->thread_index);

  if (PREDICT_FALSE (!n_bufs))
    {
      if (!tcp_alloc_tx_buffers (wrk, &n_bufs, VLIB_FRAME_SIZE))
	{
	  *bidx = ~0;
	  return -1;
	}
    }
  *bidx = wrk->tx_buffers[--n_bufs];
  _vec_len (wrk->tx_buffers) = n_bufs;
  return 0;
}

static void *
tcp_reuse_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    vlib_buffer_free_one (vm, b->next_buffer);
  /* Zero all flags but free list index and trace flag */
  b->flags &= VLIB_BUFFER_NEXT_PRESENT - 1;
  b->current_data = 0;
  b->current_length = 0;
  b->total_length_not_including_first_buffer = 0;
  vnet_buffer (b)->tcp.flags = 0;

  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
}

static void *
tcp_init_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  b->current_data = 0;
  vnet_buffer (b)->tcp.flags = 0;
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
}

/**
 * Prepare ACK
 */
static void
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
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
}

/**
 * Convert buffer to ACK
 */
void
tcp_make_ack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  tcp_reuse_buffer (vm, b);
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, TCP_FLAG_ACK);
  TCP_EVT_DBG (TCP_EVT_ACK_SENT, tc);
  tc->rcv_las = tc->rcv_nxt;
}

/**
 * Convert buffer to FIN-ACK
 */
void
tcp_make_fin (tcp_connection_t * tc, vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 flags = 0;

  tcp_reuse_buffer (vm, b);

  flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
  tcp_make_ack_i (tc, b, TCP_STATE_ESTABLISHED, flags);

  /* Reset flags, make sure ack is sent */
  vnet_buffer (b)->tcp.flags &= ~TCP_BUF_FLAG_DUPACK;
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
  tcp_opts_len = tcp_make_syn_options (&snd_opts, tc->rcv_wscale);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len, TCP_FLAG_SYN,
			     initial_wnd);
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  tcp_options_write ((u8 *) (th + 1), &snd_opts);
}

/**
 * Convert buffer to SYN-ACK
 */
void
tcp_make_synack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();
  tcp_options_t _snd_opts, *snd_opts = &_snd_opts;
  u8 tcp_opts_len, tcp_hdr_opts_len;
  tcp_header_t *th;
  u16 initial_wnd;

  clib_memset (snd_opts, 0, sizeof (*snd_opts));
  tcp_reuse_buffer (vm, b);

  initial_wnd = tcp_initial_window_to_advertise (tc);
  tcp_opts_len = tcp_make_synack_options (tc, snd_opts);
  tcp_hdr_opts_len = tcp_opts_len + sizeof (tcp_header_t);

  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			     tc->rcv_nxt, tcp_hdr_opts_len,
			     TCP_FLAG_SYN | TCP_FLAG_ACK, initial_wnd);
  tcp_options_write ((u8 *) (th + 1), snd_opts);

  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;

  /* Init retransmit timer. Use update instead of set because of
   * retransmissions */
  tcp_retransmit_timer_force_update (tc);
  TCP_EVT_DBG (TCP_EVT_SYNACK_SENT, tc);
}

always_inline void
tcp_enqueue_to_ip_lookup_i (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
			    u8 is_ip4, u32 fib_index, u8 flush)
{
  vlib_main_t *vm = wrk->vm;
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  vnet_buffer (b)->sw_if_index[VLIB_TX] = fib_index;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;

  /* Send to IP lookup */
  next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  tcp_trajectory_add_start (b, 1);

  f = wrk->ip_lookup_tx_frames[!is_ip4];
  if (!f)
    {
      f = vlib_get_frame_to_node (vm, next_index);
      ASSERT (f);
      wrk->ip_lookup_tx_frames[!is_ip4] = f;
    }

  to_next = vlib_frame_vector_args (f);
  to_next[f->n_vectors] = bi;
  f->n_vectors += 1;
  if (flush || f->n_vectors == VLIB_FRAME_SIZE)
    {
      vlib_put_frame_to_node (vm, next_index, f);
      wrk->ip_lookup_tx_frames[!is_ip4] = 0;
    }
}

static void
tcp_enqueue_to_ip_lookup_now (tcp_worker_ctx_t * wrk, vlib_buffer_t * b,
			      u32 bi, u8 is_ip4, u32 fib_index)
{
  tcp_enqueue_to_ip_lookup_i (wrk, b, bi, is_ip4, fib_index, 1);
}

static void
tcp_enqueue_to_ip_lookup (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
			  u8 is_ip4, u32 fib_index)
{
  tcp_enqueue_to_ip_lookup_i (wrk, b, bi, is_ip4, fib_index, 0);
  if (wrk->vm->thread_index == 0 && vlib_num_workers ())
    session_flush_frames_main_thread (wrk->vm);
}

always_inline void
tcp_enqueue_to_output_i (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
			 u8 is_ip4, u8 flush)
{
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Decide where to send the packet */
  next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  tcp_trajectory_add_start (b, 2);

  /* Get frame to v4/6 output node */
  f = wrk->tx_frames[!is_ip4];
  if (!f)
    {
      f = vlib_get_frame_to_node (wrk->vm, next_index);
      ASSERT (f);
      wrk->tx_frames[!is_ip4] = f;
    }
  to_next = vlib_frame_vector_args (f);
  to_next[f->n_vectors] = bi;
  f->n_vectors += 1;
  if (flush || f->n_vectors == VLIB_FRAME_SIZE)
    {
      vlib_put_frame_to_node (wrk->vm, next_index, f);
      wrk->tx_frames[!is_ip4] = 0;
    }
}

static void
tcp_enqueue_to_output (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
		       u8 is_ip4)
{
  tcp_enqueue_to_output_i (wrk, b, bi, is_ip4, 0);
}

static void
tcp_enqueue_to_output_now (tcp_worker_ctx_t * wrk, vlib_buffer_t * b, u32 bi,
			   u8 is_ip4)
{
  tcp_enqueue_to_output_i (wrk, b, bi, is_ip4, 1);
}

static int
tcp_make_reset_in_place (vlib_main_t * vm, vlib_buffer_t * b0,
			 tcp_state_t state, u8 thread_index, u8 is_ip4)
{
  ip4_header_t *ih4;
  ip6_header_t *ih6;
  tcp_header_t *th0;
  ip4_address_t src_ip40, dst_ip40;
  ip6_address_t src_ip60, dst_ip60;
  u16 src_port, dst_port;
  u32 tmp;
  u32 seq, ack;
  u8 flags;

  /* Find IP and TCP headers */
  th0 = tcp_buffer_hdr (b0);

  /* Save src and dst ip */
  if (is_ip4)
    {
      ih4 = vlib_buffer_get_current (b0);
      ASSERT ((ih4->ip_version_and_header_length & 0xF0) == 0x40);
      src_ip40.as_u32 = ih4->src_address.as_u32;
      dst_ip40.as_u32 = ih4->dst_address.as_u32;
    }
  else
    {
      ih6 = vlib_buffer_get_current (b0);
      ASSERT ((ih6->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60);
      clib_memcpy_fast (&src_ip60, &ih6->src_address, sizeof (ip6_address_t));
      clib_memcpy_fast (&dst_ip60, &ih6->dst_address, sizeof (ip6_address_t));
    }

  src_port = th0->src_port;
  dst_port = th0->dst_port;

  /* Try to determine what/why we're actually resetting */
  if (state == TCP_STATE_CLOSED)
    {
      if (!tcp_syn (th0))
	return -1;

      tmp = clib_net_to_host_u32 (th0->seq_number);

      /* Got a SYN for no listener. */
      flags = TCP_FLAG_RST | TCP_FLAG_ACK;
      ack = clib_host_to_net_u32 (tmp + 1);
      seq = 0;
    }
  else
    {
      flags = TCP_FLAG_RST;
      seq = th0->ack_number;
      ack = 0;
    }

  tcp_reuse_buffer (vm, b0);
  tcp_trajectory_add_start (b0, 4);
  th0 = vlib_buffer_push_tcp_net_order (b0, dst_port, src_port, seq, ack,
					sizeof (tcp_header_t), flags, 0);

  if (is_ip4)
    {
      ih4 = vlib_buffer_push_ip4 (vm, b0, &dst_ip40, &src_ip40,
				  IP_PROTOCOL_TCP, 1);
      th0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ih4);
    }
  else
    {
      int bogus = ~0;
      ih6 = vlib_buffer_push_ip6 (vm, b0, &dst_ip60, &src_ip60,
				  IP_PROTOCOL_TCP);
      th0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ih6, &bogus);
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
tcp_send_reset_w_pkt (tcp_connection_t * tc, vlib_buffer_t * pkt, u8 is_ip4)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi, sw_if_index, fib_index;
  u8 tcp_hdr_len, flags = 0;
  tcp_header_t *th, *pkt_th;
  u32 seq, ack;
  ip4_header_t *ih4, *pkt_ih4;
  ip6_header_t *ih6, *pkt_ih6;
  fib_protocol_t fib_proto;

  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    return;

  b = vlib_get_buffer (vm, bi);
  sw_if_index = vnet_buffer (pkt)->sw_if_index[VLIB_RX];
  fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  fib_index = fib_table_get_index_for_sw_if_index (fib_proto, sw_if_index);
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
				  &pkt_ih4->src_address, IP_PROTOCOL_TCP, 1);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih4);
    }
  else
    {
      int bogus = ~0;
      ASSERT ((pkt_ih6->ip_version_traffic_class_and_flow_label & 0xF0) ==
	      0x60);
      ih6 = vlib_buffer_push_ip6 (vm, b, &pkt_ih6->dst_address,
				  &pkt_ih6->src_address, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih6, &bogus);
      ASSERT (!bogus);
    }

  tcp_enqueue_to_ip_lookup_now (wrk, b, bi, is_ip4, fib_index);
  TCP_EVT_DBG (TCP_EVT_RST_SENT, tc);
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

  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    return;
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);

  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);
  tcp_hdr_opts_len = tc->snd_opts_len + sizeof (tcp_header_t);
  advertise_wnd = tcp_window_to_advertise (tc, TCP_STATE_ESTABLISHED);
  flags = TCP_FLAG_RST;
  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
			     tc->rcv_nxt, tcp_hdr_opts_len, flags,
			     advertise_wnd);
  opts_write_len = tcp_options_write ((u8 *) (th + 1), &tc->snd_opts);
  ASSERT (opts_write_len == tc->snd_opts_len);
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  if (tc->c_is_ip4)
    {
      ip4_header_t *ih4;
      ih4 = vlib_buffer_push_ip4 (vm, b, &tc->c_lcl_ip.ip4,
				  &tc->c_rmt_ip.ip4, IP_PROTOCOL_TCP, 0);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih4);
    }
  else
    {
      int bogus = ~0;
      ip6_header_t *ih6;
      ih6 = vlib_buffer_push_ip6 (vm, b, &tc->c_lcl_ip.ip6,
				  &tc->c_rmt_ip.ip6, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih6, &bogus);
      ASSERT (!bogus);
    }
  tcp_enqueue_to_ip_lookup_now (wrk, b, bi, tc->c_is_ip4, tc->c_fib_index);
  TCP_EVT_DBG (TCP_EVT_RST_SENT, tc);
}

static void
tcp_push_ip_hdr (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		 vlib_buffer_t * b)
{
  tcp_header_t *th = vlib_buffer_get_current (b);
  vlib_main_t *vm = wrk->vm;
  if (tc->c_is_ip4)
    {
      ip4_header_t *ih;
      ih = vlib_buffer_push_ip4 (vm, b, &tc->c_lcl_ip4,
				 &tc->c_rmt_ip4, IP_PROTOCOL_TCP, 1);
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t *ih;
      int bogus = ~0;

      ih = vlib_buffer_push_ip6 (vm, b, &tc->c_lcl_ip6,
				 &tc->c_rmt_ip6, IP_PROTOCOL_TCP);
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ih, &bogus);
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
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  /*
   * Setup retransmit and establish timers before requesting buffer
   * such that we can return if we've ran out.
   */
  tcp_timer_set (tc, TCP_TIMER_ESTABLISH_AO, TCP_ESTABLISH_TIME);
  tcp_timer_update (tc, TCP_TIMER_RETRANSMIT_SYN,
		    tc->rto * TCP_TO_TIMER_TICK);

  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    return;

  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_syn (tc, b);

  /* Measure RTT with this */
  tc->rtt_ts = tcp_time_now_us (vlib_num_workers ()? 1 : 0);
  tc->rtt_seq = tc->snd_nxt;
  tc->rto_boff = 0;

  tcp_push_ip_hdr (wrk, tc, b);
  tcp_enqueue_to_ip_lookup (wrk, b, bi, tc->c_is_ip4, tc->c_fib_index);
  TCP_EVT_DBG (TCP_EVT_SYN_SENT, tc);
}

void
tcp_send_synack (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  /* Get buffer */
  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    return;

  tc->rtt_ts = tcp_time_now_us (tc->c_thread_index);
  b = vlib_get_buffer (vm, bi);
  tcp_make_synack (tc, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
}

/**
 * Flush tx frame populated by retransmits and timer pops
 */
void
tcp_flush_frame_to_output (tcp_worker_ctx_t * wrk, u8 is_ip4)
{
  if (wrk->tx_frames[!is_ip4])
    {
      u32 next_index;
      next_index = is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
      vlib_put_frame_to_node (wrk->vm, next_index, wrk->tx_frames[!is_ip4]);
      wrk->tx_frames[!is_ip4] = 0;
    }
}

/**
 * Flush ip lookup tx frames populated by timer pops
 */
static void
tcp_flush_frame_to_ip_lookup (tcp_worker_ctx_t * wrk, u8 is_ip4)
{
  if (wrk->ip_lookup_tx_frames[!is_ip4])
    {
      u32 next_index;
      next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
      vlib_put_frame_to_node (wrk->vm, next_index,
			      wrk->ip_lookup_tx_frames[!is_ip4]);
      wrk->ip_lookup_tx_frames[!is_ip4] = 0;
    }
}

/**
 * Flush v4 and v6 tcp and ip-lookup tx frames for thread index
 */
void
tcp_flush_frames_to_output (tcp_worker_ctx_t * wrk)
{
  tcp_flush_frame_to_output (wrk, 1);
  tcp_flush_frame_to_output (wrk, 0);
  tcp_flush_frame_to_ip_lookup (wrk, 1);
  tcp_flush_frame_to_ip_lookup (wrk, 0);
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
    tc->snd_nxt = tc->snd_una;

  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    {
      /* Out of buffers so program fin retransmit ASAP */
      tcp_timer_update (tc, TCP_TIMER_RETRANSMIT, 1);
      if (fin_snt)
	tc->snd_nxt = tc->snd_una_max;
      return;
    }

  tcp_retransmit_timer_force_update (tc);
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);
  tcp_make_fin (tc, b);
  tcp_enqueue_to_output_now (wrk, b, bi, tc->c_is_ip4);
  TCP_EVT_DBG (TCP_EVT_FIN_SENT, tc);

  if (!fin_snt)
    {
      tc->flags |= TCP_CONN_FINSNT;
      tc->flags &= ~TCP_CONN_FINPNDG;
      /* Account for the FIN */
      tc->snd_una_max += 1;
      tc->snd_nxt = tc->snd_una_max;
    }
  else
    {
      tc->snd_nxt = tc->snd_una_max;
    }
}

always_inline u8
tcp_make_state_flags (tcp_connection_t * tc, tcp_state_t next_state)
{
  switch (next_state)
    {
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_TIME_WAIT:
    case TCP_STATE_FIN_WAIT_2:
      return TCP_FLAG_ACK;
    case TCP_STATE_SYN_RCVD:
      return TCP_FLAG_SYN | TCP_FLAG_ACK;
    case TCP_STATE_SYN_SENT:
      return TCP_FLAG_SYN;
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_CLOSING:
      if (tc->snd_nxt + 1 < tc->snd_una_max)
	return TCP_FLAG_ACK;
      else
	return TCP_FLAG_FIN;
    default:
      clib_warning ("Shouldn't be here!");
    }
  return 0;
}

/**
 * Push TCP header and update connection variables
 */
always_inline void
tcp_push_hdr_i (tcp_connection_t * tc, vlib_buffer_t * b,
		tcp_state_t next_state, u8 compute_opts, u8 maybe_burst)
{
  u32 advertise_wnd, data_len;
  u8 tcp_hdr_opts_len, flags;
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
    advertise_wnd = tcp_window_to_advertise (tc, next_state);

  flags = tcp_make_state_flags (tc, next_state);
  if (PREDICT_FALSE (tc->flags & TCP_CONN_PSH_PENDING))
    {
      if (seq_geq (tc->psh_seq, tc->snd_nxt)
	  && seq_lt (tc->psh_seq, tc->snd_nxt + data_len))
	flags |= TCP_FLAG_PSH;
    }
  th = vlib_buffer_push_tcp (b, tc->c_lcl_port, tc->c_rmt_port, tc->snd_nxt,
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

  tc->snd_nxt += data_len;
  tc->rcv_las = tc->rcv_nxt;

  TCP_EVT_DBG (TCP_EVT_PKTIZE, tc);
}

u32
tcp_push_header (tcp_connection_t * tc, vlib_buffer_t * b)
{
  tcp_push_hdr_i (tc, b, TCP_STATE_ESTABLISHED, /* compute opts */ 0,
		  /* burst */ 1);
  tc->snd_una_max = tc->snd_nxt;
  ASSERT (seq_leq (tc->snd_una_max, tc->snd_una + tc->snd_wnd));
  tcp_validate_txf_size (tc, tc->snd_una_max - tc->snd_una);
  /* If not tracking an ACK, start tracking */
  if (tc->rtt_ts == 0 && !tcp_in_cong_recovery (tc))
    {
      tc->rtt_ts = tcp_time_now_us (tc->c_thread_index);
      tc->rtt_seq = tc->snd_nxt;
    }
  if (PREDICT_FALSE (!tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT)))
    {
      tcp_retransmit_timer_set (tc);
      tc->rto_boff = 0;
    }
  tcp_trajectory_add_start (b, 3);
  return 0;
}

void
tcp_send_ack (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  /* Get buffer */
  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    return;
  b = vlib_get_buffer (vm, bi);
  tcp_init_buffer (vm, b);

  /* Fill in the ACK */
  tcp_make_ack (tc, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
}

void
tcp_program_ack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_SNDACK))
    {
      vec_add1 (wrk->pending_acks, tc->c_c_index);
      tc->flags |= TCP_CONN_SNDACK;
    }
}

void
tcp_program_dupack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_SNDACK))
    {
      vec_add1 (wrk->pending_acks, tc->c_c_index);
      tc->flags |= TCP_CONN_SNDACK;
    }
  if (tc->pending_dupacks < 255)
    tc->pending_dupacks += 1;
}

void
tcp_send_acks (tcp_worker_ctx_t * wrk)
{
  u32 thread_index, *pending_acks;
  tcp_connection_t *tc;
  int i, j, n_acks;

  if (!vec_len (wrk->pending_acks))
    return;

  thread_index = wrk->vm->thread_index;
  pending_acks = wrk->pending_acks;
  for (i = 0; i < vec_len (pending_acks); i++)
    {
      tc = tcp_connection_get (pending_acks[i], thread_index);
      tc->flags &= ~TCP_CONN_SNDACK;
      n_acks = clib_max (1, tc->pending_dupacks);
      /* If we're supposed to send dupacks but have no ooo data
       * send only one ack */
      if (tc->pending_dupacks && !vec_len (tc->snd_sacks))
	n_acks = 1;
      for (j = 0; j < n_acks; j++)
	tcp_send_ack (tc);
      tc->pending_dupacks = 0;
    }
  _vec_len (wrk->pending_acks) = 0;
}

/**
 * Delayed ack timer handler
 *
 * Sends delayed ACK when timer expires
 */
void
tcp_timer_delack_handler (u32 index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_connection_t *tc;

  tc = tcp_connection_get (index, thread_index);
  tc->timers[TCP_TIMER_DELACK] = TCP_TIMER_HANDLE_INVALID;
  tcp_send_ack (tc);
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
  u32 bi, seg_size;
  vlib_main_t *vm = wrk->vm;
  int n_bytes = 0;
  u8 *data;

  seg_size = max_deq_bytes + MAX_HDRS_LEN;

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
      if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
	return 0;
      *b = vlib_get_buffer (vm, bi);
      data = tcp_init_buffer (vm, *b);
      n_bytes = stream_session_peek_bytes (&tc->connection, data, offset,
					   max_deq_bytes);
      ASSERT (n_bytes == max_deq_bytes);
      b[0]->current_length = n_bytes;
      tcp_push_hdr_i (tc, *b, tc->state, /* compute opts */ 0, /* burst */ 0);
      if (seq_gt (tc->snd_nxt, tc->snd_una_max))
	tc->snd_una_max = tc->snd_nxt;
    }
  /* Split mss into multiple buffers */
  else
    {
      u32 chain_bi = ~0, n_bufs_per_seg;
      u16 n_peeked, len_to_deq, available_bufs;
      vlib_buffer_t *chain_b, *prev_b;
      int i;

      /* Make sure we have enough buffers */
      n_bufs_per_seg = ceil ((double) seg_size / bytes_per_buffer);
      available_bufs = vec_len (wrk->tx_buffers);
      if (n_bufs_per_seg > available_bufs)
	{
	  tcp_alloc_tx_buffers (wrk, &available_bufs, VLIB_FRAME_SIZE);
	  if (n_bufs_per_seg > available_bufs)
	    {
	      *b = 0;
	      return 0;
	    }
	}

      (void) tcp_get_free_buffer_index (wrk, &bi);
      ASSERT (bi != (u32) ~ 0);
      *b = vlib_get_buffer (vm, bi);
      data = tcp_init_buffer (vm, *b);
      n_bytes = stream_session_peek_bytes (&tc->connection, data, offset,
					   bytes_per_buffer - MAX_HDRS_LEN);
      b[0]->current_length = n_bytes;
      b[0]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      b[0]->total_length_not_including_first_buffer = 0;
      max_deq_bytes -= n_bytes;

      chain_b = *b;
      for (i = 1; i < n_bufs_per_seg; i++)
	{
	  prev_b = chain_b;
	  len_to_deq = clib_min (max_deq_bytes, bytes_per_buffer);
	  tcp_get_free_buffer_index (wrk, &chain_bi);
	  ASSERT (chain_bi != (u32) ~ 0);
	  chain_b = vlib_get_buffer (vm, chain_bi);
	  chain_b->current_data = 0;
	  data = vlib_buffer_get_current (chain_b);
	  n_peeked = stream_session_peek_bytes (&tc->connection, data,
						offset + n_bytes, len_to_deq);
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

      tcp_push_hdr_i (tc, *b, tc->state, /* compute opts */ 0, /* burst */ 0);
      if (seq_gt (tc->snd_nxt, tc->snd_una_max))
	tc->snd_una_max = tc->snd_nxt;
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
  available_bytes = session_tx_fifo_max_dequeue (&tc->connection);
  ASSERT (available_bytes >= offset);
  available_bytes -= offset;
  if (!available_bytes)
    return 0;

  max_deq_bytes = clib_min (tc->snd_mss, max_deq_bytes);
  max_deq_bytes = clib_min (available_bytes, max_deq_bytes);

  /* Start is beyond snd_congestion */
  start = tc->snd_una + offset;
  if (seq_geq (start, tc->snd_congestion))
    goto done;

  /* Don't overshoot snd_congestion */
  if (seq_gt (start + max_deq_bytes, tc->snd_congestion))
    {
      max_deq_bytes = tc->snd_congestion - start;
      if (max_deq_bytes == 0)
	goto done;
    }

  n_bytes = tcp_prepare_segment (wrk, tc, offset, max_deq_bytes, b);
  if (!n_bytes)
    return 0;

  if (tcp_in_fastrecovery (tc))
    tc->snd_rxt_bytes += n_bytes;

done:
  TCP_EVT_DBG (TCP_EVT_CC_RTX, tc, offset, n_bytes);
  return n_bytes;
}

/**
 * Reset congestion control, switch cwnd to loss window and try again.
 */
static void
tcp_rxt_timeout_cc (tcp_connection_t * tc)
{
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 6);
  tc->prev_ssthresh = tc->ssthresh;
  tc->prev_cwnd = tc->cwnd;

  /* Cleanly recover cc (also clears up fast retransmit) */
  if (tcp_in_fastrecovery (tc))
    {
      /* TODO be less aggressive about this */
      scoreboard_clear (&tc->sack_sb);
      tcp_cc_fastrecovery_exit (tc);
    }

  /* Start again from the beginning */
  tc->cc_algo->congestion (tc);
  tc->cwnd = tcp_loss_wnd (tc);
  tc->snd_congestion = tc->snd_una_max;
  tc->rtt_ts = 0;
  tc->cwnd_acc_bytes = 0;
  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 2 * tc->snd_mss);
  tcp_recovery_on (tc);
}

static inline void
tcp_timer_retransmit_handler_i (u32 index, u8 is_syn)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  vlib_main_t *vm = wrk->vm;
  tcp_connection_t *tc;
  vlib_buffer_t *b = 0;
  u32 bi, n_bytes;

  if (is_syn)
    {
      tc = tcp_half_open_connection_get (index);
      /* Note: the connection may have transitioned to ESTABLISHED... */
      if (PREDICT_FALSE (tc == 0 || tc->state != TCP_STATE_SYN_SENT))
	return;
      tc->timers[TCP_TIMER_RETRANSMIT_SYN] = TCP_TIMER_HANDLE_INVALID;
    }
  else
    {
      tc = tcp_connection_get (index, thread_index);
      /* Note: the connection may have been closed and pool_put */
      if (PREDICT_FALSE (tc == 0 || tc->state == TCP_STATE_SYN_SENT))
	return;
      tc->timers[TCP_TIMER_RETRANSMIT] = TCP_TIMER_HANDLE_INVALID;
      /* Wait-close and retransmit could pop at the same time */
      if (tc->state == TCP_STATE_CLOSED)
	return;
    }

  if (tc->state >= TCP_STATE_ESTABLISHED)
    {
      TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 2);

      /* Lost FIN, retransmit and return */
      if (tcp_is_lost_fin (tc))
	{
	  tcp_send_fin (tc);
	  tc->rto_boff += 1;
	  tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);
	  return;
	}

      /* Shouldn't be here. This condition is tricky because it has to take
       * into account boff > 0 due to persist timeout. */
      if ((tc->rto_boff == 0 && tc->snd_una == tc->snd_una_max)
	  || (tc->rto_boff > 0 && seq_geq (tc->snd_una, tc->snd_congestion)
	      && !tcp_flight_size (tc)))
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

      /* Increment RTO backoff (also equal to number of retries) and go back
       * to first un-acked byte  */
      tc->rto_boff += 1;

      /* First retransmit timeout */
      if (tc->rto_boff == 1)
	tcp_rxt_timeout_cc (tc);
      else
	scoreboard_clear (&tc->sack_sb);

      /* If we've sent beyond snd_congestion, update it */
      if (seq_gt (tc->snd_una_max, tc->snd_congestion))
	tc->snd_congestion = tc->snd_una_max;

      tc->snd_una_max = tc->snd_nxt = tc->snd_una;
      tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

      /* Send one segment. Note that n_bytes may be zero due to buffer
       * shortfall */
      n_bytes = tcp_prepare_retransmit_segment (wrk, tc, 0, tc->snd_mss, &b);
      if (!n_bytes)
	{
	  tcp_retransmit_timer_force_update (tc);
	  return;
	}

      bi = vlib_get_buffer_index (vm, b);

      /* For first retransmit, record timestamp (Eifel detection RFC3522) */
      if (tc->rto_boff == 1)
	tc->snd_rxt_ts = tcp_time_now_w_thread (tc->c_thread_index);

      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
      tcp_retransmit_timer_force_update (tc);
    }
  /* Retransmit for SYN */
  else if (tc->state == TCP_STATE_SYN_SENT)
    {
      /* Half-open connection actually moved to established but we were
       * waiting for syn retransmit to pop to call cleanup from the right
       * thread. */
      if (tc->flags & TCP_CONN_HALF_OPEN_DONE)
	{
	  if (tcp_half_open_connection_cleanup (tc))
	    TCP_DBG ("could not remove half-open connection");
	  return;
	}

      TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 2);

      /* Try without increasing RTO a number of times. If this fails,
       * start growing RTO exponentially */
      tc->rto_boff += 1;
      if (tc->rto_boff > TCP_RTO_SYN_RETRIES)
	tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

      tcp_timer_update (tc, TCP_TIMER_RETRANSMIT_SYN,
			tc->rto * TCP_TO_TIMER_TICK);

      if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
	return;

      b = vlib_get_buffer (vm, bi);
      tcp_init_buffer (vm, b);
      tcp_make_syn (tc, b);

      tc->rtt_ts = 0;
      TCP_EVT_DBG (TCP_EVT_SYN_RXT, tc, 0);

      /* This goes straight to ipx_lookup. Retransmit timer set already */
      tcp_push_ip_hdr (wrk, tc, b);
      tcp_enqueue_to_ip_lookup (wrk, b, bi, tc->c_is_ip4, tc->c_fib_index);
    }
  /* Retransmit SYN-ACK */
  else if (tc->state == TCP_STATE_SYN_RCVD)
    {
      TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 2);

      tc->rto_boff += 1;
      if (tc->rto_boff > TCP_RTO_SYN_RETRIES)
	tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);
      tc->rtt_ts = 0;

      if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
	{
	  tcp_retransmit_timer_force_update (tc);
	  return;
	}

      b = vlib_get_buffer (vm, bi);
      tcp_init_buffer (vm, b);
      tcp_make_synack (tc, b);
      TCP_EVT_DBG (TCP_EVT_SYN_RXT, tc, 1);

      /* Retransmit timer already updated, just enqueue to output */
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
    }
  else
    {
      ASSERT (tc->state == TCP_STATE_CLOSED);
      return;
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
 * Got 0 snd_wnd from peer, try to do something about it.
 *
 */
void
tcp_timer_persist_handler (u32 index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  u32 bi, max_snd_bytes, available_bytes, offset;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_main_t *vm = wrk->vm;
  tcp_connection_t *tc;
  vlib_buffer_t *b;
  int n_bytes = 0;
  u8 *data;

  tc = tcp_connection_get_if_valid (index, thread_index);

  if (!tc)
    return;

  /* Make sure timer handle is set to invalid */
  tc->timers[TCP_TIMER_PERSIST] = TCP_TIMER_HANDLE_INVALID;

  /* Problem already solved or worse */
  if (tc->state == TCP_STATE_CLOSED || tc->state > TCP_STATE_ESTABLISHED
      || tc->snd_wnd > tc->snd_mss)
    return;

  available_bytes = session_tx_fifo_max_dequeue (&tc->connection);
  offset = tc->snd_una_max - tc->snd_una;

  /* Reprogram persist if no new bytes available to send. We may have data
   * next time */
  if (!available_bytes)
    {
      tcp_persist_timer_set (tc);
      return;
    }

  if (available_bytes <= offset)
    {
      ASSERT (tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT));
      return;
    }

  /* Increment RTO backoff */
  tc->rto_boff += 1;
  tc->rto = clib_min (tc->rto << 1, TCP_RTO_MAX);

  /*
   * Try to force the first unsent segment (or buffer)
   */
  if (PREDICT_FALSE (tcp_get_free_buffer_index (wrk, &bi)))
    {
      tcp_persist_timer_set (tc);
      return;
    }
  b = vlib_get_buffer (vm, bi);
  data = tcp_init_buffer (vm, b);

  tcp_validate_txf_size (tc, offset);
  tc->snd_opts_len = tcp_make_options (tc, &tc->snd_opts, tc->state);
  max_snd_bytes = clib_min (tc->snd_mss, tm->bytes_per_buffer - MAX_HDRS_LEN);
  n_bytes = stream_session_peek_bytes (&tc->connection, data, offset,
				       max_snd_bytes);
  b->current_length = n_bytes;
  ASSERT (n_bytes != 0 && (tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT)
			   || tc->snd_nxt == tc->snd_una_max
			   || tc->rto_boff > 1));

  tcp_push_hdr_i (tc, b, tc->state, /* compute opts */ 0, /* burst */ 0);
  tc->snd_una_max = tc->snd_nxt;
  tcp_validate_txf_size (tc, tc->snd_una_max - tc->snd_una);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

  /* Just sent new data, enable retransmit */
  tcp_retransmit_timer_update (tc);
}

/**
 * Retransmit first unacked segment
 */
int
tcp_retransmit_first_unacked (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  u32 bi, old_snd_nxt, n_bytes;
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;

  old_snd_nxt = tc->snd_nxt;
  tc->snd_nxt = tc->snd_una;

  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 1);

  n_bytes = tcp_prepare_retransmit_segment (wrk, tc, 0, tc->snd_mss, &b);
  if (!n_bytes)
    return -1;

  bi = vlib_get_buffer_index (vm, b);
  tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
  tc->snd_nxt = old_snd_nxt;

  return 0;
}

static int
tcp_fast_retransmit_unsent (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
			    u32 burst_size)
{
  u32 offset, n_segs = 0, n_written, bi;
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;

  tc->snd_nxt = tc->snd_una_max;
  offset = tc->snd_una_max - tc->snd_una;
  while (n_segs < burst_size)
    {
      n_written = tcp_prepare_segment (wrk, tc, offset, tc->snd_mss, &b);
      if (!n_written)
	goto done;

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);
      offset += n_written;
      n_segs += 1;
    }

done:
  return n_segs;
}

#define scoreboard_rescue_rxt_valid(_sb, _tc)			\
    (seq_geq (_sb->rescue_rxt, _tc->snd_una) 			\
	&& seq_leq (_sb->rescue_rxt, _tc->snd_congestion))

/**
 * Do fast retransmit with SACKs
 */
int
tcp_fast_retransmit_sack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
			  u32 burst_size)
{
  u32 n_written = 0, offset, max_bytes, n_segs = 0, n_segs_now;
  sack_scoreboard_hole_t *hole;
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b = 0;
  sack_scoreboard_t *sb;
  u32 bi, old_snd_nxt;
  int snd_space;
  u32 max_deq;
  u8 snd_limited = 0, can_rescue = 0;

  ASSERT (tcp_in_fastrecovery (tc));

  snd_space = tcp_available_cc_snd_space (tc);
  if (snd_space < tc->snd_mss)
    {
      tcp_program_fastretransmit (wrk, tc);
      return 0;
    }

  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 0);
  old_snd_nxt = tc->snd_nxt;
  sb = &tc->sack_sb;
  hole = scoreboard_get_hole (sb, sb->cur_rxt_hole);

  max_deq = session_tx_fifo_max_dequeue (&tc->connection);
  max_deq -= tc->snd_una_max - tc->snd_una;

  while (snd_space > 0 && n_segs < burst_size)
    {
      hole = scoreboard_next_rxt_hole (sb, hole, max_deq, &can_rescue,
				       &snd_limited);
      if (!hole)
	{
	  if (max_deq)
	    {
	      snd_space = clib_min (max_deq, snd_space);
	      burst_size = clib_min (burst_size - n_segs,
				     snd_space / tc->snd_mss);
	      n_segs_now = tcp_fast_retransmit_unsent (wrk, tc, burst_size);
	      if (max_deq > n_segs_now * tc->snd_mss)
		tcp_program_fastretransmit (wrk, tc);
	      n_segs += n_segs_now;
	      goto done;
	    }

	  if (!can_rescue || scoreboard_rescue_rxt_valid (sb, tc))
	    break;

	  /* If rescue rxt undefined or less than snd_una then one segment of
	   * up to SMSS octets that MUST include the highest outstanding
	   * unSACKed sequence number SHOULD be returned, and RescueRxt set to
	   * RecoveryPoint. HighRxt MUST NOT be updated.
	   */
	  max_bytes = clib_min (tc->snd_mss,
				tc->snd_congestion - tc->snd_una);
	  max_bytes = clib_min (max_bytes, snd_space);
	  offset = tc->snd_congestion - tc->snd_una - max_bytes;
	  sb->rescue_rxt = tc->snd_congestion;
	  tc->snd_nxt = tc->snd_una + offset;
	  n_written = tcp_prepare_retransmit_segment (wrk, tc, offset,
						      max_bytes, &b);
	  if (!n_written)
	    goto done;

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
      tc->snd_nxt = sb->high_rxt;
      n_written = tcp_prepare_retransmit_segment (wrk, tc, offset, max_bytes,
						  &b);
      ASSERT (n_written <= snd_space);

      /* Nothing left to retransmit */
      if (n_written == 0)
	break;

      bi = vlib_get_buffer_index (vm, b);
      tcp_enqueue_to_output (wrk, b, bi, tc->c_is_ip4);

      sb->high_rxt += n_written;
      snd_space -= n_written;
      n_segs += 1;
    }

  if (hole)
    tcp_program_fastretransmit (wrk, tc);

done:
  /* If window allows, send 1 SMSS of new data */
  tc->snd_nxt = old_snd_nxt;
  return n_segs;
}

/**
 * Fast retransmit without SACK info
 */
int
tcp_fast_retransmit_no_sack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
			     u32 burst_size)
{
  u32 n_written = 0, offset = 0, bi, old_snd_nxt, max_deq, n_segs_now;
  vlib_main_t *vm = wrk->vm;
  int snd_space, n_segs = 0;
  vlib_buffer_t *b;

  ASSERT (tcp_in_fastrecovery (tc));
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 0);
  old_snd_nxt = tc->snd_nxt;

  if (!tcp_fastrecovery_first (tc))
    goto send_unsent;

  /* RFC 6582: [If a partial ack], retransmit the first unacknowledged
   * segment. */
  snd_space = tc->sack_sb.last_bytes_delivered;
  tc->snd_nxt = tc->snd_una;
  while (snd_space > 0 && n_segs < burst_size)
    {
      n_written = tcp_prepare_retransmit_segment (wrk, tc, offset,
						  tc->snd_mss, &b);

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
  snd_space = tcp_available_cc_snd_space (tc);
  if (snd_space < tc->snd_mss || tc->snd_mss == 0)
    goto done;

  max_deq = session_tx_fifo_max_dequeue (&tc->connection);
  max_deq -= tc->snd_una_max - tc->snd_una;
  if (max_deq)
    {
      snd_space = clib_min (max_deq, snd_space);
      burst_size = clib_min (burst_size - n_segs, snd_space / tc->snd_mss);
      n_segs_now = tcp_fast_retransmit_unsent (wrk, tc, burst_size);
      if (max_deq > n_segs_now * tc->snd_mss)
	tcp_program_fastretransmit (wrk, tc);
      n_segs += n_segs_now;
    }

  /* Restore snd_nxt */
  tc->snd_nxt = old_snd_nxt;

done:
  tcp_fastrecovery_first_off (tc);
  return n_segs;
}

/**
 * Do fast retransmit
 */
int
tcp_fast_retransmit (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		     u32 burst_size)
{
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    return tcp_fast_retransmit_sack (wrk, tc, burst_size);
  else
    return tcp_fast_retransmit_no_sack (wrk, tc, burst_size);
}

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
  u32 n_trace = vlib_get_trace_count (vm, node);
  tcp_connection_t *tc;
  tcp_tx_trace_t *t;
  vlib_buffer_t *b;
  tcp_header_t *th;
  int i;

  for (i = 0; i < clib_min (n_trace, n_bufs); i++)
    {
      b = vlib_get_buffer (vm, to_next[i]);
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
  tcp_header_t *th0 = 0;

  th0 = vlib_buffer_get_current (b0);
  TCP_EVT_DBG (TCP_EVT_OUTPUT, tc0, th0->flags, b0->current_length);
  if (is_ip4)
    {
      vlib_buffer_push_ip4 (vm, b0, &tc0->c_lcl_ip4, &tc0->c_rmt_ip4,
			    IP_PROTOCOL_TCP, 1);
      b0->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;
      th0->checksum = 0;
    }
  else
    {
      ip6_header_t *ih0;
      ih0 = vlib_buffer_push_ip6 (vm, b0, &tc0->c_lcl_ip6,
				  &tc0->c_rmt_ip6, IP_PROTOCOL_TCP);
      b0->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
      vnet_buffer (b0)->l3_hdr_offset = (u8 *) ih0 - b0->data;
      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;
      th0->checksum = 0;
    }
}

always_inline void
tcp_output_handle_packet (tcp_connection_t * tc0, vlib_buffer_t * b0,
			  u32 * error0, u16 * next0, u8 is_ip4)
{

  if (PREDICT_FALSE (tc0->state == TCP_STATE_CLOSED))
    {
      *error0 = TCP_ERROR_INVALID_CONNECTION;
      *next0 = TCP_OUTPUT_NEXT_DROP;
      return;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = tc0->c_fib_index;
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;

  if (!is_ip4)
    {
      if (PREDICT_FALSE (ip6_address_is_link_local_unicast (&tc0->c_rmt_ip6)))
	tcp_output_handle_link_local (tc0, b0, next0, error0);
    }

  if (!TCP_ALWAYS_ACK)
    tcp_timer_reset (tc0, TCP_TIMER_DELACK);
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
  tcp_set_time_now (tcp_get_worker (thread_index));

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    tcp46_output_trace_frame (vm, node, from, n_left_from);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      u32 error0 = TCP_ERROR_PKTS_SENT, error1 = TCP_ERROR_PKTS_SENT;
      tcp_connection_t *tc0, *tc1;

      {
	vlib_prefetch_buffer_header (b[2], STORE);
	CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[3], STORE);
	CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
      }

      next[0] = next[1] = TCP_OUTPUT_NEXT_IP_LOOKUP;

      tc0 = tcp_connection_get (vnet_buffer (b[0])->tcp.connection_index,
				thread_index);
      tc1 = tcp_connection_get (vnet_buffer (b[1])->tcp.connection_index,
				thread_index);

      tcp_output_push_ip (vm, b[0], tc0, is_ip4);
      tcp_output_push_ip (vm, b[1], tc1, is_ip4);

      tcp_output_handle_packet (tc0, b[0], &error0, &next[0], is_ip4);
      tcp_output_handle_packet (tc1, b[1], &error1, &next[1], is_ip4);

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      u32 error0 = TCP_ERROR_PKTS_SENT;
      tcp_connection_t *tc0;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	}

      next[0] = TCP_OUTPUT_NEXT_IP_LOOKUP;
      tc0 = tcp_connection_get (vnet_buffer (b[0])->tcp.connection_index,
				thread_index);

      tcp_output_push_ip (vm, b[0], tc0, is_ip4);
      tcp_output_handle_packet (tc0, b[0], &error0, &next[0], is_ip4);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
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
  .function = tcp4_output,
  .name = "tcp4-output",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .protocol_hint = VLIB_NODE_PROTO_HINT_TCP,
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
  .protocol_hint = VLIB_NODE_PROTO_HINT_TCP,
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
  u32 my_thread_index = vm->thread_index;

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
	  tcp_tx_trace_t *t0;
	  tcp_header_t *th0;
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
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
	  next0 = TCP_RESET_NEXT_IP_LOOKUP;

	done:
	  b0->error = node->errors[error0];
	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      th0 = vlib_buffer_get_current (b0);
	      if (is_ip4)
		th0 = ip4_next_header ((ip4_header_t *) th0);
	      else
		th0 = ip6_next_header ((ip6_header_t *) th0);
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy_fast (&t0->tcp_header, th0,
				sizeof (t0->tcp_header));
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
  .format_trace = format_tcp_tx_trace,
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
  .format_trace = format_tcp_tx_trace,
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
