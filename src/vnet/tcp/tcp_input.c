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

#include <vppinfra/sparse_vec.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/session/session.h>
#include <math.h>

static char *tcp_error_strings[] = {
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

/* All TCP nodes have the same outgoing arcs */
#define foreach_tcp_state_next                  \
  _ (DROP4, "ip4-drop")                         \
  _ (DROP6, "ip6-drop")                         \
  _ (TCP4_OUTPUT, "tcp4-output")                \
  _ (TCP6_OUTPUT, "tcp6-output")

typedef enum _tcp_established_next
{
#define _(s,n) TCP_ESTABLISHED_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_ESTABLISHED_N_NEXT,
} tcp_established_next_t;

typedef enum _tcp_rcv_process_next
{
#define _(s,n) TCP_RCV_PROCESS_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_RCV_PROCESS_N_NEXT,
} tcp_rcv_process_next_t;

typedef enum _tcp_syn_sent_next
{
#define _(s,n) TCP_SYN_SENT_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_SYN_SENT_N_NEXT,
} tcp_syn_sent_next_t;

typedef enum _tcp_listen_next
{
#define _(s,n) TCP_LISTEN_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_LISTEN_N_NEXT,
} tcp_listen_next_t;

/* Generic, state independent indices */
typedef enum _tcp_state_next
{
#define _(s,n) TCP_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_STATE_N_NEXT,
} tcp_state_next_t;

#define tcp_next_output(is_ip4) (is_ip4 ? TCP_NEXT_TCP4_OUTPUT          \
                                        : TCP_NEXT_TCP6_OUTPUT)

#define tcp_next_drop(is_ip4) (is_ip4 ? TCP_NEXT_DROP4                  \
                                      : TCP_NEXT_DROP6)

vlib_node_registration_t tcp4_established_node;
vlib_node_registration_t tcp6_established_node;

/**
 * Validate segment sequence number. As per RFC793:
 *
 * Segment Receive Test
 *      Length  Window
 *      ------- -------  -------------------------------------------
 *      0       0       SEG.SEQ = RCV.NXT
 *      0       >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *      >0      0       not acceptable
 *      >0      >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 *
 * This ultimately consists in checking if segment falls within the window.
 * The one important difference compared to RFC793 is that we use rcv_las,
 * or the rcv_nxt at last ack sent instead of rcv_nxt since that's the
 * peer's reference when computing our receive window.
 *
 * This:
 *  seq_leq (end_seq, tc->rcv_las + tc->rcv_wnd) && seq_geq (seq, tc->rcv_las)
 * however, is too strict when we have retransmits. Instead we just check that
 * the seq is not beyond the right edge and that the end of the segment is not
 * less than the left edge.
 *
 * N.B. rcv_nxt and rcv_wnd are both updated in this node if acks are sent, so
 * use rcv_nxt in the right edge window test instead of rcv_las.
 *
 */
always_inline u8
tcp_segment_in_rcv_wnd (tcp_connection_t * tc, u32 seq, u32 end_seq)
{
  return (seq_geq (end_seq, tc->rcv_las)
	  && seq_leq (seq, tc->rcv_nxt + tc->rcv_wnd));
}

/**
 * Parse TCP header options.
 *
 * @param th TCP header
 * @param to TCP options data structure to be populated
 * @param is_syn set if packet is syn
 * @return -1 if parsing failed
 */
static inline int
tcp_options_parse (tcp_header_t * th, tcp_options_t * to, u8 is_syn)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j;
  sack_block_t b;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  /* Zero out all flags but those set in SYN */
  to->flags &= (TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_WSCALE
		| TCP_OPTS_FLAG_TSTAMP | TCP_OPTION_MSS);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  /* broken options */
	  if (opts_len < 2)
	    return -1;
	  opt_len = data[1];

	  /* weird option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    return -1;
	}

      /* Parse options */
      switch (kind)
	{
	case TCP_OPTION_MSS:
	  if (!is_syn)
	    break;
	  if ((opt_len == TCP_OPTION_LEN_MSS) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_MSS;
	      to->mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
	    }
	  break;
	case TCP_OPTION_WINDOW_SCALE:
	  if (!is_syn)
	    break;
	  if ((opt_len == TCP_OPTION_LEN_WINDOW_SCALE) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_WSCALE;
	      to->wscale = data[2];
	      if (to->wscale > TCP_MAX_WND_SCALE)
		to->wscale = TCP_MAX_WND_SCALE;
	    }
	  break;
	case TCP_OPTION_TIMESTAMP:
	  if (is_syn)
	    to->flags |= TCP_OPTS_FLAG_TSTAMP;
	  if ((to->flags & TCP_OPTS_FLAG_TSTAMP)
	      && opt_len == TCP_OPTION_LEN_TIMESTAMP)
	    {
	      to->tsval = clib_net_to_host_u32 (*(u32 *) (data + 2));
	      to->tsecr = clib_net_to_host_u32 (*(u32 *) (data + 6));
	    }
	  break;
	case TCP_OPTION_SACK_PERMITTED:
	  if (!is_syn)
	    break;
	  if (opt_len == TCP_OPTION_LEN_SACK_PERMITTED && tcp_syn (th))
	    to->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
	  break;
	case TCP_OPTION_SACK_BLOCK:
	  /* If SACK permitted was not advertised or a SYN, break */
	  if ((to->flags & TCP_OPTS_FLAG_SACK_PERMITTED) == 0 || tcp_syn (th))
	    break;

	  /* If too short or not correctly formatted, break */
	  if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	    break;

	  to->flags |= TCP_OPTS_FLAG_SACK;
	  to->n_sack_blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
	  vec_reset_length (to->sacks);
	  for (j = 0; j < to->n_sack_blocks; j++)
	    {
	      b.start = clib_net_to_host_u32 (*(u32 *) (data + 2 + 8 * j));
	      b.end = clib_net_to_host_u32 (*(u32 *) (data + 6 + 8 * j));
	      vec_add1 (to->sacks, b);
	    }
	  break;
	default:
	  /* Nothing to see here */
	  continue;
	}
    }
  return 0;
}

/**
 * RFC1323: Check against wrapped sequence numbers (PAWS). If we have
 * timestamp to echo and it's less than tsval_recent, drop segment
 * but still send an ACK in order to retain TCP's mechanism for detecting
 * and recovering from half-open connections
 *
 * Or at least that's what the theory says. It seems that this might not work
 * very well with packet reordering and fast retransmit. XXX
 */
always_inline int
tcp_segment_check_paws (tcp_connection_t * tc)
{
  return tcp_opts_tstamp (&tc->rcv_opts)
    && timestamp_lt (tc->rcv_opts.tsval, tc->tsval_recent);
}

/**
 * Update tsval recent
 */
always_inline void
tcp_update_timestamp (tcp_connection_t * tc, u32 seq, u32 seq_end)
{
  /*
   * RFC1323: If Last.ACK.sent falls within the range of sequence numbers
   * of an incoming segment:
   *    SEG.SEQ <= Last.ACK.sent < SEG.SEQ + SEG.LEN
   * then the TSval from the segment is copied to TS.Recent;
   * otherwise, the TSval is ignored.
   */
  if (tcp_opts_tstamp (&tc->rcv_opts) && seq_leq (seq, tc->rcv_las)
      && seq_leq (tc->rcv_las, seq_end))
    {
      ASSERT (timestamp_leq (tc->tsval_recent, tc->rcv_opts.tsval));
      tc->tsval_recent = tc->rcv_opts.tsval;
      tc->tsval_recent_age = tcp_time_now_w_thread (tc->c_thread_index);
    }
}

/**
 * Validate incoming segment as per RFC793 p. 69 and RFC1323 p. 19
 *
 * It first verifies if segment has a wrapped sequence number (PAWS) and then
 * does the processing associated to the first four steps (ignoring security
 * and precedence): sequence number, rst bit and syn bit checks.
 *
 * @return 0 if segments passes validation.
 */
static int
tcp_segment_validate (tcp_worker_ctx_t * wrk, tcp_connection_t * tc0,
		      vlib_buffer_t * b0, tcp_header_t * th0, u32 * error0)
{
  /* We could get a burst of RSTs interleaved with acks */
  if (PREDICT_FALSE (tc0->state == TCP_STATE_CLOSED))
    {
      tcp_send_reset (tc0);
      *error0 = TCP_ERROR_CONNECTION_CLOSED;
      goto error;
    }

  if (PREDICT_FALSE (!tcp_ack (th0) && !tcp_rst (th0) && !tcp_syn (th0)))
    {
      *error0 = TCP_ERROR_SEGMENT_INVALID;
      goto error;
    }

  if (PREDICT_FALSE (tcp_options_parse (th0, &tc0->rcv_opts, 0)))
    {
      *error0 = TCP_ERROR_OPTIONS;
      goto error;
    }

  if (PREDICT_FALSE (tcp_segment_check_paws (tc0)))
    {
      *error0 = TCP_ERROR_PAWS;
      TCP_EVT_DBG (TCP_EVT_PAWS_FAIL, tc0, vnet_buffer (b0)->tcp.seq_number,
		   vnet_buffer (b0)->tcp.seq_end);

      /* If it just so happens that a segment updates tsval_recent for a
       * segment over 24 days old, invalidate tsval_recent. */
      if (timestamp_lt (tc0->tsval_recent_age + TCP_PAWS_IDLE,
			tcp_time_now_w_thread (tc0->c_thread_index)))
	{
	  tc0->tsval_recent = tc0->rcv_opts.tsval;
	  clib_warning ("paws failed: 24-day old segment");
	}
      /* Drop after ack if not rst. Resets can fail paws check as per
       * RFC 7323 sec. 5.2: When an <RST> segment is received, it MUST NOT
       * be subjected to the PAWS check by verifying an acceptable value in
       * SEG.TSval */
      else if (!tcp_rst (th0))
	{
	  tcp_program_ack (wrk, tc0);
	  TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc0, vnet_buffer (b0)->tcp);
	  goto error;
	}
    }

  /* 1st: check sequence number */
  if (!tcp_segment_in_rcv_wnd (tc0, vnet_buffer (b0)->tcp.seq_number,
			       vnet_buffer (b0)->tcp.seq_end))
    {
      *error0 = TCP_ERROR_RCV_WND;
      /* If our window is 0 and the packet is in sequence, let it pass
       * through for ack processing. It should be dropped later. */
      if (!(tc0->rcv_wnd == 0
	    && tc0->rcv_nxt == vnet_buffer (b0)->tcp.seq_number))
	{
	  /* If not RST, send dup ack */
	  if (!tcp_rst (th0))
	    {
	      tcp_program_dupack (wrk, tc0);
	      TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc0, vnet_buffer (b0)->tcp);
	    }
	  goto error;
	}
    }

  /* 2nd: check the RST bit */
  if (PREDICT_FALSE (tcp_rst (th0)))
    {
      tcp_connection_reset (tc0);
      *error0 = TCP_ERROR_RST_RCVD;
      goto error;
    }

  /* 3rd: check security and precedence (skip) */

  /* 4th: check the SYN bit */
  if (PREDICT_FALSE (tcp_syn (th0)))
    {
      /* TODO implement RFC 5961 */
      if (tc0->state == TCP_STATE_SYN_RCVD)
	{
	  tcp_options_parse (th0, &tc0->rcv_opts, 1);
	  tcp_send_synack (tc0);
	  TCP_EVT_DBG (TCP_EVT_SYN_RCVD, tc0, 0);
	}
      else
	{
	  tcp_program_ack (wrk, tc0);
	  TCP_EVT_DBG (TCP_EVT_SYNACK_RCVD, tc0);
	}
      goto error;
    }

  /* If segment in window, save timestamp */
  tcp_update_timestamp (tc0, vnet_buffer (b0)->tcp.seq_number,
			vnet_buffer (b0)->tcp.seq_end);
  return 0;

error:
  return -1;
}

always_inline int
tcp_rcv_ack_is_acceptable (tcp_connection_t * tc0, vlib_buffer_t * tb0)
{
  /* SND.UNA =< SEG.ACK =< SND.NXT */
  return (seq_leq (tc0->snd_una, vnet_buffer (tb0)->tcp.ack_number)
	  && seq_leq (vnet_buffer (tb0)->tcp.ack_number, tc0->snd_nxt));
}

/**
 * Compute smoothed RTT as per VJ's '88 SIGCOMM and RFC6298
 *
 * Note that although the original article, srtt and rttvar are scaled
 * to minimize round-off errors, here we don't. Instead, we rely on
 * better precision time measurements.
 *
 * TODO support us rtt resolution
 */
static void
tcp_estimate_rtt (tcp_connection_t * tc, u32 mrtt)
{
  int err, diff;

  if (tc->srtt != 0)
    {
      err = mrtt - tc->srtt;

      /* XXX Drop in RTT results in RTTVAR increase and bigger RTO.
       * The increase should be bound */
      tc->srtt = clib_max ((int) tc->srtt + (err >> 3), 1);
      diff = (clib_abs (err) - (int) tc->rttvar) >> 2;
      tc->rttvar = clib_max ((int) tc->rttvar + diff, 1);
    }
  else
    {
      /* First measurement. */
      tc->srtt = mrtt;
      tc->rttvar = mrtt >> 1;
    }
}

void
tcp_update_rto (tcp_connection_t * tc)
{
  tc->rto = clib_min (tc->srtt + (tc->rttvar << 2), TCP_RTO_MAX);
  tc->rto = clib_max (tc->rto, TCP_RTO_MIN);
}

/**
 * Update RTT estimate and RTO timer
 *
 * Measure RTT: We have two sources of RTT measurements: TSOPT and ACK
 * timing. Middle boxes are known to fiddle with TCP options so we
 * should give higher priority to ACK timing.
 *
 * This should be called only if previously sent bytes have been acked.
 *
 * return 1 if valid rtt 0 otherwise
 */
static int
tcp_update_rtt (tcp_connection_t * tc, u32 ack)
{
  u32 mrtt = 0;

  /* Karn's rule, part 1. Don't use retransmitted segments to estimate
   * RTT because they're ambiguous. */
  if (tcp_in_cong_recovery (tc) || tc->sack_sb.sacked_bytes)
    {
      if (tcp_in_recovery (tc))
	return 0;
      goto done;
    }

  if (tc->rtt_ts && seq_geq (ack, tc->rtt_seq))
    {
      f64 sample = tcp_time_now_us (tc->c_thread_index) - tc->rtt_ts;
      tc->mrtt_us = tc->mrtt_us + (sample - tc->mrtt_us) * 0.125;
      mrtt = clib_max ((u32) (sample * THZ), 1);
      /* Allow measuring of a new RTT */
      tc->rtt_ts = 0;
    }
  /* As per RFC7323 TSecr can be used for RTTM only if the segment advances
   * snd_una, i.e., the left side of the send window:
   * seq_lt (tc->snd_una, ack). This is a condition for calling update_rtt */
  else if (tcp_opts_tstamp (&tc->rcv_opts) && tc->rcv_opts.tsecr)
    {
      u32 now = tcp_time_now_w_thread (tc->c_thread_index);
      mrtt = clib_max (now - tc->rcv_opts.tsecr, 1);
    }

  /* Ignore dubious measurements */
  if (mrtt == 0 || mrtt > TCP_RTT_MAX)
    goto done;

  tcp_estimate_rtt (tc, mrtt);

done:

  /* If we got here something must've been ACKed so make sure boff is 0,
   * even if mrtt is not valid since we update the rto lower */
  tc->rto_boff = 0;
  tcp_update_rto (tc);

  return 0;
}

static void
tcp_estimate_initial_rtt (tcp_connection_t * tc)
{
  u8 thread_index = vlib_num_workers ()? 1 : 0;
  int mrtt;

  if (tc->rtt_ts)
    {
      tc->mrtt_us = tcp_time_now_us (thread_index) - tc->rtt_ts;
      mrtt = clib_max ((u32) (tc->mrtt_us * THZ), 1);
      tc->rtt_ts = 0;
    }
  else
    {
      mrtt = tcp_time_now_w_thread (thread_index) - tc->rcv_opts.tsecr;
      mrtt = clib_max (mrtt, 1);
      tc->mrtt_us = (f64) mrtt *TCP_TICK;
    }

  if (mrtt > 0 && mrtt < TCP_RTT_MAX)
    tcp_estimate_rtt (tc, mrtt);
  tcp_update_rto (tc);
}

/**
 * Dequeue bytes for connections that have received acks in last burst
 */
static void
tcp_handle_postponed_dequeues (tcp_worker_ctx_t * wrk)
{
  u32 thread_index = wrk->vm->thread_index;
  u32 *pending_deq_acked;
  tcp_connection_t *tc;
  int i;

  if (!vec_len (wrk->pending_deq_acked))
    return;

  pending_deq_acked = wrk->pending_deq_acked;
  for (i = 0; i < vec_len (pending_deq_acked); i++)
    {
      tc = tcp_connection_get (pending_deq_acked[i], thread_index);
      tc->flags &= ~TCP_CONN_DEQ_PENDING;

      if (PREDICT_FALSE (!tc->burst_acked))
	continue;

      /* Dequeue the newly ACKed bytes */
      stream_session_dequeue_drop (&tc->connection, tc->burst_acked);
      tc->burst_acked = 0;
      tcp_validate_txf_size (tc, tc->snd_una_max - tc->snd_una);

      if (PREDICT_FALSE (tc->flags & TCP_CONN_PSH_PENDING))
	{
	  if (seq_leq (tc->psh_seq, tc->snd_una))
	    tc->flags &= ~TCP_CONN_PSH_PENDING;
	}

      /* If everything has been acked, stop retransmit timer
       * otherwise update. */
      tcp_retransmit_timer_update (tc);

      /* If not congested, update pacer based on our new
       * cwnd estimate */
      if (!tcp_in_fastrecovery (tc))
	tcp_connection_tx_pacer_update (tc);
    }
  _vec_len (wrk->pending_deq_acked) = 0;
}

static void
tcp_program_dequeue (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_DEQ_PENDING))
    {
      vec_add1 (wrk->pending_deq_acked, tc->c_c_index);
      tc->flags |= TCP_CONN_DEQ_PENDING;
    }
  tc->burst_acked += tc->bytes_acked + tc->sack_sb.snd_una_adv;
}

/**
 * Check if duplicate ack as per RFC5681 Sec. 2
 */
static u8
tcp_ack_is_dupack (tcp_connection_t * tc, vlib_buffer_t * b, u32 prev_snd_wnd,
		   u32 prev_snd_una)
{
  return ((vnet_buffer (b)->tcp.ack_number == prev_snd_una)
	  && seq_gt (tc->snd_una_max, tc->snd_una)
	  && (vnet_buffer (b)->tcp.seq_end == vnet_buffer (b)->tcp.seq_number)
	  && (prev_snd_wnd == tc->snd_wnd));
}

/**
 * Checks if ack is a congestion control event.
 */
static u8
tcp_ack_is_cc_event (tcp_connection_t * tc, vlib_buffer_t * b,
		     u32 prev_snd_wnd, u32 prev_snd_una, u8 * is_dack)
{
  /* Check if ack is duplicate. Per RFC 6675, ACKs that SACK new data are
   * defined to be 'duplicate' */
  *is_dack = tc->sack_sb.last_sacked_bytes
    || tcp_ack_is_dupack (tc, b, prev_snd_wnd, prev_snd_una);

  return ((*is_dack || tcp_in_cong_recovery (tc)) && !tcp_is_lost_fin (tc));
}

static u32
scoreboard_hole_index (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  ASSERT (!pool_is_free_index (sb->holes, hole - sb->holes));
  return hole - sb->holes;
}

static u32
scoreboard_hole_bytes (sack_scoreboard_hole_t * hole)
{
  return hole->end - hole->start;
}

sack_scoreboard_hole_t *
scoreboard_get_hole (sack_scoreboard_t * sb, u32 index)
{
  if (index != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, index);
  return 0;
}

sack_scoreboard_hole_t *
scoreboard_next_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->next);
  return 0;
}

sack_scoreboard_hole_t *
scoreboard_prev_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->prev);
  return 0;
}

sack_scoreboard_hole_t *
scoreboard_first_hole (sack_scoreboard_t * sb)
{
  if (sb->head != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->head);
  return 0;
}

sack_scoreboard_hole_t *
scoreboard_last_hole (sack_scoreboard_t * sb)
{
  if (sb->tail != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->tail);
  return 0;
}

static void
scoreboard_remove_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  sack_scoreboard_hole_t *next, *prev;

  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    {
      next = pool_elt_at_index (sb->holes, hole->next);
      next->prev = hole->prev;
    }
  else
    {
      sb->tail = hole->prev;
    }

  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    {
      prev = pool_elt_at_index (sb->holes, hole->prev);
      prev->next = hole->next;
    }
  else
    {
      sb->head = hole->next;
    }

  if (scoreboard_hole_index (sb, hole) == sb->cur_rxt_hole)
    sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    clib_memset (hole, 0xfe, sizeof (*hole));

  pool_put (sb->holes, hole);
}

static sack_scoreboard_hole_t *
scoreboard_insert_hole (sack_scoreboard_t * sb, u32 prev_index,
			u32 start, u32 end)
{
  sack_scoreboard_hole_t *hole, *next, *prev;
  u32 hole_index;

  pool_get (sb->holes, hole);
  clib_memset (hole, 0, sizeof (*hole));

  hole->start = start;
  hole->end = end;
  hole_index = scoreboard_hole_index (sb, hole);

  prev = scoreboard_get_hole (sb, prev_index);
  if (prev)
    {
      hole->prev = prev_index;
      hole->next = prev->next;

      if ((next = scoreboard_next_hole (sb, hole)))
	next->prev = hole_index;
      else
	sb->tail = hole_index;

      prev->next = hole_index;
    }
  else
    {
      sb->head = hole_index;
      hole->prev = TCP_INVALID_SACK_HOLE_INDEX;
      hole->next = TCP_INVALID_SACK_HOLE_INDEX;
    }

  return hole;
}

static void
scoreboard_update_bytes (tcp_connection_t * tc, sack_scoreboard_t * sb)
{
  sack_scoreboard_hole_t *left, *right;
  u32 bytes = 0, blks = 0;

  sb->lost_bytes = 0;
  sb->sacked_bytes = 0;
  left = scoreboard_last_hole (sb);
  if (!left)
    return;

  if (seq_gt (sb->high_sacked, left->end))
    {
      bytes = sb->high_sacked - left->end;
      blks = 1;
    }

  while ((right = left)
	 && bytes < (TCP_DUPACK_THRESHOLD - 1) * tc->snd_mss
	 && blks < TCP_DUPACK_THRESHOLD
	 /* left not updated if above conditions fail */
	 && (left = scoreboard_prev_hole (sb, right)))
    {
      bytes += right->start - left->end;
      blks++;
    }

  /* left is first lost */
  if (left)
    {
      do
	{
	  sb->lost_bytes += scoreboard_hole_bytes (right);
	  left->is_lost = 1;
	  left = scoreboard_prev_hole (sb, right);
	  if (left)
	    bytes += right->start - left->end;
	}
      while ((right = left));
    }

  sb->sacked_bytes = bytes;
}

/**
 * Figure out the next hole to retransmit
 *
 * Follows logic proposed in RFC6675 Sec. 4, NextSeg()
 */
sack_scoreboard_hole_t *
scoreboard_next_rxt_hole (sack_scoreboard_t * sb,
			  sack_scoreboard_hole_t * start,
			  u8 have_unsent, u8 * can_rescue, u8 * snd_limited)
{
  sack_scoreboard_hole_t *hole = 0;

  hole = start ? start : scoreboard_first_hole (sb);
  while (hole && seq_leq (hole->end, sb->high_rxt) && hole->is_lost)
    hole = scoreboard_next_hole (sb, hole);

  /* Nothing, return */
  if (!hole)
    {
      sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
      return 0;
    }

  /* Rule (1): if higher than rxt, less than high_sacked and lost */
  if (hole->is_lost && seq_lt (hole->start, sb->high_sacked))
    {
      sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
    }
  else
    {
      /* Rule (2): available unsent data */
      if (have_unsent)
	{
	  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
	  return 0;
	}
      /* Rule (3): if hole not lost */
      else if (seq_lt (hole->start, sb->high_sacked))
	{
	  *snd_limited = 0;
	  sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
	}
      /* Rule (4): if hole beyond high_sacked */
      else
	{
	  ASSERT (seq_geq (hole->start, sb->high_sacked));
	  *snd_limited = 1;
	  *can_rescue = 1;
	  /* HighRxt MUST NOT be updated */
	  return 0;
	}
    }

  if (hole && seq_lt (sb->high_rxt, hole->start))
    sb->high_rxt = hole->start;

  return hole;
}

static void
scoreboard_init_high_rxt (sack_scoreboard_t * sb, u32 snd_una)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (sb);
  if (hole)
    {
      snd_una = seq_gt (snd_una, hole->start) ? snd_una : hole->start;
      sb->cur_rxt_hole = sb->head;
    }
  sb->high_rxt = snd_una;
  sb->rescue_rxt = snd_una - 1;
}

void
scoreboard_init (sack_scoreboard_t * sb)
{
  sb->head = TCP_INVALID_SACK_HOLE_INDEX;
  sb->tail = TCP_INVALID_SACK_HOLE_INDEX;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
}

void
scoreboard_clear (sack_scoreboard_t * sb)
{
  sack_scoreboard_hole_t *hole;
  while ((hole = scoreboard_first_hole (sb)))
    {
      scoreboard_remove_hole (sb, hole);
    }
  ASSERT (sb->head == sb->tail && sb->head == TCP_INVALID_SACK_HOLE_INDEX);
  ASSERT (pool_elts (sb->holes) == 0);
  sb->sacked_bytes = 0;
  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->snd_una_adv = 0;
  sb->high_sacked = 0;
  sb->high_rxt = 0;
  sb->lost_bytes = 0;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
}

/**
 * Test that scoreboard is sane after recovery
 *
 * Returns 1 if scoreboard is empty or if first hole beyond
 * snd_una.
 */
static u8
tcp_scoreboard_is_sane_post_recovery (tcp_connection_t * tc)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (&tc->sack_sb);
  return (!hole || (seq_geq (hole->start, tc->snd_una)
		    && seq_lt (hole->end, tc->snd_una_max)));
}

void
tcp_rcv_sacks (tcp_connection_t * tc, u32 ack)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *blk, tmp;
  sack_scoreboard_hole_t *hole, *next_hole, *last_hole;
  u32 blk_index = 0, old_sacked_bytes, hole_index;
  int i, j;

  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->snd_una_adv = 0;

  if (!tcp_opts_sack (&tc->rcv_opts)
      && sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    return;

  old_sacked_bytes = sb->sacked_bytes;

  /* Remove invalid blocks */
  blk = tc->rcv_opts.sacks;
  while (blk < vec_end (tc->rcv_opts.sacks))
    {
      if (seq_lt (blk->start, blk->end)
	  && seq_gt (blk->start, tc->snd_una)
	  && seq_gt (blk->start, ack)
	  && seq_lt (blk->start, tc->snd_una_max)
	  && seq_leq (blk->end, tc->snd_una_max))
	{
	  blk++;
	  continue;
	}
      vec_del1 (tc->rcv_opts.sacks, blk - tc->rcv_opts.sacks);
    }

  /* Add block for cumulative ack */
  if (seq_gt (ack, tc->snd_una))
    {
      tmp.start = tc->snd_una;
      tmp.end = ack;
      vec_add1 (tc->rcv_opts.sacks, tmp);
    }

  if (vec_len (tc->rcv_opts.sacks) == 0)
    return;

  tcp_scoreboard_trace_add (tc, ack);

  /* Make sure blocks are ordered */
  for (i = 0; i < vec_len (tc->rcv_opts.sacks); i++)
    for (j = i + 1; j < vec_len (tc->rcv_opts.sacks); j++)
      if (seq_lt (tc->rcv_opts.sacks[j].start, tc->rcv_opts.sacks[i].start))
	{
	  tmp = tc->rcv_opts.sacks[i];
	  tc->rcv_opts.sacks[i] = tc->rcv_opts.sacks[j];
	  tc->rcv_opts.sacks[j] = tmp;
	}

  if (sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    {
      /* If no holes, insert the first that covers all outstanding bytes */
      last_hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
					  tc->snd_una, tc->snd_una_max);
      sb->tail = scoreboard_hole_index (sb, last_hole);
      tmp = tc->rcv_opts.sacks[vec_len (tc->rcv_opts.sacks) - 1];
      sb->high_sacked = tmp.end;
    }
  else
    {
      /* If we have holes but snd_una_max is beyond the last hole, update
       * last hole end */
      tmp = tc->rcv_opts.sacks[vec_len (tc->rcv_opts.sacks) - 1];
      last_hole = scoreboard_last_hole (sb);
      if (seq_gt (tc->snd_una_max, last_hole->end))
	{
	  if (seq_geq (last_hole->start, sb->high_sacked))
	    {
	      last_hole->end = tc->snd_una_max;
	    }
	  /* New hole after high sacked block */
	  else if (seq_lt (sb->high_sacked, tc->snd_una_max))
	    {
	      scoreboard_insert_hole (sb, sb->tail, sb->high_sacked,
				      tc->snd_una_max);
	    }
	}
      /* Keep track of max byte sacked for when the last hole
       * is acked */
      if (seq_gt (tmp.end, sb->high_sacked))
	sb->high_sacked = tmp.end;
    }

  /* Walk the holes with the SACK blocks */
  hole = pool_elt_at_index (sb->holes, sb->head);
  while (hole && blk_index < vec_len (tc->rcv_opts.sacks))
    {
      blk = &tc->rcv_opts.sacks[blk_index];
      if (seq_leq (blk->start, hole->start))
	{
	  /* Block covers hole. Remove hole */
	  if (seq_geq (blk->end, hole->end))
	    {
	      next_hole = scoreboard_next_hole (sb, hole);

	      /* Byte accounting: snd_una needs to be advanced */
	      if (blk->end == ack)
		{
		  if (next_hole)
		    {
		      if (seq_lt (ack, next_hole->start))
			sb->snd_una_adv = next_hole->start - ack;
		      sb->last_bytes_delivered +=
			next_hole->start - hole->end;
		    }
		  else
		    {
		      ASSERT (seq_geq (sb->high_sacked, ack));
		      sb->snd_una_adv = sb->high_sacked - ack;
		      sb->last_bytes_delivered += sb->high_sacked - hole->end;
		    }
		}

	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  hole->start = blk->end;
		}
	      blk_index++;
	    }
	}
      else
	{
	  /* Hole must be split */
	  if (seq_lt (blk->end, hole->end))
	    {
	      hole_index = scoreboard_hole_index (sb, hole);
	      next_hole = scoreboard_insert_hole (sb, hole_index, blk->end,
						  hole->end);

	      /* Pool might've moved */
	      hole = scoreboard_get_hole (sb, hole_index);
	      hole->end = blk->start;
	      blk_index++;
	      ASSERT (hole->next == scoreboard_hole_index (sb, next_hole));
	    }
	  else if (seq_lt (blk->start, hole->end))
	    {
	      hole->end = blk->start;
	    }
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

  if (pool_elts (sb->holes) == 1)
    {
      hole = scoreboard_first_hole (sb);
      if (hole->start == ack + sb->snd_una_adv
	  && hole->end == tc->snd_una_max)
	scoreboard_remove_hole (sb, hole);
    }

  scoreboard_update_bytes (tc, sb);
  sb->last_sacked_bytes = sb->sacked_bytes
    - (old_sacked_bytes - sb->last_bytes_delivered);
  ASSERT (sb->last_sacked_bytes <= sb->sacked_bytes || tcp_in_recovery (tc));
  ASSERT (sb->sacked_bytes == 0 || tcp_in_recovery (tc)
	  || sb->sacked_bytes < tc->snd_una_max - seq_max (tc->snd_una, ack));
  ASSERT (sb->last_sacked_bytes + sb->lost_bytes <= tc->snd_una_max
	  - seq_max (tc->snd_una, ack) || tcp_in_recovery (tc));
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX || tcp_in_recovery (tc)
	  || sb->holes[sb->head].start == ack + sb->snd_una_adv);
  TCP_EVT_DBG (TCP_EVT_CC_SCOREBOARD, tc);
}

/**
 * Try to update snd_wnd based on feedback received from peer.
 *
 * If successful, and new window is 'effectively' 0, activate persist
 * timer.
 */
static void
tcp_update_snd_wnd (tcp_connection_t * tc, u32 seq, u32 ack, u32 snd_wnd)
{
  /* If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
   * SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK */
  if (seq_lt (tc->snd_wl1, seq)
      || (tc->snd_wl1 == seq && seq_leq (tc->snd_wl2, ack)))
    {
      tc->snd_wnd = snd_wnd;
      tc->snd_wl1 = seq;
      tc->snd_wl2 = ack;
      TCP_EVT_DBG (TCP_EVT_SND_WND, tc);

      if (PREDICT_FALSE (tc->snd_wnd < tc->snd_mss))
	{
	  /* Set persist timer if not set and we just got 0 wnd */
	  if (!tcp_timer_is_active (tc, TCP_TIMER_PERSIST)
	      && !tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
	    tcp_persist_timer_set (tc);
	}
      else
	{
	  tcp_persist_timer_reset (tc);
	  if (PREDICT_FALSE (!tcp_in_recovery (tc) && tc->rto_boff > 0))
	    {
	      tc->rto_boff = 0;
	      tcp_update_rto (tc);
	    }
	}
    }
}

/**
 * Init loss recovery/fast recovery.
 *
 * Triggered by dup acks as opposed to timer timeout. Note that cwnd is
 * updated in @ref tcp_cc_handle_event after fast retransmit
 */
void
tcp_cc_init_congestion (tcp_connection_t * tc)
{
  tcp_fastrecovery_on (tc);
  tc->snd_congestion = tc->snd_una_max;
  tc->cwnd_acc_bytes = 0;
  tc->snd_rxt_bytes = 0;
  tc->prev_ssthresh = tc->ssthresh;
  tc->prev_cwnd = tc->cwnd;
  tc->cc_algo->congestion (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 4);
}

static void
tcp_cc_recovery_exit (tcp_connection_t * tc)
{
  tc->rto_boff = 0;
  tcp_update_rto (tc);
  tc->snd_rxt_ts = 0;
  tc->snd_nxt = tc->snd_una_max;
  tc->rtt_ts = 0;
  tcp_recovery_off (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 3);
}

void
tcp_cc_fastrecovery_exit (tcp_connection_t * tc)
{
  tc->cc_algo->recovered (tc);
  tc->snd_rxt_bytes = 0;
  tc->rcv_dupacks = 0;
  tc->snd_nxt = tc->snd_una_max;
  tc->snd_rxt_bytes = 0;
  tc->rtt_ts = 0;

  tcp_fastrecovery_off (tc);
  tcp_fastrecovery_first_off (tc);

  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 3);
}

static void
tcp_cc_congestion_undo (tcp_connection_t * tc)
{
  tc->cwnd = tc->prev_cwnd;
  tc->ssthresh = tc->prev_ssthresh;
  tc->snd_nxt = tc->snd_una_max;
  tc->rcv_dupacks = 0;
  if (tcp_in_recovery (tc))
    tcp_cc_recovery_exit (tc);
  else if (tcp_in_fastrecovery (tc))
    tcp_cc_fastrecovery_exit (tc);
  ASSERT (tc->rto_boff == 0);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 5);
}

static inline u8
tcp_cc_is_spurious_timeout_rxt (tcp_connection_t * tc)
{
  return (tcp_in_recovery (tc) && tc->rto_boff == 1
	  && tc->snd_rxt_ts
	  && tcp_opts_tstamp (&tc->rcv_opts)
	  && timestamp_lt (tc->rcv_opts.tsecr, tc->snd_rxt_ts));
}

static inline u8
tcp_cc_is_spurious_fast_rxt (tcp_connection_t * tc)
{
  return (tcp_in_fastrecovery (tc)
	  && tc->cwnd > tc->ssthresh + 3 * tc->snd_mss);
}

static u8
tcp_cc_is_spurious_retransmit (tcp_connection_t * tc)
{
  return (tcp_cc_is_spurious_timeout_rxt (tc)
	  || tcp_cc_is_spurious_fast_rxt (tc));
}

static int
tcp_cc_recover (tcp_connection_t * tc)
{
  ASSERT (tcp_in_cong_recovery (tc));
  if (tcp_cc_is_spurious_retransmit (tc))
    {
      tcp_cc_congestion_undo (tc);
      return 1;
    }

  if (tcp_in_recovery (tc))
    tcp_cc_recovery_exit (tc);
  else if (tcp_in_fastrecovery (tc))
    tcp_cc_fastrecovery_exit (tc);

  ASSERT (tc->rto_boff == 0);
  ASSERT (!tcp_in_cong_recovery (tc));
  ASSERT (tcp_scoreboard_is_sane_post_recovery (tc));
  return 0;
}

static void
tcp_cc_update (tcp_connection_t * tc, vlib_buffer_t * b)
{
  ASSERT (!tcp_in_cong_recovery (tc) || tcp_is_lost_fin (tc));

  /* Congestion avoidance */
  tcp_cc_rcv_ack (tc);

  /* If a cumulative ack, make sure dupacks is 0 */
  tc->rcv_dupacks = 0;

  /* When dupacks hits the threshold we only enter fast retransmit if
   * cumulative ack covers more than snd_congestion. Should snd_una
   * wrap this test may fail under otherwise valid circumstances.
   * Therefore, proactively update snd_congestion when wrap detected. */
  if (PREDICT_FALSE
      (seq_leq (tc->snd_congestion, tc->snd_una - tc->bytes_acked)
       && seq_gt (tc->snd_congestion, tc->snd_una)))
    tc->snd_congestion = tc->snd_una - 1;
}

static u8
tcp_should_fastrecover_sack (tcp_connection_t * tc)
{
  return (TCP_DUPACK_THRESHOLD - 1) * tc->snd_mss < tc->sack_sb.sacked_bytes;
}

static u8
tcp_should_fastrecover (tcp_connection_t * tc)
{
  return (tc->rcv_dupacks == TCP_DUPACK_THRESHOLD
	  || tcp_should_fastrecover_sack (tc));
}

void
tcp_program_fastretransmit (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!(tc->flags & TCP_CONN_FRXT_PENDING))
    {
      vec_add1 (wrk->pending_fast_rxt, tc->c_c_index);
      tc->flags |= TCP_CONN_FRXT_PENDING;
    }
}

void
tcp_do_fastretransmits (tcp_worker_ctx_t * wrk)
{
  u32 *ongoing_fast_rxt, burst_bytes, sent_bytes, thread_index;
  u32 max_burst_size, burst_size, n_segs = 0, n_segs_now;
  tcp_connection_t *tc;
  u64 last_cpu_time;
  int i;

  if (vec_len (wrk->pending_fast_rxt) == 0
      && vec_len (wrk->postponed_fast_rxt) == 0)
    return;

  thread_index = wrk->vm->thread_index;
  last_cpu_time = wrk->vm->clib_time.last_cpu_time;
  ongoing_fast_rxt = wrk->ongoing_fast_rxt;
  vec_append (ongoing_fast_rxt, wrk->postponed_fast_rxt);
  vec_append (ongoing_fast_rxt, wrk->pending_fast_rxt);

  _vec_len (wrk->postponed_fast_rxt) = 0;
  _vec_len (wrk->pending_fast_rxt) = 0;

  max_burst_size = VLIB_FRAME_SIZE / vec_len (ongoing_fast_rxt);
  max_burst_size = clib_max (max_burst_size, 1);

  for (i = 0; i < vec_len (ongoing_fast_rxt); i++)
    {
      if (n_segs >= VLIB_FRAME_SIZE)
	{
	  vec_add1 (wrk->postponed_fast_rxt, ongoing_fast_rxt[i]);
	  continue;
	}

      tc = tcp_connection_get (ongoing_fast_rxt[i], thread_index);
      tc->flags &= ~TCP_CONN_FRXT_PENDING;

      if (!tcp_in_fastrecovery (tc))
	continue;

      burst_size = clib_min (max_burst_size, VLIB_FRAME_SIZE - n_segs);
      burst_bytes = transport_connection_tx_pacer_burst (&tc->connection,
							 last_cpu_time);
      burst_size = clib_min (burst_size, burst_bytes / tc->snd_mss);
      if (!burst_size)
	{
	  tcp_program_fastretransmit (wrk, tc);
	  continue;
	}

      n_segs_now = tcp_fast_retransmit (wrk, tc, burst_size);
      sent_bytes = clib_min (n_segs_now * tc->snd_mss, burst_bytes);
      transport_connection_tx_pacer_update_bytes (&tc->connection,
						  sent_bytes);
      n_segs += n_segs_now;
    }
  _vec_len (ongoing_fast_rxt) = 0;
  wrk->ongoing_fast_rxt = ongoing_fast_rxt;
}

/**
 * One function to rule them all ... and in the darkness bind them
 */
static void
tcp_cc_handle_event (tcp_connection_t * tc, u32 is_dack)
{
  u32 rxt_delivered;

  if (tcp_in_fastrecovery (tc) && tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      if (tc->bytes_acked)
	goto partial_ack;
      tcp_program_fastretransmit (tcp_get_worker (tc->c_thread_index), tc);
      return;
    }
  /*
   * Duplicate ACK. Check if we should enter fast recovery, or if already in
   * it account for the bytes that left the network.
   */
  else if (is_dack && !tcp_in_recovery (tc))
    {
      TCP_EVT_DBG (TCP_EVT_DUPACK_RCVD, tc, 1);
      ASSERT (tc->snd_una != tc->snd_una_max
	      || tc->sack_sb.last_sacked_bytes);

      tc->rcv_dupacks++;

      /* Pure duplicate ack. If some data got acked, it's handled lower */
      if (tc->rcv_dupacks > TCP_DUPACK_THRESHOLD && !tc->bytes_acked)
	{
	  ASSERT (tcp_in_fastrecovery (tc));
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);
	  return;
	}
      else if (tcp_should_fastrecover (tc))
	{
	  u32 pacer_wnd;

	  ASSERT (!tcp_in_fastrecovery (tc));

	  /* Heuristic to catch potential late dupacks
	   * after fast retransmit exits */
	  if (is_dack && tc->snd_una == tc->snd_congestion
	      && timestamp_leq (tc->rcv_opts.tsecr, tc->tsecr_last_ack))
	    {
	      tc->rcv_dupacks = 0;
	      return;
	    }

	  tcp_cc_init_congestion (tc);
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);

	  if (tcp_opts_sack_permitted (&tc->rcv_opts))
	    {
	      tc->cwnd = tc->ssthresh;
	      scoreboard_init_high_rxt (&tc->sack_sb, tc->snd_una);
	    }
	  else
	    {
	      /* Post retransmit update cwnd to ssthresh and account for the
	       * three segments that have left the network and should've been
	       * buffered at the receiver XXX */
	      tc->cwnd = tc->ssthresh + 3 * tc->snd_mss;
	    }

	  /* Constrain rate until we get a partial ack */
	  pacer_wnd = clib_max (0.1 * tc->cwnd, 2 * tc->snd_mss);
	  tcp_connection_tx_pacer_reset (tc, pacer_wnd,
					 0 /* start bucket */ );
	  tcp_program_fastretransmit (tcp_get_worker (tc->c_thread_index),
				      tc);
	  return;
	}
      else if (!tc->bytes_acked
	       || (tc->bytes_acked && !tcp_in_cong_recovery (tc)))
	{
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);
	  return;
	}
      else
	goto partial_ack;
    }
  /* Don't allow entry in fast recovery if still in recovery, for now */
  else if (0 && is_dack && tcp_in_recovery (tc))
    {
      /* If of of the two conditions lower hold, reset dupacks because
       * we're probably after timeout (RFC6582 heuristics).
       * If Cumulative ack does not cover more than congestion threshold,
       * and:
       * 1) The following doesn't hold: The congestion window is greater
       *    than SMSS bytes and the difference between highest_ack
       *    and prev_highest_ack is at most 4*SMSS bytes
       * 2) Echoed timestamp in the last non-dup ack does not equal the
       *    stored timestamp
       */
      if (seq_leq (tc->snd_una, tc->snd_congestion)
	  && ((!(tc->cwnd > tc->snd_mss
		 && tc->bytes_acked <= 4 * tc->snd_mss))
	      || (tc->rcv_opts.tsecr != tc->tsecr_last_ack)))
	{
	  tc->rcv_dupacks = 0;
	  return;
	}
    }

  if (!tc->bytes_acked)
    return;

partial_ack:
  TCP_EVT_DBG (TCP_EVT_CC_PACK, tc);

  /*
   * Legitimate ACK. 1) See if we can exit recovery
   */

  /* Update the pacing rate. For the first partial ack we move from
   * the artificially constrained rate to the one after congestion */
  tcp_connection_tx_pacer_update (tc);

  if (seq_geq (tc->snd_una, tc->snd_congestion))
    {
      tcp_retransmit_timer_update (tc);

      /* If spurious return, we've already updated everything */
      if (tcp_cc_recover (tc))
	{
	  tc->tsecr_last_ack = tc->rcv_opts.tsecr;
	  return;
	}

      tc->snd_nxt = tc->snd_una_max;

      /* Treat as congestion avoidance ack */
      tcp_cc_rcv_ack (tc);
      return;
    }

  /*
   * Legitimate ACK. 2) If PARTIAL ACK try to retransmit
   */

  /* XXX limit this only to first partial ack? */
  tcp_retransmit_timer_update (tc);

  /* RFC6675: If the incoming ACK is a cumulative acknowledgment,
   * reset dupacks to 0. Also needed if in congestion recovery */
  tc->rcv_dupacks = 0;

  /* Post RTO timeout don't try anything fancy */
  if (tcp_in_recovery (tc))
    {
      tcp_cc_rcv_ack (tc);
      transport_add_tx_event (&tc->connection);
      return;
    }

  /* Remove retransmitted bytes that have been delivered */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      ASSERT (tc->bytes_acked + tc->sack_sb.snd_una_adv
	      >= tc->sack_sb.last_bytes_delivered
	      || (tc->flags & TCP_CONN_FINSNT));

      /* If we have sacks and we haven't gotten an ack beyond high_rxt,
       * remove sacked bytes delivered */
      if (seq_lt (tc->snd_una, tc->sack_sb.high_rxt))
	{
	  rxt_delivered = tc->bytes_acked + tc->sack_sb.snd_una_adv
	    - tc->sack_sb.last_bytes_delivered;
	  ASSERT (tc->snd_rxt_bytes >= rxt_delivered);
	  tc->snd_rxt_bytes -= rxt_delivered;
	}
      else
	{
	  /* Apparently all retransmitted holes have been acked */
	  tc->snd_rxt_bytes = 0;
	  tc->sack_sb.high_rxt = tc->snd_una;
	}
    }
  else
    {
      tcp_fastrecovery_first_on (tc);
      /* Reuse last bytes delivered to track total bytes acked */
      tc->sack_sb.last_bytes_delivered += tc->bytes_acked;
      if (tc->snd_rxt_bytes > tc->bytes_acked)
	tc->snd_rxt_bytes -= tc->bytes_acked;
      else
	tc->snd_rxt_bytes = 0;
    }

  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_PARTIALACK);

  /*
   * Since this was a partial ack, try to retransmit some more data
   */
  tcp_program_fastretransmit (tcp_get_worker (tc->c_thread_index), tc);
}

/**
 * Process incoming ACK
 */
static int
tcp_rcv_ack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, vlib_buffer_t * b,
	     tcp_header_t * th, u32 * error)
{
  u32 prev_snd_wnd, prev_snd_una;
  u8 is_dack;

  TCP_EVT_DBG (TCP_EVT_CC_STAT, tc);

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) */
  if (PREDICT_FALSE (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)))
    {
      /* When we entered recovery, we reset snd_nxt to snd_una. Seems peer
       * still has the data so accept the ack */
      if (tcp_in_recovery (tc)
	  && seq_leq (vnet_buffer (b)->tcp.ack_number, tc->snd_congestion))
	{
	  tc->snd_nxt = vnet_buffer (b)->tcp.ack_number;
	  if (seq_gt (tc->snd_nxt, tc->snd_una_max))
	    tc->snd_una_max = tc->snd_nxt;
	  goto process_ack;
	}

      /* If we have outstanding data and this is within the window, accept it,
       * probably retransmit has timed out. Otherwise ACK segment and then
       * drop it */
      if (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_una_max))
	{
	  tcp_program_ack (wrk, tc);
	  *error = TCP_ERROR_ACK_FUTURE;
	  TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 0,
		       vnet_buffer (b)->tcp.ack_number);
	  return -1;
	}

      TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 2,
		   vnet_buffer (b)->tcp.ack_number);

      tc->snd_nxt = vnet_buffer (b)->tcp.ack_number;
    }

  /* If old ACK, probably it's an old dupack */
  if (PREDICT_FALSE (seq_lt (vnet_buffer (b)->tcp.ack_number, tc->snd_una)))
    {
      *error = TCP_ERROR_ACK_OLD;
      TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 1,
		   vnet_buffer (b)->tcp.ack_number);
      if (tcp_in_fastrecovery (tc) && tc->rcv_dupacks == TCP_DUPACK_THRESHOLD)
	tcp_cc_handle_event (tc, 1);
      /* Don't drop yet */
      return 0;
    }

  /*
   * Looks okay, process feedback
   */
process_ack:
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    tcp_rcv_sacks (tc, vnet_buffer (b)->tcp.ack_number);

  prev_snd_wnd = tc->snd_wnd;
  prev_snd_una = tc->snd_una;
  tcp_update_snd_wnd (tc, vnet_buffer (b)->tcp.seq_number,
		      vnet_buffer (b)->tcp.ack_number,
		      clib_net_to_host_u16 (th->window) << tc->snd_wscale);
  tc->bytes_acked = vnet_buffer (b)->tcp.ack_number - tc->snd_una;
  tc->snd_una = vnet_buffer (b)->tcp.ack_number + tc->sack_sb.snd_una_adv;
  tcp_validate_txf_size (tc, tc->bytes_acked);

  if (tc->bytes_acked)
    {
      tcp_program_dequeue (wrk, tc);
      tcp_update_rtt (tc, vnet_buffer (b)->tcp.ack_number);
    }

  TCP_EVT_DBG (TCP_EVT_ACK_RCVD, tc);

  /*
   * Check if we have congestion event
   */

  if (tcp_ack_is_cc_event (tc, b, prev_snd_wnd, prev_snd_una, &is_dack))
    {
      tcp_cc_handle_event (tc, is_dack);
      if (!tcp_in_cong_recovery (tc))
	{
	  *error = TCP_ERROR_ACK_OK;
	  return 0;
	}
      *error = TCP_ERROR_ACK_DUP;
      if (vnet_buffer (b)->tcp.data_len || tcp_is_fin (th))
	return 0;
      return -1;
    }

  /*
   * Update congestion control (slow start/congestion avoidance)
   */
  tcp_cc_update (tc, b);
  *error = TCP_ERROR_ACK_OK;
  return 0;
}

static void
tcp_program_disconnect (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!tcp_disconnect_pending (tc))
    {
      vec_add1 (wrk->pending_disconnects, tc->c_c_index);
      tcp_disconnect_pending_on (tc);
    }
}

static void
tcp_handle_disconnects (tcp_worker_ctx_t * wrk)
{
  u32 thread_index, *pending_disconnects;
  tcp_connection_t *tc;
  int i;

  if (!vec_len (wrk->pending_disconnects))
    return;

  thread_index = wrk->vm->thread_index;
  pending_disconnects = wrk->pending_disconnects;
  for (i = 0; i < vec_len (pending_disconnects); i++)
    {
      tc = tcp_connection_get (pending_disconnects[i], thread_index);
      tcp_disconnect_pending_off (tc);
      session_transport_closing_notify (&tc->connection);
    }
  _vec_len (wrk->pending_disconnects) = 0;
}

static void
tcp_rcv_fin (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, vlib_buffer_t * b,
	     u32 * error)
{
  /* Account for the FIN and send ack */
  tc->rcv_nxt += 1;
  tcp_program_ack (wrk, tc);
  /* Enter CLOSE-WAIT and notify session. To avoid lingering
   * in CLOSE-WAIT, set timer (reuse WAITCLOSE). */
  tcp_connection_set_state (tc, TCP_STATE_CLOSE_WAIT);
  tcp_program_disconnect (wrk, tc);
  tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
  TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc);
  *error = TCP_ERROR_FIN_RCVD;
}

static u8
tcp_sack_vector_is_sane (sack_block_t * sacks)
{
  int i;
  for (i = 1; i < vec_len (sacks); i++)
    {
      if (sacks[i - 1].end == sacks[i].start)
	return 0;
    }
  return 1;
}

/**
 * Build SACK list as per RFC2018.
 *
 * Makes sure the first block contains the segment that generated the current
 * ACK and the following ones are the ones most recently reported in SACK
 * blocks.
 *
 * @param tc TCP connection for which the SACK list is updated
 * @param start Start sequence number of the newest SACK block
 * @param end End sequence of the newest SACK block
 */
void
tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end)
{
  sack_block_t *new_list = 0, *block = 0;
  int i;

  /* If the first segment is ooo add it to the list. Last write might've moved
   * rcv_nxt over the first segment. */
  if (seq_lt (tc->rcv_nxt, start))
    {
      vec_add2 (new_list, block, 1);
      block->start = start;
      block->end = end;
    }

  /* Find the blocks still worth keeping. */
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    {
      /* Discard if rcv_nxt advanced beyond current block */
      if (seq_leq (tc->snd_sacks[i].start, tc->rcv_nxt))
	continue;

      /* Merge or drop if segment overlapped by the new segment */
      if (block && (seq_geq (tc->snd_sacks[i].end, new_list[0].start)
		    && seq_leq (tc->snd_sacks[i].start, new_list[0].end)))
	{
	  if (seq_lt (tc->snd_sacks[i].start, new_list[0].start))
	    new_list[0].start = tc->snd_sacks[i].start;
	  if (seq_lt (new_list[0].end, tc->snd_sacks[i].end))
	    new_list[0].end = tc->snd_sacks[i].end;
	  continue;
	}

      /* Save to new SACK list if we have space. */
      if (vec_len (new_list) < TCP_MAX_SACK_BLOCKS)
	{
	  vec_add1 (new_list, tc->snd_sacks[i]);
	}
      else
	{
	  clib_warning ("sack discarded");
	}
    }

  ASSERT (vec_len (new_list) <= TCP_MAX_SACK_BLOCKS);

  /* Replace old vector with new one */
  vec_free (tc->snd_sacks);
  tc->snd_sacks = new_list;

  /* Segments should not 'touch' */
  ASSERT (tcp_sack_vector_is_sane (tc->snd_sacks));
}

u32
tcp_sack_list_bytes (tcp_connection_t * tc)
{
  u32 bytes = 0, i;
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    bytes += tc->snd_sacks[i].end - tc->snd_sacks[i].start;
  return bytes;
}

/** Enqueue data for delivery to application */
static int
tcp_session_enqueue_data (tcp_connection_t * tc, vlib_buffer_t * b,
			  u16 data_len)
{
  int written, error = TCP_ERROR_ENQUEUED;

  ASSERT (seq_geq (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt));
  ASSERT (data_len);
  written = session_enqueue_stream_connection (&tc->connection, b, 0,
					       1 /* queue event */ , 1);

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 0, data_len, written);

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      tc->rcv_nxt += written;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      tc->rcv_nxt += written;
      TCP_EVT_DBG (TCP_EVT_CC_INPUT, tc, data_len, written);
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      tc->rcv_nxt += written;
      error = TCP_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      return TCP_ERROR_FIFO_FULL;
    }

  /* Update SACK list if need be */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      /* Remove SACK blocks that have been delivered */
      tcp_update_sack_list (tc, tc->rcv_nxt, tc->rcv_nxt);
    }

  return error;
}

/** Enqueue out-of-order data */
static int
tcp_session_enqueue_ooo (tcp_connection_t * tc, vlib_buffer_t * b,
			 u16 data_len)
{
  stream_session_t *s0;
  int rv, offset;

  ASSERT (seq_gt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt));
  ASSERT (data_len);

  /* Enqueue out-of-order data with relative offset */
  rv = session_enqueue_stream_connection (&tc->connection, b,
					  vnet_buffer (b)->tcp.seq_number -
					  tc->rcv_nxt, 0 /* queue event */ ,
					  0);

  /* Nothing written */
  if (rv)
    {
      TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, 0);
      return TCP_ERROR_FIFO_FULL;
    }

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, data_len);

  /* Update SACK list if in use */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      ooo_segment_t *newest;
      u32 start, end;

      s0 = session_get (tc->c_s_index, tc->c_thread_index);

      /* Get the newest segment from the fifo */
      newest = svm_fifo_newest_ooo_segment (s0->server_rx_fifo);
      if (newest)
	{
	  offset = ooo_segment_offset (s0->server_rx_fifo, newest);
	  ASSERT (offset <= vnet_buffer (b)->tcp.seq_number - tc->rcv_nxt);
	  start = tc->rcv_nxt + offset;
	  end = start + ooo_segment_length (s0->server_rx_fifo, newest);
	  tcp_update_sack_list (tc, start, end);
	  svm_fifo_newest_ooo_segment_reset (s0->server_rx_fifo);
	  TCP_EVT_DBG (TCP_EVT_CC_SACKS, tc);
	}
    }

  return TCP_ERROR_ENQUEUED_OOO;
}

/**
 * Check if ACK could be delayed. If ack can be delayed, it should return
 * true for a full frame. If we're always acking return 0.
 */
always_inline int
tcp_can_delack (tcp_connection_t * tc)
{
  /* Send ack if ... */
  if (TCP_ALWAYS_ACK
      /* just sent a rcv wnd 0 */
      || (tc->flags & TCP_CONN_SENT_RCV_WND0) != 0
      /* constrained to send ack */
      || (tc->flags & TCP_CONN_SNDACK) != 0
      /* we're almost out of tx wnd */
      || tcp_available_cc_snd_space (tc) < 4 * tc->snd_mss)
    return 0;

  return 1;
}

static int
tcp_buffer_discard_bytes (vlib_buffer_t * b, u32 n_bytes_to_drop)
{
  u32 discard, first = b->current_length;
  vlib_main_t *vm = vlib_get_main ();

  /* Handle multi-buffer segments */
  if (n_bytes_to_drop > b->current_length)
    {
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	return -1;
      do
	{
	  discard = clib_min (n_bytes_to_drop, b->current_length);
	  vlib_buffer_advance (b, discard);
	  b = vlib_get_buffer (vm, b->next_buffer);
	  n_bytes_to_drop -= discard;
	}
      while (n_bytes_to_drop);
      if (n_bytes_to_drop > first)
	b->total_length_not_including_first_buffer -= n_bytes_to_drop - first;
    }
  else
    vlib_buffer_advance (b, n_bytes_to_drop);
  vnet_buffer (b)->tcp.data_len -= n_bytes_to_drop;
  return 0;
}

/**
 * Receive buffer for connection and handle acks
 *
 * It handles both in order or out-of-order data.
 */
static int
tcp_segment_rcv (tcp_worker_ctx_t * wrk, tcp_connection_t * tc,
		 vlib_buffer_t * b)
{
  u32 error, n_bytes_to_drop, n_data_bytes;

  vlib_buffer_advance (b, vnet_buffer (b)->tcp.data_offset);
  n_data_bytes = vnet_buffer (b)->tcp.data_len;
  ASSERT (n_data_bytes);

  /* Handle out-of-order data */
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.seq_number != tc->rcv_nxt))
    {
      /* Old sequence numbers allowed through because they overlapped
       * the rx window */
      if (seq_lt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt))
	{
	  /* Completely in the past (possible retransmit). Ack
	   * retransmissions since we may not have any data to send */
	  if (seq_leq (vnet_buffer (b)->tcp.seq_end, tc->rcv_nxt))
	    {
	      tcp_program_ack (wrk, tc);
	      error = TCP_ERROR_SEGMENT_OLD;
	      goto done;
	    }

	  /* Chop off the bytes in the past and see if what is left
	   * can be enqueued in order */
	  n_bytes_to_drop = tc->rcv_nxt - vnet_buffer (b)->tcp.seq_number;
	  n_data_bytes -= n_bytes_to_drop;
	  vnet_buffer (b)->tcp.seq_number = tc->rcv_nxt;
	  if (tcp_buffer_discard_bytes (b, n_bytes_to_drop))
	    {
	      error = TCP_ERROR_SEGMENT_OLD;
	      goto done;
	    }
	  goto in_order;
	}

      /* RFC2581: Enqueue and send DUPACK for fast retransmit */
      error = tcp_session_enqueue_ooo (tc, b, n_data_bytes);
      tcp_program_dupack (wrk, tc);
      TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc, vnet_buffer (b)->tcp);
      goto done;
    }

in_order:

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);
  if (tcp_can_delack (tc))
    {
      if (!tcp_timer_is_active (tc, TCP_TIMER_DELACK))
	tcp_timer_set (tc, TCP_TIMER_DELACK, TCP_DELACK_TIME);
      goto done;
    }

  tcp_program_ack (wrk, tc);

done:
  return error;
}

typedef struct
{
  tcp_header_t tcp_header;
  tcp_connection_t tcp_connection;
} tcp_rx_trace_t;

static u8 *
format_tcp_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_rx_trace_t *t = va_arg (*args, tcp_rx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U\n%U%U",
	      format_tcp_header, &t->tcp_header, 128,
	      format_white_space, indent,
	      format_tcp_connection, &t->tcp_connection, 1);

  return s;
}

static u8 *
format_tcp_rx_trace_short (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_rx_trace_t *t = va_arg (*args, tcp_rx_trace_t *);

  s = format (s, "%d -> %d (%U)",
	      clib_net_to_host_u16 (t->tcp_header.dst_port),
	      clib_net_to_host_u16 (t->tcp_header.src_port), format_tcp_state,
	      t->tcp_connection.state);

  return s;
}

static void
tcp_set_rx_trace_data (tcp_rx_trace_t * t0, tcp_connection_t * tc0,
		       tcp_header_t * th0, vlib_buffer_t * b0, u8 is_ip4)
{
  if (tc0)
    {
      clib_memcpy_fast (&t0->tcp_connection, tc0,
			sizeof (t0->tcp_connection));
    }
  else
    {
      th0 = tcp_buffer_hdr (b0);
    }
  clib_memcpy_fast (&t0->tcp_header, th0, sizeof (t0->tcp_header));
}

static void
tcp_established_trace_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame, u8 is_ip4)
{
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 1)
    {
      tcp_connection_t *tc0;
      tcp_rx_trace_t *t0;
      tcp_header_t *th0;
      vlib_buffer_t *b0;
      u32 bi0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				    vm->thread_index);
	  th0 = tcp_buffer_hdr (b0);
	  tcp_set_rx_trace_data (t0, tc0, th0, b0, is_ip4);
	}

      from += 1;
      n_left -= 1;
    }
}

always_inline void
tcp_node_inc_counter_i (vlib_main_t * vm, u32 tcp4_node, u32 tcp6_node,
			u8 is_ip4, u32 evt, u32 val)
{
  if (is_ip4)
    vlib_node_increment_counter (vm, tcp4_node, evt, val);
  else
    vlib_node_increment_counter (vm, tcp6_node, evt, val);
}

#define tcp_maybe_inc_counter(node_id, err, count)			\
{									\
  if (next0 != tcp_next_drop (is_ip4))					\
    tcp_node_inc_counter_i (vm, tcp4_##node_id##_node.index,		\
                            tcp6_##node_id##_node.index, is_ip4, err, 	\
			    1);						\
}
#define tcp_inc_counter(node_id, err, count)				\
  tcp_node_inc_counter_i (vm, tcp4_##node_id##_node.index,		\
	                   tcp6_##node_id##_node.index, is_ip4,		\
	                   err, count)
#define tcp_maybe_inc_err_counter(cnts, err)				\
{									\
  cnts[err] += (next0 != tcp_next_drop (is_ip4));			\
}
#define tcp_inc_err_counter(cnts, err, val)				\
{									\
  cnts[err] += val;							\
}
#define tcp_store_err_counters(node_id, cnts)				\
{									\
  int i;								\
  for (i = 0; i < TCP_N_ERROR; i++)					\
    if (cnts[i])							\
      tcp_inc_counter(node_id, i, cnts[i]);				\
}


always_inline uword
tcp46_established_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, int is_ip4)
{
  u32 thread_index = vm->thread_index, errors = 0;
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  u32 n_left_from, *from, *first_buffer;
  u16 err_counters[TCP_N_ERROR] = { 0 };

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    tcp_established_trace_frame (vm, node, frame, is_ip4);

  first_buffer = from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0, error0 = TCP_ERROR_ACK_OK;
      vlib_buffer_t *b0;
      tcp_header_t *th0;
      tcp_connection_t *tc0;

      if (n_left_from > 1)
	{
	  vlib_buffer_t *pb;
	  pb = vlib_get_buffer (vm, from[1]);
	  vlib_prefetch_buffer_header (pb, LOAD);
	  CLIB_PREFETCH (pb->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	}

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				thread_index);

      if (PREDICT_FALSE (tc0 == 0))
	{
	  error0 = TCP_ERROR_INVALID_CONNECTION;
	  goto done;
	}

      th0 = tcp_buffer_hdr (b0);

      /* TODO header prediction fast path */

      /* 1-4: check SEQ, RST, SYN */
      if (PREDICT_FALSE (tcp_segment_validate (wrk, tc0, b0, th0, &error0)))
	{
	  TCP_EVT_DBG (TCP_EVT_SEG_INVALID, tc0, vnet_buffer (b0)->tcp);
	  goto done;
	}

      /* 5: check the ACK field  */
      if (PREDICT_FALSE (tcp_rcv_ack (wrk, tc0, b0, th0, &error0)))
	goto done;

      /* 6: check the URG bit TODO */

      /* 7: process the segment text */
      if (vnet_buffer (b0)->tcp.data_len)
	error0 = tcp_segment_rcv (wrk, tc0, b0);

      /* 8: check the FIN bit */
      if (PREDICT_FALSE (tcp_is_fin (th0)))
	tcp_rcv_fin (wrk, tc0, b0, &error0);

    done:
      tcp_inc_err_counter (err_counters, error0, 1);
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 thread_index);
  err_counters[TCP_ERROR_MSG_QUEUE_FULL] = errors;
  tcp_store_err_counters (established, err_counters);
  tcp_handle_postponed_dequeues (wrk);
  tcp_handle_disconnects (wrk);
  vlib_buffer_free (vm, first_buffer, frame->n_vectors);

  return frame->n_vectors;
}

static uword
tcp4_established (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_established (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_established_node) =
{
  .function = tcp4_established,
  .name = "tcp4-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_established_node, tcp4_established);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_established_node) =
{
  .function = tcp6_established,
  .name = "tcp6-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */


VLIB_NODE_FUNCTION_MULTIARCH (tcp6_established_node, tcp6_established);

vlib_node_registration_t tcp4_syn_sent_node;
vlib_node_registration_t tcp6_syn_sent_node;

static u8
tcp_lookup_is_valid (tcp_connection_t * tc, tcp_header_t * hdr)
{
  transport_connection_t *tmp = 0;
  u64 handle;

  if (!tc)
    return 1;

  /* Proxy case */
  if (tc->c_lcl_port == 0 && tc->state == TCP_STATE_LISTEN)
    return 1;

  u8 is_valid = (tc->c_lcl_port == hdr->dst_port
		 && (tc->state == TCP_STATE_LISTEN
		     || tc->c_rmt_port == hdr->src_port));

  if (!is_valid)
    {
      handle = session_lookup_half_open_handle (&tc->connection);
      tmp = session_lookup_half_open_connection (handle & 0xFFFFFFFF,
						 tc->c_proto, tc->c_is_ip4);

      if (tmp)
	{
	  if (tmp->lcl_port == hdr->dst_port
	      && tmp->rmt_port == hdr->src_port)
	    {
	      TCP_DBG ("half-open is valid!");
	    }
	}
    }
  return is_valid;
}

/**
 * Lookup transport connection
 */
static tcp_connection_t *
tcp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
		       u8 is_ip4)
{
  tcp_header_t *tcp;
  transport_connection_t *tconn;
  tcp_connection_t *tc;
  u8 is_filtered = 0;
  if (is_ip4)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      tcp = ip4_next_header (ip4);
      tconn = session_lookup_connection_wt4 (fib_index,
					     &ip4->dst_address,
					     &ip4->src_address,
					     tcp->dst_port,
					     tcp->src_port,
					     TRANSPORT_PROTO_TCP,
					     thread_index, &is_filtered);
      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, tcp));
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      tcp = ip6_next_header (ip6);
      tconn = session_lookup_connection_wt6 (fib_index,
					     &ip6->dst_address,
					     &ip6->src_address,
					     tcp->dst_port,
					     tcp->src_port,
					     TRANSPORT_PROTO_TCP,
					     thread_index, &is_filtered);
      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, tcp));
    }
  return tc;
}

always_inline uword
tcp46_syn_sent_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, *from, *first_buffer, errors = 0;
  u32 my_thread_index = vm->thread_index;
  tcp_worker_ctx_t *wrk = tcp_get_worker (my_thread_index);

  from = first_buffer = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0, ack0, seq0, error0 = TCP_ERROR_NONE;
      tcp_connection_t *tc0, *new_tc0;
      tcp_header_t *tcp0 = 0;
      tcp_rx_trace_t *t0;
      vlib_buffer_t *b0;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      tc0 =
	tcp_half_open_connection_get (vnet_buffer (b0)->tcp.connection_index);
      if (PREDICT_FALSE (tc0 == 0))
	{
	  error0 = TCP_ERROR_INVALID_CONNECTION;
	  goto drop;
	}

      /* Half-open completed recently but the connection was't removed
       * yet by the owning thread */
      if (PREDICT_FALSE (tc0->flags & TCP_CONN_HALF_OPEN_DONE))
	{
	  /* Make sure the connection actually exists */
	  ASSERT (tcp_lookup_connection (tc0->c_fib_index, b0,
					 my_thread_index, is_ip4));
	  goto drop;
	}

      ack0 = vnet_buffer (b0)->tcp.ack_number;
      seq0 = vnet_buffer (b0)->tcp.seq_number;
      tcp0 = tcp_buffer_hdr (b0);

      /* Crude check to see if the connection handle does not match
       * the packet. Probably connection just switched to established */
      if (PREDICT_FALSE (tcp0->dst_port != tc0->c_lcl_port
			 || tcp0->src_port != tc0->c_rmt_port))
	{
	  error0 = TCP_ERROR_INVALID_CONNECTION;
	  goto drop;
	}

      if (PREDICT_FALSE (!tcp_ack (tcp0) && !tcp_rst (tcp0)
			 && !tcp_syn (tcp0)))
	{
	  error0 = TCP_ERROR_SEGMENT_INVALID;
	  goto drop;
	}

      /* SYNs consume sequence numbers */
      vnet_buffer (b0)->tcp.seq_end += tcp_is_syn (tcp0);

      /*
       *  1. check the ACK bit
       */

      /*
       *   If the ACK bit is set
       *     If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
       *     the RST bit is set, if so drop the segment and return)
       *       <SEQ=SEG.ACK><CTL=RST>
       *     and discard the segment.  Return.
       *     If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
       */
      if (tcp_ack (tcp0))
	{
	  if (seq_leq (ack0, tc0->iss) || seq_gt (ack0, tc0->snd_nxt))
	    {
	      if (!tcp_rst (tcp0))
		tcp_send_reset_w_pkt (tc0, b0, is_ip4);
	      error0 = TCP_ERROR_RCV_WND;
	      goto drop;
	    }

	  /* Make sure ACK is valid */
	  if (seq_gt (tc0->snd_una, ack0))
	    {
	      error0 = TCP_ERROR_ACK_INVALID;
	      goto drop;
	    }
	}

      /*
       * 2. check the RST bit
       */

      if (tcp_rst (tcp0))
	{
	  /* If ACK is acceptable, signal client that peer is not
	   * willing to accept connection and drop connection*/
	  if (tcp_ack (tcp0))
	    tcp_connection_reset (tc0);
	  error0 = TCP_ERROR_RST_RCVD;
	  goto drop;
	}

      /*
       * 3. check the security and precedence (skipped)
       */

      /*
       * 4. check the SYN bit
       */

      /* No SYN flag. Drop. */
      if (!tcp_syn (tcp0))
	{
	  clib_warning ("not synack");
	  error0 = TCP_ERROR_SEGMENT_INVALID;
	  goto drop;
	}

      /* Parse options */
      if (tcp_options_parse (tcp0, &tc0->rcv_opts, 1))
	{
	  clib_warning ("options parse fail");
	  error0 = TCP_ERROR_OPTIONS;
	  goto drop;
	}

      /* Valid SYN or SYN-ACK. Move connection from half-open pool to
       * current thread pool. */
      pool_get (tm->connections[my_thread_index], new_tc0);
      clib_memcpy_fast (new_tc0, tc0, sizeof (*new_tc0));
      new_tc0->c_c_index = new_tc0 - tm->connections[my_thread_index];
      new_tc0->c_thread_index = my_thread_index;
      new_tc0->rcv_nxt = vnet_buffer (b0)->tcp.seq_end;
      new_tc0->irs = seq0;
      new_tc0->timers[TCP_TIMER_ESTABLISH_AO] = TCP_TIMER_HANDLE_INVALID;
      new_tc0->timers[TCP_TIMER_RETRANSMIT_SYN] = TCP_TIMER_HANDLE_INVALID;
      new_tc0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /* If this is not the owning thread, wait for syn retransmit to
       * expire and cleanup then */
      if (tcp_half_open_connection_cleanup (tc0))
	tc0->flags |= TCP_CONN_HALF_OPEN_DONE;

      if (tcp_opts_tstamp (&new_tc0->rcv_opts))
	{
	  new_tc0->tsval_recent = new_tc0->rcv_opts.tsval;
	  new_tc0->tsval_recent_age = tcp_time_now ();
	}

      if (tcp_opts_wscale (&new_tc0->rcv_opts))
	new_tc0->snd_wscale = new_tc0->rcv_opts.wscale;
      else
	new_tc0->rcv_wscale = 0;

      new_tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window)
	<< new_tc0->snd_wscale;
      new_tc0->snd_wl1 = seq0;
      new_tc0->snd_wl2 = ack0;

      tcp_connection_init_vars (new_tc0);

      /* SYN-ACK: See if we can switch to ESTABLISHED state */
      if (PREDICT_TRUE (tcp_ack (tcp0)))
	{
	  /* Our SYN is ACKed: we have iss < ack = snd_una */

	  /* TODO Dequeue acknowledged segments if we support Fast Open */
	  new_tc0->snd_una = ack0;
	  new_tc0->state = TCP_STATE_ESTABLISHED;

	  /* Make sure las is initialized for the wnd computation */
	  new_tc0->rcv_las = new_tc0->rcv_nxt;

	  /* Notify app that we have connection. If session layer can't
	   * allocate session send reset */
	  if (session_stream_connect_notify (&new_tc0->connection, 0))
	    {
	      clib_warning ("connect notify fail");
	      tcp_send_reset_w_pkt (new_tc0, b0, is_ip4);
	      tcp_connection_cleanup (new_tc0);
	      goto drop;
	    }

	  new_tc0->tx_fifo_size =
	    transport_tx_fifo_size (&new_tc0->connection);
	  /* Update rtt with the syn-ack sample */
	  tcp_estimate_initial_rtt (new_tc0);
	  TCP_EVT_DBG (TCP_EVT_SYNACK_RCVD, new_tc0);
	  error0 = TCP_ERROR_SYN_ACKS_RCVD;
	}
      /* SYN: Simultaneous open. Change state to SYN-RCVD and send SYN-ACK */
      else
	{
	  new_tc0->state = TCP_STATE_SYN_RCVD;

	  /* Notify app that we have connection */
	  if (session_stream_connect_notify (&new_tc0->connection, 0))
	    {
	      tcp_connection_cleanup (new_tc0);
	      tcp_send_reset_w_pkt (tc0, b0, is_ip4);
	      TCP_EVT_DBG (TCP_EVT_RST_SENT, tc0);
	      goto drop;
	    }

	  new_tc0->tx_fifo_size =
	    transport_tx_fifo_size (&new_tc0->connection);
	  new_tc0->rtt_ts = 0;
	  tcp_init_snd_vars (new_tc0);
	  tcp_send_synack (new_tc0);
	  error0 = TCP_ERROR_SYNS_RCVD;
	  goto drop;
	}

      /* Read data, if any */
      if (PREDICT_FALSE (vnet_buffer (b0)->tcp.data_len))
	{
	  clib_warning ("rcvd data in syn-sent");
	  error0 = tcp_segment_rcv (wrk, new_tc0, b0);
	  if (error0 == TCP_ERROR_ACK_OK)
	    error0 = TCP_ERROR_SYN_ACKS_RCVD;
	}
      else
	{
	  tcp_program_ack (wrk, new_tc0);
	}

    drop:

      tcp_inc_counter (syn_sent, error0, 1);
      if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED) && tcp0 != 0))
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  clib_memcpy_fast (&t0->tcp_header, tcp0, sizeof (t0->tcp_header));
	  clib_memcpy_fast (&t0->tcp_connection, tc0,
			    sizeof (t0->tcp_connection));
	}
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 my_thread_index);
  tcp_inc_counter (syn_sent, TCP_ERROR_MSG_QUEUE_FULL, errors);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

static uword
tcp4_syn_sent (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_syn_sent_rcv (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_syn_sent_node) =
{
  .function = tcp4_syn_sent,
  .name = "tcp4-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_syn_sent_node, tcp4_syn_sent);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_syn_sent_node) =
{
  .function = tcp6_syn_sent_rcv,
  .name = "tcp6-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_syn_sent_node, tcp6_syn_sent_rcv);

vlib_node_registration_t tcp4_rcv_process_node;
vlib_node_registration_t tcp6_rcv_process_node;

/**
 * Handles reception for all states except LISTEN, SYN-SENT and ESTABLISHED
 * as per RFC793 p. 64
 */
always_inline uword
tcp46_rcv_process_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame, int is_ip4)
{
  u32 thread_index = vm->thread_index, errors = 0, *first_buffer;
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  u32 n_left_from, *from, max_dequeue;

  from = first_buffer = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0, error0 = TCP_ERROR_NONE;
      tcp_header_t *tcp0 = 0;
      tcp_connection_t *tc0;
      vlib_buffer_t *b0;
      u8 is_fin0;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				thread_index);
      if (PREDICT_FALSE (tc0 == 0))
	{
	  error0 = TCP_ERROR_INVALID_CONNECTION;
	  goto drop;
	}

      tcp0 = tcp_buffer_hdr (b0);
      is_fin0 = tcp_is_fin (tcp0);

      if (CLIB_DEBUG)
	{
	  tcp_connection_t *tmp;
	  tmp = tcp_lookup_connection (tc0->c_fib_index, b0, thread_index,
				       is_ip4);
	  if (tmp->state != tc0->state)
	    {
	      clib_warning ("state changed");
	      goto drop;
	    }
	}

      /*
       * Special treatment for CLOSED
       */
      if (PREDICT_FALSE (tc0->state == TCP_STATE_CLOSED))
	{
	  error0 = TCP_ERROR_CONNECTION_CLOSED;
	  goto drop;
	}

      /*
       * For all other states (except LISTEN)
       */

      /* 1-4: check SEQ, RST, SYN */
      if (PREDICT_FALSE (tcp_segment_validate (wrk, tc0, b0, tcp0, &error0)))
	goto drop;

      /* 5: check the ACK field  */
      switch (tc0->state)
	{
	case TCP_STATE_SYN_RCVD:
	  /*
	   * If the segment acknowledgment is not acceptable, form a
	   * reset segment,
	   *  <SEQ=SEG.ACK><CTL=RST>
	   * and send it.
	   */
	  if (!tcp_rcv_ack_is_acceptable (tc0, b0))
	    {
	      tcp_connection_reset (tc0);
	      error0 = TCP_ERROR_ACK_INVALID;
	      goto drop;
	    }

	  /* Make sure the ack is exactly right */
	  if (tc0->rcv_nxt != vnet_buffer (b0)->tcp.seq_number || is_fin0
	      || vnet_buffer (b0)->tcp.data_len)
	    {
	      tcp_connection_reset (tc0);
	      error0 = TCP_ERROR_SEGMENT_INVALID;
	      goto drop;
	    }

	  /* Update rtt and rto */
	  tcp_estimate_initial_rtt (tc0);

	  /* Switch state to ESTABLISHED */
	  tc0->state = TCP_STATE_ESTABLISHED;
	  TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);

	  /* Initialize session variables */
	  tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	  tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window)
	    << tc0->rcv_opts.wscale;
	  tc0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	  tc0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

	  /* Reset SYN-ACK retransmit and SYN_RCV establish timers */
	  tcp_retransmit_timer_reset (tc0);
	  tcp_timer_reset (tc0, TCP_TIMER_ESTABLISH);
	  if (stream_session_accept_notify (&tc0->connection))
	    {
	      error0 = TCP_ERROR_MSG_QUEUE_FULL;
	      tcp_connection_reset (tc0);
	      goto drop;
	    }
	  error0 = TCP_ERROR_ACK_OK;
	  break;
	case TCP_STATE_ESTABLISHED:
	  /* We can get packets in established state here because they
	   * were enqueued before state change */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  break;
	case TCP_STATE_FIN_WAIT_1:
	  /* In addition to the processing for the ESTABLISHED state, if
	   * our FIN is now acknowledged then enter FIN-WAIT-2 and
	   * continue processing in that state. */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  /* Still have to send the FIN */
	  if (tc0->flags & TCP_CONN_FINPNDG)
	    {
	      /* TX fifo finally drained */
	      max_dequeue = session_tx_fifo_max_dequeue (&tc0->connection);
	      if (max_dequeue <= tc0->burst_acked)
		tcp_send_fin (tc0);
	    }
	  /* If FIN is ACKed */
	  else if (tc0->snd_una == tc0->snd_una_max)
	    {
	      tcp_connection_set_state (tc0, TCP_STATE_FIN_WAIT_2);

	      /* Stop all retransmit timers because we have nothing more
	       * to send. Enable waitclose though because we're willing to
	       * wait for peer's FIN but not indefinitely. */
	      tcp_connection_timers_reset (tc0);
	      tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);

	      /* Don't try to deq the FIN acked */
	      if (tc0->burst_acked > 1)
		stream_session_dequeue_drop (&tc0->connection,
					     tc0->burst_acked - 1);
	      tc0->burst_acked = 0;
	    }
	  break;
	case TCP_STATE_FIN_WAIT_2:
	  /* In addition to the processing for the ESTABLISHED state, if
	   * the retransmission queue is empty, the user's CLOSE can be
	   * acknowledged ("ok") but do not delete the TCB. */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;
	  tc0->burst_acked = 0;
	  break;
	case TCP_STATE_CLOSE_WAIT:
	  /* Do the same processing as for the ESTABLISHED state. */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  if (tc0->flags & TCP_CONN_FINPNDG)
	    {
	      /* TX fifo finally drained */
	      if (!session_tx_fifo_max_dequeue (&tc0->connection))
		{
		  tcp_send_fin (tc0);
		  tcp_connection_timers_reset (tc0);
		  tcp_connection_set_state (tc0, TCP_STATE_LAST_ACK);
		  tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
		}
	    }
	  break;
	case TCP_STATE_CLOSING:
	  /* In addition to the processing for the ESTABLISHED state, if
	   * the ACK acknowledges our FIN then enter the TIME-WAIT state,
	   * otherwise ignore the segment. */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  tcp_connection_timers_reset (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_TIME_WAIT);
	  tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	  goto drop;

	  break;
	case TCP_STATE_LAST_ACK:
	  /* The only thing that [should] arrive in this state is an
	   * acknowledgment of our FIN. If our FIN is now acknowledged,
	   * delete the TCB, enter the CLOSED state, and return. */

	  if (!tcp_rcv_ack_is_acceptable (tc0, b0))
	    {
	      error0 = TCP_ERROR_ACK_INVALID;
	      goto drop;
	    }
	  error0 = TCP_ERROR_ACK_OK;
	  tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	  /* Apparently our ACK for the peer's FIN was lost */
	  if (is_fin0 && tc0->snd_una != tc0->snd_una_max)
	    {
	      tcp_send_fin (tc0);
	      goto drop;
	    }

	  tcp_connection_set_state (tc0, TCP_STATE_CLOSED);

	  /* Don't free the connection from the data path since
	   * we can't ensure that we have no packets already enqueued
	   * to output. Rely instead on the waitclose timer */
	  tcp_connection_timers_reset (tc0);
	  tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);

	  goto drop;

	  break;
	case TCP_STATE_TIME_WAIT:
	  /* The only thing that can arrive in this state is a
	   * retransmission of the remote FIN. Acknowledge it, and restart
	   * the 2 MSL timeout. */

	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  tcp_program_ack (wrk, tc0);
	  tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	  goto drop;

	  break;
	default:
	  ASSERT (0);
	}

      /* 6: check the URG bit TODO */

      /* 7: process the segment text */
      switch (tc0->state)
	{
	case TCP_STATE_ESTABLISHED:
	case TCP_STATE_FIN_WAIT_1:
	case TCP_STATE_FIN_WAIT_2:
	  if (vnet_buffer (b0)->tcp.data_len)
	    error0 = tcp_segment_rcv (wrk, tc0, b0);
	  break;
	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
	case TCP_STATE_TIME_WAIT:
	  /* This should not occur, since a FIN has been received from the
	   * remote side.  Ignore the segment text. */
	  break;
	}

      /* 8: check the FIN bit */
      if (!is_fin0)
	goto drop;

      TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc0);

      switch (tc0->state)
	{
	case TCP_STATE_ESTABLISHED:
	  /* Account for the FIN and send ack */
	  tc0->rcv_nxt += 1;
	  tcp_program_ack (wrk, tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_CLOSE_WAIT);
	  tcp_program_disconnect (wrk, tc0);
	  tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
	  break;
	case TCP_STATE_SYN_RCVD:
	  /* Send FIN-ACK, enter LAST-ACK and because the app was not
	   * notified yet, set a cleanup timer instead of relying on
	   * disconnect notify and the implicit close call. */
	  tcp_connection_timers_reset (tc0);
	  tc0->rcv_nxt += 1;
	  tcp_send_fin (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_LAST_ACK);
	  tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	  break;
	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
	  /* move along .. */
	  break;
	case TCP_STATE_FIN_WAIT_1:
	  tc0->rcv_nxt += 1;
	  tcp_connection_set_state (tc0, TCP_STATE_CLOSING);
	  tcp_program_ack (wrk, tc0);
	  /* Wait for ACK but not forever */
	  tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	  break;
	case TCP_STATE_FIN_WAIT_2:
	  /* Got FIN, send ACK! Be more aggressive with resource cleanup */
	  tc0->rcv_nxt += 1;
	  tcp_connection_set_state (tc0, TCP_STATE_TIME_WAIT);
	  tcp_connection_timers_reset (tc0);
	  tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	  tcp_program_ack (wrk, tc0);
	  break;
	case TCP_STATE_TIME_WAIT:
	  /* Remain in the TIME-WAIT state. Restart the time-wait
	   * timeout.
	   */
	  tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	  break;
	}
      error0 = TCP_ERROR_FIN_RCVD;

    drop:

      tcp_inc_counter (rcv_process, error0, 1);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  tcp_rx_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  tcp_set_rx_trace_data (t0, tc0, tcp0, b0, is_ip4);
	}
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 thread_index);
  tcp_inc_counter (rcv_process, TCP_ERROR_MSG_QUEUE_FULL, errors);
  tcp_handle_postponed_dequeues (wrk);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

static uword
tcp4_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_rcv_process_node) =
{
  .function = tcp4_rcv_process,
  .name = "tcp4-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_rcv_process_node, tcp4_rcv_process);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_rcv_process_node) =
{
  .function = tcp6_rcv_process,
  .name = "tcp6-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_rcv_process_node, tcp6_rcv_process);

vlib_node_registration_t tcp4_listen_node;
vlib_node_registration_t tcp6_listen_node;

/**
 * LISTEN state processing as per RFC 793 p. 65
 */
always_inline uword
tcp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, *from, n_syns = 0, *first_buffer;
  u32 my_thread_index = vm->thread_index;

  from = first_buffer = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      tcp_rx_trace_t *t0;
      tcp_header_t *th0 = 0;
      tcp_connection_t *lc0;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      tcp_connection_t *child0;
      u32 error0 = TCP_ERROR_NONE;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      lc0 = tcp_listener_get (vnet_buffer (b0)->tcp.connection_index);

      if (is_ip4)
	{
	  ip40 = vlib_buffer_get_current (b0);
	  th0 = ip4_next_header (ip40);
	}
      else
	{
	  ip60 = vlib_buffer_get_current (b0);
	  th0 = ip6_next_header (ip60);
	}

      /* Create child session. For syn-flood protection use filter */

      /* 1. first check for an RST: handled in dispatch */
      /* if (tcp_rst (th0))
         goto drop;
       */

      /* 2. second check for an ACK: handled in dispatch */
      /* if (tcp_ack (th0))
         {
         tcp_send_reset (b0, is_ip4);
         goto drop;
         }
       */

      /* 3. check for a SYN (did that already) */

      /* Make sure connection wasn't just created */
      child0 = tcp_lookup_connection (lc0->c_fib_index, b0, my_thread_index,
				      is_ip4);
      if (PREDICT_FALSE (child0->state != TCP_STATE_LISTEN))
	{
	  error0 = TCP_ERROR_CREATE_EXISTS;
	  goto drop;
	}

      /* Create child session and send SYN-ACK */
      child0 = tcp_connection_alloc (my_thread_index);
      child0->c_lcl_port = th0->dst_port;
      child0->c_rmt_port = th0->src_port;
      child0->c_is_ip4 = is_ip4;
      child0->state = TCP_STATE_SYN_RCVD;
      child0->c_fib_index = lc0->c_fib_index;

      if (is_ip4)
	{
	  child0->c_lcl_ip4.as_u32 = ip40->dst_address.as_u32;
	  child0->c_rmt_ip4.as_u32 = ip40->src_address.as_u32;
	}
      else
	{
	  clib_memcpy_fast (&child0->c_lcl_ip6, &ip60->dst_address,
			    sizeof (ip6_address_t));
	  clib_memcpy_fast (&child0->c_rmt_ip6, &ip60->src_address,
			    sizeof (ip6_address_t));
	}

      if (tcp_options_parse (th0, &child0->rcv_opts, 1))
	{
	  error0 = TCP_ERROR_OPTIONS;
	  tcp_connection_free (child0);
	  goto drop;
	}

      child0->irs = vnet_buffer (b0)->tcp.seq_number;
      child0->rcv_nxt = vnet_buffer (b0)->tcp.seq_number + 1;
      child0->rcv_las = child0->rcv_nxt;
      child0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /* RFC1323: TSval timestamps sent on {SYN} and {SYN,ACK}
       * segments are used to initialize PAWS. */
      if (tcp_opts_tstamp (&child0->rcv_opts))
	{
	  child0->tsval_recent = child0->rcv_opts.tsval;
	  child0->tsval_recent_age = tcp_time_now ();
	}

      if (tcp_opts_wscale (&child0->rcv_opts))
	child0->snd_wscale = child0->rcv_opts.wscale;

      child0->snd_wnd = clib_net_to_host_u16 (th0->window)
	<< child0->snd_wscale;
      child0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
      child0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

      tcp_connection_init_vars (child0);
      TCP_EVT_DBG (TCP_EVT_SYN_RCVD, child0, 1);

      if (stream_session_accept (&child0->connection, lc0->c_s_index,
				 0 /* notify */ ))
	{
	  tcp_connection_cleanup (child0);
	  error0 = TCP_ERROR_CREATE_SESSION_FAIL;
	  goto drop;
	}

      child0->tx_fifo_size = transport_tx_fifo_size (&child0->connection);
      tcp_send_synack (child0);
      tcp_timer_set (child0, TCP_TIMER_ESTABLISH, TCP_SYN_RCVD_TIME);

    drop:

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  clib_memcpy_fast (&t0->tcp_header, th0, sizeof (t0->tcp_header));
	  clib_memcpy_fast (&t0->tcp_connection, lc0,
			    sizeof (t0->tcp_connection));
	}

      n_syns += (error0 == TCP_ERROR_NONE);
    }

  tcp_inc_counter (listen, TCP_ERROR_SYNS_RCVD, n_syns);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

static uword
tcp4_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_listen_node) =
{
  .function = tcp4_listen,
  .name = "tcp4-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_listen_node, tcp4_listen);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_listen_node) =
{
  .function = tcp6_listen,
  .name = "tcp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_listen_node, tcp6_listen);

vlib_node_registration_t tcp4_input_node;
vlib_node_registration_t tcp6_input_node;

typedef enum _tcp_input_next
{
  TCP_INPUT_NEXT_DROP,
  TCP_INPUT_NEXT_LISTEN,
  TCP_INPUT_NEXT_RCV_PROCESS,
  TCP_INPUT_NEXT_SYN_SENT,
  TCP_INPUT_NEXT_ESTABLISHED,
  TCP_INPUT_NEXT_RESET,
  TCP_INPUT_NEXT_PUNT,
  TCP_INPUT_N_NEXT
} tcp_input_next_t;

#define foreach_tcp4_input_next                 \
  _ (DROP, "ip4-drop")                          \
  _ (LISTEN, "tcp4-listen")                     \
  _ (RCV_PROCESS, "tcp4-rcv-process")           \
  _ (SYN_SENT, "tcp4-syn-sent")                 \
  _ (ESTABLISHED, "tcp4-established")		\
  _ (RESET, "tcp4-reset")			\
  _ (PUNT, "ip4-punt")

#define foreach_tcp6_input_next                 \
  _ (DROP, "ip6-drop")                          \
  _ (LISTEN, "tcp6-listen")                     \
  _ (RCV_PROCESS, "tcp6-rcv-process")           \
  _ (SYN_SENT, "tcp6-syn-sent")                 \
  _ (ESTABLISHED, "tcp6-established")		\
  _ (RESET, "tcp6-reset")			\
  _ (PUNT, "ip6-punt")

#define filter_flags (TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_FLAG_RST|TCP_FLAG_FIN)

static void
tcp_input_trace_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_buffer_t ** bs, u32 n_bufs, u8 is_ip4)
{
  tcp_connection_t *tc;
  tcp_header_t *tcp;
  tcp_rx_trace_t *t;
  int i;

  for (i = 0; i < n_bufs; i++)
    {
      if (bs[i]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t = vlib_add_trace (vm, node, bs[i], sizeof (*t));
	  tc = tcp_connection_get (vnet_buffer (bs[i])->tcp.connection_index,
				   vm->thread_index);
	  tcp = vlib_buffer_get_current (bs[i]);
	  tcp_set_rx_trace_data (t, tc, tcp, bs[i], is_ip4);
	}
    }
}

static void
tcp_input_set_error_next (tcp_main_t * tm, u16 * next, u32 * error, u8 is_ip4)
{
  if (*error == TCP_ERROR_FILTERED)
    {
      *next = TCP_INPUT_NEXT_DROP;
    }
  else if ((is_ip4 && tm->punt_unknown4) || (!is_ip4 && tm->punt_unknown6))
    {
      *next = TCP_INPUT_NEXT_PUNT;
      *error = TCP_ERROR_PUNT;
    }
  else
    {
      *next = TCP_INPUT_NEXT_RESET;
      *error = TCP_ERROR_NO_LISTENER;
    }
}

static inline tcp_connection_t *
tcp_input_lookup_buffer (vlib_buffer_t * b, u8 thread_index, u32 * error,
			 u8 is_ip4)
{
  u32 fib_index = vnet_buffer (b)->ip.fib_index;
  int n_advance_bytes, n_data_bytes;
  transport_connection_t *tc;
  tcp_header_t *tcp;
  u8 is_filtered = 0;

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

      tc = session_lookup_connection_wt4 (fib_index, &ip4->dst_address,
					  &ip4->src_address, tcp->dst_port,
					  tcp->src_port, TRANSPORT_PROTO_TCP,
					  thread_index, &is_filtered);
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

      tc = session_lookup_connection_wt6 (fib_index, &ip6->dst_address,
					  &ip6->src_address, tcp->dst_port,
					  tcp->src_port, TRANSPORT_PROTO_TCP,
					  thread_index, &is_filtered);
    }

  vnet_buffer (b)->tcp.seq_number = clib_net_to_host_u32 (tcp->seq_number);
  vnet_buffer (b)->tcp.ack_number = clib_net_to_host_u32 (tcp->ack_number);
  vnet_buffer (b)->tcp.data_offset = n_advance_bytes;
  vnet_buffer (b)->tcp.data_len = n_data_bytes;
  vnet_buffer (b)->tcp.seq_end = vnet_buffer (b)->tcp.seq_number
    + n_data_bytes;
  vnet_buffer (b)->tcp.flags = 0;

  *error = is_filtered ? TCP_ERROR_FILTERED : *error;

  return tcp_get_connection_from_transport (tc);
}

static inline void
tcp_input_dispatch_buffer (tcp_main_t * tm, tcp_connection_t * tc,
			   vlib_buffer_t * b, u16 * next, u32 * error)
{
  tcp_header_t *tcp;
  u8 flags;

  tcp = tcp_buffer_hdr (b);
  flags = tcp->flags & filter_flags;
  *next = tm->dispatch_table[tc->state][flags].next;
  *error = tm->dispatch_table[tc->state][flags].error;

  if (PREDICT_FALSE (*error == TCP_ERROR_DISPATCH
		     || *next == TCP_INPUT_NEXT_RESET))
    {
      /* Overload tcp flags to store state */
      tcp_state_t state = tc->state;
      vnet_buffer (b)->tcp.flags = tc->state;

      if (*error == TCP_ERROR_DISPATCH)
	clib_warning ("tcp conn %u disp error state %U flags %U",
		      tc->c_c_index, format_tcp_state, state,
		      format_tcp_flags, (int) flags);
    }
}

always_inline uword
tcp46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, int is_ip4)
{
  u32 n_left_from, *from, thread_index = vm->thread_index;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  tcp_set_time_now (tcp_get_worker (thread_index));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      u32 error0 = TCP_ERROR_NO_LISTENER, error1 = TCP_ERROR_NO_LISTENER;
      tcp_connection_t *tc0, *tc1;

      {
	vlib_prefetch_buffer_header (b[2], STORE);
	CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

	vlib_prefetch_buffer_header (b[3], STORE);
	CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
      }

      next[0] = next[1] = TCP_INPUT_NEXT_DROP;

      tc0 = tcp_input_lookup_buffer (b[0], thread_index, &error0, is_ip4);
      tc1 = tcp_input_lookup_buffer (b[1], thread_index, &error1, is_ip4);

      if (PREDICT_TRUE (!tc0 + !tc1 == 0))
	{
	  ASSERT (tcp_lookup_is_valid (tc0, tcp_buffer_hdr (b[0])));
	  ASSERT (tcp_lookup_is_valid (tc1, tcp_buffer_hdr (b[1])));

	  vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	  vnet_buffer (b[1])->tcp.connection_index = tc1->c_c_index;

	  tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], &error0);
	  tcp_input_dispatch_buffer (tm, tc1, b[1], &next[1], &error1);
	}
      else
	{
	  if (PREDICT_TRUE (tc0 != 0))
	    {
	      ASSERT (tcp_lookup_is_valid (tc0, tcp_buffer_hdr (b[0])));
	      vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	      tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], &error0);
	    }
	  else
	    tcp_input_set_error_next (tm, &next[0], &error0, is_ip4);

	  if (PREDICT_TRUE (tc1 != 0))
	    {
	      ASSERT (tcp_lookup_is_valid (tc1, tcp_buffer_hdr (b[1])));
	      vnet_buffer (b[1])->tcp.connection_index = tc1->c_c_index;
	      tcp_input_dispatch_buffer (tm, tc1, b[1], &next[1], &error1);
	    }
	  else
	    tcp_input_set_error_next (tm, &next[1], &error1, is_ip4);
	}

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      tcp_connection_t *tc0;
      u32 error0 = TCP_ERROR_NO_LISTENER;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	}

      next[0] = TCP_INPUT_NEXT_DROP;
      tc0 = tcp_input_lookup_buffer (b[0], thread_index, &error0, is_ip4);
      if (PREDICT_TRUE (tc0 != 0))
	{
	  ASSERT (tcp_lookup_is_valid (tc0, tcp_buffer_hdr (b[0])));
	  vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	  tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], &error0);
	}
      else
	tcp_input_set_error_next (tm, &next[0], &error0, is_ip4);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    tcp_input_trace_frame (vm, node, bufs, frame->n_vectors, is_ip4);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

static uword
tcp4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_input_node) =
{
  .function = tcp4_input,
  .name = "tcp4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp4_input_next
#undef _
  },
  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_input_node, tcp4_input);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_input_node) =
{
  .function = tcp6_input,
  .name = "tcp6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp6_input_next
#undef _
  },
  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_input_node, tcp6_input);

static void
tcp_dispatch_table_init (tcp_main_t * tm)
{
  int i, j;
  for (i = 0; i < ARRAY_LEN (tm->dispatch_table); i++)
    for (j = 0; j < ARRAY_LEN (tm->dispatch_table[i]); j++)
      {
	tm->dispatch_table[i][j].next = TCP_INPUT_NEXT_DROP;
	tm->dispatch_table[i][j].error = TCP_ERROR_DISPATCH;
      }

#define _(t,f,n,e)                                           	\
do {                                                       	\
    tm->dispatch_table[TCP_STATE_##t][f].next = (n);         	\
    tm->dispatch_table[TCP_STATE_##t][f].error = (e);        	\
} while (0)

  /* RFC 793: In LISTEN if RST drop and if ACK return RST */
  _(LISTEN, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET, TCP_ERROR_ACK_INVALID);
  _(LISTEN, TCP_FLAG_RST, TCP_INPUT_NEXT_DROP, TCP_ERROR_INVALID_CONNECTION);
  _(LISTEN, TCP_FLAG_SYN, TCP_INPUT_NEXT_LISTEN, TCP_ERROR_NONE);
  _(LISTEN, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET,
    TCP_ERROR_ACK_INVALID);
  _(LISTEN, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_INVALID_CONNECTION);
  _(LISTEN, TCP_FLAG_FIN, TCP_INPUT_NEXT_RESET, TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_NONE);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_SEGMENT_INVALID);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  /* ACK for for a SYN-ACK -> tcp-rcv-process. */
  _(SYN_RCVD, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  /* SYN-ACK for a SYN */
  _(SYN_SENT, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
    TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT, TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_RST, TCP_INPUT_NEXT_SYN_SENT, TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
    TCP_ERROR_NONE);
  /* ACK for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  /* FIN for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_FIN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST,
    TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_RST, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  /* ACK or FIN-ACK to our FIN */
  _(FIN_WAIT_1, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_ACK | TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  /* FIN in reply to our FIN from the other side */
  _(FIN_WAIT_1, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  _(FIN_WAIT_1, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  /* FIN confirming that the peer (app) has closed */
  _(FIN_WAIT_2, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  _(LAST_ACK, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* RFC793 CLOSED: An incoming segment containing a RST is discarded. An
   * incoming segment not containing a RST causes a RST to be sent in
   * response.*/
  _(CLOSED, TCP_FLAG_RST, TCP_INPUT_NEXT_DROP, TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET, TCP_ERROR_NONE);
  _(CLOSED, TCP_FLAG_SYN, TCP_INPUT_NEXT_RESET, TCP_ERROR_NONE);
  _(CLOSED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET,
    TCP_ERROR_NONE);
#undef _
}

static clib_error_t *
tcp_input_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();

  if ((error = vlib_call_init_function (vm, tcp_init)))
    return error;

  /* Initialize dispatch table. */
  tcp_dispatch_table_init (tm);

  return error;
}

VLIB_INIT_FUNCTION (tcp_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
