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

#include <vppinfra/sparse_vec.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
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

static void
tcp_handle_rst (tcp_connection_t * tc)
{
  switch (tc->rst_state)
    {
    case TCP_STATE_SYN_RCVD:
      /* Cleanup everything. App wasn't notified yet */
      session_transport_delete_notify (&tc->connection);
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_SYN_SENT:
      session_stream_connect_notify (&tc->connection, SESSION_E_REFUSED);
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_ESTABLISHED:
      session_transport_reset_notify (&tc->connection);
      session_transport_closed_notify (&tc->connection);
      break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
      session_transport_closed_notify (&tc->connection);
      break;
    case TCP_STATE_CLOSED:
    case TCP_STATE_TIME_WAIT:
      break;
    default:
      TCP_DBG ("reset state: %u", tc->state);
    }
}

static void
tcp_program_reset_ntf (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  if (!tcp_disconnect_pending (tc))
    {
      tc->rst_state = tc->state;
      vec_add1 (wrk->pending_resets, tc->c_c_index);
      tcp_disconnect_pending_on (tc);
    }
}

/**
 * Handle reset packet
 *
 * Programs disconnect/reset notification that should be sent
 * later by calling @ref tcp_handle_disconnects
 */
static void
tcp_rcv_rst (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  TCP_EVT (TCP_EVT_RST_RCVD, tc);
  switch (tc->state)
    {
    case TCP_STATE_SYN_RCVD:
      tcp_program_reset_ntf (wrk, tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      break;
    case TCP_STATE_SYN_SENT:
      /* Do not program ntf because the connection is half-open */
      tc->rst_state = tc->state;
      tcp_handle_rst (tc);
      break;
    case TCP_STATE_ESTABLISHED:
      tcp_connection_timers_reset (tc);
      tcp_cong_recovery_off (tc);
      tcp_program_reset_ntf (wrk, tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      tcp_program_cleanup (wrk, tc);
      break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
      tcp_connection_timers_reset (tc);
      tcp_cong_recovery_off (tc);
      tcp_program_reset_ntf (wrk, tc);
      /* Make sure we mark the session as closed. In some states we may
       * be still trying to send data */
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      tcp_program_cleanup (wrk, tc);
      break;
    case TCP_STATE_CLOSED:
    case TCP_STATE_TIME_WAIT:
      break;
    default:
      TCP_DBG ("reset state: %u", tc->state);
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
      TCP_EVT (TCP_EVT_PAWS_FAIL, tc0, vnet_buffer (b0)->tcp.seq_number,
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
	  tcp_program_ack (tc0);
	  TCP_EVT (TCP_EVT_DUPACK_SENT, tc0, vnet_buffer (b0)->tcp);
	  goto error;
	}
    }

  /* 1st: check sequence number */
  if (!tcp_segment_in_rcv_wnd (tc0, vnet_buffer (b0)->tcp.seq_number,
			       vnet_buffer (b0)->tcp.seq_end))
    {
      /* SYN/SYN-ACK retransmit */
      if (tcp_syn (th0)
	  && vnet_buffer (b0)->tcp.seq_number == tc0->rcv_nxt - 1)
	{
	  tcp_options_parse (th0, &tc0->rcv_opts, 1);
	  if (tc0->state == TCP_STATE_SYN_RCVD)
	    {
	      tcp_send_synack (tc0);
	      TCP_EVT (TCP_EVT_SYN_RCVD, tc0, 0);
	      *error0 = TCP_ERROR_SYNS_RCVD;
	    }
	  else
	    {
	      tcp_program_ack (tc0);
	      TCP_EVT (TCP_EVT_SYNACK_RCVD, tc0);
	      *error0 = TCP_ERROR_SYN_ACKS_RCVD;
	    }
	  goto error;
	}

      /* If our window is 0 and the packet is in sequence, let it pass
       * through for ack processing. It should be dropped later. */
      if (tc0->rcv_wnd < tc0->snd_mss
	  && tc0->rcv_nxt == vnet_buffer (b0)->tcp.seq_number)
	goto check_reset;

      /* If we entered recovery and peer did so as well, there's a chance that
       * dup acks won't be acceptable on either end because seq_end may be less
       * than rcv_las. This can happen if acks are lost in both directions. */
      if (tcp_in_recovery (tc0)
	  && seq_geq (vnet_buffer (b0)->tcp.seq_number,
		      tc0->rcv_las - tc0->rcv_wnd)
	  && seq_leq (vnet_buffer (b0)->tcp.seq_end,
		      tc0->rcv_nxt + tc0->rcv_wnd))
	goto check_reset;

      *error0 = TCP_ERROR_RCV_WND;

      /* If we advertised a zero rcv_wnd and the segment is in the past or the
       * next one that we expect, it is probably a window probe */
      if ((tc0->flags & TCP_CONN_ZERO_RWND_SENT)
	  && seq_lt (vnet_buffer (b0)->tcp.seq_end,
		     tc0->rcv_las + tc0->rcv_opts.mss))
	*error0 = TCP_ERROR_ZERO_RWND;

      tc0->errors.below_data_wnd += seq_lt (vnet_buffer (b0)->tcp.seq_end,
					    tc0->rcv_las);

      /* If not RST, send dup ack */
      if (!tcp_rst (th0))
	{
	  tcp_program_dupack (tc0);
	  TCP_EVT (TCP_EVT_DUPACK_SENT, tc0, vnet_buffer (b0)->tcp);
	}
      goto error;

    check_reset:
      ;
    }

  /* 2nd: check the RST bit */
  if (PREDICT_FALSE (tcp_rst (th0)))
    {
      tcp_rcv_rst (wrk, tc0);
      *error0 = TCP_ERROR_RST_RCVD;
      goto error;
    }

  /* 3rd: check security and precedence (skip) */

  /* 4th: check the SYN bit (in window) */
  if (PREDICT_FALSE (tcp_syn (th0)))
    {
      /* As per RFC5961 send challenge ack instead of reset */
      tcp_program_ack (tc0);
      *error0 = TCP_ERROR_SPURIOUS_SYN;
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
tcp_rcv_ack_no_cc (tcp_connection_t * tc, vlib_buffer_t * b, u32 * error)
{
  /* SND.UNA =< SEG.ACK =< SND.NXT */
  if (!(seq_leq (tc->snd_una, vnet_buffer (b)->tcp.ack_number)
	&& seq_leq (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)))
    {
      if (seq_leq (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)
	  && seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_una))
	{
	  tc->snd_nxt = vnet_buffer (b)->tcp.ack_number;
	  goto acceptable;
	}
      *error = TCP_ERROR_ACK_INVALID;
      return -1;
    }

acceptable:
  tc->bytes_acked = vnet_buffer (b)->tcp.ack_number - tc->snd_una;
  tc->snd_una = vnet_buffer (b)->tcp.ack_number;
  *error = TCP_ERROR_ACK_OK;
  return 0;
}

/**
 * Compute smoothed RTT as per VJ's '88 SIGCOMM and RFC6298
 *
 * Note that although in the original article srtt and rttvar are scaled
 * to minimize round-off errors, here we don't. Instead, we rely on
 * better precision time measurements.
 *
 * A known limitation of the algorithm is that a drop in rtt results in a
 * rttvar increase and bigger RTO.
 *
 * mrtt must be provided in @ref TCP_TICK multiples, i.e., in us. Note that
 * timestamps are measured as ms ticks so they must be converted before
 * calling this function.
 */
static void
tcp_estimate_rtt (tcp_connection_t * tc, u32 mrtt)
{
  int err, diff;

  err = mrtt - tc->srtt;
  tc->srtt = clib_max ((int) tc->srtt + (err >> 3), 1);
  diff = (clib_abs (err) - (int) tc->rttvar) >> 2;
  tc->rttvar = clib_max ((int) tc->rttvar + diff, 1);
}

static inline void
tcp_estimate_rtt_us (tcp_connection_t * tc, f64 mrtt)
{
  tc->mrtt_us = tc->mrtt_us + (mrtt - tc->mrtt_us) * 0.125;
}

/**
 * Update rtt estimate
 *
 * We have potentially three sources of rtt measurements:
 *
 * TSOPT	difference between current and echoed timestamp. It has ms
 * 	    	precision and can be computed per ack
 * ACK timing	one sequence number is tracked per rtt with us (micro second)
 * 		precision.
 * rate sample	if enabled, all outstanding bytes are tracked with us
 * 		precision. Every ack and sack are a rtt sample
 *
 * Middle boxes are known to fiddle with TCP options so we give higher
 * priority to ACK timing.
 *
 * For now, rate sample rtts are only used under congestion.
 */
static int
tcp_update_rtt (tcp_connection_t * tc, tcp_rate_sample_t * rs, u32 ack)
{
  u32 mrtt = 0;

  /* Karn's rule, part 1. Don't use retransmitted segments to estimate
   * RTT because they're ambiguous. */
  if (tcp_in_cong_recovery (tc))
    {
      /* Accept rtt estimates for samples that have not been retransmitted */
      if (!(tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
	  || (rs->flags & TCP_BTS_IS_RXT))
	goto done;
      if (rs->rtt_time)
	tcp_estimate_rtt_us (tc, rs->rtt_time);
      mrtt = rs->rtt_time * THZ;
      goto estimate_rtt;
    }

  if (tc->rtt_ts && seq_geq (ack, tc->rtt_seq))
    {
      f64 sample = tcp_time_now_us (tc->c_thread_index) - tc->rtt_ts;
      tcp_estimate_rtt_us (tc, sample);
      mrtt = clib_max ((u32) (sample * THZ), 1);
      /* Allow measuring of a new RTT */
      tc->rtt_ts = 0;
    }
  /* As per RFC7323 TSecr can be used for RTTM only if the segment advances
   * snd_una, i.e., the left side of the send window:
   * seq_lt (tc->snd_una, ack). This is a condition for calling update_rtt */
  else if (tcp_opts_tstamp (&tc->rcv_opts) && tc->rcv_opts.tsecr)
    {
      mrtt = clib_max (tcp_tstamp (tc) - tc->rcv_opts.tsecr, 1);
      mrtt *= TCP_TSTP_TO_HZ;
    }

estimate_rtt:

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
      tc->mrtt_us = clib_max (tc->mrtt_us, 0.0001);
      mrtt = clib_max ((u32) (tc->mrtt_us * THZ), 1);
      tc->rtt_ts = 0;
    }
  else
    {
      mrtt = tcp_tstamp (tc) - tc->rcv_opts.tsecr;
      mrtt = clib_max (mrtt, 1) * TCP_TSTP_TO_HZ;
      /* Due to retransmits we don't know the initial mrtt */
      if (tc->rto_boff && mrtt > 1 * THZ)
	mrtt = 1 * THZ;
      tc->mrtt_us = (f64) mrtt *TCP_TICK;
    }

  if (mrtt > 0 && mrtt < TCP_RTT_MAX)
    {
      /* First measurement as per RFC 6298 */
      tc->srtt = mrtt;
      tc->rttvar = mrtt >> 1;
    }
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
      session_tx_fifo_dequeue_drop (&tc->connection, tc->burst_acked);
      tcp_validate_txf_size (tc, tc->snd_nxt - tc->snd_una);

      if (tcp_is_descheduled (tc))
	tcp_reschedule (tc);

      /* If everything has been acked, stop retransmit timer
       * otherwise update. */
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);

      /* Update pacer based on our new cwnd estimate */
      tcp_connection_tx_pacer_update (tc);

      tc->burst_acked = 0;
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
  tc->burst_acked += tc->bytes_acked;
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
      TCP_EVT (TCP_EVT_SND_WND, tc);

      if (PREDICT_FALSE (tc->snd_wnd < tc->snd_mss))
	{
	  /* Set persist timer if not set and we just got 0 wnd */
	  if (!tcp_timer_is_active (tc, TCP_TIMER_PERSIST)
	      && !tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
	    {
	      tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
	      tcp_persist_timer_set (&wrk->timer_wheel, tc);
	    }
	}
      else
	{
	  if (PREDICT_FALSE (tcp_timer_is_active (tc, TCP_TIMER_PERSIST)))
	    {
	      tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
	      tcp_persist_timer_reset (&wrk->timer_wheel, tc);
	    }

	  if (PREDICT_FALSE (tcp_is_descheduled (tc)))
	    tcp_reschedule (tc);

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
static void
tcp_cc_init_congestion (tcp_connection_t * tc)
{
  tcp_fastrecovery_on (tc);
  tc->snd_congestion = tc->snd_nxt;
  tc->cwnd_acc_bytes = 0;
  tc->snd_rxt_bytes = 0;
  tc->rxt_delivered = 0;
  tc->prr_delivered = 0;
  tc->prr_start = tc->snd_una;
  tc->prev_ssthresh = tc->ssthresh;
  tc->prev_cwnd = tc->cwnd;

  tc->snd_rxt_ts = tcp_tstamp (tc);
  tcp_cc_congestion (tc);

  /* Post retransmit update cwnd to ssthresh and account for the
   * three segments that have left the network and should've been
   * buffered at the receiver XXX */
  if (!tcp_opts_sack_permitted (&tc->rcv_opts))
    tc->cwnd += TCP_DUPACK_THRESHOLD * tc->snd_mss;

  tc->fr_occurences += 1;
  TCP_EVT (TCP_EVT_CC_EVT, tc, 4);
}

static void
tcp_cc_congestion_undo (tcp_connection_t * tc)
{
  tc->cwnd = tc->prev_cwnd;
  tc->ssthresh = tc->prev_ssthresh;
  tcp_cc_undo_recovery (tc);
  ASSERT (tc->rto_boff == 0);
  TCP_EVT (TCP_EVT_CC_EVT, tc, 5);
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
tcp_cc_is_spurious_retransmit (tcp_connection_t * tc)
{
  return (tcp_cc_is_spurious_timeout_rxt (tc));
}

static inline u8
tcp_should_fastrecover (tcp_connection_t * tc, u8 has_sack)
{
  if (!has_sack)
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
	  return 0;
	}
    }
  return tc->sack_sb.lost_bytes || tc->rcv_dupacks >= tc->sack_sb.reorder;
}

static int
tcp_cc_recover (tcp_connection_t * tc)
{
  sack_scoreboard_hole_t *hole;
  u8 is_spurious = 0;

  ASSERT (tcp_in_cong_recovery (tc));

  if (tcp_cc_is_spurious_retransmit (tc))
    {
      tcp_cc_congestion_undo (tc);
      is_spurious = 1;
    }

  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */ );
  tc->rcv_dupacks = 0;

  /* Previous recovery left us congested. Continue sending as part
   * of the current recovery event with an updated snd_congestion */
  if (tc->sack_sb.sacked_bytes)
    {
      tc->snd_congestion = tc->snd_nxt;
      tcp_program_retransmit (tc);
      return is_spurious;
    }

  tc->rxt_delivered = 0;
  tc->snd_rxt_bytes = 0;
  tc->snd_rxt_ts = 0;
  tc->prr_delivered = 0;
  tc->rtt_ts = 0;
  tc->flags &= ~TCP_CONN_RXT_PENDING;

  hole = scoreboard_first_hole (&tc->sack_sb);
  if (hole && hole->start == tc->snd_una && hole->end == tc->snd_nxt)
    scoreboard_clear (&tc->sack_sb);

  if (!tcp_in_recovery (tc) && !is_spurious)
    tcp_cc_recovered (tc);

  tcp_fastrecovery_off (tc);
  tcp_fastrecovery_first_off (tc);
  tcp_recovery_off (tc);
  TCP_EVT (TCP_EVT_CC_EVT, tc, 3);

  ASSERT (tc->rto_boff == 0);
  ASSERT (!tcp_in_cong_recovery (tc));
  ASSERT (tcp_scoreboard_is_sane_post_recovery (tc));

  return is_spurious;
}

static void
tcp_cc_update (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  ASSERT (!tcp_in_cong_recovery (tc) || tcp_is_lost_fin (tc));

  /* Congestion avoidance */
  tcp_cc_rcv_ack (tc, rs);

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

/**
 * One function to rule them all ... and in the darkness bind them
 */
static void
tcp_cc_handle_event (tcp_connection_t * tc, tcp_rate_sample_t * rs,
		     u32 is_dack)
{
  u8 has_sack = tcp_opts_sack_permitted (&tc->rcv_opts);

  /* If reneging, wait for timer based retransmits */
  if (PREDICT_FALSE (tcp_is_lost_fin (tc) || tc->sack_sb.is_reneging))
    return;

  /*
   * If not in recovery, figure out if we should enter
   */
  if (!tcp_in_cong_recovery (tc))
    {
      ASSERT (is_dack);

      tc->rcv_dupacks++;
      TCP_EVT (TCP_EVT_DUPACK_RCVD, tc, 1);
      tcp_cc_rcv_cong_ack (tc, TCP_CC_DUPACK, rs);

      if (tcp_should_fastrecover (tc, has_sack))
	{
	  tcp_cc_init_congestion (tc);

	  if (has_sack)
	    scoreboard_init_rxt (&tc->sack_sb, tc->snd_una);

	  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */ );
	  tcp_program_retransmit (tc);
	}

      return;
    }

  /*
   * Already in recovery
   */

  /*
   * Process (re)transmit feedback. Output path uses this to decide how much
   * more data to release into the network
   */
  if (has_sack)
    {
      if (!tc->bytes_acked && tc->sack_sb.rxt_sacked)
	tcp_fastrecovery_first_on (tc);

      tc->rxt_delivered += tc->sack_sb.rxt_sacked;
      tc->prr_delivered += tc->bytes_acked + tc->sack_sb.last_sacked_bytes
	- tc->sack_sb.last_bytes_delivered;
    }
  else
    {
      if (is_dack)
	{
	  tc->rcv_dupacks += 1;
	  TCP_EVT (TCP_EVT_DUPACK_RCVD, tc, 1);
	}
      tc->rxt_delivered = clib_min (tc->rxt_delivered + tc->bytes_acked,
				    tc->snd_rxt_bytes);
      if (is_dack)
	tc->prr_delivered += clib_min (tc->snd_mss,
				       tc->snd_nxt - tc->snd_una);
      else
	tc->prr_delivered += tc->bytes_acked - clib_min (tc->bytes_acked,
							 tc->snd_mss *
							 tc->rcv_dupacks);

      /* If partial ack, assume that the first un-acked segment was lost */
      if (tc->bytes_acked || tc->rcv_dupacks == TCP_DUPACK_THRESHOLD)
	tcp_fastrecovery_first_on (tc);
    }

  /*
   * See if we can exit and stop retransmitting
   */
  if (seq_geq (tc->snd_una, tc->snd_congestion))
    {
      /* If spurious return, we've already updated everything */
      if (tcp_cc_recover (tc))
	{
	  tc->tsecr_last_ack = tc->rcv_opts.tsecr;
	  return;
	}

      /* Treat as congestion avoidance ack */
      tcp_cc_rcv_ack (tc, rs);
      return;
    }

  tcp_program_retransmit (tc);

  /*
   * Notify cc of the event
   */

  if (!tc->bytes_acked)
    {
      tcp_cc_rcv_cong_ack (tc, TCP_CC_DUPACK, rs);
      return;
    }

  /* RFC6675: If the incoming ACK is a cumulative acknowledgment,
   * reset dupacks to 0. Also needed if in congestion recovery */
  tc->rcv_dupacks = 0;

  if (tcp_in_recovery (tc))
    tcp_cc_rcv_ack (tc, rs);
  else
    tcp_cc_rcv_cong_ack (tc, TCP_CC_PARTIALACK, rs);
}

static void
tcp_handle_old_ack (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  if (!tcp_in_cong_recovery (tc))
    return;

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    tcp_rcv_sacks (tc, tc->snd_una);

  tc->bytes_acked = 0;

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_sample_delivery_rate (tc, rs);

  tcp_cc_handle_event (tc, rs, 1);
}

/**
 * Check if duplicate ack as per RFC5681 Sec. 2
 */
always_inline u8
tcp_ack_is_dupack (tcp_connection_t * tc, vlib_buffer_t * b, u32 prev_snd_wnd,
		   u32 prev_snd_una)
{
  return ((vnet_buffer (b)->tcp.ack_number == prev_snd_una)
	  && seq_gt (tc->snd_nxt, tc->snd_una)
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
   * defined to be 'duplicate' as well */
  *is_dack = tc->sack_sb.last_sacked_bytes
    || tcp_ack_is_dupack (tc, b, prev_snd_wnd, prev_snd_una);

  return (*is_dack || tcp_in_cong_recovery (tc));
}

/**
 * Process incoming ACK
 */
static int
tcp_rcv_ack (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, vlib_buffer_t * b,
	     tcp_header_t * th, u32 * error)
{
  u32 prev_snd_wnd, prev_snd_una;
  tcp_rate_sample_t rs = { 0 };
  u8 is_dack;

  TCP_EVT (TCP_EVT_CC_STAT, tc);

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) */
  if (PREDICT_FALSE (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)))
    {
      /* We've probably entered recovery and the peer still has some
       * of the data we've sent. Update snd_nxt and accept the ack */
      if (seq_leq (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)
	  && seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_una))
	{
	  tc->snd_nxt = vnet_buffer (b)->tcp.ack_number;
	  goto process_ack;
	}

      tc->errors.above_ack_wnd += 1;
      *error = TCP_ERROR_ACK_FUTURE;
      TCP_EVT (TCP_EVT_ACK_RCV_ERR, tc, 0, vnet_buffer (b)->tcp.ack_number);
      return -1;
    }

  /* If old ACK, probably it's an old dupack */
  if (PREDICT_FALSE (seq_lt (vnet_buffer (b)->tcp.ack_number, tc->snd_una)))
    {
      tc->errors.below_ack_wnd += 1;
      *error = TCP_ERROR_ACK_OLD;
      TCP_EVT (TCP_EVT_ACK_RCV_ERR, tc, 1, vnet_buffer (b)->tcp.ack_number);

      if (seq_lt (vnet_buffer (b)->tcp.ack_number, tc->snd_una - tc->rcv_wnd))
	return -1;

      tcp_handle_old_ack (tc, &rs);

      /* Don't drop yet */
      return 0;
    }

process_ack:

  /*
   * Looks okay, process feedback
   */

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    tcp_rcv_sacks (tc, vnet_buffer (b)->tcp.ack_number);

  prev_snd_wnd = tc->snd_wnd;
  prev_snd_una = tc->snd_una;
  tcp_update_snd_wnd (tc, vnet_buffer (b)->tcp.seq_number,
		      vnet_buffer (b)->tcp.ack_number,
		      clib_net_to_host_u16 (th->window) << tc->snd_wscale);
  tc->bytes_acked = vnet_buffer (b)->tcp.ack_number - tc->snd_una;
  tc->snd_una = vnet_buffer (b)->tcp.ack_number;
  tcp_validate_txf_size (tc, tc->bytes_acked);

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_sample_delivery_rate (tc, &rs);

  if (tc->bytes_acked + tc->sack_sb.last_sacked_bytes)
    {
      tcp_update_rtt (tc, &rs, vnet_buffer (b)->tcp.ack_number);
      if (tc->bytes_acked)
	tcp_program_dequeue (wrk, tc);
    }

  TCP_EVT (TCP_EVT_ACK_RCVD, tc);

  /*
   * Check if we have congestion event
   */

  if (tcp_ack_is_cc_event (tc, b, prev_snd_wnd, prev_snd_una, &is_dack))
    {
      tcp_cc_handle_event (tc, &rs, is_dack);
      tc->dupacks_in += is_dack;
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
  tcp_cc_update (tc, &rs);
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
  u32 thread_index, *pending_disconnects, *pending_resets;
  tcp_connection_t *tc;
  int i;

  if (vec_len (wrk->pending_disconnects))
    {
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

  if (vec_len (wrk->pending_resets))
    {
      thread_index = wrk->vm->thread_index;
      pending_resets = wrk->pending_resets;
      for (i = 0; i < vec_len (pending_resets); i++)
	{
	  tc = tcp_connection_get (pending_resets[i], thread_index);
	  tcp_disconnect_pending_off (tc);
	  tcp_handle_rst (tc);
	}
      _vec_len (wrk->pending_resets) = 0;
    }
}

static void
tcp_rcv_fin (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, vlib_buffer_t * b,
	     u32 * error)
{
  /* Reject out-of-order fins */
  if (vnet_buffer (b)->tcp.seq_end != tc->rcv_nxt)
    return;

  /* Account for the FIN and send ack */
  tc->rcv_nxt += 1;
  tc->flags |= TCP_CONN_FINRCVD;
  tcp_program_ack (tc);
  /* Enter CLOSE-WAIT and notify session. To avoid lingering
   * in CLOSE-WAIT, set timer (reuse WAITCLOSE). */
  tcp_connection_set_state (tc, TCP_STATE_CLOSE_WAIT);
  tcp_program_disconnect (wrk, tc);
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
		    tcp_cfg.closewait_time);
  TCP_EVT (TCP_EVT_FIN_RCVD, tc);
  *error = TCP_ERROR_FIN_RCVD;
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
  tc->bytes_in += written;

  TCP_EVT (TCP_EVT_INPUT, tc, 0, data_len, written);

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      tc->rcv_nxt += written;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      tc->rcv_nxt += written;
      TCP_EVT (TCP_EVT_CC_INPUT, tc, data_len, written);
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      tc->rcv_nxt += written;
      error = TCP_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      /* Packet made it through for ack processing */
      if (tc->rcv_wnd < tc->snd_mss)
	return TCP_ERROR_ZERO_RWND;

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
  session_t *s0;
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
      TCP_EVT (TCP_EVT_INPUT, tc, 1, data_len, 0);
      return TCP_ERROR_FIFO_FULL;
    }

  TCP_EVT (TCP_EVT_INPUT, tc, 1, data_len, data_len);
  tc->bytes_in += data_len;

  /* Update SACK list if in use */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      ooo_segment_t *newest;
      u32 start, end;

      s0 = session_get (tc->c_s_index, tc->c_thread_index);

      /* Get the newest segment from the fifo */
      newest = svm_fifo_newest_ooo_segment (s0->rx_fifo);
      if (newest)
	{
	  offset = ooo_segment_offset_prod (s0->rx_fifo, newest);
	  ASSERT (offset <= vnet_buffer (b)->tcp.seq_number - tc->rcv_nxt);
	  start = tc->rcv_nxt + offset;
	  end = start + ooo_segment_length (s0->rx_fifo, newest);
	  tcp_update_sack_list (tc, start, end);
	  svm_fifo_newest_ooo_segment_reset (s0->rx_fifo);
	  TCP_EVT (TCP_EVT_CC_SACKS, tc);
	}
    }

  return TCP_ERROR_ENQUEUED_OOO;
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
  tc->data_segs_in += 1;

  /* Make sure we don't consume trailing bytes */
  if (PREDICT_FALSE (b->current_length > n_data_bytes))
    b->current_length = n_data_bytes;

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
	      tcp_program_dupack (tc);
	      tc->errors.below_data_wnd++;
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
      tcp_program_dupack (tc);
      TCP_EVT (TCP_EVT_DUPACK_SENT, tc, vnet_buffer (b)->tcp);
      tc->errors.above_data_wnd += seq_gt (vnet_buffer (b)->tcp.seq_end,
					   tc->rcv_las + tc->rcv_wnd);
      goto done;
    }

in_order:

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);
  tcp_program_ack (tc);

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
  tcp_connection_t *tc = &t->tcp_connection;
  u32 indent = format_get_indent (s);

  s = format (s, "%U state %U\n%U%U", format_tcp_connection_id, tc,
	      format_tcp_state, tc->state, format_white_space, indent,
	      format_tcp_header, &t->tcp_header, 128);

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
	  TCP_EVT (TCP_EVT_SEG_INVALID, tc0, vnet_buffer (b0)->tcp);
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

  errors = session_main_flush_enqueue_events (TRANSPORT_PROTO_TCP,
					      thread_index);
  err_counters[TCP_ERROR_MSG_QUEUE_FULL] = errors;
  tcp_store_err_counters (established, err_counters);
  tcp_handle_postponed_dequeues (wrk);
  tcp_handle_disconnects (wrk);
  vlib_buffer_free (vm, first_buffer, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (tcp4_established_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (tcp6_established_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_established_node) =
{
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_established_node) =
{
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


static u8
tcp_lookup_is_valid (tcp_connection_t * tc, vlib_buffer_t * b,
		     tcp_header_t * hdr)
{
  transport_connection_t *tmp = 0;
  u64 handle;

  if (!tc)
    return 1;

  /* Proxy case */
  if (tc->c_lcl_port == 0 && tc->state == TCP_STATE_LISTEN)
    return 1;

  u8 is_ip_valid = 0, val_l, val_r;

  if (tc->connection.is_ip4)
    {
      ip4_header_t *ip4_hdr = (ip4_header_t *) vlib_buffer_get_current (b);

      val_l = !ip4_address_compare (&ip4_hdr->dst_address,
				    &tc->connection.lcl_ip.ip4);
      val_l = val_l || ip_is_zero (&tc->connection.lcl_ip, 1);
      val_r = !ip4_address_compare (&ip4_hdr->src_address,
				    &tc->connection.rmt_ip.ip4);
      val_r = val_r || tc->state == TCP_STATE_LISTEN;
      is_ip_valid = val_l && val_r;
    }
  else
    {
      ip6_header_t *ip6_hdr = (ip6_header_t *) vlib_buffer_get_current (b);

      val_l = !ip6_address_compare (&ip6_hdr->dst_address,
				    &tc->connection.lcl_ip.ip6);
      val_l = val_l || ip_is_zero (&tc->connection.lcl_ip, 0);
      val_r = !ip6_address_compare (&ip6_hdr->src_address,
				    &tc->connection.rmt_ip.ip6);
      val_r = val_r || tc->state == TCP_STATE_LISTEN;
      is_ip_valid = val_l && val_r;
    }

  u8 is_valid = (tc->c_lcl_port == hdr->dst_port
		 && (tc->state == TCP_STATE_LISTEN
		     || tc->c_rmt_port == hdr->src_port) && is_ip_valid);

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
	      is_valid = 1;
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
      ASSERT (tcp_lookup_is_valid (tc, b, tcp));
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
      ASSERT (tcp_lookup_is_valid (tc, b, tcp));
    }
  return tc;
}

static tcp_connection_t *
tcp_lookup_listener (vlib_buffer_t * b, u32 fib_index, int is_ip4)
{
  session_t *s;

  if (is_ip4)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      tcp_header_t *tcp = tcp_buffer_hdr (b);
      s = session_lookup_listener4 (fib_index,
				    &ip4->dst_address,
				    tcp->dst_port, TRANSPORT_PROTO_TCP, 1);
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      tcp_header_t *tcp = tcp_buffer_hdr (b);
      s = session_lookup_listener6 (fib_index,
				    &ip6->dst_address,
				    tcp->dst_port, TRANSPORT_PROTO_TCP, 1);

    }
  if (PREDICT_TRUE (s != 0))
    return tcp_get_connection_from_transport (transport_get_listener
					      (TRANSPORT_PROTO_TCP,
					       s->connection_index));
  else
    return 0;
}

always_inline void
tcp_check_tx_offload (tcp_connection_t * tc, int is_ipv4)
{
  vnet_main_t *vnm = vnet_get_main ();
  const dpo_id_t *dpo;
  const load_balance_t *lb;
  vnet_hw_interface_t *hw_if;
  u32 sw_if_idx, lb_idx;

  if (is_ipv4)
    {
      ip4_address_t *dst_addr = &(tc->c_rmt_ip.ip4);
      lb_idx = ip4_fib_forwarding_lookup (tc->c_fib_index, dst_addr);
    }
  else
    {
      ip6_address_t *dst_addr = &(tc->c_rmt_ip.ip6);
      lb_idx = ip6_fib_table_fwding_lookup (tc->c_fib_index, dst_addr);
    }

  lb = load_balance_get (lb_idx);
  if (PREDICT_FALSE (lb->lb_n_buckets > 1))
    return;
  dpo = load_balance_get_bucket_i (lb, 0);

  sw_if_idx = dpo_get_urpf (dpo);
  if (PREDICT_FALSE (sw_if_idx == ~0))
    return;

  hw_if = vnet_get_sup_hw_interface (vnm, sw_if_idx);
  if (hw_if->caps & VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO)
    tc->cfg_flags |= TCP_CFG_F_TSO;
}

always_inline uword
tcp46_syn_sent_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, int is_ip4)
{
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

      /* Half-open completed or cancelled recently but the connection
       * was't removed yet by the owning thread */
      if (PREDICT_FALSE (tc0->flags & TCP_CONN_HALF_OPEN_DONE))
	{
	  error0 = TCP_ERROR_SPURIOUS_SYN_ACK;
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
		tcp_send_reset_w_pkt (tc0, b0, my_thread_index, is_ip4);
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
	    tcp_rcv_rst (wrk, tc0);
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
	  error0 = TCP_ERROR_SEGMENT_INVALID;
	  goto drop;
	}

      /* Parse options */
      if (tcp_options_parse (tcp0, &tc0->rcv_opts, 1))
	{
	  error0 = TCP_ERROR_OPTIONS;
	  goto drop;
	}

      /* Valid SYN or SYN-ACK. Move connection from half-open pool to
       * current thread pool. */
      new_tc0 = tcp_connection_alloc_w_base (my_thread_index, tc0);
      new_tc0->rcv_nxt = vnet_buffer (b0)->tcp.seq_end;
      new_tc0->irs = seq0;
      new_tc0->timers[TCP_TIMER_RETRANSMIT_SYN] = TCP_TIMER_HANDLE_INVALID;
      new_tc0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

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
	  if (session_stream_connect_notify (&new_tc0->connection,
					     SESSION_E_NONE))
	    {
	      tcp_send_reset_w_pkt (new_tc0, b0, my_thread_index, is_ip4);
	      tcp_connection_cleanup (new_tc0);
	      error0 = TCP_ERROR_CREATE_SESSION_FAIL;
	      goto cleanup_ho;
	    }

	  transport_fifos_init_ooo (&new_tc0->connection);
	  new_tc0->tx_fifo_size =
	    transport_tx_fifo_size (&new_tc0->connection);
	  /* Update rtt with the syn-ack sample */
	  tcp_estimate_initial_rtt (new_tc0);
	  TCP_EVT (TCP_EVT_SYNACK_RCVD, new_tc0);
	  error0 = TCP_ERROR_SYN_ACKS_RCVD;
	}
      /* SYN: Simultaneous open. Change state to SYN-RCVD and send SYN-ACK */
      else
	{
	  new_tc0->state = TCP_STATE_SYN_RCVD;

	  /* Notify app that we have connection */
	  if (session_stream_connect_notify (&new_tc0->connection,
					     SESSION_E_NONE))
	    {
	      tcp_connection_cleanup (new_tc0);
	      tcp_send_reset_w_pkt (tc0, b0, my_thread_index, is_ip4);
	      TCP_EVT (TCP_EVT_RST_SENT, tc0);
	      error0 = TCP_ERROR_CREATE_SESSION_FAIL;
	      goto cleanup_ho;
	    }

	  transport_fifos_init_ooo (&new_tc0->connection);
	  new_tc0->tx_fifo_size =
	    transport_tx_fifo_size (&new_tc0->connection);
	  new_tc0->rtt_ts = 0;
	  tcp_init_snd_vars (new_tc0);
	  tcp_send_synack (new_tc0);
	  error0 = TCP_ERROR_SYNS_RCVD;
	  goto cleanup_ho;
	}

      if (!(new_tc0->cfg_flags & TCP_CFG_F_NO_TSO))
	tcp_check_tx_offload (new_tc0, is_ip4);

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
	  /* Send ack now instead of programming it because connection was
	   * just established and it's not optional. */
	  tcp_send_ack (new_tc0);
	}

    cleanup_ho:

      /* If this is not the owning thread, wait for syn retransmit to
       * expire and cleanup then */
      if (tcp_half_open_connection_cleanup (tc0))
	tc0->flags |= TCP_CONN_HALF_OPEN_DONE;

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

  errors = session_main_flush_enqueue_events (TRANSPORT_PROTO_TCP,
					      my_thread_index);
  tcp_inc_counter (syn_sent, TCP_ERROR_MSG_QUEUE_FULL, errors);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);
  tcp_handle_disconnects (wrk);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (tcp4_syn_sent_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (tcp6_syn_sent_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_syn_sent_node) =
{
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_syn_sent_node) =
{
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
	  if (!(tc0->connection.flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	    {
	      tcp_connection_t *tmp;
	      tmp = tcp_lookup_connection (tc0->c_fib_index, b0, thread_index,
					   is_ip4);
	      if (tmp->state != tc0->state)
		{
		  if (tc0->state != TCP_STATE_CLOSED)
		    clib_warning ("state changed");
		  goto drop;
		}
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

	  /* Make sure the segment is exactly right */
	  if (tc0->rcv_nxt != vnet_buffer (b0)->tcp.seq_number || is_fin0)
	    {
	      tcp_send_reset_w_pkt (tc0, b0, thread_index, is_ip4);
	      error0 = TCP_ERROR_SEGMENT_INVALID;
	      goto drop;
	    }

	  /*
	   * If the segment acknowledgment is not acceptable, form a
	   * reset segment,
	   *  <SEQ=SEG.ACK><CTL=RST>
	   * and send it.
	   */
	  if (tcp_rcv_ack_no_cc (tc0, b0, &error0))
	    {
	      tcp_send_reset_w_pkt (tc0, b0, thread_index, is_ip4);
	      error0 = TCP_ERROR_SEGMENT_INVALID;
	      goto drop;
	    }

	  /* Update rtt and rto */
	  tcp_estimate_initial_rtt (tc0);
	  tcp_connection_tx_pacer_update (tc0);

	  /* Switch state to ESTABLISHED */
	  tc0->state = TCP_STATE_ESTABLISHED;
	  TCP_EVT (TCP_EVT_STATE_CHANGE, tc0);

	  if (!(tc0->cfg_flags & TCP_CFG_F_NO_TSO))
	    tcp_check_tx_offload (tc0, is_ip4);

	  /* Initialize session variables */
	  tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	  tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window)
	    << tc0->rcv_opts.wscale;
	  tc0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	  tc0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

	  /* Reset SYN-ACK retransmit and SYN_RCV establish timers */
	  tcp_retransmit_timer_reset (&wrk->timer_wheel, tc0);
	  if (session_stream_accept_notify (&tc0->connection))
	    {
	      error0 = TCP_ERROR_MSG_QUEUE_FULL;
	      tcp_send_reset (tc0);
	      session_transport_delete_notify (&tc0->connection);
	      tcp_connection_cleanup (tc0);
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
	      max_dequeue = transport_max_tx_dequeue (&tc0->connection);
	      if (max_dequeue <= tc0->burst_acked)
		tcp_send_fin (tc0);
	      /* If a fin was received and data was acked extend wait */
	      else if ((tc0->flags & TCP_CONN_FINRCVD) && tc0->bytes_acked)
		tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
				  tcp_cfg.closewait_time);
	    }
	  /* If FIN is ACKed */
	  else if (tc0->snd_una == tc0->snd_nxt)
	    {
	      /* Stop all retransmit timers because we have nothing more
	       * to send. */
	      tcp_connection_timers_reset (tc0);

	      /* We already have a FIN but didn't transition to CLOSING
	       * because of outstanding tx data. Close the connection. */
	      if (tc0->flags & TCP_CONN_FINRCVD)
		{
		  tcp_connection_set_state (tc0, TCP_STATE_CLOSED);
		  session_transport_closed_notify (&tc0->connection);
		  tcp_program_cleanup (wrk, tc0);
		  goto drop;
		}

	      tcp_connection_set_state (tc0, TCP_STATE_FIN_WAIT_2);
	      /* Enable waitclose because we're willing to wait for peer's
	       * FIN but not indefinitely. */
	      tcp_timer_set (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			     tcp_cfg.finwait2_time);

	      /* Don't try to deq the FIN acked */
	      if (tc0->burst_acked > 1)
		session_tx_fifo_dequeue_drop (&tc0->connection,
					      tc0->burst_acked - 1);
	      tc0->burst_acked = 0;
	    }
	  break;
	case TCP_STATE_FIN_WAIT_2:
	  /* In addition to the processing for the ESTABLISHED state, if
	   * the retransmission queue is empty, the user's CLOSE can be
	   * acknowledged ("ok") but do not delete the TCB. */
	  if (tcp_rcv_ack_no_cc (tc0, b0, &error0))
	    goto drop;
	  tc0->burst_acked = 0;
	  break;
	case TCP_STATE_CLOSE_WAIT:
	  /* Do the same processing as for the ESTABLISHED state. */
	  if (tcp_rcv_ack (wrk, tc0, b0, tcp0, &error0))
	    goto drop;

	  if (!(tc0->flags & TCP_CONN_FINPNDG))
	    break;

	  /* Still have outstanding tx data */
	  max_dequeue = transport_max_tx_dequeue (&tc0->connection);
	  if (max_dequeue > tc0->burst_acked)
	    break;

	  tcp_send_fin (tc0);
	  tcp_connection_timers_reset (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_LAST_ACK);
	  tcp_timer_set (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			 tcp_cfg.lastack_time);
	  break;
	case TCP_STATE_CLOSING:
	  /* In addition to the processing for the ESTABLISHED state, if
	   * the ACK acknowledges our FIN then enter the TIME-WAIT state,
	   * otherwise ignore the segment. */
	  if (tcp_rcv_ack_no_cc (tc0, b0, &error0))
	    goto drop;

	  if (tc0->snd_una != tc0->snd_nxt)
	    goto drop;

	  tcp_connection_timers_reset (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_TIME_WAIT);
	  tcp_timer_set (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			 tcp_cfg.timewait_time);
	  session_transport_closed_notify (&tc0->connection);
	  goto drop;

	  break;
	case TCP_STATE_LAST_ACK:
	  /* The only thing that [should] arrive in this state is an
	   * acknowledgment of our FIN. If our FIN is now acknowledged,
	   * delete the TCB, enter the CLOSED state, and return. */

	  if (tcp_rcv_ack_no_cc (tc0, b0, &error0))
	    goto drop;

	  /* Apparently our ACK for the peer's FIN was lost */
	  if (is_fin0 && tc0->snd_una != tc0->snd_nxt)
	    {
	      tcp_send_fin (tc0);
	      goto drop;
	    }

	  tcp_connection_set_state (tc0, TCP_STATE_CLOSED);
	  session_transport_closed_notify (&tc0->connection);

	  /* Don't free the connection from the data path since
	   * we can't ensure that we have no packets already enqueued
	   * to output. Rely instead on the waitclose timer */
	  tcp_connection_timers_reset (tc0);
	  tcp_program_cleanup (tcp_get_worker (tc0->c_thread_index), tc0);

	  goto drop;

	  break;
	case TCP_STATE_TIME_WAIT:
	  /* The only thing that can arrive in this state is a
	   * retransmission of the remote FIN. Acknowledge it, and restart
	   * the 2 MSL timeout. */

	  if (tcp_rcv_ack_no_cc (tc0, b0, &error0))
	    goto drop;

	  if (!is_fin0)
	    goto drop;

	  tcp_program_ack (tc0);
	  tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			    tcp_cfg.timewait_time);
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
	  /* Don't accept out of order fins lower */
	  if (vnet_buffer (b0)->tcp.seq_end != tc0->rcv_nxt)
	    goto drop;
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

      TCP_EVT (TCP_EVT_FIN_RCVD, tc0);

      switch (tc0->state)
	{
	case TCP_STATE_ESTABLISHED:
	  /* Account for the FIN and send ack */
	  tc0->rcv_nxt += 1;
	  tcp_program_ack (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_CLOSE_WAIT);
	  tcp_program_disconnect (wrk, tc0);
	  tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			    tcp_cfg.closewait_time);
	  break;
	case TCP_STATE_SYN_RCVD:
	  /* Send FIN-ACK, enter LAST-ACK and because the app was not
	   * notified yet, set a cleanup timer instead of relying on
	   * disconnect notify and the implicit close call. */
	  tcp_connection_timers_reset (tc0);
	  tc0->rcv_nxt += 1;
	  tcp_send_fin (tc0);
	  tcp_connection_set_state (tc0, TCP_STATE_LAST_ACK);
	  tcp_timer_set (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			 tcp_cfg.lastack_time);
	  break;
	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_CLOSING:
	case TCP_STATE_LAST_ACK:
	  /* move along .. */
	  break;
	case TCP_STATE_FIN_WAIT_1:
	  tc0->rcv_nxt += 1;

	  if (tc0->flags & TCP_CONN_FINPNDG)
	    {
	      /* If data is outstanding, stay in FIN_WAIT_1 and try to finish
	       * sending it. Since we already received a fin, do not wait
	       * for too long. */
	      tc0->flags |= TCP_CONN_FINRCVD;
	      tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
				tcp_cfg.closewait_time);
	    }
	  else
	    {
	      tcp_connection_set_state (tc0, TCP_STATE_CLOSING);
	      tcp_program_ack (tc0);
	      /* Wait for ACK for our FIN but not forever */
	      tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
				tcp_cfg.closing_time);
	    }
	  break;
	case TCP_STATE_FIN_WAIT_2:
	  /* Got FIN, send ACK! Be more aggressive with resource cleanup */
	  tc0->rcv_nxt += 1;
	  tcp_connection_set_state (tc0, TCP_STATE_TIME_WAIT);
	  tcp_connection_timers_reset (tc0);
	  tcp_timer_set (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			 tcp_cfg.timewait_time);
	  tcp_program_ack (tc0);
	  session_transport_closed_notify (&tc0->connection);
	  break;
	case TCP_STATE_TIME_WAIT:
	  /* Remain in the TIME-WAIT state. Restart the time-wait
	   * timeout.
	   */
	  tcp_timer_update (&wrk->timer_wheel, tc0, TCP_TIMER_WAITCLOSE,
			    tcp_cfg.timewait_time);
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

  errors = session_main_flush_enqueue_events (TRANSPORT_PROTO_TCP,
					      thread_index);
  tcp_inc_counter (rcv_process, TCP_ERROR_MSG_QUEUE_FULL, errors);
  tcp_handle_postponed_dequeues (wrk);
  tcp_handle_disconnects (wrk);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (tcp4_rcv_process_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (tcp6_rcv_process_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_rcv_process_node) =
{
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_rcv_process_node) =
{
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

/**
 * LISTEN state processing as per RFC 793 p. 65
 */
always_inline uword
tcp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, *from, n_syns = 0, *first_buffer;
  u32 thread_index = vm->thread_index;

  from = first_buffer = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi, error = TCP_ERROR_NONE;
      tcp_connection_t *lc, *child;
      vlib_buffer_t *b;

      bi = from[0];
      from += 1;
      n_left_from -= 1;

      b = vlib_get_buffer (vm, bi);

      /* Flags initialized with connection state after lookup */
      if (vnet_buffer (b)->tcp.flags == TCP_STATE_LISTEN)
	{
	  lc = tcp_listener_get (vnet_buffer (b)->tcp.connection_index);
	}
      else
	{
	  tcp_connection_t *tc;
	  tc = tcp_connection_get (vnet_buffer (b)->tcp.connection_index,
				   thread_index);
	  if (tc->state != TCP_STATE_TIME_WAIT)
	    {
	      lc = 0;
	      error = TCP_ERROR_CREATE_EXISTS;
	      goto done;
	    }
	  lc = tcp_lookup_listener (b, tc->c_fib_index, is_ip4);
	  /* clean up the old session */
	  tcp_connection_del (tc);
	  /* listener was cleaned up */
	  if (!lc)
	    {
	      error = TCP_ERROR_NO_LISTENER;
	      goto done;
	    }
	}

      /* Make sure connection wasn't just created */
      child = tcp_lookup_connection (lc->c_fib_index, b, thread_index,
				     is_ip4);
      if (PREDICT_FALSE (child->state != TCP_STATE_LISTEN))
	{
	  error = TCP_ERROR_CREATE_EXISTS;
	  goto done;
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

      /* Create child session and send SYN-ACK */
      child = tcp_connection_alloc (thread_index);

      if (tcp_options_parse (tcp_buffer_hdr (b), &child->rcv_opts, 1))
	{
	  error = TCP_ERROR_OPTIONS;
	  tcp_connection_free (child);
	  goto done;
	}

      tcp_init_w_buffer (child, b, is_ip4);

      child->state = TCP_STATE_SYN_RCVD;
      child->c_fib_index = lc->c_fib_index;
      child->cc_algo = lc->cc_algo;
      tcp_connection_init_vars (child);
      child->rto = TCP_RTO_MIN;

      /*
       * This initializes elog track, must be done before synack.
       * We also do it before possible tcp_connection_cleanup() as it
       * generates TCP_EVT_DELETE event.
       */
      TCP_EVT (TCP_EVT_SYN_RCVD, child, 1);

      if (session_stream_accept (&child->connection, lc->c_s_index,
				 lc->c_thread_index, 0 /* notify */ ))
	{
	  tcp_connection_cleanup (child);
	  error = TCP_ERROR_CREATE_SESSION_FAIL;
	  goto done;
	}

      transport_fifos_init_ooo (&child->connection);
      child->tx_fifo_size = transport_tx_fifo_size (&child->connection);

      tcp_send_synack (child);

    done:

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  tcp_rx_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  tcp_set_rx_trace_data (t, lc, tcp_buffer_hdr (b), b, is_ip4);
	}

      n_syns += (error == TCP_ERROR_NONE);
    }

  tcp_inc_counter (listen, TCP_ERROR_SYNS_RCVD, n_syns);
  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (tcp4_listen_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (tcp6_listen_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_listen_node) =
{
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_listen_node) =
{
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
  if (*error == TCP_ERROR_FILTERED || *error == TCP_ERROR_WRONG_THREAD)
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

static inline void
tcp_input_dispatch_buffer (tcp_main_t * tm, tcp_connection_t * tc,
			   vlib_buffer_t * b, u16 * next,
			   vlib_node_runtime_t * error_node)
{
  tcp_header_t *tcp;
  u32 error;
  u8 flags;

  tcp = tcp_buffer_hdr (b);
  flags = tcp->flags & filter_flags;
  *next = tm->dispatch_table[tc->state][flags].next;
  error = tm->dispatch_table[tc->state][flags].error;
  tc->segs_in += 1;

  /* Track connection state when packet was received. It helps
   * @ref tcp46_listen_inline detect port reuse */
  vnet_buffer (b)->tcp.flags = tc->state;

  if (PREDICT_FALSE (error != TCP_ERROR_NONE))
    {
      b->error = error_node->errors[error];
      if (error == TCP_ERROR_DISPATCH)
	clib_warning ("tcp conn %u disp error state %U flags %U",
		      tc->c_c_index, format_tcp_state, tc->state,
		      format_tcp_flags, (int) flags);
    }
}

always_inline uword
tcp46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, int is_ip4, u8 is_nolookup)
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

      tc0 = tcp_input_lookup_buffer (b[0], thread_index, &error0, is_ip4,
				     is_nolookup);
      tc1 = tcp_input_lookup_buffer (b[1], thread_index, &error1, is_ip4,
				     is_nolookup);

      if (PREDICT_TRUE (!tc0 + !tc1 == 0))
	{
	  ASSERT (tcp_lookup_is_valid (tc0, b[0], tcp_buffer_hdr (b[0])));
	  ASSERT (tcp_lookup_is_valid (tc1, b[1], tcp_buffer_hdr (b[1])));

	  vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	  vnet_buffer (b[1])->tcp.connection_index = tc1->c_c_index;

	  tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], node);
	  tcp_input_dispatch_buffer (tm, tc1, b[1], &next[1], node);
	}
      else
	{
	  if (PREDICT_TRUE (tc0 != 0))
	    {
	      ASSERT (tcp_lookup_is_valid (tc0, b[0], tcp_buffer_hdr (b[0])));
	      vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	      tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], node);
	    }
	  else
	    {
	      tcp_input_set_error_next (tm, &next[0], &error0, is_ip4);
	      b[0]->error = node->errors[error0];
	    }

	  if (PREDICT_TRUE (tc1 != 0))
	    {
	      ASSERT (tcp_lookup_is_valid (tc1, b[1], tcp_buffer_hdr (b[1])));
	      vnet_buffer (b[1])->tcp.connection_index = tc1->c_c_index;
	      tcp_input_dispatch_buffer (tm, tc1, b[1], &next[1], node);
	    }
	  else
	    {
	      tcp_input_set_error_next (tm, &next[1], &error1, is_ip4);
	      b[1]->error = node->errors[error1];
	    }
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
      tc0 = tcp_input_lookup_buffer (b[0], thread_index, &error0, is_ip4,
				     is_nolookup);
      if (PREDICT_TRUE (tc0 != 0))
	{
	  ASSERT (tcp_lookup_is_valid (tc0, b[0], tcp_buffer_hdr (b[0])));
	  vnet_buffer (b[0])->tcp.connection_index = tc0->c_c_index;
	  tcp_input_dispatch_buffer (tm, tc0, b[0], &next[0], node);
	}
      else
	{
	  tcp_input_set_error_next (tm, &next[0], &error0, is_ip4);
	  b[0]->error = node->errors[error0];
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    tcp_input_trace_frame (vm, node, bufs, frame->n_vectors, is_ip4);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (tcp4_input_nolookup_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 1 /* is_ip4 */ ,
			     1 /* is_nolookup */ );
}

VLIB_NODE_FN (tcp6_input_nolookup_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 0 /* is_ip4 */ ,
			     1 /* is_nolookup */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_input_nolookup_node) =
{
  .name = "tcp4-input-nolookup",
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_input_nolookup_node) =
{
  .name = "tcp6-input-nolookup",
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

VLIB_NODE_FN (tcp4_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 1 /* is_ip4 */ ,
			     0 /* is_nolookup */ );
}

VLIB_NODE_FN (tcp6_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 0 /* is_ip4 */ ,
			     0 /* is_nolookup */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_input_node) =
{
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_input_node) =
{
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

#ifndef CLIB_MARCH_VARIANT
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
    TCP_ERROR_SEGMENT_INVALID);
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
  _(SYN_SENT, TCP_FLAG_FIN, TCP_INPUT_NEXT_SYN_SENT, TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
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
  _(CLOSING, 0, TCP_INPUT_NEXT_DROP, TCP_ERROR_SEGMENT_INVALID);
  _(CLOSING, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_SYN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSING, TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* FIN confirming that the peer (app) has closed */
  _(FIN_WAIT_2, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
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
  _(TIME_WAIT, TCP_FLAG_SYN, TCP_INPUT_NEXT_LISTEN, TCP_ERROR_NONE);
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
  _(CLOSED, TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET, TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_SYN, TCP_INPUT_NEXT_RESET, TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET,
    TCP_ERROR_CONNECTION_CLOSED);
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

#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
