/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef SRC_VNET_TCP_TCP_CC_H_
#define SRC_VNET_TCP_TCP_CC_H_

#include <vnet/tcp/tcp_types.h>

always_inline void
tcp_cc_rcv_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  tc->cc_algo->rcv_ack (tc, ac);
  tc->tsecr_last_ack = tc->rcv_opts.tsecr;
}

static inline void
tcp_cc_rcv_cong_ack (tcp_connection_t *tc, tcp_cc_ack_t ack_type, tcp_ack_ctx_t *ac)
{
  tc->cc_algo->rcv_cong_ack (tc, ack_type, ac);
}

static inline void
tcp_cc_congestion (tcp_connection_t * tc)
{
  tc->cc_algo->congestion (tc);
}

static inline void
tcp_cc_loss (tcp_connection_t * tc)
{
  tc->cc_algo->loss (tc);
}

static inline void
tcp_cc_recovered (tcp_connection_t * tc)
{
  tc->cc_algo->recovered (tc);
}

static inline void
tcp_cc_undo_recovery (tcp_connection_t * tc)
{
  if (tc->cc_algo->undo_recovery)
    tc->cc_algo->undo_recovery (tc);
}

static inline void
tcp_cc_event (tcp_connection_t * tc, tcp_cc_event_t evt)
{
  if (tc->cc_algo->event)
    tc->cc_algo->event (tc, evt);
}

static inline u64
tcp_cc_get_pacing_rate (tcp_connection_t * tc)
{
  if (tc->cc_algo->get_pacing_rate)
    return tc->cc_algo->get_pacing_rate (tc);

  f64 srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);

  /* TODO should constrain to interface's max throughput but
   * we don't have link speeds for sw ifs ..*/
  return ((f64) tc->cwnd / srtt);
}

static inline void *
tcp_cc_data (tcp_connection_t * tc)
{
  return (void *) tc->cc_data;
}

/**
 * Record the end of a flight that permits congestion window growth.
 *
 * @param tc		TCP connection
 * @param max_dequeue	TX fifo bytes at burst start, including outstanding data
 */
always_inline void
tcp_cc_update_cwnd_limited (tcp_connection_t *tc, u32 max_dequeue)
{
  u32 outstanding;

  /* Keep an expired marker close to snd_una across sequence wrap. */
  if (seq_lt (tc->cwnd_limited_seq, tc->snd_una))
    tc->cwnd_limited_seq = tc->snd_una;

  /* A smaller receive window, rather than cwnd, constrained the sender. */
  if (tc->cwnd > tc->snd_wnd)
    return;

  /* Queued data could fill cwnd, so a short flight reflects pacing or output
   * scheduling rather than application-limited input. */
  if (max_dequeue >= tc->cwnd)
    tc->cwnd_limited_seq = tc->snd_nxt;
  else
    {
      outstanding = tc->snd_nxt - tc->snd_una;

      /* RFC 7661 allows standard slow-start growth once the sender has
       * validated more than half of cwnd. Unsent data with less than one MSS
       * of headroom also exhausts cwnd. */
      if (outstanding >= tc->cwnd || (tcp_in_slowstart (tc) && outstanding > tc->cwnd / 2) ||
	  (tc->cwnd - outstanding < tc->snd_mss && max_dequeue > outstanding))
	tc->cwnd_limited_seq = tc->snd_nxt;
    }
}

/** Return true if this ACK covers a flight that permits cwnd growth. */
always_inline u8
tcp_cc_is_cwnd_limited (const tcp_connection_t *tc, const tcp_ack_ctx_t *ac)
{
  return seq_lt (tc->snd_una - ac->bytes_acked, tc->cwnd_limited_seq);
}

/* Eifel spurious-retransmit detection (RFC 3522 Sec. 3.2). Spurious if the ack
 * echoes a timestamp older than the first retransmit (tsecr < snd_rxt_ts) and
 * leaves part of the flight outstanding (snd_una < snd_congestion). A
 * full-flight ack is ambiguous (e.g. an rto from losing all acks) and needs
 * dsack to disambiguate. Other outstanding loss is handled as a new recovery
 * event. Must be called on a cumulative ack in recovery. */
static inline u8
tcp_cc_is_spurious_retransmit (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  ASSERT (tcp_in_cong_recovery (tc) && ac->bytes_acked);
  return (tc->snd_rxt_ts && seq_lt (tc->snd_una, tc->snd_congestion) &&
	  tcp_opts_tstamp (&tc->rcv_opts) && timestamp_lt (tc->rcv_opts.tsecr, tc->snd_rxt_ts));
}

/**
 * Register exiting cc algo type
 */
void tcp_cc_algo_register (tcp_cc_algorithm_type_e type,
			   const tcp_cc_algorithm_t * vft);

/**
 * Register new cc algo type
 */
tcp_cc_algorithm_type_e tcp_cc_algo_new_type (const tcp_cc_algorithm_t * vft);
tcp_cc_algorithm_t *tcp_cc_algo_get (tcp_cc_algorithm_type_e type);

/** Enter fast recovery using the connection's negotiated ACK mechanism. */
void tcp_cc_enter_recovery (tcp_connection_t *tc);

void newreno_rcv_cong_ack (tcp_connection_t *tc, tcp_cc_ack_t ack_type, tcp_ack_ctx_t *ac);

#endif /* SRC_VNET_TCP_TCP_CC_H_ */
