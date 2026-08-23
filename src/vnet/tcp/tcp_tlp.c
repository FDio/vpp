/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_tlp.h>
#include <vnet/tcp/tcp_inlines.h>

/* RFC 8985 leaves this budget implementation specific and recommends waiting
 * long enough for a receiver to release a delayed ACK. Use TCP's minimum RTO
 * so a one-segment flight is not probed aggressively ahead of delayed ACKs. */
#define TCP_TLP_MAX_ACK_DELAY (TCP_RTO_MIN * TCP_TICK)

static_always_inline void
tcp_tlp_clear (tcp_connection_t *tc, tcp_rack_state_t *rack)
{
  tc->flags &= ~TCP_CONN_TLP_PENDING;
  rack->flags &= ~TCP_RACK_F_TLP_IS_RXT;
  rack->tlp_end_seq = 0;
}

void
tcp_tlp_recovery_init (tcp_connection_t *tc)
{
  ASSERT (tcp_rack_enabled (tc));
  tcp_tlp_clear (tc, tcp_rack_get_state (tc));
}

void
tcp_tlp_retransmit_disarm_rtt (tcp_connection_t *tc, u32 start, u32 end)
{
  ASSERT (seq_lt (start, end));

  /* ACK timing cannot distinguish the original segment from its probe
   * retransmission. Timestamp-based RTT measurement remains available. */
  if (tc->rtt_ts && seq_gt (tc->rtt_seq, start) && seq_leq (tc->rtt_seq, end))
    tc->rtt_ts = 0;
}

static_always_inline u8
tcp_tlp_can_schedule (tcp_connection_t *tc)
{
  return tc->state >= TCP_STATE_ESTABLISHED && !tcp_in_cong_recovery (tc) &&
	 !(tc->flags & TCP_CONN_FINSNT) && tc->snd_una != tc->snd_nxt &&
	 !tc->sack_sb.sacked_bytes && !tcp_tlp_is_pending (tc);
}

u8
tcp_tlp_new_data_fits_cwnd (tcp_connection_t *tc, u32 n_bytes)
{
  return n_bytes && tcp_available_cc_snd_space (tc) >= n_bytes;
}

u32
tcp_tlp_pto_ticks (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;
  f64 pto;

  /* RFC 8985 permits only one probe until a new RTT sample is obtained. Do
   * not arm an early timer when the freshness gate cannot send a probe. */
  if (!tcp_tlp_can_schedule (tc))
    return 0;

  rack = tcp_rack_get_state (tc);
  if (!(rack->flags & TCP_RACK_F_TLP_RTT))
    return 0;

  if (tc->srtt)
    {
      pto = 2.0 * (f64) tc->srtt * TCP_TICK;
      if (tcp_flight_size (tc) <= tc->snd_mss)
	pto += TCP_TLP_MAX_ACK_DELAY;
    }
  else
    pto = (f64) TCP_RTO_INIT * TCP_TICK;

  /* Round up before PTO competes with the RTO. A PTO that maps to the RTO
   * tick remains a probe and starts a fresh RTO after it fires. */
  return clib_max ((u32) (pto / TCP_TIMER_TICK) + 1, 1);
}

u8
tcp_tlp_retransmit_timer_expired (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 interval = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);

  ASSERT (tcp_rack_timer_is_probe (tc));
  ASSERT (rack->flags & TCP_RACK_F_TLP_RTT);
  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_retransmit_timer_reset (&wrk->timer_wheel, tc);
      return 1;
    }

  rack->timer_type = TCP_RACK_TIMER_RTO;
  if (tc->flags & TCP_CONN_FINSNT)
    {
      /* FINs bypass the data output path and its TLP bookkeeping. Use the
       * dedicated FIN retransmit path so sequence and timer handling stay
       * in the FIN path. */
      tcp_send_fin (tc);
    }
  else if (tcp_tlp_can_schedule (tc))
    tcp_tlp_send_probe (tc);
  else
    tcp_retransmit_timer_reschedule (&wrk->timer_wheel, tc, interval);

  return 1;
}

u8
tcp_tlp_dsack_matches (tcp_connection_t *tc, const sack_block_t *dsack)
{
  tcp_rack_state_t *rack;

  if (!tcp_rack_enabled (tc))
    return 0;

  rack = tcp_rack_get_state (tc);

  return tcp_tlp_is_pending (tc) && (rack->flags & TCP_RACK_F_TLP_IS_RXT) &&
	 dsack->end - dsack->start <= tc->snd_mss && dsack->end != dsack->start &&
	 dsack->end == rack->tlp_end_seq;
}

void
tcp_tlp_process_ack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 end = rack->tlp_end_seq;

  ASSERT (tcp_tlp_is_pending (tc));
  ASSERT (!tcp_in_cong_recovery (tc));

  if (seq_lt (ack, end))
    return;

  /* An ACK covering a new-data probe fully resolves it. */
  if (!(rack->flags & TCP_RACK_F_TLP_IS_RXT))
    {
      tcp_tlp_clear (tc, rack);
      return;
    }

  /* The cumulative ACK retired the retransmitted copy, even if the probe
   * outcome remains ambiguous. */
  ASSERT (rack->rxt_in_flight == 0);
  ASSERT (tc->rxt_delivered == 0);
  tc->snd_rxt_bytes = 0;

  /* The probe was duplicate, so no congestion response is needed. */
  if (ac->ack_flags & TCP_ACK_F_TLP_DSACK)
    {
      tcp_tlp_clear (tc, rack);
      return;
    }

  /* Progress beyond the probe proves that it repaired the tail loss. */
  if (seq_gt (ack, end))
    {
      tcp_tlp_clear (tc, rack);
      ac->ack_flags |= TCP_ACK_F_TLP_RECOVERY;
      return;
    }

  /* The first exact ACK is ambiguous. A subsequent plain duplicate ACK
   * indicates that the retransmitted copy arrived after the original. */
  if ((ac->ack_flags & TCP_ACK_F_REPEATED) && !(ac->ack_flags & (TCP_ACK_F_SACK | TCP_ACK_F_DSACK)))
    tcp_tlp_clear (tc, rack);
}
