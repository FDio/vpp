/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_tlp.h>
#include <vnet/tcp/tcp_cc.h>
#include <vnet/tcp/tcp_inlines.h>

/*
 * Tail Loss Probe, RFC 8985 section 7. See tcp_tlp.h for the rationale.
 *
 * The probe-send mechanics (tcp_tlp_send_probe) live in tcp_output.c next to
 * the segment helpers they need; this file holds the PTO arming and the
 * probe-ack congestion response.
 */

/* Lower bound on the probe timeout. Mirrors Linux's 10ms TLP_MIN_TIMEOUT: an
 * SRTT-derived PTO can be tiny on a fast path, and probing sooner than this
 * just races the receiver's ack. */
#define TCP_TLP_MIN_PTO (0.01)

/* Delayed-ack allowance added to the PTO when a single segment is outstanding:
 * that segment's ack may be held by the receiver's delayed-ack timer, so wait a
 * little longer before deeming it lost. Capped to avoid pushing the PTO past
 * the RTO on high-RTT paths (RFC 8985 uses the worst-case delayed-ack time;
 * we use a fraction of SRTT so the probe still precedes the RTO). */
#define TCP_TLP_DELACK_MAX (0.025)

void
tcp_tlp_arm_pto (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk;
  f64 srtt_s, pto_s;
  u32 pto, rto, pto_ticks;

  /* Whatever the retransmit timer holds after this call, it is no longer a PTO
   * unless we (re)arm one below. Clearing here keeps the flag in sync with the
   * RTO the caller just (re)armed, so a stale PTO never fires as a probe. */
  tc->tlp_pto_armed = 0;

  if (!tcp_tlp_is_enabled (tc))
    return;

  /* Only when idle at the tail: data outstanding, but nothing left unsent.
   * Mid-bulk the cwnd/pacer gate progress, not a tail loss; in recovery the
   * RACK reorder timer / RTO already cover us. */
  if (tcp_in_cong_recovery (tc) || tc->snd_una == tc->snd_nxt)
    return;
  if (transport_max_tx_dequeue (&tc->connection) != tc->snd_nxt - tc->snd_una)
    return;

  /* Need an RTT estimate to derive the PTO; otherwise leave the RTO in place. */
  srtt_s = clib_max ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);
  if (srtt_s <= 0.0)
    return;

  pto_s = 2.0 * srtt_s;
  if (tc->snd_nxt - tc->snd_una <= tc->snd_mss)
    pto_s += clib_min (srtt_s, TCP_TLP_DELACK_MAX);
  pto_s = clib_max (pto_s, TCP_TLP_MIN_PTO);

  pto = (u32) (pto_s * THZ);
  rto = clib_max (tc->rto, (u32) TCP_RTO_MIN);

  /* The probe must precede the RTO; if it wouldn't, the RTO is doing the job. */
  if (pto >= rto)
    return;

  pto_ticks = clib_max ((u32) (pto * TCP_TO_TIMER_TICK), 1);

  wrk = tcp_get_worker (tc->c_thread_index);
  tc->rack_timeout_armed = 0;
  tc->tlp_pto_armed = 1;
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, pto_ticks);
}

void
tcp_tlp_rcv_ack (tcp_connection_t *tc)
{
  /* Probe outstanding and now cumulatively acked: the retransmitted tail
   * reached the peer. If we did not enter recovery off this ack (handled
   * upstream, which also clears TCP_CONN_TLP), the probe alone repaired the
   * loss -- apply a one-time multiplicative decrease, as a tail loss is still a
   * congestion signal. Without DSACK we cannot tell a merely-delayed tail from
   * a lost one, so a probe of a delayed (not lost) segment costs one spurious
   * cwnd reduction; the delayed-ack allowance in the PTO keeps this rare. */
  if (!(tc->flags & TCP_CONN_TLP))
    return;

  if (seq_lt (tc->snd_una, tc->tlp_end_seq))
    return;

  tc->flags &= ~TCP_CONN_TLP;
  tc->tlp_end_seq = 0;

  if (tcp_in_cong_recovery (tc))
    return;

  tcp_cc_congestion (tc);
  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */);
}
