/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_types.h>

/**
 * RACK loss detection (RFC 8985).
 *
 * RACK ("recent acknowledgment") declares a segment lost when a segment sent
 * after it has been (s)acked and a reordering window (reo_wnd) has elapsed
 * since it was (re)transmitted. This detects losses -- including lost
 * retransmits -- by time rather than by dup-ack counting or an RTO, which
 * avoids the multi-second stalls that lost retransmits otherwise incur (no
 * other mechanism re-sends a lost retransmit until the RTO fires).
 *
 * Implementation relies on the byte tracker (@ref tcp_bt_sample_t) for
 * per-segment transmit timestamps. RACK is therefore equivalent to rate
 * sampling: it is active exactly when the byte tracker (TCP_CFG_F_RATE_SAMPLE)
 * is enabled.
 */

/* A newly (s)acked segment is "more recent" than the current rack record if it
 * was transmitted later, or at the same time but higher in sequence space. */
always_inline int
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 cur_ts, u32 cur_end)
{
  return ts != cur_ts ? ts > cur_ts : seq_gt (end_seq, cur_end);
}

/**
 * Record that a (re)transmitted segment has been (s)acked.
 *
 * Called from the byte-tracker ack walk for each newly (s)acked sample;
 * advances rack_xmit_ts/rack_end_seq to the most recently transmitted such
 * segment.
 */
always_inline void
tcp_rack_sample_acked (tcp_connection_t *tc, u32 max_seq, f64 tx_time, u32 flags)
{
  /* RFC 8985's retransmission-ambiguity guard (skip a retransmitted segment
   * whose RTT is below min_rtt, as its ack was likely elicited by the original
   * transmission) is omitted: we derive no RTT estimate here, so a
   * mis-attributed retransmit can only declare loss marginally early, bounded
   * by reo_wnd. */
  if (tcp_rack_sent_after (tx_time, max_seq, tc->rack_xmit_ts, tc->rack_end_seq))
    {
      tc->rack_xmit_ts = tx_time;
      tc->rack_end_seq = max_seq;
    }
}

/**
 * Detect and mark losses per the RACK time threshold.
 *
 * Walks outstanding (unacked, unsacked) byte-tracker samples. A sample is lost
 * if a later-sent segment has been delivered (the sample was sent no later than
 * rack_xmit_ts) and it has been outstanding longer than reo_wnd; such samples
 * are marked lost in the SACK scoreboard so the normal retransmit path re-sends
 * them. Returns the number of bytes newly marked lost.
 *
 * @param tc		connection
 * @param[out] next_to	earliest future time (relative, in seconds) at which a
 *			not-yet-expired suspect segment would cross the reo_wnd
 *			threshold, or 0 if none. Used to arm the reorder timeout
 *			on the retransmit timer.
 */
u32 tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to);

/**
 * Arm the (shared) retransmit timer for a RACK reorder timeout.
 *
 * @param tc		connection
 * @param next_to	seconds until the earliest suspect segment crosses the
 *			reordering window (from tcp_rack_detect_loss)
 */
void tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
