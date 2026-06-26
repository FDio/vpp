/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_types.h>

/**
 * RACK-TLP loss detection (RFC 8985).
 *
 * RACK ("recent acknowledgment") declares a segment lost when a segment sent
 * after it has been (s)acked and a reordering window (reo_wnd) has elapsed
 * since it was (re)transmitted. This detects losses -- including lost
 * retransmits -- by time rather than by dup-ack counting or an RTO, which
 * avoids the multi-second stalls that lost retransmits otherwise incur (no
 * other mechanism re-sends a lost retransmit until the RTO fires).
 *
 * Implementation relies on the byte tracker (@ref tcp_bt_sample_t) for
 * per-segment transmit timestamps, so a RACK connection always has the byte
 * tracker enabled (TCP_CONN_RACK implies it).
 */

/**
 * Update RACK state from the segments (s)acked by the current ack.
 *
 * Advances tc->rack_xmit_ts/rack_end_seq to the most recently transmitted
 * segment among those newly (s)acked, and refreshes the reordering window.
 * Must be called after the scoreboard and byte tracker have processed the ack.
 */
void tcp_rack_update (tcp_connection_t *tc);

/**
 * Record that a (re)transmitted segment has been (s)acked.
 *
 * Called from the byte-tracker ack walk for each newly (s)acked sample;
 * advances rack_xmit_ts/rack_end_seq to the most recently transmitted such
 * segment. @see tcp_rack_update for the per-ack post-processing.
 */
void tcp_rack_sample_acked (tcp_connection_t *tc, u32 max_seq, f64 tx_time, u32 flags);

/**
 * Detect and mark losses per the RACK time threshold.
 *
 * Walks outstanding (unacked, unsacked) byte-tracker samples and marks those
 * sent more than reo_wnd before rack_xmit_ts as lost in the SACK scoreboard,
 * so the normal retransmit path re-sends them. Returns the number of bytes
 * newly marked lost.
 *
 * @param tc		connection
 * @param[out] next_to	if non-null, set to the earliest future time (relative,
 *			in seconds) at which a not-yet-expired suspect segment
 *			would cross the reo_wnd threshold, or 0 if none. Used to
 *			arm the reorder timeout on the retransmit timer.
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

/**
 * True if RACK is active for this connection.
 */
always_inline int
tcp_rack_is_enabled (tcp_connection_t *tc)
{
  return (tc->flags & TCP_CONN_RACK) != 0;
}

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
