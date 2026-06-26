/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_TLP_H_
#define SRC_VNET_TCP_TCP_TLP_H_

#include <vnet/tcp/tcp_types.h>

/**
 * Tail Loss Probe (TLP), RFC 8985 section 7.
 *
 * RACK detects a lost segment only once a later-sent segment is (s)acked. At
 * the tail of a flow nothing is sent after the last segment(s), so a tail loss
 * generates no further acks and RACK cannot fire -- only the RTO recovers it,
 * at >=200ms and with a cwnd collapse + exponential backoff (the multi-second
 * stall). TLP closes this gap: when the flow goes idle with unacked data, it
 * arms a probe timeout (PTO ~= 2*SRTT, capped at the RTO) on the shared
 * retransmit timer instead of the RTO. When the PTO fires it sends a single
 * probe -- new data if any, else a retransmit of the tail -- whose ack either
 * cumulatively repairs the tail (mild one-time congestion response) or elicits
 * the SACK/dup-acks that drive normal fast recovery. A real RTO is armed as a
 * backstop in case the probe itself is lost.
 *
 * TLP shares RACK's enable knob and the byte tracker.
 */

/**
 * True if TLP is active for this connection (folded under the RACK knob).
 */
always_inline int
tcp_tlp_is_enabled (tcp_connection_t *tc)
{
  return (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE) != 0;
}

/**
 * Arm the (shared) retransmit timer for a tail loss probe, if applicable.
 *
 * No-op unless TLP is enabled, the connection is outside congestion recovery,
 * has unacked data, and the tail is idle (everything queued has been sent). In
 * that case the retransmit timer is (re)armed at the PTO rather than the RTO,
 * overriding any RTO the caller just set. Called from the send path after the
 * last segment is pushed and from the ack path after data is dequeued.
 */
void tcp_tlp_arm_pto (tcp_connection_t *tc);

/**
 * Send a tail loss probe. Called from the retransmit timer handler when the
 * timer was armed as a PTO (tc->tlp_pto_armed). Sends one segment, marks the
 * probe outstanding (TCP_CONN_TLP, tlp_end_seq) and arms an RTO backstop.
 */
void tcp_tlp_send_probe (tcp_worker_ctx_t *wrk, tcp_connection_t *tc);

/**
 * Process an incoming ack while a probe is outstanding (TCP_CONN_TLP set).
 *
 * Must be called after snd_una has been advanced by the ack and after the
 * congestion-control event handling (which clears TCP_CONN_TLP on recovery
 * entry). If the probe is now cumulatively acked and the connection is not in
 * recovery, the probe repaired a genuine tail loss: apply a one-time
 * congestion response and clear the probe state. Dup-acks that do not yet
 * cover the probe are a no-op (the normal dup-ack/RACK path and the RTO
 * backstop still apply).
 */
void tcp_tlp_rcv_ack (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_TLP_H_ */
