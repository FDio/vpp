/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_types.h>

typedef struct tcp_rack_state_
{
  f64 xmit_ts;	     /**< Transmit time of RACK.segment */
  f64 rtt;	     /**< RTT of RACK.segment */
  f64 min_rtt;	     /**< Windowed minimum RTT */
  f64 min_rtt_ts;    /**< Start of the current min-RTT window */
  u64 rto_deadline;  /**< Absolute retransmit timer-wheel tick */
  u64 reo_deadline;  /**< Absolute reordering timer-wheel tick */
  u32 end_seq;	     /**< End sequence of RACK.segment */
  u32 ack_fack;	     /**< Forward ACK while processing one ACK */
  u32 rxt_in_flight; /**< Active retransmission-copy bytes */
  u32 loss_segs;     /**< Transmissions declared lost by RACK */
  u32 rxt_loss_segs; /**< Retransmissions declared lost by RACK */
  u32 timeouts;	     /**< RACK reordering timer expirations */
  u8 reordered;	     /**< Reordering observed during this connection */
} tcp_rack_state_t;

void tcp_rack_init (tcp_connection_t *tc);
void tcp_rack_ack_begin (tcp_connection_t *tc, u32 prior_fack);

always_inline tcp_rack_state_t *
tcp_rack_get_state (tcp_connection_t *tc)
{
  ASSERT (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE);
  ASSERT (tcp_opts_sack_permitted (&tc->rcv_opts));
  return (tcp_rack_state_t *) (tc->bt + 1);
}

always_inline u8
tcp_rack_reordered (tcp_connection_t *tc)
{
  return tcp_rack_get_state (tc)->reordered;
}

always_inline void
tcp_rack_reordered_on (tcp_connection_t *tc)
{
  tcp_rack_get_state (tc)->reordered = 1;
}

always_inline void
tcp_rack_reordered_off (tcp_connection_t *tc)
{
  tcp_rack_get_state (tc)->reordered = 0;
}

/* Compare transmissions by send time, then ending sequence. */
always_inline u8
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 other_ts, u32 other_end)
{
  return ts != other_ts ? ts > other_ts : seq_gt (end_seq, other_end);
}

void tcp_rack_sample_acked (tcp_connection_t *tc, tcp_bt_sample_t *bts, u32 delivered_end);
f64 tcp_rack_reo_wnd (tcp_connection_t *tc);
u32 tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to);
u32 tcp_rack_mark_losses_on_rto (tcp_connection_t *tc);
void tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to);
void tcp_loss_timer_restore_rto (tcp_connection_t *tc);
void tcp_rack_reorder_timeout (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
