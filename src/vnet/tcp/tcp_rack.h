/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_types.h>

typedef struct tcp_rack_state_
{
  f64 xmit_ts;		/**< Transmit time of RACK.segment */
  f64 rtt;		/**< RTT of RACK.segment */
  f64 min_rtt;		/**< Windowed minimum RTT */
  f64 min_rtt_ts;	/**< Start of the current min-RTT window */
  u64 rto_deadline;	/**< Absolute retransmit timer-wheel tick */
  u32 end_seq;		/**< End sequence of RACK.segment */
  u32 ack_fack;		/**< Forward ACK while processing one ACK */
  u32 rxt_in_flight;	/**< Active retransmission-copy bytes */
  u32 dsack_round;	/**< SND.NXT at the last reo_wnd adjustment */
  u8 reo_wnd_mult;	/**< Multiples of min_rtt/4 in reo_wnd */
  u8 reo_wnd_persist;	/**< Recoveries before reo_wnd resets */
  u8 dsack_round_valid; /**< A reo_wnd adjustment round is active */
  u8 reo_wnd_updated;	/**< reo_wnd grew on the current ACK */
  u8 reordered;		/**< Reordering observed during this connection */
} tcp_rack_state_t;

#define TCP_RACK_REO_WND_PERSIST 16

void tcp_rack_init (tcp_connection_t *tc);
void tcp_rack_ack_begin (tcp_connection_t *tc, u32 prior_fack);
void tcp_rack_update_reo_wnd (tcp_connection_t *tc, u8 is_dsack);
void tcp_rack_recovery_exit (tcp_connection_t *tc);

always_inline u8
tcp_rack_enabled (tcp_connection_t *tc)
{
  return !!(tc->cfg_flags & TCP_CFG_F_RACK);
}

always_inline tcp_rack_state_t *
tcp_rack_get_state (tcp_connection_t *tc)
{
  ASSERT (tcp_rack_enabled (tc));
  ASSERT (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER);
  ASSERT (tcp_opts_sack_permitted (&tc->rcv_opts));
  ASSERT (tc->bt != 0);
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

always_inline u8
tcp_rack_loss_timer_is_reordering (tcp_connection_t *tc)
{
  return !!(tc->flags & TCP_CONN_LOSS_TIMER_REORDER);
}

always_inline void
tcp_rack_loss_timer_set_reordering (tcp_connection_t *tc)
{
  tc->flags |= TCP_CONN_LOSS_TIMER_REORDER;
}

always_inline void
tcp_rack_loss_timer_set_rto (tcp_connection_t *tc)
{
  tc->flags &= ~TCP_CONN_LOSS_TIMER_REORDER;
}

/* Compare transmissions by send time, then ending sequence. */
always_inline u8
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 other_ts, u32 other_end)
{
  return ts != other_ts ? ts > other_ts : seq_gt (end_seq, other_end);
}

void tcp_rack_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
			    u32 delivered_end);
f64 tcp_rack_reo_wnd (tcp_connection_t *tc);
u32 tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to);
u32 tcp_rack_mark_losses_on_rto (tcp_connection_t *tc);
void tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to, u8 rto_restarts);
void tcp_rack_restore_rto (tcp_connection_t *tc);
void tcp_rack_reorder_timeout (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
