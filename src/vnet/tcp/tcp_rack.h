/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_bt.h>

typedef struct tcp_rack_state_
{
  f64 xmit_ts;	      /**< Transmit time of RACK.segment */
  f64 rtt;	      /**< RTT of RACK.segment */
  f64 min_rtt;	      /**< Windowed minimum RTT */
  f64 min_rtt_ts;     /**< Start of the current min-RTT window */
  u64 rto_deadline;   /**< Absolute retransmit timer-wheel tick */
  u64 reo_deadline;   /**< Absolute reordering timer-wheel tick */
  u32 end_seq;	      /**< End sequence of RACK.segment */
  u32 rxt_in_flight;  /**< Active retransmission-copy bytes */
  u32 dsack_round;    /**< SND.NXT at the last reo_wnd adjustment */
  u8 reo_wnd_mult;    /**< Multiples of min_rtt/4 in reo_wnd */
  u8 reo_wnd_persist; /**< Recoveries before reo_wnd resets */
  u8 flags;	      /**< RACK connection flags */
} tcp_rack_state_t;

typedef enum
{
  TCP_RACK_F_DSACK_ROUND = 1,
  TCP_RACK_F_REORDERED = 1 << 1,
  TCP_RACK_F_REF_IS_RXT = 1 << 2,
} tcp_rack_flags_t;

#define TCP_RACK_REO_WND_PERSIST 16

void tcp_rack_init (tcp_connection_t *tc);
void tcp_rack_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
u8 tcp_rack_update_reo_wnd (tcp_connection_t *tc, u8 is_dsack);
void tcp_rack_recovery_init (tcp_connection_t *tc);
void tcp_rack_recovery_exit (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
void tcp_rack_recovery_sync (tcp_connection_t *tc);
u8 tcp_rack_recovery_account_is_sane (tcp_connection_t *tc);
void tcp_rack_prepare_rto (tcp_connection_t *tc, u8 *sack_reneged);
u8 tcp_rack_retransmit_timer_expired (tcp_connection_t *tc);

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
  return (tcp_rack_state_t *) tcp_bt_opaque (tc);
}

always_inline u8
tcp_rack_reordered (tcp_connection_t *tc)
{
  return !!(tcp_rack_get_state (tc)->flags & TCP_RACK_F_REORDERED);
}

/* Compare transmissions by send time, then ending sequence. */
always_inline u8
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 other_ts, u32 other_end)
{
  return ts != other_ts ? ts > other_ts : seq_gt (end_seq, other_end);
}

u8 tcp_rack_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
			  u32 delivered_end, u32 *fack, f64 now);
f64 tcp_rack_reo_wnd (tcp_connection_t *tc);
u32 tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to);
u32 tcp_rack_mark_losses_on_rto (tcp_connection_t *tc);
void tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to, u8 rto_update_deferred);
void tcp_rack_restore_rto (tcp_connection_t *tc);
void tcp_rack_reorder_timeout (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
