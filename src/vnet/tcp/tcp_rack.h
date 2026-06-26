/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_types.h>

always_inline u8
tcp_rack_is_enabled (tcp_connection_t *tc)
{
  return ((tc->cfg_flags & TCP_CFG_F_RACK) && tc->bt && tcp_opts_sack_permitted (&tc->rcv_opts));
}

/* A segment is newer if it was transmitted later, or at the same time with a
 * higher ending sequence number. */
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
void tcp_rack_timer_reset (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
