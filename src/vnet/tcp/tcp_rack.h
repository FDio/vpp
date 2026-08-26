/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp_bt.h>

typedef enum
{
  TCP_RACK_TIMER_RTO,
  TCP_RACK_TIMER_REO,
} __clib_packed tcp_rack_timer_type_t;

typedef struct tcp_rack_state_
{
  f64 xmit_ts;			    /**< Transmit time of RACK.segment */
  f64 rtt;			    /**< RTT of RACK.segment */
  f64 min_rtt;			    /**< Windowed minimum RTT */
  f64 min_rtt_ts;		    /**< Start of the current min-RTT window */
  f64 rto_deadline;		    /**< Absolute retransmit time in seconds */
  f64 reo_deadline;		    /**< Absolute reordering time in seconds */
  u32 end_seq;			    /**< End sequence of RACK.segment */
  u32 rxt_in_flight;		    /**< Active retransmission-copy bytes */
  u32 dsack_round;		    /**< SND.NXT at the last reo_wnd adjustment */
  u8 reo_wnd_mult;		    /**< Multiples of min_rtt/4 in reo_wnd */
  u8 reo_wnd_persist;		    /**< Recoveries before reo_wnd resets */
  tcp_rack_timer_type_t timer_type; /**< Selected shared retransmit timer */
  u8 flags;			    /**< RACK connection flags */
} tcp_rack_state_t;

typedef enum
{
  TCP_RACK_F_DSACK_ROUND = 1,
  TCP_RACK_F_REORDERED = 1 << 1,
  TCP_RACK_F_SEG_IS_RXT = 1 << 2,
} tcp_rack_flags_t;

#define TCP_RACK_REO_WND_PERSIST 16
#define TCP_RACK_MIN_RTT_WINDOW	 10.0

static_always_inline void
tcp_rack_note_rtt_sample (tcp_rack_state_t *rack, f64 rtt, f64 now)
{
  ASSERT (rtt > 0.0);

  if (rack->min_rtt == 0.0 || now - rack->min_rtt_ts >= TCP_RACK_MIN_RTT_WINDOW)
    {
      rack->min_rtt = rtt;
      rack->min_rtt_ts = now;
    }
  else
    rack->min_rtt = clib_min (rack->min_rtt, rtt);
}

void tcp_rack_init (tcp_connection_t *tc);
void tcp_rack_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
u8 tcp_rack_update_reo_wnd (tcp_connection_t *tc, u8 is_dsack);
u32 tcp_rack_mark_sample_lost (tcp_connection_t *tc, tcp_bt_sample_t *bts);
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

u8 tcp_rack_rxt_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
			      u32 delivered_end, u32 *fack, f64 now);

always_inline u8
tcp_rack_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
		       u32 delivered_end, u32 *fack, f64 now)
{
  f64 rtt;
  u8 advance;

  if (PREDICT_FALSE (bts->flags & TCP_BTS_IS_RXT))
    return tcp_rack_rxt_sample_acked (tc, rack, bts, delivered_end, fack, now);

  /* Original data delivered below the ACK-local FACK indicates reordering. */
  if (seq_lt (delivered_end, *fack))
    rack->flags |= TCP_RACK_F_REORDERED;
  else if (seq_gt (delivered_end, *fack))
    *fack = delivered_end;

  rtt = now - bts->tx_time;
  if (rtt <= 0.0)
    return 0;

  tcp_rack_note_rtt_sample (rack, rtt, now);
  advance = rack->rtt == 0.0 ||
	    tcp_bt_tx_sent_after (bts->tx_time, delivered_end, rack->xmit_ts, rack->end_seq);
  rack->rtt = rtt;
  if (advance)
    {
      rack->xmit_ts = bts->tx_time;
      rack->end_seq = delivered_end;
      rack->flags &= ~TCP_RACK_F_SEG_IS_RXT;
    }
  return 1;
}

f64 tcp_rack_reo_wnd (tcp_connection_t *tc);
u32 tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to);
u32 tcp_rack_mark_losses_on_rto (tcp_connection_t *tc);
void tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to, u8 timer_update_deferred);
void tcp_rack_restore_rto (tcp_connection_t *tc);
void tcp_rack_reorder_timeout (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
