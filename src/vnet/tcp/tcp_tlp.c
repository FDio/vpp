/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_tlp.h>
#include <vnet/tcp/tcp_inlines.h>

/* Allow for a delayed ACK when only one segment is outstanding. */
#define TCP_TLP_MAX_ACK_DELAY 0.025

static_always_inline void
tcp_tlp_clear (tcp_rack_state_t *rack)
{
  rack->flags &= ~(TCP_RACK_F_TLP_IN_FLIGHT | TCP_RACK_F_TLP_IS_RXT);
  rack->tlp_end_seq = 0;
}

void
tcp_tlp_recovery_init (tcp_connection_t *tc)
{
  ASSERT (tcp_rack_enabled (tc));
  tcp_tlp_clear (tcp_rack_get_state (tc));
}

static_always_inline u8
tcp_tlp_can_schedule (tcp_connection_t *tc)
{
  return tc->state >= TCP_STATE_ESTABLISHED && !tcp_in_cong_recovery (tc) &&
	 !(tc->flags & TCP_CONN_FINSNT) && tc->snd_una != tc->snd_nxt &&
	 !tc->sack_sb.sacked_bytes && !tcp_tlp_is_in_flight (tc);
}

static u32
tcp_tlp_pto_ticks (tcp_connection_t *tc)
{
  f64 pto;

  if (tc->srtt)
    {
      pto = 2.0 * (f64) tc->srtt * TCP_TICK;
      if (tcp_flight_size (tc) <= tc->snd_mss)
	pto += TCP_TLP_MAX_ACK_DELAY;
    }
  else
    pto = (f64) TCP_RTO_INIT * TCP_TICK;

  /* Round up so the loss probe never fires before the computed PTO. */
  return clib_max ((u32) (pto / TCP_TIMER_TICK) + 1, 1);
}

u64
tcp_tlp_pto_deadline (tcp_connection_t *tc, u64 now)
{
  if (!tcp_tlp_can_schedule (tc))
    return 0;

  return now + tcp_tlp_pto_ticks (tc);
}

u8
tcp_tlp_retransmit_timer_expired (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 interval = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);

  ASSERT (tcp_rack_timer_is_probe (tc));
  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_retransmit_timer_reset (&wrk->timer_wheel, tc);
      return 1;
    }

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
  if (tcp_tlp_can_schedule (tc) && (rack->flags & TCP_RACK_F_TLP_RTT))
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

  return (rack->flags & TCP_RACK_F_TLP_IN_FLIGHT) && (rack->flags & TCP_RACK_F_TLP_IS_RXT) &&
	 dsack->end == rack->tlp_end_seq;
}

void
tcp_tlp_process_ack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac, u8 is_repeated)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 end = rack->tlp_end_seq;

  if (seq_lt (ack, end))
    return;

  if (rack->flags & TCP_RACK_F_TLP_IS_RXT)
    {
      /* Cumulative delivery retired the only retransmission copy that can
       * exist outside recovery. Keep flight-size accounting neutral. */
      ASSERT (rack->rxt_in_flight == 0);
      tc->snd_rxt_bytes = 0;
      tc->rxt_delivered = 0;
    }

  if (!(rack->flags & TCP_RACK_F_TLP_IS_RXT))
    tcp_tlp_clear (rack);
  else if ((ac->ack_flags & TCP_ACK_F_DSACK) && ac->dsack_end == end)
    tcp_tlp_clear (rack);
  else if (seq_gt (ack, end))
    {
      tcp_tlp_clear (rack);
      ac->ack_flags |= TCP_ACK_F_TLP_RECOVERY;
    }
  else if (is_repeated && !(ac->ack_flags & (TCP_ACK_F_SACK | TCP_ACK_F_DSACK)))
    tcp_tlp_clear (rack);
}
