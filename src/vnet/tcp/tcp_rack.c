/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_inlines.h>

void
tcp_rack_init (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  ASSERT (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER);
  ASSERT (tcp_opts_sack_permitted (&tc->rcv_opts));
  tcp_bt_init_opaque (tc, sizeof (tcp_rack_state_t));
  rack = tcp_rack_get_state (tc);
  rack->reo_wnd_mult = 1;
}

void
tcp_rack_recovery_init (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  rack = tcp_rack_get_state (tc);
  tc->snd_rxt_bytes = rack->rxt_in_flight;
  tcp_bt_init_rxt (tc, tc->snd_rxt_bytes ? tc->sack_sb.high_rxt : tc->snd_una);
}

void
tcp_rack_recovery_exit (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  /* A DSACK adjustment on the recovery-ending ACK takes precedence. */
  if (ac->ack_flags & TCP_ACK_F_REO_WND_UPDATED)
    return;

  rack = tcp_rack_get_state (tc);
  if (rack->reo_wnd_persist)
    rack->reo_wnd_persist--;
  if (!rack->reo_wnd_persist)
    rack->reo_wnd_mult = 1;
}

static_always_inline void
tcp_rack_sync_rxt_delivery (tcp_connection_t *tc, tcp_rack_state_t *rack)
{
  ASSERT (rack->rxt_in_flight <= tc->snd_rxt_bytes);
  rack->rxt_in_flight = clib_min (rack->rxt_in_flight, tc->snd_rxt_bytes);
  tc->rxt_delivered = tc->snd_rxt_bytes - rack->rxt_in_flight;
}

void
tcp_rack_recovery_sync (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  ASSERT (tcp_in_cong_recovery (tc));
  rack = tcp_rack_get_state (tc);
  tcp_rack_sync_rxt_delivery (tc, rack);
}

u8
tcp_rack_recovery_account_is_sane (tcp_connection_t *tc)
{
  ASSERT (tcp_rack_enabled (tc));
  return tc->rxt_delivered <= tc->snd_rxt_bytes &&
	 tc->snd_rxt_bytes - tc->rxt_delivered == tcp_rack_get_state (tc)->rxt_in_flight;
}

static void
tcp_rack_mark_reneged_lost (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u32 index = bt->head, next, newly_lost = 0;

  while (index != TCP_BTS_INVALID_INDEX)
    {
      bts = pool_elt_at_index (bt->samples, index);
      next = bts->next;
      if (!(bts->flags & TCP_BTS_TX_LOST))
	{
	  newly_lost += bts->max_seq - bts->min_seq;
	  tcp_rack_mark_sample_lost (tc, bts);
	}
      index = next;
    }
  /* Reneging handling already rebuilt sack_sb.lost_bytes for this range. */
  tc->lost += newly_lost;
}

void
tcp_rack_prepare_rto (tcp_connection_t *tc, u8 *sack_reneged)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  rack = tcp_rack_get_state (tc);
  if (!tcp_in_cong_recovery (tc))
    {
      tc->snd_rxt_bytes = rack->rxt_in_flight;
      tc->rxt_delivered = 0;
    }
  *sack_reneged = tcp_bt_handle_sack_reneging (tc, 0 /* restore_tx_order */);
  if (*sack_reneged)
    {
      /* The receiver discarded data it had previously SACKed. Unlike the
       * normal RTO age test, every restored current transmission copy must
       * become immediately eligible for retransmission. */
      tcp_rack_mark_reneged_lost (tc);
    }
  else
    tcp_rack_mark_losses_on_rto (tc);
  tcp_rack_sync_rxt_delivery (tc, rack);
}

u8
tcp_rack_retransmit_timer_expired (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));
  rack = tcp_rack_get_state (tc);

  if (rack->timer_type == TCP_RACK_TIMER_REO)
    {
      rack->reo_deadline = 0;
      tcp_rack_reorder_timeout (tc);
      return 1;
    }

  rack->rto_deadline = 0;
  rack->reo_deadline = 0;
  return 0;
}

u8
tcp_rack_update_reo_wnd (tcp_connection_t *tc, u8 is_dsack)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  if ((rack->flags & TCP_RACK_F_DSACK_ROUND) && seq_geq (tc->snd_una, rack->dsack_round))
    rack->flags &= ~TCP_RACK_F_DSACK_ROUND;

  if (!is_dsack)
    return 0;

  rack->flags |= TCP_RACK_F_REORDERED;
  if (rack->flags & TCP_RACK_F_DSACK_ROUND)
    return 0;

  /* RFC 8985 permits one linear increase per round trip with a DSACK. */
  rack->dsack_round = tc->snd_nxt;
  rack->flags |= TCP_RACK_F_DSACK_ROUND;
  rack->reo_wnd_mult = clib_min (rack->reo_wnd_mult + 1, 0xff);
  rack->reo_wnd_persist = TCP_RACK_REO_WND_PERSIST;
  return 1;
}

u8
tcp_rack_rxt_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
			   u32 delivered_end, u32 *fack, f64 now)
{
  f64 rtt = now - bts->tx_time;
  u8 advance;

  ASSERT (bts->flags & TCP_BTS_IS_RXT);
  if (seq_gt (delivered_end, *fack))
    *fack = delivered_end;

  if (rtt <= 0.0)
    return 0;

  /* Ignore ambiguous retransmission ACKs per RFC 8985 section 6.2. */
  if (tcp_opts_tstamp (&tc->rcv_opts))
    {
      /* Derive the retransmission TSval from its tracked send time. */
      u32 tx_tsval = (u32) ((u64) (bts->tx_time * TCP_TSTP_HZ)) - tc->timestamp_delta;
      if (timestamp_lt (tc->rcv_opts.tsecr, tx_tsval))
	return 0;
    }

  /* Connection setup finalizes the handshake RTT after RACK allocation. Use
   * that RFC 6298 measurement to bootstrap the ambiguity check if the first
   * delivered data is a retransmission. */
  if (rack->min_rtt <= 0.0 && tc->mrtt_us > 0.0 && tc->mrtt_us < (f64) TCP_RTT_MAX * TCP_TICK)
    tcp_rack_note_rtt_sample (rack, tc->mrtt_us, now);

  if (rack->min_rtt <= 0.0 || rtt < rack->min_rtt)
    return 0;

  tcp_rack_note_rtt_sample (rack, rtt, now);

  advance = rack->rtt == 0.0 ||
	    tcp_bt_tx_sent_after (bts->tx_time, delivered_end, rack->xmit_ts, rack->end_seq);
  rack->rtt = rtt;
  if (advance)
    {
      rack->xmit_ts = bts->tx_time;
      rack->end_seq = delivered_end;
      rack->flags |= TCP_RACK_F_SEG_IS_RXT;
    }
  return 1;
}

f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  f64 srtt;

  /* RFC 8985 makes the reordering signal connection-wide and sticky. Once observed, loss detection
   * retains the bounded reo_wnd instead of returning to the DupThresh fast path. Before that, use
   * the SACK-learned packet reordering estimate, initialized to TCP_DUPACK_THRESHOLD. */
  if (!(rack->flags & TCP_RACK_F_REORDERED) &&
      (tcp_in_cong_recovery (tc) || tc->sack_sb.sacked_bytes >= tc->sack_sb.reorder * tc->snd_mss))
    return 0.0;

  if (rack->min_rtt <= 0.0)
    return 0.0;

  srtt = (f64) tc->srtt * TCP_TICK;
  return clib_min (rack->reo_wnd_mult * rack->min_rtt / 4.0, srtt);
}

typedef struct
{
  tcp_rack_state_t *rack;
  f64 now;
  f64 reo_wnd;
  f64 next_to;
  u32 range_start;
  u32 range_end;
  u32 force_end;
  u32 lost_bytes;
  u32 first_lost_seq;
  u8 is_rto;
  u8 has_lost_seq;
} tcp_rack_loss_ctx_t;

u32
tcp_rack_mark_sample_lost (tcp_connection_t *tc, tcp_bt_sample_t *bts)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 available, delivered, departed = 0, recovery_credit;

  ASSERT (!(bts->flags & (TCP_BTS_TX_LOST | TCP_BTS_IS_SACKED)));
  if (bts->flags & TCP_BTS_IS_RXT)
    {
      departed = bts->max_seq - bts->min_seq;
      ASSERT (departed <= rack->rxt_in_flight);
      departed = clib_min (departed, rack->rxt_in_flight);
      rack->rxt_in_flight -= departed;
      if (tcp_in_cong_recovery (tc))
	{
	  ASSERT (tc->rxt_delivered <= tc->snd_rxt_bytes);
	  delivered = clib_min (tc->rxt_delivered, tc->snd_rxt_bytes);
	  available = tc->snd_rxt_bytes - delivered;
	  ASSERT (departed <= available);
	  recovery_credit = clib_min (departed, available);
	  tc->rxt_delivered = delivered + recovery_credit;
	  departed = recovery_credit;
	}
    }
  tcp_bt_tx_order_remove (tc->bt, bts);
  bts->flags |= TCP_BTS_IS_LOST | TCP_BTS_TX_LOST;
  return departed;
}

static_always_inline void
tcp_rack_evaluate_sample_loss (tcp_connection_t *tc, tcp_bt_sample_t *bts, tcp_rack_loss_ctx_t *ctx)
{
  u32 start, end, len, loss_len, newly_lost;
  f64 remaining;
  u8 force_rto, was_lost;

  if ((bts->flags & (TCP_BTS_TX_LOST | TCP_BTS_IS_SACKED)) ||
      (!(bts->flags & TCP_BTS_IS_RXT) && (bts->flags & TCP_BTS_IS_LOST)))
    return;

  start = seq_gt (bts->min_seq, ctx->range_start) ? bts->min_seq : ctx->range_start;
  end = seq_lt (bts->max_seq, ctx->range_end) ? bts->max_seq : ctx->range_end;
  if (!seq_lt (start, end))
    return;

  /* Scan boundaries must align with sample boundaries. Avoid marking an
   * entire sample lost if that invariant is violated. */
  if (PREDICT_FALSE (start != bts->min_seq || end != bts->max_seq))
    {
      ASSERT (start == bts->min_seq && end == bts->max_seq);
      return;
    }

  force_rto = ctx->is_rto && seq_lt (start, ctx->force_end);

  if (ctx->is_rto && !force_rto && ctx->rack->rtt <= 0.0)
    return;

  remaining = bts->tx_time + ctx->rack->rtt + ctx->reo_wnd - ctx->now;
  if (!force_rto && remaining > 0.0)
    {
      if (!ctx->is_rto)
	ctx->next_to = clib_max (ctx->next_to, remaining);
      return;
    }

  len = end - start;
  was_lost = !!(bts->flags & TCP_BTS_IS_LOST);
  tcp_rack_mark_sample_lost (tc, bts);
  newly_lost = was_lost ? 0 : len;
  tc->sack_sb.lost_bytes += newly_lost;

  /* A retransmission loss is new even if its sequence range was already
   * marked lost for an earlier transmission. */
  loss_len = (bts->flags & TCP_BTS_IS_RXT) ? len : newly_lost;
  if (!loss_len)
    return;

  ctx->lost_bytes += loss_len;
  if (!ctx->has_lost_seq || seq_lt (start, ctx->first_lost_seq))
    {
      ctx->first_lost_seq = start;
      ctx->has_lost_seq = 1;
    }
}

static_always_inline void
tcp_rack_mark_lost_samples (tcp_connection_t *tc, tcp_rack_loss_ctx_t *ctx)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_tx_order_t *order = tcp_bt_tx_order (tc);
  tcp_bt_sample_t *bts;
  u8 has_tx_order = order->links != 0;
  u32 index, next;

  index = has_tx_order ? order->head : bt->head;
  while (index != TCP_BTS_INVALID_INDEX)
    {
      bts = pool_elt_at_index (bt->samples, index);
      next = has_tx_order ? order->links[index].next : bts->next;

      /* Stop at the first sample not sent before RACK.segment. All following samples are
       * ineligible. Until a retransmission, sequence order also preserves transmit order, so the
       * sequence list is sufficient. */
      if (!ctx->is_rto && !tcp_bt_tx_sent_after (ctx->rack->xmit_ts, ctx->rack->end_seq,
						 bts->tx_time, bts->max_seq))
	break;
      if (seq_gt (bts->max_seq, ctx->range_start))
	{
	  if (seq_lt (bts->min_seq, ctx->range_end))
	    tcp_rack_evaluate_sample_loss (tc, bts, ctx);
	}
      index = next;
    }
}

static_always_inline u32
tcp_rack_detect_loss_internal (tcp_connection_t *tc, f64 *next_to, u8 is_rto)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 end, first_end;

  /* BT owns all SACK ranges for RACK connections. sack_sb retains only the
   * common scalar accounting consumed by congestion control. */
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX);
  ASSERT (pool_elts (sb->holes) == 0);

  if (tc->snd_una == tc->snd_nxt)
    {
      if (next_to)
	*next_to = 0.0;
      return 0;
    }

  tcp_rack_loss_ctx_t ctx = {
    .rack = rack,
    .now = tcp_time_now_us (tc->c_thread_index),
    /* RFC 8985 suppresses the reordering window during RTO recovery unless
     * this connection has observed reordering. prepare_rto runs before the
     * generic recovery flag is set, so make that RTO state explicit here. */
    .reo_wnd = is_rto && !tcp_rack_reordered (tc) ? 0.0 : tcp_rack_reo_wnd (tc),
    .is_rto = is_rto,
  };

  if (!is_rto)
    {
      if (rack->rtt <= 0.0)
	goto done;

      /* An ACKed retransmission may be newer than outstanding data at higher
       * sequence numbers. Since RACK uses transmit order, scan through SND.NXT. */
      if (!(rack->flags & TCP_RACK_F_SEG_IS_RXT) && seq_leq (sb->high_sacked, tc->snd_una))
	goto done;
    }

  if (is_rto)
    {
      first_end = tc->snd_una + tc->snd_mss;
      if (seq_gt (first_end, tc->snd_nxt))
	first_end = tc->snd_nxt;
      tcp_bt_split_at (tc, first_end);
      ctx.force_end = first_end;
      end = tc->snd_nxt;
    }
  else
    {
      if (rack->flags & TCP_RACK_F_SEG_IS_RXT)
	end = tc->snd_nxt;
      else
	{
	  end = sb->high_sacked;
	  tcp_bt_split_at (tc, end);
	}
    }

  /* In byte-tracker mode, SACK state and loss ranges are owned by the
   * samples. Walk the unsacked transmission samples directly instead of
   * rebuilding a parallel scoreboard-hole view. */
  ctx.range_start = tc->snd_una;
  ctx.range_end = end;
  tcp_rack_mark_lost_samples (tc, &ctx);

  tc->lost += ctx.lost_bytes;
  if (ctx.has_lost_seq)
    tcp_bt_rxt_rewind (tc, ctx.first_lost_seq);

done:
  if (next_to)
    *next_to = ctx.next_to;
  return ctx.lost_bytes;
}

u32
tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to)
{
  return tcp_rack_detect_loss_internal (tc, next_to, 0 /* is_rto */);
}

u32
tcp_rack_mark_losses_on_rto (tcp_connection_t *tc)
{
  return tcp_rack_detect_loss_internal (tc, 0, 1 /* is_rto */);
}

void
tcp_rack_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  f64 next_to = 0.0;

  ASSERT (tcp_rack_enabled (tc));

  /* Only a D-SACK matched to retained retransmission history is credible
   * evidence for adapting the reordering window. */
  if (tcp_rack_update_reo_wnd (tc, ac->ack_flags & TCP_ACK_F_DSACK_MATCHED))
    ac->ack_flags |= TCP_ACK_F_REO_WND_UPDATED;

  /* Without a retransmitted RACK.segment, only SACKed data above SND.UNA
   * can expose an older outstanding transmission. */
  if ((rack->flags & TCP_RACK_F_SEG_IS_RXT) || seq_gt (tc->sack_sb.high_sacked, tc->snd_una))
    {
      u32 lost = tcp_rack_detect_loss (tc, &next_to);

      if (lost)
	{
	  ac->last_lost += lost;
	  ac->lost += lost;
	}
    }
  tcp_rack_arm_reorder_timer (tc, next_to, ac->bytes_acked != 0);
}

static_always_inline f64
tcp_rack_timer_deadline (f64 now, u32 interval)
{
  return now + interval * TCP_TIMER_TICK;
}

static_always_inline u32
tcp_rack_timer_ticks (f64 timeout)
{
  return timeout > 0.0 ? (u32) (timeout / TCP_TIMER_TICK) + 1 : 1;
}

typedef struct
{
  f64 deadline;
  tcp_rack_timer_type_t type;
} tcp_rack_timer_choice_t;

static_always_inline tcp_rack_timer_choice_t
tcp_rack_select_loss_timer (tcp_rack_state_t *rack)
{
  tcp_rack_timer_choice_t choice = {
    .deadline = rack->rto_deadline,
    .type = TCP_RACK_TIMER_RTO,
  };

  ASSERT (choice.deadline != 0.0);
  if (rack->reo_deadline && rack->reo_deadline < choice.deadline)
    {
      choice.deadline = rack->reo_deadline;
      choice.type = TCP_RACK_TIMER_REO;
    }

  return choice;
}

static_always_inline void
tcp_rack_program_loss_timer (tcp_timer_wheel_t *tw, tcp_connection_t *tc, tcp_rack_state_t *rack,
			     tcp_rack_timer_choice_t choice, u32 interval)
{
  ASSERT (interval > 0);
  rack->timer_type = choice.type;
  tcp_timer_update (tw, tc, TCP_TIMER_RETRANSMIT, interval);
}

void
tcp_rack_restore_rto (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u8 was_rto = tcp_rack_timer_type (tc) == TCP_RACK_TIMER_RTO;
  f64 now = tcp_time_now_us (tc->c_thread_index);
  tcp_rack_timer_choice_t choice;
  u32 remaining;

  rack->timer_type = TCP_RACK_TIMER_RTO;
  rack->reo_deadline = 0;

  if (tc->snd_una == tc->snd_nxt)
    {
      rack->rto_deadline = 0;
      tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
      return;
    }

  if (!rack->rto_deadline)
    rack->rto_deadline =
      tcp_rack_timer_deadline (now, clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1));

  if (was_rto && tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
    return;

  choice = tcp_rack_select_loss_timer (rack);
  remaining = tcp_rack_timer_ticks (choice.deadline - now);
  tcp_rack_program_loss_timer (&wrk->timer_wheel, tc, rack, choice, remaining);
}

static_always_inline void
tcp_rack_defer_rto_update (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  rack->timer_type = TCP_RACK_TIMER_RTO;
  rack->reo_deadline = 0;
  /* Forward progress was queued before loss detection. Its postponed dequeue
   * will program the refreshed RTO once for the entire input burst. */
  if (tc->snd_una == tc->snd_nxt)
    rack->rto_deadline = 0;
}

void
tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to, u8 timer_update_deferred)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_timer_choice_t choice;
  tcp_rack_timer_type_t old_type = tcp_rack_timer_type (tc);
  f64 now;
  u32 ticks = 0, rto_ticks, interval;
  u8 rto_refreshed;

  ASSERT (!timer_update_deferred || ((tc->flags & TCP_CONN_DEQ_PENDING) && tc->burst_acked));

  now = tcp_time_now_us (tc->c_thread_index);
  rto_ticks = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);
  rto_refreshed = timer_update_deferred || !rack->rto_deadline;
  if (rto_refreshed)
    rack->rto_deadline = tcp_rack_timer_deadline (now, rto_ticks);

  if (PREDICT_TRUE (timer_update_deferred && next_to <= 0.0))
    {
      tcp_rack_defer_rto_update (tc);
      return;
    }

  if (next_to <= 0.0 || tc->snd_una == tc->snd_nxt)
    rack->reo_deadline = 0;
  else
    {
      /* Round the RACK deadline up to the next timer tick. */
      ticks = tcp_rack_timer_ticks (next_to);
      rack->reo_deadline = now + ticks * TCP_TIMER_TICK;
    }

  if (tc->snd_una == tc->snd_nxt)
    {
      rack->timer_type = TCP_RACK_TIMER_RTO;
      rack->rto_deadline = 0;
      if (!timer_update_deferred)
	tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
      return;
    }

  choice = tcp_rack_select_loss_timer (rack);
  if (choice.type != TCP_RACK_TIMER_REO)
    rack->reo_deadline = 0;

  if (timer_update_deferred)
    {
      if (choice.type == TCP_RACK_TIMER_RTO)
	tcp_rack_defer_rto_update (tc);
      else
	rack->timer_type = choice.type;
      return;
    }

  if (choice.type == TCP_RACK_TIMER_RTO && !rto_refreshed && old_type == TCP_RACK_TIMER_RTO &&
      tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
    return;

  interval = choice.type == TCP_RACK_TIMER_REO ?
	       ticks :
	       (rto_refreshed ? rto_ticks : tcp_rack_timer_ticks (choice.deadline - now));
  tcp_rack_program_loss_timer (&wrk->timer_wheel, tc, rack, choice, interval);
}

void
tcp_rack_timer_rto_set (tcp_connection_t *tc, u32 interval)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  rack->timer_type = TCP_RACK_TIMER_RTO;
  rack->rto_deadline = tcp_rack_timer_deadline (tcp_time_now_us (tc->c_thread_index), interval);
  rack->reo_deadline = 0;
}

void
tcp_rack_timer_reset (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  rack->timer_type = TCP_RACK_TIMER_RTO;
  rack->rto_deadline = 0;
  rack->reo_deadline = 0;
}

u32
tcp_rack_timer_rto_update (tcp_connection_t *tc, u32 interval)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  f64 now = tcp_time_now_us (tc->c_thread_index);
  tcp_rack_timer_choice_t choice;

  rack->rto_deadline = tcp_rack_timer_deadline (now, interval);
  /* No REO deadline means RTO wins without arbitration. */
  if (PREDICT_TRUE (rack->reo_deadline == 0.0))
    {
      rack->timer_type = TCP_RACK_TIMER_RTO;
      return interval;
    }

  choice = tcp_rack_select_loss_timer (rack);
  if (choice.type != TCP_RACK_TIMER_REO)
    rack->reo_deadline = 0;
  rack->timer_type = choice.type;

  return choice.type == TCP_RACK_TIMER_RTO ? interval :
					     tcp_rack_timer_ticks (choice.deadline - now);
}

void
tcp_rack_reorder_timeout (tcp_connection_t *tc)
{
  f64 next_to = 0.0;
  u32 lost;

  ASSERT (tcp_rack_enabled (tc));
  ASSERT (tcp_rack_timer_is_reordering (tc));
  if (tc->state < TCP_STATE_ESTABLISHED || tc->snd_una == tc->snd_nxt)
    {
      tcp_rack_restore_rto (tc);
      return;
    }

  lost = tcp_rack_detect_loss (tc, &next_to);
  if (lost)
    {
      if (tcp_in_cong_recovery (tc))
	tcp_program_retransmit (tc);
      else
	tcp_loss_enter_recovery (tc);
    }
  tcp_rack_arm_reorder_timer (tc, next_to, 0 /* timer_update_deferred */);
}
