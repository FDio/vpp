/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_inlines.h>

#define TCP_RACK_MIN_RTT_WINDOW 10.0

static_always_inline u32
tcp_rack_sample_index (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  return bts - bt->samples;
}

static_always_inline void
tcp_rack_tx_sample_init (tcp_rack_state_t *rack, tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  tcp_rack_tx_link_t *link;
  u32 index = tcp_rack_sample_index (bt, bts);

  vec_validate (rack->tx_order, index);
  link = &rack->tx_order[index];
  link->next = link->prev = TCP_BTS_INVALID_INDEX;
}

static_always_inline u8
tcp_rack_tx_sample_is_linked (tcp_rack_state_t *rack, u32 index)
{
  tcp_rack_tx_link_t *link;

  ASSERT (index < vec_len (rack->tx_order));
  link = &rack->tx_order[index];
  return rack->tx_order_head == index || link->prev != TCP_BTS_INVALID_INDEX ||
	 link->next != TCP_BTS_INVALID_INDEX;
}

void
tcp_rack_tx_sample_insert (tcp_rack_state_t *rack, tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  tcp_rack_tx_link_t *link, *prev_link;
  tcp_bt_sample_t *prev;
  u32 index, prev_index;

  index = tcp_rack_sample_index (bt, bts);
  if (index >= vec_len (rack->tx_order))
    tcp_rack_tx_sample_init (rack, bt, bts);
  link = &rack->tx_order[index];
  ASSERT (!tcp_rack_tx_sample_is_linked (rack, index));

  prev_index = rack->tx_order_tail;
  while (prev_index != TCP_BTS_INVALID_INDEX)
    {
      prev = pool_elt_at_index (bt->samples, prev_index);
      if (!tcp_rack_sent_after (prev->tx_time, prev->max_seq, bts->tx_time, bts->max_seq))
	break;
      prev_index = rack->tx_order[prev_index].prev;
    }

  if (prev_index == TCP_BTS_INVALID_INDEX)
    {
      link->next = rack->tx_order_head;
      if (link->next != TCP_BTS_INVALID_INDEX)
	rack->tx_order[link->next].prev = index;
      else
	rack->tx_order_tail = index;
      rack->tx_order_head = index;
      return;
    }

  prev_link = &rack->tx_order[prev_index];
  link->prev = prev_index;
  link->next = prev_link->next;
  if (link->next != TCP_BTS_INVALID_INDEX)
    rack->tx_order[link->next].prev = index;
  else
    rack->tx_order_tail = index;
  prev_link->next = index;
}

u8
tcp_rack_tx_sample_remove (tcp_rack_state_t *rack, tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  tcp_rack_tx_link_t *link;
  u32 index = tcp_rack_sample_index (bt, bts);

  ASSERT (index < vec_len (rack->tx_order));
  if (!tcp_rack_tx_sample_is_linked (rack, index))
    return 0;

  link = &rack->tx_order[index];
  if (link->prev != TCP_BTS_INVALID_INDEX)
    rack->tx_order[link->prev].next = link->next;
  else
    rack->tx_order_head = link->next;
  if (link->next != TCP_BTS_INVALID_INDEX)
    rack->tx_order[link->next].prev = link->prev;
  else
    rack->tx_order_tail = link->prev;
  link->next = link->prev = TCP_BTS_INVALID_INDEX;
  return 1;
}

void
tcp_rack_tx_sample_reinsert (tcp_rack_state_t *rack, tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  u32 index = tcp_rack_sample_index (bt, bts);

  if (!tcp_rack_tx_sample_is_linked (rack, index))
    return;
  tcp_rack_tx_sample_remove (rack, bt, bts);
  tcp_rack_tx_sample_insert (rack, bt, bts);
}

void
tcp_rack_tx_sample_split (tcp_rack_state_t *rack, tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts,
			  tcp_bt_sample_t *split)
{
  u32 index = tcp_rack_sample_index (bt, bts);

  tcp_rack_tx_sample_init (rack, bt, split);
  if (!tcp_rack_tx_sample_is_linked (rack, index))
    return;

  /* Splitting changes bts' end-sequence tie-breaker. Reinsert both pieces
   * because other samples can have the same transmit timestamp. */
  tcp_rack_tx_sample_reinsert (rack, bt, bts);
  tcp_rack_tx_sample_insert (rack, bt, split);
}

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
  rack->tx_order_head = rack->tx_order_tail = TCP_BTS_INVALID_INDEX;
}

void
tcp_rack_cleanup (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  vec_free (rack->tx_order);
  rack->tx_order_head = rack->tx_order_tail = TCP_BTS_INVALID_INDEX;
}

void
tcp_rack_tx_order_build (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u32 index;

  ASSERT (rack->tx_order == 0);
  index = bt->head;
  while (index != TCP_BTS_INVALID_INDEX)
    {
      bts = pool_elt_at_index (bt->samples, index);
      tcp_rack_tx_sample_init (rack, bt, bts);
      if (!(bts->flags & TCP_BTS_RACK_LOST))
	tcp_rack_tx_sample_insert (rack, bt, bts);
      index = bts->next;
    }
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
  *sack_reneged = tcp_bt_handle_sack_reneging (tc);
  tcp_rack_mark_losses_on_rto (tc);
  tcp_rack_sync_rxt_delivery (tc, rack);
}

u8
tcp_rack_retransmit_timer_expired (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;

  ASSERT (tcp_rack_enabled (tc));

  if (tcp_rack_timer_is_reordering (tc))
    {
      rack = tcp_rack_get_state (tc);
      rack->reo_deadline = 0;
      tcp_rack_reorder_timeout (tc);
      return 1;
    }

  rack = tcp_rack_get_state (tc);
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
tcp_rack_sample_acked (tcp_connection_t *tc, tcp_rack_state_t *rack, tcp_bt_sample_t *bts,
		       u32 delivered_end, u32 *fack, f64 now)
{
  f64 rtt = now - bts->tx_time;
  u8 advance;

  /* Original data delivered below the ACK-local FACK indicates reordering. */
  if (!(bts->flags & TCP_BTS_IS_RXT) && seq_lt (delivered_end, *fack))
    rack->flags |= TCP_RACK_F_REORDERED;
  if (seq_gt (delivered_end, *fack))
    *fack = delivered_end;

  if (rtt <= 0.0)
    return 0;

  /* Ignore ambiguous retransmission ACKs per RFC 8985 section 6.2. */
  if (bts->flags & TCP_BTS_IS_RXT)
    {
      if (tcp_opts_tstamp (&tc->rcv_opts))
	{
	  /* Derive the retransmission TSval from its tracked send time. */
	  u32 tx_tsval = (u32) ((u64) (bts->tx_time * TCP_TSTP_HZ)) - tc->timestamp_delta;
	  if (timestamp_lt (tc->rcv_opts.tsecr, tx_tsval))
	    return 0;
	}

      if (rack->min_rtt <= 0.0 || rtt < rack->min_rtt)
	return 0;
    }

  if (rack->min_rtt == 0.0 || now - rack->min_rtt_ts >= TCP_RACK_MIN_RTT_WINDOW)
    {
      rack->min_rtt = rtt;
      rack->min_rtt_ts = now;
    }
  else
    rack->min_rtt = clib_min (rack->min_rtt, rtt);

  advance = rack->rtt == 0.0 ||
	    tcp_rack_sent_after (bts->tx_time, delivered_end, rack->xmit_ts, rack->end_seq);
  rack->rtt = rtt;
  if (advance)
    {
      rack->xmit_ts = bts->tx_time;
      rack->end_seq = delivered_end;
      rack->flags = (rack->flags & ~TCP_RACK_F_REF_IS_RXT) |
		    ((bts->flags & TCP_BTS_IS_RXT) ? TCP_RACK_F_REF_IS_RXT : 0);
    }
  return 1;
}

f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  f64 srtt;

  /* RFC 8985 makes the reordering signal connection-wide and sticky. Once
   * observed, loss detection retains the bounded reo_wnd instead of returning
   * to the DupThresh fast path. */
  if (!(rack->flags & TCP_RACK_F_REORDERED) &&
      (tcp_in_cong_recovery (tc) || tc->sack_sb.sacked_bytes >= TCP_DUPACK_THRESHOLD * tc->snd_mss))
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
  u32 departed = 0;

  ASSERT (!(bts->flags & (TCP_BTS_RACK_LOST | TCP_BTS_IS_SACKED)));
  if (bts->flags & TCP_BTS_IS_RXT)
    {
      departed = bts->max_seq - bts->min_seq;
      ASSERT (departed <= rack->rxt_in_flight);
      rack->rxt_in_flight -= departed;
      if (tcp_in_cong_recovery (tc))
	{
	  ASSERT (tc->rxt_delivered + departed <= tc->snd_rxt_bytes);
	  tc->rxt_delivered += departed;
	}
    }
  if (rack->tx_order)
    tcp_rack_tx_sample_remove (rack, tc->bt, bts);
  bts->flags |= TCP_BTS_IS_LOST | TCP_BTS_RACK_LOST;
  return departed;
}

static_always_inline void
tcp_rack_evaluate_sample_loss (tcp_connection_t *tc, tcp_bt_sample_t *bts, tcp_rack_loss_ctx_t *ctx)
{
  u32 start, end, len, loss_len, newly_lost, departed;
  f64 remaining;
  u8 force_rto, was_lost;

  if ((bts->flags & (TCP_BTS_RACK_LOST | TCP_BTS_IS_SACKED)) ||
      (!(bts->flags & TCP_BTS_IS_RXT) && (bts->flags & TCP_BTS_IS_LOST)))
    return;

  start = seq_gt (bts->min_seq, ctx->range_start) ? bts->min_seq : ctx->range_start;
  end = seq_lt (bts->max_seq, ctx->range_end) ? bts->max_seq : ctx->range_end;
  if (!seq_lt (start, end))
    return;

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

  /* Loss classification is sample-wide. The scan boundaries must therefore
   * be materialized as sample boundaries before accounting. */
  ASSERT (start == bts->min_seq && end == bts->max_seq);
  len = end - start;
  was_lost = !!(bts->flags & TCP_BTS_IS_LOST);
  departed = tcp_rack_mark_sample_lost (tc, bts);
  newly_lost = was_lost ? 0 : len;
  tc->sack_sb.lost_bytes += newly_lost;

  /* tc->lost counts transmission copies, whereas SACK loss accounting
   * describes sequence space. Charge the full retransmission copy even when
   * its range was already marked lost for an earlier copy. */
  loss_len = (bts->flags & TCP_BTS_IS_RXT) ? len : newly_lost;
  if (!loss_len)
    return;

  ctx->lost_bytes += loss_len;
  if (!ctx->has_lost_seq || seq_lt (start, ctx->first_lost_seq))
    {
      ctx->first_lost_seq = start;
      ctx->has_lost_seq = 1;
    }

  if (!(bts->flags & TCP_BTS_IS_RXT))
    return;

  if (tcp_in_cong_recovery (tc))
    tc->prr_delivered += departed;
}

static_always_inline void
tcp_rack_mark_lost_samples (tcp_connection_t *tc, tcp_rack_loss_ctx_t *ctx)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u8 has_tx_order = ctx->rack->tx_order != 0;
  u32 index, next;

  index = has_tx_order ? ctx->rack->tx_order_head : bt->head;
  while (index != TCP_BTS_INVALID_INDEX)
    {
      bts = pool_elt_at_index (bt->samples, index);
      next = has_tx_order ? ctx->rack->tx_order[index].next : bts->next;

      /* Transmit ordering makes every later sample ineligible once the
       * delivered RACK reference is reached. Before the first retransmission,
       * the sequence list has the same ordering and needs no side storage. */
      if (!ctx->is_rto &&
	  !tcp_rack_sent_after (ctx->rack->xmit_ts, ctx->rack->end_seq, bts->tx_time, bts->max_seq))
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
  tcp_rack_loss_ctx_t ctx = {
    .rack = rack,
    .now = tcp_time_now_us (tc->c_thread_index),
    .reo_wnd = tcp_rack_reo_wnd (tc),
    .is_rto = is_rto,
  };
  u32 end, first_end;

  /* BT owns all SACK ranges for RACK connections. sack_sb retains only the
   * common scalar accounting consumed by congestion control. */
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX);
  ASSERT (pool_elts (sb->holes) == 0);

  if (tc->snd_una == tc->snd_nxt)
    goto done;

  if (!is_rto)
    {
      if (rack->rtt <= 0.0)
	goto done;

      /* A delivered retransmission can be newer than original
	 transmissions at higher sequence numbers. In that case sequence-space
	 SACK progress cannot bound the time-based RACK scan. */
      if (!(rack->flags & TCP_RACK_F_REF_IS_RXT) && seq_leq (sb->high_sacked, tc->snd_una))
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
      if (rack->flags & TCP_RACK_F_REF_IS_RXT)
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
  f64 next_to = 0.0;
  u32 lost;

  ASSERT (tcp_rack_enabled (tc));

  /* Only a D-SACK matched to retained retransmission history is credible
   * evidence for adapting the reordering window. */
  if (tcp_rack_update_reo_wnd (tc, ac->ack_flags & TCP_ACK_F_DSACK_MATCHED))
    ac->ack_flags |= TCP_ACK_F_REO_WND_UPDATED;
  lost = tcp_rack_detect_loss (tc, &next_to);
  if (lost)
    {
      ac->last_lost += lost;
      ac->lost += lost;
    }
  tcp_rack_arm_reorder_timer (tc, next_to, ac->bytes_acked != 0);
}

void
tcp_rack_restore_rto (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u8 was_reordering = tcp_rack_timer_is_reordering (tc);
  u64 now = wrk->timer_wheel.current_tick;
  u32 remaining;

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
  rack->reo_deadline = 0;

  if (tc->snd_una == tc->snd_nxt)
    {
      rack->rto_deadline = 0;
      tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT);
      return;
    }

  if (!rack->rto_deadline)
    rack->rto_deadline = now + clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);

  if (!was_reordering && tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
    return;

  remaining =
    rack->rto_deadline > now ? (u32) clib_min (rack->rto_deadline - now, (u64) CLIB_U32_MAX) : 1;
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, remaining);
}

static void
tcp_rack_select_rto (tcp_connection_t *tc, u8 update_deferred)
{
  if (!update_deferred)
    {
      tcp_rack_restore_rto (tc);
      return;
    }

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
  tcp_rack_get_state (tc)->reo_deadline = 0;
  /* Forward progress was queued before loss detection. Its postponed dequeue
   * will program the refreshed RTO once for the entire input burst. */
  ASSERT ((tc->flags & TCP_CONN_DEQ_PENDING) && tc->burst_acked);
  if (tc->snd_una == tc->snd_nxt)
    tcp_rack_get_state (tc)->rto_deadline = 0;
}

void
tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to, u8 rto_update_deferred)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u64 now = wrk->timer_wheel.current_tick, deadline;
  u32 ticks, rto_ticks;

  rto_ticks = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);
  if (rto_update_deferred || !rack->rto_deadline)
    rack->rto_deadline = now + rto_ticks;

  if (next_to <= 0.0 || tc->snd_una == tc->snd_nxt)
    {
      tcp_rack_select_rto (tc, rto_update_deferred);
      return;
    }

  /* Round the RACK deadline up to the next timer tick. */
  ticks = (u32) (next_to / TCP_TIMER_TICK) + 1;
  deadline = now + ticks;

  /* The shared loss timer always runs the earlier of REO and RTO. */
  if (deadline >= rack->rto_deadline)
    {
      tcp_rack_select_rto (tc, rto_update_deferred);
      return;
    }

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_REO);
  rack->reo_deadline = deadline;
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, clib_max (ticks, 1));
}

void
tcp_rack_timer_rto_set (tcp_timer_wheel_t *tw, tcp_connection_t *tc, u32 interval)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
  rack->rto_deadline = tw->current_tick + interval;
  rack->reo_deadline = 0;
}

void
tcp_rack_timer_reset (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
  rack->rto_deadline = 0;
  rack->reo_deadline = 0;
}

u8
tcp_rack_timer_rto_update (tcp_timer_wheel_t *tw, tcp_connection_t *tc, u32 interval)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  rack->rto_deadline = tw->current_tick + interval;
  if (!tcp_rack_timer_is_reordering (tc) || !rack->reo_deadline ||
      rack->rto_deadline <= rack->reo_deadline)
    {
      tcp_rack_timer_set_type (tc, TCP_RACK_TIMER_RTO);
      rack->reo_deadline = 0;
      return 0;
    }

  return 1;
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
  tcp_rack_arm_reorder_timer (tc, next_to, 0 /* rto_update_deferred */);
}
