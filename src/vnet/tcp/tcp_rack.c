/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_bt.h>
#include <vnet/tcp/tcp_inlines.h>

#define TCP_RACK_MIN_RTT_WINDOW 10.0

void
tcp_rack_recovery_start (tcp_connection_t *tc)
{
  if (!tcp_in_cong_recovery (tc))
    {
      tcp_cc_init_congestion (tc);
      scoreboard_init_rxt (&tc->sack_sb, tc->snd_una);
      tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */);
      tc->rcv_dupacks = 0;
    }
  tcp_program_retransmit (tc);
}

void
tcp_rack_sample_acked (tcp_connection_t *tc, tcp_bt_sample_t *bts, u32 delivered_end, u32 *fack)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  tcp_byte_tracker_t *bt = tc->bt;
  f64 now = tcp_time_now_us (tc->c_thread_index);
  f64 rtt = now - bts->tx_time;

  /* Original data delivered below the ACK-local FACK indicates reordering. */
  if (!(bts->flags & TCP_BTS_IS_RXT) && seq_lt (delivered_end, *fack))
    tcp_rack_reordered_on (tc);
  if (seq_gt (delivered_end, *fack))
    *fack = delivered_end;

  if (rtt <= 0.0)
    return;

  /* Ignore ambiguous retransmission ACKs per RFC 8985 section 6.2. */
  if (bts->flags & TCP_BTS_IS_RXT)
    {
      if (tcp_opts_tstamp (&tc->rcv_opts) && tc->rcv_opts.tsecr)
	{
	  /* Derive the retransmission TSval from its tracked send time. */
	  u32 tx_tsval = (u32) ((u64) (bts->tx_time * TCP_TSTP_HZ)) - tc->timestamp_delta;
	  if (timestamp_lt (tc->rcv_opts.tsecr, tx_tsval))
	    return;
	}
      if (bt->min_rtt > 0.0 && rtt < bt->min_rtt)
	return;
    }

  if (bt->min_rtt == 0.0 || now - bt->min_rtt_ts >= TCP_RACK_MIN_RTT_WINDOW)
    {
      bt->min_rtt = rtt;
      bt->min_rtt_ts = now;
    }
  else
    bt->min_rtt = clib_min (bt->min_rtt, rtt);

  if (tcp_rack_sent_after (bts->tx_time, delivered_end, rack->xmit_ts, rack->end_seq))
    {
      rack->xmit_ts = bts->tx_time;
      rack->end_seq = delivered_end;
      rack->rtt = rtt;
    }
}

f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  f64 srtt;

  /* Disable reo_wnd after sufficient SACK evidence until reordering is seen. */
  if (!tcp_rack_reordered (tc) &&
      (tcp_in_cong_recovery (tc) || tc->sack_sb.sacked_bytes >= TCP_DUPACK_THRESHOLD * tc->snd_mss))
    return 0.0;

  if (tc->bt->min_rtt <= 0.0)
    return 0.0;

  srtt = (f64) tc->srtt * TCP_TICK;
  return clib_min (tc->bt->min_rtt / 4.0, srtt);
}

typedef struct
{
  f64 now;
  f64 reo_wnd;
  f64 next_to;
  u32 range_start;
  u32 range_end;
  u32 lost_bytes;
  u32 lost_segs;
  u32 lost_rxt_segs;
  u32 first_lost_seq;
  u8 is_rto;
  u8 has_lost_seq;
} tcp_rack_loss_ctx_t;

static void
tcp_rack_mark_sample_lost (tcp_connection_t *tc, tcp_bt_sample_t *bts, void *opaque)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  tcp_rack_loss_ctx_t *ctx = opaque;
  u32 start, end, len, loss_len, newly_lost, departed;
  f64 remaining;
  u8 force_first;

  if ((bts->flags & TCP_BTS_IS_LOST) || (!ctx->is_rto && (bts->flags & TCP_BTS_IS_SACKED)))
    return;

  start = seq_gt (bts->min_seq, ctx->range_start) ? bts->min_seq : ctx->range_start;
  end = seq_lt (bts->max_seq, ctx->range_end) ? bts->max_seq : ctx->range_end;
  if (!seq_lt (start, end))
    return;

  force_first = ctx->is_rto && seq_leq (start, tc->snd_una) && seq_gt (end, tc->snd_una);

  if (!ctx->is_rto)
    {
      /* RACK requires a strictly newer delivered transmission. */
      if (!tcp_rack_sent_after (rack->xmit_ts, rack->end_seq, bts->tx_time, bts->max_seq))
	return;
    }
  else if (!force_first && rack->rtt <= 0.0)
    return;

  remaining = bts->tx_time + rack->rtt + ctx->reo_wnd - ctx->now;
  if (!force_first && remaining > 0.0)
    {
      if (!ctx->is_rto && (ctx->next_to == 0.0 || remaining < ctx->next_to))
	ctx->next_to = remaining;
      return;
    }

  len = end - start;
  bts->flags |= TCP_BTS_IS_LOST;
  newly_lost = scoreboard_mark_range_lost (&tc->sack_sb, start, end);

  /* Count lost retransmissions independently of scoreboard range state. */
  loss_len = (bts->flags & TCP_BTS_IS_RXT) ? len : newly_lost;
  if (!loss_len)
    return;

  ctx->lost_bytes += loss_len;
  ctx->lost_segs += clib_max ((loss_len + tc->snd_mss - 1) / tc->snd_mss, 1);
  if (!ctx->has_lost_seq || seq_lt (start, ctx->first_lost_seq))
    {
      ctx->first_lost_seq = start;
      ctx->has_lost_seq = 1;
    }

  if (!(bts->flags & TCP_BTS_IS_RXT))
    return;

  ctx->lost_rxt_segs += clib_max ((loss_len + tc->snd_mss - 1) / tc->snd_mss, 1);

  /* Account lost retransmissions as departed data for PRR. */
  if (tcp_in_cong_recovery (tc))
    {
      departed =
	clib_min (loss_len, tc->snd_rxt_bytes - clib_min (tc->rxt_delivered, tc->snd_rxt_bytes));
      tc->rxt_delivered += departed;
      tc->prr_delivered += departed;
    }
}

static u32
tcp_rack_detect_loss_internal (tcp_connection_t *tc, f64 *next_to, u8 is_rto)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_scoreboard_hole_t *hole;
  tcp_rack_loss_ctx_t ctx = {
    .now = tcp_time_now_us (tc->c_thread_index),
    .reo_wnd = tcp_rack_reo_wnd (tc),
    .is_rto = is_rto,
  };
  sack_block_t *ranges = 0, *range;
  u32 end, first_end;

  if (!tc->bt || tc->snd_una == tc->snd_nxt)
    goto done;

  if (!is_rto && (rack->rtt <= 0.0 || seq_leq (sb->high_sacked, tc->snd_una)))
    goto done;

  if (is_rto)
    {
      scoreboard_init_holes (sb, tc->snd_una, tc->snd_nxt);
      first_end = tc->snd_una + tc->snd_mss;
      if (seq_gt (first_end, tc->snd_nxt))
	first_end = tc->snd_nxt;
      tcp_bt_split_at (tc, first_end);
    }

  /* Snapshot ranges before loss marking mutates the hole pool. */
  for (hole = scoreboard_first_hole (sb); hole; hole = scoreboard_next_hole (sb, hole))
    {
      end = hole->end;
      if (!is_rto)
	{
	  if (seq_geq (hole->start, sb->high_sacked))
	    break;
	  if (seq_gt (end, sb->high_sacked))
	    end = sb->high_sacked;
	}
      if (seq_lt (hole->start, end))
	vec_add1 (ranges, ((sack_block_t) { hole->start, end }));
    }

  /* Align byte-tracker samples with scoreboard ranges before marking loss. */
  vec_foreach (range, ranges)
    {
      tcp_bt_split_at (tc, range->start);
      tcp_bt_split_at (tc, range->end);
    }

  vec_foreach (range, ranges)
    {
      ctx.range_start = range->start;
      ctx.range_end = range->end;
      tcp_bt_walk_range (tc, range->start, range->end, tcp_rack_mark_sample_lost, &ctx);
    }

  tc->lost += ctx.lost_bytes;
  rack->loss_segs += ctx.lost_segs;
  rack->rxt_loss_segs += ctx.lost_rxt_segs;
  if (ctx.has_lost_seq)
    scoreboard_rxt_rewind (sb, ctx.first_lost_seq);

done:
  vec_free (ranges);
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
tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  u32 ticks, rto_ticks;

  if (!tcp_rack_is_enabled (tc) || next_to <= 0.0 || tc->snd_una == tc->snd_nxt)
    {
      tcp_rack_timer_reset (tc);
      return;
    }

  /* Round the RACK deadline up to the next timer tick. */
  ticks = (u32) (next_to / TCP_TIMER_TICK) + 1;
  rto_ticks = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);
  if (ticks >= rto_ticks)
    {
      tcp_rack_timer_reset (tc);
      return;
    }

  tcp_rack_timeout_armed_on (tc);
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, clib_max (ticks, 1));
}

void
tcp_rack_timer_reset (tcp_connection_t *tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  if (!tcp_rack_timeout_armed (tc))
    return;

  /* Replace the RACK event with an RTO for outstanding data. */
  tcp_retransmit_timer_reset (&wrk->timer_wheel, tc);
  if (tc->snd_una != tc->snd_nxt)
    tcp_retransmit_timer_set (&wrk->timer_wheel, tc);
}

void
tcp_rack_reorder_timeout (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack;
  f64 next_to = 0.0;
  u8 was_in_recovery;

  ASSERT (tcp_rack_timeout_armed (tc));
  if (!tcp_rack_is_enabled (tc) || tc->state < TCP_STATE_ESTABLISHED || tc->snd_una == tc->snd_nxt)
    {
      tcp_rack_timer_reset (tc);
      return;
    }

  rack = tcp_rack_get_state (tc);
  rack->timeouts++;
  if (tcp_rack_detect_loss (tc, &next_to))
    {
      was_in_recovery = tcp_in_cong_recovery (tc);
      tcp_rack_recovery_start (tc);
      if (!was_in_recovery)
	tcp_rack_detect_loss (tc, &next_to);
    }
  tcp_rack_arm_reorder_timer (tc, next_to);
}
