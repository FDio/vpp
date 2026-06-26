/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_bt.h>
#include <vnet/tcp/tcp_inlines.h>

/*
 * RACK loss detection, RFC 8985.
 *
 * The byte tracker holds per-segment transmit timestamps and IS_RXT/IS_SACKED
 * flags. On every ack we advance rack_xmit_ts to the transmit time of the most
 * recently sent segment among those newly (s)acked (tcp_rack_sample_acked,
 * called from the byte-tracker walk). A still-outstanding segment is then
 * declared lost if some such later-sent segment has been delivered (i.e. the
 * outstanding segment was sent no later than rack_xmit_ts) and it has been
 * outstanding more than reo_wnd (tcp_rack_detect_loss).
 */

/* A newly (s)acked segment is "more recent" than the current rack record if it
 * was transmitted later, or at the same time but higher in sequence space. */
always_inline int
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 cur_ts, u32 cur_end)
{
  return ts != cur_ts ? ts > cur_ts : seq_gt (end_seq, cur_end);
}

void
tcp_rack_sample_acked (tcp_connection_t *tc, u32 max_seq, f64 tx_time, u32 flags)
{
  /* RFC 8985's retransmission-ambiguity guard (skip a retransmitted segment
   * whose RTT is below min_rtt, as its ack was likely elicited by the original
   * transmission) is omitted: we derive no RTT estimate here, so a
   * mis-attributed retransmit can only declare loss marginally early, bounded
   * by reo_wnd. */
  if (tcp_rack_sent_after (tx_time, max_seq, tc->rack_xmit_ts, tc->rack_end_seq))
    {
      tc->rack_xmit_ts = tx_time;
      tc->rack_end_seq = max_seq;
    }
}

/* RACK reordering window (RFC 8985 sec 6.1): once a later-sent segment has been
 * (s)acked, how long an earlier-sent segment may remain outstanding before RACK
 * declares it lost. Absorbs benign reordering and within-flight jitter. Use an
 * rtt/4 floor (not 0) so same-burst out-of-order delivery is not mistaken for
 * loss; cap at SRTT. RFC 8985 uses min_RTT here; we approximate it with mrtt_us
 * (a smoothed estimate, not a true minimum -- VPP keeps no windowed min RTT). */
always_inline f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  f64 srtt_s, rtt_s, reo;

  srtt_s = (f64) tc->srtt * TCP_TICK;
  rtt_s = tc->mrtt_us > 0.0 ? tc->mrtt_us : srtt_s;

  reo = rtt_s / 4.0;
  if (reo > srtt_s)
    reo = srtt_s;
  return reo;
}

typedef struct
{
  tcp_connection_t *tc;
  f64 now;
  f64 reo_wnd;
  f64 next_to;	   /* earliest future reo-wnd crossing (relative s), 0 if none */
  u32 lost_seq_lo; /* lowest seq newly marked lost (~0 if none) */
  u32 lost_seq_hi; /* highest seq newly marked lost */
  u32 lost_bytes;
} tcp_rack_loss_ctx_t;

static void
tcp_rack_loss_visit (tcp_connection_t *tc, u32 min_seq, u32 max_seq, f64 tx_time, u32 flags,
		     void *opaque)
{
  tcp_rack_loss_ctx_t *ctx = opaque;
  f64 elapsed;

  /* Already delivered (sacked) -- not outstanding. */
  if (flags & TCP_BTS_IS_SACKED)
    return;

  /* Loss requires evidence that data *higher in sequence* was delivered: only
   * consider segments below the highest sacked byte (the SACK frontier). A
   * segment above high_sacked has nothing delivered beyond it, so it is just
   * in-flight, not lost. Without this, when the SACK frontier stalls (receiver
   * blocked behind a low hole) rack_xmit_ts keeps advancing off retransmits and
   * RACK would mark the entire un-sacked tail lost -- mass spurious
   * retransmission. RFC 8985 keys loss off a *higher-sequence* (s)ack. */
  if (seq_geq (max_seq, ctx->tc->sack_sb.high_sacked))
    return;

  /* Only segments sent at or before the most-recent acked segment are
   * candidates (something later was delivered). */
  if (tcp_rack_sent_after (tx_time, max_seq, ctx->tc->rack_xmit_ts, ctx->tc->rack_end_seq))
    return;

  elapsed = ctx->now - tx_time;
  if (elapsed > ctx->reo_wnd)
    {
      /* Lost: extend the [lo, hi) span to mark in the scoreboard. Both bounds
       * use the "no loss recorded yet" sentinel (lost_seq_lo == ~0) to seed the
       * first value: lost_seq_hi cannot use a plain 0 initializer and seq_gt,
       * because sequence numbers are compared with wraparound (seq_gt(max,0) is
       * false whenever max is in the upper half of the sequence space), which
       * would leave hi stuck at 0. */
      if (ctx->lost_seq_lo == ~0)
	{
	  ctx->lost_seq_lo = min_seq;
	  ctx->lost_seq_hi = max_seq;
	}
      else
	{
	  if (seq_lt (min_seq, ctx->lost_seq_lo))
	    ctx->lost_seq_lo = min_seq;
	  if (seq_gt (max_seq, ctx->lost_seq_hi))
	    ctx->lost_seq_hi = max_seq;
	}
      ctx->lost_bytes += max_seq - min_seq;
    }
  else
    {
      /* Not yet expired: note when it would cross the threshold so the caller
       * can arm the reorder timeout. */
      f64 to = ctx->reo_wnd - elapsed;
      if (ctx->next_to == 0.0 || to < ctx->next_to)
	ctx->next_to = to;
    }
}

u32
tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to)
{
  tcp_rack_loss_ctx_t ctx = {
    .tc = tc,
    .now = tcp_time_now_us (tc->c_thread_index),
    .reo_wnd = tcp_rack_reo_wnd (tc),
    .next_to = 0.0,
    .lost_seq_lo = ~0,
    .lost_seq_hi = 0,
    .lost_bytes = 0,
  };

  if (tc->rack_xmit_ts == 0.0)
    {
      if (next_to)
	*next_to = 0.0;
      return 0;
    }

  tcp_bt_walk_outstanding (tc, tcp_rack_loss_visit, &ctx);

  /* Mark the span lost in the scoreboard for the retransmit path; this also
   * adds the newly lost bytes to sb->lost_bytes so the cc event handled on this
   * same ack (or a timer fire with no ack at all) sees them. */
  if (ctx.lost_bytes && ctx.lost_seq_lo != ~0 && seq_lt (ctx.lost_seq_lo, ctx.lost_seq_hi))
    {
      if (!scoreboard_mark_lost_span (&tc->sack_sb, ctx.lost_seq_lo, ctx.lost_seq_hi))
	ctx.lost_bytes = 0; /* nothing actually outstanding to re-send */
      /* A lost span below high_rxt means a retransmit was itself lost; rewind
       * high_rxt so the selector re-sends it instead of waiting for the RTO. */
      else if (seq_lt (ctx.lost_seq_lo, tc->sack_sb.high_rxt))
	scoreboard_rxt_rewind (&tc->sack_sb, ctx.lost_seq_lo);
    }
  else
    ctx.lost_bytes = 0;

  if (next_to)
    *next_to = ctx.next_to;

  return ctx.lost_bytes;
}

/**
 * Arm the retransmit timer for a RACK reorder timeout.
 *
 * When RACK has segments suspected lost but not yet past the reordering
 * window, fire the (shared) retransmit timer at the earliest threshold
 * crossing rather than waiting for the RTO -- but never later than the RTO.
 * @ref tcp_timer_retransmit_handler distinguishes the two via the
 * TCP_CONN_RACK_TIMEOUT flag. Called from the ack path after RACK loss
 * detection. */
void
tcp_rack_arm_reorder_timer (tcp_connection_t *tc, f64 next_to)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  u32 reo_ticks, rto_ticks;

  if (next_to <= 0.0 || tc->snd_una == tc->snd_nxt)
    return;

  /* next_to is seconds until the earliest suspect crosses reo_wnd. */
  reo_ticks = clib_max ((u32) (next_to * THZ * TCP_TO_TIMER_TICK), 1);
  rto_ticks = clib_max ((u32) tc->rto * TCP_TO_TIMER_TICK, 1);
  if (reo_ticks >= rto_ticks)
    return; /* RTO would fire first; leave the normal RTO arming in place */

  tcp_rack_timeout_armed_on (tc);
  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, reo_ticks);
}
