/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_bt.h>
#include <vnet/tcp/tcp_inlines.h>

/*
 * RACK-TLP loss detection, RFC 8985.
 *
 * The byte tracker holds per-segment transmit timestamps and IS_RXT/IS_SACKED
 * flags. On every ack we advance rack_xmit_ts to the most recently transmitted
 * segment among those newly (s)acked (tcp_rack_sample_acked, called from the
 * byte-tracker walk), then mark as lost any still-outstanding segment that was
 * sent more than reo_wnd before rack_xmit_ts (tcp_rack_detect_loss).
 */

/* A newly (s)acked segment is "more recent" than the current rack record if it
 * was transmitted later, or at the same time but higher in sequence space. */
always_inline int
tcp_rack_sent_after (f64 ts, u32 end_seq, f64 cur_ts, u32 cur_end)
{
  if (ts != cur_ts)
    return ts > cur_ts;
  return seq_gt (end_seq, cur_end);
}

void
tcp_rack_sample_acked (tcp_connection_t *tc, u32 max_seq, f64 tx_time, u32 flags)
{
  /* RFC 8985 step 1: ignore a sacked segment whose RTT sample is implausibly
   * small relative to min/srtt -- skipped here for simplicity; VPP's rate
   * sampler already filters re-sacked segments. */
  if (tcp_rack_sent_after (tx_time, max_seq, tc->rack_xmit_ts, tc->rack_end_seq))
    {
      tc->rack_xmit_ts = tx_time;
      tc->rack_end_seq = max_seq;
      tc->rack_rtt = tcp_time_now_us (tc->c_thread_index) - tx_time;
    }
}

/* RACK reordering window (RFC 8985 sec 6.1, RACK_update_reo_wnd).
 *
 * A still-outstanding segment is declared lost once a later-sent segment has
 * been (s)acked and this much time has elapsed since it was (re)transmitted.
 * The window absorbs benign reordering / within-flight delivery jitter so RACK
 * does not declare in-flight (not actually lost) segments lost.
 *
 * Even before reordering is observed we use a min_RTT/4 floor (not 0): with a
 * zero window any segment sent microseconds before a delivered one -- e.g. a
 * lower-seq segment of the same burst delivered slightly out of order -- is
 * flagged lost, which on a path with any jitter or a standing queue causes mass
 * spurious retransmission. The window is capped at SRTT. */
always_inline f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  f64 srtt_s, min_rtt_s, reo;

  srtt_s = (f64) tc->srtt * TCP_TICK;
  min_rtt_s = tc->mrtt_us > 0.0 ? tc->mrtt_us : srtt_s;

  /* min_RTT/4 floor, applied whether or not reordering has been seen. */
  reo = min_rtt_s / 4.0;
  if (reo > srtt_s)
    reo = srtt_s;
  return reo;
}

void
tcp_rack_update (tcp_connection_t *tc)
{
  /* The scoreboard's reordering estimate doubles as "reordering seen": once it
   * climbs past the dupack threshold, the peer is reordering and we widen the
   * reorder window so RACK stops treating every gap as immediate loss. */
  if (tc->sack_sb.reorder > TCP_DUPACK_THRESHOLD)
    tc->rack_reo_seen = 1;
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

  if (!tc->bt || tc->rack_xmit_ts == 0.0)
    {
      if (next_to)
	*next_to = 0.0;
      return 0;
    }

  tcp_bt_walk_outstanding (tc, tcp_rack_loss_visit, &ctx);

  /* Mark the lost span lost in the SACK scoreboard so the normal retransmit
   * path re-sends it. We only set is_lost on existing holes that overlap the
   * span -- we never insert a hole or touch sb->lost_bytes here.
   * scoreboard_update_bytes (run from tcp_rcv_sacks on this and every ack) is
   * the single owner of lost_bytes/sacked_bytes and recounts them from the
   * is_lost flags, which keeps sacked+lost consistent with the outstanding
   * window (a second recount now would corrupt last_sacked_bytes, so we let
   * the next ack pick it up; until then lost_bytes only under-counts, so the
   * flight-size estimate stays non-negative). */
  if (ctx.lost_bytes && ctx.lost_seq_lo != ~0 &&
      seq_lt (ctx.lost_seq_lo, ctx.lost_seq_hi))
    {
      if (!scoreboard_mark_lost_span (&tc->sack_sb, ctx.lost_seq_lo,
				      ctx.lost_seq_hi))
	ctx.lost_bytes = 0; /* nothing actually outstanding to re-send */
      /* If the lost span dips below high_rxt, a previously retransmitted
       * segment was itself lost. The retransmit selector skips holes already
       * below high_rxt, so rewind it -- otherwise the lost retransmit is not
       * re-sent until the RTO (the whole point of RACK is to avoid that). */
      else if (seq_lt (ctx.lost_seq_lo, tc->sack_sb.high_rxt))
	scoreboard_rxt_rewind (&tc->sack_sb, ctx.lost_seq_lo);
    }
  else
    ctx.lost_bytes = 0;

  if (next_to)
    *next_to = ctx.next_to;

  return ctx.lost_bytes;
}
