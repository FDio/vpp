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

/* reo_wnd = min(srtt/4, rtt of latest ack). Zero until reordering is observed,
 * so before any reordering RACK behaves like immediate (dupthresh-free)
 * detection of holes below the most-recent ack. RFC 8985 sec 6.2 (simplified:
 * we do not implement the DSACK-driven reo_wnd growth ceiling). */
always_inline f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  f64 srtt_s, reo;

  if (!tc->rack_reo_seen)
    return 0.0;

  srtt_s = (f64) tc->srtt * TCP_TICK;
  reo = srtt_s / 4.0;
  if (tc->rack_rtt > 0.0 && tc->rack_rtt < reo)
    reo = tc->rack_rtt;
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

  /* Only segments sent at or before the most-recent acked segment are
   * candidates (something later was delivered). */
  if (tcp_rack_sent_after (tx_time, max_seq, ctx->tc->rack_xmit_ts, ctx->tc->rack_end_seq))
    return;

  elapsed = ctx->now - tx_time;
  if (elapsed > ctx->reo_wnd)
    {
      /* Lost: record the span to mark in the scoreboard. */
      if (ctx->lost_seq_lo == ~0 || seq_lt (min_seq, ctx->lost_seq_lo))
	ctx->lost_seq_lo = min_seq;
      if (seq_gt (max_seq, ctx->lost_seq_hi))
	ctx->lost_seq_hi = max_seq;
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

  /* Mark the lost span in the SACK scoreboard so the normal retransmit path
   * re-sends it. scoreboard_update_bytes recounts lost_bytes from is_lost on
   * the next ack, so marking holes here is sufficient and idempotent. */
  if (ctx.lost_bytes)
    scoreboard_rxt_mark_lost (&tc->sack_sb, ctx.lost_seq_lo, ctx.lost_seq_hi);

  if (next_to)
    *next_to = ctx.next_to;

  return ctx.lost_bytes;
}
