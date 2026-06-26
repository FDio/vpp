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

/* RACK reordering window (RFC 8985 sec 6.1): once a later-sent segment has been
 * (s)acked, how long an earlier-sent segment may remain outstanding before RACK
 * declares it lost. Absorbs benign reordering and within-flight jitter. Use an
 * rtt/4 floor (not 0) so same-burst out-of-order delivery is not mistaken for
 * loss; cap at SRTT. RFC 8985 uses min_RTT here; we approximate it with mrtt_us
 * (a smoothed estimate, not a true minimum -- we keep no windowed min RTT). */
always_inline f64
tcp_rack_reo_wnd (tcp_connection_t *tc)
{
  f64 srtt_s, rtt_s;

  srtt_s = (f64) tc->srtt * TCP_TICK;
  rtt_s = tc->mrtt_us > 0.0 ? tc->mrtt_us : srtt_s;

  return clib_min (rtt_s / 4.0, srtt_s);
}

u32
tcp_rack_detect_loss (tcp_connection_t *tc, f64 *next_to)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_scoreboard_hole_t *hole;
  u32 lost_bytes = 0, lost_seq_lo = ~0;
  f64 now, reo_wnd, nto = 0.0;

  /* Nothing (s)acked yet, or the SACK frontier has not advanced past snd_una
   * (no sacks) -- no segment can be below it, so there is nothing to detect. */
  if (tc->rack_xmit_ts == 0.0 || seq_leq (sb->high_sacked, tc->snd_una))
    {
      *next_to = 0.0;
      return 0;
    }

  now = tcp_time_now_us (tc->c_thread_index);
  reo_wnd = tcp_rack_reo_wnd (tc);

  /* RACK loss candidates are exactly the un-sacked gaps below the SACK frontier,
   * i.e. the scoreboard holes below high_sacked. Walk them directly -- rather
   * than every outstanding byte-tracker sample, which would re-skip the sacked
   * ones each ack -- and fetch each hole's transmit time from the byte tracker.
   *
   * Test (and mark) each hole INDEPENDENTLY per RFC 8985: a hole is lost only
   * if its own send time is before the most-recent delivery and it has been
   * outstanding past reo_wnd. We do not mark the whole [lowest, highest] lost
   * span (that would be RFC 6675 sequence-domain marking, which over-marks the
   * un-aged holes in between -- RACK is purely time-domain and per-segment). A
   * hole's start is its oldest unacked byte, so its send time governs the
   * hole. */
  for (hole = scoreboard_first_hole (sb); hole; hole = scoreboard_next_hole (sb, hole))
    {
      f64 tx_time, elapsed;
      u32 end_seq;

      if (seq_geq (hole->start, sb->high_sacked))
	break;

      if (!tcp_bt_seq_tx_time (tc, hole->start, &tx_time, &end_seq))
	continue; /* no covering sample (should not happen below cum-ack) */

      /* Only a candidate if a later-sent segment was delivered. Guards against
       * rack_xmit_ts having advanced off a retransmit. */
      if (tcp_rack_sent_after (tx_time, end_seq, tc->rack_xmit_ts, tc->rack_end_seq))
	continue;

      elapsed = now - tx_time;
      if (elapsed > reo_wnd)
	{
	  /* Lost. Mark the hole and account the newly lost bytes directly, so
	   * the cc event on this same ack (or a timer fire with no ack) sees
	   * them; scoreboard_update_bytes recomputes from is_lost next ack and
	   * reconverges. Only fresh not-lost -> lost flips are counted. */
	  if (!hole->is_lost)
	    {
	      hole->is_lost = 1;
	      sb->lost_bytes += scoreboard_hole_bytes (hole);
	      lost_bytes += scoreboard_hole_bytes (hole);
	      if (lost_seq_lo == ~0)
		lost_seq_lo = hole->start;
	    }
	}
      else
	{
	  /* Not yet expired: note when it would cross the threshold so the
	   * caller can arm the reorder timeout. */
	  f64 to = reo_wnd - elapsed;
	  if (nto == 0.0 || to < nto)
	    nto = to;
	}
    }

  /* A newly lost hole below high_rxt means a retransmit was itself lost; rewind
   * high_rxt so the selector re-sends it instead of waiting for the RTO. */
  if (lost_seq_lo != ~0 && seq_lt (lost_seq_lo, sb->high_rxt))
    scoreboard_rxt_rewind (sb, lost_seq_lo);

  *next_to = nto;

  return lost_bytes;
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
