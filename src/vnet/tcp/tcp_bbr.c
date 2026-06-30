/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_bbr.h>
#include <vnet/tcp/tcp_inlines.h>

/*
 * BBRv3 (draft-cardwell-iccrg-bbr-congestion-control-02, Google's BBRv3). See
 * tcp_bbr.h for the overview.
 *
 * We work in bytes for cwnd and f64 seconds for time/rate, so the model is
 * carried in those units (the draft is in packets and fixed-point); the
 * algorithm is unchanged. Gains are plain f64 multipliers (a gain of 1.0 is
 * unity).
 *
 * The model keeps v1's STARTUP/DRAIN/PROBE_RTT, the bandwidth max-filter, the
 * min-RTT min-filter, full-pipe detection, and ack-aggregation. On top of that
 * v3 adds:
 *   - short/long-term inflight bounds (inflight_hi/inflight_lo) and a
 *     short-term bandwidth bound (bw_lo) that gate cwnd and pacing;
 *   - loss as an explicit congestion signal: a round whose loss rate exceeds
 *     BBR_LOSS_THRESH cuts the bounds, so BBR coexists with loss-based flows
 *     instead of either starving or overrunning a lossy path;
 *   - a restructured PROBE_BW cycle with four sub-states (DOWN, CRUISE, REFILL,
 *     UP) driven by loss and inflight rather than a fixed round-robin.
 *
 * ECN is the third v3 signal but is not implemented here: VPP TCP does not
 * negotiate or process ECN, so BBR runs in loss-only mode (bd->ecn_eligible is
 * always 0, exactly as in a no-ECN deployment). The ECN response can be wired
 * in when TCP gains ECN support.
 */

#define BBR_HIGH_GAIN	    2.885 /* 2/ln2: STARTUP ~doubles per round */
#define BBR_CWND_GAIN	    2.0	  /* PROBE_BW cwnd headroom */
#define BBR_CWND_MIN	    4	  /* cwnd floor, in MSS */
#define BBR_FULL_BW_THRESH  1.25  /* bw must grow this much to be "still growing" */
#define BBR_FULL_BW_CNT	    3	  /* rounds of no growth => pipe full */
#define BBR_BW_WIN_RTTS	    10	  /* bandwidth max-filter window, round trips */
#define BBR_MIN_RTT_WIN	    10.0  /* min-rtt min-filter window, seconds */
#define BBR_PROBE_RTT_S	    0.2	  /* PROBE_RTT hold, seconds (200ms) */
#define BBR_PACING_MARGIN   0.99  /* pace ~1% under bw to bound queue growth */
#define BBR_EXTRA_ACKED_WIN 10	  /* ack-aggregation max-filter window, round trips */
#define BBR_ACK_EPOCH_MAX   0.1	  /* cap an ack-aggregation epoch at 100ms */

/* v3 loss/bound response */
#define BBR_LOSS_THRESH	       0.02  /* per-round loss rate that marks congestion */
#define BBR_FULL_LOSS_CNT      3     /* loss-rounds above thresh to exit STARTUP */
#define BBR_BETA	       0.7   /* inflight_lo/bw_lo multiplicative cut on loss */
#define BBR_INFLIGHT_HEADROOM  0.15  /* leave 15% of inflight_hi as headroom */
#define BBR_PROBE_UP_GAIN      1.25  /* PROBE_BW UP pacing gain */
#define BBR_PROBE_DOWN_GAIN    0.75  /* PROBE_BW DOWN pacing gain */
#define BBR_PROBE_BW_CWND_GAIN 2.0   /* PROBE_BW cwnd gain */
#define BBR_CRUISE_ROUNDS      4     /* rounds to cruise before probing up again */
#define BBR_UP_ROUNDS_MAX      6     /* max rounds to spend probing up */
#define BBR_INFLIGHT_MAX       (~0U) /* "unset" sentinel for the inflight bounds */

typedef enum
{
  BBR_STARTUP,
  BBR_DRAIN,
  BBR_PROBE_BW,
  BBR_PROBE_RTT,
} bbr_mode_t;

/* PROBE_BW sub-states (v3). DOWN drains to make room, CRUISE holds below the
 * inflight ceiling, REFILL tops the pipe back up, UP probes for more bw. */
typedef enum
{
  BBR_BW_DOWN,
  BBR_BW_CRUISE,
  BBR_BW_REFILL,
  BBR_BW_UP,
} bbr_probe_bw_phase_t;

typedef struct
{
  bbr_minmax_t bw;	    /**< max-filtered bandwidth, bytes/sec */
  bbr_minmax_t extra_acked; /**< max-filtered ack-aggregation excess, bytes */
  f64 min_rtt;		    /**< min-filtered RTT, seconds */
  f64 min_rtt_stamp;	    /**< time min_rtt was set */
  f64 probe_rtt_done_stamp; /**< when the PROBE_RTT hold may end (0 if unset) */
  f64 full_bw;		    /**< bw at last full-pipe check */
  f64 pacing_rate;	    /**< paced send rate, bytes/sec (get_pacing_rate) */
  f64 pacing_gain;	    /**< current pacing gain */
  f64 cwnd_gain;	    /**< current cwnd gain */
  f64 ack_epoch_stamp;	    /**< start time of the current ack-aggregation epoch */
  f64 bw_lo;		    /**< short-term bandwidth bound, bytes/sec (v3) */
  f64 bw_latest;	    /**< max bw seen in the current round (v3) */
  u64 ack_epoch_delivered;  /**< tc->delivered at the epoch start */
  u64 next_rtt_delivered;   /**< tc->delivered marking the next round's start */
  u64 loss_round_delivered; /**< tc->delivered marking the loss-round boundary */
  u32 inflight_hi;	    /**< long-term inflight ceiling, bytes (v3) */
  u32 inflight_lo;	    /**< short-term inflight floor, bytes (v3) */
  u32 inflight_latest;	    /**< max inflight delivered in the current round (v3) */
  u32 extra_acked_cnt;	    /**< ack-aggregation epoch counter (filter time) */
  u32 prior_cwnd;	    /**< cwnd saved across recovery / PROBE_RTT */
  u32 rtt_cnt;		    /**< packet-timed round-trip counter */
  u32 bw_probe_up_rounds;   /**< rounds spent in PROBE_BW UP (probe pace-up) (v3) */
  u32 phase_rounds;	    /**< round-starts elapsed in the current phase (v3) */
  u8 mode;		    /**< bbr_mode_t */
  u8 probe_bw_phase;	    /**< bbr_probe_bw_phase_t within PROBE_BW (v3) */
  u8 full_bw_cnt;	    /**< rounds without >=25% bw growth */
  u8 full_loss_cnt;	    /**< consecutive high-loss rounds in STARTUP (v3) */
  u8 full_bw_reached;	    /**< STARTUP pipe-full latch */
  u8 round_start;	    /**< a new round started on this ack */
  u8 loss_round_start;	    /**< a loss-accounting round ended on this ack (v3) */
  u8 probe_rtt_round_done;  /**< a round elapsed during PROBE_RTT */
  u8 idle_restart;	    /**< restarting from idle */
  u8 ecn_eligible;	    /**< ECN in use (always 0: VPP has no ECN) (v3) */
} bbr_data_t;

/* BBR state is heap-allocated; only the pointer lives in the cc scratch area. */
STATIC_ASSERT (sizeof (bbr_data_t *) <= TCP_CC_DATA_SZ, "bbr ptr fits cc_data");

static inline bbr_data_t *
bbr_data (tcp_connection_t *tc)
{
  return *(bbr_data_t **) tc->cc_data;
}

static inline f64
bbr_now (tcp_connection_t *tc)
{
  return tcp_time_now_us (tc->c_thread_index);
}

static inline f64
bbr_max_bw (bbr_data_t *bd)
{
  return (f64) bbr_minmax_get (&bd->bw);
}

/* The bandwidth BBR actually uses to set pacing and cwnd: the max-filtered
 * estimate capped by the short-term bound bw_lo (which a lossy round pulls
 * down). bw_lo == 0 means "unset" (no recent loss), so the cap is inactive. */
static inline f64
bbr_bw (bbr_data_t *bd)
{
  f64 bw = bbr_max_bw (bd);
  if (bd->bw_lo > 0.0 && bd->bw_lo < bw)
    return bd->bw_lo;
  return bw;
}

/* Bytes the BDP target translates to, in cwnd (bytes) units. Uses the bounded
 * bandwidth (bbr_bw) so a lossy round's bw_lo cap flows through to cwnd. */
static inline u32
bbr_bdp (tcp_connection_t *tc, bbr_data_t *bd, f64 gain)
{
  f64 bw = bbr_bw (bd);

  /* No RTT estimate yet: fall back to a safe initial window. */
  if (bd->min_rtt <= 0.0 || bd->min_rtt == 1e9)
    return tcp_initial_cwnd (tc);

  /* bdp = bw * min_rtt; target = bdp * gain, rounded up to whole segments
   * plus a small quanta so PROBE_BW can exceed the BDP. */
  f64 bdp = bw * bd->min_rtt * gain;
  u32 segs = (u32) (bdp / tc->snd_mss) + 1;
  return (segs + 3) * tc->snd_mss;
}

static inline void
bbr_reset_startup (bbr_data_t *bd)
{
  bd->mode = BBR_STARTUP;
  bd->pacing_gain = BBR_HIGH_GAIN;
  bd->cwnd_gain = BBR_HIGH_GAIN;
}

static inline void
bbr_reset_probe_bw (tcp_connection_t *tc, bbr_data_t *bd)
{
  bd->mode = BBR_PROBE_BW;
  /* Enter cruising below the inflight ceiling; the phase machine
   * (bbr_update_cycle_phase) drives DOWN/CRUISE/REFILL/UP from here. */
  bd->probe_bw_phase = BBR_BW_DOWN;
  bd->pacing_gain = BBR_PROBE_DOWN_GAIN;
  bd->cwnd_gain = BBR_PROBE_BW_CWND_GAIN;
  bd->phase_rounds = 0;
  bd->bw_probe_up_rounds = 0;
}

static inline void
bbr_reset_mode (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (!bd->full_bw_reached)
    bbr_reset_startup (bd);
  else
    bbr_reset_probe_bw (tc, bd);
}

static void
bbr_save_cwnd (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (!tcp_in_cong_recovery (tc) && bd->mode != BBR_PROBE_RTT)
    bd->prior_cwnd = tc->cwnd;
  else
    bd->prior_cwnd = clib_max (bd->prior_cwnd, tc->cwnd);
}

/* Per-ack: sample bandwidth and advance the packet-timed round counter. */
static void
bbr_update_bw (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  bd->round_start = 0;

  if (rs->delivered == 0 || rs->interval_time <= 0.0)
    return;

  /* A round trip elapsed once we ack data that was sent at or after the
   * delivered-count snapshot taken at the last round boundary. */
  if (rs->prior_delivered >= bd->next_rtt_delivered)
    {
      bd->next_rtt_delivered = tc->delivered;
      bd->rtt_cnt++;
      bd->round_start = 1;
    }

  f64 bw = (f64) rs->delivered / rs->interval_time; /* bytes/sec */

  /* Feed the max-filter, but never let a sample that was limited by something
   * other than the path lower the estimate: app-limited (sender-starved) or
   * taken while in loss recovery, when sending is gated by the retransmit path
   * rather than the bottleneck. Such a low sample must not be allowed to drag
   * max_bw (and hence cwnd/pacing) down into a self-reinforcing collapse -- on a
   * short-RTT link recovery spans several rounds and would otherwise age the
   * good sample out of the window. A sample that still beats the current max is
   * always taken (it is a real improvement). */
  if (!(rs->flags & TCP_BTS_IS_APP_LIMITED) || bw >= bbr_max_bw (bd))
    {
      if (!tcp_in_cong_recovery (tc) || bw >= bbr_max_bw (bd))
	bbr_minmax_running_max (&bd->bw, BBR_BW_WIN_RTTS, bd->rtt_cnt, (u64) bw);
    }
}

/* Estimate ACK aggregation: how much more has been delivered over the current
 * epoch than the bottleneck bandwidth alone could account for. On a polled,
 * TSO/GRO-batched high-speed link, ACKs arrive in large bursts, so the pipe
 * needs cwnd headroom beyond the min-RTT BDP to stay full. We track a windowed
 * max of this excess and add it to the cwnd target (the ack-aggregation term in
 * BBR v1 implementations). */
static void
bbr_update_ack_aggregation (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  f64 epoch, expected;
  u64 extra;

  if (bbr_max_bw (bd) <= 0.0 || rs->acked_and_sacked == 0)
    return;

  /* Reset the filter time once per round so old samples age out. */
  if (bd->round_start)
    bd->extra_acked_cnt++;

  epoch = bbr_now (tc) - bd->ack_epoch_stamp;
  expected = bbr_max_bw (bd) * epoch; /* bytes the bottleneck could deliver */

  /* Start a fresh epoch if this one is too long or the delivered count fell
   * behind what bw alone would explain (no aggregation to measure). */
  if (epoch > BBR_ACK_EPOCH_MAX || (f64) (tc->delivered - bd->ack_epoch_delivered) <= expected)
    {
      bd->ack_epoch_stamp = bbr_now (tc);
      bd->ack_epoch_delivered = tc->delivered;
      return;
    }

  extra = (tc->delivered - bd->ack_epoch_delivered) - (u64) expected;
  bbr_minmax_running_max (&bd->extra_acked, BBR_EXTRA_ACKED_WIN, bd->extra_acked_cnt, extra);
}

/*
 * v3 loss accounting and inflight/bw bounds.
 */

/* A "loss round" ends when we ack data sent at/after the delivered-count marked
 * at the previous loss round; per round we note whether any loss occurred. */
static void
bbr_update_loss_round (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  bd->loss_round_start = 0;

  if (rs->prior_delivered >= bd->loss_round_delivered)
    {
      bd->loss_round_delivered = tc->delivered;
      bd->loss_round_start = 1;
    }
}

/* Track the per-round maxima of bw and inflight; these feed the short-term
 * bounds so a single good sample can lift them back up after a loss cut. */
static void
bbr_update_latest_max (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  f64 bw;

  if (bd->round_start)
    {
      bd->bw_latest = 0.0;
      bd->inflight_latest = 0;
    }

  if (rs->interval_time > 0.0 && rs->delivered > 0)
    {
      bw = (f64) rs->delivered / rs->interval_time;
      if (bw > bd->bw_latest)
	bd->bw_latest = bw;
    }
  if (rs->delivered > bd->inflight_latest)
    bd->inflight_latest = rs->delivered;
}

/* On a high-loss round, pull the short-term bounds down toward the rate/inflight
 * that were actually sustained, so we back off to coexist with the loss. */
static void
bbr_adapt_lower_bounds (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  f64 bw;

  if (!bd->loss_round_start)
    return;

  /* bw_lo: never below the best rate seen this round, and cut by BETA. */
  bw = bbr_max_bw (bd);
  if (bd->bw_lo == 0.0)
    bd->bw_lo = bw;
  bd->bw_lo = clib_max (bd->bw_latest, bd->bw_lo * BBR_BETA);

  /* inflight_lo: same shape, in bytes, floored at the round's inflight. */
  if (bd->inflight_lo == BBR_INFLIGHT_MAX)
    bd->inflight_lo = tc->cwnd;
  bd->inflight_lo = clib_max (bd->inflight_latest, (u32) (bd->inflight_lo * BBR_BETA));
}

/* When a round is loss-free, relax the short-term bounds back toward "unset" so
 * BBR resumes probing for more bandwidth. */
static void
bbr_reset_lower_bounds (bbr_data_t *bd)
{
  bd->bw_lo = 0.0;
  bd->inflight_lo = BBR_INFLIGHT_MAX;
}

/* PROBE_BW UP: raise the long-term inflight ceiling, once per round, by a
 * doubling-then-linear amount so probing accelerates the longer the path stays
 * clear. Only grows on a round boundary so it cannot run away per-ack. */
static void
bbr_probe_inflight_hi_upward (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  u32 inc, base;

  if (!bd->round_start)
    return;

  base = (bd->inflight_hi == BBR_INFLIGHT_MAX) ? tc->cwnd : bd->inflight_hi;
  bd->bw_probe_up_rounds = clib_min (bd->bw_probe_up_rounds + 1, 30);
  /* ~ (1 << rounds) segments/round early, capped so it stays sane. */
  inc = clib_min (1u << bd->bw_probe_up_rounds, 64u) * tc->snd_mss;
  bd->inflight_hi = base + inc;
}

/* PROBE_BW: advance the DOWN/CRUISE/REFILL/UP phase machine (v3). Transitions
 * are driven by loss and by inflight relative to the model, not a fixed
 * round-robin. */
static void
bbr_update_cycle_phase (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  u32 inflight, bdp, loss_thresh;
  u8 is_loss_high;

  if (bd->mode != BBR_PROBE_BW)
    return;

  inflight = tcp_flight_size (tc);
  bdp = bbr_bdp (tc, bd, 1.0);

  /* Count rounds spent in the current phase; transitions are round-based so a
   * short-RTT link cannot skip through phases within a single round. */
  if (bd->round_start)
    bd->phase_rounds++;

  /* Loss is "high" this round if bytes lost exceed BBR_LOSS_THRESH of what the
   * round delivered. Computed on the loss-round boundary. */
  loss_thresh = (u32) (BBR_LOSS_THRESH * (f64) rs->delivered);
  is_loss_high = bd->loss_round_start && rs->lost > loss_thresh;

  switch (bd->probe_bw_phase)
    {
    case BBR_BW_DOWN:
      /* Drain any queue the last UP built; once inflight is at/below the BDP,
       * start cruising. */
      bd->pacing_gain = BBR_PROBE_DOWN_GAIN;
      bd->cwnd_gain = BBR_PROBE_BW_CWND_GAIN;
      if (inflight <= bdp || bd->phase_rounds >= BBR_UP_ROUNDS_MAX)
	{
	  bd->probe_bw_phase = BBR_BW_CRUISE;
	  bd->phase_rounds = 0;
	}
      break;

    case BBR_BW_CRUISE:
      /* Hold near the BDP for a few rounds, then refill and probe up again so a
       * path with spare capacity is re-probed. A high-loss round holds us in
       * cruise (do not probe up into congestion). */
      bd->pacing_gain = 1.0;
      bd->cwnd_gain = BBR_PROBE_BW_CWND_GAIN;
      if (!is_loss_high && bd->phase_rounds >= BBR_CRUISE_ROUNDS)
	{
	  bd->probe_bw_phase = BBR_BW_REFILL;
	  bd->phase_rounds = 0;
	  bbr_reset_lower_bounds (bd);
	  bd->bw_probe_up_rounds = 0;
	}
      break;

    case BBR_BW_REFILL:
      /* Top the pipe back up at unity gain for one round, then probe upward. */
      bd->pacing_gain = 1.0;
      bd->cwnd_gain = BBR_PROBE_BW_CWND_GAIN;
      if (bd->phase_rounds >= 1)
	{
	  bd->probe_bw_phase = BBR_BW_UP;
	  bd->phase_rounds = 0;
	}
      break;

    case BBR_BW_UP:
      /* Probe for more bandwidth: pace above 1.0 and lift inflight_hi once per
       * round. Leave for DOWN on high loss (cap the ceiling at the inflight at
       * loss) or after BBR_UP_ROUNDS_MAX rounds of probing. The round bound
       * guarantees we stop pacing at 1.25x and drain even on a clear path. */
      bd->pacing_gain = BBR_PROBE_UP_GAIN;
      bd->cwnd_gain = BBR_PROBE_BW_CWND_GAIN;
      if (is_loss_high)
	{
	  if (rs->tx_in_flight)
	    bd->inflight_hi = clib_max ((u32) rs->tx_in_flight, BBR_CWND_MIN * tc->snd_mss);
	  bd->probe_bw_phase = BBR_BW_DOWN;
	  bd->phase_rounds = 0;
	  bd->bw_probe_up_rounds = 0;
	}
      else
	{
	  bbr_probe_inflight_hi_upward (tc, bd, rs);
	  if (bd->phase_rounds >= BBR_UP_ROUNDS_MAX)
	    {
	      bd->probe_bw_phase = BBR_BW_DOWN;
	      bd->phase_rounds = 0;
	      bd->bw_probe_up_rounds = 0;
	    }
	}
      break;
    }
}

/* STARTUP: detect when the pipe is full. Two exits: (a) bw stopped growing for
 * BBR_FULL_BW_CNT rounds; (b, v3) the ramp is clearly overshooting -- several
 * loss-rounds each above BBR_LOSS_THRESH *and* inflight already well past the
 * estimated BDP. A single lossy round must NOT exit (on a link with a little
 * random loss the ramp would stop at the initial window), so we require
 * BBR_FULL_LOSS_CNT loss-rounds and an inflight check, matching v3. */
static void
bbr_check_full_bw (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  f64 bw;
  u32 loss_thresh;

  if (bd->full_bw_reached || (rs->flags & TCP_BTS_IS_APP_LIMITED))
    return;

  if (bd->loss_round_start)
    {
      loss_thresh = (u32) (BBR_LOSS_THRESH * (f64) rs->delivered);
      if (rs->lost > loss_thresh)
	bd->full_loss_cnt++;
      else
	bd->full_loss_cnt = 0;

      if (bd->full_loss_cnt >= BBR_FULL_LOSS_CNT &&
	  tcp_flight_size (tc) >= bbr_bdp (tc, bd, BBR_PROBE_UP_GAIN))
	{
	  bd->full_bw_reached = 1;
	  if (rs->tx_in_flight)
	    bd->inflight_hi = clib_max ((u32) rs->tx_in_flight, BBR_CWND_MIN * tc->snd_mss);
	  return;
	}
    }

  if (!bd->round_start)
    return;

  bw = bbr_max_bw (bd);
  if (bw >= bd->full_bw * BBR_FULL_BW_THRESH)
    {
      bd->full_bw = bw;
      bd->full_bw_cnt = 0;
      return;
    }
  bd->full_bw_cnt++;
  bd->full_bw_reached = bd->full_bw_cnt >= BBR_FULL_BW_CNT;
}

/* STARTUP -> DRAIN -> PROBE_BW transitions. DRAIN empties the queue STARTUP's
 * 2x overshoot built. We drain at the gentle PROBE_BW DOWN gain rather than the
 * classic 1/high_gain (~0.35): on a short-RTT link a single 0.35x round empties
 * the pipe below the BDP and the bandwidth samples (and pacing) collapse with
 * it. 0.75 drains within a couple of rounds without starving the flow, matching
 * v3's "drain via PROBE_BW_DOWN" structure. */
static void
bbr_check_drain (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (bd->mode == BBR_STARTUP && bd->full_bw_reached)
    {
      bd->mode = BBR_DRAIN;
      bd->pacing_gain = BBR_PROBE_DOWN_GAIN;
      bd->cwnd_gain = BBR_HIGH_GAIN; /* hold cwnd while draining */
      tc->ssthresh = bbr_bdp (tc, bd, 1.0);
      bd->phase_rounds = 0;
    }

  if (bd->mode == BBR_DRAIN)
    {
      if (bd->round_start)
	bd->phase_rounds++;
      /* Exit once inflight has drained to the BDP, or after a couple of rounds
       * regardless: on a short-RTT link the BDP tracks the (falling) bandwidth
       * estimate, so a pure flight<=BDP test can chase its tail and never fire,
       * pinning the flow in DRAIN at 0.75x while its bw estimate collapses. */
      if (tcp_flight_size (tc) <= bbr_bdp (tc, bd, 1.0) || bd->phase_rounds >= 2)
	bbr_reset_probe_bw (tc, bd);
    }
}

static void
bbr_check_probe_rtt_done (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (!(bd->probe_rtt_done_stamp && bbr_now (tc) > bd->probe_rtt_done_stamp))
    return;

  bd->min_rtt_stamp = bbr_now (tc);
  tc->cwnd = clib_max (tc->cwnd, bd->prior_cwnd);
  bbr_reset_mode (tc, bd);
}

/* Track the min-RTT over a 10s window; enter/maintain PROBE_RTT. */
static void
bbr_update_min_rtt (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  f64 now = bbr_now (tc);
  u8 expired = now > bd->min_rtt_stamp + BBR_MIN_RTT_WIN;

  if (rs->rtt_time > 0.0 && (rs->rtt_time < bd->min_rtt || expired))
    {
      bd->min_rtt = rs->rtt_time;
      bd->min_rtt_stamp = now;
    }

  if (expired && !bd->idle_restart && bd->mode != BBR_PROBE_RTT)
    {
      bd->mode = BBR_PROBE_RTT;
      bd->pacing_gain = 1.0;
      bd->cwnd_gain = 1.0;
      bbr_save_cwnd (tc, bd);
      bd->probe_rtt_done_stamp = 0;
    }

  if (bd->mode == BBR_PROBE_RTT)
    {
      /* Hold cwnd at the floor; once inflight drains to it, time the hold. */
      if (!bd->probe_rtt_done_stamp && tcp_flight_size (tc) <= BBR_CWND_MIN * tc->snd_mss)
	{
	  bd->probe_rtt_done_stamp = now + BBR_PROBE_RTT_S;
	  bd->probe_rtt_round_done = 0;
	  bd->next_rtt_delivered = tc->delivered;
	}
      else if (bd->probe_rtt_done_stamp)
	{
	  if (bd->round_start)
	    bd->probe_rtt_round_done = 1;
	  if (bd->probe_rtt_round_done)
	    bbr_check_probe_rtt_done (tc, bd);
	}
    }

  bd->idle_restart = 0;
}

/* Initial paced rate before any bandwidth sample: ramp from the initial
 * window over the RTT at the STARTUP gain, so the flow can get going. */
static f64
bbr_init_pacing_rate (tcp_connection_t *tc)
{
  f64 srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);

  /* srtt is seeded to 100ms at init; mrtt_us starts at a sentinel that the
   * clib_min above filters out until the first RTT sample lands. */
  if (srtt <= 0.0)
    srtt = 0.1;
  return BBR_HIGH_GAIN * (f64) tcp_initial_cwnd (tc) / srtt * BBR_PACING_MARGIN;
}

/* Pacing rate = pacing_gain * bw, held ~1% under bw. Before the pipe is known
 * to be full, the rate only ratchets up (a single low/noisy early bandwidth
 * sample must not throttle the STARTUP ramp); afterwards it tracks the model
 * up or down. */
static void
bbr_set_pacing_rate (tcp_connection_t *tc, bbr_data_t *bd)
{
  f64 bw = bbr_bw (bd); /* v3: bounded by bw_lo so loss throttles pacing */
  f64 rate;

  if (bw <= 0.0)
    {
      if (bd->pacing_rate == 0.0)
	bd->pacing_rate = bbr_init_pacing_rate (tc);
      return;
    }

  rate = bd->pacing_gain * bw * BBR_PACING_MARGIN;

  if (bd->full_bw_reached || rate > bd->pacing_rate)
    bd->pacing_rate = rate;

  /* Floor the paced rate at the unbounded max-filtered bandwidth (one BDP worth
   * of pacing) unless a loss round legitimately lowered the bound. This mirrors
   * the cwnd floor: a low transient rate during recovery must not starve the
   * pacer burst and ack-clock the flow into a collapse. */
  if (bd->full_bw_reached && bd->bw_lo == 0.0)
    {
      f64 floor = bbr_max_bw (bd) * BBR_PACING_MARGIN;
      if (bd->pacing_rate < floor)
	bd->pacing_rate = floor;
    }
}

static void
bbr_set_cwnd (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  u32 target, acked = rs->acked_and_sacked;

  /* PROBE_RTT pins cwnd at the floor regardless of the model. */
  if (bd->mode == BBR_PROBE_RTT)
    {
      tc->cwnd = clib_min (tc->cwnd, BBR_CWND_MIN * tc->snd_mss);
      return;
    }

  target = bbr_bdp (tc, bd, bd->cwnd_gain);

  /* Add headroom for ACK aggregation so the pipe stays full when acks arrive
   * in bursts (the min-RTT BDP alone undershoots on a batchy high-speed link).
   * Only once the pipe is known full, matching the pacing model. */
  if (bd->full_bw_reached)
    target += (u32) bbr_minmax_get (&bd->extra_acked);

  if (bd->full_bw_reached)
    tc->cwnd = clib_min (tc->cwnd + acked, target);
  else if (tc->cwnd < target || tc->delivered < tcp_initial_cwnd (tc))
    tc->cwnd = tc->cwnd + acked;

  /* v3: never exceed the inflight bounds. inflight_hi is the loss-probed
   * ceiling; inflight_lo is the short-term floor a lossy round pulled down.
   * Reserve headroom below inflight_hi so we do not sit right at the edge. */
  if (bd->inflight_hi != BBR_INFLIGHT_MAX)
    {
      u32 hi = bd->inflight_hi;
      u32 headroom = (u32) (BBR_INFLIGHT_HEADROOM * (f64) hi);
      hi = hi > headroom ? hi - headroom : hi;
      tc->cwnd = clib_min (tc->cwnd, clib_max (hi, BBR_CWND_MIN * tc->snd_mss));
    }
  if (bd->inflight_lo != BBR_INFLIGHT_MAX)
    tc->cwnd = clib_min (tc->cwnd, clib_max (bd->inflight_lo, BBR_CWND_MIN * tc->snd_mss));

  /* Floor cwnd at one BDP once the pipe is known full, unless a loss round has
   * legitimately pulled the short-term bound down (inflight_lo set). Without
   * this, a burst of small acks during recovery shrinks cwnd below the BDP; the
   * pacer burst then shrinks with it and the flow ack-clocks itself down into a
   * collapse it never recovers from on a short-RTT link. */
  if (bd->full_bw_reached && bd->inflight_lo == BBR_INFLIGHT_MAX)
    tc->cwnd = clib_max (tc->cwnd, bbr_bdp (tc, bd, 1.0));

  tc->cwnd = clib_max (tc->cwnd, BBR_CWND_MIN * tc->snd_mss);
  tc->cwnd = clib_min (tc->cwnd, tc->tx_fifo_size);
}

/* Per round, move the short-term bounds. Only a round whose loss rate exceeds
 * BBR_LOSS_THRESH counts as congestion and cuts the bounds; any other round --
 * including one with a little sub-threshold (non-congestive) loss -- relaxes the
 * bounds back toward "unset" so probing resumes. This is what lets v3 ride
 * through random loss instead of collapsing on every drop. */
static void
bbr_update_lower_bounds (tcp_connection_t *tc, bbr_data_t *bd, tcp_rate_sample_t *rs)
{
  u32 loss_thresh;

  if (!bd->loss_round_start)
    return;

  loss_thresh = (u32) (BBR_LOSS_THRESH * (f64) rs->delivered);
  if (rs->lost > loss_thresh)
    bbr_adapt_lower_bounds (tc, bd, rs);
  else
    bbr_reset_lower_bounds (bd);
}

/* The per-ack BBR update: model, then control (pacing + cwnd). */
static void
bbr_update (tcp_connection_t *tc, tcp_rate_sample_t *rs)
{
  bbr_data_t *bd = bbr_data (tc);

  bbr_update_bw (tc, bd, rs);
  bbr_update_ack_aggregation (tc, bd, rs);
  bbr_update_loss_round (tc, bd, rs);
  bbr_update_latest_max (tc, bd, rs);
  bbr_update_lower_bounds (tc, bd, rs);
  bbr_update_cycle_phase (tc, bd, rs);
  bbr_check_full_bw (tc, bd, rs);
  bbr_check_drain (tc, bd);
  bbr_update_min_rtt (tc, bd, rs);
  bbr_set_pacing_rate (tc, bd);
  bbr_set_cwnd (tc, bd, rs);
}

/*
 * CC algorithm callbacks
 */

static void
bbr_rcv_ack (tcp_connection_t *tc, tcp_rate_sample_t *rs)
{
  bbr_update (tc, rs);
}

static void
bbr_rcv_cong_ack (tcp_connection_t *tc, tcp_cc_ack_t ack_type, tcp_rate_sample_t *rs)
{
  /* BBR does not treat loss/dup-acks as a distinct congestion signal; run the
   * same model update. Retransmission is still driven by the core/RACK. */
  bbr_update (tc, rs);
}

static void
bbr_congestion (tcp_connection_t *tc)
{
  /* No multiplicative decrease. Just remember the pre-loss cwnd to restore on
   * recovery exit. */
  bbr_save_cwnd (tc, bbr_data (tc));
}

static void
bbr_loss (tcp_connection_t *tc)
{
  /* RTO: the core resets cwnd; BBR re-grows from the model. Drop the full-pipe
   * latch so a STARTUP-style ramp can resume if needed. An RTO is strong
   * congestion evidence, so (v3) also pull the inflight ceiling down toward
   * what is in flight now and cut the short-term bound. */
  bbr_data_t *bd = bbr_data (tc);
  u32 inflight = tcp_flight_size (tc);

  bd->full_bw = 0;
  bd->full_bw_cnt = 0;

  inflight = clib_max (inflight, BBR_CWND_MIN * tc->snd_mss);
  if (bd->inflight_hi == BBR_INFLIGHT_MAX || inflight < bd->inflight_hi)
    bd->inflight_hi = inflight;
  bd->inflight_lo = inflight;
  bd->bw_lo = 0.0; /* let bw re-probe; the inflight bound carries the response */
}

static void
bbr_recovered (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);
  tc->cwnd = clib_max (tc->cwnd, bd->prior_cwnd);
}

static void
bbr_event (tcp_connection_t *tc, tcp_cc_event_t evt)
{
  bbr_data_t *bd = bbr_data (tc);

  if (evt == TCP_CC_EVT_START_TX)
    bd->idle_restart = 1;
}

static u64
bbr_get_pacing_rate (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);

  /* The rate is maintained by bbr_set_pacing_rate on every ack. Seed it on the
   * first read (e.g. the pacer init before the first ack arrives). */
  if (bd->pacing_rate == 0.0)
    bd->pacing_rate = bbr_init_pacing_rate (tc);

  return (u64) bd->pacing_rate;
}

/* Fast-recovery send space. BBR does not cut cwnd on loss, so recovery uses the
 * same cwnd-based space as the rest of the flow (model cwnd minus what is still
 * in flight); the tx pacer, not PRR, paces what actually goes out. */
static int
bbr_cong_control (tcp_connection_t *tc)
{
  return tcp_available_cc_snd_space (tc);
}

static void
bbr_conn_init (tcp_connection_t *tc)
{
  bbr_data_t *bd;

  /* BBR is driven entirely by the delivery-rate estimator (bandwidth and RTT
   * samples from the byte tracker), so it requires rate sampling. init runs
   * before tcp_connection_init_vars allocates the byte tracker, so setting the
   * flag here is enough to opt in (same mechanism RACK uses). */
  tc->cfg_flags |= TCP_CFG_F_RATE_SAMPLE;

  bd = clib_mem_alloc (sizeof (*bd));
  clib_memset (bd, 0, sizeof (*bd));
  *(bbr_data_t **) tc->cc_data = bd;

  bd->min_rtt = 1e9; /* "unset"; first RTT sample replaces it */
  bd->min_rtt_stamp = bbr_now (tc);
  bd->next_rtt_delivered = tc->delivered;
  bd->ack_epoch_stamp = bbr_now (tc);
  bd->ack_epoch_delivered = tc->delivered;
  bd->loss_round_delivered = tc->delivered;
  /* v3 bounds start "unset" so they impose no limit until loss/probing set
   * them; bw_lo starts unset (0) likewise. */
  bd->inflight_hi = BBR_INFLIGHT_MAX;
  bd->inflight_lo = BBR_INFLIGHT_MAX;
  bd->bw_lo = 0.0;
  bd->ecn_eligible = 0; /* VPP has no ECN: loss-only mode */
  tc->cwnd = tcp_initial_cwnd (tc);
  tc->ssthresh = tc->snd_wnd; /* BBR doesn't use ssthresh to gate; keep high */
  bbr_reset_startup (bd);
}

static void
bbr_conn_cleanup (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);
  if (bd)
    {
      clib_mem_free (bd);
      *(bbr_data_t **) tc->cc_data = 0;
    }
}

const static tcp_cc_algorithm_t tcp_bbr = {
  .name = "bbr",
  .init = bbr_conn_init,
  .cleanup = bbr_conn_cleanup,
  .rcv_ack = bbr_rcv_ack,
  .rcv_cong_ack = bbr_rcv_cong_ack,
  .congestion = bbr_congestion,
  .loss = bbr_loss,
  .recovered = bbr_recovered,
  .event = bbr_event,
  .get_pacing_rate = bbr_get_pacing_rate,
  .cong_control = bbr_cong_control,
};

clib_error_t *
tcp_bbr_init (vlib_main_t *vm)
{
  /* Register at a fixed type index, like the other built-in algorithms.
   * tcp_cc_algo_new_type is for runtime (post tcp_main_enable) registration;
   * at init time cc_last_type is not yet seeded, so it would alias an existing
   * slot. */
  tcp_cc_algo_register (TCP_CC_BBR, &tcp_bbr);
  return 0;
}

VLIB_INIT_FUNCTION (tcp_bbr_init);
