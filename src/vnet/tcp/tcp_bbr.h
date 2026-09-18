/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_BBR_H_
#define SRC_VNET_TCP_TCP_BBR_H_

#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/random.h>

/**
 * BBR congestion control (BBRv3).
 *
 * draft-ietf-ccwg-bbr-06. BBR models the path by its bottleneck bandwidth (windowed max of per-ack
 * delivery-rate samples) and its round-trip propagation delay (windowed min RTT), and paces sending
 * at gain * bw while holding cwnd near bw * min_rtt. Unlike a loss-based algorithm it does not cut
 * cwnd multiplicatively on loss, instead BBR bounds inflight and bandwidth
 * (inflight_hi/inflight_lo/bw_lo) and treats a high per-round loss rate as the signal to lower
 * those bounds, so it coexists with loss-based flows. ECN, BBRv3's third signal, is not yet
 * supported, so it runs in loss-only mode.
 *
 * Built on the byte-tracker delivery-rate estimator (tcp_ack_ctx_t) and RACK loss detection. SACK
 * must be negotiated, additionaly BBR enables pacing, byte tracking, and RACK on the connection.
 * Per-connection BBR state is kept in worker-local pools and referenced from tc->cc_data, so
 * enabling BBR adds nothing to connections using other congestion-control algorithms.
 */

/* draft-ietf-ccwg-bbr-06, loss-only operation (VPP TCP has no ECN). */
#define BBR_STARTUP_PACING_GAIN	 2.77
#define BBR_DEFAULT_CWND_GAIN	 2.0
#define BBR_DRAIN_PACING_GAIN	 0.5
#define BBR_PROBE_DOWN_GAIN	 0.90
#define BBR_PROBE_UP_PACING_GAIN 1.25
#define BBR_PROBE_UP_CWND_GAIN	 2.25
#define BBR_PROBE_RTT_CWND_GAIN	 0.5
#define BBR_PACING_MARGIN	 0.99

#define BBR_FULL_BW_THRESH	  1.25
#define BBR_FULL_BW_CNT		  3
#define BBR_STARTUP_FULL_LOSS_CNT 6
#define BBR_LOSS_THRESH		  0.02
#define BBR_BETA		  0.7
#define BBR_HEADROOM		  0.15

#define BBR_MIN_PIPE_PKTS	   4
#define BBR_MIN_RTT_FILTER_LEN	   10.0
#define BBR_PROBE_RTT_INTERVAL	   5.0
#define BBR_PROBE_RTT_DURATION	   0.2
#define BBR_PROBE_WAIT_BASE	   2.0
#define BBR_PROBE_WAIT_RAND	   1.0
#define BBR_RENO_ROUNDS_MAX	   63
#define BBR_EXTRA_ACKED_FILTER_LEN 10
#define BBR_SEND_QUANTUM_INTERVAL  0.001
#define BBR_SEND_QUANTUM_MAX	   (64 << 10)

/* Cover the output-to-ACK pipeline without increasing paced bursts. */
#define BBR_OFFLOAD_BUDGET_INTERVAL 0.00013
#define BBR_OFFLOAD_QUANTA_MIN	    3
#define BBR_OFFLOAD_QUANTA_MAX	    16

#define BBR_INFLIGHT_INFINITY ((u32) ~0)
#define BBR_BW_INFINITY	      CLIB_F64_MAX

typedef enum __clib_packed
{
  BBR_STARTUP,
  BBR_DRAIN,
  BBR_PROBE_BW,
  BBR_PROBE_RTT,
} bbr_mode_t;

typedef enum __clib_packed
{
  BBR_BW_DOWN,
  BBR_BW_CRUISE,
  BBR_BW_REFILL,
  BBR_BW_UP,
} bbr_probe_bw_phase_t;

typedef enum __clib_packed
{
  BBR_ACKS_INIT,
  BBR_ACKS_REFILLING,
  BBR_ACKS_PROBE_STARTING,
  BBR_ACKS_PROBE_FEEDBACK,
  BBR_ACKS_PROBE_STOPPING,
} bbr_ack_phase_t;

typedef enum __clib_packed
{
  BBR_UNDO_NONE,
  BBR_UNDO_STARTUP,
  BBR_UNDO_PROBE_UP,
} bbr_undo_state_t;

typedef enum
{
  BBR_F_FULL_BW_REACHED = 1 << 0,
  BBR_F_ROUND_START = 1 << 1,
  BBR_F_LOSS_ROUND_START = 1 << 2,
  BBR_F_LOSS_IN_ROUND = 1 << 3,
  BBR_F_LOSS_ROUND_HAD_LOSS = 1 << 4,
  BBR_F_LOSS_EVENT_PENDING = 1 << 5,
  BBR_F_RECOVERY_IN_ROUND = 1 << 6,
  BBR_F_IS_BW_PROBE_SAMPLE = 1 << 7,
  BBR_F_PREV_PROBE_TOO_HIGH = 1 << 8,
  BBR_F_PREV_PROBE_PRECAUTIONARY = 1 << 9,
  BBR_F_PROBE_RTT_ROUND_DONE = 1 << 10,
  BBR_F_IDLE_RESTART = 1 << 11,
  BBR_F_HAS_SEEN_RTT = 1 << 12,
} bbr_flag_t;

/*
 * Windowed max/min tracker (Kathleen Nichols' algorithm). Keeps the running
 * extreme over a sliding window using only three samples, in constant time.
 * Time is a round-trip count and values are excess acknowledged bytes.
 */
typedef struct
{
  u32 t; /**< time of the sample */
  u32 v; /**< value of the sample */
} bbr_minmax_sample_t;

typedef struct
{
  bbr_minmax_sample_t s[3];
} bbr_minmax_t;

static inline u32
bbr_minmax_get (bbr_minmax_t *m)
{
  return m->s[0].v;
}

static inline void
bbr_minmax_reset (bbr_minmax_t *m, u32 t, u32 v)
{
  bbr_minmax_sample_t val = { .t = t, .v = v };
  m->s[2] = m->s[1] = m->s[0] = val;
}

/* As the window slides, the second/third best samples may need to age out. */
static inline u32
bbr_minmax_subwin_update (bbr_minmax_t *m, u32 win, bbr_minmax_sample_t *val)
{
  u32 dt = val->t - m->s[0].t;

  if (PREDICT_FALSE (dt > win))
    {
      /* Primary sample is too old: promote the secondaries and re-seed the
       * newest from the incoming value. */
      m->s[0] = m->s[1];
      m->s[1] = m->s[2];
      m->s[2] = *val;
      if (PREDICT_FALSE (val->t - m->s[0].t > win))
	{
	  m->s[0] = m->s[1];
	  m->s[1] = m->s[2];
	  m->s[2] = *val;
	}
    }
  else if (PREDICT_FALSE (m->s[1].t == m->s[0].t && dt > win / 4))
    {
      /* Second sample passed 1/4 of the window without a third: split. */
      m->s[2] = m->s[1] = *val;
    }
  else if (PREDICT_FALSE (m->s[2].t == m->s[1].t && dt > win / 2))
    {
      m->s[2] = *val;
    }
  return m->s[0].v;
}

/* Update the running max over the window [t-win, t]; returns the new max. */
static inline u32
bbr_minmax_running_max (bbr_minmax_t *m, u32 win, u32 t, u32 meas)
{
  bbr_minmax_sample_t val = { .t = t, .v = meas };

  if (PREDICT_FALSE (val.v >= m->s[0].v ||     /* new max, or */
		     val.t - m->s[2].t > win)) /* everything stale */
    {
      bbr_minmax_reset (m, t, meas);
      return m->s[0].v;
    }

  if (val.v >= m->s[1].v)
    m->s[2] = m->s[1] = val;
  else if (val.v >= m->s[2].v)
    m->s[2] = val;

  return bbr_minmax_subwin_update (m, win, &val);
}

typedef struct
{
  bbr_minmax_t extra_acked;
  u64 bw_hi[2];
  f64 bw_lo;
  f64 bw_latest;
  f64 undo_bw_lo;
  f64 min_rtt;
  f64 min_rtt_stamp;
  f64 probe_rtt_min_delay;
  f64 probe_rtt_min_stamp;
  f64 probe_rtt_done_stamp;
  f64 pacing_rate;
  f64 ack_epoch_stamp;
  f64 cycle_stamp;
  f64 bw_probe_wait;
  f64 full_bw;
  u64 ack_epoch_acked;
  u64 next_round_delivered;
  u64 loss_round_delivered;
  u64 last_loss_counted;
  u32 inflight_hi;
  u32 inflight_lo;
  u32 inflight_latest;
  u32 undo_inflight_hi;
  u32 undo_inflight_lo;
  u32 prior_cwnd;
  u32 initial_cwnd;
  u32 round_count;
  u32 bw_probe_up_acked;
  u32 probe_up_acked_per_inc;
  u32 random_seed;
  u32 offload_budget;
  bbr_flag_t flags;
  u16 offload_mss;
  bbr_mode_t mode;
  bbr_probe_bw_phase_t probe_bw_phase;
  bbr_ack_phase_t ack_phase;
  bbr_undo_state_t undo_state;
  u8 full_bw_count;
  u8 drain_rounds;
  u8 bw_probe_up_rounds;
  u8 loss_events;
  u8 rounds_since_probe_up;
} bbr_data_t;

STATIC_ASSERT (sizeof (bbr_data_t) <= 240, "bbr state size");

typedef struct
{
  u32 state_index_plus_one;
} bbr_data_ref_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  bbr_data_t *states;
} bbr_worker_ctx_t;

typedef struct
{
  bbr_worker_ctx_t *wrk;
} bbr_main_t;

STATIC_ASSERT (sizeof (bbr_data_ref_t) <= TCP_CC_DATA_SZ, "bbr reference fits cc_data");

static_always_inline u8
bbr_has_flag (const bbr_data_t *bd, bbr_flag_t flag)
{
  return (bd->flags & flag) != 0;
}

static_always_inline u8
bbr_full_bw_now (const bbr_data_t *bd)
{
  return bd->full_bw_count >= BBR_FULL_BW_CNT;
}

static inline f64
bbr_now (tcp_connection_t *tc)
{
  return tcp_time_now_us (tc->c_thread_index);
}

static inline u8
bbr_has_rtt_estimate (tcp_connection_t *tc)
{
  return tc->mrtt_us > 0.0 && tc->mrtt_us < (f64) (u32) ~0;
}

static inline u8
bbr_sample_valid (tcp_ack_ctx_t *rs)
{
  return rs->delivered && rs->interval_time > 0.0;
}

static inline f64
bbr_sample_bw (tcp_ack_ctx_t *rs)
{
  return bbr_sample_valid (rs) ? (f64) rs->delivered / rs->interval_time : 0.0;
}

static inline f64
bbr_max_bw (bbr_data_t *bd)
{
  return (f64) clib_max (bd->bw_hi[0], bd->bw_hi[1]);
}

static inline f64
bbr_bw (bbr_data_t *bd)
{
  return clib_min (bbr_max_bw (bd), bd->bw_lo);
}

static inline u32
bbr_min_pipe_cwnd (tcp_connection_t *tc)
{
  return BBR_MIN_PIPE_PKTS * tc->snd_mss;
}

static inline u32
bbr_u32_bytes (f64 bytes)
{
  if (bytes >= (f64) BBR_INFLIGHT_INFINITY)
    return BBR_INFLIGHT_INFINITY;
  return bytes > 0.0 ? (u32) bytes : 0;
}

/* Round a byte target up to an integral number of SMSS-sized packets. */
static inline u32
bbr_packet_aligned (tcp_connection_t *tc, f64 bytes)
{
  u64 n_bytes, packets;

  if (bytes >= (f64) BBR_INFLIGHT_INFINITY)
    return BBR_INFLIGHT_INFINITY;

  n_bytes = bytes > 0.0 ? (u64) bytes : 0;
  packets = (n_bytes + tc->snd_mss - 1) / tc->snd_mss;
  if (packets > BBR_INFLIGHT_INFINITY / tc->snd_mss)
    return BBR_INFLIGHT_INFINITY;
  return packets * tc->snd_mss;
}

static inline u32
bbr_bdp_multiple_for_bw (tcp_connection_t *tc, bbr_data_t *bd, f64 bw, f64 gain)
{
  if (bd->min_rtt == BBR_BW_INFINITY || bw <= 0.0)
    return bd->initial_cwnd;
  return bbr_packet_aligned (tc, bw * bd->min_rtt * gain);
}

static inline u32
bbr_bdp_multiple (tcp_connection_t *tc, bbr_data_t *bd, f64 gain)
{
  return bbr_bdp_multiple_for_bw (tc, bd, bbr_bw (bd), gain);
}

static inline u32
bbr_send_quantum (tcp_connection_t *tc, f64 pacing_rate)
{
  u32 quantum;

  quantum = bbr_u32_bytes (pacing_rate * BBR_SEND_QUANTUM_INTERVAL);
  quantum = clib_min (quantum, BBR_SEND_QUANTUM_MAX);
  return clib_max (quantum, 2 * tc->snd_mss);
}

static inline u32
bbr_offload_budget (u32 quantum, f64 pacing_rate)
{
  u64 pipeline_bytes, min_budget, max_budget, quanta;

  /* Adapt model inflight to the local output pipeline without changing the
   * pacer's burst limits. */
  pipeline_bytes = bbr_u32_bytes (pacing_rate * BBR_OFFLOAD_BUDGET_INTERVAL);
  min_budget = BBR_OFFLOAD_QUANTA_MIN * (u64) quantum;
  if (pipeline_bytes <= min_budget)
    return (u32) min_budget;

  max_budget = BBR_OFFLOAD_QUANTA_MAX * (u64) quantum;
  if (pipeline_bytes > max_budget - quantum)
    return (u32) max_budget;

  quanta = (pipeline_bytes + quantum - 1) / quantum;
  return (u32) (quanta * quantum);
}

static inline void
bbr_update_offload_budget (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 quantum = bbr_send_quantum (tc, bd->pacing_rate);

  /* Keep output batching from constraining the model's inflight target. */
  bd->offload_budget = bbr_offload_budget (quantum, bd->pacing_rate);
  bd->offload_mss = tc->snd_mss;
}

static inline u32
bbr_quantization_budget (tcp_connection_t *tc, bbr_data_t *bd, u32 inflight)
{
  u64 budget = bd->offload_budget;

  budget = clib_max (budget, (u64) bbr_min_pipe_cwnd (tc));
  budget = clib_max (budget, (u64) inflight);
  if (bd->mode == BBR_PROBE_BW && bd->probe_bw_phase == BBR_BW_UP)
    budget += 2 * tc->snd_mss;
  return clib_min (budget, (u64) BBR_INFLIGHT_INFINITY);
}

static inline u32
bbr_inflight (tcp_connection_t *tc, bbr_data_t *bd, f64 gain)
{
  return bbr_quantization_budget (tc, bd, bbr_bdp_multiple (tc, bd, gain));
}

static inline u32
bbr_inflight_for_bw (tcp_connection_t *tc, bbr_data_t *bd, f64 bw, f64 gain)
{
  return bbr_quantization_budget (tc, bd, bbr_bdp_multiple_for_bw (tc, bd, bw, gain));
}

static inline u32
bbr_probe_rtt_cwnd (tcp_connection_t *tc, bbr_data_t *bd)
{
  return clib_max (bbr_bdp_multiple (tc, bd, BBR_PROBE_RTT_CWND_GAIN), bbr_min_pipe_cwnd (tc));
}

static inline u8
bbr_is_probe_bw (bbr_data_t *bd)
{
  return bd->mode == BBR_PROBE_BW;
}

static inline u8
bbr_is_probing_bw (bbr_data_t *bd)
{
  return bd->mode == BBR_STARTUP ||
	 (bd->mode == BBR_PROBE_BW &&
	  (bd->probe_bw_phase == BBR_BW_REFILL || bd->probe_bw_phase == BBR_BW_UP));
}

static inline void
bbr_start_round (tcp_connection_t *tc, bbr_data_t *bd)
{
  bd->next_round_delivered = tc->delivered;
}

static inline void
bbr_reset_full_bw (bbr_data_t *bd)
{
  bd->full_bw = 0.0;
  bd->full_bw_count = 0;
}

static inline void
bbr_reset_short_term_model (bbr_data_t *bd)
{
  bd->bw_lo = BBR_BW_INFINITY;
  bd->inflight_lo = BBR_INFLIGHT_INFINITY;
}

static inline void
bbr_reset_congestion_signals (bbr_data_t *bd)
{
  bd->flags &= ~(BBR_F_LOSS_IN_ROUND | BBR_F_LOSS_ROUND_HAD_LOSS | BBR_F_LOSS_EVENT_PENDING |
		 BBR_F_RECOVERY_IN_ROUND);
  bd->loss_events = 0;
  bd->bw_latest = 0.0;
  bd->inflight_latest = 0;
}

static inline void
bbr_enter_startup (bbr_data_t *bd)
{
  bd->mode = BBR_STARTUP;
}

static inline void
bbr_enter_drain (bbr_data_t *bd)
{
  bd->mode = BBR_DRAIN;
  bd->drain_rounds = 0;
}

static inline void
bbr_pick_probe_wait (bbr_data_t *bd)
{
  bd->rounds_since_probe_up = random_u32 (&bd->random_seed) & 1;
  bd->bw_probe_wait = BBR_PROBE_WAIT_BASE + BBR_PROBE_WAIT_RAND * random_f64 (&bd->random_seed);
}

static inline void
bbr_start_probe_bw_cruise (bbr_data_t *bd)
{
  bd->probe_bw_phase = BBR_BW_CRUISE;
}

static inline void
bbr_raise_inflight_hi_slope (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 shift = clib_min (bd->bw_probe_up_rounds, 30u);
  u32 growth = 1u << shift;

  bd->bw_probe_up_rounds = clib_min (bd->bw_probe_up_rounds + 1, 30u);
  bd->probe_up_acked_per_inc = clib_max (tc->cwnd / growth, (u32) tc->snd_mss);
}

static inline void
bbr_enter_probe_rtt (bbr_data_t *bd)
{
  bd->mode = BBR_PROBE_RTT;
}

static inline void
bbr_advance_max_bw_filter (bbr_data_t *bd)
{
  if (!bd->bw_hi[1])
    return;

  bd->bw_hi[0] = bd->bw_hi[1];
  bd->bw_hi[1] = 0;
}

static inline void
bbr_save_cwnd (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (!tcp_in_cong_recovery (tc) && bd->mode != BBR_PROBE_RTT)
    bd->prior_cwnd = tc->cwnd;
  else
    bd->prior_cwnd = clib_max (bd->prior_cwnd, tc->cwnd);
}

static inline void
bbr_save_state_upon_loss (tcp_connection_t *tc, bbr_data_t *bd)
{
  bbr_save_cwnd (tc, bd);
  bd->undo_state = BBR_UNDO_NONE;
  bd->undo_bw_lo = bd->bw_lo;
  bd->undo_inflight_lo = bd->inflight_lo;
  bd->undo_inflight_hi = bd->inflight_hi;
}

static_always_inline void
bbr_count_loss_event (bbr_data_t *bd)
{
  /* Samples exposed together form one loss-marking event. */
  if (PREDICT_FALSE (bbr_has_flag (bd, BBR_F_LOSS_EVENT_PENDING)) && bd->mode == BBR_STARTUP &&
      bd->loss_events < BBR_STARTUP_FULL_LOSS_CNT)
    bd->loss_events++;
  bd->flags &= ~BBR_F_LOSS_EVENT_PENDING;
}

static inline void
bbr_advance_latest_delivery_signals (bbr_data_t *bd, tcp_ack_ctx_t *rs, f64 sample_bw)
{
  if (!bbr_has_flag (bd, BBR_F_LOSS_ROUND_START))
    return;
  bd->bw_latest = sample_bw;
  bd->inflight_latest = rs->delivered;
  bd->loss_events = 0;
  bd->flags &= ~BBR_F_RECOVERY_IN_ROUND;
}

static inline void
bbr_adapt_lower_bounds (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (bbr_is_probing_bw (bd) || !bbr_has_flag (bd, BBR_F_LOSS_ROUND_HAD_LOSS))
    return;

  if (bd->bw_lo == BBR_BW_INFINITY)
    bd->bw_lo = bbr_max_bw (bd);
  if (bd->inflight_lo == BBR_INFLIGHT_INFINITY)
    bd->inflight_lo = tc->cwnd;

  bd->bw_lo = clib_max (bd->bw_latest, BBR_BETA * bd->bw_lo);
  bd->inflight_lo = clib_max (bd->inflight_latest, (u32) (BBR_BETA * bd->inflight_lo));
}

static inline u8
bbr_is_inflight_too_high (tcp_ack_ctx_t *rs)
{
  if (!rs->lost)
    return 0;
  return (f64) rs->lost > (f64) rs->tx_in_flight * BBR_LOSS_THRESH;
}

static inline void
bbr_check_startup_done (bbr_data_t *bd)
{
  ASSERT (bd->mode == BBR_STARTUP);
  if (bbr_has_flag (bd, BBR_F_FULL_BW_REACHED))
    bbr_enter_drain (bd);
}

static inline u32
bbr_inflight_with_headroom (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 headroom;

  if (bd->inflight_hi == BBR_INFLIGHT_INFINITY)
    return BBR_INFLIGHT_INFINITY;
  headroom = clib_max (tc->snd_mss, (u32) (BBR_HEADROOM * bd->inflight_hi));
  return clib_max (bd->inflight_hi - clib_min (headroom, bd->inflight_hi), bbr_min_pipe_cwnd (tc));
}

static inline u8
bbr_is_time_to_cruise (tcp_connection_t *tc, bbr_data_t *bd)
{
  return tcp_flight_size (tc) <= bbr_inflight_with_headroom (tc, bd) &&
	 tcp_flight_size (tc) <= bbr_inflight_for_bw (tc, bd, bbr_max_bw (bd), 1.0);
}

static inline u32
bbr_target_inflight (tcp_connection_t *tc, bbr_data_t *bd)
{
  return clib_min (bbr_bdp_multiple (tc, bd, 1.0), tc->cwnd);
}

static inline u8
bbr_is_time_to_probe_bw (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 reno_rounds;

  if (bbr_now (tc) > bd->cycle_stamp + bd->bw_probe_wait)
    return 1;

  reno_rounds = (bbr_target_inflight (tc, bd) + tc->snd_mss - 1) / tc->snd_mss;
  reno_rounds = clib_min (reno_rounds, BBR_RENO_ROUNDS_MAX);
  return bd->rounds_since_probe_up >= reno_rounds;
}

static inline void
bbr_restore_cwnd (tcp_connection_t *tc, bbr_data_t *bd)
{
  tc->cwnd = clib_max (tc->cwnd, bd->prior_cwnd);
}

static_always_inline f64
bbr_pacing_gain (const bbr_data_t *bd)
{
  if (bd->mode == BBR_STARTUP)
    return BBR_STARTUP_PACING_GAIN;
  if (bd->mode == BBR_DRAIN)
    return BBR_DRAIN_PACING_GAIN;
  if (bd->mode == BBR_PROBE_RTT)
    return 1.0;
  return bd->probe_bw_phase == BBR_BW_DOWN ? BBR_PROBE_DOWN_GAIN :
	 bd->probe_bw_phase == BBR_BW_UP   ? BBR_PROBE_UP_PACING_GAIN :
					     1.0;
}

static_always_inline f64
bbr_cwnd_gain (const bbr_data_t *bd)
{
  if (bd->mode == BBR_PROBE_RTT)
    return BBR_PROBE_RTT_CWND_GAIN;
  if (bd->mode == BBR_PROBE_BW && bd->probe_bw_phase == BBR_BW_UP)
    return BBR_PROBE_UP_CWND_GAIN;
  return BBR_DEFAULT_CWND_GAIN;
}

static inline u32
bbr_max_inflight (tcp_connection_t *tc, bbr_data_t *bd)
{
  u64 target = bbr_bdp_multiple (tc, bd, bbr_cwnd_gain (bd));

  target += bbr_minmax_get (&bd->extra_acked);
  return bbr_quantization_budget (tc, bd, clib_min (target, (u64) BBR_INFLIGHT_INFINITY));
}

static inline u32
bbr_bound_cwnd_for_model (tcp_connection_t *tc, bbr_data_t *bd, u32 cwnd)
{
  u32 cap = BBR_INFLIGHT_INFINITY;

  if (bbr_is_probe_bw (bd) && bd->probe_bw_phase != BBR_BW_CRUISE)
    cap = bd->inflight_hi;
  else if (bd->mode == BBR_PROBE_RTT ||
	   (bbr_is_probe_bw (bd) && bd->probe_bw_phase == BBR_BW_CRUISE))
    cap = bbr_inflight_with_headroom (tc, bd);

  cap = clib_min (cap, bd->inflight_lo);
  cap = clib_max (cap, bbr_min_pipe_cwnd (tc));
  return clib_min (cwnd, cap);
}

format_function_t format_tcp_bbr;

#endif /* SRC_VNET_TCP_TCP_BBR_H_ */
