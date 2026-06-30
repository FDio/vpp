/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_bbr.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/random.h>

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
#define BBR_TCP_OFFLOAD_QUANTA	   3

#define BBR_INFLIGHT_INFINITY ((u32) ~0)
#define BBR_BW_INFINITY	      CLIB_F64_MAX

typedef enum
{
  BBR_STARTUP,
  BBR_DRAIN,
  BBR_PROBE_BW,
  BBR_PROBE_RTT,
} bbr_mode_t;

typedef enum
{
  BBR_BW_DOWN,
  BBR_BW_CRUISE,
  BBR_BW_REFILL,
  BBR_BW_UP,
} bbr_probe_bw_phase_t;

typedef enum
{
  BBR_ACKS_INIT,
  BBR_ACKS_REFILLING,
  BBR_ACKS_PROBE_STARTING,
  BBR_ACKS_PROBE_FEEDBACK,
  BBR_ACKS_PROBE_STOPPING,
} bbr_ack_phase_t;

typedef enum
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
} bbr_flags_t;

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
  u32 rounds_since_probe_up;
  u32 bw_probe_up_acked;
  u32 probe_up_acked_per_inc;
  u32 random_seed;
  u32 flags;
  u8 mode;
  u8 probe_bw_phase;
  u8 ack_phase;
  u8 undo_state;
  u8 full_bw_count;
  u8 drain_rounds;
  u8 bw_probe_up_rounds;
  u8 loss_events;
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

static bbr_main_t bbr_main;

STATIC_ASSERT (sizeof (bbr_data_ref_t) <= TCP_CC_DATA_SZ, "bbr reference fits cc_data");

static inline bbr_data_t *
bbr_data (tcp_connection_t *tc)
{
  bbr_data_ref_t *ref = (bbr_data_ref_t *) tcp_cc_data (tc);
  bbr_worker_ctx_t *wrk = vec_elt_at_index (bbr_main.wrk, tc->c_thread_index);

  ASSERT (ref->state_index_plus_one != 0);
  return pool_elt_at_index (wrk->states, ref->state_index_plus_one - 1);
}

static_always_inline u8
bbr_has_flag (const bbr_data_t *bd, bbr_flags_t flag)
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
bbr_send_quantum (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 quantum;

  quantum = bbr_u32_bytes (bd->pacing_rate * BBR_SEND_QUANTUM_INTERVAL);
  quantum = clib_min (quantum, BBR_SEND_QUANTUM_MAX);
  quantum = clib_min (quantum, TRANSPORT_PACER_MAX_BURST);
  quantum = clib_max (quantum, 2 * tc->snd_mss);
  return clib_max (quantum, (u32) TRANSPORT_PACER_MIN_BURST);
}

static inline void
bbr_set_send_quantum (tcp_connection_t *tc, bbr_data_t *bd)
{
  /* VPP's pacer uses min_burst as its scheduling quantum. */
  tc->connection.pacer.min_burst = bbr_send_quantum (tc, bd);
}

static inline u32
bbr_quantization_budget (tcp_connection_t *tc, bbr_data_t *bd, u32 inflight)
{
  u64 budget = BBR_TCP_OFFLOAD_QUANTA * (u64) bbr_send_quantum (tc, bd);

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

static void
bbr_start_probe_bw_down (tcp_connection_t *tc, bbr_data_t *bd)
{
  bbr_reset_congestion_signals (bd);
  bd->probe_up_acked_per_inc = BBR_INFLIGHT_INFINITY;
  bbr_pick_probe_wait (bd);
  bd->cycle_stamp = bbr_now (tc);
  bd->ack_phase = BBR_ACKS_PROBE_STOPPING;
  bbr_start_round (tc, bd);
  bd->mode = BBR_PROBE_BW;
  bd->probe_bw_phase = BBR_BW_DOWN;
}

static inline void
bbr_start_probe_bw_cruise (bbr_data_t *bd)
{
  bd->probe_bw_phase = BBR_BW_CRUISE;
}

static void
bbr_start_probe_bw_refill (tcp_connection_t *tc, bbr_data_t *bd)
{
  bbr_reset_short_term_model (bd);
  bd->bw_probe_up_rounds = 0;
  bd->bw_probe_up_acked = 0;
  bd->flags &= ~BBR_F_PREV_PROBE_PRECAUTIONARY;
  bd->ack_phase = BBR_ACKS_REFILLING;
  bbr_start_round (tc, bd);
  bd->mode = BBR_PROBE_BW;
  bd->probe_bw_phase = BBR_BW_REFILL;
}

static inline void
bbr_raise_inflight_hi_slope (tcp_connection_t *tc, bbr_data_t *bd)
{
  u32 shift = clib_min (bd->bw_probe_up_rounds, 30u);
  u32 growth = 1u << shift;

  bd->bw_probe_up_rounds = clib_min (bd->bw_probe_up_rounds + 1, 30u);
  bd->probe_up_acked_per_inc = clib_max (tc->cwnd / growth, (u32) tc->snd_mss);
}

static void
bbr_start_probe_bw_up (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  bd->ack_phase = BBR_ACKS_PROBE_STARTING;
  bbr_start_round (tc, bd);
  bbr_reset_full_bw (bd);
  bd->full_bw = bbr_sample_bw (rs);
  bd->probe_bw_phase = BBR_BW_UP;
  bbr_raise_inflight_hi_slope (tc, bd);
}

static inline void
bbr_enter_probe_bw (tcp_connection_t *tc, bbr_data_t *bd)
{
  bbr_start_probe_bw_down (tc, bd);
}

static inline void
bbr_enter_probe_rtt (bbr_data_t *bd)
{
  bd->mode = BBR_PROBE_RTT;
}

static void
bbr_update_round (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  bd->flags &= ~BBR_F_ROUND_START;
  if (!bbr_sample_valid (rs) || rs->prior_delivered < bd->next_round_delivered)
    return;

  if (bd->mode == BBR_DRAIN && bd->drain_rounds < 4)
    bd->drain_rounds++;
  bbr_start_round (tc, bd);
  bd->round_count++;
  bd->rounds_since_probe_up++;
  bd->flags |= BBR_F_ROUND_START;
}

static inline void
bbr_advance_max_bw_filter (bbr_data_t *bd)
{
  bd->bw_hi[0] = bd->bw_hi[1];
  bd->bw_hi[1] = 0;
}

static void
bbr_update_max_bw (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs, f64 sample_bw)
{
  bbr_update_round (tc, bd, rs);
  if (sample_bw <= 0.0 || ((rs->flags & TCP_BTS_IS_APP_LIMITED) && sample_bw < bbr_max_bw (bd)))
    return;

  bd->bw_hi[1] = clib_max (bd->bw_hi[1], (u64) sample_bw);
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

/* Record loss-round state and coalesce loss samples until the next ACK or
 * recovery callback. */
static void
bbr_note_loss (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (tc->lost == bd->last_loss_counted)
    return;

  if (!bbr_has_flag (bd, BBR_F_LOSS_IN_ROUND))
    {
      bd->loss_round_delivered = tc->delivered;
      bbr_save_state_upon_loss (tc, bd);
    }

  bd->last_loss_counted = tc->lost;
  bd->flags |= BBR_F_LOSS_IN_ROUND | BBR_F_LOSS_EVENT_PENDING;
  if (tcp_in_fastrecovery (tc))
    bd->flags |= BBR_F_RECOVERY_IN_ROUND;
}

static_always_inline void
bbr_count_loss_event (bbr_data_t *bd)
{
  if (PREDICT_FALSE (bbr_has_flag (bd, BBR_F_LOSS_EVENT_PENDING)) && bd->mode == BBR_STARTUP &&
      bd->loss_events < BBR_STARTUP_FULL_LOSS_CNT)
    bd->loss_events++;
  bd->flags &= ~BBR_F_LOSS_EVENT_PENDING;
}

static void
bbr_update_latest_delivery_signals (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs,
				    f64 sample_bw)
{
  bd->flags &= ~(BBR_F_LOSS_ROUND_START | BBR_F_LOSS_ROUND_HAD_LOSS);
  bd->bw_latest = clib_max (bd->bw_latest, sample_bw);
  bd->inflight_latest = clib_max (bd->inflight_latest, rs->delivered);

  if (bbr_sample_valid (rs) && rs->prior_delivered >= bd->loss_round_delivered)
    {
      bd->loss_round_delivered = tc->delivered;
      bd->flags |= BBR_F_LOSS_ROUND_START;
      if (bbr_has_flag (bd, BBR_F_LOSS_IN_ROUND))
	bd->flags |= BBR_F_LOSS_ROUND_HAD_LOSS;
    }
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

static void
bbr_update_congestion_signals (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs,
			       f64 sample_bw)
{
  bbr_update_max_bw (tc, bd, rs, sample_bw);
  if (!bbr_has_flag (bd, BBR_F_LOSS_ROUND_START))
    return;
  bbr_adapt_lower_bounds (tc, bd);
  bd->flags &= ~BBR_F_LOSS_IN_ROUND;
}

static void
bbr_update_ack_aggregation (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  f64 expected, now;
  u64 extra;
  u32 filter_len;

  if (!rs->acked_and_sacked || bbr_bw (bd) <= 0.0)
    return;

  now = bbr_now (tc);
  expected = bbr_bw (bd) * (now - bd->ack_epoch_stamp);
  if ((f64) bd->ack_epoch_acked <= expected)
    {
      bd->ack_epoch_acked = 0;
      bd->ack_epoch_stamp = now;
      expected = 0.0;
    }

  bd->ack_epoch_acked += rs->acked_and_sacked;
  extra = bd->ack_epoch_acked > (u64) expected ? bd->ack_epoch_acked - (u64) expected : 0;
  extra = clib_min (extra, (u64) tc->cwnd);
  filter_len = bbr_has_flag (bd, BBR_F_FULL_BW_REACHED) ? BBR_EXTRA_ACKED_FILTER_LEN : 1;
  bbr_minmax_running_max (&bd->extra_acked, filter_len, bd->round_count, (u32) extra);
}

static void
bbr_check_full_bw_reached (bbr_data_t *bd, tcp_ack_ctx_t *rs, f64 sample_bw)
{
  if (bbr_full_bw_now (bd) || (rs->flags & TCP_BTS_IS_APP_LIMITED))
    return;

  if (sample_bw >= bd->full_bw * BBR_FULL_BW_THRESH)
    {
      bbr_reset_full_bw (bd);
      bd->full_bw = sample_bw;
      return;
    }

  if (!bbr_has_flag (bd, BBR_F_ROUND_START))
    return;

  bd->full_bw_count++;
  if (bbr_full_bw_now (bd))
    bd->flags |= BBR_F_FULL_BW_REACHED;
}

static inline u8
bbr_is_inflight_too_high (tcp_connection_t *tc, tcp_ack_ctx_t *rs)
{
  if (!rs->lost)
    return 0;
  if (!tcp_opts_sack_permitted (&tc->rcv_opts))
    return 1;
  return (f64) rs->lost > (f64) rs->tx_in_flight * BBR_LOSS_THRESH;
}

static void
bbr_check_startup_high_loss (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  u8 enough_events;

  if (bd->mode != BBR_STARTUP || !bbr_has_flag (bd, BBR_F_LOSS_ROUND_START) ||
      !bbr_has_flag (bd, BBR_F_LOSS_ROUND_HAD_LOSS) || !bbr_has_flag (bd, BBR_F_RECOVERY_IN_ROUND))
    return;

  enough_events =
    tcp_opts_sack_permitted (&tc->rcv_opts) ? bd->loss_events >= BBR_STARTUP_FULL_LOSS_CNT : 1;
  if (!enough_events || !bbr_is_inflight_too_high (tc, rs))
    return;

  bd->undo_state = BBR_UNDO_STARTUP;
  bd->flags |= BBR_F_FULL_BW_REACHED;
  bd->inflight_hi = clib_max (bbr_bdp_multiple (tc, bd, 1.0), bd->inflight_latest);
}

static inline void
bbr_check_startup_done (bbr_data_t *bd)
{
  if (bd->mode == BBR_STARTUP && bbr_has_flag (bd, BBR_F_FULL_BW_REACHED))
    bbr_enter_drain (bd);
}

static void
bbr_check_drain_done (tcp_connection_t *tc, bbr_data_t *bd)
{
  if (bd->mode == BBR_DRAIN &&
      (tcp_flight_size (tc) <= bbr_inflight (tc, bd, 1.0) || bd->drain_rounds > 3))
    bbr_enter_probe_bw (tc, bd);
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

static void
bbr_probe_inflight_hi_upward (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  u32 delta;

  if (!tcp_cc_is_cwnd_limited (tc, rs) || tc->cwnd < bd->inflight_hi ||
      bd->probe_up_acked_per_inc == BBR_INFLIGHT_INFINITY)
    return;

  bd->bw_probe_up_acked += rs->acked_and_sacked;
  if (bd->bw_probe_up_acked >= bd->probe_up_acked_per_inc)
    {
      delta = bd->bw_probe_up_acked / bd->probe_up_acked_per_inc;
      bd->bw_probe_up_acked -= delta * bd->probe_up_acked_per_inc;
      bd->inflight_hi =
	clib_min ((u64) bd->inflight_hi + (u64) delta * tc->snd_mss, (u64) BBR_INFLIGHT_INFINITY);
    }
  if (bbr_has_flag (bd, BBR_F_ROUND_START))
    bbr_raise_inflight_hi_slope (tc, bd);
}

static void
bbr_handle_inflight_too_high (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  u32 target;

  bd->flags |= BBR_F_PREV_PROBE_TOO_HIGH;
  bd->flags &= ~BBR_F_IS_BW_PROBE_SAMPLE;
  if (!(rs->flags & TCP_BTS_IS_APP_LIMITED))
    {
      target = bbr_u32_bytes (BBR_BETA * bbr_target_inflight (tc, bd));
      bd->inflight_hi =
	clib_max ((u32) clib_min (rs->tx_in_flight, (u64) BBR_INFLIGHT_INFINITY), target);
      bd->inflight_hi = clib_max (bd->inflight_hi, bbr_min_pipe_cwnd (tc));
    }

  if (bd->mode == BBR_PROBE_BW && bd->probe_bw_phase == BBR_BW_UP)
    {
      bd->undo_state = BBR_UNDO_PROBE_UP;
      bbr_start_probe_bw_down (tc, bd);
    }
}

static u32
bbr_inflight_at_loss (const tcp_ack_ctx_t *rs, u32 size)
{
  u64 inflight_prev, lost_prev;
  f64 loss_budget, lost_prefix;

  if (PREDICT_FALSE (size > rs->tx_in_flight || size > rs->lost))
    return BBR_INFLIGHT_INFINITY;

  inflight_prev = rs->tx_in_flight - size;
  lost_prev = rs->lost - size;
  /* Find the prefix of this sample where cumulative loss crossed the
   * tolerated fraction of inflight. */
  loss_budget = BBR_LOSS_THRESH * inflight_prev;
  lost_prefix =
    lost_prev >= loss_budget ? 0.0 : (loss_budget - lost_prev) / (1.0 - BBR_LOSS_THRESH);
  return bbr_u32_bytes (inflight_prev + lost_prefix);
}

static void
bbr_lost_sample (tcp_connection_t *tc, const tcp_cc_loss_sample_t *sample)
{
  bbr_data_t *bd = bbr_data (tc);
  tcp_ack_ctx_t rs = {
    .tx_in_flight = sample->tx_in_flight,
    .tx_lost = sample->tx_lost,
    .lost = tc->lost - sample->tx_lost,
    .flags = sample->flags,
  };

  bbr_note_loss (tc, bd);
  if (!bbr_has_flag (bd, BBR_F_IS_BW_PROBE_SAMPLE) || !bbr_is_inflight_too_high (tc, &rs))
    return;

  rs.tx_in_flight = bbr_inflight_at_loss (&rs, sample->bytes);
  bbr_handle_inflight_too_high (tc, bd, &rs);
}

/* Gate feedback to the packet-timed REFILL/UP interval. */
static u8
bbr_adapt_long_term_model (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  u8 too_high = bbr_has_flag (bd, BBR_F_IS_BW_PROBE_SAMPLE) && bbr_is_inflight_too_high (tc, rs);

  if (bd->ack_phase == BBR_ACKS_PROBE_STARTING && bbr_has_flag (bd, BBR_F_ROUND_START))
    {
      bd->ack_phase = BBR_ACKS_PROBE_FEEDBACK;
      bd->flags |= BBR_F_IS_BW_PROBE_SAMPLE;
      too_high = bbr_is_inflight_too_high (tc, rs);
    }

  if (bd->ack_phase == BBR_ACKS_PROBE_STOPPING && bbr_has_flag (bd, BBR_F_ROUND_START))
    {
      bd->flags &= ~BBR_F_IS_BW_PROBE_SAMPLE;
      bd->ack_phase = BBR_ACKS_INIT;
      if (bbr_is_probe_bw (bd) && !(rs->flags & TCP_BTS_IS_APP_LIMITED))
	bbr_advance_max_bw_filter (bd);
      if (bbr_is_probe_bw (bd) && bbr_has_flag (bd, BBR_F_PREV_PROBE_PRECAUTIONARY) &&
	  !bbr_has_flag (bd, BBR_F_PREV_PROBE_TOO_HIGH))
	{
	  bbr_start_probe_bw_refill (tc, bd);
	  return 1;
	}
    }

  if (too_high)
    {
      bbr_handle_inflight_too_high (tc, bd, rs);
      return 1;
    }

  if (bd->inflight_hi != BBR_INFLIGHT_INFINITY)
    {
      bd->inflight_hi =
	clib_max (bd->inflight_hi, (u32) clib_min (rs->tx_in_flight, (u64) BBR_INFLIGHT_INFINITY));
      if (bbr_is_probe_bw (bd) && bd->probe_bw_phase == BBR_BW_UP)
	bbr_probe_inflight_hi_upward (tc, bd, rs);
    }
  return 0;
}

static u8
bbr_is_time_to_go_down (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  if (bbr_has_flag (bd, BBR_F_PREV_PROBE_TOO_HIGH) && bd->inflight_hi != BBR_INFLIGHT_INFINITY &&
      tcp_flight_size (tc) >= bd->inflight_hi)
    {
      bd->flags |= BBR_F_PREV_PROBE_PRECAUTIONARY;
      return 1;
    }

  if (bd->inflight_hi != BBR_INFLIGHT_INFINITY && tcp_cc_is_cwnd_limited (tc, rs) &&
      tc->cwnd >= bd->inflight_hi)
    {
      bbr_reset_full_bw (bd);
      bd->full_bw = bbr_sample_bw (rs);
    }
  else if (bbr_full_bw_now (bd))
    return 1;
  return 0;
}

static void
bbr_update_probe_bw_cycle (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  if (!bbr_has_flag (bd, BBR_F_FULL_BW_REACHED))
    return;
  if (bbr_adapt_long_term_model (tc, bd, rs))
    return;
  if (!bbr_is_probe_bw (bd))
    return;

  switch ((bbr_probe_bw_phase_t) bd->probe_bw_phase)
    {
    case BBR_BW_DOWN:
      if (bbr_is_time_to_probe_bw (tc, bd))
	bbr_start_probe_bw_refill (tc, bd);
      else if (bbr_is_time_to_cruise (tc, bd))
	bbr_start_probe_bw_cruise (bd);
      break;
    case BBR_BW_CRUISE:
      if (bbr_is_time_to_probe_bw (tc, bd))
	bbr_start_probe_bw_refill (tc, bd);
      break;
    case BBR_BW_REFILL:
      if (bbr_has_flag (bd, BBR_F_ROUND_START))
	{
	  bd->flags |= BBR_F_IS_BW_PROBE_SAMPLE;
	  bbr_start_probe_bw_up (tc, bd, rs);
	}
      break;
    case BBR_BW_UP:
      if (bbr_is_time_to_go_down (tc, bd, rs))
	{
	  bd->flags &= ~BBR_F_PREV_PROBE_TOO_HIGH;
	  bbr_start_probe_bw_down (tc, bd);
	}
      break;
    }
}

static inline void
bbr_restore_cwnd (tcp_connection_t *tc, bbr_data_t *bd)
{
  tc->cwnd = clib_max (tc->cwnd, bd->prior_cwnd);
}

static u8
bbr_update_min_rtt (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  f64 now = bbr_now (tc);
  f64 rtt_sample = rs->rtt_time;
  u8 min_rtt_expired, probe_rtt_expired;

  /* BBR deliberately filters raw RTT samples from the latest-transmitted data
   * acknowledged by this ACK, independently of TCP's smoothed RTO estimate. */
  u8 rtt_valid = rtt_sample > 0.0 && rtt_sample < (f64) TCP_RTT_MAX * TCP_TICK &&
		 rs->acked_and_sacked && !(rs->flags & TCP_BTS_IS_RXT);

  probe_rtt_expired = now > bd->probe_rtt_min_stamp + BBR_PROBE_RTT_INTERVAL;
  if (rtt_valid && (rtt_sample < bd->probe_rtt_min_delay || probe_rtt_expired))
    {
      bd->probe_rtt_min_delay = rtt_sample;
      bd->probe_rtt_min_stamp = now;
    }

  min_rtt_expired = now > bd->min_rtt_stamp + BBR_MIN_RTT_FILTER_LEN;
  if (bd->probe_rtt_min_delay <= bd->min_rtt || min_rtt_expired)
    {
      bd->min_rtt = bd->probe_rtt_min_delay;
      bd->min_rtt_stamp = bd->probe_rtt_min_stamp;
    }
  return probe_rtt_expired;
}

static void
bbr_exit_probe_rtt (tcp_connection_t *tc, bbr_data_t *bd)
{
  bbr_reset_short_term_model (bd);
  if (bbr_has_flag (bd, BBR_F_FULL_BW_REACHED))
    {
      bbr_start_probe_bw_down (tc, bd);
      bbr_start_probe_bw_cruise (bd);
    }
  else
    bbr_enter_startup (bd);
}

static void
bbr_check_probe_rtt_done (tcp_connection_t *tc, bbr_data_t *bd)
{
  f64 now;

  if (!bd->probe_rtt_done_stamp)
    return;

  if (bbr_has_flag (bd, BBR_F_ROUND_START))
    bd->flags |= BBR_F_PROBE_RTT_ROUND_DONE;

  now = bbr_now (tc);
  if (!bbr_has_flag (bd, BBR_F_PROBE_RTT_ROUND_DONE) || now <= bd->probe_rtt_done_stamp)
    return;

  bd->probe_rtt_min_stamp = now;
  bbr_restore_cwnd (tc, bd);
  bbr_exit_probe_rtt (tc, bd);
}

static void
bbr_handle_probe_rtt (tcp_connection_t *tc, bbr_data_t *bd)
{
  f64 now = bbr_now (tc);
  u32 flight = tcp_flight_size (tc);

  tc->app_limited = tc->delivered + flight ?: 1;
  if (!bd->probe_rtt_done_stamp && flight <= bbr_probe_rtt_cwnd (tc, bd))
    {
      bd->probe_rtt_done_stamp = now + BBR_PROBE_RTT_DURATION;
      bd->flags &= ~BBR_F_PROBE_RTT_ROUND_DONE;
      bbr_start_round (tc, bd);
    }
  else if (bd->probe_rtt_done_stamp)
    bbr_check_probe_rtt_done (tc, bd);
}

static void
bbr_check_probe_rtt (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs, u8 probe_rtt_expired)
{
  if (bd->mode != BBR_PROBE_RTT && probe_rtt_expired && !bbr_has_flag (bd, BBR_F_IDLE_RESTART))
    {
      bbr_enter_probe_rtt (bd);
      bbr_save_cwnd (tc, bd);
      bd->probe_rtt_done_stamp = 0.0;
      bd->ack_phase = BBR_ACKS_PROBE_STOPPING;
      bbr_start_round (tc, bd);
    }
  if (bd->mode == BBR_PROBE_RTT)
    bbr_handle_probe_rtt (tc, bd);
  if (rs->delivered)
    bd->flags &= ~BBR_F_IDLE_RESTART;
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

static f64
bbr_initial_pacing_rate (tcp_connection_t *tc, bbr_data_t *bd)
{
  f64 rtt = (f64) tc->srtt * TCP_TICK;

  if (!bbr_has_rtt_estimate (tc) || rtt <= 0.0)
    rtt = 0.001;
  return BBR_STARTUP_PACING_GAIN * bd->initial_cwnd / rtt;
}

static void
bbr_set_pacing_rate_with_gain (tcp_connection_t *tc, bbr_data_t *bd, f64 gain)
{
  f64 rate;

  if (!bbr_has_flag (bd, BBR_F_HAS_SEEN_RTT) && bbr_has_rtt_estimate (tc))
    {
      bd->pacing_rate = bbr_initial_pacing_rate (tc, bd);
      bd->flags |= BBR_F_HAS_SEEN_RTT;
    }

  if (bbr_bw (bd) <= 0.0)
    {
      if (bd->pacing_rate <= 0.0)
	bd->pacing_rate = bbr_initial_pacing_rate (tc, bd);
      return;
    }

  rate = gain * bbr_bw (bd) * BBR_PACING_MARGIN;
  if (bbr_has_flag (bd, BBR_F_FULL_BW_REACHED) || rate > bd->pacing_rate)
    bd->pacing_rate = rate;
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

static void
bbr_set_cwnd (tcp_connection_t *tc, bbr_data_t *bd, tcp_ack_ctx_t *rs)
{
  u32 target = bbr_max_inflight (tc, bd);
  u64 grown;

  if (bbr_has_flag (bd, BBR_F_FULL_BW_REACHED))
    {
      grown = (u64) tc->cwnd + rs->acked_and_sacked;
      tc->cwnd = clib_min (grown, (u64) target);
    }
  else if (tc->cwnd < target || tc->delivered < bd->initial_cwnd)
    tc->cwnd = clib_min ((u64) tc->cwnd + rs->acked_and_sacked, (u64) BBR_INFLIGHT_INFINITY);

  tc->cwnd = clib_max (tc->cwnd, bbr_min_pipe_cwnd (tc));
  if (bd->mode == BBR_PROBE_RTT)
    tc->cwnd = clib_min (tc->cwnd, bbr_probe_rtt_cwnd (tc, bd));
  tc->cwnd = bbr_bound_cwnd_for_model (tc, bd, tc->cwnd);
  tc->cwnd = clib_min (tc->cwnd, tc->tx_fifo_size);
}

static void
bbr_update (tcp_connection_t *tc, tcp_ack_ctx_t *rs)
{
  bbr_data_t *bd = bbr_data (tc);
  f64 sample_bw = bbr_sample_bw (rs);
  u8 probe_rtt_expired;

  bbr_note_loss (tc, bd);
  bbr_count_loss_event (bd);
  bbr_update_latest_delivery_signals (tc, bd, rs, sample_bw);
  bbr_update_congestion_signals (tc, bd, rs, sample_bw);
  bbr_update_ack_aggregation (tc, bd, rs);
  bbr_check_full_bw_reached (bd, rs, sample_bw);
  bbr_check_startup_high_loss (tc, bd, rs);
  bbr_check_startup_done (bd);
  bbr_check_drain_done (tc, bd);
  bbr_update_probe_bw_cycle (tc, bd, rs);
  probe_rtt_expired = bbr_update_min_rtt (tc, bd, rs);
  bbr_check_probe_rtt (tc, bd, rs, probe_rtt_expired);
  bbr_advance_latest_delivery_signals (bd, rs, sample_bw);
  bbr_set_pacing_rate_with_gain (tc, bd, bbr_pacing_gain (bd));
  bbr_set_send_quantum (tc, bd);
  bbr_set_cwnd (tc, bd, rs);
}

static void
bbr_rcv_ack (tcp_connection_t *tc, tcp_ack_ctx_t *rs)
{
  bbr_update (tc, rs);
}

static void
bbr_rcv_cong_ack (tcp_connection_t *tc, tcp_cc_ack_t ack_type, tcp_ack_ctx_t *rs)
{
  bbr_update (tc, rs);
}

static void
bbr_congestion (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);

  bbr_note_loss (tc, bd);
  bbr_count_loss_event (bd);
  if (!bbr_has_flag (bd, BBR_F_LOSS_IN_ROUND))
    bbr_save_state_upon_loss (tc, bd);
  if (tcp_in_fastrecovery (tc))
    bd->flags |= BBR_F_RECOVERY_IN_ROUND;
}

static void
bbr_loss (tcp_connection_t *tc)
{
  bbr_note_loss (tc, bbr_data (tc));
  tc->cwnd = tcp_loss_wnd (tc);
}

static void
bbr_recovered (tcp_connection_t *tc)
{
  bbr_restore_cwnd (tc, bbr_data (tc));
}

static void
bbr_undo_recovery (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);

  bbr_restore_cwnd (tc, bd);
  bd->flags &= ~BBR_F_LOSS_IN_ROUND;
  bbr_reset_full_bw (bd);
  bd->bw_lo = clib_max (bd->bw_lo, bd->undo_bw_lo);
  bd->inflight_lo = clib_max (bd->inflight_lo, bd->undo_inflight_lo);
  bd->inflight_hi = clib_max (bd->inflight_hi, bd->undo_inflight_hi);

  if (bd->undo_state == BBR_UNDO_STARTUP && bd->mode != BBR_STARTUP)
    {
      bd->flags &= ~BBR_F_FULL_BW_REACHED;
      if (bd->mode != BBR_PROBE_RTT)
	bbr_enter_startup (bd);
    }
  else if (bd->undo_state == BBR_UNDO_PROBE_UP &&
	   (bd->mode != BBR_PROBE_BW || bd->probe_bw_phase != BBR_BW_UP) &&
	   bd->mode != BBR_PROBE_RTT)
    bbr_start_probe_bw_refill (tc, bd);
  bd->undo_state = BBR_UNDO_NONE;
}

static void
bbr_event (tcp_connection_t *tc, tcp_cc_event_t evt)
{
  bbr_data_t *bd = bbr_data (tc);

  if (evt != TCP_CC_EVT_START_TX || tcp_flight_size (tc) || !tc->app_limited)
    return;

  bd->flags |= BBR_F_IDLE_RESTART;
  bd->ack_epoch_stamp = bbr_now (tc);
  bd->ack_epoch_acked = 0;
  if (bbr_is_probe_bw (bd))
    {
      bbr_set_pacing_rate_with_gain (tc, bd, 1.0);
      bbr_set_send_quantum (tc, bd);
    }
  else if (bd->mode == BBR_PROBE_RTT)
    bbr_check_probe_rtt_done (tc, bd);
}

static u64
bbr_get_pacing_rate (tcp_connection_t *tc)
{
  bbr_data_t *bd = bbr_data (tc);

  if (!bbr_has_flag (bd, BBR_F_HAS_SEEN_RTT) && bbr_has_rtt_estimate (tc))
    {
      bd->pacing_rate = bbr_initial_pacing_rate (tc, bd);
      bd->flags |= BBR_F_HAS_SEEN_RTT;
    }
  else if (bd->pacing_rate <= 0.0)
    bd->pacing_rate = bbr_initial_pacing_rate (tc, bd);
  bbr_set_send_quantum (tc, bd);
  return clib_max ((u64) bd->pacing_rate, 1ULL);
}

static int
bbr_cong_control (tcp_connection_t *tc)
{
  return tcp_available_cc_snd_space (tc);
}

static void
bbr_conn_init (tcp_connection_t *tc)
{
  bbr_data_ref_t *ref = (bbr_data_ref_t *) tcp_cc_data (tc);
  bbr_worker_ctx_t *wrk = vec_elt_at_index (bbr_main.wrk, tc->c_thread_index);
  bbr_data_t *bd;
  f64 now;

  pool_get_zero (wrk->states, bd);
  ref->state_index_plus_one = bd - wrk->states + 1;

  now = bbr_now (tc);
  bd->initial_cwnd = tcp_initial_cwnd (tc);
  bd->min_rtt = BBR_BW_INFINITY;
  if (bbr_has_rtt_estimate (tc))
    {
      bd->flags |= BBR_F_HAS_SEEN_RTT;
      bd->min_rtt = tc->mrtt_us;
    }
  bd->min_rtt_stamp = now;
  bd->probe_rtt_min_delay = BBR_BW_INFINITY;
  bd->probe_rtt_min_stamp = now;
  bd->ack_epoch_stamp = now;
  bd->next_round_delivered = tc->delivered;
  bd->loss_round_delivered = tc->delivered;
  bd->last_loss_counted = tc->lost;
  bd->inflight_hi = BBR_INFLIGHT_INFINITY;
  bd->probe_up_acked_per_inc = BBR_INFLIGHT_INFINITY;
  bd->random_seed = (u32) (tc->iss ^ tc->c_c_index ^ tc->c_thread_index);
  bbr_reset_short_term_model (bd);
  bbr_reset_congestion_signals (bd);
  bbr_reset_full_bw (bd);
  bbr_minmax_reset (&bd->extra_acked, 0, 0);
  bbr_enter_startup (bd);
  bd->pacing_rate = bbr_initial_pacing_rate (tc, bd);
  bbr_set_send_quantum (tc, bd);

  tc->cwnd = bd->initial_cwnd;
  tc->ssthresh = BBR_INFLIGHT_INFINITY;
}

static void
bbr_conn_cleanup (tcp_connection_t *tc)
{
  bbr_data_ref_t *ref = (bbr_data_ref_t *) tcp_cc_data (tc);
  bbr_worker_ctx_t *wrk = vec_elt_at_index (bbr_main.wrk, tc->c_thread_index);

  if (ref->state_index_plus_one)
    pool_put_index (wrk->states, ref->state_index_plus_one - 1);
  ref->state_index_plus_one = 0;
}

u8 *
format_tcp_bbr (u8 *s, va_list *args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  bbr_data_t *bd = bbr_data (tc);

  return format (s,
		 "state %u/%u ack_phase %u round %u bw %.3f/%.3fMbit/s "
		 "min_rtt %.3fms pace %.3fMbit/s inflight hi/lo %u/%u latest %u "
		 "loss %u/%u",
		 bd->mode, bd->probe_bw_phase, bd->ack_phase, bd->round_count, bbr_bw (bd) * 8e-6,
		 bbr_max_bw (bd) * 8e-6, bd->min_rtt * 1e3, bd->pacing_rate * 8e-6, bd->inflight_hi,
		 bd->inflight_lo, bd->inflight_latest, bd->loss_events,
		 bbr_has_flag (bd, BBR_F_LOSS_IN_ROUND));
}

const static tcp_cc_algorithm_t tcp_bbr = {
  .name = "bbr",
  .flags = TCP_CC_ALGO_F_BYTE_TRACKER,
  .init = bbr_conn_init,
  .cleanup = bbr_conn_cleanup,
  .rcv_ack = bbr_rcv_ack,
  .rcv_cong_ack = bbr_rcv_cong_ack,
  .congestion = bbr_congestion,
  .loss = bbr_loss,
  .recovered = bbr_recovered,
  .undo_recovery = bbr_undo_recovery,
  .event = bbr_event,
  .lost_sample = bbr_lost_sample,
  .get_pacing_rate = bbr_get_pacing_rate,
  .cong_control = bbr_cong_control,
};

clib_error_t *
tcp_bbr_init (vlib_main_t *vm)
{
  vec_validate_aligned (bbr_main.wrk, vlib_get_n_threads () - 1, CLIB_CACHE_LINE_BYTES);
  tcp_cc_algo_register (TCP_CC_BBR, &tcp_bbr);
  return 0;
}

VLIB_INIT_FUNCTION (tcp_bbr_init);
