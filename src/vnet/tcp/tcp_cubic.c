/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <math.h>

#define beta_cubic 	0.7
#define cubic_c		0.4
#define west_const 	(3 * (1 - beta_cubic) / (1 + beta_cubic))

/* K in 2^-20 s ticks, u32 covers the max K of ~2207 s */
#define CUBIC_K_SCALE (1U << 20)

/* RFC 9406 recommended constants, RTTs in TCP_TICK units */
#define HYSTART_MIN_RTT_THRESH	   (4 * THZ / 1000)
#define HYSTART_MAX_RTT_THRESH	   (16 * THZ / 1000)
#define HYSTART_MIN_RTT_DIVISOR	   8
#define HYSTART_N_RTT_SAMPLE	   8
#define HYSTART_CSS_GROWTH_DIVISOR 4
#define HYSTART_CSS_ROUNDS	   5
#define HYSTART_UNPACED_ACK_LIMIT  8

typedef struct cubic_cfg_
{
  u8 fast_convergence;
  u8 hystart;
  u8 hystart_css;
  u32 ssthresh;
} cubic_cfg_t;

static cubic_cfg_t cubic_cfg = {
  .fast_convergence = 1,
  .hystart = 1,
  .hystart_css = 1,
  .ssthresh = 0x7FFFFFFFU,
};

typedef enum
{
  CUBIC_MODE_AVOIDANCE,
  CUBIC_MODE_HYSTART,
  CUBIC_MODE_CSS,
} cubic_mode_t;

typedef struct cubic_data_
{
  /* HyStart++ and curve state are never live at the same time */
  union
  {
    struct
    {
      /** Epoch start, negative if paused */
      f64 t_start;

      /** Time to reach w_max, in 2^-20 s ticks */
      u32 K_ticks;

      /** Inflection point, in snd_mss segments */
      u32 w_max;

      /** w_max snapshot taken at congestion entry */
      u32 prev_w_max;
    } __clib_packed;

    struct
    {
      /** Min rtts in TCP_TICK units, 0 is infinity */
      u32 last_round_min_rtt;
      u32 current_round_min_rtt;

      /** Current round end sequence */
      u32 window_end;

      u8 rtt_sample_count;

      /** Overlaps prev_w_max, kept by congestion for undo */
      u32 css_baseline_min_rtt;
    };
  };

  u8 mode;
  u8 prev_mode;

  /** Not in the union, so it survives congestion */
  u8 css_round_count;

} __clib_packed cubic_data_t;

STATIC_ASSERT (sizeof (cubic_data_t) <= TCP_CC_DATA_SZ, "cubic data len");
STATIC_ASSERT (STRUCT_OFFSET_OF (cubic_data_t, css_baseline_min_rtt) ==
		 STRUCT_OFFSET_OF (cubic_data_t, prev_w_max),
	       "css baseline must survive congestion");

static inline f64
cubic_time (clib_thread_index_t thread_index)
{
  return tcp_time_now_us (thread_index);
}

/* t_start normally contains an absolute time. Negating the elapsed epoch
 * time, with a one-second bias, lets us retain both the paused state and the
 * curve position without growing the per-connection CC state. */
#define CUBIC_PAUSED_EPOCH_BIAS 1.0

static inline u8
cubic_epoch_is_paused (const cubic_data_t *cd)
{
  return cd->t_start < 0;
}

static inline void
cubic_pause_epoch (cubic_data_t *cd, f64 now)
{
  f64 elapsed;

  if (cubic_epoch_is_paused (cd))
    return;

  elapsed = clib_max (now - cd->t_start, 0.0);
  cd->t_start = -(elapsed + CUBIC_PAUSED_EPOCH_BIAS);
}

static inline void
cubic_resume_epoch (cubic_data_t *cd, f64 now)
{
  ASSERT (cubic_epoch_is_paused (cd));
  cd->t_start = clib_min (now + cd->t_start + CUBIC_PAUSED_EPOCH_BIAS, now);
}

/**
 * RFC 8312 Eq. 1
 *
 * CUBIC window increase function. Time t is provided in seconds.
 */
static inline u64
W_cubic (cubic_data_t * cd, f64 t)
{
  f64 diff = t - (f64) cd->K_ticks / CUBIC_K_SCALE;

  /* W_cubic(t) = C*(t-K)^3 + W_max */
  return cubic_c * diff * diff * diff + cd->w_max;
}

/**
 * RFC 8312 Eq. 2. Returns K in 2^-20 second ticks.
 */
static inline u32
K_cubic (cubic_data_t *cd, f64 wnd)
{
  /* K = cubic_root(W_max*(1-beta_cubic)/C)
   * Because the current window may be less than W_max * beta_cubic because
   * of fast convergence, we pass it as parameter, in unrounded segments */
  return pow (clib_max (cd->w_max - wnd, 0.0) / cubic_c, 1 / 3.0) * CUBIC_K_SCALE;
}

/** Exit slow start without loss, cwnd rounded to the segments sent */
static void
cubic_hystart_lossless_exit (tcp_connection_t *tc, cubic_data_t *cd)
{
  tc->cwnd -= tc->cwnd % tc->snd_mss;
  tc->ssthresh = tc->cwnd;
  tc->cwnd_acc_bytes = 0;
  cd->mode = CUBIC_MODE_AVOIDANCE;
  cd->t_start = cubic_time (tc->c_thread_index);
  cd->K_ticks = 0;
  cd->w_max = tc->cwnd / tc->snd_mss;
}

/** Returns 0 if cubic avoidance must also process the ack */
static u8
cubic_hystart_rcv_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac, cubic_data_t *cd)
{
  u32 bytes_acked, rtt, rtt_thresh;

  /* Configured ssthresh reached */
  if (!tcp_in_slowstart (tc))
    {
      cubic_hystart_lossless_exit (tc, cd);
      return 0;
    }

  if (ac->bytes_acked)
    {
      /* Marker acked while drained, rearm to avoid an empty round */
      if (seq_geq (tc->snd_una - ac->bytes_acked, cd->window_end))
	cd->window_end = tc->snd_nxt;

      if (seq_geq (tc->snd_una, cd->window_end))
	{
	  cd->last_round_min_rtt = cd->current_round_min_rtt;
	  cd->current_round_min_rtt = 0;
	  cd->rtt_sample_count = 0;
	  cd->window_end = tc->snd_nxt;

	  /* Partial CSS round counts (RFC 9406) */
	  if (cd->mode == CUBIC_MODE_CSS && ++cd->css_round_count >= HYSTART_CSS_ROUNDS)
	    {
	      cubic_hystart_lossless_exit (tc, cd);
	      /* Credit this ack in avoidance */
	      return 0;
	    }
	}
    }

  /* Per ack growth limit only if unpaced (RFC 9406) */
  if (tc->cwnd < tc->tx_fifo_size && tcp_cc_is_cwnd_limited (tc, ac))
    {
      bytes_acked = ac->acked_and_sacked;
      if (!transport_connection_is_tx_paced (&tc->connection))
	bytes_acked = clib_min (bytes_acked, HYSTART_UNPACED_ACK_LIMIT * tc->snd_mss);

      if (cd->mode == CUBIC_MODE_CSS)
	{
	  tc->cwnd_acc_bytes += bytes_acked;
	  tc->cwnd += tc->cwnd_acc_bytes / HYSTART_CSS_GROWTH_DIVISOR;
	  tc->cwnd_acc_bytes %= HYSTART_CSS_GROWTH_DIVISOR;
	}
      else
	tc->cwnd += bytes_acked;
    }

  /* Sample cumulative acks, even if cwnd did not grow */
  if (!ac->bytes_acked || ac->rtt_time <= 0)
    return 1;

  rtt = clib_max ((u32) (ac->rtt_time * THZ), 1);
  if (!cd->current_round_min_rtt || rtt < cd->current_round_min_rtt)
    cd->current_round_min_rtt = rtt;
  if (cd->rtt_sample_count != (u8) ~0)
    cd->rtt_sample_count++;

  if (cd->rtt_sample_count < HYSTART_N_RTT_SAMPLE)
    return 1;

  if (cd->mode == CUBIC_MODE_CSS)
    {
      if (cd->current_round_min_rtt < cd->css_baseline_min_rtt)
	{
	  cd->mode = CUBIC_MODE_HYSTART;
	  cd->css_baseline_min_rtt = 0;
	  cd->css_round_count = 0;
	  tc->cwnd_acc_bytes = 0;
	}
      return 1;
    }

  if (!cd->last_round_min_rtt)
    return 1;

  rtt_thresh = clib_clamp (cd->last_round_min_rtt / HYSTART_MIN_RTT_DIVISOR, HYSTART_MIN_RTT_THRESH,
			   HYSTART_MAX_RTT_THRESH);
  if (cd->current_round_min_rtt >= cd->last_round_min_rtt + rtt_thresh)
    {
      if (!cubic_cfg.hystart_css)
	{
	  cubic_hystart_lossless_exit (tc, cd);
	  /* This ack already grew cwnd */
	  return 1;
	}
      cd->css_baseline_min_rtt = cd->current_round_min_rtt;
      cd->css_round_count = 0;
      cd->mode = CUBIC_MODE_CSS;
      tc->cwnd_acc_bytes = 0;
    }

  return 1;
}

/**
 * RFC 8312 Eq. 4
 *
 * Estimates the window size of AIMD(alpha_aimd, beta_aimd) for
 * alpha_aimd=3*(1-beta_cubic)/(1+beta_cubic) and beta_aimd=beta_cubic.
 * Time (t) and rtt should be provided in seconds. As per RFC 9438 Sec. 4.3, the estimate starts
 * from cwnd_epoch, i.e., W_cubic(0).
 */
static inline u32
W_est (cubic_data_t *cd, f64 t, f64 rtt)
{
  f64 k = (f64) cd->K_ticks / CUBIC_K_SCALE;

  /* W_est(t) = cwnd_epoch+[3*(1-beta_cubic)/(1+beta_cubic)]*(t/RTT), with
   * cwnd_epoch = W_cubic(0) = W_max-C*K^3, unrounded */
  return cd->w_max - cubic_c * k * k * k + west_const * (t / rtt);
}

static void
cubic_congestion (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  u32 old_w_max, w_max;

  cd->prev_mode = cd->mode;
  old_w_max = cd->mode == CUBIC_MODE_AVOIDANCE ? cd->w_max : 0;
  cd->mode = CUBIC_MODE_AVOIDANCE;

  /* Leaving HyStart++, keep prev_w_max as it holds the CSS baseline */
  if (cd->prev_mode != CUBIC_MODE_AVOIDANCE)
    {
      cd->t_start = cubic_time (tc->c_thread_index);
      cd->K_ticks = 0;
    }
  else
    {
      /* For spurious retransmit undo (RFC 9438 Sec. 4.9.2) */
      cd->prev_w_max = old_w_max;
    }

  w_max = tc->cwnd / tc->snd_mss;
  if (cubic_cfg.fast_convergence && w_max < old_w_max)
    w_max = w_max * ((1.0 + beta_cubic) / 2.0);

  cd->w_max = w_max;
  tc->ssthresh = clib_max (tc->cwnd * beta_cubic, 2 * tc->snd_mss);
  tc->cwnd = tc->ssthresh;
}

static void
cubic_loss (tcp_connection_t *tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);

  tc->cwnd = tcp_loss_wnd (tc);
  cd->t_start = cubic_time (tc->c_thread_index);
  cd->K_ticks = 0;
  /* Use the once-per-event slow-start threshold as the post-timeout w_max so
   * consecutive RTOs do not collapse it further with the loss window. */
  cd->w_max = tc->ssthresh / tc->snd_mss;
}

static void
cubic_recovered (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);

  if (tcp_in_recovery (tc))
    return;

  cd->t_start = cubic_time (tc->c_thread_index);
  tc->cwnd = tc->ssthresh;
  cd->K_ticks = K_cubic (cd, (f64) tc->cwnd / tc->snd_mss);
}

/* Spurious retransmit detected: the cc layer has already restored
 * cwnd/ssthresh to their pre-congestion values, so also undo the cubic
 * state changed on congestion entry (RFC 9438 Sec. 4.9.2). */
static void
cubic_undo_recovery (tcp_connection_t *tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);

  /* Resume the prior mode with fresh rounds */
  if (cd->prev_mode != CUBIC_MODE_AVOIDANCE)
    {
      cd->last_round_min_rtt = 0;
      cd->current_round_min_rtt = 0;
      cd->rtt_sample_count = 0;
      cd->window_end = tc->snd_nxt;
      cd->mode = cd->prev_mode;
      cd->prev_mode = CUBIC_MODE_AVOIDANCE;
      tc->cwnd_acc_bytes = 0;
      return;
    }

  f64 wnd = (f64) tc->cwnd / tc->snd_mss;

  cd->w_max = cd->prev_w_max;
  cd->t_start = cubic_time (tc->c_thread_index);
  /* Convex epoch if the restored window already reached w_max */
  cd->K_ticks = (wnd < cd->w_max) ? K_cubic (cd, wnd) : 0;
  cd->prev_mode = CUBIC_MODE_AVOIDANCE;
}

static void
cubic_cwnd_accumulate (tcp_connection_t *tc, u32 thresh, u32 bytes_acked)
{
  /* We just updated the threshold and don't know how large the previous
   * one was. Still, optimistically increase cwnd by one segment and
   * clear the accumulated bytes. */
  if (tc->cwnd_acc_bytes > thresh)
    {
      tc->cwnd += tc->snd_mss;
      tc->cwnd_acc_bytes = 0;
    }

  tcp_cwnd_accumulate (tc, thresh, bytes_acked);
}

static void
cubic_rcv_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  u64 w_cubic, w_aimd;
  f64 now, t, rtt_sec;
  u32 thresh;

  if (cd->mode != CUBIC_MODE_AVOIDANCE && cubic_hystart_rcv_ack (tc, ac, cd))
    return;

  now = cubic_time (tc->c_thread_index);

  /* RFC 9438 Sec. 4.2 excludes periods in which cwnd is not updated because
   * the flow is application-limited. A local tx-fifo ceiling has the same
   * effect and must not allow the cubic clock to run ahead either. */
  if (!tcp_cc_is_cwnd_limited (tc, ac) || tc->cwnd >= tc->tx_fifo_size)
    {
      cubic_pause_epoch (cd, now);
      return;
    }

  if (cubic_epoch_is_paused (cd))
    cubic_resume_epoch (cd, now);

  if (tcp_in_slowstart (tc))
    {
      tc->cwnd += ac->acked_and_sacked;
      return;
    }

  t = now - cd->t_start;
  rtt_sec = clib_min (tc->mrtt_us, (f64) tc->srtt * TCP_TICK);

  w_cubic = W_cubic (cd, t + rtt_sec) * tc->snd_mss;
  w_aimd = (u64) W_est (cd, t, rtt_sec) * tc->snd_mss;
  if (w_cubic < w_aimd)
    {
      cubic_cwnd_accumulate (tc, tc->cwnd, ac->acked_and_sacked);
    }
  else
    {
      if (w_cubic > tc->cwnd)
	{
	  /* For NewReno and slow start, we increment cwnd based on the
	   * number of bytes acked, not the number of acks received. In
	   * particular, for NewReno we increment the cwnd by 1 snd_mss
	   * only after we accumulate 1 cwnd of acked bytes (RFC 3465).
	   *
	   * For Cubic, as per RFC 8312 we should increment cwnd by
	   * (w_cubic - cwnd)/cwnd for each ack. Instead of using that,
	   * we compute the number of packets that need to be acked
	   * before adding snd_mss to cwnd and compute the threshold
	   */
	  thresh = (tc->snd_mss * tc->cwnd) / (w_cubic - tc->cwnd);

	  /* Make sure we don't increase cwnd more often than every segment */
	  thresh = clib_max (thresh, tc->snd_mss);
	}
      else
	{
	  /* Practically we can't increment so just inflate threshold */
	  thresh = 50 * tc->cwnd;
	}
      cubic_cwnd_accumulate (tc, thresh, ac->acked_and_sacked);
    }
}

static int
cubic_conn_init (tcp_connection_t *tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  tc->ssthresh = cubic_cfg.ssthresh;
  tc->cwnd = tcp_initial_cwnd (tc);
  cd->mode = cubic_cfg.hystart && tcp_in_slowstart (tc) ? CUBIC_MODE_HYSTART : CUBIC_MODE_AVOIDANCE;
  cd->prev_mode = CUBIC_MODE_AVOIDANCE;

  if (cd->mode == CUBIC_MODE_HYSTART)
    {
      cd->last_round_min_rtt = 0;
      cd->current_round_min_rtt = 0;
      cd->css_baseline_min_rtt = 0;
      cd->window_end = tc->snd_nxt;
      cd->rtt_sample_count = 0;
      cd->css_round_count = 0;
    }
  else
    {
      cd->w_max = 0;
      cd->prev_w_max = 0;
      cd->K_ticks = 0;
      cd->t_start = cubic_time (tc->c_thread_index);
    }
  return 0;
}

static uword
cubic_unformat_config (unformat_input_t *input)
{
  u32 ssthresh = 0x7FFFFFFFU;

  if (!input)
    return 0;

  unformat_skip_white_space (input);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "no-fast-convergence"))
	cubic_cfg.fast_convergence = 0;
      else if (unformat (input, "no-hystart-css"))
	cubic_cfg.hystart_css = 0;
      else if (unformat (input, "hystart-css"))
	cubic_cfg.hystart_css = 1;
      else if (unformat (input, "no-hystart"))
	cubic_cfg.hystart = 0;
      else if (unformat (input, "hystart"))
	cubic_cfg.hystart = 1;
      else if (unformat (input, "ssthresh %u", &ssthresh))
	cubic_cfg.ssthresh = ssthresh;
      else
	return 0;
    }
  return 1;
}

void
cubic_event (tcp_connection_t *tc, tcp_cc_event_t evt)
{
  cubic_data_t *cd;
  f64 idle, now;

  if (evt != TCP_CC_EVT_START_TX)
    return;

  /* No epoch until HyStart++ ends */
  cd = (cubic_data_t *) tcp_cc_data (tc);
  if (cd->mode != CUBIC_MODE_AVOIDANCE)
    return;

  /* App was idle so update t_start to avoid artificially inflating cwnd. Shift
   * the cubic epoch forward by that idle time (RFC 9438 Sec. 4.2: t MUST NOT
   * include application-limited periods). delivered_time is recorded when the
   * local flight drains and is not affected by reverse traffic. A zero value
   * means no delivery baseline is available, so start a fresh epoch. */
  now = cubic_time (tc->c_thread_index);

  /* Keep a paused epoch frozen until an ACK proves that the new flight was
   * cwnd-limited. Resuming here would charge one RTT for every restarted
   * flight that remains application-limited. */
  if (cubic_epoch_is_paused (cd))
    return;

  if (tc->delivered_time == 0)
    {
      cd->t_start = now;
      return;
    }

  idle = now - tc->delivered_time;
  if (idle > 0)
    cd->t_start = clib_min (cd->t_start + idle, now);
}

static u64
cubic_get_pacing_rate (tcp_connection_t *tc)
{
  f64 gain = 1.0;

  if (tcp_in_slowstart (tc))
    {
      cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);

      /* CSS needs less headroom */
      if (cd->mode == CUBIC_MODE_CSS)
	gain = 1.25;
      else if (tc->cwnd < tc->ssthresh / 2)
	gain = 2.0;
    }

  return tcp_cc_window_pacing_rate (tc, gain);
}

const static tcp_cc_algorithm_t tcp_cubic = {
  .name = "cubic",
  .unformat_cfg = cubic_unformat_config,
  .congestion = cubic_congestion,
  .loss = cubic_loss,
  .recovered = cubic_recovered,
  .undo_recovery = cubic_undo_recovery,
  .rcv_ack = cubic_rcv_ack,
  .rcv_cong_ack = newreno_rcv_cong_ack,
  .event = cubic_event,
  .init = cubic_conn_init,
  .get_pacing_rate = cubic_get_pacing_rate,
};

clib_error_t *
cubic_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  tcp_cc_algo_register (TCP_CC_CUBIC, &tcp_cubic);

  return error;
}

VLIB_INIT_FUNCTION (cubic_init);
