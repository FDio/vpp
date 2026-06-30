/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_BBR_H_
#define SRC_VNET_TCP_TCP_BBR_H_

#include <vnet/tcp/tcp_types.h>

/**
 * BBR congestion control (BBRv3).
 *
 * draft-ietf-ccwg-bbr-06. BBR models the path by its
 * bottleneck bandwidth (windowed max of per-ack delivery-rate samples) and its
 * round-trip propagation delay (windowed min RTT), and paces sending at
 * gain * bw while holding cwnd near bw * min_rtt. Unlike a loss-based algorithm
 * it does not cut cwnd multiplicatively on loss; instead v3 bounds inflight and
 * bandwidth (inflight_hi/inflight_lo/bw_lo) and treats a high per-round loss
 * rate as the signal to lower those bounds, so it coexists with loss-based
 * flows. ECN, v3's third signal, is unused here (VPP TCP has no ECN), so BBR
 * runs in loss-only mode.
 *
 * Built on the byte-tracker delivery-rate estimator (tcp_ack_ctx_t), so it
 * requires byte tracking (TCP_CFG_F_BYTE_TRACKER), like RACK. Per-connection BBR
 * state is kept in worker-local pools and referenced from tc->cc_data, so
 * enabling BBR adds nothing to connections using other congestion-control
 * algorithms.
 */

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

format_function_t format_tcp_bbr;

#endif /* SRC_VNET_TCP_TCP_BBR_H_ */
