/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_nsim_rate_h__
#define __included_nsim_rate_h__

/*
 * nsim time-varying bottleneck-rate models.
 *
 * The queued (bufferbloat) model serializes packets at a single fixed bottleneck rate. A rate model
 * varies that rate over time -- the bandwidth analog of the correlated burst-loss model in
 * nsim_loss.h.
 *
 * NSIM_RATE_MARKOV is a two-state (good/bad) continuous-time Markov model, inspired by the
 * Gilbert-Elliott burst-loss model (Gilbert 1960, Elliott 1963) but applied to rate rather than
 * loss: the link mostly runs at the configured rate (good state) but intermittently collapses to a
 * low rate for a correlated interval (bad state) -- rate adaptation dropping to a lower modulation
 * and coding scheme (MCS), a burst of L2 retransmits, contention, a scan/roam, etc. Dwell times in
 * each state are exponentially distributed, so stalls are memoryless and of variable length. A deep
 * buffer in front of such a link turns a bad-state stall into a transient RTT spike (buffered bytes
 * / low rate), which is how a one-off multi-second latency excursion arises on an otherwise fast
 * path.
 *
 * A rate model only affects the queued model (buffer > 0); with the fixed-delay model there is no
 * serialization step to modulate.
 *
 * The per-packet applier is header-inline so it specializes into each CPU-march variant of the nsim
 * node; control-plane construction/reset/format live in nsim_rate.c.
 */

#include <math.h>
#include <vppinfra/clib.h>
#include <vppinfra/random.h>

typedef enum nsim_rate_type_
{
  NSIM_RATE_NONE = 0,
  NSIM_RATE_MARKOV, /**< two-state good/bad correlated rate variation */
  NSIM_RATE_N_TYPES,
} nsim_rate_type_t;

typedef struct nsim_rate_model_
{
  nsim_rate_type_t type;

  /* Per-packet serialization time (packet_size / rate) in each state. The
   * queued model uses good_ser at the configured bandwidth; bad_ser is the
   * (larger) serialization time at the reduced stall rate. */
  f64 good_ser;
  f64 bad_ser;

  union
  {
    /* Two-state Markov: exponential dwell in each state with the given means.
     * `state` is live (0 good / 1 bad); `next_transition` is the wall-clock time
     * of the next flip (0 => not yet initialized). */
    struct
    {
      f64 good_dwell; /**< mean seconds at full rate before a stall */
      f64 bad_dwell;  /**< mean seconds of a stall */
      f64 next_transition;
      u8 state;
    } markov;
  };
} nsim_rate_model_t;

/* Sample an exponential dwell with the given mean (seconds). `random_f64`
 * returns [0,1]; clamp away from 0 so the log is finite. */
static_always_inline f64
nsim_rate_dwell (u32 *seed, f64 mean)
{
  f64 u = random_f64 (seed);
  if (u < 1e-9)
    u = 1e-9;
  return -mean * log (u);
}

/* Effective per-packet serialization time for the next departure, advancing the
 * rate-model state to `now`. Only call when m->type != NSIM_RATE_NONE. */
static_always_inline f64
nsim_rate_serialization_time (nsim_rate_model_t *m, u32 *seed, f64 now)
{
  if (PREDICT_FALSE (m->markov.next_transition == 0.0))
    m->markov.next_transition = now + nsim_rate_dwell (seed, m->markov.good_dwell);

  /* Lazy single flip: at most one state change per packet. Between packets the
   * gap is microseconds in a bulk transfer, so a state spans many packets and
   * transitions land at the right cadence; after a long idle we simply resync on
   * the next packet (rate is irrelevant while nothing is queued). */
  if (now >= m->markov.next_transition)
    {
      m->markov.state ^= 1;
      m->markov.next_transition =
	now + nsim_rate_dwell (seed, m->markov.state ? m->markov.bad_dwell : m->markov.good_dwell);
    }

  return m->markov.state ? m->bad_ser : m->good_ser;
}

/* Control-plane helpers (nsim_rate.c). */
format_function_t format_nsim_rate_model;
void nsim_rate_model_reset (nsim_rate_model_t *m);
void nsim_rate_model_markov (nsim_rate_model_t *m, f64 good_ser, f64 bad_ser, f64 good_dwell,
			     f64 bad_dwell);

#endif /* __included_nsim_rate_h__ */
