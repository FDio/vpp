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
  NSIM_RATE_CYCLE,  /**< deterministic two-state good/bad cycle */
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

  /* Dwell times are exact for a deterministic cycle and means for Markov.
   * The remaining fields are live per-worker state. A transition time of zero
   * means the model has not seen its first packet. */
  f64 good_dwell;
  f64 bad_dwell;
  f64 next_transition;
  u64 transitions;
  u8 state;
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

static_always_inline f64
nsim_rate_state_dwell (nsim_rate_model_t *m, u32 *seed)
{
  f64 dwell = m->state ? m->bad_dwell : m->good_dwell;

  return m->type == NSIM_RATE_MARKOV ? nsim_rate_dwell (seed, dwell) : dwell;
}

static_always_inline void
nsim_rate_advance (nsim_rate_model_t *m, u32 *seed)
{
  m->state ^= 1;
  m->next_transition += nsim_rate_state_dwell (m, seed);
  m->transitions++;
}

/* Return the departure time of a packet whose service starts at
 * `service_start`. If the packet straddles a rate transition, serialize the
 * corresponding fraction of its bits at each rate. */
static_always_inline f64
nsim_rate_departure_time_slow (nsim_rate_model_t *m, u32 *seed, f64 service_start)
{
  f64 remaining = 1.0, now = service_start;

  if (PREDICT_FALSE (m->next_transition == 0.0))
    m->next_transition = now + nsim_rate_state_dwell (m, seed);

  while (PREDICT_FALSE (now >= m->next_transition))
    nsim_rate_advance (m, seed);

  while (1)
    {
      f64 serialization = m->state ? m->bad_ser : m->good_ser;
      f64 departure = now + remaining * serialization;

      if (PREDICT_TRUE (departure <= m->next_transition))
	return departure;

      remaining = clib_max (remaining - (m->next_transition - now) / serialization, 0.0);
      now = m->next_transition;
      nsim_rate_advance (m, seed);
    }
}

static_always_inline f64
nsim_rate_departure_time (nsim_rate_model_t *m, u32 *seed, f64 service_start)
{
  f64 serialization = m->state ? m->bad_ser : m->good_ser;
  f64 departure = service_start + serialization;

  /* A continuously busy link normally takes this one-comparison path. The
   * slow path initializes or catches up state and integrates a straddling
   * packet across one or more transitions. */
  if (PREDICT_TRUE (departure <= m->next_transition))
    return departure;
  return nsim_rate_departure_time_slow (m, seed, service_start);
}

/* Control-plane helpers (nsim_rate.c). */
format_function_t format_nsim_rate_model;
format_function_t format_nsim_rate_config;
void nsim_rate_model_reset (nsim_rate_model_t *m);
void nsim_rate_model_markov (nsim_rate_model_t *m, f64 good_ser, f64 bad_ser, f64 good_dwell,
			     f64 bad_dwell);
void nsim_rate_model_cycle (nsim_rate_model_t *m, f64 good_ser, f64 bad_ser, f64 good_dwell,
			    f64 bad_dwell);

#endif /* __included_nsim_rate_h__ */
