/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_nsim_model_h__
#define __included_nsim_model_h__

/*
 * nsim service and release models.
 *
 * The queued model serializes packets at a fixed or time-varying bottleneck rate. Release batching
 * can be applied after either the queued or fixed-delay model.
 *
 * The per-packet applier is header-inline so it specializes into each CPU-march variant of the nsim
 * node; control-plane construction/reset/format live in nsim_model.c.
 */

#include <math.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>

typedef enum nsim_rate_type_
{
  NSIM_RATE_NONE = 0,
  /** Two-state good/bad continuous-time Markov rate model. Exponential dwell
   * times model correlated periods of rate adaptation, retransmission, or
   * contention without replaying a captured traffic trace. */
  NSIM_RATE_MARKOV,
  NSIM_RATE_CYCLE, /**< deterministic two-state good/bad cycle */
  NSIM_RATE_N_TYPES,
} nsim_rate_type_t;

typedef struct nsim_rate_config_
{
  nsim_rate_type_t type;

  /* Per-packet serialization time (packet_size / rate) in each state. The
   * queued model uses good_ser at the configured bandwidth; bad_ser is the
   * (larger) serialization time at the reduced stall rate. */
  f64 good_ser;
  f64 bad_ser;

  /* Dwell times are exact for a deterministic cycle and means for Markov. */
  f64 good_dwell;
  f64 bad_dwell;
} nsim_rate_config_t;

typedef struct nsim_rate_state_
{
  /* A transition time of zero means the model has not seen its first packet. */
  f64 next_transition;
  /* Explicitly materialized transition boundaries. A Markov catch-up accounts
   * for its first certain boundary here and marginalizes any later ones. */
  u64 transitions;
  u64 catchups;
  u8 state;
} nsim_rate_state_t;

#define NSIM_MAX_BATCH_GAPS 8

typedef struct
{
  f64 interval;
  f64 probability;
} nsim_batch_gap_t;

typedef struct
{
  f64 interval;
  f64 max_gap;
  nsim_batch_gap_t gaps[NSIM_MAX_BATCH_GAPS];
  /* Maximum packets released at one opportunity. If nonzero, this is also a
   * packet-rate service limit; excess packets wait for later opportunities. */
  u32 packet_limit;
  u8 n_gaps;
} nsim_batch_config_t;

typedef struct
{
  f64 next_boundary;
  f64 max_gap;
  u64 delayed_packets;
  u64 batches;
  u64 extended_batches;
  u64 budget_deferrals;
  u32 current_batch_size;
  u32 max_batch_size;
} nsim_batch_state_t;

typedef struct
{
  f64 buffer_time;
  nsim_rate_config_t rate;
  nsim_batch_config_t batch;
  f64 serialization_time;
} nsim_model_config_t;

/* Parsed model request. Kept separate from the datapath configuration so CLI
 * aliases and optional values do not leak into the worker-visible model. */
typedef struct
{
  f64 buffer_time;
  f64 batch_interval;
  nsim_batch_gap_t batch_gaps[NSIM_MAX_BATCH_GAPS];
  f64 rate_bad_bandwidth;
  f64 rate_good_dwell;
  f64 rate_bad_dwell;
  u32 batch_packet_limit;
  u8 n_batch_gaps;
  u8 batch_gaps_overflow;
  u8 wifi_preset;
  u8 rate_stall;
  u8 rate_cycle;
} nsim_model_spec_t;

typedef struct
{
  nsim_rate_state_t rate;
  nsim_batch_state_t batch;
  nsim_batch_state_t reorder_batch;
  u32 rate_seed;
  u32 batch_seed;
} nsim_model_state_t;

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
nsim_rate_state_dwell (const nsim_rate_config_t *c, const nsim_rate_state_t *s, u32 *seed)
{
  f64 dwell = s->state ? c->bad_dwell : c->good_dwell;

  return c->type == NSIM_RATE_MARKOV ? nsim_rate_dwell (seed, dwell) : dwell;
}

static_always_inline void
nsim_rate_advance (const nsim_rate_config_t *c, nsim_rate_state_t *s, u32 *seed)
{
  s->state ^= 1;
  s->next_transition += nsim_rate_state_dwell (c, s, seed);
  s->transitions++;
}

static_always_inline void
nsim_rate_catch_up (const nsim_rate_config_t *c, nsim_rate_state_t *s, u32 *seed, f64 now)
{
  if (PREDICT_FALSE (s->next_transition == 0.0))
    {
      s->next_transition = now + nsim_rate_state_dwell (c, s, seed);
      return;
    }

  if (now < s->next_transition)
    return;

  if (c->type == NSIM_RATE_MARKOV)
    {
      f64 good_rate = 1.0 / c->good_dwell;
      f64 bad_rate = 1.0 / c->bad_dwell;
      f64 sum = good_rate + bad_rate;
      f64 elapsed = now - s->next_transition;
      f64 p_good, decay = exp (-sum * elapsed);
      u8 start_state = s->state ^ 1;

      /* A transition at next_transition is certain. Marginalize all later
       * transitions analytically, then use the exponential distribution's
       * memoryless property for the residual dwell. This avoids an unbounded
       * replay loop without biasing every idle restart into the other state. */
      if (start_state == 0)
	p_good = bad_rate / sum + good_rate / sum * decay;
      else
	p_good = bad_rate / sum * (1.0 - decay);
      s->state = random_f64 (seed) < p_good ? 0 : 1;
      s->next_transition = now + nsim_rate_state_dwell (c, s, seed);
      s->transitions++;
      s->catchups++;
      return;
    }

  f64 cycle = c->good_dwell + c->bad_dwell;
  u64 n_cycles = (u64) ((now - s->next_transition) / cycle);

  s->next_transition += n_cycles * cycle;
  s->transitions += 2 * n_cycles;
  while (now >= s->next_transition)
    nsim_rate_advance (c, s, seed);
}

/* Return the departure time of a packet whose service starts at
 * `service_start`. If the packet straddles a rate transition, serialize the
 * corresponding fraction of its bits at each rate. */
static_always_inline f64
nsim_rate_departure_time_slow (const nsim_rate_config_t *c, nsim_rate_state_t *s, u32 *seed,
			       f64 service_start)
{
  f64 remaining = 1.0, now = service_start;

  nsim_rate_catch_up (c, s, seed, now);

  while (1)
    {
      f64 serialization = s->state ? c->bad_ser : c->good_ser;
      f64 departure = now + remaining * serialization;

      if (PREDICT_TRUE (departure <= s->next_transition))
	return departure;

      remaining = clib_max (remaining - (s->next_transition - now) / serialization, 0.0);
      now = s->next_transition;
      nsim_rate_advance (c, s, seed);

      if (c->type == NSIM_RATE_CYCLE)
	{
	  f64 cycle = c->good_dwell + c->bad_dwell;
	  f64 service = c->good_dwell / c->good_ser + c->bad_dwell / c->bad_ser;
	  u64 n_cycles = (u64) (remaining / service);

	  if (n_cycles)
	    {
	      remaining = clib_max (remaining - n_cycles * service, 0.0);
	      now += n_cycles * cycle;
	      s->next_transition += n_cycles * cycle;
	      s->transitions += 2 * n_cycles;
	      if (remaining == 0.0)
		return now;
	    }
	}
    }
}

static_always_inline f64
nsim_rate_departure_time (const nsim_rate_config_t *c, nsim_rate_state_t *s, u32 *seed,
			  f64 service_start)
{
  f64 serialization = s->state ? c->bad_ser : c->good_ser;
  f64 departure = service_start + serialization;

  /* A continuously busy link normally takes this one-comparison path. The
   * slow path initializes or catches up state and integrates a straddling
   * packet across one or more transitions. */
  if (PREDICT_TRUE (departure <= s->next_transition))
    return departure;
  return nsim_rate_departure_time_slow (c, s, seed, service_start);
}

static_always_inline f64
nsim_batch_gap (const nsim_batch_config_t *c, nsim_batch_state_t *s, u32 *seed)
{
  f64 gap = c->interval;

  if (PREDICT_FALSE (c->n_gaps != 0))
    {
      f64 sample = random_f64 (seed), cumulative = 0.0;

      for (u32 i = 0; i < c->n_gaps; i++)
	{
	  cumulative += c->gaps[i].probability;
	  if (sample < cumulative)
	    {
	      gap = c->gaps[i].interval;
	      s->extended_batches++;
	      break;
	    }
	}
    }

  s->max_gap = clib_max (s->max_gap, gap);
  return gap;
}

static_always_inline f64
nsim_batch_release_time (const nsim_batch_config_t *c, nsim_batch_state_t *s, u32 *seed,
			 f64 tx_time)
{
  if (PREDICT_FALSE (s->next_boundary == 0.0))
    {
      s->next_boundary = tx_time + nsim_batch_gap (c, s, seed);
      s->current_batch_size = 0;
      s->batches = 1;
    }
  else if (PREDICT_FALSE (tx_time > s->next_boundary))
    {
      if (PREDICT_TRUE (c->n_gaps == 0))
	{
	  u64 n_intervals = (u64) ((tx_time - s->next_boundary) / c->interval) + 1;

	  s->next_boundary += n_intervals * c->interval;
	  s->max_gap = c->interval;
	}
      else
	/* Start the next sampled hold at this packet rather than walking empty
	 * stochastic intervals after an idle period. */
	s->next_boundary = tx_time + nsim_batch_gap (c, s, seed);
      s->current_batch_size = 0;
      s->batches++;
    }

  if (PREDICT_FALSE (c->packet_limit && s->current_batch_size >= c->packet_limit))
    {
      s->next_boundary += nsim_batch_gap (c, s, seed);
      s->current_batch_size = 0;
      s->batches++;
      s->budget_deferrals++;
    }

  if (tx_time < s->next_boundary)
    s->delayed_packets++;
  s->current_batch_size++;
  s->max_batch_size = clib_max (s->max_batch_size, s->current_batch_size);
  return s->next_boundary;
}

/* Control-plane helpers (nsim_model.c). */
unformat_function_t unformat_nsim_model_spec;
format_function_t format_nsim_model_config;
format_function_t format_nsim_model_state;
format_function_t format_nsim_rate_state;
format_function_t format_nsim_rate_config;
clib_error_t *nsim_model_validate (const nsim_model_spec_t *spec, f64 bandwidth);
void nsim_model_configure (nsim_model_config_t *c, const nsim_model_spec_t *spec, f64 bandwidth,
			   u32 packet_size);
u64 nsim_model_wheel_slots (const nsim_model_config_t *c, f64 bandwidth, f64 delay,
			    u32 packet_size);
void nsim_rate_config_reset (nsim_rate_config_t *c);
void nsim_rate_config_markov (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			      f64 bad_dwell);
void nsim_rate_config_cycle (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			     f64 bad_dwell);

#endif /* __included_nsim_model_h__ */
