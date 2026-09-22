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

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

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
  u64 service_approximations;
  /* Packets are attributed to the state in which their service starts. */
  u64 service_packets[2];
  u64 straddled_packets;
  u8 state;
} nsim_rate_state_t;

#define NSIM_RATE_MAX_PACKET_TRANSITIONS 256

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
  u64 gap_samples[NSIM_MAX_BATCH_GAPS + 1];
  f64 gap_total;
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
  u32 rate_seed;
  u32 batch_seed;
} nsim_model_state_t;

f64 nsim_rate_departure_time_slow (const nsim_rate_config_t *c, nsim_rate_state_t *s, u32 *seed,
				   f64 service_start);

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
    {
      s->service_packets[s->state]++;
      return departure;
    }
  return nsim_rate_departure_time_slow (c, s, seed, service_start);
}

f64 nsim_batch_gap (const nsim_batch_config_t *c, nsim_batch_state_t *s, u32 *seed);

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
u64 nsim_model_queue_slots (const nsim_model_config_t *c, f64 bandwidth, u32 packet_size);
u64 nsim_model_wheel_slots (const nsim_model_config_t *c, f64 bandwidth, f64 delay,
			    f64 reorder_delay, u32 packet_size);
void nsim_rate_config_reset (nsim_rate_config_t *c);
void nsim_rate_config_markov (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			      f64 bad_dwell);
void nsim_rate_config_cycle (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			     f64 bad_dwell);

#endif /* __included_nsim_model_h__ */
