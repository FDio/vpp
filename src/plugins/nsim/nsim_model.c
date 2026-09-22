/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Control-plane construction, reset and formatting for nsim service models.
 * Per-packet model application is header-inline in nsim_model.h. */

#include <vppinfra/format.h>
#include <nsim/nsim.h>

#define NSIM_WIFI_BAD_BANDWIDTH 6e6
#define NSIM_WIFI_GOOD_DWELL	8.0
#define NSIM_WIFI_BAD_DWELL	0.25

uword
unformat_nsim_model_spec (unformat_input_t *input, va_list *args)
{
  nsim_model_spec_t *spec = va_arg (*args, nsim_model_spec_t *);
  f64 interval, probability;

  if (unformat (input, "buffer %U", unformat_nsim_delay, &spec->buffer_time))
    ;
  else if (unformat (input, "batch-interval %U", unformat_nsim_delay, &spec->batch_interval))
    ;
  else if (unformat (input, "batch-packets %u", &spec->batch_packet_limit))
    ;
  else if (unformat (input, "batch-gap %U probability %f", unformat_nsim_delay, &interval,
		     &probability))
    {
      if (spec->n_batch_gaps == NSIM_MAX_BATCH_GAPS)
	spec->batch_gaps_overflow = 1;
      else
	{
	  spec->batch_gaps[spec->n_batch_gaps].interval = interval;
	  spec->batch_gaps[spec->n_batch_gaps].probability = probability;
	  spec->n_batch_gaps++;
	}
    }
  else if (unformat (input, "rate-stall bandwidth %U every %U for %U", unformat_nsim_bandwidth,
		     &spec->rate_bad_bandwidth, unformat_nsim_delay, &spec->rate_good_dwell,
		     unformat_nsim_delay, &spec->rate_bad_dwell))
    spec->rate_stall = 1;
  else if (unformat (input, "rate-cycle bandwidth %U good %U bad %U", unformat_nsim_bandwidth,
		     &spec->rate_bad_bandwidth, unformat_nsim_delay, &spec->rate_good_dwell,
		     unformat_nsim_delay, &spec->rate_bad_dwell))
    spec->rate_cycle = 1;
  else if (unformat (input, "wifi"))
    spec->wifi_preset = 1;
  else
    return 0;
  return 1;
}

clib_error_t *
nsim_model_validate (const nsim_model_spec_t *spec, f64 bandwidth)
{
  f64 probability = 0.0;

  if (spec->batch_gaps_overflow)
    return clib_error_return (0, "at most %u batch gaps may be configured", NSIM_MAX_BATCH_GAPS);
  if (spec->buffer_time < 0.0)
    return clib_error_return (0, "buffer time must not be negative");
  if (spec->batch_interval < 0.0)
    return clib_error_return (0, "batch interval must not be negative");
  if (spec->n_batch_gaps && spec->batch_interval <= 0.0)
    return clib_error_return (0, "batch gaps require 'batch-interval <time>'");
  if (spec->batch_packet_limit && spec->batch_interval <= 0.0)
    return clib_error_return (0, "batch packet budget requires 'batch-interval <time>'");
  for (u32 i = 0; i < spec->n_batch_gaps; i++)
    {
      if (spec->batch_gaps[i].interval < spec->batch_interval)
	return clib_error_return (0, "batch gaps must not be shorter than the batch interval");
      if (spec->batch_gaps[i].probability <= 0.0 || spec->batch_gaps[i].probability > 1.0)
	return clib_error_return (0, "batch gap probability must be between zero and 1");
      probability += spec->batch_gaps[i].probability;
    }
  if (probability > 1.0 + 1e-9)
    return clib_error_return (0, "batch gap probabilities exceed 1");

  if (spec->rate_cycle && (spec->wifi_preset || spec->rate_stall))
    return clib_error_return (0, "configure only one rate model");
  if ((spec->rate_cycle || spec->wifi_preset || spec->rate_stall) && spec->buffer_time <= 0.0)
    return clib_error_return (0, "rate model requires the queued model; set 'buffer <time>'");
  if (spec->rate_cycle &&
      (spec->rate_bad_bandwidth <= 0.0 || spec->rate_bad_bandwidth >= bandwidth ||
       spec->rate_good_dwell <= 0.0 || spec->rate_bad_dwell <= 0.0))
    return clib_error_return (
      0, "rate cycle requires a lower bad-state bandwidth and positive good/bad durations");
  if (spec->rate_stall && (spec->rate_bad_bandwidth <= 0.0 || spec->rate_good_dwell <= 0.0 ||
			   spec->rate_bad_dwell <= 0.0))
    return clib_error_return (0, "rate stall requires positive bandwidth and good/bad durations");
  if (!spec->rate_cycle && bandwidth > 0.0 && (spec->wifi_preset || spec->rate_stall) &&
      (spec->rate_bad_bandwidth > 0.0 ? spec->rate_bad_bandwidth : NSIM_WIFI_BAD_BANDWIDTH) >=
	bandwidth)
    return clib_error_return (0, "stall bandwidth must be below link bandwidth");
  return 0;
}

void
nsim_model_configure (nsim_model_config_t *c, const nsim_model_spec_t *spec, f64 bandwidth,
		      u32 packet_size)
{
  f64 bad_bandwidth, good_dwell, bad_dwell;

  clib_memset (c, 0, sizeof (*c));
  c->buffer_time = spec->buffer_time;
  c->serialization_time = bandwidth > 0.0 ? (f64) (packet_size * 8) / bandwidth : 0.0;
  c->batch.interval = spec->batch_interval;
  c->batch.packet_limit = spec->batch_packet_limit;
  c->batch.n_gaps = spec->n_batch_gaps;
  c->batch.max_gap = spec->batch_interval;
  for (u32 i = 0; i < spec->n_batch_gaps; i++)
    {
      c->batch.gaps[i] = spec->batch_gaps[i];
      c->batch.max_gap = clib_max (c->batch.max_gap, spec->batch_gaps[i].interval);
    }

  nsim_rate_config_reset (&c->rate);
  if (spec->rate_cycle)
    {
      nsim_rate_config_cycle (&c->rate, c->serialization_time,
			      (f64) (packet_size * 8) / spec->rate_bad_bandwidth,
			      spec->rate_good_dwell, spec->rate_bad_dwell);
      return;
    }
  if (!spec->wifi_preset && !spec->rate_stall)
    return;

  /* The compatibility alias models long good periods interrupted by brief
   * collapses to a low, but still draining, wireless rate. Explicit rate-stall
   * values override each default independently. */
  bad_bandwidth =
    spec->rate_bad_bandwidth > 0.0 ? spec->rate_bad_bandwidth : NSIM_WIFI_BAD_BANDWIDTH;
  good_dwell = spec->rate_good_dwell > 0.0 ? spec->rate_good_dwell : NSIM_WIFI_GOOD_DWELL;
  bad_dwell = spec->rate_bad_dwell > 0.0 ? spec->rate_bad_dwell : NSIM_WIFI_BAD_DWELL;
  nsim_rate_config_markov (&c->rate, c->serialization_time, (f64) (packet_size * 8) / bad_bandwidth,
			   good_dwell, bad_dwell);
}

u64
nsim_model_wheel_slots (const nsim_model_config_t *c, f64 bandwidth, f64 delay, u32 packet_size)
{
  f64 queue_time = c->buffer_time > 0.0 ? c->buffer_time : delay;
  u64 bytes = (((queue_time + c->batch.max_gap) * bandwidth) / 8.0) + 0.5;

  return bytes / packet_size + 1;
}

static u8 *
format_rate_bps (u8 *s, va_list *args)
{
  /* serialization time (s/pkt) -> bits/s, using the configured packet size. */
  f64 ser = va_arg (*args, f64);
  u32 packet_size = va_arg (*args, u32);
  f64 bps = ser > 0.0 ? (f64) (packet_size * 8) / ser : 0.0;

  if (bps >= 1e9)
    return format (s, "%.1f gbps", bps / 1e9);
  if (bps >= 1e6)
    return format (s, "%.1f mbps", bps / 1e6);
  if (bps >= 1e3)
    return format (s, "%.1f kbps", bps / 1e3);
  return format (s, "%.0f bps", bps);
}

static u8 *
format_dwell_secs (u8 *s, va_list *args)
{
  f64 d = va_arg (*args, f64);
  if (d >= 1.0)
    return format (s, "%.2f s", d);
  return format (s, "%.0f ms", d * 1e3);
}

static u8 *
format_model_delay (u8 *s, va_list *args)
{
  f64 delay = va_arg (*args, f64);

  if (delay < 1e-3)
    return format (s, "%.1f us", delay * 1e6);
  if (delay < 1.0)
    return format (s, "%.1f ms", delay * 1e3);
  return format (s, "%f sec", delay);
}

u8 *
format_nsim_model_config (u8 *s, va_list *args)
{
  nsim_model_config_t *c = va_arg (*args, nsim_model_config_t *);
  u32 packet_size = va_arg (*args, u32);

  if (c->buffer_time > 0.0)
    s = format (s, " buffer: %U (queued/bufferbloat model)\n", format_model_delay, c->buffer_time);
  else
    s = format (s, " buffer: 1 bdp (fixed-delay model)\n");
  if (c->rate.type != NSIM_RATE_NONE)
    s = format (s, " rate model: %U\n", format_nsim_rate_config, &c->rate, packet_size);
  if (c->batch.interval > 0.0)
    {
      s = format (s, " batch interval: %U\n", format_model_delay, c->batch.interval);
      if (c->batch.packet_limit)
	s = format (s, " batch packet budget: %u (base capacity %.1f packets/s)\n",
		    c->batch.packet_limit, c->batch.packet_limit / c->batch.interval);
    }
  if (c->batch.n_gaps)
    {
      f64 probability = 0.0;

      s = format (s, " batch gap distribution:");
      for (u32 i = 0; i < c->batch.n_gaps; i++)
	{
	  probability += c->batch.gaps[i].probability;
	  s = format (s, " %U %.5f", format_model_delay, c->batch.gaps[i].interval,
		      c->batch.gaps[i].probability);
	}
      s = format (s, " base %.5f\n", clib_max (1.0 - probability, 0.0));
    }
  return s;
}

u8 *
format_nsim_model_state (u8 *s, va_list *args)
{
  nsim_model_config_t *c = va_arg (*args, nsim_model_config_t *);
  nsim_model_state_t *state = va_arg (*args, nsim_model_state_t *);
  u32 packet_size = va_arg (*args, u32);

  if (c->rate.type != NSIM_RATE_NONE)
    s = format (s, "  rate service tail: %U next transition %.6f\n", format_nsim_rate_state,
		&c->rate, &state->rate, packet_size, state->rate.next_transition);
  if (c->batch.interval > 0.0)
    s = format (s,
		"  batching: delayed %llu batches %llu extended %llu budget deferrals %llu "
		"max gap %U max batch %u next %.6f\n",
		state->batch.delayed_packets + state->reorder_batch.delayed_packets,
		state->batch.batches + state->reorder_batch.batches,
		state->batch.extended_batches + state->reorder_batch.extended_batches,
		state->batch.budget_deferrals + state->reorder_batch.budget_deferrals,
		format_model_delay, clib_max (state->batch.max_gap, state->reorder_batch.max_gap),
		clib_max (state->batch.max_batch_size, state->reorder_batch.max_batch_size),
		clib_max (state->batch.next_boundary, state->reorder_batch.next_boundary));
  return s;
}

static u8 *
format_nsim_rate (u8 *s, const nsim_rate_config_t *c, const nsim_rate_state_t *state,
		  u32 packet_size)
{
  switch (c->type)
    {
    case NSIM_RATE_MARKOV:
      s = format (s, "markov (good/bad): good %U for ~%U, bad %U for ~%U", format_rate_bps,
		  c->good_ser, packet_size, format_dwell_secs, c->good_dwell, format_rate_bps,
		  c->bad_ser, packet_size, format_dwell_secs, c->bad_dwell);
      break;
    case NSIM_RATE_CYCLE:
      s = format (s, "cycle: good %U for %U, bad %U for %U", format_rate_bps, c->good_ser,
		  packet_size, format_dwell_secs, c->good_dwell, format_rate_bps, c->bad_ser,
		  packet_size, format_dwell_secs, c->bad_dwell);
      break;
    default:
      return format (s, "none");
    }

  if (state)
    s = format (s, " (%s, %llu tracked transitions, %llu catchups)", state->state ? "bad" : "good",
		state->transitions, state->catchups);
  return s;
}

u8 *
format_nsim_rate_state (u8 *s, va_list *args)
{
  nsim_rate_config_t *c = va_arg (*args, nsim_rate_config_t *);
  nsim_rate_state_t *state = va_arg (*args, nsim_rate_state_t *);
  u32 packet_size = va_arg (*args, u32);

  return format_nsim_rate (s, c, state, packet_size);
}

u8 *
format_nsim_rate_config (u8 *s, va_list *args)
{
  nsim_rate_config_t *c = va_arg (*args, nsim_rate_config_t *);
  u32 packet_size = va_arg (*args, u32);

  return format_nsim_rate (s, c, 0, packet_size);
}

void
nsim_rate_config_reset (nsim_rate_config_t *c)
{
  clib_memset (c, 0, sizeof (*c));
  c->type = NSIM_RATE_NONE;
}

void
nsim_rate_config_markov (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			 f64 bad_dwell)
{
  nsim_rate_config_reset (c);
  if (bad_dwell <= 0.0 || good_dwell <= 0.0)
    return;
  c->type = NSIM_RATE_MARKOV;
  c->good_ser = good_ser;
  c->bad_ser = bad_ser;
  c->good_dwell = good_dwell;
  c->bad_dwell = bad_dwell;
}

void
nsim_rate_config_cycle (nsim_rate_config_t *c, f64 good_ser, f64 bad_ser, f64 good_dwell,
			f64 bad_dwell)
{
  nsim_rate_config_reset (c);
  if (bad_dwell <= 0.0 || good_dwell <= 0.0)
    return;
  c->type = NSIM_RATE_CYCLE;
  c->good_ser = good_ser;
  c->bad_ser = bad_ser;
  c->good_dwell = good_dwell;
  c->bad_dwell = bad_dwell;
}
