/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Control-plane construction, reset and formatting for nsim loss models. The
 * per-packet datapath appliers are header-inline in nsim_loss.h. */

#include <vppinfra/format.h>
#include <nsim/nsim.h>

uword
unformat_nsim_loss_spec (unformat_input_t *input, va_list *args)
{
  nsim_loss_spec_t *spec = va_arg (*args, nsim_loss_spec_t *);
  u32 packets_per_drop;

  if (unformat (input, "packets-per-drop %u", &packets_per_drop))
    {
      if (packets_per_drop)
	spec->drop_fraction = 1.0 / (f64) packets_per_drop;
    }
  else if (unformat (input, "drop-fraction %f", &spec->drop_fraction))
    ;
  else if (unformat (input, "burst-loss-prob %f", &spec->burst_probability))
    ;
  else if (unformat (input, "burst-duration %U", unformat_nsim_delay, &spec->burst_duration))
    ;
  else if (unformat (input, "drop-once after %U for %U", unformat_nsim_delay, &spec->drop_once_at,
		     unformat_nsim_delay, &spec->drop_once_duration))
    spec->drop_once_set = 1;
  else if (unformat (input, "drop-seq %u retransmits %u", &spec->target_offset,
		     &spec->target_retransmits))
    spec->target_set = 1;
  else if (unformat (input, "drop-seq %u", &spec->target_offset))
    spec->target_set = 1;
  else
    return 0;
  return 1;
}

clib_error_t *
nsim_loss_validate (const nsim_loss_spec_t *spec)
{
  if (spec->drop_fraction < 0.0 || spec->drop_fraction > 1.0)
    return clib_error_return (0, "drop fraction must be between zero and 1");
  if (spec->burst_probability < 0.0 || spec->burst_probability > 1.0)
    return clib_error_return (0, "burst loss probability must be between zero and 1");
  if (spec->burst_duration < 0.0)
    return clib_error_return (0, "burst duration must not be negative");
  if (spec->drop_once_set && (spec->drop_once_at < 0.0 || spec->drop_once_duration <= 0.0))
    return clib_error_return (0,
			      "one-shot loss requires a non-negative start and positive duration");
  return 0;
}

void
nsim_loss_configure (nsim_loss_model_t *m, const nsim_loss_spec_t *spec)
{
  if (spec->target_set)
    nsim_loss_model_target_seq (m, spec->target_offset, spec->target_retransmits);
  else if (spec->drop_once_set)
    nsim_loss_model_once (m, spec->drop_once_at, spec->drop_once_duration);
  else if (spec->burst_probability > 0.0)
    nsim_loss_model_burst (m, spec->burst_probability, spec->burst_duration);
  else
    nsim_loss_model_uniform (m, spec->drop_fraction);
}

static u8 *
format_delay_secs (u8 *s, va_list *args)
{
  f64 d = va_arg (*args, f64);
  if (d >= 1.0)
    return format (s, "%.3f s", d);
  return format (s, "%.1f ms", d * 1e3);
}

u8 *
format_nsim_loss_config (u8 *s, va_list *args)
{
  nsim_loss_model_t *m = va_arg (*args, nsim_loss_model_t *);

  switch (m->type)
    {
    case NSIM_LOSS_UNIFORM:
      /* %g: drop/burst probabilities span [1e-6, 1]; a fixed precision would
       * either be verbose for common values or round the small burst
       * probabilities (e.g. 2e-6) down to zero. */
      s = format (s, "uniform: drop fraction %g", m->uniform.fraction);
      break;
    case NSIM_LOSS_BURST:
      s = format (s, "burst (statistical): prob %g/pkt duration %U", m->burst.prob,
		  format_delay_secs, m->burst.duration);
      break;
    case NSIM_LOSS_ONCE:
      s = format (s, "one-shot (statistical): after %U for %U", format_delay_secs, m->once.at,
		  format_delay_secs, m->once.duration);
      break;
    case NSIM_LOSS_TARGET_SEQ:
      s = format (s, "targeted (stateful): offset %u retransmits %u", m->target_seq.offset,
		  m->target_seq.rxt);
      break;
    default:
      s = format (s, "none");
      break;
    }
  return s;
}

u8 *
format_nsim_loss_model (u8 *s, va_list *args)
{
  nsim_loss_model_t *m = va_arg (*args, nsim_loss_model_t *);

  s = format (s, "%U", format_nsim_loss_config, m);
  if (m->type == NSIM_LOSS_ONCE)
    s = format (s, " (done %u, %u packets dropped)", m->once.done, m->once.count);
  else if (m->type == NSIM_LOSS_TARGET_SEQ)
    s = format (s, " (armed %u remaining %u)", m->target_seq.armed, m->target_seq.remaining);
  return s;
}

void
nsim_loss_model_reset (nsim_loss_model_t *m)
{
  clib_memset (m, 0, sizeof (*m));
  m->type = NSIM_LOSS_NONE;
}

void
nsim_loss_model_uniform (nsim_loss_model_t *m, f64 fraction)
{
  nsim_loss_model_reset (m);
  if (fraction <= 0.0)
    return;
  m->type = NSIM_LOSS_UNIFORM;
  m->uniform.fraction = fraction;
}

void
nsim_loss_model_burst (nsim_loss_model_t *m, f64 prob, f64 duration)
{
  nsim_loss_model_reset (m);
  if (prob <= 0.0)
    return;
  m->type = NSIM_LOSS_BURST;
  m->burst.prob = prob;
  /* Default the burst duration to ~2 ms if none given -- short vs any realistic
   * RTT so a retransmit sent a round later survives. */
  m->burst.duration = duration > 0.0 ? duration : 0.002;
}

void
nsim_loss_model_once (nsim_loss_model_t *m, f64 at, f64 duration)
{
  nsim_loss_model_reset (m);
  if (duration <= 0.0)
    return;
  m->type = NSIM_LOSS_ONCE;
  m->once.at = at;
  m->once.duration = duration;
}

void
nsim_loss_model_target_seq (nsim_loss_model_t *m, u32 offset, u32 rxt)
{
  nsim_loss_model_reset (m);
  m->type = NSIM_LOSS_TARGET_SEQ;
  m->stateful = 1;
  m->needs_inspect = 1;
  m->target_seq.offset = offset;
  m->target_seq.rxt = rxt;
  m->target_seq.remaining = rxt;
  m->target_seq.armed = 1;
}
