/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Control-plane construction, reset and formatting for nsim loss models. The
 * per-packet datapath appliers are header-inline in nsim_loss.h. */

#include <vppinfra/format.h>
#include <nsim/nsim.h>

static u8 *
format_delay_secs (u8 *s, va_list *args)
{
  f64 d = va_arg (*args, f64);
  if (d >= 1.0)
    return format (s, "%.3f s", d);
  return format (s, "%.1f ms", d * 1e3);
}

u8 *
format_nsim_loss_model (u8 *s, va_list *args)
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
      s = format (s, "one-shot (statistical): after %U for %U (%u pkts dropped)", format_delay_secs,
		  m->once.at, format_delay_secs, m->once.duration, m->once.count);
      break;
    case NSIM_LOSS_TARGET_SEQ:
      s = format (s,
		  "targeted (stateful): offset %u retransmits %u "
		  "(armed %u remaining %u)",
		  m->target_seq.offset, m->target_seq.rxt, m->target_seq.armed,
		  m->target_seq.remaining);
      break;
    default:
      s = format (s, "none");
      break;
    }
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
