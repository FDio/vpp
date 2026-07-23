/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Control-plane construction, reset and formatting for nsim rate models. The
 * per-packet datapath applier is header-inline in nsim_rate.h. */

#include <vppinfra/format.h>
#include <nsim/nsim.h>

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

u8 *
format_nsim_rate_model (u8 *s, va_list *args)
{
  nsim_rate_model_t *m = va_arg (*args, nsim_rate_model_t *);
  u32 packet_size = va_arg (*args, u32);

  switch (m->type)
    {
    case NSIM_RATE_MARKOV:
      s = format (s,
		  "markov (good/bad): good %U for ~%U, bad %U for ~%U "
		  "(currently %s)",
		  format_rate_bps, m->good_ser, packet_size, format_dwell_secs,
		  m->markov.good_dwell, format_rate_bps, m->bad_ser, packet_size, format_dwell_secs,
		  m->markov.bad_dwell, m->markov.state ? "bad" : "good");
      break;
    default:
      s = format (s, "none");
      break;
    }
  return s;
}

void
nsim_rate_model_reset (nsim_rate_model_t *m)
{
  clib_memset (m, 0, sizeof (*m));
  m->type = NSIM_RATE_NONE;
}

void
nsim_rate_model_markov (nsim_rate_model_t *m, f64 good_ser, f64 bad_ser, f64 good_dwell,
			f64 bad_dwell)
{
  nsim_rate_model_reset (m);
  if (bad_dwell <= 0.0 || good_dwell <= 0.0)
    return;
  m->type = NSIM_RATE_MARKOV;
  m->good_ser = good_ser;
  m->bad_ser = bad_ser;
  m->markov.good_dwell = good_dwell;
  m->markov.bad_dwell = bad_dwell;
  m->markov.state = 0; /* start in the good state */
  m->markov.next_transition = 0.0;
}
