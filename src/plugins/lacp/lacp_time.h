/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __included_lacp_time_h__
#define __included_lacp_time_h__

#include <time.h>
#include <vppinfra/types.h>

/*
 * LACP member timers are armed by lacp-input on the worker that receives
 * the LACPDU and evaluated by lacp-process on the main thread. Use one
 * process-wide monotonic clock for all LACP timestamps and timers so that
 * arming and checking always share the same timebase, independent of
 * per-thread vlib time.
 */
static inline f64
lacp_time_now (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (f64) ts.tv_sec + 1e-9 * (f64) ts.tv_nsec;
}

#endif /* __included_lacp_time_h__ */
