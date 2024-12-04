/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vppinfra/time.h>

#define VPP_SIMTIME_CLOCK 1e9

__clib_export clib_simtime_main_t clib_simtime_main = {};

__clib_export int
clib_simtime_enable ()
{
#ifndef VPP_SIMTIME
  return -1;
#else
  ASSERT (clib_simtime_main.too_late_to_enable == 0);
  clib_simtime_main.is_enabled = 1;
  return 0;
#endif
}

void
clib_simtime_update_maybe (void)
{
  // If we are in pull-mode, call owner to get new time
  if (clib_simtime_main.get_time_cb)
    {
      clib_simtime_main.current_time = clib_simtime_main.get_time_cb ();
    }
}

__clib_export u64
clib_cpu_simtime_now (void)
{
  ASSERT (clib_simtime_main.is_enabled);
  clib_simtime_update_maybe ();
  return clib_simtime_main.current_time * VPP_SIMTIME_CLOCK;
}

__clib_export f64
clib_simtime_now (clib_time_t *c)
{
  ASSERT (clib_simtime_main.is_enabled);
  clib_simtime_update_maybe ();
  c->last_cpu_time = clib_simtime_main.current_time * c->clocks_per_second;
  return clib_simtime_main.current_time;
}

__clib_export void
clib_simtime_set_time (f64 t)
{
  ASSERT (clib_simtime_main.is_enabled);
  clib_simtime_main.current_time = t;
}

void
clib_simtime_init (clib_time_t *c)
{
  c->clocks_per_second = 1e9;
  c->seconds_per_clock = 1.0 / c->clocks_per_second;
  c->init_cpu_time = 0;
  c->init_reference_time = 0;
  c->last_cpu_time = 0;
  c->init_cpu_time = c->last_verify_cpu_time = c->last_cpu_time;

  /* All these are only used by internal code and will be ignored when
   * simulated time is used. */
  c->total_cpu_time = 0xfefefefe;		    // Should not be used
  c->last_verify_reference_time = 0xfefefefe;	    // Should not be used
  c->log2_clocks_per_second = 0xfefefefe;	    // Should not be used
  c->log2_clocks_per_frequency_verify = 0xfefefefe; // Should not be used
  c->damping_constant = 0xfefefefe;		    // Should not be used
}
