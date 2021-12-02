/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include "vppinfra/string.h"
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon/perfmon.h>

static_always_inline void
perfmon_read_pmcs (u64 *counters, u32 *indexes, u8 n_counters)
{
  for (int i = 0; i < n_counters; i++)
    counters[i] = _rdpmc (indexes[i] - 1);
}

static_always_inline uword
perfmon_dispatch_wrapper_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vlib_frame_t *frame, u8 n_events)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt =
    vec_elt_at_index (pm->thread_runtimes, vm->thread_index);
  perfmon_node_stats_t *s =
    vec_elt_at_index (rt->node_stats, node->node_index);

  struct
  {
    u64 t[2][PERF_MAX_EVENTS];
  } samples;
  uword rv;

  clib_prefetch_load (s);

  perfmon_read_pmcs (&samples.t[0][0], &rt->indexes[0], n_events);
  rv = node->function (vm, node, frame);
  perfmon_read_pmcs (&samples.t[1][0], &rt->indexes[0], n_events);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;

  for (int i = 0; i < n_events; i++)
    {
      if (!(rt->preserve_samples & 1 << i))
	{
	  s->value[i] += samples.t[1][i] - samples.t[0][i];
	}
      else
	{
	  s->t[0].value[i] = samples.t[0][i];
	  s->t[1].value[i] = samples.t[1][i];
	}
    }

  return rv;
}

#define foreach_n_events                                                      \
  _ (1) _ (2) _ (3) _ (4) _ (5) _ (6) _ (7) _ (8) _ (9) _ (10) _ (11) _ (12)

#define _(x)                                                                  \
  static uword perfmon_dispatch_wrapper##x (                                  \
    vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)          \
  {                                                                           \
    return perfmon_dispatch_wrapper_inline (vm, node, frame, x);              \
  }

foreach_n_events
#undef _

  vlib_node_function_t *perfmon_dispatch_wrappers[PERF_MAX_EVENTS + 1] = {
#define _(x) [x] = &perfmon_dispatch_wrapper##x,
    foreach_n_events
#undef _
  };
