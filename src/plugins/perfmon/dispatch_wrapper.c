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
  switch (n_counters)
    {
    case 12:
      counters[11] = _rdpmc (indexes[11] - 1);
    case 11:
      counters[10] = _rdpmc (indexes[10] - 1);
    case 10:
      counters[9] = _rdpmc (indexes[9] - 1);
    case 9:
      counters[8] = _rdpmc (indexes[8] - 1);
    case 8:
      counters[7] = _rdpmc (indexes[7] - 1);
    case 7:
      counters[6] = _rdpmc (indexes[6] - 1);
    case 6:
      counters[5] = _rdpmc (indexes[5] - 1);
    case 5:
      counters[4] = _rdpmc (indexes[4] - 1);
    case 4:
      counters[3] = _rdpmc (indexes[3] - 1);
    case 3:
      counters[2] = _rdpmc (indexes[2] - 1);
    case 2:
      counters[1] = _rdpmc (indexes[1] - 1);
    case 1:
      counters[0] = _rdpmc (indexes[0] - 1);
    }
}

uword
perfmon_dispatch_wrapper (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt =
    vec_elt_at_index (pm->thread_runtimes, vm->thread_index);
  perfmon_node_stats_t *s =
    vec_elt_at_index (rt->node_stats, node->node_index);

  u8 n_events = rt->n_events;

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
