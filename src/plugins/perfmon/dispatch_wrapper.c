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

#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon/perfmon.h>

static_always_inline void
perfmon_read_pmcs (u64 * counters, int *pmc_index, u8 n_counters)
{
  switch (n_counters)
    {
    default:
    case 7:
      counters[6] = _rdpmc (pmc_index[6]);
    case 6:
      counters[5] = _rdpmc (pmc_index[5]);
    case 5:
      counters[4] = _rdpmc (pmc_index[4]);
    case 4:
      counters[3] = _rdpmc (pmc_index[3]);
    case 3:
      counters[2] = _rdpmc (pmc_index[2]);
    case 2:
      counters[1] = _rdpmc (pmc_index[1]);
    case 1:
      counters[0] = _rdpmc (pmc_index[0]);
      break;
    }
}

static_always_inline int
perfmon_calc_pmc_index (perfmon_thread_runtime_t * tr, u8 i)
{
  return (int) (tr->mmap_pages[i]->index + tr->mmap_pages[i]->offset);
}

uword
perfmon_dispatch_wrapper (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt = vec_elt_at_index (pm->thread_runtimes,
						   vm->thread_index);
  perfmon_node_stats_t *s =
    vec_elt_at_index (rt->node_stats, node->node_index);
  u8 n_events = rt->n_events;
  int pmc_index[PERF_MAX_EVENTS];
  u64 before[PERF_MAX_EVENTS];
  u64 after[PERF_MAX_EVENTS];
  uword rv;

  clib_prefetch_load (s);

  switch (n_events)
    {
    default:
    case 7:
      pmc_index[6] = perfmon_calc_pmc_index (rt, 6);
    case 6:
      pmc_index[5] = perfmon_calc_pmc_index (rt, 5);
    case 5:
      pmc_index[4] = perfmon_calc_pmc_index (rt, 4);
    case 4:
      pmc_index[3] = perfmon_calc_pmc_index (rt, 3);
    case 3:
      pmc_index[2] = perfmon_calc_pmc_index (rt, 2);
    case 2:
      pmc_index[1] = perfmon_calc_pmc_index (rt, 1);
    case 1:
      pmc_index[0] = perfmon_calc_pmc_index (rt, 0);
      break;
    }

  perfmon_read_pmcs (before, pmc_index, n_events);
  rv = node->function (vm, node, frame);
  perfmon_read_pmcs (after, pmc_index, n_events);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;
  for (int i = 0; i < n_events; i++)
    s->value[i] += after[i] - before[i];

  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
