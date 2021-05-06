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

static_always_inline u64
perfmon_mmap_read_pmc1 (const struct perf_event_mmap_page *mmap_page)
{
  u64 count;
  u32 seq;

  /* See documentation in /usr/include/linux/perf_event.h, for more details
   * but the 2 main important things are:
   *  1) if seq != mmap_page->lock, it means the kernel is currently updating
   *     the user page and we need to read it again
   *  2) if idx == 0, it means the perf event is currently turned off and we
   *     just need to read the kernel-updated 'offset', otherwise we must also
   *     add the current hw value (hence rdmpc) */
  do
    {
      u32 idx;

      seq = mmap_page->lock;
      CLIB_COMPILER_BARRIER ();

      idx = mmap_page->index;
      count = mmap_page->offset;
      if (idx)
	count += _rdpmc (idx - 1);

      CLIB_COMPILER_BARRIER ();
    }
  while (mmap_page->lock != seq);

  return count;
}

static_always_inline void
perfmon_mmap_read_pmcs (u64 *counters,
			struct perf_event_mmap_page **mmap_pages,
			u8 n_counters)
{
  switch (n_counters)
    {
    default:
    case 7:
      counters[6] = perfmon_mmap_read_pmc1 (mmap_pages[6]);
    case 6:
      counters[5] = perfmon_mmap_read_pmc1 (mmap_pages[5]);
    case 5:
      counters[4] = perfmon_mmap_read_pmc1 (mmap_pages[4]);
    case 4:
      counters[3] = perfmon_mmap_read_pmc1 (mmap_pages[3]);
    case 3:
      counters[2] = perfmon_mmap_read_pmc1 (mmap_pages[2]);
    case 2:
      counters[1] = perfmon_mmap_read_pmc1 (mmap_pages[1]);
    case 1:
      counters[0] = perfmon_mmap_read_pmc1 (mmap_pages[0]);
      break;
    }
}

uword
perfmon_dispatch_wrapper_mmap (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt =
    vec_elt_at_index (pm->thread_runtimes, vm->thread_index);
  perfmon_stats_t *s = vec_elt_at_index (rt->node_stats, node->node_index);

  u8 n_events = rt->n_events;

  u64 before[PERF_MAX_EVENTS];
  u64 after[PERF_MAX_EVENTS];
  uword rv;

  clib_prefetch_load (s);

  perfmon_mmap_read_pmcs (&before[0], rt->mmap_pages, n_events);
  rv = node->function (vm, node, frame);
  perfmon_mmap_read_pmcs (&after[0], rt->mmap_pages, n_events);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;

  for (int i = 0; i < n_events; i++)
    s->value[i] += after[i] - before[i];

  return rv;
}

static_always_inline void
perfmon_metric_read_pmcs (u64 *counters, int *pmc_index, u8 n_counters)
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
perfmon_metric_index (perfmon_bundle_t *b, u8 i)
{
  return (int) (b->metrics[i]);
}

uword
perfmon_dispatch_wrapper_metrics (vlib_main_t *vm, vlib_node_runtime_t *node,
				  vlib_frame_t *frame)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt =
    vec_elt_at_index (pm->thread_runtimes, vm->thread_index);
  perfmon_stats_t *s = vec_elt_at_index (rt->node_stats, node->node_index);

  u8 n_events = rt->n_events;

  u64 before[PERF_MAX_EVENTS];
  int pmc_index[PERF_MAX_EVENTS];
  uword rv;

  clib_prefetch_load (s);

  switch (n_events)
    {
    default:
    case 7:
      pmc_index[6] = perfmon_metric_index (rt->bundle, 6);
    case 6:
      pmc_index[5] = perfmon_metric_index (rt->bundle, 5);
    case 5:
      pmc_index[4] = perfmon_metric_index (rt->bundle, 4);
    case 4:
      pmc_index[3] = perfmon_metric_index (rt->bundle, 3);
    case 3:
      pmc_index[2] = perfmon_metric_index (rt->bundle, 2);
    case 2:
      pmc_index[1] = perfmon_metric_index (rt->bundle, 1);
    case 1:
      pmc_index[0] = perfmon_metric_index (rt->bundle, 0);
      break;
    }

  perfmon_metric_read_pmcs (&before[0], pmc_index, n_events);
  rv = node->function (vm, node, frame);

  clib_memcpy_fast (&s->t[0].value[0], &before, sizeof (before));
  perfmon_metric_read_pmcs (&s->t[1].value[0], pmc_index, n_events);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;

  return rv;
}

uword
perfmon_dispatch_wrapper_stats (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_runtime_t *rt =
    vec_elt_at_index (pm->thread_runtimes, vm->thread_index);
  perfmon_stats_t *s = vec_elt_at_index (rt->node_stats, node->node_index);
  uword rv;

  clib_prefetch_load (s);

  rv = node->function (vm, node, frame);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;

  return rv;
}
