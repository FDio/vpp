/*
 * Copyright (c) 2021 Arm and/or its affiliates.
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

#define barrier() asm volatile("dmb ish" : : : "memory");
#define isb()	  asm volatile("isb" : : : "memory");

typedef int64_t s64;

static u64
get_pmc_register (u32 pmc_idx)
{
  u64 value = 0;
  if (pmc_idx == 31)
    // i.e. CPU Cycle event code 0x11 - need to read via pmccntr_el0
    asm volatile("mrs %x0, pmccntr_el0" : "=r"(value));
  else
    {
      // set event register 0x0-0x1F
      asm volatile("msr pmselr_el0, %x0" : : "r"((pmc_idx)));
      // get register value
      asm volatile("mrs %x0, pmxevcntr_el0" : "=r"(value));
    }
  isb ();
  return value;
}

static u64
read_pmc_from_mmap (struct perf_event_mmap_page *pc)
{
  u32 seq, idx, width;
  u64 offset = 0;
  s64 pmc = 0;

  do
    {
      seq = pc->lock;
      barrier ();
      idx = pc->index;
      if (pc->cap_user_rdpmc && idx)
	{
	  offset = pc->offset;
	  width = pc->pmc_width;
	  pmc = get_pmc_register (idx - 1);
	  // for 32 bit registers, left shift 32b to zero/discard the top bits
	  pmc <<= 64 - width;
	  pmc >>= 64 - width;
	}
      barrier ();
    }
  while (pc->lock != seq);

  return pmc + offset;
}

static_always_inline void
perfmon_read_pmcs (u64 *counters, perfmon_thread_runtime_t *rt, u8 n_counters)
{
  switch (n_counters)
    {
    default:
    case 7:
      counters[6] = read_pmc_from_mmap (rt->mmap_pages[6]);
    case 6:
      counters[5] = read_pmc_from_mmap (rt->mmap_pages[5]);
    case 5:
      counters[4] = read_pmc_from_mmap (rt->mmap_pages[4]);
    case 4:
      counters[3] = read_pmc_from_mmap (rt->mmap_pages[3]);
    case 3:
      counters[2] = read_pmc_from_mmap (rt->mmap_pages[2]);
    case 2:
      counters[1] = read_pmc_from_mmap (rt->mmap_pages[1]);
    case 1:
      counters[0] = read_pmc_from_mmap (rt->mmap_pages[0]);
      break;
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
  u64 before[n_events];
  u64 after[n_events];

  uword rv;

  clib_prefetch_load (s);

  perfmon_read_pmcs (before, rt, n_events);
  rv = node->function (vm, node, frame);
  perfmon_read_pmcs (after, rt, n_events);

  if (rv == 0)
    return rv;

  s->n_calls += 1;
  s->n_packets += rv;

  for (int i = 0; i < n_events; i++)
    {
      s->value[i] += after[i] - before[i];
    }

  return rv;
}