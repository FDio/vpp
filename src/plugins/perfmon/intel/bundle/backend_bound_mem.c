/*
 * Copyright (c) 2021 Intel and/or its affiliates.
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

#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

enum
{
  STALLS_L1D_MISS = 0,
  STALLS_L2_MISS = 1,
  STALLS_L3_MISS = 2,
  STALLS_MEM_ANY = 3,
  STALLS_TOTAL = 4,
  BOUND_ON_STORES = 5,
  FB_FULL = 6,
  THREAD = 7,
};

static u8 *
format_intel_backend_bound_mem (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;

  if (!ss->n_packets)
    return s;

  if (0 == row)
    {
      sv = ss->value[THREAD] / ss->n_packets;

      s = format (s, "%.0f", sv);
      return s;
    }

  switch (row)
    {
    case 1:
      sv = ss->value[BOUND_ON_STORES];
      break;
    case 2:
      sv = ss->value[STALLS_MEM_ANY] - ss->value[STALLS_L1D_MISS];
      break;
    case 3:
      sv = ss->value[FB_FULL];
      break;
    case 4:
      sv = ss->value[STALLS_L1D_MISS] - ss->value[STALLS_L2_MISS];
      break;
    case 5:
      sv = ss->value[STALLS_L2_MISS] - ss->value[STALLS_L3_MISS];
      break;
    case 6:
      sv = ss->value[STALLS_L3_MISS];
      break;
    }

  sv = clib_max ((sv / ss->value[THREAD]) * 100, 0);

  s = format (s, "%04.1f", sv);

  return s;
}

static perfmon_cpu_supports_t backend_bound_mem_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_backend_bound_mem) = {
  .name = "td-backend-mem",
  .description = "Topdown BackEnd-bound Memory - % cycles not retiring "
		 "instructions due to memory stalls",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_L1D_MISS, /* 0x0F */
  .events[1] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_L2_MISS,  /* 0x0F */
  .events[2] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_L3_MISS,  /* 0x0F */
  .events[3] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_MEM_ANY,  /* 0xFF */
  .events[4] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_TOTAL,    /* 0xFF */
  .events[5] = INTEL_CORE_E_EXE_ACTIVITY_BOUND_ON_STORES,   /* 0xFF */
  .events[6] = INTEL_CORE_E_L1D_PEND_MISS_FB_FULL,	    /* 0x0F */
  .events[7] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,	    /* 0xFF */
  .n_events = 8,
  .format_fn = format_intel_backend_bound_mem,
  .cpu_supports = backend_bound_mem_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (backend_bound_mem_cpu_supports),
  .column_headers = PERFMON_STRINGS ("Clocks/Packet", "%Store Bound",
				     "%L1 Bound", "%FB Full", "%L2 Bound",
				     "%L3 Bound", "%DRAM Bound"),
};
