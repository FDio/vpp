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

static u8 *
format_intel_memory_stalls (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;

  if (!ss->n_packets)
    return s;

  sv = ss->value[row] / ss->n_packets;

  s = format (s, "%5.0f", sv);

  return s;
}

static perfmon_cpu_supports_t memory_stalls_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_memory_stalls) = {
  .name = "memory-stalls",
  .description = "cycles not retiring instructions due to memory stalls",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,	    /* FIXED */
  .events[1] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_TOTAL,    /*CMask: 0xFF*/
  .events[2] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_MEM_ANY,  /*CMask: 0xFF*/
  .events[3] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_L1D_MISS, /*CMask: 0xF*/
  .events[4] = INTEL_CORE_E_L1D_PEND_MISS_FB_FULL,	    /*CMask: 0xF*/
  .events[5] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_L3_MISS,  /*CMask: 0xF*/
  .events[6] = INTEL_CORE_E_SQ_MISC_SQ_FULL,		    /*CMask: 0xF*/
  .n_events = 7,
  .format_fn = format_intel_memory_stalls,
  .cpu_supports = memory_stalls_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (memory_stalls_cpu_supports),
  .column_headers = PERFMON_STRINGS ("Cycles/Packet", "Cycles Stall/Packet",
				     "Mem Stall/Packet",
				     "L1D Miss Stall/Packet", "FB Full/Packet",
				     "L3 Miss Stall/Packet", "SQ Full/Packet"),
};
