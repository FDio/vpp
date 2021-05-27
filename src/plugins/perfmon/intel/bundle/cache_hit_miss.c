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
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static f64
calculate_inst_and_clock (perfmon_stats_t *ts, int idx)
{
  f64 sv = 0;

  if (!ts->n_packets)
    return sv;

  switch (idx)
    {
    case 0:
      sv = (u64) ts->value[0] / ts->n_packets;
      break;
    case 1:
      sv = (u64) ts->value[1] / ts->n_packets;
      break;
    case 2:
      sv = (u64) (ts->value[1] - clib_min (ts->value[1], ts->value[2])) /
	   ts->n_packets;
      break;
    case 3:
      sv = (u64) ts->value[2] / ts->n_packets;
      break;
    case 4:
      sv = (u64) (ts->value[2] - clib_min (ts->value[2], ts->value[3])) /
	   ts->n_packets;
      break;
    case 5:
      sv = (u64) ts->value[3] / ts->n_packets;
      break;
    }

  return sv;
}

static u64
update_inst_and_clock (perfmon_stats_t *ts, int idx)
{
  return (f64) calculate_inst_and_clock (ts, idx);
}

static u8 *
format_intel_core_cache_hit_miss (u8 *s, va_list *args)
{
  perfmon_stats_t *ss = va_arg (*args, perfmon_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = calculate_inst_and_clock (ss, row);

  s = format (s, "%0.2f", sv);

  return s;
}

PERFMON_REGISTER_BUNDLE (intel_core_cache_miss_hit) = {
  .name = "cache-hierarchy",
  .description = "cache hits and misses",
  .source = "intel-core",
  .type_flags = PERFMON_BUNDLE_TYPE_NODE_FLAG |
		PERFMON_BUNDLE_TYPE_THREAD_FLAG,
  .events[0] = INTEL_CORE_E_MEM_LOAD_RETIRED_L1_HIT,
  .events[1] = INTEL_CORE_E_MEM_LOAD_RETIRED_L1_MISS,
  .events[2] = INTEL_CORE_E_MEM_LOAD_RETIRED_L2_MISS,
  .events[3] = INTEL_CORE_E_MEM_LOAD_RETIRED_L3_MISS,
  .n_events = 4,
  .format_fn = format_intel_core_cache_hit_miss,
  .update_fn = update_inst_and_clock,
  .column_headers = PERFMON_STRINGS ("L1 hit/pkt", "L1 miss/pkt", "L2 hit/pkt",
				     "L2 miss/pkt", "L3 hit/pkt",
				     "L3 miss/pkt"),
};
