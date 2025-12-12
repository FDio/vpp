/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static u8 *
format_intel_core_cache_hit_miss (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%0.2f", (f64) ns->value[0] / ns->n_packets);
      break;
    case 1:
      s = format (s, "%0.2f", (f64) ns->value[1] / ns->n_packets);
      break;
    case 2:
      s =
	format (s, "%0.2f",
		(f64) (ns->value[1] - clib_min (ns->value[1], ns->value[2])) /
		  ns->n_packets);
      break;
    case 3:
      s = format (s, "%0.2f", (f64) ns->value[2] / ns->n_packets);
      break;
    case 4:
      s =
	format (s, "%0.2f",
		(f64) (ns->value[2] - clib_min (ns->value[2], ns->value[3])) /
		  ns->n_packets);
      break;
    case 5:
      s = format (s, "%0.2f", (f64) ns->value[3] / ns->n_packets);
      break;
    }

  return s;
}

PERFMON_REGISTER_BUNDLE (intel_core_cache_miss_hit) = {
  .name = "cache-hierarchy",
  .description = "cache hits and misses",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_NODE,

  .events[0] = INTEL_CORE_E_MEM_LOAD_RETIRED_L1_HIT,
  .events[1] = INTEL_CORE_E_MEM_LOAD_RETIRED_L1_MISS,
  .events[2] = INTEL_CORE_E_MEM_LOAD_RETIRED_L2_MISS,
  .events[3] = INTEL_CORE_E_MEM_LOAD_RETIRED_L3_MISS,
  .n_events = 4,
  .format_fn = format_intel_core_cache_hit_miss,
  .column_headers = PERFMON_STRINGS ("L1 hit/pkt", "L1 miss/pkt", "L2 hit/pkt",
				     "L2 miss/pkt", "L3 hit/pkt",
				     "L3 miss/pkt"),
};
