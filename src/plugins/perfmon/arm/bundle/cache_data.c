/*
 * Copyright (c) 2022 Arm and/or its affiliates.
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
#include <perfmon/arm/events.h>

// as per .events[n] in PERFMON_REGISTER_BUNDLE
enum
{
  L1D_CACHE,
  L1D_CACHE_REFILL,
  L2D_CACHE,
  L2D_CACHE_REFILL,
  L3D_CACHE,
  L3D_CACHE_REFILL
};

static clib_error_t *
bundle_init_fn (vlib_main_t *vm, perfmon_bundle_t *b)
{
  /* setup dependencies for each column in terms of events used:
   * column refers to switch cases in format fn below
   *                  col  events                                 */
  set_column_events (b, 0, L1D_CACHE, VA_END);
  set_column_events (b, 1, L1D_CACHE_REFILL, VA_END);
  set_column_events (b, 2, L1D_CACHE, L1D_CACHE_REFILL, VA_END);
  set_column_events (b, 3, L2D_CACHE, VA_END);
  set_column_events (b, 4, L2D_CACHE_REFILL, VA_END);
  set_column_events (b, 5, L2D_CACHE, L2D_CACHE_REFILL, VA_END);
  set_column_events (b, 6, L3D_CACHE, VA_END);
  set_column_events (b, 7, L3D_CACHE_REFILL, VA_END);
  set_column_events (b, 8, L3D_CACHE, L3D_CACHE_REFILL, VA_END);
  return 0;
}

static u8 *
format_arm_cache_data (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%.2f", (f64) ns->value[L1D_CACHE] / ns->n_packets);
      break;

    case 1:
      s =
	format (s, "%.2f", (f64) ns->value[L1D_CACHE_REFILL] / ns->n_packets);
      break;

    case 2:
      s = format (s, "%.2f%%",
		  (ns->value[L1D_CACHE] ? (f64) ns->value[L1D_CACHE_REFILL] /
					    ns->value[L1D_CACHE] * 100 :
						0));
      break;

    case 3:
      s = format (s, "%.2f", (f64) ns->value[L2D_CACHE] / ns->n_packets);
      break;

    case 4:
      s =
	format (s, "%.2f", (f64) ns->value[L2D_CACHE_REFILL] / ns->n_packets);
      break;

    case 5:
      s = format (s, "%.2f%%",
		  (ns->value[L2D_CACHE] ? (f64) ns->value[L2D_CACHE_REFILL] /
					    ns->value[L2D_CACHE] * 100 :
						0));
      break;

    case 6:
      s = format (s, "%.2f", (f64) ns->value[L3D_CACHE] / ns->n_packets);
      break;

    case 7:
      s =
	format (s, "%.2f", (f64) ns->value[L3D_CACHE_REFILL] / ns->n_packets);
      break;

    case 8:
      s = format (s, "%.2f%%",
		  (ns->value[L3D_CACHE] ? (f64) ns->value[L3D_CACHE_REFILL] /
					    ns->value[L3D_CACHE] * 100 :
						0));
      break;

    case 9:
      s = format (s, "%llu", ns->n_packets);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_cache_data) = {
  .name = "cache-data",
  .description = "L1D/L2D/L3D data cache accesses and refills per packet",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_L1D_CACHE,
  .events[1] = ARMV8_PMUV3_L1D_CACHE_REFILL,
  .events[2] = ARMV8_PMUV3_L2D_CACHE,
  .events[3] = ARMV8_PMUV3_L2D_CACHE_REFILL,
  .events[4] = ARMV8_PMUV3_L3D_CACHE,
  .events[5] = ARMV8_PMUV3_L3D_CACHE_REFILL,
  .n_events = 6,
  .n_columns = 10,
  .init_fn = bundle_init_fn,
  .format_fn = format_arm_cache_data,
  .column_headers = PERFMON_STRINGS ("L1D: access", "refill", "\%*",
				     "L2D: access", "refill", "\%*",
				     "L3D: access", "refill", "\%*", "pkts"),
  .footer = "all stats are per packet except refill rate (\%)\n"
	    "*\% percentage shown is total refills/accesses\n\n"
	    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
	    " event numbers for full description.\n"
};
