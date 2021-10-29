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
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perfmon.h>
#include <perfmon/arm/bundle.h>
#include <perfmon/arm/events.h>

static clib_error_t *
bundle_init_fn (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = bundle_event_support (vm, b);
  /* setup dependencies for each column in terms of events used:  */
  /*                  col  events                                 */
  set_column_events (b, 0, 0, -1);
  set_column_events (b, 1, 1, -1);
  set_column_events (b, 2, 0, 1, -1);
  set_column_events (b, 3, 2, -1);
  set_column_events (b, 4, 3, -1);
  set_column_events (b, 5, 2, 3, -1);
  set_column_events (b, 6, 4, -1);
  set_column_events (b, 7, 5, -1);
  set_column_events (b, 8, 4, 5, -1);
  return err;
}

static u8 *
format_arm_cache_data (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%.2f", (f64) ns->value[0] / ns->n_packets);
      break;

    case 1:
      s = format (s, "%.2f", (f64) ns->value[1] / ns->n_packets);
      break;

    case 2:
      s =
	format (s, "%.2f%%",
		(ns->value[0] ? (f64) ns->value[1] / ns->value[0] * 100 : 0));
      break;

    case 3:
      s = format (s, "%.2f", (f64) ns->value[2] / ns->n_packets);
      break;

    case 4:
      s = format (s, "%.2f", (f64) ns->value[3] / ns->n_packets);
      break;

    case 5:
      s =
	format (s, "%.2f%%",
		(ns->value[2] ? (f64) ns->value[3] / ns->value[2] * 100 : 0));
      break;

    case 6:
      s = format (s, "%.2f", (f64) ns->value[4] / ns->n_packets);
      break;

    case 7:
      s = format (s, "%.2f", (f64) ns->value[5] / ns->n_packets);
      break;

    case 8:
      s =
	format (s, "%.2f%%",
		(ns->value[4] ? (f64) ns->value[5] / ns->value[4] * 100 : 0));
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
