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

/* as per .events[n] in PERFMON_REGISTER_BUNDLE */
enum
{
  L1I_CACHE,
  L1I_CACHE_REFILL,
  L2I_CACHE,
  L2I_CACHE_REFILL
};

static u8 *
format_arm_cache_inst (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%.2f", (f64) ns->value[L1I_CACHE] / ns->n_packets);
      break;

    case 1:
      s =
	format (s, "%.2f", (f64) ns->value[L1I_CACHE_REFILL] / ns->n_packets);
      break;

    case 2:
      s = format (s, "%.2f%%",
		  (ns->value[L1I_CACHE] ? (f64) ns->value[L1I_CACHE_REFILL] /
					    ns->value[L1I_CACHE] * 100 :
						0));
      break;

    case 3:
      s = format (s, "%.2f", (f64) ns->value[L2I_CACHE] / ns->n_packets);
      break;

    case 4:
      s =
	format (s, "%.2f", (f64) ns->value[L2I_CACHE_REFILL] / ns->n_packets);
      break;

    case 5:
      s = format (s, "%.2f%%",
		  (ns->value[L2I_CACHE] ? (f64) ns->value[L2I_CACHE_REFILL] /
					    ns->value[L2I_CACHE] * 100 :
						0));
      break;

    case 6:
      s = format (s, "%llu", ns->n_packets);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_cache_inst) = {
  .name = "cache-inst",
  .description = "L1I/L2I instruction cache accesses and refills per packet",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_L1I_CACHE,
  .events[1] = ARMV8_PMUV3_L1I_CACHE_REFILL,
  .events[2] = ARMV8_PMUV3_L2I_CACHE,
  .events[3] = ARMV8_PMUV3_L2I_CACHE_REFILL,
  .n_events = 4,
  .n_columns = 7,
  .format_fn = format_arm_cache_inst,
  .column_headers = PERFMON_STRINGS ("L1I: access", "refill", "\%*",
				     "L2I: access", "refill", "\%*", "pkts"),
  /*
   * set a bit for every event used in each column
   * this allows us to disable columns at bundle registration if an
   * event is not supported
   */
  .column_events = PERFMON_COLUMN_EVENTS (
    SET_BIT (L1I_CACHE), SET_BIT (L1I_CACHE_REFILL),
    SET_BIT (L1I_CACHE) | SET_BIT (L1I_CACHE_REFILL), SET_BIT (L2I_CACHE),
    SET_BIT (L2I_CACHE_REFILL),
    SET_BIT (L2I_CACHE) | SET_BIT (L2I_CACHE_REFILL), 0),
  .footer = "all stats are per packet except refill rate (\%)\n"
	    "*\% percentage shown is total refills/accesses\n"
};
