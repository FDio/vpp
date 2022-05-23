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

enum /* as per .events[n] in PERFMON_REGISTER_BUNDLE */
{
  L1I_TLB,
  L1I_TLB_REFILL,
  L2I_TLB,
  L2I_TLB_REFILL,
};

static u8 *
format_arm_cache_inst_tlb (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%.2f", (f64) ns->value[L1I_TLB] / ns->n_packets);
      break;

    case 1:
      s = format (s, "%.2f", (f64) ns->value[L1I_TLB_REFILL] / ns->n_packets);
      break;

    case 2:
      s = format (s, "%.2f%%",
		  (ns->value[L1I_TLB] ? (f64) ns->value[L1I_TLB_REFILL] /
					  ns->value[L1I_TLB] * 100 :
					      0));
      break;

    case 3:
      s = format (s, "%.2f", (f64) ns->value[L2I_TLB] / ns->n_packets);
      break;

    case 4:
      s = format (s, "%.2f", (f64) ns->value[L2I_TLB_REFILL] / ns->n_packets);
      break;

    case 5:
      s = format (s, "%.2f%%",
		  (ns->value[L2I_TLB] ? (f64) ns->value[L2I_TLB_REFILL] /
					  ns->value[L2I_TLB] * 100 :
					      0));
      break;

    case 6:
      s = format (s, "%llu", ns->n_packets);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_cache_inst_tlb) = {
  .name = "cache-inst-tlb",
  .description =
    "L1/L2 instruction TLB cache accesses, refills, walks per packet",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_L1I_TLB,
  .events[1] = ARMV8_PMUV3_L1I_TLB_REFILL,
  .events[2] = ARMV8_PMUV3_L2I_TLB,
  .events[3] = ARMV8_PMUV3_L2I_TLB_REFILL,
  .n_events = 4,
  .n_columns = 7,
  .format_fn = format_arm_cache_inst_tlb,
  .column_headers = PERFMON_STRINGS ("L1I-TLB: access", "refill", "\%*",
				     "L2I-TLB: access", "refill", "\%*",
				     "pkts"),
  /*
   * set a bit for every event used in each column
   * this allows us to disable columns at bundle registration if an
   * event is not supported
   */
  .column_events = PERFMON_COLUMN_EVENTS (
    SET_BIT (L1I_TLB), SET_BIT (L1I_TLB_REFILL),
    SET_BIT (L1I_TLB) | SET_BIT (L1I_TLB_REFILL), SET_BIT (L2I_TLB),
    SET_BIT (L2I_TLB_REFILL), SET_BIT (L2I_TLB) | SET_BIT (L2I_TLB_REFILL), 0),
  .footer = "all stats are per packet except refill rate (\%)\n"
	    "*\% percentage shown is total refills/accesses\n\n"
	    "TLB: Instruction memory access that causes a TLB access to at "
	    "least the Level 1/2 instruction TLB.\n"
	    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
	    " event numbers for full description.\n"
};
