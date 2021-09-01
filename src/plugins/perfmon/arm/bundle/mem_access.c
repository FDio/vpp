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
#include <perfmon/arm/events.h>

static u8 *
format_arm_memory_access (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);

  switch (row)
    {
    case 0:
      s = (!b->event_enabled[0] ?
	     format (s, "%s", "-") :
	     format (s, "%.2f", (f64) ns->value[0] / ns->n_packets));
      break;

    case 1:
      s = (!b->event_enabled[1] ?
	     format (s, "%s", "-") :
	     format (s, "%.3f", (f64) ns->value[1] / ns->n_packets));
      break;

    case 2:
      s = (!b->event_enabled[2] ? format (s, "%s", "-") :
				  format (s, "%llu", ns->value[2]));
      break;

    case 3:
      s = format (s, "%llu", ns->n_packets);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_memory_access) = {
  .name = "memory-access",
  .description = "Memory/bus accesses per pkt + total memory errors",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_MEM_ACCESS,
  .events[1] = ARMV8_PMUV3_BUS_ACCESS,
  .events[2] = ARMV8_PMUV3_MEMORY_ERROR,
  .n_events = 3,
  .format_fn = format_arm_memory_access,
  .column_headers = PERFMON_STRINGS ("Mem-access/pkt", "Bus-access/pkt",
				     "Total-mem-errors", "pkts"),
  .footer =
    "Mem-access: The counter counts Memory-read operations and Memory-write"
    " operations that the PE made\n"
    "Bus-access: The counter counts Memory-read operations and Memory-write"
    " operations that access outside of the boundary of the PE and its "
    "closely-coupled caches\n"
    "Mem-error: Memory error refers to a physical error in memory closely "
    "coupled to this PE, and detected by the hardware, such as a parity or"
    " ECC error\n"
    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
    " event numbers for full description.\n"
};
