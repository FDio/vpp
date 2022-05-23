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
  CPU_CYCLES,
  INST_RETIRED
};

static u8 *
format_arm_inst_clock (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%llu", ns->n_packets);
      break;

    case 1:
      s = format (s, "%llu", ns->n_calls);
      break;

    case 2:
      s = format (s, "%llu", ns->value[0]); /* Cycles */
      break;

    case 3:
      s = format (s, "%llu", ns->value[1]); /* Inst */
      break;

    case 4:
      s = format (s, "%.2f",
		  (f64) ns->n_packets / ns->n_calls); /* Packets/Call */
      break;

    case 5:
      s = format (s, "%.2f",
		  (f64) ns->value[0] / ns->n_packets); /* Clocks/Packet */
      break;

    case 6:
      s =
	format (s, "%.2f",
		(f64) ns->value[1] / ns->n_packets); /* Instructions/Packet */
      break;

    case 7:
      s = format (s, "%.2f", (f64) ns->value[1] / ns->value[0]); /* IPC */
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_inst_clock) = {
  .name = "inst-and-clock",
  .description =
    "CPU cycles, instructions, instructions/packet, cycles/packet and IPC",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_CPU_CYCLES,
  .events[1] = ARMV8_PMUV3_INST_RETIRED,
  .n_events = 2,
  .n_columns = 8,
  .format_fn = format_arm_inst_clock,
  .column_headers = PERFMON_STRINGS ("Packets", "Calls", "CPU Cycles", "Inst*",
				     "Pkts/Call", "Cycles/Pkt", "Inst/Pkt",
				     "IPC"),
  /*
   * set a bit for every event used in each column
   * this allows us to disable columns at bundle registration if an
   * event is not supported
   */
  .column_events =
    PERFMON_COLUMN_EVENTS (0, 0, SET_BIT (CPU_CYCLES), SET_BIT (INST_RETIRED),
			   0, SET_BIT (CPU_CYCLES), SET_BIT (INST_RETIRED),
			   SET_BIT (CPU_CYCLES) | SET_BIT (INST_RETIRED)),
  .footer = "* Instructions retired: the counter increments for every "
	    "architecturally executed instruction\n"
	    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
	    " event numbers for full description.\n"
};
