/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static u8 *
format_inst_and_clock (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%lu", ns->n_calls);
      break;
    case 1:
      s = format (s, "%lu", ns->n_packets);
      break;
    case 2:
      s = format (s, "%.2f", (f64) ns->n_packets / ns->n_calls);
      break;
    case 3:
      s = format (s, "%.2f", (f64) ns->value[1] / ns->n_packets);
      break;
    case 4:
      s = format (s, "%.2f", (f64) ns->value[0] / ns->n_packets);
      break;
    case 5:
      s = format (s, "%.2f", (f64) ns->value[0] / ns->value[1]);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (inst_and_clock) = {
  .name = "inst-and-clock",
  .description = "instructions/packet, cycles/packet and IPC",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = INTEL_CORE_E_INST_RETIRED_ANY_P,
  .events[1] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,
  .events[2] = INTEL_CORE_E_CPU_CLK_UNHALTED_REF_TSC,
  .n_events = 3,
  .format_fn = format_inst_and_clock,
  .column_headers = PERFMON_STRINGS ("Calls", "Packets", "Packets/Call",
				     "Clocks/Packet", "Instructions/Packet",
				     "IPC"),
};
