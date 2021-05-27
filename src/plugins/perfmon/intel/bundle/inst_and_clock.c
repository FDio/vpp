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
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static f64
calculate_inst_and_clock (perfmon_stats_t *ts, int idx)
{
  f64 t = (f64) ts->time_running * 1e-9;
  f64 sv = 0;

  switch (idx)
    {
    case 0:
      sv = (u64) ts->n_calls / t;
      break;
    case 1:
      sv = (u64) ts->n_packets / t;
      break;
    case 2:
      if (ts->n_calls) /* catch div by 0 */
	sv = (u64) ts->n_packets / ts->n_calls;
      break;
    case 3:
      if (ts->n_packets) /* catch div by 0 */
	sv = (u64) ts->value[1] / ts->n_packets;
      break;
    case 4:
      if (ts->n_packets) /* catch div by 0 */
	sv = (u64) ts->value[0] / ts->n_packets;
      break;
    case 5:
      sv = (u64) ts->value[0] / ts->value[1];
      break;
    }

  return sv;
}

static u64
update_inst_and_clock (perfmon_stats_t *ss, int idx)
{
  return (u64) calculate_inst_and_clock (ss, idx);
}

static u8 *
format_inst_and_clock (u8 *s, va_list *args)
{
  perfmon_stats_t *ss = va_arg (*args, perfmon_stats_t *);
  int idx = va_arg (*args, int);

  f64 sv = calculate_inst_and_clock (ss, idx);

  switch (idx)
    {
    case 0:
    case 1:
      s = format (s, "%lu", (u64) sv);
      break;
    default:
      s = format (s, "%.2f", sv);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (inst_and_clock) = {
  .name = "inst-and-clock",
  .description = "instructions/packet, cycles/packet and IPC",
  .source = "intel-core",
  .type_flags = PERFMON_BUNDLE_TYPE_NODE_FLAG |
		PERFMON_BUNDLE_TYPE_THREAD_FLAG,
  .events[0] = INTEL_CORE_E_INST_RETIRED_ANY_P,
  .events[1] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,
  .events[2] = INTEL_CORE_E_CPU_CLK_UNHALTED_REF_TSC,
  .n_events = 3,
  .format_fn = format_inst_and_clock,
  .update_fn = update_inst_and_clock,
  .column_headers = PERFMON_STRINGS ("Calls/Sec", "Packets/Sec",
				     "Packets/Call", "Clocks/Packet",
				     "Instructions/Packet", "IPC"),
};
