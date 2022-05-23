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

static clib_error_t *
bundle_init_fn (vlib_main_t *vm, perfmon_bundle_t *b)
{
  /* setup dependencies for each column in terms of events used:  */
  /*                  col  events                                 */
  set_column_events (b, 0, 0, -1);
  set_column_events (b, 1, 1, -1);
  set_column_events (b, 2, 0, -1);
  set_column_events (b, 3, 1, -1);
  return 0;
}

static u8 *
format_arm_stall (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%llu", ns->value[0] / ns->n_packets);
      break;

    case 1:
      s = format (s, "%llu", ns->value[1] / ns->n_packets);
      break;

    case 2:
      s = format (s, "%llu", ns->value[0] / ns->n_calls);
      break;

    case 3:
      s = format (s, "%llu", ns->value[1] / ns->n_calls);
      break;

    case 4:
      s = format (s, "%llu", ns->n_packets);
      break;

    case 5:
      s = format (s, "%llu", ns->n_calls);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_stall) = {
  .name = "stall",
  .description = "PE cycle stalls per pkt/call",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_STALL_BACKEND,
  .events[1] = ARMV8_PMUV3_STALL_FRONTEND,
  .n_events = 2,
  .n_columns = 6,
  .init_fn = bundle_init_fn,
  .format_fn = format_arm_stall,
  .column_headers = PERFMON_STRINGS ("Backend/pkt", "Frontend/pkt",
				     "Backend/call", "Frontend/call",
				     "packets", "calls"),
  .footer =
    "The stall counter counts every Attributable cycle on which no\n"
    "Attributable instruction or operation was sent for execution\n"
    "on this PE.\n\n"
    "     Stall backend: No operation issued due to the backend\n"
    "     Stall frontend: No operation issued due to the frontend\n"
    "The division between frontend and backend is IMPLEMENTATION DEFINED\n\n"
    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
    " event numbers for full description.\n"
};
