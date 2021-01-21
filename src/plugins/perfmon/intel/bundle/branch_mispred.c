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

static u8 *
format_branch_mispredictions (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%9.2f", ns->value[0] / (f64) ns->n_calls);
      break;
    case 1:
      s = format (s, "%9.2f", ns->value[0] / (f64) ns->n_packets);
      break;
    case 2:
      s = format (s, "%9.2f", ns->value[1] / (f64) ns->n_calls);
      break;
    case 3:
      s = format (s, "%9.2f", ns->value[1] / (f64) ns->n_packets);
      break;
    case 4:
      s = format (s, "%05.2f", (ns->value[2] / (f64) ns->value[0]) * 100);
      break;
    case 5:
      s = format (s, "%9f", (f64) ns->value[0]);
      break;
    case 6:
      s = format (s, "%9f", (f64) ns->value[1]);
      break;
    case 7:
      s = format (s, "%9f", (f64) ns->value[2]);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (branch_mispredictions) = {
  .name = "branch-mispred",
  .description = "Branches, branches taken and mis-predictions",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = INTEL_CORE_E_BR_INST_RETIRED_ALL_BRANCHES,
  .events[1] = INTEL_CORE_E_BR_INST_RETIRED_NEAR_TAKEN,
  .events[2] = INTEL_CORE_E_BR_MISP_RETIRED_ALL_BRANCHES,
  .n_events = 3,
  .format_fn = format_branch_mispredictions,
  .column_headers = PERFMON_STRINGS ("Branches/call", "Branches/pkt",
				     "Taken/call", "Taken/pkt", "% MisPred"),
  .raw_column_headers = PERFMON_STRINGS ("branches", "taken", "misses"),
};
