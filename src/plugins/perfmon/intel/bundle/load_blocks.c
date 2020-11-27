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
format_load_blocks (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%12lu", ns->n_calls);
      break;
    case 1:
      s = format (s, "%12lu", ns->n_packets);
      break;
    case 2:
      s = format (s, "%9.2f", (f64) ns->value[0] / ns->n_calls);
      break;
    case 3:
      s = format (s, "%9.2f", (f64) ns->value[1] / ns->n_calls);
      break;
    case 4:
      s = format (s, "%9.2f", (f64) ns->value[2] / ns->n_calls);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (load_blocks) = {
  .name = "load-blocks",
  .description = "load operations blocked due to various uarch reasons",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = INTEL_CORE_E_LD_BLOCKS_STORE_FORWARD,
  .events[1] = INTEL_CORE_E_LD_BLOCKS_NO_SR,
  .events[2] = INTEL_CORE_E_LD_BLOCKS_PARTIAL_ADDRESS_ALIAS,
  .n_events = 3,
  .format_fn = format_load_blocks,
  .column_headers = PERFMON_STRINGS ("Calls", "Packets", "[1]", "[2]", "[3]"),
  .footer = "Per node call statistics:\n"
	    "[1] Loads blocked due to overlapping with a preceding store that "
	    "cannot be forwarded.\n"
	    "[2] The number of times that split load operations are "
	    "temporarily blocked because\n"
	    "    all resources for handling the split accesses are in use\n"
	    "[3] False dependencies in Memory Order Buffer (MOB) due to "
	    "partial compare on address.\n",
};
