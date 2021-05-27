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
calculate_load_blocks (struct perfmon_stats *ts, int idx)
{
  f64 sv = 0;

  if (!ts->n_calls)
    return 0;

  switch (idx)
    {
    case 0:
      sv = ts->n_calls;
      break;
    case 1:
      sv = ts->n_packets;
      break;
    case 2:
      sv = (u64) ts->value[0] / ts->n_calls;
      break;
    case 3:
      sv = (u64) ts->value[1] / ts->n_calls;
      break;
    case 4:
      sv = (u64) ts->value[2] / ts->n_calls;
      break;
    }
  return sv;
}

static u64
update_load_blocks (struct perfmon_stats *ts, int idx)
{
  return (u64) calculate_load_blocks (ts, idx);
}

static u8 *
format_load_blocks (u8 *s, va_list *args)
{
  perfmon_stats_t *ss = va_arg (*args, perfmon_stats_t *);
  int idx = va_arg (*args, int);
  f64 sv = calculate_load_blocks (ss, idx);

  switch (idx)
    {
    case 0:
    case 1:
      s = format (s, "%12lu", sv);
      break;
    default:
      s = format (s, "%9.2f", sv);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (load_blocks) = {
  .name = "load-blocks",
  .description = "load operations blocked due to various uarch reasons",
  .source = "intel-core",
  .type_flags = PERFMON_BUNDLE_TYPE_NODE_FLAG |
		PERFMON_BUNDLE_TYPE_THREAD_FLAG,
  .events[0] = INTEL_CORE_E_LD_BLOCKS_STORE_FORWARD,
  .events[1] = INTEL_CORE_E_LD_BLOCKS_NO_SR,
  .events[2] = INTEL_CORE_E_LD_BLOCKS_PARTIAL_ADDRESS_ALIAS,
  .n_events = 3,
  .format_fn = format_load_blocks,
  .update_fn = update_load_blocks,
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
