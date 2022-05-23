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
  BR_RETIRED,
  BR_MIS_PRED_RETIRED,
  BR_PRED,
  BR_MIS_PRED
};

static u8 *
format_arm_branch_pred (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ns = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%.2f", (f64) ns->value[BR_RETIRED] / ns->n_calls);
      break;

    case 1:
      s = format (s, "%.2f", (f64) ns->value[BR_RETIRED] / ns->n_packets);
      break;

    case 2:
      s =
	format (s, "%.2f", (f64) ns->value[BR_MIS_PRED_RETIRED] / ns->n_calls);
      break;

    case 3:
      s = format (s, "%.2f",
		  (f64) ns->value[BR_MIS_PRED_RETIRED] / ns->n_packets);
      break;

    case 4:
      s =
	format (s, "%.2f%%",
		(ns->value[BR_RETIRED] ? (f64) ns->value[BR_MIS_PRED_RETIRED] /
					   ns->value[BR_RETIRED] * 100 :
					       0));
      break;

    case 5:
      s = format (s, "%.2f", (f64) ns->value[BR_PRED] / ns->n_calls);
      break;

    case 6:
      s = format (s, "%.2f", (f64) ns->value[BR_PRED] / ns->n_packets);
      break;

    case 7:
      s = format (s, "%.2f", (f64) ns->value[BR_MIS_PRED] / ns->n_calls);
      break;

    case 8:
      s = format (s, "%.2f", (f64) ns->value[BR_MIS_PRED] / ns->n_packets);
      break;

    case 9:
      s = format (s, "%.2f%%",
		  (ns->value[BR_PRED] ?
			   (f64) ns->value[BR_MIS_PRED] / ns->value[BR_PRED] * 100 :
			   0));
      break;

    case 10:
      s = format (s, "%llu", ns->n_packets);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (arm_branch_pred) = {
  .name = "branch-pred",
  .description = "Branch (mis)predictions per call/packet",
  .source = "arm",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .events[0] = ARMV8_PMUV3_BR_RETIRED,
  .events[1] = ARMV8_PMUV3_BR_MIS_PRED_RETIRED,
  .events[2] = ARMV8_PMUV3_BR_PRED,
  .events[3] = ARMV8_PMUV3_BR_MIS_PRED,
  .n_events = 4,
  .n_columns = 11,
  .format_fn = format_arm_branch_pred,
  .column_headers = PERFMON_STRINGS ("[1.1]", "[1.2]", "[1.3]", "[1.4]", "\%",
				     "[2.1]", "[2.2]", "[2.3]", "[2.4]", "\%",
				     "pkts"),
  /*
   * set a bit for every event used in each column
   * this allows us to disable columns at bundle registration if an
   * event is not supported
   */
  .column_events = PERFMON_COLUMN_EVENTS (
    SET_BIT (BR_RETIRED), SET_BIT (BR_RETIRED), SET_BIT (BR_MIS_PRED_RETIRED),
    SET_BIT (BR_MIS_PRED_RETIRED),
    SET_BIT (BR_RETIRED) | SET_BIT (BR_MIS_PRED_RETIRED), SET_BIT (BR_PRED),
    SET_BIT (BR_PRED), SET_BIT (BR_MIS_PRED), SET_BIT (BR_MIS_PRED),
    SET_BIT (BR_PRED) | SET_BIT (BR_MIS_PRED), 0),
  .footer =
    "An instruction that has been executed and retired is defined to\n"
    "be architecturally executed. When a PE can perform speculative\n"
    "execution, an instruction is not architecturally executed if the\n"
    "PE discards the results of the speculative execution.\n\n"
    "Per node statistics:\n"
    "[1] Branch instruction architecturally executed\n"
    "    [1.1] Branches/call\n"
    "    [1.2] Branches/pkt\n"
    "    [1.3] Mispredicted/call \n"
    "    [1.4] Mispredicted/pkt\n"
    "    [\%] Percentage of branches mispredicted\n"
    "[2] Predictable branch speculatively executed\n"
    "    [2.1] Branches/call\n"
    "    [2.2] Branches/pkt\n"
    "    [2.3] Mispredicted/call \n"
    "    [2.4] Mispredicted/pkt\n"
    "    [\%] Percentage of branches mispredicted\n\n"
    "- See Armv8-A Architecture Reference Manual, D7.10 PMU events and"
    " event numbers for full description.\n"
};
