/*
 * Copyright (c) 2021 Intel and/or its affiliates.
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

#define GET_METRIC(m, i)  (((m) >> (i * 8)) & 0xff)
#define GET_RATIO(m, i)	  (((m) >> (i * 32)) & 0xffffffff)
#define RDPMC_FIXED_SLOTS (1 << 30) /* fixed slots */
#define RDPMC_L1_METRICS  (1 << 29) /* l1 metric counters */

#define FIXED_COUNTER_SLOTS	  3
#define METRIC_COUNTER_TOPDOWN_L1 0

typedef enum
{
  TOPDOWN_E_METRIC_RETIRING = 0,
  TOPDOWN_E_METRIC_BAD_SPEC,
  TOPDOWN_E_METRIC_FE_BOUND,
  TOPDOWN_E_METRIC_BE_BOUND,
} topdown_lvl1_counters_t;

enum
{
  TOPDOWN_SLOTS = 0,
  TOPDOWN_METRICS,
} topdown_lvl1_metrics_t;

static_always_inline f32
topdown_lvl1_parse_row (perfmon_node_stats_t *ns, topdown_lvl1_counters_t e)
{
  f64 slots_t0 =
    ns->t[0].value[TOPDOWN_SLOTS] *
    ((f64) GET_METRIC (ns->t[0].value[TOPDOWN_METRICS], e) / 0xff);
  f64 slots_t1 =
    ns->t[1].value[TOPDOWN_SLOTS] *
    ((f64) GET_METRIC (ns->t[1].value[TOPDOWN_METRICS], e) / 0xff);
  u64 slots_delta =
    ns->t[1].value[TOPDOWN_SLOTS] - ns->t[0].value[TOPDOWN_SLOTS];

  slots_t1 = slots_t1 - slots_t0;

  return (slots_t1 / slots_delta) * 100;
}

static u8 *
format_topdown_lvl1 (u8 *s, va_list *args)
{
  perfmon_node_stats_t *st = va_arg (*args, perfmon_node_stats_t *);
  u64 row = va_arg (*args, int);

  switch (row)
    {
    case 0:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_BAD_SPEC) +
		    topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_RETIRING));
      break;
    case 1:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_BE_BOUND) +
		    topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_FE_BOUND));
      break;
    case 2:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_RETIRING));
      break;
    case 3:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_BAD_SPEC));
      break;
    case 4:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_FE_BOUND));
      break;
    case 5:
      s = format (s, "%f",
		  topdown_lvl1_parse_row (st, TOPDOWN_E_METRIC_BE_BOUND));
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (topdown_lvl1) = {
  .name = "topdown-level1",
  .description = "Top-down Microarchitecture Analysis Level 1",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_NODE,
  .offset_type = PERFMON_OFFSET_TYPE_METRICS,
  .events[0] = INTEL_CORE_E_TOPDOWN_SLOTS,
  .events[1] = INTEL_CORE_E_TOPDOWN_L1_METRICS,
  .metrics[0] = RDPMC_FIXED_SLOTS | FIXED_COUNTER_SLOTS,
  .metrics[1] = RDPMC_L1_METRICS | METRIC_COUNTER_TOPDOWN_L1,
  .n_events = 2,
  .cpu_supports = clib_cpu_supports_avx512_bitalg,
  .format_fn = format_topdown_lvl1,
  .column_headers = PERFMON_STRINGS ("% NS", "% ST", "% NS.RT", "% NS.MP",
				     "% ST.FE", "% ST.BE"),
  .footer = "Not Stalled (NS),STalled (ST),\n"
	    "Retiring (RT),MisPredicted (MP),\n"
	    "FrontEnd bound (FE),BackEnd bound (BE)",
};
