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

#include "vppinfra/types.h"
#include <vppinfra/clib.h>
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
  TOPDOWN_E_RETIRING = 0,
  TOPDOWN_E_BAD_SPEC,
  TOPDOWN_E_FE_BOUND,
  TOPDOWN_E_BE_BOUND,
} topdown_lvl1_t;

enum
{
  TOPDOWN_E_RDPMC_SLOTS = 0,
  TOPDOWN_E_RDPMC_METRICS,
};

typedef f64 (topdown_lvl1_parse_fn_t) (perfmon_stats_t *, topdown_lvl1_t);

/* Parse thread level states from perfmon_reading */
static_always_inline f64
topdown_lvl1_perf_reading (perfmon_stats_t *ss, topdown_lvl1_t e)
{
  /* slots are at value[0], everthing else follows at +1 */
  return ((f64) ss->value[e + 1] / ss->value[0]) * 100;
}

static_always_inline f64
topdown_lvl1_rdpmc_metric (perfmon_stats_t *ss, topdown_lvl1_t e)
{
  f64 slots_t0 =
    ss->t[0].value[TOPDOWN_E_RDPMC_SLOTS] *
    ((f64) GET_METRIC (ss->t[0].value[TOPDOWN_E_RDPMC_METRICS], e) / 0xff);
  f64 slots_t1 =
    ss->t[1].value[TOPDOWN_E_RDPMC_SLOTS] *
    ((f64) GET_METRIC (ss->t[1].value[TOPDOWN_E_RDPMC_METRICS], e) / 0xff);
  u64 slots_delta = ss->t[1].value[TOPDOWN_E_RDPMC_SLOTS] -
		    ss->t[0].value[TOPDOWN_E_RDPMC_SLOTS];

  slots_t1 = slots_t1 - slots_t0;

  return (slots_t1 / slots_delta) * 100;
}

static f64
calculate_topdown_lvl1 (perfmon_stats_t *ts, int idx, uword type)
{
  f64 sv = 0;
  topdown_lvl1_parse_fn_t *parse_fn,
    *parse_fns[PERFMON_BUNDLE_TYPE_MAX] = { 0, topdown_lvl1_rdpmc_metric,
					    topdown_lvl1_perf_reading, 0 };

  parse_fn = parse_fns[type];
  ASSERT (parse_fn);

  switch (idx)
    {
    case 0:
      sv =
	parse_fn (ts, TOPDOWN_E_BAD_SPEC) + parse_fn (ts, TOPDOWN_E_RETIRING);
      break;
    case 1:
      sv =
	parse_fn (ts, TOPDOWN_E_BE_BOUND) + parse_fn (ts, TOPDOWN_E_FE_BOUND);
      break;
    default:
      sv = parse_fn (ts, (topdown_lvl1_t) idx - 2);
      break;
    }

  return sv;
}

static u8 *
format_topdown_lvl1 (u8 *s, va_list *args)
{
  perfmon_stats_t *ss = va_arg (*args, perfmon_stats_t *);
  u64 idx = va_arg (*args, int);
  uword type = va_arg (*args, uword);

  f64 sv = calculate_topdown_lvl1 (ss, idx, type);
  s = format (s, "%f", sv);

  return s;
}

static perfmon_cpu_supports_t topdown_lvl1_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg,
    PERFMON_BUNDLE_TYPE_NODE_FLAG | PERFMON_BUNDLE_TYPE_THREAD_FLAG },
  { clib_cpu_supports_movdiri, PERFMON_BUNDLE_TYPE_THREAD_FLAG },
};

PERFMON_REGISTER_BUNDLE (topdown_lvl1_metric) = {
  .name = "topdown-level1",
  .description = "Top-down Microarchitecture Analysis Level 1",
  .source = "intel-core",
  .offset_type = PERFMON_OFFSET_TYPE_METRICS,
  .events[0] = INTEL_CORE_E_TOPDOWN_SLOTS,
  .events[1] = INTEL_CORE_E_TOPDOWN_L1_RETIRING_METRIC,
  .events[2] = INTEL_CORE_E_TOPDOWN_L1_BAD_SPEC_METRIC,
  .events[3] = INTEL_CORE_E_TOPDOWN_L1_FE_BOUND_METRIC,
  .events[4] = INTEL_CORE_E_TOPDOWN_L1_BE_BOUND_METRIC,
  .n_events = 5,
  .metrics[0] = RDPMC_FIXED_SLOTS | FIXED_COUNTER_SLOTS,
  .metrics[1] = RDPMC_L1_METRICS | METRIC_COUNTER_TOPDOWN_L1,
  .n_metrics = 2,
  .cpu_supports = topdown_lvl1_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl1_cpu_supports),
  .format_fn = format_topdown_lvl1,
  .column_headers = PERFMON_STRINGS ("% NS", "% ST", "% NS.RT", "% NS.BS",
				     "% ST.FE", "% ST.BE"),
  .footer = "Not Stalled (NS),STalled (ST),\n"
	    " Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (FE), BackEnd bound (BE)",
};
