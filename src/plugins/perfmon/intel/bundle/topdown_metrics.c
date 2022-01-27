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
#include <vppinfra/math.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

#define GET_METRIC(m, i)  (((m) >> (i * 8)) & 0xff)
#define GET_RATIO(m, i)	  (((m) >> (i * 32)) & 0xffffffff)
#define RDPMC_SLOTS	  (1 << 30) /* fixed slots */
#define RDPMC_METRICS	  (1 << 29) /* l1 & l2 metric counters */

#define FIXED_COUNTER_SLOTS	  3
#define METRIC_COUNTER_TOPDOWN_L1_L2 0

typedef enum
{
  TOPDOWN_E_RETIRING = 0,
  TOPDOWN_E_BAD_SPEC,
  TOPDOWN_E_FE_BOUND,
  TOPDOWN_E_BE_BOUND,
  TOPDOWN_E_HEAVYOPS,
  TOPDOWN_E_LIGHTOPS,
  TOPDOWN_E_BMISPRED,
  TOPDOWN_E_MCHCLEAR,
  TOPDOWN_E_FETCHLAT,
  TOPDOWN_E_FETCH_BW,
  TOPDOWN_E_MEMBOUND,
  TOPDOWN_E_CORBOUND,
  TOPDOWN_E_MAX,
} topdown_e_t;

enum
{
  TOPDOWN_E_RDPMC_SLOTS = 0,
  TOPDOWN_E_RDPMC_METRICS,
};

typedef f64 (topdown_lvl1_parse_fn_t) (void *, topdown_e_t);

/* Parse thread level states from perfmon_reading */
static_always_inline f64
topdown_lvl1_perf_reading (void *ps, topdown_e_t e)
{
  perfmon_reading_t *ss = (perfmon_reading_t *) ps;

  /* slots are at value[0], everthing else follows at +1 */
  return ((f64) ss->value[e + 1] / ss->value[0]) * 100;
}

static_always_inline f64
topdown_lvl1_rdpmc_metric (void *ps, topdown_e_t e)
{
  perfmon_node_stats_t *ss = (perfmon_node_stats_t *) ps;
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

/* Convert the TopDown enum to the perf reading index */
#define TO_LVL2_PERF_IDX(e)                                                   \
  ({                                                                          \
    u8 to_idx[TOPDOWN_E_MAX] = { 0, 0, 0, 0, 5, 5, 6, 6, 7, 7, 8, 8 };        \
    to_idx[e];                                                                \
  })

/* Parse thread level stats from perfmon_reading */
static_always_inline f64
topdown_lvl2_perf_reading (void *ps, topdown_e_t e)
{
  perfmon_reading_t *ss = (perfmon_reading_t *) ps;
  u64 value = ss->value[TO_LVL2_PERF_IDX (e)];

  /* If it is an L1 metric, call L1 format */
  if (TOPDOWN_E_BE_BOUND >= e)
    {
      return topdown_lvl1_perf_reading (ps, e);
    }

  /* all the odd metrics, are inferred from even and L1 metrics */
  if (e & 0x1)
    {
      topdown_e_t e1 = TO_LVL2_PERF_IDX (e) - 4;
      value = ss->value[e1] - value;
    }

  return (f64) value / ss->value[0] * 100;
}

/* Convert the TopDown enum to the rdpmc metric byte position */
#define TO_LVL2_METRIC_BYTE(e)                                                \
  ({                                                                          \
    u8 to_metric[TOPDOWN_E_MAX] = { 0, 0, 0, 0, 4, 4, 5, 5, 6, 6, 7, 7 };     \
    to_metric[e];                                                             \
  })

/* Convert the TopDown L2 enum to the reference TopDown L1 enum */
#define TO_LVL1_REF(e)                                                        \
  ({                                                                          \
    u8 to_lvl1[TOPDOWN_E_MAX] = { -1,                                         \
				  -1,                                         \
				  -1,                                         \
				  -1,                                         \
				  TOPDOWN_E_RETIRING,                         \
				  TOPDOWN_E_RETIRING,                         \
				  TOPDOWN_E_BAD_SPEC,                         \
				  TOPDOWN_E_BAD_SPEC,                         \
				  TOPDOWN_E_FE_BOUND,                         \
				  TOPDOWN_E_FE_BOUND,                         \
				  TOPDOWN_E_BE_BOUND,                         \
				  TOPDOWN_E_BE_BOUND };                       \
    to_lvl1[e];                                                               \
  })

static_always_inline f64
topdown_lvl2_rdpmc_metric (void *ps, topdown_e_t e)
{
  f64 r, l1_value = 0;

  /* If it is an L1 metric, call L1 format */
  if (TOPDOWN_E_BE_BOUND >= e)
    {
      return topdown_lvl1_rdpmc_metric (ps, e);
    }

  /* all the odd metrics, are inferred from even and L1 metrics */
  if (e & 0x1)
    {
      /* get the L1 reference metric */
      l1_value = topdown_lvl1_rdpmc_metric (ps, TO_LVL1_REF (e));
    }

  /* calculate the l2 metric */
  r =
    fabs (l1_value - topdown_lvl1_rdpmc_metric (ps, TO_LVL2_METRIC_BYTE (e)));
  return r;
}

static u8 *
format_topdown_lvl2 (u8 *s, va_list *args)
{
  void *ps = va_arg (*args, void *);
  u64 idx = va_arg (*args, int);
  perfmon_bundle_type_t type = va_arg (*args, perfmon_bundle_type_t);
  f64 sv = 0;

  topdown_lvl1_parse_fn_t *parse_fn,
    *parse_fns[PERFMON_BUNDLE_TYPE_MAX] = { 0, topdown_lvl2_rdpmc_metric,
					    topdown_lvl2_perf_reading, 0 };

  parse_fn = parse_fns[type];
  ASSERT (parse_fn);

  sv = parse_fn (ps, (topdown_e_t) idx);
  s = format (s, "%f", sv);

  return s;
}

static perfmon_cpu_supports_t topdown_lvl2_cpu_supports[] = {
  /* Intel SPR supports papi/thread or rdpmc/node */
  { clib_cpu_supports_avx512_fp16, PERFMON_BUNDLE_TYPE_NODE_OR_THREAD }
};

PERFMON_REGISTER_BUNDLE (topdown_lvl2_metric) = {
  .name = "topdown",
  .description = "Top-down Microarchitecture Analysis Level 1 & 2",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_TOPDOWN_SLOTS,
  .events[1] = INTEL_CORE_E_TOPDOWN_L1_RETIRING_METRIC,
  .events[2] = INTEL_CORE_E_TOPDOWN_L1_BAD_SPEC_METRIC,
  .events[3] = INTEL_CORE_E_TOPDOWN_L1_FE_BOUND_METRIC,
  .events[4] = INTEL_CORE_E_TOPDOWN_L1_BE_BOUND_METRIC,
  .events[5] = INTEL_CORE_E_TOPDOWN_L2_HEAVYOPS_METRIC,
  .events[6] = INTEL_CORE_E_TOPDOWN_L2_BMISPRED_METRIC,
  .events[7] = INTEL_CORE_E_TOPDOWN_L2_FETCHLAT_METRIC,
  .events[8] = INTEL_CORE_E_TOPDOWN_L2_MEMBOUND_METRIC,
  .n_events = 9,
  .preserve_samples = 0x1FF,
  .cpu_supports = topdown_lvl2_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl2_cpu_supports),
  .format_fn = format_topdown_lvl2,
  .column_headers = PERFMON_STRINGS ("% RT", "% BS", "% FE", "% BE", "% RT.HO",
				     "% RT.LO", "% BS.BM", "% BS.MC",
				     "% FE.FL", "% FE.FB", "% BE.MB",
				     "% BE.CB"),
  .footer = "Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (1FE), BackEnd bound (BE),\n"
	    " Light Operations (LO), Heavy Operations (HO),\n"
	    " Branch Misprediction (BM), Machine Clears (MC),\n"
	    " Fetch Latency (FL), Fetch Bandwidth (FB),\n"
	    " Memory Bound (MB), Core Bound (CB)",
};
