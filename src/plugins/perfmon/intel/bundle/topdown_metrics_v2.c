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

#include "vppinfra/elf.h"
#include <vnet/vnet.h>
#include <vppinfra/math.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

#define GET_METRIC(m, i) (((m) >> (i * 8)) & 0xff)

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
  TD_SLOTS = 0,
  DUMMY1,
  DUMMY2,
  DUMMY3,
  DUMMY4,
  DUMMY5,
  DUMMY6,
  TD_RETIRING,
  TD_BAD_SPEC,
  TD_FE_BOUND,
  TD_BE_BOUND,
  TD_HEAVYOPS,
  TD_BMISPRED,
  TD_FETCHLAT,
  TD_MEMBOUND,
};

enum
{
  T0,
  T1
};

/* Parse thread level states from perfmon_reading */
static_always_inline f64
td_l1_calc (void *ps, topdown_e_t e, perfmon_bundle_type_t t)
{
  f64 r = 0;

  if (PERFMON_BUNDLE_TYPE_NODE == t)
    {
      perfmon_node_stats_t *ns = (perfmon_node_stats_t *) ps;

      if (ns->value[e + 7] < 0)
	return 0;

      /* slots are at value[0], everthing else follows at +1 */
      r = (ns->value[e + 7] / (f64) ns->value[TD_SLOTS]) * 100;
    }
  else
    {
      perfmon_reading_t *ts = (perfmon_reading_t *) ps;

      if (ts->value[e + 7] < 0)
	return 0;

      r = (ts->value[e + 7] / (f64) ts->value[TD_SLOTS]) * 100;
    }

  ASSERT (r < 100);

  return r;
}

static_always_inline f64
perf_get_metric (perfmon_raw_node_stats_t *rs, u8 idx)
{
  f64 slots_t0 =
    rs->raw[T0].value[TD_SLOTS] *
    ((f64) GET_METRIC (rs->raw[T0].value[TD_RETIRING], idx) / 0xff);
  f64 slots_t1 =
    rs->raw[T1].value[TD_SLOTS] *
    ((f64) GET_METRIC (rs->raw[T1].value[TD_RETIRING], idx) / 0xff);

  return clib_max (0, slots_t1 - slots_t0);
}

static u8 *
format_topdown_lvl1 (u8 *s, va_list *args)
{
  void *ps = va_arg (*args, void *);
  u64 idx = va_arg (*args, int);
  perfmon_bundle_type_t type = va_arg (*args, perfmon_bundle_type_t);
  f64 sv = 0;

  switch (idx)
    {
    case 0:
      sv = td_l1_calc (ps, TOPDOWN_E_BAD_SPEC, type) +
	   td_l1_calc (ps, TOPDOWN_E_RETIRING, type);
      break;
    case 1:
      sv = td_l1_calc (ps, TOPDOWN_E_BE_BOUND, type) +
	   td_l1_calc (ps, TOPDOWN_E_FE_BOUND, type);
      break;
    default:
      sv = td_l1_calc (ps, (topdown_e_t) idx - 2, type);
      break;
    }

  s = format (s, "%f", sv);

  if (idx == 5)
    {
      perfmon_node_stats_t *ns = (perfmon_node_stats_t *) ps;

      s = format (s, " %x %x %x %x %x", ns->value[TD_SLOTS],
		  ns->value[TD_RETIRING], ns->value[TD_BAD_SPEC],
		  ns->value[TD_FE_BOUND], ns->value[TD_BE_BOUND]);
    }

  return s;
}

static perfmon_cpu_supports_t topdown_lvl1_cpu_supports[] = {
  /* Intel ICX supports papi/thread or rdpmc/node */
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE_OR_THREAD }
};

static clib_error_t *
td_preprocess (vlib_main_t *vm, perfmon_node_stats_t *s,
	       perfmon_raw_node_stats_t *rs)
{
  f64 v[4];

  v[0] = perf_get_metric (rs, TOPDOWN_E_RETIRING);
  v[1] = perf_get_metric (rs, TOPDOWN_E_BAD_SPEC);
  v[2] = perf_get_metric (rs, TOPDOWN_E_FE_BOUND);
  v[3] = perf_get_metric (rs, TOPDOWN_E_BE_BOUND);

  s->value[TD_RETIRING] += v[0];
  s->value[TD_BAD_SPEC] += v[1];
  s->value[TD_FE_BOUND] += v[2];
  s->value[TD_BE_BOUND] += v[3];

  return 0;
}

PERFMON_REGISTER_BUNDLE (topdown_lvl1_metric) = {
  .name = "topdown-level1",
  .description = "Top-down Microarchitecture Analysis Level 1",
  .source = "intel-core",
  /* .events[0] = INTEL_CORE_E_TOPDOWN_SLOTS, */
  /* .events[1] = INTEL_CORE_E_TOPDOWN_L1_RETIRING_METRIC, */
  /* .events[2] = INTEL_CORE_E_TOPDOWN_L1_BAD_SPEC_METRIC, */
  /* .events[3] = INTEL_CORE_E_TOPDOWN_L1_FE_BOUND_METRIC, */
  /* .events[4] = INTEL_CORE_E_TOPDOWN_L1_BE_BOUND_METRIC, */
  .events[0] = INTEL_CORE_E_TOPDOWN_SLOTS,
  .events[1] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_MEM_ANY,
  .events[2] = INTEL_CORE_E_CYCLE_ACTIVITY_STALLS_TOTAL,
  .events[3] = INTEL_CORE_E_EXE_ACTIVITY_BOUND_ON_STORES,
  .events[4] = INTEL_CORE_E_INT_MISC_RECOVERY_CYCLES,
  .events[5] = INTEL_CORE_E_INT_MISC_UOP_DROPPING,
  .events[6] = INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CORE,
  .events[7] = INTEL_CORE_E_TOPDOWN_L1_RETIRING_METRIC,
  .events[8] = INTEL_CORE_E_TOPDOWN_L1_BAD_SPEC_METRIC,
  .events[9] = INTEL_CORE_E_TOPDOWN_L1_FE_BOUND_METRIC,
  .events[10] = INTEL_CORE_E_TOPDOWN_L1_BE_BOUND_METRIC,
  /* .n_events = 5, */
  /* .preserve_samples = 0x1E, */
  .n_events = 11,
  .preserve_samples = 0x780, /* TD METRICS */
  .preprocess_fn = td_preprocess,
  .cpu_supports = topdown_lvl1_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl1_cpu_supports),
  .format_fn = format_topdown_lvl1,
  .column_headers = PERFMON_STRINGS ("% NS", "% ST", "% NS.RT", "% NS.BS",
				     "% ST.FE", "% ST.BE"),
  .footer = "Not Stalled (NS),STalled (ST),\n"
	    " Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (FE), BackEnd bound (BE)",
};

/* Convert the TopDown enum to the perf reading index */
#define TO_LVL2_PERF_IDX(e)                                                   \
  ({                                                                          \
    u8 to_idx[TOPDOWN_E_MAX] = { 0, 0, 0, 0, 5, 5, 6, 6, 7, 7, 8, 8 };        \
    to_idx[e];                                                                \
  })

/* Parse thread level stats from perfmon_reading */
static_always_inline f64
td_l2_calc (void *ps, topdown_e_t e, perfmon_bundle_type_t t)
{
  /* If it is an L1 metric, call L1 format */
  if (TOPDOWN_E_BE_BOUND >= e)
    {
      return td_l1_calc (ps, e, t);
    }

  if (PERFMON_BUNDLE_TYPE_NODE == t)
    {
      perfmon_node_stats_t *ns = (perfmon_node_stats_t *) ps;
      u64 value = ns->value[TO_LVL2_PERF_IDX (e)];

      /* all the odd metrics, are inferred from even and L1 metrics */
      if (e & 0x1)
	{
	  topdown_e_t e1 = TO_LVL2_PERF_IDX (e) - 4;
	  value = ns->value[e1] - value;
	}

      return (f64) value / ns->value[0] * 100;
    }

  perfmon_reading_t *rs = (perfmon_reading_t *) ps;
  u64 value = rs->value[TO_LVL2_PERF_IDX (e)];

  /* all the odd metrics, are inferred from even and L1 metrics */
  if (e & 0x1)
    {
      topdown_e_t e1 = TO_LVL2_PERF_IDX (e) - 4;
      value = rs->value[e1] - value;
    }

  return (f64) value / rs->value[0] * 100;
}

static clib_error_t *
td2_preprocess (vlib_main_t *vm, perfmon_node_stats_t *s,
		perfmon_raw_node_stats_t *rs)
{
  s->value[TD_RETIRING] += perf_get_metric (rs, TOPDOWN_E_RETIRING);
  s->value[TD_BAD_SPEC] += perf_get_metric (rs, TOPDOWN_E_BAD_SPEC);
  s->value[TD_FE_BOUND] += perf_get_metric (rs, TOPDOWN_E_FE_BOUND);
  s->value[TD_BE_BOUND] += perf_get_metric (rs, TOPDOWN_E_BE_BOUND);
  /* s->value[TD_HEAVYOPS] += perf_get_metric (rs, TOPDOWN_E_HEAVYOPS); */
  /* s->value[TD_BMISPRED] += perf_get_metric (rs, TOPDOWN_E_BMISPRED); */
  /* s->value[TD_FETCHLAT] += perf_get_metric (rs, TOPDOWN_E_FETCHLAT); */
  /* s->value[TD_MEMBOUND] += perf_get_metric (rs, TOPDOWN_E_MEMBOUND); */

  return 0;
}

static u8 *
format_topdown_lvl2 (u8 *s, va_list *args)
{
  void *ps = va_arg (*args, void *);
  u64 idx = va_arg (*args, int);
  perfmon_bundle_type_t type = va_arg (*args, perfmon_bundle_type_t);
  f64 sv = 0;

  sv = td_l2_calc (ps, (topdown_e_t) idx, type);
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
  .preserve_samples = 0x1FE,
  .preprocess_fn = td2_preprocess,
  .cpu_supports = topdown_lvl2_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl2_cpu_supports),
  .format_fn = format_topdown_lvl2,
  .column_headers = PERFMON_STRINGS ("% RT", "% BS", "% FE", "% BE", "% RT.HO",
				     "% RT.LO", "% BS.BM", "% BS.MC",
				     "% FE.FL", "% FE.FB", "% BE.MB",
				     "% BE.CB"),
  .footer = "Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (FE), BackEnd bound (BE),\n"
	    " Light Operations (LO), Heavy Operations (HO),\n"
	    " Branch Misprediction (BM), Machine Clears (MC),\n"
	    " Fetch Latency (FL), Fetch Bandwidth (FB),\n"
	    " Memory Bound (MB), Core Bound (CB)",
};
