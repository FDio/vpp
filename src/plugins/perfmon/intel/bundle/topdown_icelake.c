/*
 * Copyright (c) 2022 Intel and/or its affiliates.
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
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static int
is_icelake ()
{
  return clib_cpu_supports_avx512_bitalg () && !clib_cpu_supports_movdir64b ();
}

static perfmon_cpu_supports_t topdown_lvl2_cpu_supports_icx[] = {
  { is_icelake, PERFMON_BUNDLE_TYPE_THREAD }
};

#define GET_METRIC(m, i) (f64) (((m) >> (i * 8)) & 0xff)

enum
{
  TD_SLOTS = 0,
  STALLS_MEM_ANY,
  STALLS_TOTAL,
  BOUND_ON_STORES,
  RECOVERY_CYCLES,
  UOP_DROPPING,
  UOP_NOT_DELIVERED,
  TD_RETIRING,
  TD_BAD_SPEC,
  TD_FE_BOUND,
  TD_BE_BOUND,
};

static_always_inline f64
memory_bound_fraction (perfmon_reading_t *ss)
{
  return (ss->value[STALLS_MEM_ANY] + ss->value[BOUND_ON_STORES]) /
	 (f64) (ss->value[STALLS_TOTAL] + ss->value[BOUND_ON_STORES]);
}

static_always_inline f64
perf_metrics_sum (perfmon_reading_t *ss)
{
  return ss->value[TD_RETIRING] + ss->value[TD_BAD_SPEC] +
	 ss->value[TD_FE_BOUND] + ss->value[TD_BE_BOUND];
}

static_always_inline f64
retiring (perfmon_reading_t *ss)
{
  return ss->value[TD_RETIRING] / perf_metrics_sum (ss);
}

static_always_inline f64
bad_speculation (perfmon_reading_t *ss)
{
  return ss->value[TD_BAD_SPEC] / perf_metrics_sum (ss);
}

static_always_inline f64
frontend_bound (perfmon_reading_t *ss)
{
  return (ss->value[TD_FE_BOUND] / perf_metrics_sum (ss)) -
	 (ss->value[UOP_DROPPING] / perf_metrics_sum (ss));
}

static_always_inline f64
backend_bound (perfmon_reading_t *ss)
{
  return (ss->value[TD_BE_BOUND] / perf_metrics_sum (ss)) +
	 ((5 * ss->value[RECOVERY_CYCLES]) / perf_metrics_sum (ss));
}

static_always_inline f64
fetch_latency (perfmon_reading_t *ss)
{
  f64 r = ((5 * ss->value[UOP_NOT_DELIVERED] - ss->value[UOP_DROPPING]) /
	   (f64) ss->value[TD_SLOTS]);
  return r;
}

static_always_inline f64
fetch_bandwidth (perfmon_reading_t *ss)
{
  return clib_max (0, frontend_bound (ss) - fetch_latency (ss));
}

static_always_inline f64
memory_bound (perfmon_reading_t *ss)
{
  return backend_bound (ss) * memory_bound_fraction (ss);
}

static_always_inline f64
core_bound (perfmon_reading_t *ss)
{
  return backend_bound (ss) - memory_bound (ss);
}

static u8 *
format_topdown_lvl2_icx (u8 *s, va_list *args)
{
  perfmon_reading_t *ss = va_arg (*args, perfmon_reading_t *);
  u64 idx = va_arg (*args, int);
  f64 sv = 0;

  switch (idx)
    {
    case 0:
      sv = retiring (ss);
      break;
    case 1:
      sv = bad_speculation (ss);
      break;
    case 2:
      sv = frontend_bound (ss);
      break;
    case 3:
      sv = backend_bound (ss);
      break;
    case 4:
      sv = fetch_latency (ss);
      break;
    case 5:
      sv = fetch_bandwidth (ss);
      break;
    case 6:
      sv = memory_bound (ss);
      break;
    case 7:
      sv = core_bound (ss);
      break;
    }

  s = format (s, "%f", sv * 100);

  return s;
}

PERFMON_REGISTER_BUNDLE (topdown_lvl2_metric_icx) = {
  .name = "topdown",
  .description = "Top-down Microarchitecture Analysis Level 1 & 2",
  .source = "intel-core",
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
  .n_events = 11,
  .cpu_supports = topdown_lvl2_cpu_supports_icx,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl2_cpu_supports_icx),
  .format_fn = format_topdown_lvl2_icx,
  .column_headers = PERFMON_STRINGS ("% RT", "% BS", "% FE", "% BE", "% FE.FL",
				     "% FE.FB", "% BE.MB", "% BE.CB"),
  .footer = "Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (FE), BackEnd bound (BE),\n"
	    " Fetch Latency (FL), Fetch Bandwidth (FB),\n"
	    " Memory Bound (MB), Core Bound (CB)",
};
