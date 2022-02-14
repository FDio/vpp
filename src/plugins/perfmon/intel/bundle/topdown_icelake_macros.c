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
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static int
is_icelake ()
{
  return clib_cpu_supports_avx512_bitalg () && !clib_cpu_supports_movdir64b ();
}

static perfmon_cpu_supports_t topdown_lvl2_cpu_supports_icx[] = {
  { is_icelake, PERFMON_BUNDLE_TYPE_NODE_OR_THREAD }
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
  L1_METRICS,
  TD_RETIRING = L1_METRICS,
  TD_BAD_SPEC,
  TD_FE_BOUND,
  TD_BE_BOUND,
};

enum
{
  T0,
  T1
};

#define MEMORY_BOUND_FRACTION(ss)                                             \
  ({                                                                          \
    f64 r = (ss->value[STALLS_MEM_ANY] + ss->value[BOUND_ON_STORES]) /        \
	    (f64) (ss->value[STALLS_TOTAL] + ss->value[BOUND_ON_STORES]);     \
    r;                                                                        \
  })

static f64
memory_bound_fraction (perfmon_node_stats_t *ss)
{
  return MEMORY_BOUND_FRACTION (ss);
}

#define _value(ss, x) ((f64) ss->value[x])

#define PERF_METRICS_SUM(ss)                                                  \
  ({                                                                          \
    f64 r = _value (ss, TD_RETIRING) + _value (ss, TD_BAD_SPEC) +             \
	    _value (ss, TD_FE_BOUND) + _value (ss, TD_BE_BOUND);              \
    r;                                                                        \
  })

#define FRONTEND_BOUND(ss)                                                    \
  ({                                                                          \
    f64 r = (_value (ss, TD_FE_BOUND) / PERF_METRICS_SUM (ss)) -              \
	    (_value (ss, UOP_DROPPING) / PERF_METRICS_SUM (ss));              \
    r;                                                                        \
  })

#define BACKEND_BOUND(ss)                                                     \
  ({                                                                          \
    f64 r = (_value (ss, TD_BE_BOUND) / PERF_METRICS_SUM (ss)) +              \
	    ((5 * _value (ss, RECOVERY_CYCLES)) / PERF_METRICS_SUM (ss));     \
    r;                                                                        \
  })

#define RETIRING(ss)                                                          \
  ({                                                                          \
    f64 r = (_value (ss, TD_RETIRING) / _value (ss, TD_SLOTS));               \
    r;                                                                        \
  })

#define BAD_SPECULATION(ss)                                                   \
  ({                                                                          \
    f64 r = (_value (ss, TD_BAD_SPEC) / _value (ss, TD_SLOTS));               \
    r;                                                                        \
  })

#define FETCH_LATENCY(ss)                                                     \
  ({                                                                          \
    f64 r =                                                                   \
      ((5 * _value (ss, UOP_NOT_DELIVERED) - _value (ss, UOP_DROPPING)) /     \
       PERF_METRICS_SUM (ss));                                                \
    r;                                                                        \
  })

static f64
retiring (perfmon_node_stats_t *ss)
{
  return RETIRING (ss);
}

static f64
bad_speculation (perfmon_node_stats_t *ss)
{
  return BAD_SPECULATION (ss);
}

static f64
frontend_bound (perfmon_node_stats_t *ss)
{
  return FRONTEND_BOUND (ss);
}

static f64
backend_bound (perfmon_node_stats_t *ss)
{
  return BACKEND_BOUND (ss);
}

static f64
fetch_latency (perfmon_node_stats_t *ss)
{
  return FETCH_LATENCY (ss);
}

static f64
fetch_bandwidth (perfmon_node_stats_t *ss)
{
  return clib_max (0, frontend_bound (ss) - fetch_latency (ss));
}

static f64
memory_bound (perfmon_node_stats_t *ss)
{

  return backend_bound (ss) * memory_bound_fraction (ss);
}

static f64
core_bound (perfmon_node_stats_t *ss)
{
  return backend_bound (ss) - memory_bound (ss);
}

static u8 *
format_topdown_lvl2_icx (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
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
      sv = 0;
      break;
    case 5:
      sv = fetch_bandwidth (ss);
      sv = 0;
      break;
    case 6:
      sv = memory_bound (ss);
      sv = 0;
      break;
    case 7:
      sv = core_bound (ss);
      sv = 0;
      break;
    }

  s = format (s, "%f", sv * 100);

  return s;
}

static_always_inline f64
perf_get_metric (perfmon_raw_node_stats_t *rs, u8 idx)
{
  f64 slots_t0 =
    rs->raw[T0].value[TD_SLOTS] *
    ((f64) GET_METRIC (rs->raw[T0].value[L1_METRICS], idx) / 0xff);
  f64 slots_t1 =
    rs->raw[T1].value[TD_SLOTS] *
    ((f64) GET_METRIC (rs->raw[T1].value[L1_METRICS], idx) / 0xff);

  return clib_max (0, slots_t1 - slots_t0);
}

typedef enum
{
  TOPDOWN_E_RETIRING = 0,
  TOPDOWN_E_BAD_SPEC,
  TOPDOWN_E_FE_BOUND,
  TOPDOWN_E_BE_BOUND,
} topdown_e_t;

static clib_error_t *
td_preprocess (vlib_main_t *vm, perfmon_node_stats_t *s,
	       perfmon_raw_node_stats_t *rs)
{
  s->value[TD_RETIRING] += perf_get_metric (rs, TOPDOWN_E_RETIRING);
  s->value[TD_BAD_SPEC] += perf_get_metric (rs, TOPDOWN_E_BAD_SPEC);
  s->value[TD_FE_BOUND] += perf_get_metric (rs, TOPDOWN_E_FE_BOUND);
  s->value[TD_BE_BOUND] += perf_get_metric (rs, TOPDOWN_E_BE_BOUND);

  return 0;
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
  .preserve_samples = 0x780, /* TD METRICS */
  .preprocess_fn = td_preprocess,
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
