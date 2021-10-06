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

typedef enum
{
  TOPDOWN_E_RETIRING = 0,
  TOPDOWN_E_BAD_SPEC,
  TOPDOWN_E_FE_BOUND,
  TOPDOWN_E_BE_BOUND,
  TOPDOWN_E_MAX,
} topdown_lvl1_t;

static u8 *
format_topdown_lvl1 (u8 *s, va_list *args)
{
  perfmon_reading_t *ss = va_arg (*args, perfmon_reading_t *);
  u64 idx = va_arg (*args, int);
  f64 sv = 0;
  u64 total = 0;

  for (int i = 0; i < TOPDOWN_E_MAX; i++)
    total += ss->value[i];

  switch (idx)
    {
    case 0:
      sv = (f64) ss->value[TOPDOWN_E_RETIRING] + ss->value[TOPDOWN_E_BAD_SPEC];
      break;
    case 1:
      sv = (f64) ss->value[TOPDOWN_E_FE_BOUND] + ss->value[TOPDOWN_E_BE_BOUND];
      break;
    default:
      sv = (f64) ss->value[idx - 2];
      break;
    }

  sv = (sv / total) * 100;
  s = format (s, "%f", sv);
  return s;
}

static int
is_tremont ()
{
  return clib_cpu_supports_movdir64b () && !clib_cpu_supports_avx2 ();
}

static perfmon_cpu_supports_t topdown_lvl1_cpu_supports[] = {
  { is_tremont, PERFMON_BUNDLE_TYPE_THREAD }
};

PERFMON_REGISTER_BUNDLE (topdown_lvl1_tremont) = {
  .name = "topdown-level1",
  .description = "Top-down Microarchitecture Analysis Level 1",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_TOPDOWN_L1_RETIRING_TREMONT,
  .events[1] = INTEL_CORE_E_TOPDOWN_L1_BAD_SPEC_TREMONT,
  .events[2] = INTEL_CORE_E_TOPDOWN_L1_FE_BOUND_TREMONT,
  .events[3] = INTEL_CORE_E_TOPDOWN_L1_BE_BOUND_TREMONT,
  .n_events = 4,
  .cpu_supports = topdown_lvl1_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (topdown_lvl1_cpu_supports),
  .format_fn = format_topdown_lvl1,
  .column_headers = PERFMON_STRINGS ("% NS", "% ST", "% NS.RT", "% NS.BS",
				     "% ST.FE", "% ST.BE"),
  .footer = "Not Stalled (NS),STalled (ST),\n"
	    " Retiring (RT), Bad Speculation (BS),\n"
	    " FrontEnd bound (FE), BackEnd bound (BE)",
};
