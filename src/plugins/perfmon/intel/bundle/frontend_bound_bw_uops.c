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

enum
{
  THREAD_P,
  THREE_UOP,
  TWO_UOP,
  ONE_UOP,
  NO_UOP,
  FOUR_UOP,
};

static u8 *
format_intel_frontend_bound_bw_uops (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;
  f64 cycles = ss->value[THREAD_P];

  switch (row)
    {
    case 0:
      sv = (ss->value[FOUR_UOP] / cycles) * 100;
      break;
    case 1:
      sv = ((ss->value[THREE_UOP] - ss->value[TWO_UOP]) / cycles) * 100;
      break;
    case 2:
      sv = ((ss->value[TWO_UOP] - ss->value[ONE_UOP]) / cycles) * 100;
      break;
    case 3:
      sv = ((ss->value[ONE_UOP] - ss->value[NO_UOP]) / cycles) * 100;
      break;
    case 4:
      sv = (ss->value[NO_UOP] / cycles) * 100;
      break;
    }

  s = format (s, "%04.1f", sv);

  return s;
}

static perfmon_cpu_supports_t frontend_bound_bw_cpu_supports_uops[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_frontend_bound_bw_uops) = {
  .name = "td-frontend-bw-uops",
  .description = "Topdown FrontEnd-bound BandWidth - distribution of "
		 "uops delivered to frontend",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P, /* 0x0F */
  .events[1] =
    INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CYCLES_3_UOP_DELIV_CORE, /* 0xFF */
  .events[2] =
    INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CYCLES_2_UOP_DELIV_CORE, /* 0xFF */
  .events[3] =
    INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CYCLES_1_UOP_DELIV_CORE, /* 0xFF */
  .events[4] =
    INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CYCLES_0_UOP_DELIV_CORE,     /* 0xFF */
  .events[5] = INTEL_CORE_E_IDQ_UOPS_NOT_DELIVERED_CYCLES_FE_WAS_OK, /* 0xFF */
  .n_events = 6,
  .format_fn = format_intel_frontend_bound_bw_uops,
  .cpu_supports = frontend_bound_bw_cpu_supports_uops,
  .n_cpu_supports = ARRAY_LEN (frontend_bound_bw_cpu_supports_uops),
  .column_headers = PERFMON_STRINGS ("% 4 UOPS", "% 3 UOPS", "% 2 UOPS",
				     "% 1 UOPS", "% 0 UOPS"),
  .footer =
    "For more information, see the Intel(R) 64 and IA-32 Architectures\n"
    "Optimization Reference Manual section on the Front End.",
};
