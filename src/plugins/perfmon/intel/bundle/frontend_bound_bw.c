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
  DSB_UOPS,
  MS_UOPS,
  MITE_UOPS,
  LSD_UOPS,
};

static u8 *
format_intel_frontend_bound_bw (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;
  f64 uops = ss->value[DSB_UOPS] + ss->value[MS_UOPS] + ss->value[MITE_UOPS] +
	     ss->value[LSD_UOPS];

  if (!ss->n_packets)
    return s;

  if (row == 0)
    {
      sv = uops / ss->n_packets;
      s = format (s, "%.0f", sv);

      return s;
    }

  switch (row)
    {
    case 1:
      sv = (ss->value[DSB_UOPS] / uops) * 100;
      break;
    case 2:
      sv = (ss->value[MS_UOPS] / uops) * 100;
      break;
    case 3:
      sv = (ss->value[MITE_UOPS] / uops) * 100;
      break;
    case 4:
      sv = (ss->value[LSD_UOPS] / uops) * 100;
      break;
    }

  s = format (s, "%04.1f", sv);

  return s;
}

static perfmon_cpu_supports_t frontend_bound_bw_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_frontend_bound_bw) = {
  .name = "td-frontend-bw",
  .description =
    "Topdown FrontEnd-bound BandWidth - % uops from each uop fetch source",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_IDQ_DSB_UOPS,  /* 0x0F */
  .events[1] = INTEL_CORE_E_IDQ_MS_UOPS,   /* 0x0F */
  .events[2] = INTEL_CORE_E_IDQ_MITE_UOPS, /* 0x0F */
  .events[3] = INTEL_CORE_E_LSD_UOPS,	   /* 0x0F */
  .n_events = 4,
  .format_fn = format_intel_frontend_bound_bw,
  .cpu_supports = frontend_bound_bw_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (frontend_bound_bw_cpu_supports),
  .column_headers = PERFMON_STRINGS ("UOPs/PKT", "% DSB UOPS", "% MS UOPS",
				     "% MITE UOPS", "% LSD UOPS"),
  .footer =
    "For more information, see the Intel(R) 64 and IA-32 Architectures\n"
    "Optimization Reference Manual section on the Front End.",
};
