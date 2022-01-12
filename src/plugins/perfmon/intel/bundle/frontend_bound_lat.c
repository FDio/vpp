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

static const int MS_Switches_Cost = 3;
static const int BA_Clear_Cost = 10;

enum
{
  ICACHE_MISS,
  DSB_SWITCHES,
  RESTEER,
  MS_SWITCHES,
  BACLEARS,
  THREAD,
};

static u8 *
format_intel_frontend_bound_lat (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;
  f64 cycles = ss->value[THREAD];

  if (!ss->n_packets)
    return s;

  if (!row)
    {
      sv = ss->value[THREAD] / ss->n_packets;

      s = format (s, "%.0f", sv);

      return s;
    }

  switch (row)
    {
    case 1:
      sv = ss->value[ICACHE_MISS] / cycles;
      break;
    case 2:
      sv = ss->value[DSB_SWITCHES] / cycles;
      break;
    case 3:
      sv =
	(ss->value[RESTEER] + (ss->value[BACLEARS] * BA_Clear_Cost)) / cycles;
      break;
    case 4:
      sv = (ss->value[MS_SWITCHES] * MS_Switches_Cost) / cycles;
      break;
    }

  s = format (s, "%04.1f", sv * 100);

  return s;
}

static perfmon_cpu_supports_t frontend_bound_lat_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_frontend_bound_lat) = {
  .name = "td-frontend-lat",
  .description = "Topdown FrontEnd-bound Latency - % cycles not retiring uops "
		 "due to frontend latency",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_ICACHE_16B_IFDATA_STALL,	      /* 0x0F */
  .events[1] = INTEL_CORE_E_DSB2MITE_SWITCHES_PENALTY_CYCLES, /* 0x0F */
  .events[2] = INTEL_CORE_E_INT_MISC_CLEAR_RESTEER_CYCLES,    /* 0xFF */
  .events[3] = INTEL_CORE_E_IDQ_MS_SWITCHES,		      /* 0x0F */
  .events[4] = INTEL_CORE_E_BACLEARS_ANY,		      /* 0x0F */
  .events[5] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,	      /* FIXED */
  .n_events = 6,
  .format_fn = format_intel_frontend_bound_lat,
  .cpu_supports = frontend_bound_lat_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (frontend_bound_lat_cpu_supports),
  .column_headers = PERFMON_STRINGS ("Clocks/Packet", "% iCache Miss",
				     "% DSB Switch", "% Branch Resteer",
				     "% MS Switch"),
  .footer =
    "For more information, see the Intel(R) 64 and IA-32 Architectures\n"
    "Optimization Reference Manual on the Front End.",
};
