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
  PORT0 = 0,
  PORT1 = 1,
  PORT5 = 2,
  PORT6 = 3,
  PORT2_3 = 4,
  PORT4_9 = 5,
  PORT7_8 = 6,
  DISTRIBUTED = 7,
};

static u8 *
format_intel_backend_bound_core (u8 *s, va_list *args)
{
  perfmon_node_stats_t *ss = va_arg (*args, perfmon_node_stats_t *);
  int row = va_arg (*args, int);
  f64 sv = 0;

  if (!ss->n_packets)
    return s;

  if (0 == row)
    {
      sv = ss->value[DISTRIBUTED] / ss->n_packets;

      s = format (s, "%.0f", sv);
      return s;
    }

  switch (row)
    {
    case 1:
      sv = ss->value[PORT0] / (f64) ss->value[DISTRIBUTED];
      break;
    case 2:
      sv = ss->value[PORT1] / (f64) ss->value[DISTRIBUTED];
      break;
    case 3:
      sv = ss->value[PORT5] / (f64) ss->value[DISTRIBUTED];
      break;
    case 4:
      sv = ss->value[PORT6] / (f64) ss->value[DISTRIBUTED];
      break;
    case 5:
      sv = (ss->value[PORT2_3]) / (f64) (2 * ss->value[DISTRIBUTED]);
      break;
    case 6:
      sv = (ss->value[PORT4_9] + ss->value[PORT7_8]) /
	   (f64) (4 * ss->value[DISTRIBUTED]);
      break;
    }

  sv = clib_max (sv * 100, 0);
  s = format (s, "%04.1f", sv);

  return s;
}

static perfmon_cpu_supports_t backend_bound_core_cpu_supports[] = {
  { clib_cpu_supports_avx512_bitalg, PERFMON_BUNDLE_TYPE_NODE },
};

PERFMON_REGISTER_BUNDLE (intel_core_backend_bound_core) = {
  .name = "td-backend-core",
  .description = "Topdown BackEnd-bound Core - % cycles core resources busy",
  .source = "intel-core",
  .events[0] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_0,	  /* 0xFF */
  .events[1] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_1,	  /* 0xFF */
  .events[2] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_5,	  /* 0xFF */
  .events[3] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_6,	  /* 0xFF */
  .events[4] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_2_3,	  /* 0xFF */
  .events[5] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_4_9,	  /* 0xFF */
  .events[6] = INTEL_CORE_E_UOPS_DISPATCHED_PORT_7_8,	  /* 0xFF */
  .events[7] = INTEL_CORE_E_CPU_CLK_UNHALTED_DISTRIBUTED, /* 0xFF */
  .n_events = 8,
  .format_fn = format_intel_backend_bound_core,
  .cpu_supports = backend_bound_core_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (backend_bound_core_cpu_supports),
  .column_headers = PERFMON_STRINGS ("Clocks/Packet", "%Port0", "%Port1",
				     "%Port5", "%Port6", "%Load", "%Store"),
};
