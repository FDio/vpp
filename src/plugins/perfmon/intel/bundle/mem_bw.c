/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perfmon.h>
#include <perfmon/intel/uncore.h>

static u8 *
format_intel_uncore_imc_bw (u8 *s, va_list *args)
{
  perfmon_reading_t *r = va_arg (*args, perfmon_reading_t *);
  int col = va_arg (*args, int);
  f64 tr = r->time_running * 1e-9;

  switch (col)
    {
    case 0:
      s = format (s, "%9.2f", tr);
      break;
    case 1:
      if (r->time_running)
	s = format (s, "%9.2f", (f64) r->value[0] * 64 * 1e-6 / tr);
      break;
    case 2:
      if (r->time_running)
	s = format (s, "%9.2f", (f64) r->value[1] * 64 * 1e-6 / tr);
      break;
    case 3:
      if (r->time_running)
	s = format (s, "%9.2f",
		    (f64) (r->value[0] + r->value[1]) * 64 * 1e-6 / tr);
      break;
    default:
      break;
    }

  return s;
}

PERFMON_REGISTER_BUNDLE (intel_uncore_imc_bw) = {
  .name = "memory-bandwidth",
  .description = "memory reads and writes per memory controller channel",
  .source = "intel-uncore",
  .type = PERFMON_BUNDLE_TYPE_SYSTEM,
  .events[0] = INTEL_UNCORE_E_IMC_UNC_M_CAS_COUNT_RD,
  .events[1] = INTEL_UNCORE_E_IMC_UNC_M_CAS_COUNT_WR,
  .n_events = 2,
  .format_fn = format_intel_uncore_imc_bw,
  .column_headers = PERFMON_STRINGS ("RunTime", "Reads (MB/s)",
				     "Writes (MB/s)", "Total (MB/s)"),
};
