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
#include <perfmon/perfmon.h>
#include <perfmon/intel/core.h>

static f64
calculate_power_licensing (perfmon_stats_t *ss, int idx)
{
  f64 sv = 0;

  switch (idx)
    {
    case 0:
      sv = (ss->value[1] / (f64) ss->value[0]) * 100;
      break;
    case 1:
      sv = (ss->value[2] / (f64) ss->value[0]) * 100;
      break;
    case 2:
      sv = (ss->value[3] / (f64) ss->value[0]) * 100;
      break;
    case 3:
      sv = (ss->value[4] / (f64) ss->value[0]) * 100;
      break;
    }

  return sv;
}

static u64
update_power_licensing (perfmon_stats_t *ss, int idx)
{
  return (u64) calculate_power_licensing (ss, idx);
}

static u8 *
format_power_licensing (u8 *s, va_list *args)
{
  perfmon_stats_t *ss = va_arg (*args, perfmon_stats_t *);
  int idx = va_arg (*args, int);
  f64 sv = calculate_power_licensing (ss, idx);

  return format (s, "%.2f", sv);
}

PERFMON_REGISTER_BUNDLE (power_licensing) = {
  .name = "power-licensing",
  .description = "Thread power licensing",
  .source = "intel-core",
  .type_flags = PERFMON_BUNDLE_TYPE_THREAD_FLAG,
  .events[0] = INTEL_CORE_E_CPU_CLK_UNHALTED_THREAD_P,
  .events[1] = INTEL_CORE_E_CORE_POWER_LVL0_TURBO_LICENSE,
  .events[2] = INTEL_CORE_E_CORE_POWER_LVL1_TURBO_LICENSE,
  .events[3] = INTEL_CORE_E_CORE_POWER_LVL2_TURBO_LICENSE,
  .events[4] = INTEL_CORE_E_CORE_POWER_THROTTLE,
  .n_events = 5,
  .format_fn = format_power_licensing,
  .update_fn = update_power_licensing,
  .column_headers = PERFMON_STRINGS ("LVL0", "LVL1", "LVL2", "Throttle"),
};
