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

PERFMON_REGISTER_BUNDLE (core_power) = {
  .name = "core-power",
  .description = "core cycles per cpu core level",
  .source = "intel-core",
  .type = PERFMON_BUNDLE_TYPE_THREAD,
  .events[0] = INTEL_CORE_E_CORE_POWER_LVL0_TURBO_LICENSE,
  .events[1] = INTEL_CORE_E_CORE_POWER_LVL1_TURBO_LICENSE,
  .events[2] = INTEL_CORE_E_CORE_POWER_LVL2_TURBO_LICENSE,
  .events[3] = INTEL_CORE_E_CORE_POWER_THROTTLE,
  .n_events = 4,
};
