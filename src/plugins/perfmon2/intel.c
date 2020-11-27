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
#include <perfmon/perfmon_intel.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon2/perfmon2.h>
#include <perfmon2/intel.h>

static perfmon2_event_t events[] = {
#define _(event, umask, edge, any, inv, cmask, unit, n, suffix, desc) \
  [IA32_CORE_E_##n##_##suffix] = { \
    .type = PERF_TYPE_RAW, \
    .config = PERF_INTEL_CODE(event, umask, edge, any, inv, cmask), \
    .name = #n "." #suffix, \
    .description = desc, \
  },

  foreach_perf_x86_event
#undef _
};

static u8 *
format_ia32_core_config (u8 * s, va_list * args)
{
  u64 config = va_arg (*args, u64);
  u8 v;

  s = format (s, "event=0x%02x, umask=0x%02x",
	      config & 0xff, (config >> 8) & 0xff);

  if ((v = (config >> 18) & 1))
    s = format (s, ", edge=%u", v);

  if ((v = (config >> 19) & 1))
    s = format (s, ", pc=%u", v);

  if ((v = (config >> 21) & 1))
    s = format (s, ", any=%u", v);

  if ((v = (config >> 23) & 1))
    s = format (s, ", inv=%u", v);

  if ((v = (config >> 24) & 0xff))
    s = format (s, ", cmask=0x%02x", v);

  return s;
}

PERFMON2_REGISTER_SOURCE (intel_ia32_core) = {
  .name = "intel-ia32-core",
  .description = "intel IA-32 core events",
  .events = events,
  .n_events = ARRAY_LEN(events),
  .format_config = format_ia32_core_config,
};

PERFMON2_REGISTER_BUNDLE (inst_and_cycles) = {
  .name = "ipc",
  .description = "instructions/packet, cycles/packet and IPC",
  .source = "intel-ia32-core",
  .type = PERFMON2_BUNDLE_TYPE_NODE,
  .events[0] = IA32_CORE_E_INST_RETIRED_ANY_P,
  .events[1] = IA32_CORE_E_CPU_CLK_UNHALTED_THREAD_P,
  .events[2] = IA32_CORE_E_CPU_CLK_UNHALTED_REF_TSC,
  .n_events = 3,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
