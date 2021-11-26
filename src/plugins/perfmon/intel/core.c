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
#include <linux/perf_event.h>

static perfmon_event_t events[] = {
#define _(event, umask, edge, any, inv, cmask, n, suffix, desc)               \
  [INTEL_CORE_E_##n##_##suffix] = { .type = PERF_TYPE_RAW,                    \
				    .config = PERF_INTEL_CODE (               \
				      event, umask, edge, any, inv, cmask),   \
				    .name = #n "." #suffix,                   \
				    .description = desc,                      \
				    .exclude_kernel = 1 },

  foreach_perf_intel_core_event foreach_perf_intel_peusdo_event
    foreach_perf_intel_tremont_event

#undef _
};

u8 *
format_intel_core_config (u8 *s, va_list *args)
{
  u64 config = va_arg (*args, u64);
  u8 v;

  s = format (s, "event=0x%02x, umask=0x%02x", config & 0xff,
	      (config >> 8) & 0xff);

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

  /* show the raw config, for convenience sake */
  if (!((config >> 16) & 0xffff))
    s = format (s, ", raw=r%x", config & 0xffff);

  return s;
}

static clib_error_t *
intel_core_init (vlib_main_t *vm, perfmon_source_t *src)
{
  u32 eax, ebx, ecx, edx;
  if (__get_cpuid (0, &eax, &ebx, &ecx, &edx) == 0)
    return clib_error_return (0, "unknown CPU (missing cpuid)");

  // GenuineIntel
  if (ebx != 0x756e6547 || ecx != 0x6c65746e || edx != 0x49656e69)
    return clib_error_return (0, "not a IA-32 CPU");
  return 0;
}

u8
intel_core_is_fixed (u32 event)
{
  u64 config = events[event].config;
  u8 eventcode = (config & 0xFF);

  return !eventcode ? 1 : 0;
}

PERFMON_REGISTER_SOURCE (intel_core) = {
  .name = "intel-core",
  .description = "intel arch core events",
  .events = events,
  .n_events = ARRAY_LEN (events),
  .init_fn = intel_core_init,
  .is_fixed = intel_core_is_fixed,
  .format_config = format_intel_core_config,
};
