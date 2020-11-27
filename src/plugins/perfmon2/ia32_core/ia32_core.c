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
#include <perfmon2/perfmon2.h>
#include <perfmon2/ia32_core/ia32_core.h>
#include <linux/perf_event.h>

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

static clib_error_t *
intel_ia32_core_init (vlib_main_t * vm, perfmon2_source_t * src)
{
  u32 eax, ebx, ecx, edx;
  if (__get_cpuid (0, &eax, &ebx, &ecx, &edx) == 0)
    return clib_error_return (0, "unknown CPU (missing cpuid)");

  // GenuineIntel
  if (ebx != 0x756e6547 || ecx != 0x6c65746e || edx != 0x49656e69)
    return clib_error_return (0, "not a IA-32 CPU");
  return 0;
}

PERFMON2_REGISTER_SOURCE (intel_ia32_core) = {
  .name = "intel-ia32-core",
  .description = "intel IA-32 core events",
  .events = events,
  .n_events = ARRAY_LEN (events),
  .init_fn = intel_ia32_core_init,
  .format_config = format_ia32_core_config,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
