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

static u64 config_by_event_index_intel[PERF_E_N_EVENTS] = {
#define _(event, umask, edge, any, inv, cmask, unit, name, suffix, desc) \
      PERF_INTEL_CODE(event, umask, edge, any, inv, cmask),
  foreach_perf_x86_event
#undef _
};

static char *event_names[] = {
#define _(event, umask, edge, any, inv, cmask, unit, name, suffix, desc) \
	#name "." #suffix,
  foreach_perf_x86_event
#undef _
};

static u8 *
format_event_name_intel (u8 * s, va_list * args)
{
  u32 event_index = va_arg (*args, u32);
  return format (s, "%s", event_names[event_index]);
}

static u8 *
format_event_details_intel (u8 * s, va_list * args)
{
  u32 event_index = va_arg (*args, u32);
  u64 config = config_by_event_index_intel[event_index];
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

perfmon2_platform_t perfmon2_platform_intel = {
  .config_by_event_index = config_by_event_index_intel,
  .format_event_name = format_event_name_intel,
  .format_event_details = format_event_details_intel,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
