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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon/perfmon.h>

#include <linux/perf_event.h>

#define foreach_perf_sw_counter                                               \
  _ (CONTEXT_SWITCHES, "context-switches")                                    \
  _ (PAGE_FAULTS_MIN, "page-faults-minor")                                    \
  _ (PAGE_FAULTS_MAJ, "page-faults-major")

typedef enum
{
#define _(n, s) n,
  foreach_perf_sw_counter
#undef _
} linux_sw_events;

static perfmon_event_t events[] = {
#define _(n, s)                                                               \
  [n] = {                                                                     \
    .type = PERF_TYPE_SOFTWARE,                                               \
    .config = PERF_COUNT_SW_##n,                                              \
    .name = s,                                                                \
    .implemented = 1,                                                         \
  },
  foreach_perf_sw_counter
#undef _
};

PERFMON_REGISTER_SOURCE (linux) = {
  .name = "linux",
  .description = "Linux kernel performance counters",
  .events = events,
  .n_events = ARRAY_LEN (events),
};

static u8 *
format_context_switches (u8 *s, va_list *args)
{
  perfmon_reading_t *r = va_arg (*args, perfmon_reading_t *);
  int row = va_arg (*args, int);
  f64 t = (f64) r->time_running * 1e-9;

  switch (row)
    {
    case 0:
      s = format (s, "%9.2f", t);
      break;
    case 1:
      if (r->time_running)
	s = format (s, "%9.2f", (f64) r->value[0] / t);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (context_switches) = {
  .name = "context-switches",
  .description = "per-thread context switches",
  .source = "linux",
  .type = PERFMON_BUNDLE_TYPE_THREAD,
  .events[0] = CONTEXT_SWITCHES,
  .n_events = 1,
  .format_fn = format_context_switches,
  .column_headers = PERFMON_STRINGS ("RunTime", "ContextSwitches/Sec"),
};

static u8 *
format_page_faults (u8 *s, va_list *args)
{
  perfmon_reading_t *r = va_arg (*args, perfmon_reading_t *);
  int row = va_arg (*args, int);
  f64 t = (f64) r->time_running * 1e-9;

  switch (row)
    {
    case 0:
      s = format (s, "%9.2f", t);
      break;
    case 1:
      if (r->time_running)
	s = format (s, "%9.2f", (f64) r->value[0] / t);
      break;
    case 2:
      if (r->time_running)
	s = format (s, "%9.2f", (f64) r->value[1] / t);
      break;
    }
  return s;
}

PERFMON_REGISTER_BUNDLE (page_faults) = {
  .name = "page-faults",
  .description = "per-thread page faults",
  .source = "linux",
  .type = PERFMON_BUNDLE_TYPE_THREAD,
  .events[0] = PAGE_FAULTS_MIN,
  .events[1] = PAGE_FAULTS_MAJ,
  .n_events = 2,
  .format_fn = format_page_faults,
  .column_headers = PERFMON_STRINGS ("RunTime", "MinorPageFaults/Sec",
				     "MajorPageFaults/Sec"),
};
