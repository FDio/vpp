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

#define foreach_lin

#define foreach_perf_sw_counter \
  _(CONTEXT_SWITCHES, "context-switches")

perfmon2_event_t events[] = {
#define _(n,s) \
  {.type = PERF_TYPE_SOFTWARE, .config = PERF_COUNT_SW_##n, .name = s},
  foreach_perf_sw_counter
#undef _
};

PERFMON2_REGISTER_SOURCE (linux) = {
  .name = "linux",
  .events = events,
  .n_events = ARRAY_LEN(events),
};

PERFMON2_REGISTER_BUNDLE (linux) = {
  .name = "linux",
  .description = "blabla",
  .source = "linux",
  .type = PERFMON2_BUNDLE_TYPE_THREAD,
};

PERFMON2_REGISTER_BUNDLE (linux2) = {
  .name = "linux2",
  .description = "blabla",
  .source = "linux",
  .type = PERFMON2_BUNDLE_TYPE_THREAD,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
