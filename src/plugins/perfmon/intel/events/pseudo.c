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

#include <vnet/vnet.h>
#include <perfmon/perf_events.h>

#include "intel.h"

#define foreach_pseudo_event                                                  \
  _ (0x00, 0x80, "topdown-retiring",                                          \
     "TMA retiring slots for an unhalted logical processor.")                 \
  _ (0x00, 0x81, "topdown-bad-spec",                                          \
     "TMA bad spec slots or an unhalted logical processor.")                  \
  _ (0x00, 0x82, "topdown-fe-bound",                                          \
     "TMA fe bound slots for an unhalted logical processor.")                 \
  _ (0x00, 0x83, "topdown-be-bound",                                          \
     "TMA be bound slots for an unhalted logical processor.")                 \
  _ (0x00, 0x84, "topdown_heavyops",                                          \
     "TMA heavy operations for an unhalted logical processor.")               \
  _ (0x00, 0x85, "topdown-bmispred",                                          \
     "TMA branch misprediction slots or an unhalted logical processor.")      \
  _ (0x00, 0x86, "topdown-fetchlat",                                          \
     "TMA fetch latency slots for an unhalted logical processor.")            \
  _ (0x00, 0x87, "topdown-membound",                                          \
     "TMA mem bound slots for an unhalted logical processor.")

static perf_event_t pseudo_events[] = {
#define _(code, mask, ename, desc)                                            \
  { .source = PERF_SOURCE_SOFTWARE,                                           \
    .source_name = "software",                                                \
    .config = PERF_INTEL_PERF_PSEUDO (code, mask),                            \
    .name = ename,                                                            \
    .description = desc,                                                      \
    .exclude_kernel = 1 },

  foreach_pseudo_event

#undef _
};

/* requires Intel ICX or above */
static perf_uarch_features_t pseudo_uarch_features[] = {
  { is_genuine_intel_cpu, 1 }, { clib_cpu_supports_avx512_bitalg, 1 }
};

PERF_REGISTER_EVENTS (pseudo) = {
  .name = "pseudo-kernel",
  .events = pseudo_events,
  .n_events = ARRAY_LEN (pseudo_events),
  .uarch_features = pseudo_uarch_features,
  .n_uarch_features = ARRAY_LEN (pseudo_uarch_features),
};
