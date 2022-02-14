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

/* EventCode: code
 * UMask: mask
 * EventName: ename
 * BriefDescription: desc
 * PublicDescription: pdesc
 * Counter: ctrs
 * PEBScounters: pc
 * SampleAfterValue: sav
 * MSRIndex: msri
 * MSRValue: msrv
 * CollectPEBSRecord: cpr
 * CounterMask: cm
 * Invert: invt
 * AnyThread: any
 * EdgeDetect: edge
 * PEBS: pebs
 * Data_LA: data
 * Errata: <ignored>
 * Offcore: offc
 */

#define core_event(code, mask, ename, desc, pdesc, ctrs, pc, sav, msri, msrv, \
		   cpr, cm, invt, any, edge, pebs, data, offc)                \
  { .source = PERF_SOURCE_CPU,                                                \
    .source_name = "cpu",                                                     \
    .counter_type = IS_FIXED (ctrs),                                          \
    .config = PERF_INTEL_PERF_ARCH4 (code, mask, edge, any, invt, cm),        \
    .format_config = format_intel_core_config,                                \
    .name = ename,                                                            \
    .description = desc,                                                      \
    .long_description = pdesc,                                                \
    .pmc_mask = ctrs,                                                         \
    .exclude_kernel = 1 },

static perf_event_t glm_events[] = {
#include <plugins/perfmon/intel/events/goldmont_core.def>
};

static perf_uarch_features_t glm_uarch_features[] = {
  { is_genuine_intel_cpu, 1 },
  { clib_cpu_supports_sha, 1 },
  { clib_cpu_supports_avx2, 0 }
};

PERF_REGISTER_EVENTS (goldmont) = {
  .name = "goldmont",
  .events = glm_events,
  .n_events = ARRAY_LEN (glm_events),
  .uarch_features = glm_uarch_features,
  .n_uarch_features = ARRAY_LEN (glm_uarch_features),
};
