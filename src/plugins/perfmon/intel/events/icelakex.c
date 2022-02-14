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
 * EventName: name
 * BriefDescription: desc
 * PublicDescription: pdesc
 * Counter: ctrs
 * PEBScounters: pc
 * SampleAfterValue: sav
 * MSRIndex: msri
 * MSRValue: msrv
 * CollectPEBSRecord: cpr
 * TakenAlone: ta
 * CounterMask: cm
 * Invert: invt
 * EdgeDetect: edge
 * PEBS: pebs
 * Data_LA: data
 * L1_Hit_Indication: l1hi
 * Errata: <ignored>
 * Offcore: offc
 * Speculative: spec
 */

#define core_event(code, mask, ename, desc, pdesc, ctrs, pc, sav, msri, msrv, \
		   cpr, ta, cm, invt, edge, pebs, data, l1ht, offc, spec)     \
  { .source = PERF_SOURCE_CPU,                                                \
    .source_name = "cpu",                                                     \
    .counter_type = IS_FIXED (ctrs),                                          \
    .config = PERF_INTEL_PERF_ARCH5 (code, mask, edge, invt, cm),             \
    .format_config = format_intel_core_config,                                \
    .name = ename,                                                            \
    .description = desc,                                                      \
    .long_description = pdesc,                                                \
    .pmc_mask = ctrs,                                                         \
    .exclude_kernel = 1 },

/* Unit: unit
 * EventCode: code
 * UMask: mask
 * PortMask: pmsk
 * FCMask: fcmsk
 * UMaskExt: uext
 * EventName: name
 * BriefDescription: desc
 * PublicDescription: pdesc
 * Counter: ctrs
 * MSRValue: msrv
 * ELLC: ellc
 * Filter: fltr
 * ExtSel: exts
 * Deprecated: dprc
 * FILTER_VALUE: fval
 * CounterType: type
 */

#define uncore_event(unit, code, mask, pmsk, fcmsk, uext, ename, desc, pdesc, \
		     ctrs, msrv, ellc, fltr, exts, dprc, fval, etype)         \
  { .source = PERF_SOURCE_OTHER,                                              \
    .source_name = unit,                                                      \
    .config = PERF_INTEL_UNCORE_ICX (code, mask, pmsk, fcmsk),                \
    .format_config = format_intel_core_config,                                \
    .name = ename,                                                            \
    .description = desc,                                                      \
    .long_description = pdesc,                                                \
    .pmc_mask = ctrs,                                                         \
    .exclude_kernel = 1 },

static perf_event_t icx_events[] = {
#include <plugins/perfmon/intel/events/icelakex_core.def>
#include <plugins/perfmon/intel/events/icelakex_uncore.def>
};

static perf_uarch_features_t icx_uarch_features[] = {
  { is_genuine_intel_cpu, 1 },
  { clib_cpu_supports_avx512_bitalg, 1 },
  { clib_cpu_supports_movdir64b, 0 }
};

PERF_REGISTER_EVENTS (icelakex) = {
  .name = "icelakex",
  .events = icx_events,
  .n_events = ARRAY_LEN (icx_events),
  .uarch_features = icx_uarch_features,
  .n_uarch_features = ARRAY_LEN (icx_uarch_features),
};
