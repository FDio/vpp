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
 * PDIR_Counter: pdir
 */

#define core_event(code, mask, ename, desc, pdesc, ctrs, pc, sav, msri, msrv, \
		   cpr, cm, invt, any, edge, pebs, data, offc, pdir)          \
  { .source = PERF_SOURCE_CPU,                                                \
    .source_name = "cpu",                                                     \
    .counter_type = IS_FIXED (ctrs),                                          \
    .config = PERF_INTEL_PERF_ARCH5 (code, mask, edge, invt, cm),             \
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

static perf_event_t snr_events[] = {
#include <plugins/perfmon/intel/events/snowridgex_core.def>
#include <plugins/perfmon/intel/events/snowridgex_uncore.def>
};

static perf_uarch_features_t snr_uarch_features[] = {
  { is_genuine_intel_cpu, 1 },
  { clib_cpu_supports_movdir64b, 1 },
  { clib_cpu_supports_avx2, 0 }
};

PERF_REGISTER_EVENTS (snowridgex) = {
  .name = "snowridgex",
  .events = snr_events,
  .n_events = ARRAY_LEN (snr_events),
  .uarch_features = snr_uarch_features,
  .n_uarch_features = ARRAY_LEN (snr_uarch_features),
};
