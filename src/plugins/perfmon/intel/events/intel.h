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

#ifndef __intel_h
#define __intel_h

#include <linux/perf_event.h>

#define PERF_INTEL_PERF_ARCH4(evtc, umsk, edge, any, invt, cmsk)              \
  ((evtc) | (umsk) << 8 | (edge) << 18 | (any) << 21 | (invt) << 23 |         \
   (cmsk) << 24)

#define PERF_INTEL_PERF_ARCH5(evtc, umsk, edge, invt, cmsk)                   \
  ((evtc) | (umsk) << 8 | (edge) << 18 | (invt) << 23 | (cmsk) << 24)

#define PERF_INTEL_PERF_PSEUDO(evtc, umsk) ((evtc) | (umsk) << 8)

#define PERF_INTEL_UNCORE_SKX(evtc, umsk, pmsk, fmsk)                         \
  ((evtc) | (umsk) << 8 | (u64) (pmsk) << 36 | (u64) (fmsk) << 44)

#define PERF_INTEL_UNCORE_ICX(evtc, umsk, pmsk, fmsk)                         \
  ((evtc) | (umsk) << 8 | (u64) (pmsk) << 36 | (u64) (fmsk) << 48)

#define IS_FIXED(ctrs) (perf_e_counter_type_t) (!ctrs)

int is_genuine_intel_cpu ();

u8 *format_intel_core_config (u8 *s, va_list *args);

#endif
