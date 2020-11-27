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

#ifndef __perfmon_intel_uncore_h__
#define __perfmon_intel_uncore_h__

#define foreach_intel_uncore_unit_type \
  _(IMC, "imc", "integrated Memory Controller (iMC)", "iMC%u/%u") \
  _(UPI, "upi", "Ultra Path Interconnect (UPI)", "UPI%u/%u") \

typedef enum
{
#define _(t,n,name,fmt) INTEL_UNCORE_UNIT_##t,
  foreach_intel_uncore_unit_type
#undef _
    INTEL_UNCORE_N_UNITS,
} intel_uncore_unit_type_t;

#define PERF_INTEL_CODE(event, umask, edge, any, inv, cmask) \
  ((event) | (umask) << 8 | (edge) << 18 | (any) << 21 | (inv) << 23 |  (cmask) << 24)

/* Type, EventCode, UMask, name, suffix, description */
#define foreach_intel_uncore_event \
  _(IMC, 0x04, 0x03, UNC_M_CAS_COUNT, RD, \
    "All DRAM Read CAS Commands issued (including underfills)") \
  _(IMC, 0x04, 0x0c, UNC_M_CAS_COUNT, WR, \
    "All DRAM Write CAS commands issued") \
  _(IMC, 0x04, 0x0f, UNC_M_CAS_COUNT, ALL, \
    "All DRAM CAS commands issued") \

typedef enum
{
#define _(unit, event, umask, name, suffix, desc) \
    INTEL_UNCORE_E_##unit##_##name##_##suffix,
  foreach_intel_uncore_event
#undef _
    INTEL_UNCORE_N_EVENTS,
} perfmon_intel_uncore_event_index_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
