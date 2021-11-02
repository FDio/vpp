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

#define foreach_intel_uncore_unit_type                                        \
  _ (IMC, "imc", "integrated Memory Controller (iMC)", "iMC%u/%u")            \
  _ (UPI, "upi", "Ultra Path Interconnect (UPI)", "UPI%u/%u")                 \
  _ (IIO, "iio", "Internal IO (IIO)", "IIO%u/%u")

typedef enum
{
#define _(t, n, name, fmt) INTEL_UNCORE_UNIT_##t,
  foreach_intel_uncore_unit_type
#undef _
    INTEL_UNCORE_N_UNITS,
} intel_uncore_unit_type_t;

typedef struct
{
  intel_uncore_unit_type_t unit_type;
  char **unit_names;
} intel_uncore_unit_type_names_t;

#define PERF_INTEL_CODE(event, umask, edge, any, inv, cmask)                  \
  ((event) | (umask) << 8 | (edge) << 18 | (any) << 21 | (inv) << 23 |        \
   (cmask) << 24)

/* Type, EventCode, UMask, ch_mask, fc_mask, name, suffix, description */
#define foreach_intel_uncore_event                                            \
  _ (IMC, 0x04, 0x03, 0, 0, UNC_M_CAS_COUNT, RD,                              \
     "All DRAM Read CAS Commands issued (including underfills)")              \
  _ (IMC, 0x04, 0x0c, 0, 0, UNC_M_CAS_COUNT, WR,                              \
     "All DRAM Write CAS commands issued")                                    \
  _ (IMC, 0x04, 0x0f, 0, 0, UNC_M_CAS_COUNT, ALL,                             \
     "All DRAM CAS commands issued")                                          \
  _ (IIO, 0x83, 0x01, 0x1, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART0, WR,            \
     "Four byte data request of the CPU : Card writing to DRAM")              \
  _ (IIO, 0x83, 0x01, 0x2, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART1, WR,            \
     "Four byte data request of the CPU : Card writing to DRAM")              \
  _ (IIO, 0x83, 0x01, 0x4, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART2, WR,            \
     "Four byte data request of the CPU : Card writing to DRAM")              \
  _ (IIO, 0x83, 0x01, 0x8, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART3, WR,            \
     "Four byte data request of the CPU : Card writing to DRAM")              \
  _ (IIO, 0x83, 0x04, 0x1, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART0, RD,            \
     "Four byte data request of the CPU : Card reading from DRAM")            \
  _ (IIO, 0x83, 0x04, 0x2, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART1, RD,            \
     "Four byte data request of the CPU : Card reading from DRAM")            \
  _ (IIO, 0x83, 0x04, 0x4, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART2, RD,            \
     "Four byte data request of the CPU : Card reading from DRAM")            \
  _ (IIO, 0x83, 0x04, 0x8, 0x7, UNC_IIO_DATA_REQ_OF_CPU_PART3, RD,            \
     "Four byte data request of the CPU : Card reading from DRAM")            \
  _ (IIO, 0xC0, 0x01, 0x1, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART0, WR,            \
     "Data requested by the CPU : Core writing to Card's MMIO space")         \
  _ (IIO, 0xC0, 0x01, 0x2, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART1, WR,            \
     "Data requested by the CPU : Core writing to Card's MMIO space")         \
  _ (IIO, 0xC0, 0x01, 0x4, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART2, WR,            \
     "Data requested by the CPU : Core writing to Card's MMIO space")         \
  _ (IIO, 0xC0, 0x01, 0x8, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART3, WR,            \
     "Data requested by the CPU : Core writing to Card's MMIO space")         \
  _ (IIO, 0x83, 0x80, 0x1, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART0, RD,            \
     "Data requested by the CPU : Core reading from Card's MMIO space")       \
  _ (IIO, 0x83, 0x80, 0x2, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART1, RD,            \
     "Data requested by the CPU : Core reading from Card's MMIO space")       \
  _ (IIO, 0x83, 0x80, 0x4, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART2, RD,            \
     "Data requested by the CPU : Core reading from Card's MMIO space")       \
  _ (IIO, 0x83, 0x80, 0x8, 0x7, UNC_IIO_DATA_REQ_BY_CPU_PART3, RD,            \
     "Data requested by the CPU : Core reading from Card's MMIO space")

typedef enum
{
#define _(unit, event, umask, ch_mask, fc_mask, name, suffix, desc)           \
  INTEL_UNCORE_E_##unit##_##name##_##suffix,
  foreach_intel_uncore_event
#undef _
    INTEL_UNCORE_N_EVENTS,
} perfmon_intel_uncore_event_index_t;

#endif
