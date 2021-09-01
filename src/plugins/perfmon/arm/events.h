/*
 * Copyright (c) 2021 Arm and/or its affiliates.
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

#ifndef __perfmon_arm_h
#define __perfmon_arm_h

/*
 * Events from the Armv8 PMUv3 - See "Arm Architecture Reference Manual Armv8,
 * for Armv8-A architecture profile" D7.10 PMU events and event numbers:
 * https://developer.arm.com/documentation/ddi0487/latest/
 * EventCode, name, description
 */
#define foreach_perf_arm_event                                                \
  _ (0x0D, BR_IMMED_RETIRED, "Immediate branch architecturally executed")     \
  _ (0x10, BR_MIS_PRED,                                                       \
     "Mispredicted or not predicted branch Speculatively executed")           \
  _ (0x22, BR_MIS_PRED_RETIRED,                                               \
     "Instruction architecturally executed, mispredicted branch")             \
  _ (0x12, BR_PRED, "Predictable branch Speculatively executed")              \
  _ (0x21, BR_RETIRED, "Branch instruction architecturally executed")         \
  _ (0x0E, BR_RETURN_RETIRED,                                                 \
     "Function return instruction architecturally executed and the "          \
     "condition code check pass")                                             \
  _ (0x19, BUS_ACCESS, "Attributable Bus access")                             \
  _ (0x1D, BUS_CYCLES, "Bus cycle")                                           \
  _ (0x1E, CHAIN,                                                             \
     "For an odd numbered counter, increment when an overflow occurs on"      \
     "the preceding even-numbered counter on the same PE")                    \
  _ (0x0B, CID_WRITE_RETIRED,                                                 \
     "Instruction architecturally executed, Condition code check pass, "      \
     "write to CONTEXTIDR")                                                   \
  _ (0x11, CPU_CYCLES, "Cycle counter")                                       \
  _ (0x34, DTLB_WALK,                                                         \
     "Access to data or unified TLB causes a translation table walk")         \
  _ (0x0A, EXC_RETURN,                                                        \
     "Exception return instruction architecturally executed and the "         \
     "condition code check pass")                                             \
  _ (0x09, EXC_TAKEN, "Exception entry")                                      \
  _ (0x08, INST_RETIRED, "Instruction architecturally executed")              \
  _ (0x1B, INST_SPEC, "Operation Speculatively executed")                     \
  _ (0x35, ITLB_WALK,                                                         \
     "Access to instruction TLB that causes a translation table walk")        \
  _ (0x04, L1D_CACHE, "Level 1 data cache access")                            \
  _ (0x1F, L1D_CACHE_ALLOCATE,                                                \
     "Level 1 data cache allocation without refill")                          \
  _ (0x39, L1D_CACHE_LMISS_RD, "Level 1 data cache long-latency read miss")   \
  _ (0x03, L1D_CACHE_REFILL, "Level 1 data cache refill")                     \
  _ (0x15, L1D_CACHE_WB, "Attributable Level 1 data cache write-back")        \
  _ (0x25, L1D_TLB, "Level 1 data or unified TLB access")                     \
  _ (0x05, L1D_TLB_REFILL, "Level 1 data or unified TLB refill")              \
  _ (0x14, L1I_CACHE, "Level 1 instruction cache access")                     \
  _ (0x01, L1I_CACHE_REFILL, "Level 1 instruction cache refill")              \
  _ (0x26, L1I_TLB, "Level 1 instruction TLB access")                         \
  _ (0x02, L1I_TLB_REFILL, "Level 1 instruction TLB refill")                  \
  _ (0x16, L2D_CACHE, "Level 2 data cache access")                            \
  _ (0x20, L2D_CACHE_ALLOCATE,                                                \
     "Level 2 data cache allocation without refill")                          \
  _ (0x17, L2D_CACHE_REFILL, "Level 2 data cache refill")                     \
  _ (0x18, L2D_CACHE_WB, "Attributable Level 2 data cache write-back")        \
  _ (0x2F, L2D_TLB, "Level 2 data or unified TLB access")                     \
  _ (0x2D, L2D_TLB_REFILL, "Level 2 data or unified TLB refill")              \
  _ (0x27, L2I_CACHE, "Level 2 instruction cache access")                     \
  _ (0x28, L2I_CACHE_REFILL, "Attributable Level 2 instruction cache refill") \
  _ (0x30, L2I_TLB, "Level 2 instruction TLB access")                         \
  _ (0x2E, L2I_TLB_REFILL, "Level 2 instruction TLB refill")                  \
  _ (0x2B, L3D_CACHE, "Level 3 data cache access")                            \
  _ (0x29, L3D_CACHE_ALLOCATE,                                                \
     "Level 3 data cache allocation without refill")                          \
  _ (0x2A, L3D_CACHE_REFILL, "Attributable Level 3 data cache refill")        \
  _ (0x2C, L3D_CACHE_WB, "Attributable Level 3 data cache write-back")        \
  _ (0x06, LD_RETIRED,                                                        \
     "Memory-reading instruction architecturally executed and condition"      \
     " code check pass")                                                      \
  _ (0x32, LL_CACHE, "Last Level cache access")                               \
  _ (0x33, LL_CACHE_MISS, "Last Level cache miss")                            \
  _ (0x37, LL_CACHE_MISS_RD, "Last level cache miss, read")                   \
  _ (0x36, LL_CACHE_RD, "Last level data cache access, read")                 \
  _ (0x1A, MEMORY_ERROR, "Local memory error")                                \
  _ (0x13, MEM_ACCESS, "Data memory access")                                  \
  _ (0x3A, OP_RETIRED, "Micro-operation architecturally executed")            \
  _ (0x3B, OP_SPEC, "Micro-operation Speculatively executed")                 \
  _ (0x0C, PC_WRITE_RETIRED,                                                  \
     "Software change to the Program Counter (PC). Instruction is "           \
     "architecturally executed and condition code check pass")                \
  _ (0x31, REMOTE_ACCESS,                                                     \
     "Access to another socket in a multi-socket system")                     \
  _ (0x38, REMOTE_ACCESS_RD,                                                  \
     "Access to another socket in a multi-socket system, read")               \
  _ (0x3C, STALL, "No operation sent for execution")                          \
  _ (0x24, STALL_BACKEND, "No operation issued due to the backend")           \
  _ (0x23, STALL_FRONTEND, "No operation issued due to the frontend")         \
  _ (0x3F, STALL_SLOT, "No operation sent for execution on a Slot")           \
  _ (0x3D, STALL_SLOT_BACKEND,                                                \
     "No operation sent for execution on a Slot due to the backend")          \
  _ (0x3E, STALL_SLOT_FRONTEND,                                               \
     "No operation sent for execution on a Slot due to the frontend")         \
  _ (0x07, ST_RETIRED,                                                        \
     "Memory-writing instruction architecturally executed and condition"      \
     " code check pass")                                                      \
  _ (0x00, SW_INCR,                                                           \
     "Instruction architecturally executed, Condition code check pass, "      \
     "software increment")                                                    \
  _ (0x1C, TTBR_WRITE_RETIRED,                                                \
     "Instruction architecturally executed, Condition code check pass, "      \
     "write to TTBR")                                                         \
  _ (0x0F, UNALIGNED_LDST_RETIRED,                                            \
     "Unaligned memory memory-reading or memory-writing instruction "         \
     "architecturally executed and condition code check pass")

typedef enum
{
#define _(event, n, desc) ARMV8_PMUV3_##n,
  foreach_perf_arm_event
#undef _
    ARM_N_EVENTS,
} perf_arm_event_t;

#endif
