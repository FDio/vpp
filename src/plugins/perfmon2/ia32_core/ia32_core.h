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

#ifndef __perfmon2_intel_h
#define __perfmon2_intel_h

#define PERF_INTEL_CODE(event, umask, edge, any, inv, cmask) \
  ((event) | (umask) << 8 | (edge) << 18 | (any) << 21 | (inv) << 23 |  (cmask) << 24)

/* EventCode, UMask, EdgeDetect, AnyThread, Invert, CounterMask
 * counter_unit, name, suffix, description */
#define foreach_perf_x86_event \
  _(0x00, 0x02, 0, 0, 0, 0x00, 4, CPU_CLK_UNHALTED, THREAD, \
    "Core cycles when the thread is not in halt state") \
  _(0x00, 0x03, 0, 0, 0, 0x00, 4, CPU_CLK_UNHALTED, REF_TSC, \
    "Reference cycles when the core is not in halt state.") \
  _(0x03, 0x02, 0, 0, 0, 0x00, 2, LD_BLOCKS, STORE_FORWARD, \
    "Loads blocked due to overlapping with a preceding store that cannot be" \
    " forwarded.") \
  _(0x08, 0x01, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, MISS_CAUSES_A_WALK, \
    "Load misses in all DTLB levels that cause page walks") \
  _(0x08, 0x02, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, WALK_COMPLETED_4K, \
    "Page walk completed due to a demand data load to a 4K page") \
  _(0x08, 0x04, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, WALK_COMPLETED_2M_4M, \
    "Page walk completed due to a demand data load to a 2M/4M page") \
  _(0x08, 0x08, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, WALK_COMPLETED_1G, \
    "Page walk completed due to a demand data load to a 1G page") \
  _(0x08, 0x0E, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, WALK_COMPLETED, \
    "Load miss in all TLB levels causes a page walk that completes. (All " \
    "page sizes)") \
  _(0x08, 0x10, 0, 0, 0, 0x00, 4, DTLB_LOAD_MISSES, WALK_PENDING, \
    "Counts 1 per cycle for each PMH that is busy with a page walk for a " \
    "load. EPT page walk duration are excluded in Skylake.") \
  _(0x08, 0x20, 0, 0, 0, 0x00, 2, DTLB_LOAD_MISSES, STLB_HIT, \
    "Loads that miss the DTLB and hit the STLB.") \
  _(0x0D, 0x01, 0, 0, 0, 0x00, 0, INT_MISC, RECOVERY_CYCLES, \
    "Core cycles the allocator was stalled due to recovery from earlier " \
    "clear event for this thread (e.g. misprediction or memory nuke)") \
  _(0x0E, 0x01, 0, 0, 0, 0x00, 6, UOPS_ISSUED, ANY, \
    "Uops that Resource Allocation Table (RAT) issues to Reservation " \
    "Station (RS)") \
  _(0x28, 0x07, 0, 0, 0, 0x00, 4, CORE_POWER, LVL0_TURBO_LICENSE, \
    "Core cycles where the core was running in a manner where Turbo may be " \
    "clipped to the Non-AVX turbo schedule.") \
  _(0x28, 0x18, 0, 0, 0, 0x00, 4, CORE_POWER, LVL1_TURBO_LICENSE, \
    "Core cycles where the core was running in a manner where Turbo may be " \
    "clipped to the AVX2 turbo schedule.") \
  _(0x28, 0x20, 0, 0, 0, 0x00, 4, CORE_POWER, LVL2_TURBO_LICENSE, \
    "Core cycles where the core was running in a manner where Turbo may be " \
    "clipped to the AVX512 turbo schedule.") \
  _(0x28, 0x40, 0, 0, 0, 0x00, 4, CORE_POWER, THROTTLE, \
    "Core cycles the core was throttled due to a pending power level " \
    "request.") \
  _(0x3C, 0x00, 0, 0, 0, 0x00, 4, CPU_CLK_UNHALTED, THREAD_P, \
    "Thread cycles when thread is not in halt state") \
  _(0x3C, 0x00, 0, 1, 0, 0x00, 4, CPU_CLK_UNHALTED, THREAD_P_ANY, \
    "Core cycles when at least one thread on the physical core is not in " \
    "halt state.") \
  _(0x3C, 0x00, 1, 0, 0, 0x01, 5, CPU_CLK_UNHALTED, RING0_TRANS, \
    "Counts when there is a transition from ring 1, 2 or 3 to ring 0.") \
  _(0x48, 0x01, 0, 0, 0, 0x01, 4, L1D_PEND_MISS, PENDING_CYCLES, \
    "Cycles with L1D load Misses outstanding.") \
  _(0x48, 0x01, 0, 0, 0, 0x00, 4, L1D_PEND_MISS, PENDING, \
    "L1D miss outstandings duration in cycles") \
  _(0x48, 0x02, 0, 0, 0, 0x00, 0, L1D_PEND_MISS, FB_FULL, \
    "Number of times a request needed a FB entry but there was no entry " \
    "available for it. That is the FB unavailability was dominant reason " \
    "for blocking the request. A request includes cacheable/uncacheable " \
    "demands that is load, store or SW prefetch.") \
  _(0x51, 0x01, 0, 0, 0, 0x00, 0, L1D, REPLACEMENT, \
    "L1D data line replacements") \
  _(0x51, 0x04, 0, 0, 0, 0x00, 0, L1D, M_EVICT, \
    "L1D data line evictions") \
  _(0x83, 0x02, 0, 0, 0, 0x00, 0, ICACHE_64B, IFTAG_MISS, \
    "Instruction fetch tag lookups that miss in the instruction cache " \
    "(L1I). Counts at 64-byte cache-line granularity.") \
  _(0x9C, 0x01, 0, 0, 0, 0x00, 0, IDQ_UOPS_NOT_DELIVERED, CORE, \
    "Uops not delivered to Resource Allocation Table (RAT) per thread when " \
    "backend of the machine is not stalled") \
  _(0xC0, 0x00, 0, 0, 0, 0x00, 1, INST_RETIRED, ANY_P, \
    "Number of instructions retired. General Counter - architectural event") \
  _(0xC2, 0x02, 0, 0, 0, 0x00, 0, UOPS_RETIRED, RETIRE_SLOTS, \
    "Retirement slots used.") \
  _(0xD0, 0x81, 0, 0, 0, 0x00, 2, MEM_INST_RETIRED, ALL_LOADS, \
    "All retired load instructions.") \
  _(0xD0, 0x82, 0, 0, 0, 0x00, 3, MEM_INST_RETIRED, ALL_STORES, \
    "All retired store instructions.") \
  _(0xD1, 0x01, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L1_HIT, \
    "Retired load instructions with L1 cache hits as data sources") \
  _(0xD1, 0x02, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L2_HIT, \
    "Retired load instructions with L2 cache hits as data sources") \
  _(0xD1, 0x04, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L3_HIT, \
    "Retired load instructions with L3 cache hits as data sources") \
  _(0xD1, 0x08, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L1_MISS, \
    "Retired load instructions missed L1 cache as data sources") \
  _(0xD1, 0x10, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L2_MISS, \
    "Retired load instructions missed L2 cache as data sources") \
  _(0xD1, 0x20, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, L3_MISS, \
    "Retired load instructions missed L3 cache as data sources") \
  _(0xD1, 0x40, 0, 0, 0, 0x00, 2, MEM_LOAD_RETIRED, FB_HIT, \
    "Retired load instructions which data sources were load missed L1 but " \
    "hit FB due to preceding miss to the same cache line with data not " \
    "ready") \
  _(0xD2, 0x01, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_HIT_RETIRED, XSNP_MISS, \
    "Retired load instructions which data sources were L3 hit and cross-" \
    "core snoop missed in on-pkg core cache.") \
  _(0xD2, 0x02, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_HIT_RETIRED, XSNP_HIT, \
    "Retired load instructions which data sources were L3 and cross-core " \
    "snoop hits in on-pkg core cache") \
  _(0xD2, 0x04, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_HIT_RETIRED, XSNP_HITM, \
    "Retired load instructions which data sources were HitM responses from " \
    "shared L3") \
  _(0xD2, 0x08, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_HIT_RETIRED, XSNP_NONE, \
    "Retired load instructions which data sources were hits in L3 without " \
    "snoops required") \
  _(0xD3, 0x01, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_MISS_RETIRED, LOCAL_DRAM, \
    "Retired load instructions which data sources missed L3 but serviced " \
    "from local dram") \
  _(0xD3, 0x02, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_MISS_RETIRED, REMOTE_DRAM, \
    "Retired load instructions which data sources missed L3 but serviced " \
    "from remote dram") \
  _(0xD3, 0x04, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_MISS_RETIRED, REMOTE_HITM, \
    "Retired load instructions whose data sources was remote HITM") \
  _(0xD3, 0x08, 0, 0, 0, 0x00, 2, MEM_LOAD_L3_MISS_RETIRED, REMOTE_FWD, \
    "Retired load instructions whose data sources was forwarded from a " \
    "remote cache") \
  _(0xF0, 0x40, 0, 0, 0, 0x00, 7, L2_TRANS, L2_WB, \
    "L2 writebacks that access L2 cache") \
  _(0xF1, 0x1F, 0, 0, 0, 0x00, 7, L2_LINES_IN, ALL, \
    "L2 cache lines filling L2") \
  _(0xFE, 0x02, 0, 0, 0, 0x00, 7, IDI_MISC, WB_UPGRADE, \
    "Counts number of cache lines that are allocated and written back to L3" \
    " with the intention that they are more likely to be reused shortly") \
  _(0xFE, 0x04, 0, 0, 0, 0x00, 7, IDI_MISC, WB_DOWNGRADE, \
    "Counts number of cache lines that are dropped and not written back to " \
    "L3 as they are deemed to be less likely to be reused shortly") \

typedef enum
{
#define _(event, umask, edge, any, inv, cmask, unit, name, suffix, desc) \
    IA32_CORE_E_##name##_##suffix,
  foreach_perf_x86_event
#undef _
    PERF_E_N_EVENTS,
} perf_event_type_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
