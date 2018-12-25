/*
 * perfmon.h - performance monitor
 *
 * Copyright (c) 2018 Cisco Systems and/or its affiliates
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
#ifndef __included_perfmon_h__
#define __included_perfmon_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/log.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <linux/perf_event.h>

/*
If type is PERF_TYPE_HW_CACHE, then we are measuring a hardware CPU cache event.
To calculate the appropriate config value use the following equation:
    (perf_hw_cache_id) | (perf_hw_cache_op_id << 8) |
    (perf_hw_cache_op_result_id << 16)
*/

#define foreach_perfmon_event                                           \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, "cpu-cycles")           \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, "instructions")       \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES,                   \
  "cache-references")                                                   \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, "cache-misses")       \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS, "branches")    \
 _(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, "branch-misses")    \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES, "bus-cycles")           \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,            \
  "stall-frontend")                                                     \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND,             \
  "stall-backend")                                                      \
_(PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES, "ref-cpu-cycles")   \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS, "page-faults")         \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, "context-switches") \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS, "cpu-migrations")   \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN, "minor-pagefaults") \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ, "major-pagefaults") \
_(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS, "emulation-faults") \
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "L1-dcache-loads")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "L1-dcache-load-misses")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "L1-dcache-stores")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "L1-dcache-store-misses")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1I | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "L1-icache-loads")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1I | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "L1-icache-load-misses")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "LLC-loads")	\
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "LLC-load-misses") \
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "LLC-stores") \
_(PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "LLC-store-misses")

typedef struct
{
  char *name;
  int pe_type;
  int pe_config;
} perfmon_event_config_t;

typedef enum
{
  PERFMON_STATE_OFF = 0,
  PERFMON_STATE_RUNNING,
} perfmon_state_t;

typedef struct
{
  u8 *thread_and_node_name;
  u8 **counter_names;
  u64 *counter_values;
  u64 *vectors_this_counter;
} perfmon_capture_t;

typedef struct
{
  u32 cpuid;
  const char **table;
} perfmon_cpuid_and_table_t;

typedef struct
{
  u8 *name;
  u8 *value;
} name_value_pair_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  volatile u8 state;

  /* capture pool, hash table */
  perfmon_capture_t *capture_pool;
  uword *capture_by_thread_and_node_name;

  /* available generic events */
  perfmon_event_config_t *perfmon_generic_events;

  /* CPU-specific event tables, hash table of selected table (if any)  */
  perfmon_cpuid_and_table_t *perfmon_tables;
  uword *perfmon_table;

  /* vector of events to collect */
  perfmon_event_config_t *events_to_collect;

  /* Base indices of synthetic event tuples */
  u32 ipc_event_index;
  u32 mispredict_event_index;

  /* Length of time to capture a single event */
  f64 timeout_interval;

  /* Current event (index) being collected */
  u32 current_event;
  u32 *rdpmc_indices;
  /* mmap base / size of (mapped) struct perf_event_mmap_page */
  u8 **perf_event_pages;
  u32 page_size;

  /* Current perf_event file descriptors, per thread */
  int *pm_fds;

  /* Logging */
  vlib_log_class_t log_class;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} perfmon_main_t;

extern perfmon_main_t perfmon_main;

extern vlib_node_registration_t perfmon_periodic_node;
uword *perfmon_parse_table (perfmon_main_t * pm, char *path, char *filename);
int perfmon_test_event (char *name, int pe_type, unsigned long pe_config);


/* Periodic function events */
#define PERFMON_START 1

#endif /* __included_perfmon_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
