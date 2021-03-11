/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_stat_segment_h
#define included_stat_segment_h

#include <vlib/vlib.h>
#include <vppinfra/socket.h>
#include <vpp/stats/stat_segment_shared.h>

typedef enum
{
 STAT_COUNTER_VECTOR_RATE = 0,
 STAT_COUNTER_NUM_WORKER_THREADS,
 STAT_COUNTER_VECTOR_RATE_PER_WORKER,
 STAT_COUNTER_INPUT_RATE,
 STAT_COUNTER_LAST_UPDATE,
 STAT_COUNTER_LAST_STATS_CLEAR,
 STAT_COUNTER_HEARTBEAT,
 STAT_COUNTER_NODE_CLOCKS,
 STAT_COUNTER_NODE_VECTORS,
 STAT_COUNTER_NODE_CALLS,
 STAT_COUNTER_NODE_SUSPENDS,
 STAT_COUNTER_INTERFACE_NAMES,
 STAT_COUNTER_NODE_NAMES,
 STAT_COUNTER_MEM_STATSEG_TOTAL,
 STAT_COUNTER_MEM_STATSEG_USED,
 STAT_COUNTERS
} stat_segment_counter_t;

#define foreach_stat_segment_counter_name                       \
  _(VECTOR_RATE, SCALAR_INDEX, vector_rate, /sys)               \
  _(VECTOR_RATE_PER_WORKER, COUNTER_VECTOR_SIMPLE,              \
    vector_rate_per_worker, /sys)                               \
  _(NUM_WORKER_THREADS, SCALAR_INDEX, num_worker_threads, /sys) \
  _(INPUT_RATE, SCALAR_INDEX, input_rate, /sys)                 \
  _(LAST_UPDATE, SCALAR_INDEX, last_update, /sys)               \
  _(LAST_STATS_CLEAR, SCALAR_INDEX, last_stats_clear, /sys)     \
  _(HEARTBEAT, SCALAR_INDEX, heartbeat, /sys)                   \
  _(NODE_CLOCKS, COUNTER_VECTOR_SIMPLE, clocks, /sys/node)      \
  _(NODE_VECTORS, COUNTER_VECTOR_SIMPLE, vectors, /sys/node)    \
  _(NODE_CALLS, COUNTER_VECTOR_SIMPLE, calls, /sys/node)        \
  _(NODE_SUSPENDS, COUNTER_VECTOR_SIMPLE, suspends, /sys/node)  \
  _(INTERFACE_NAMES, NAME_VECTOR, names, /if)                   \
  _(NODE_NAMES, NAME_VECTOR, names, /sys/node)                  \
  _(MEM_STATSEG_TOTAL, SCALAR_INDEX, total, /mem/statseg)       \
  _(MEM_STATSEG_USED, SCALAR_INDEX, used, /mem/statseg)

/* Default stat segment 32m */
#define STAT_SEGMENT_DEFAULT_SIZE	(32<<20)

/* Shared segment memory layout version */
#define STAT_SEGMENT_VERSION		2

#define STAT_SEGMENT_INDEX_INVALID	UINT32_MAX

typedef void (*stat_segment_update_fn)(stat_segment_directory_entry_t * e, u32 i);

typedef struct {
  u32 directory_index;
  stat_segment_update_fn fn;
  u32 caller_index;
} stat_segment_gauges_pool_t;

typedef struct
{
  /* internal, does not point to shared memory */
  stat_segment_gauges_pool_t *gauges;

  /* statistics segment */
  uword *directory_vector_by_name;
  stat_segment_directory_entry_t *directory_vector;
  volatile u64 **error_vector;
  stat_segment_symlink_entry_t *symlink_vector;
  u8 **interfaces;
  u8 **nodes;

  /* Update interval */
  f64 update_interval;

  clib_spinlock_t *stat_segment_lockp;
  clib_socket_t *socket;
  u8 *socket_name;
  ssize_t memory_size;
  clib_mem_page_sz_t log2_page_sz;
  u8 node_counters_enabled;
  void *last;
  void *heap;
  stat_segment_shared_header_t *shared_header;	/* pointer to shared memory segment */
  int memfd;

  u64 last_input_packets; // OLE REMOVE?
} stat_segment_main_t;

extern stat_segment_main_t stat_segment_main;

clib_error_t *
stat_segment_register_gauge (u8 *names, stat_segment_update_fn update_fn, u32 index);
clib_error_t *
stat_segment_register_state_counter(u8 *name, u32 *index);
clib_error_t *
stat_segment_deregister_state_counter(u32 index);
void stat_segment_set_state_counter (u32 index, u64 value);

#endif
