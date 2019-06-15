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

#include <stdatomic.h>
#include <vlib/vlib.h>
#include <vppinfra/socket.h>
#include <vpp-api/client/stat_client.h>

typedef enum
{
 STAT_COUNTER_VECTOR_RATE = 0,
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
 STAT_COUNTERS
} stat_segment_counter_t;

#define foreach_stat_segment_counter_name			\
  _(VECTOR_RATE, SCALAR_INDEX, vector_rate, /sys)		\
  _(INPUT_RATE, SCALAR_INDEX, input_rate, /sys)			\
  _(LAST_UPDATE, SCALAR_INDEX, last_update, /sys)		\
  _(LAST_STATS_CLEAR, SCALAR_INDEX, last_stats_clear, /sys)	\
  _(HEARTBEAT, SCALAR_INDEX, heartbeat, /sys)			\
  _(NODE_CLOCKS, COUNTER_VECTOR_SIMPLE, clocks, /sys/node)	\
  _(NODE_VECTORS, COUNTER_VECTOR_SIMPLE, vectors, /sys/node)	\
  _(NODE_CALLS, COUNTER_VECTOR_SIMPLE, calls, /sys/node)	\
  _(NODE_SUSPENDS, COUNTER_VECTOR_SIMPLE, suspends, /sys/node)	\
  _(INTERFACE_NAMES, NAME_VECTOR, names, /if)                   \
  _(NODE_NAMES, NAME_VECTOR, names, /sys/node)

typedef struct
{
  stat_directory_type_t type;
  union {
    uint64_t offset;
    uint64_t index;
    uint64_t value;
  };
  uint64_t offset_vector;
  char name[128]; // TODO change this to pointer to "somewhere"
} stat_segment_directory_entry_t;

/* Default stat segment 32m */
#define STAT_SEGMENT_DEFAULT_SIZE	(32<<20)

/*
 * Shared header first in the shared memory segment.
 */
typedef struct
{
  atomic_int_fast64_t epoch;
  atomic_int_fast64_t in_progress;
  atomic_int_fast64_t directory_offset;
  atomic_int_fast64_t error_offset;
  atomic_int_fast64_t stats_offset;
} stat_segment_shared_header_t;

static inline uint64_t
stat_segment_offset (void *start, void *data)
{
  return (char *) data - (char *) start;
}

static inline void *
stat_segment_pointer (void *start, uint64_t offset)
{
  return ((char *) start + offset);
}

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
  u8 **interfaces;
  u8 **nodes;

  clib_spinlock_t *stat_segment_lockp;
  clib_socket_t *socket;
  u8 *socket_name;
  ssize_t memory_size;
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

#endif
