/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_stats_stats_h
#define included_stats_stats_h

#include <vppinfra/socket.h>
#include <vppinfra/lock.h>
#include <vlib/stats/shared.h>

/* Default stat segment 32m */
#define STAT_SEGMENT_DEFAULT_SIZE (32 << 20)

/* Shared segment memory layout version */
#define STAT_SEGMENT_VERSION 2

#define STAT_SEGMENT_INDEX_INVALID UINT32_MAX

typedef enum
{
  STAT_COUNTER_NUM_WORKER_THREADS = 0,
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

typedef void (*vlib_stats_update_fn) (vlib_stats_directory_entry_t *e, u32 i);

typedef struct
{
  u32 directory_index;
  vlib_stats_update_fn fn;
  u32 caller_index;
} stat_segment_gauges_pool_t;

typedef struct
{
  /* internal, does not point to shared memory */
  stat_segment_gauges_pool_t *gauges;

  /* statistics segment */
  uword *directory_vector_by_name;
  vlib_stats_directory_entry_t *directory_vector;
  volatile u64 **error_vector;
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
  void *heap;
  vlib_stats_shared_header_t
    *shared_header; /* pointer to shared memory segment */
  int memfd;

  u64 last_input_packets; // OLE REMOVE?
} vlib_stats_segment_t;

extern vlib_stats_segment_t stat_segment_main;

static_always_inline vlib_stats_segment_t *
vlib_stats_get_segment (u32 index)
{
  return &stat_segment_main;
}

void vlib_stats_pop_heap (void *, void *, u32, stat_directory_type_t);
void vlib_stats_register_error_index (void *, u8 *, u64 *, u64);
void vlib_stats_pop_heap2 (u64 *, u32, void *, int);
void *vlib_stats_set_heap ();
void vlib_stats_segment_lock (void);
void vlib_stats_segment_unlock (void);
void vlib_stats_delete_cm (void *);
void vlib_stats_register_mem_heap (clib_mem_heap_t *);
void vlib_stats_set_state_counter (u32 index, u64 value);
u32 vlib_stats_new_entry (u8 *name, stat_directory_type_t t);
clib_error_t *vlib_stats_register_gauge (u8 *names,
					 vlib_stats_update_fn update_fn,
					 u32 index);
u32 vlib_stats_create_counter (vlib_stats_directory_entry_t *e, void *oldheap);
void vlib_stats_delete_counter (u32 index, void *oldheap);
clib_error_t *vlib_stats_register_state_counter (u8 *name, u32 *index);
clib_error_t *vlib_stats_unregister_state_counter (u32 index);
void vlib_stats_register_symlink (void *oldheap, u8 *name, u32 index1,
				  u32 index2, u8 lock);
void vlib_stats_rename_symlink (void *oldheap, u64 index, u8 *new_name);
f64 vlib_stats_get_segment_update_rate (void);
u32 vlib_stats_find_directory_index (u8 *name);
void vlib_stats_register_update_fn (u32 vector_index,
				    vlib_stats_update_fn update_fn,
				    u32 caller_index, u32 interval);

format_function_t format_vlib_stats_symlink;

#endif
