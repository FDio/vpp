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
  STAT_COUNTER_HEARTBEAT = 0,
  STAT_COUNTER_LAST_STATS_CLEAR,
  STAT_COUNTER_NODE_CLOCKS,
  STAT_COUNTER_NODE_VECTORS,
  STAT_COUNTER_NODE_CALLS,
  STAT_COUNTER_NODE_SUSPENDS,
  STAT_COUNTER_NODE_NAMES,
  STAT_COUNTERS
} stat_segment_counter_t;

#define foreach_stat_segment_node_counter_name                                \
  _ (NODE_CLOCKS, COUNTER_VECTOR_SIMPLE, clocks, / sys / node)                \
  _ (NODE_VECTORS, COUNTER_VECTOR_SIMPLE, vectors, / sys / node)              \
  _ (NODE_CALLS, COUNTER_VECTOR_SIMPLE, calls, / sys / node)                  \
  _ (NODE_SUSPENDS, COUNTER_VECTOR_SIMPLE, suspends, / sys / node)

#define foreach_stat_segment_counter_name                                     \
  _ (LAST_STATS_CLEAR, SCALAR_INDEX, last_stats_clear, / sys)                 \
  _ (HEARTBEAT, SCALAR_INDEX, heartbeat, / sys)                               \
  _ (NODE_NAMES, NAME_VECTOR, names, / sys / node)                            \
  foreach_stat_segment_node_counter_name

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
  void *hash_heap;
  void *heap;
  vlib_stats_shared_header_t
    *shared_header; /* pointer to shared memory segment */
  int memfd;

} vlib_stats_segment_t;

extern vlib_stats_segment_t stat_segment_main;

static_always_inline vlib_stats_segment_t *
vlib_stats_get_segment (u32 index)
{
  return &stat_segment_main;
}

static_always_inline void
vlib_stats_set_value (u32 index, u64 value)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  sm->directory_vector[index].value = value;
}

clib_error_t *vlib_stats_init (vlib_main_t *vm);
void *vlib_stats_set_heap ();
void vlib_stats_update_counter (void *, u32, stat_directory_type_t);
void vlib_stats_register_error_index (u8 *, u64 *, u64);
void vlib_stats_update_error_vector (u64 *error_vector, u32 thread_index,
				     int lock);
void vlib_stats_segment_lock (void);
void vlib_stats_segment_unlock (void);
void vlib_stats_delete_cm (void *);
void vlib_stats_register_mem_heap (clib_mem_heap_t *);
void vlib_stats_set_state_counter (u32 index, u64 value);
u32 vlib_stats_new_entry (stat_directory_type_t t, char *fmt, ...);
clib_error_t *vlib_stats_register_gauge (u8 *names,
					 vlib_stats_update_fn update_fn,
					 u32 index);
u32 vlib_stats_create_counter (vlib_stats_directory_entry_t *e);
void vlib_stats_delete_counter (u32 index);
clib_error_t *vlib_stats_register_state_counter (u8 *name, u32 *index);
clib_error_t *vlib_stats_unregister_state_counter (u32 index);
void vlib_stats_register_symlink (u32 index1, u32 index2, char *fmt, ...);
void vlib_stats_rename_symlink (u64 index, char *fmt, ...);
f64 vlib_stats_get_segment_update_rate (void);
u32 vlib_stats_find_directory_index (u8 *name);
void vlib_stats_register_update_fn (u32 vector_index,
				    vlib_stats_update_fn update_fn,
				    u32 caller_index);

format_function_t format_vlib_stats_symlink;

#endif
