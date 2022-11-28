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
  STAT_COUNTER_BOOTTIME,
  STAT_COUNTERS
} stat_segment_counter_t;

#define foreach_stat_segment_counter_name                                     \
  _ (LAST_STATS_CLEAR, SCALAR_INDEX, last_stats_clear, "/sys")                \
  _ (HEARTBEAT, SCALAR_INDEX, heartbeat, "/sys")                              \
  _ (BOOTTIME, SCALAR_INDEX, boottime, "/sys")

typedef struct
{
  u32 entry_index;
  u32 vector_index;
  u64 private_data;
  vlib_stats_entry_t *entry;
} vlib_stats_collector_data_t;

typedef void (*vlib_stats_collector_fn_t) (vlib_stats_collector_data_t *);

typedef struct
{
  vlib_stats_collector_fn_t collect_fn;
  u32 entry_index;
  u32 vector_index;
  u64 private_data;
} vlib_stats_collector_reg_t;

typedef struct
{
  vlib_stats_collector_fn_t fn;
  u32 entry_index;
  u32 vector_index;
  u64 private_data;
} vlib_stats_collector_t;

typedef struct
{
  /* internal, does not point to shared memory */
  vlib_stats_collector_t *collectors;

  /* statistics segment */
  uword *directory_vector_by_name;
  vlib_stats_entry_t *directory_vector;
  u32 dir_vector_first_free_elt;

  /* Update interval */
  f64 update_interval;

  clib_spinlock_t *stat_segment_lockp;
  u32 locking_thread_index;
  u32 n_locks;
  clib_socket_t *socket;
  u8 *socket_name;
  ssize_t memory_size;
  clib_mem_page_sz_t log2_page_sz;
  u8 node_counters_enabled;
  void *heap;
  vlib_stats_shared_header_t
    *shared_header; /* pointer to shared memory segment */
  int memfd;

} vlib_stats_segment_t;

typedef struct
{
  u32 entry_index;
} vlib_stats_header_t;

typedef struct
{
  vlib_stats_segment_t segment;
} vlib_stats_main_t;

extern vlib_stats_main_t vlib_stats_main;

static_always_inline vlib_stats_segment_t *
vlib_stats_get_segment ()
{
  return &vlib_stats_main.segment;
}

static_always_inline vlib_stats_entry_t *
vlib_stats_get_entry (vlib_stats_segment_t *sm, u32 entry_index)
{
  vlib_stats_entry_t *e;
  ASSERT (entry_index < vec_len (sm->directory_vector));
  e = sm->directory_vector + entry_index;
  ASSERT (e->type != STAT_DIR_TYPE_EMPTY && e->type != STAT_DIR_TYPE_ILLEGAL);
  return e;
}

static_always_inline void *
vlib_stats_get_entry_data_pointer (u32 entry_index)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  return e->data;
}

clib_error_t *vlib_stats_init (vlib_main_t *vm);
void *vlib_stats_set_heap ();
void vlib_stats_segment_lock (void);
void vlib_stats_segment_unlock (void);
void vlib_stats_register_mem_heap (clib_mem_heap_t *);
f64 vlib_stats_get_segment_update_rate (void);

/* gauge */
u32 vlib_stats_add_gauge (char *fmt, ...);
void vlib_stats_set_gauge (u32 entry_index, u64 value);

/* timestamp */
u32 vlib_stats_add_timestamp (char *fmt, ...);
void vlib_stats_set_timestamp (u32 entry_index, f64 value);

/* counter vector */
u32 vlib_stats_add_counter_vector (char *fmt, ...);

/* counter pair vector */
u32 vlib_stats_add_counter_pair_vector (char *fmt, ...);

/* string vector */
typedef u8 **vlib_stats_string_vector_t;
vlib_stats_string_vector_t vlib_stats_add_string_vector (char *fmt, ...);
void vlib_stats_set_string_vector (vlib_stats_string_vector_t *sv, u32 index,
				   char *fmt, ...);
void vlib_stats_free_string_vector (vlib_stats_string_vector_t *sv);

/* symlink */
u32 vlib_stats_add_symlink (u32 entry_index, u32 vector_index, char *fmt, ...);
void vlib_stats_rename_symlink (u64 entry_index, char *fmt, ...);

/* common to all types */
void vlib_stats_validate (u32 entry_index, ...);
int vlib_stats_validate_will_expand (u32 entry_index, ...);
void vlib_stats_remove_entry (u32 entry_index);
u32 vlib_stats_find_entry_index (char *fmt, ...);
void vlib_stats_register_collector_fn (vlib_stats_collector_reg_t *r);

format_function_t format_vlib_stats_symlink;

#endif
