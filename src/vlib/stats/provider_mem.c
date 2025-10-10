/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

static clib_mem_heap_t **memory_heaps_vec;

enum
{
  STAT_MEM_TOTAL = 0,
  STAT_MEM_USED,
  STAT_MEM_FREE,
  STAT_MEM_USED_MMAP,
  STAT_MEM_TOTAL_ALLOC,
  STAT_MEM_FREE_CHUNKS,
  STAT_MEM_RELEASABLE,
} stat_mem_usage_e;

/*
 * Called from the stats periodic process to update memory counters.
 */
static void
stat_provider_mem_usage_update_fn (vlib_stats_collector_data_t *d)
{
  clib_mem_usage_t usage;
  clib_mem_heap_t *heap;
  counter_t **counters = d->entry->data;
  counter_t *cb;

  heap = vec_elt (memory_heaps_vec, d->private_data);
  clib_mem_get_heap_usage (heap, &usage);
  cb = counters[0];
  cb[STAT_MEM_TOTAL] = usage.bytes_total;
  cb[STAT_MEM_USED] = usage.bytes_used;
  cb[STAT_MEM_FREE] = usage.bytes_free;
  cb[STAT_MEM_USED_MMAP] = usage.bytes_used_mmap;
  cb[STAT_MEM_TOTAL_ALLOC] = usage.bytes_max;
  cb[STAT_MEM_FREE_CHUNKS] = usage.bytes_free_reclaimed;
  cb[STAT_MEM_RELEASABLE] = usage.bytes_overhead;
}

/*
 * Provide memory heap counters.
 * Two dimensional array of heap index and per-heap gauges.
 */
void
vlib_stats_register_mem_heap (clib_mem_heap_t *heap)
{
  vlib_stats_collector_reg_t r = {};
  u32 idx;

  vec_add1 (memory_heaps_vec, heap);

  r.entry_index = idx =
    vlib_stats_add_counter_vector ("/mem/%U", format_clib_mem_heap_name, heap);
  vlib_stats_validate (idx, 0, STAT_MEM_RELEASABLE);

  /* Create symlink */
  vlib_stats_add_symlink (idx, STAT_MEM_USED, "/mem/%U/used",
			  format_clib_mem_heap_name, heap);
  vlib_stats_add_symlink (idx, STAT_MEM_TOTAL, "/mem/%U/total",
			  format_clib_mem_heap_name, heap);
  vlib_stats_add_symlink (idx, STAT_MEM_FREE, "/mem/%U/free",
			  format_clib_mem_heap_name, heap);

  r.private_data = vec_len (memory_heaps_vec) - 1;
  r.collect_fn = stat_provider_mem_usage_update_fn;
  vlib_stats_register_collector_fn (&r);
}
