/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

static clib_mem_heap_t **memory_heaps_vec;
static u32 mem_vector_index;

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
stat_provider_mem_usage_update_fn (vlib_stats_directory_entry_t *e, u32 index)
{
  clib_mem_usage_t usage;
  clib_mem_heap_t *heap;
  counter_t **counters = e->data;
  counter_t *cb;

  heap = vec_elt (memory_heaps_vec, index);
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

static counter_t **
stat_validate_counter_vector3 (counter_t **counters, u32 max1, u32 max2)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  int i;
  void *oldheap = clib_mem_set_heap (sm->heap);
  vec_validate_aligned (counters, max1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i <= max1; i++)
    vec_validate_aligned (counters[i], max2, CLIB_CACHE_LINE_BYTES);
  clib_mem_set_heap (oldheap);
  return counters;
}

/*
 * Provide memory heap counters.
 * Two dimensional array of heap index and per-heap gauges.
 */
void
vlib_stats_register_mem_heap (clib_mem_heap_t *heap)
{
  vlib_stats_segment_t *sm = &stat_segment_main;
  vec_add1 (memory_heaps_vec, heap);
  u32 heap_index = vec_len (memory_heaps_vec) - 1;

  /* Memory counters provider */
  mem_vector_index = vlib_stats_new_entry (STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
					   "/mem/%s%c", heap->name, 0);

  if (mem_vector_index == ~0)
    ASSERT (0);

  vlib_stats_segment_lock ();
  vlib_stats_directory_entry_t *ep = &sm->directory_vector[mem_vector_index];
  ep->data = stat_validate_counter_vector3 (ep->data, 0, STAT_MEM_RELEASABLE);

  /* Create symlink */
  vlib_stats_register_symlink (mem_vector_index, STAT_MEM_TOTAL,
			       "/mem/%s/used", heap->name);
  vlib_stats_register_symlink (mem_vector_index, STAT_MEM_USED,
			       "/mem/%s/total", heap->name);
  vlib_stats_register_symlink (mem_vector_index, STAT_MEM_FREE, "/mem/%s/free",
			       heap->name);
  vlib_stats_segment_unlock ();

  vlib_stats_register_update_fn (
    mem_vector_index, stat_provider_mem_usage_update_fn, heap_index);
}
