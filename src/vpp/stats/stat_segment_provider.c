/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

/*
 * Counters handled by the stats module directly.
 */

#include <stdbool.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vlib/counter.h>
#include "stat_segment.h"

clib_mem_heap_t **memory_heaps_vec;
u32 mem_vector_index;
bool initialized = false;

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
stat_provider_mem_usage_update_fn (stat_segment_directory_entry_t *e,
				   u32 index)
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
  stat_segment_main_t *sm = &stat_segment_main;
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
  stat_segment_main_t *sm = &stat_segment_main;
  vec_add1 (memory_heaps_vec, heap);
  u32 heap_index = vec_len (memory_heaps_vec) - 1;

  /* Memory counters provider */
  u8 *s = format (0, "/mem/%s", heap->name);
  u8 *s_used = format (0, "/mem/%s/used", heap->name);
  u8 *s_total = format (0, "/mem/%s/total", heap->name);
  u8 *s_free = format (0, "/mem/%s/free", heap->name);
  mem_vector_index =
    stat_segment_new_entry (s, STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE);
  vec_free (s);
  if (mem_vector_index == ~0)
    ASSERT (0);

  vlib_stat_segment_lock ();
  stat_segment_directory_entry_t *ep = &sm->directory_vector[mem_vector_index];
  ep->data = stat_validate_counter_vector3 (ep->data, 0, STAT_MEM_RELEASABLE);

  /* Create symlink */
  void *oldheap = clib_mem_set_heap (sm->heap);
  vlib_stats_register_symlink (oldheap, s_total, mem_vector_index,
			       STAT_MEM_TOTAL, 0);
  vlib_stats_register_symlink (oldheap, s_used, mem_vector_index,
			       STAT_MEM_USED, 0);
  vlib_stats_register_symlink (oldheap, s_free, mem_vector_index,
			       STAT_MEM_FREE, 0);
  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
  vec_free (s_used);
  vec_free (s_total);
  vec_free (s_free);

  stat_segment_poll_add (mem_vector_index, stat_provider_mem_usage_update_fn,
			 heap_index, 10);
}
