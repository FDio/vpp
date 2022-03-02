/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

static counter_t **
stat_validate_counter_vector3 (counter_t **counters, u32 max1, u32 max2)
{
  vlib_stats_segment_t *sm = &stat_segment_main;
  int i;
  void *oldheap = clib_mem_set_heap (sm->heap);
  vec_validate_aligned (counters, max1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i <= max1; i++)
    vec_validate_aligned (counters[i], max2, CLIB_CACHE_LINE_BYTES);
  clib_mem_set_heap (oldheap);
  return counters;
}

static void
stat_provider_vector_rate_per_thread_update_fn (
  vlib_stats_directory_entry_t *e, u32 index)
{
  vlib_main_t *this_vlib_main;
  int i;
  ASSERT (e->data);
  counter_t **counters = e->data;

  for (i = 0; i < vlib_get_n_threads (); i++)
    {

      f64 this_vector_rate;

      this_vlib_main = vlib_get_main_by_index (i);

      this_vector_rate = vlib_internal_node_vector_rate (this_vlib_main);
      vlib_clear_internal_node_vector_rate (this_vlib_main);
      /* Set the per-worker rate */
      counter_t *cb = counters[i];
      cb[0] = this_vector_rate;
    }
}

static void
stat_provider_vector_rate_update_fn (vlib_stats_directory_entry_t *e,
				     u32 index)
{
  vlib_main_t *this_vlib_main;
  int i;
  f64 vector_rate = 0.0;
  for (i = 0; i < vlib_get_n_threads (); i++)
    {

      f64 this_vector_rate;

      this_vlib_main = vlib_get_main_by_index (i);

      this_vector_rate = vlib_internal_node_vector_rate (this_vlib_main);
      vlib_clear_internal_node_vector_rate (this_vlib_main);

      vector_rate += this_vector_rate;
    }

  /* And set the system average rate */
  vector_rate /= (f64) (i > 1 ? i - 1 : 1);
  e->value = vector_rate;
}

void
stat_provider_register_vector_rate (u32 num_workers)
{
  int i;

  i = vlib_stats_new_entry (STAT_DIR_TYPE_SCALAR_INDEX, "/sys/vector_rate");
  if (i == ~0)
    ASSERT (0);
  vlib_stats_register_update_fn (i, stat_provider_vector_rate_update_fn, ~0,
				 10);

  i = vlib_stats_new_entry (STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
			    "/sys/vector_rate_per_worker");
  if (i == ~0)
    ASSERT (0);
  vlib_stats_register_update_fn (
    i, stat_provider_vector_rate_per_thread_update_fn, ~0, 10);

  vlib_stats_segment_t *sm = &stat_segment_main;
  vlib_stats_segment_lock ();
  vlib_stats_directory_entry_t *ep = &sm->directory_vector[i];
  ep->data = stat_validate_counter_vector3 (ep->data, num_workers, 0);
  vlib_stats_segment_unlock ();
}
