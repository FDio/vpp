/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

enum
{
  TSC_ROLLBACK = 0,
  LARGE_FREQUENCY_CHANGE,
} time_error_type;

/*
 * Called from the stats periodic process to update time error counters.
 */
static void
stat_provider_time_error_update_fn (vlib_stats_collector_data_t *d)
{
  time_error_t *time_error;
  counter_t **counters = d->entry->data;
  counter_t *cb;
  int tid;

  time_error = clib_time_get_error ();
  ASSERT (time_error != 0);
  ASSERT (vec_len (time_error) == vec_len (counters));
  vec_foreach_index (tid, counters)
    {
      cb = counters[tid];
      cb[TSC_ROLLBACK] = time_error[tid].tsc_error;
      cb[LARGE_FREQUENCY_CHANGE] = time_error[tid].large_freq_change;
    }
}

/*
 * Provide time error counters.
 * Two dimensional array of thread index and time error type.
 */
void
vlib_stats_register_time_error (void)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_stats_collector_reg_t r = {};

  r.entry_index = vlib_stats_add_counter_vector ("/time/errors");
  vlib_stats_validate (r.entry_index, tm->n_vlib_mains - 1,
		       LARGE_FREQUENCY_CHANGE);
  r.collect_fn = stat_provider_time_error_update_fn;
  vlib_stats_register_collector_fn (&r);
}
