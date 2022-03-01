/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

static void
stat_provider_vector_rate_per_thread_collector_fn (
  vlib_stats_collector_data_t *d)
{
  vlib_main_t *this_vlib_main;
  counter_t **counters = d->entry->data;
  counter_t *cb = counters[0];

  ASSERT (d->entry->data);

  for (int i = 0; i < vlib_get_n_threads (); i++)
    {
      f64 this_vector_rate;
      this_vlib_main = vlib_get_main_by_index (i);

      this_vector_rate = vlib_internal_node_vector_rate (this_vlib_main);
      vlib_clear_internal_node_vector_rate (this_vlib_main);
      /* Set the per-worker rate */
      cb[i] = this_vector_rate;
    }
}

static void
stat_provider_vector_rate_collector_fn (vlib_stats_collector_data_t *d)
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
  d->entry->value = vector_rate;
}

void
stat_provider_register_vector_rate (u32 num_workers)
{
  vlib_stats_collector_reg_t reg = {};

  reg.collect_fn = stat_provider_vector_rate_collector_fn;
  reg.entry_index = vlib_stats_add_gauge ("/sys/vector_rate");
  vlib_stats_register_collector_fn (&reg);

  reg.collect_fn = stat_provider_vector_rate_per_thread_collector_fn;
  reg.entry_index =
    vlib_stats_add_counter_vector ("/sys/vector_rate_per_worker");
  vlib_stats_register_collector_fn (&reg);
}
