/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

enum
{
  NODE_CLOCKS,
  NODE_VECTORS,
  NODE_CALLS,
  NODE_SUSPENDS,
  N_NODE_COUNTERS
};

struct
{
  u32 entry_index;
  char *name;
} node_counters[] = {
  [NODE_CLOCKS] = { .name = "clocks" },
  [NODE_VECTORS] = { .name = "vectors" },
  [NODE_CALLS] = { .name = "calls" },
  [NODE_SUSPENDS] = { .name = "suspends" },
};

static struct
{
  u8 *name;
  u32 symlinks[N_NODE_COUNTERS];
} *node_data = 0;

static vlib_stats_string_vector_t node_names = 0;

static inline void
update_node_counters (vlib_stats_segment_t *sm)
{
  clib_bitmap_t *bmp = 0;
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  u32 n_nodes;
  int i, j;

  vlib_node_get_nodes (0 /* vm, for barrier sync */,
		       (u32) ~0 /* all threads */, 1 /* include stats */,
		       0 /* barrier sync */, &node_dups, &stat_vms);

  n_nodes = vec_len (node_dups[0]);

  vec_validate (node_data, n_nodes - 1);

  for (i = 0; i < n_nodes; i++)
    if (vec_is_equal (node_data[i].name, node_dups[0][i]) == 0)
      bmp = clib_bitmap_set (bmp, i, 1);

  if (bmp)
    {
      u32 last_thread = vlib_get_n_threads ();
      vlib_stats_segment_lock ();
      clib_bitmap_foreach (i, bmp)
	{
	  if (node_data[i].name)
	    {
	      vec_free (node_data[i].name);
	      for (j = 0; j < ARRAY_LEN (node_data->symlinks); j++)
		vlib_stats_remove_entry (node_data[i].symlinks[j]);
	    }
	}
      /* We can't merge the loops because a node index corresponding to a given
       * node name can change between 2 updates. Otherwise, we could add
       * already existing symlinks or delete valid ones.
       */
      clib_bitmap_foreach (i, bmp)
	{
	  vlib_node_t *n = node_dups[0][i];
	  node_data[i].name = vec_dup (n->name);
	  vlib_stats_set_string_vector (&node_names, n->index, "%v", n->name);

	  for (int j = 0; j < ARRAY_LEN (node_counters); j++)
	    {
	      vlib_stats_validate (node_counters[j].entry_index, last_thread,
				   n_nodes - 1);
	      node_data[i].symlinks[j] = vlib_stats_add_symlink (
		node_counters[j].entry_index, n->index, "/nodes/%U/%s",
		format_vlib_stats_symlink, n->name, node_counters[j].name);
	      ASSERT (node_data[i].symlinks[j] != CLIB_U32_MAX);
	    }
	}
      vlib_stats_segment_unlock ();
      vec_free (bmp);
    }

  for (j = 0; j < vec_len (node_dups); j++)
    {
      vlib_node_t **nodes = node_dups[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  counter_t **counters;
	  counter_t *c;
	  vlib_node_t *n = nodes[i];

	  counters = vlib_stats_get_entry_data_pointer (
	    node_counters[NODE_CLOCKS].entry_index);
	  c = counters[j];
	  c[n->index] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  counters = vlib_stats_get_entry_data_pointer (
	    node_counters[NODE_VECTORS].entry_index);
	  c = counters[j];
	  c[n->index] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  counters = vlib_stats_get_entry_data_pointer (
	    node_counters[NODE_CALLS].entry_index);
	  c = counters[j];
	  c[n->index] = n->stats_total.calls - n->stats_last_clear.calls;

	  counters = vlib_stats_get_entry_data_pointer (
	    node_counters[NODE_SUSPENDS].entry_index);
	  c = counters[j];
	  c[n->index] = n->stats_total.suspends - n->stats_last_clear.suspends;
	}
      vec_free (node_dups[j]);
    }
  vec_free (node_dups);
  vec_free (stat_vms);
}

static void
do_stat_segment_updates (vlib_main_t *vm, vlib_stats_segment_t *sm)
{
  if (sm->node_counters_enabled)
    update_node_counters (sm);

  vlib_stats_collector_t *c;
  pool_foreach (c, sm->collectors)
    {
      vlib_stats_collector_data_t data = {
	.entry_index = c->entry_index,
	.vector_index = c->vector_index,
	.private_data = c->private_data,
	.entry = sm->directory_vector + c->entry_index,
      };
      c->fn (&data);
    }

  /* Heartbeat, so clients detect we're still here */
  sm->directory_vector[STAT_COUNTER_HEARTBEAT].value++;
}

static uword
stat_segment_collector_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
				vlib_frame_t *f)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  if (sm->node_counters_enabled)
    {
      node_names = vlib_stats_add_string_vector ("/sys/node/names");
      ASSERT (node_names);

      for (int x = 0; x < ARRAY_LEN (node_counters); x++)
	{
	  node_counters[x].entry_index = vlib_stats_add_counter_vector (
	    "/sys/node/%s", node_counters[x].name);
	  ASSERT (node_counters[x].entry_index != CLIB_U32_MAX);
	}
    }

  sm->directory_vector[STAT_COUNTER_BOOTTIME].value = unix_time_now();

  while (1)
    {
      do_stat_segment_updates (vm, sm);
      vlib_process_suspend (vm, sm->update_interval);
    }
  return 0; /* or not */
}

VLIB_REGISTER_NODE (stat_segment_collector, static) = {
  .function = stat_segment_collector_process,
  .name = "statseg-collector-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
