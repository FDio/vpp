/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

enum
{
  NODE_STATS_COUNTER_CLOCKS,
  NODE_STATS_COUNTER_VECTORS,
  NODE_STATS_COUNTER_CALLS,
  NODE_STATS_COUNTER_SUSPENDS,
  NODE_STATS_N_COUNTERS
};

static struct
{
  char *name;
  vlib_stats_data_type_t type;
  u8 dim;
  u32 index;
} entries[] = {
  [NODE_STATS_COUNTER_CLOCKS] = { .name = "clocks",
				  .dim = 2,
				  .type = VLIB_STATS_TYPE_UINT64 },
  [NODE_STATS_COUNTER_VECTORS] = { .name = "vectors",
				   .dim = 2,
				   .type = VLIB_STATS_TYPE_UINT64 },
  [NODE_STATS_COUNTER_CALLS] = { .name = "calls",
				 .dim = 2,
				 .type = VLIB_STATS_TYPE_UINT64 },
  [NODE_STATS_COUNTER_SUSPENDS] = { .name = "suspends",
				    .dim = 2,
				    .type = VLIB_STATS_TYPE_UINT64 },
};
static u32 node_names_index;
static u32 **symlink_indices;

static inline void
update_node_counters (vlib_stats_segment_t *sm)
{
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  clib_bitmap_t *changed = 0;

  vlib_node_get_nodes (0 /* vm, for barrier sync */,
		       (u32) ~0 /* all threads */, 1 /* include stats */,
		       0 /* barrier sync */, &node_dups, &stat_vms);

  u32 last_node = vec_len (node_dups[0]) - 1;

  for (int i = 0; i <= last_node; i++)
    {
      int set = 0;
      if (i >= vec_len (symlink_indices))
	set = 1;
      else
	{
	  u8 **s = ((u8 **) vlib_stats_get_data_ptr (node_names_index, i));
	  if (vec_cmp (s[0], node_dups[0][i]->name) != 0)
	    set = 1;
	}

      if (set)
	changed = clib_bitmap_set (changed, i, 1);
    }

  if (changed)
    {
      u32 last_thread = vlib_get_n_threads () - 1;
      u32 i;
      vlib_stats_segment_lock ();

      vec_validate (symlink_indices, last_node);

      for (u32 i = 0; i < ARRAY_LEN (entries); i++)
	vlib_stats_validate (entries[i].index, last_thread, last_node);

      clib_bitmap_foreach (i, changed)
	{
	  vlib_node_t *n = node_dups[0][i];
	  vlib_stats_set_string_vector (node_names_index, i, "%v", n->name);
	  vec_validate_init_empty (symlink_indices[i],
				   NODE_STATS_N_COUNTERS - 1, ~0);

	  ASSERT (i == n->index);

	  for (u32 j = 0; j < ARRAY_LEN (entries); j++)
	    {
	      if (symlink_indices[i][j] != ~0)
		vlib_stats_remove_entry (symlink_indices[i][j]);

	      symlink_indices[i][j] = vlib_stats_add_symlink (
		entries[j].index, i, "/nodes/%U/%s",
		format_vlib_stats_symlink_name, n->name, entries[j].name);
	    }
	}
      vlib_stats_segment_unlock ();
    }

  for (int j = 0; j < vec_len (node_dups); j++)
    {
      u32 clocks_index = entries[NODE_STATS_COUNTER_CLOCKS].index;
      u32 vectors_index = entries[NODE_STATS_COUNTER_VECTORS].index;
      u32 calls_index = entries[NODE_STATS_COUNTER_CALLS].index;
      u32 suspends_index = entries[NODE_STATS_COUNTER_SUSPENDS].index;

      for (int i = 0; i < vec_len (node_dups[j]); i++)
	{
	  counter_t *c;
	  ;
	  vlib_node_t *n = node_dups[j][i];

	  c = vlib_stats_get_data_ptr (clocks_index, j, i);
	  c[0] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  c = vlib_stats_get_data_ptr (vectors_index, j, i);
	  c[0] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  c = vlib_stats_get_data_ptr (calls_index, j, i);
	  c[0] = n->stats_total.calls - n->stats_last_clear.calls;

	  c = vlib_stats_get_data_ptr (suspends_index, j, i);
	  c[0] = n->stats_total.suspends - n->stats_last_clear.suspends;
	}
      vec_free (node_dups[j]);
    }

  vec_free (node_dups);
  vec_free (stat_vms);
  vec_free (changed);
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
      for (u32 i = 0; i < ARRAY_LEN (entries); i++)
	entries[i].index = vlib_stats_add (entries[i].type, entries[i].dim,
					   "/sys/node/%s", entries[i].name);
      node_names_index =
	vlib_stats_add (VLIB_STATS_TYPE_STRING, 1, "/sys/node/names");
    }

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
