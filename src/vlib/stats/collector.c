/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

static inline void
update_node_counters (vlib_stats_segment_t *sm)
{
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  int i, j;
  static u32 no_max_nodes = 0;

  vlib_node_get_nodes (0 /* vm, for barrier sync */,
		       (u32) ~0 /* all threads */, 1 /* include stats */,
		       0 /* barrier sync */, &node_dups, &stat_vms);

  u32 l = vec_len (node_dups[0]);
  u8 *symlink_name = 0;

  /*
   * Extend performance nodes if necessary
   */
  if (l > no_max_nodes)
    {
      u32 last_thread = vlib_get_n_threads ();
      void *oldheap = clib_mem_set_heap (sm->heap);
      vlib_stats_segment_lock ();

      vlib_stats_validate (STAT_COUNTER_NODE_CLOCKS, last_thread, l - 1);
      vlib_stats_validate (STAT_COUNTER_NODE_VECTORS, last_thread, l - 1);
      vlib_stats_validate (STAT_COUNTER_NODE_CALLS, last_thread, l - 1);
      vlib_stats_validate (STAT_COUNTER_NODE_SUSPENDS, last_thread, l - 1);

      vec_validate (sm->nodes, l - 1);
      vlib_stats_entry_t *ep;
      ep = &sm->directory_vector[STAT_COUNTER_NODE_NAMES];
      ep->data = sm->nodes;

      /* Update names dictionary */
      vlib_node_t **nodes = node_dups[0];
      int i;
      for (i = 0; i < vec_len (nodes); i++)
	{
	  vlib_node_t *n = nodes[i];
	  u8 *s = format (0, "%v%c", n->name, 0);
	  if (sm->nodes[n->index])
	    vec_free (sm->nodes[n->index]);
	  sm->nodes[n->index] = s;

	  oldheap = clib_mem_set_heap (oldheap);
#define _(E, t, name, p)                                                      \
  vlib_stats_add_symlink (STAT_COUNTER_##E, n->index, "/nodes/%U/" #name,     \
			  format_vlib_stats_symlink, s);
	  foreach_stat_segment_node_counter_name
#undef _
	    oldheap = clib_mem_set_heap (oldheap);
	}

      vlib_stats_segment_unlock ();
      clib_mem_set_heap (oldheap);
      no_max_nodes = l;
    }

  for (j = 0; j < vec_len (node_dups); j++)
    {
      vlib_node_t **nodes = node_dups[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  counter_t **counters;
	  counter_t *c;
	  vlib_node_t *n = nodes[i];

	  if (j == 0)
	    {
	      if (strncmp ((char *) sm->nodes[n->index], (char *) n->name,
			   strlen ((char *) sm->nodes[n->index])))
		{
		  u32 vector_index;
		  void *oldheap = clib_mem_set_heap (sm->heap);
		  vlib_stats_segment_lock ();
		  u8 *s = format (0, "%v%c", n->name, 0);
		  clib_mem_set_heap (oldheap);
#define _(E, t, name, p)                                                      \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/nodes/%U/" #name,                    \
			 format_vlib_stats_symlink, sm->nodes[n->index]);     \
  vector_index = vlib_stats_find_entry_index ("%v", symlink_name);            \
  ASSERT (vector_index != -1);                                                \
  vlib_stats_rename_symlink (vector_index, "/nodes/%U/" #name,                \
			     format_vlib_stats_symlink, s);
		  foreach_stat_segment_node_counter_name
#undef _
		    vec_free (symlink_name);
		  clib_mem_set_heap (sm->heap);
		  vec_free (sm->nodes[n->index]);
		  sm->nodes[n->index] = s;
		  vlib_stats_segment_unlock ();
		  clib_mem_set_heap (oldheap);
		}
	    }

	  counters = sm->directory_vector[STAT_COUNTER_NODE_CLOCKS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_VECTORS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_CALLS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.calls - n->stats_last_clear.calls;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_SUSPENDS].data;
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
