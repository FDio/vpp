/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tracepath/tracepath.h>
#include <vlib/trace.h>
#include <vppinfra/xxhash.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

static u8 *
format_trace_path (u8 *s, va_list *va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  trace_path_t *p = va_arg (*va, trace_path_t *);
  u32 i;
  vlib_node_t *node;

  for (i = 0; i < vec_len (p->path_indices); i++)
    {
      if (i > 0)
	s = format (s, " -> ");

      node = vlib_get_node (vm, p->path_indices[i]);
      s = format (s, "%v", node->name);
    }

  return s;
}

static u8 *
format_thread_list (u8 *s, va_list *va)
{
  clib_bitmap_t *bitmap = va_arg (*va, clib_bitmap_t *);
  uword i;
  u8 first = 1;

  s = format (s, "[");
  clib_bitmap_foreach (i, bitmap)
    {
      if (!first)
	s = format (s, ", ");
      s = format (s, "%d", i);
      first = 0;
    }
  s = format (s, "]");
  return s;
}

static inline u64
trace_path_id (u32 *path_indices)
{
  /* for each path, produce hash based on path length and path indices */
  u64 h = clib_xxhash (vec_len (path_indices));
  for (u32 i = 0; i < vec_len (path_indices); i++)
    h = clib_xxhash (h ^ path_indices[i]);
  return h;
}

static int
trace_path_cmp (void *v1, void *v2)
{
  trace_path_t *p1 = (trace_path_t *) v1;
  trace_path_t *p2 = (trace_path_t *) v2;
  return (i32) p2->n_pkts - (i32) p1->n_pkts;
}

static trace_path_t
trace_path_from_header (vlib_trace_header_t *h)
{
  vlib_trace_header_t *e = vec_end (h);
  trace_path_t path = { 0 };

  /* Iterate over trace header to build trace_path entry */
  while (h < e)
    {
      vec_add1 (path.path_indices, h->node_index);
      h = vlib_trace_header_next (h);
    }

  if (path.path_indices)
    {
      path.n_pkts = 1;
      path.path_id = trace_path_id (path.path_indices);
    }

  /* return path entry, with an initialized path_indices vector */
  return path;
}

static trace_path_t *
trace_paths_collect (vlib_main_t *vm)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  trace_path_t *paths = 0;
  uword *path_id_table = 0;

  /* Iterate over all valid traces */
  pool_foreach (h, tm->trace_buffer_pool)
    {
      trace_path_t new_path = trace_path_from_header (h[0]);

      if (!new_path.path_indices)
	continue;

      uword *p = hash_get (path_id_table, new_path.path_id);
      if (p)
	{
	  /* if path already exists in hash table, increment packet count
	   *  and free path_indices vector */
	  vec_elt_at_index (paths, p[0])->n_pkts++;
	  vec_free (new_path.path_indices);
	}
      else
	{
	  u32 idx = vec_len (paths);
	  vec_add1 (paths, new_path);
	  hash_set (path_id_table, new_path.path_id, idx);
	}
    }

  hash_free (path_id_table);

  /* return paths entries, each with an initialized path_indices vector */
  return paths;
}

static trace_path_t *
trace_paths_collect_all (void)
{
  trace_path_t *merged_paths = 0;
  uword *path_id_table = 0;
  u32 thread_index = 0;

  /* Collect and merge paths from all threads */
  foreach_vlib_main ()
    {
      trace_path_t *thread_paths = trace_paths_collect (this_vlib_main);
      trace_path_t *p;
      vec_foreach (p, thread_paths)
	{
	  uword *existing = hash_get (path_id_table, p->path_id);
	  if (existing)
	    {
	      trace_path_t *mp = vec_elt_at_index (merged_paths, existing[0]);
	      mp->thread_bitmap = clib_bitmap_set (mp->thread_bitmap, thread_index, 1);
	      mp->n_pkts += p->n_pkts;

	      /* free path_indices vector */
	      vec_free (p->path_indices);
	    }
	  else
	    {
	      u32 idx = vec_len (merged_paths);
	      trace_path_t mp = *p;
	      mp.thread_bitmap = clib_bitmap_set (0 /* alloc new */, thread_index, 1);
	      vec_add1 (merged_paths, mp);
	      hash_set (path_id_table, p->path_id, idx);
	    }
	}

      vec_free (thread_paths);
      thread_index++;
    }

  hash_free (path_id_table);

  /* Sort by packet count descending */
  if (vec_len (merged_paths) > 1)
    vec_sort_with_function (merged_paths, trace_path_cmp);

  return merged_paths;
}

static vlib_trace_header_t **
trace_paths_get_traces_by_id (vlib_main_t *vm, u64 path_id)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  vlib_trace_header_t **matching_traces = 0;

  pool_foreach (h, tm->trace_buffer_pool)
    {
      /* Compute path ID and match */
      trace_path_t path = trace_path_from_header (h[0]);

      if (path.path_id == path_id)
	vec_add1 (matching_traces, h[0]);

      /* free path_indices vector */
      vec_free (path.path_indices);
    }

  /* Sort by time */
  if (vec_len (matching_traces) > 1)
    vec_sort_with_function (matching_traces, trace_time_cmp);

  return matching_traces;
}

static clib_error_t *
show_trace_paths_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 max_paths = 10;
  u8 *s = 0;
  trace_path_t *tmp_path, *merged_paths = 0;

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max %d", &max_paths))
	;
      else
	return clib_error_create ("expected 'max COUNT', got `%U'", format_unformat_error, input);
    }

  /* Collect and merge paths from all threads */
  merged_paths = trace_paths_collect_all ();

  if (vec_len (merged_paths) == 0)
    {
      s = format (s, "\nNo trace paths found\n");
    }
  else
    {
      u32 display_count = clib_min (vec_len (merged_paths), max_paths);
      trace_path_t *p;
      u32 i = 0;

      s = format (s, "\nFound %d unique paths across all threads (showing top %d):\n\n",
		  vec_len (merged_paths), display_count);

      vec_foreach (p, merged_paths)
	{
	  if (i >= display_count)
	    break;
	  s = format (s, "  [%d] Count: %d  ID: 0x%016lx  Length: %2d  Threads: %U\n", i, p->n_pkts,
		      p->path_id, vec_len (p->path_indices), format_thread_list, p->thread_bitmap);
	  s = format (s, "      Path: %U\n\n", format_trace_path, vm, p);
	  i++;
	}

      if (vec_len (merged_paths) > max_paths)
	s = format (s, "  ... %d more paths not shown (use 'max' to see more)\n",
		    vec_len (merged_paths) - max_paths);
    }

  vec_foreach (tmp_path, merged_paths)
    {
      vec_free (tmp_path->path_indices);
      clib_bitmap_free (tmp_path->thread_bitmap);
    }
  vec_free (merged_paths);

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/*
 * Example output:
 *
 * vpp# show trace paths
 *
 * Found 2 unique paths across all threads (showing top 2):
 *
 *  [0] Count: 7  ID: 0x00000007c61bef93  Length:  7  Threads: [0]
 *      Path: pg-input -> ethernet-input -> ip4-input -> ip4-lookup -> ip4-drop -> error-drop ->
 * drop
 *
 *  [1] Count: 5  ID: 0x0000000707c1f778  Length:  7  Threads: [0]
 *      Path: pg-input -> ethernet-input -> ip4-input -> ip4-lookup -> ip4-rewrite -> pg1-output ->
 * pg1-tx
 *
 */
VLIB_CLI_COMMAND (show_trace_paths_cli, static) = {
  .path = "show trace paths",
  .short_help = "show trace paths [max COUNT]",
  .function = show_trace_paths_fn,
};

static clib_error_t *
show_trace_path_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 path_index;
  u32 max_traces = 50;
  u32 thread_index = 0;
  u32 traces_shown = 0;
  u8 *s = 0;
  uword *path_filter = 0;
  trace_path_t *tmp_path, *merged_paths = 0;

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &path_index))
	hash_set (path_filter, path_index, 1);
      else if (unformat (input, "max %d", &max_traces))
	;
      else
	{
	  hash_free (path_filter);
	  return clib_error_create ("expected '<INDEX> [<INDEX>...]' or 'max COUNT', got `%U'",
				    format_unformat_error, input);
	}
    }

  if (!path_filter)
    {
      vlib_cli_output (vm, "path index required. Use 'show trace paths' to see available paths.");
      return 0;
    }

  merged_paths = trace_paths_collect_all ();
  u32 n_paths = vec_len (merged_paths);

  for (u32 idx = 0; idx < n_paths && traces_shown < max_traces; idx++)
    {
      if (!hash_get (path_filter, idx))
	continue;

      trace_path_t *p = vec_elt_at_index (merged_paths, idx);

      vlib_cli_output (vm, "\n==================== Path [%d] ====================\n", idx);
      s = format (s, "Path: %U\n", format_trace_path, vm, p);
      s = format (s, "Threads: %U  Count: %d\n\n", format_thread_list, p->thread_bitmap, p->n_pkts);
      vlib_cli_output (vm, "%v", s);
      vec_reset_length (s);

      thread_index = 0;
      foreach_vlib_main ()
	{
	  if (!clib_bitmap_get (p->thread_bitmap, thread_index))
	    {
	      vlib_cli_output (vm, "--- Thread %d %s ---\nNo packets\n\n", thread_index,
			       vlib_worker_threads[thread_index].name);
	      thread_index++;
	      continue;
	    }

	  vlib_cli_output (vm, "--- Thread %d %s ---", thread_index,
			   vlib_worker_threads[thread_index].name);

	  vlib_trace_header_t **traces = trace_paths_get_traces_by_id (this_vlib_main, p->path_id);

	  u32 i;
	  for (i = 0; i < vec_len (traces) && traces_shown < max_traces; i++)
	    {
	      s = format (s, "Packet %d\n\n%U\n\n", traces_shown + 1, format_vlib_trace,
			  this_vlib_main, traces[i]);
	      vlib_cli_output (vm, "%v", s);
	      vec_reset_length (s);
	      traces_shown++;
	    }

	  if (traces_shown >= max_traces && i < vec_len (traces))
	    vlib_cli_output (vm, "Limiting display to %d packets. To display more specify max.\n",
			     max_traces);
	  else
	    vlib_cli_output (vm, "");

	  vec_free (traces);
	  thread_index++;
	}
    }

  if (traces_shown == 0)
    vlib_cli_output (vm, "No traces found for requested path indices");

  vec_free (s);
  hash_free (path_filter);
  vec_foreach (tmp_path, merged_paths)
    {
      vec_free (tmp_path->path_indices);
      clib_bitmap_free (tmp_path->thread_bitmap);
    }
  vec_free (merged_paths);
  return 0;
}

/*
 * Example output:
 *
 * vpp# show trace path 0
 *
 * ==================== Path [0] ====================
 * Path: pg-input -> ethernet-input -> ip4-input -> ip4-lookup -> ip4-drop -> error-drop -> drop
 * Threads: [0]  Count: 7
 *
 * --- Thread 0 vpp_main ---
 * Packet 1
 *
 * 00:00:00:682233: pg-input
 *   stream 0, 42 bytes, sw_if_index 1, next_node ethernet-input
 * ....
 *
 */
VLIB_CLI_COMMAND (show_trace_path_cli, static) = {
  .path = "show trace path",
  .short_help = "show trace path [<INDEX>] [<INDEX>...] [max COUNT]",
  .function = show_trace_path_fn,
};
