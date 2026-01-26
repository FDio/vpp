/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tracepath/tracepath.h>
#include <vlib/trace.h>
#include <vppinfra/crc32.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* FIXME: No state is preserved today on packet trace paths.. therefore we always iterate over all
 * traces */

static u8 *
format_trace_path (u8 *s, va_list *va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  trace_path_t *p = va_arg (*va, trace_path_t *);
  u32 i;
  vlib_node_t *node;

  for (i = 0; i < p->path_length; i++)
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
  u64 bitmap = va_arg (*va, u64);
  u8 first = 1;

  s = format (s, "[");
  for (u32 i = 0; i < 64; i++)
    {
      if (bitmap & ((u64) 1 << i))
	{
	  if (!first)
	    s = format (s, ", ");
	  s = format (s, "%d", i);
	  first = 0;
	}
    }
  s = format (s, "]");
  return s;
}

/* FIXME - Assess if crc32c is the best approach for path hash */
static inline u32
trace_path_hash (u32 path_len, u32 *path_indices)
{
  return clib_crc32c ((u8 *) path_indices, sizeof (u32) * path_len);
}

static int
trace_path_cmp (void *v1, void *v2)
{
  trace_path_t *p1 = (trace_path_t *) v1;
  trace_path_t *p2 = (trace_path_t *) v2;
  return (i32) p2->n_pkts - (i32) p1->n_pkts;
}

static trace_path_t
trace_path_from_header (vlib_trace_header_t *h) // ?
{
  vlib_trace_header_t *e = vec_end (h);
  trace_path_t path = { .path_length = 0 };

  /* Iterate over trace header to build trace_path entry */
  while (h < e && path.path_length < TRACE_PATH_MAX_LENGTH)
    {
      path.path_indices[path.path_length] = h->node_index;
      path.path_length++;
      h = vlib_trace_header_next (h);
    }

  if (path.path_length > 0)
    {
      path.n_pkts = 1;
      path.path_hash = trace_path_hash (path.path_length, path.path_indices);
    }

  return path;
}

trace_path_t *
trace_paths_collect (vlib_main_t *vm)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  trace_path_t *paths = 0;
  trace_path_t *path = 0;
  uword *path_hash_table = 0;

  /* Iterate over all valid traces */
  pool_foreach (h, tm->trace_buffer_pool)
    {
      trace_path_t new_path = trace_path_from_header (h[0]);

      if (new_path.path_length == 0)
	continue;

      uword *p = hash_get (path_hash_table, new_path.path_hash);
      if (p)
	{
	  /* TODO - vec_elt here */
	  path = vec_elt_at_index (paths, p[0]);
	  path->n_pkts++;
	}
      else
	{
	  /* TODO - Update hash table entries directly, rather than keep a
	  parallel vector/hash table data structures */
	  u32 idx = vec_len (paths);
	  vec_add1 (paths, new_path);
	  hash_set (path_hash_table, new_path.path_hash, idx);
	}
    }

  hash_free (path_hash_table);

  /* Sort by packet count descending */
  if (vec_len (paths) > 1)
    vec_sort_with_function (paths, trace_path_cmp);

  return paths;
}

/* Collect and merge paths from all threads */
trace_path_t *
trace_paths_collect_all (void)
{
  trace_path_t *merged_paths = 0;
  uword *path_hash_table = 0;
  u32 thread_index = 0;

  foreach_vlib_main ()
    {
      trace_path_t *thread_paths = trace_paths_collect (this_vlib_main);

      trace_path_t *p;
      vec_foreach (p, thread_paths)
	{
	  uword *existing = hash_get (path_hash_table, p->path_hash);
	  if (existing)
	    {
	      u32 idx = existing[0];
	      /* TODO - vec_elt here */
	      merged_paths[idx].thread_bitmap |= ((u64) 1 << thread_index);
	      merged_paths[idx].n_pkts += p->n_pkts;
	    }
	  else
	    {
	      u32 idx = vec_len (merged_paths);
	      trace_path_t mp = *p;
	      mp.thread_bitmap = ((u64) 1 << thread_index);
	      vec_add1 (merged_paths, mp);
	      hash_set (path_hash_table, p->path_hash, idx);
	    }
	}

      vec_free (thread_paths);
      thread_index++;
    }

  hash_free (path_hash_table);

  /* Sort by packet count descending */
  if (vec_len (merged_paths) > 1)
    vec_sort_with_function (merged_paths, trace_path_cmp);

  return merged_paths;
}

static vlib_trace_header_t **
trace_paths_get_traces_by_hash (vlib_main_t *vm, u32 path_hash)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  vlib_trace_header_t **matching_traces = 0;

  pool_foreach (h, tm->trace_buffer_pool)
    {
      /* Computes paths and paths hashes.. */
      trace_path_t path = trace_path_from_header (h[0]);

      if (path.path_hash == path_hash)
	vec_add1 (matching_traces, h[0]);
    }

  /* Sort by time */
  if (vec_len (matching_traces) > 1)
    vec_sort_with_function (matching_traces, trace_time_cmp);

  return matching_traces;
}

static clib_error_t *
show_trace_paths_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  f64 start_time = vlib_time_now (vm);
  u32 max_paths = 10;
  u8 *s = 0;
  trace_path_t *merged_paths = 0;

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max %d", &max_paths))
	;
      else
	return clib_error_create ("expected 'max COUNT', got `%U'", format_unformat_error, input);
    }

  vlib_worker_thread_barrier_sync (vm);

  /* Collect and merge paths from all threads */
  merged_paths = trace_paths_collect_all ();

  vlib_worker_thread_barrier_release (vm);

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
	  if (i > max_paths)
	    break;
	  s = format (s, "  [%d] Count: %d  Hash: 0x%08x  Length: %2d  Threads: %U\n", i, p->n_pkts,
		      p->path_hash, p->path_length, format_thread_list, p->thread_bitmap);
	  s = format (s, "      Path: %U\n\n", format_trace_path, vm, p);
	  i++;
	}

      if (vec_len (merged_paths) > max_paths)
	s = format (s, "  ... %d more paths not shown (use 'max' to see more)\n",
		    vec_len (merged_paths) - max_paths);
    }

  vec_free (merged_paths);

  f64 elapsed_time = vlib_time_now (vm) - start_time;
  clib_warning ("show trace paths: execution time %.6f seconds", elapsed_time);

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (show_trace_paths_cli, static) = {
  .path = "show trace paths",
  .short_help = "show trace paths [max COUNT]",
  .function = show_trace_paths_fn,
};

/* Show traces for a specific path indices.. */
static clib_error_t *
show_trace_path_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  /* FIXME - if 'show trace path' is called without any args */
  /* it fails, and 'show trace' is called instead.. */
  f64 start_time = vlib_time_now (vm);
  u32 path_index;
  u32 max_traces = 50;
  u32 thread_index = 0;
  u8 *s = 0;
  u32 *path_indices = 0;
  uword *path_filter = 0;
  trace_path_t *merged_paths = 0;

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &path_index))
	{
	  clib_warning ("Path indice %d", path_index);
	  vec_add1 (path_indices, path_index);
	  hash_set (path_filter, path_index, 1);
	}
      else if (unformat (input, "max %d", &max_traces))
	;
      else
	{
	  vec_free (path_indices);
	  hash_free (path_filter);
	  return clib_error_create ("expected '<INDEX> [<INDEX>...]' or 'max COUNT', got `%U'",
				    format_unformat_error, input);
	}
    }

  if (vec_len (path_indices) == 0)
    return clib_error_create (
      "path index required. Use 'show trace paths' to see available paths.");

  vlib_worker_thread_barrier_sync (vm);

  /* Collect and merge paths from all threads */
  merged_paths = trace_paths_collect_all ();

  /* First pass: show all requested trace path summaries */
  u32 n_paths = vec_len (merged_paths);

  s = format (s, "\nRequested trace paths:\n");
  for (u32 idx = 0; idx < n_paths; idx++)
    {
      /* Skip if not in filter */
      if (!hash_get (path_filter, idx))
	continue;

      trace_path_t *p = &merged_paths[idx];

      s = format (s, "\n  Path [%d]: %U\n", idx, format_trace_path, vm, p);
      s = format (s, "  Threads: %U  Total Count: %d\n", format_thread_list, p->thread_bitmap,
		  p->n_pkts);
    }

  s = format (s, "\n");

  /* Second pass: show traces for selected paths from all threads they appeared on */
  u32 traces_shown = 0;

  for (u32 idx = 0; idx < n_paths && traces_shown < max_traces; idx++)
    {
      /* Skip if not in filter */
      if (!hash_get (path_filter, idx))
	continue;

      trace_path_t *p = &merged_paths[idx];

      s = format (s, "\n==================== Path [%d] Traces ====================\n", idx);
      s = format (s, "Path: %U\n\n", format_trace_path, vm, p);

      /* Iterate over threads where this path was seen */
      thread_index = 0;
      foreach_vlib_main ()
	{
	  s = format (s, "------------------- Start of thread %d %s -------------------\n",
		      thread_index, vlib_worker_threads[thread_index].name);

	  if (!(p->thread_bitmap & ((u64) 1 << thread_index)))
	    {
	      s = format (s, "No packets in trace buffer\n");
	      thread_index++;
	      continue;
	    }

	  vlib_trace_header_t **traces =
	    trace_paths_get_traces_by_hash (this_vlib_main, p->path_hash);

	  if (vec_len (traces) > 0)
	    {
	      u32 i;
	      for (i = 0; i < vec_len (traces) && traces_shown < max_traces; i++)
		{
		  s = format (s, "Packet %d\n%U\n\n", traces_shown + 1, format_vlib_trace,
			      this_vlib_main, traces[i]);
		  traces_shown++;
		}

	      if (traces_shown >= max_traces && i < vec_len (traces))
		s = format (s,
			    "Limiting display to %d packets."
			    " To display more specify max.\n",
			    max_traces);
	    }

	  vec_free (traces);
	  thread_index++;
	}
    }

  vlib_worker_thread_barrier_release (vm);

  if (vec_len (s) == 0)
    {
      s = format (s, "No traces found for path index");
      if (vec_len (path_indices) == 1)
	s = format (s, " %d\n", path_indices[0]);
      else
	{
	  s = format (s, "es:");
	  for (u32 i = 0; i < vec_len (path_indices); i++)
	    s = format (s, " %d", path_indices[i]);
	  s = format (s, "\n");
	}
    }

  f64 elapsed_time = vlib_time_now (vm) - start_time;
  clib_warning ("show trace path: execution time %.6f seconds", elapsed_time);

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  vec_free (path_indices);
  hash_free (path_filter);
  vec_free (merged_paths);
  return 0;
}

VLIB_CLI_COMMAND (show_trace_path_cli, static) = {
  .path = "show trace path",
  .short_help = "show trace path [<INDEX>] [<INDEX>...] [max COUNT]",
  .function = show_trace_path_fn,
};
