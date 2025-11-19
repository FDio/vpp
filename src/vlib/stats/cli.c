/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

static int
name_sort_cmp (void *a1, void *a2)
{
  vlib_stats_entry_t *n1 = a1;
  vlib_stats_entry_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static u8 *
format_stat_dir_entry (u8 *s, va_list *args)
{
  vlib_stats_entry_t *ep = va_arg (*args, vlib_stats_entry_t *);
  char *type_name;
  char *format_string;

  format_string = "%-74s %-10s %10lld";

  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      type_name = "ScalarPtr";
      break;

    case STAT_DIR_TYPE_GAUGE:
      type_name = "Gauge";
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      type_name = "CMainPtr";
      break;

    case STAT_DIR_TYPE_NAME_VECTOR:
      type_name = "NameVector";
      break;

    case STAT_DIR_TYPE_RING_BUFFER:
      type_name = "RingBuffer";
      break;

    case STAT_DIR_TYPE_HISTOGRAM_LOG2:
      type_name = "Histogram";
      break;
    case STAT_DIR_TYPE_EMPTY:
      type_name = "empty";
      break;

    case STAT_DIR_TYPE_SYMLINK:
      type_name = "Symlink";
      break;

    default:
      type_name = "illegal!";
      break;
    }

  return format (s, format_string, ep->name, type_name, 0);
}

static u8 *
format_stat_dir_entry_detail (u8 *s, va_list *args)
{
  vlib_stats_entry_t *ep = va_arg (*args, vlib_stats_entry_t *);

  if (ep->type == STAT_DIR_TYPE_RING_BUFFER)
    {
      vlib_stats_ring_buffer_t *rb = ep->data;
      if (rb)
	{
	  s = format (s, "RingBuffer: %s\n", ep->name);
	  s = format (s, "  ring_size: %u\n", rb->config.ring_size);
	  s = format (s, "  entry_size: %u\n", rb->config.entry_size);
	  s = format (s, "  n_threads: %u\n", rb->config.n_threads);
	  for (u32 t = 0; t < rb->config.n_threads; t++)
	    {
	      vlib_stats_ring_metadata_t *md =
		(vlib_stats_ring_metadata_t
		   *) ((u8 *) rb + rb->metadata_offset +
		       t * sizeof (vlib_stats_ring_metadata_t));
	      s = format (s, "  [thread %u] head:%u seq:%llu\n", t, md->head,
			  (unsigned long long) md->sequence);
	    }
	}
      else
	{
	  s = format (s, "RingBuffer: %s (uninitialized)\n", ep->name);
	}
    }
  else if (ep->type == STAT_DIR_TYPE_HISTOGRAM_LOG2)
    {
      u64 **log2_histogram_bins = ep->data;
      if (!log2_histogram_bins)
	{
	  s = format (s, "Histogram: %s (uninitialized)\n", ep->name);
	  return s;
	}

      s = format (s, "Histogram: %s\n", ep->name);
      for (u32 k = 0; k < vec_len (log2_histogram_bins); k++)
	{
	  u64 *bins = log2_histogram_bins[k];
	  int n_bins = vec_len (bins);
	  if (n_bins < 2) // Need at least min_exp + one bin
	    continue;
	  u32 min_exp = bins[0];
	  u64 cumulative = 0;
	  u64 sum = 0;
	  s = format (s, "  [thread %u]:\n", k);
	  for (int j = 1; j < n_bins; ++j)
	    {
	      cumulative += bins[j];
	      sum += bins[j] * (1ULL << (min_exp + j - 1)); // midpoint approx
	      s = format (s, "    <= %llu: %llu (cumulative: %llu)\n",
			  (1ULL << (min_exp + j - 1)), bins[j], cumulative);
	    }
	  s = format (s, "    +Inf: %llu (total count: %llu, sum: %llu)\n",
		      cumulative, cumulative, sum);
	}
    }
  else
    {
      s = format (s, "Entry: %s (type %d)\n", ep->name, ep->type);
    }
  return s;
}

static clib_error_t *
show_stat_segment_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *show_data;
  int i;
  int verbose = 0;
  u8 *counter_name = 0;

  // Parse both 'verbose' and counter name in any order
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "%s", &counter_name))
	;
      else
	break;
    }

  if (counter_name)
    {
      u32 index = vlib_stats_find_entry_index ("%s", counter_name);
      if (index != STAT_SEGMENT_INDEX_INVALID)
	{
	  vlib_stats_entry_t *ep = sm->directory_vector + index;
	  vlib_cli_output (vm, "%U", format_stat_dir_entry_detail, ep);
	  if (verbose)
	    {
	      ASSERT (sm->heap);
	      vlib_cli_output (vm, "%U", format_clib_mem_heap, sm->heap,
			       0 /* verbose */);
	    }
	}
      else
	{
	  vlib_cli_output (vm, "Counter '%s' not found.", counter_name);
	}
      vec_free (counter_name);
      return 0;
    }

  /* Lock even as reader, as this command doesn't handle epoch changes */
  vlib_stats_segment_lock ();
  show_data = vec_dup (sm->directory_vector);
  vlib_stats_segment_unlock ();

  vec_sort_with_function (show_data, name_sort_cmp);

  vlib_cli_output (vm, "%-74s %10s %10s", "Name", "Type", "Value");

  for (i = 0; i < vec_len (show_data); i++)
    {
      vlib_stats_entry_t *ep = vec_elt_at_index (show_data, i);

      if (ep->type == STAT_DIR_TYPE_EMPTY)
	continue;

      vlib_cli_output (vm, "%-100U", format_stat_dir_entry,
		       vec_elt_at_index (show_data, i));
    }

  if (verbose)
    {
      ASSERT (sm->heap);
      vlib_cli_output (vm, "%U", format_clib_mem_heap, sm->heap,
		       0 /* verbose */);
    }

  return 0;
}

static clib_error_t *
show_stat_segment_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  char *name;
  u32 i;
  hash_foreach_mem (name, i, sm->directory_vector_by_name,
		    ({ vlib_cli_output (vm, "%d: %s\n", i, name); }));
  return 0;
}

VLIB_CLI_COMMAND (show_stat_segment_hash_command, static) = {
  .path = "show statistics hash",
  .short_help = "show statistics hash",
  .function = show_stat_segment_hash_command_fn,
};

VLIB_CLI_COMMAND (show_stat_segment_command, static) = {
  .path = "show statistics segment",
  .short_help = "show statistics segment [counter-name] [verbose]",
  .function = show_stat_segment_command_fn,
};
