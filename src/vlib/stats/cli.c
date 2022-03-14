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

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      type_name = "CMainPtr";
      break;

    case STAT_DIR_TYPE_NAME_VECTOR:
      type_name = "NameVector";
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
static clib_error_t *
show_stat_segment_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *show_data;
  int i;

  int verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;

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
  .short_help = "show statistics segment [verbose]",
  .function = show_stat_segment_command_fn,
};
