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

static clib_error_t *
show_stat_directory_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input = {}, *line_input = &_line_input;
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *show_data = 0, *e;
  clib_error_t *err = 0;
  char *match = 0;
  u8 *fmt = 0;
  u32 max_name_len = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%s", &match))
	    ;
	  else
	    {
	      err = clib_error_return (0, "parse error: '%U'",
				       format_unformat_error, line_input);
	      goto done;
	    }
	}
    }

  /* Lock even as reader, as this command doesn't handle epoch changes */
  vlib_stats_segment_lock ();
  vec_foreach (e, sm->directory_vector)
    {
      if (e->in_use == 0)
	continue;

      if (match && strstr (e->name, match) == 0)
	continue;

      max_name_len = clib_max (max_name_len, strlen (e->name));

      vec_add1 (show_data, *e);
    }
  vlib_stats_segment_unlock ();

  vec_sort_with_function (show_data, name_sort_cmp);

  max_name_len = clib_min (max_name_len, 74);
  fmt = format (fmt, "%%-%us %%-10s %%s%c", max_name_len, 0);
  vlib_cli_output (vm, (char *) fmt, "Name", "Type", "Dim");

  vec_reset_length (fmt);
  fmt = format (fmt, "%%-%us %%-10s %%U%c", max_name_len, 0);
  vec_foreach (e, show_data)
    {
      vlib_stats_data_type_info_t *dti = vlib_stats_data_types + e->data_type;
      vlib_cli_output (vm, (char *) fmt, e->name, dti->name,
		       format_vlib_stats_entry_dim, e);
    }

done:
  vec_free (fmt);
  vec_free (match);
  vec_free (show_data);
  return err;
}

VLIB_CLI_COMMAND (show_stat_directory_command, static) = {
  .path = "show statistics directory",
  .short_help = "show statistics directory [<match>]",
  .function = show_stat_directory_command_fn,
};

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

static clib_error_t *
show_stat_entry_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e;
  vlib_stats_data_type_info_t *dti;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u32 entry_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "please specify command line arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_stats_entry_name,
		    &entry_index))
	;
      else
	{
	  err = clib_error_return (0, "parse error: '%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (entry_index == ~0)
    {
      err = clib_error_return (0, "entry not found");
      goto done;
    }

  e = vlib_stats_get_entry (sm, entry_index);
  dti = vlib_stats_data_types + e->data_type;
  vlib_cli_output (vm, "Entry:      %s", e->name);
  vlib_cli_output (vm, "Type:       %s", dti->name);
  vlib_cli_output (vm, "Elt Size:   %u bytes", dti->size);
  vlib_cli_output (vm, "Dimensions: %U", format_vlib_stats_entry_dim, e);
  vlib_cli_output (vm, "Value:      %U", format_vlib_stats_entry_value, e);

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (show_stats_entry_command, static) = {
  .path = "show statistics entry",
  .short_help = "show statistics entry <entry-name>",
  .function = show_stat_entry_command_fn,
};
