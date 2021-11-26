/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <perfmon/perfmon.h>
#include <vppinfra/format_table.h>

uword
unformat_perfmon_bundle_name (unformat_input_t *input, va_list *args)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t **b = va_arg (*args, perfmon_bundle_t **);
  uword *p;
  u8 *str = 0;

  if (unformat (input, "%s", &str) == 0)
    return 0;

  p = hash_get_mem (pm->bundle_by_name, str);

  if (p)
    b[0] = (perfmon_bundle_t *) p[0];

  vec_free (str);
  return p ? 1 : 0;
}

uword
unformat_perfmon_active_type (unformat_input_t *input, va_list *args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  perfmon_bundle_type_t *bundle_type = va_arg (*args, perfmon_bundle_type_t *);
  char *str = 0;

  char *_str_types[PERFMON_BUNDLE_TYPE_MAX];

#define _(type, pstr) _str_types[type] = (char *) pstr;

  foreach_perfmon_bundle_type
#undef _

    if (!b) return 0;

  if (unformat (input, "%s", &str) == 0)
    return 0;

  for (int i = PERFMON_BUNDLE_TYPE_NODE; i < PERFMON_BUNDLE_TYPE_MAX; i++)
    {
      /* match the name and confirm it is available on this cpu */
      if (strncmp (str, _str_types[i], strlen (_str_types[i])) == 0 &&
	  (b->type_flags & 1 << i))
	{
	  *bundle_type = i;
	  break;
	}
    }

  vec_free (str);
  return bundle_type ? 1 : 0;
}

uword
unformat_perfmon_source_name (unformat_input_t *input, va_list *args)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t **b = va_arg (*args, perfmon_source_t **);
  uword *p;
  u8 *str = 0;

  if (unformat (input, "%s", &str) == 0)
    return 0;

  p = hash_get_mem (pm->source_by_name, str);

  if (p)
    b[0] = (perfmon_source_t *) p[0];

  vec_free (str);
  return p ? 1 : 0;
}

typedef enum
{
  FORMAT_PERFMON_BUNDLE_NONE = 0,
  FORMAT_PERFMON_BUNDLE_VERBOSE = 1,
  FORMAT_PERFMON_BUNDLE_SHOW_CONFIG = 2
} format_perfmon_bundle_args_t;

u8 *
format_perfmon_bundle (u8 *s, va_list *args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  format_perfmon_bundle_args_t cfg =
    va_arg (*args, format_perfmon_bundle_args_t);

  int vl = 0;

  u8 *_bundle_type = 0;
  const char *bundle_type[PERFMON_BUNDLE_TYPE_MAX];
#define _(type, pstr) bundle_type[type] = (const char *) pstr;

  foreach_perfmon_bundle_type
#undef _

    if (b == 0) return format (s, "%-20s%-20s%-20s%s", "Name", "Type(s)",
			       "Source", "Description");

  if (cfg != FORMAT_PERFMON_BUNDLE_NONE)
    {
      s = format (s, "name: %s\n", b->name);
      s = format (s, "description: %s\n", b->description);
      s = format (s, "source: %s\n", b->src->name);
      for (int i = 0; i < b->n_events; i++)
	{
	  perfmon_event_t *e = b->src->events + b->events[i];
	  s = format (s, "event %u: %s", i, e->name);

	  format_function_t *format_config = b->src->format_config;

	  if (format_config && cfg == FORMAT_PERFMON_BUNDLE_SHOW_CONFIG)
	    s = format (s, " (%U)", format_config, e->config);

	  s = format (s, "\n");
	}
    }
  else
    {
      s = format (s, "%-20s", b->name);
      for (int i = PERFMON_BUNDLE_TYPE_NODE; i < PERFMON_BUNDLE_TYPE_MAX; i++)
	{
	  /* check the type is available on this uarch*/
	  if (b->type_flags & 1 << i)
	    _bundle_type = format (_bundle_type, "%s,", bundle_type[i]);
	}
      /* remove any stray commas */
      if ((vl = vec_len (_bundle_type)))
	_bundle_type[vl - 1] = 0;

      s =
	format (s, "%-20s%-20s%s", _bundle_type, b->src->name, b->description);
    }

  vec_free (_bundle_type);

  return s;
}

static int
bundle_name_sort_cmp (void *a1, void *a2)
{
  perfmon_bundle_t **n1 = a1;
  perfmon_bundle_t **n2 = a2;

  return clib_strcmp ((char *) (*n1)->name, (char *) (*n2)->name);
}

static clib_error_t *
show_perfmon_bundle_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_bundle_t *b = 0, **vb = 0;
  int verbose = 0;
  format_perfmon_bundle_args_t cfg = FORMAT_PERFMON_BUNDLE_NONE;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "%U", unformat_perfmon_bundle_name,
			     &b))
	    vec_add (vb, &b, 1);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  if (verbose) /* if verbose is specified */
    cfg = FORMAT_PERFMON_BUNDLE_VERBOSE;

  if (vb)
    {
      if (verbose) /* if verbose is specified with a bundle */
	cfg = FORMAT_PERFMON_BUNDLE_SHOW_CONFIG;
      else
	cfg = FORMAT_PERFMON_BUNDLE_VERBOSE;
    }
  else
    {
      char *key;
      hash_foreach_mem (key, b, pm->bundle_by_name, vec_add (vb, &b, 1););
    }

  if (cfg == FORMAT_PERFMON_BUNDLE_NONE)
    vlib_cli_output (vm, "%U\n", format_perfmon_bundle, 0, cfg);

  vec_sort_with_function (vb, bundle_name_sort_cmp);

  for (int i = 0; i < vec_len (vb); i++)
    /* bundle type will be unknown if no cpu_supports matched */
    if (vb[i]->type_flags)
      vlib_cli_output (vm, "%U\n", format_perfmon_bundle, vb[i], cfg);

  vec_free (vb);
  return 0;
}

VLIB_CLI_COMMAND (show_perfmon_bundle_command, static) = {
  .path = "show perfmon bundle",
  .short_help = "show perfmon bundle [<bundle-name>] [verbose]",
  .function = show_perfmon_bundle_command_fn,
  .is_mp_safe = 1,
};

u8 *
format_perfmon_source (u8 *s, va_list *args)
{
  perfmon_source_t *src = va_arg (*args, perfmon_source_t *);
  int verbose = va_arg (*args, int);

  if (src == 0)
    return format (s, "%-20s%-9s %s", "Name", "NumEvents", "Description");

  if (verbose)
    {
      s = format (s, "name:        %s\n", src->name);
      s = format (s, "description: %s\n", src->description);
      s = format (s, "Events:\n");
      for (int i = 0; i < src->n_events; i++)
	{
	  perfmon_event_t *e = src->events + i;
	  s = format (s, "  %s", e->name);
	  if (src->format_config)
	    s = format (s, " (%U)\n", src->format_config, e->config);
	  else
	    s = format (s, " (0x%x)\n", e->config);
	  if (e->description)
	    s = format (s, "    %s\n", e->description);
	}

      if (src->instances_by_type)
	{
	  s = format (s, "Instances:\n");
	  for (int i = 0; i < vec_len (src->instances_by_type); i++)
	    {
	      perfmon_instance_type_t *it;
	      it = vec_elt_at_index (src->instances_by_type, i);
	      if (vec_len (it->instances) == 0)
		continue;
	      s = format (s, "  %s:\n   ", it->name);
	      for (int j = 0; j < vec_len (it->instances); j++)
		{
		  perfmon_instance_t *in = vec_elt_at_index (it->instances, j);
		  s = format (s, " %s", in->name);
		}
	      s = format (s, "\n");
	    }
	}
    }
  else
    s = format (s, "%-20s%9u %s", src->name, src->n_events, src->description);

  return s;
}

static clib_error_t *
show_perfmon_source_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_source_t *s = 0, **vs = 0;
  int verbose = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "%U", unformat_perfmon_source_name,
			     &s))
	    vec_add (vs, &s, 1);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  if (vs == 0)
    {
      char *key;
      hash_foreach_mem (key, s, pm->source_by_name, vec_add (vs, &s, 1););
    }
  else
    verbose = 1;

  if (verbose == 0)
    vlib_cli_output (vm, "%U\n", format_perfmon_source, 0, 0);

  for (int i = 0; i < vec_len (vs); i++)
    vlib_cli_output (vm, "%U\n", format_perfmon_source, vs[i], verbose);

  vec_free (vs);
  return 0;
}

VLIB_CLI_COMMAND (show_perfmon_source_command, static) = {
  .path = "show perfmon source",
  .short_help = "show perfmon source [<source-name>] [verbose]",
  .function = show_perfmon_source_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_perfmon_active_bundle_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  perfmon_main_t *pm = &perfmon_main;

  vlib_cli_output (vm, "%U\n", format_perfmon_bundle, pm->active_bundle, 1);
  return 0;
}

VLIB_CLI_COMMAND (show_perfmon_active_bundle_command, static) = {
  .path = "show perfmon active-bundle",
  .short_help = "show perfmon active-bundle",
  .function = show_perfmon_active_bundle_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_perfmon_stats_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = pm->active_bundle;
  clib_error_t *err = 0;
  table_t table = {}, *t = &table;
  u32 n_instances;
  perfmon_reading_t *r, *readings = 0;
  perfmon_instance_type_t *it = pm->active_instance_type;
  perfmon_instance_t *in;
  u8 *s = 0;
  int n_row = 0;

  if (b == 0)
    return clib_error_return (0, "no bundle selected");

  n_instances = vec_len (it->instances);
  vec_validate (readings, n_instances - 1);

  /*Only perform read() for THREAD or SYSTEM bundles*/
  for (int i = 0;
       i < n_instances && b->active_type != PERFMON_BUNDLE_TYPE_NODE; i++)
    {
      in = vec_elt_at_index (it->instances, i);
      r = vec_elt_at_index (readings, i);

      if (read (pm->group_fds[i], r, (b->n_events + 3) * sizeof (u64)) == -1)
	{
	  err = clib_error_return_unix (0, "read");
	  goto done;
	}
    }

  table_format_title (t, "%s", b->description);

  table_add_header_col (t, 0);
  table_add_header_row (t, 0);

  if (b->column_headers)
    {
      char **hdr = b->column_headers;
      while (hdr[0])
	table_format_cell (t, -1, n_row++, "%s", hdr++[0]);
    }

  int col = 0;
  for (int i = 0; i < n_instances; i++)
    {
      in = vec_elt_at_index (it->instances, i);
      r = vec_elt_at_index (readings, i);
      table_format_cell (t, col, -1, "%s", in->name, b->active_type);
      if (b->active_type == PERFMON_BUNDLE_TYPE_NODE)
	{
	  perfmon_thread_runtime_t *tr;
	  tr = vec_elt_at_index (pm->thread_runtimes, i);
	  for (int j = 0; j < tr->n_nodes; j++)
	    if (tr->node_stats[j].n_calls)
	      {
		perfmon_node_stats_t ns;
		table_format_cell (t, ++col, -1, "%U", format_vlib_node_name,
				   vm, j, b->active_type);
		table_set_cell_align (t, col, -1, TTAA_RIGHT);
		table_set_cell_fg_color (t, col, -1, TTAC_CYAN);
		clib_memcpy_fast (&ns, tr->node_stats + j, sizeof (ns));

		for (int j = 0; j < n_row; j++)
		  table_format_cell (t, col, j, "%U", b->format_fn, &ns, j,
				     b->active_type);
	      }
	}
      else
	{
	  for (int j = 0; j < n_row; j++)
	    table_format_cell (t, i, j, "%U", b->format_fn, r, j,
			       b->active_type);
	}
      col++;
    }

  vlib_cli_output (vm, "%U\n", format_table, t);
  table_free (t);

  if (b->footer)
    vlib_cli_output (vm, "\n%s\n", b->footer);

done:
  vec_free (readings);
  vec_free (s);
  return err;
}

VLIB_CLI_COMMAND (show_perfmon_stats_command, static) = {
  .path = "show perfmon statistics",
  .short_help = "show perfmon statistics [raw]",
  .function = show_perfmon_stats_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
perfmon_reset_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  perfmon_reset (vm);
  return 0;
}

VLIB_CLI_COMMAND (perfmon_reset_command, static) = {
  .path = "perfmon reset",
  .short_help = "perfmon reset",
  .function = perfmon_reset_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
perfmon_start_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_bundle_t *b = 0;
  perfmon_bundle_type_t bundle_type = PERFMON_BUNDLE_TYPE_UNKNOWN;

  if (pm->is_running)
    return clib_error_return (0, "please stop first");

  if (unformat_user (input, unformat_line_input, line_input) == 0)
    return clib_error_return (0, "please specify bundle name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "bundle %U", unformat_perfmon_bundle_name, &b))
	;
      else if (unformat (line_input, "type %U", unformat_perfmon_active_type,
			 b, &bundle_type))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (b == 0)
    return clib_error_return (0, "please specify bundle name");

  /* if there is more than one valid mode */
  if (count_set_bits (b->type_flags) > 1)
    {
      /* what did the user indicate */
      if (!bundle_type)
	return clib_error_return (0, "please specify a valid type");
    }
  else /* otherwise just use the default  */
    {
      if (bundle_type && !(b->type_flags & bundle_type))
	return clib_error_return (0, "please specify a valid type");

      bundle_type =
	(perfmon_bundle_type_t) count_trailing_zeros (b->type_flags);
    }

  b->active_type = bundle_type;

  return perfmon_start (vm, b);
}

VLIB_CLI_COMMAND (perfmon_start_command, static) = {
  .path = "perfmon start",
  .short_help = "perfmon start bundle [<bundle-name>] type [<node|thread>]",
  .function = perfmon_start_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
perfmon_stop_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  return perfmon_stop (vm);
}

VLIB_CLI_COMMAND (perfmon_stop_command, static) = {
  .path = "perfmon stop",
  .short_help = "perfmon stop",
  .function = perfmon_stop_command_fn,
  .is_mp_safe = 1,
};
