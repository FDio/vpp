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

uword
unformat_perfmon_bundle_name (unformat_input_t * input, va_list * args)
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
unformat_perfmon_source_name (unformat_input_t * input, va_list * args)
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

u8 *
format_perfmon_bundle (u8 * s, va_list * args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  int verbose = va_arg (*args, int);

  const char *bundle_type[] = {
    [PERFMON2_BUNDLE_TYPE_NODE] = "node",
    [PERFMON2_BUNDLE_TYPE_THREAD] = "thread",
    [PERFMON2_BUNDLE_TYPE_SYSTEM] = "system",
  };

  if (b == 0)
    return format (s, "%-20s%-10s%-20s%s",
		   "Name", "Type", "Source", "Description");

  if (verbose)
    {
      s = format (s, "name: %s\n", b->name);
      s = format (s, "description: %s\n", b->description);
      s = format (s, "source: %s\n", b->src->name);
      for (int i = 0; i < b->n_events; i++)
	{
	  perfmon_event_t *e = b->src->events + b->events[i];
	  s = format (s, "event %u: %s\n", i, e->name);
	}
    }
  else
    s = format (s, "%-20s%-10s%-20s%s", b->name, bundle_type[b->type],
		b->src->name, b->description);

  return s;
}

static clib_error_t *
show_perfmon_bundle_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_bundle_t *b = 0, **vb = 0;
  int verbose = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "%U",
			     unformat_perfmon_bundle_name, &b))
	    vec_add (vb, &b, 1);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  if (vb == 0)
    {
      char *key;

      /* *INDENT-OFF* */
      hash_foreach_mem (key, b, pm->bundle_by_name,
        vec_add (vb, &b, 1); );
      /* *INDENT-ON* */
    }
  else
    verbose = 1;

  if (verbose == 0)
    vlib_cli_output (vm, "%U\n", format_perfmon_bundle, 0, 0);

  for (int i = 0; i < vec_len (vb); i++)
    vlib_cli_output (vm, "%U\n", format_perfmon_bundle, vb[i], verbose);

  vec_free (vb);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_perfmon_bundle_command, static) =
{
  .path = "show perfmon bundle",
  .short_help = "show perfmon bundle [<bundle-name>] [verbose]",
  .function = show_perfmon_bundle_command_fn,
};

u8 *
format_perfmon_source (u8 * s, va_list * args)
{
  perfmon_source_t *src = va_arg (*args, perfmon_source_t *);
  int verbose = va_arg (*args, int);

  if (src == 0)
    return format (s, "%-20s%-10s%-20s%s",
		   "Name", "Type", "Source", "Description");

  if (verbose)
    {
      s = format (s, "name: %s\n", src->name);
      s = format (s, "description: %s\n", src->description);
      for (int i = 0; i < src->n_events; i++)
	{
	  perfmon_event_t *e = src->events + i;
	  s = format (s, "event: %s\n", e->name);
	  if (src->format_config)
	    s = format (s, "config: %U\n", src->format_config, e->config);
	  if (src->format_config)
	    s = format (s, "description: %s\n", e->description);
	  s = format (s, "\n");
	}
    }
  else
    s = format (s, "%-20s%s", src->name, src->description);

  return s;
}

static clib_error_t *
show_perfmon_source_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
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
	  else if (unformat (line_input, "%U",
			     unformat_perfmon_source_name, &s))
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

      /* *INDENT-OFF* */
      hash_foreach_mem (key, s, pm->source_by_name, ({
	  vec_add (vs, &s, 1);
	}));
      /* *INDENT-ON* */
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_perfmon_source_command, static) =
{
  .path = "show perfmon source",
  .short_help = "show perfmon source [<source-name>] [verbose]",
  .function = show_perfmon_source_command_fn,
};

static clib_error_t *
show_perfmon_active_bundle_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;

  vlib_cli_output (vm, "%U\n", format_perfmon_bundle, pm->active_bundle, 1);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_perfmon_active_bundle_command, static) =
{
  .path = "show perfmon active-bundle",
  .short_help = "show perfmon active-bundle",
  .function = show_perfmon_active_bundle_command_fn,
};


static u8 *
format_perfmon_header_generic (u8 *s, va_list * args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  s = format (s, "%10s", "Calls");
  s = format (s, "%12s", "Packets");
  for (int j = 0; j < b->n_events; j++)
    s = format (s, "             [%u]", j);
  return s;
}

static u8 *
format_perfmon_node_generic (u8 *s, va_list * args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  perfmon_node_counters_t *nc = va_arg (*args, perfmon_node_counters_t *);
  s = format (s, "%10lu", nc->n_calls);
  s = format (s, "%12lu", nc->n_packets);
  for (int j = 0; j < b->n_events; j++)
    s = format (s, "%16lu", nc->event_ctr[j]);
  return s;
}

static u8 *
format_perfmon_footer_generic (u8 *s, va_list * args)
{
  perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  for (int j = 0; j < b->n_events; j++)
    {
      perfmon_event_t *e = b->src->events + b->events[j];
      s = format (s, "\n[%u] %s", j, e->name);
      s = format (s, "\n     %s", e->description);
    }
  return s;
}


static clib_error_t *
show_perfmon_report_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = pm->active_bundle;
  u32 n_nodes = vec_len (vm->node_main.nodes);
  u8 *s = 0;

  if (pm->is_running)
    return clib_error_return (0, "please stop first");

  vlib_cli_output (vm, "Bundle: %s (%s)\n", b->name, b->description);

  vlib_cli_output (vm, "%28s%U\n", "", b->format_header ? b->format_header :
		   format_perfmon_header_generic, b);

  for (int t = 0; t < vec_len (pm->threads); t++)
    {
      perfmon_thread_t *pt = vec_elt_at_index (pm->threads, t);

      for (int i = 0; i <  n_nodes; i++)
	{
	  perfmon_node_counters_t *nc;
	  nc = perfmon_get_node_counters (pt, i);
	  if (nc->n_calls == 0)
	    continue;

	  s = format (s, "%28U%U\n", format_vlib_node_name, vm, i,
		      b->format_node ? b->format_node :
		      format_perfmon_node_generic, b, nc);
	}

      if (vec_len (s))
        vlib_cli_output (vm, "Thread: %u\n%v\n", t, s);

      vec_reset_length (s);
    }

  vlib_cli_output (vm, "%U\n", b->format_footer ? b->format_footer :
		   format_perfmon_footer_generic, b);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_perfmon_report_command, static) =
{
  .path = "show perfmon report",
  .short_help = "show perfmon report",
  .function = show_perfmon_report_command_fn,
};

static clib_error_t *
set_perfmon_bundle_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_bundle_t *b = 0;

  if (unformat_user (input, unformat_line_input, line_input) == 0)
    return clib_error_return (0, "please specify bundle name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_perfmon_bundle_name, &b))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (b == 0)
    return clib_error_return (0, "please specify bundle name");

  if (pm->is_running)
    return clib_error_return (0, "please stop first");

  pm->active_bundle = b;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_perfmon_bundle_command, static) =
{
  .path = "set perfmon bundle",
  .short_help = "set perfmon bundle [<bundle-name>]",
  .function = set_perfmon_bundle_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
perfmon_start_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  return perfmon_start (vm);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (perfmon_start_command, static) =
{
  .path = "perfmon start",
  .short_help = "perfmon start",
  .function = perfmon_start_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
perfmon_stop_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  return perfmon_stop (vm);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (perfmon_stop_command, static) =
{
  .path = "perfmon stop",
  .short_help = "perfmon stop",
  .function = perfmon_stop_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
