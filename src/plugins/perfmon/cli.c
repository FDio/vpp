/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <perfmon/perfmon.h>
#include <vppinfra/format_table.h>

/* the value of the name types is the pointer to the bundle or source */
static u8 *
parse_perfmon_name (uword *by_name, char *what, u8 *tok, cli_value_t *v)
{
  u8 *name = format (0, "%v%c", tok, 0);
  uword *p = hash_get_mem (by_name, name);

  vec_free (name);

  if (p == 0)
    return format (0, "unknown %s '%v'", what, tok);

  v->u64 = p[0];

  return 0;
}

static u8 *
parse_perfmon_bundle (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_perfmon_name (perfmon_main.bundle_by_name, "bundle", tok, v);
}

static void
complete_perfmon_bundle (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  perfmon_bundle_t *b;
  char *name;

  hash_foreach_mem (name, b, perfmon_main.bundle_by_name, {
    if (cli_prefix_match (name, prefix))
      cli_candidate_add (out, name, b->description);
  });
}

CLIB_CLI_TYPE (cli_type_perfmon_bundle, static) = {
  .name = "bundle-name",
  .help = "perfmon bundle",
  .parse = parse_perfmon_bundle,
  .complete = complete_perfmon_bundle,
};

static u8 *
parse_perfmon_source (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_perfmon_name (perfmon_main.source_by_name, "source", tok, v);
}

static void
complete_perfmon_source (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  perfmon_source_t *src;
  char *name;

  hash_foreach_mem (name, src, perfmon_main.source_by_name, {
    if (cli_prefix_match (name, prefix))
      cli_candidate_add (out, name, src->description);
  });
}

CLIB_CLI_TYPE (cli_type_perfmon_source, static) = {
  .name = "source-name",
  .help = "perfmon source",
  .parse = parse_perfmon_source,
  .complete = complete_perfmon_source,
};

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
show_perfmon_bundle_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = 0, **vb = 0;
  int verbose = cli_flag (ctx, "verbose");
  format_perfmon_bundle_args_t cfg = FORMAT_PERFMON_BUNDLE_NONE;
  cli_value_t *v;

  cli_foreach (v, ctx, "bundle-name")
  {
    b = uword_to_pointer (v->u64, perfmon_bundle_t *);
    vec_add1 (vb, b);
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
  .short_help = "Show the perfmon bundles",
  .args = CLI_ARGS (CLI_VALUE ("bundle-name", cli_type_perfmon_bundle,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("verbose", .help = "show the event configuration")),
  .handler = show_perfmon_bundle_command_fn,
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
show_perfmon_source_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t *s = 0, **vs = 0;
  int verbose = cli_flag (ctx, "verbose");
  cli_value_t *v;

  cli_foreach (v, ctx, "source-name")
  {
    s = uword_to_pointer (v->u64, perfmon_source_t *);
    vec_add1 (vs, s);
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
  .short_help = "Show the perfmon event sources",
  .args = CLI_ARGS (CLI_VALUE ("source-name", cli_type_perfmon_source,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("verbose", .help = "show the events")),
  .handler = show_perfmon_source_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_perfmon_active_bundle_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  perfmon_main_t *pm = &perfmon_main;

  vlib_cli_output (vm, "%U\n", format_perfmon_bundle, pm->active_bundle, 1);
  return 0;
}

VLIB_CLI_COMMAND (show_perfmon_active_bundle_command, static) = {
  .path = "show perfmon active-bundle",
  .short_help = "Show the active perfmon bundle",
  .handler = show_perfmon_active_bundle_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_perfmon_stats_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
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

  table_add_hdr_row (t, 0);
  table_add_hdr_col (t, 0);

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

		if (PREDICT_TRUE (clib_bitmap_is_zero (b->event_disabled)))
		  clib_memcpy_fast (&ns, tr->node_stats + j, sizeof (ns));
		/* if some events are not implemented, we need to realign these
		   to display under the correct column headers */
		else
		  {
		    perfmon_node_stats_t *tr_ns = tr->node_stats + j;
		    ns.n_calls = tr_ns->n_calls;
		    ns.n_packets = tr_ns->n_packets;
		    /* loop through all events in bundle + manually copy into
		       the correct place, until we've read all values that are
		       implemented */
		    int num_enabled_events =
		      b->n_events -
		      clib_bitmap_count_set_bits (b->event_disabled);
		    for (int i = 0, k = 0; k < num_enabled_events; i++)
		      {
			if (!clib_bitmap_get (b->event_disabled, i))
			  {
			    ns.value[i] = tr_ns->value[k];
			    k++;
			  }
		      }
		  }

		for (int j = 0; j < n_row; j++)
		  {
		    if (clib_bitmap_get (b->column_disabled, j))
		      table_format_cell (t, col, j, "-");
		    else
		      table_format_cell (t, col, j, "%U", b->format_fn, &ns, j,
					 b->active_type);
		  }
	      }
	}
      else /* b->type != PERFMON_BUNDLE_TYPE_NODE */
	{
	  if (PREDICT_TRUE (clib_bitmap_is_zero (b->event_disabled)))
	    {
	      for (int j = 0; j < n_row; j++)
		table_format_cell (t, i, j, "%U", b->format_fn, r, j,
				   b->active_type);
	    }
	  /* similarly for THREAD/SYSTEM bundles, if some events are not
	     implemented, we need to realign readings under column headings */
	  else
	    {
	      perfmon_reading_t aligned_r[b->n_events];
	      aligned_r->nr = r->nr;
	      aligned_r->time_enabled = r->time_enabled;
	      aligned_r->time_running = r->time_running;
	      int num_enabled_events =
		b->n_events - clib_bitmap_count_set_bits (b->event_disabled);
	      for (int i = 0, k = 0; k < num_enabled_events; i++)
		{
		  if (!clib_bitmap_get (b->event_disabled, i))
		    {
		      aligned_r->value[i] = r->value[k];
		      k++;
		    }
		}
	      for (int j = 0; j < n_row; j++)
		{
		  if (clib_bitmap_get (b->column_disabled, j))
		    table_format_cell (t, col, j, "-");
		  else
		    table_format_cell (t, i, j, "%U", b->format_fn, aligned_r,
				       j, b->active_type);
		}
	    }
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
  .short_help = "Show the perfmon statistics",
  /* "raw" was accepted and ignored, scripts may still give it */
  .args = CLI_ARGS (CLI_FLAG ("raw", .flags = CLI_F_HIDDEN)),
  .handler = show_perfmon_stats_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
perfmon_reset_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  perfmon_reset (vm);
  return 0;
}

VLIB_CLI_COMMAND (perfmon_reset_command, static) = {
  .path = "perfmon reset",
  .short_help = "Reset the perfmon statistics",
  .handler = perfmon_reset_command_fn,
  .is_mp_safe = 1,
};

static const cli_choice_t perfmon_type_choices[] = {
  { "node", "per graph node", PERFMON_BUNDLE_TYPE_NODE },
  { "thread", "per thread", PERFMON_BUNDLE_TYPE_THREAD },
  { "system", "for the whole system", PERFMON_BUNDLE_TYPE_SYSTEM },
  {},
};

static clib_error_t *
perfmon_start_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = uword_to_pointer (cli_get (ctx, "bundle")->u64, perfmon_bundle_t *);
  perfmon_bundle_type_t bundle_type = PERFMON_BUNDLE_TYPE_UNKNOWN;
  cli_value_t *v = cli_get (ctx, "type");

  if (pm->is_running)
    return clib_error_return (0, "please stop first");

  /* a type the bundle does not have counts as not given */
  if (v && (b->type_flags & 1 << v->index))
    bundle_type = v->index;

  /* if there is more than one valid mode */
  if (count_set_bits (b->type_flags) > 1)
    {
      /* what did the user indicate */
      if (!bundle_type)
	return clib_error_return (0, "please specify a valid type");
    }
  /* otherwise just use the default  */
  else if (!bundle_type)
    {
      bundle_type =
	(perfmon_bundle_type_t) count_trailing_zeros (b->type_flags);
    }

  b->active_type = bundle_type;

  return perfmon_start (vm, b);
}

VLIB_CLI_COMMAND (perfmon_start_command, static) = {
  .path = "perfmon start",
  .short_help = "Start collecting the events of a perfmon bundle",
  .args = CLI_ARGS (CLI_KEYWORD ("bundle", cli_type_perfmon_bundle),
		    CLI_OPT_KEYWORD ("type", cli_type_enum, .choices = perfmon_type_choices,
				     .help = "needed if the bundle has more than one type")),
  .handler = perfmon_start_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
perfmon_stop_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return perfmon_stop (vm);
}

VLIB_CLI_COMMAND (perfmon_stop_command, static) = {
  .path = "perfmon stop",
  .short_help = "Stop collecting perfmon events",
  .handler = perfmon_stop_command_fn,
  .is_mp_safe = 1,
};
