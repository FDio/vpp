/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* trace.c: VLIB trace buffer. */

#include <vlib/vlib.h>
#include <vlib/threads.h>

u8 *vnet_trace_placeholder;

vlib_trace_timestamp_format_t
vlib_trace_get_timestamp_format (void)
{
  return vlib_trace_filter_main.timestamp_format;
}

void
vlib_trace_set_timestamp_format (vlib_trace_timestamp_format_t fmt)
{
  vlib_trace_filter_main.timestamp_format = fmt;
}

/* Helper function for nodes which only trace buffer data. */
void
vlib_trace_frame_buffers_only (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       u32 * buffers,
			       uword n_buffers,
			       uword next_buffer_stride,
			       uword n_buffer_data_bytes_in_trace)
{
  u32 n_left, *from;

  n_left = n_buffers;
  from = buffers;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      u8 *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t0, b0->data + b0->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t1, b1->data + b1->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u8 *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t0, b0->data + b0->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      from += 1;
      n_left -= 1;
    }
}

/* Free up all trace buffer memory. */
void
clear_trace_buffer (void)
{
  int i;
  vlib_trace_main_t *tm;

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;

      tm->trace_enable = 0;
      vec_free (tm->nodes);
    }

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;

      for (i = 0; i < vec_len (tm->trace_buffer_pool); i++)
	if (!pool_is_free_index (tm->trace_buffer_pool, i))
	  vec_free (tm->trace_buffer_pool[i]);
      pool_free (tm->trace_buffer_pool);
    }
}

u8 *
format_vlib_trace (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_trace_header_t *h = va_arg (*va, vlib_trace_header_t *);
  vlib_trace_header_t *e = vec_end (h);
  vlib_node_t *node, *prev_node;
  clib_time_t *ct = &vm->clib_time;
  f64 t;

  prev_node = 0;
  while (h < e)
    {
      node = vlib_get_node (vm, h->node_index);

      if (node != prev_node)
	{
	  switch (vlib_trace_filter_main.timestamp_format)
	    {
	    case VLIB_TRACE_TIMESTAMP_UNIX:
	      t = ct->init_reference_time + (h->time - ct->init_cpu_time) * ct->seconds_per_clock;
	      s = format (s, "\n%.6f: %v", t, node->name);
	      break;
	    case VLIB_TRACE_TIMESTAMP_DATETIME:
	      {
		u32 usec;
		t = ct->init_reference_time + (h->time - ct->init_cpu_time) * ct->seconds_per_clock;
		usec = (u32) (1e6 * (t - (i64) t));
		s = format (s, "\n%U.%06d: %v", format_time_float, "y-m-dTH:M:S", t, usec,
			    node->name);
	      }
	      break;
	    case VLIB_TRACE_TIMESTAMP_RELATIVE:
	    default:
	      t = (h->time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
	      s = format (s, "\n%U: %v", format_time_interval, "h:m:s:u", t, node->name);
	      break;
	    }
	}
      prev_node = node;

      if (node->format_trace)
	s = format (s, "\n  %U", node->format_trace, vm, node, h->data);
      else
	s = format (s, "\n  %U", node->format_buffer, h->data);

      h = vlib_trace_header_next (h);
    }

  return s;
}

/* Root of all trace cli commands. */
VLIB_CLI_COMMAND (trace_cli_command,static) = {
  .path = "trace",
  .short_help = "Packet tracer commands",
};

int
trace_time_cmp (void *a1, void *a2)
{
  vlib_trace_header_t **t1 = a1;
  vlib_trace_header_t **t2 = a2;
  i64 dt = t1[0]->time - t2[0]->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

/*
 * Return 1 if this packet passes the trace filter, or 0 otherwise
 */
u32
filter_accept (vlib_trace_main_t * tm, vlib_trace_header_t * h)
{
  vlib_trace_header_t *e = vec_end (h);

  if (tm->filter_flag == 0)
    return 1;

  /*
   * When capturing a post-mortem dispatch trace,
   * toss all existing traces once per dispatch cycle.
   * So we can trace 4 billion pkts without running out of
   * memory...
   */
  if (tm->filter_flag == FILTER_FLAG_POST_MORTEM)
    return 0;

  if (tm->filter_flag == FILTER_FLAG_INCLUDE)
    {
      while (h < e)
	{
	  if (h->node_index == tm->filter_node_index)
	    return 1;
	  h = vlib_trace_header_next (h);
	}
      return 0;
    }
  else				/* FILTER_FLAG_EXCLUDE */
    {
      while (h < e)
	{
	  if (h->node_index == tm->filter_node_index)
	    return 0;
	  h = vlib_trace_header_next (h);
	}
      return 1;
    }

  return 0;
}

/*
 * Remove traces from the trace buffer pool that don't pass the filter
 */
void
trace_apply_filter (vlib_main_t * vm)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  vlib_trace_header_t ***traces_to_remove = 0;
  u32 index;
  u32 trace_index;
  u32 n_accepted;

  u32 accept;

  if (tm->filter_flag == FILTER_FLAG_NONE)
    return;

  /*
   * Ideally we would retain the first N traces that pass the filter instead
   * of any N traces.
   */
  n_accepted = 0;
  pool_foreach (h, tm->trace_buffer_pool)
    {
      accept = filter_accept(tm, h[0]);

      if ((n_accepted == tm->filter_count) || !accept)
          vec_add1 (traces_to_remove, h);
      else
          n_accepted++;
  }

  /* remove all traces that we don't want to keep */
  for (index = 0; index < vec_len (traces_to_remove); index++)
    {
      trace_index = traces_to_remove[index] - tm->trace_buffer_pool;
      vec_set_len (tm->trace_buffer_pool[trace_index], 0);
      pool_put_index (tm->trace_buffer_pool, trace_index);
    }

  vec_free (traces_to_remove);
}

static clib_error_t *
cli_show_trace_buffer (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_main_t *tm;
  vlib_trace_header_t **h, **traces;
  u32 i, index = 0;
  char *fmt;
  u8 *s = 0;
  u32 max;

  /*
   * By default display only this many traces. To display more, explicitly
   * specify a max. This prevents unexpectedly huge outputs.
   */
  max = 50;
  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max %d", &max))
	;
      else
	return clib_error_create ("expected 'max COUNT', got `%U'",
				  format_unformat_error, input);
    }


  /* Get active traces from pool. */

  foreach_vlib_main ()
    {
      fmt = "------------------- Start of thread %d %s -------------------\n";
      s = format (s, fmt, index, vlib_worker_threads[index].name);

      tm = &this_vlib_main->trace_main;

      trace_apply_filter (this_vlib_main);

      traces = 0;
      pool_foreach (h, tm->trace_buffer_pool)
	{
	  vec_add1 (traces, h[0]);
	}

      if (vec_len (traces) == 0)
	{
	  s = format (s, "No packets in trace buffer\n");
	  goto done;
	}

      /* Sort them by increasing time. */
      vec_sort_with_function (traces, trace_time_cmp);

      for (i = 0; i < vec_len (traces); i++)
	{
	  if (i == max)
	    {
	      char *warn = "Limiting display to %d packets."
			   " To display more specify max.";
	      vlib_cli_output (vm, warn, max);
	      s = format (s, warn, max);
	      goto done;
	    }

	  s = format (s, "Packet %d\n%U\n\n", i + 1, format_vlib_trace, vm,
		      traces[i]);
	}

    done:
      vec_free (traces);

      index++;
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (show_trace_cli,static) = {
  .path = "show trace",
  .short_help = "Show trace buffer [max COUNT]",
  .function = cli_show_trace_buffer,
};

int vlib_enable_disable_pkt_trace_filter (int enable) __attribute__ ((weak));

int
vlib_enable_disable_pkt_trace_filter (int enable)
{
  return 0;
}

void
vlib_trace_stop_and_clear (void)
{
  vlib_enable_disable_pkt_trace_filter (0);	/* disble tracing */
  clear_trace_buffer ();
}


void
trace_update_capture_options (u32 add, u32 node_index, u32 filter, u8 verbose)
{
  vlib_trace_main_t *tm;
  vlib_trace_node_t *tn;

  if (add == ~0)
    add = 50;

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;
      tm->verbose = verbose;
      vec_validate (tm->nodes, node_index);
      tn = tm->nodes + node_index;

      /*
       * Adding 0 makes no real sense, and there wa no other way
       * to explicilty zero-out the limits and count, so make
       * an "add 0" request really be "set to 0".
       */
      if (add == 0)
	  tn->limit = tn->count = 0;
      else
	  tn->limit += add;
    }

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;
      tm->trace_enable = 1;
    }

  vlib_enable_disable_pkt_trace_filter (! !filter);
}

static clib_error_t *
cli_add_trace_buffer (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_node_t *node;
  u32 node_index, add;
  u8 verbose = 0;
  int filter = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (vnet_trace_placeholder == 0)
    vec_validate_aligned (vnet_trace_placeholder, 2048,
			  CLIB_CACHE_LINE_BYTES);

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %d",
		    unformat_vlib_node, vm, &node_index, &add))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "filter"))
	filter = 1;
      else
	{
	  error = clib_error_create ("expected NODE COUNT, got `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  node = vlib_get_node (vm, node_index);

  if ((node->flags & VLIB_NODE_FLAG_TRACE_SUPPORTED) == 0)
    {
      error = clib_error_create ("node '%U' doesn't support per-node "
				 "tracing. There may be another way to "
				 "initiate trace on this node.",
				 format_vlib_node_name, vm, node_index);
      goto done;
    }

  trace_update_capture_options (add, node_index, filter, verbose);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (add_trace_cli,static) = {
  .path = "trace add",
  .short_help = "trace add <input-graph-node> <add'l-pkts-for-node-> [filter] [verbose]",
  .function = cli_add_trace_buffer,
};

/*
 * Configure a filter for packet traces.
 *
 * This supplements the packet trace feature so that only packets matching
 * the filter are included in the trace. Currently the only filter is to
 * keep packets that include a certain node in the trace or exclude a certain
 * node in the trace.
 *
 * The count of traced packets in the "trace add" command is still used to
 * create a certain number of traces. The "trace filter" command specifies
 * how many of those packets should be retained in the trace.
 *
 * For example, 1Mpps of traffic is arriving and one of those packets is being
 * dropped. To capture the trace for only that dropped packet, you can do:
 *     trace filter include error-drop 1
 *     trace add dpdk-input 1000000
 *     <wait one second>
 *     show trace
 *
 * Note that the filter could be implemented by capturing all traces and just
 * reducing traces displayed by the "show trace" function. But that would
 * require a lot of memory for storing the traces, making that infeasible.
 *
 * To remove traces from the trace pool that do not include a certain node
 * requires that the trace be "complete" before applying the filter. To
 * accomplish this, the trace pool is filtered upon each iteraction of the
 * main vlib loop. Doing so keeps the number of allocated traces down to a
 * reasonably low number. This requires that tracing for a buffer is not
 * performed after the vlib main loop interation completes. i.e. you can't
 * save away a buffer temporarily then inject it back into the graph and
 * expect that the trace_index is still valid (such as a traffic manager might
 * do). A new trace buffer should be allocated for those types of packets.
 *
 * The filter can be extended to support multiple nodes and other match
 * criteria (e.g. input sw_if_index, mac address) but for now just checks if
 * a specified node is in the trace or not in the trace.
 */

void
trace_filter_set (u32 node_index, u32 flag, u32 count)
{
  foreach_vlib_main ()
    {
      vlib_trace_main_t *tm;

      tm = &this_vlib_main->trace_main;
      tm->filter_node_index = node_index;
      tm->filter_flag = flag;
      tm->filter_count = count;

      /*
       * Clear the trace limits to stop any in-progress tracing
       * Prevents runaway trace allocations when the filter changes
       * (or is removed)
       */
      vec_free (tm->nodes);
    }
}


static clib_error_t *
cli_filter_trace (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 filter_node_index;
  u32 filter_flag;
  u32 filter_count;

  if (unformat (input, "include %U %d",
		unformat_vlib_node, vm, &filter_node_index, &filter_count))
    {
      filter_flag = FILTER_FLAG_INCLUDE;
    }
  else if (unformat (input, "exclude %U %d",
		     unformat_vlib_node, vm, &filter_node_index,
		     &filter_count))
    {
      filter_flag = FILTER_FLAG_EXCLUDE;
    }
  else if (unformat (input, "none"))
    {
      filter_flag = FILTER_FLAG_NONE;
      filter_node_index = 0;
      filter_count = 0;
    }
  else
    return
      clib_error_create
      ("expected 'include NODE COUNT' or 'exclude NODE COUNT' or 'none', got `%U'",
       format_unformat_error, input);

  trace_filter_set (filter_node_index, filter_flag, filter_count);

  return 0;
}

VLIB_CLI_COMMAND (filter_trace_cli,static) = {
  .path = "trace filter",
  .short_help = "trace filter none | [include|exclude] NODE COUNT",
  .function = cli_filter_trace,
};

static clib_error_t *
cli_clear_trace_buffer (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_stop_and_clear ();
  return 0;
}

VLIB_CLI_COMMAND (clear_trace_cli,static) = {
  .path = "clear trace",
  .short_help = "Clear trace buffer and free memory",
  .function = cli_clear_trace_buffer,
};

/* Placeholder function to get us linked in. */
void
vlib_trace_cli_reference (void)
{
}

void *
vlib_add_trace (vlib_main_t * vm,
		vlib_node_runtime_t * r, vlib_buffer_t * b, u32 n_data_bytes)
{
  return vlib_add_trace_inline (vm, r, b, n_data_bytes);
}

vlib_is_packet_traced_fn_t *
vlib_is_packet_traced_function_from_name (const char *name)
{
  vlib_trace_filter_function_registration_t *reg =
    vlib_trace_filter_main.trace_filter_registration;
  while (reg)
    {
      if (clib_strcmp (reg->name, name) == 0)
	break;
      reg = reg->next;
    }
  if (!reg)
    return 0;
  return reg->function;
}

vlib_is_packet_traced_fn_t *
vlib_is_packet_traced_default_function ()
{
  vlib_trace_filter_function_registration_t *reg =
    vlib_trace_filter_main.trace_filter_registration;
  vlib_trace_filter_function_registration_t *tmp_reg = reg;
  while (reg)
    {
      if (reg->priority > tmp_reg->priority)
	tmp_reg = reg;
      reg = reg->next;
    }
  return tmp_reg->function;
}

static clib_error_t *
vlib_trace_filter_function_init (vlib_main_t *vm)
{
  vlib_is_packet_traced_fn_t *default_fn =
    vlib_is_packet_traced_default_function ();
  foreach_vlib_main ()
    {
      vlib_trace_main_t *tm = &this_vlib_main->trace_main;
      tm->current_trace_filter_function = default_fn;
    }
  return 0;
}

vlib_trace_filter_main_t vlib_trace_filter_main;

VLIB_INIT_FUNCTION (vlib_trace_filter_function_init);

static clib_error_t *
show_trace_filter_function (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_is_packet_traced_fn_t *current_trace_filter_fn =
    tm->current_trace_filter_function;
  vlib_trace_filter_function_registration_t *reg =
    tfm->trace_filter_registration;

  while (reg)
    {
      vlib_cli_output (vm, "%sname:%s description: %s priority: %u",
		       reg->function == current_trace_filter_fn ? "(*) " : "",
		       reg->name, reg->description, reg->priority);
      reg = reg->next;
    }
  return 0;
}

VLIB_CLI_COMMAND (show_trace_filter_function_cli, static) = {
  .path = "show trace filter function",
  .short_help = "show trace filter function",
  .function = show_trace_filter_function,
};

uword
unformat_vlib_trace_filter_function (unformat_input_t *input, va_list *args)
{
  vlib_is_packet_traced_fn_t **res =
    va_arg (*args, vlib_is_packet_traced_fn_t **);
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;

  vlib_trace_filter_function_registration_t *reg =
    tfm->trace_filter_registration;
  while (reg)
    {
      if (unformat (input, reg->name))
	{
	  *res = reg->function;
	  return 1;
	}
      reg = reg->next;
    }
  return 0;
}

void
vlib_set_trace_filter_function (vlib_is_packet_traced_fn_t *x)
{
  foreach_vlib_main ()
    {
      this_vlib_main->trace_main.current_trace_filter_function = x;
    }
}

static clib_error_t *
set_trace_filter_function (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_is_packet_traced_fn_t *res = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_trace_filter_function,
		    &res))
	;
      else
	{
	  error = clib_error_create (
	    "expected valid trace filter function, got `%U'",
	    format_unformat_error, line_input);
	  goto done;
	}
    }
  vlib_set_trace_filter_function (res);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (set_trace_filter_function_cli, static) = {
  .path = "set trace filter function",
  .short_help = "set trace filter function <func_name>",
  .function = set_trace_filter_function,
};

static clib_error_t *
set_trace_timestamp_format_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_create ("expected timestamp format");

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "relative"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_RELATIVE;
      else if (unformat (line_input, "unix"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_UNIX;
      else if (unformat (line_input, "datetime"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_DATETIME;
      else
	{
	  error = clib_error_create ("expected 'relative', 'unix', or 'datetime', got `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (set_trace_timestamp_format_cli_cmd, static) = {
  .path = "set trace timestamp-format",
  .short_help = "set trace timestamp-format <relative|unix|datetime>",
  .function = set_trace_timestamp_format_cli,
};

static clib_error_t *
show_trace_timestamp_format_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  char *fmt_str;
  switch (vlib_trace_filter_main.timestamp_format)
    {
    case VLIB_TRACE_TIMESTAMP_UNIX:
      fmt_str = "unix";
      break;
    case VLIB_TRACE_TIMESTAMP_DATETIME:
      fmt_str = "datetime";
      break;
    case VLIB_TRACE_TIMESTAMP_RELATIVE:
    default:
      fmt_str = "relative";
      break;
    }
  vlib_cli_output (vm, "trace timestamp format: %s", fmt_str);
  return 0;
}

VLIB_CLI_COMMAND (show_trace_timestamp_format_cli_cmd, static) = {
  .path = "show trace timestamp-format",
  .short_help = "show trace timestamp-format",
  .function = show_trace_timestamp_format_cli,
};

/*
 * Startup configuration for trace settings.
 *
 * trace {
 *   timestamp-format <relative|unix|datetime>
 * }
 */
static clib_error_t *
trace_config (vlib_main_t *vm, unformat_input_t *input)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "timestamp-format relative"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_RELATIVE;
      else if (unformat (input, "timestamp-format unix"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_UNIX;
      else if (unformat (input, "timestamp-format datetime"))
	vlib_trace_filter_main.timestamp_format = VLIB_TRACE_TIMESTAMP_DATETIME;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (trace_config, "trace");
