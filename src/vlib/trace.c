/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * trace.c: VLIB trace buffer.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>

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
	  clib_memcpy (t0, b0->data + b0->current_data,
		       n_buffer_data_bytes_in_trace);
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, n_buffer_data_bytes_in_trace);
	  clib_memcpy (t1, b1->data + b1->current_data,
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
	  clib_memcpy (t0, b0->data + b0->current_data,
		       n_buffer_data_bytes_in_trace);
	}
      from += 1;
      n_left -= 1;
    }
}

/* Free up all trace buffer memory. */
always_inline void
clear_trace_buffer (void)
{
  int i;
  vlib_trace_main_t *tm;

  /* *INDENT-OFF* */
  foreach_vlib_main (
  ({
    void *mainheap;

    tm = &this_vlib_main->trace_main;
    mainheap = clib_mem_set_heap (this_vlib_main->heap_base);

    tm->trace_active_hint = 0;

    for (i = 0; i < vec_len (tm->trace_buffer_pool); i++)
      if (! pool_is_free_index (tm->trace_buffer_pool, i))
        vec_free (tm->trace_buffer_pool[i]);
    pool_free (tm->trace_buffer_pool);
    clib_mem_set_heap (mainheap);
  }));
  /* *INDENT-ON* */
}

static u8 *
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
	  t =
	    (h->time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
	  s =
	    format (s, "\n%U: %v", format_time_interval, "h:m:s:u", t,
		    node->name);
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (trace_cli_command,static) = {
  .path = "trace",
  .short_help = "Packet tracer commands",
};
/* *INDENT-ON* */

static int
trace_cmp (void *a1, void *a2)
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
  /* *INDENT-OFF* */
  pool_foreach (h, tm->trace_buffer_pool,
   ({
      accept = filter_accept(tm, h[0]);

      if ((n_accepted == tm->filter_count) || !accept)
          vec_add1 (traces_to_remove, h);
      else
          n_accepted++;
  }));
  /* *INDENT-ON* */

  /* remove all traces that we don't want to keep */
  for (index = 0; index < vec_len (traces_to_remove); index++)
    {
      trace_index = traces_to_remove[index] - tm->trace_buffer_pool;
      _vec_len (tm->trace_buffer_pool[trace_index]) = 0;
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

  /* *INDENT-OFF* */
  foreach_vlib_main (
  ({
    void *mainheap;

    fmt = "------------------- Start of thread %d %s -------------------\n";
    s = format (s, fmt, index, vlib_worker_threads[index].name);

    tm = &this_vlib_main->trace_main;

    mainheap = clib_mem_set_heap (this_vlib_main->heap_base);

    trace_apply_filter(this_vlib_main);

    traces = 0;
    pool_foreach (h, tm->trace_buffer_pool,
    ({
      vec_add1 (traces, h[0]);
    }));

    if (vec_len (traces) == 0)
      {
        clib_mem_set_heap (mainheap);
        s = format (s, "No packets in trace buffer\n");
        goto done;
      }

    /* Sort them by increasing time. */
    vec_sort_with_function (traces, trace_cmp);

    for (i = 0; i < vec_len (traces); i++)
      {
        if (i == max)
          {
            vlib_cli_output (vm, "Limiting display to %d packets."
                                 " To display more specify max.", max);
            goto done;
          }

        clib_mem_set_heap (mainheap);

        s = format (s, "Packet %d\n%U\n\n", i + 1,
                         format_vlib_trace, vm, traces[i]);

        mainheap = clib_mem_set_heap (this_vlib_main->heap_base);
      }

  done:
    vec_free (traces);
    clib_mem_set_heap (mainheap);

    index++;
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_trace_cli,static) = {
  .path = "show trace",
  .short_help = "Show trace buffer [max COUNT]",
  .function = cli_show_trace_buffer,
};
/* *INDENT-ON* */

static clib_error_t *
cli_add_trace_buffer (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_trace_main_t *tm;
  vlib_trace_node_t *tn;
  u32 node_index, add;
  u8 verbose = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %d",
		    unformat_vlib_node, vm, &node_index, &add))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else
	{
	  error = clib_error_create ("expected NODE COUNT, got `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* *INDENT-OFF* */
  foreach_vlib_main ((
    {
      void *oldheap;
      tm = &this_vlib_main->trace_main;
      tm->trace_active_hint = 1;
      tm->verbose = verbose;
      oldheap =
	clib_mem_set_heap (this_vlib_main->heap_base);
      vec_validate (tm->nodes, node_index);
      tn = tm->nodes + node_index;
      tn->limit += add; clib_mem_set_heap (oldheap);
    }));
  /* *INDENT-ON* */

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (add_trace_cli,static) = {
  .path = "trace add",
  .short_help = "Trace given number of packets",
  .function = cli_add_trace_buffer,
};
/* *INDENT-ON* */


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
static clib_error_t *
cli_filter_trace (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  u32 filter_node_index;
  u32 filter_flag;
  u32 filter_count;
  void *mainheap;

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

  /* *INDENT-OFF* */
  foreach_vlib_main (
    ({
    tm = &this_vlib_main->trace_main;
    tm->filter_node_index = filter_node_index;
    tm->filter_flag = filter_flag;
    tm->filter_count = filter_count;

    /*
     * Clear the trace limits to stop any in-progress tracing
     * Prevents runaway trace allocations when the filter changes (or is removed)
     */
    mainheap = clib_mem_set_heap (this_vlib_main->heap_base);
    vec_free (tm->nodes);
    clib_mem_set_heap (mainheap);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_trace_cli,static) = {
  .path = "trace filter",
  .short_help = "filter trace output - include NODE COUNT | exclude NODE COUNT | none",
  .function = cli_filter_trace,
};
/* *INDENT-ON* */

static clib_error_t *
cli_clear_trace_buffer (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clear_trace_buffer ();
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_trace_cli,static) = {
  .path = "clear trace",
  .short_help = "Clear trace buffer and free memory",
  .function = cli_clear_trace_buffer,
};
/* *INDENT-ON* */

/* Dummy function to get us linked in. */
void
vlib_trace_cli_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
