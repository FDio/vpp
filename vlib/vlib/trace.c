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
  u32 n_left, * from;

  n_left = n_buffers;
  from = buffers;
  
  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t * b0, * b1;
      u8 * t0, * t1;

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
	  memcpy (t0, b0->data + b0->current_data,
		  n_buffer_data_bytes_in_trace);
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, n_buffer_data_bytes_in_trace);
	  memcpy (t1, b1->data + b1->current_data,
		  n_buffer_data_bytes_in_trace);
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      u8 * t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, n_buffer_data_bytes_in_trace);
	  memcpy (t0, b0->data + b0->current_data,
		  n_buffer_data_bytes_in_trace);
	}
      from += 1;
      n_left -= 1;
    }
}

/* Free up all trace buffer memory. */
always_inline void
clear_trace_buffer (vlib_trace_main_t * tm)
{
  int i;

  foreach_vlib_main (
  ({
    void *mainheap;

    tm = &this_vlib_main->trace_main;
    mainheap = clib_mem_set_heap (this_vlib_main->heap_base);

    for (i = 0; i < vec_len (tm->trace_buffer_pool); i++)
      if (! pool_is_free_index (tm->trace_buffer_pool, i))
        vec_free (tm->trace_buffer_pool[i]);
    pool_free (tm->trace_buffer_pool);
    clib_mem_set_heap (mainheap);
  }));
}

static u8 * format_vlib_trace (u8 * s, va_list * va)
{
  vlib_main_t * vm = va_arg (*va, vlib_main_t *);
  vlib_trace_header_t * h = va_arg (*va, vlib_trace_header_t *);
  vlib_trace_header_t * e = vec_end (h);
  vlib_node_t * node, * prev_node;
  clib_time_t * ct = &vm->clib_time;
  f64 t;
  
  prev_node = 0;
  while (h < e)
    {
      node = vlib_get_node (vm, h->node_index);

      if (node != prev_node)
	{
	  t = (h->time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
	  s = format (s, "\n%U: %v",
		      format_time_interval, "h:m:s:u", t,
		      node->name);
	}
      prev_node = node;

      if (node->format_trace)
	s = format (s, "\n  %U",
		    node->format_trace, vm, node, h->data);
      else
	s = format (s, "\n  %U",
		    node->format_buffer, h->data);

      h = vlib_trace_header_next (h);
    }

  return s;
}

/* Root of all trace cli commands. */
VLIB_CLI_COMMAND (trace_cli_command,static) = {
  .path = "trace",
  .short_help = "Packet tracer commands",
};

static int
trace_cmp (void * a1, void * a2)
{
  vlib_trace_header_t ** t1 = a1;
  vlib_trace_header_t ** t2 = a2;
  i64 dt = t1[0]->time - t2[0]->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

static clib_error_t *
cli_show_trace_buffer (vlib_main_t * vm,
		       unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  vlib_trace_main_t * tm = &vm->trace_main;
  vlib_trace_header_t ** h, ** traces;
  u32 i, index = 0;
  char * fmt;
  u8 * s = 0;

  /* Get active traces from pool. */

  foreach_vlib_main (
  ({
    void *mainheap;

    fmt = "------------------- Start of thread %d %s -------------------\n";
    s = format (s, fmt, index, vlib_worker_threads[index].name);

    tm = &this_vlib_main->trace_main;

    mainheap = clib_mem_set_heap (this_vlib_main->heap_base);
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

  vlib_cli_output (vm, (char *) s);
  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (show_trace_cli,static) = {
  .path = "show trace",
  .short_help = "Show trace buffer",
  .function = cli_show_trace_buffer,
};

static clib_error_t *
cli_add_trace_buffer (vlib_main_t * vm,
		      unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  vlib_trace_main_t * tm;
  vlib_trace_node_t * tn;
  u32 node_index, add;

  if (unformat (input, "%U %d", unformat_vlib_node, vm, &node_index, &add))
    ;
  else
    return clib_error_create ("expected NODE COUNT, got `%U'",
                              format_unformat_error, input);

  foreach_vlib_main (
  ({
    void *oldheap;
    tm = &this_vlib_main->trace_main;

    oldheap = clib_mem_set_heap (this_vlib_main->heap_base);

    vec_validate (tm->nodes, node_index);
    tn = tm->nodes + node_index;
    tn->limit += add;
    clib_mem_set_heap (oldheap);
  }));

  return 0;
}

VLIB_CLI_COMMAND (add_trace_cli,static) = {
  .path = "trace add",
  .short_help = "Trace given number of packets",
  .function = cli_add_trace_buffer,
};

static clib_error_t *
cli_clear_trace_buffer (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  vlib_trace_main_t * tm = &vm->trace_main;
  clear_trace_buffer (tm);
  return 0;
}

VLIB_CLI_COMMAND (clear_trace_cli,static) = {
  .path = "clear trace",
  .short_help = "Clear trace buffer and free memory",
  .function = cli_clear_trace_buffer,
};

/* Dummy function to get us linked in. */
void vlib_trace_cli_reference (void) {}
