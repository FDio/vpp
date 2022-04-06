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
 * error.c: VLIB error handler
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
#include <vppinfra/heap.h>
#include <vlib/stats/stats.h>

uword
vlib_error_drop_buffers (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 u32 * buffers,
			 u32 next_buffer_stride,
			 u32 n_buffers,
			 u32 next_index,
			 u32 drop_error_node, u32 drop_error_code)
{
  u32 n_left_this_frame, n_buffers_left, *args, n_args_left;
  vlib_error_t drop_error;
  vlib_node_t *n;

  n = vlib_get_node (vm, drop_error_node);
  drop_error = n->error_heap_index + drop_error_code;

  n_buffers_left = n_buffers;
  while (n_buffers_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, args, n_args_left);

      n_left_this_frame = clib_min (n_buffers_left, n_args_left);
      n_buffers_left -= n_left_this_frame;
      n_args_left -= n_left_this_frame;

      while (n_left_this_frame >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;

	  args[0] = bi0 = buffers[0];
	  args[1] = bi1 = buffers[1];
	  args[2] = bi2 = buffers[2];
	  args[3] = bi3 = buffers[3];

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  b0->error = drop_error;
	  b1->error = drop_error;
	  b2->error = drop_error;
	  b3->error = drop_error;

	  buffers += 4;
	  args += 4;
	  n_left_this_frame -= 4;
	}

      while (n_left_this_frame >= 1)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  args[0] = bi0 = buffers[0];

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->error = drop_error;

	  buffers += 1;
	  args += 1;
	  n_left_this_frame -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_args_left);
    }

  return n_buffers;
}

static u8 *
format_stats_counter_name (u8 *s, va_list *va)
{
  u8 *id = va_arg (*va, u8 *);

  for (u32 i = 0; id[i] != 0; i++)
    vec_add1 (s, id[i] == ' ' ? ' ' : id[i]);

  return s;
}

void
vlib_unregister_errors (vlib_main_t *vm, u32 node_index)
{
  vlib_error_main_t *em = &vm->error_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_desc_t *cd;

  if (n->n_errors > 0)
    {
      cd = vec_elt_at_index (em->counters_heap, n->error_heap_index);
      for (u32 i = 0; i < n->n_errors; i++)
	vlib_stats_remove_entry (cd[i].stats_entry_index);
      heap_dealloc (em->counters_heap, n->error_heap_handle);
      n->n_errors = 0;
    }
}

/* Reserves given number of error codes for given node. */
void
vlib_register_errors (vlib_main_t *vm, u32 node_index, u32 n_errors,
		      char *error_strings[], vlib_error_desc_t counters[])
{
  vlib_error_main_t *em = &vm->error_main;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_desc_t *cd;
  u32 n_threads = vlib_get_n_threads ();
  elog_event_type_t t = {};
  uword l;
  u64 **sc;

  ASSERT (vlib_get_thread_index () == 0);

  vlib_stats_segment_lock ();

  /* Free up any previous error strings. */
  vlib_unregister_errors (vm, node_index);

  n->n_errors = n_errors;
  n->error_counters = counters;

  if (n_errors == 0)
    goto done;

  n->error_heap_index =
    heap_alloc (em->counters_heap, n_errors, n->error_heap_handle);
  l = vec_len (em->counters_heap);
  cd = vec_elt_at_index (em->counters_heap, n->error_heap_index);

  /*  Legacy node */
  if (!counters)
    {
      for (int i = 0; i < n_errors; i++)
	{
	  cd[i].name = error_strings[i];
	  cd[i].desc = error_strings[i];
	  cd[i].severity = VL_COUNTER_SEVERITY_ERROR;
	}
    }
  else
    clib_memcpy (cd, counters, n_errors * sizeof (counters[0]));

  vec_validate (vm->error_elog_event_types, l - 1);

  if (em->stats_err_entry_index == 0)
    em->stats_err_entry_index = vlib_stats_add_counter_vector ("/node/errors");

  ASSERT (em->stats_err_entry_index != 0 && em->stats_err_entry_index != ~0);

  vlib_stats_validate (em->stats_err_entry_index, n_threads - 1, l - 1);
  sc = vlib_stats_get_entry_data_pointer (em->stats_err_entry_index);

  for (int i = 0; i < n_threads; i++)
    {
      vlib_main_t *tvm = vlib_get_main_by_index (i);
      vlib_error_main_t *tem = &tvm->error_main;
      tem->counters = sc[i];

      /* Zero counters for re-registrations of errors. */
      if (n->error_heap_index + n_errors <= vec_len (tem->counters_last_clear))
	clib_memcpy (tem->counters + n->error_heap_index,
		     tem->counters_last_clear + n->error_heap_index,
		     n_errors * sizeof (tem->counters[0]));
      else
	clib_memset (tem->counters + n->error_heap_index, 0,
		     n_errors * sizeof (tem->counters[0]));
    }

  /* Register counter indices in the stat segment directory */
  for (int i = 0; i < n_errors; i++)
    cd[i].stats_entry_index = vlib_stats_add_symlink (
      em->stats_err_entry_index, n->error_heap_index + i, "/err/%v/%U",
      n->name, format_stats_counter_name, cd[i].name);

  vec_validate (nm->node_by_error, n->error_heap_index + n_errors - 1);

  for (u32 i = 0; i < n_errors; i++)
    {
      t.format = (char *) format (0, "%v %s: %%d", n->name, cd[i].name);
      vm->error_elog_event_types[n->error_heap_index + i] = t;
      nm->node_by_error[n->error_heap_index + i] = n->index;
    }

done:
  vlib_stats_segment_unlock ();
}

uword
unformat_vlib_error (unformat_input_t *input, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  const vlib_error_main_t *em = &vm->error_main;
  vlib_error_t *error_index = va_arg (*args, vlib_error_t *);
  const vlib_node_t *node;
  char *error_name;
  u32 node_index;
  vlib_error_t i;

  if (!unformat (input, "%U.%s", unformat_vlib_node, vm, &node_index,
		 &error_name))
    return 0;

  node = vlib_get_node (vm, node_index);
  for (i = 0; i < node->n_errors; i++)
    {
      vlib_error_t ei = node->error_heap_index + i;
      if (strcmp (em->counters_heap[ei].name, error_name) == 0)
	{
	  *error_index = ei;
	  vec_free (error_name);
	  return 1;
	}
    }

  vec_free (error_name);
  return 0;
}

static char *
sev2str (enum vl_counter_severity_e s)
{
  switch (s)
    {
    case VL_COUNTER_SEVERITY_ERROR:
      return "error";
    case VL_COUNTER_SEVERITY_WARN:
      return "warn";
    case VL_COUNTER_SEVERITY_INFO:
      return "info";
    default:
      return "unknown";
    }
}

static clib_error_t *
show_errors (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_error_main_t *em = &vm->error_main;
  vlib_node_t *n;
  u32 code, i, ni;
  u64 c;
  int index = 0;
  int verbose = 0;
  u64 *sums = 0;

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

  vec_validate (sums, vec_len (em->counters));

  if (verbose)
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s%=6s", "Count", "Node",
		     "Reason", "Severity", "Index");
  else
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s", "Count", "Node", "Reason",
		     "Severity");

  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;

      if (verbose)
	vlib_cli_output (vm, "Thread %u (%v):", index,
			 vlib_worker_threads[index].name);

      for (ni = 0; ni < vec_len (this_vlib_main->node_main.nodes); ni++)
	{
	  n = vlib_get_node (this_vlib_main, ni);
	  for (code = 0; code < n->n_errors; code++)
	    {
	      i = n->error_heap_index + code;
	      c = em->counters[i];
	      if (i < vec_len (em->counters_last_clear))
		c -= em->counters_last_clear[i];
	      sums[i] += c;

	      if (c == 0 && verbose < 2)
		continue;

	      if (verbose)
		vlib_cli_output (vm, "%10lu%=35v%=35s%=10s%=6d", c, n->name,
				 em->counters_heap[i].desc,
				 sev2str (em->counters_heap[i].severity), i);
	      else
		vlib_cli_output (vm, "%10lu%=35v%=35s%=10s", c, n->name,
				 em->counters_heap[i].desc,
				 sev2str (em->counters_heap[i].severity));
	    }
	}
      index++;
    }

  if (verbose)
    vlib_cli_output (vm, "Total:");

  for (ni = 0; ni < vec_len (vm->node_main.nodes); ni++)
    {
      n = vlib_get_node (vm, ni);
      for (code = 0; code < n->n_errors; code++)
	{
	  i = n->error_heap_index + code;
	  if (sums[i])
	    {
	      if (verbose)
		vlib_cli_output (vm, "%10lu%=40v%=20s%=10d", sums[i], n->name,
				 em->counters_heap[i].desc, i);
	    }
	}
    }

  vec_free (sums);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_errors) = {
  .path = "show errors",
  .short_help = "Show error counts",
  .function = show_errors,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_node_counters, static) = {
  .path = "show node counters",
  .short_help = "Show node counters",
  .function = show_errors,
};
/* *INDENT-ON* */

static clib_error_t *
clear_error_counters (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_error_main_t *em;
  u32 i;

  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;
      vec_validate (em->counters_last_clear, vec_len (em->counters) - 1);
      for (i = 0; i < vec_len (em->counters); i++)
	em->counters_last_clear[i] = em->counters[i];
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_clear_error_counters, static) = {
  .path = "clear errors",
  .short_help = "Clear error counters",
  .function = clear_error_counters,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_clear_node_counters, static) = {
  .path = "clear node counters",
  .short_help = "Clear node counters",
  .function = clear_error_counters,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
