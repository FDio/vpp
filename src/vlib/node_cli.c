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
 * node_cli.c: node CLI
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>

static int
node_cmp (void *a1, void *a2)
{
  vlib_node_t **n1 = a1;
  vlib_node_t **n2 = a2;

  return vec_cmp (n1[0]->name, n2[0]->name);
}

static clib_error_t *
show_node_graph (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u32 node_index;

  vlib_cli_output (vm, "%U\n", format_vlib_node_graph, nm, 0);

  if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
    {
      n = vlib_get_node (vm, node_index);
      vlib_cli_output (vm, "%U\n", format_vlib_node_graph, nm, n);
    }
  else
    {
      vlib_node_t **nodes = vec_dup (nm->nodes);
      uword i;

      vec_sort_with_function (nodes, node_cmp);

      for (i = 0; i < vec_len (nodes); i++)
	vlib_cli_output (vm, "%U\n\n", format_vlib_node_graph, nm, nodes[i]);

      vec_free (nodes);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_node_graph_command, static) = {
  .path = "show vlib graph",
  .short_help = "Show packet processing node graph",
  .function = show_node_graph,
};
/* *INDENT-ON* */

static clib_error_t *
show_node_graphviz (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_node_main_t *nm = &vm->node_main;
  u8 *chroot_filename = 0;
  int fd;
  vlib_node_t **nodes = 0;
  uword i, j;

  if (!unformat_user (input, unformat_vlib_tmpfile, &chroot_filename))
    {
      fd = -1;
    }
  else
    {
      fd =
	open ((char *) chroot_filename, O_CREAT | O_TRUNC | O_WRONLY, 0664);
    }

#define format__(vm__, fd__, ...) \
  if ((fd) < 0) \
    { \
      vlib_cli_output((vm__), ## __VA_ARGS__); \
    } \
  else \
    { \
      fdformat((fd__), ## __VA_ARGS__); \
    }

  format__ (vm, fd, "%s", "digraph {\n");

  nodes = vec_dup (nm->nodes);
  vec_sort_with_function (nodes, node_cmp);

  for (i = 0; i < vec_len (nodes); i++)
    {
      for (j = 0; j < vec_len (nodes[i]->next_nodes); j++)
	{
	  vlib_node_t *x;

	  if (nodes[i]->next_nodes[j] == VLIB_INVALID_NODE_INDEX)
	    continue;

	  x = vec_elt (nm->nodes, nodes[i]->next_nodes[j]);
	  format__ (vm, fd, "  \"%v\" -> \"%v\"\n", nodes[i]->name, x->name);
	}
    }

  format__ (vm, fd, "%s", "}");

  if (fd >= 0)
    {
      vlib_cli_output (vm,
		       "vlib graph dumped into `%s'. Run eg. `fdp -Tsvg -O %s'.",
		       chroot_filename, chroot_filename);
    }

  vec_free (nodes);
  vec_free (chroot_filename);
  vec_free (nodes);
  if (fd >= 0)
    close (fd);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_node_graphviz_command, static) = {
  .path = "show vlib graphviz",
  .short_help = "Dump packet processing node graph as a graphviz dotfile",
  .function = show_node_graphviz,
};
/* *INDENT-ON* */

static u8 *
format_vlib_node_state (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_node_t *n = va_arg (*va, vlib_node_t *);
  char *state;

  state = "active";
  if (n->type == VLIB_NODE_TYPE_PROCESS)
    {
      vlib_process_t *p = vlib_get_process_from_node (vm, n);

      switch (p->flags & (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
			  | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT))
	{
	default:
	  if (!(p->flags & VLIB_PROCESS_IS_RUNNING))
	    state = "done";
	  break;

	case VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK:
	  state = "time wait";
	  break;

	case VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT:
	  state = "event wait";
	  break;

	case (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK):
	  state =
	    "any wait";
	  break;
	}
    }
  else if (n->type != VLIB_NODE_TYPE_INTERNAL)
    {
      state = "polling";
      if (n->state == VLIB_NODE_STATE_DISABLED)
	state = "disabled";
      else if (n->state == VLIB_NODE_STATE_INTERRUPT)
	state = "interrupt wait";
    }

  return format (s, "%s", state);
}

static u8 *
format_vlib_node_stats (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_node_t *n = va_arg (*va, vlib_node_t *);
  int max = va_arg (*va, int);
  f64 v;
  u8 *ns;
  u8 *misc_info = 0;
  u64 c, p, l, d;
  f64 x;
  f64 maxc, maxcn;
  u32 maxn;
  u32 indent;

  if (!n)
    {
      if (max)
	s = format (s,
		    "%=30s%=17s%=16s%=16s%=16s%=16s",
		    "Name", "Max Node Clocks", "Vectors at Max",
		    "Max Clocks", "Avg Clocks", "Avg Vectors/Call");
      else
	s = format (s,
		    "%=30s%=12s%=16s%=16s%=16s%=16s%=16s",
		    "Name", "State", "Calls", "Vectors", "Suspends",
		    "Clocks", "Vectors/Call");
      return s;
    }

  indent = format_get_indent (s);

  l = n->stats_total.clocks - n->stats_last_clear.clocks;
  c = n->stats_total.calls - n->stats_last_clear.calls;
  p = n->stats_total.vectors - n->stats_last_clear.vectors;
  d = n->stats_total.suspends - n->stats_last_clear.suspends;
  maxc = (f64) n->stats_total.max_clock;
  maxn = n->stats_total.max_clock_n;
  if (n->stats_total.max_clock_n)
    maxcn = (f64) n->stats_total.max_clock / (f64) maxn;
  else
    maxcn = 0.0;

  /* Clocks per packet, per call or per suspend. */
  x = 0;
  if (p > 0)
    x = (f64) l / (f64) p;
  else if (c > 0)
    x = (f64) l / (f64) c;
  else if (d > 0)
    x = (f64) l / (f64) d;

  if (c > 0)
    v = (double) p / (double) c;
  else
    v = 0;

  if (n->type == VLIB_NODE_TYPE_PROCESS)
    {
      vlib_process_t *p = vlib_get_process_from_node (vm, n);

      /* Show processes with events pending.  This helps spot bugs where events are not
         being handled. */
      if (!clib_bitmap_is_zero (p->non_empty_event_type_bitmap))
	misc_info = format (misc_info, "events pending, ");
    }
  ns = n->name;

  if (max)
    s = format (s, "%-30v%=17.2e%=16d%=16.2e%=16.2e%=16.2e",
		ns, maxc, maxn, maxcn, x, v);
  else
    s = format (s, "%-30v%=12U%16Ld%16Ld%16Ld%16.2e%16.2f", ns,
		format_vlib_node_state, vm, n, c, p, d, x, v);

  if (ns != n->name)
    vec_free (ns);

  if (misc_info)
    {
      s = format (s, "\n%U%v", format_white_space, indent + 4, misc_info);
      vec_free (misc_info);
    }

  return s;
}

f64 vlib_get_stat_segment_update_rate (void) __attribute__ ((weak));
f64
vlib_get_stat_segment_update_rate (void)
{
  return 1e70;
}

static clib_error_t *
show_node_runtime (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  f64 time_now;
  u32 node_index;
  vlib_node_t ***node_dups = 0;
  f64 *internal_node_vector_rates = 0;

  time_now = vlib_time_now (vm);

  if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
    {
      n = vlib_get_node (vm, node_index);
      vlib_node_sync_stats (vm, n);
      vlib_cli_output (vm, "%U\n", format_vlib_node_stats, vm, 0, 0);
      vlib_cli_output (vm, "%U\n", format_vlib_node_stats, vm, n, 0);
    }
  else
    {
      vlib_node_t **nodes;
      uword i, j;
      f64 dt;
      u64 n_input, n_output, n_drop, n_punt;
      u64 n_internal_vectors, n_internal_calls;
      u64 n_clocks, l, v, c, d;
      int brief = 1;
      int summary = 0;
      int max = 0;
      vlib_main_t **stat_vms = 0, *stat_vm;

      /* Suppress nodes with zero calls since last clear */
      if (unformat (input, "brief") || unformat (input, "b"))
	brief = 1;
      if (unformat (input, "verbose") || unformat (input, "v"))
	brief = 0;
      if (unformat (input, "max") || unformat (input, "m"))
	max = 1;
      if (unformat (input, "summary") || unformat (input, "sum")
	  || unformat (input, "su"))
	summary = 1;

      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  stat_vm = vlib_mains[i];
	  if (stat_vm)
	    vec_add1 (stat_vms, stat_vm);
	}

      /*
       * Barrier sync across stats scraping.
       * Otherwise, the counts will be grossly inaccurate.
       */
      vlib_worker_thread_barrier_sync (vm);

      for (j = 0; j < vec_len (stat_vms); j++)
	{
	  stat_vm = stat_vms[j];
	  nm = &stat_vm->node_main;

	  for (i = 0; i < vec_len (nm->nodes); i++)
	    {
	      n = nm->nodes[i];
	      vlib_node_sync_stats (stat_vm, n);
	    }

	  nodes = vec_dup (nm->nodes);

	  vec_add1 (node_dups, nodes);
	  vec_add1 (internal_node_vector_rates,
		    vlib_internal_node_vector_rate (stat_vm));
	}
      vlib_worker_thread_barrier_release (vm);


      for (j = 0; j < vec_len (stat_vms); j++)
	{
	  stat_vm = stat_vms[j];
	  nodes = node_dups[j];

	  vec_sort_with_function (nodes, node_cmp);

	  n_input = n_output = n_drop = n_punt = n_clocks = 0;
	  n_internal_vectors = n_internal_calls = 0;
	  for (i = 0; i < vec_len (nodes); i++)
	    {
	      n = nodes[i];

	      l = n->stats_total.clocks - n->stats_last_clear.clocks;
	      n_clocks += l;

	      v = n->stats_total.vectors - n->stats_last_clear.vectors;
	      c = n->stats_total.calls - n->stats_last_clear.calls;

	      switch (n->type)
		{
		default:
		  continue;

		case VLIB_NODE_TYPE_INTERNAL:
		  n_output += (n->flags & VLIB_NODE_FLAG_IS_OUTPUT) ? v : 0;
		  n_drop += (n->flags & VLIB_NODE_FLAG_IS_DROP) ? v : 0;
		  n_punt += (n->flags & VLIB_NODE_FLAG_IS_PUNT) ? v : 0;
		  if (!(n->flags & VLIB_NODE_FLAG_IS_OUTPUT))
		    {
		      n_internal_vectors += v;
		      n_internal_calls += c;
		    }
		  if (n->flags & VLIB_NODE_FLAG_IS_HANDOFF)
		    n_input += v;
		  break;

		case VLIB_NODE_TYPE_INPUT:
		  n_input += v;
		  break;
		}
	    }

	  if (vec_len (vlib_mains) > 1)
	    {
	      vlib_worker_thread_t *w = vlib_worker_threads + j;
	      if (j > 0)
		vlib_cli_output (vm, "---------------");

	      if (w->cpu_id > -1)
		vlib_cli_output (vm, "Thread %d %s (lcore %u)", j, w->name,
				 w->cpu_id);
	      else
		vlib_cli_output (vm, "Thread %d %s", j, w->name);
	    }

	  dt = time_now - nm->time_last_runtime_stats_clear;
	  vlib_cli_output
	    (vm,
	     "Time %.1f, %f sec internal node vector rate %.2f loops/sec %.2f\n"
	     "  vector rates in %.4e, out %.4e, drop %.4e, punt %.4e",
	     dt,
	     vlib_get_stat_segment_update_rate (),
	     internal_node_vector_rates[j],
	     stat_vm->loops_per_second,
	     (f64) n_input / dt,
	     (f64) n_output / dt, (f64) n_drop / dt, (f64) n_punt / dt);

	  if (summary == 0)
	    {
	      vlib_cli_output (vm, "%U", format_vlib_node_stats, stat_vm,
			       0, max);
	      for (i = 0; i < vec_len (nodes); i++)
		{
		  c =
		    nodes[i]->stats_total.calls -
		    nodes[i]->stats_last_clear.calls;
		  d =
		    nodes[i]->stats_total.suspends -
		    nodes[i]->stats_last_clear.suspends;
		  if (c || d || !brief)
		    {
		      vlib_cli_output (vm, "%U", format_vlib_node_stats,
				       stat_vm, nodes[i], max);
		    }
		}
	    }
	  vec_free (nodes);
	}
      vec_free (stat_vms);
      vec_free (node_dups);
      vec_free (internal_node_vector_rates);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_node_runtime_command, static) = {
  .path = "show runtime",
  .short_help = "Show packet processing runtime",
  .function = show_node_runtime,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
clear_node_runtime (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm;
  vlib_node_t *n;
  int i, j;
  vlib_main_t **stat_vms = 0, *stat_vm;
  vlib_node_runtime_t *r;

  for (i = 0; i < vec_len (vlib_mains); i++)
    {
      stat_vm = vlib_mains[i];
      if (stat_vm)
	vec_add1 (stat_vms, stat_vm);
    }

  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (stat_vms); j++)
    {
      stat_vm = stat_vms[j];
      nm = &stat_vm->node_main;

      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  vlib_node_sync_stats (stat_vm, n);
	  n->stats_last_clear = n->stats_total;

	  r = vlib_node_get_runtime (stat_vm, n->index);
	  r->max_clock = 0;
	}
      /* Note: input/output rates computed using vlib_global_main */
      nm->time_last_runtime_stats_clear = vlib_time_now (vm);
    }

  vlib_worker_thread_barrier_release (vm);

  vec_free (stat_vms);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_node_runtime_command, static) = {
  .path = "clear runtime",
  .short_help = "Clear packet processing runtime statistics",
  .function = clear_node_runtime,
};
/* *INDENT-ON* */

static clib_error_t *
show_node (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u8 *s = 0, *s2 = 0;
  u32 i, node_index = ~0, verbose = 0;
  char *type_str;
  u8 valid_node_name = 0;
  u64 cl, ca, v;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %u", &node_index))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else
	if (unformat (line_input, "%U", unformat_vlib_node, vm, &node_index))
	valid_node_name = 1;
      else if (!valid_node_name)
	error = clib_error_return (0, "unknown node name: '%U'",
				   format_unformat_error, line_input);
      else
	error = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);

      if (error)
	break;
    }

  unformat_free (line_input);

  if (error)
    return error;

  if (node_index >= vec_len (vm->node_main.nodes))
    return clib_error_return (0, "please specify valid node");

  n = vlib_get_node (vm, node_index);
  vlib_node_sync_stats (vm, n);

  switch (n->type)
    {
    case VLIB_NODE_TYPE_INTERNAL:
      type_str = "internal";
      break;
    case VLIB_NODE_TYPE_INPUT:
      type_str = "input";
      break;
    case VLIB_NODE_TYPE_PRE_INPUT:
      type_str = "pre-input";
      break;
    case VLIB_NODE_TYPE_PROCESS:
      type_str = "process";
      break;
    default:
      type_str = "unknown";
    }

  if (n->sibling_of)
    s = format (s, ", sibling-of %s", n->sibling_of);

  vlib_cli_output (vm, "node %v, type %s, state %U, index %d%v\n",
		   n->name, type_str, format_vlib_node_state, vm, n,
		   n->index, s);
  vec_reset_length (s);

  if (n->node_fn_registrations)
    {
      vlib_node_fn_registration_t *fnr = n->node_fn_registrations;
      vlib_node_fn_variant_t *v;
      while (fnr)
	{
	  v = vec_elt_at_index (vm->node_main.variants, fnr->march_variant);
	  if (vec_len (s) == 0)
	    s = format (s, "\n    %-15s  %=8s  %6s  %s", "Name", "Priority",
			"Active", "Description");
	  s = format (s, "\n    %-15s  %8d  %=6s  %s", v->suffix, v->priority,
		      fnr->function == n->function ? "yes" : "", v->desc);
	  fnr = fnr->next_registration;
	}
    }
  else
    s = format (s, "\n    default only");
  vlib_cli_output (vm, "  node function variants:%v\n", s);
  vec_reset_length (s);

  for (i = 0; i < vec_len (n->next_nodes); i++)
    {
      vlib_node_t *pn;
      if (n->next_nodes[i] == VLIB_INVALID_NODE_INDEX)
	continue;

      pn = vec_elt (nm->nodes, n->next_nodes[i]);

      if (vec_len (s) == 0)
	s = format (s, "\n    %10s  %10s  %=30s %8s",
		    "next-index", "node-index", "Node", "Vectors");

      s = format (s, "\n    %=10u  %=10u  %=30v %=8llu", i, n->next_nodes[i],
		  pn->name, vec_elt (n->n_vectors_by_next_node, i));
    }

  if (vec_len (s) == 0)
    s = format (s, "\n    none");
  vlib_cli_output (vm, "\n  next nodes:%v\n", s);
  vec_reset_length (s);

  if (n->type == VLIB_NODE_TYPE_INTERNAL)
    {
      int j = 0;
      /* *INDENT-OFF* */
      clib_bitmap_foreach (i, n->prev_node_bitmap)  {
	    vlib_node_t *pn = vlib_get_node (vm, i);
	    if (j++ % 3 == 0)
	      s = format (s, "\n    ");
	    s2 = format (s2, "%v (%u)", pn->name, i);
	    s = format (s, "%-35v", s2);
	    vec_reset_length (s2);
	  }
      /* *INDENT-ON* */

      if (vec_len (s) == 0)
	s = format (s, "\n    none");
      vlib_cli_output (vm, "\n  known previous nodes:%v\n", s);
      vec_reset_length (s);
      vec_free (s2);
    }

  if (!verbose)
    goto done;

  s = format (s, "\n%8s %=12s %=12s %=12s %=12s %=12s\n", "Thread", "Calls",
	      "Clocks", "Vectors", "Max Clock", "Max Vectors");
  for (i = 0; i < vec_len (vlib_mains); i++)
    {
      n = vlib_get_node (vlib_mains[i], node_index);
      vlib_node_sync_stats (vlib_mains[i], n);

      cl = n->stats_total.clocks - n->stats_last_clear.clocks;
      ca = n->stats_total.calls - n->stats_last_clear.calls;
      v = n->stats_total.vectors - n->stats_last_clear.vectors;

      s = format (s, "%=8u %=12lu %=12lu %=12lu %=12u %=12u\n", i, ca, cl, v,
		  n->stats_total.max_clock, n->stats_total.max_clock_n);
    }

  vlib_cli_output (vm, "%v", s);

done:

  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_node_command, static) = {
  .path = "show node",
  .short_help = "show node [index] <node-name | node-index>",
  .function = show_node,
};

static clib_error_t *
set_node_fn(vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 node_index, march_variant;
  vlib_node_t *n;
  clib_error_t *err = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%U", unformat_vlib_node, vm, &node_index))
    {
      err = clib_error_return (0, "please specify valid node name");
      goto done;
    }

  if (!unformat (line_input, "%U", unformat_vlib_node_variant, &march_variant))
    {
      err = clib_error_return (0, "please specify node function variant");
      goto done;
    }

  n = vlib_get_node (vm, node_index);

  if (n->node_fn_registrations == 0)
    {
      err = clib_error_return (0, "node doesn't have function variants");
      goto done;
    }

  if (vlib_node_set_node_fn_variant (vm, node_index, march_variant))
    {
      vlib_node_fn_variant_t *v;
      v = vec_elt_at_index (vm->node_main.variants, march_variant);
      err = clib_error_return (0, "node function variant '%s' not found",
			       v->suffix);
      goto done;
    }


done:
  unformat_free (line_input);
  return err;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_node_fn_command, static) = {
  .path = "set node function",
  .short_help = "set node function <node-name> <variant-name>",
  .function = set_node_fn,
};
/* *INDENT-ON* */

/* Dummy function to get us linked in. */
void
vlib_node_cli_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
