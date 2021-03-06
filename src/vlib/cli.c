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
 * cli.c: command line interface
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
#include <vlib/unix/unix.h>
#include <vppinfra/callback.h>
#include <vppinfra/cpu.h>
#include <vppinfra/elog.h>
#include <unistd.h>
#include <ctype.h>

/** \file src/vlib/cli.c Debug CLI Implementation
 */

int vl_api_set_elog_trace_api_messages (int enable);
int vl_api_get_elog_trace_api_messages (void);

static void *current_traced_heap;

/* Root of all show commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_command, static) = {
  .path = "show",
  .short_help = "Show commands",
};
/* *INDENT-ON* */

/* Root of all clear commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_clear_command, static) = {
  .path = "clear",
  .short_help = "Clear commands",
};
/* *INDENT-ON* */

/* Root of all set commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_set_command, static) = {
  .path = "set",
  .short_help = "Set commands",
};
/* *INDENT-ON* */

/* Root of all test commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_test_command, static) = {
  .path = "test",
  .short_help = "Test commands",
};
/* *INDENT-ON* */

/* Returns bitmap of commands which match key. */
static uword *
vlib_cli_sub_command_match (vlib_cli_command_t * c, unformat_input_t * input)
{
  int i, n;
  uword *match = 0;
  vlib_cli_parse_position_t *p;

  unformat_skip_white_space (input);

  for (i = 0;; i++)
    {
      uword k;

      k = unformat_get_input (input);
      switch (k)
	{
	case 'a' ... 'z':
	case 'A' ... 'Z':
	case '0' ... '9':
	case '-':
	case '_':
	  break;

	case ' ':
	case '\t':
	case '\r':
	case '\n':
	case UNFORMAT_END_OF_INPUT:
	  /* White space or end of input removes any non-white
	     matches that were before possible. */
	  if (i < vec_len (c->sub_command_positions)
	      && clib_bitmap_count_set_bits (match) > 1)
	    {
	      p = vec_elt_at_index (c->sub_command_positions, i);
	      for (n = 0; n < vec_len (p->bitmaps); n++)
		match = clib_bitmap_andnot (match, p->bitmaps[n]);
	    }
	  goto done;

	default:
	  unformat_put_input (input);
	  goto done;
	}

      if (i >= vec_len (c->sub_command_positions))
	{
	no_match:
	  clib_bitmap_free (match);
	  return 0;
	}

      p = vec_elt_at_index (c->sub_command_positions, i);
      if (vec_len (p->bitmaps) == 0)
	goto no_match;

      n = k - p->min_char;
      if (n < 0 || n >= vec_len (p->bitmaps))
	goto no_match;

      if (i == 0)
	match = clib_bitmap_dup (p->bitmaps[n]);
      else
	match = clib_bitmap_and (match, p->bitmaps[n]);

      if (clib_bitmap_is_zero (match))
	goto no_match;
    }

done:
  return match;
}

/* Looks for string based sub-input formatted { SUB-INPUT }. */
uword
unformat_vlib_cli_sub_input (unformat_input_t * i, va_list * args)
{
  unformat_input_t *sub_input = va_arg (*args, unformat_input_t *);
  u8 *s;
  uword c;

  while (1)
    {
      c = unformat_get_input (i);
      switch (c)
	{
	case ' ':
	case '\t':
	case '\n':
	case '\r':
	case '\f':
	  break;

	case '{':
	default:
	  /* Put back paren. */
	  if (c != UNFORMAT_END_OF_INPUT)
	    unformat_put_input (i);

	  if (c == '{' && unformat (i, "%v", &s))
	    {
	      unformat_init_vector (sub_input, s);
	      return 1;
	    }
	  return 0;
	}
    }
  return 0;
}

static vlib_cli_command_t *
get_sub_command (vlib_cli_main_t * cm, vlib_cli_command_t * parent, u32 si)
{
  vlib_cli_sub_command_t *s = vec_elt_at_index (parent->sub_commands, si);
  return vec_elt_at_index (cm->commands, s->index);
}

static uword
unformat_vlib_cli_sub_command (unformat_input_t * i, va_list * args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_command_t *c = va_arg (*args, vlib_cli_command_t *);
  vlib_cli_command_t **result = va_arg (*args, vlib_cli_command_t **);
  vlib_cli_main_t *cm = &vgm->cli_main;
  uword *match_bitmap, is_unique, index;

  match_bitmap = vlib_cli_sub_command_match (c, i);
  is_unique = clib_bitmap_count_set_bits (match_bitmap) == 1;
  index = ~0;
  if (is_unique)
    {
      index = clib_bitmap_first_set (match_bitmap);
      *result = get_sub_command (cm, c, index);
    }
  clib_bitmap_free (match_bitmap);

  return is_unique;
}

static int
vlib_cli_cmp_strings (void *a1, void *a2)
{
  u8 *c1 = *(u8 **) a1;
  u8 *c2 = *(u8 **) a2;

  return vec_cmp (c1, c2);
}

u8 **
vlib_cli_get_possible_completions (u8 * str)
{
  vlib_cli_command_t *c;
  vlib_cli_sub_command_t *sc;
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_main_t *vcm = &vgm->cli_main;
  uword *match_bitmap = 0;
  uword index, is_unique, help_next_level;
  u8 **result = 0;
  unformat_input_t input;
  unformat_init_vector (&input, vec_dup (str));
  c = vec_elt_at_index (vcm->commands, 0);

  /* remove trailing whitespace, except for one of them */
  while (vec_len (input.buffer) >= 2 &&
	 isspace (input.buffer[vec_len (input.buffer) - 1]) &&
	 isspace (input.buffer[vec_len (input.buffer) - 2]))
    {
      vec_del1 (input.buffer, vec_len (input.buffer) - 1);
    }

  /* if input is empty, directly return list of root commands */
  if (vec_len (input.buffer) == 0 ||
      (vec_len (input.buffer) == 1 && isspace (input.buffer[0])))
    {
      vec_foreach (sc, c->sub_commands)
      {
	vec_add1 (result, (u8 *) sc->name);
      }
      goto done;
    }

  /* add a trailing '?' so that vlib_cli_sub_command_match can find
   * all commands starting with the input string */
  vec_add1 (input.buffer, '?');

  while (1)
    {
      match_bitmap = vlib_cli_sub_command_match (c, &input);
      /* no match: return no result */
      if (match_bitmap == 0)
	{
	  goto done;
	}
      is_unique = clib_bitmap_count_set_bits (match_bitmap) == 1;
      /* unique match: try to step one subcommand level further */
      if (is_unique)
	{
	  /* stop if no more input */
	  if (input.index >= vec_len (input.buffer) - 1)
	    {
	      break;
	    }

	  index = clib_bitmap_first_set (match_bitmap);
	  c = get_sub_command (vcm, c, index);
	  clib_bitmap_free (match_bitmap);
	  continue;
	}
      /* multiple matches: stop here, return all matches */
      break;
    }

  /* remove trailing '?' */
  vec_del1 (input.buffer, vec_len (input.buffer) - 1);

  /* if we have a space at the end of input, and a unique match,
   * autocomplete the next level of subcommands */
  help_next_level = (vec_len (str) == 0) || isspace (str[vec_len (str) - 1]);
  /* *INDENT-OFF* */
  clib_bitmap_foreach (index, match_bitmap) {
    if (help_next_level && is_unique) {
	c = get_sub_command (vcm, c, index);
	vec_foreach (sc, c->sub_commands) {
	  vec_add1 (result, (u8*) sc->name);
	}
	goto done; /* break doesn't work in this macro-loop */
    }
    sc = &c->sub_commands[index];
    vec_add1(result, (u8*) sc->name);
  }
  /* *INDENT-ON* */

done:
  clib_bitmap_free (match_bitmap);
  unformat_free (&input);

  if (result)
    vec_sort_with_function (result, vlib_cli_cmp_strings);
  return result;
}

static u8 *
format_vlib_cli_command_help (u8 * s, va_list * args)
{
  vlib_cli_command_t *c = va_arg (*args, vlib_cli_command_t *);
  int is_long = va_arg (*args, int);
  if (is_long && c->long_help)
    s = format (s, "%s", c->long_help);
  else if (c->short_help)
    s = format (s, "%s", c->short_help);
  else
    s = format (s, "%v commands", c->path);
  return s;
}

static u8 *
format_vlib_cli_path (u8 * s, va_list * args)
{
  u8 *path = va_arg (*args, u8 *);

  s = format (s, "%v", path);

  return s;
}

static vlib_cli_command_t *
all_subs (vlib_cli_main_t * cm, vlib_cli_command_t * subs, u32 command_index)
{
  vlib_cli_command_t *c = vec_elt_at_index (cm->commands, command_index);
  vlib_cli_sub_command_t *sc;

  if (c->function)
    vec_add1 (subs, c[0]);

  vec_foreach (sc, c->sub_commands) subs = all_subs (cm, subs, sc->index);

  return subs;
}

static int
vlib_cli_cmp_rule (void *a1, void *a2)
{
  vlib_cli_sub_rule_t *r1 = a1;
  vlib_cli_sub_rule_t *r2 = a2;

  return vec_cmp (r1->name, r2->name);
}

static int
vlib_cli_cmp_command (void *a1, void *a2)
{
  vlib_cli_command_t *c1 = a1;
  vlib_cli_command_t *c2 = a2;

  return vec_cmp (c1->path, c2->path);
}

static clib_error_t *
vlib_cli_dispatch_sub_commands (vlib_main_t * vm,
				vlib_cli_main_t * cm,
				unformat_input_t * input,
				uword parent_command_index)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_command_t *parent, *c;
  clib_error_t *error = 0;
  unformat_input_t sub_input;
  u8 *string;
  uword is_main_dispatch = cm == &vgm->cli_main;

  parent = vec_elt_at_index (cm->commands, parent_command_index);
  if (is_main_dispatch && unformat (input, "help"))
    {
      uword help_at_end_of_line, i;

      help_at_end_of_line =
	unformat_check_input (input) == UNFORMAT_END_OF_INPUT;
      while (1)
	{
	  c = parent;
	  if (unformat_user
	      (input, unformat_vlib_cli_sub_command, vm, c, &parent))
	    ;

	  else if (!(unformat_check_input (input) == UNFORMAT_END_OF_INPUT))
	    goto unknown;

	  else
	    break;
	}

      /* help SUB-COMMAND => long format help.
         "help" at end of line: show all commands. */
      if (!help_at_end_of_line)
	vlib_cli_output (vm, "%U", format_vlib_cli_command_help, c,
			 /* is_long */ 1);

      else if (vec_len (c->sub_commands) == 0)
	vlib_cli_output (vm, "%v: no sub-commands", c->path);

      else
	{
	  vlib_cli_sub_rule_t *sr, *subs = 0;
	  vlib_cli_sub_command_t *sc;

	  vec_foreach (sc, c->sub_commands)
	  {
	    vec_add2 (subs, sr, 1);
	    sr->name = sc->name;
	    sr->command_index = sc->index;
	    sr->rule_index = ~0;
	  }

	  vec_sort_with_function (subs, vlib_cli_cmp_rule);

	  for (i = 0; i < vec_len (subs); i++)
	    {
	      vlib_cli_command_t *d;

	      d = vec_elt_at_index (cm->commands, subs[i].command_index);
	      vlib_cli_output
		(vm, "  %-30v %U", subs[i].name,
		 format_vlib_cli_command_help, d, /* is_long */ 0);
	    }

	  vec_free (subs);
	}
    }

  else if (is_main_dispatch
	   && (unformat (input, "choices") || unformat (input, "?")))
    {
      vlib_cli_command_t *sub, *subs;

      subs = all_subs (cm, 0, parent_command_index);
      vec_sort_with_function (subs, vlib_cli_cmp_command);
      vec_foreach (sub, subs)
	vlib_cli_output (vm, "  %-40U %U",
			 format_vlib_cli_path, sub->path,
			 format_vlib_cli_command_help, sub, /* is_long */ 0);
      vec_free (subs);
    }

  else if (unformat (input, "comment %v", &string))
    {
      vec_free (string);
    }

  else if (unformat (input, "vpplog %v", &string))
    {
      int i;
      /*
       * Delete leading whitespace, so "vpplog { this and that }"
       * and "vpplog this" line up nicely.
       */
      for (i = 0; i < vec_len (string); i++)
	if (string[i] != ' ')
	  break;
      if (i > 0)
	vec_delete (string, i, 0);

      vlib_log_notice (cm->log, "CLI: %v", string);
      vec_free (string);
    }

  else if (unformat (input, "uncomment %U",
		     unformat_vlib_cli_sub_input, &sub_input))
    {
      error =
	vlib_cli_dispatch_sub_commands (vm, cm, &sub_input,
					parent_command_index);
      unformat_free (&sub_input);
    }
  else if (unformat (input, "leak-check %U",
		     unformat_vlib_cli_sub_input, &sub_input))
    {
      u8 *leak_report;
      if (current_traced_heap)
	{
	  void *oldheap;
	  oldheap = clib_mem_set_heap (current_traced_heap);
	  clib_mem_trace (0);
	  clib_mem_set_heap (oldheap);
	  current_traced_heap = 0;
	}
      clib_mem_trace (1);
      error =
	vlib_cli_dispatch_sub_commands (vm, cm, &sub_input,
					parent_command_index);
      unformat_free (&sub_input);

      /* Otherwise, the clib_error_t shows up as a leak... */
      if (error)
	{
	  vlib_cli_output (vm, "%v", error->what);
	  clib_error_free (error);
	  error = 0;
	}

      (void) clib_mem_trace_enable_disable (0);
      leak_report = format (0, "%U", format_clib_mem_heap, 0,
			    1 /* verbose, i.e. print leaks */ );
      clib_mem_trace (0);
      vlib_cli_output (vm, "%v", leak_report);
      vec_free (leak_report);
    }

  else
    if (unformat_user (input, unformat_vlib_cli_sub_command, vm, parent, &c))
    {
      unformat_input_t *si;
      uword has_sub_commands =
	vec_len (c->sub_commands) + vec_len (c->sub_rules) > 0;

      si = input;
      if (unformat_user (input, unformat_vlib_cli_sub_input, &sub_input))
	si = &sub_input;

      if (has_sub_commands)
	error = vlib_cli_dispatch_sub_commands (vm, cm, si, c - cm->commands);

      if (has_sub_commands && !error)
	/* Found valid sub-command. */ ;

      else if (c->function)
	{
	  clib_error_t *c_error;

	  /* Skip white space for benefit of called function. */
	  unformat_skip_white_space (si);

	  if (unformat (si, "?"))
	    {
	      vlib_cli_output (vm, "  %-40U %U", format_vlib_cli_path, c->path, format_vlib_cli_command_help, c,	/* is_long */
			       0);
	    }
	  else
	    {
	      if (PREDICT_FALSE (vm->elog_trace_cli_commands))
		{
                  /* *INDENT-OFF* */
                  ELOG_TYPE_DECLARE (e) =
                    {
                      .format = "cli-cmd: %s",
                      .format_args = "T4",
                    };
                  /* *INDENT-ON* */
		  struct
		  {
		    u32 c;
		  } *ed;
		  ed = ELOG_DATA (&vgm->elog_main, e);
		  ed->c = elog_string (&vgm->elog_main, "%v", c->path);
		}

	      if (!c->is_mp_safe)
		vlib_worker_thread_barrier_sync (vm);
	      if (PREDICT_FALSE (vec_len (cm->perf_counter_cbs) != 0))
		clib_call_callbacks (cm->perf_counter_cbs, cm,
				     c - cm->commands, 0 /* before */ );

	      c->hit_counter++;
	      c_error = c->function (vm, si, c);

	      if (PREDICT_FALSE (vec_len (cm->perf_counter_cbs) != 0))
		clib_call_callbacks (cm->perf_counter_cbs, cm,
				     c - cm->commands, 1 /* after */ );
	      if (!c->is_mp_safe)
		vlib_worker_thread_barrier_release (vm);

	      if (PREDICT_FALSE (vm->elog_trace_cli_commands))
		{
                  /* *INDENT-OFF* */
                  ELOG_TYPE_DECLARE (e) =
                    {
                      .format = "cli-cmd: %s %s",
                      .format_args = "T4T4",
                    };
                  /* *INDENT-ON* */
		  struct
		  {
		    u32 c, err;
		  } *ed;
		  ed = ELOG_DATA (&vgm->elog_main, e);
		  ed->c = elog_string (&vgm->elog_main, "%v", c->path);
		  if (c_error)
		    {
		      vec_add1 (c_error->what, 0);
		      ed->err =
			elog_string (&vgm->elog_main, (char *) c_error->what);
		      _vec_len (c_error->what) -= 1;
		    }
		  else
		    ed->err = elog_string (&vgm->elog_main, "OK");
		}

	      if (c_error)
		{
		  error =
		    clib_error_return (0, "%v: %v", c->path, c_error->what);
		  clib_error_free (c_error);
		  /* Free sub input. */
		  if (si != input)
		    unformat_free (si);

		  return error;
		}
	    }

	  /* Free any previous error. */
	  clib_error_free (error);
	}

      else if (!error)
	error = clib_error_return (0, "%v: no sub-commands", c->path);

      /* Free sub input. */
      if (si != input)
	unformat_free (si);
    }

  else
    goto unknown;

  return error;

unknown:
  if (parent->path)
    return clib_error_return (0, "%v: unknown input `%U'", parent->path,
			      format_unformat_error, input);
  else
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);
}


void vlib_unix_error_report (vlib_main_t *, clib_error_t *)
  __attribute__ ((weak));

void
vlib_unix_error_report (vlib_main_t * vm, clib_error_t * error)
{
}

/* Process CLI input. */
int
vlib_cli_input (vlib_main_t * vm,
		unformat_input_t * input,
		vlib_cli_output_function_t * function, uword function_arg)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_process_t *cp = vlib_get_current_process (vm);
  clib_error_t *error;
  vlib_cli_output_function_t *save_function;
  uword save_function_arg;
  int rv = 0;

  save_function = cp->output_function;
  save_function_arg = cp->output_function_arg;

  cp->output_function = function;
  cp->output_function_arg = function_arg;

  do
    {
      error = vlib_cli_dispatch_sub_commands (vm, &vgm->cli_main, input,
					      /* parent */ 0);
    }
  while (!error && !unformat (input, "%U", unformat_eof));

  if (error)
    {
      vlib_cli_output (vm, "%v", error->what);
      vlib_unix_error_report (vm, error);
      /* clib_error_return is unfortunately often called with a '0'
         return code */
      rv = error->code != 0 ? error->code : -1;
      clib_error_free (error);
    }

  cp->output_function = save_function;
  cp->output_function_arg = save_function_arg;
  return rv;
}

/* Output to current CLI connection. */
void
vlib_cli_output (vlib_main_t * vm, char *fmt, ...)
{
  vlib_process_t *cp = vlib_get_current_process (vm);
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  /* some format functions might return 0
   * e.g. show int addr */
  if (NULL == s)
    return;

  /* Terminate with \n if not present. */
  if (vec_len (s) > 0 && s[vec_len (s) - 1] != '\n')
    vec_add1 (s, '\n');

  if ((!cp) || (!cp->output_function))
    fformat (stdout, "%v", s);
  else
    cp->output_function (cp->output_function_arg, s, vec_len (s));

  vec_free (s);
}

void *vl_msg_push_heap (void) __attribute__ ((weak));
void *
vl_msg_push_heap (void)
{
  return 0;
}

void vl_msg_pop_heap (void *oldheap) __attribute__ ((weak));
void
vl_msg_pop_heap (void *oldheap)
{
}

void *vlib_stats_push_heap (void *) __attribute__ ((weak));
void *
vlib_stats_push_heap (void *notused)
{
  return 0;
}

static clib_error_t *
show_memory_usage (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_mem_main_t *mm = &clib_mem_main;
  int verbose __attribute__ ((unused)) = 0;
  int api_segment = 0, stats_segment = 0, main_heap = 0, numa_heaps = 0;
  int map = 0;
  clib_error_t *error;
  u32 index = 0;
  int i;
  uword clib_mem_trace_enable_disable (uword enable);
  uword was_enabled;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "api-segment"))
	api_segment = 1;
      else if (unformat (input, "stats-segment"))
	stats_segment = 1;
      else if (unformat (input, "main-heap"))
	main_heap = 1;
      else if (unformat (input, "numa-heaps"))
	numa_heaps = 1;
      else if (unformat (input, "map"))
	map = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  return error;
	}
    }

  if ((api_segment + stats_segment + main_heap + numa_heaps + map) == 0)
    return clib_error_return
      (0, "Need one of api-segment, stats-segment, main-heap, numa-heaps "
       "or map");

  if (api_segment)
    {
      void *oldheap = vl_msg_push_heap ();
      was_enabled = clib_mem_trace_enable_disable (0);
      u8 *s_in_svm = format (0, "%U\n", format_clib_mem_heap, 0, 1);
      vl_msg_pop_heap (oldheap);
      u8 *s = vec_dup (s_in_svm);

      oldheap = vl_msg_push_heap ();
      vec_free (s_in_svm);
      clib_mem_trace_enable_disable (was_enabled);
      vl_msg_pop_heap (oldheap);
      vlib_cli_output (vm, "API segment");
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
    }
  if (stats_segment)
    {
      void *oldheap = vlib_stats_push_heap (0);
      was_enabled = clib_mem_trace_enable_disable (0);
      u8 *s_in_svm = format (0, "%U\n", format_clib_mem_heap, 0, 1);
      if (oldheap)
	clib_mem_set_heap (oldheap);
      u8 *s = vec_dup (s_in_svm);

      oldheap = vlib_stats_push_heap (0);
      vec_free (s_in_svm);
      if (oldheap)
	{
	  clib_mem_trace_enable_disable (was_enabled);
	  clib_mem_set_heap (oldheap);
	}
      vlib_cli_output (vm, "Stats segment");
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
    }


  {
    if (main_heap)
      {
	/*
	 * Note: the foreach_vlib_main causes allocator traffic,
	 * so shut off tracing before we go there...
	 */
	was_enabled = clib_mem_trace_enable_disable (0);

        /* *INDENT-OFF* */
        foreach_vlib_main (
        ({
          vlib_cli_output (vm, "%sThread %d %s\n", index ? "\n":"", index,
                           vlib_worker_threads[index].name);
          vlib_cli_output (vm, "  %U\n", format_clib_mem_heap,
                           mm->per_cpu_mheaps[index],
                           verbose);
          index++;
        }));
        /* *INDENT-ON* */

	/* Restore the trace flag */
	clib_mem_trace_enable_disable (was_enabled);
      }
    if (numa_heaps)
      {
	for (i = 0; i < ARRAY_LEN (mm->per_numa_mheaps); i++)
	  {
	    if (mm->per_numa_mheaps[i] == 0)
	      continue;
	    if (mm->per_numa_mheaps[i] == mm->per_cpu_mheaps[i])
	      {
		vlib_cli_output (vm, "Numa %d uses the main heap...", i);
		continue;
	      }
	    was_enabled = clib_mem_trace_enable_disable (0);

	    vlib_cli_output (vm, "Numa %d:", i);
	    vlib_cli_output (vm, "  %U\n", format_clib_mem_heap,
			     mm->per_numa_mheaps[index], verbose);
	  }
      }
    if (map)
      {
	clib_mem_page_stats_t stats = { };
	clib_mem_vm_map_hdr_t *hdr = 0;
	u8 *s = 0;
	int numa = -1;

	s = format (s, "\n%-16s%7s%5s%7s%7s",
		    "StartAddr", "size", "FD", "PageSz", "Pages");
	while ((numa = vlib_mem_get_next_numa_node (numa)) != -1)
	  s = format (s, " Numa%u", numa);
	s = format (s, " NotMap");
	s = format (s, " Name");
	vlib_cli_output (vm, "%v", s);
	vec_reset_length (s);

	while ((hdr = clib_mem_vm_get_next_map_hdr (hdr)))
	  {
	    clib_mem_get_page_stats ((void *) hdr->base_addr,
				     hdr->log2_page_sz, hdr->num_pages,
				     &stats);
	    s = format (s, "%016lx%7U",
			hdr->base_addr, format_memory_size,
			hdr->num_pages << hdr->log2_page_sz);

	    if (hdr->fd != -1)
	      s = format (s, "%5d", hdr->fd);
	    else
	      s = format (s, "%5s", " ");

	    s = format (s, "%7U%7lu",
			format_log2_page_size, hdr->log2_page_sz,
			hdr->num_pages);
	    while ((numa = vlib_mem_get_next_numa_node (numa)) != -1)
	      s = format (s, "%6lu", stats.per_numa[numa]);
	    s = format (s, "%7lu", stats.not_mapped);
	    s = format (s, " %s", hdr->name);
	    vlib_cli_output (vm, "%v", s);
	    vec_reset_length (s);
	  }
	vec_free (s);
      }
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_memory_usage_command, static) = {
  .path = "show memory",
  .short_help = "show memory [api-segment][stats-segment][verbose]\n"
  "            [numa-heaps][map]",
  .function = show_memory_usage,
};
/* *INDENT-ON* */

static clib_error_t *
show_cpu (vlib_main_t * vm, unformat_input_t * input,
	  vlib_cli_command_t * cmd)
{
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
  _("Model name", "%U", format_cpu_model_name);
  _("Microarch model (family)", "%U", format_cpu_uarch);
  _("Flags", "%U", format_cpu_flags);
  _("Base frequency", "%.2f GHz",
    ((f64) vm->clib_time.clocks_per_second) * 1e-9);
#undef _
  return 0;
}

/*?
 * Displays various information about the CPU.
 *
 * @cliexpar
 * @cliexstart{show cpu}
 * Model name:               Intel(R) Xeon(R) CPU E5-2667 v4 @ 3.20GHz
 * Microarchitecture:        Broadwell (Broadwell-EP/EX)
 * Flags:                    sse3 ssse3 sse41 sse42 avx avx2 aes
 * Base Frequency:           3.20 GHz
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cpu_command, static) = {
  .path = "show cpu",
  .short_help = "Show cpu information",
  .function = show_cpu,
};
/* *INDENT-ON* */

static clib_error_t *
enable_disable_memory_trace (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  clib_mem_main_t *mm = &clib_mem_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  int enable = 1;
  int api_segment = 0;
  int stats_segment = 0;
  int main_heap = 0;
  u32 numa_id = ~0;
  void *oldheap;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_enable_disable, &enable))
	;
      else if (unformat (line_input, "api-segment"))
	api_segment = 1;
      else if (unformat (line_input, "stats-segment"))
	stats_segment = 1;
      else if (unformat (line_input, "main-heap"))
	main_heap = 1;
      else if (unformat (line_input, "numa-heap %d", &numa_id))
	;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "invalid input");
	}
    }
  unformat_free (line_input);

  if ((api_segment + stats_segment + main_heap + (enable == 0)
       + (numa_id != ~0)) == 0)
    {
      return clib_error_return
	(0, "Need one of main-heap, stats-segment, api-segment,\n"
	 "numa-heap <nn> or disable");
    }

  /* Turn off current trace, if any */
  if (current_traced_heap)
    {
      void *oldheap;
      oldheap = clib_mem_set_heap (current_traced_heap);
      clib_mem_trace (0);
      clib_mem_set_heap (oldheap);
      current_traced_heap = 0;
    }

  if (enable == 0)
    return 0;

  /* API segment */
  if (api_segment)
    {
      oldheap = vl_msg_push_heap ();
      current_traced_heap = clib_mem_get_heap ();
      clib_mem_trace (1);
      vl_msg_pop_heap (oldheap);

    }

  /* Stats segment */
  if (stats_segment)
    {
      oldheap = vlib_stats_push_heap (0);
      current_traced_heap = clib_mem_get_heap ();
      clib_mem_trace (stats_segment);
      /* We don't want to call vlib_stats_pop_heap... */
      if (oldheap)
	clib_mem_set_heap (oldheap);
    }

  /* main_heap */
  if (main_heap)
    {
      current_traced_heap = clib_mem_get_heap ();
      clib_mem_trace (main_heap);
    }

  if (numa_id != ~0)
    {
      if (numa_id >= ARRAY_LEN (mm->per_numa_mheaps))
	return clib_error_return (0, "Numa %d out of range", numa_id);
      if (mm->per_numa_mheaps[numa_id] == 0)
	return clib_error_return (0, "Numa %d heap not active", numa_id);

      if (mm->per_numa_mheaps[numa_id] == clib_mem_get_heap ())
	return clib_error_return (0, "Numa %d uses the main heap...",
				  numa_id);
      current_traced_heap = mm->per_numa_mheaps[numa_id];
      oldheap = clib_mem_set_heap (current_traced_heap);
      clib_mem_trace (1);
      clib_mem_set_heap (oldheap);
    }


  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_disable_memory_trace_command, static) = {
  .path = "memory-trace",
  .short_help = "memory-trace on|off [api-segment][stats-segment][main-heap]\n"
  "                   [numa-heap <numa-id>]\n",
  .function = enable_disable_memory_trace,
};
/* *INDENT-ON* */

static clib_error_t *
restart_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
		vlib_cli_command_t * cmd)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  clib_file_main_t *fm = &file_main;
  clib_file_t *f;

  /* environ(7) does not indicate a header for this */
  extern char **environ;

  /* Close all known open files */
  /* *INDENT-OFF* */
  pool_foreach (f, fm->file_pool)
     {
      if (f->file_descriptor > 2)
        close(f->file_descriptor);
    }
  /* *INDENT-ON* */

  /* Exec ourself */
  execve (vgm->name, (char **) vm->argv, environ);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (restart_cmd,static) = {
    .path = "restart",
    .short_help = "restart process",
    .function = restart_cmd_fn,
};
/* *INDENT-ON* */

#ifdef TEST_CODE
/*
 * A trivial test harness to verify the per-process output_function
 * is working correcty.
 */

static clib_error_t *
sleep_ten_seconds (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u16 i;
  u16 my_id = rand ();

  vlib_cli_output (vm, "Starting 10 seconds sleep with id %u\n", my_id);

  for (i = 0; i < 10; i++)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_cli_output (vm, "Iteration number %u, my id: %u\n", i, my_id);
    }
  vlib_cli_output (vm, "Done with sleep with id %u\n", my_id);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ping_command, static) = {
  .path = "test sleep",
  .function = sleep_ten_seconds,
  .short_help = "Sleep for 10 seconds",
};
/* *INDENT-ON* */
#endif /* ifdef TEST_CODE */

static uword
vlib_cli_normalize_path (char *input, char **result)
{
  char *i = input;
  char *s = 0;
  uword l = 0;
  uword index_of_last_space = ~0;

  while (*i != 0)
    {
      u8 c = *i++;
      /* Multiple white space -> single space. */
      switch (c)
	{
	case ' ':
	case '\t':
	case '\n':
	case '\r':
	  if (l > 0 && s[l - 1] != ' ')
	    {
	      vec_add1 (s, ' ');
	      l++;
	    }
	  break;

	default:
	  if (l > 0 && s[l - 1] == ' ')
	    index_of_last_space = vec_len (s);
	  vec_add1 (s, c);
	  l++;
	  break;
	}
    }

  /* Remove any extra space at end. */
  if (l > 0 && s[l - 1] == ' ')
    _vec_len (s) -= 1;

  *result = s;
  return index_of_last_space;
}

always_inline uword
parent_path_len (char *path)
{
  word i;
  for (i = vec_len (path) - 1; i >= 0; i--)
    {
      if (path[i] == ' ')
	return i;
    }
  return ~0;
}

static void
add_sub_command (vlib_cli_main_t * cm, uword parent_index, uword child_index)
{
  vlib_cli_command_t *p, *c;
  vlib_cli_sub_command_t *sub_c;
  u8 *sub_name;
  word i, l;

  p = vec_elt_at_index (cm->commands, parent_index);
  c = vec_elt_at_index (cm->commands, child_index);

  l = parent_path_len (c->path);
  if (l == ~0)
    sub_name = vec_dup ((u8 *) c->path);
  else
    {
      ASSERT (l + 1 < vec_len (c->path));
      sub_name = 0;
      vec_add (sub_name, c->path + l + 1, vec_len (c->path) - (l + 1));
    }

  if (sub_name[0] == '%')
    {
      uword *q;
      vlib_cli_sub_rule_t *sr;

      /* Remove %. */
      vec_delete (sub_name, 1, 0);

      if (!p->sub_rule_index_by_name)
	p->sub_rule_index_by_name = hash_create_vec ( /* initial length */ 32,
						     sizeof (sub_name[0]),
						     sizeof (uword));
      q = hash_get_mem (p->sub_rule_index_by_name, sub_name);
      if (q)
	{
	  sr = vec_elt_at_index (p->sub_rules, q[0]);
	  ASSERT (sr->command_index == child_index);
	  return;
	}

      hash_set_mem (p->sub_rule_index_by_name, sub_name,
		    vec_len (p->sub_rules));
      vec_add2 (p->sub_rules, sr, 1);
      sr->name = sub_name;
      sr->rule_index = sr - p->sub_rules;
      sr->command_index = child_index;
      return;
    }

  if (!p->sub_command_index_by_name)
    p->sub_command_index_by_name = hash_create_vec ( /* initial length */ 32,
						    sizeof (c->path[0]),
						    sizeof (uword));

  /* Check if sub-command has already been created. */
  if (hash_get_mem (p->sub_command_index_by_name, sub_name))
    {
      vec_free (sub_name);
      return;
    }

  vec_add2 (p->sub_commands, sub_c, 1);
  sub_c->index = child_index;
  sub_c->name = sub_name;
  hash_set_mem (p->sub_command_index_by_name, sub_c->name,
		sub_c - p->sub_commands);

  vec_validate (p->sub_command_positions, vec_len (sub_c->name) - 1);
  for (i = 0; i < vec_len (sub_c->name); i++)
    {
      int n;
      vlib_cli_parse_position_t *pos;

      pos = vec_elt_at_index (p->sub_command_positions, i);

      if (!pos->bitmaps)
	pos->min_char = sub_c->name[i];

      n = sub_c->name[i] - pos->min_char;
      if (n < 0)
	{
	  pos->min_char = sub_c->name[i];
	  vec_insert (pos->bitmaps, -n, 0);
	  n = 0;
	}

      vec_validate (pos->bitmaps, n);
      pos->bitmaps[n] =
	clib_bitmap_ori (pos->bitmaps[n], sub_c - p->sub_commands);
    }
}

static void
vlib_cli_make_parent (vlib_cli_main_t * cm, uword ci)
{
  uword p_len, pi, *p;
  char *p_path;
  vlib_cli_command_t *c, *parent;

  /* Root command (index 0) should have already been added. */
  ASSERT (vec_len (cm->commands) > 0);

  c = vec_elt_at_index (cm->commands, ci);
  p_len = parent_path_len (c->path);

  /* No space?  Parent is root command. */
  if (p_len == ~0)
    {
      add_sub_command (cm, 0, ci);
      return;
    }

  p_path = 0;
  vec_add (p_path, c->path, p_len);

  p = hash_get_mem (cm->command_index_by_path, p_path);

  /* Parent exists? */
  if (!p)
    {
      /* Parent does not exist; create it. */
      vec_add2 (cm->commands, parent, 1);
      parent->path = p_path;
      hash_set_mem (cm->command_index_by_path, parent->path,
		    parent - cm->commands);
      pi = parent - cm->commands;
    }
  else
    {
      pi = p[0];
      vec_free (p_path);
    }

  add_sub_command (cm, pi, ci);

  /* Create parent's parent. */
  if (!p)
    vlib_cli_make_parent (cm, pi);
}

always_inline uword
vlib_cli_command_is_empty (vlib_cli_command_t * c)
{
  return (c->long_help == 0 && c->short_help == 0 && c->function == 0);
}

clib_error_t *
vlib_cli_register (vlib_main_t * vm, vlib_cli_command_t * c)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_main_t *cm = &vgm->cli_main;
  clib_error_t *error = 0;
  uword ci, *p;
  char *normalized_path;

  if ((error = vlib_call_init_function (vm, vlib_cli_init)))
    return error;

  (void) vlib_cli_normalize_path (c->path, &normalized_path);

  if (!cm->command_index_by_path)
    cm->command_index_by_path = hash_create_vec ( /* initial length */ 32,
						 sizeof (c->path[0]),
						 sizeof (uword));

  /* See if command already exists with given path. */
  p = hash_get_mem (cm->command_index_by_path, normalized_path);
  if (p)
    {
      vlib_cli_command_t *d;

      ci = p[0];
      d = vec_elt_at_index (cm->commands, ci);

      /* If existing command was created via vlib_cli_make_parent
         replaced it with callers data. */
      if (vlib_cli_command_is_empty (d))
	{
	  vlib_cli_command_t save = d[0];

	  ASSERT (!vlib_cli_command_is_empty (c));

	  /* Copy callers fields. */
	  d[0] = c[0];

	  /* Save internal fields. */
	  d->path = save.path;
	  d->sub_commands = save.sub_commands;
	  d->sub_command_index_by_name = save.sub_command_index_by_name;
	  d->sub_command_positions = save.sub_command_positions;
	  d->sub_rules = save.sub_rules;
	}
      else
	error =
	  clib_error_return (0, "duplicate command name with path %v",
			     normalized_path);

      vec_free (normalized_path);
      if (error)
	return error;
    }
  else
    {
      /* Command does not exist: create it. */

      /* Add root command (index 0). */
      if (vec_len (cm->commands) == 0)
	{
	  /* Create command with index 0; path is empty string. */
	  vec_resize (cm->commands, 1);
	}

      ci = vec_len (cm->commands);
      hash_set_mem (cm->command_index_by_path, normalized_path, ci);
      vec_add1 (cm->commands, c[0]);

      c = vec_elt_at_index (cm->commands, ci);
      c->path = normalized_path;

      /* Don't inherit from registration. */
      c->sub_commands = 0;
      c->sub_command_index_by_name = 0;
      c->sub_command_positions = 0;
    }

  vlib_cli_make_parent (cm, ci);
  return 0;
}

#if 0
/* $$$ turn back on again someday, maybe */
clib_error_t *
vlib_cli_register_parse_rule (vlib_main_t * vm, vlib_cli_parse_rule_t * r_reg)
{
  vlib_cli_main_t *cm = &vm->cli_main;
  vlib_cli_parse_rule_t *r;
  clib_error_t *error = 0;
  u8 *r_name;
  uword *p;

  if (!cm->parse_rule_index_by_name)
    cm->parse_rule_index_by_name = hash_create_vec ( /* initial length */ 32,
						    sizeof (r->name[0]),
						    sizeof (uword));

  /* Make vector copy of name. */
  r_name = format (0, "%s", r_reg->name);

  if ((p = hash_get_mem (cm->parse_rule_index_by_name, r_name)))
    {
      vec_free (r_name);
      return clib_error_return (0, "duplicate parse rule name `%s'",
				r_reg->name);
    }

  vec_add2 (cm->parse_rules, r, 1);
  r[0] = r_reg[0];
  r->name = (char *) r_name;
  hash_set_mem (cm->parse_rule_index_by_name, r->name, r - cm->parse_rules);

  return error;
}

static clib_error_t *vlib_cli_register_parse_rules (vlib_main_t * vm,
						    vlib_cli_parse_rule_t *
						    lo,
						    vlib_cli_parse_rule_t *
						    hi)
  __attribute__ ((unused))
{
  clib_error_t *error = 0;
  vlib_cli_parse_rule_t *r;

  for (r = lo; r < hi; r = clib_elf_section_data_next (r, 0))
    {
      if (!r->name || strlen (r->name) == 0)
	{
	  error = clib_error_return (0, "parse rule with no name");
	  goto done;
	}

      error = vlib_cli_register_parse_rule (vm, r);
      if (error)
	goto done;
    }

done:
  return error;
}
#endif

static clib_error_t *
event_logger_trace_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int enable = 1;
  int api = 0, cli = 0, barrier = 0, dispatch = 0, circuit = 0;
  u32 circuit_node_index;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto print_status;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "api"))
	api = 1;
      else if (unformat (line_input, "dispatch"))
	dispatch = 1;
      else if (unformat (line_input, "circuit-node %U",
			 unformat_vlib_node, vm, &circuit_node_index))
	circuit = 1;
      else if (unformat (line_input, "cli"))
	cli = 1;
      else if (unformat (line_input, "barrier"))
	barrier = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else if (unformat (line_input, "enable"))
	enable = 1;
      else
	break;
    }
  unformat_free (line_input);

  vl_api_set_elog_trace_api_messages
    (api ? enable : vl_api_get_elog_trace_api_messages ());
  vm->elog_trace_cli_commands = cli ? enable : vm->elog_trace_cli_commands;
  vm->elog_trace_graph_dispatch = dispatch ?
    enable : vm->elog_trace_graph_dispatch;
  vm->elog_trace_graph_circuit = circuit ?
    enable : vm->elog_trace_graph_circuit;
  vlib_worker_threads->barrier_elog_enabled =
    barrier ? enable : vlib_worker_threads->barrier_elog_enabled;
  vm->elog_trace_graph_circuit_node_index = circuit_node_index;

  /*
   * Set up start-of-buffer logic-analyzer trigger
   * for main loop event logs, which are fairly heavyweight.
   * See src/vlib/main/vlib_elog_main_loop_event(...), which
   * will fully disable the scheme when the elog buffer fills.
   */
  if (dispatch || circuit)
    {
      elog_main_t *em = &vlib_global_main.elog_main;

      em->n_total_events_disable_limit =
	em->n_total_events + vec_len (em->event_ring);
    }


print_status:
  vlib_cli_output (vm, "Current status:");

  vlib_cli_output
    (vm, "    Event log API message trace: %s\n    CLI command trace: %s",
     vl_api_get_elog_trace_api_messages ()? "on" : "off",
     vm->elog_trace_cli_commands ? "on" : "off");
  vlib_cli_output
    (vm, "    Barrier sync trace: %s",
     vlib_worker_threads->barrier_elog_enabled ? "on" : "off");
  vlib_cli_output
    (vm, "    Graph Dispatch: %s",
     vm->elog_trace_graph_dispatch ? "on" : "off");
  vlib_cli_output
    (vm, "    Graph Circuit: %s",
     vm->elog_trace_graph_circuit ? "on" : "off");
  if (vm->elog_trace_graph_circuit)
    vlib_cli_output
      (vm, "                   node %U",
       format_vlib_node_name, vm, vm->elog_trace_graph_circuit_node_index);

  return 0;
}

/*?
 * Control event logging of api, cli, and thread barrier events
 * With no arguments, displays the current trace status.
 * Name the event groups you wish to trace or stop tracing.
 *
 * @cliexpar
 * @clistart
 * event-logger trace api cli barrier
 * event-logger trace api cli barrier disable
 * event-logger trace dispatch
 * event-logger trace circuit-node ethernet-input
 * @cliend
 * @cliexcmd{event-logger trace [api][cli][barrier][disable]}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (event_logger_trace_command, static) =
{
  .path = "event-logger trace",
  .short_help = "event-logger trace [api][cli][barrier][dispatch]\n"
  "[circuit-node <name> e.g. ethernet-input][disable]",
  .function = event_logger_trace_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
suspend_command_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_process_suspend (vm, 30e-3);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (suspend_command, static) =
{
  .path = "suspend",
  .short_help = "suspend debug CLI for 30ms",
  .function = suspend_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */


static int
sort_cmds_by_path (void *a1, void *a2)
{
  u32 *index1 = a1;
  u32 *index2 = a2;
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_main_t *cm = &vgm->cli_main;
  vlib_cli_command_t *c1, *c2;
  int i, lmin;

  c1 = vec_elt_at_index (cm->commands, *index1);
  c2 = vec_elt_at_index (cm->commands, *index2);

  lmin = vec_len (c1->path);
  lmin = (vec_len (c2->path) >= lmin) ? lmin : vec_len (c2->path);

  for (i = 0; i < lmin; i++)
    {
      if (c1->path[i] < c2->path[i])
	return -1;
      else if (c1->path[i] > c2->path[i])
	return 1;
    }

  return 0;
}

typedef struct
{
  vlib_cli_main_t *cm;
  u32 parent_command_index;
  int show_mp_safe;
  int show_not_mp_safe;
  int show_hit;
  int clear_hit;
} vlib_cli_walk_args_t;

static void
cli_recursive_walk (vlib_cli_walk_args_t * aa)
{
  vlib_cli_command_t *parent;
  vlib_cli_sub_command_t *sub;
  vlib_cli_walk_args_t _a, *a = &_a;
  vlib_cli_main_t *cm;
  int i;

  /* Copy args into this stack frame */
  *a = *aa;
  cm = a->cm;

  parent = vec_elt_at_index (cm->commands, a->parent_command_index);

  if (parent->function)
    {
      if (((a->show_mp_safe && parent->is_mp_safe)
	   || (a->show_not_mp_safe && !parent->is_mp_safe))
	  && (a->show_hit == 0 || parent->hit_counter))
	{
	  vec_add1 (cm->sort_vector, a->parent_command_index);
	}

      if (a->clear_hit)
	parent->hit_counter = 0;
    }

  for (i = 0; i < vec_len (parent->sub_commands); i++)
    {
      sub = vec_elt_at_index (parent->sub_commands, i);
      a->parent_command_index = sub->index;
      cli_recursive_walk (a);
    }
}

static u8 *
format_mp_safe (u8 * s, va_list * args)
{
  vlib_cli_main_t *cm = va_arg (*args, vlib_cli_main_t *);
  int show_mp_safe = va_arg (*args, int);
  int show_not_mp_safe = va_arg (*args, int);
  int show_hit = va_arg (*args, int);
  int clear_hit = va_arg (*args, int);
  vlib_cli_command_t *c;
  vlib_cli_walk_args_t _a, *a = &_a;
  int i;
  char *format_string = "\n%v";

  if (show_hit)
    format_string = "\n%v: %u";

  vec_reset_length (cm->sort_vector);

  a->cm = cm;
  a->parent_command_index = 0;
  a->show_mp_safe = show_mp_safe;
  a->show_not_mp_safe = show_not_mp_safe;
  a->show_hit = show_hit;
  a->clear_hit = clear_hit;

  cli_recursive_walk (a);

  vec_sort_with_function (cm->sort_vector, sort_cmds_by_path);

  for (i = 0; i < vec_len (cm->sort_vector); i++)
    {
      c = vec_elt_at_index (cm->commands, cm->sort_vector[i]);
      s = format (s, format_string, c->path, c->hit_counter);
    }

  return s;
}


static clib_error_t *
show_cli_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  int show_mp_safe = 0;
  int show_not_mp_safe = 0;
  int show_hit = 0;
  int clear_hit = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mp-safe"))
	show_mp_safe = 1;
      if (unformat (input, "not-mp-safe"))
	show_not_mp_safe = 1;
      else if (unformat (input, "hit"))
	show_hit = 1;
      else if (unformat (input, "clear-hit"))
	clear_hit = 1;
      else
	break;
    }

  /* default set: all cli commands */
  if (clear_hit == 0 && (show_mp_safe + show_not_mp_safe) == 0)
    show_mp_safe = show_not_mp_safe = 1;

  vlib_cli_output (vm, "%U", format_mp_safe, &vgm->cli_main, show_mp_safe,
		   show_not_mp_safe, show_hit, clear_hit);
  if (clear_hit)
    vlib_cli_output (vm, "hit counters cleared...");

  return 0;
}

/*?
 * Displays debug cli command information
 *
 * @cliexpar
 * @cliexstart{show cli [mp-safe][not-mp-safe][hit][clear-hit]}
 *
 * "show cli" displays the entire debug cli:
 *
 * abf attach
 * abf policy
 * adjacency counters
 * api trace
 * app ns
 * bfd key del
 * ... and so on ...
 *
 * "show cli mp-safe" displays mp-safe debug CLI commands:
 *
 * abf policy
 * binary-api
 * create vhost-user
 * exec
 * ip container
 * ip mroute
 * ip probe-neighbor
 * ip route
 * ip scan-neighbor
 * ip table
 * ip6 table
 *
 * "show cli not-mp-safe" displays debug CLI commands
 * which cause worker thread barrier synchronization
 *
 * "show cli hit" displays commands which have been executed. Qualify
 * as desired with "mp-safe" or "not-mp-safe".
 *
 * "show cli clear-hit" clears the per-command hit counters.
 * @cliexend
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cli_command, static) =
{
  .path = "show cli",
  .short_help = "show cli [mp-safe][not-mp-safe][hit][clear-hit]",
  .function = show_cli_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
vlib_cli_init (vlib_main_t * vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_main_t *cm = &vgm->cli_main;
  clib_error_t *error = 0;
  vlib_cli_command_t *cmd;

  cmd = cm->cli_command_registrations;

  while (cmd)
    {
      error = vlib_cli_register (vm, cmd);
      if (error)
	return error;
      cmd = cmd->next_cli_command;
    }

  cm->log = vlib_log_register_class_rate_limit (
    "cli", "log", 0x7FFFFFFF /* aka no rate limit */);
  return error;
}

VLIB_INIT_FUNCTION (vlib_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
