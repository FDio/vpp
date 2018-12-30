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
#include <vppinfra/cpu.h>
#include <vppinfra/elog.h>
#include <unistd.h>
#include <ctype.h>

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
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_cli_command_t *c = va_arg (*args, vlib_cli_command_t *);
  vlib_cli_command_t **result = va_arg (*args, vlib_cli_command_t **);
  vlib_cli_main_t *cm = &vm->cli_main;
  uword *match_bitmap, is_unique, index;

  {
    vlib_cli_sub_rule_t *sr;
    vlib_cli_parse_rule_t *r;
    vec_foreach (sr, c->sub_rules)
    {
      void **d;
      r = vec_elt_at_index (cm->parse_rules, sr->rule_index);
      vec_add2 (cm->parse_rule_data, d, 1);
      vec_reset_length (d[0]);
      if (r->data_size)
	d[0] = _vec_resize (d[0],
			    /* length increment */ 1,
			    r->data_size,
			    /* header_bytes */ 0,
			    /* data align */ sizeof (uword));
      if (unformat_user (i, r->unformat_function, vm, d[0]))
	{
	  *result = vec_elt_at_index (cm->commands, sr->command_index);
	  return 1;
	}
    }
  }

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
  vlib_main_t *vm = vlib_get_main ();
  vlib_cli_main_t *vcm = &vm->cli_main;
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
  clib_bitmap_foreach(index, match_bitmap, {
    if (help_next_level && is_unique) {
	c = get_sub_command (vcm, c, index);
	vec_foreach (sc, c->sub_commands) {
	  vec_add1 (result, (u8*) sc->name);
	}
	goto done; /* break doesn't work in this macro-loop */
    }
    sc = &c->sub_commands[index];
    vec_add1(result, (u8*) sc->name);
  });
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
format_vlib_cli_parse_rule_name (u8 * s, va_list * args)
{
  vlib_cli_parse_rule_t *r = va_arg (*args, vlib_cli_parse_rule_t *);
  return format (s, "<%U>", format_c_identifier, r->name);
}

static u8 *
format_vlib_cli_path (u8 * s, va_list * args)
{
  u8 *path = va_arg (*args, u8 *);
  int i, in_rule;
  in_rule = 0;
  for (i = 0; i < vec_len (path); i++)
    {
      switch (path[i])
	{
	case '%':
	  in_rule = 1;
	  vec_add1 (s, '<');	/* start of <RULE> */
	  break;

	case '_':
	  /* _ -> space in rules. */
	  vec_add1 (s, in_rule ? ' ' : '_');
	  break;

	case ' ':
	  if (in_rule)
	    {
	      vec_add1 (s, '>');	/* end of <RULE> */
	      in_rule = 0;
	    }
	  vec_add1 (s, ' ');
	  break;

	default:
	  vec_add1 (s, path[i]);
	  break;
	}
    }

  if (in_rule)
    vec_add1 (s, '>');		/* terminate <RULE> */

  return s;
}

static vlib_cli_command_t *
all_subs (vlib_cli_main_t * cm, vlib_cli_command_t * subs, u32 command_index)
{
  vlib_cli_command_t *c = vec_elt_at_index (cm->commands, command_index);
  vlib_cli_sub_command_t *sc;
  vlib_cli_sub_rule_t *sr;

  if (c->function)
    vec_add1 (subs, c[0]);

  vec_foreach (sr, c->sub_rules)
    subs = all_subs (cm, subs, sr->command_index);
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
  vlib_cli_command_t *parent, *c;
  clib_error_t *error = 0;
  unformat_input_t sub_input;
  u8 *string;
  uword is_main_dispatch = cm == &vm->cli_main;

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

      else if (vec_len (c->sub_commands) + vec_len (c->sub_rules) == 0)
	vlib_cli_output (vm, "%v: no sub-commands", c->path);

      else
	{
	  vlib_cli_sub_command_t *sc;
	  vlib_cli_sub_rule_t *sr, *subs;

	  subs = vec_dup (c->sub_rules);

	  /* Add in rules if any. */
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
	      vlib_cli_parse_rule_t *r;

	      d = vec_elt_at_index (cm->commands, subs[i].command_index);
	      r =
		subs[i].rule_index != ~0 ? vec_elt_at_index (cm->parse_rules,
							     subs
							     [i].rule_index) :
		0;

	      if (r)
		vlib_cli_output
		  (vm, "  %-30U %U",
		   format_vlib_cli_parse_rule_name, r,
		   format_vlib_cli_command_help, d, /* is_long */ 0);
	      else
		vlib_cli_output
		  (vm, "  %-30v %U",
		   subs[i].name,
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

  else if (unformat (input, "uncomment %U",
		     unformat_vlib_cli_sub_input, &sub_input))
    {
      error =
	vlib_cli_dispatch_sub_commands (vm, cm, &sub_input,
					parent_command_index);
      unformat_free (&sub_input);
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
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->c = elog_global_id_for_msg_name (c->path);
		}

	      if (!c->is_mp_safe)
		vlib_worker_thread_barrier_sync (vm);

	      c_error = c->function (vm, si, c);

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
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->c = elog_global_id_for_msg_name (c->path);
		  if (c_error)
		    {
		      vec_add1 (c_error->what, 0);
		      ed->err = elog_global_id_for_msg_name
			((const char *) c_error->what);
		      _vec_len (c_error->what) -= 1;
		    }
		  else
		    ed->err = elog_global_id_for_msg_name ("OK");
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
void
vlib_cli_input (vlib_main_t * vm,
		unformat_input_t * input,
		vlib_cli_output_function_t * function, uword function_arg)
{
  vlib_process_t *cp = vlib_get_current_process (vm);
  vlib_cli_main_t *cm = &vm->cli_main;
  clib_error_t *error;
  vlib_cli_output_function_t *save_function;
  uword save_function_arg;

  save_function = cp->output_function;
  save_function_arg = cp->output_function_arg;

  cp->output_function = function;
  cp->output_function_arg = function_arg;

  do
    {
      vec_reset_length (cm->parse_rule_data);
      error = vlib_cli_dispatch_sub_commands (vm, &vm->cli_main, input,	/* parent */
					      0);
    }
  while (!error && !unformat (input, "%U", unformat_eof));

  if (error)
    {
      vlib_cli_output (vm, "%v", error->what);
      vlib_unix_error_report (vm, error);
      clib_error_free (error);
    }

  cp->output_function = save_function;
  cp->output_function_arg = save_function_arg;
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
void vl_msg_pop_heap (void *oldheap) __attribute__ ((weak));

static clib_error_t *
show_memory_usage (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int verbose __attribute__ ((unused)) = 0, api_segment = 0;
  clib_error_t *error;
  u32 index = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "api-segment"))
	api_segment = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  return error;
	}
    }

  if (api_segment)
    {
      void *oldheap = vl_msg_push_heap ();
      u8 *s_in_svm =
	format (0, "%U\n", format_mheap, clib_mem_get_heap (), 1);
      vl_msg_pop_heap (oldheap);
      u8 *s = vec_dup (s_in_svm);

      oldheap = vl_msg_push_heap ();
      vec_free (s_in_svm);
      vl_msg_pop_heap (oldheap);
      vlib_cli_output (vm, "API segment start:");
      vlib_cli_output (vm, "%v", s);
      vlib_cli_output (vm, "API segment end:");
      vec_free (s);
    }

#if USE_DLMALLOC == 0
  /* *INDENT-OFF* */
  foreach_vlib_main (
  ({
      mheap_t *h = mheap_header (clib_per_cpu_mheaps[index]);
      vlib_cli_output (vm, "%sThread %d %s\n", index ? "\n":"", index,
		       vlib_worker_threads[index].name);
      vlib_cli_output (vm, "  %U\n", format_page_map, pointer_to_uword (h) -
		       h->vm_alloc_offset_from_header,
		       h->vm_alloc_size);
      vlib_cli_output (vm, "  %U\n", format_mheap, clib_per_cpu_mheaps[index],
                       verbose);
      index++;
  }));
  /* *INDENT-ON* */
#else
  {
    uword clib_mem_trace_enable_disable (uword enable);
    uword was_enabled;

    /*
     * Note: the foreach_vlib_main cause allocator traffic,
     * so shut off tracing before we go there...
     */
    was_enabled = clib_mem_trace_enable_disable (0);

    /* *INDENT-OFF* */
    foreach_vlib_main (
    ({
      struct dlmallinfo mi;
      void *mspace;
      mspace = clib_per_cpu_mheaps[index];

      mi = mspace_mallinfo (mspace);
      vlib_cli_output (vm, "%sThread %d %s\n", index ? "\n":"", index,
		       vlib_worker_threads[index].name);
      vlib_cli_output (vm, "  %U\n", format_page_map,
                       pointer_to_uword (mspace_least_addr(mspace)),
                       mi.arena);
      vlib_cli_output (vm, "  %U\n", format_mheap, clib_per_cpu_mheaps[index],
                       verbose);
      index++;
    }));
    /* *INDENT-ON* */

    /* Restore the trace flag */
    clib_mem_trace_enable_disable (was_enabled);
  }
#endif /* USE_DLMALLOC */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_memory_usage_command, static) = {
  .path = "show memory",
  .short_help = "[verbose | api-segment] Show current memory usage",
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
  unformat_input_t _line_input, *line_input = &_line_input;
  int enable;
  int api_segment = 0;
  void *oldheap;


  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_enable_disable, &enable))
	;
      else if (unformat (line_input, "api-segment"))
	api_segment = 1;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "invalid input");
	}
    }
  unformat_free (line_input);

  if (api_segment)
    oldheap = vl_msg_push_heap ();
  clib_mem_trace (enable);
  if (api_segment)
    vl_msg_pop_heap (oldheap);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_disable_memory_trace_command, static) = {
  .path = "memory-trace",
  .short_help = "on|off [api-segment] Enable/disable memory allocation trace",
  .function = enable_disable_memory_trace,
};
/* *INDENT-ON* */


static clib_error_t *
test_heap_validate (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
#if USE_DLMALLOC == 0
  clib_error_t *error = 0;
  void *heap;
  mheap_t *mheap;

  if (unformat (input, "on"))
    {
        /* *INDENT-OFF* */
        foreach_vlib_main({
          heap = clib_per_cpu_mheaps[this_vlib_main->thread_index];
          mheap = mheap_header(heap);
          mheap->flags |= MHEAP_FLAG_VALIDATE;
          // Turn off small object cache because it delays detection of errors
          mheap->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
        });
        /* *INDENT-ON* */

    }
  else if (unformat (input, "off"))
    {
        /* *INDENT-OFF* */
        foreach_vlib_main({
          heap = clib_per_cpu_mheaps[this_vlib_main->thread_index];
          mheap = mheap_header(heap);
          mheap->flags &= ~MHEAP_FLAG_VALIDATE;
          mheap->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
        });
        /* *INDENT-ON* */
    }
  else if (unformat (input, "now"))
    {
        /* *INDENT-OFF* */
        foreach_vlib_main({
          heap = clib_per_cpu_mheaps[this_vlib_main->thread_index];
          mheap = mheap_header(heap);
          mheap_validate(heap);
        });
        /* *INDENT-ON* */
      vlib_cli_output (vm, "heap validation complete");

    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  return error;
#else
  return clib_error_return (0, "unimplemented...");
#endif /* USE_DLMALLOC */
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_heap_validate,static) = {
    .path = "test heap-validate",
    .short_help = "<on/off/now> validate heap on future allocs/frees or right now",
    .function = test_heap_validate,
};
/* *INDENT-ON* */

static clib_error_t *
restart_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
		vlib_cli_command_t * cmd)
{
  clib_file_main_t *fm = &file_main;
  clib_file_t *f;

  /* environ(7) does not indicate a header for this */
  extern char **environ;

  /* Close all known open files */
  /* *INDENT-OFF* */
  pool_foreach(f, fm->file_pool,
    ({
      if (f->file_descriptor > 2)
        close(f->file_descriptor);
    }));
  /* *INDENT-ON* */

  /* Exec ourself */
  execve (vm->name, (char **) vm->argv, environ);

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

      q = hash_get_mem (cm->parse_rule_index_by_name, sub_name);
      if (!q)
	{
	  clib_error ("reference to unknown rule `%%%v' in path `%v'",
		      sub_name, c->path);
	  return;
	}

      hash_set_mem (p->sub_rule_index_by_name, sub_name,
		    vec_len (p->sub_rules));
      vec_add2 (p->sub_rules, sr, 1);
      sr->name = sub_name;
      sr->rule_index = q[0];
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
  vlib_cli_main_t *cm = &vm->cli_main;
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

#if 0
/* $$$ turn back on again someday, maybe */
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

static int
cli_path_compare (void *a1, void *a2)
{
  u8 **s1 = a1;
  u8 **s2 = a2;

  if ((vec_len (*s1) < vec_len (*s2)) &&
      memcmp ((char *) *s1, (char *) *s2, vec_len (*s1)) == 0)
    return -1;


  if ((vec_len (*s1) > vec_len (*s2)) &&
      memcmp ((char *) *s1, (char *) *s2, vec_len (*s2)) == 0)
    return 1;

  return vec_cmp (*s1, *s2);
}

static clib_error_t *
show_cli_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  vlib_cli_main_t *cm = &vm->cli_main;
  vlib_cli_command_t *cli;
  u8 **paths = 0, **s;

  /* *INDENT-OFF* */
  vec_foreach (cli, cm->commands)
    if (vec_len (cli->path) > 0)
      vec_add1 (paths, (u8 *) cli->path);

  vec_sort_with_function (paths, cli_path_compare);

  vec_foreach (s, paths)
    vlib_cli_output (vm, "%v", *s);
  /* *INDENT-ON* */

  vec_free (paths);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cli_command, static) = {
  .path = "show cli",
  .short_help = "Show cli commands",
  .function = show_cli_cmd_fn,
};
/* *INDENT-ON* */

static clib_error_t *
elog_trace_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int enable = 1;
  int api = 0, cli = 0, barrier = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto print_status;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "api"))
	api = 1;
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

  vm->elog_trace_api_messages = api ? enable : vm->elog_trace_api_messages;
  vm->elog_trace_cli_commands = cli ? enable : vm->elog_trace_cli_commands;
  vlib_worker_threads->barrier_elog_enabled =
    barrier ? enable : vlib_worker_threads->barrier_elog_enabled;

print_status:
  vlib_cli_output (vm, "Current status:");

  vlib_cli_output
    (vm, "    Event log API message trace: %s\n    CLI command trace: %s",
     vm->elog_trace_api_messages ? "on" : "off",
     vm->elog_trace_cli_commands ? "on" : "off");
  vlib_cli_output
    (vm, "    Barrier sync trace: %s",
     vlib_worker_threads->barrier_elog_enabled ? "on" : "off");

  return 0;
}

/*?
 * Control event logging of api, cli, and thread barrier events
 * With no arguments, displays the current trace status.
 * Name the event groups you wish to trace or stop tracing.
 *
 * @cliexpar
 * @clistart
 * elog trace api cli barrier
 * elog trace api cli barrier disable
 * elog trace
 * @cliend
 * @cliexcmd{elog trace [api][cli][barrier][disable]}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (elog_trace_command, static) =
{
  .path = "elog trace",
  .short_help = "elog trace [api][cli][barrier][disable]",
  .function = elog_trace_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vlib_cli_init (vlib_main_t * vm)
{
  vlib_cli_main_t *cm = &vm->cli_main;
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
