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
 * init.c: mechanism for functions to be called at init/exit.
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
#include <vppinfra/ptclosure.h>

/**
 * @file
 * @brief Init function ordering and execution implementation
 * Topological sort for all classes of init functions, and
 * a relatively simple API routine to invoke them.
 */

/*? %%clicmd:group_label Init functions %% ?*/

static int
comma_split (u8 * s, u8 ** a, u8 ** b)
{
  *a = s;

  while (*s && *s != ',')
    s++;

  if (*s == ',')
    *s = 0;
  else
    return 1;

  *b = (u8 *) (s + 1);
  return 0;
}

/**
 * @brief Topological sorter for init function chains.
 * @param head [in/out] address of the listhead to be sorted
 * @returns 0 on success, otherwise a clib_error_t *.
 */

clib_error_t *vlib_sort_init_exit_functions
  (_vlib_init_function_list_elt_t ** head)
{
  uword *index_by_name;
  uword *reg_by_index;
  u8 **init_f_names = 0;
  u8 *init_f_name;
  char **these_constraints;
  char *this_constraint_c;
  u8 **constraints = 0;
  u8 *constraint_tuple;
  u8 *this_constraint;
  char *prev_name;
  u8 **orig, **closure;
  uword *p;
  int i, j, k;
  u8 *a_name, *b_name;
  int a_index, b_index;
  int n_init_fns;
  u32 *result = 0;
  _vlib_init_function_list_elt_t *this_reg = 0;
  hash_pair_t *hp;
  u8 **keys_to_delete = 0;

  /*
   * two hash tables: name to index in init_f_names, and
   * init function registration pointer by index
   */
  index_by_name = hash_create_string (0, sizeof (uword));
  reg_by_index = hash_create (0, sizeof (uword));

  this_reg = *head;

  /* pass 1, collect init fcn names, construct a before b pairs */
  while (this_reg)
    {
      init_f_name = format (0, "%s%c", this_reg->name, 0);
      hash_set (reg_by_index, vec_len (init_f_names), (uword) this_reg);

      hash_set_mem (index_by_name, init_f_name, vec_len (init_f_names));

      vec_add1 (init_f_names, init_f_name);

      these_constraints = this_reg->runs_before;
      while (these_constraints && these_constraints[0])
	{
	  this_constraint_c = these_constraints[0];

	  constraint_tuple = format (0, "%s,%s%c", init_f_name,
				     this_constraint_c, 0);
	  vec_add1 (constraints, constraint_tuple);
	  these_constraints++;
	}

      these_constraints = this_reg->runs_after;
      while (these_constraints && these_constraints[0])
	{
	  this_constraint_c = these_constraints[0];

	  constraint_tuple = format (0, "%s,%s%c",
				     this_constraint_c, init_f_name, 0);
	  vec_add1 (constraints, constraint_tuple);
	  these_constraints++;
	}

      this_reg = this_reg->next_init_function;
    }

  /*
   * pass 2: collect "a then b then c then d" constraints.
   * all init fcns must be known at this point.
   */
  this_reg = *head;
  while (this_reg)
    {
      these_constraints = this_reg->init_order;

      prev_name = 0;
      /* Across the list of constraints */
      while (these_constraints && these_constraints[0])
	{
	  this_constraint_c = these_constraints[0];
	  p = hash_get_mem (index_by_name, this_constraint_c);
	  if (p == 0)
	    {
	      clib_warning
		("order constraint fcn '%s' not found", this_constraint_c);
	      these_constraints++;
	      continue;
	    }

	  if (prev_name == 0)
	    {
	      prev_name = this_constraint_c;
	      these_constraints++;
	      continue;
	    }

	  constraint_tuple = format (0, "%s,%s%c", prev_name,
				     this_constraint_c, 0);
	  vec_add1 (constraints, constraint_tuple);
	  prev_name = this_constraint_c;
	  these_constraints++;
	}
      this_reg = this_reg->next_init_function;
    }

  n_init_fns = vec_len (init_f_names);
  orig = clib_ptclosure_alloc (n_init_fns);

  for (i = 0; i < vec_len (constraints); i++)
    {
      this_constraint = constraints[i];

      if (comma_split (this_constraint, &a_name, &b_name))
	return clib_error_return (0, "comma_split failed!");

      p = hash_get_mem (index_by_name, a_name);
      /*
       * Note: the next two errors mean that something is
       * b0rked. As in: if you code "A runs before on B," and you type
       * B incorrectly, you lose. Nonexistent init functions are tolerated.
       */
      if (p == 0)
	{
	  clib_warning ("init function '%s' not found (before '%s')",
			a_name, b_name);
	  continue;
	}
      a_index = p[0];

      p = hash_get_mem (index_by_name, b_name);
      if (p == 0)
	{
	  clib_warning ("init function '%s' not found (after '%s')",
			b_name, a_name);
	  continue;
	}
      b_index = p[0];

      /* add a before b to the original set of constraints */
      orig[a_index][b_index] = 1;
      vec_free (this_constraint);
    }

  /* Compute the positive transitive closure of the original constraints */
  closure = clib_ptclosure (orig);

  /* Compute a partial order across feature nodes, if one exists. */
again:
  for (i = 0; i < n_init_fns; i++)
    {
      for (j = 0; j < n_init_fns; j++)
	{
	  if (closure[i][j])
	    goto item_constrained;
	}
      /* Item i can be output */
      vec_add1 (result, i);
      {
	for (k = 0; k < n_init_fns; k++)
	  closure[k][i] = 0;
	/*
	 * Add a "Magic" a before a constraint.
	 * This means we'll never output it again
	 */
	closure[i][i] = 1;
	goto again;
      }
    item_constrained:
      ;
    }

  /* see if we got a partial order... */
  if (vec_len (result) != n_init_fns)
    return clib_error_return
      (0, "Failed to find a suitable init function order!");

  /*
   * We win.
   * Bind the index variables, and output the feature node name vector
   * using the partial order we just computed. Result is in stack
   * order, because the entry with the fewest constraints (e.g. none)
   * is output first, etc.
   * Reset the listhead, and add items in result (aka reverse) order.
   */
  *head = 0;
  for (i = 0; i < n_init_fns; i++)
    {
      p = hash_get (reg_by_index, result[i]);
      ASSERT (p != 0);
      this_reg = (_vlib_init_function_list_elt_t *) p[0];

      this_reg->next_init_function = *head;
      *head = this_reg;
    }

  /* Finally, clean up all the fine data we allocated */
  /* *INDENT-OFF* */
  hash_foreach_pair (hp, index_by_name,
  ({
    vec_add1 (keys_to_delete, (u8 *)hp->key);
  }));
  /* *INDENT-ON* */
  hash_free (index_by_name);
  for (i = 0; i < vec_len (keys_to_delete); i++)
    vec_free (keys_to_delete[i]);
  vec_free (keys_to_delete);
  hash_free (reg_by_index);
  vec_free (result);
  clib_ptclosure_free (orig);
  clib_ptclosure_free (closure);
  return 0;
}

/**
 * @brief call a set of init / exit / main-loop enter functions
 * @param vm vlib_main_t
 * @param head address of the listhead to sort and then invoke
 * @returns 0 on success, clib_error_t * on error
 *
 * The "init_functions_called" hash supports a subtle mix of procedural
 * and formally-specified ordering constraints. The following schemes
 * are *roughly* equivalent:
 *
 * static clib_error_t *init_runs_first (vlib_main_t *vm)
 * {
 *    clib_error_t *error;
 *
 *    ... do some stuff...
 *
 *    if ((error = vlib_call_init_function (init_runs_next)))
 *      return error;
 *    ...
 * }
 * VLIB_INIT_FUNCTION (init_runs_first);
 *
 * and
 *
 * static clib_error_t *init_runs_first (vlib_main_t *vm)
 * {
 *    ... do some stuff...
 * }
 * VLIB_INIT_FUNCTION (init_runs_first) =
 * {
 *     .runs_before = VLIB_INITS("init_runs_next"),
 * };
 *
 * The first form will [most likely] call "init_runs_next" on the
 * spot. The second form means that "init_runs_first" runs before
 * "init_runs_next," possibly much earlier in the sequence.
 *
 * Please DO NOT construct sets of init functions where A before B
 * actually means A *right before* B. It's not necessary - simply combine
 * A and B - and it leads to hugely annoying debugging exercises.
 */

static inline clib_error_t *
call_init_exit_functions_internal (vlib_main_t *vm,
				   _vlib_init_function_list_elt_t **headp,
				   int call_once, int do_sort, int is_global)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  clib_error_t *error = 0;
  _vlib_init_function_list_elt_t *i;

  if (do_sort && (error = vlib_sort_init_exit_functions (headp)))
    return (error);

  i = *headp;
  while (i)
    {
      uword *h;

      if (is_global)
	h = hash_get (vgm->init_functions_called, i->f);
      else
	h = hash_get (vm->worker_init_functions_called, i->f);

      if (call_once && !h)
	{
	  if (call_once)
	    {
	      if (is_global)
		hash_set1 (vgm->init_functions_called, i->f);
	      else
		hash_set1 (vm->worker_init_functions_called, i->f);
	    }
	  error = i->f (vm);
	  if (error)
	    return error;
	}
      i = i->next_init_function;
    }
  return error;
}

clib_error_t *
vlib_call_init_exit_functions (vlib_main_t *vm,
			       _vlib_init_function_list_elt_t **headp,
			       int call_once, int is_global)
{
  return call_init_exit_functions_internal (vm, headp, call_once,
					    1 /* do_sort */, is_global);
}

clib_error_t *
vlib_call_init_exit_functions_no_sort (vlib_main_t *vm,
				       _vlib_init_function_list_elt_t **headp,
				       int call_once, int is_global)
{
  return call_init_exit_functions_internal (vm, headp, call_once,
					    0 /* do_sort */, is_global);
}

clib_error_t *
vlib_call_all_init_functions (vlib_main_t * vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  /* Call placeholder functions to make sure purely static modules are
     linked in. */
#define _(f) vlib_##f##_reference ();
  foreach_vlib_module_reference;
#undef _

  return vlib_call_init_exit_functions (vm, &vgm->init_function_registrations,
					1 /* call_once */, 1 /* is_global */);
}

clib_error_t *
vlib_call_all_main_loop_enter_functions (vlib_main_t * vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  return vlib_call_init_exit_functions (
    vm, &vgm->main_loop_enter_function_registrations, 1 /* call_once */,
    1 /* is_global */);
}

clib_error_t *
vlib_call_all_main_loop_exit_functions (vlib_main_t * vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  return vlib_call_init_exit_functions (
    vm, &vgm->main_loop_exit_function_registrations, 1 /* call_once */,
    1 /* is_global */);
}

clib_error_t *
vlib_call_all_config_functions (vlib_main_t * vm,
				unformat_input_t * input, int is_early)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  clib_error_t *error = 0;
  vlib_config_function_runtime_t *c, **all;
  uword *hash = 0, *p;
  uword i;

  hash = hash_create_string (0, sizeof (uword));
  all = 0;

  c = vgm->config_function_registrations;

  while (c)
    {
      hash_set_mem (hash, c->name, vec_len (all));
      vec_add1 (all, c);
      unformat_init (&c->input, 0, 0);
      c = c->next_registration;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u8 *s, *v;

      if (!unformat (input, "%s %v", &s, &v) || !(p = hash_get_mem (hash, s)))
	{
	  error = clib_error_create ("unknown input `%s %v'", s, v);
	  goto done;
	}

      c = all[p[0]];
      if (vec_len (c->input.buffer) > 0)
	vec_add1 (c->input.buffer, ' ');
      vec_add (c->input.buffer, v, vec_len (v));
      vec_free (v);
      vec_free (s);
    }

  for (i = 0; i < vec_len (all); i++)
    {
      c = all[i];

      /* Is this an early config? Are we doing early configs? */
      if (is_early ^ c->is_early)
	continue;

      /* Already called? */
      if (hash_get (vgm->init_functions_called, c->function))
	continue;
      hash_set1 (vgm->init_functions_called, c->function);

      error = c->function (vm, &c->input);
      if (error)
	goto done;
    }

done:
  for (i = 0; i < vec_len (all); i++)
    {
      c = all[i];
      unformat_free (&c->input);
    }
  vec_free (all);
  hash_free (hash);
  return error;
}

void
vlib_init_dump (void)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  int i = 0;

  _vlib_init_function_list_elt_t *head, *this;
  head = vgm->init_function_registrations;

  this = head;
  while (this)
    {
      fformat (stdout, "[%d]: %s\n", i++, this->name);
      this = this->next_init_function;
    }
}

static clib_error_t *
show_init_function_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  int which = 1;
  int verbose = 0;
  int i, n_init_fns;
  _vlib_init_function_list_elt_t *head, *this;
  uword *index_by_name;
  uword *reg_by_index;
  u8 **init_f_names = 0;
  u8 *init_f_name;
  uword *p;
  _vlib_init_function_list_elt_t *this_reg = 0;
  hash_pair_t *hp;
  u8 **keys_to_delete = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "init"))
	which = 1;
      else if (unformat (input, "enter"))
	which = 2;
      else if (unformat (input, "exit"))
	which = 3;
      else if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
    }

  switch (which)
    {
    case 1:
      head = vgm->init_function_registrations;
      break;
    case 2:
      head = vgm->main_loop_enter_function_registrations;
      break;
    case 3:
      head = vgm->main_loop_exit_function_registrations;
      break;
    default:
      return clib_error_return (0, "BUG");
    }

  if (verbose == 0)
    {
      this = head;
      i = 0;
      while (this)
	{
	  vlib_cli_output (vm, "[%d]: %s", i++, this->name);
	  this = this->next_init_function;
	}
      return 0;
    }

  index_by_name = hash_create_string (0, sizeof (uword));
  reg_by_index = hash_create (0, sizeof (uword));

  this_reg = head;
  n_init_fns = 0;
  /* collect init fcn names */
  while (this_reg)
    {
      init_f_name = format (0, "%s%c", this_reg->name, 0);
      hash_set (reg_by_index, vec_len (init_f_names), (uword) this_reg);

      hash_set_mem (index_by_name, init_f_name, vec_len (init_f_names));
      vec_add1 (init_f_names, init_f_name);
      n_init_fns++;
      this_reg = this_reg->next_init_function;
    }

  for (i = 0; i < n_init_fns; i++)
    {
      p = hash_get (reg_by_index, i);
      ASSERT (p != 0);
      this_reg = (_vlib_init_function_list_elt_t *) p[0];
      vlib_cli_output (vm, "[%d] %s", i, this_reg->name);
      {
	char **runs_before, **runs_after, **init_order;
	runs_before = this_reg->runs_before;
	while (runs_before && runs_before[0])
	  {
	    _vlib_init_function_list_elt_t *successor;
	    uword successor_index;
	    p = hash_get_mem (index_by_name, runs_before[0]);
	    if (p == 0)
	      {
		clib_warning ("couldn't find successor '%s'", runs_before[0]);
		runs_before++;
		continue;
	      }
	    successor_index = p[0];
	    p = hash_get (reg_by_index, p[0]);
	    ASSERT (p != 0);
	    successor = (_vlib_init_function_list_elt_t *) p[0];
	    vlib_cli_output (vm, "  before '%s' [%lld]",
			     successor->name, successor_index);
	    runs_before++;
	  }
	runs_after = this_reg->runs_after;
	while (runs_after && runs_after[0])
	  {
	    _vlib_init_function_list_elt_t *predecessor;
	    uword predecessor_index;
	    p = hash_get_mem (index_by_name, runs_after[0]);
	    if (p == 0)
	      {
		clib_warning ("couldn't find predecessor '%s'",
			      runs_after[0]);
		runs_after++;
		continue;
	      }
	    predecessor_index = p[0];
	    p = hash_get (reg_by_index, p[0]);
	    ASSERT (p != 0);
	    predecessor = (_vlib_init_function_list_elt_t *) p[0];
	    vlib_cli_output (vm, "  after '%s' [%lld]",
			     predecessor->name, predecessor_index);
	    runs_after++;
	  }
	init_order = this_reg->init_order;
	while (init_order && init_order[0])
	  {
	    _vlib_init_function_list_elt_t *inorder;
	    uword inorder_index;
	    p = hash_get_mem (index_by_name, init_order[0]);
	    if (p == 0)
	      {
		clib_warning ("couldn't find order element'%s'",
			      init_order[0]);
		init_order++;
		continue;
	      }
	    inorder_index = p[0];
	    p = hash_get (reg_by_index, p[0]);
	    ASSERT (p != 0);
	    inorder = (_vlib_init_function_list_elt_t *) p[0];
	    vlib_cli_output (vm, "  in order '%s' [%lld]",
			     inorder->name, inorder_index);
	    init_order++;
	  }
      }
    }
  /* *INDENT-OFF* */
  hash_foreach_pair (hp, index_by_name,
  ({
    vec_add1 (keys_to_delete, (u8 *)hp->key);
  }));
  /* *INDENT-ON* */
  hash_free (index_by_name);
  for (i = 0; i < vec_len (keys_to_delete); i++)
    vec_free (keys_to_delete[i]);
  vec_free (keys_to_delete);
  hash_free (reg_by_index);

  return 0;
}

/*?
 * Show init function order
 *
 * @cliexpar
 * @cliexstart{show init-function [init | enter | exit] [verbose [nn]]}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_init_function, static) = {
  .path = "show init-function",
  .short_help = "show init-function [init | enter | exit][verbose [nn]]",
  .function = show_init_function_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
