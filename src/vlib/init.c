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

clib_error_t *
vlib_call_init_exit_functions (vlib_main_t * vm,
			       _vlib_init_function_list_elt_t * head,
			       int call_once)
{
  clib_error_t *error = 0;
  _vlib_init_function_list_elt_t *i;

  i = head;
  while (i)
    {
      if (call_once && !hash_get (vm->init_functions_called, i->f))
	{
	  if (call_once)
	    hash_set1 (vm->init_functions_called, i->f);
	  error = i->f (vm);
	  if (error)
	    return error;
	}
      i = i->next_init_function;
    }
  return error;
}

clib_error_t *
vlib_call_all_init_functions (vlib_main_t * vm)
{
  /* Call dummy functions to make sure purely static modules are
     linked in. */
#define _(f) vlib_##f##_reference ();
  foreach_vlib_module_reference;
#undef _

  return vlib_call_init_exit_functions
    (vm, vm->init_function_registrations, 1 /* call_once */ );
}

clib_error_t *
vlib_call_all_main_loop_enter_functions (vlib_main_t * vm)
{
  return vlib_call_init_exit_functions
    (vm, vm->main_loop_enter_function_registrations, 1 /* call_once */ );
}

clib_error_t *
vlib_call_all_main_loop_exit_functions (vlib_main_t * vm)
{
  return vlib_call_init_exit_functions
    (vm, vm->main_loop_exit_function_registrations, 1 /* call_once */ );
}

clib_error_t *
vlib_call_all_config_functions (vlib_main_t * vm,
				unformat_input_t * input, int is_early)
{
  clib_error_t *error = 0;
  vlib_config_function_runtime_t *c, **all;
  uword *hash = 0, *p;
  uword i;

  hash = hash_create_string (0, sizeof (uword));
  all = 0;

  c = vm->config_function_registrations;

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
      if (hash_get (vm->init_functions_called, c->function))
	continue;
      hash_set1 (vm->init_functions_called, c->function);

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
