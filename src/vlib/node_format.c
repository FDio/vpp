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
 * node_format.c: node formatting
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

u8 *
format_vlib_node_graph (u8 * s, va_list * va)
{
  vlib_node_main_t *nm = va_arg (*va, vlib_node_main_t *);
  vlib_node_t *n = va_arg (*va, vlib_node_t *);
  int i, j;
  u32 indent;
  typedef struct
  {
    u32 next_node;
    u32 next_slot;
    u32 prev_node;
  } tmp_t;
  tmp_t *tmps = 0;
  tmp_t empty = {.next_node = ~0,.prev_node = ~0 };

  if (!n)
    return format (s, "%=26s%=26s%=26s", "Name", "Next", "Previous");

  s = format (s, "%-26v", n->name);

  indent = format_get_indent (s);

  for (i = j = 0; i < vec_len (n->next_nodes); i++)
    {
      if (n->next_nodes[i] == VLIB_INVALID_NODE_INDEX)
	continue;
      vec_validate_init_empty (tmps, j, empty);
      tmps[j].next_node = n->next_nodes[i];
      tmps[j].next_slot = i;
      j++;
    }

  j = 0;
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, n->prev_node_bitmap, ({
	vec_validate_init_empty (tmps, j, empty);
	tmps[j].prev_node = i;
	j++;
      }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (tmps); i++)
    {
      if (i > 0)
	s = format (s, "\n%U", format_white_space, indent);

      if (tmps[i].next_node != ~0)
	{
	  vlib_node_t *x;
	  u8 *t = 0;

	  x = vec_elt (nm->nodes, tmps[i].next_node);
	  t = format (t, "%v [%d]", x->name, tmps[i].next_slot);
	  s = format (s, "%=26v", t);
	  vec_free (t);
	}
      else
	s = format (s, "%26s", "");

      if (tmps[i].prev_node != ~0)
	{
	  vlib_node_t *x;
	  x = vec_elt (nm->nodes, tmps[i].prev_node);
	  s = format (s, "%=26v", x->name);
	}
    }

  vec_free (tmps);

  return s;
}

u8 *
format_vlib_node_and_next (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_node_t *n = va_arg (*va, vlib_node_t *);
  u32 next_index = va_arg (*va, u32);
  vlib_node_t *n_next;
  u32 *ni;

  ni = vec_elt_at_index (n->next_nodes, next_index);
  n_next = vlib_get_node (vm, ni[0]);
  return format (s, "%v -> %v", n->name, n_next->name);
}

u8 *
format_vlib_node_name (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  u32 node_index = va_arg (*va, u32);
  vlib_node_t *n = vlib_get_node (vm, node_index);

  return format (s, "%v", n->name);
}

u8 *
format_vlib_next_node_name (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  u32 node_index = va_arg (*va, u32);
  u32 next_index = va_arg (*va, u32);
  vlib_node_t *next = vlib_get_next_node (vm, node_index, next_index);
  return format (s, "%v", next->name);
}

/* Parse node name -> node index. */
uword
unformat_vlib_node (unformat_input_t * input, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  u32 *result = va_arg (*args, u32 *);

  return unformat_user (input, unformat_hash_vec_string,
			vm->node_main.node_by_name, result);
}

u8 *
format_vlib_time (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  f64 time = va_arg (*va, f64);
  return format (s, "%12.4f", time);
}

u8 *
format_vlib_cpu_time (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  u64 cpu_time = va_arg (*va, u64);
  f64 dt;

  dt =
    (cpu_time -
     vm->clib_time.init_cpu_time) * vm->clib_time.seconds_per_clock;
  return format (s, "%U", format_vlib_time, vm, dt);
}

uword
unformat_vlib_node_variant (unformat_input_t *input, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 *march_variant = va_arg (*args, u32 *);
  uword *p;
  u8 *str = 0;

  if (unformat (input, "%s", &str) == 0)
    return 0;

  p = hash_get (vm->node_main.node_fn_march_variant_by_suffix, str);

  vec_free (str);

  if (p)
    *march_variant = p[0];

  return p ? 1 : 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
