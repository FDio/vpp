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
 * osi.c: osi support
 *
 * Copyright (c) 2010 Eliot Dresselhaus
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

#include <vnet/vnet.h>
#include <vnet/osi/osi.h>

/* Global main structure. */
osi_main_t osi_main;

u8 *
format_osi_protocol (u8 * s, va_list * args)
{
  osi_protocol_t p = va_arg (*args, u32);
  osi_main_t *pm = &osi_main;
  osi_protocol_info_t *pi = osi_get_protocol_info (pm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%02x", p);

  return s;
}

u8 *
format_osi_header_with_length (u8 * s, va_list * args)
{
  osi_main_t *pm = &osi_main;
  osi_header_t *h = va_arg (*args, osi_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  osi_protocol_t p = h->protocol;
  u32 indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "osi header truncated");

  indent = format_get_indent (s);

  s = format (s, "OSI %U", format_osi_protocol, p);

  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    {
      osi_protocol_info_t *pi = osi_get_protocol_info (pm, p);
      vlib_node_t *node = vlib_get_node (pm->vlib_main, pi->node_index);
      if (node->format_buffer)
	s = format (s, "\n%U%U",
		    format_white_space, indent,
		    node->format_buffer, (void *) (h + 1),
		    max_header_bytes - header_bytes);
    }

  return s;
}

u8 *
format_osi_header (u8 * s, va_list * args)
{
  osi_header_t *h = va_arg (*args, osi_header_t *);
  return format (s, "%U", format_osi_header_with_length, h, 0);
}

/* Returns osi protocol as an int in host byte order. */
uword
unformat_osi_protocol (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  osi_main_t *pm = &osi_main;
  int p, i;

  /* Numeric type. */
  if (unformat (input, "0x%x", &p) || unformat (input, "%d", &p))
    {
      if (p >= (1 << 8))
	return 0;
      *result = p;
      return 1;
    }

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     pm->protocol_info_by_name, &i))
    {
      osi_protocol_info_t *pi = vec_elt_at_index (pm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_osi_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  osi_header_t _h, *h = &_h;
  u8 p;

  if (!unformat (input, "%U", unformat_osi_protocol, &p))
    return 0;

  h->protocol = p;

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static void
add_protocol (osi_main_t * pm, osi_protocol_t protocol, char *protocol_name)
{
  osi_protocol_info_t *pi;
  u32 i;

  vec_add2 (pm->protocol_infos, pi, 1);
  i = pi - pm->protocol_infos;

  pi->name = protocol_name;
  pi->protocol = protocol;
  pi->next_index = pi->node_index = ~0;

  hash_set (pm->protocol_info_by_protocol, protocol, i);
  hash_set_mem (pm->protocol_info_by_name, pi->name, i);
}

static clib_error_t *
osi_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  osi_main_t *pm = &osi_main;

  /* init order dependency: llc_init -> osi_init */
  if ((error = vlib_call_init_function (vm, llc_init)))
    return error;

  clib_memset (pm, 0, sizeof (pm[0]));
  pm->vlib_main = vm;

  pm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  pm->protocol_info_by_protocol = hash_create (0, sizeof (uword));

#define _(f,n) add_protocol (pm, OSI_PROTOCOL_##f, #f);
  foreach_osi_protocol;
#undef _

  return vlib_call_init_function (vm, osi_input_init);
}

VLIB_INIT_FUNCTION (osi_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
