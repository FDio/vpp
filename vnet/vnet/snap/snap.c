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
 * snap.c: snap support
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
#include <vnet/snap/snap.h>
#include <vnet/ethernet/ethernet.h>

/* Global main structure. */
snap_main_t snap_main;

static u8 *
format_cisco_snap_protocol (u8 * s, va_list * args)
{
  snap_header_t *h = va_arg (*args, snap_header_t *);
  u16 protocol = clib_net_to_host_u16 (h->protocol);
  char *t = 0;
  switch (protocol)
    {
#define _(n,f) case n: t = #f; break;
      foreach_snap_cisco_protocol;
#undef _
    default:
      break;
    }
  if (t)
    return format (s, "%s", t);
  else
    return format (s, "unknown 0x%x", protocol);
}

u8 *
format_snap_protocol (u8 * s, va_list * args)
{
  snap_header_t *h = va_arg (*args, snap_header_t *);
  u32 oui = snap_header_get_oui (h);
  u16 protocol = clib_net_to_host_u16 (h->protocol);

  switch (oui)
    {
    case IEEE_OUI_ethernet:
      return format (s, "ethernet %U", format_ethernet_type, h->protocol);

    case IEEE_OUI_cisco:
      return format (s, "cisco %U", format_cisco_snap_protocol, h);

    default:
      return format (s, "oui 0x%06x 0x%04x", oui, protocol);
    }
}

u8 *
format_snap_header_with_length (u8 * s, va_list * args)
{
  snap_main_t *sm = &snap_main;
  snap_header_t *h = va_arg (*args, snap_header_t *);
  snap_protocol_info_t *pi = snap_get_protocol_info (sm, h);
  u32 max_header_bytes = va_arg (*args, u32);
  uword indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "snap header truncated");

  indent = format_get_indent (s);

  s = format (s, "SNAP %U", format_snap_protocol, h);

  if (max_header_bytes != 0 && header_bytes > max_header_bytes && pi != 0)
    {
      vlib_node_t *node = vlib_get_node (sm->vlib_main, pi->node_index);
      if (node->format_buffer)
	s = format (s, "\n%U%U",
		    format_white_space, indent,
		    node->format_buffer, (void *) (h + 1),
		    max_header_bytes - header_bytes);
    }

  return s;
}

u8 *
format_snap_header (u8 * s, va_list * args)
{
  snap_header_t *h = va_arg (*args, snap_header_t *);
  return format (s, "%U", format_snap_header_with_length, h, 0);
}

/* Returns snap protocol as an int in host byte order. */
uword
unformat_snap_protocol (unformat_input_t * input, va_list * args)
{
  snap_header_t *result = va_arg (*args, snap_header_t *);
  snap_main_t *sm = &snap_main;
  snap_oui_and_protocol_t p;
  u32 i;

  /* Numeric type. */
  if (unformat (input, "0x%x 0x%x", &p.oui, &p.protocol))
    {
      if (p.oui >= (1 << 24))
	return 0;
      if (p.protocol >= (1 << 16))
	return 0;
    }

  /* Named type. */
  else if (unformat_user (input, unformat_vlib_number_by_name,
			  sm->protocol_info_by_name, &i))
    {
      snap_protocol_info_t *pi = vec_elt_at_index (sm->protocols, i);
      p = pi->oui_and_protocol;
    }

  else
    return 0;

  snap_header_set_protocol (result, &p);
  return 1;
}

uword
unformat_snap_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  snap_header_t _h, *h = &_h;

  if (!unformat (input, "%U", unformat_snap_protocol, h))
    return 0;

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static clib_error_t *
snap_init (vlib_main_t * vm)
{
  snap_main_t *sm = &snap_main;

  memset (sm, 0, sizeof (sm[0]));
  sm->vlib_main = vm;

  mhash_init (&sm->protocol_hash, sizeof (uword),
	      sizeof (snap_oui_and_protocol_t));

  sm->protocol_info_by_name
    = hash_create_string ( /* elts */ 0, sizeof (uword));

  return vlib_call_init_function (vm, snap_input_init);
}

VLIB_INIT_FUNCTION (snap_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
