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
 * srp_format.c: srp formatting/parsing.
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
#include <vnet/srp/srp.h>
#include <vnet/ethernet/ethernet.h>

static u8 * format_srp_mode (u8 * s, va_list * args)
{
  u32 mode = va_arg (*args, u32);
  char * t = 0;
  switch (mode)
    {
#define _(f) case SRP_MODE_##f: t = #f; break;
  foreach_srp_mode
#undef _
    default: t = 0; break;
    }
  if (t)
    s = format (s, "%s", t);
  else
    s = format (s, "unknown 0x%x", mode);

  return s;
}

u8 * format_srp_header_with_length (u8 * s, va_list * args)
{
  srp_and_ethernet_header_t * h = va_arg (*args, srp_and_ethernet_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  ethernet_main_t * em = &ethernet_main;
  u32 indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "srp header truncated");

  indent = format_get_indent (s);

  s = format (s, "mode %U, ring %s, priority %d, ttl %d",
	      format_srp_mode, h->srp.mode,
	      h->srp.is_inner_ring ? "inner" : "outer",
	      h->srp.priority, h->srp.ttl);

  s = format (s, "\n%U%U: %U -> %U",
	      format_white_space, indent,
	      format_ethernet_type, clib_net_to_host_u16 (h->ethernet.type),
	      format_ethernet_address, h->ethernet.src_address,
	      format_ethernet_address, h->ethernet.dst_address);

  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      ethernet_type_info_t * ti;
      vlib_node_t * node;

      ti = ethernet_get_type_info (em, h->ethernet.type);
      node = ti ? vlib_get_node (em->vlib_main, ti->node_index) : 0;
      if (node && node->format_buffer)
	s = format (s, "\n%U%U",
		    format_white_space, indent,
		    node->format_buffer, (void *) h + header_bytes,
		    max_header_bytes - header_bytes);
    }

  return s;
}

u8 * format_srp_header (u8 * s, va_list * args)
{
  srp_header_t * m = va_arg (*args, srp_header_t *);
  return format (s, "%U", format_srp_header_with_length, m, 0);
}

uword
unformat_srp_header (unformat_input_t * input, va_list * args)
{
  u8 ** result = va_arg (*args, u8 **);
  srp_and_ethernet_header_t * h;

  {
    void * p;
    vec_add2 (*result, p, sizeof (h[0]));
    h = p;
  }

  if (! unformat (input, "%U: %U -> %U",
		  unformat_ethernet_type_net_byte_order, &h->ethernet.type,
		  unformat_ethernet_address, &h->ethernet.src_address,
		  unformat_ethernet_address, &h->ethernet.dst_address))
    return 0;

  h->srp.mode = SRP_MODE_data;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u32 x;

      if (unformat (input, "control"))
	h->srp.mode = SRP_MODE_control_pass_to_host;
      
      else if (unformat (input, "pri %d", &x))
	h->srp.priority = x;

      else if (unformat (input, "ttl %d", &x))
	h->srp.ttl = x;

      else
	return 0;
    }

  return 1;
}
