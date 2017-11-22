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
 * hdlc.c: hdlc
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
#include <vnet/hdlc/hdlc.h>

/* Global main structure. */
hdlc_main_t hdlc_main;

u8 *
format_hdlc_protocol (u8 * s, va_list * args)
{
  hdlc_protocol_t p = va_arg (*args, u32);
  hdlc_main_t *pm = &hdlc_main;
  hdlc_protocol_info_t *pi = hdlc_get_protocol_info (pm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%04x", p);

  return s;
}

u8 *
format_hdlc_header_with_length (u8 * s, va_list * args)
{
  hdlc_main_t *pm = &hdlc_main;
  hdlc_header_t *h = va_arg (*args, hdlc_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  hdlc_protocol_t p = clib_net_to_host_u16 (h->protocol);
  u32 indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "hdlc header truncated");

  indent = format_get_indent (s);

  s = format (s, "HDLC %U", format_hdlc_protocol, p);

  if (h->address != 0xff)
    s = format (s, ", address 0x%02x", h->address);
  if (h->control != 0x03)
    s = format (s, ", control 0x%02x", h->control);

  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    {
      hdlc_protocol_info_t *pi = hdlc_get_protocol_info (pm, p);
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
format_hdlc_header (u8 * s, va_list * args)
{
  hdlc_header_t *h = va_arg (*args, hdlc_header_t *);
  return format (s, "%U", format_hdlc_header_with_length, h, 0);
}

/* Returns hdlc protocol as an int in host byte order. */
uword
unformat_hdlc_protocol_host_byte_order (unformat_input_t * input,
					va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  hdlc_main_t *pm = &hdlc_main;
  int p, i;

  /* Numeric type. */
  if (unformat (input, "0x%x", &p) || unformat (input, "%d", &p))
    {
      if (p >= (1 << 16))
	return 0;
      *result = p;
      return 1;
    }

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     pm->protocol_info_by_name, &i))
    {
      hdlc_protocol_info_t *pi = vec_elt_at_index (pm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_hdlc_protocol_net_byte_order (unformat_input_t * input,
				       va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  if (!unformat_user (input, unformat_hdlc_protocol_host_byte_order, result))
    return 0;
  *result = clib_host_to_net_u16 ((u16) * result);
  return 1;
}

uword
unformat_hdlc_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  hdlc_header_t _h, *h = &_h;
  u16 p;

  if (!unformat (input, "%U", unformat_hdlc_protocol_host_byte_order, &p))
    return 0;

  h->address = 0xff;
  h->control = 0x03;
  h->protocol = clib_host_to_net_u16 (p);

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static u8 *
hdlc_build_rewrite (vnet_main_t * vnm,
		    u32 sw_if_index,
		    vnet_link_t link_type, const void *dst_address)
{
  hdlc_header_t *h;
  u8 *rewrite = NULL;
  hdlc_protocol_t protocol;

  switch (link_type)
    {
#define _(a,b) case VNET_LINK_##a: protocol = HDLC_PROTOCOL_##b; break
      _(IP4, ip4);
      _(IP6, ip6);
      _(MPLS, mpls_unicast);
#undef _
    default:
      return (NULL);
    }

  vec_validate (rewrite, sizeof (*h) - 1);
  h = (hdlc_header_t *) rewrite;
  h->address = 0x0f;
  h->control = 0x00;
  h->protocol = clib_host_to_net_u16 (protocol);

  return (rewrite);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (hdlc_hw_interface_class) = {
  .name = "HDLC",
  .format_header = format_hdlc_header_with_length,
  .unformat_header = unformat_hdlc_header,
  .build_rewrite = hdlc_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static void
add_protocol (hdlc_main_t * pm, hdlc_protocol_t protocol, char *protocol_name)
{
  hdlc_protocol_info_t *pi;
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
hdlc_init (vlib_main_t * vm)
{
  hdlc_main_t *pm = &hdlc_main;

  memset (pm, 0, sizeof (pm[0]));
  pm->vlib_main = vm;

  pm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  pm->protocol_info_by_protocol = hash_create (0, sizeof (uword));

#define _(n,s) add_protocol (pm, HDLC_PROTOCOL_##s, #s);
  foreach_hdlc_protocol
#undef _
    return vlib_call_init_function (vm, hdlc_input_init);
}

VLIB_INIT_FUNCTION (hdlc_init);

hdlc_main_t *
hdlc_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, hdlc_init);
  return &hdlc_main;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
