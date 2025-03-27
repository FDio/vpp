/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2010 Eliot Dresselhaus
 */

/* llc.c: llc support */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/llc/llc.h>

/* Global main structure. */
llc_main_t llc_main;

u8 *
format_llc_protocol (u8 * s, va_list * args)
{
  llc_protocol_t p = va_arg (*args, u32);
  llc_main_t *pm = &llc_main;
  llc_protocol_info_t *pi = llc_get_protocol_info (pm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%02x", p);

  return s;
}

u8 *
format_llc_header_with_length (u8 * s, va_list * args)
{
  llc_main_t *pm = &llc_main;
  llc_header_t *h = va_arg (*args, llc_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  llc_protocol_t p = h->dst_sap;
  u32 indent, header_bytes;

  header_bytes = llc_header_length (h);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "llc header truncated");

  indent = format_get_indent (s);

  s = format (s, "LLC %U -> %U",
	      format_llc_protocol, h->src_sap,
	      format_llc_protocol, h->dst_sap);

  if (h->control != 0x03)
    s = format (s, ", control 0x%x", llc_header_get_control (h));

  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    {
      llc_protocol_info_t *pi = llc_get_protocol_info (pm, p);
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
format_llc_header (u8 * s, va_list * args)
{
  llc_header_t *h = va_arg (*args, llc_header_t *);
  return format (s, "%U", format_llc_header_with_length, h, 0);
}

/* Returns llc protocol as an int in host byte order. */
uword
unformat_llc_protocol (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  llc_main_t *pm = &llc_main;
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
      llc_protocol_info_t *pi = vec_elt_at_index (pm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_llc_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  llc_header_t _h, *h = &_h;
  u8 p;

  if (!unformat (input, "%U", unformat_llc_protocol, &p))
    return 0;

  h->src_sap = h->dst_sap = p;
  h->control = 0x3;

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
llc_build_rewrite (vnet_main_t * vnm,
		   u32 sw_if_index,
		   vnet_link_t link_type, const void *dst_address)
{
  llc_header_t *h;
  u8 *rewrite = NULL;
  llc_protocol_t protocol;

  switch (link_type)
    {
#define _(a,b) case VNET_LINK_##a: protocol = LLC_PROTOCOL_##b; break
      _(IP4, ip4);
#undef _
    default:
      return (NULL);
    }

  vec_validate (rewrite, sizeof (*h) - 1);
  h = (llc_header_t *) rewrite;
  h->src_sap = h->dst_sap = protocol;
  h->control = 0x3;

  return (rewrite);
}

VNET_HW_INTERFACE_CLASS (llc_hw_interface_class) = {
  .name = "LLC",
  .format_header = format_llc_header_with_length,
  .unformat_header = unformat_llc_header,
  .build_rewrite = llc_build_rewrite,
};

static void
add_protocol (llc_main_t * pm, llc_protocol_t protocol, char *protocol_name)
{
  llc_protocol_info_t *pi;
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
llc_init (vlib_main_t * vm)
{
  llc_main_t *pm = &llc_main;

  clib_memset (pm, 0, sizeof (pm[0]));
  pm->vlib_main = vm;

  pm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  pm->protocol_info_by_protocol = hash_create (0, sizeof (uword));

#define _(f,n) add_protocol (pm, LLC_PROTOCOL_##f, #f);
  foreach_llc_protocol;
#undef _

  ethernet_register_input_type (vm, ETHERNET_TYPE_LLC_ENCAP, llc_input_node.index);

  return vlib_call_init_function (vm, llc_input_init);
}

VLIB_INIT_FUNCTION (llc_init);
