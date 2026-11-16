/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/cli_types.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>

static int
tok_is_number (u8 *tok)
{
  if (vec_len (tok) == 0)
    return 0;
  for (u32 i = 0; i < vec_len (tok); i++)
    if (!cli_is_digit (tok[i]))
      return 0;
  return 1;
}

static u8 *
parse_sw_interface (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  unformat_input_t in;
  u32 sw_if_index;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok && tok_is_number (tok))
    {
      sw_if_index = atoi ((char *) format (0, "%v%c", tok, 0));
      ok = !pool_is_free_index (im->sw_interfaces, sw_if_index);
    }
  if (!ok)
    return format (0, "unknown interface '%v'", tok);

  v->index = sw_if_index;
  return 0;
}

static void
complete_sw_interface (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;

  pool_foreach (si, vnm->interface_main.sw_interfaces)
    {
      u8 *name = format (0, "%U", format_vnet_sw_interface_name, vnm, si);
      cli_candidate_t *c;

      if (vec_len (name) < vec_len (prefix) ||
	  (vec_len (prefix) && memcmp (name, prefix, vec_len (prefix))))
	{
	  vec_free (name);
	  continue;
	}
      vec_add2 (*out, c, 1);
      c->text = name;
      c->help = format (0, "sw_if_index %u, %s", si->sw_if_index,
			(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down");
    }
}

CLIB_CLI_TYPE (cli_type_sw_interface) = {
  .name = "interface",
  .help = "interface name or index",
  .parse = parse_sw_interface,
  .complete = complete_sw_interface,
};

static u8 *
parse_hw_interface (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t in;
  u32 hw_if_index;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);
  if (!ok)
    return format (0, "unknown hardware interface '%v'", tok);

  v->index = hw_if_index;
  return 0;
}

static void
complete_hw_interface (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;

  pool_foreach (hi, vnm->interface_main.hw_interfaces)
    {
      u8 *name = format (0, "%v", hi->name);
      cli_candidate_t *c;

      if (vec_len (name) < vec_len (prefix) ||
	  (vec_len (prefix) && memcmp (name, prefix, vec_len (prefix))))
	{
	  vec_free (name);
	  continue;
	}
      vec_add2 (*out, c, 1);
      c->text = name;
      c->help = format (0, "hw_if_index %u", hi->hw_if_index);
    }
}

CLIB_CLI_TYPE (cli_type_hw_interface) = {
  .name = "hw-interface",
  .help = "hardware interface name",
  .parse = parse_hw_interface,
  .complete = complete_hw_interface,
};

static u8 *
parse_ip_prefix (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  ip4_address_t a4;
  ip6_address_t a6;
  u32 len;
  u8 *err = 0;

  unformat_init_vector (&in, vec_dup (tok));
  if (unformat (&in, "%U/%d", unformat_ip4_address, &a4, &len) &&
      unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
    {
      if (len > 32)
	err = format (0, "IPv4 prefix length %u is larger than 32", len);
      else
	{
	  clib_memcpy (v->prefix.addr, &a4, 4);
	  v->prefix.len = len;
	  v->prefix.is_ip6 = 0;
	}
    }
  else
    {
      unformat_free (&in);
      unformat_init_vector (&in, vec_dup (tok));
      if (unformat (&in, "%U/%d", unformat_ip6_address, &a6, &len) &&
	  unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
	{
	  if (len > 128)
	    err = format (0, "IPv6 prefix length %u is larger than 128", len);
	  else
	    {
	      clib_memcpy (v->prefix.addr, &a6, 16);
	      v->prefix.len = len;
	      v->prefix.is_ip6 = 1;
	    }
	}
      else
	err = format (0, "'%v' is not an IP address/length", tok);
    }
  unformat_free (&in);
  return err;
}

CLIB_CLI_TYPE (cli_type_ip_prefix) = {
  .name = "ip-prefix",
  .help = "IPv4 or IPv6 address/length",
  .parse = parse_ip_prefix,
};
