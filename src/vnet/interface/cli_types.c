/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/interface/cli_types.h>

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
