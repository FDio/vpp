/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip4_cli.c: ip4 commands */

#include <vnet/interface/cli_types.h>
#include <vnet/ip/cli_types.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>

/**
 * @file
 * @brief Set IP Address.
 *
 * Configure an IPv4 or IPv6 address for on an interface.
 */

VLIB_CLI_COMMAND (set_interface_ip_command, static) = {
  .path = "set interface ip",
  .short_help = "IP4/IP6 commands",
};

void
ip_del_all_interface_addresses (vlib_main_t * vm, u32 sw_if_index)
{
  ip4_main_t *im4 = &ip4_main;
  ip4_address_t *ip4_addrs = 0;
  u32 *ip4_masks = 0;
  ip6_main_t *im6 = &ip6_main;
  ip6_address_t *ip6_addrs = 0;
  u32 *ip6_masks = 0;
  ip_interface_address_t *ia;
  int i;

  foreach_ip_interface_address (&im4->lookup_main, ia, sw_if_index,
                                0 /* honor unnumbered */,
  ({
    ip4_address_t * x = (ip4_address_t *)
      ip_interface_address_get_address (&im4->lookup_main, ia);
    vec_add1 (ip4_addrs, x[0]);
    vec_add1 (ip4_masks, ia->address_length);
  }));

  foreach_ip_interface_address (&im6->lookup_main, ia, sw_if_index,
                                0 /* honor unnumbered */,
  ({
    ip6_address_t * x = (ip6_address_t *)
      ip_interface_address_get_address (&im6->lookup_main, ia);
    vec_add1 (ip6_addrs, x[0]);
    vec_add1 (ip6_masks, ia->address_length);
  }));

  for (i = 0; i < vec_len (ip4_addrs); i++)
    ip4_add_del_interface_address (vm, sw_if_index, &ip4_addrs[i],
				   ip4_masks[i], 1 /* is_del */ );
  for (i = 0; i < vec_len (ip6_addrs); i++)
    ip6_add_del_interface_address (vm, sw_if_index, &ip6_addrs[i],
				   ip6_masks[i], 1 /* is_del */ );

  vec_free (ip4_addrs);
  vec_free (ip4_masks);
  vec_free (ip6_addrs);
  vec_free (ip6_masks);
}

static clib_error_t *
ip_address_delete_cleanup (vnet_main_t * vnm, u32 hw_if_index, u32 is_create)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw;

  if (is_create)
    return 0;

  hw = vnet_get_hw_interface (vnm, hw_if_index);

  ip_del_all_interface_addresses (vm, hw->sw_if_index);
  return 0;
}

VNET_HW_INTERFACE_ADD_DEL_FUNCTION (ip_address_delete_cleanup);

static clib_error_t *
add_del_ip_address (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 sw_if_index = cli_index (ctx, "interface");
  u32 is_del = cli_flag (ctx, "del");
  cli_value_t *p = cli_get (ctx, "prefix");

  if (cli_flag (ctx, "all"))
    {
      if (!is_del)
	return clib_error_return (0, "'all' can only be used with 'del'");
      ip_del_all_interface_addresses (vm, sw_if_index);
      return 0;
    }

  if (p->prefix.is_ip6)
    return ip6_add_del_interface_address (vm, sw_if_index, (ip6_address_t *) p->prefix.addr,
					  p->prefix.len, is_del);

  return ip4_add_del_interface_address (vm, sw_if_index, (ip4_address_t *) p->prefix.addr,
					p->prefix.len, is_del);
}

/*?
 * Add an IP Address to an interface or remove and IP Address from an interface.
 * The IP Address can be an IPv4 or an IPv6 address. Interfaces may have multiple
 * IPv4 and IPv6 addresses. There is no concept of primary vs. secondary
 * interface addresses; they're just addresses.
 *
 * To display the addresses associated with a given interface, use the command
 * '<em>show interface address <interface></em>'.
 *
 * Note that the debug CLI does not enforce classful mask-width / addressing
 * constraints.
 *
 * @cliexpar
 * @parblock
 * An example of how to add an IPv4 address to an interface:
 * @cliexcmd{set interface ip address GigabitEthernet2/0/0 172.16.2.12/24}
 *
 * An example of how to add an IPv6 address to an interface:
 * @cliexcmd{set interface ip address GigabitEthernet2/0/0 @::a:1:1:0:7/126}
 *
 * To delete a specific interface ip address:
 * @cliexcmd{set interface ip address del GigabitEthernet2/0/0 172.16.2.12/24}
 *
 * To delete all interfaces addresses (IPv4 and IPv6):
 * @cliexcmd{set interface ip address del GigabitEthernet2/0/0 all}
 * @endparblock
 ?*/
VLIB_CLI_COMMAND (set_interface_ip_address_command, static) = {
  .path = "set interface ip address",
  .short_help = "Add or delete an IPv4/IPv6 address of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_FLAG ("del", .help = "delete instead of add"),
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_ONEOF ("address", 0,
		 CLI_VALUE ("prefix", cli_type_ip_prefix,
			    .help = "IPv4/IPv6 address and prefix length"),
		 CLI_FLAG ("all", .help = "all addresses (with del)")),
      {},
    },
  .handler = add_del_ip_address,
};

static clib_error_t *
set_reassembly_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  u8 ip4_on = 0;
  u8 ip6_on = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return NULL;
    }

  if (!unformat_user
      (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      return clib_error_return (0, "Invalid interface name");
    }

  if (unformat (line_input, "on"))
    {
      ip4_on = 1;
      ip6_on = 1;
    }
  else if (unformat (line_input, "off"))
    {
      ip4_on = 0;
      ip6_on = 0;
    }
  else if (unformat (line_input, "ip4"))
    {
      ip4_on = 1;
      ip6_on = 0;
    }
  else if (unformat (line_input, "ip6"))
    {
      ip4_on = 0;
      ip6_on = 1;
    }
  else
    {
      return clib_error_return (0, "Unknown input `%U'",
				format_unformat_error, line_input);
    }


  vnet_api_error_t rv4 = ip4_full_reass_enable_disable (sw_if_index, ip4_on);
  vnet_api_error_t rv6 = ip6_full_reass_enable_disable (sw_if_index, ip6_on);
  if (rv4 && rv6)
    {
      return clib_error_return (0,
				"`ip4_full_reass_enable_disable' API call failed, rv=%d:%U, "
				"`ip6_full_reass_enable_disable' API call failed, rv=%d:%U",
				(int) rv4, format_vnet_api_errno, rv4,
				(int) rv6, format_vnet_api_errno, rv6);
    }
  else if (rv4)
    {
      return clib_error_return (0,
				"`ip4_full_reass_enable_disable' API call failed, rv=%d:%U",
				(int) rv4, format_vnet_api_errno, rv4);
    }
  else if (rv6)
    {
      return clib_error_return (0,
				"`ip6_full_reass_enable_disable' API call failed, rv=%d:%U",
				(int) rv6, format_vnet_api_errno, rv6);
    }
  return NULL;
}

VLIB_CLI_COMMAND (set_reassembly_command, static) = {
    .path = "set interface reassembly",
    .short_help = "set interface reassembly <interface-name> [on|off|ip4|ip6]",
    .function = set_reassembly_command_fn,
};

static clib_error_t *
set_sv_reass_extended_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 ip4_set = 0;
  u8 ip6_set = 0;
  u8 enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4"))
	ip4_set = 1;
      else if (unformat (line_input, "ip6"))
	ip6_set = 1;
      else if (unformat (line_input, "on"))
	enable = 1;
      else if (unformat (line_input, "off"))
	enable = 0;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "Unknown input `%U'", format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

  if (!ip4_set && !ip6_set)
    {
      ip4_set = 1;
      ip6_set = 1;
    }

  if (ip4_set)
    ip4_sv_reass_enable_disable_extended (enable);
  if (ip6_set)
    ip6_sv_reass_enable_disable_extended (enable);

  return NULL;
}

VLIB_CLI_COMMAND (set_sv_reass_extended_command, static) = {
  .path = "set ip reassembly extended",
  .short_help = "set ip reassembly extended [ip4|ip6] [on|off]",
  .function = set_sv_reass_extended_command_fn,
};

static clib_error_t *
enable_ip4_interface_cmd (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      vnet_feature_enable_disable ("ip4-unicast", "ip4-not-enabled",
				   sw_if_index, 0, 0, 0);

      vnet_feature_enable_disable ("ip4-multicast", "ip4-not-enabled",
				   sw_if_index, 0, 0, 0);
    }
  else
    {
      error = clib_error_return (0, "unknown interface\n'",
				 format_unformat_error, input);
    }
  return error;
}

/*?
 * This command is used to enable IPv4 on a given interface.
 *
 * @cliexpar
 * Example of how enable IPv4 on a given interface:
 * @cliexcmd{enable ip4 interface GigabitEthernet2/0/0}
?*/
VLIB_CLI_COMMAND (enable_ip4_interface_command, static) = {
  .path = "enable ip4 interface",
  .function = enable_ip4_interface_cmd,
  .short_help = "enable ip4 interface <interface>",
};

/* Dummy init function to get us linked in. */
static clib_error_t *
ip4_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip4_cli_init);
