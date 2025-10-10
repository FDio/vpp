/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <sfdp_services/geneve/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

/*
 * add CLI:
 * set gateway geneve-output tenant <tenant-id> src <src ip> dst <dst ip>
 *      src-port <src-port> dst-port <dst-port> <forward|reverse>
 *
 * it sets the geneve output data in each direction
 */

static clib_error_t *
gateway_set_output_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  gw_set_geneve_output_args_t args = { .tenant_id = ~0,
				       .src_addr = { .as_u32 = ~0 },
				       .dst_addr = { .as_u32 = ~0 },
				       .src_port = ~0,
				       .dst_port = ~0,
				       .direction = ~0,
				       .output_tenant_id = ~0,
				       .src_mac = { .bytes = { 0 } },
				       .dst_mac = { .bytes = { 0 } } };
  clib_error_t *err = 0;
  u32 tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &args.tenant_id))
	;
      else if (unformat (line_input, "output-tenant %d",
			 &args.output_tenant_id))
	;
      else if (unformat (line_input, "src %U", unformat_ip4_address,
			 &args.src_addr))
	;
      else if (unformat (line_input, "dst %U", unformat_ip4_address,
			 &args.dst_addr))
	;
      else if (unformat (line_input, "src-port %d", &tmp))
	args.src_port = clib_host_to_net_u16 (tmp);
      else if (unformat (line_input, "dst-port %d", &tmp))
	args.dst_port = clib_host_to_net_u16 (tmp);
      else if (unformat (line_input, "src-mac %U dst-mac %U",
			 unformat_mac_address, &args.src_mac,
			 unformat_mac_address, &args.dst_mac))
	args.static_mac = 1;
      else if (unformat (line_input, "forward"))
	args.direction = SFDP_FLOW_FORWARD;
      else if (unformat (line_input, "reverse"))
	args.direction = SFDP_FLOW_REVERSE;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (args.tenant_id == ~0 || args.src_addr.as_u32 == ~0 ||
      args.dst_addr.as_u32 == ~0 || args.src_port == (u16) ~0 ||
      args.dst_port == (u16) ~0 || args.direction == (u8) ~0)
    {
      err = clib_error_return (0, "missing geneve output parameters");
      goto done;
    }
  gw_set_geneve_output (&args);
  err = args.err;
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (gateway_set_output_command, static) = {
  .path = "set sfdp gateway geneve-output",
  .short_help = "set sfdp gateway geneve-output tenant <tenant-id> "
		"src <src ip> dst <dst ip> "
		"src-port <src-port> dst-port <dst-port> "
		"[output-tenant <tenant-id>] "
		"[src-mac <src-mac-address> dst-mac <dst-mac-address>]"
		"<forward|reverse>",
  .function = gateway_set_output_command_fn,
};

/*
 * Add CLI:
 *  gateway geneve-input interface <ifname> <enable-disable>
 *
 */

static clib_error_t *
gateway_geneve_enable_disable_command_fn (vlib_main_t *vm,
					  unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  int enable_disable = -1;
  gw_enable_disable_geneve_input_args_t args;
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  args.sw_if_index = ~0;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnet_get_main (), &args.sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable_disable = 1;
      else if (unformat (line_input, "disable"))
	enable_disable = 0;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (enable_disable == -1)
    {
      err = clib_error_return (0, "enable or disable?");
      goto done;
    }
  if (args.sw_if_index == ~0)
    {
      err = clib_error_return (0, "valid interface name required");
      goto done;
    }
  args.enable_disable = enable_disable;
  gw_enable_disable_geneve_input (&args);
  err = args.err;

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (gateway_geneve_input_enable_disable_command, static) = {
  .path = "sfdp gateway geneve-input",
  .short_help =
    "sfdp gateway geneve-input interface <ifname> <enable|disable>",
  .function = gateway_geneve_enable_disable_command_fn,
};