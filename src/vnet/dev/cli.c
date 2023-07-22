/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

static clib_error_t *
device_attach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vnet_dev_attach_args_t args = {};
  clib_error_t *err;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pci-addr %U", unformat_vlib_pci_addr,
		    &args.pci_addr))
	args.bus_type = VNET_DEV_BUS_TYPE_PCIE;
      else if (unformat (input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  err = vnet_dev_attach (vm, args);

  vec_free (args.name);

  return err;
}

VLIB_CLI_COMMAND (device_attach_cmd, static) = {
  .path = "device attach",
  .short_help = "device-attach pci-addr <pci-address> [name <name>]",
  .function = device_attach_cmd_fn,
};

static clib_error_t *
device_detach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);

  return vnet_dev_detach (vm, hw->dev_instance);

  return 0;
}

VLIB_CLI_COMMAND (device_detach_cmd, static) = {
  .path = "device detach",
  .short_help = "device detach "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = device_detach_cmd_fn,
  .is_mp_safe = 1,
};
