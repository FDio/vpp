/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <usbnet/usbnet.h>

static clib_error_t *
usbnet_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  usbnet_create_if_args_t args = {};
  clib_error_t *err;
  u32 a, b;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u-%u", &a, &b))
	{
	  if (a > 255 || b > 255)
	    return clib_error_return (
	      0, "both bus and port values must be lower than 256");
	  args.busnum = a;
	  args.ports[0] = b;
	  args.n_ports = 1;
	  while (unformat (input, ".%u", &a))
	    {
	      if (args.n_ports >= VLIB_USB_N_TIERS)
		return clib_error_return (
		  0, "number of ports must be lower than %u",
		  VLIB_USB_N_TIERS);

	      if (a > 255)
		return clib_error_return (0,
					  "port value must be lower than 256");
	      args.ports[args.n_ports++] = a;
	    }
	}
      else if (unformat (input, "%u/%u", &a, &b))
	{
	  if (a > 255 || b > 255)
	    return clib_error_return (
	      0, "both bus and device values must be lower than 256");
	  args.busnum = a;
	  args.devnum = b;
	}
      else if (unformat (input, "%x:%x", &a, &b))
	{
	  if (a > 255 || b > 255)
	    return clib_error_return (
	      0, "both vid and pid values must be lower than 256");
	  args.vid = a;
	  args.pid = b;
	}
      else if (unformat (input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  err = usbnet_create_if (vm, &args);

  vec_free (args.name);

  return err;
}

VLIB_CLI_COMMAND (usbnet_create_command, static) = {
  .path = "create interface usbnet",
  .short_help = "create interface usbnet <bus:device> | <vid:pid> "
		"[name <name>]",
  .function = usbnet_create_command_fn,
};

static clib_error_t *
usbnet_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
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

  return usbnet_delete_if (vm, sw_if_index);
}

VLIB_CLI_COMMAND (usbnet_delete_command, static) = {
  .path = "delete interface usbnet",
  .short_help = "delete interface usbnet "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = usbnet_delete_command_fn,
};
