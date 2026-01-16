/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <hdrskip/hdrskip.h>

static clib_error_t *
hdrskip_input_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 sw_if_index = ~0;
  u32 skip_bytes = 0;
  int enable_disable = 1;
  int have_bytes = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "bytes %u", &skip_bytes))
	have_bytes = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 hsm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (enable_disable && !have_bytes)
    return clib_error_return (0, "Please specify bytes to skip");

  rv = hdrskip_input_enable_disable (hsm, sw_if_index, enable_disable,
				     skip_bytes, have_bytes);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "Skip bytes must be <= %u",
				HDRSKIP_MAX_ADJUST);
    default:
      return clib_error_return (0, "hdrskip input returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (hdrskip_input_command, static) = {
  .path = "hdrskip input",
  .short_help = "hdrskip input <interface-name> bytes <n> [disable]",
  .function = hdrskip_input_command_fn,
};

static clib_error_t *
hdrskip_output_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 sw_if_index = ~0;
  u32 restore_bytes = 0;
  int enable_disable = 1;
  int have_bytes = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "bytes %u", &restore_bytes))
	have_bytes = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 hsm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (enable_disable && !have_bytes)
    return clib_error_return (0, "Please specify bytes to restore");

  rv = hdrskip_output_enable_disable (hsm, sw_if_index, enable_disable,
				      restore_bytes, have_bytes);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "Restore bytes must be <= %u",
				HDRSKIP_MAX_ADJUST);
    default:
      return clib_error_return (0, "hdrskip output returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (hdrskip_output_command, static) = {
  .path = "hdrskip output",
  .short_help = "hdrskip output <interface-name> bytes <n> [disable]",
  .function = hdrskip_output_command_fn,
};
