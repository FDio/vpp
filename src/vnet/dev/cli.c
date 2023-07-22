/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

static uword
unformat_c_string_array (unformat_input_t *input, va_list *va)
{
  char *device_id = va_arg (*va, char *);
  u32 max_len = va_arg (*va, u32);
  uword c, rv = 0;
  u8 *s = 0;

  if (unformat (input, "%v", &s) == 0)
    return 0;

  c = vec_len (s);

  if (c > 0 && c < max_len)
    {
      clib_memcpy (device_id, s, c);
      device_id[c] = 0;
      rv = 1;
    }

  vec_free (s);
  return rv;
}

static clib_error_t *
device_attach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vnet_dev_attach_args_t args = {};
  vnet_dev_rv_t rv;

  if (!unformat_user (input, unformat_c_string_array, args.device_id,
		      sizeof (args.device_id)))
    return clib_error_return (0, "please specify valid device id");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!args.driver_name[0] &&
	  unformat (input, "driver %U", unformat_c_string_array,
		    args.driver_name, sizeof (args.driver_name)))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = vnet_dev_attach (vm, args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to attach '%s': %U", args.device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_attach_cmd, static) = {
  .path = "device attach",
  .short_help = "device attach <device-id> [driver <name>]",
  .function = device_attach_cmd_fn,
};

static clib_error_t *
device_detach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vnet_dev_detach_args_t args = {};
  vnet_dev_rv_t rv;

  if (!unformat_user (input, unformat_c_string_array, args.device_id,
		      sizeof (args.device_id)))
    return clib_error_return (0, "please specify valid device id");

  rv = vnet_dev_detach (vm, args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to detach '%s': %U", args.device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_detach_cmd, static) = {
  .path = "device detach",
  .short_help = "device detach <device-id>",
  .function = device_detach_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_create_if_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  vnet_dev_create_if_args_t args = {};
  vnet_dev_rv_t rv;
  u32 n;

  if (!unformat_user (input, unformat_c_string_array, args.device_id,
		      sizeof (args.device_id)))
    return clib_error_return (0, "please specify valid device id");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!args.intf_name[0] &&
	  unformat (input, "if-name %U", unformat_c_string_array,
		    args.intf_name, sizeof (args.intf_name)))
	;
      else if (!args.port_id && unformat (input, "port %u", &n))
	args.port_id = n;
      else if (!args.num_rx_queues && unformat (input, "num-rx-queues %u", &n))
	args.num_rx_queues = n;
      else if (!args.num_tx_queues && unformat (input, "num-tx-queues %u", &n))
	args.num_rx_queues = n;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = vnet_dev_create_if (vm, args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to create_if '%s': %U",
			      args.device_id, format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_create_if_cmd, static) = {
  .path = "device create-interface",
  .short_help = "device create-interface <device-id> [port <port-id>]",
  .function = device_create_if_cmd_fn,
  .is_mp_safe = 1,
};
