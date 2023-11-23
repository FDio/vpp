/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/api.h>

static clib_error_t *
device_attach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vnet_dev_api_attach_args_t a = {};
  vnet_dev_rv_t rv;

  if (!unformat_user (input, unformat_c_string_array, a.device_id,
		      sizeof (a.device_id)))
    return clib_error_return (0, "please specify valid device id");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!a.driver_name[0] &&
	  unformat (input, "driver %U", unformat_c_string_array, a.driver_name,
		    sizeof (a.driver_name)))
	;
      else if (!a.flags.n &&
	       unformat (input, "flags %U", unformat_vnet_dev_flags, &a.flags))
	;
      else if (!a.args && unformat (input, "args %v", &a.args))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = vnet_dev_api_attach (vm, &a);

  vec_free (a.args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to attach '%s': %U", a.device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_attach_cmd, static) = {
  .path = "device attach",
  .short_help = "device attach <device-id> [driver <name>] "
		"[args <dev-args>]",
  .function = device_attach_cmd_fn,
};

static clib_error_t *
device_detach_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vnet_dev_rv_t rv;
  vnet_dev_device_id_t device_id = {};
  vnet_dev_t *dev;

  if (!unformat_user (input, unformat_c_string_array, device_id,
		      sizeof (device_id)))
    return clib_error_return (0, "please specify valid device id");

  dev = vnet_dev_by_id (device_id);

  if (dev)
    {
      vnet_dev_api_detach_args_t a = { .dev_index = dev->index };
      rv = vnet_dev_api_detach (vm, &a);
    }
  else
    rv = VNET_DEV_ERR_UNKNOWN_DEVICE;

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to detach '%s': %U", device_id,
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
device_reset_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vnet_dev_api_reset_args_t a = {};
  vnet_dev_rv_t rv;

  if (!unformat_user (input, unformat_c_string_array, a.device_id,
		      sizeof (a.device_id)))
    return clib_error_return (0, "please specify valid device id");

  rv = vnet_dev_api_reset (vm, &a);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to reset '%s': %U", a.device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_reset_cmd, static) = {
  .path = "device reset",
  .short_help = "device reset <device-id>",
  .function = device_reset_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_create_if_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  vnet_dev_api_create_port_if_args_t a = {};
  vnet_dev_rv_t rv;
  vnet_dev_device_id_t device_id = {};
  vnet_dev_t *dev = 0;
  u32 n;

  if (unformat_user (input, unformat_c_string_array, device_id,
		     sizeof (device_id)))
    dev = vnet_dev_by_id (device_id);

  if (!dev)
    return clib_error_return (0, "please specify valid device id");

  a.dev_index = dev->index;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!a.intf_name[0] &&
	  unformat (input, "if-name %U", unformat_c_string_array, a.intf_name,
		    sizeof (a.intf_name)))
	;
      else if (!a.port_id && unformat (input, "port %u", &n))
	a.port_id = n;
      else if (!a.flags.n && unformat (input, "flags %U",
				       unformat_vnet_dev_port_flags, &a.flags))
	;
      else if (!a.num_rx_queues && unformat (input, "num-rx-queues %u", &n))
	a.num_rx_queues = n;
      else if (!a.num_tx_queues && unformat (input, "num-tx-queues %u", &n))
	a.num_tx_queues = n;
      else if (!a.rx_queue_size && unformat (input, "rx-queues-size %u", &n))
	a.rx_queue_size = n;
      else if (!a.tx_queue_size && unformat (input, "tx-queues-size %u", &n))
	a.tx_queue_size = n;
      else if (!a.intf_name[0] &&
	       unformat (input, "name %U", unformat_c_string_array,
			 &a.intf_name, sizeof (a.intf_name)))
	;
      else if (!a.args && unformat (input, "args %v", &a.args))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = vnet_dev_api_create_port_if (vm, &a);

  vec_free (a.args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to create_if '%s': %U", device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_create_if_cmd, static) = {
  .path = "device create-interface",
  .short_help = "device create-interface <device-id> [port <port-id>] "
		"[args <iface-args>]",
  .function = device_create_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_remove_if_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  vnet_dev_api_remove_port_if_args_t a = { .sw_if_index = ~0 };
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_rv_t rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &a.sw_if_index))
	;
      else if (unformat (input, "sw-if-index %u", &a.sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (a.sw_if_index == ~0)
    return clib_error_return (0, "please specify existing interface name");

  rv = vnet_dev_api_remove_port_if (vm, &a);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to remove interface: %U",
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_remove_if_cmd, static) = {
  .path = "device remove-interface",
  .short_help = "device remove-interface [<interface-name> | sw-if-index <n>]",
  .function = device_remove_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_devices_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_format_args_t fa = {}, *a = &fa;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "counters"))
	fa.counters = 1;
      else if (unformat (input, "all"))
	fa.show_zero_counters = 1;
      else if (unformat (input, "debug"))
	fa.debug = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  pool_foreach_pointer (dev, dm->devices)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_vnet_dev_info, a, dev);
      foreach_vnet_dev_port (p, dev)
	{
	  vlib_cli_output (vm, "  Port %u:", p->port_id);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_port_info, a, p);
	  if (fa.counters)
	    vlib_cli_output (vm, "    %U", format_vnet_dev_counters, a,
			     p->counter_main);

	  foreach_vnet_dev_port_rx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    RX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_rx_queue_info,
			       a, q);
	    }

	  foreach_vnet_dev_port_tx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    TX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_tx_queue_info,
			       a, q);
	    }
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (show_devices_cmd, static) = {
  .path = "show device",
  .short_help = "show device [counters]",
  .function = show_devices_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_device_counters_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_format_args_t fa = { .counters = 1 };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	fa.show_zero_counters = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  pool_foreach_pointer (dev, dm->devices)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      foreach_vnet_dev_port (p, dev)
	{
	  vlib_cli_output (vm, "    %U", format_vnet_dev_counters, &fa,
			   p->counter_main);

	  foreach_vnet_dev_port_rx_queue (q, p)
	    if (q->counter_main)
	      {
		vlib_cli_output (vm, "  RX queue %u:", q->queue_id);
		vlib_cli_output (vm, "    %U", format_vnet_dev_counters, &fa,
				 q->counter_main);
	      }

	  foreach_vnet_dev_port_tx_queue (q, p)
	    if (q->counter_main)
	      {
		vlib_cli_output (vm, "  TX queue %u:", q->queue_id);
		vlib_cli_output (vm, "    %U", format_vnet_dev_counters, &fa,
				 q->counter_main);
	      }
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (show_device_counters_cmd, static) = {
  .path = "show device counters",
  .short_help = "show device counters [all]",
  .function = show_device_counters_cmd_fn,
  .is_mp_safe = 1,
};
