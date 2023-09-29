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
  vnet_dev_api_attach_args_t args = {};
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

  rv = vnet_dev_api_attach (vm, &args);

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
  vnet_dev_api_detach_args_t args = {};
  vnet_dev_rv_t rv;

  if (!unformat_user (input, unformat_c_string_array, args.device_id,
		      sizeof (args.device_id)))
    return clib_error_return (0, "please specify valid device id");

  rv = vnet_dev_api_detach (vm, &args);

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
  vnet_dev_api_create_port_if_args_t a = {};
  vnet_dev_rv_t rv;
  u32 n;

  if (!unformat_user (input, unformat_c_string_array, a.device_id,
		      sizeof (a.device_id)))
    return clib_error_return (0, "please specify valid device id");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!a.intf_name[0] &&
	  unformat (input, "if-name %U", unformat_c_string_array, a.intf_name,
		    sizeof (a.intf_name)))
	;
      else if (!a.port_id && unformat (input, "port %u", &n))
	a.port_id = n;
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
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = vnet_dev_api_create_port_if (vm, &a);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to create_if '%s': %U", a.device_id,
			      format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_create_if_cmd, static) = {
  .path = "device create-interface",
  .short_help = "device create-interface <device-id> [port <port-id>]",
  .function = device_create_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_devices_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  int counters = 0, all = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "counters"))
	counters = 1;
      else if (unformat (input, "all"))
	all = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  pool_foreach_pointer (dev, dm->devices)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_vnet_dev_info, dev);
      pool_foreach_pointer (p, dev->ports)
	{
	  vlib_cli_output (vm, "  Port %u:", p->port_id);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_port_info, p);
	  if (counters)
	    vlib_cli_output (vm, "    %U",
			     all ? format_vnet_dev_counters_all :
					 format_vnet_dev_counters,
			     p->counter_main);

	  pool_foreach_pointer (q, p->rx_queues)
	    {
	      vlib_cli_output (vm, "    RX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_rx_queue_info,
			       q);
	    }

	  pool_foreach_pointer (q, p->tx_queues)
	    {
	      vlib_cli_output (vm, "    TX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_tx_queue_info,
			       q);
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
  format_function_t *fmt = format_vnet_dev_counters;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	fmt = format_vnet_dev_counters_all;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  pool_foreach_pointer (dev, dm->devices)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      pool_foreach_pointer (p, dev->ports)
	{
	  vlib_cli_output (vm, "    %U", fmt, p->counter_main);

	  pool_foreach_pointer (q, p->rx_queues)
	    {
	      vlib_cli_output (vm, "  RX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "    %U", fmt, q->counter_main);
	    }

	  pool_foreach_pointer (q, p->tx_queues)
	    {
	      vlib_cli_output (vm, "  TX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "    %U", fmt, q->counter_main);
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
