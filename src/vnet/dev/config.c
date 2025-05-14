/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/api.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "config",
};

static clib_error_t *
vnet_dev_config_one_interface (vlib_main_t *vm, unformat_input_t *input,
			       vnet_dev_api_create_port_if_args_t *args)
{
  clib_error_t *err = 0;

  log_debug (0, "port %u %U", args->port_id, format_unformat_input, input);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u32 n;

      if (unformat (input, "name %U", unformat_c_string_array, args->intf_name,
		    sizeof (args->intf_name)))
	;
      else if (unformat (input, "num-rx-queues %u", &n))
	args->num_rx_queues = n;
      else if (unformat (input, "num-tx-queues %u", &n))
	args->num_tx_queues = n;
      else if (unformat (input, "rx-queue-size %u", &n))
	args->rx_queue_size = n;
      else if (unformat (input, "tx-queue-size %u", &n))
	args->tx_queue_size = n;
      else if (unformat (input, "flags %U", unformat_vnet_dev_port_flags,
			 &args->flags))
	;
      else if (unformat (input, "args %U", unformat_single_quoted_string,
			 &args->args))
	;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
	  break;
	}
    }
  return err;
}

static clib_error_t *
vnet_dev_config_driver_args (vlib_main_t *vm, unformat_input_t *input,
			     char *driver_name)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  clib_error_t *err = 0;
  u8 *args;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "args %U", unformat_single_quoted_string, &args))
	;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
	  break;
	}
    }

  if (err == 0)
    {
      vnet_dev_driver_t *driver;
      vnet_dev_rv_t rv = VNET_DEV_OK;

      vec_foreach (driver, dm->drivers)
	{
	  if (driver_name[0] &&
	      strcmp (driver_name, driver->registration->name))
	    continue;
	  if (driver->registration->drv_args)
	    {
	      for (vnet_dev_arg_t *a = driver->registration->drv_args;
		   a->type != VNET_DEV_ARG_END; a++)
		vec_add1 (driver->args, *a);

	      if (args)
		{
		  rv = vnet_dev_arg_parse (vm, NULL, driver->args, args);
		  if (rv != VNET_DEV_OK)
		    goto done;

		  if (driver->ops.config_args)
		    rv = driver->ops.config_args (vm, driver);
		  break;
		}
	    }
	}
    done:
      vec_free (args);

      if (rv != VNET_DEV_OK)
	err = clib_error_return (0, "error: %U for driver '%s'",
				 format_vnet_dev_rv, rv, driver_name);
    }

  return err;
}

static clib_error_t *
vnet_dev_config_one_device (vlib_main_t *vm, unformat_input_t *input,
			    char *device_id)
{
  log_debug (0, "device %s %U", device_id, format_unformat_input, input);
  clib_error_t *err = 0;
  vnet_dev_api_attach_args_t args = {};
  vnet_dev_api_create_port_if_args_t *if_args_vec = 0, *if_args;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      u32 n;

      if (unformat (input, "driver %U", unformat_c_string_array,
		    args.driver_name, sizeof (args.driver_name)))
	;
      else if (unformat (input, "flags %U", unformat_vnet_dev_flags,
			 &args.flags))
	;
      else if (unformat (input, "args %U", unformat_single_quoted_string,
			 &args.args))
	;
      else if (unformat (input, "port %u %U", &n, unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  vnet_dev_api_create_port_if_args_t *if_args;
	  vec_add2 (if_args_vec, if_args, 1);
	  if_args->port_id = n;
	  err = vnet_dev_config_one_interface (vm, &sub_input, if_args);
	  unformat_free (&sub_input);
	  if (err)
	    break;
	}
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
	  break;
	}
    }

  if (err == 0)
    {
      vnet_dev_rv_t rv;

      clib_memcpy (args.device_id, device_id, sizeof (args.device_id));
      rv = vnet_dev_api_attach (vm, &args);
      vec_free (args.args);

      if (rv == VNET_DEV_OK)
	{
	  vec_foreach (if_args, if_args_vec)
	    {
	      if_args->dev_index = args.dev_index;
	      rv = vnet_dev_api_create_port_if (vm, if_args);
	      if (rv != VNET_DEV_OK)
		break;
	    }
	}

      if (rv != VNET_DEV_OK)
	err = clib_error_return (0, "error: %U for device '%s'",
				 format_vnet_dev_rv, rv, device_id);
    }

  vec_free (if_args_vec);
  return err;
}

uword
dev_config_process_node_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
			    vlib_frame_t *f)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_driver_name_t driver_name;
  unformat_input_t input;
  clib_error_t *err = 0;

  if (dm->startup_config == 0)
    return 0;

  unformat_init_vector (&input, dm->startup_config);
  dm->startup_config = 0;

  while (!err && unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      vnet_dev_device_id_t device_id;
      if (unformat (&input, "dev %U %U", unformat_c_string_array, device_id,
		    sizeof (device_id), unformat_vlib_cli_sub_input,
		    &sub_input))
	{
	  err = vnet_dev_config_one_device (vm, &sub_input, device_id);
	  unformat_free (&sub_input);
	}
      else if (unformat (&input, "dev %U", unformat_c_string_array, device_id,
			 sizeof (device_id)))
	{
	  unformat_input_t no_input = {};
	  unformat_init_vector (&no_input, 0);
	  err = vnet_dev_config_one_device (vm, &no_input, device_id);
	  unformat_free (&no_input);
	}
      else if (unformat (&input, "driver %U %U", unformat_c_string_array,
			 driver_name, sizeof (driver_name),
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  err = vnet_dev_config_driver_args (vm, &sub_input, driver_name);
	  unformat_free (&sub_input);
	}
      else
	err = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, &input);
    }

  unformat_free (&input);

  if (err)
    {
      log_err (0, "%U", format_clib_error, err);
      clib_error_free (err);
    }

  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);
  vlib_node_rename (vm, rt->node_index, "deleted-%u", rt->node_index);
  vec_add1 (dm->free_process_node_indices, rt->node_index);
  return 0;
}

VLIB_REGISTER_NODE (dev_config_process_node) = {
  .function = dev_config_process_node_fn,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dev-config",
};

static clib_error_t *
devices_config (vlib_main_t *vm, unformat_input_t *input)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  uword c;

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    vec_add1 (dm->startup_config, c);

  return 0;
}

VLIB_CONFIG_FUNCTION (devices_config, "devices");
