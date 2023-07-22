/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "config",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

static clib_error_t *
vnet_dev_config_one_interface (vlib_main_t *vm, unformat_input_t *input,
			       vnet_dev_create_if_args_t *args)
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
vnet_dev_config_one_device (vlib_main_t *vm, unformat_input_t *input,
			    char *device_id)
{
  log_debug (0, "device %s %U", device_id, format_unformat_input, input);
  clib_error_t *err = 0;
  vnet_dev_attach_args_t args = {};
  vnet_dev_create_if_args_t *if_args_vec = 0, *if_args;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      u32 n;

      if (unformat (input, "driver %U", unformat_c_string_array,
		    args.driver_name, sizeof (args.driver_name)))
	;
      else if (unformat (input, "port %u %U", &n, unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  vnet_dev_create_if_args_t *if_args;
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
      rv = vnet_dev_attach (vm, &args);

      if (rv == VNET_DEV_OK)
	{
	  vec_foreach (if_args, if_args_vec)
	    {
	      clib_memcpy (if_args->device_id, device_id,
			   sizeof (if_args->device_id));
	      rv = vnet_dev_create_if (vm, if_args);
	      if (rv != VNET_DEV_OK)
		break;
	    }

	  if (rv != VNET_DEV_OK)
	    err = clib_error_return (0, "error: %U for device '%s'",
				     format_vnet_dev_rv, rv, device_id);
	}
    }

  vec_free (if_args_vec);
  return err;
}

clib_error_t *
vnet_main_loop_enter (vlib_main_t *vm)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  unformat_input_t input;
  clib_error_t *err = 0;

  if (dm->startup_config == 0)
    return 0;

  log_debug (0, "startup config: %v", dm->startup_config);

  unformat_init_vector (&input, dm->startup_config);
  dm->startup_config = 0;

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      char device_id[VNET_DEV_MAX_DEVICE_ID_LEN];
      if (unformat (&input, "dev %U %U", unformat_c_string_array, device_id,
		    sizeof (device_id), unformat_vlib_cli_sub_input,
		    &sub_input))
	{
	  err = vnet_dev_config_one_device (vm, &sub_input, device_id);
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

  unformat_free (&input);

  return err;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (vnet_main_loop_enter) = {
  .runs_after = VLIB_INITS ("start_workers"),
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
