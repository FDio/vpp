/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/api.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "api",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

void *_vnet_dev_alloc_with_data (u32, u32);

static int
_vnet_dev_queue_size_validate (u32 size, vnet_dev_queue_config_t c)
{
  if (size < c.min_size)
    return 0;
  if (size > c.max_size)
    return 0;
  if (c.size_is_power_of_two && count_set_bits (size) != 1)
    return 0;
  if (c.multiplier && size % c.multiplier)
    return 0;

  return 1;
}

vnet_dev_rv_t
vnet_dev_api_attach (vlib_main_t *vm, vnet_dev_api_attach_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_bus_t *bus;
  vnet_dev_driver_t *driver;
  void *bus_dev_info = 0;
  u8 *dev_desc = 0;

  if (vnet_dev_by_id (args->device_id))
    return VNET_DEV_ERR_ALREADY_IN_USE;

  bus = vnet_dev_find_device_bus (vm, args->device_id);
  if (!bus)
    {
      log_err (dev, "unknown bus");
      rv = VNET_DEV_ERR_INVALID_BUS;
      goto done;
    }

  bus_dev_info = vnet_dev_get_device_info (vm, args->device_id);
  if (!bus_dev_info)
    {
      log_err (dev, "invalid or unsupported device id");
      rv = VNET_DEV_ERR_INVALID_DEVICE_ID;
      goto done;
    }

  vec_foreach (driver, dm->drivers)
    {
      if (args->driver_name[0] &&
	  strcmp (args->driver_name, driver->registration->name))
	continue;
      if (driver->ops.probe &&
	  (dev_desc = driver->ops.probe (vm, bus->index, bus_dev_info)))
	break;
    }

  if (!dev_desc)
    {
      log_err (dev, "driver not available for %s", args->device_id);
      rv = VNET_DEV_ERR_DRIVER_NOT_AVAILABLE;
      goto done;
    }

  dev = vnet_dev_alloc (vm, args->device_id, driver);
  if (!dev)
    {
      log_err (dev, "dev alloc failed for %s", args->device_id);
      rv = VNET_DEV_ERR_BUG;
      goto done;
    }
  dev->description = dev_desc;

  log_debug (0, "found '%v'", dev->description);

  rv = vnet_dev_process_call_op (vm, dev, vnet_dev_init);

done:
  if (bus_dev_info)
    bus->ops.free_device_info (vm, bus_dev_info);

  if (rv != VNET_DEV_OK && dev)
    vnet_dev_process_call_op_no_rv (vm, dev, vnet_dev_free);

  return rv;
}

vnet_dev_rv_t
vnet_dev_api_detach (vlib_main_t *vm, vnet_dev_api_detach_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);

  log_debug (dev, "detach");

  if (dev)
    return vnet_dev_process_call_op_no_rv (vm, dev, vnet_dev_free);

  return VNET_DEV_ERR_NOT_FOUND;
}

vnet_dev_rv_t
vnet_dev_api_reset (vlib_main_t *vm, vnet_dev_api_reset_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);

  log_debug (dev, "detach");

  if (!dev)
    return VNET_DEV_ERR_NOT_FOUND;

  if (dev->ops.device_reset)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  return vnet_dev_process_call_op (vm, dev, vnet_dev_reset);
}

vnet_dev_rv_t
vnet_dev_api_create_port_if (vlib_main_t *vm,
			     vnet_dev_api_create_port_if_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);
  vnet_dev_port_t *port = 0;
  u16 n_threads = vlib_get_n_threads ();

  log_debug (dev, "create_port_if: port %u", args->port_id);

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  pool_foreach_pointer (p, dev->ports)
    if (p->port_id == args->port_id)
      {
	port = p;
	break;
      }

  if (!port)
    return VNET_DEV_ERR_INVALID_DEVICE_ID;

  if (port->interface_created)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  if (args->num_rx_queues)
    {
      if (args->num_rx_queues > port->config.max_rx_queues)
	return VNET_DEV_ERR_INVALID_NUM_RX_QUEUES;
      port->intf.num_rx_queues = args->num_rx_queues;
    }
  else
    port->intf.num_rx_queues = clib_min (port->config.max_tx_queues, 1);

  if (args->num_tx_queues)
    {
      if (args->num_tx_queues > port->config.max_tx_queues)
	return VNET_DEV_ERR_INVALID_NUM_TX_QUEUES;
      port->intf.num_tx_queues = args->num_tx_queues;
    }
  else
    port->intf.num_tx_queues =
      clib_min (port->config.max_tx_queues, n_threads);

  if (args->rx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->rx_queue_size,
					  port->rx_queue_config))
	return VNET_DEV_ERR_INVALID_RX_QUEUE_SIZE;
      port->intf.rxq_sz = args->rx_queue_size;
    }
  else
    port->intf.rxq_sz = port->rx_queue_config.default_size;

  if (args->tx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->tx_queue_size,
					  port->tx_queue_config))
	return VNET_DEV_ERR_INVALID_TX_QUEUE_SIZE;
      port->intf.txq_sz = args->tx_queue_size;
    }
  else
    port->intf.txq_sz = port->tx_queue_config.default_size;

  clib_memcpy (port->intf.name, args->intf_name, sizeof (port->intf.name));

  return vnet_dev_process_call_port_op (vm, port, vnet_dev_port_if_create);
}

vnet_dev_rv_t
vnet_dev_api_remove_port_if (vlib_main_t *vm,
			     vnet_dev_api_remove_port_if_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  vnet_dev_port_t *port;

  si = vnet_get_sw_interface_or_null (vnm, args->sw_if_index);
  if (!si)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  hi = vnet_get_hw_interface_or_null (vnm, si->hw_if_index);
  if (!hi)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  if (pool_is_free_index (dm->ports_by_dev_instance, hi->dev_instance))
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);

  if (port->intf.hw_if_index != si->hw_if_index)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  return vnet_dev_process_call_port_op (vm, port, vnet_dev_port_if_remove);
}
