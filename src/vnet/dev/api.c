/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>
#include <vnet/dev/api.h>
#include <vppinfra/error.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "api",
};

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
  u64 probe_handle = 0;
  u8 *dev_desc = 0;

  log_debug (0, "%s driver %s flags '%U' args '%v'", args->device_id,
	     args->driver_name, format_vnet_dev_flags, &args->flags,
	     args->args);

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
      if (driver->ops.probe)
	{
	  vnet_dev_probe_args_t pa = {
	    .bus_index = bus->index,
	    .device_info = bus_dev_info,
	  };
	  if ((dev_desc = driver->ops.probe (vm, &pa)))
	    {
	      probe_handle = pa.probe_handle;
	      break;
	    }
	}
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
  dev->probe_handle = probe_handle;

  if (driver->registration->device.args)
    dev->args = clib_args_init (driver->registration->device.args);

  if (args->args)
    {
      clib_error_t *err = clib_args_parse (dev->args, args->args);
      if (err)
	{
	  log_err (dev, "%U", format_clib_error, err);
	  clib_error_free (err);
	  rv = VNET_DEV_ERR_INVALID_ARG;
	  goto done;
	}
    }

  if ((args->flags.e & VNET_DEV_F_NO_STATS) == 0)
    dev->poll_stats = 1;

  log_debug (0, "found '%v'", dev->description);

  rv = vnet_dev_process_call_op (vm, dev, vnet_dev_init);

done:
  if (bus_dev_info)
    bus->ops.free_device_info (vm, bus_dev_info);

  if (rv != VNET_DEV_OK && dev)
    vnet_dev_process_call_op_no_rv (vm, dev, vnet_dev_free);
  else if (dev)
    args->dev_index = dev->index;

  return rv;
}

vnet_dev_rv_t
vnet_dev_api_detach (vlib_main_t *vm, vnet_dev_api_detach_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_index (args->dev_index);

  log_debug (dev, "detach");

  if (dev)
    return vnet_dev_process_call_op_no_rv (vm, dev, vnet_dev_detach);

  return VNET_DEV_ERR_NOT_FOUND;
}

vnet_dev_rv_t
vnet_dev_api_reset (vlib_main_t *vm, vnet_dev_api_reset_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);

  log_debug (dev, "reset");

  if (!dev)
    return VNET_DEV_ERR_NOT_FOUND;

  if (dev->ops.reset == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  return vnet_dev_process_call_op (vm, dev, vnet_dev_reset);
}

vnet_dev_rv_t
vnet_dev_api_create_port_if (vlib_main_t *vm,
			     vnet_dev_api_create_port_if_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_index (args->dev_index);
  vnet_dev_port_t *port = 0;
  vnet_dev_port_if_create_args_t a = {};
  u16 n_threads = vlib_get_n_threads ();
  int default_is_intr_mode;
  vnet_dev_rv_t rv;

  log_debug (dev,
	     "create_port_if: dev_index %u port %u intf_name '%s' num_rx_q %u "
	     "num_tx_q %u rx_q_sz %u tx_q_sz %u, flags '%U' args '%v'",
	     args->dev_index, args->port_id, args->intf_name,
	     args->num_rx_queues, args->num_tx_queues, args->rx_queue_size,
	     args->tx_queue_size, format_vnet_dev_port_flags, &args->flags,
	     args->args);

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  foreach_vnet_dev_port (p, dev)
    if (p->port_id == args->port_id)
      {
	port = p;
	break;
      }

  if (!port)
    return VNET_DEV_ERR_INVALID_DEVICE_ID;

  if (port->interfaces)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  if (args->args)
    {
      clib_error_t *err = clib_args_parse (port->args, args->args);
      if (err)
	{
	  log_err (dev, "%U", format_clib_error, err);
	  clib_error_free (err);
	  return VNET_DEV_ERR_INVALID_ARG;
	}
    }

  default_is_intr_mode = (args->flags.e & VNET_DEV_PORT_F_INTERRUPT_MODE) != 0;
  if (default_is_intr_mode && port->attr.caps.interrupt_mode == 0)
    {
      log_err (dev, "interrupt mode requested and port doesn't support it");
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  if (args->flags.e & VNET_DEV_PORT_F_QUEUE_PER_THREAD)
    {
      if (args->num_rx_queues)
	return VNET_DEV_ERR_INVALID_NUM_RX_QUEUES;
      if (args->num_tx_queues)
	return VNET_DEV_ERR_INVALID_NUM_TX_QUEUES;
      args->num_rx_queues = args->num_tx_queues = n_threads;
    }

  if (args->num_rx_queues)
    {
      if (args->num_rx_queues > port->attr.max_rx_queues)
	return VNET_DEV_ERR_INVALID_NUM_RX_QUEUES;
      a.num_rx_queues = args->num_rx_queues;
    }
  else
    a.num_rx_queues = 1;

  if (args->num_tx_queues)
    {
      if (args->num_tx_queues > port->attr.max_tx_queues)
	return VNET_DEV_ERR_INVALID_NUM_TX_QUEUES;
      a.num_tx_queues = args->num_tx_queues;
    }
  else
    a.num_tx_queues = clib_min (port->attr.max_tx_queues, n_threads);

  if (args->rx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->rx_queue_size,
					  port->rx_queue_config))
	return VNET_DEV_ERR_INVALID_RX_QUEUE_SIZE;
      a.rxq_sz = args->rx_queue_size;
    }
  else
    a.rxq_sz = port->rx_queue_config.default_size;

  if (args->tx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->tx_queue_size,
					  port->tx_queue_config))
	return VNET_DEV_ERR_INVALID_TX_QUEUE_SIZE;
      a.txq_sz = args->tx_queue_size;
    }
  else
    a.txq_sz = port->tx_queue_config.default_size;

  clib_memcpy (a.name, args->intf_name, sizeof (a.name));
  a.default_is_intr_mode = default_is_intr_mode;
  a.consistent_qp = (args->flags.n & VNET_DEV_PORT_F_CONSISTENT_QP) != 0;
  a.queue_per_thread = (args->flags.n & VNET_DEV_PORT_F_QUEUE_PER_THREAD) != 0;

  rv = vnet_dev_process_call_port_op_with_ptr (vm, port,
					       vnet_dev_port_if_create, &a);
  args->sw_if_index = (rv == VNET_DEV_OK) ? a.sw_if_index : ~0;

  return rv;
}

vnet_dev_rv_t
vnet_dev_api_port_add_sec_if (vlib_main_t *vm,
			      vnet_dev_api_port_add_sec_if_args_t *args)
{
  vnet_dev_port_t *port = 0;
  vnet_dev_t *dev = 0;
  vnet_dev_port_sec_if_create_args_t a = {};
  vnet_dev_rv_t rv = VNET_DEV_OK;

  port = vnet_dev_get_port_from_sw_if_index (args->primary_sw_if_index);
  if (port == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  log_debug (dev,
	     "create_port_if: primary_sw_if_index %u intf_name '%s' "
	     "args '%v'",
	     args->primary_sw_if_index, args->intf_name, args->args);

  if (port->interfaces == 0)
    return VNET_DEV_ERR_PRIMARY_INTERFACE_MISSING;

  clib_memcpy (a.name, args->intf_name, sizeof (a.name));
  a.args = args->args;

  rv = vnet_dev_process_call_port_op_with_ptr (vm, port,
					       vnet_dev_port_add_sec_if, &a);

  if (rv != VNET_DEV_OK)
    args->sw_if_index = ~0;
  else
    args->sw_if_index = a.sw_if_index;

  return rv;
}

vnet_dev_rv_t
vnet_dev_api_remove_port_if (vlib_main_t *vm,
			     vnet_dev_api_remove_port_if_args_t *args)
{
  vnet_dev_port_t *port;

  port = vnet_dev_get_port_from_sw_if_index (args->sw_if_index);

  if (port == 0)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  return vnet_dev_process_call_port_op (vm, port, vnet_dev_port_if_remove);
}

vnet_dev_rv_t
vnet_dev_api_port_del_sec_if (vlib_main_t *vm,
			      vnet_dev_api_port_del_sec_if_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si, *sup_si;
  vnet_hw_interface_t *hi;
  vnet_dev_port_t *port;

  si = vnet_get_sw_interface_or_null (vnm, args->sw_if_index);
  if (!si)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  if (si->sup_sw_if_index == si->sw_if_index)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  sup_si = vnet_get_sw_interface_or_null (vnm, si->sup_sw_if_index);
  if (!sup_si)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  hi = vnet_get_hw_interface_or_null (vnm, sup_si->hw_if_index);
  if (!hi)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  if (pool_is_free_index (dm->dev_instances, hi->dev_instance))
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);

  if (port->interfaces->primary_interface.hw_if_index != si->hw_if_index)
    return VNET_DEV_ERR_UNKNOWN_INTERFACE;

  return vnet_dev_process_call_port_op_with_ptr (
    vm, port, vnet_dev_port_del_sec_if,
    &(vnet_dev_port_del_sec_if_args_t){ .sw_if_index = args->sw_if_index });
}

vnet_dev_rv_t
vnet_dev_api_port_set_rss_key (vlib_main_t *vm,
			       vnet_dev_api_port_set_rss_key_args_t *args)
{
  vnet_dev_port_t *port = 0;
  vnet_dev_t *dev = vnet_dev_by_index (args->dev_index);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_SET_RSS_CONFIG,
    .rss_config = {
      .key = args->rss_key,
      .ip4 = VNET_ETH_RSS_TYPE_NOT_SET,
      .ip6 = VNET_ETH_RSS_TYPE_NOT_SET,
    },
  };

  if (!dev)
    return VNET_DEV_ERR_UNKNOWN_DEVICE;

  log_debug (dev, "port %u rss_key %U", args->port_id,
	     format_hex_bytes_no_wrap, args->rss_key.key,
	     args->rss_key.length);

  port = vnet_dev_get_port_by_id (dev, args->port_id);
  if (!port)
    return VNET_DEV_ERR_UNKNOWN_DEVICE;

  rv = vnet_dev_port_cfg_change_req_validate (vm, port, &req);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "RSS key cannot be set");
      return rv;
    }

  rv = vnet_dev_process_port_cfg_change_req (vm, port, &req);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "device failed to set RSS key");
      return rv;
    }

  return rv;
}
