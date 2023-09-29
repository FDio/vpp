/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

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

vnet_dev_bus_t *
vnet_dev_find_device_bus (vlib_main_t *vm, vnet_dev_device_id_t id)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus;

  pool_foreach (bus, dm->buses)
    {
      int n = strlen (bus->registration->name);
      int l = strlen (id);
      int dl = strlen (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER);

      if (l <= n + dl)
	continue;

      if (strncmp (bus->registration->name, id, n))
	continue;

      if (strncmp (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER, id + n, dl))
	continue;

      return bus;
    }

  return 0;
}

void *
vnet_dev_get_device_info (vlib_main_t *vm, vnet_dev_device_id_t id)
{
  vnet_dev_bus_t *bus;

  bus = vnet_dev_find_device_bus (vm, id);
  if (bus == 0)
    return 0;

  return bus->ops.get_device_info (vm, id);
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

  if ((rv = bus->ops.device_open (vm, dev)) != VNET_DEV_OK)
    goto done;

  if ((rv = vnet_dev_process_create (vm, dev)) != VNET_DEV_OK)
    goto done;

  if ((rv = dev->ops.device_init (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device init failed [rv %d]", rv);
      goto done;
    }
  dev->initialized = 1;

done:
  if (bus_dev_info)
    bus->ops.free_device_info (vm, bus_dev_info);

  if (rv != VNET_DEV_OK)
    {
      if (dev)
	vnet_dev_free (vm, dev);
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_api_detach (vlib_main_t *vm, vnet_dev_api_detach_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);

  log_debug (dev, "detach");

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  vnet_dev_free (vm, dev);

  return VNET_DEV_OK;
}

char *nnn[9] = VNET_DEVICE_INPUT_NEXT_NODES;

vnet_dev_rv_t
vnet_dev_api_create_port_if (vlib_main_t *vm,
			     vnet_dev_api_create_port_if_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);
  vnet_dev_driver_t *driver;
  vnet_dev_port_t *port = 0;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rxq_sz, txq_sz, ti = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_if_t *intf;
  u16 n_threads = vlib_get_n_threads ();

  log_debug (dev, "create_if: port %u", args->port_id);

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  driver = pool_elt_at_index (dm->drivers, dev->driver_index);

  pool_foreach_pointer (p, dev->ports)
    if (p->port_id == args->port_id)
      {
	port = p;
	break;
      }

  if (!port)
    return VNET_DEV_ERR_INVALID_DEVICE_ID;

  if (args->num_rx_queues)
    {
      if (args->num_rx_queues > port->config.max_rx_queues)
	return VNET_DEV_ERR_INVALID_NUM_RX_QUEUES;
      num_rx_queues = args->num_rx_queues;
    }
  else
    num_rx_queues = clib_min (port->config.max_tx_queues, 1);

  if (args->num_tx_queues)
    {
      if (args->num_tx_queues > port->config.max_tx_queues)
	return VNET_DEV_ERR_INVALID_NUM_TX_QUEUES;
      num_tx_queues = args->num_tx_queues;
    }
  else
    num_tx_queues = clib_min (port->config.max_tx_queues, n_threads);

  if (args->rx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->rx_queue_size,
					  port->rx_queue_config))
	return VNET_DEV_ERR_INVALID_RX_QUEUE_SIZE;
      rxq_sz = args->rx_queue_size;
    }
  else
    rxq_sz = port->rx_queue_config.default_size;

  if (args->tx_queue_size)
    {
      if (!_vnet_dev_queue_size_validate (args->tx_queue_size,
					  port->tx_queue_config))
	return VNET_DEV_ERR_INVALID_TX_QUEUE_SIZE;
      txq_sz = args->tx_queue_size;
    }
  else
    txq_sz = port->tx_queue_config.default_size;

  log_debug (dev, "creating %u rx queues with size %u", num_rx_queues, rxq_sz);
  for (int i = 0; i < num_rx_queues; i++)
    if ((rv = vnet_dev_rx_queue_alloc (vm, port, rxq_sz)) != VNET_DEV_OK)
      goto error;

  log_debug (dev, "creating %u tx queues with size %u", num_tx_queues, txq_sz);
  for (u32 i = 0; i < num_tx_queues; i++)
    if ((rv = vnet_dev_tx_queue_alloc (vm, port, txq_sz)) != VNET_DEV_OK)
      goto error;

  pool_foreach_pointer (q, port->tx_queues)
    {
      q->assigned_threads = clib_bitmap_set (q->assigned_threads, ti, 1);
      log_debug (dev, "create_if: port %u tx queue %u assigned to thread %u",
		 port->port_id, q->queue_id, ti);
      if (++ti >= n_threads)
	break;
    }

  if (port->type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      vnet_dev_rx_node_runtime_t *rtd;
      vnet_device_class_t *dev_class;
      vnet_sw_interface_t *sw;
      vnet_hw_interface_t *hw;
      u32 rx_node_index;

      pool_get_zero (dm->interfaces, intf);
      port->dev_if_index = intf - dm->interfaces;
      intf->driver_index = port->dev->driver_index;
      intf->dev_index = port->dev->index;
      intf->port_index = port->index;
      clib_memcpy (intf->name, args->intf_name, sizeof (intf->name));

      /* hack to provide per-port tx node function */
      dev_class = vnet_get_device_class (vnm, driver->dev_class_index);
      dev_class->tx_fn_registrations = port->tx_node.node_fn->registrations;
      dev_class->format_tx_trace = port->tx_node.format_trace;
      dev_class->tx_function_error_counters = port->tx_node.error_counters;
      dev_class->tx_function_n_errors = port->tx_node.n_error_counters;

      /* create new interface including tx and output nodes */
      intf->hw_if_index = vnet_eth_register_interface (
	vnm, &(vnet_eth_interface_registration_t){
	       .address = port->config.hw_addr,
	       .max_frame_size = port->config.max_frame_size,
	       .dev_class_index = driver->dev_class_index,
	       .dev_instance = port->dev_if_index,
	     });

      sw = vnet_get_hw_sw_interface (vnm, intf->hw_if_index);
      hw = vnet_get_hw_interface (vnm, intf->hw_if_index);
      vlib_node_rename (vm, hw->tx_node_index, "%s-port-%u-tx", dev->device_id,
			port->port_id);
      vlib_node_rename (vm, hw->output_node_index, "%s-port-%u-output",
			dev->device_id, port->port_id);
      intf->sw_if_index = sw->sw_if_index;
      vnet_hw_interface_set_flags (
	vnm, intf->hw_if_index,
	port->link_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      if (port->speed)
	vnet_hw_interface_set_link_speed (vnm, intf->hw_if_index, port->speed);

      port->tx_node_index = hw->tx_node_index;
      port->interface_assigned = 1;

      /* create / reuse rx node */
      if (vec_len (dm->free_rx_node_indices))
	{
	  vlib_node_t *n;
	  rx_node_index = vec_pop (dm->free_rx_node_indices);
	  vlib_node_rename (vm, rx_node_index, "%s-port-%u-rx", dev->device_id,
			    port->port_id);
	  n = vlib_get_node (vm, rx_node_index);
	  n->function = vlib_node_get_preferred_node_fn_variant (
	    vm, port->rx_node.node_fn->registrations);
	  n->format_trace = port->rx_node.format_trace;
	  vlib_register_errors (vm, rx_node_index,
				port->rx_node.n_error_counters, 0,
				port->rx_node.error_counters);
	}
      else
	{
	  dev_class->format_tx_trace = port->tx_node.format_trace;
	  dev_class->tx_function_error_counters = port->tx_node.error_counters;
	  dev_class->tx_function_n_errors = port->tx_node.n_error_counters;
	  vlib_node_registration_t rx_node_reg = {
	    //.sibling_of = "device-input",
	    .type = VLIB_NODE_TYPE_INPUT,
	    .state = VLIB_NODE_STATE_DISABLED,
	    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	    .node_fn_registrations = port->rx_node.node_fn->registrations,
	    .format_trace = port->rx_node.format_trace,
	    .error_counters = port->rx_node.error_counters,
	    .n_errors = port->rx_node.n_error_counters,
	  };
	  rx_node_index = vlib_register_node (
	    vm, &rx_node_reg, "%s-port-%u-rx", dev->device_id, port->port_id);
	  for (int i = 0; i < ARRAY_LEN (nnn); i++)
	    vlib_node_add_named_next (vm, rx_node_index, nnn[i]);
	}

      rtd = vlib_node_get_runtime_data (vm, rx_node_index);
      rtd->hw_if_index = intf->hw_if_index;
      rtd->sw_if_index = intf->sw_if_index;
      rtd->next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      port->rx_node_index = rx_node_index;
      port->rx_node_created = 1;

      vlib_worker_thread_node_runtime_update ();
      log_debug (dev,
		 "ethernet interface created, hw_if_index %u sxw_if_index %u "
		 "rx_node_index %u tx_node_index %u",
		 intf->hw_if_index, intf->sw_if_index, port->rx_node_index,
		 port->tx_node_index);
    }

  vnet_dev_port_update_tx_node_runtime (port);

  if (port->port_ops.init)
    rv = port->port_ops.init (vm, port);

error:
  if (rv != VNET_DEV_OK)
    vnet_dev_port_remove (vm, port);
  return rv;
}
