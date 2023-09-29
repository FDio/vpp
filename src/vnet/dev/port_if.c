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
  .subclass_name = "port_if",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

void *_vnet_dev_alloc_with_data (u32 sz, u32 data_sz);

char *nnn[9] = VNET_DEVICE_INPUT_NEXT_NODES;

vnet_dev_rv_t
vnet_dev_port_if_create (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_main_t *vnm = vnet_get_main ();
  u16 n_threads = vlib_get_n_threads ();
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_t **pp;
  vnet_dev_rv_t rv;
  u16 ti = 0;

  log_debug (dev, "creating %u rx queues with size %u",
	     port->intf.num_rx_queues, port->intf.rxq_sz);

  for (int i = 0; i < port->intf.num_rx_queues; i++)
    if ((rv = vnet_dev_rx_queue_alloc (vm, port, port->intf.rxq_sz)) !=
	VNET_DEV_OK)
      goto error;

  log_debug (dev, "creating %u tx queues with size %u",
	     port->intf.num_tx_queues, port->intf.txq_sz);
  for (u32 i = 0; i < port->intf.num_tx_queues; i++)
    if ((rv = vnet_dev_tx_queue_alloc (vm, port, port->intf.txq_sz)) !=
	VNET_DEV_OK)
      goto error;

  pool_foreach_pointer (q, port->tx_queues)
    {
      q->assigned_threads = clib_bitmap_set (q->assigned_threads, ti, 1);
      log_debug (dev, "create_if: port %u tx queue %u assigned to thread %u",
		 port->port_id, q->queue_id, ti);
      if (++ti >= n_threads)
	break;
    }

  /* pool of port pointers helps us to assign unique dev_instance */
  pool_get (dm->ports_by_dev_instance, pp);
  port->intf.dev_instance = pp - dm->ports_by_dev_instance;
  pp[0] = port;

  if (port->type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      vnet_dev_rx_node_runtime_t *rtd;
      vnet_device_class_t *dev_class;
      vnet_dev_driver_t *driver;
      vnet_sw_interface_t *sw;
      vnet_hw_interface_t *hw;
      u32 rx_node_index;

      driver = pool_elt_at_index (dm->drivers, dev->driver_index);

      /* hack to provide per-port tx node function */
      dev_class = vnet_get_device_class (vnm, driver->dev_class_index);
      dev_class->tx_fn_registrations = port->tx_node.node_fn->registrations;
      dev_class->format_tx_trace = port->tx_node.format_trace;
      dev_class->tx_function_error_counters = port->tx_node.error_counters;
      dev_class->tx_function_n_errors = port->tx_node.n_error_counters;

      /* create new interface including tx and output nodes */
      port->intf.hw_if_index = vnet_eth_register_interface (
	vnm, &(vnet_eth_interface_registration_t){
	       .address = port->config.hw_addr,
	       .max_frame_size = port->config.max_frame_size,
	       .dev_class_index = driver->dev_class_index,
	       .dev_instance = port->intf.dev_instance,
	     });

      sw = vnet_get_hw_sw_interface (vnm, port->intf.hw_if_index);
      hw = vnet_get_hw_interface (vnm, port->intf.hw_if_index);
      port->intf.sw_if_index = sw->sw_if_index;
      vnet_hw_interface_set_flags (
	vnm, port->intf.hw_if_index,
	port->link_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      if (port->speed)
	vnet_hw_interface_set_link_speed (vnm, port->intf.hw_if_index,
					  port->speed);

      port->intf.tx_node_index = hw->tx_node_index;

      /* create / reuse rx node */
      if (vec_len (dm->free_rx_node_indices))
	{
	  vlib_node_t *n;
	  rx_node_index = vec_pop (dm->free_rx_node_indices);
	  vlib_node_rename (vm, rx_node_index, "%s-rx", port->intf.name);
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
	  rx_node_index =
	    vlib_register_node (vm, &rx_node_reg, "%s-rx", port->intf.name);
	  for (int i = 0; i < ARRAY_LEN (nnn); i++)
	    vlib_node_add_named_next (vm, rx_node_index, nnn[i]);
	}

      rtd = vlib_node_get_runtime_data (vm, rx_node_index);
      rtd->hw_if_index = port->intf.hw_if_index;
      rtd->sw_if_index = port->intf.sw_if_index;
      rtd->next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      port->intf.rx_node_index = rx_node_index;

      vlib_worker_thread_node_runtime_update ();
      log_debug (dev,
		 "ethernet interface created, hw_if_index %u sxw_if_index %u "
		 "rx_node_index %u tx_node_index %u",
		 port->intf.hw_if_index, port->intf.sw_if_index,
		 port->intf.rx_node_index, port->intf.tx_node_index);
    }

  port->interface_created = 1;

  vnet_dev_port_update_tx_node_runtime (vm, port);

  if (port->port_ops.init)
    rv = port->port_ops.init (vm, port);

error:
  if (rv != VNET_DEV_OK)
    vnet_dev_port_if_remove (vm, port);
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_if_remove (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();

  vnet_dev_port_validate (vm, port);

  if (!port->interface_created)
    return VNET_DEV_ERR_NOT_FOUND;

  vnet_dev_port_stop (vm, port);

  pool_foreach_pointer (q, port->tx_queues)
    vnet_dev_tx_queue_free (vm, q);

  pool_foreach_pointer (q, port->rx_queues)
    vnet_dev_rx_queue_free (vm, q);

  pool_free (port->rx_queues);
  pool_free (port->tx_queues);

  vlib_worker_thread_barrier_sync (vm);
  vnet_delete_hw_interface (vnm, port->intf.hw_if_index);
  vlib_worker_thread_barrier_release (vm);

  vlib_node_rename (vm, port->intf.rx_node_index, "deleted-%u",
		    port->intf.rx_node_index);
  vec_add1 (dm->free_rx_node_indices, port->intf.rx_node_index);

  port->interface_created = 0;

  pool_put_index (dm->ports_by_dev_instance, port->intf.dev_instance);

  port->intf = (typeof (port->intf)){};

  return VNET_DEV_OK;
}
