/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "port",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

void
vnet_dev_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "rx_queue_free: queue %u", rxq->queue_id);
  if (port->rx_queue_ops.free)
    port->rx_queue_ops.free (vm, rxq);
  pool_put_index (port->rx_queues, rxq->index);
  clib_mem_free (rxq);
}

vnet_dev_rv_t
vnet_dev_rx_queue_alloc (vlib_main_t *vm, vnet_dev_port_t *port,
			 u16 queue_size)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_rx_queue_t *rxq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u16 n_threads = vlib_get_n_threads ();

  vnet_dev_port_validate (vm, port);

  log_debug (dev, "rx_queue_alloc: port %u queue_size %u", port->port_id,
	     queue_size);

  rxq = vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				  port->rx_queue_config.data_size);
  pool_get (port->rx_queues, qp);
  qp[0] = rxq;
  rxq->enabled = 1;
  rxq->port = port;
  rxq->size = queue_size;
  rxq->index = qp - port->rx_queues;

  if (n_threads > 1)
    {
      rxq->rx_thread_index = dm->next_rx_queue_thread++;
      if (dm->next_rx_queue_thread >= n_threads)
	dm->next_rx_queue_thread = 1;
    }

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);

  if (port->rx_queue_ops.alloc)
    rv = port->rx_queue_ops.alloc (vm, rxq);

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "rx_queue_add: driver rejected with rv %d", rv);
      vnet_dev_rx_queue_free (vm, rxq);
    }
  else
    log_debug (dev, "rx_queue_add: queue %u added, assigned to thread %u",
	       rxq->queue_id, rxq->rx_thread_index);

  return rv;
}

vnet_dev_rv_t
vnet_dev_rx_queue_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  if (rxq->port->rx_queue_ops.start)
    rv = rxq->port->rx_queue_ops.start (vm, rxq);

  if (rv == VNET_DEV_OK)
    rxq->started = 1;

  return rv;
}

void
vnet_dev_rx_queue_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  if (rxq->port->rx_queue_ops.stop)
    rxq->port->rx_queue_ops.stop (vm, rxq);
  vlib_node_set_state (vm, rxq->port->intf.rx_node_index,
		       VLIB_NODE_STATE_DISABLED);
  rxq->started = 0;
}

void
vnet_dev_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  vnet_dev_port_validate (vm, port);

  log_debug (dev, "tx_queue_free: queue %u", txq->queue_id);
  if (port->tx_queue_ops.free)
    port->tx_queue_ops.free (vm, txq);

  clib_bitmap_free (txq->assigned_threads);
  pool_put_index (port->tx_queues, txq->index);
  clib_mem_free (txq);
}

vnet_dev_rv_t
vnet_dev_tx_queue_alloc (vlib_main_t *vm, vnet_dev_port_t *port,
			 u16 queue_size)
{
  vnet_dev_tx_queue_t *txq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "tx_queue_alloc: port %u size %u", port->port_id,
	     queue_size);

  txq = vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				  port->tx_queue_config.data_size);
  pool_get (port->tx_queues, qp);
  qp[0] = txq;
  txq->port = port;
  txq->size = queue_size;
  txq->index = qp - port->tx_queues;

  if (port->tx_queue_ops.alloc)
    rv = port->tx_queue_ops.alloc (vm, txq);

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "tx_queue_alloc: driver rejected with rv %d", rv);
      vnet_dev_tx_queue_free (vm, txq);
    }
  else
    log_debug (dev, "tx_queue_alloc: queue %u added", txq->queue_id);

  return rv;
}

vnet_dev_rv_t
vnet_dev_tx_queue_start (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  if (txq->port->tx_queue_ops.start)
    rv = txq->port->tx_queue_ops.start (vm, txq);

  if (rv == VNET_DEV_OK)
    txq->started = 1;

  return rv;
}

void
vnet_dev_tx_queue_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  if (txq->port->tx_queue_ops.stop)
    txq->port->tx_queue_ops.stop (vm, txq);
  txq->started = 0;
}

void
vnet_dev_port_remove (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  vnet_dev_port_validate (vm, port);

  ASSERT (port->started == 0);

  log_debug (dev, "port_remove: port %u", port->port_id);

  if (port->interface_created)
    vnet_dev_port_if_remove (vm, port);

  if (port->port_ops.free)
    port->port_ops.free (vm, port);

  pool_put_index (dev->ports, port->index);
  clib_mem_free (port);
}

void
vnet_dev_port_update_tx_node_runtime (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_validate (vm, port);

  pool_foreach_pointer (q, port->tx_queues)
    {
      u32 ti;
      clib_bitmap_foreach (ti, q->assigned_threads)
	{
	  vlib_main_t *tvm = vlib_get_main_by_index (ti);
	  vlib_node_runtime_t *nr =
	    vlib_node_get_runtime (tvm, port->intf.tx_node_index);
	  vnet_dev_tx_node_runtime_t *tnr = vnet_dev_get_tx_node_runtime (nr);
	  tnr->hw_if_index = port->intf.hw_if_index;
	  tnr->lock_required =
	    clib_bitmap_count_set_bits (q->assigned_threads) > 1 ? 1 : 0;
	  tnr->tx_queue = q;
	}
    }
}

void
vnet_dev_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rt_op_t *ops = 0;

  log_debug (dev, "port_stop: stopping port %u", port->port_id);

  pool_foreach_pointer (q, port->rx_queues)
    if (q->started)
      {
	vnet_dev_rt_op_t op = {
	  .type = VNET_DEV_RT_OP_TYPE_RX_QUEUE,
	  .action = VNET_DEV_RT_OP_ACTION_STOP,
	  .thread_index = q->rx_thread_index,
	  .rx_queue = q,
	};
	vec_add1 (ops, op);
      }

  vnet_dev_rt_exec_ops (vm, dev, ops, vec_len (ops));
  vec_free (ops);

  port->port_ops.stop (vm, port);

  pool_foreach_pointer (q, port->rx_queues)
    {
      q->started = 0;
      log_debug (dev, "port_stop: port %u queue %u stopped", port->port_id,
		 q->queue_id);
    }

  log_debug (dev, "port_stop: port %u stopped", port->port_id);
  port->started = 0;
}

vnet_dev_rv_t
vnet_dev_port_start_all_rx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_validate (vm, port);

  pool_foreach_pointer (q, port->rx_queues)
    {
      rv = vnet_dev_rx_queue_start (vm, q);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start_all_tx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_validate (vm, port);

  pool_foreach_pointer (q, port->tx_queues)
    {
      rv = vnet_dev_tx_queue_start (vm, q);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rt_op_t *ops = 0;
  vnet_dev_rv_t rv;

  vnet_dev_port_validate (vm, port);

  log_debug (dev, "port_start: starting port %u", port->port_id);

  vnet_dev_port_update_tx_node_runtime (vm, port);

  if ((rv = port->port_ops.start (vm, port)) != VNET_DEV_OK)
    {
      vnet_dev_port_stop (vm, port);
      return rv;
    }

  pool_foreach_pointer (q, port->rx_queues)
    if (q->enabled)
      {
	vnet_dev_rt_op_t op = {
	  .type = VNET_DEV_RT_OP_TYPE_RX_QUEUE,
	  .action = VNET_DEV_RT_OP_ACTION_START,
	  .thread_index = q->rx_thread_index,
	  .rx_queue = q,
	};
	vec_add1 (ops, op);
      }

  vnet_dev_rt_exec_ops (vm, dev, ops, vec_len (ops));
  vec_free (ops);

  pool_foreach_pointer (q, port->rx_queues)
    if (q->enabled)
      {
	log_debug (dev, "port_start: port %u queue %u started", port->port_id,
		   q->queue_id);
	q->started = 1;
      }

  port->started = 1;
  log_debug (dev, "port_start: port %u started", port->port_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t id,
		   vnet_dev_port_add_args_t *args)
{
  vnet_dev_port_t **pp, *port;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  ASSERT (args->port.config.type != VNET_DEV_PORT_TYPE_UNKNOWN);
  ASSERT (args->port.config.max_frame_size);

  port = vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				   args->port.config.data_size);
  pool_get (dev->ports, pp);
  pp[0] = port;
  port->port_id = id;
  port->index = pp - dev->ports;
  port->dev = dev;
  port->type = args->port.config.type;
  port->config = args->port.config;
  port->rx_queue_config = args->rx_queue.config;
  port->tx_queue_config = args->tx_queue.config;
  port->rx_queue_ops = args->rx_queue.ops;
  port->tx_queue_ops = args->tx_queue.ops;
  port->port_ops = args->port.ops;
  port->rx_node = args->rx_node;
  port->tx_node = args->tx_node;

  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_validate (vm, port);

  if (port->started == 0 && port->admin_up && port->link_up)
    rv = vnet_dev_port_start (vm, port);
  else if (port->started == 1 && (port->admin_up == 0 || port->link_up == 0))
    vnet_dev_port_stop (vm, port);
  else
    {
      log_debug (dev, "port_start_stop: no change");
      return VNET_DEV_OK;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_config_change (vlib_main_t *vm, vnet_dev_port_t *port,
			     vnet_dev_port_config_changes_t changes)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int start_stop = 0;

  vnet_dev_port_validate (vm, port);

  if (port->port_ops.config_change)
    rv = port->port_ops.config_change (vm, port);

  if (rv != VNET_DEV_OK)
    return rv;

  if (changes.change.admin_state)
    {
      ASSERT (changes.admin_state != port->admin_up);
      port->admin_up = changes.admin_state;
      log_debug (dev, "port %u admin state changed to %s", port->port_id,
		 port->admin_up ? "up" : "down");
      start_stop = 1;
    }

  if (start_stop)
    vnet_dev_port_start_stop (vm, port);

  return VNET_DEV_OK;
}

void
vnet_dev_port_state_change (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_port_state_changes_t changes)
{
  vnet_main_t *vnm = vnet_get_main ();
  int port_start_stop = 1;

  vnet_dev_port_validate (vm, port);

  if (changes.change.link_speed)
    {
      port->speed = changes.link_speed;
      if (port->interface_created)
	vnet_hw_interface_set_link_speed (vnm, port->intf.hw_if_index,
					  changes.link_speed);
      log_debug (port->dev, "port speed changed to %u", changes.link_speed);
    }

  if (changes.change.link_state)
    {
      port->link_up = changes.link_state;
      if (port->interface_created)
	vnet_hw_interface_set_flags (
	  vnm, port->intf.hw_if_index,
	  changes.link_state ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      log_debug (port->dev, "port link state changed to %s",
		 changes.link_state ? "up" : "down");
    }

  if (port_start_stop)
    vnet_dev_port_start_stop (vm, port);
}

void
vnet_dev_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_counter_t *counters, u16 n_counters)
{
  vnet_dev_port_validate (vm, port);

  port->counter_main =
    vnet_dev_counters_alloc (vm, counters, n_counters, "%s port %u counters",
			     port->dev->device_id, port->port_id);
}

void
vnet_dev_port_free_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_validate (vm, port);

  if (port->counter_main)
    vnet_dev_counters_free (vm, port->counter_main);
}

void
vnet_dev_rx_queue_add_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq,
				vnet_dev_counter_t *counters, u16 n_counters)
{
  rxq->counter_main = vnet_dev_counters_alloc (
    vm, counters, n_counters, "%s port %u rx-queue %u counters",
    rxq->port->dev->device_id, rxq->port->port_id, rxq->queue_id);
}

void
vnet_dev_rx_queue_free_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  if (rxq->counter_main)
    vnet_dev_counters_free (vm, rxq->counter_main);
}

void
vnet_dev_tx_queue_add_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *txq,
				vnet_dev_counter_t *counters, u16 n_counters)
{
  txq->counter_main = vnet_dev_counters_alloc (
    vm, counters, n_counters, "%s port %u tx-queue %u counters",
    txq->port->dev->device_id, txq->port->port_id, txq->queue_id);
}

void
vnet_dev_tx_queue_free_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  if (txq->counter_main)
    vnet_dev_counters_free (vm, txq->counter_main);
}

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

  if (port->intf.name[0] == 0)
    {
      u8 *s;
      s = format (0, "%s%u/%u",
		  dm->drivers[port->dev->driver_index].registration->name,
		  port->dev->index, port->index);
      u32 n = vec_len (s);

      if (n >= sizeof (port->intf.name))
	{
	  vec_free (s);
	  return VNET_DEV_ERR_BUG;
	}
      clib_memcpy (port->intf.name, s, n);
      port->intf.name[n] = 0;
      vec_free (s);
    }

  log_debug (dev,
	     "port_if_create: allocating %u rx queues with size %u and %u tx "
	     "queues with size %u",
	     port->intf.num_rx_queues, port->intf.rxq_sz,
	     port->intf.num_tx_queues, port->intf.txq_sz);

  for (int i = 0; i < port->intf.num_rx_queues; i++)
    if ((rv = vnet_dev_rx_queue_alloc (vm, port, port->intf.rxq_sz)) !=
	VNET_DEV_OK)
      goto error;

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
      port->rx_node_assigned = 1;
      port->intf.rx_node_index = rx_node_index;

      rtd = vlib_node_get_runtime_data (vm, rx_node_index);
      rtd->hw_if_index = port->intf.hw_if_index;
      rtd->sw_if_index = port->intf.sw_if_index;
      rtd->next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

      vlib_worker_thread_node_runtime_update ();
      log_debug (dev,
		 "ethernet interface created, hw_if_index %u sw_if_index %u "
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

  if (port->started)
    vnet_dev_port_stop (vm, port);

  if (port->interface_created)
    {
      vlib_worker_thread_barrier_sync (vm);
      vnet_delete_hw_interface (vnm, port->intf.hw_if_index);
      vlib_worker_thread_barrier_release (vm);
      port->interface_created = 0;
    }

  if (port->rx_node_assigned)
    {
      vlib_node_rename (vm, port->intf.rx_node_index, "deleted-%u",
			port->intf.rx_node_index);
      vec_add1 (dm->free_rx_node_indices, port->intf.rx_node_index);
      port->rx_node_assigned = 0;
    }

  pool_foreach_pointer (q, port->tx_queues)
    vnet_dev_tx_queue_free (vm, q);

  pool_foreach_pointer (q, port->rx_queues)
    vnet_dev_rx_queue_free (vm, q);

  pool_free (port->rx_queues);
  pool_free (port->tx_queues);

  pool_put_index (dm->ports_by_dev_instance, port->intf.dev_instance);

  port->intf = (typeof (port->intf)){};

  return VNET_DEV_OK;
}
