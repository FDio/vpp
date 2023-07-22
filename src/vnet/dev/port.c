/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "port",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

void *_vnet_dev_alloc_with_data (u32 sz, u32 data_sz);

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

static void
vnet_dev_rx_queue_remove (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "rx_queue_remove: queue %u", rxq->queue_id);
  if (port->ops.rx_queue_free)
    port->ops.rx_queue_free (vm, rxq);
  pool_put_index (port->rx_queues, rxq->index);
}

static vnet_dev_rv_t
vnet_dev_rx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port, u16 queue_size)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_rx_queue_t *rxq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u16 n_threads = vlib_get_n_threads ();

  log_debug (dev, "rx_queue_add: port %u queue_size %u", port->port_id,
	     queue_size);

  rxq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				   port->rx_queue_config.data_size);
  pool_get (port->rx_queues, qp);
  qp[0] = rxq;
  rxq->port = port;
  rxq->size = queue_size;
  rxq->index = qp - port->rx_queues;

  if (n_threads)
    {
      rxq->rx_thread_index = dm->next_rx_queue_thread++;
      if (dm->next_rx_queue_thread >= n_threads)
	dm->next_rx_queue_thread = 1;
    }

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);

  if (port->ops.rx_queue_alloc)
    rv = port->ops.rx_queue_alloc (vm, rxq);

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "rx_queue_add: driver rejected with rv %d", rv);
      vnet_dev_rx_queue_remove (vm, rxq);
    }
  else
    log_debug (dev, "rx_queue_add: queue %u added, assigned to thread %u",
	       rxq->queue_id, rxq->rx_thread_index);

  return rv;
}

void
vnet_dev_tx_queue_remove (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "tx_queue_remove: queue %u", txq->queue_id);
  if (port->ops.tx_queue_free)
    port->ops.tx_queue_free (vm, txq);
  pool_put_index (port->tx_queues, txq->index);
}

vnet_dev_rv_t
vnet_dev_tx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port, u16 queue_size)
{
  vnet_dev_tx_queue_t *txq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "tx_queue_add: port %u", port->port_id);

  txq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				   port->tx_queue_config.data_size);
  pool_get (port->tx_queues, qp);
  qp[0] = txq;
  txq->port = port;
  txq->size = queue_size;
  txq->index = qp - port->tx_queues;
  if (port->ops.tx_queue_alloc)
    rv = port->ops.tx_queue_alloc (vm, txq);

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "tx_queue_add: driver rejected with rv %d", rv);
      vnet_dev_tx_queue_remove (vm, txq);
    }
  else
    log_debug (dev, "tx_queue_add: queue %u added", txq->queue_id);

  return rv;
}

void
vnet_dev_port_remove (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "port_remove: port %u", port->port_id);

  if (port->started)
    vnet_dev_port_stop (vm, port);

  foreach_vnet_dev_pool (q, port->tx_queues)
    vnet_dev_tx_queue_remove (vm, q);

  foreach_vnet_dev_pool (q, port->rx_queues)
    vnet_dev_rx_queue_remove (vm, q);

  pool_free (port->rx_queues);
  pool_free (port->tx_queues);

  if (port->ops.free)
    port->ops.free (vm, port);

  if (port->rx_node_created)
    {
      vlib_node_set_state (vm, port->rx_node_index, VLIB_NODE_STATE_DISABLED);
      vlib_node_rename (vm, port->rx_node_index, "deleted-%u",
			port->rx_node_index);
      vec_add1 (dm->free_process_node_indices, port->rx_node_index);
    }

  if (port->interface_created)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_dev_if_t *intf =
	pool_elt_at_index (dm->interfaces, port->dev_if_index);
      vnet_delete_hw_interface (vnm, intf->hw_if_index);
      pool_put_index (dm->interfaces, port->dev_if_index);
    }

  pool_put_index (dev->ports, port->index);
  clib_mem_free (port);
}

vnet_dev_rv_t
vnet_dev_create_if (vlib_main_t *vm, vnet_dev_create_if_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);
  vnet_dev_driver_t *driver;
  vnet_dev_port_t *port = 0;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rxq_sz, txq_sz;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_if_t *intf;

  log_debug (dev, "create_if: port %u", args->port_id);

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  driver = pool_elt_at_index (dm->drivers, dev->driver_index);

  foreach_vnet_dev_pool (p, dev->ports)
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
    num_tx_queues =
      clib_min (port->config.max_tx_queues, vlib_get_n_threads ());

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
    if ((rv = vnet_dev_rx_queue_add (vm, port, rxq_sz)) != VNET_DEV_OK)
      goto error;

  log_debug (dev, "creating %u tx queues with size %u", num_tx_queues, txq_sz);
  for (int i = 0; i < num_tx_queues; i++)
    if ((rv = vnet_dev_tx_queue_add (vm, port, txq_sz)) != VNET_DEV_OK)
      goto error;

  if (port->type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      vnet_hw_if_rx_node_runtime_t *rtd;
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
      dev_class->tx_fn_registrations = port->ops.tx_node_fn->registrations;

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
      port->interface_created = 1;

      /* create / reuse rx node */
      if (vec_len (dm->free_rx_node_indices))
	{
	  rx_node_index = vec_pop (dm->free_rx_node_indices);
	  vlib_node_rename (vm, rx_node_index, "%s-port-%u-rx", dev->device_id,
			    port->port_id);
	}
      else
	{
	  vlib_node_registration_t rx_node_reg = {
	    .sibling_of = "device-input",
	    .type = VLIB_NODE_TYPE_INPUT,
	    .state = VLIB_NODE_STATE_DISABLED,
	    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	    .node_fn_registrations = port->ops.rx_node_fn->registrations,
	  };
	  rx_node_index = vlib_register_node (
	    vm, &rx_node_reg, "%s-port-%u-rx", dev->device_id, port->port_id);
	}

      rtd = vlib_node_get_runtime_data (vm, rx_node_index);
      rtd->hw_if_index = intf->hw_if_index;
      port->rx_node_index = rx_node_index;
      port->rx_node_created = 1;

      vlib_worker_thread_node_runtime_update ();
    }

  if (port->ops.init)
    rv = port->ops.init (vm, port);

error:
  if (rv != VNET_DEV_OK)
    vnet_dev_port_remove (vm, port);
  return rv;
}

void
vnet_dev_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "port_start_stop: stopping port %u", port->port_id);
  foreach_vnet_dev_pool (q, port->rx_queues)
    {
      vnet_dev_mgmt_op_t op = {
	.action = VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_UNASSIGN,
	.rx_queue = q,
	.thread_index = q->rx_thread_index,
      };
      if (q->started == 0)
	continue;

      log_debug (dev, "port_start_stop: stopping queue %u", q->queue_id);
      vnet_dev_mgmt_add_action (vm, &op, 1);
      q->started = 0;
    }
  port->started = 0;
  port->ops.stop (vm, port);
}

vnet_dev_rv_t
vnet_dev_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;

  log_debug (dev, "port_start_stop: starting port %u", port->port_id);
  if ((rv = port->ops.start (vm, port)) != VNET_DEV_OK)
    {
      vnet_dev_port_stop (vm, port);
      return rv;
    }

  foreach_vnet_dev_pool (q, port->rx_queues)
    {
      vnet_dev_mgmt_op_t op = {
	.action = VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_ASSIGN,
	.rx_queue = q,
	.thread_index = q->rx_thread_index,
      };
      log_debug (dev, "port_start_stop: starting queue %u", q->queue_id);
      vnet_dev_mgmt_add_action (vm, &op, 1);
      q->started = 1;
    }
  port->started = 1;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t id,
		   vnet_dev_port_add_args_t *args)
{
  vnet_dev_port_t **pp, *port;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  ASSERT (args->type != VNET_DEV_PORT_TYPE_UNKNOWN);
  ASSERT (args->port.max_frame_size);

  port =
    _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), args->port.data_size);
  pool_get (dev->ports, pp);
  pp[0] = port;
  port->port_id = id;
  port->index = pp - dev->ports;
  port->dev = dev;
  port->type = args->type;
  port->config = args->port;
  port->rx_queue_config = args->rx_queue;
  port->tx_queue_config = args->tx_queue;
  port->ops = args->ops;

  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

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

  if (port->ops.config_change)
    rv = port->ops.config_change (vm, port);

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
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, port->dev_if_index);
  int port_start_stop = 1;
  if (changes.change.link_speed)
    {
      vnet_hw_interface_set_link_speed (vnm, intf->hw_if_index,
					changes.link_speed);
      log_debug (port->dev, "port speed changed to %u", changes.link_speed);
    }
  if (changes.change.link_state)
    {
      vnet_hw_interface_set_flags (
	vnm, intf->hw_if_index,
	changes.link_state ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      log_debug (port->dev, "port link state changed to %s",
		 changes.link_state ? "up" : "down");
      port->link_up = changes.change.link_state;
    }

  if (port_start_stop)
    vnet_dev_port_start_stop (vm, port);
}
