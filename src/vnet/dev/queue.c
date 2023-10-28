/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "error",
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
  u8 buffer_pool_index;

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

  buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);

  rxq->buffer_template = bp->buffer_template;
  vnet_buffer (&rxq->buffer_template)->sw_if_index[VLIB_TX] = ~0;

  rxq->next_index = vnet_dev_default_next_index_by_port_type[port->attr.type];

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
  txq->enabled = 1;
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
