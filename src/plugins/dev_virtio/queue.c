/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_virtio/virtio.h>
#include <dev_virtio/pci.h>

VLIB_REGISTER_LOG_CLASS (virtio_log, static) = {
  .class_name = "virtio",
  .subclass_name = "queue",
};

vnet_dev_rv_t
virtio_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "queue %u alocated", RX_QUEUE (rxq->queue_id));
  return VNET_DEV_OK;
}

void
virtio_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (rxq);
  vnet_virtio_vring_t *vring = &vrq->vring;
  vnet_dev_t *dev = rxq->port->dev;

  log_debug (dev, "RX queue free %u", RX_QUEUE (rxq->queue_id));

  virtio_vring_free_rx (vm, dev, vring);
}

vnet_dev_rv_t
virtio_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "queue %u alocated", TX_QUEUE (txq->queue_id));

  return VNET_DEV_OK;
}

void
virtio_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  virtio_rxq_t *vtq = vnet_dev_get_tx_queue_data (txq);
  vnet_virtio_vring_t *vring = &vtq->vring;
  vnet_dev_t *dev = txq->port->dev;

  log_debug (dev, "TX queue free %u", TX_QUEUE (txq->queue_id));

  virtio_vring_free_tx (vm, dev, vring);
}

vnet_dev_rv_t
virtio_rx_queue_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (rxq);
  vnet_virtio_vring_t *vring = &vrq->vring;

  log_debug (dev, "RX queue start %u", RX_QUEUE (rxq->queue_id));

  virtio_vring_fill (vm, vif, vring, 0);

  return VNET_DEV_OK;
}

void
virtio_rx_queue_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "RX queue stop %u", RX_QUEUE (rxq->queue_id));
}

vnet_dev_rv_t
virtio_tx_queue_start (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "TX queue start %u", TX_QUEUE (txq->queue_id));

  return VNET_DEV_OK;
}

void
virtio_tx_queue_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "TX queue stop %u", TX_QUEUE (txq->queue_id));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
