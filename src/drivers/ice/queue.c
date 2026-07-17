/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "queue",
};

vnet_dev_rv_t
ice_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  iq->buffer_indices =
    clib_mem_alloc_aligned (rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  if (!iq->buffer_indices)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  clib_memset (iq->buffer_indices, 0, rxq->size * sizeof (iq->buffer_indices[0]));

  rv = vnet_dev_dma_mem_alloc (vm, dev, rxq->size * sizeof (ice_rx_desc_t), 128,
			       (void **) &iq->descs, "RX queue %u descriptors", rxq->queue_id);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (iq->buffer_indices);
      iq->buffer_indices = 0;
    }
  else
    log_debug (dev, "allocated RX queue %u: %u descriptors at %p", rxq->queue_id, rxq->size,
	       iq->descs);
  return rv;
}

vnet_dev_rv_t
ice_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;

  iq->buffer_indices =
    clib_mem_alloc_aligned (txq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  if (!iq->buffer_indices)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  clib_memset (iq->buffer_indices, 0, txq->size * sizeof (iq->buffer_indices[0]));

  rv = vnet_dev_dma_mem_alloc (vm, dev, txq->size * sizeof (ice_tx_desc_t), 128,
			       (void **) &iq->descs, "TX queue %u descriptors", txq->queue_id);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (iq->buffer_indices);
      iq->buffer_indices = 0;
    }
  else
    log_debug (dev, "allocated TX queue %u: %u descriptors at %p", txq->queue_id, txq->size,
	       iq->descs);
  return rv;
}

void
ice_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  log_debug (rxq->port->dev, "freeing RX queue %u", rxq->queue_id);
  if (iq->descs)
    vnet_dev_dma_mem_free (vm, rxq->port->dev, iq->descs);
  if (iq->buffer_indices)
    clib_mem_free (iq->buffer_indices);
}

void
ice_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  log_debug (txq->port->dev, "freeing TX queue %u", txq->queue_id);
  if (iq->descs)
    vnet_dev_dma_mem_free (vm, txq->port->dev, iq->descs);
  if (iq->buffer_indices)
    clib_mem_free (iq->buffer_indices);
}
