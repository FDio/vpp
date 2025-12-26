/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <ige.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "queue",
};

vnet_dev_rv_t
ige_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  if (id->avail_rxq_bmp == 0)
    {
      log_err (dev, "no free RX queues (requested size %u)", rxq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;

  iq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  if (iq->buffer_indices == 0)
    {
      id->avail_rxq_bmp |= 1 << rxq->queue_id;
      log_err (dev, "queue %u buffer ring alloc failed (ring size %u)",
	       rxq->queue_id, rxq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  clib_memset_u32 (iq->buffer_indices, 0, rxq->size);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ige_rx_desc_t) * rxq->size, 0,
			       (void **) &iq->descs);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (iq->buffer_indices);
      iq->buffer_indices = 0;
      id->avail_rxq_bmp |= 1 << rxq->queue_id;
      log_err (dev, "queue %u DMA descriptor alloc failed (rv %d)",
	       rxq->queue_id, rv);
      return rv;
    }

  log_debug (dev, "rx queue %u allocated (size %u)", rxq->queue_id, rxq->size);
  return rv;
}

vnet_dev_rv_t
ige_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (id->avail_txq_bmp == 0)
    {
      log_err (dev, "no free TX queues (requested size %u)", txq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  txq->queue_id = get_lowest_set_bit_index (id->avail_txq_bmp);
  id->avail_txq_bmp ^= 1 << txq->queue_id;
  iq->buffer_indices = clib_mem_alloc_aligned (
    txq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  if (iq->buffer_indices == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto done;
    }

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ige_tx_desc_t) * txq->size, 0,
			       (void **) &iq->descs);

  if (rv != VNET_DEV_OK)
    goto done;

  rv = vnet_dev_dma_mem_alloc (vm, dev, CLIB_CACHE_LINE_BYTES,
			       CLIB_CACHE_LINE_BYTES, (void **) &iq->wb);

  if (rv != VNET_DEV_OK)
    goto done;

  log_debug (dev, "tx queue %u allocated (size %u)", txq->queue_id, txq->size);

done:
  if (rv != VNET_DEV_OK)
    {
      if (iq->wb)
	vnet_dev_dma_mem_free (vm, dev, iq->wb);
      if (iq->descs)
	vnet_dev_dma_mem_free (vm, dev, iq->descs);
      if (iq->buffer_indices)
	clib_mem_free (iq->buffer_indices);

      id->avail_txq_bmp |= 1 << txq->queue_id;
      log_err (dev, "queue %u allocation failed (rv %d)", txq->queue_id, rv);
    }

  return rv;
}

void
ige_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, iq->descs);
  iq->descs = 0;

  if (iq->buffer_indices)
    {
      clib_mem_free (iq->buffer_indices);
      iq->buffer_indices = 0;
    }
}

void
ige_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_txq_t *iq = vnet_dev_get_tx_queue_data (txq);

  id->avail_txq_bmp |= 1 << txq->queue_id;

  if (iq->descs)
    vnet_dev_dma_mem_free (vm, dev, iq->descs);

  if (iq->buffer_indices)
    clib_mem_free (iq->buffer_indices);

  if (iq->wb)
    vnet_dev_dma_mem_free (vm, dev, iq->wb);
}
