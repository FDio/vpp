/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "queue",
};

vnet_dev_rv_t
atl_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  if (ad->avail_rxq_bmp == 0)
    {
      log_err (dev, "no free RX queues (requested size %u)", rxq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq->queue_id = get_lowest_set_bit_index (ad->avail_rxq_bmp);
  ad->avail_rxq_bmp ^= 1 << rxq->queue_id;

  aq->buffer_indices =
    clib_mem_alloc_aligned (rxq->size * sizeof (aq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  if (aq->buffer_indices == 0)
    {
      ad->avail_rxq_bmp |= 1 << rxq->queue_id;
      log_err (dev, "queue %u buffer ring alloc failed (ring size %u)", rxq->queue_id, rxq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  clib_memset_u32 (aq->buffer_indices, 0, rxq->size);

  rv =
    vnet_dev_dma_mem_alloc (vm, dev, sizeof (atl_rx_desc_t) * rxq->size, 128, (void **) &aq->descs);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (aq->buffer_indices);
      aq->buffer_indices = 0;
      ad->avail_rxq_bmp |= 1 << rxq->queue_id;
      log_err (dev, "queue %u DMA descriptor alloc failed (rv %d)", rxq->queue_id, rv);
      return rv;
    }

  aq->head = aq->tail = 0;
  aq->tail_reg = 0;
  aq->next_index = 0;
  aq->stats_rx_packets = 0;
  aq->stats_rx_bytes = 0;

  log_debug (dev, "rx queue %u allocated (size %u)", rxq->queue_id, rxq->size);
  return rv;
}

vnet_dev_rv_t
atl_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (ad->avail_txq_bmp == 0)
    {
      log_err (dev, "no free TX queues (requested size %u)", txq->size);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  txq->queue_id = get_lowest_set_bit_index (ad->avail_txq_bmp);
  ad->avail_txq_bmp ^= 1 << txq->queue_id;
  aq->buffer_indices =
    clib_mem_alloc_aligned (txq->size * sizeof (aq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  if (aq->buffer_indices == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto done;
    }

  rv =
    vnet_dev_dma_mem_alloc (vm, dev, sizeof (atl_tx_desc_t) * txq->size, 128, (void **) &aq->descs);

  if (rv != VNET_DEV_OK)
    goto done;

  rv = vnet_dev_dma_mem_alloc (vm, dev, CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES,
			       (void **) &aq->wb);

  if (rv != VNET_DEV_OK)
    goto done;

  aq->tail_reg = 0;

  log_debug (dev, "tx queue %u allocated (size %u)", txq->queue_id, txq->size);

done:
  if (rv != VNET_DEV_OK)
    {
      if (aq->wb)
	vnet_dev_dma_mem_free (vm, dev, aq->wb);
      if (aq->descs)
	vnet_dev_dma_mem_free (vm, dev, aq->descs);
      if (aq->buffer_indices)
	clib_mem_free (aq->buffer_indices);

      ad->avail_txq_bmp |= 1 << txq->queue_id;
      log_err (dev, "queue %u allocation failed (rv %d)", txq->queue_id, rv);
    }

  return rv;
}

void
atl_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u32 n_free = (u16) (aq->tail - aq->head);
  u16 start = aq->head & mask;

  ad->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, aq->descs);
  aq->descs = 0;

  if (aq->buffer_indices)
    {
      if (n_free)
	vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, start, rxq->size, n_free);
      clib_mem_free (aq->buffer_indices);
      aq->buffer_indices = 0;
    }
}

void
atl_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);

  ad->avail_txq_bmp |= 1 << txq->queue_id;

  if (aq->descs)
    vnet_dev_dma_mem_free (vm, dev, aq->descs);

  if (aq->buffer_indices)
    clib_mem_free (aq->buffer_indices);

  if (aq->wb)
    vnet_dev_dma_mem_free (vm, dev, aq->wb);
}
