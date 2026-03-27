/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <cadence.h>

vnet_dev_rv_t
cdn_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  crq->buffer_indices =
    clib_mem_alloc_aligned (rxq->size * sizeof (crq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  if (crq->buffer_indices == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  clib_memset_u32 (crq->buffer_indices, 0, rxq->size);

  rv =
    vnet_dev_dma_mem_alloc (vm, dev, sizeof (crq->descs[0]) * rxq->size, 0, (void **) &crq->descs);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (crq->buffer_indices);
      crq->buffer_indices = 0;
      return rv;
    }

  clib_memset (crq->descs, 0, sizeof (crq->descs[0]) * rxq->size);
  crq->rbqp_reg = cdn_rbqp_reg (rxq->queue_id);
  crq->rbqph_reg = cdn_rbqph_reg (rxq->queue_id);
  crq->rbqs_reg = rxq->queue_id ? cdn_rbqs_reg (rxq->queue_id) : 0;
  crq->head = 0;
  crq->tail = 0;

  return VNET_DEV_OK;
}

void
cdn_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);

  if (crq->descs)
    vnet_dev_dma_mem_free (vm, dev, crq->descs);

  if (crq->buffer_indices)
    clib_mem_free (crq->buffer_indices);
}

vnet_dev_rv_t
cdn_tx_queue_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  vnet_dev_rv_t rv;

  ctq->buffer_indices =
    clib_mem_alloc_aligned (txq->size * sizeof (ctq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  if (ctq->buffer_indices == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  clib_memset_u32 (ctq->buffer_indices, 0, txq->size);

  rv =
    vnet_dev_dma_mem_alloc (vm, dev, sizeof (ctq->descs[0]) * txq->size, 0, (void **) &ctq->descs);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (ctq->buffer_indices);
      ctq->buffer_indices = 0;
      return rv;
    }

  clib_memset (ctq->descs, 0, sizeof (ctq->descs[0]) * txq->size);
  ctq->tbqp_reg = cdn_tbqp_reg (txq->queue_id);
  ctq->tbqph_reg = cdn_tbqph_reg (txq->queue_id);
  ctq->head = 0;
  ctq->tail = 0;

  return VNET_DEV_OK;
}
void
cdn_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);

  if (ctq->descs)
    vnet_dev_dma_mem_free (vm, dev, ctq->descs);

  if (ctq->buffer_indices)
    clib_mem_free (ctq->buffer_indices);
}
