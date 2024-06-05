/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

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
      log_err (dev, "no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;

  iq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  clib_memset_u32 (iq->buffer_indices, 0, rxq->size);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ige_rx_desc_t) * rxq->size, 0,
			       (void **) &iq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "queue %u alocated", rxq->queue_id);
  return rv;
}

vnet_dev_rv_t
ige_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  if (id->avail_txq_bmp == 0)
    {
      log_err (dev, "no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  txq->queue_id = get_lowest_set_bit_index (id->avail_txq_bmp);
  id->avail_txq_bmp ^= 1 << txq->queue_id;
  log_debug (dev, "queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

void
ige_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (dev, "queue %u", rxq->queue_id);

  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, iq->descs);
}

void
ige_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  log_debug (dev, "queue %u", txq->queue_id);
  id->avail_txq_bmp |= 1 << txq->queue_id;
}
