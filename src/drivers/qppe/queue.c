/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "queue",
};

static vnet_dev_rv_t
qppe_rx_ring_ids_alloc (vnet_dev_rx_queue_t *rxq, qppe_rxq_t *qr)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
  u32 ring_index = qp->source_profile;
  u32 ring_mask;

  ASSERT (ring_index < PPE_EDMA_RX_RING_COUNT);
  ring_mask = 1 << ring_index;
  if (!(qd->avail_rxfill_ring_bmp & ring_mask) || !(qd->avail_rxdesc_ring_bmp & ring_mask))
    {
      log_warn (dev, "no free EDMA RX ring pair for port %u source profile %u", rxq->port->port_id,
		ring_index);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  qd->avail_rxfill_ring_bmp &= ~ring_mask;
  qd->avail_rxdesc_ring_bmp &= ~ring_mask;
  qr->fill_ring_id = PPE_EDMA_RXFILL_RING_START + ring_index;
  qr->desc_ring_id = PPE_EDMA_RXDESC_RING_START + ring_index;
  qr->rxfill_prod_offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_PROD_IDX (qr->fill_ring_id);
  qr->rxdesc_offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_PROD_IDX (qr->desc_ring_id);
  qr->rxdesc_cons_offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CONS_IDX (qr->desc_ring_id);
  qr->ring_ids_allocated = 1;
  log_debug (dev,
	     "assigned port %u source profile %u RX queue ring pair: fill ring %u, "
	     "descriptor ring %u",
	     rxq->port->port_id, ring_index, qr->fill_ring_id, qr->desc_ring_id);
  return VNET_DEV_OK;
}

static void
qppe_rx_ring_ids_free (vnet_dev_t *dev, qppe_rxq_t *qr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (!qr->ring_ids_allocated)
    return;

  ASSERT (qr->fill_ring_id >= PPE_EDMA_RXFILL_RING_START &&
	  qr->fill_ring_id < PPE_EDMA_RXFILL_RING_START + PPE_EDMA_RX_RING_COUNT);
  ASSERT (qr->desc_ring_id >= PPE_EDMA_RXDESC_RING_START &&
	  qr->desc_ring_id < PPE_EDMA_RXDESC_RING_START + PPE_EDMA_RX_RING_COUNT);
  qd->avail_rxfill_ring_bmp |= 1 << (qr->fill_ring_id - PPE_EDMA_RXFILL_RING_START);
  qd->avail_rxdesc_ring_bmp |= 1 << (qr->desc_ring_id - PPE_EDMA_RXDESC_RING_START);
  qr->ring_ids_allocated = 0;
  log_debug (dev, "released RX queue ring pair: fill ring %u, descriptor ring %u", qr->fill_ring_id,
	     qr->desc_ring_id);
}

vnet_dev_rv_t
qppe_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  vnet_dev_rv_t rv;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  rv = qppe_rx_ring_ids_alloc (rxq, qr);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_edma_rx_ring_alloc (vm, rxq);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_edma_rx_ring_configure (rxq);
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      goto error;
    }

  log_debug (dev, "rx queue %u allocated EDMA ring storage and verified disabled ring base/size",
	     rxq->queue_id);

  return VNET_DEV_OK;

error:
  qppe_rx_ring_ids_free (rxq->port->dev, qr);
  return rv;
}

void
qppe_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  qppe_edma_rx_ring_free (vm, rxq);
  qppe_rx_ring_ids_free (rxq->port->dev, qr);
  log_debug (dev, "rx queue %u freed EDMA ring storage", rxq->queue_id);
}

vnet_dev_rv_t
qppe_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  log_debug (txq->port->dev, "");

  /* TODO: allocate and program the PPE TX descriptor ring for this queue.
   * 'buffers' below is a placeholder for whatever per-slot bookkeeping the
   * real implementation ends up needing. */
  vec_validate_aligned (tq->buffers, txq->size - 1, CLIB_CACHE_LINE_BYTES);

  return VNET_DEV_OK;
}

void
qppe_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  log_debug (txq->port->dev, "");

  vec_free (tq->buffers);
}
