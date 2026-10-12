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
qppe_rx_ring_ids_alloc (vnet_dev_t *dev, qppe_rxq_t *qr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 i;

  for (i = 0; i < PPE_EDMA_RX_RING_COUNT; i++)
    if (qd->avail_rxfill_ring_bmp & (1 << i) && qd->avail_rxdesc_ring_bmp & (1 << i))
      {
	qd->avail_rxfill_ring_bmp &= ~(1 << i);
	qd->avail_rxdesc_ring_bmp &= ~(1 << i);
	qr->fill_ring_id = PPE_EDMA_RXFILL_RING_START + i;
	qr->desc_ring_id = PPE_EDMA_RXDESC_RING_START + i;
	qr->ring_ids_allocated = 1;
	log_debug (dev, "assigned RX queue ring pair: fill ring %u, descriptor ring %u",
		   qr->fill_ring_id, qr->desc_ring_id);
	return VNET_DEV_OK;
      }

  log_warn (dev, "no free EDMA RX fill/descriptor ring pair for another RX queue");
  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
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
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  if (qd->rxq_owner)
    {
      qppe_rxq_t *owner_qr = vnet_dev_get_rx_queue_data (qd->rxq_owner);

      if (rxq->size != qd->rxq_owner->size)
	{
	  log_err (dev, "RX queue %u on port %u has size %u; shared EDMA RX queue size is %u",
		   rxq->queue_id, rxq->port->port_id, rxq->size, qd->rxq_owner->size);
	  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	}
      qr->shared_ring = 1;
      qd->n_rxq_users++;
      log_debug (dev, "RX queue %u on port %u shares EDMA fill ring %u and descriptor ring %u",
		 rxq->queue_id, rxq->port->port_id, owner_qr->fill_ring_id, owner_qr->desc_ring_id);
      return VNET_DEV_OK;
    }

  rv = qppe_rx_ring_ids_alloc (dev, qr);
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

  qd->rxq_owner = rxq;
  qd->n_rxq_users = 1;
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
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  ASSERT (qd->n_rxq_users > 0);
  if (rxq != qd->rxq_owner)
    {
      ASSERT (qr->shared_ring);
      qd->n_rxq_users--;
      log_debug (dev, "RX queue %u on port %u released its shared EDMA ring reference",
		 rxq->queue_id, rxq->port->port_id);
      return;
    }

  if (qd->n_rxq_users > 1)
    {
      vnet_dev_rx_queue_t *new_owner = 0;

      foreach_vnet_dev_port (port, dev)
	{
	  foreach_vnet_dev_port_rx_queue (candidate, port)
	    if (candidate != rxq)
	      {
		qppe_rxq_t *candidate_qr = vnet_dev_get_rx_queue_data (candidate);
		if (candidate_qr->shared_ring)
		  {
		    new_owner = candidate;
		    *candidate_qr = *qr;
		    candidate_qr->shared_ring = 0;
		    qd->rxq_owner = candidate;
		    break;
		  }
	      }
	  if (new_owner)
	    break;
	}
      ASSERT (new_owner != 0);
      qr->fill_descs = 0;
      qr->primary_descs = 0;
      qr->secondary_descs = 0;
      qr->buffer_indices = 0;
      qr->n_buffers = 0;
      qr->ring_ids_allocated = 0;
      qr->started = 0;
      qd->n_rxq_users--;
      log_debug (dev, "moved shared EDMA RX ring ownership to port %u queue %u",
		 new_owner->port->port_id, new_owner->queue_id);
      return;
    }

  qppe_edma_rx_ring_free (vm, rxq);
  qppe_rx_ring_ids_free (rxq->port->dev, qr);
  qd->rxq_owner = 0;
  qd->n_rxq_users = 0;
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
