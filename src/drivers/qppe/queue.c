/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
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
  u32 ring_index, ring_mask;

  ASSERT (rxq->queue_id < EDMA_RX_QUEUES_PER_PORT);
  if (qd->avail_rx_ring_bmp == 0)
    {
      log_warn (dev, "no free EDMA RX ring pair for port %u queue %u", rxq->port->port_id,
		rxq->queue_id);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  ring_index = count_trailing_zeros (qd->avail_rx_ring_bmp);
  ring_mask = 1u << ring_index;
  qd->avail_rx_ring_bmp &= ~ring_mask;
  qr->desc_ring_id = EDMA_RXDESC_RING_START + ring_index;
  qr->rxdesc_prod_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_PROD_IDX (qr->desc_ring_id);
  qr->rxdesc_cons_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_CONS_IDX (qr->desc_ring_id);
  qr->ring_ids_allocated = 1;
  log_debug (dev, "assigned port %u RX queue %u descriptor ring %u", rxq->port->port_id,
	     rxq->queue_id, qr->desc_ring_id);
  return VNET_DEV_OK;
}

static void
qppe_rx_ring_ids_free (vnet_dev_t *dev, qppe_rxq_t *qr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (!qr->ring_ids_allocated)
    return;

  ASSERT (qr->desc_ring_id >= EDMA_RXDESC_RING_START &&
	  qr->desc_ring_id < EDMA_RXDESC_RING_START + EDMA_RX_RING_COUNT);
  qd->avail_rx_ring_bmp |= 1 << (qr->desc_ring_id - EDMA_RXDESC_RING_START);
  qr->ring_ids_allocated = 0;
  log_debug (dev, "released RX descriptor ring %u", qr->desc_ring_id);
}

vnet_dev_rv_t
qppe_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  vnet_dev_rv_t rv;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  qr->fill_ring_index = EDMA_RXFILL_RING_COUNT;
  rv = qppe_rx_ring_ids_alloc (rxq, qr);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_edma_rx_ring_alloc (vm, rxq);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_edma_rx_ring_configure (vm, rxq);
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

static vnet_dev_rv_t
qppe_tx_ring_ids_alloc (vnet_dev_tx_queue_t *txq, qppe_txq_t *tq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 ring_index, ring_mask;

  ASSERT (txq->queue_id < EDMA_TX_QUEUES_PER_PORT);
  if (qd->avail_tx_ring_bmp == 0)
    {
      log_warn (dev, "no free EDMA TX ring pair for port %u queue %u", txq->port->port_id,
		txq->queue_id);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  ring_index = count_trailing_zeros (qd->avail_tx_ring_bmp);
  ring_mask = 1u << ring_index;
  qd->avail_tx_ring_bmp &= ~ring_mask;
  tq->desc_ring_id = EDMA_TXDESC_RING_START + ring_index;
  tq->cmpl_ring_id = EDMA_TXCMPL_RING_START + ring_index;
  tq->txdesc_prod_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_PROD_IDX (tq->desc_ring_id);
  tq->txdesc_cons_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_CONS_IDX (tq->desc_ring_id);
  tq->txcmpl_prod_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_PROD_IDX (tq->cmpl_ring_id);
  tq->txcmpl_cons_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_CONS_IDX (tq->cmpl_ring_id);
  tq->ring_ids_allocated = 1;
  log_debug (dev,
	     "assigned port %u TX queue %u ring pair: descriptor ring %u, "
	     "completion ring %u",
	     txq->port->port_id, txq->queue_id, tq->desc_ring_id, tq->cmpl_ring_id);
  return VNET_DEV_OK;
}

static void
qppe_tx_ring_ids_free (vnet_dev_t *dev, qppe_txq_t *tq)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (!tq->ring_ids_allocated)
    return;

  ASSERT (tq->desc_ring_id >= EDMA_TXDESC_RING_START &&
	  tq->desc_ring_id < EDMA_TXDESC_RING_START + EDMA_TX_RING_COUNT);
  ASSERT (tq->cmpl_ring_id >= EDMA_TXCMPL_RING_START &&
	  tq->cmpl_ring_id < EDMA_TXCMPL_RING_START + EDMA_TX_RING_COUNT);
  ASSERT (tq->desc_ring_id - EDMA_TXDESC_RING_START == tq->cmpl_ring_id - EDMA_TXCMPL_RING_START);
  qd->avail_tx_ring_bmp |= 1u << (tq->desc_ring_id - EDMA_TXDESC_RING_START);
  tq->ring_ids_allocated = 0;
  log_debug (dev, "released TX queue ring pair: descriptor ring %u, completion ring %u",
	     tq->desc_ring_id, tq->cmpl_ring_id);
}

vnet_dev_rv_t
qppe_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  vnet_dev_rv_t rv;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  rv = qppe_tx_ring_ids_alloc (txq, tq);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_edma_tx_ring_alloc (vm, txq);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_edma_tx_ring_configure (vm, txq);
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_free (vm, txq);
      goto error;
    }

  log_debug (dev, "tx queue %u allocated EDMA ring storage and verified disabled ring base/size",
	     txq->queue_id);

  return VNET_DEV_OK;

error:
  qppe_tx_ring_ids_free (txq->port->dev, tq);
  return rv;
}

void
qppe_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  qppe_edma_tx_ring_free (vm, txq);
  qppe_tx_ring_ids_free (txq->port->dev, tq);
  log_debug (dev, "tx queue %u freed EDMA ring storage", txq->queue_id);
}
