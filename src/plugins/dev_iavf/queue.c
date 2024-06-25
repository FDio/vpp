/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/virtchnl.h>
#include <dev_iavf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "queue",
};

vnet_dev_rv_t
iavf_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  arq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (arq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  if ((rv =
	 vnet_dev_dma_mem_alloc (vm, dev, sizeof (iavf_rx_desc_t) * rxq->size,
				 0, (void **) &arq->descs)))
    return rv;

  arq->qrx_tail = ad->bar0 + IAVF_QRX_TAIL (rxq->queue_id);

  log_debug (dev, "queue %u alocated", rxq->queue_id);
  return rv;
}

void
iavf_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  iavf_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (dev, "queue %u", rxq->queue_id);

  vnet_dev_dma_mem_free (vm, dev, aq->descs);

  foreach_pointer (p, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}

vnet_dev_rv_t
iavf_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;

  if ((rv =
	 vnet_dev_dma_mem_alloc (vm, dev, sizeof (iavf_tx_desc_t) * txq->size,
				 0, (void **) &atq->descs)))
    return rv;

  clib_ring_new_aligned (atq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);
  atq->buffer_indices = clib_mem_alloc_aligned (
    txq->size * sizeof (atq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  atq->tmp_descs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_descs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);
  atq->tmp_bufs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_bufs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);

  atq->qtx_tail = ad->bar0 + IAVF_QTX_TAIL (txq->queue_id);

  log_debug (dev, "queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

void
iavf_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  iavf_txq_t *aq = vnet_dev_get_tx_queue_data (txq);

  log_debug (dev, "queue %u", txq->queue_id);
  vnet_dev_dma_mem_free (vm, dev, aq->descs);
  clib_ring_free (atq->rs_slots);

  foreach_pointer (p, aq->tmp_descs, aq->tmp_bufs, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}

vnet_dev_rv_t
iavf_rx_queue_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  iavf_rx_desc_t *d = arq->descs;
  u32 n_enq, *bi = arq->buffer_indices;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  n_enq = vlib_buffer_alloc_from_pool (vm, bi, rxq->size - 8, bpi);

  if (n_enq < 8)
    {
      if (n_enq)
	vlib_buffer_free (vm, bi, n_enq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  for (u32 i = 0; i < n_enq; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
      u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, b->data);
      d[i] = (iavf_rx_desc_t){ .addr = dma_addr };
    }

  arq->n_enqueued = n_enq;
  arq->next = 0;
  __atomic_store_n (arq->qrx_tail, n_enq, __ATOMIC_RELEASE);
  return VNET_DEV_OK;
}

void
iavf_rx_queue_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);

  __atomic_store_n (arq->qrx_tail, 0, __ATOMIC_RELAXED);
  if (arq->n_enqueued)
    {
      vlib_buffer_free_from_ring_no_next (vm, arq->buffer_indices, arq->next,
					  rxq->size, arq->n_enqueued);
      log_debug (rxq->port->dev, "%u buffers freed from rx queue %u",
		 arq->n_enqueued, rxq->queue_id);
    }
  arq->n_enqueued = arq->next = 0;
}

vnet_dev_rv_t
iavf_tx_queue_start (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  atq->next = 0;
  atq->n_enqueued = 0;
  clib_ring_reset (atq->rs_slots);
  __atomic_store_n (atq->qtx_tail, 0, __ATOMIC_RELAXED);
  return VNET_DEV_OK;
}

void
iavf_tx_queue_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);

  log_debug (txq->port->dev, "queue %u", txq->queue_id);

  __atomic_store_n (atq->qtx_tail, 0, __ATOMIC_RELAXED);
  if (atq->n_enqueued)
    {
      vlib_buffer_free_from_ring_no_next (vm, atq->buffer_indices,
					  atq->next - atq->n_enqueued,
					  txq->size, atq->n_enqueued);
      log_debug (txq->port->dev, "%u buffers freed from tx queue %u",
		 atq->n_enqueued, txq->queue_id);
    }
  atq->n_enqueued = atq->next = 0;
}
