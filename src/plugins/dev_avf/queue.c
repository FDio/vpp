/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <dev_avf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "queue",
};

vnet_dev_rv_t
avf_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  arq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (arq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (avf_rx_desc_t) * rxq->size, 0,
			       (void **) &arq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  arq->qrx_tail = ad->bar0 + AVF_QTX_TAIL (rxq->queue_id);

  log_debug (dev, "rx_queue_alloc: queue %u alocated", rxq->queue_id);
  return rv;
}

void
avf_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  avf_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (dev, "rx_queue_free: queue %u", rxq->queue_id);

  vnet_dev_dma_mem_free (vm, dev, aq->descs);

  foreach_pointer (p, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}

vnet_dev_rv_t
avf_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (avf_tx_desc_t) * txq->size, 0,
			       (void **) &atq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  clib_ring_new_aligned (atq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);
  atq->buffer_indices = clib_mem_alloc_aligned (
    txq->size * sizeof (atq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  atq->tmp_descs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_descs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);
  atq->tmp_bufs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_bufs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);

  atq->qtx_tail = ad->bar0 + AVF_QTX_TAIL (txq->queue_id);

  log_debug (dev, "tx_queue_alloc: queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

void
avf_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  avf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  avf_txq_t *aq = vnet_dev_get_tx_queue_data (txq);

  log_debug (dev, "tx_queue_free: queue %u", txq->queue_id);
  vnet_dev_dma_mem_free (vm, dev, aq->descs);
  clib_ring_free (atq->rs_slots);

  foreach_pointer (p, aq->tmp_descs, aq->tmp_bufs, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}
