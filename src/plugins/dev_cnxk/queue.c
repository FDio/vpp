/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_cnxk/cnxk.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (cnxk_log, static) = {
  .class_name = "cnxk",
  .subclass_name = "queue",
};

vnet_dev_rv_t
cnxk_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  cnxk_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  aq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (aq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  log_debug (dev, "rx_queue_alloc: queue %u alocated", rxq->queue_id);
  return VNET_DEV_OK;
}

void
cnxk_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  cnxk_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  foreach_pointer (p, aq->buffer_indices)
    if (p)
      clib_mem_free (p);

  log_debug (dev, "rx_queue_free: queue %u", rxq->queue_id);
}

vnet_dev_rv_t
cnxk_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cnxk_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  atq->buffer_indices = clib_mem_alloc_aligned (
    txq->size * sizeof (atq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  log_debug (dev, "tx_queue_alloc: queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

void
cnxk_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cnxk_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "tx_queue_free: queue %u", txq->queue_id);

  foreach_pointer (p, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}
