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
