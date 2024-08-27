/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-queue",
};

vnet_dev_rv_t
mvpp2_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  log_debug (txq->port->dev, "");

  ASSERT (mtq->buffers == 0);
  if (mtq->buffers == 0)
    {
      u32 sz = sizeof (u32) * txq->size;
      mtq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      clib_memset (mtq->buffers, 0, sz);
    }

  return rv;
}

void
mvpp2_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);

  log_debug (txq->port->dev, "");
  if (mtq->buffers)
    {
      clib_mem_free (mtq->buffers);
      mtq->buffers = 0;
    }
}
