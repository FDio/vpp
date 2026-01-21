/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <driver.h>

vnet_dev_rv_t
vn_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  return VNET_DEV_OK;
}

void
vn_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
}

vnet_dev_rv_t
vn_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  return VNET_DEV_OK;
}

void
vn_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
}
