/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

vnet_dev_rv_t
rdma_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  if ((rv = vnet_dev_port_start_all_rx_queues (vm, port)))
    return rv;

  if ((rv = vnet_dev_port_start_all_tx_queues (vm, port)))
    return rv;

  return VNET_DEV_OK;
}

void
rdma_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  (void) vm;
  (void) port;
}
