/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_cnxk/cnxk.h>

static_always_inline uword
cnxk_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, vnet_dev_port_t *port,
			  vnet_dev_rx_queue_t *rxq, int with_flows)
{
  return 0;
}

VNET_DEV_NODE_FN (cnxk_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;
      n_rx += cnxk_device_input_inline (vm, node, frame, port, rxq, 0);
    }

  return n_rx;
}
