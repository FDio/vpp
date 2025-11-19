/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <dpdk/dev/dpdk.h>

VNET_DEV_NODE_FN (dev_dpdk_tx_node)
(vlib_main_t __clib_unused *vm, vlib_node_runtime_t __clib_unused *node,
 vlib_frame_t __clib_unused *frame)
{
  return 0;
}
