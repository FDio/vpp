/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <driver.h>

VNET_DEV_NODE_FN (vn_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return 0; }
