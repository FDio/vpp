/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_atlantic/atlantic.h>

VNET_DEV_NODE_FN (atl_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return 0; }
