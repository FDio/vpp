/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <rdma.h>

u8 *
format_rdma_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  rdma_rx_trace_t *t = va_arg (*args, rdma_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "rdma-ibv: %v (%d) qid %u next-node %U len %u", hi->name,
    t->hw_if_index, t->qid, format_vlib_next_node_name, vm, node->index,
    t->next_index, t->length);

  return s;
}
