/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <vmxnet3/vmxnet3.h>

u8 *
format_vmxnet3_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd = vec_elt_at_index (vmxm->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vd->pci_dev_handle);

  s = format (s, "vmxnet3-%x/%x/%x/%x",
	      addr->domain, addr->bus, addr->slot, addr->function);
  return s;
}

u8 *
format_vmxnet3_device_flags (u8 * s, va_list * args)
{
  vmxnet3_device_t *vd = va_arg (*args, vmxnet3_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (vd->flags & (1 << a)) \
    t = format (t, "%s%s", t ? " ":"", c);
  foreach_vmxnet3_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_vmxnet3_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd = vec_elt_at_index (vmxm->devices, i);
  u32 indent = format_get_indent (s);
  vmxnet3_queues *q = &vd->dma->queues;
  vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, 0);
  vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, 0);

  s = format (s, "flags: %U", format_vmxnet3_device_flags, vd);
  s = format (s, "\n%Uspeed %u", format_white_space, indent, vd->link_speed);
  s = format (s, "\n%Urx queues %u, rx desc %u, tx queues %u, tx desc %u",
	      format_white_space, indent,
	      vd->num_rx_queues, rxq->size, vd->num_tx_queues, txq->size);
  if (vd->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, vd->error);

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_GET_STATS);

  s = format (s, "\n%UTX:", format_white_space, indent);
  s = format (s, "\n%U  TSO packets                         %llu",
	      format_white_space, indent, q->tx.stats.tso_pkts);
  s = format (s, "\n%U  TSO bytes                           %llu",
	      format_white_space, indent, q->tx.stats.tso_bytes);
  s = format (s, "\n%U  ucast packets                       %llu",
	      format_white_space, indent, q->tx.stats.ucast_pkts);
  s = format (s, "\n%U  ucast bytes                         %llu",
	      format_white_space, indent, q->tx.stats.ucast_bytes);
  s = format (s, "\n%U  mcast packets                       %llu",
	      format_white_space, indent, q->tx.stats.mcast_pkts);
  s = format (s, "\n%U  mcast bytes                         %llu",
	      format_white_space, indent, q->tx.stats.mcast_bytes);
  s = format (s, "\n%U  bcast packets                       %llu",
	      format_white_space, indent, q->tx.stats.bcast_pkts);
  s = format (s, "\n%U  bcast bytes                         %llu",
	      format_white_space, indent, q->tx.stats.bcast_bytes);
  s = format (s, "\n%U  Errors packets                      %llu",
	      format_white_space, indent, q->tx.stats.error_pkts);
  s = format (s, "\n%U  Discard packets                     %llu",
	      format_white_space, indent, q->tx.stats.discard_pkts);

  s = format (s, "\n%URX:", format_white_space, indent);
  s = format (s, "\n%U  LRO packets                         %llu",
	      format_white_space, indent, q->rx.stats.lro_pkts);
  s = format (s, "\n%U  LRO bytes                           %llu",
	      format_white_space, indent, q->rx.stats.lro_bytes);
  s = format (s, "\n%U  ucast packets                       %llu",
	      format_white_space, indent, q->rx.stats.ucast_pkts);
  s = format (s, "\n%U  ucast bytes                         %llu",
	      format_white_space, indent, q->rx.stats.ucast_bytes);
  s = format (s, "\n%U  mcast packets                       %llu",
	      format_white_space, indent, q->rx.stats.mcast_pkts);
  s = format (s, "\n%U  mcast bytes                         %llu",
	      format_white_space, indent, q->rx.stats.mcast_bytes);
  s = format (s, "\n%U  bcast packets                       %llu",
	      format_white_space, indent, q->rx.stats.bcast_pkts);
  s = format (s, "\n%U  bcast bytes                         %llu",
	      format_white_space, indent, q->rx.stats.bcast_bytes);
  s = format (s, "\n%U  No Bufs                             %llu",
	      format_white_space, indent, q->rx.stats.nobuf_pkts);
  s = format (s, "\n%U  Error packets                       %llu",
	      format_white_space, indent, q->rx.stats.error_pkts);
  return s;
}

u8 *
format_vmxnet3_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  vmxnet3_input_trace_t *t = va_arg (*args, vmxnet3_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "vmxnet3: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);
  s = format (s, "\n  buffer %U", format_vlib_buffer, &t->buffer);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
