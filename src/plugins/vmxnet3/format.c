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
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd = vec_elt_at_index (vmxm->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, vd->pci_dev_handle);

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
  vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, 0);
  vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, 0);
  vmxnet3_tx_queue *tx = VMXNET3_TX_START (vd);
  vmxnet3_rx_queue *rx = VMXNET3_RX_START (vd);
  u16 qid;

  s = format (s, "flags: %U", format_vmxnet3_device_flags, vd);
  s = format (s, "\n%Urx queues %u, rx desc %u, tx queues %u, tx desc %u",
	      format_white_space, indent,
	      vd->num_rx_queues, rxq->size, vd->num_tx_queues, txq->size);
  if (vd->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, vd->error);

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_GET_STATS);

  vec_foreach_index (qid, vd->txqs)
  {
    vmxnet3_tx_stats *txs = vec_elt_at_index (vd->tx_stats, qid);

    s = format (s, "\n%UTX Queue %u:", format_white_space, indent, qid);
    s = format (s, "\n%U  TSO packets                         %llu",
		format_white_space, indent,
		tx->stats.tso_pkts - txs->tso_pkts);
    s = format (s, "\n%U  TSO bytes                           %llu",
		format_white_space, indent,
		tx->stats.tso_bytes - txs->tso_bytes);
    s = format (s, "\n%U  ucast packets                       %llu",
		format_white_space, indent,
		tx->stats.ucast_pkts - txs->ucast_pkts);
    s = format (s, "\n%U  ucast bytes                         %llu",
		format_white_space, indent,
		tx->stats.ucast_bytes - txs->ucast_bytes);
    s = format (s, "\n%U  mcast packets                       %llu",
		format_white_space, indent,
		tx->stats.mcast_pkts - txs->mcast_pkts);
    s = format (s, "\n%U  mcast bytes                         %llu",
		format_white_space, indent,
		tx->stats.mcast_bytes - txs->mcast_bytes);
    s = format (s, "\n%U  bcast packets                       %llu",
		format_white_space, indent,
		tx->stats.bcast_pkts - txs->bcast_pkts);
    s = format (s, "\n%U  bcast bytes                         %llu",
		format_white_space, indent,
		tx->stats.bcast_bytes - txs->bcast_bytes);
    s = format (s, "\n%U  Errors packets                      %llu",
		format_white_space, indent,
		tx->stats.error_pkts - txs->error_pkts);
    s = format (s, "\n%U  Discard packets                     %llu",
		format_white_space, indent,
		tx->stats.discard_pkts - txs->discard_pkts);
    tx++;
  }

  vec_foreach_index (qid, vd->rxqs)
  {
    vmxnet3_rx_stats *rxs = vec_elt_at_index (vd->rx_stats, qid);

    s = format (s, "\n%URX Queue %u:", format_white_space, indent, qid);
    s = format (s, "\n%U  LRO packets                         %llu",
		format_white_space, indent,
		rx->stats.lro_pkts - rxs->lro_pkts);
    s = format (s, "\n%U  LRO bytes                           %llu",
		format_white_space, indent,
		rx->stats.lro_bytes - rxs->lro_bytes);
    s = format (s, "\n%U  ucast packets                       %llu",
		format_white_space, indent,
		rx->stats.ucast_pkts - rxs->ucast_pkts);
    s = format (s, "\n%U  ucast bytes                         %llu",
		format_white_space, indent,
		rx->stats.ucast_bytes - rxs->ucast_bytes);
    s = format (s, "\n%U  mcast packets                       %llu",
		format_white_space, indent,
		rx->stats.mcast_pkts - rxs->mcast_pkts);
    s = format (s, "\n%U  mcast bytes                         %llu",
		format_white_space, indent,
		rx->stats.mcast_bytes - rxs->mcast_bytes);
    s = format (s, "\n%U  bcast packets                       %llu",
		format_white_space, indent,
		rx->stats.bcast_pkts - rxs->bcast_pkts);
    s = format (s, "\n%U  bcast bytes                         %llu",
		format_white_space, indent,
		rx->stats.bcast_bytes - rxs->bcast_bytes);
    s = format (s, "\n%U  No Bufs                             %llu",
		format_white_space, indent,
		rx->stats.nobuf_pkts - rxs->nobuf_pkts);
    s = format (s, "\n%U  Error packets                       %llu",
		format_white_space, indent,
		rx->stats.error_pkts - rxs->error_pkts);
    rx++;
  }
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
  s = format (s, "\n  buffer %U", format_vnet_buffer, &t->buffer);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
