/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <rdma/common.h>
#include <ibverbs.h>

u8 *
format_ibv_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  s = format (s, "%u buffers of %u bytes per wqe", iq->n_ds, iq->buf_sz);
  if (iq->single_buffer)
    s = format (s, ", single buffer");
  return s;
}

u8 *
format_ibv_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ibv_rx_trace_t *t = va_arg (*args, ibv_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "ibverbs: %v (%d) qid %u next-node %U", hi->name, t->hw_if_index, t->qid,
	      format_vlib_next_node_name, vm, node->index, t->next_index);
  s = format_newline (s, indent);
  s = format (s, "wc: %U", format_rdma_ibv_wc, &t->wc);
  if (t->buffer_flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED)
    {
      vlib_buffer_t b = { .flags = t->buffer_flags };
      s = format_newline (s, indent);
      s = format (s, "flags: %U", format_vnet_buffer_flags, &b);
    }
  s = format_newline (s, indent);
  s = format (s, "posted recv wr, slot %u:", t->slot);
  for (u32 i = 0; i < t->n_sge; i++)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "sge %u: addr 0x%llx length %u lkey 0x%x", i,
		  (unsigned long long) t->sge[i].addr, t->sge[i].length, t->sge[i].lkey);
    }

  return s;
}

u8 *
format_ibv_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  ibv_tx_trace_t *t = va_arg (*args, ibv_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "ibverbs-tx: %v (%u) qid %u buffer %u len %u", hi->name, t->hw_if_index, t->qid,
	      t->buffer_index, t->data_len);
  if (t->dropped)
    return format (s, " dropped");

  s = format_newline (s, indent + 2);
  s = format (s, "send wr: wr_id %llu opcode %s send_flags 0x%x%s%s num_sge %u",
	      (unsigned long long) t->wr_id,
	      t->opcode == IBV_WR_TSO  ? "tso" :
	      t->opcode == IBV_WR_SEND ? "send" :
					 "other",
	      t->send_flags, t->send_flags & IBV_SEND_SIGNALED ? " signaled" : "",
	      t->send_flags & IBV_SEND_IP_CSUM ? " ip-csum" : "", t->n_sge);
  if (t->opcode == IBV_WR_TSO)
    s = format (s, " tso hdr_sz %u mss %u", t->tso_hdr_sz, t->tso_mss);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  for (u32 i = 0; i < t->n_sge; i++)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "sge %u: addr 0x%llx length %u lkey 0x%x", i,
		  (unsigned long long) t->sge[i].addr, t->sge[i].length, t->sge[i].lkey);
    }
  return s;
}

u8 *
format_ibv_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ibv_dev_t *rd = vnet_dev_get_data (port->dev);
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "%U", format_rdma_port_status, rd->ctx, port->port_id, ip->netdev_ifindex);
  if (ip->rss.rwq_ind_tbl)
    {
      s = format_newline (s, indent);
      s = format (s, "%U", format_rdma_rss_flows, a, &ip->rss);
    }

  return s;
}

u8 *
format_ibv_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ibv_dev_t *rd = vnet_dev_get_data (dev);

  return format (s, "%U", format_rdma_ibv_dev_info, a, rd->ctx);
}
