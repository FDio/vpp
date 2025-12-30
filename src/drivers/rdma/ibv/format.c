/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <common/common.h>
#include <ibverbs.h>

static u8 *
format_ibv_wc (u8 *s, va_list *args)
{
  struct ibv_wc *wc = va_arg (*args, struct ibv_wc *);
  u32 indent = format_get_indent (s);

  s = format (s, "wr_id 0x%llx status %u opcode %u vendor_err 0x%x byte_len %u qp_num %u",
	      (unsigned long long) wc->wr_id, wc->status, wc->opcode, wc->vendor_err, wc->byte_len,
	      wc->qp_num);
  s = format_newline (s, indent);
  s = format (s, "src_qp %u wc_flags 0x%x pkey_index %u sl %u slid %u dlid_path_bits %u",
	      wc->src_qp, wc->wc_flags, wc->pkey_index, wc->sl, wc->slid, wc->dlid_path_bits);

  if (wc->wc_flags & IBV_WC_WITH_IMM)
    s = format (s, " imm_data 0x%x", wc->imm_data);

  if (wc->wc_flags & IBV_WC_WITH_INV)
    s = format (s, " invalidated_rkey 0x%x", wc->invalidated_rkey);

  return s;
}

u8 *
format_ibv_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u32 indent = format_get_indent (s);

  s = format (s, "rss %s, n-ds-per-wqe %u, max-tails %u, buf-size %u", iq->use_rss ? "on" : "off",
	      iq->n_ds_per_wqe, iq->max_tails, iq->buf_sz);
  if (a->debug > 0)
    {
      s = format_newline (s, indent);
      s = format (s, "head %u, tail %u, left-to-post %u, qp %p, wq %p, cq %p", iq->head, iq->tail,
		  iq->n_left_to_post, iq->ibv_qp, iq->ibv_wq, iq->ibv_cq);
    }

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
  s = format (s, "wc: %U", format_ibv_wc, &t->wc);

  return s;
}

u8 *
format_ibv_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 indent = format_get_indent (s);

  s = format (s, "head %u, tail %u", tq->head, tq->tail);
  if (a->debug > 0)
    {
      s = format_newline (s, indent);
      s = format (s, "qp %p, cq %p, wr-template %p, sge-template %p", tq->ibv_qp, tq->ibv_cq,
		  tq->wr_template, tq->sge_template);
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

  s = format (s, "ibverbs-tx: %v (%u) qid %u buffer %u len %u n_sge %u send_flags 0x%x dropped %u",
	      hi->name, t->hw_if_index, t->qid, t->buffer_index, t->data_len, t->n_sge,
	      t->send_flags, t->dropped);
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

  s = format (s, "%U", format_rdma_port_status, a, rd->ctx, (u32) port->port_id);
  s = format_newline (s, indent);
  s = format (s, "flows:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_rdma_rxq_flows, a, ip->flows);

  return s;
}

u8 *
format_ibv_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ibv_dev_t *rd = vnet_dev_get_data (dev);

  s = format (s, "%U", format_rdma_dev_info, a, rd->ctx);
  return s;
}
