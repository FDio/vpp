/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>
#include <common.h>
#include <vppinfra/format_ansi.h>

static u8 *
format_mlx5dv_context_flags (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 flags = va_arg (*args, u64);

  static rdma_cap_list_entry_t mlx5dv_context_flags[] = {
    { MLX5DV_CONTEXT_FLAGS_CQE_V1, "cqe-v1" },
    { MLX5DV_CONTEXT_FLAGS_OBSOLETE, "obsolete" },
    { MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED, "mpw" },
    { MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW, "empw" },
    { MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP, "cqe-128b-comp" },
    { MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD, "cqe-128b-pad" },
    { MLX5DV_CONTEXT_FLAGS_PACKET_BASED_CREDIT_MODE, "pkt-credit-mode" },
    { MLX5DV_CONTEXT_FLAGS_REAL_TIME_TS, "real-time-ts" },
    { MLX5DV_CONTEXT_FLAGS_BLUEFLAME, "blueflame" },
  };

  s = format_rdma_cap_list (s, a, mlx5dv_context_flags, ARRAY_LEN (mlx5dv_context_flags), flags);

  return s;
}

static u8 *
format_mlx5dv_flow_action_flags (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u32 flags = va_arg (*args, u32);

  static rdma_cap_list_entry_t mlx5dv_flow_action_flags[] = {
    { MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM, "esp-aes-gcm" },
    { MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_REQ_METADATA, "esp-aes-gcm-req-metadata" },
    { MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_SPI_STEERING, "esp-aes-gcm-spi-steering" },
    { MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_FULL_OFFLOAD, "esp-aes-gcm-full-offload" },
    { MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_TX_IV_IS_ESN, "esp-aes-gcm-tx-iv-is-esn" },
  };

  s = format_rdma_cap_list (s, a, mlx5dv_flow_action_flags, ARRAY_LEN (mlx5dv_flow_action_flags),
			    flags);

  return s;
}

static u8 *
format_mlx5dv_tunnel_offloads (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u32 caps = va_arg (*args, u32);

  static rdma_cap_list_entry_t mlx5dv_tunnel_offloads[] = {
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN, "vxlan" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE, "gre" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE, "geneve" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_GRE, "cw-mpls-over-gre" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_UDP, "cw-mpls-over-udp" },
  };

  s = format_rdma_cap_list (s, a, mlx5dv_tunnel_offloads, ARRAY_LEN (mlx5dv_tunnel_offloads), caps);

  return s;
}

static u8 *
format_mlx5dv_sw_parsing_offloads (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u32 offloads = va_arg (*args, u32);

  static rdma_cap_list_entry_t mlx5dv_sw_parsing_offloads[] = {
    { MLX5DV_SW_PARSING, "sw-parsing" },
    { MLX5DV_SW_PARSING_CSUM, "sw-parsing-csum" },
    { MLX5DV_SW_PARSING_LSO, "sw-parsing-lso" },
  };

  s = format_rdma_cap_list (s, a, mlx5dv_sw_parsing_offloads,
			    ARRAY_LEN (mlx5dv_sw_parsing_offloads), offloads);

  return s;
}

static u8 *
format_mlx5dv_rx_features (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  struct mlx5dv_context *attrs = va_arg (*args, struct mlx5dv_context *);
  u64 caps = 0;
  static rdma_cap_list_entry_t features[] = {
    { 1ULL << 0, "striding-rq" },
    { 1ULL << 1, "mini-cqe" },
  };

  if (attrs->striding_rq_caps.max_single_stride_log_num_of_bytes > 0)
    caps |= 1ULL << 0;
  if (attrs->cqe_comp_caps.supported_format & MLX5DV_CQE_RES_FORMAT_HASH)
    caps |= 1ULL << 1;

  s = format_rdma_cap_list (s, a, features, ARRAY_LEN (features), caps);

  return s;
}

u8 *
format_mlx5_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  struct mlx5dv_context mlx5dv_attrs = {
    .comp_mask = MLX5DV_CONTEXT_MASK_CQE_COMPRESION | MLX5DV_CONTEXT_MASK_STRIDING_RQ |
		 MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS | MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS |
		 MLX5DV_CONTEXT_MASK_SWP,
  };
  u32 indent = format_get_indent (s);
  char *title = a->no_color ? 0 : ANSI_DIM;
  int rv_ibv;

  s = format (s, "%U", format_rdma_dev_info, a, rd->ctx);

  rv_ibv = mlx5dv_query_device (rd->ctx, &mlx5dv_attrs);
  if (rv_ibv != 0)
    return format (s, " mlx5dv_query_device() failed with rv %d", rv_ibv);

  s = format_newline (s, indent);
  s = format_ansi (s, title, "Direct Verbs:");
  s = format_newline (s, indent + 2);
  s = format_ansi (s, title, "flags:");
  s = format_newline (s, indent + 4);
  s = format (s, "%U", format_mlx5dv_context_flags, a, (u64) mlx5dv_attrs.flags);
  s = format (s, " %U", format_mlx5dv_rx_features, a, &mlx5dv_attrs);
  s = format_newline (s, indent + 2);
  s = format_ansi (s, title, "flow-action-flags:");
  s = format_newline (s, indent + 4);
  s = format (s, "%U", format_mlx5dv_flow_action_flags, a, mlx5dv_attrs.flow_action_flags);
  s = format_newline (s, indent + 2);
  s = format_ansi (s, title, "tunnel-offloads:");
  s = format_newline (s, indent + 4);
  s = format (s, "%U", format_mlx5dv_tunnel_offloads, a, mlx5dv_attrs.tunnel_offloads_caps);
  s = format_newline (s, indent + 2);
  s = format_ansi (s, title, "sw-parsing-offloads:");
  s = format_newline (s, indent + 4);
  s = format (s, "%U", format_mlx5dv_sw_parsing_offloads, a,
	      mlx5dv_attrs.sw_parsing_caps.sw_parsing_offloads);

  return s;
}

u8 *
format_mlx5_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 indent = format_get_indent (s);

  s = format (s, "mode %s, n-ds-per-wqe %u, buf-size %u", mq->ibv_wq ? "striding" : "legacy",
	      mq->n_ds_per_wqe, mq->buf_sz);
  if (a->debug > 0)
    {
      s = format_newline (s, indent);
      s = format (s,
		  "head %u, tail %u, cq-idx %u, wqe-cnt %u, n-mini-cqes %u, "
		  "n-mini-cqes-left %u, qp %p, wq %p, cq %p",
		  mq->head, mq->tail, mq->dv_cq_idx, mq->wqe_cnt, mq->n_mini_cqes,
		  mq->n_mini_cqes_left, mq->ibv_qp, mq->ibv_wq, mq->ibv_cq);
    }

  return s;
}

u8 *
format_mlx5_cqe64 (u8 *s, va_list *args)
{
  struct mlx5_cqe64 *cqe = va_arg (*args, struct mlx5_cqe64 *);
  u32 byte_cnt = clib_net_to_host_u32 (cqe->byte_cnt);
  u16 wqe_counter = clib_net_to_host_u16 (cqe->wqe_counter);
  u16 wqe_id = clib_net_to_host_u16 (cqe->wqe_id);
  u32 flags_rqpn = clib_net_to_host_u32 (cqe->flags_rqpn);
  u8 ml_path = cqe->ml_path;
  u16 slid = clib_net_to_host_u16 (cqe->slid);
  u8 hds_ip_ext = cqe->hds_ip_ext;
  u8 l4_hdr_type_etc = cqe->l4_hdr_type_etc;
  u16 vlan_info = clib_net_to_host_u16 (cqe->vlan_info);
  u32 srqn_uidx = clib_net_to_host_u32 (cqe->srqn_uidx);
  u32 imm_inval_pkey = clib_net_to_host_u32 (cqe->imm_inval_pkey);
  u8 app = cqe->app;
  u8 app_op = cqe->app_op;
  u16 app_info = clib_net_to_host_u16 (cqe->app_info);
  u64 timestamp = clib_net_to_host_u64 (cqe->timestamp);
  u32 sop_drop_qpn = clib_net_to_host_u32 (cqe->sop_drop_qpn);
  u8 signature = cqe->signature;
  u8 op_own = cqe->op_own;
  u8 opcode = op_own >> 4;
  u8 owner = op_own & MLX5_CQE_OWNER_MASK;
  u16 cqe_flags = (u16) mlx5_get_bits (cqe, 0x1c, 31, 16);
  u8 l3_hdr_type = CQE_FLAG_L3_HDR_TYPE (cqe_flags);
  u8 l4_hdr_type = CQE_FLAG_L4_HDR_TYPE (cqe_flags);
  const char *l4_hdr_types[8] = {
    0, "tcp", "udp", "tcp-empty-ack", "tcp-with-acl",
  };
  const char *l3_hdr_types[4] = {
    0,
    "ip6",
    "ip4",
  };

  s = format (s,
	      "cqe wqe_id %u ml_path 0x%x slid 0x%x flags_rqpn 0x%x "
	      "hds_ip_ext 0x%x l4_hdr_type_etc 0x%x vlan_info 0x%x "
	      "srqn_uidx 0x%x imm_inval_pkey 0x%x app 0x%x app_op 0x%x "
	      "app_info 0x%x byte_cnt %u timestamp 0x%llx sop_drop_qpn 0x%x "
	      "wqe_counter %u signature 0x%x op_own 0x%x opcode 0x%x "
	      "owner 0x%x",
	      wqe_id, ml_path, slid, flags_rqpn, hds_ip_ext, l4_hdr_type_etc, vlan_info, srqn_uidx,
	      imm_inval_pkey, app, app_op, app_info, byte_cnt, (unsigned long long) timestamp,
	      sop_drop_qpn, wqe_counter, signature, op_own, opcode, owner);

  s = format (s, " flags 0x%x", cqe_flags);

  if (cqe_flags & CQE_FLAG_L2_OK)
    s = format (s, " l2-ok");
  if (cqe_flags & CQE_FLAG_L3_OK)
    s = format (s, " l3-ok");
  if (cqe_flags & CQE_FLAG_L4_OK)
    s = format (s, " l4-ok");
  if (cqe_flags & CQE_FLAG_IP_FRAG)
    s = format (s, " ip-frag");
  if (l3_hdr_type)
    s = format (s, " %s", l3_hdr_types[l3_hdr_type]);
  if (l4_hdr_type)
    s = format (s, " %s", l4_hdr_types[l4_hdr_type]);
  if (cqe_flags & CQE_FLAG_IP_EXT_OPTS)
    {
      if (l3_hdr_type == CQE_FLAG_L3_HDR_TYPE_IP6)
	s = format (s, " ip4-ext-hdr");
      if (l3_hdr_type == CQE_FLAG_L3_HDR_TYPE_IP4)
	s = format (s, " ip4-opt");
    }

  return s;
}

u8 *
format_mlx5_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 indent = format_get_indent (s);

  s = format (s, "sq-head %u, sq-tail %u, pkt-head %u, pkt-tail %u, cq-idx %u", tq->sq_head,
	      tq->sq_tail, tq->pkt_head, tq->pkt_tail, tq->dv_cq_idx);
  if (a->debug > 0)
    {
      s = format_newline (s, indent);
      s = format (s, "qp %p, cq %p, dv-sq-wqes %p, dv-sq-dbrec %p, dv-cq-cqes %p, dv-cq-dbrec %p",
		  tq->ibv_qp, tq->ibv_cq, tq->dv_sq_wqes, tq->dv_sq_dbrec, tq->dv_cq_cqes,
		  tq->dv_cq_dbrec);
    }

  return s;
}

u8 *
format_mlx5_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mlx5_rx_trace_t *t = va_arg (*args, mlx5_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "rdma-mlx5: %v (%d) qid %u next-node %U len %u", hi->name, t->hw_if_index, t->qid,
	      format_vlib_next_node_name, vm, node->index, t->next_index, t->length);

  return s;
}

u8 *
format_mlx5_wqe (u8 *s, va_list *args)
{
  mlx5_wqe_t *wqe = va_arg (*args, mlx5_wqe_t *);
  u32 indent = format_get_indent (s);
  u32 opmod_idx_opcode = clib_net_to_host_u32 (wqe->ctrl.opmod_idx_opcode);
  u32 qpn_ds = clib_net_to_host_u32 (wqe->ctrl.qpn_ds);
  u32 imm = clib_net_to_host_u32 (wqe->ctrl.imm);
  u16 dci_stream_channel_id = clib_net_to_host_u16 (wqe->ctrl.dci_stream_channel_id);
  u32 byte_count = clib_net_to_host_u32 (wqe->dseg.byte_count);
  u32 lkey = clib_net_to_host_u32 (wqe->dseg.lkey);
  u64 addr = clib_net_to_host_u64 (wqe->dseg.addr);
  u16 inline_hdr_sz = clib_net_to_host_u16 (wqe->eseg.inline_hdr_sz);
  u32 ds = qpn_ds & 0x3f;
  u32 qp_num = qpn_ds >> 8;
  u32 wqe_index = (wqe->wqe_index_hi << 8) | wqe->wqe_index_lo;
  u32 inline_n = clib_min ((u32) inline_hdr_sz, (u32) sizeof (wqe->eseg.inline_hdr));

  s = format (s, "opmod_idx_opcode 0x%08x opcode 0x%x opmod 0x%x wqe-index %u", opmod_idx_opcode,
	      wqe->opcode, wqe->opc_mod, wqe_index);
  s = format_newline (s, indent);
  s = format (s,
	      "qpn_ds 0x%08x qp_num %u ds %u signature 0x%x dci_stream_channel_id %u fm_ce_se 0x%x",
	      qpn_ds, qp_num, ds, wqe->ctrl.signature, dci_stream_channel_id, wqe->ctrl.fm_ce_se);
  s = format_newline (s, indent);
  s = format (s, "imm 0x%08x eseg cs_flags 0x%x mss %u inline_hdr_sz %u inline_hdr_start 0x%U", imm,
	      wqe->eseg.cs_flags, clib_net_to_host_u16 (wqe->eseg.mss), inline_hdr_sz,
	      format_hex_bytes_no_wrap, wqe->eseg.inline_hdr_start,
	      sizeof (wqe->eseg.inline_hdr_start));
  s = format_newline (s, indent);
  s = format (s, "inline_hdr 0x%U", format_hex_bytes_no_wrap, wqe->eseg.inline_hdr, inline_n);
  s = format_newline (s, indent);
  s = format (s, "dseg byte_count %u lkey 0x%x addr 0x%llx", byte_count, lkey,
	      (unsigned long long) addr);
  return s;
}

static u8 *
format_mlx5_wqe_ctrl_seg (u8 *s, va_list *args)
{
  struct mlx5_wqe_ctrl_seg *ctrl = va_arg (*args, struct mlx5_wqe_ctrl_seg *);
  u32 opmod_idx_opcode = clib_net_to_host_u32 (ctrl->opmod_idx_opcode);
  u32 qpn_ds = clib_net_to_host_u32 (ctrl->qpn_ds);
  u32 imm = clib_net_to_host_u32 (ctrl->imm);
  u16 dci_stream_channel_id = clib_net_to_host_u16 (ctrl->dci_stream_channel_id);
  u32 ds = qpn_ds & 0x3f;
  u32 qp_num = qpn_ds >> 8;
  u8 opcode = opmod_idx_opcode & 0xff;
  u8 opmod = (opmod_idx_opcode >> 24) & 0xff;
  u16 wqe_index = (opmod_idx_opcode >> 8) & 0xffff;

  s = format (
    s,
    "opmod_idx_opcode 0x%08x opcode 0x%x opmod 0x%x wqe-index %u qpn_ds 0x%08x qp_num %u ds %u "
    "signature 0x%x dci_stream_channel_id %u fm_ce_se 0x%x imm 0x%08x",
    opmod_idx_opcode, opcode, opmod, wqe_index, qpn_ds, qp_num, ds, ctrl->signature,
    dci_stream_channel_id, ctrl->fm_ce_se, imm);

  return s;
}

static u8 *
format_mlx5_wqe_eth_seg (u8 *s, va_list *args)
{
  struct mlx5_wqe_eth_seg *eseg = va_arg (*args, struct mlx5_wqe_eth_seg *);
  u16 inline_hdr_sz = clib_net_to_host_u16 (eseg->inline_hdr_sz);
  u32 inline_n = clib_min ((u32) inline_hdr_sz, (u32) sizeof (eseg->inline_hdr));

  s = format (s, "cs_flags 0x%x mss %u inline_hdr_sz %u inline_hdr_start 0x%U inline_hdr 0x%U",
	      eseg->cs_flags, clib_net_to_host_u16 (eseg->mss), inline_hdr_sz,
	      format_hex_bytes_no_wrap, eseg->inline_hdr_start, sizeof (eseg->inline_hdr_start),
	      format_hex_bytes_no_wrap, eseg->inline_hdr, inline_n);

  return s;
}

static u8 *
format_mlx5_wqe_data_seg (u8 *s, va_list *args)
{
  struct mlx5_wqe_data_seg *dseg = va_arg (*args, struct mlx5_wqe_data_seg *);
  u32 byte_count = clib_net_to_host_u32 (dseg->byte_count);
  u32 lkey = clib_net_to_host_u32 (dseg->lkey);
  u64 addr = clib_net_to_host_u64 (dseg->addr);

  s =
    format (s, "byte_count %u lkey 0x%x addr 0x%llx", byte_count, lkey, (unsigned long long) addr);

  return s;
}

u8 *
format_mlx5_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  mlx5_tx_trace_t *t = va_arg (*args, mlx5_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "rdma-mlx5-tx: %v (%u) qid %u buffer %u len %u n_sge %u cs_flags 0x%x dropped %u",
	      hi->name, t->hw_if_index, t->qid, t->buffer_index, t->data_len, t->n_sge, t->cs_flags,
	      t->dropped);
  s = format_newline (s, indent);
  s = format (s, "ctrl: %U", format_mlx5_wqe_ctrl_seg, &t->ctrl);
  s = format_newline (s, indent);
  s = format (s, "eseg: %U", format_mlx5_wqe_eth_seg, &t->eseg);
  s = format_newline (s, indent);
  s = format (s, "dseg: %U", format_mlx5_wqe_data_seg, &t->dseg);
  return s;
}

u8 *
format_mlx5_port_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mlx5_dev_t *rd = vnet_dev_get_data (port->dev);
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  const char *rx_path = "base";
  const char *tx_path = "send";
  u32 indent = format_get_indent (s);
  char *value = a->no_color ? 0 : ANSI_BOLD;

  if (port->rx_node.registrations == mlx5_rx_node_striding.registrations)
    rx_path = "striding";
  else if (port->rx_node.registrations == mlx5_rx_node_mini_cqe.registrations)
    rx_path = "mini-cqe";

  if (port->tx_node.registrations == mlx5_tx_node_empw.registrations)
    tx_path = "empw";
  else if (port->tx_node.registrations == mlx5_tx_node_send.registrations)
    tx_path = "send";

  s = format (s, "rx-path ");
  s = format_ansi (s, value, "%s", rx_path);
  s = format (s, ", tx-path ");
  s = format_ansi (s, value, "%s", tx_path);
  s = format_newline (s, indent);

  s = format (s, "%U", format_rdma_port_status, a, rd->ctx, (u32) port->port_id);
  s = format_newline (s, indent);
  s = format (s, "flows:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_rdma_rxq_flows, a, mp->flow_state.flows);

  return s;
}
