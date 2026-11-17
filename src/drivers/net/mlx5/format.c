/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>
#include <common.h>

u8 *
format_mlx5_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);

  if (mq->log_stride_per_wqe)
    s = format (s, "striding rq, %u strides of %u bytes per wqe", 1 << mq->log_stride_per_wqe,
		mq->buf_sz);
  else
    s = format (s, "legacy rq, %u buffers of %u bytes per wqe", mq->n_ds_per_wqe, mq->buf_sz);
  if (mq->single_buffer)
    s = format (s, ", single buffer");
  if (mq->q_counter_valid)
    s = format (s, ", q-counter %u", mq->q_counter_set_id);
  return s;
}

u8 *
format_mlx5_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  if (tq->empw)
    s =
      format (s, "enhanced multi-packet send, up to %u packets per wqe", MLX5_TX_EMPW_MAX_PACKETS);
  else
    s = format (s, "send wqe per packet");
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
  mlx5_cqe_flags_t f = { .as_u16 = cqe->hds_ip_ext << 8 | cqe->l4_hdr_type_etc };
  const char *l4_hdr_types[8] = {
    0, "tcp", "udp", "tcp-empty-ack", "tcp-with-acl",
  };
  const char *l3_hdr_types[4] = {
    0,
    "ip6",
    "ip4",
  };

  u32 indent = format_get_indent (s);

  s = format (s, "opcode 0x%x owner %u byte_cnt 0x%x wqe_counter %u wqe_id %u sop_drop_qpn 0x%x",
	      opcode, owner, byte_cnt, wqe_counter, wqe_id, sop_drop_qpn);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent);
  s = format (s,
	      "flags_rqpn 0x%x srqn_uidx 0x%x imm_inval_pkey 0x%x vlan_info 0x%x "
	      "hds_ip_ext 0x%x l4_hdr_type_etc 0x%x ml_path 0x%x slid 0x%x",
	      flags_rqpn, srqn_uidx, imm_inval_pkey, vlan_info, hds_ip_ext, l4_hdr_type_etc,
	      ml_path, slid);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent);
  s = format (s, "app 0x%x app_op 0x%x app_info 0x%x timestamp 0x%llx signature 0x%x op_own 0x%x",
	      app, app_op, app_info, (unsigned long long) timestamp, signature, op_own);

  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent);
  s = format (s, "flags 0x%x", f.as_u16);

  if (f.l2_ok)
    s = format (s, " l2-ok");
  if (f.l3_ok)
    s = format (s, " l3-ok");
  if (f.l4_ok)
    s = format (s, " l4-ok");
  if (f.ip_frag)
    s = format (s, " ip-frag");
  if (f.cv)
    s = format (s, " vlan");
  if (f.l3_hdr_type)
    s = format (s, " %s", l3_hdr_types[f.l3_hdr_type]);
  if (f.l4_hdr_type)
    s = format (s, " %s", l4_hdr_types[f.l4_hdr_type]);
  if (f.ip_ext_opts)
    {
      if (f.l3_hdr_type == MLX5_CQE_L3_HDR_TYPE_IPV6)
	s = format (s, " ip6-ext-hdr");
      if (f.l3_hdr_type == MLX5_CQE_L3_HDR_TYPE_IPV4)
	s = format (s, " ip4-opt");
    }

  return format_word_wrap_last_line_with_indent (s, 100, 2);
}

static u8 *
format_mlx5_rx_trace_hdr (u8 *s, vlib_main_t *vm, vlib_node_t *node, u32 hw_if_index, u16 qid,
			  u16 next_index, u32 length, u32 buffer_flags, mlx5_rx_cqe_copy_t *c,
			  u32 indent)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnet_get_main (), hw_if_index);

  s = format (s, "rdma-mlx5: %v (%d) qid %u next-node %U len %u", hi->name, hw_if_index, qid,
	      format_vlib_next_node_name, vm, node->index, next_index, length);
  if (buffer_flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED)
    {
      vlib_buffer_t b = { .flags = buffer_flags };
      s = format (s, " flags %U", format_vnet_buffer_flags, &b);
    }
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent + 2);
  s = format (s, "%s: %U", c->compressed ? "title cqe" : "cqe", format_mlx5_cqe64, &c->cqe);
  if (c->compressed)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "mini cqe: byte_count 0x%x checksum/rx_hash 0x%x",
		  clib_net_to_host_u32 (c->mini_cqe.byte_count),
		  clib_net_to_host_u32 (c->mini_cqe.checksum));
    }
  return s;
}

static u8 *
format_mlx5_wqe_ds (u8 *s, va_list *args)
{
  mlx5dv_wqe_ds_t *ds = va_arg (*args, mlx5dv_wqe_ds_t *);
  u64 v = ds->dsz_and_lkey;

  return format (s, "byte_count %u lkey 0x%x addr 0x%llx", clib_net_to_host_u32 ((u32) v),
		 clib_net_to_host_u32 (v >> 32),
		 (unsigned long long) clib_net_to_host_u64 (ds->addr));
}

u8 *
format_mlx5_rx_legacy_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mlx5_rx_legacy_trace_t *t = va_arg (*args, mlx5_rx_legacy_trace_t *);
  u32 indent = format_get_indent (s);

  s = format_mlx5_rx_trace_hdr (s, vm, node, t->hw_if_index, t->qid, t->next_index, t->length,
				t->buffer_flags, &t->cqe, indent);
  s = format_newline (s, indent + 2);
  s = format (s, "wqe %u:", t->wqe_index);
  for (u32 i = 0; i < t->n_ds; i++)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "ds %u: %U", i, format_mlx5_wqe_ds, t->ds + i);
    }
  return s;
}

u8 *
format_mlx5_rx_striding_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mlx5_rx_striding_trace_t *t = va_arg (*args, mlx5_rx_striding_trace_t *);
  u32 indent = format_get_indent (s);

  s = format_mlx5_rx_trace_hdr (s, vm, node, t->hw_if_index, t->qid, t->next_index, t->length,
				t->buffer_flags, &t->cqe, indent);
  for (u32 i = 0; i < t->n_strides; i++)
    {
      u32 stride = t->first_stride + i;
      s = format_newline (s, indent + 2);
      s = format (s, "stride %u (wqe %u): %U", stride, stride >> t->log_stride_per_wqe,
		  format_mlx5_wqe_ds, t->stride_ds + i);
    }
  return s;
}

static u8 *
format_mlx5_wqe_dseg (u8 *s, va_list *args)
{
  struct mlx5_wqe_data_seg *d = va_arg (*args, struct mlx5_wqe_data_seg *);

  return format (s, "byte_count %u lkey 0x%x addr 0x%llx", clib_net_to_host_u32 (d->byte_count),
		 clib_net_to_host_u32 (d->lkey),
		 (unsigned long long) clib_net_to_host_u64 (d->addr));
}

u8 *
format_mlx5_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  mlx5_tx_trace_t *t = va_arg (*args, mlx5_tx_trace_t *);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnet_get_main (), t->hw_if_index);
  struct mlx5_wqe_ctrl_seg *c = (void *) t->wqe;
  struct mlx5_wqe_eth_seg *e = (void *) (t->wqe + 16);
  u32 indent = format_get_indent (s), oio, qd, inl, off;
  char *op;

  s = format (s, "rdma-mlx5-tx: %v (%u) qid %u buffer %u len %u", hi->name, t->hw_if_index, t->qid,
	      t->buffer_index, t->data_len);
  if (t->dropped)
    return format (s, " dropped");

  oio = clib_net_to_host_u32 (c->opmod_idx_opcode);
  qd = clib_net_to_host_u32 (c->qpn_ds);
  switch (oio & 0xff)
    {
    case MLX5_OPCODE_SEND:
      op = "send";
      break;
    case MLX5_OPCODE_TSO:
      op = "tso";
      break;
    case MLX5_OPCODE_ENHANCED_MPSW:
      op = "enhanced-mpsw";
      break;
    default:
      op = "unknown";
    }
  s = format_newline (s, indent + 2);
  s = format (s, "wqe %u: opcode 0x%x (%s) opc_mod %u wqe_index %u qpn 0x%x ds %u fm_ce_se 0x%x",
	      t->wqe_index, oio & 0xff, op, oio >> 24, (oio >> 8) & 0xffff, qd >> 8, qd & 0xff,
	      c->fm_ce_se);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);

  if (t->empw_n_pkts)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "eseg: cs_flags 0x%x", e->cs_flags);
      s = format_newline (s, indent + 4);
      return format (s, "packet %u of %u: %U", t->empw_pkt, t->empw_n_pkts, format_mlx5_wqe_dseg,
		     t->wqe + 32);
    }

  inl = clib_net_to_host_u16 (e->inline_hdr_sz);
  s = format_newline (s, indent + 4);
  s = format (s, "eseg: cs_flags 0x%x mss %u inline_hdr_sz %u", e->cs_flags,
	      clib_net_to_host_u16 (e->mss), inl);
  if (inl)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "inline: %U", format_hex_bytes, t->wqe + MLX5_TX_INLINE_OFF,
		  clib_min (inl, t->n_ds * 16 - MLX5_TX_INLINE_OFF));
    }
  off = round_pow2 (MLX5_TX_INLINE_OFF + inl, 16);
  for (u32 i = 0; off + 16 <= t->n_ds * 16; off += 16, i++)
    {
      s = format_newline (s, indent + 4);
      s = format (s, "ds %u: %U", i, format_mlx5_wqe_dseg, t->wqe + off);
    }
  return s;
}

u8 *
format_mlx5_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);
  struct mlx5dv_context c = {
    .comp_mask = MLX5DV_CONTEXT_MASK_CQE_COMPRESION | MLX5DV_CONTEXT_MASK_STRIDING_RQ |
		 MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS,
  };
  rdma_cap_name_t flags[] = {
    { MLX5DV_CONTEXT_FLAGS_CQE_V1, "cqe-v1" },
    { MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED, "mpw-allowed" },
    { MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW, "enhanced-mpw" },
    { MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP, "cqe-128b-comp" },
    { MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD, "cqe-128b-pad" },
    { MLX5DV_CONTEXT_FLAGS_PACKET_BASED_CREDIT_MODE, "packet-based-credit" },
    { MLX5DV_CONTEXT_FLAGS_REAL_TIME_TS, "real-time-ts" },
    { MLX5DV_CONTEXT_FLAGS_BLUEFLAME, "blueflame" },
  };
  rdma_cap_name_t cqe_formats[] = {
    { MLX5DV_CQE_RES_FORMAT_HASH, "hash" },
    { MLX5DV_CQE_RES_FORMAT_CSUM, "csum" },
    { MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX, "csum-stridx" },
  };
  rdma_cap_name_t tunnels[] = {
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN, "vxlan" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE, "gre" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE, "geneve" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_GRE, "cw-mpls-over-gre" },
    { MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_UDP, "cw-mpls-over-udp" },
  };
  int rv;

  s = format (s, "%U", format_rdma_ibv_dev_info, a, rd->ctx);

  rv = mlx5dv_query_device (rd->ctx, &c);
  if (rv)
    {
      s = format_newline (s, indent);
      return format (s, "mlx5dv_query_device failed rv %d", rv);
    }

  s = format_newline (s, indent);
  s = format (s, "mlx5dv flags:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_rdma_cap_list, flags, ARRAY_LEN (flags), c.flags);

  if (c.comp_mask & MLX5DV_CONTEXT_MASK_CQE_COMPRESION)
    {
      s = format_newline (s, indent);
      s = format (s, "cqe_comp_caps: max_num %u, supported_format: ", c.cqe_comp_caps.max_num);
      s = format (s, "%U", format_rdma_cap_list, cqe_formats, ARRAY_LEN (cqe_formats),
		  (u64) c.cqe_comp_caps.supported_format);
    }

  if (c.comp_mask & MLX5DV_CONTEXT_MASK_STRIDING_RQ)
    {
      s = format_newline (s, indent);
      s = format (s,
		  "striding_rq_caps: single stride log bytes %u-%u, single wqe log strides "
		  "%u-%u, raw-packet%c",
		  c.striding_rq_caps.min_single_stride_log_num_of_bytes,
		  c.striding_rq_caps.max_single_stride_log_num_of_bytes,
		  c.striding_rq_caps.min_single_wqe_log_num_of_strides,
		  c.striding_rq_caps.max_single_wqe_log_num_of_strides,
		  c.striding_rq_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET) ? '+' : '-');
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
    }

  if (c.comp_mask & MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS)
    {
      s = format_newline (s, indent);
      s = format (s, "tunnel_offloads_caps: ");
      s = format (s, "%U", format_rdma_cap_list, tunnels, ARRAY_LEN (tunnels),
		  (u64) c.tunnel_offloads_caps);
    }

  return s;
}

u8 *
format_mlx5_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mlx5_dev_t *rd = vnet_dev_get_data (port->dev);
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "%U", format_rdma_port_status, rd->ctx, port->port_id, mp->netdev_ifindex);
  if (mp->rss.rwq_ind_tbl)
    {
      s = format_newline (s, indent);
      s = format (s, "%U", format_rdma_rss_flows, a, &mp->rss);
    }

  return s;
}
