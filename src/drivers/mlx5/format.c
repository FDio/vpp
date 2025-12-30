/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>

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
    0,
    "tcp",
    "udp",
    "tcp-empty-ack",
    "tcp-with-acl",
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
    wqe_id, ml_path, slid, flags_rqpn, hds_ip_ext, l4_hdr_type_etc, vlan_info,
    srqn_uidx, imm_inval_pkey, app, app_op, app_info, byte_cnt,
    (unsigned long long) timestamp, sop_drop_qpn, wqe_counter, signature,
    op_own, opcode, owner);

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
format_mlx5_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mlx5_rx_trace_t *t = va_arg (*args, mlx5_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "rdma-mlx5: %v (%d) qid %u next-node %U len %u", hi->name,
    t->hw_if_index, t->qid, format_vlib_next_node_name, vm, node->index,
    t->next_index, t->length);

  return s;
}
