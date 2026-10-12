/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "counters",
};
#define foreach_qppe_ppe_counter                                                                   \
  _ (PTX_PORT, TX, "ptx_port", HPPE_REG_PORT_TX_COUNTER_TBL (p))                                   \
  _ (POLICER_PORT_TX_DROP, TX, "policer_port_drop", HPPE_REG_PORT_TX_DROP_CNT_TBL (p))             \
  _ (PRX_SILENT_DROP, RX, "prx_silent_drop", HPPE_REG_PRX_SILENT_DROP_CNT (p))                     \
  _ (PRX_OVERFLOW_DROP, RX, "prx_overflow_drop", HPPE_REG_PRX_OVERFLOW_DROP_CNT (p))               \
  _ (POLICER_PORT, RX, "policer_port", APPE_REG_PHY_PORT_RX_CNT (p))                               \
  _ (POLICER_VP, RX, "policer_vp", APPE_REG_VP_RX_CNT (p))                                         \
  _ (POLICER_PRE_L2, RX, "policer_pre_l2", APPE_REG_PRE_L2_CNT (p))

#define foreach_qppe_ppe_split_counter                                                             \
  _ (POLICER_PORT_DROP, RX, "policer_port_drop", APPE_REG_PHY_PORT_RX_CNT (p))                     \
  _ (POLICER_VP_DROP, RX, "policer_vp_drop", APPE_REG_VP_RX_CNT (p))                               \
  _ (POLICER_PRE_L2_DROP, RX, "policer_pre_l2_drop", APPE_REG_PRE_L2_CNT (p))

#define foreach_qppe_ppe_counter40                                                                 \
  _ (PTX_PORT_BYTES, TX, "ptx_port", HPPE_REG_PORT_TX_COUNTER_TBL (p))                             \
  _ (POLICER_PORT_TX_DROP_BYTES, TX, "policer_port_drop", HPPE_REG_PORT_TX_DROP_CNT_TBL (p))       \
  _ (PRX_OVERFLOW_DROP_BYTES, RX, "prx_overflow_drop", HPPE_REG_PRX_OVERFLOW_DROP_CNT (p))

#define foreach_qppe_ppe_rx_counter40                                                              \
  _ (POLICER_PORT_BYTES, RX, "policer_port", APPE_REG_PHY_PORT_RX_CNT (p))                         \
  _ (POLICER_VP_BYTES, RX, "policer_vp", APPE_REG_VP_RX_CNT (p))                                   \
  _ (POLICER_PRE_L2_BYTES, RX, "policer_pre_l2", APPE_REG_PRE_L2_CNT (p))

#define foreach_qppe_ppe_drop_counter40                                                            \
  _ (POLICER_PORT_DROP_BYTES, RX, "policer_port_drop", APPE_REG_PHY_PORT_RX_CNT (p))               \
  _ (POLICER_VP_DROP_BYTES, RX, "policer_vp_drop", APPE_REG_VP_RX_CNT (p))                         \
  _ (POLICER_PRE_L2_DROP_BYTES, RX, "policer_pre_l2_drop", APPE_REG_PRE_L2_CNT (p))

#define foreach_qppe_qm_drop_counter                                                               \
  _ (QM_GREEN_PROBABILITY_DROP, "qm_grn_prob_drop", 0)                                             \
  _ (QM_YELLOW_PROBABILITY_DROP, "qm_yel_prob_drop", 1)                                            \
  _ (QM_RED_PROBABILITY_DROP, "qm_red_prob_drop", 2)                                               \
  _ (QM_GREEN_FORCE_DROP, "qm_grn_force_drop", 3)                                                  \
  _ (QM_YELLOW_FORCE_DROP, "qm_yel_force_drop", 4)                                                 \
  _ (QM_RED_FORCE_DROP, "qm_red_force_drop", 5)

/* APPE DROP_CPU_CNT_TBL reasons; these span ingress and egress stages. */
#define foreach_qppe_drop_reason                                                                   \
  _ (1, "policer_drop_l2_proto")                                                                   \
  _ (2, "policer_drop_pppoe_hdr")                                                                  \
  _ (3, "policer_drop_ppp_proto")                                                                  \
  _ (4, "policer_drop_ip4_ver")                                                                    \
  _ (5, "policer_drop_ip4_format")                                                                 \
  _ (6, "policer_drop_ip4_option")                                                                 \
  _ (7, "policer_drop_ip4_length")                                                                 \
  _ (8, "policer_drop_ip4_frag")                                                                   \
  _ (9, "policer_drop_ip4_pod")                                                                    \
  _ (10, "policer_drop_ip4_ttl")                                                                   \
  _ (11, "policer_drop_ip4_proto")                                                                 \
  _ (12, "policer_drop_ip4_csum")                                                                  \
  _ (13, "policer_drop_ip4_addr")                                                                  \
  _ (14, "policer_drop_ip4_land")                                                                  \
  _ (15, "policer_drop_ip4_other")                                                                 \
  _ (16, "policer_drop_ip6_ver")                                                                   \
  _ (17, "policer_drop_ip6_format")                                                                \
  _ (18, "policer_drop_ip6_length")                                                                \
  _ (19, "policer_drop_ip6_ext")                                                                   \
  _ (20, "policer_drop_ip6_hlimit")                                                                \
  _ (21, "policer_drop_ip6_addr")                                                                  \
  _ (22, "policer_drop_ip6_land")                                                                  \
  _ (23, "policer_drop_ip6_frag")                                                                  \
  _ (24, "policer_drop_ip6_pod")                                                                   \
  _ (25, "policer_drop_ip6_exts")                                                                  \
  _ (26, "policer_drop_ip6_other")                                                                 \
  _ (27, "policer_drop_tcp_format")                                                                \
  _ (28, "policer_drop_tcp_ports")                                                                 \
  _ (29, "policer_drop_tcp_flags")                                                                 \
  _ (30, "policer_drop_tcp_csum")                                                                  \
  _ (31, "policer_drop_udp_format")                                                                \
  _ (32, "policer_drop_udp_ports")                                                                 \
  _ (33, "policer_drop_udp_length")                                                                \
  _ (34, "policer_drop_udp_csum")                                                                  \
  _ (35, "policer_drop_udpl_fmt")                                                                  \
  _ (36, "policer_drop_udpl_csum")                                                                 \
  _ (37, "policer_drop_pre_rt")                                                                    \
  _ (38, "policer_drop_pre_snapt")                                                                 \
  _ (39, "policer_drop_pre_dnapt")                                                                 \
  _ (40, "policer_drop_pre_snat")                                                                  \
  _ (41, "policer_drop_pre_dnat")                                                                  \
  _ (42, "policer_drop_tnl_intf")                                                                  \
  _ (43, "policer_drop_tnl_vlan")                                                                  \
  _ (44, "policer_drop_tnl_pppoe")                                                                 \
  _ (45, "policer_drop_tnl_deacc")                                                                 \
  _ (46, "policer_drop_tnl_udpc0")                                                                 \
  _ (47, "policer_drop_tnl_ttl")                                                                   \
  _ (48, "policer_drop_lpm_intf")                                                                  \
  _ (49, "policer_drop_lpm_vlan")                                                                  \
  _ (50, "policer_drop_map_src")                                                                   \
  _ (51, "policer_drop_map_dst")                                                                   \
  _ (52, "policer_drop_map_udpc0")                                                                 \
  _ (53, "policer_drop_map_proto")                                                                 \
  _ (54, "policer_drop_pre_acl")                                                                   \
  _ (55, "policer_drop_tnl_l2_ctx")                                                                \
  _ (56, "policer_drop_tnl_ip4pad")                                                                \
  _ (57, "policer_drop_tnl_ip6pad")                                                                \
  _ (58, "policer_drop_tnl_ecn")                                                                   \
  _ (59, "policer_drop_tnl_short")                                                                 \
  _ (60, "policer_drop_vxlan_hdr")                                                                 \
  _ (61, "policer_drop_vxlangpe")                                                                  \
  _ (62, "policer_drop_geneve_hdr")                                                                \
  _ (63, "policer_drop_gre_hdr")                                                                   \
  _ (64, "policer_drop_gre_csum")                                                                  \
  _ (65, "policer_drop_tnl_type")                                                                  \
  _ (66, "policer_drop_tnl_flags")                                                                 \
  _ (67, "policer_drop_tnl_prog")                                                                  \
  _ (68, "policer_drop_tnl_fwd")                                                                   \
  _ (69, "policer_drop_l3_br_69")                                                                  \
  _ (70, "policer_drop_ph_nat")                                                                    \
  _ (71, "policer_drop_ph_nat_cfg")                                                                \
  _ (72, "policer_drop_l3_route")                                                                  \
  _ (73, "policer_drop_l3_noroute")                                                                \
  _ (74, "policer_drop_l3_nexthop")                                                                \
  _ (75, "policer_drop_l3_ph")                                                                     \
  _ (76, "policer_drop_l3_br_76")                                                                  \
  _ (77, "policer_drop_l3_flow")                                                                   \
  _ (78, "policer_drop_flow_miss")                                                                 \
  _ (79, "policer_drop_l2_mru")                                                                    \
  _ (80, "policer_drop_l2_mtu")                                                                    \
  _ (81, "policer_drop_ip_bcast")                                                                  \
  _ (82, "policer_drop_l3_mtu")                                                                    \
  _ (83, "policer_drop_l3_mru")                                                                    \
  _ (84, "policer_drop_icmp_redir")                                                                \
  _ (85, "policer_drop_fake_mac")                                                                  \
  _ (86, "policer_drop_ip_ttl0")                                                                   \
  _ (87, "policer_drop_sc_loop")                                                                   \
  _ (88, "policer_drop_flow_deacc")                                                                \
  _ (89, "policer_drop_flow_intf")                                                                 \
  _ (90, "policer_drop_flow_tgl")                                                                  \
  _ (91, "policer_drop_mtu_df")                                                                    \
  _ (92, "policer_drop_pppoe_mc")                                                                  \
  _ (93, "policer_drop_ip4_sg_unk")                                                                \
  _ (94, "policer_drop_ip6_sg_unk")                                                                \
  _ (95, "policer_drop_arp_sg_unk")                                                                \
  _ (96, "policer_drop_nd_sg_unk")                                                                 \
  _ (97, "policer_drop_ip4_sg")                                                                    \
  _ (98, "policer_drop_ip6_sg")                                                                    \
  _ (99, "policer_drop_arp_sg")                                                                    \
  _ (100, "policer_drop_nd_sg")                                                                    \
  _ (101, "policer_drop_new_mac")                                                                  \
  _ (102, "policer_drop_l2_hash")                                                                  \
  _ (103, "policer_drop_sta_move")                                                                 \
  _ (104, "policer_drop_learn_lmt")                                                                \
  _ (105, "policer_drop_sa_lookup")                                                                \
  _ (106, "policer_drop_da_lookup")                                                                \
  _ (107, "policer_drop_app_ctrl")                                                                 \
  _ (108, "policer_drop_in_vlan")                                                                  \
  _ (109, "policer_drop_vlan_xlt")                                                                 \
  _ (110, "policer_drop_eg_vlan")                                                                  \
  _ (111, "policer_drop_acl_pre")                                                                  \
  _ (112, "policer_drop_acl_post")                                                                 \
  _ (113, "policer_drop_mc_bc_sa")                                                                 \
  _ (114, "policer_drop_no_dest")                                                                  \
  _ (115, "policer_drop_in_stg")                                                                   \
  _ (116, "policer_drop_eg_stg")                                                                   \
  _ (117, "policer_drop_src_port")                                                                 \
  _ (118, "policer_drop_trunk")                                                                    \
  _ (119, "policer_drop_tx_mac")                                                                   \
  _ (120, "policer_drop_in_tag")                                                                   \
  _ (121, "policer_drop_crc")                                                                      \
  _ (122, "policer_drop_pause")                                                                    \
  _ (123, "policer_drop_promisc")                                                                  \
  _ (124, "policer_drop_isolation")                                                                \
  _ (125, "policer_drop_mgmt_app")                                                                 \
  _ (126, "policer_drop_fake_l2")                                                                  \
  _ (127, "policer_drop_policing")

enum
{
  QPPE_XGMAC_CTR_RX_BYTES,
  QPPE_XGMAC_CTR_RX_PACKETS,
  QPPE_XGMAC_CTR_TX_BYTES,
  QPPE_XGMAC_CTR_TX_PACKETS,
  QPPE_XGMAC_CTR_RX_DROPS,
  QPPE_XGMAC_CTR_TX_DROPS,
#define _(offset, name, description, unit) QPPE_XGMAC_CTR_RX_##name,
  foreach_ppe_xgmac_rx_counter32 foreach_ppe_xgmac_rx_counter64
#undef _
#define _(offset, name, description, unit) QPPE_XGMAC_CTR_TX_##name,
    foreach_ppe_xgmac_tx_counter32 foreach_ppe_xgmac_tx_counter64
#undef _
#define _(name, direction, description, reg) QPPE_XGMAC_CTR_##name,
      foreach_qppe_ppe_counter foreach_qppe_ppe_split_counter
#undef _
#define _(name, direction, description, reg) QPPE_XGMAC_CTR_##name,
	foreach_qppe_ppe_counter40 foreach_qppe_ppe_rx_counter40 foreach_qppe_ppe_drop_counter40
#undef _
#define _(code, description) QPPE_XGMAC_CTR_DROP_##code, QPPE_XGMAC_CTR_DROP_##code##_BYTES,
	  foreach_qppe_drop_reason
#undef _
};

enum
{
  QPPE_GMAC_CTR_RX_BYTES,
  QPPE_GMAC_CTR_RX_PACKETS,
  QPPE_GMAC_CTR_TX_BYTES,
  QPPE_GMAC_CTR_TX_PACKETS,
  QPPE_GMAC_CTR_RX_DROPS,
  QPPE_GMAC_CTR_TX_DROPS,
#define _(offset, name, description, unit) QPPE_GMAC_CTR_RX_##name,
  foreach_ppe_gmac_rx_counter32 foreach_ppe_gmac_rx_counter64
#undef _
#define _(offset, name, description, unit) QPPE_GMAC_CTR_TX_##name,
    foreach_ppe_gmac_tx_counter32 foreach_ppe_gmac_tx_counter64
#undef _
#define _(name, direction, description, reg) QPPE_GMAC_CTR_##name,
      foreach_qppe_ppe_counter foreach_qppe_ppe_split_counter
#undef _
#define _(name, direction, description, reg) QPPE_GMAC_CTR_##name,
	foreach_qppe_ppe_counter40 foreach_qppe_ppe_rx_counter40 foreach_qppe_ppe_drop_counter40
#undef _
#define _(code, description) QPPE_GMAC_CTR_DROP_##code, QPPE_GMAC_CTR_DROP_##code##_BYTES,
	  foreach_qppe_drop_reason
#undef _
};

static vnet_dev_counter_t qppe_xgmac_port_counters[] = {
  [QPPE_XGMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_XGMAC_CTR_RX_BYTES),
  [QPPE_XGMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_XGMAC_CTR_RX_PACKETS),
  [QPPE_XGMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_XGMAC_CTR_TX_BYTES),
  [QPPE_XGMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_XGMAC_CTR_TX_PACKETS),
  [QPPE_XGMAC_CTR_RX_DROPS] = VNET_DEV_CTR_RX_DROPS (QPPE_XGMAC_CTR_RX_DROPS),
  [QPPE_XGMAC_CTR_TX_DROPS] = VNET_DEV_CTR_TX_DROPS (QPPE_XGMAC_CTR_TX_DROPS),
#define _(offset, name, description, unit)                                                         \
  [QPPE_XGMAC_CTR_RX_##name] =                                                                     \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_RX_##name, RX, unit, description),
  foreach_ppe_xgmac_rx_counter32 foreach_ppe_xgmac_rx_counter64
#undef _
#define _(offset, name, description, unit)                                                         \
  [QPPE_XGMAC_CTR_TX_##name] =                                                                     \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_TX_##name, TX, unit, description),
    foreach_ppe_xgmac_tx_counter32 foreach_ppe_xgmac_tx_counter64
#undef _
#define _(name, direction, description, reg)                                                       \
  [QPPE_XGMAC_CTR_##name] =                                                                        \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_##name, direction, PACKETS, description),
      foreach_qppe_ppe_counter foreach_qppe_ppe_split_counter
#undef _
#define _(name, direction, description, reg)                                                       \
  [QPPE_XGMAC_CTR_##name] =                                                                        \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_##name, direction, BYTES, description),
	foreach_qppe_ppe_counter40 foreach_qppe_ppe_rx_counter40 foreach_qppe_ppe_drop_counter40
#undef _
#define _(code, description)                                                                       \
  [QPPE_XGMAC_CTR_DROP_##code] =                                                                   \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_DROP_##code, NA, PACKETS, description),                    \
  [QPPE_XGMAC_CTR_DROP_##code##_BYTES] =                                                           \
    VNET_DEV_CTR_VENDOR (QPPE_XGMAC_CTR_DROP_##code##_BYTES, NA, BYTES, description),
	  foreach_qppe_drop_reason
#undef _
};

static vnet_dev_counter_t qppe_gmac_port_counters[] = {
  [QPPE_GMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_GMAC_CTR_RX_BYTES),
  [QPPE_GMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_GMAC_CTR_RX_PACKETS),
  [QPPE_GMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_GMAC_CTR_TX_BYTES),
  [QPPE_GMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_GMAC_CTR_TX_PACKETS),
  [QPPE_GMAC_CTR_RX_DROPS] = VNET_DEV_CTR_RX_DROPS (QPPE_GMAC_CTR_RX_DROPS),
  [QPPE_GMAC_CTR_TX_DROPS] = VNET_DEV_CTR_TX_DROPS (QPPE_GMAC_CTR_TX_DROPS),
#define _(offset, name, description, unit)                                                         \
  [QPPE_GMAC_CTR_RX_##name] = VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_RX_##name, RX, unit, description),
  foreach_ppe_gmac_rx_counter32 foreach_ppe_gmac_rx_counter64
#undef _
#define _(offset, name, description, unit)                                                         \
  [QPPE_GMAC_CTR_TX_##name] = VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_TX_##name, TX, unit, description),
    foreach_ppe_gmac_tx_counter32 foreach_ppe_gmac_tx_counter64
#undef _
#define _(name, direction, description, reg)                                                       \
  [QPPE_GMAC_CTR_##name] =                                                                         \
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_##name, direction, PACKETS, description),
      foreach_qppe_ppe_counter foreach_qppe_ppe_split_counter
#undef _
#define _(name, direction, description, reg)                                                       \
  [QPPE_GMAC_CTR_##name] =                                                                         \
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_##name, direction, BYTES, description),
	foreach_qppe_ppe_counter40 foreach_qppe_ppe_rx_counter40 foreach_qppe_ppe_drop_counter40
#undef _
#define _(code, description)                                                                       \
  [QPPE_GMAC_CTR_DROP_##code] =                                                                    \
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_DROP_##code, NA, PACKETS, description),                     \
  [QPPE_GMAC_CTR_DROP_##code##_BYTES] =                                                            \
    VNET_DEV_CTR_VENDOR (QPPE_GMAC_CTR_DROP_##code##_BYTES, NA, BYTES, description),
	  foreach_qppe_drop_reason
#undef _
};

enum
{
  QPPE_RXQ_CTR_PTX_QUEUE,
  QPPE_RXQ_CTR_PTX_QUEUE_BYTES,
#define _(name, description, type) QPPE_RXQ_CTR_##name, QPPE_RXQ_CTR_##name##_BYTES,
  foreach_qppe_qm_drop_counter
#undef _
};

static vnet_dev_counter_t qppe_rxq_counters[] = {
  [QPPE_RXQ_CTR_PTX_QUEUE] = VNET_DEV_CTR_VENDOR (QPPE_RXQ_CTR_PTX_QUEUE, RX, PACKETS, "ptx_queue"),
  [QPPE_RXQ_CTR_PTX_QUEUE_BYTES] =
    VNET_DEV_CTR_VENDOR (QPPE_RXQ_CTR_PTX_QUEUE_BYTES, RX, BYTES, "ptx_queue"),
#define _(name, description, type)                                                                 \
  [QPPE_RXQ_CTR_##name] = VNET_DEV_CTR_VENDOR (QPPE_RXQ_CTR_##name, RX, PACKETS, description),     \
  [QPPE_RXQ_CTR_##name##_BYTES] =                                                                  \
    VNET_DEV_CTR_VENDOR (QPPE_RXQ_CTR_##name##_BYTES, RX, BYTES, description),
  foreach_qppe_qm_drop_counter
#undef _
};

static u64
qppe_gmac_counter_read64 (vnet_dev_port_t *port, u32 reg)
{
  u32 low = qppe_gmac_reg_rd (port, reg);
  u32 high = qppe_gmac_reg_rd (port, reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u64
qppe_xgmac_counter_read64 (vnet_dev_port_t *port, u32 reg)
{
  u32 low = qppe_xgmac_reg_rd (port, reg);
  u32 high = qppe_xgmac_reg_rd (port, reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u32
qppe_port_drop_cnt_read (qppe_device_t *qd, u32 reg)
{
  u32 words[5];

  /* Match the SSDK table read sequence, starting with word zero. */
  for (u32 i = 0; i < ARRAY_LEN (words); i++)
    words[i] = qppe_mmio_read32 (qd, reg + i * sizeof (u32));

  return (words[2] >> 8) | ((words[3] & 0xff) << 24);
}

static u64
qppe_ppe_counter_read40 (qppe_device_t *qd, u32 reg)
{
  u32 words[3];

  for (u32 i = 0; i < ARRAY_LEN (words); i++)
    words[i] = qppe_mmio_read32 (qd, reg + i * sizeof (u32));

  return ((u64) (words[2] & 0xff) << 32) | words[1];
}

static u64
qppe_port_counter_read40 (qppe_device_t *qd, u32 reg)
{
  u32 words[5];

  for (u32 i = 0; i < ARRAY_LEN (words); i++)
    words[i] = qppe_mmio_read32 (qd, reg + i * sizeof (u32));

  return ((u64) (words[2] & 0xff) << 32) | words[1];
}

static u64
qppe_port_drop_counter_read40 (qppe_device_t *qd, u32 reg)
{
  u32 words[5];

  for (u32 i = 0; i < ARRAY_LEN (words); i++)
    words[i] = qppe_mmio_read32 (qd, reg + i * sizeof (u32));

  return ((u64) (words[4] & 0xffff) << 24) | (words[3] >> 8);
}

static void
qppe_rxq_counters_poll (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  qppe_device_t *qd = vnet_dev_get_data (rxq->port->dev);
  qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
  u32 q = qp->source_profile * EDMA_RX_QUEUES_PER_RING + rxq->queue_id;
  vnet_dev_counter_t *c;

  ASSERT (rxq->queue_id < EDMA_RX_QUEUES_PER_PORT);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, rxq, QPPE_RXQ_CTR_PTX_QUEUE);
  vnet_dev_counter_value_update (vm, c, qppe_mmio_read32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (q)));
  c = vnet_dev_rx_queue_get_counter_by_index (vm, rxq, QPPE_RXQ_CTR_PTX_QUEUE_BYTES);
  vnet_dev_counter_value_update (vm, c, qppe_ppe_counter_read40 (qd, HPPE_REG_QM_QUEUE_TX_CNT (q)));

#define _(name, description, type)                                                                 \
  c = vnet_dev_rx_queue_get_counter_by_index (vm, rxq, QPPE_RXQ_CTR_##name);                       \
  vnet_dev_counter_value_update (vm, c,                                                            \
				 qppe_mmio_read32 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (q, type)));   \
  c = vnet_dev_rx_queue_get_counter_by_index (vm, rxq, QPPE_RXQ_CTR_##name##_BYTES);               \
  vnet_dev_counter_value_update (                                                                  \
    vm, c, qppe_ppe_counter_read40 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (q, type)));
  foreach_qppe_qm_drop_counter
#undef _
}

static void
qppe_port_ppe_counters_clear (vnet_dev_port_t *port)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  u32 q = qp->source_profile * EDMA_RX_QUEUES_PER_RING;
  vnet_dev_port_id_t p = port->port_id;

  /* PPE counters have no MAC reset line; clear state from previous users. */

  qppe_mmio_write32 (qd, HPPE_REG_PRX_SILENT_DROP_CNT (p), 0);
  qppe_mmio_write32 (qd, HPPE_REG_PRX_OVERFLOW_DROP_CNT (p), 0);
  qppe_mmio_write32 (qd, HPPE_REG_PRX_OVERFLOW_DROP_CNT (p) + 4, 0);
  qppe_mmio_write32 (qd, HPPE_REG_PRX_OVERFLOW_DROP_CNT (p) + 8, 0);
  for (u32 offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
    {
      qppe_mmio_write32 (qd, APPE_REG_PHY_PORT_RX_CNT (p) + offset, 0);
      qppe_mmio_write32 (qd, APPE_REG_VP_RX_CNT (p) + offset, 0);
    }

  for (u32 i = 0; i < EDMA_RX_QUEUES_PER_PORT; i++)
    {
      for (u32 offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
	qppe_mmio_write32 (qd, HPPE_REG_QM_QUEUE_TX_CNT (q + i) + offset, 0);
      for (u32 type = 0; type < HPPE_QM_UNICAST_DROP_TYPES; type++)
	for (u32 offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
	  qppe_mmio_write32 (qd, HPPE_REG_QM_UNICAST_DROP_CNT (q + i, type) + offset, 0);
    }
  for (u32 offset = 0; offset < 5 * sizeof (u32); offset += sizeof (u32))
    qppe_mmio_write32 (qd, APPE_REG_PRE_L2_CNT (p) + offset, 0);
  for (u32 reason = 1; reason < HPPE_DROP_REASON_COUNT; reason++)
    for (u32 offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
      qppe_mmio_write32 (qd, HPPE_REG_DROP_CPU_CNT (p, reason) + offset, 0);
}

vnet_dev_rv_t
qppe_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_xgmac_mmc_control_t mmc;
  ppe_reg_mru_mtu_ctrl_w1_t mru_mtu_ctrl;
  ppe_reg_mc_mtu_ctrl_tbl_t mc_mtu_ctrl;
  ppe_reg_port_eg_vlan_t eg_vlan;
  vnet_dev_port_id_t p = port->port_id;
  u32 mru_mtu[3];

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnet_dev_rx_queue_add_counters (vm, rxq, qppe_rxq_counters, ARRAY_LEN (qppe_rxq_counters));

  for (u32 i = 0; i < ARRAY_LEN (mru_mtu); i++)
    mru_mtu[i] = qppe_mmio_read32 (qd, HPPE_REG_MRU_MTU_CTRL_W0 (p) + i * sizeof (u32));
  mru_mtu_ctrl.as_u32 = mru_mtu[1];
  mru_mtu_ctrl.rx_cnt_en = 1;
  mru_mtu_ctrl.tx_cnt_en = 1;
  mru_mtu[1] = mru_mtu_ctrl.as_u32;
  for (u32 i = 0; i < ARRAY_LEN (mru_mtu); i++)
    qppe_mmio_write32 (qd, HPPE_REG_MRU_MTU_CTRL_W0 (p) + i * sizeof (u32), mru_mtu[i]);

  mc_mtu_ctrl.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (p));
  mc_mtu_ctrl.tx_cnt_en = 1;
  qppe_mmio_write32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (p), mc_mtu_ctrl.as_u32);

  eg_vlan.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_EG_VLAN (p));
  eg_vlan.tx_counting_en = 1;
  qppe_mmio_write32 (qd, HPPE_REG_PORT_EG_VLAN (p), eg_vlan.as_u32);

  for (u32 i = 0; i < ARRAY_LEN (mru_mtu); i++)
    mru_mtu[i] = qppe_mmio_read32 (qd, HPPE_REG_MRU_MTU_CTRL_W0 (p) + i * sizeof (u32));
  mru_mtu_ctrl.as_u32 = mru_mtu[1];
  mc_mtu_ctrl.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (p));
  eg_vlan.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_EG_VLAN (p));
  if (!mru_mtu_ctrl.rx_cnt_en || !mru_mtu_ctrl.tx_cnt_en || !mc_mtu_ctrl.tx_cnt_en ||
      !eg_vlan.tx_counting_en)
    {
      log_err (dev, "port %u PPE counter enable readback failed", p);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  for (u32 offset = 0; offset < 3 * sizeof (u32); offset += sizeof (u32))
    {
      qppe_mmio_write32 (qd, HPPE_REG_PORT_TX_COUNTER_TBL (p) + offset, 0);
      qppe_mmio_write32 (qd, HPPE_REG_PORT_TX_DROP_CNT_TBL (p) + offset, 0);
    }

  if (!qp->is_xgmac)
    {
      ppe_reg_gmac_mib_control_t gmac_mib;

      gmac_mib.as_u32 = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_MIB_CONTROL);
      log_debug (dev, "port %u read GMAC MIB control at offset 0x%x: 0x%08x", p,
		 HPPE_REG_GMAC_BASE (p) + HPPE_GMAC_REG_MIB_CONTROL, gmac_mib.as_u32);
      if (gmac_mib.as_u32 == 0xffffffff)
	{
	  log_err (dev, "port %u GMAC MIB control read returned all ones", p);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      gmac_mib.enable = 1;
      gmac_mib.reset = 1;
      gmac_mib.read_clear = 1;
      log_debug (dev, "port %u enabling/resetting GMAC read-clear MIB counters: 0x%08x", p,
		 gmac_mib.as_u32);
      qppe_gmac_reg_wr (port, HPPE_GMAC_REG_MIB_CONTROL, gmac_mib.as_u32);
      gmac_mib.reset = 0;
      qppe_gmac_reg_wr (port, HPPE_GMAC_REG_MIB_CONTROL, gmac_mib.as_u32);
      log_debug (dev, "port %u GMAC MIB counters enabled in read-clear mode", p);

      qppe_port_ppe_counters_clear (port);

      vnet_dev_port_add_counters (vm, port, qppe_gmac_port_counters,
				  ARRAY_LEN (qppe_gmac_port_counters));
      log_debug (dev, "port %u registered %u hardware GMAC MIB counters", p,
		 ARRAY_LEN (qppe_gmac_port_counters));
      return VNET_DEV_OK;
    }

  mmc.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_MMC_CONTROL);
  log_debug (dev, "port %u read XGMAC MMC control at offset 0x%x: 0x%08x", p,
	     HPPE_REG_XGMAC_BASE (p) + HPPE_XGMAC_REG_MMC_CONTROL, mmc.as_u32);
  if (mmc.as_u32 == 0xffffffff)
    {
      log_err (dev, "port %u XGMAC MMC control read returned all ones", p);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mmc.counter_reset = 1;
  mmc.counter_stop_rollover = 0;
  mmc.reset_on_read = 0;
  mmc.counter_freeze = 0;
  log_debug (dev, "port %u resetting XGMAC MIB counters with MMC control 0x%08x", p, mmc.as_u32);
  qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_MMC_CONTROL, mmc.as_u32);

  qppe_port_ppe_counters_clear (port);

  vnet_dev_port_add_counters (vm, port, qppe_xgmac_port_counters,
			      ARRAY_LEN (qppe_xgmac_port_counters));
  log_debug (dev, "port %u registered %u hardware XGMAC MIB counters", p,
	     ARRAY_LEN (qppe_xgmac_port_counters));

  return VNET_DEV_OK;
}

void
qppe_port_counters_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_counter_t *c;
  u64 gmac_values[ARRAY_LEN (qppe_gmac_port_counters)];
  vnet_dev_port_id_t p = port->port_id;
  u32 drop_index = qp->is_xgmac ? QPPE_XGMAC_CTR_DROP_1 : QPPE_GMAC_CTR_DROP_1;

  if (qp->is_xgmac)
    {
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_RX_BYTES);
      vnet_dev_counter_value_update (
	vm, c, qppe_xgmac_counter_read64 (port, HPPE_XGMAC_REG_RX_BYTES_GOOD_BAD));
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_RX_PACKETS);
      vnet_dev_counter_value_update (
	vm, c, qppe_xgmac_counter_read64 (port, HPPE_XGMAC_REG_RX_FRAMES_GOOD_BAD));
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_TX_BYTES);
      vnet_dev_counter_value_update (
	vm, c, qppe_xgmac_counter_read64 (port, HPPE_XGMAC_REG_TX_BYTES_GOOD_BAD));
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_TX_PACKETS);
      vnet_dev_counter_value_update (
	vm, c, qppe_xgmac_counter_read64 (port, HPPE_XGMAC_REG_TX_FRAMES_GOOD_BAD));
    }
  else
    {
      /* Cache read-clear samples for both generic totals and vendor counters. */
#define _(offset, name, description, unit)                                                         \
  gmac_values[QPPE_GMAC_CTR_RX_##name] = qppe_gmac_reg_rd (port, offset);
      foreach_ppe_gmac_rx_counter32
#undef _
#define _(offset, name, description, unit)                                                         \
  gmac_values[QPPE_GMAC_CTR_RX_##name] = qppe_gmac_counter_read64 (port, offset);
	foreach_ppe_gmac_rx_counter64
#undef _
#define _(offset, name, description, unit)                                                         \
  gmac_values[QPPE_GMAC_CTR_TX_##name] = qppe_gmac_reg_rd (port, offset);
	  foreach_ppe_gmac_tx_counter32
#undef _
#define _(offset, name, description, unit)                                                         \
  gmac_values[QPPE_GMAC_CTR_TX_##name] = qppe_gmac_counter_read64 (port, offset);
	    foreach_ppe_gmac_tx_counter64
#undef _

	      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_RX_BYTES);
      vnet_dev_counter_value_add (vm, c,
				  qppe_gmac_counter_read64 (port, HPPE_GMAC_REG_RX_BYTES_GOOD));
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_RX_PACKETS);
      vnet_dev_counter_value_add (vm, c,
				  gmac_values[QPPE_GMAC_CTR_RX_UNICAST] +
				    gmac_values[QPPE_GMAC_CTR_RX_MULTICAST] +
				    gmac_values[QPPE_GMAC_CTR_RX_BROADCAST]);
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_TX_BYTES);
      vnet_dev_counter_value_add (vm, c, qppe_gmac_counter_read64 (port, HPPE_GMAC_REG_TX_BYTES));
      c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_TX_PACKETS);
      vnet_dev_counter_value_add (vm, c,
				  gmac_values[QPPE_GMAC_CTR_TX_UNICAST] +
				    gmac_values[QPPE_GMAC_CTR_TX_MULTICAST] +
				    gmac_values[QPPE_GMAC_CTR_TX_BROADCAST]);
    }

  c = vnet_dev_port_get_counter_by_index (
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_RX_DROPS : QPPE_GMAC_CTR_RX_DROPS);
  vnet_dev_counter_value_update (vm, c, qppe_port_drop_cnt_read (qd, APPE_REG_PHY_PORT_RX_CNT (p)));
  c = vnet_dev_port_get_counter_by_index (
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_TX_DROPS : QPPE_GMAC_CTR_TX_DROPS);
  vnet_dev_counter_value_update (vm, c, qppe_mmio_read32 (qd, HPPE_REG_PORT_TX_DROP_CNT_TBL (p)));

  if (qp->is_xgmac)
    {
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_RX_##name);                     \
  vnet_dev_counter_value_update (vm, c, qppe_xgmac_reg_rd (port, offset));
      foreach_ppe_xgmac_rx_counter32
#undef _
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_RX_##name);                     \
  vnet_dev_counter_value_update (vm, c, qppe_xgmac_counter_read64 (port, offset));
	foreach_ppe_xgmac_rx_counter64
#undef _
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_TX_##name);                     \
  vnet_dev_counter_value_update (vm, c, qppe_xgmac_reg_rd (port, offset));
	  foreach_ppe_xgmac_tx_counter32
#undef _
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_XGMAC_CTR_TX_##name);                     \
  vnet_dev_counter_value_update (vm, c, qppe_xgmac_counter_read64 (port, offset));
	foreach_ppe_xgmac_tx_counter64
#undef _
    }
  else
    {
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_RX_##name);                      \
  vnet_dev_counter_value_add (vm, c, gmac_values[QPPE_GMAC_CTR_RX_##name]);
      foreach_ppe_gmac_rx_counter32 foreach_ppe_gmac_rx_counter64
#undef _
#define _(offset, name, description, unit)                                                         \
  c = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_TX_##name);                      \
  vnet_dev_counter_value_add (vm, c, gmac_values[QPPE_GMAC_CTR_TX_##name]);
	foreach_ppe_gmac_tx_counter32 foreach_ppe_gmac_tx_counter64
#undef _
    }

#define _(name, direction, description, reg)                                                       \
  c = vnet_dev_port_get_counter_by_index (                                                         \
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_##name : QPPE_GMAC_CTR_##name);                        \
  vnet_dev_counter_value_update (vm, c, qppe_mmio_read32 (qd, reg));
  foreach_qppe_ppe_counter
#undef _

#define _(name, direction, description, reg)                                                       \
  c = vnet_dev_port_get_counter_by_index (                                                         \
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_##name : QPPE_GMAC_CTR_##name);                        \
  vnet_dev_counter_value_update (vm, c, qppe_port_drop_cnt_read (qd, reg));
    foreach_qppe_ppe_split_counter
#undef _

#define _(name, direction, description, reg)                                                       \
  c = vnet_dev_port_get_counter_by_index (                                                         \
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_##name : QPPE_GMAC_CTR_##name);                        \
  vnet_dev_counter_value_update (vm, c, qppe_ppe_counter_read40 (qd, reg));
      foreach_qppe_ppe_counter40
#undef _

#define _(name, direction, description, reg)                                                       \
  c = vnet_dev_port_get_counter_by_index (                                                         \
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_##name : QPPE_GMAC_CTR_##name);                        \
  vnet_dev_counter_value_update (vm, c, qppe_port_counter_read40 (qd, reg));
	foreach_qppe_ppe_rx_counter40
#undef _

#define _(name, direction, description, reg)                                                       \
  c = vnet_dev_port_get_counter_by_index (                                                         \
    vm, port, qp->is_xgmac ? QPPE_XGMAC_CTR_##name : QPPE_GMAC_CTR_##name);                        \
  vnet_dev_counter_value_update (vm, c, qppe_port_drop_counter_read40 (qd, reg));
	  foreach_qppe_ppe_drop_counter40
#undef _

    for (u32 reason = 1; reason < HPPE_DROP_REASON_COUNT; reason++)
  {
    u32 reg = HPPE_REG_DROP_CPU_CNT (p, reason);

    c = vnet_dev_port_get_counter_by_index (vm, port, drop_index++);
    vnet_dev_counter_value_update (vm, c, qppe_mmio_read32 (qd, reg));
    c = vnet_dev_port_get_counter_by_index (vm, port, drop_index++);
    vnet_dev_counter_value_update (vm, c, qppe_ppe_counter_read40 (qd, reg));
  }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->started)
      qppe_rxq_counters_poll (vm, rxq);
}
