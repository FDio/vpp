/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <qppe.h>

/* GLOBAL */

#define QPPE_MAX_PORTS 8

/* HPPE_REG_IN_L2_SERVICE_TBL word 0's egress_bypass_bitmap sub-field above,
 * every bit named per fal_servcode.h bits 32-55 (local bit = that bit
 * number minus 32, since this field only covers that 24-bit range). */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 eg_vlan_member_check_byp : 1;
    u32 eg_vlan_xlt_byp : 1;
    u32 eg_vlan_tag_fmt_ctrl_byp : 1;
    u32 fdb_learn_byp : 1;
    u32 fdb_refresh_byp : 1;
    u32 l2_source_sec_byp : 1;
    u32 management_fwd_byp : 1;
    u32 bridging_fwd_byp : 1;
    u32 in_stp_fltr_byp : 1;
    u32 eg_stp_fltr_byp : 1;
    u32 source_fltr_byp : 1;
    u32 policer_byp : 1;
    u32 l2_pkt_edit_byp : 1;
    u32 l3_pkt_edit_byp : 1;
    u32 acl_post_routing_check_byp : 1;
    u32 port_isolation_byp : 1;
    u32 pre_acl_qos_byp : 1;
    u32 post_acl_qos_byp : 1;
    u32 dscp_qos_byp : 1;
    u32 pcp_qos_byp : 1;
    u32 preheader_qos_byp : 1;
    u32 fake_mac_drop_byp : 1;
    u32 tunnel_context_byp : 1;
    u32 reserved_23 : 1;
    u32 reserved_24_31 : 8;
  };
} ppe_reg_eg_bypass_bitmap_t;

#define foreach_ppe_chip_type                                                                      \
  _ (0x15, HPPE)                                                                                   \
  _ (0x17, MHT)                                                                                    \
  _ (0x20, APPE)                                                                                   \
  _ (0x21, MRPPE)                                                                                  \
  _ (0x30, JHPPE)                                                                                  \
  _ (0x40, HMSPPE)                                                                                 \
  _ (0x50, HTTPPE)

/* PORT */

#define HPPE_REG_PORT_BRIDGE_CTRL(port) (0x060300 + (0x4 * (port)))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 mru : 14;
    u32 mru_cmd : 2;
    u32 mtu : 14;
    u32 mtu_cmd : 2;
  };
} ppe_reg_mru_mtu_ctrl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_cnt_en : 1;
    u32 tx_cnt_en : 1;
    u32 source_profile : 2;
    u32 pcp_qos_group_id : 1;
    u32 dscp_qos_group_id : 1;
    u32 pcp_res_prec_force : 1;
    u32 dscp_res_prec_force : 1;
    u32 preheader_res_prec : 3;
    u32 pcp_res_prec : 3;
    u32 dscp_res_prec : 3;
    u32 flow_res_prec : 3;
    u32 pre_acl_res_prec : 3;
    u32 post_acl_res_prec : 3;
    u32 source_filtering_bypass : 1;
    u32 source_filtering_mode : 1;
    u32 pre_ipo_outer_res_prec : 3;
    u32 pre_ipo_inner_res_prec_0 : 1;
  };
} ppe_reg_mru_mtu_ctrl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 pre_ipo_inner_res_prec_1 : 2;
    u32 reserved_2_31 : 30;
  };
} ppe_reg_mru_mtu_ctrl_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 mtu : 14;
    u32 mtu_cmd : 2;
    u32 tx_cnt_en : 1;
    u32 reserved_17_31 : 15;
  };
} ppe_reg_mc_mtu_ctrl_tbl_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0_7 : 8;
    u32 tx_counting_en : 1;
    u32 reserved_9_31 : 23;
  };
} ppe_reg_port_eg_vlan_t;

/* default reset value 0x2ff09 per the vendor SSDK confirms
 * new_addr_lrn_en/station_move_lrn_en are already 1 out of reset (so
 * PORT_BRIDGE_CTRL itself never needed the same fix VSI_TBL did) and
 * that bits 1-2/8-15 are real fields, not reserved as this struct
 * previously had them. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 new_addr_lrn_en : 1;
    u32 new_addr_fwd_cmd : 2;
    u32 station_move_lrn_en : 1;
    u32 station_move_fwd_cmd : 2;
    u32 reserved_6_7 : 2;
    u32 port_isolation_bitmap : 8;
    u32 txmac_en : 1;
    u32 promisc_en : 1;
    u32 reserved_18_31 : 14;
  };
} ppe_reg_port_bridge_ctrl_t;

/* MY_MAC_TBL entry: a 48-bit MAC_DA plus a valid bit, split across the two
 * words of the entry exactly like the FDB/GMAC MAC address registers
 * elsewhere in this driver - mac_da_0 holds the low 32 bits, mac_da_1 the
 * high 16, so eth_mac[0] (the address's first octet) lands in the top byte
 * of mac_da_1. */
typedef union
{
  u32 val[2];
  struct
  {
    u32 mac_da_0 : 32;
    u32 mac_da_1 : 16;
    u32 valid : 1;
    u32 reserved_17_31 : 15;
  };
} ppe_reg_my_mac_tbl_t;

#define APPE_REG_PORT_MUX_CTRL	       0x10
#define HPPE_REG_MC_MTU_CTRL_TBL(port) (0x60a00 + (0x4 * (port)))
#define HPPE_REG_MRU_MTU_CTRL_W0(port) (0x65000 + (0x10 * (port)))

#define foreach_ppe_reg_port_mux_control_t_fields                                                  \
  _ (1, port1_pcs_sel)                                                                             \
  _ (1, port2_pcs_sel)                                                                             \
  _ (1, port3_pcs_sel)                                                                             \
  _ (1, port4_pcs_sel)                                                                             \
  _ (1, port5_pcs_sel)                                                                             \
  _ (1, port6_pcs_sel)                                                                             \
  _ (2, _reserved0)                                                                                \
  _ (1, port1_mac_sel)                                                                             \
  _ (1, port2_mac_sel)                                                                             \
  _ (1, port3_mac_sel)                                                                             \
  _ (1, port4_mac_sel)                                                                             \
  _ (1, port5_mac_sel)                                                                             \
  _ (1, port6_mac_sel)                                                                             \
  _ (18, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_port_mux_control_t_fields
#undef _
  };
} ppe_reg_port_mux_control_t;

#define HPPE_REG_PRX_SILENT_DROP_CNT(port)   (0x00b024 + 0x4 * (port))
#define HPPE_REG_PRX_OVERFLOW_DROP_CNT(port) (0x0000e000 + 0x10 * (port))
#define HPPE_REG_PORT_TX_COUNTER_TBL(port)   (0x045000 + 0x10 * (port))
#define HPPE_REG_PORT_EG_VLAN(port)	     (0x020020 + 0x4 * (port))
#define HPPE_REG_MY_MAC_TBL(index)	     (0x200000 + (0x8 * (index)))
#define HPPE_MC_MTU_CTRL_TBL_MTU_MASK	     0x00003fff
#define HPPE_MRU_MTU_CTRL_W0_MRU_MASK	     0x00003fff
#define HPPE_MRU_MTU_CTRL_W0_MTU_MASK	     0x3fff0000

#define foreach_ppe_reg_port_tdm_ctrl_t_fields                                                     \
  _ (8, tdm_depth)                                                                                 \
  _ (7, tdm_offset)                                                                                \
  _ (16, _reserved0)                                                                               \
  _ (1, tdm_en)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_port_tdm_ctrl_t_fields
#undef _
  };
} ppe_reg_port_tdm_ctrl_t;

#define HPPE_REG_PORT_TDM_CTRL		  0x00b000
#define HPPE_REG_PORT_RX_FIFO_CFG(port)	  (0x00b004 + 4 * (port))
#define HPPE_REG_PORT_TDM_CFG(index)	  (0x00c000 + 0x10 * (index))
#define HPPE_REG_PORT_IN_FORWARD(port)	  (0x060700 + 4 * (port))
#define APPE_REG_PORT_TX_BUFF_THRSH(port) (0x026100 + 4 * (port))
#define HPPE_PORT_TDM_ENTRIES		  128

#define foreach_ppe_reg_port_tdm_cfg_t_fields                                                      \
  _ (4, port_num)                                                                                  \
  _ (1, dir)                                                                                       \
  _ (1, valid)                                                                                     \
  _ (1, sec_valid)                                                                                 \
  _ (1, resv)                                                                                      \
  _ (4, sec_port_num)                                                                              \
  _ (20, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_port_tdm_cfg_t_fields
#undef _
  };
} ppe_reg_port_tdm_cfg_t;

/* MAC */

#define HPPE_REG_GMAC_BASE(port)  (0x001000 + ((port) - 1) * 0x200)
#define HPPE_REG_XGMAC_BASE(port) (0x500000 + ((port) - 1) * 0x4000)
#define HPPE_GMAC_REG_ENABLE	  0x0
#define HPPE_XGMAC_REG_TX_CONFIG  0x0
#define HPPE_XGMAC_REG_RX_CONFIG  0x4
#define HPPE_XGMAC_MAX_FRAME_SIZE 0x3000

static_always_inline u32
qppe_xgmac_reg_rd (vnet_dev_port_t *port, u32 reg)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);

  return qppe_mmio_read32 (qd, HPPE_REG_XGMAC_BASE (port->port_id) + reg);
}

static_always_inline void
qppe_xgmac_reg_wr (vnet_dev_port_t *port, u32 reg, u32 value)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);

  qppe_mmio_write32 (qd, HPPE_REG_XGMAC_BASE (port->port_id) + reg, value);
}

static_always_inline u32
qppe_gmac_reg_rd (vnet_dev_port_t *port, u32 reg)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);

  return qppe_mmio_read32 (qd, HPPE_REG_GMAC_BASE (port->port_id) + reg);
}

static_always_inline void
qppe_gmac_reg_wr (vnet_dev_port_t *port, u32 reg, u32 value)
{
  qppe_device_t *qd = vnet_dev_get_data (port->dev);

  qppe_mmio_write32 (qd, HPPE_REG_GMAC_BASE (port->port_id) + reg, value);
}

#define foreach_ppe_reg_gmac_enable_t_fields                                                       \
  _ (1, rx_enable)                                                                                 \
  _ (1, tx_enable)                                                                                 \
  _ (2, _reserved0)                                                                                \
  _ (1, full_duplex)                                                                               \
  _ (1, rx_flow_control)                                                                           \
  _ (1, tx_flow_control)                                                                           \
  _ (25, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_enable_t_fields
#undef _
  };
} ppe_reg_gmac_enable_t;

#define foreach_ppe_reg_gmac_speed_t_fields                                                        \
  _ (2, speed)                                                                                     \
  _ (30, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_speed_t_fields
#undef _
  };
} ppe_reg_gmac_speed_t;

#define foreach_ppe_reg_xgmac_tx_config_t_fields                                                   \
  _ (1, tx_enable)                                                                                 \
  _ (1, ddic)                                                                                      \
  _ (1, _reserved0)                                                                                \
  _ (1, ism)                                                                                       \
  _ (4, isr)                                                                                       \
  _ (3, ipg)                                                                                       \
  _ (1, ifp)                                                                                       \
  _ (4, _reserved1)                                                                                \
  _ (1, jabber_disable)                                                                            \
  _ (3, _reserved2)                                                                                \
  _ (3, sarc)                                                                                      \
  _ (1, _reserved3)                                                                                \
  _ (1, vne)                                                                                       \
  _ (1, vnm)                                                                                       \
  _ (2, _reserved4)                                                                                \
  _ (1, g9991en)                                                                                   \
  _ (3, speed)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_tx_config_t_fields
#undef _
  };
} ppe_reg_xgmac_tx_config_t;

#define foreach_ppe_reg_xgmac_rx_config_t_fields                                                   \
  _ (1, rx_enable)                                                                                 \
  _ (1, address_aligned_beats)                                                                     \
  _ (1, crc_strip)                                                                                 \
  _ (1, dcrcc)                                                                                     \
  _ (1, spen)                                                                                      \
  _ (1, usp)                                                                                       \
  _ (1, giant_packet_size_limit_enable)                                                            \
  _ (1, giant_packet_size_limit_watchdog)                                                          \
  _ (1, je)                                                                                        \
  _ (1, ipc)                                                                                       \
  _ (1, lm)                                                                                        \
  _ (1, s2kp)                                                                                      \
  _ (3, hdsms)                                                                                     \
  _ (1, _reserved0)                                                                                \
  _ (14, giant_packet_size_limit)                                                                  \
  _ (1, elen)                                                                                      \
  _ (1, arpen)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_rx_config_t_fields
#undef _
  };
} ppe_reg_xgmac_rx_config_t;

#define foreach_ppe_reg_xgmac_packet_filter_t_fields                                               \
  _ (1, promiscuous_mode)                                                                          \
  _ (1, huc)                                                                                       \
  _ (1, hmc)                                                                                       \
  _ (1, daif)                                                                                      \
  _ (1, pm)                                                                                        \
  _ (1, dbf)                                                                                       \
  _ (2, pass_control_frames)                                                                       \
  _ (1, saif)                                                                                      \
  _ (1, saf)                                                                                       \
  _ (1, hpf)                                                                                       \
  _ (5, _reserved0)                                                                                \
  _ (1, vtfe)                                                                                      \
  _ (3, _reserved1)                                                                                \
  _ (1, ipfe)                                                                                      \
  _ (1, dntu)                                                                                      \
  _ (1, vucc)                                                                                      \
  _ (8, _reserved2)                                                                                \
  _ (1, receive_all)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_packet_filter_t_fields
#undef _
  };
} ppe_reg_xgmac_packet_filter_t;

#define foreach_ppe_reg_xgmac_watchdog_timeout_t_fields                                            \
  _ (4, watchdog_timeout)                                                                          \
  _ (4, _reserved0)                                                                                \
  _ (1, programmable_watchdog_enable)                                                              \
  _ (23, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_watchdog_timeout_t_fields
#undef _
  };
} ppe_reg_xgmac_watchdog_timeout_t;

#define foreach_ppe_reg_xgmac_mmc_control_t_fields                                                 \
  _ (1, counter_reset)                                                                             \
  _ (1, counter_stop_rollover)                                                                     \
  _ (1, reset_on_read)                                                                             \
  _ (1, counter_freeze)                                                                            \
  _ (2, mct)                                                                                       \
  _ (1, _reserved0)                                                                                \
  _ (1, cntprst)                                                                                   \
  _ (8, _reserved1)                                                                                \
  _ (3, pr_mmc_sel)                                                                                \
  _ (13, _reserved2)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mmc_control_t_fields
#undef _
  };
} ppe_reg_xgmac_mmc_control_t;

#define foreach_ppe_reg_gmac_mib_control_t_fields                                                  \
  _ (1, enable)                                                                                    \
  _ (1, reset)                                                                                     \
  _ (1, read_clear)                                                                                \
  _ (29, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mib_control_t_fields
#undef _
  };
} ppe_reg_gmac_mib_control_t;

#define HPPE_GMAC_REG_MIB_CONTROL	  0x34
#define HPPE_XGMAC_REG_MMC_CONTROL	  0x800
#define HPPE_GMAC_REG_RX_BYTES_GOOD	  0x84
#define HPPE_GMAC_REG_TX_BYTES		  0xcc
#define HPPE_XGMAC_REG_TX_BYTES_GOOD_BAD  0x814
#define HPPE_XGMAC_REG_TX_FRAMES_GOOD_BAD 0x81c
#define HPPE_XGMAC_REG_RX_FRAMES_GOOD_BAD 0x900
#define HPPE_XGMAC_REG_RX_BYTES_GOOD_BAD  0x908

#define foreach_ppe_xgmac_rx_counter32                                                             \
  _ (0x930, FRAGMENT_ERROR, "xgmac_frag_err", PACKETS)                                             \
  _ (0x934, JABBER_ERROR, "xgmac_jabber_err", PACKETS)                                             \
  _ (0x938, UNDERSIZE_G, "xgmac_good_undersize", PACKETS)                                          \
  _ (0x93c, OVERSIZE_G, "xgmac_good_oversize", PACKETS)                                            \
  _ (0x9a0, WATCHDOG_ERROR, "xgmac_wdog_err", PACKETS)                                             \
  _ (0x9a4, LPI_USEC, "xgmac_lpi_usec", NA)                                                        \
  _ (0x9a8, LPI_TRANSITIONS, "xgmac_lpi_tran", NA)

#define foreach_ppe_xgmac_rx_counter64                                                             \
  _ (0x910, BYTES_G, "xgmac_good_bytes", BYTES)                                                    \
  _ (0x918, BROADCAST_G, "xgmac_good_broadcast", PACKETS)                                          \
  _ (0x920, MULTICAST_G, "xgmac_good_multicast", PACKETS)                                          \
  _ (0x928, CRC_ERROR, "xgmac_crc_err", PACKETS)                                                   \
  _ (0x940, PACKETS_64_GB, "xgmac_all_pkt64", PACKETS)                                             \
  _ (0x948, PACKETS_65_TO_127_GB, "xgmac_all_65_127_byte", PACKETS)                                \
  _ (0x950, PACKETS_128_TO_255_GB, "xgmac_all_128_255_byte", PACKETS)                              \
  _ (0x958, PACKETS_256_TO_511_GB, "xgmac_all_256_511_byte", PACKETS)                              \
  _ (0x960, PACKETS_512_TO_1023_GB, "xgmac_all_512_1023_byte", PACKETS)                            \
  _ (0x968, PACKETS_1024_TO_MAX_GB, "xgmac_all_1024_max_byte", PACKETS)                            \
  _ (0x970, UNICAST_G, "xgmac_good_unicast", PACKETS)                                              \
  _ (0x978, LENGTH_ERROR, "xgmac_len_err", PACKETS)                                                \
  _ (0x980, OUT_OF_RANGE, "xgmac_outofrange_err", PACKETS)                                         \
  _ (0x988, PAUSE, "xgmac_pause", PACKETS)                                                         \
  _ (0x990, FIFO_OVERFLOW, "xgmac_fifo_overflow", PACKETS)                                         \
  _ (0x998, VLAN_GB, "xgmac_all_vlan", PACKETS)                                                    \
  _ (0x9ac, DISCARD_GB, "xgmac_all_drop_frames", PACKETS)                                          \
  _ (0x9b4, DISCARD_BYTES_GB, "xgmac_all_drop_bytes", BYTES)

#define foreach_ppe_xgmac_tx_counter32                                                             \
  _ (0x8a4, LPI_USEC, "xgmac_lpi_usec", NA)                                                        \
  _ (0x8a8, LPI_TRANSITIONS, "xgmac_lpi_tran", NA)

#define foreach_ppe_xgmac_tx_counter64                                                             \
  _ (0x824, BROADCAST_G, "xgmac_good_broadcast", PACKETS)                                          \
  _ (0x82c, MULTICAST_G, "xgmac_good_multicast", PACKETS)                                          \
  _ (0x834, PACKETS_64_GB, "xgmac_all_pkt64", PACKETS)                                             \
  _ (0x83c, PACKETS_65_TO_127_GB, "xgmac_all_65_127_byte", PACKETS)                                \
  _ (0x844, PACKETS_128_TO_255_GB, "xgmac_all_128_255_byte", PACKETS)                              \
  _ (0x84c, PACKETS_256_TO_511_GB, "xgmac_all_256_511_byte", PACKETS)                              \
  _ (0x854, PACKETS_512_TO_1023_GB, "xgmac_all_512_1023_byte", PACKETS)                            \
  _ (0x85c, PACKETS_1024_TO_MAX_GB, "xgmac_all_1024_max_byte", PACKETS)                            \
  _ (0x864, UNICAST_GB, "xgmac_all_unicast", PACKETS)                                              \
  _ (0x86c, MULTICAST_GB, "xgmac_all_multicast", PACKETS)                                          \
  _ (0x874, BROADCAST_GB, "xgmac_all_broadcast", PACKETS)                                          \
  _ (0x87c, UNDERFLOW_ERROR, "xgmac_underflow_err", PACKETS)                                       \
  _ (0x884, BYTES_G, "xgmac_good_bytes", BYTES)                                                    \
  _ (0x88c, PACKETS_G, "xgmac_good_frames", PACKETS)                                               \
  _ (0x894, PAUSE, "xgmac_pause", PACKETS)                                                         \
  _ (0x89c, VLAN_G, "xgmac_good_vlan", PACKETS)

#define foreach_ppe_gmac_rx_counter32                                                              \
  _ (0x40, BROADCAST, "gmac_broadcast", PACKETS)                                                   \
  _ (0x44, PAUSE, "gmac_pause", PACKETS)                                                           \
  _ (0x48, MULTICAST, "gmac_multicast", PACKETS)                                                   \
  _ (0x4c, FCS_ERROR, "gmac_fcserr", PACKETS)                                                      \
  _ (0x50, ALIGN_ERROR, "gmac_alignerr", PACKETS)                                                  \
  _ (0x54, RUNT, "gmac_runt", PACKETS)                                                             \
  _ (0x58, FRAGMENT, "gmac_frag", PACKETS)                                                         \
  _ (0x5c, JUMBO_FCS_ERROR, "gmac_jumbofcserr", PACKETS)                                           \
  _ (0x60, JUMBO_ALIGN_ERROR, "gmac_jumboalignerr", PACKETS)                                       \
  _ (0x64, PACKETS_64, "gmac_pkt64", PACKETS)                                                      \
  _ (0x68, PACKETS_65_TO_127, "gmac_65_to_127_byte", PACKETS)                                      \
  _ (0x6c, PACKETS_128_TO_255, "gmac_128_to_255_byte", PACKETS)                                    \
  _ (0x70, PACKETS_256_TO_511, "gmac_256_to_511_byte", PACKETS)                                    \
  _ (0x74, PACKETS_512_TO_1023, "gmac_512_to_1023_byte", PACKETS)                                  \
  _ (0x78, PACKETS_1024_TO_1518, "gmac_1024_to_1518_byte", PACKETS)                                \
  _ (0x7c, PACKETS_1519_TO_X, "gmac_1519_to_max_bytes", PACKETS)                                   \
  _ (0x80, TOO_LONG, "gmac_toolong", PACKETS)                                                      \
  _ (0x94, UNICAST, "gmac_unicast", PACKETS)

#define foreach_ppe_gmac_rx_counter64 _ (0x8c, BYTES_BAD, "gmac_bad_bytes", BYTES)

#define foreach_ppe_gmac_tx_counter32                                                              \
  _ (0xa0, BROADCAST, "gmac_broadcast", PACKETS)                                                   \
  _ (0xa4, PAUSE, "gmac_pause", PACKETS)                                                           \
  _ (0xa8, MULTICAST, "gmac_multicast", PACKETS)                                                   \
  _ (0xac, UNDERRUN, "gmac_underrun", PACKETS)                                                     \
  _ (0xb0, PACKETS_64, "gmac_pkt64", PACKETS)                                                      \
  _ (0xb4, PACKETS_65_TO_127, "gmac_65_to_127_byte", PACKETS)                                      \
  _ (0xb8, PACKETS_128_TO_255, "gmac_128_to_255_byte", PACKETS)                                    \
  _ (0xbc, PACKETS_256_TO_511, "gmac_256_to_511_byte", PACKETS)                                    \
  _ (0xc0, PACKETS_512_TO_1023, "gmac_512_to_1023_byte", PACKETS)                                  \
  _ (0xc4, PACKETS_1024_TO_1518, "gmac_1024_to_1518_byte", PACKETS)                                \
  _ (0xc8, PACKETS_1519_TO_X, "gmac_1519_to_max_bytes", PACKETS)                                   \
  _ (0xd4, COLLISIONS, "gmac_collisions", NA)                                                      \
  _ (0xd8, ABORT_COLLISIONS, "gmac_abortcol", NA)                                                  \
  _ (0xdc, MULTIPLE_COLLISIONS, "gmac_multicol", NA)                                               \
  _ (0xe0, SINGLE_COLLISIONS, "gmac_singlecol", NA)                                                \
  _ (0xe4, EXCESSIVE_DEFER, "gmac_excdeffer", NA)                                                  \
  _ (0xe8, DEFER, "gmac_deffer", NA)                                                               \
  _ (0xec, LATE_COLLISION, "gmac_latecol", NA)                                                     \
  _ (0xf0, UNICAST, "gmac_unicast", PACKETS)

#define foreach_ppe_gmac_tx_counter64
#define HPPE_XGMAC_REG_PACKET_FILTER	0x8
#define HPPE_XGMAC_REG_WATCHDOG_TIMEOUT 0xc
#define HPPE_XGMAC_REG_ADDR0_HIGH	0x300
#define HPPE_XGMAC_REG_ADDR0_LOW	0x304
#define HPPE_XGMAC_ADDR_ENABLE		(1u << 31)
#define HPPE_GMAC_REG_ADDR0		0x8
#define HPPE_GMAC_REG_ADDR1		0xc
#define HPPE_GMAC_REG_SPEED		0x4
#define HPPE_XGMAC_SPEED_10000		0
#define HPPE_XGMAC_SPEED_10000_USXGMII	4
#define HPPE_XGMAC_SPEED_5000		5
#define HPPE_XGMAC_SPEED_2500		2
#define HPPE_XGMAC_SPEED_2500_USXGMII	6
#define HPPE_XGMAC_SPEED_1000		3

#define foreach_ppe_reg_gmac_mac_ctrl0_t_fields                                                    \
  _ (7, ipgt)                                                                                      \
  _ (1, _reserved0)                                                                                \
  _ (7, ipgr2)                                                                                     \
  _ (1, half_thdf_ctrl)                                                                            \
  _ (1, hugen)                                                                                     \
  _ (1, huge)                                                                                      \
  _ (1, flchk)                                                                                     \
  _ (1, abebe)                                                                                     \
  _ (8, _reserved1)                                                                                \
  _ (1, amaxc_en)                                                                                  \
  _ (1, bpnb)                                                                                      \
  _ (1, nobo)                                                                                      \
  _ (1, drbnib_rxok_en)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mac_ctrl0_t_fields
#undef _
  };
} ppe_reg_gmac_mac_ctrl0_t;

#define foreach_ppe_reg_gmac_mac_ctrl1_t_fields                                                    \
  _ (4, jam_ipg)                                                                                   \
  _ (1, tpause)                                                                                    \
  _ (1, tctl)                                                                                      \
  _ (1, sstct)                                                                                     \
  _ (1, simr)                                                                                      \
  _ (4, retry)                                                                                     \
  _ (4, prlen)                                                                                     \
  _ (1, ppad)                                                                                      \
  _ (1, povr)                                                                                      \
  _ (1, phug)                                                                                      \
  _ (1, mbof)                                                                                      \
  _ (8, lcol)                                                                                      \
  _ (1, long_jam_en)                                                                               \
  _ (3, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mac_ctrl1_t_fields
#undef _
  };
} ppe_reg_gmac_mac_ctrl1_t;

#define foreach_ppe_reg_gmac_mac_ctrl2_t_fields                                                    \
  _ (1, _reserved0)                                                                                \
  _ (1, ipg_dec_len)                                                                               \
  _ (1, test_pause)                                                                                \
  _ (1, mac_lpi_tx_idle)                                                                           \
  _ (1, mac_loop_back)                                                                             \
  _ (1, ipg_dec_en)                                                                                \
  _ (1, crs_sel)                                                                                   \
  _ (1, crc_rsv_en)                                                                                \
  _ (14, maxfr)                                                                                    \
  _ (2, _reserved1)                                                                                \
  _ (4, mac_tx_thd)                                                                                \
  _ (4, mac_rsv)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mac_ctrl2_t_fields
#undef _
  };
} ppe_reg_gmac_mac_ctrl2_t;

#define foreach_ppe_reg_gmac_mac_dbg_ctrl_t_fields                                                 \
  _ (7, ipgr1)                                                                                     \
  _ (1, _reserved0)                                                                                \
  _ (8, high_ipg)                                                                                  \
  _ (4, _reserved1)                                                                                \
  _ (4, mac_ipg_ctrl)                                                                              \
  _ (6, _reserved2)                                                                                \
  _ (1, mac_len_ctrl)                                                                              \
  _ (1, edxsdfr_transmit_en)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mac_dbg_ctrl_t_fields
#undef _
  };
} ppe_reg_gmac_mac_dbg_ctrl_t;

#define foreach_ppe_reg_gmac_mac_jumbo_size_t_fields                                               \
  _ (14, mac_jumbo_size)                                                                           \
  _ (18, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_gmac_mac_jumbo_size_t_fields
#undef _
  };
} ppe_reg_gmac_mac_jumbo_size_t;

#define foreach_ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields                                         \
  _ (1, fcb)                                                                                       \
  _ (1, tfe)                                                                                       \
  _ (2, _reserved0)                                                                                \
  _ (3, plt)                                                                                       \
  _ (1, dapq)                                                                                      \
  _ (8, _reserved1)                                                                                \
  _ (16, pt)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t;

#define foreach_ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields                                            \
  _ (1, rfe)                                                                                       \
  _ (1, up)                                                                                        \
  _ (6, _reserved0)                                                                                \
  _ (1, pfce)                                                                                      \
  _ (23, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_rx_flow_ctrl_t;

#define foreach_ppe_reg_xgmac_mac_lpi_timers_control_t_fields                                      \
  _ (16, twt)                                                                                      \
  _ (10, lst)                                                                                      \
  _ (6, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_lpi_timers_control_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_lpi_timers_control_t;

#define foreach_ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields                                    \
  _ (3, _reserved0)                                                                                \
  _ (17, lpiet)                                                                                    \
  _ (12, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_lpi_auto_entry_timer_t;

#define foreach_ppe_reg_xgmac_mac_1us_tic_counter_t_fields                                         \
  _ (12, tic_1us_cntr)                                                                             \
  _ (20, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_1us_tic_counter_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_1us_tic_counter_t;

#define foreach_ppe_reg_xgmac_mac_snps_scs_t_fields                                                \
  _ (31, _reserved0)                                                                               \
  _ (1, mtl_scs1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_snps_scs_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_snps_scs_t;

#define foreach_ppe_reg_xgmac_mac_vlan_tag_t_fields                                                \
  _ (16, vl)                                                                                       \
  _ (1, etv)                                                                                       \
  _ (1, vtim)                                                                                      \
  _ (1, esvl)                                                                                      \
  _ (1, ersvlm)                                                                                    \
  _ (1, dovltc)                                                                                    \
  _ (2, evls)                                                                                      \
  _ (1, _reserved_23)                                                                              \
  _ (1, evlrxs)                                                                                    \
  _ (1, vthm)                                                                                      \
  _ (1, edvlp)                                                                                     \
  _ (1, erivlt)                                                                                    \
  _ (2, eivls)                                                                                     \
  _ (1, _reserved_30)                                                                              \
  _ (1, eivlrxs)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_vlan_tag_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_vlan_tag_t;

#define HPPE_REG_XGMAC_MAC_VLAN_TAG 0x50

#define foreach_ppe_reg_xgmac_mac_rx_eth_type_match_t_fields                                       \
  _ (16, et)                                                                                       \
  _ (16, _reserved_16)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_rx_eth_type_match_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_rx_eth_type_match_t;

#define HPPE_REG_XGMAC_MAC_RX_ETH_TYPE_MATCH 0x6c

#define foreach_ppe_reg_xgmac_mac_interrupt_enable_t_fields                                        \
  _ (4, _reserved_0)                                                                               \
  _ (1, pmtie)                                                                                     \
  _ (1, lpiie)                                                                                     \
  _ (6, _reserved_6)                                                                               \
  _ (1, tsie)                                                                                      \
  _ (1, txesie)                                                                                    \
  _ (1, rxesie)                                                                                    \
  _ (17, _reserved_15)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mac_interrupt_enable_t_fields
#undef _
  };
} ppe_reg_xgmac_mac_interrupt_enable_t;

#define HPPE_REG_XGMAC_MAC_INTERRUPT_ENABLE 0xb4

#define foreach_ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields                                \
  _ (1, rxgbfrmie)                                                                                 \
  _ (1, rxgboctie)                                                                                 \
  _ (1, rxgoctie)                                                                                  \
  _ (1, rxbcgfie)                                                                                  \
  _ (1, rxmcgfie)                                                                                  \
  _ (1, rxcrcerfie)                                                                                \
  _ (1, rxruntfie)                                                                                 \
  _ (1, rxjaberfie)                                                                                \
  _ (1, rxusizegfie)                                                                               \
  _ (1, rxosizegfie)                                                                               \
  _ (1, rx64octgbfie)                                                                              \
  _ (1, rx65t127octgbfie)                                                                          \
  _ (1, rx128t255octgbfie)                                                                         \
  _ (1, rx256t511octgbfie)                                                                         \
  _ (1, rx512t1023octgbfie)                                                                        \
  _ (1, rx1024tmaxoctgbfie)                                                                        \
  _ (1, rxucgfie)                                                                                  \
  _ (1, rxlenerfie)                                                                                \
  _ (1, rxorangefie)                                                                               \
  _ (1, rxpausfie)                                                                                 \
  _ (1, rxfovfie)                                                                                  \
  _ (1, rxvlangbfie)                                                                               \
  _ (1, rxwdogfie)                                                                                 \
  _ (1, rxdisfcie)                                                                                 \
  _ (1, rxdisocie)                                                                                 \
  _ (1, rxlpiuscie)                                                                                \
  _ (1, rxlpitrcie)                                                                                \
  _ (4, _reserved_27)                                                                              \
  _ (1, rxprmmcise)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields
#undef _
  };
} ppe_reg_xgmac_mmc_receive_interrupt_enable_t;

#define HPPE_REG_XGMAC_MMC_RECEIVE_INTERRUPT_ENABLE 0x80c

#define foreach_ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields                               \
  _ (1, txgboctie)                                                                                 \
  _ (1, txgbfrmie)                                                                                 \
  _ (1, txbcgfie)                                                                                  \
  _ (1, txmcgfie)                                                                                  \
  _ (1, tx64octgbfie)                                                                              \
  _ (1, tx65t127octgbfie)                                                                          \
  _ (1, tx128t255octgbfie)                                                                         \
  _ (1, tx256t511octgbfie)                                                                         \
  _ (1, tx512t1023octgbfie)                                                                        \
  _ (1, tx1024tmaxoctgbfie)                                                                        \
  _ (1, txucgbfie)                                                                                 \
  _ (1, txmcgbfie)                                                                                 \
  _ (1, txbcgbfie)                                                                                 \
  _ (1, txuflowerfie)                                                                              \
  _ (1, txgoctie)                                                                                  \
  _ (1, txgfrmie)                                                                                  \
  _ (1, txpausfie)                                                                                 \
  _ (1, txvlangfie)                                                                                \
  _ (1, txlpiuscie)                                                                                \
  _ (1, txlpitrcie)                                                                                \
  _ (11, _reserved_20)                                                                             \
  _ (1, txprmmcise)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields
#undef _
  };
} ppe_reg_xgmac_mmc_transmit_interrupt_enable_t;

#define HPPE_REG_XGMAC_MMC_TRANSMIT_INTERRUPT_ENABLE 0x810
#define HPPE_REG_GMAC_MAC_CTRL0			     0x10
#define HPPE_REG_GMAC_MAC_CTRL1			     0x14
#define HPPE_REG_GMAC_MAC_CTRL2			     0x18
#define HPPE_REG_GMAC_MAC_DBG_CTRL		     0x1c
#define HPPE_REG_GMAC_MAC_JUMBO_SIZE		     0x30
#define HPPE_REG_GMAC_MAC_MIB_CTRL		     0x34
#define HPPE_REG_XGMAC_MAC_Q0_TX_FLOW_CTRL	     0x70
#define HPPE_REG_XGMAC_MAC_RX_FLOW_CTRL		     0x90
#define HPPE_REG_XGMAC_MAC_LPI_TIMERS_CONTROL	     0xd4
#define HPPE_REG_XGMAC_MAC_LPI_AUTO_ENTRY_TIMER	     0xd8
#define HPPE_REG_XGMAC_MAC_1US_TIC_COUNTER	     0xdc
#define HPPE_REG_XGMAC_MAC_SNPS_SCS		     0x160
#define HPPE_REG_XGMAC_MMC_CONTROL		     0x800
#define HPPE_XGMAC_MAX_RX_FRAME_SIZE		     (HPPE_XGMAC_MAX_FRAME_SIZE - 4)

/* BM */

#define HPPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290

typedef union
{
  u32 as_u32;
  struct
  {
    u32 shared_buffer_limit : 11;
    u32 reserved_11 : 21;
  };
} ppe_reg_bm_shared_group_config_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_bm_port_fc_mode_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 xon_threshold : 11;
    u32 reserved_11 : 5;
    u32 fc_status : 2;
    u32 reserved_18 : 14;
  };
} ppe_reg_bm_port_fc_status_t;

#define foreach_ppe_reg_bm_fb_fifo_cfg_t_fields                                                    \
  _ (5, fb_fifo_threshold)                                                                         \
  _ (27, _reserved_5)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_fb_fifo_cfg_t_fields
#undef _
  };
} ppe_reg_bm_fb_fifo_cfg_t;

#define foreach_ppe_reg_bm_fp_fifo_cfg_t_fields                                                    \
  _ (5, fp_fifo_threshold)                                                                         \
  _ (27, _reserved_5)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_fp_fifo_cfg_t_fields
#undef _
  };
} ppe_reg_bm_fp_fifo_cfg_t;

#define foreach_ppe_reg_bm_tick_dly_cfg_t_fields                                                   \
  _ (1, tick_delay)                                                                                \
  _ (31, _reserved_1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_tick_dly_cfg_t_fields
#undef _
  };
} ppe_reg_bm_tick_dly_cfg_t;

#define foreach_ppe_reg_bm_total_react_profile_th_cfg_t_fields                                     \
  _ (11, total_react_profile_threshold)                                                            \
  _ (21, _reserved_11)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_total_react_profile_th_cfg_t_fields
#undef _
  };
} ppe_reg_bm_total_react_profile_th_cfg_t;

#define foreach_ppe_reg_bm_port_profile_cnt_en_t_fields                                            \
  _ (1, port_cnt_en_0)                                                                             \
  _ (1, port_cnt_en_1)                                                                             \
  _ (1, port_cnt_en_2)                                                                             \
  _ (1, port_cnt_en_3)                                                                             \
  _ (1, port_cnt_en_4)                                                                             \
  _ (1, port_cnt_en_5)                                                                             \
  _ (1, port_cnt_en_6)                                                                             \
  _ (1, port_cnt_en_7)                                                                             \
  _ (1, port_cnt_en_8)                                                                             \
  _ (1, port_cnt_en_9)                                                                             \
  _ (1, port_cnt_en_10)                                                                            \
  _ (1, port_cnt_en_11)                                                                            \
  _ (1, port_cnt_en_12)                                                                            \
  _ (1, port_cnt_en_13)                                                                            \
  _ (1, port_cnt_en_14)                                                                            \
  _ (1, _reserved_15)                                                                              \
  _ (1, react_cnt_en_0)                                                                            \
  _ (1, react_cnt_en_1)                                                                            \
  _ (1, react_cnt_en_2)                                                                            \
  _ (1, react_cnt_en_3)                                                                            \
  _ (1, react_cnt_en_4)                                                                            \
  _ (1, react_cnt_en_5)                                                                            \
  _ (1, react_cnt_en_6)                                                                            \
  _ (1, react_cnt_en_7)                                                                            \
  _ (1, react_cnt_en_8)                                                                            \
  _ (1, react_cnt_en_9)                                                                            \
  _ (1, react_cnt_en_10)                                                                           \
  _ (1, react_cnt_en_11)                                                                           \
  _ (1, react_cnt_en_12)                                                                           \
  _ (1, react_cnt_en_13)                                                                           \
  _ (1, react_cnt_en_14)                                                                           \
  _ (1, _reserved_31)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_port_profile_cnt_en_t_fields
#undef _
  };
} ppe_reg_bm_port_profile_cnt_en_t;

#define foreach_ppe_reg_bm_grp_profile_cnt_en_t_fields                                             \
  _ (1, grp_cnt_en_0)                                                                              \
  _ (1, grp_cnt_en_1)                                                                              \
  _ (1, grp_cnt_en_2)                                                                              \
  _ (1, grp_cnt_en_3)                                                                              \
  _ (1, total_react_cnt_en)                                                                        \
  _ (27, _reserved_5)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_bm_grp_profile_cnt_en_t_fields
#undef _
  };
} ppe_reg_bm_grp_profile_cnt_en_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 next_ptr : 11;
    u32 eop : 1;
    u32 reserved_12 : 20;
  };
} ppe_reg_bm_llm_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 shared_group_id : 2;
    u32 reserved_2 : 30;
  };
} ppe_reg_bm_port_group_id_t;

/* ceiling is an 11-bit value split across ceiling_low here and
 * ceiling_high in word1: ceil = (ceiling_high << 3) | ceiling_low. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 react_limit : 9;
    u32 resume_threshold : 9;
    u32 resume_offset : 11;
    u32 ceiling_low : 3;
  };
} ppe_reg_bm_port_fc_cfg_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ceiling_high : 8;
    u32 weight : 3;
    u32 dynamic : 1;
    u32 pre_alloc : 11;
    u32 reserved_23 : 9;
  };
} ppe_reg_bm_port_fc_cfg_w1_t;

#define HPPE_BM_PORT_ID_CPU		      0
#define HPPE_REG_BM_PORT_FC_MODE(bm_port)     (0x600100 + 0x4 * (bm_port))
#define HPPE_REG_BM_PORT_GROUP_ID(bm_port)    (0x600180 + 0x4 * (bm_port))
#define HPPE_REG_BM_PORT_FC_CFG_W0(bm_port)   (0x601000 + 0x10 * (bm_port))
#define HPPE_REG_BM_PORT_FC_CFG_W1(bm_port)   (0x601004 + 0x10 * (bm_port))
#define HPPE_BM_SHARED_GROUP0_LIMIT	      1550
#define HPPE_REG_BM_FB_FIFO_CFG		      0x600000
#define HPPE_REG_BM_FP_FIFO_CFG		      0x600004
#define HPPE_REG_BM_DEQ_FIFO_CFG(i)	      (0x600008 + 4 * (i))
#define HPPE_REG_BM_TICK_DLY_CFG	      0x60002c
#define HPPE_REG_BM_PORT_FC_STATUS(p)	      (0x600140 + 4 * (p))
#define HPPE_REG_BM_PORT_CNT(p)		      (0x6001c0 + 4 * (p))
#define HPPE_REG_BM_PORT_REACTED_CNT(p)	      (0x600240 + 4 * (p))
#define HPPE_REG_BM_SHARED_GROUP_CNT(g)	      (0x600280 + 4 * (g))
#define HPPE_REG_BM_PORT_PROFILE_CNT_EN	      0x600300
#define HPPE_REG_BM_GRP_PROFILE_CNT_EN	      0x600304
#define HPPE_REG_BM_PORT_PROFILE_TH_CFG(p)    (0x600308 + 4 * (p))
#define HPPE_REG_BM_REACT_PROFILE_TH_CFG(p)   (0x600348 + 4 * (p))
#define HPPE_REG_BM_GRP_PROFILE_TH_CFG(g)     (0x600388 + 4 * (g))
#define HPPE_REG_BM_TOT_REACT_PROFILE_TH_CFG  0x600398
#define HPPE_REG_BM_PORT_OUT_PROFILE_CNT(p)   (0x6003a0 + 4 * (p))
#define HPPE_REG_BM_PORT_IN_PROFILE_CNT(p)    (0x6003e0 + 4 * (p))
#define HPPE_REG_BM_REACT_OUT_PROFILE_CNT(p)  (0x600420 + 4 * (p))
#define HPPE_REG_BM_REACT_IN_PROFILE_CNT(p)   (0x600460 + 4 * (p))
#define HPPE_REG_BM_GRP_OUT_PROFILE_CNT(g)    (0x6004a0 + 4 * (g))
#define HPPE_REG_BM_GRP_IN_PROFILE_CNT(g)     (0x6004b0 + 4 * (g))
#define HPPE_REG_BM_TOT_REACT_OUT_PROFILE_CNT 0x6004c0
#define HPPE_REG_BM_TOT_REACT_IN_PROFILE_CNT  0x6004c4
#define HPPE_REG_BM_LLM(i)		      (0x610000 + 0x10 * (i))
#define HPPE_REG_BM_RCM(i)		      (0x620000 + 0x10 * (i))
#define HPPE_REG_BM_DM(i)		      (0x680000 + 0x40 * (i))
#define HPPE_BM_PORT_COUNT		      15
#define HPPE_BM_GROUP_COUNT		      4
#define HPPE_BM_DEQ_FIFO_COUNT		      9
#define HPPE_BM_LLM_COUNT		      2048
#define HPPE_BM_RCM_COUNT		      2048
#define HPPE_BM_DM_COUNT		      8192
#define HPPE_BM_FIFO_THRESHOLD_MASK	      0x1f
#define HPPE_BM_DEQ_THRESHOLD_MASK	      0x7
#define HPPE_BM_BUFFER_COUNT_MASK	      0x7ff
#define HPPE_BM_REACT_COUNT_MASK	      0x1ff
#define HPPE_BM_REF_COUNT_MASK		      0xf
#define HPPE_BM_PORT_ID_PHYS_BASE	      7
#define HPPE_BM_PHYS_PORT_CEIL		      250
#define HPPE_BM_PHYS_PORT_WEIGHT	      4
#define HPPE_BM_PHYS_PORT_RESUME_OFFSET	      36
#define HPPE_BM_PHYS_PORT_REACT_LIMIT	      128

/* AC */

#define HPPE_REG_AC_GRP_CFG_W0(grp)		(0x84c000 + 0x10 * (grp))
#define HPPE_REG_AC_UNICAST_QUEUE_CFG_W0(queue) (0x848000 + 0x10 * (queue))
#define HPPE_AC_UNICAST_QUEUE_COUNT		256
#define HPPE_AC_MULTICAST_QUEUE_BASE		256
#define HPPE_AC_MULTICAST_QUEUE_COUNT		44

#define HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0(queue)                                                  \
  (0x84a000 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ac_en : 1;
    u32 ac_fc_en : 1;
    u32 clr_aware : 1;
    u32 gap_grn_red : 11;
    u32 gap_grn_yel : 11;
    u32 threshold_low : 7;
  };
} ppe_reg_ac_grp_cfg_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 threshold_high : 4;
    u32 buf_limit : 11;
    u32 resume_red : 11;
    u32 resume_yel_low : 6;
  };
} ppe_reg_ac_grp_cfg_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 resume_yel_high : 5;
    u32 resume_grn : 11;
    u32 pre_alloc : 11;
    u32 reserved_27_31 : 5;
  };
} ppe_reg_ac_grp_cfg_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 en : 1;
    u32 wred_en : 1;
    u32 fc_en : 1;
    u32 clr_aware : 1;
    u32 grp_id : 2;
    u32 pre_limit : 11;
    u32 dynamic : 1;
    u32 weight : 3;
    u32 threshold : 11;
  };
} ppe_reg_ac_unicast_queue_cfg_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 gap_grn_grn_min : 11;
    u32 gap_grn_yel_max : 11;
    u32 gap_grn_yel_min_low : 10;
  };
} ppe_reg_ac_unicast_queue_cfg_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 gap_grn_yel_min_high : 1;
    u32 gap_grn_red_max : 11;
    u32 gap_grn_red_min : 11;
    u32 red_resume_low : 9;
  };
} ppe_reg_ac_unicast_queue_cfg_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 red_resume_high : 2;
    u32 yel_resume : 11;
    u32 grn_resume : 11;
    u32 reserved_24 : 8;
  };
} ppe_reg_ac_unicast_queue_cfg_w3_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 en : 1;
    u32 fc_en : 1;
    u32 clr_aware : 1;
    u32 grp_id : 2;
    u32 pre_limit : 11;
    u32 threshold : 11;
    u32 gap_grn_yel_low : 5;
  };
} ppe_reg_ac_multicast_queue_cfg_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 gap_grn_yel_high : 6;
    u32 gap_grn_red : 11;
    u32 red_resume : 11;
    u32 yel_resume_low : 4;
  };
} ppe_reg_ac_multicast_queue_cfg_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 yel_resume_high : 7;
    u32 resume : 11;
    u32 reserved_18 : 14;
  };
} ppe_reg_ac_multicast_queue_cfg_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 buffers : 16;
    u32 alloc_used : 16;
  };
} ppe_reg_ac_grp_cnt_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 red_resume : 11;
    u32 yel_resume : 11;
    u32 grn_resume_low : 10;
  };
} ppe_reg_ac_drop_state_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 grn_resume_high : 1;
    u32 red_drop : 4;
    u32 yel_drop : 4;
    u32 grn_drop : 4;
    u32 reserved : 19;
  } unicast;
  struct
  {
    u32 grn_resume_high : 1;
    u32 red_drop : 1;
    u32 yel_drop : 1;
    u32 grn_drop : 1;
    u32 reserved : 28;
  } multicast;
} ppe_reg_ac_drop_state_w1_t;

#define HPPE_REG_AC_MSEQ_TBL(index)		 (0x846000 + 0x10 * (index))
#define HPPE_REG_AC_UNICAST_QUEUE_CNT_TBL(queue) (0x84e000 + 0x10 * (queue))

#define HPPE_REG_AC_MULTICAST_QUEUE_CNT_TBL(queue)                                                 \
  (0x852000 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))

#define HPPE_REG_AC_GRP_CNT_TBL(grp)			(0x854000 + 0x10 * (grp))
#define HPPE_REG_AC_UNICAST_QUEUE_DROP_STATE_TBL(queue) (0x856000 + 0x10 * (queue))

#define HPPE_REG_AC_MULTICAST_QUEUE_DROP_STATE_TBL(queue)                                          \
  (0x858000 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))

#define HPPE_REG_AC_GRP_DROP_STATE_TBL(grp) (0x85a000 + 0x10 * (grp))
#define HPPE_AC_MSEQ_COUNT		    256
#define HPPE_AC_MSEQ_MASK		    0x7fff
#define HPPE_AC_UNICAST_QUEUE_CNT_MASK	    0xfff
#define HPPE_AC_MULTICAST_QUEUE_CNT_MASK    0x1fff

/* ACL */

/* MY_MAC_TBL (vendor's IPE_L3_BASE_ADDR + MY_MAC_TBL_ADDRESS): a small,
 * global (not per-VSI) table of this chip's own MAC addresses, consulted by
 * PORT_BRIDGE_CTRL.promisc_en when it is clear to admit unicast frames
 * addressed to us while dropping everything else before FDB/VSI forwarding
 * is even consulted. */
#define HPPE_ACL_ACTION_FWD		  0
#define APPE_ACL_PRI_PERMIT		  1
#define APPE_PRE_ACL_SECONDARY_MAX	  4
#define APPE_PRE_ACL_ROWS_PER_PORT	  (2 + APPE_PRE_ACL_SECONDARY_MAX + 2)
#define HPPE_ACL_ACTION_DROP		  1
#define HPPE_ACL_ACTION_COPYCPU		  2
#define HPPE_ACL_ACTION_RDTCPU		  3
#define APPE_ACL_PRI_DENY		  0
#define APPE_PRE_ACL_BCAST_ROW(port_id)	  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT)
#define APPE_PRE_ACL_PRIMARY_ROW(port_id) ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 1)

#define APPE_PRE_ACL_DENY_ROW(port_id)                                                             \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + APPE_PRE_ACL_SECONDARY_MAX)

#define APPE_PRE_ACL_ROWS_RESERVED	    (QPPE_MAX_PORTS * APPE_PRE_ACL_ROWS_PER_PORT)
#define HPPE_REG_IPO_RULE_REG(index)	    (0x0b0000 + (0x10 * (index)))
#define HPPE_REG_IPO_MASK_REG(index)	    (0x0b2000 + (0x10 * (index)))
#define HPPE_REG_IPO_ACTION(index)	    (0x0b8000 + (0x20 * (index)))
#define HPPE_REG_IPO_CNT_TBL(index)	    (0x074000 + (0x10 * (index)))
#define HPPE_ACL_ACTION_WORDS		    8
#define HPPE_ACL_RULE_TYPE_MAC_DA	    0
#define HPPE_ACL_SRC_TYPE_PORTBITMAP	    0
#define HPPE_ACL_TOTAL_ROWS		    512
#define APPE_REG_PRE_IPO_RULE_REG(index)    (0x180000 + (0x10 * (index)))
#define APPE_REG_PRE_IPO_MASK_REG(index)    (0x182000 + (0x10 * (index)))
#define APPE_REG_PRE_IPO_ACTION(index)	    (0x188000 + (0x40 * (index)))
#define APPE_REG_PRE_IPO_GLB_HIT_COUNTER    0x18430c
#define APPE_REG_PRE_IPO_GLB_MISS_COUNTER   0x184310
#define APPE_REG_PRE_IPO_GLB_BYPASS_COUNTER 0x184314
#define APPE_REG_PRE_IPO_CNT_TBL(index)	    (0x176000 + (0x10 * (index)))
#define APPE_PRE_ACL_ACTION_WORDS	    16
#define APPE_PRE_ACL_TOTAL_ROWS		    512

typedef union
{
  u32 val[3];
  struct
  {
    u32 mac_addr_0 : 32;
    u32 mac_addr_1 : 16;
    u32 is_ip : 1;
    u32 is_ipv6 : 1;
    u32 is_ethernet : 1;
    u32 is_snap : 1;
    u32 fake_mac_header : 1;
    u32 range_en : 1;
    u32 inverse_en : 1;
    u32 rule_type : 5;
    u32 src_type : 3;
    u32 src_0 : 1;
    u32 src_1 : 7;
    u32 pri : 9;
    u32 res_chain : 1;
    u32 post_routing_en : 1;
    u32 reserved_82_95 : 14;
  } bf;
} ppe_reg_ipo_rule_reg_t;

typedef union
{
  u32 val[2];
  struct
  {
    u32 mac_addr_mask_0 : 32;
    u32 mac_addr_mask_1 : 16;
    u32 is_ip_mask : 1;
    u32 is_ipv6_mask : 1;
    u32 is_ethernet_mask : 1;
    u32 is_snap_mask : 1;
    u32 fake_mac_header_mask : 1;
    u32 reserved_21_31 : 11;
  } bf;
} ppe_reg_ipo_mask_reg_t;

typedef union
{
  u32 val[5];
  struct
  {
    u32 dest_info_change_en : 1;
    u32 fwd_cmd : 2;
    u32 dest_info : 14;
    u32 mirror_en : 1;
    u32 bypass_bitmap_0 : 14;
    u32 bypass_bitmap_1 : 18;
    u32 svid_change_en : 1;
    u32 stag_fmt : 1;
    u32 svid : 12;
    u32 cvid_change_en : 1;
    u32 ctag_fmt : 1;
    u32 cvid : 12;
    u32 dscp_tc_change_en : 1;
    u32 dscp_tc : 8;
    u32 stag_pcp_change_en : 1;
    u32 stag_pcp : 3;
    u32 stag_dei_change_en : 1;
    u32 stag_dei : 1;
    u32 ctag_pcp_change_en : 1;
    u32 ctag_pcp_0 : 2;
    u32 ctag_pcp_1 : 1;
    u32 ctag_dei_change_en : 1;
    u32 ctag_dei : 1;
    u32 enqueue_pri_change_en : 1;
    u32 enqueue_pri : 4;
    u32 int_dp_change_en : 1;
    u32 int_dp : 2;
    u32 policer_en : 1;
    u32 policer_index : 9;
    u32 qid_en : 1;
    u32 qid : 8;
    u32 service_code_en : 1;
    u32 service_code_0 : 1;
    u32 service_code_1 : 7;
    u32 syn_toggle : 1;
    u32 cpu_code_en : 1;
    u32 cpu_code : 8;
    u32 metadata_en : 1;
    u32 dscp_tc_mask : 8;
    u32 qos_res_prec : 3;
    u32 reserved_157_159 : 3;
  } bf;
} ppe_reg_ipo_action_t;

typedef union
{
  u32 val[3];
  struct
  {
    u32 rule_field_0 : 32;
    u32 rule_field_1 : 20;
    u32 fake_mac_header : 1;
    u32 range_en : 1;
    u32 inverse_en : 1;
    u32 rule_type : 5;
    u32 src_type : 3;
    u32 src_0 : 1;
    u32 src_1 : 7;
    u32 pri : 9;
    u32 res_chain : 1;
    u32 inner_outer_sel : 1;
    u32 reserved_82_95 : 14;
  } bf;
} ppe_reg_pre_ipo_rule_reg_t;

typedef union
{
  u32 val[2];
  struct
  {
    u32 maskfield_0 : 32;
    u32 maskfield_1 : 21;
    u32 reserved_53_63 : 11;
  } bf;
} ppe_reg_pre_ipo_mask_reg_t;

typedef union
{
  u32 val[7];
  struct
  {
    u32 dest_info_change_en : 1;
    u32 fwd_cmd : 2;
    u32 dest_info : 14;
    u32 mirror_en : 1;
    u32 svid_change_en : 1;
    u32 stag_fmt : 1;
    u32 svid : 12;
    u32 cvid_change_en : 1;
    u32 ctag_fmt : 1;
    u32 cvid : 12;
    u32 dscp_tc_change_en : 1;
    u32 dscp_tc : 8;
    u32 stag_pcp_change_en : 1;
    u32 stag_pcp : 3;
    u32 stag_dei_change_en : 1;
    u32 stag_dei : 1;
    u32 ctag_pcp_change_en : 1;
    u32 ctag_pcp_0 : 2;
    u32 ctag_pcp_1 : 1;
    u32 ctag_dei_change_en : 1;
    u32 ctag_dei : 1;
    u32 enqueue_pri_change_en : 1;
    u32 enqueue_pri : 4;
    u32 int_dp_change_en : 1;
    u32 int_dp : 2;
    u32 policer_en : 1;
    u32 policer_index : 9;
    u32 qid_en : 1;
    u32 qid : 8;
    u32 service_code_en : 1;
    u32 service_code_0 : 1;
    u32 service_code_1 : 7;
    u32 syn_toggle : 1;
    u32 cpu_code_en : 1;
    u32 cpu_code : 8;
    u32 dscp_tc_mask : 8;
    u32 qos_res_prec : 3;
    u32 cascade_en : 1;
    u32 cascade_data_0 : 3;
    u32 cascade_data_1 : 4;
    u32 metadata_en : 1;
    u32 reserved_132 : 1;
    u32 nat_action : 3;
    u32 l4_port : 16;
    u32 vpn_valid : 1;
    u32 vpn_type : 1;
    u32 vpn_id_0 : 5;
    u32 vpn_id_1 : 1;
    u32 learn_dis : 1;
    u32 reserved_162_193 : 32;
    u32 reserved_194_223 : 30;
  } bf;
} ppe_reg_pre_ipo_action_t;

#define APPE_ACL_PRI_PROMISC 2

#define APPE_PRE_ACL_SECONDARY_ROW(port_id, slot)                                                  \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + (slot))

#define APPE_PRE_ACL_PROMISC_ROW(port_id)                                                          \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + APPE_PRE_ACL_SECONDARY_MAX + 1)

/* FDB */

#define HPPE_REG_FDB_TBL_OP		      0x060008
#define HPPE_REG_FDB_TBL_OP_RSLT	      0x060020
#define HPPE_REG_FDB_TBL_OP_DATA0	      0x060230
#define HPPE_REG_FDB_TBL_OP_DATA1	      0x060234
#define HPPE_REG_FDB_TBL_OP_DATA2	      0x060238
#define HPPE_REG_AGE_TIMER		      0x060034
#define HPPE_REG_L2_GLOBAL_CONF		      0x060038
#define HPPE_REG_PORT_LRN_LIMIT_CTRL(port)    (0x060400 + 4 * (port))
#define HPPE_REG_PORT_LRN_LIMIT_COUNTER(port) (0x060500 + 4 * (port))
#define HPPE_REG_RFDB_TBL(index)	      (0x063000 + 8 * (index))
#define HPPE_REG_FDB_TBL(index)		      (0x070000 + 0x10 * (index))
#define HPPE_RFDB_TBL_ENTRIES		      32
#define HPPE_FDB_TBL_ENTRIES		      2048

typedef union
{
  u32 val[3];
  struct
  {
    u32 mac_addr_5 : 8;
    u32 mac_addr_4 : 8;
    u32 mac_addr_3 : 8;
    u32 mac_addr_2 : 8;
    u32 mac_addr_1 : 8;
    u32 mac_addr_0 : 8;
    u32 entry_valid : 1;
    u32 lookup_valid : 1;
    u32 vsi : 6;
    u32 dst_value_0 : 8;
    u32 dst_value_1 : 4;
    u32 dst_type : 2;
    u32 sa_cmd : 2;
    u32 da_cmd : 2;
    u32 hit_age : 2;
    u32 _reserved0 : 20;
  } bf;
} qppe_fdb_entry_t;

/* FDB_TBL_OP, per the vendor SSDK's struct fdb_tbl_op (hppe_fdb_reg.h). op_type
 * values are the adpt layer's OP_TYPE_* constants (adpt_hppe_fdb.c): only ADD
 * and DEL are used here; GET(2)/FLUSH(4)/AGE(5) are untouched by this driver. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 cmd_id : 4;
    u32 byp_rslt_en : 1;
    u32 op_type : 3;
    u32 hash_block_bitmap : 2;
    u32 op_mode : 1;
    u32 entry_index : 11;
    u32 reserved_22_31 : 10;
  };
} ppe_reg_fdb_tbl_op_t;

#define HPPE_FDB_OP_TYPE_ADD 0
#define HPPE_FDB_OP_TYPE_DEL 1

#define foreach_ppe_reg_age_timer_t_fields                                                         \
  _ (20, age_val)                                                                                  \
  _ (12, _reserved_20)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_age_timer_t_fields
#undef _
  };
} ppe_reg_age_timer_t;

#define foreach_ppe_reg_l2_global_conf_t_fields                                                    \
  _ (2, fdb_hash_mode_0)                                                                           \
  _ (2, fdb_hash_mode_1)                                                                           \
  _ (2, fdb_hash_full_fwd_cmd)                                                                     \
  _ (1, lrn_en)                                                                                    \
  _ (1, age_en)                                                                                    \
  _ (1, lrn_ctrl_mode)                                                                             \
  _ (1, age_ctrl_mode)                                                                             \
  _ (1, failover_en)                                                                               \
  _ (1, service_code_loop)                                                                         \
  _ (1, flow_cpy_escape)                                                                           \
  _ (19, _reserved_13)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_l2_global_conf_t_fields
#undef _
  };
} ppe_reg_l2_global_conf_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 lrn_lmt_cnt : 12;
    u32 lrn_lmt_en : 1;
    u32 lrn_lmt_exceed_fwd : 2;
    u32 _reserved_15 : 17;
  };
} ppe_reg_port_lrn_limit_ctrl_t;

/* VSI */

#define HPPE_REG_VSI_TBL_W0(vsi) (0x063800 + (0x10 * (vsi)))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 member_port_bitmap : 8;
    u32 uuc_bitmap : 8;
    u32 umc_bitmap : 8;
    u32 bc_bitmap : 8;
  };
} ppe_reg_vsi_tbl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 new_addr_lrn_en : 1;
    u32 new_addr_fwd_cmd : 2;
    u32 station_move_lrn_en : 1;
    u32 station_move_fwd_cmd : 2;
    u32 reserved_6_31 : 26;
  };
} ppe_reg_vsi_tbl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 valid : 1;
    u32 port_bitmap : 8;
    u32 skey_fmt : 3;
    u32 skey_vid_incl : 1;
    u32 skey_vid : 12;
    u32 skey_pcp_incl : 1;
    u32 skey_pcp : 3;
    u32 skey_dei_incl : 1;
    u32 skey_dei : 1;
    u32 ckey_fmt_0 : 1;
  };
} ppe_reg_xlt_rule_tbl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ckey_fmt_1 : 2;
    u32 ckey_vid_incl : 1;
    u32 ckey_vid : 12;
    u32 ckey_pcp_incl : 1;
    u32 ckey_pcp : 3;
    u32 ckey_dei_incl : 1;
    u32 ckey_dei : 1;
    u32 frm_type_incl : 1;
    u32 frm_type : 2;
    u32 prot_incl : 1;
    u32 prot_value_0 : 7;
  };
} ppe_reg_xlt_rule_tbl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 prot_value_1 : 9;
    u32 port_type : 2;
    u32 vni_resv_incl : 1;
    u32 vni_resv_type : 1;
    u32 vni_resv_0 : 19;
  };
} ppe_reg_xlt_rule_tbl_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 vni_resv_1 : 13;
    u32 reserved_13_31 : 19;
  };
} ppe_reg_xlt_rule_tbl_w3_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 vid_swap_cmd : 1;
    u32 xlt_svid_cmd : 2;
    u32 xlt_svid : 12;
    u32 xlt_cvid_cmd : 2;
    u32 xlt_cvid : 12;
    u32 pcp_swap_cmd : 1;
    u32 xlt_spcp_cmd : 1;
    u32 xlt_spcp_0 : 1;
  };
} ppe_reg_xlt_action_tbl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 xlt_spcp_1 : 2;
    u32 xlt_cpcp_cmd : 1;
    u32 xlt_cpcp : 3;
    u32 dei_swap_cmd : 1;
    u32 xlt_sdei_cmd : 1;
    u32 xlt_sdei : 1;
    u32 xlt_cdei_cmd : 1;
    u32 xlt_cdei : 1;
    u32 vsi_cmd : 1;
    u32 vsi : 6;
    u32 src_info_valid : 1;
    u32 src_info_type : 1;
    u32 src_info : 8;
    u32 counter_en : 1;
    u32 counter_id_0 : 3;
  };
} ppe_reg_xlt_action_tbl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 counter_id_1 : 4;
    u32 reserved_4_31 : 28;
  };
} ppe_reg_xlt_action_tbl_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enqueue_vp : 8;
    u32 enqueue_valid : 1;
    u32 reserved_9_31 : 23;
  };
} ppe_reg_port_vsi_enqueue_map_t;

/* full 4-word struct per the APPE vendor SSDK (appe_l2_vp_reg.h); note
 * new_addr_lrn_en/station_move_lrn_en here mirror the same fields found
 * in VSI_TBL - this driver's read-modify-write only ever touches
 * invalid_vsi_forwarding_en/dst_info, preserving whatever these read as
 * (hardware default, never explicitly set either way). */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 invalid_vsi_forwarding_en : 1;
    u32 promisc_en : 1;
    u32 dst_info : 8;
    u32 physical_port : 3;
    u32 new_addr_lrn_en : 1;
    u32 new_addr_fwd_cmd : 2;
    u32 station_move_lrn_en : 1;
    u32 station_move_fwd_cmd : 2;
    u32 lrn_lmt_cnt : 12;
    u32 lrn_lmt_en : 1;
  };
} ppe_reg_l2_vp_port_tbl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 lrn_lmt_exceed_fwd : 2;
    u32 eg_vlan_fltr_cmd : 1;
    u32 port_isolation_bitmap : 8;
    u32 isol_profile : 6;
    u32 isol_profile_en : 1;
    u32 policer_en : 1;
    u32 policer_index : 9;
    u32 vp_state_check_en : 1;
    u32 vp_type : 1;
    u32 vp_context_active : 1;
    u32 vp_eg_data_valid : 1;
  };
} ppe_reg_l2_vp_port_tbl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 physical_port_mtu_check_en : 1;
    u32 mtu_check_type : 1;
    u32 extra_header_len : 8;
    u32 eg_vlan_fmt_valid : 1;
    u32 eg_stag_fmt : 1;
    u32 eg_ctag_fmt : 1;
    u32 exception_fmt_ctrl : 1;
    u32 enq_service_code_en : 1;
    u32 enq_service_code : 8;
    u32 enq_phy_port : 3;
    u32 app_ctrl_profile_0 : 6;
  };
} ppe_reg_l2_vp_port_tbl_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 app_ctrl_profile_1 : 2;
    u32 reserved_2_31 : 30;
  };
} ppe_reg_l2_vp_port_tbl_w3_t;

/* APPE-specific extension, 9-word entry: word8 holds vsi_remap_en/br_vsi,
 * words 0-7 are plain 32-bit member_port_bitmap_N slices (bit N*32+k ==
 * membership for VP/port k of chunk N) - read as raw u32 rather than a
 * bitfield struct, since each is already a flat 32-bit bitmap. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 vsi_remap_en : 1;
    u32 br_vsi : 6;
    u32 reserved_7_31 : 25;
  };
} ppe_reg_vsi_remap_tbl_w8_t;

#define HPPE_REG_XLT_RULE_TBL(index)		   (0x011000 + (0x10 * (index)))
#define HPPE_REG_XLT_ACTION_TBL(index)		   (0x013000 + (0x10 * (index)))
#define HPPE_XLT_RULE_TBL_ENTRIES		   128
#define HPPE_VSI_TBL_ENTRIES			   64
#define APPE_REG_VSI_REMAP_TBL(vsi)		   (0x093000 + (0x40 * (vsi)))
#define APPE_VSI_REMAP_TBL_ENTRIES		   64
#define APPE_REG_PORT_VSI_ENQUEUE_MAP(port, vsi)   (0x09d000 + (0x4 * (((port) << 6) | (vsi))))
#define APPE_REG_L2_VP_PORT_TBL_W0(port)	   (0x098000 + (0x10 * (port)))
#define APPE_L2_VP_PORT_TBL_ENTRIES		   256
#define APPE_REG_VP_LRN_LIMIT_COUNTER(vp)	   (0x060b00 + 4 * (vp))
#define APPE_PORT_VSI_ENQUEUE_MAP_ENTRIES	   544
#define APPE_FLOW_ENQUEUE_MAP_BASE		   512
#define APPE_REG_PORT_VSI_ENQUEUE_MAP_INDEX(index) (0x09d000 + 4 * (index))
#define APPE_REG_VP_ISOL_TBL(profile)		   (0x09c000 + 0x10 * (profile))
#define HPPE_REG_L3_VP_PORT_TBL(vp)		   (0x204000 + 0x10 * (vp))
#define HPPE_REG_EG_VSI_TAG(vsi)		   (0x020800 + 0x10 * (vsi))
#define APPE_REG_EG_VSI_VP_TAG(index)		   (0x028000 + 0x10 * (index))
#define HPPE_REG_VLAN_CNT_TBL(index)		   (0x178000 + 0x10 * (index))

/* The SDK API uses all 64 VSIs; the register header's NUM=32 is stale. */
#define HPPE_VLAN_CNT_TBL_ENTRIES	 64
#define APPE_VP_ISOL_TBL_ENTRIES	 64
#define HPPE_L3_VP_PORT_TBL_ENTRIES	 256
#define HPPE_REG_EG_VSI_COUNTER_TBL(vsi) (0x041000 + 0x10 * (vsi))

typedef union
{
  u32 words[4];
  struct
  {
    u32 l3_if_valid : 1;
    u32 l3_if_index : 8;
    u32 ipv4_sg_en : 1;
    u32 ipv4_sg_vio_cmd : 2;
    u32 ipv4_sg_port_en : 1;
    u32 ipv4_sg_svlan_en : 1;
    u32 ipv4_sg_cvlan_en : 1;
    u32 ipv4_src_unk_cmd : 2;
    u32 ipv6_sg_en : 1;
    u32 ipv6_sg_vio_cmd : 2;
    u32 ipv6_sg_port_en : 1;
    u32 ipv6_sg_svlan_en : 1;
    u32 ipv6_sg_cvlan_en : 1;
    u32 ipv6_src_unk_cmd : 2;
    u32 ip_arp_sg_en : 1;
    u32 ip_arp_sg_vio_cmd : 2;
    u32 ip_arp_sg_port_en : 1;
    u32 ip_arp_sg_svlan_en : 1;
    u32 ip_arp_src_unk_cmd : 2;
    u32 ip_arp_sg_cvlan_en : 1;
    u32 ip_nd_sg_en : 1;
    u32 ip_nd_sg_vio_cmd : 2;
    u32 ip_nd_sg_port_en : 1;
    u32 ip_nd_sg_svlan_en : 1;
    u32 ip_nd_sg_cvlan_en : 1;
    u32 ip_nd_src_unk_cmd : 2;
    u32 vsi_valid : 1;
    u32 vsi : 6;
    u32 mac_valid : 1;
    u32 mac_da_0 : 15;
    u32 mac_da_1 : 32;
    u32 mac_da_2 : 1;
    u32 ipo_vp_profile : 8;
    u32 _reserved0 : 23;
  };
} ppe_reg_vsi_l3_vp_port_t;

/* QM */

#define HPPE_REG_UCAST_PRIORITY_MAP_TBL(profile, priority)                                         \
  (0x842000 + (0x10 * (((profile) << 4) + (priority))))

/* Unicast queues have separate probability and forced drop counters for
 * green, yellow, and red traffic, each stored in a three-word entry. */
#define HPPE_QM_UNICAST_DROP_TYPES 6

typedef union
{
  u32 as_u32;
  struct
  {
    u32 disable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_enq_deq_opr_t;

#define foreach_ppe_reg_eg_bridge_config_t_fields                                                  \
  _ (1, bridge_type)                                                                               \
  _ (1, pkt_l2_edit_en)                                                                            \
  _ (1, queue_cnt_en)                                                                              \
  _ (5, _reserved_3)                                                                               \
  _ (2, eip_reserved_w4_3130)                                                                      \
  _ (1, field_update_enable)                                                                       \
  _ (21, _reserved_11)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_eg_bridge_config_t_fields
#undef _
  };
} ppe_reg_eg_bridge_config_t;

#define foreach_ppe_reg_qm_flush_cfg_t_fields                                                      \
  _ (9, flush_qid)                                                                                 \
  _ (1, _reserved_9)                                                                               \
  _ (1, flush_status)                                                                              \
  _ (10, flush_wait_time)                                                                          \
  _ (3, flush_dst_port)                                                                            \
  _ (1, flush_all_queues)                                                                          \
  _ (6, _reserved_25)                                                                              \
  _ (1, flush_busy)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_qm_flush_cfg_t_fields
#undef _
  };
} ppe_reg_qm_flush_cfg_t;

#define foreach_ppe_reg_qm_mirror_priority_t_fields                                                \
  _ (4, priority)                                                                                  \
  _ (28, _reserved_4)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_qm_mirror_priority_t_fields
#undef _
  };
} ppe_reg_qm_mirror_priority_t;

#define foreach_ppe_reg_qm_default_hash_t_fields                                                   \
  _ (8, hash)                                                                                      \
  _ (24, _reserved_8)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_qm_default_hash_t_fields
#undef _
  };
} ppe_reg_qm_default_hash_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 empty : 1;
    u32 tail : 11;
    u32 head : 11;
    u32 _reserved_23 : 9;
  };
} ppe_reg_qm_oq_head_uni_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 normal_fwd : 1;
    u32 egress_mirror : 1;
    u32 ingress_mirror : 1;
    u32 empty : 1;
    u32 tail : 11;
    u32 head : 11;
    u32 _reserved_26 : 6;
  };
} ppe_reg_qm_oq_head_mul_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 aggregation_id : 3;
    u32 enable : 1;
    u32 _reserved_4 : 28;
  };
} ppe_reg_qm_aggregation_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 normal_fwd : 1;
    u32 egress_mirror : 1;
    u32 ingress_mirror : 1;
    u32 next_pointer : 11;
    u32 _reserved_14 : 18;
  };
} ppe_reg_qm_oq_ll_mul_t;

#define HPPE_REG_MCAST_PRIORITY_MAP_TBL(port, priority)                                            \
  (0x800100 + (0x40 * (port)) + (0x4 * (priority)))

#define HPPE_REG_MCAST_QUEUE_MAP_TBL(cpu_code) (0x844000 + (0x10 * (cpu_code)))
#define HPPE_REG_ENQ_OPR(queue)		       (0x85c000 + 0x10 * (queue))
#define HPPE_REG_EG_BRIDGE_CONFIG	       0x20044
#define HPPE_QM_GROUP0_BUF_LIMIT	       2000
#define HPPE_QM_UCAST_CEIL		       1200
#define HPPE_QM_UCAST_WEIGHT		       7
#define HPPE_QM_UCAST_RESUME_OFFSET	       36
#define HPPE_QM_MCAST_CEIL		       250
#define HPPE_QM_MCAST_RESUME_OFFSET	       36

#define HPPE_REG_UCAST_QUEUE_MAP_TBL(profile, port)                                                \
  (0x810000 + (0x10 * (((profile) << 8) + (port))))

#define HPPE_REG_QM_FLUSH_CFG		    0x800000
#define HPPE_REG_QM_IN_MIRROR_PRIORITY_CTRL 0x800004
#define HPPE_REG_QM_EG_MIRROR_PRIORITY_CTRL 0x800008
#define HPPE_REG_QM_UCAST_DEFAULT_HASH	    0x800060
#define HPPE_REG_UCAST_HASH_MAP_TBL(index)  (0x830000 + 0x10 * (index))
#define HPPE_REG_OQ_DEQ_OPR(queue)	    (0x864000 + 0x10 * (queue))
#define HPPE_REG_OQ_HEAD_UNI_TBL(queue)	    (0x86c000 + 0x10 * (queue))
#define HPPE_REG_OQ_HEAD_MUL_TBL(queue)	    (0x874000 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))
#define HPPE_REG_UQ_AGG_PROFILE_MAP(queue)  (0x9f8000 + 0x10 * (queue))
#define HPPE_QM_SOURCE_PROFILES		    4
#define HPPE_QM_MAP_KEYS		    256
#define HPPE_QM_QUEUE_MAP_DOMAINS	    3
#define HPPE_QM_PRIORITY_PROFILES	    16
#define HPPE_QM_PRIORITIES		    16
#define HPPE_QM_QUEUE_COUNT		    (HPPE_AC_UNICAST_QUEUE_COUNT + HPPE_AC_MULTICAST_QUEUE_COUNT)
#define HPPE_QM_OQ_LL_ENTRIES		    2048
#define HPPE_QM_PKT_DESP_ENTRIES	    2048
#define HPPE_REG_OQ_LL_UNI_TBL(index)	    (0x890000 + 0x10 * (index))
#define HPPE_REG_PKT_DESP_TBL(index)	    (0x9c0000 + 0x40 * (index))
#define HPPE_QM_PKT_DESP_WORDS		    13
#define HPPE_REG_OQ_LL_MUL_P0_TBL(index)    (0x8b0000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P1_TBL(index)    (0x8d0000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P2_TBL(index)    (0x910000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P3_TBL(index)    (0x930000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P4_TBL(index)    (0x950000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P5_TBL(index)    (0x970000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P6_TBL(index)    (0x990000 + 0x10 * (index))
#define HPPE_REG_OQ_LL_MUL_P7_TBL(index)    (0x9b0000 + 0x10 * (index))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 profile_id : 4;
    u32 queue_id : 8;
    u32 reserved_12_31 : 20;
  };
} ppe_reg_ucast_queue_map_t;

#define HPPE_REG_QM_QUEUE_TX_CNT(queue) (0x04a000 + 0x10 * (queue))

#define HPPE_REG_QM_UNICAST_DROP_CNT(queue, type)                                                  \
  (0x009e0000 + 0x10 * ((queue) * HPPE_QM_UNICAST_DROP_TYPES + (type)))

#define foreach_qppe_qm_descriptor_field                                                           \
  _ (org_src_port_vp, 0, 12, 0)                                                                    \
  _ (src_port_vp, 12, 12, 0)                                                                       \
  _ (packet_length, 24, 14, 0)                                                                     \
  _ (ts_dir, 38, 1, 0)                                                                             \
  _ (tx_ts_en, 39, 1, 1)                                                                           \
  _ (rx_ts_valid, 39, 1, 2)                                                                        \
  _ (rx_ts, 40, 40, 2)                                                                             \
  _ (tx_os_correction_en, 40, 1, 1)                                                                \
  _ (tx_ptp_tag, 41, 10, 1)                                                                        \
  _ (int_pri, 80, 4, 0)                                                                            \
  _ (int_dp, 84, 2, 0)                                                                             \
  _ (cpu_code, 86, 8, 0)                                                                           \
  _ (service_code, 94, 8, 0)                                                                       \
  _ (dst_l3_if, 102, 8, 0)                                                                         \
  _ (mac_da, 110, 48, 0)                                                                           \
  _ (route_flag, 158, 1, 0)                                                                        \
  _ (pppoe_strip_flag, 159, 1, 0)                                                                  \
  _ (nat_action, 160, 3, 0)                                                                        \
  _ (napt_port, 163, 16, 0)                                                                        \
  _ (napt_addr, 179, 32, 0)                                                                        \
  _ (dscp_update, 211, 1, 0)                                                                       \
  _ (dscp, 212, 8, 0)                                                                              \
  _ (ttl_update, 220, 1, 0)                                                                        \
  _ (ttl, 221, 8, 0)                                                                               \
  _ (stag_flag, 229, 1, 0)                                                                         \
  _ (ctag_flag, 230, 1, 0)                                                                         \
  _ (snap_flag, 231, 1, 0)                                                                         \
  _ (pppoe_flag, 232, 1, 0)                                                                        \
  _ (int_stag_fmt, 233, 1, 0)                                                                      \
  _ (int_ctag_fmt, 234, 1, 0)                                                                      \
  _ (int_svid, 235, 12, 0)                                                                         \
  _ (int_cvid, 247, 12, 0)                                                                         \
  _ (int_spcp, 259, 3, 0)                                                                          \
  _ (int_cpcp, 262, 3, 0)                                                                          \
  _ (int_sdei, 265, 1, 0)                                                                          \
  _ (int_cdei, 266, 1, 0)                                                                          \
  _ (vsi, 267, 5, 0)                                                                               \
  _ (l3_offset, 272, 8, 0)                                                                         \
  _ (l3_type, 280, 2, 0)                                                                           \
  _ (l4_offset, 282, 8, 0)                                                                         \
  _ (l4_type, 290, 3, 0)                                                                           \
  _ (next_header, 293, 8, 0)                                                                       \
  _ (eg_vlan_tag_fmt_bypass_en, 301, 1, 0)                                                         \
  _ (eg_vlan_xlt_bypass_en, 302, 1, 0)                                                             \
  _ (pkt_l2_edit_bypass, 303, 1, 0)                                                                \
  _ (pkt_l3_edit_bypass, 304, 1, 0)                                                                \
  _ (acl_index_toggle, 305, 1, 0)                                                                  \
  _ (acl_index_valid, 306, 1, 0)                                                                   \
  _ (acl_index, 307, 9, 0)                                                                         \
  _ (ip_addr_index_type, 316, 1, 0)                                                                \
  _ (ip_addr_index_toggle, 317, 1, 0)                                                              \
  _ (ip_addr_index_valid, 318, 1, 0)                                                               \
  _ (ip_addr_index, 319, 13, 0)                                                                    \
  _ (chg_port_vp, 332, 12, 0)                                                                      \
  _ (hash_flag, 344, 3, 0)                                                                         \
  _ (hash_value, 347, 21, 0)                                                                       \
  _ (copy_cpu_flag, 368, 1, 0)                                                                     \
  _ (src_pn, 369, 4, 0)                                                                            \
  _ (rx_ptp_type, 373, 4, 0)                                                                       \
  _ (fake_l2_prot, 377, 1, 0)                                                                      \
  _ (fake_mac_header, 378, 1, 0)                                                                   \
  _ (vsi_valid, 379, 1, 0)                                                                         \
  _ (vp_tx_cnt_en, 380, 1, 0)                                                                      \
  _ (ac_group_bitmap, 388, 4, 0)                                                                   \
  _ (one_enq_flag, 392, 1, 0)                                                                      \
  _ (edma_vp, 393, 3, 0)                                                                           \
  _ (fc_grp_id, 396, 3, 0)                                                                         \
  _ (fc_en, 399, 1, 0)

/* SCHED */

#define HPPE_REG_RING_Q_MAP_TBL(ring) (0x42a000 + (0x40 * (ring)))
#define HPPE_SCHED_QUEUE_COUNT	      300
#define HPPE_REG_SCHED_DEQ_DIS_TBL    0x430000

#define foreach_ppe_reg_sched_tdm_depth_cfg_t_fields                                               \
  _ (8, tdm_depth)                                                                                 \
  _ (24, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_tdm_depth_cfg_t_fields
#undef _
  };
} ppe_reg_sched_tdm_depth_cfg_t;

#define HPPE_REG_SCHED_TDM_DEPTH_CFG 0x400000

#define foreach_ppe_reg_sched_shp_slot_cfg_l0_t_fields                                             \
  _ (12, l0_shp_slot_time)                                                                         \
  _ (20, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_shp_slot_cfg_l0_t_fields
#undef _
  };
} ppe_reg_sched_shp_slot_cfg_l0_t;

#define HPPE_REG_SCHED_SHP_SLOT_CFG_L0 0x400010

#define foreach_ppe_reg_sched_shp_slot_cfg_l1_t_fields                                             \
  _ (12, l1_shp_slot_time)                                                                         \
  _ (20, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_shp_slot_cfg_l1_t_fields
#undef _
  };
} ppe_reg_sched_shp_slot_cfg_l1_t;

#define HPPE_REG_SCHED_SHP_SLOT_CFG_L1 0x400014

#define foreach_ppe_reg_sched_shp_slot_cfg_port_t_fields                                           \
  _ (12, port_shp_slot_time)                                                                       \
  _ (20, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_shp_slot_cfg_port_t_fields
#undef _
  };
} ppe_reg_sched_shp_slot_cfg_port_t;

#define HPPE_REG_SCHED_SHP_SLOT_CFG_PORT 0x400018

#define foreach_ppe_reg_sched_ipg_pre_len_cfg_t_fields                                             \
  _ (5, ipg_pre_len)                                                                               \
  _ (27, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_ipg_pre_len_cfg_t_fields
#undef _
  };
} ppe_reg_sched_ipg_pre_len_cfg_t;

#define HPPE_REG_SCHED_IPG_PRE_LEN_CFG 0x400008

#define foreach_ppe_reg_sched_min_max_mode_cfg_t_fields                                            \
  _ (1, min_max_mode)                                                                              \
  _ (31, _reserved0)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_min_max_mode_cfg_t_fields
#undef _
  };
} ppe_reg_sched_min_max_mode_cfg_t;

#define APPE_REG_SCHED_MIN_MAX_MODE_CFG 0x400004

#define foreach_ppe_reg_sched_shp_cfg_l0_t_fields                                                  \
  _ (9, l0_shp_ll_tail)                                                                            \
  _ (7, _reserved0)                                                                                \
  _ (9, l0_shp_ll_head)                                                                            \
  _ (7, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_shp_cfg_l0_t_fields
#undef _
  };
} ppe_reg_sched_shp_cfg_l0_t;

#define APPE_REG_SCHED_SHP_CFG_L0 0x400030

#define foreach_ppe_reg_sched_shp_cfg_l1_t_fields                                                  \
  _ (6, l1_shp_ll_tail)                                                                            \
  _ (10, _reserved0)                                                                               \
  _ (6, l1_shp_ll_head)                                                                            \
  _ (10, _reserved1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_sched_shp_cfg_l1_t_fields
#undef _
  };
} ppe_reg_sched_shp_cfg_l1_t;

#define APPE_REG_SCHED_SHP_CFG_L1	       0x400034
#define HPPE_REG_SCHED_L0_FLOW_MAP_TBL	       0x402000
#define HPPE_REG_SCHED_L0_C_SP_CFG_TBL	       0x404000
#define HPPE_REG_SCHED_L0_E_SP_CFG_TBL	       0x406000
#define HPPE_REG_SCHED_L0_FLOW_PORT_MAP_TBL    0x408000
#define HPPE_REG_SCHED_L0_C_DRR_HEAD_TBL       0x40a000
#define HPPE_REG_SCHED_L0_E_DRR_HEAD_TBL       0x40c000
#define HPPE_REG_SCHED_L0_DRR_CREDIT_TBL       0x40e000
#define HPPE_REG_SCHED_L0_C_DRR_LL_TBL	       0x410000
#define HPPE_REG_SCHED_L0_C_DRR_REVERSE_LL_TBL 0x412000
#define HPPE_REG_SCHED_L0_E_DRR_LL_TBL	       0x414000
#define HPPE_REG_SCHED_L0_E_DRR_REVERSE_LL_TBL 0x416000
#define HPPE_REG_SCHED_L0_SP_ENTRY_TBL	       0x418000
#define HPPE_REG_SCHED_L0_ENS_Q_LL_TBL	       0x41e000
#define HPPE_REG_SCHED_L0_ENS_Q_HEAD_TBL       0x420000
#define HPPE_REG_SCHED_L0_ENS_Q_ENTRY_TBL      0x422000
#define HPPE_REG_SCHED_L0_FLOW_STATUS_TBL      0x424000
#define HPPE_REG_SCHED_RFC_BLOCK_TBL	       0x42c000
#define HPPE_REG_SCHED_RFC_STATUS_TBL	       0x42e000
#define HPPE_REG_SCHED_L1_FLOW_MAP_TBL	       0x440000
#define HPPE_REG_SCHED_L1_C_SP_CFG_TBL	       0x442000
#define HPPE_REG_SCHED_L1_E_SP_CFG_TBL	       0x444000
#define HPPE_REG_SCHED_L1_FLOW_PORT_MAP_TBL    0x446000
#define HPPE_REG_SCHED_L1_C_DRR_HEAD_TBL       0x448000
#define HPPE_REG_SCHED_L1_E_DRR_HEAD_TBL       0x44a000
#define HPPE_REG_SCHED_L1_DRR_CREDIT_TBL       0x44c000
#define HPPE_REG_SCHED_L1_C_DRR_LL_TBL	       0x44e000
#define HPPE_REG_SCHED_L1_C_DRR_REVERSE_LL_TBL 0x450000
#define HPPE_REG_SCHED_L1_E_DRR_LL_TBL	       0x452000
#define HPPE_REG_SCHED_L1_E_DRR_REVERSE_LL_TBL 0x454000
#define HPPE_REG_SCHED_L1_A_FLOW_ENTRY_TBL     0x456000
#define HPPE_REG_SCHED_L1_B_FLOW_ENTRY_TBL     0x458000
#define HPPE_REG_SCHED_L1_SP_ENTRY_TBL	       0x45a000
#define HPPE_REG_SCHED_L1_ENS_Q_LL_TBL	       0x460000
#define HPPE_REG_SCHED_L1_ENS_Q_HEAD_TBL       0x462000
#define HPPE_REG_SCHED_L1_ENS_Q_ENTRY_TBL      0x464000
#define HPPE_REG_SCHED_L1_FLOW_STATUS_TBL      0x466000
#define HPPE_REG_SCHED_PSCH_TDM_CFG_TBL	       0x47a000
#define HPPE_REG_SCHED_L0_SHP_CREDIT_TBL       0x41a000
#define HPPE_REG_SCHED_L0_SHP_CFG_TBL	       0x41c000
#define HPPE_REG_SCHED_L0_COMP_TBL	       0x426000
#define HPPE_REG_SCHED_L0_COMP_CFG_TBL	       0x428000
#define HPPE_REG_SCHED_L1_SHP_CREDIT_TBL       0x45c000
#define HPPE_REG_SCHED_L1_SHP_CFG_TBL	       0x45e000
#define HPPE_REG_SCHED_L1_COMP_TBL	       0x468000
#define HPPE_REG_SCHED_L1_COMP_CFG_TBL	       0x46a000
#define HPPE_REG_SCHED_PSCH_SHP_SIGN_TBL       0x470000
#define HPPE_REG_SCHED_PSCH_SHP_CREDIT_TBL     0x472000
#define HPPE_REG_SCHED_PSCH_SHP_CFG_TBL	       0x474000
#define HPPE_REG_SCHED_PSCH_COMP_TBL	       0x476000
#define HPPE_REG_SCHED_PSCH_COMP_CFG_TBL       0x478000
#define APPE_REG_SCHED_QOS_MAPPING_TBL	       0x080000

#define foreach_qppe_sched_l0_flow_map_tbl_fields                                                  \
  _ ("sp_id", "", 0, 6, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("c_pri", "", 6, 3, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("e_pri", "", 9, 3, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("c_drr", "weight", 12, 10, QPPE_SCHED_FIELD_NUMBER)                                           \
  _ ("e_drr", "weight", 22, 10, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_c_sp_cfg_tbl_fields                                                  \
  _ ("drr_id", "", 0, 8, QPPE_SCHED_FIELD_NUMBER)                                                  \
  _ ("credit", "unit", 8, 1, QPPE_SCHED_FIELD_METER_UNIT)

#define foreach_qppe_sched_l0_flow_port_map_tbl_fields                                             \
  _ ("port_num", "", 0, 4, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_c_drr_head_tbl_fields                                                \
  _ ("backup", "tail", 0, 9, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "head", 9, 9, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "vld", 18, 1, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "max_n", 19, 5, QPPE_SCHED_FIELD_NUMBER)                                            \
  _ ("active", "tail", 24, 9, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("active", "head", 33, 9, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("active", "vld", 42, 1, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("active", "max_n", 43, 5, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_drr_credit_tbl_fields                                                \
  _ ("c_drr_credit", "", 0, 24, QPPE_SCHED_FIELD_NUMBER)                                           \
  _ ("c_drr_credit_neg", "", 24, 1, QPPE_SCHED_FIELD_NUMBER)                                       \
  _ ("e_drr_credit", "", 25, 24, QPPE_SCHED_FIELD_NUMBER)                                          \
  _ ("e_drr_credit_neg", "", 49, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_c_drr_ll_tbl_fields _ ("next_ptr", "", 0, 9, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_c_drr_reverse_ll_tbl_fields                                          \
  _ ("pre_ptr", "", 0, 9, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_sp_entry_tbl_fields                                                  \
  _ ("entry_path_id", "packed", 0, 144, QPPE_SCHED_FIELD_NUMBER)                                   \
  _ ("valid", "entries", 144, 16, QPPE_SCHED_FIELD_BITMAP)

#define foreach_qppe_sched_l0_ens_q_head_tbl_fields                                                \
  _ ("tail", "", 0, 9, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("head", "", 9, 9, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("vld", "", 18, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_ens_q_entry_tbl_fields                                               \
  _ ("entry_ens_type", "", 0, 2, QPPE_SCHED_FIELD_NUMBER)                                          \
  _ ("entry_ens_vld", "", 2, 1, QPPE_SCHED_FIELD_NUMBER)                                           \
  _ ("entry_ens_in_q", "", 3, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_flow_status_tbl_fields                                               \
  _ ("en_level", "", 0, 1, QPPE_SCHED_FIELD_NUMBER)                                                \
  _ ("en_cdrr", "", 1, 1, QPPE_SCHED_FIELD_NUMBER)                                                 \
  _ ("en_edrr", "", 2, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_rfc_block_tbl_fields	 _ ("rfc_block", "", 0, 1, QPPE_SCHED_FIELD_NUMBER)
#define foreach_qppe_sched_rfc_status_tbl_fields _ ("rfc_status", "", 0, 1, QPPE_SCHED_FIELD_NUMBER)
#define foreach_qppe_sched_deq_dis_tbl_fields	 _ ("deq_dis", "", 0, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_flow_map_tbl_fields                                                  \
  _ ("sp_id", "", 0, 4, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("c_pri", "", 4, 3, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("e_pri", "", 7, 3, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("c_drr", "weight", 10, 10, QPPE_SCHED_FIELD_NUMBER)                                           \
  _ ("e_drr", "weight", 20, 10, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_c_sp_cfg_tbl_fields                                                  \
  _ ("drr_id", "", 0, 6, QPPE_SCHED_FIELD_NUMBER)                                                  \
  _ ("credit", "unit", 6, 1, QPPE_SCHED_FIELD_METER_UNIT)

#define foreach_qppe_sched_l1_c_drr_head_tbl_fields                                                \
  _ ("backup", "tail", 0, 6, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "head", 6, 6, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "vld", 12, 1, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("backup", "max_n", 13, 5, QPPE_SCHED_FIELD_NUMBER)                                            \
  _ ("active", "tail", 18, 6, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("active", "head", 24, 6, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("active", "vld", 30, 1, QPPE_SCHED_FIELD_NUMBER)                                              \
  _ ("active", "max_n", 31, 5, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_c_drr_ll_tbl_fields _ ("next_ptr", "", 0, 6, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_c_drr_reverse_ll_tbl_fields                                          \
  _ ("pre_ptr", "", 0, 6, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_a_flow_entry_tbl_fields                                              \
  _ ("entry_path_id", "packed", 0, 10, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_sp_entry_tbl_fields                                                  \
  _ ("entry_path_id", "packed", 0, 256, QPPE_SCHED_FIELD_NUMBER)                                   \
  _ ("valid", "entries", 256, 16, QPPE_SCHED_FIELD_BITMAP)

#define foreach_qppe_sched_l1_ens_q_head_tbl_fields                                                \
  _ ("tail", "", 0, 6, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("head", "", 6, 6, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("vld", "", 12, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_tdm_cfg_tbl_fields                                                 \
  _ ("des_port", "", 0, 4, QPPE_SCHED_FIELD_NUMBER)                                                \
  _ ("ens_port", "", 4, 4, QPPE_SCHED_FIELD_NUMBER)                                                \
  _ ("enqueue_ports", "", 8, 8, QPPE_SCHED_FIELD_BITMAP)

#define foreach_qppe_sched_l0_shp_credit_tbl_fields                                                \
  _ ("c_shaper_credit", "", 0, 30, QPPE_SCHED_FIELD_NUMBER)                                        \
  _ ("c_shaper_credit_neg", "", 30, 1, QPPE_SCHED_FIELD_NUMBER)                                    \
  _ ("e_shaper_credit", "", 31, 30, QPPE_SCHED_FIELD_NUMBER)                                       \
  _ ("e_shaper_credit_neg", "", 61, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l0_shp_cfg_tbl_fields                                                   \
  _ ("cir", "", 0, 18, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("cbs", "", 18, 14, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("eir", "", 32, 18, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("ebs", "", 50, 14, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("token_unit", "", 64, 3, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("meter_unit", "", 67, 1, QPPE_SCHED_FIELD_METER_UNIT)                                         \
  _ ("c_shaper", "en", 68, 1, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("e_shaper", "en", 69, 1, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("cf", "", 70, 1, QPPE_SCHED_FIELD_NUMBER)                                                     \
  _ ("grp_cf", "", 71, 1, QPPE_SCHED_FIELD_NUMBER)                                                 \
  _ ("grp_end", "", 72, 1, QPPE_SCHED_FIELD_NUMBER)                                                \
  _ ("refresh", "next_ptr", 73, 9, QPPE_SCHED_FIELD_NUMBER)                                        \
  _ ("cir_max", "", 82, 18, QPPE_SCHED_FIELD_NUMBER)                                               \
  _ ("eir_max", "", 100, 18, QPPE_SCHED_FIELD_NUMBER)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 byte_count : 18;
    u32 byte_negative : 1;
    u32 packet_count : 4;
    u32 _reserved_23 : 9;
  };
} ppe_reg_sched_compensation_t;

#define foreach_qppe_sched_l0_comp_tbl_fields                                                      \
  _ ("c_shaper", "bytes/neg/packets", 0, 23, QPPE_SCHED_FIELD_COMPENSATION)                        \
  _ ("c_drr", "bytes/neg/packets", 23, 23, QPPE_SCHED_FIELD_COMPENSATION)                          \
  _ ("e_shaper", "bytes/neg/packets", 46, 23, QPPE_SCHED_FIELD_COMPENSATION)                       \
  _ ("e_drr", "bytes/neg/packets", 69, 23, QPPE_SCHED_FIELD_COMPENSATION)

#define foreach_qppe_sched_l0_comp_cfg_tbl_fields                                                  \
  _ ("shaper_meter", "len", 0, 2, QPPE_SCHED_FIELD_NUMBER)                                         \
  _ ("drr_meter", "len", 2, 2, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_l1_shp_cfg_tbl_fields                                                   \
  _ ("cir", "", 0, 18, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("cbs", "", 18, 14, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("eir", "", 32, 18, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("ebs", "", 50, 14, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("token_unit", "", 64, 3, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("meter_unit", "", 67, 1, QPPE_SCHED_FIELD_METER_UNIT)                                         \
  _ ("c_shaper", "en", 68, 1, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("e_shaper", "en", 69, 1, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("cf", "", 70, 1, QPPE_SCHED_FIELD_NUMBER)                                                     \
  _ ("grp_cf", "", 71, 1, QPPE_SCHED_FIELD_NUMBER)                                                 \
  _ ("grp_end", "", 72, 1, QPPE_SCHED_FIELD_NUMBER)                                                \
  _ ("refresh", "next_ptr", 73, 6, QPPE_SCHED_FIELD_NUMBER)                                        \
  _ ("cir_max", "", 79, 18, QPPE_SCHED_FIELD_NUMBER)                                               \
  _ ("eir_max", "", 97, 18, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_shp_sign_tbl_fields                                                \
  _ ("shaper_credit_neg", "", 0, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_shp_credit_tbl_fields                                              \
  _ ("shaper_credit", "", 0, 30, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_shp_cfg_tbl_fields                                                 \
  _ ("cir", "", 0, 18, QPPE_SCHED_FIELD_NUMBER)                                                    \
  _ ("cbs", "", 18, 14, QPPE_SCHED_FIELD_NUMBER)                                                   \
  _ ("token_unit", "", 32, 3, QPPE_SCHED_FIELD_NUMBER)                                             \
  _ ("meter_unit", "", 35, 1, QPPE_SCHED_FIELD_METER_UNIT)                                         \
  _ ("shaper", "en", 36, 1, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_comp_tbl_fields                                                    \
  _ ("shaper_compensate_byte_cnt", "", 0, 18, QPPE_SCHED_FIELD_NUMBER)                             \
  _ ("shaper_compensate_byte_neg", "", 18, 1, QPPE_SCHED_FIELD_NUMBER)                             \
  _ ("shaper_compensate_pkt_cnt", "", 19, 4, QPPE_SCHED_FIELD_NUMBER)

#define foreach_qppe_sched_psch_comp_cfg_tbl_fields                                                \
  _ ("shaper_meter", "len", 0, 2, QPPE_SCHED_FIELD_NUMBER)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 value : 8;
    u32 mask : 8;
    u32 enable : 1;
    u32 _reserved_17 : 15;
  };
} ppe_reg_sched_qos_dscp_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 value : 31;
  };
} ppe_reg_sched_enabled_value_t;

#define foreach_qppe_sched_qos_mapping_tbl_fields                                                  \
  _ ("int DSCP/TC", "value/mask/en", 0, 17, QPPE_SCHED_FIELD_QOS_DSCP)                             \
  _ ("int PCP", "value/en", 17, 4, QPPE_SCHED_FIELD_ENABLED_VALUE)                                 \
  _ ("int DEI", "value/en", 21, 2, QPPE_SCHED_FIELD_ENABLED_VALUE)                                 \
  _ ("int priority", "value/en", 23, 5, QPPE_SCHED_FIELD_ENABLED_VALUE)                            \
  _ ("int drop prec", "value/en", 28, 3, QPPE_SCHED_FIELD_ENABLED_VALUE)                           \
  _ ("QoS result", "precedence", 31, 3, QPPE_SCHED_FIELD_NUMBER)

#define HPPE_SCHED_L0_FLOW_MAP_TBL_COUNT	    300
#define HPPE_SCHED_L0_FLOW_MAP_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_FLOW_MAP_TBL_WORDS	    1
#define HPPE_SCHED_L0_C_SP_CFG_TBL_COUNT	    512
#define HPPE_SCHED_L0_C_SP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_C_SP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L0_E_SP_CFG_TBL_COUNT	    512
#define HPPE_SCHED_L0_E_SP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_E_SP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_COUNT	    300
#define HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_WORDS	    1
#define HPPE_SCHED_L0_FLOW_STATUS_TBL_COUNT	    300
#define HPPE_SCHED_L0_FLOW_STATUS_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_FLOW_STATUS_TBL_WORDS	    1
#define HPPE_SCHED_RFC_BLOCK_TBL_COUNT		    300
#define HPPE_SCHED_RFC_BLOCK_TBL_STRIDE		    0x10
#define HPPE_SCHED_RFC_BLOCK_TBL_WORDS		    1
#define HPPE_SCHED_RFC_STATUS_TBL_COUNT		    300
#define HPPE_SCHED_RFC_STATUS_TBL_STRIDE	    0x10
#define HPPE_SCHED_RFC_STATUS_TBL_WORDS		    1
#define HPPE_SCHED_DEQ_DIS_TBL_COUNT		    300
#define HPPE_SCHED_DEQ_DIS_TBL_STRIDE		    0x10
#define HPPE_SCHED_DEQ_DIS_TBL_WORDS		    1
#define HPPE_SCHED_L1_FLOW_MAP_TBL_COUNT	    64
#define HPPE_SCHED_L1_FLOW_MAP_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_FLOW_MAP_TBL_WORDS	    1
#define HPPE_SCHED_L1_C_SP_CFG_TBL_COUNT	    64
#define HPPE_SCHED_L1_C_SP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_C_SP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L1_E_SP_CFG_TBL_COUNT	    64
#define HPPE_SCHED_L1_E_SP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_E_SP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_COUNT	    64
#define HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_WORDS	    1
#define HPPE_SCHED_L1_FLOW_STATUS_TBL_COUNT	    64
#define HPPE_SCHED_L1_FLOW_STATUS_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_FLOW_STATUS_TBL_WORDS	    1
#define HPPE_SCHED_PSCH_TDM_CFG_TBL_COUNT	    128
#define HPPE_SCHED_PSCH_TDM_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_PSCH_TDM_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L0_SHP_CFG_TBL_COUNT		    300
#define HPPE_SCHED_L0_SHP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_SHP_CFG_TBL_WORDS		    4
#define HPPE_SCHED_L0_COMP_CFG_TBL_COUNT	    300
#define HPPE_SCHED_L0_COMP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_COMP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_L1_SHP_CFG_TBL_COUNT		    64
#define HPPE_SCHED_L1_SHP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_SHP_CFG_TBL_WORDS		    4
#define HPPE_SCHED_L1_COMP_CFG_TBL_COUNT	    64
#define HPPE_SCHED_L1_COMP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_COMP_CFG_TBL_WORDS	    1
#define HPPE_SCHED_PSCH_SHP_CFG_TBL_COUNT	    8
#define HPPE_SCHED_PSCH_SHP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_PSCH_SHP_CFG_TBL_WORDS	    2
#define HPPE_SCHED_PSCH_COMP_CFG_TBL_COUNT	    8
#define HPPE_SCHED_PSCH_COMP_CFG_TBL_STRIDE	    0x10
#define HPPE_SCHED_PSCH_COMP_CFG_TBL_WORDS	    1
#define APPE_REG_SCHED_QOS_MAPPING_TBL_FLOW	    (APPE_REG_SCHED_QOS_MAPPING_TBL + 0 * 0x10)
#define APPE_SCHED_QOS_MAPPING_TBL_FLOW_COUNT	    4096
#define APPE_SCHED_QOS_MAPPING_TBL_FLOW_STRIDE	    0x10
#define APPE_SCHED_QOS_MAPPING_TBL_FLOW_WORDS	    2
#define APPE_REG_SCHED_QOS_MAPPING_TBL_DSCP_TC	    (APPE_REG_SCHED_QOS_MAPPING_TBL + 4096 * 0x10)
#define APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_COUNT    512
#define APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_STRIDE   0x10
#define APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_WORDS    2
#define APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_MAP_SIZE 256
#define APPE_REG_SCHED_QOS_MAPPING_TBL_PCP_DEI	    (APPE_REG_SCHED_QOS_MAPPING_TBL + 4608 * 0x10)
#define APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_COUNT    32
#define APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_STRIDE   0x10
#define APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_WORDS    2
#define APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_MAP_SIZE 16
#define HPPE_SCHED_L0_C_DRR_HEAD_TBL_COUNT	    160
#define HPPE_SCHED_L0_C_DRR_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_C_DRR_HEAD_TBL_WORDS	    2
#define HPPE_SCHED_L0_E_DRR_HEAD_TBL_COUNT	    160
#define HPPE_SCHED_L0_E_DRR_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_E_DRR_HEAD_TBL_WORDS	    2
#define HPPE_SCHED_L0_DRR_CREDIT_TBL_COUNT	    300
#define HPPE_SCHED_L0_DRR_CREDIT_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_DRR_CREDIT_TBL_WORDS	    2
#define HPPE_SCHED_L0_C_DRR_LL_TBL_COUNT	    300
#define HPPE_SCHED_L0_C_DRR_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_C_DRR_LL_TBL_WORDS	    1
#define HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_COUNT    300
#define HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_STRIDE   0x10
#define HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_WORDS    1
#define HPPE_SCHED_L0_E_DRR_LL_TBL_COUNT	    300
#define HPPE_SCHED_L0_E_DRR_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_E_DRR_LL_TBL_WORDS	    1
#define HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_COUNT    300
#define HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_STRIDE   0x10
#define HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_WORDS    1
#define HPPE_SCHED_L0_SP_ENTRY_TBL_COUNT	    64
#define HPPE_SCHED_L0_SP_ENTRY_TBL_STRIDE	    0x20
#define HPPE_SCHED_L0_SP_ENTRY_TBL_WORDS	    5
#define HPPE_SCHED_L0_ENS_Q_LL_TBL_COUNT	    300
#define HPPE_SCHED_L0_ENS_Q_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_ENS_Q_LL_TBL_WORDS	    1
#define HPPE_SCHED_L0_ENS_Q_HEAD_TBL_COUNT	    8
#define HPPE_SCHED_L0_ENS_Q_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_ENS_Q_HEAD_TBL_WORDS	    1
#define HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_COUNT	    300
#define HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_WORDS	    1
#define HPPE_SCHED_L1_C_DRR_HEAD_TBL_COUNT	    36
#define HPPE_SCHED_L1_C_DRR_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_C_DRR_HEAD_TBL_WORDS	    2
#define HPPE_SCHED_L1_E_DRR_HEAD_TBL_COUNT	    36
#define HPPE_SCHED_L1_E_DRR_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_E_DRR_HEAD_TBL_WORDS	    2
#define HPPE_SCHED_L1_DRR_CREDIT_TBL_COUNT	    64
#define HPPE_SCHED_L1_DRR_CREDIT_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_DRR_CREDIT_TBL_WORDS	    2
#define HPPE_SCHED_L1_C_DRR_LL_TBL_COUNT	    64
#define HPPE_SCHED_L1_C_DRR_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_C_DRR_LL_TBL_WORDS	    1
#define HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_COUNT    64
#define HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_STRIDE   0x10
#define HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_WORDS    1
#define HPPE_SCHED_L1_E_DRR_LL_TBL_COUNT	    64
#define HPPE_SCHED_L1_E_DRR_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_E_DRR_LL_TBL_WORDS	    1
#define HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_COUNT    64
#define HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_STRIDE   0x10
#define HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_WORDS    1
#define HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_COUNT	    64
#define HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_WORDS	    1
#define HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_COUNT	    64
#define HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_WORDS	    1
#define HPPE_SCHED_L1_SP_ENTRY_TBL_COUNT	    8
#define HPPE_SCHED_L1_SP_ENTRY_TBL_STRIDE	    0x40
#define HPPE_SCHED_L1_SP_ENTRY_TBL_WORDS	    9
#define HPPE_SCHED_L1_ENS_Q_LL_TBL_COUNT	    64
#define HPPE_SCHED_L1_ENS_Q_LL_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_ENS_Q_LL_TBL_WORDS	    1
#define HPPE_SCHED_L1_ENS_Q_HEAD_TBL_COUNT	    8
#define HPPE_SCHED_L1_ENS_Q_HEAD_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_ENS_Q_HEAD_TBL_WORDS	    1
#define HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_COUNT	    64
#define HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_WORDS	    1
#define HPPE_SCHED_L0_SHP_CREDIT_TBL_COUNT	    300
#define HPPE_SCHED_L0_SHP_CREDIT_TBL_STRIDE	    0x10
#define HPPE_SCHED_L0_SHP_CREDIT_TBL_WORDS	    2
#define HPPE_SCHED_L0_COMP_TBL_COUNT		    300
#define HPPE_SCHED_L0_COMP_TBL_STRIDE		    0x10
#define HPPE_SCHED_L0_COMP_TBL_WORDS		    3
#define HPPE_SCHED_L1_SHP_CREDIT_TBL_COUNT	    64
#define HPPE_SCHED_L1_SHP_CREDIT_TBL_STRIDE	    0x10
#define HPPE_SCHED_L1_SHP_CREDIT_TBL_WORDS	    2
#define HPPE_SCHED_L1_COMP_TBL_COUNT		    64
#define HPPE_SCHED_L1_COMP_TBL_STRIDE		    0x10
#define HPPE_SCHED_L1_COMP_TBL_WORDS		    3
#define HPPE_SCHED_PSCH_SHP_SIGN_TBL_COUNT	    8
#define HPPE_SCHED_PSCH_SHP_SIGN_TBL_STRIDE	    0x10
#define HPPE_SCHED_PSCH_SHP_SIGN_TBL_WORDS	    1
#define HPPE_SCHED_PSCH_SHP_CREDIT_TBL_COUNT	    8
#define HPPE_SCHED_PSCH_SHP_CREDIT_TBL_STRIDE	    0x10
#define HPPE_SCHED_PSCH_SHP_CREDIT_TBL_WORDS	    1
#define HPPE_SCHED_PSCH_COMP_TBL_COUNT		    8
#define HPPE_SCHED_PSCH_COMP_TBL_STRIDE		    0x10
#define HPPE_SCHED_PSCH_COMP_TBL_WORDS		    1

/* POLICER */

/* Physical-port ingress packet/drop counter: sits right after the MAC, so it
 * shows whether a frame the MAC successfully received ever made it past PPE
 * ingress classification. Entry format is 5 words (0x20-strided): word0 is
 * the full 32-bit packet count; the 32-bit drop count is split as bits 8-31
 * of word2 (its own low 24 bits) and bits 0-7 of word3 (its own high 8
 * bits). */
#define APPE_REG_PHY_PORT_RX_CNT(port)	    (0x00156000 + 0x20 * (port))
#define APPE_REG_VP_RX_CNT(vp)		    (0x00150000 + 0x20 * (vp))
#define APPE_REG_PRE_L2_CNT(vsi)	    (0x0017c000 + 0x20 * (vsi))
#define HPPE_REG_PORT_TX_DROP_CNT_TBL(port) (0x17d000 + 0x10 * (port))

#define HPPE_REG_DROP_CPU_CNT(port, reason)                                                        \
  (0x160000 + 0x10 * (256 + QPPE_MAX_PORTS * (reason) + (port)))

#define HPPE_DROP_REASON_COUNT 128

/* SERVICE */

#define HPPE_REG_IN_L2_SERVICE_TBL(sc) (0x66000 + (0x10 * (sc)))
#define HPPE_REG_SERVICE_TBL(sc)       (0x15000 + (0x10 * (sc)))

/* HPPE_REG_IN_L2_SERVICE_TBL word 0: egress_bypass_bitmap bit positions match
 * enum ppe_sc_bypass_egress in the vendor driver (e.g. bit 14 is the
 * post-routing ACL check). */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 dst_port_id_valid : 1;
    u32 dst_port_id : 4;
    u32 dst_direction : 1;
    u32 egress_bypass_bitmap : 24;
    u32 rx_cnt_en : 1;
    u32 tx_cnt_en : 1;
  };
} ppe_reg_in_l2_service_tbl_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_counting_en : 1;
    u32 reserved_1_31 : 31;
  };
} ppe_reg_service_tbl_w1_t;

/* HPPE_REG_SERVICE_TBL word 0, including APPE additions from fal_servcode.h. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 in_vlan_tag_fmt_check_byp : 1;
    u32 in_vlan_member_check_byp : 1;
    u32 in_vlan_xlt_byp : 1;
    u32 my_mac_check_byp : 1;
    u32 dip_lookup_byp : 1;
    u32 flow_lookup_byp : 1;
    u32 flow_action_byp : 1;
    u32 acl_byp : 1;
    u32 fake_mac_header_byp : 1;
    u32 service_code_byp : 1;
    u32 wrong_pkt_fmt_l2_byp : 1;
    u32 wrong_pkt_fmt_l3_ipv4_byp : 1;
    u32 wrong_pkt_fmt_l3_ipv6_byp : 1;
    u32 wrong_pkt_fmt_l4_byp : 1;
    u32 flow_service_code_byp : 1;
    u32 acl_service_code_byp : 1;
    u32 fake_l2_proto_byp : 1;
    u32 pppoe_termination_byp : 1;
    u32 default_vlan_byp : 1;
    u32 default_pcp_byp : 1;
    u32 vsi_assign_byp : 1;
    u32 wrong_pkt_fmt_tunnel_byp : 1;
    u32 reserved_22_23 : 2;
    u32 in_vlan_assign_fail_byp : 1;
    u32 source_guard_byp : 1;
    u32 mru_mtu_check_byp : 1;
    u32 flow_src_check_byp : 1;
    u32 flow_qos_byp : 1;
    u32 reserved_29_31 : 3;
  };
} ppe_reg_service_tbl_bypass_bitmap_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 next_service_code : 8;
    u32 hw_services : 6;
    u32 offset_sel : 1;
    u32 tx_counting_en : 1;
    u32 reserved_16_31 : 16;
  };
} ppe_reg_eg_service_tbl_w1_t;

#define HPPE_REG_EG_SERVICE_TBL(sc) (0x43000 + (0x10 * (sc)))
#define APPE_REG_TL_SERVICE_TBL(sc) (0x306000 + (0x4 * (sc)))
#define HPPE_SERVICE_CODE_COUNT	    256

/* RSS */

#define HPPE_REG_RSS_HASH_MASK		  0x0b4318
#define HPPE_REG_RSS_HASH_SEED		  0x0b431c
#define HPPE_REG_RSS_HASH_MIX(index)	  (0x0b4320 + 4 * (index))
#define HPPE_REG_RSS_HASH_FIN(index)	  (0x0b4350 + 4 * (index))
#define HPPE_REG_RSS_HASH_MASK_IPV4	  0x0b4380
#define HPPE_REG_RSS_HASH_SEED_IPV4	  0x0b4384
#define HPPE_REG_RSS_HASH_MIX_IPV4(index) (0x0b4390 + 4 * (index))
#define HPPE_REG_RSS_HASH_FIN_IPV4(index) (0x0b43b0 + 4 * (index))
#define HPPE_RSS_REG_STRIDE		  4
#define HPPE_RSS_HASH_MIX_COUNT		  11
#define HPPE_RSS_HASH_MIX_IPV4_COUNT	  5
#define HPPE_RSS_HASH_FIN_COUNT		  5

#define foreach_ppe_reg_rss_hash_mask_t_fields                                                     \
  _ (21, mask)                                                                                     \
  _ (7, _reserved_21)                                                                              \
  _ (1, rss_hash_fragment)                                                                         \
  _ (3, _reserved_29)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_rss_hash_mask_t_fields
#undef _
  };
} ppe_reg_rss_hash_mask_t;

#define foreach_ppe_reg_rss_hash_seed_t_fields _ (32, seed)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_rss_hash_seed_t_fields
#undef _
  };
} ppe_reg_rss_hash_seed_t;

#define foreach_ppe_reg_rss_hash_mix_t_fields                                                      \
  _ (5, hash_mix)                                                                                  \
  _ (27, _reserved_5)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_rss_hash_mix_t_fields
#undef _
  };
} ppe_reg_rss_hash_mix_t;

#define foreach_ppe_reg_rss_hash_fin_t_fields                                                      \
  _ (5, fin_inner)                                                                                 \
  _ (5, fin_outer)                                                                                 \
  _ (22, _reserved_10)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_ppe_reg_rss_hash_fin_t_fields
#undef _
  };
} ppe_reg_rss_hash_fin_t;
