/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

#define QPPE_MAX_PORTS		       8
#define HPPE_REG_MRU_MTU_CTRL_W1(port) (0x65004 + (0x10 * (port)))
#define HPPE_REG_UCAST_PRIORITY_MAP_TBL(profile, priority)                                         \
  (0x842000 + (0x10 * (((profile) << 4) + (priority))))
#define HPPE_XLT_ACTION_TBL_ENTRIES	128
#define HPPE_REG_VSI_TBL_W0(vsi)	(0x063800 + (0x10 * (vsi)))
#define HPPE_REG_PORT_BRIDGE_CTRL(port) (0x060300 + (0x4 * (port)))
#define HPPE_REG_IN_L2_SERVICE_TBL(sc)	(0x66000 + (0x10 * (sc)))
#define HPPE_REG_SERVICE_TBL(sc)	(0x15000 + (0x10 * (sc)))
/* MY_MAC_TBL (vendor's IPE_L3_BASE_ADDR + MY_MAC_TBL_ADDRESS): a small,
 * global (not per-VSI) table of this chip's own MAC addresses, consulted by
 * PORT_BRIDGE_CTRL.promisc_en when it is clear to admit unicast frames
 * addressed to us while dropping everything else before FDB/VSI forwarding
 * is even consulted. */
#define HPPE_MY_MAC_TBL_ENTRIES 8

#define HPPE_ACL_ACTION_FWD 0
#define APPE_ACL_PRI_PERMIT 1

#define APPE_PRE_ACL_SECONDARY_MAX 4
#define APPE_PRE_ACL_ROWS_PER_PORT (2 + APPE_PRE_ACL_SECONDARY_MAX + 2)

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
    u32 profile_id : 4;
    u32 queue_id : 8;
    u32 reserved_12_31 : 20;
  };
} ppe_reg_ucast_queue_map_t;

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

/* BM per-port silent-drop counter: one cumulative packet count per physical
 * port (0 = CPU, 1-7 = MAC ports), incremented whenever the buffer manager
 * drops a frame for that port rather than being able to queue it. */

/* BM per-port overflow-drop counter: packets dropped because hardware
 * buffers were only partially available for the packet. Entry format is a
 * 3-word (0x10-strided) table; only word0 (the full 32 bits) holds the
 * count, words 1-2 are unused for this table. */

/* Physical-port ingress packet/drop counter: sits right after the MAC, so it
 * shows whether a frame the MAC successfully received ever made it past PPE
 * ingress classification. Entry format is 5 words (0x20-strided): word0 is
 * the full 32-bit packet count; the 32-bit drop count is split as bits 8-31
 * of word2 (its own low 24 bits) and bits 0-7 of word3 (its own high 8
 * bits). */
#define APPE_REG_PHY_PORT_RX_CNT(port) (0x00156000 + 0x20 * (port))

/* Virtual-port ingress packet/drop counter: same 5-word layout as
 * APPE_REG_PHY_PORT_RX_CNT above, but indexed by VP (EDMA_VP_BASE +
 * port_id) rather than the raw physical port - the stage right after
 * VSI/XLT resolves a frame to this port's own VP. */

/* Pre-L2-forwarding packet/drop counter: same 5-word layout as
 * APPE_REG_PHY_PORT_RX_CNT above, indexed by VSI (qppe's own
 * per-port-private VSI number, i.e. the physical port_id - no VP offset
 * involved here). Sits right at the input to the VSI/XLT/FDB forwarding
 * decision that HPPE_REG_VSI_TBL_W0 et al configure, so its drop count
 * directly reflects the L2-forwarding stage rather than ingress
 * classification or the Queue Manager. */

/* Queue Manager stage, the last one before EDMA actually dequeues a packet
 * into its ring: QUEUE_TX is how many packets this hardware unicast queue
 * successfully handed off (3-word entry, only word0/the full 32 bits used);
 * UNICAST_DROP is 6 separate drop-reason counters per queue (RED/YEL/GRN
 * AQM, a forced-drop reason, and others the vendor driver doesn't name
 * individually), each its own 3-word entry, summed here into one total. */
#define HPPE_QM_UNICAST_DROP_TYPES 6

/* HPPE port TX counters under the APPE PTX module and policer module. */
/* HPPE port TX counters under the APPE PTX module and policer module. */

#define HPPE_REG_PORT_MUX_CONTROL	 0x10
#define HPPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290

#define HPPE_REG_AC_GRP_CFG_W0(grp)		(0x84c000 + 0x10 * (grp))
#define HPPE_REG_AC_GRP_CFG_W1(grp)		(0x84c004 + 0x10 * (grp))
#define HPPE_REG_AC_UNICAST_QUEUE_CFG_W0(queue) (0x848000 + 0x10 * (queue))
#define HPPE_AC_UNICAST_QUEUE_COUNT		256
#define HPPE_AC_MULTICAST_QUEUE_BASE		256
#define HPPE_AC_MULTICAST_QUEUE_COUNT		44
#define HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0(queue)                                                  \
  (0x84a000 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))
#define PPE_REG_GMAC_ENABLE(port)      (0x1000 + ((port) - 1) * 0x200)
#define PPE_REG_GMAC_BASE(port)	       (0x001000 + ((port) - 1) * 0x200)
#define PPE_REG_XGMAC_BASE(port)       (0x500000 + ((port) - 1) * 0x4000)
#define HPPE_REG_MC_MTU_CTRL_TBL(port) (0x60a00 + (0x4 * (port)))
#define HPPE_REG_MRU_MTU_CTRL_W0(port) (0x65000 + (0x10 * (port)))
#define PPE_XGMAC_REG_TX_CONFIG	       0x0
#define PPE_XGMAC_REG_RX_CONFIG	       0x4
#define PPE_XGMAC_MAX_FRAME_SIZE       0x3000

#define foreach_ppe_xgmac_rx_counter                                                               \
  _ (0x900, PACKETS_GB, "xgmac_frames", 8, GENERIC, PACKETS)                                       \
  _ (0x908, BYTES_GB, "xgmac_bytes", 8, GENERIC, BYTES)                                            \
  _ (0x910, BYTES_G, "xgmac_bytes_g", 8, VENDOR, BYTES)                                            \
  _ (0x918, BROADCAST_G, "xgmac_broadcast_g", 8, VENDOR, PACKETS)                                  \
  _ (0x920, MULTICAST_G, "xgmac_multicast_g", 8, VENDOR, PACKETS)                                  \
  _ (0x928, CRC_ERROR, "xgmac_crc_err", 8, VENDOR, PACKETS)                                        \
  _ (0x930, FRAGMENT_ERROR, "xgmac_frag_err", 4, VENDOR, PACKETS)                                  \
  _ (0x934, JABBER_ERROR, "xgmac_jabber_err", 4, VENDOR, PACKETS)                                  \
  _ (0x938, UNDERSIZE_G, "xgmac_undersize_g", 4, VENDOR, PACKETS)                                  \
  _ (0x93c, OVERSIZE_G, "xgmac_oversize_g", 4, VENDOR, PACKETS)                                    \
  _ (0x940, PACKETS_64_GB, "xgmac_pkt64", 8, VENDOR, PACKETS)                                      \
  _ (0x948, PACKETS_65_TO_127_GB, "xgmac_65_to_127_byte", 8, VENDOR, PACKETS)                      \
  _ (0x950, PACKETS_128_TO_255_GB, "xgmac_128_to_255_byte", 8, VENDOR, PACKETS)                    \
  _ (0x958, PACKETS_256_TO_511_GB, "xgmac_256_to_511_byte", 8, VENDOR, PACKETS)                    \
  _ (0x960, PACKETS_512_TO_1023_GB, "xgmac_512_to_1023_byte", 8, VENDOR, PACKETS)                  \
  _ (0x968, PACKETS_1024_TO_MAX_GB, "xgmac_1024_to_max_bytes", 8, VENDOR, PACKETS)                 \
  _ (0x970, UNICAST_G, "xgmac_unicast_g", 8, VENDOR, PACKETS)                                      \
  _ (0x978, LENGTH_ERROR, "xgmac_len_err", 8, VENDOR, PACKETS)                                     \
  _ (0x980, OUT_OF_RANGE, "xgmac_outofrange_err", 8, VENDOR, PACKETS)                              \
  _ (0x988, PAUSE, "xgmac_pause", 8, VENDOR, PACKETS)                                              \
  _ (0x990, FIFO_OVERFLOW, "xgmac_fifo_overflow", 8, VENDOR, PACKETS)                              \
  _ (0x998, VLAN_GB, "xgmac_vlan", 8, VENDOR, PACKETS)                                             \
  _ (0x9a0, WATCHDOG_ERROR, "xgmac_wdog_err", 4, VENDOR, PACKETS)                                  \
  _ (0x9a4, LPI_USEC, "xgmac_lpi_usec", 4, VENDOR, NA)                                             \
  _ (0x9a8, LPI_TRANSITIONS, "xgmac_lpi_tran", 4, VENDOR, NA)                                      \
  _ (0x9ac, DISCARD_GB, "xgmac_drop_frames", 8, VENDOR, PACKETS)                                   \
  _ (0x9b4, DISCARD_BYTES_GB, "xgmac_drop_bytes", 8, VENDOR, BYTES)

#define foreach_ppe_xgmac_tx_counter                                                               \
  _ (0x814, BYTES_GB, "xgmac_bytes", 8, GENERIC, BYTES)                                            \
  _ (0x81c, PACKETS_GB, "xgmac_frames", 8, GENERIC, PACKETS)                                       \
  _ (0x824, BROADCAST_G, "xgmac_broadcast_g", 8, VENDOR, PACKETS)                                  \
  _ (0x82c, MULTICAST_G, "xgmac_multicast_g", 8, VENDOR, PACKETS)                                  \
  _ (0x834, PACKETS_64_GB, "xgmac_pkt64", 8, VENDOR, PACKETS)                                      \
  _ (0x83c, PACKETS_65_TO_127_GB, "xgmac_65_to_127_byte", 8, VENDOR, PACKETS)                      \
  _ (0x844, PACKETS_128_TO_255_GB, "xgmac_128_to_255_byte", 8, VENDOR, PACKETS)                    \
  _ (0x84c, PACKETS_256_TO_511_GB, "xgmac_256_to_511_byte", 8, VENDOR, PACKETS)                    \
  _ (0x854, PACKETS_512_TO_1023_GB, "xgmac_512_to_1023_byte", 8, VENDOR, PACKETS)                  \
  _ (0x85c, PACKETS_1024_TO_MAX_GB, "xgmac_1024_to_max_bytes", 8, VENDOR, PACKETS)                 \
  _ (0x864, UNICAST_GB, "xgmac_unicast", 8, VENDOR, PACKETS)                                       \
  _ (0x86c, MULTICAST_GB, "xgmac_multicast", 8, VENDOR, PACKETS)                                   \
  _ (0x874, BROADCAST_GB, "xgmac_broadcast", 8, VENDOR, PACKETS)                                   \
  _ (0x87c, UNDERFLOW_ERROR, "xgmac_underflow_err", 8, VENDOR, PACKETS)                            \
  _ (0x884, BYTES_G, "xgmac_bytes_g", 8, VENDOR, BYTES)                                            \
  _ (0x88c, PACKETS_G, "xgmac_frames_g", 8, VENDOR, PACKETS)                                       \
  _ (0x894, PAUSE, "xgmac_pause", 8, VENDOR, PACKETS)                                              \
  _ (0x89c, VLAN_G, "xgmac_vlan_g", 8, VENDOR, PACKETS)                                            \
  _ (0x8a4, LPI_USEC, "xgmac_lpi_usec", 4, VENDOR, NA)                                             \
  _ (0x8a8, LPI_TRANSITIONS, "xgmac_lpi_tran", 4, VENDOR, NA)

#define foreach_ppe_gmac_rx_counter                                                                \
  _ (0x40, BROADCAST, "gmac_broadcast", 4, VENDOR, PACKETS)                                        \
  _ (0x44, PAUSE, "gmac_pause", 4, VENDOR, PACKETS)                                                \
  _ (0x48, MULTICAST, "gmac_multicast", 4, VENDOR, PACKETS)                                        \
  _ (0x4c, FCS_ERROR, "gmac_fcserr", 4, VENDOR, PACKETS)                                           \
  _ (0x50, ALIGN_ERROR, "gmac_alignerr", 4, VENDOR, PACKETS)                                       \
  _ (0x54, RUNT, "gmac_runt", 4, VENDOR, PACKETS)                                                  \
  _ (0x58, FRAGMENT, "gmac_frag", 4, VENDOR, PACKETS)                                              \
  _ (0x5c, JUMBO_FCS_ERROR, "gmac_jumbofcserr", 4, VENDOR, PACKETS)                                \
  _ (0x60, JUMBO_ALIGN_ERROR, "gmac_jumboalignerr", 4, VENDOR, PACKETS)                            \
  _ (0x64, PACKETS_64, "gmac_pkt64", 4, VENDOR, PACKETS)                                           \
  _ (0x68, PACKETS_65_TO_127, "gmac_65_to_127_byte", 4, VENDOR, PACKETS)                           \
  _ (0x6c, PACKETS_128_TO_255, "gmac_128_to_255_byte", 4, VENDOR, PACKETS)                         \
  _ (0x70, PACKETS_256_TO_511, "gmac_256_to_511_byte", 4, VENDOR, PACKETS)                         \
  _ (0x74, PACKETS_512_TO_1023, "gmac_512_to_1023_byte", 4, VENDOR, PACKETS)                       \
  _ (0x78, PACKETS_1024_TO_1518, "gmac_1024_to_1518_byte", 4, VENDOR, PACKETS)                     \
  _ (0x7c, PACKETS_1519_TO_X, "gmac_1519_to_max_bytes", 4, VENDOR, PACKETS)                        \
  _ (0x80, TOO_LONG, "gmac_toolong", 4, VENDOR, PACKETS)                                           \
  _ (0x84, BYTES_GOOD, "gmac_bytes_g", 8, GENERIC, BYTES)                                          \
  _ (0x8c, BYTES_BAD, "gmac_bytes_b", 8, VENDOR, BYTES)                                            \
  _ (0x94, UNICAST, "gmac_unicast", 4, VENDOR, PACKETS)

#define foreach_ppe_gmac_tx_counter                                                                \
  _ (0xa0, BROADCAST, "gmac_broadcast", 4, VENDOR, PACKETS)                                        \
  _ (0xa4, PAUSE, "gmac_pause", 4, VENDOR, PACKETS)                                                \
  _ (0xa8, MULTICAST, "gmac_multicast", 4, VENDOR, PACKETS)                                        \
  _ (0xac, UNDERRUN, "gmac_underrun", 4, VENDOR, PACKETS)                                          \
  _ (0xb0, PACKETS_64, "gmac_pkt64", 4, VENDOR, PACKETS)                                           \
  _ (0xb4, PACKETS_65_TO_127, "gmac_65_to_127_byte", 4, VENDOR, PACKETS)                           \
  _ (0xb8, PACKETS_128_TO_255, "gmac_128_to_255_byte", 4, VENDOR, PACKETS)                         \
  _ (0xbc, PACKETS_256_TO_511, "gmac_256_to_511_byte", 4, VENDOR, PACKETS)                         \
  _ (0xc0, PACKETS_512_TO_1023, "gmac_512_to_1023_byte", 4, VENDOR, PACKETS)                       \
  _ (0xc4, PACKETS_1024_TO_1518, "gmac_1024_to_1518_byte", 4, VENDOR, PACKETS)                     \
  _ (0xc8, PACKETS_1519_TO_X, "gmac_1519_to_max_bytes", 4, VENDOR, PACKETS)                        \
  _ (0xcc, BYTES, "gmac_bytes", 8, GENERIC, BYTES)                                                 \
  _ (0xd4, COLLISIONS, "gmac_collisions", 4, VENDOR, NA)                                           \
  _ (0xd8, ABORT_COLLISIONS, "gmac_abortcol", 4, VENDOR, NA)                                       \
  _ (0xdc, MULTIPLE_COLLISIONS, "gmac_multicol", 4, VENDOR, NA)                                    \
  _ (0xe0, SINGLE_COLLISIONS, "gmac_singlecol", 4, VENDOR, NA)                                     \
  _ (0xe4, EXCESSIVE_DEFER, "gmac_excdeffer", 4, VENDOR, NA)                                       \
  _ (0xe8, DEFER, "gmac_deffer", 4, VENDOR, NA)                                                    \
  _ (0xec, LATE_COLLISION, "gmac_latecol", 4, VENDOR, NA)                                          \
  _ (0xf0, UNICAST, "gmac_unicast", 4, VENDOR, PACKETS)

typedef enum
{
#define _(offset, name, description, width, type, unit) PPE_XGMAC_REG_RX_##name = offset,
  foreach_ppe_xgmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit) PPE_XGMAC_REG_TX_##name = offset,
    foreach_ppe_xgmac_tx_counter
#undef _
#define _(offset, name, description, width, type, unit) PPE_GMAC_REG_RX_##name = offset,
      foreach_ppe_gmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit) PPE_GMAC_REG_TX_##name = offset,
	foreach_ppe_gmac_tx_counter
#undef _
} ppe_mib_counter_reg_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0 : 4;
    u32 port5_pcs1_select : 1;
    u32 reserved_5 : 3;
    u32 xgmac_select : 6;
    u32 reserved_14 : 18;
  };
} ppe_reg_port_mux_control_t;

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
    u32 ac_en : 1;
    u32 ac_fc_en : 1;
    u32 clr_aware : 1;
    u32 reserved_3_24 : 22;
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
    u32 reserved_15_31 : 17;
  };
} ppe_reg_ac_grp_cfg_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0_4 : 5;
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
    u32 reserved_0_12 : 13;
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
    u32 reserved_27 : 5;
  };
} ppe_reg_ac_multicast_queue_cfg_w0_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0_6 : 7;
    u32 resume : 11;
    u32 reserved_18 : 14;
  };
} ppe_reg_ac_multicast_queue_cfg_w2_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 disable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_enq_deq_opr_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0_1 : 2;
    u32 queue_cnt_en : 1;
    u32 reserved_3 : 29;
  };
} ppe_reg_eg_bridge_config_t;

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

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 tx_enable : 1;
    u32 reserved_2_3 : 2;
    u32 full_duplex : 1;
    u32 reserved_5 : 1;
    u32 rx_flow_control : 1;
    u32 tx_flow_control : 1;
    u32 reserved_8_31 : 24;
  };
} ppe_reg_gmac_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 speed : 2;
    u32 reserved_2_31 : 30;
  };
} ppe_reg_gmac_speed_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_enable : 1;
    u32 reserved_1_15 : 15;
    u32 jabber_disable : 1;
    u32 reserved_17_28 : 12;
    u32 speed : 3;
  };
} ppe_reg_xgmac_tx_config_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 address_aligned_beats : 1;
    u32 crc_strip : 1;
    u32 reserved_3_5 : 3;
    u32 giant_packet_size_limit_enable : 1;
    u32 giant_packet_size_limit_watchdog : 1;
    u32 reserved_8_15 : 8;
    u32 giant_packet_size_limit : 14;
    u32 reserved_30_31 : 2;
  };
} ppe_reg_xgmac_rx_config_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 promiscuous_mode : 1;
    u32 reserved_1_5 : 5;
    u32 pass_control_frames : 2;
    u32 reserved_8_30 : 23;
    u32 receive_all : 1;
  };
} ppe_reg_xgmac_packet_filter_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 watchdog_timeout : 4;
    u32 reserved_4_7 : 4;
    u32 programmable_watchdog_enable : 1;
    u32 reserved_9_31 : 23;
  };
} ppe_reg_xgmac_watchdog_timeout_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 counter_reset : 1;
    u32 reserved_1_2 : 2;
    u32 counter_freeze : 1;
    u32 reserved_4_31 : 28;
  };
} ppe_reg_xgmac_mmc_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reset : 1;
    u32 read_clear : 1;
    u32 reserved_3_31 : 29;
  };
} ppe_reg_gmac_mib_control_t;

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

/* HPPE_REG_SERVICE_TBL word 0 (bypass_bitmap), every bit named per the
 * vendor's fal_servcode.h enum (bits 0-28; 19-23 and 29-31 are gaps in
 * that enum itself, not just unused by this driver). */
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
    u32 reserved_19_23 : 5;
    u32 in_vlan_assign_fail_byp : 1;
    u32 source_guard_byp : 1;
    u32 mru_mtu_check_byp : 1;
    u32 flow_src_check_byp : 1;
    u32 flow_qos_byp : 1;
    u32 reserved_29_31 : 3;
  };
} ppe_reg_service_tbl_bypass_bitmap_t;

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
    u32 reserved_21_23 : 3;
    u32 reserved_24_31 : 8;
  };
} ppe_reg_eg_bypass_bitmap_t;

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
