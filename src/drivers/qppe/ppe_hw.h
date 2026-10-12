/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

/* This is the only supported PPE variant; the compatible string serves as its revision ID. */
#define PPE_DT_COMPATIBLE "qcom,ipq9574-ppe"
#define foreach_ppe_chip_type                                                                      \
  _ (0x15, HPPE)                                                                                   \
  _ (0x17, MHT)                                                                                    \
  _ (0x20, APPE)                                                                                   \
  _ (0x21, MRPPE)                                                                                  \
  _ (0x30, JHPPE)                                                                                  \
  _ (0x40, HMSPPE)                                                                                 \
  _ (0x50, HTTPPE)
#define PPE_MAX_PORTS				   8
#define PPE_PORT_RESET_DELAY_US			   10000
#define PPE_REG_MRU_MTU_CTRL_W1(port)		   (0x65004 + (0x10 * (port)))
#define PPE_REG_UCAST_QUEUE_MAP_TBL(profile, port) (0x810000 + (0x10 * (((profile) << 8) + (port))))
#define PPE_REG_UCAST_HASH_MAP_TBL(profile, hash)  (0x830000 + (0x10 * (((profile) << 8) + (hash))))
#define PPE_REG_UCAST_PRIORITY_MAP_TBL(profile, priority)                                          \
  (0x842000 + (0x10 * (((profile) << 4) + (priority))))
#define PPE_REG_MCAST_PRIORITY_MAP_TBL(port, priority)                                             \
  (0x800100 + (0x40 * (port)) + (0x4 * (priority)))
#define PPE_REG_MCAST_QUEUE_MAP_TBL(cpu_code) (0x844000 + (0x10 * (cpu_code)))
/* ingress VLAN classification stage (port [+ VLAN] -> VSI), consulted for L2
 * bridging/flood-domain membership; this is NOT the L3-routing-only VSI field in
 * L3_VP_PORT_TBL. */
#define PPE_REG_XLT_RULE_TBL(index)   (0x011000 + (0x10 * (index)))
#define PPE_REG_XLT_ACTION_TBL(index) (0x013000 + (0x10 * (index)))
#define PPE_XLT_RULE_TBL_ENTRIES      128
#define PPE_XLT_ACTION_TBL_ENTRIES    128
#define PPE_REG_VSI_TBL_W0(vsi)	      (0x063800 + (0x10 * (vsi)))
#define PPE_VSI_TBL_ENTRIES	      64
/* APPE-specific extension (not present on plain HPPE): an alternate, much
 * wider (256-bit, covering the full VP space) flood-membership bitmap per
 * VSI, gated by vsi_remap_en - disabled (0) by default/never written by
 * this driver, so VSI_TBL's narrower 8-bit bitmap above remains the one
 * actually in effect. Shown read-only for completeness. */
#define PPE_REG_VSI_REMAP_TBL(vsi) (0x093000 + (0x40 * (vsi)))
#define PPE_VSI_REMAP_TBL_ENTRIES  64
/* indexed by (dst_phy_port << 6) | vsi; resolves a VSI-flooded frame's CPU delivery
 * to a virtual port (enqueue_vp), which then gets its own UCAST_QUEUE_MAP_TBL row. */
#define PPE_REG_PORT_VSI_ENQUEUE_MAP(port, vsi) (0x09d000 + (0x4 * (((port) << 6) | (vsi))))
/* per physical port; governs where a frame goes when its ingress classification
 * fails to resolve a valid VSI at all - a separate fallback from VSI_TBL-based
 * flooding, e.g. for a destination-unknown unicast frame before it even reaches
 * the flood decision. */
#define PPE_REG_L2_VP_PORT_TBL_W0(port) (0x098000 + (0x10 * (port)))
#define PPE_L2_VP_PORT_TBL_ENTRIES	256
/* per physical port (and port 0 for the CPU port); txmac_en gates whether the
 * switch core will actually deliver frames to this port's destination - the
 * CPU port's own entry is enabled once, globally, while every physical port's
 * entry is toggled with that port's link state. */
#define PPE_REG_PORT_BRIDGE_CTRL(port) (0x060300 + (0x4 * (port)))
/* service code table rows; service code 1 is reserved by this driver to mean
 * "bypass everything the switch core would otherwise do to a CPU-originated
 * frame" so that packets qppe hands to the EDMA TX ring go straight out the
 * destination port instead of being re-run through bridging/ACL/QoS. */
#define PPE_REG_IN_L2_SERVICE_TBL(sc) (0x66000 + (0x10 * (sc)))
#define PPE_REG_SERVICE_TBL(sc)	      (0x15000 + (0x10 * (sc)))
#define PPE_REG_EG_SERVICE_TBL(sc)    (0x43000 + (0x10 * (sc)))
#define PPE_REG_TL_SERVICE_TBL(sc)    (0x306000 + (0x4 * (sc)))

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

/* BM per-port silent-drop counter: one cumulative packet count per physical
 * port (0 = CPU, 1-7 = MAC ports), incremented whenever the buffer manager
 * drops a frame for that port rather than being able to queue it. */
#define PPE_REG_BM_SILENT_DROP_CNT(port) (0x00b024 + 0x4 * (port))

/* BM per-port overflow-drop counter: packets dropped because hardware
 * buffers were only partially available for the packet. Entry format is a
 * 3-word (0x10-strided) table; only word0 (the full 32 bits) holds the
 * count, words 1-2 are unused for this table. */
#define PPE_REG_BM_OVERFLOW_DROP_CNT(port) (0x0000e000 + 0x10 * (port))

/* Physical-port ingress packet/drop counter: sits right after the MAC, so it
 * shows whether a frame the MAC successfully received ever made it past PPE
 * ingress classification. Entry format is 5 words (0x20-strided): word0 is
 * the full 32-bit packet count; the 32-bit drop count is split as bits 8-31
 * of word2 (its own low 24 bits) and bits 0-7 of word3 (its own high 8
 * bits). */
#define PPE_REG_PHY_PORT_RX_CNT(port) (0x00156000 + 0x20 * (port))

/* Virtual-port ingress packet/drop counter: same 5-word layout as
 * PPE_REG_PHY_PORT_RX_CNT above, but indexed by VP (EDMA_VP_BASE +
 * port_id) rather than the raw physical port - the stage right after
 * VSI/XLT resolves a frame to this port's own VP. */
#define PPE_REG_VP_RX_CNT(vp) (0x00150000 + 0x20 * (vp))

/* Pre-L2-forwarding packet/drop counter: same 5-word layout as
 * PPE_REG_PHY_PORT_RX_CNT above, indexed by VSI (qppe's own
 * per-port-private VSI number, i.e. the physical port_id - no VP offset
 * involved here). Sits right at the input to the VSI/XLT/FDB forwarding
 * decision that PPE_REG_VSI_TBL_W0 et al configure, so its drop count
 * directly reflects the L2-forwarding stage rather than ingress
 * classification or the Queue Manager. */
#define PPE_REG_PRE_L2_CNT(vsi) (0x0017c000 + 0x20 * (vsi))

/* Queue Manager stage, the last one before EDMA actually dequeues a packet
 * into its ring: QUEUE_TX is how many packets this hardware unicast queue
 * successfully handed off (3-word entry, only word0/the full 32 bits used);
 * UNICAST_DROP is 6 separate drop-reason counters per queue (RED/YEL/GRN
 * AQM, a forced-drop reason, and others the vendor driver doesn't name
 * individually), each its own 3-word entry, summed here into one total. */
#define PPE_REG_QM_QUEUE_TX_CNT(queue) (0x81a000 + 0x10 * (queue))
#define PPE_QM_UNICAST_DROP_TYPES      6
#define PPE_REG_QM_UNICAST_DROP_CNT(queue, type)                                                   \
  (0x009e0000 + 0x10 * ((queue) * PPE_QM_UNICAST_DROP_TYPES + (type)))

/* HPPE port TX counters under the APPE PTX module and policer module. */
#define PPE_REG_PORT_TX_COUNTER_TBL(port)  (0x034000 + 0x10 * (port))
#define PPE_REG_PORT_TX_DROP_CNT_TBL(port) (0x17d000 + 0x10 * (port))

#define PPE_REG_PORT_MUX_CONTROL	0x10
#define PPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290
/* BM port flow-control admission control: 15 BM ports share a single
 * 2048-buffer pool. BM port 0 is the CPU/EDMA port, BM ports 1-7 cover
 * EDMA's other profiles, BM ports 8-13 map to physical PPE ports 1-6
 * (bm_port = port_id + PPE_BM_PORT_ID_PHYS_BASE), BM port 14 is EIP. Left
 * unconfigured, ports draw from the shared pool under undefined reset
 * thresholds instead of the real per-port ceiling/weight/dynamic scheme -
 * under combined multi-port traffic this starves the shared pool and
 * stalls EVERY port's RX ring simultaneously, not just one. */
#define PPE_BM_PORT_ID_CPU		   0
#define PPE_BM_PORT_ID_PHYS_BASE	   7
#define PPE_REG_BM_PORT_FC_MODE(bm_port)   (0x600100 + 0x4 * (bm_port))
#define PPE_REG_BM_PORT_GROUP_ID(bm_port)  (0x600180 + 0x4 * (bm_port))
#define PPE_REG_BM_PORT_FC_CFG_W0(bm_port) (0x601000 + 0x10 * (bm_port))
#define PPE_REG_BM_PORT_FC_CFG_W1(bm_port) (0x601004 + 0x10 * (bm_port))
/* ipq9574-specific admission control constants, matching mainline's
 * ipq9574_ppe_bm_port_config[]/ipq9574_ppe_bm_group_config exactly. The
 * physical-port bucket (BM ports 8-13) is applied per VPP port as it
 * starts/stops, not fixed at device init, so a stopped port's share is
 * freed back to the shared pool for the ports still running. */
#define PPE_BM_SHARED_GROUP0_LIMIT     1550
#define PPE_BM_PHYS_PORT_CEIL	       250
#define PPE_BM_PHYS_PORT_WEIGHT	       4
#define PPE_BM_PHYS_PORT_RESUME_OFFSET 36
#define PPE_BM_PHYS_PORT_REACT_LIMIT   128

/* QM (Queue Manager) admission control: a separate subsystem from BM
 * above - BM gates buffer admission per physical port, QM gates them
 * again per hardware queue. Queues additionally reset with enqueue and
 * dequeue explicitly DISABLED per-queue (PPE_REG_ENQ_OPR/PPE_REG_DEQ_OPR);
 * nothing in this driver has ever cleared those bits. Configured once,
 * globally, at device init - not tied to any VPP port's lifecycle, same
 * as mainline's one-time ppe_config_qm(). */
#define PPE_REG_AC_GRP_CFG_W0(grp)	       (0x84c000 + 0x10 * (grp))
#define PPE_REG_AC_GRP_CFG_W1(grp)	       (0x84c004 + 0x10 * (grp))
#define PPE_REG_AC_UNICAST_QUEUE_CFG_W0(queue) (0x848000 + 0x10 * (queue))
#define PPE_REG_AC_UNICAST_QUEUE_CFG_W3(queue) (0x84800c + 0x10 * (queue))
#define PPE_REG_ENQ_OPR(queue)		       (0x85c000 + 0x10 * (queue))
#define PPE_REG_DEQ_OPR(queue)		       (0x430000 + 0x10 * (queue))
#define PPE_REG_EG_BRIDGE_CONFIG	       0x20044
#define PPE_AC_UNICAST_QUEUE_COUNT	       256
#define PPE_AC_MULTICAST_QUEUE_BASE	       256
#define PPE_AC_MULTICAST_QUEUE_COUNT	       44
/* indexed LOCALLY (0-43), unlike mainline's qcom_ppe source which (per a
 * cross-check against the vendor SSDK's AC_MUL_QUEUE_CFG_TBL, 44 entries
 * at this same base) appears to multiply by the raw global queue id
 * (256-299) instead - confirmed wrong against real hardware, which
 * rejects the resulting out-of-range write. */
#define PPE_REG_AC_MULTICAST_QUEUE_CFG_W0(queue)                                                   \
  (0x84a000 + 0x10 * ((queue) - PPE_AC_MULTICAST_QUEUE_BASE))
#define PPE_REG_AC_MULTICAST_QUEUE_CFG_W2(queue)                                                   \
  (0x84a008 + 0x10 * ((queue) - PPE_AC_MULTICAST_QUEUE_BASE))
/* ipq9574-specific constants, matching mainline's
 * ipq9574_ppe_qm_group_config/ipq9574_ppe_qm_queue_config[] exactly. */
#define PPE_QM_GROUP0_BUF_LIMIT	       2000
#define PPE_QM_UCAST_CEIL	       1200
#define PPE_QM_UCAST_WEIGHT	       7
#define PPE_QM_UCAST_RESUME_OFFSET     36
#define PPE_QM_MCAST_CEIL	       250
#define PPE_QM_MCAST_RESUME_OFFSET     36
#define PPE_REG_GMAC_ENABLE(port)      (0x1000 + ((port) - 1) * 0x200)
#define PPE_REG_GMAC_BASE(port)	       (0x001000 + ((port) - 1) * 0x200)
#define PPE_REG_XGMAC_BASE(port)       (0x500000 + ((port) - 1) * 0x4000)
#define PPE_REG_MC_MTU_CTRL_TBL(port)  (0x60a00 + (0x4 * (port)))
#define PPE_REG_MRU_MTU_CTRL_W0(port)  (0x65000 + (0x10 * (port)))
#define PPE_MC_MTU_CTRL_TBL_MTU_MASK   0x00003fff
#define PPE_MRU_MTU_CTRL_W0_MRU_MASK   0x00003fff
#define PPE_MRU_MTU_CTRL_W0_MTU_MASK   0x3fff0000
#define PPE_XGMAC_REG_TX_CONFIG	       0x0
#define PPE_XGMAC_REG_RX_CONFIG	       0x4
#define PPE_XGMAC_REG_PACKET_FILTER    0x8
#define PPE_XGMAC_REG_WATCHDOG_TIMEOUT 0xc
#define PPE_GMAC_REG_SPEED	       0x4
#define PPE_XGMAC_SPEED_10000	       0
#define PPE_XGMAC_SPEED_10000_USXGMII  4
#define PPE_XGMAC_SPEED_5000	       5
#define PPE_XGMAC_SPEED_2500	       2
#define PPE_XGMAC_SPEED_2500_USXGMII   6
#define PPE_XGMAC_SPEED_1000	       3
#define PPE_XGMAC_MAX_FRAME_SIZE       0x3000
#define PPE_XGMAC_MAX_RX_FRAME_SIZE    (PPE_XGMAC_MAX_FRAME_SIZE - 4)
#define PPE_GMAC_REG_MIB_CONTROL       0x34
#define PPE_XGMAC_REG_MMC_CONTROL      0x800

#define foreach_ppe_xgmac_rx_counter                                                               \
  _ (0x900, PACKETS_GB, "xgmac_rx_frames", 8, GENERIC, PACKETS)                                    \
  _ (0x908, BYTES_GB, "xgmac_rx_bytes", 8, GENERIC, BYTES)                                         \
  _ (0x910, BYTES_G, "xgmac_rx_bytes_g", 8, VENDOR, BYTES)                                         \
  _ (0x918, BROADCAST_G, "xgmac_rx_broadcast_g", 8, VENDOR, PACKETS)                               \
  _ (0x920, MULTICAST_G, "xgmac_rx_multicast_g", 8, VENDOR, PACKETS)                               \
  _ (0x928, CRC_ERROR, "xgmac_rx_crc_err", 8, VENDOR, PACKETS)                                     \
  _ (0x930, FRAGMENT_ERROR, "xgmac_rx_frag_err", 4, VENDOR, PACKETS)                               \
  _ (0x934, JABBER_ERROR, "xgmac_rx_jabber_err", 4, VENDOR, PACKETS)                               \
  _ (0x938, UNDERSIZE_G, "xgmac_rx_undersize_g", 4, VENDOR, PACKETS)                               \
  _ (0x93c, OVERSIZE_G, "xgmac_rx_oversize_g", 4, VENDOR, PACKETS)                                 \
  _ (0x940, PACKETS_64_GB, "xgmac_rx_pkt64", 8, VENDOR, PACKETS)                                   \
  _ (0x948, PACKETS_65_TO_127_GB, "xgmac_rx_pkt65to127", 8, VENDOR, PACKETS)                       \
  _ (0x950, PACKETS_128_TO_255_GB, "xgmac_rx_pkt128to255", 8, VENDOR, PACKETS)                     \
  _ (0x958, PACKETS_256_TO_511_GB, "xgmac_rx_pkt256to511", 8, VENDOR, PACKETS)                     \
  _ (0x960, PACKETS_512_TO_1023_GB, "xgmac_rx_pkt512to1023", 8, VENDOR, PACKETS)                   \
  _ (0x968, PACKETS_1024_TO_MAX_GB, "xgmac_rx_pkt1024tomax", 8, VENDOR, PACKETS)                   \
  _ (0x970, UNICAST_G, "xgmac_rx_unicast_g", 8, VENDOR, PACKETS)                                   \
  _ (0x978, LENGTH_ERROR, "xgmac_rx_len_err", 8, VENDOR, PACKETS)                                  \
  _ (0x980, OUT_OF_RANGE, "xgmac_rx_outofrange_err", 8, VENDOR, PACKETS)                           \
  _ (0x988, PAUSE, "xgmac_rx_pause", 8, VENDOR, PACKETS)                                           \
  _ (0x990, FIFO_OVERFLOW, "xgmac_rx_fifo_overflow", 8, VENDOR, PACKETS)                           \
  _ (0x998, VLAN_GB, "xgmac_rx_vlan", 8, VENDOR, PACKETS)                                          \
  _ (0x9a0, WATCHDOG_ERROR, "xgmac_rx_wdog_err", 4, VENDOR, PACKETS)                               \
  _ (0x9a4, LPI_USEC, "xgmac_rx_lpi_usec", 4, VENDOR, NA)                                          \
  _ (0x9a8, LPI_TRANSITIONS, "xgmac_rx_lpi_tran", 4, VENDOR, NA)                                   \
  _ (0x9ac, DISCARD_GB, "xgmac_rx_drop_frames", 8, VENDOR, PACKETS)                                \
  _ (0x9b4, DISCARD_BYTES_GB, "xgmac_rx_drop_bytes", 8, VENDOR, BYTES)

#define foreach_ppe_xgmac_tx_counter                                                               \
  _ (0x814, BYTES_GB, "xgmac_tx_bytes", 8, GENERIC, BYTES)                                         \
  _ (0x81c, PACKETS_GB, "xgmac_tx_frames", 8, GENERIC, PACKETS)                                    \
  _ (0x824, BROADCAST_G, "xgmac_tx_broadcast_g", 8, VENDOR, PACKETS)                               \
  _ (0x82c, MULTICAST_G, "xgmac_tx_multicast_g", 8, VENDOR, PACKETS)                               \
  _ (0x834, PACKETS_64_GB, "xgmac_tx_pkt64", 8, VENDOR, PACKETS)                                   \
  _ (0x83c, PACKETS_65_TO_127_GB, "xgmac_tx_pkt65to127", 8, VENDOR, PACKETS)                       \
  _ (0x844, PACKETS_128_TO_255_GB, "xgmac_tx_pkt128to255", 8, VENDOR, PACKETS)                     \
  _ (0x84c, PACKETS_256_TO_511_GB, "xgmac_tx_pkt256to511", 8, VENDOR, PACKETS)                     \
  _ (0x854, PACKETS_512_TO_1023_GB, "xgmac_tx_pkt512to1023", 8, VENDOR, PACKETS)                   \
  _ (0x85c, PACKETS_1024_TO_MAX_GB, "xgmac_tx_pkt1024tomax", 8, VENDOR, PACKETS)                   \
  _ (0x864, UNICAST_GB, "xgmac_tx_unicast", 8, VENDOR, PACKETS)                                    \
  _ (0x86c, MULTICAST_GB, "xgmac_tx_multicast", 8, VENDOR, PACKETS)                                \
  _ (0x874, BROADCAST_GB, "xgmac_tx_broadcast", 8, VENDOR, PACKETS)                                \
  _ (0x87c, UNDERFLOW_ERROR, "xgmac_tx_underflow_err", 8, VENDOR, PACKETS)                         \
  _ (0x884, BYTES_G, "xgmac_tx_bytes_g", 8, VENDOR, BYTES)                                         \
  _ (0x88c, PACKETS_G, "xgmac_tx_frames_g", 8, VENDOR, PACKETS)                                    \
  _ (0x894, PAUSE, "xgmac_tx_pause", 8, VENDOR, PACKETS)                                           \
  _ (0x89c, VLAN_G, "xgmac_tx_vlan_g", 8, VENDOR, PACKETS)                                         \
  _ (0x8a4, LPI_USEC, "xgmac_tx_lpi_usec", 4, VENDOR, NA)                                          \
  _ (0x8a8, LPI_TRANSITIONS, "xgmac_tx_lpi_tran", 4, VENDOR, NA)

#define foreach_ppe_gmac_rx_counter                                                                \
  _ (0x40, BROADCAST, "gmac_rx_broadcast", 4, VENDOR, PACKETS)                                     \
  _ (0x44, PAUSE, "gmac_rx_pause", 4, VENDOR, PACKETS)                                             \
  _ (0x48, MULTICAST, "gmac_rx_multicast", 4, VENDOR, PACKETS)                                     \
  _ (0x4c, FCS_ERROR, "gmac_rx_fcserr", 4, VENDOR, PACKETS)                                        \
  _ (0x50, ALIGN_ERROR, "gmac_rx_alignerr", 4, VENDOR, PACKETS)                                    \
  _ (0x54, RUNT, "gmac_rx_runt", 4, VENDOR, PACKETS)                                               \
  _ (0x58, FRAGMENT, "gmac_rx_frag", 4, VENDOR, PACKETS)                                           \
  _ (0x5c, JUMBO_FCS_ERROR, "gmac_rx_jumbofcserr", 4, VENDOR, PACKETS)                             \
  _ (0x60, JUMBO_ALIGN_ERROR, "gmac_rx_jumboalignerr", 4, VENDOR, PACKETS)                         \
  _ (0x64, PACKETS_64, "gmac_rx_pkt64", 4, VENDOR, PACKETS)                                        \
  _ (0x68, PACKETS_65_TO_127, "gmac_rx_pkt65to127", 4, VENDOR, PACKETS)                            \
  _ (0x6c, PACKETS_128_TO_255, "gmac_rx_pkt128to255", 4, VENDOR, PACKETS)                          \
  _ (0x70, PACKETS_256_TO_511, "gmac_rx_pkt256to511", 4, VENDOR, PACKETS)                          \
  _ (0x74, PACKETS_512_TO_1023, "gmac_rx_pkt512to1023", 4, VENDOR, PACKETS)                        \
  _ (0x78, PACKETS_1024_TO_1518, "gmac_rx_pkt1024to1518", 4, VENDOR, PACKETS)                      \
  _ (0x7c, PACKETS_1519_TO_X, "gmac_rx_pkt1519tomax", 4, VENDOR, PACKETS)                          \
  _ (0x80, TOO_LONG, "gmac_rx_toolong", 4, VENDOR, PACKETS)                                        \
  _ (0x84, BYTES_GOOD, "gmac_rx_bytes_g", 8, GENERIC, BYTES)                                       \
  _ (0x8c, BYTES_BAD, "gmac_rx_bytes_b", 8, VENDOR, BYTES)                                         \
  _ (0x94, UNICAST, "gmac_rx_unicast", 4, VENDOR, PACKETS)

#define foreach_ppe_gmac_tx_counter                                                                \
  _ (0xa0, BROADCAST, "gmac_tx_broadcast", 4, VENDOR, PACKETS)                                     \
  _ (0xa4, PAUSE, "gmac_tx_pause", 4, VENDOR, PACKETS)                                             \
  _ (0xa8, MULTICAST, "gmac_tx_multicast", 4, VENDOR, PACKETS)                                     \
  _ (0xac, UNDERRUN, "gmac_tx_underrun", 4, VENDOR, PACKETS)                                       \
  _ (0xb0, PACKETS_64, "gmac_tx_pkt64", 4, VENDOR, PACKETS)                                        \
  _ (0xb4, PACKETS_65_TO_127, "gmac_tx_pkt65to127", 4, VENDOR, PACKETS)                            \
  _ (0xb8, PACKETS_128_TO_255, "gmac_tx_pkt128to255", 4, VENDOR, PACKETS)                          \
  _ (0xbc, PACKETS_256_TO_511, "gmac_tx_pkt256to511", 4, VENDOR, PACKETS)                          \
  _ (0xc0, PACKETS_512_TO_1023, "gmac_tx_pkt512to1023", 4, VENDOR, PACKETS)                        \
  _ (0xc4, PACKETS_1024_TO_1518, "gmac_tx_pkt1024to1518", 4, VENDOR, PACKETS)                      \
  _ (0xc8, PACKETS_1519_TO_X, "gmac_tx_pkt1519tomax", 4, VENDOR, PACKETS)                          \
  _ (0xcc, BYTES, "gmac_tx_bytes", 8, GENERIC, BYTES)                                              \
  _ (0xd4, COLLISIONS, "gmac_tx_collisions", 4, VENDOR, NA)                                        \
  _ (0xd8, ABORT_COLLISIONS, "gmac_tx_abortcol", 4, VENDOR, NA)                                    \
  _ (0xdc, MULTIPLE_COLLISIONS, "gmac_tx_multicol", 4, VENDOR, NA)                                 \
  _ (0xe0, SINGLE_COLLISIONS, "gmac_tx_singlecol", 4, VENDOR, NA)                                  \
  _ (0xe4, EXCESSIVE_DEFER, "gmac_tx_excdeffer", 4, VENDOR, NA)                                    \
  _ (0xe8, DEFER, "gmac_tx_deffer", 4, VENDOR, NA)                                                 \
  _ (0xec, LATE_COLLISION, "gmac_tx_latecol", 4, VENDOR, NA)                                       \
  _ (0xf0, UNICAST, "gmac_tx_unicast", 4, VENDOR, PACKETS)

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

/* PPE_REG_IN_L2_SERVICE_TBL word 0: egress_bypass_bitmap bit positions match
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

typedef struct
{
  ppe_reg_gmac_enable_t gmac_enable;
  ppe_reg_gmac_speed_t gmac_speed;
  ppe_reg_xgmac_tx_config_t xgmac_tx_config;
  ppe_reg_xgmac_rx_config_t xgmac_rx_config;
  ppe_reg_port_bridge_ctrl_t port_bridge_ctrl;
} ppe_hw_port_state_t;
