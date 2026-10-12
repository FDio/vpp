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
#define PPE_CLOCK_RATE				   353000000
#define PPE_EDMA_RESET_DELAY_US			   100
#define PPE_PORT_RESET_DELAY_US			   10000
#define PPE_EDMA_BASE_OFFSET			   0xb00000
#define PPE_EDMA_REG_MAS_CTRL_ADDR		   0x0
#define PPE_EDMA_REG_PORT_CTRL_ADDR		   0x4
#define PPE_EDMA_REG_RXFILL_BA(ring)		   (0x29000 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXFILL_PROD_IDX(ring)	   (0x29004 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXFILL_RING_SIZE(ring)	   (0x2900c + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXFILL_RING_EN(ring)	   (0x2901c + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_BA(ring)		   (0x39000 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_PROD_IDX(ring)	   (0x39004 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_CONS_IDX(ring)	   (0x39008 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_PREHEADER_BA(ring)	   (0x39028 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_RING_SIZE(ring)	   (0x3900c + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC_CTRL(ring)		   (0x39018 + (0x1000 * (ring)))
#define PPE_EDMA_REG_RX_INT_CTRL(ring)		   (0x5900c + (0x1000 * (ring)))
#define PPE_EDMA_REG_RXDESC2FILL_MAP_0		   0x14
#define PPE_EDMA_REG_QID2RID_TABLE(qid)		   (0xb9000 + (0x4 * ((qid) / 4)))
#define PPE_REG_RING_Q_MAP_TBL(ring)		   (0x42a000 + (0x40 * (ring)))
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
#define PPE_REG_VSI_TBL_W0(vsi)	      (0x063800 + (0x10 * (vsi)))
/* indexed by (dst_phy_port << 6) | vsi; resolves a VSI-flooded frame's CPU delivery
 * to a virtual port (enqueue_vp), which then gets its own UCAST_QUEUE_MAP_TBL row. */
#define PPE_REG_PORT_VSI_ENQUEUE_MAP(port, vsi) (0x09d000 + (0x4 * (((port) << 6) | (vsi))))
/* per physical port; governs where a frame goes when its ingress classification
 * fails to resolve a valid VSI at all - a separate fallback from VSI_TBL-based
 * flooding, e.g. for a destination-unknown unicast frame before it even reaches
 * the flood decision. */
#define PPE_REG_L2_VP_PORT_TBL_W0(port) (0x098000 + (0x10 * (port)))
#define PPE_EDMA_CPU_PORT_ID		0
/* PPE virtual ports start at 64; physical ports never reach that high. */
#define PPE_EDMA_VP_BASE		      64
#define PPE_EDMA_RING_Q_MAP_WORDS	      10
#define PPE_EDMA_RX_QUEUE_ID_COUNT	      32
#define PPE_EDMA_QID2RID_WORD_COUNT	      (PPE_EDMA_RX_QUEUE_ID_COUNT / 4)
#define PPE_CPU_MCAST_QUEUE_START	      256
#define PPE_CPU_MCAST_QUEUE_COUNT	      16
#define PPE_CPU_MCAST_QUEUES_PER_PROFILE      (PPE_CPU_MCAST_QUEUE_COUNT / PPE_EDMA_RX_RING_COUNT)
#define PPE_EDMA_REG_RX_RING_INDEX_MASK	      0x1f
#define PPE_EDMA_RX_PROD_CONS_MASK	      0xffff
#define PPE_EDMA_QID2RID_WORD(q0, q1, q2, q3) ((q0) | ((q1) << 8) | ((q2) << 16) | ((q3) << 24))
#define PPE_EDMA_RX_QUEUES_PER_RING	      8
#define PPE_EDMA_RXFILL_RING_PRODUCER_START   0
#define PPE_EDMA_RXFILL_RING_START	      4
#define PPE_EDMA_RXDESC_RING_START	      20
#define PPE_EDMA_RX_RING_COUNT		      4
#define PPE_EDMA_RX_NE_INT_EN		      0x2

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0_1 : 2;
    u32 source_profile : 2;
    u32 reserved_4_31 : 28;
  };
} ppe_reg_mru_mtu_ctrl_w1_t;

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
    u32 enqueue_vp : 8;
    u32 enqueue_valid : 1;
    u32 reserved_9_31 : 23;
  };
} ppe_reg_port_vsi_enqueue_map_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 invalid_vsi_forwarding_en : 1;
    u32 promisc_en : 1;
    u32 dst_info : 8;
    u32 reserved_10_31 : 22;
  };
} ppe_reg_l2_vp_port_tbl_w0_t;

#define PPE_REG_PORT_MUX_CONTROL	0x10
#define PPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290
#define PPE_REG_GMAC_ENABLE(port)	(0x1000 + ((port) - 1) * 0x200)
#define PPE_REG_GMAC_BASE(port)		(0x001000 + ((port) - 1) * 0x200)
#define PPE_REG_XGMAC_BASE(port)	(0x500000 + ((port) - 1) * 0x4000)
#define PPE_REG_MC_MTU_CTRL_TBL(port)	(0x60a00 + (0x4 * (port)))
#define PPE_REG_MRU_MTU_CTRL_W0(port)	(0x65000 + (0x10 * (port)))
#define PPE_MC_MTU_CTRL_TBL_MTU_MASK	0x00003fff
#define PPE_MRU_MTU_CTRL_W0_MRU_MASK	0x00003fff
#define PPE_MRU_MTU_CTRL_W0_MTU_MASK	0x3fff0000
#define PPE_XGMAC_REG_TX_CONFIG		0x0
#define PPE_XGMAC_REG_RX_CONFIG		0x4
#define PPE_XGMAC_REG_PACKET_FILTER	0x8
#define PPE_XGMAC_REG_WATCHDOG_TIMEOUT	0xc
#define PPE_GMAC_REG_SPEED		0x4
#define PPE_XGMAC_SPEED_10000		0
#define PPE_XGMAC_SPEED_10000_USXGMII	4
#define PPE_XGMAC_SPEED_5000		5
#define PPE_XGMAC_SPEED_2500		2
#define PPE_XGMAC_SPEED_2500_USXGMII	6
#define PPE_XGMAC_SPEED_1000		3
#define PPE_XGMAC_MAX_FRAME_SIZE	0x3000
#define PPE_XGMAC_MAX_RX_FRAME_SIZE	(PPE_XGMAC_MAX_FRAME_SIZE - 4)
#define PPE_GMAC_REG_MIB_CONTROL	0x34
#define PPE_XGMAC_REG_MMC_CONTROL	0x800

#define foreach_ppe_xgmac_rx_counter                                                               \
  _ (0x900, PACKETS_GB, "rx_frames", 8, GENERIC, PACKETS)                                          \
  _ (0x908, BYTES_GB, "rx_bytes", 8, GENERIC, BYTES)                                               \
  _ (0x910, BYTES_G, "rx_bytes_g", 8, VENDOR, BYTES)                                               \
  _ (0x918, BROADCAST_G, "rx_broadcast_g", 8, VENDOR, PACKETS)                                     \
  _ (0x920, MULTICAST_G, "rx_multicast_g", 8, VENDOR, PACKETS)                                     \
  _ (0x928, CRC_ERROR, "rx_crc_err", 8, VENDOR, PACKETS)                                           \
  _ (0x930, FRAGMENT_ERROR, "rx_frag_err", 4, VENDOR, PACKETS)                                     \
  _ (0x934, JABBER_ERROR, "rx_jabber_err", 4, VENDOR, PACKETS)                                     \
  _ (0x938, UNDERSIZE_G, "rx_undersize_g", 4, VENDOR, PACKETS)                                     \
  _ (0x93c, OVERSIZE_G, "rx_oversize_g", 4, VENDOR, PACKETS)                                       \
  _ (0x940, PACKETS_64_GB, "rx_pkt64", 8, VENDOR, PACKETS)                                         \
  _ (0x948, PACKETS_65_TO_127_GB, "rx_pkt65to127", 8, VENDOR, PACKETS)                             \
  _ (0x950, PACKETS_128_TO_255_GB, "rx_pkt128to255", 8, VENDOR, PACKETS)                           \
  _ (0x958, PACKETS_256_TO_511_GB, "rx_pkt256to511", 8, VENDOR, PACKETS)                           \
  _ (0x960, PACKETS_512_TO_1023_GB, "rx_pkt512to1023", 8, VENDOR, PACKETS)                         \
  _ (0x968, PACKETS_1024_TO_MAX_GB, "rx_pkt1024tomax", 8, VENDOR, PACKETS)                         \
  _ (0x970, UNICAST_G, "rx_unicast_g", 8, VENDOR, PACKETS)                                         \
  _ (0x978, LENGTH_ERROR, "rx_len_err", 8, VENDOR, PACKETS)                                        \
  _ (0x980, OUT_OF_RANGE, "rx_outofrange_err", 8, VENDOR, PACKETS)                                 \
  _ (0x988, PAUSE, "rx_pause", 8, VENDOR, PACKETS)                                                 \
  _ (0x990, FIFO_OVERFLOW, "rx_fifo_overflow", 8, VENDOR, PACKETS)                                 \
  _ (0x998, VLAN_GB, "rx_vlan", 8, VENDOR, PACKETS)                                                \
  _ (0x9a0, WATCHDOG_ERROR, "rx_wdog_err", 4, VENDOR, PACKETS)                                     \
  _ (0x9a4, LPI_USEC, "rx_lpi_usec", 4, VENDOR, NA)                                                \
  _ (0x9a8, LPI_TRANSITIONS, "rx_lpi_tran", 4, VENDOR, NA)                                         \
  _ (0x9ac, DISCARD_GB, "rx_drop_frames", 8, VENDOR, PACKETS)                                      \
  _ (0x9b4, DISCARD_BYTES_GB, "rx_drop_bytes", 8, VENDOR, BYTES)

#define foreach_ppe_xgmac_tx_counter                                                               \
  _ (0x814, BYTES_GB, "tx_bytes", 8, GENERIC, BYTES)                                               \
  _ (0x81c, PACKETS_GB, "tx_frames", 8, GENERIC, PACKETS)                                          \
  _ (0x824, BROADCAST_G, "tx_broadcast_g", 8, VENDOR, PACKETS)                                     \
  _ (0x82c, MULTICAST_G, "tx_multicast_g", 8, VENDOR, PACKETS)                                     \
  _ (0x834, PACKETS_64_GB, "tx_pkt64", 8, VENDOR, PACKETS)                                         \
  _ (0x83c, PACKETS_65_TO_127_GB, "tx_pkt65to127", 8, VENDOR, PACKETS)                             \
  _ (0x844, PACKETS_128_TO_255_GB, "tx_pkt128to255", 8, VENDOR, PACKETS)                           \
  _ (0x84c, PACKETS_256_TO_511_GB, "tx_pkt256to511", 8, VENDOR, PACKETS)                           \
  _ (0x854, PACKETS_512_TO_1023_GB, "tx_pkt512to1023", 8, VENDOR, PACKETS)                         \
  _ (0x85c, PACKETS_1024_TO_MAX_GB, "tx_pkt1024tomax", 8, VENDOR, PACKETS)                         \
  _ (0x864, UNICAST_GB, "tx_unicast", 8, VENDOR, PACKETS)                                          \
  _ (0x86c, MULTICAST_GB, "tx_multicast", 8, VENDOR, PACKETS)                                      \
  _ (0x874, BROADCAST_GB, "tx_broadcast", 8, VENDOR, PACKETS)                                      \
  _ (0x87c, UNDERFLOW_ERROR, "tx_underflow_err", 8, VENDOR, PACKETS)                               \
  _ (0x884, BYTES_G, "tx_bytes_g", 8, VENDOR, BYTES)                                               \
  _ (0x88c, PACKETS_G, "tx_frames_g", 8, VENDOR, PACKETS)                                          \
  _ (0x894, PAUSE, "tx_pause", 8, VENDOR, PACKETS)                                                 \
  _ (0x89c, VLAN_G, "tx_vlan_g", 8, VENDOR, PACKETS)                                               \
  _ (0x8a4, LPI_USEC, "tx_lpi_usec", 4, VENDOR, NA)                                                \
  _ (0x8a8, LPI_TRANSITIONS, "tx_lpi_tran", 4, VENDOR, NA)

#define foreach_ppe_gmac_rx_counter                                                                \
  _ (0x40, BROADCAST, "rx_broadcast", 4, VENDOR, PACKETS)                                          \
  _ (0x44, PAUSE, "rx_pause", 4, VENDOR, PACKETS)                                                  \
  _ (0x48, MULTICAST, "rx_multicast", 4, VENDOR, PACKETS)                                          \
  _ (0x4c, FCS_ERROR, "rx_fcserr", 4, VENDOR, PACKETS)                                             \
  _ (0x50, ALIGN_ERROR, "rx_alignerr", 4, VENDOR, PACKETS)                                         \
  _ (0x54, RUNT, "rx_runt", 4, VENDOR, PACKETS)                                                    \
  _ (0x58, FRAGMENT, "rx_frag", 4, VENDOR, PACKETS)                                                \
  _ (0x5c, JUMBO_FCS_ERROR, "rx_jumbofcserr", 4, VENDOR, PACKETS)                                  \
  _ (0x60, JUMBO_ALIGN_ERROR, "rx_jumboalignerr", 4, VENDOR, PACKETS)                              \
  _ (0x64, PACKETS_64, "rx_pkt64", 4, VENDOR, PACKETS)                                             \
  _ (0x68, PACKETS_65_TO_127, "rx_pkt65to127", 4, VENDOR, PACKETS)                                 \
  _ (0x6c, PACKETS_128_TO_255, "rx_pkt128to255", 4, VENDOR, PACKETS)                               \
  _ (0x70, PACKETS_256_TO_511, "rx_pkt256to511", 4, VENDOR, PACKETS)                               \
  _ (0x74, PACKETS_512_TO_1023, "rx_pkt512to1023", 4, VENDOR, PACKETS)                             \
  _ (0x78, PACKETS_1024_TO_1518, "rx_pkt1024to1518", 4, VENDOR, PACKETS)                           \
  _ (0x7c, PACKETS_1519_TO_X, "rx_pkt1519tomax", 4, VENDOR, PACKETS)                               \
  _ (0x80, TOO_LONG, "rx_toolong", 4, VENDOR, PACKETS)                                             \
  _ (0x84, BYTES_GOOD, "rx_bytes_g", 8, GENERIC, BYTES)                                            \
  _ (0x8c, BYTES_BAD, "rx_bytes_b", 8, VENDOR, BYTES)                                              \
  _ (0x94, UNICAST, "rx_unicast", 4, VENDOR, PACKETS)

#define foreach_ppe_gmac_tx_counter                                                                \
  _ (0xa0, BROADCAST, "tx_broadcast", 4, VENDOR, PACKETS)                                          \
  _ (0xa4, PAUSE, "tx_pause", 4, VENDOR, PACKETS)                                                  \
  _ (0xa8, MULTICAST, "tx_multicast", 4, VENDOR, PACKETS)                                          \
  _ (0xac, UNDERRUN, "tx_underrun", 4, VENDOR, PACKETS)                                            \
  _ (0xb0, PACKETS_64, "tx_pkt64", 4, VENDOR, PACKETS)                                             \
  _ (0xb4, PACKETS_65_TO_127, "tx_pkt65to127", 4, VENDOR, PACKETS)                                 \
  _ (0xb8, PACKETS_128_TO_255, "tx_pkt128to255", 4, VENDOR, PACKETS)                               \
  _ (0xbc, PACKETS_256_TO_511, "tx_pkt256to511", 4, VENDOR, PACKETS)                               \
  _ (0xc0, PACKETS_512_TO_1023, "tx_pkt512to1023", 4, VENDOR, PACKETS)                             \
  _ (0xc4, PACKETS_1024_TO_1518, "tx_pkt1024to1518", 4, VENDOR, PACKETS)                           \
  _ (0xc8, PACKETS_1519_TO_X, "tx_pkt1519tomax", 4, VENDOR, PACKETS)                               \
  _ (0xcc, BYTES, "tx_bytes", 8, GENERIC, BYTES)                                                   \
  _ (0xd4, COLLISIONS, "tx_collisions", 4, VENDOR, NA)                                             \
  _ (0xd8, ABORT_COLLISIONS, "tx_abortcol", 4, VENDOR, NA)                                         \
  _ (0xdc, MULTIPLE_COLLISIONS, "tx_multicol", 4, VENDOR, NA)                                      \
  _ (0xe0, SINGLE_COLLISIONS, "tx_singlecol", 4, VENDOR, NA)                                       \
  _ (0xe4, EXCESSIVE_DEFER, "tx_excdeffer", 4, VENDOR, NA)                                         \
  _ (0xe8, DEFER, "tx_deffer", 4, VENDOR, NA)                                                      \
  _ (0xec, LATE_COLLISION, "tx_latecol", 4, VENDOR, NA)                                            \
  _ (0xf0, UNICAST, "tx_unicast", 4, VENDOR, PACKETS)

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

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_padding_enable : 1;
    u32 edma_enable : 1;
    u32 reserved_2 : 30;
  };
} ppe_reg_edma_port_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 preheader_offset : 9;
    u32 reserved_25 : 7;
  };
} ppe_reg_edma_rxdesc_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_edma_rxfill_ring_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_edma_rxdesc_control_t;

#define PPE_EDMA_RX_SOURCE_TYPE_PORT_ID	 2
#define PPE_EDMA_RX_SOURCE_TYPE_GEM_PORT 0

typedef struct
{
  u32 buffer_address;
  u16 _reserved_1_0_15;
  u16 buffer_size;
  u32 opaque_low;
  u32 opaque_high;
} ppe_edma_rxfill_desc_t;

typedef union
{
  u32 as_u32;
  struct
  {
    /* word 7: vendor struct comment names this word "DSCP, packet offsets"; only
     * l3_offset and pid have documented bit-level accessors, so the DSCP sub-range
     * is left unparsed rather than guessed at. */
    u32 _unparsed_7_0_15 : 16;
    u32 l3_offset : 7;
    /* pid is a packet-format identifier used for checksum handling (0x0-0x3 = IPv4
     * variants, bit 2 set = IPv6), not a priority value. */
    u32 pid : 4;
    u32 _unparsed_7_27_31 : 5;
  };
} ppe_edma_rx_metadata_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0 */
    u32 buffer_address;

    /* word 1: bits 16-29 (service_code, acl_idx_valid, int_pri below) are instead read
     * as a single 14-bit ACL index when acl_idx_valid is set. */
    u32 buffer_address_hi : 8;
    u32 _unparsed_1_8_9 : 2;
    u32 fake_mac : 1;
    u32 _unparsed_1_11 : 1;
    u32 cpu_code_valid : 1;
    u32 _unparsed_1_13_15 : 3;
    u32 service_code : 9;
    u32 acl_idx_valid : 1;
    u32 int_pri : 4;
    u32 more : 1;
    u32 _unparsed_1_31 : 1;

    /* word 2 */
    u32 opaque_low;

    /* word 3 */
    u32 opaque_high;

    /* word 4 */
    u32 source_port_id : 12;
    u32 source_type : 4;
    u32 destination_port_id : 12;
    u32 destination_type : 4;

    /* word 5: for WiFi-sourced traffic the top byte (bits 24-31) is instead read as a
     * WiFi QoS value, overlapping the top 2 bits of cpu_code. */
    u32 packet_length : 16;
    u32 cpu_code : 10;
    u32 _unparsed_5_26_31 : 6;

    /* word 6: vendor struct comment names this word "hash value, check sum status";
     * only the checksum status bits have documented accessors, so the hash value
     * sub-range is left unparsed rather than guessed at. */
    u32 data_offset : 12;
    u32 l4_checksum_status : 1;
    u32 l3_checksum_status : 1;
    u32 _unparsed_6_14_31 : 18;

    /* word 7 */
    ppe_edma_rx_metadata_t metadata;
  };
} ppe_edma_rx_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0 */
    u32 timestamp_lo;

    /* word 1 */
    u32 timestamp_hi : 8;
    u32 _unparsed_1_8_31 : 24;

    /* word 2: vendor struct comment names this word "QoS tag"; no bit-level accessor
     * is documented for it. */
    u32 qos_tag;

    /* word 3 */
    u32 flow_idx : 20;
    u32 flow_idx_valid : 1;
    u32 _unparsed_3_22 : 1;
    u32 timestamp_valid : 1;
    u32 _unparsed_3_24_31 : 8;

    /* word 4: vendor struct comment names this word "secondary packet offsets"; no
     * bit-level accessor is documented for it. */
    u32 secondary_packet_offsets;

    /* word 5: vendor struct comment names this word "multicast bit, checksum"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_5;

    /* word 6: vendor struct comment names this word "SVLAN, CVLAN"; no bit-level
     * accessor is documented for it. */
    u32 _unparsed_6;

    /* word 7: vendor struct comment names this word "secondary SVLAN, CVLAN"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_7;
  };
} ppe_edma_rx_sec_desc_t;

typedef struct
{
  ppe_reg_port_mux_control_t port_mux_control;
  ppe_reg_bm_shared_group_config_t bm_shared_group0_config;
  u32 edma_version;
  ppe_reg_edma_port_control_t edma_port_control;
} ppe_hw_device_state_t;

STATIC_ASSERT_SIZEOF (ppe_edma_rxfill_desc_t, 16);
STATIC_ASSERT_SIZEOF (ppe_edma_rx_metadata_t, 4);
STATIC_ASSERT_SIZEOF (ppe_edma_rx_desc_t, 32);
STATIC_ASSERT_SIZEOF (ppe_edma_rx_sec_desc_t, 32);

typedef struct
{
  ppe_reg_gmac_enable_t gmac_enable;
  ppe_reg_gmac_speed_t gmac_speed;
  ppe_reg_xgmac_tx_config_t xgmac_tx_config;
  ppe_reg_xgmac_rx_config_t xgmac_rx_config;
} ppe_hw_port_state_t;
