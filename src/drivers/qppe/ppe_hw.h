/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

/* This is the only supported PPE variant; the compatible string serves as its revision ID. */
#define PPE_DT_COMPATIBLE			   "qcom,ipq9574-ppe"
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
#define PPE_EDMA_RING_Q_MAP_WORDS	      10
#define PPE_EDMA_RX_QUEUE_ID_COUNT	      32
#define PPE_EDMA_QID2RID_WORD_COUNT	      (PPE_EDMA_RX_QUEUE_ID_COUNT / 4)
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
  } fields;
} ppe_reg_mru_mtu_ctrl_w1_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 profile_id : 4;
    u32 queue_id : 8;
    u32 reserved_12_31 : 20;
  } fields;
} ppe_reg_ucast_queue_map_t;

#define PPE_REG_PORT_MUX_CONTROL	0x10
#define PPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290
#define PPE_REG_GMAC_ENABLE(port)	(0x1000 + ((port) - 1) * 0x200)
#define PPE_REG_GMAC_BASE(port)		(0x001000 + ((port) - 1) * 0x200)
#define PPE_REG_XGMAC_BASE(port)	(0x500000 + ((port) - 1) * 0x4000)
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
#define PPE_GMAC_REG_MIB_CONTROL	0x34
#define PPE_GMAC_REG_RX_BYTES_GOOD	0x84
#define PPE_GMAC_REG_RX_UNICAST		0x94
#define PPE_GMAC_REG_RX_BROADCAST	0x40
#define PPE_GMAC_REG_RX_MULTICAST	0x48
#define PPE_GMAC_REG_TX_BYTES		0xcc
#define PPE_GMAC_REG_TX_UNICAST		0xf0
#define PPE_GMAC_REG_TX_BROADCAST	0xa0
#define PPE_GMAC_REG_TX_MULTICAST	0xa8
#define PPE_XGMAC_REG_MMC_CONTROL	0x800
#define PPE_XGMAC_REG_TX_BYTES		0x814
#define PPE_XGMAC_REG_TX_PACKETS	0x81c
#define PPE_XGMAC_REG_RX_BROADCAST	0x918
#define PPE_XGMAC_REG_RX_MULTICAST	0x920
#define PPE_XGMAC_REG_RX_BYTES		0x908
#define PPE_XGMAC_REG_RX_UNICAST	0x970

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
  } fields;
} ppe_reg_port_mux_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 shared_buffer_limit : 11;
    u32 reserved_11 : 21;
  } fields;
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
  } fields;
} ppe_reg_gmac_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 speed : 2;
    u32 reserved_2_31 : 30;
  } fields;
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
  } fields;
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
  } fields;
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
  } fields;
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
  } fields;
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
  } fields;
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
  } fields;
} ppe_reg_gmac_mib_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 version : 32;
  } fields;
} ppe_reg_edma_master_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_padding_enable : 1;
    u32 edma_enable : 1;
    u32 reserved_2 : 30;
  } fields;
} ppe_reg_edma_port_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 dma_address : 32;
  } fields;
} ppe_reg_edma_ring_base_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 reserved_16 : 16;
  } fields;
} ppe_reg_edma_rxfill_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 preheader_offset : 9;
    u32 reserved_25 : 7;
  } fields;
} ppe_reg_edma_rxdesc_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reserved_1 : 31;
  } fields;
} ppe_reg_edma_rxfill_ring_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 reserved_1 : 31;
  } fields;
} ppe_reg_edma_rxdesc_control_t;

#define PPE_EDMA_RX_SOURCE_TYPE_PORT_ID 2

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
    u32 _unparsed_7_0_11 : 12;
    u32 pid : 4;
    u32 l3_offset : 8;
    u32 _unparsed_7_24_31 : 8;
  } fields;
} ppe_edma_rx_metadata_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0 */
    u32 buffer_address;

    /* word 1 */
    u32 _unparsed_1_0_29 : 30;
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

    /* word 5 */
    u32 packet_length : 18;
    u32 _unparsed_5_18_31 : 14;

    /* word 6 */
    u32 data_offset : 12;
    u32 l4_checksum_status : 1;
    u32 l3_checksum_status : 1;
    u32 _unparsed_6_14_31 : 18;

    /* word 7 */
    ppe_edma_rx_metadata_t metadata;
  };
} ppe_edma_rx_desc_t;

typedef struct
{
  ppe_reg_port_mux_control_t port_mux_control;
  ppe_reg_bm_shared_group_config_t bm_shared_group0_config;
  ppe_reg_edma_master_control_t edma_master_control;
  ppe_reg_edma_port_control_t edma_port_control;
} ppe_hw_device_state_t;

STATIC_ASSERT_SIZEOF (ppe_edma_rxfill_desc_t, 16);
STATIC_ASSERT_SIZEOF (ppe_edma_rx_metadata_t, 4);
STATIC_ASSERT_SIZEOF (ppe_edma_rx_desc_t, 32);

typedef struct
{
  ppe_reg_gmac_enable_t gmac_enable;
  ppe_reg_gmac_speed_t gmac_speed;
  ppe_reg_xgmac_tx_config_t xgmac_tx_config;
  ppe_reg_xgmac_rx_config_t xgmac_rx_config;
} ppe_hw_port_state_t;
