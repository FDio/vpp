/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

/* This is the only supported PPE variant; the compatible string serves as its revision ID. */
#define QPPE_DT_COMPATIBLE			"qcom,ipq9574-ppe"
#define QPPE_MAX_PORTS				8
#define QPPE_CLOCK_RATE				353000000
#define QPPE_EDMA_RESET_DELAY_US		100
#define QPPE_EDMA_BASE_OFFSET			0xb00000
#define QPPE_EDMA_REG_MAS_CTRL_ADDR		0x0
#define QPPE_EDMA_REG_PORT_CTRL_ADDR		0x4
#define QPPE_EDMA_REG_RXFILL_BA(ring)		(0x29000 + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXFILL_RING_SIZE(ring)	(0x2900c + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXFILL_RING_EN(ring)	(0x2901c + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXDESC_BA(ring)		(0x39000 + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXDESC_PREHEADER_BA(ring) (0x39028 + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXDESC_RING_SIZE(ring)	(0x3900c + (0x1000 * (ring)))
#define QPPE_EDMA_REG_RXDESC_CTRL(ring)		(0x39018 + (0x1000 * (ring)))
#define QPPE_EDMA_RX_BUFFER_SIZE		1984
#define QPPE_EDMA_RXFILL_RING_ID		4
#define QPPE_EDMA_RXDESC_RING_ID		20

#define QPPE_REG_PORT_MUX_CONTROL	 0x10
#define QPPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290
#define QPPE_REG_GMAC_ENABLE(port)	 (0x1000 + ((port) - 1) * 0x200)
#define QPPE_REG_GMAC_BASE(port)	 (0x001000 + ((port) - 1) * 0x200)
#define QPPE_REG_XGMAC_BASE(port)	 (0x500000 + ((port) - 1) * 0x4000)
#define QPPE_GMAC_REG_MIB_CONTROL	 0x34
#define QPPE_GMAC_REG_RX_BYTES_GOOD	 0x84
#define QPPE_GMAC_REG_RX_UNICAST	 0x94
#define QPPE_GMAC_REG_RX_BROADCAST	 0x40
#define QPPE_GMAC_REG_RX_MULTICAST	 0x48
#define QPPE_GMAC_REG_TX_BYTES		 0xcc
#define QPPE_GMAC_REG_TX_UNICAST	 0xf0
#define QPPE_GMAC_REG_TX_BROADCAST	 0xa0
#define QPPE_GMAC_REG_TX_MULTICAST	 0xa8
#define QPPE_XGMAC_REG_MMC_CONTROL	 0x800
#define QPPE_XGMAC_REG_TX_BYTES		 0x814
#define QPPE_XGMAC_REG_TX_PACKETS	 0x81c
#define QPPE_XGMAC_REG_RX_BROADCAST	 0x918
#define QPPE_XGMAC_REG_RX_MULTICAST	 0x920
#define QPPE_XGMAC_REG_RX_BYTES		 0x908
#define QPPE_XGMAC_REG_RX_UNICAST	 0x970

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
} qppe_reg_port_mux_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 shared_buffer_limit : 11;
    u32 reserved_11 : 21;
  } fields;
} qppe_reg_bm_shared_group_config_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 tx_enable : 1;
    u32 reserved_2 : 30;
  } fields;
} qppe_reg_gmac_enable_t;

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
} qppe_reg_xgmac_mmc_control_t;

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
} qppe_reg_gmac_mib_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 version : 32;
  } fields;
} qppe_reg_edma_master_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_padding_enable : 1;
    u32 edma_enable : 1;
    u32 reserved_2 : 30;
  } fields;
} qppe_reg_edma_port_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 dma_address : 32;
  } fields;
} qppe_reg_edma_ring_base_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 reserved_16 : 16;
  } fields;
} qppe_reg_edma_rxfill_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 preheader_offset : 9;
    u32 reserved_25 : 7;
  } fields;
} qppe_reg_edma_rxdesc_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reserved_1 : 31;
  } fields;
} qppe_reg_edma_rxfill_ring_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 reserved_1 : 31;
  } fields;
} qppe_reg_edma_rxdesc_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 buffer_address : 32;
  } fields;
} qppe_edma_dma_address_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 reserved_0 : 16;
    u32 buffer_size : 16;
  } fields;
} qppe_edma_rxfill_length_t;

typedef struct
{
  qppe_edma_dma_address_t buffer_address;
  qppe_edma_rxfill_length_t length;
  u32 opaque_low;
  u32 opaque_high;
} qppe_edma_rxfill_desc_t;

typedef struct
{
  u32 words[8];
} qppe_edma_rx_desc_t;

typedef struct
{
  qppe_reg_port_mux_control_t port_mux_control;
  qppe_reg_bm_shared_group_config_t bm_shared_group0_config;
  qppe_reg_edma_master_control_t edma_master_control;
  qppe_reg_edma_port_control_t edma_port_control;
} qppe_hw_device_state_t;

STATIC_ASSERT_SIZEOF (qppe_edma_rxfill_desc_t, 16);
STATIC_ASSERT_SIZEOF (qppe_edma_rx_desc_t, 32);

typedef struct
{
  qppe_reg_gmac_enable_t gmac_enable;
} qppe_hw_port_state_t;
