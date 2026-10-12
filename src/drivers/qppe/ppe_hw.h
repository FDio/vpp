/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

/* This is the only supported PPE variant; the compatible string serves as its revision ID. */
#define QPPE_DT_COMPATIBLE	    "qcom,ipq9574-ppe"
#define QPPE_MAX_PORTS		    8
#define QPPE_CLOCK_RATE		    353000000
#define QPPE_EDMA_RESET_DELAY_US    100
#define QPPE_EDMA_BASE_OFFSET	    0xb00000
#define QPPE_EDMA_REG_MAS_CTRL_ADDR 0x0

#define QPPE_REG_PORT_MUX_CONTROL	0x10
#define QPPE_PORT_MUX_XGMAC_SELECT_MASK 0x3f00
#define QPPE_PORT_MUX_PORT5_PCS1_SELECT (1 << 4)

#define QPPE_REG_BM_SHARED_GROUP0_CONFIG 0x600290
#define QPPE_BM_SHARED_GROUP_LIMIT_MASK	 0x7ff

#define QPPE_REG_GMAC_ENABLE(port) (0x1000 + ((port) - 1) * 0x200)
#define QPPE_GMAC_TX_ENABLE	   (1 << 1)
#define QPPE_GMAC_RX_ENABLE	   (1 << 0)

typedef struct
{
  u32 port_mux_control;
  u32 bm_shared_group0_config;
  u32 edma_version;
} qppe_hw_device_state_t;

typedef struct
{
  u32 gmac_enable;
} qppe_hw_port_state_t;
