/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <vppinfra/types.h>
#include <vnet/dev/types.h>

typedef u64 dma_addr_t;
typedef u64 phys_addr_t;

typedef struct vlib_main_t vlib_main_t;

#define MV_MH_SIZE		      2
#define MV_ETH_ALEN		      6
#define MV_SYS_DMA_MAX_NUM_MEM_ID     4
#define PP2_MAX_FIELDS_SUPPORTED      2
#define PP2_PPIO_MAX_NUM_TCS	      32
#define PP2_PPIO_MAX_NUM_INQS	      32
#define PP2_PPIO_MAX_NUM_OUTQS	      8
#define PP2_PPIO_TC_CLUSTER_MAX_POOLS 2

typedef u8 eth_addr_t[MV_ETH_ALEN];

enum mv_net_link_speed
{
  MV_NET_LINK_SPEED_AN = 0,
  MV_NET_LINK_SPEED_10,
  MV_NET_LINK_SPEED_100,
  MV_NET_LINK_SPEED_1000,
  MV_NET_LINK_SPEED_2500,
  MV_NET_LINK_SPEED_10000,
};

enum mv_net_link_duplex
{
  MV_NET_LINK_DUPLEX_AN = 0,
  MV_NET_LINK_DUPLEX_HALF,
  MV_NET_LINK_DUPLEX_FULL,
};

enum mv_net_phy_mode
{
  MV_NET_PHY_MODE_NONE = 0,
  MV_NET_PHY_MODE_MII,
  MV_NET_PHY_MODE_GMII,
  MV_NET_PHY_MODE_SGMII,
  MV_NET_PHY_MODE_TBI,
  MV_NET_PHY_MODE_REVMII,
  MV_NET_PHY_MODE_RMII,
  MV_NET_PHY_MODE_RGMII,
  MV_NET_PHY_MODE_RGMII_ID,
  MV_NET_PHY_MODE_RGMII_RXID,
  MV_NET_PHY_MODE_RGMII_TXID,
  MV_NET_PHY_MODE_RTBI,
  MV_NET_PHY_MODE_SMII,
  MV_NET_PHY_MODE_XGMII,
  MV_NET_PHY_MODE_MOCA,
  MV_NET_PHY_MODE_QSGMII,
  MV_NET_PHY_MODE_XAUI,
  MV_NET_PHY_MODE_RXAUI,
  MV_NET_PHY_MODE_KR,
  MV_NET_PHY_MODE_OUT_OF_RANGE,
};

enum pp2_ppio_hash_type
{
  PP2_PPIO_HASH_T_NONE = 0,
  PP2_PPIO_HASH_T_2_TUPLE,
  PP2_PPIO_HASH_T_5_TUPLE,
  PP2_PPIO_HASH_T_OUT_OF_RANGE,
};

enum pp2_ppio_eth_start_hdr
{
  PP2_PPIO_HDR_ETH = 0,
  PP2_PPIO_HDR_ETH_DSA,
  PP2_PPIO_HDR_ETH_EXT_DSA,
  PP2_PPIO_HDR_ETH_CUSTOM,
  PP2_PPIO_HDR_OUT_OF_RANGE,
};

enum pp2_ppio_color
{
  PP2_PPIO_COLOR_GREEN = 0,
  PP2_PPIO_COLOR_YELLOW,
  PP2_PPIO_COLOR_RED,
};

enum pp2_ppio_outq_sched_mode
{
  PP2_PPIO_SCHED_M_WRR = 0,
  PP2_PPIO_SCHED_M_SP,
};

struct pp2_ppio_link_info
{
  int up;
  enum mv_net_link_speed speed;
  enum mv_net_link_duplex duplex;
  enum mv_net_phy_mode phy_mode;
};
