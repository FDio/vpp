/* SPDX-License-Identifier: Apache-2.0
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

typedef struct
{
  u8 id;
  u32 buf_sz;
  uintptr_t virt_base;
  uintptr_t phys_base;
  u8 fc_not_supported : 1;
  u8 is_initialized : 1;
} mvpp2_bpool_t;

struct pp2_bpool_params
{
  struct vlib_main_t *vm;
  vnet_dev_t *dev;
  u8 id;
  u32 buff_len;
  int dummy_short_pool;
};

struct pp2_buff_inf
{
  dma_addr_t addr;
  u64 cookie;
};

struct buff_release_entry
{
  struct pp2_buff_inf buff;
  mvpp2_bpool_t *bpool;
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

struct pp2_ppio_inq_params
{
  u32 size;
  u8 tc_pools_mem_id_index;
};

struct pp2_ppio_tc_params
{
  u16 pkt_offset;
  u16 num_in_qs;
  struct pp2_ppio_inq_params *inqs_params;
  mvpp2_bpool_t *pools[MV_SYS_DMA_MAX_NUM_MEM_ID][PP2_PPIO_TC_CLUSTER_MAX_POOLS];
  enum pp2_ppio_color default_color;
};

struct pp2_ppio_inqs_params
{
  u16 num_tcs;
  struct pp2_ppio_tc_params tcs_params[PP2_PPIO_MAX_NUM_TCS];
  enum pp2_ppio_hash_type hash_type;
};

enum pp2_ppio_outq_sched_mode
{
  PP2_PPIO_SCHED_M_WRR = 0,
  PP2_PPIO_SCHED_M_SP,
};

struct pp2_ppio_outq_params
{
  u32 size;
  enum pp2_ppio_outq_sched_mode sched_mode;
  u8 weight;
};

struct pp2_ppio_outqs_params
{
  u16 num_outqs;
  struct pp2_ppio_outq_params outqs_params[PP2_PPIO_MAX_NUM_OUTQS];
};

struct pp2_ppio_params
{
  u8 pp2_id;
  u8 id;
  struct pp2_ppio_inqs_params inqs_params;
  struct pp2_ppio_outqs_params outqs_params;
  enum pp2_ppio_eth_start_hdr eth_start_hdr;
};

struct pp2_ppio_link_info
{
  int up;
  enum mv_net_link_speed speed;
  enum mv_net_link_duplex duplex;
  enum mv_net_phy_mode phy_mode;
};

#define PP2_PPIO_DESC_NUM_WORDS 8

struct pp2_ppio_desc
{
  u32 cmds[PP2_PPIO_DESC_NUM_WORDS];
};

#define TXD_FIRST_LAST	     0x3
#define TXD_IP_CHK_DISABLE   0x1
#define TXD_L4_CHK_DISABLE   0x2
#define TXD_FL_MASK	     0x30000000
#define TXD_GEN_L4_CHK_MASK  0x00006000
#define TXD_GEN_IP_CHK_MASK  0x00008000
#define TXD_BYTE_COUNT_MASK  0xffff0000
#define TXD_BUF_PHYS_HI_MASK 0x000000ff
#define RXD_BYTE_COUNT_MASK  0xffff0000
#define RXD_BUF_VIRT_HI_MASK 0x000000ff
#define RXD_BUF_VIRT_LO_MASK 0xffffffff

vnet_dev_rv_t pp2_hif_init (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index, u8 id,
			    u32 out_size);
void pp2_hif_deinit (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index);

vnet_dev_rv_t pp2_bpool_init (struct pp2_bpool_params *params, mvpp2_bpool_t *pool);
void pp2_bpool_deinit (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool);
vnet_dev_rv_t pp2_bpool_get_buff (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool,
				  struct pp2_buff_inf *buff);
vnet_dev_rv_t pp2_bpool_put_buffs (vlib_main_t *vm, vnet_dev_t *dev,
				   struct buff_release_entry buff_entry[], u16 *num);

vnet_dev_rv_t pp2_ppio_init (vnet_dev_port_t *port, struct pp2_ppio_params *params);
vnet_dev_rv_t pp2_ppio_set_loopback (vnet_dev_port_t *port, int en);
void pp2_port_deinit (vnet_dev_port_t *port);
vnet_dev_rv_t pp2_port_set_priv_flags (vnet_dev_port_t *port, u32 val);
vnet_dev_rv_t pp2_ppio_enable (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t pp2_ppio_disable (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
vnet_dev_rv_t pp2_ppio_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
vnet_dev_rv_t pp2_ppio_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
vnet_dev_rv_t pp2_ppio_set_promisc (vnet_dev_port_t *port, int en);
vnet_dev_rv_t pp2_ppio_get_link_info (vnet_dev_port_t *port, struct pp2_ppio_link_info *link_info);
