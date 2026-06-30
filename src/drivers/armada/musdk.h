/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#pragma once

#include <stddef.h>
#include <vppinfra/types.h>
#include <vnet/dev/types.h>

#include <cma.h>

typedef u64 dma_addr_t;
typedef u64 phys_addr_t;

#define MV_MH_SIZE		      2
#define MV_ETH_ALEN		      6
#define MV_SYS_DMA_MAX_NUM_MEM_ID     4
#define PP2_MAX_PROTO_SUPPORTED	      8
#define PP2_MAX_FIELDS_SUPPORTED      2
#define PP2_MAX_UDFS_SUPPORTED	      3
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

enum mv_net_eth_fields
{
  MV_NET_ETH_F_SA = 0,
  MV_NET_ETH_F_DA,
  MV_NET_ETH_F_TYPE,
};

enum mv_net_eth_dsa_fields
{
  MV_NET_ETH_F_DSA_TAG_MODE = 0,
};

enum mv_net_vlan_fields
{
  MV_NET_VLAN_F_PRI = 0,
  MV_NET_VLAN_F_ID,
  MV_NET_VLAN_F_TCI,
};

enum mv_net_ipv4_fields
{
  MV_NET_IP4_F_DSCP = 0,
  MV_NET_IP4_F_SA,
  MV_NET_IP4_F_DA,
  MV_NET_IP4_F_PROTO,
};

enum mv_net_ipv6_fields
{
  MV_NET_IP6_F_TC = 0,
  MV_NET_IP6_F_SA,
  MV_NET_IP6_F_DA,
  MV_NET_IP6_F_FLOW,
  MV_NET_IP6_F_NEXT_HDR,
};

enum mv_net_l4_fields
{
  MV_NET_L4_F_SP = 0,
  MV_NET_L4_F_DP,
};

enum mv_net_udp_fields
{
  MV_NET_UDP_F_SP = 0,
  MV_NET_UDP_F_DP,
};

enum mv_net_tcp_fields
{
  MV_NET_TCP_F_SP = 0,
  MV_NET_TCP_F_DP,
};

struct mv_net_udf
{
  u8 id;
  u8 size;
};

enum mv_net_proto
{
  MV_NET_PROTO_NONE = 0,
  MV_NET_PROTO_ETH,
  MV_NET_PROTO_ETH_DSA,
  MV_NET_PROTO_VLAN,
  MV_NET_PROTO_PPPOE,
  MV_NET_PROTO_IP,
  MV_NET_PROTO_IP4,
  MV_NET_PROTO_IP6,
  MV_NET_PROTO_L4,
  MV_NET_PROTO_TCP,
  MV_NET_PROTO_UDP,
  MV_NET_PROTO_ICMP,
  MV_NET_PROTO_ARP,
  MV_NET_UDF,
  MV_NET_PROTO_LAST,
};

union mv_net_proto_fields
{
  enum mv_net_eth_fields eth;
  enum mv_net_eth_dsa_fields eth_dsa;
  enum mv_net_vlan_fields vlan;
  enum mv_net_ipv4_fields ipv4;
  enum mv_net_ipv6_fields ipv6;
  enum mv_net_l4_fields l4;
  enum mv_net_udp_fields udp;
  enum mv_net_tcp_fields tcp;
  struct mv_net_udf udf;
};

struct pp2_proto_field
{
  enum mv_net_proto proto;
  union mv_net_proto_fields field;
};

struct pp2_parse_udf_params
{
  enum mv_net_proto match_proto;
  union mv_net_proto_fields match_field;
  u8 *match_key;
  u8 *match_mask;
  u8 offset;
};

struct pp2_parse_udfs
{
  u8 num_udfs;
  struct pp2_parse_udf_params udfs[PP2_MAX_UDFS_SUPPORTED];
};

struct pp2_init_params
{
  u16 hif_reserved_map;
  u16 bm_pool_reserved_map;
  u8 rss_tbl_reserved_map;
  u32 policers_reserved_map;
  u32 early_drop_reserved_map;
  int skip_hw_init;
  u32 res_maps_auto_detect_map;
  struct pp2_parse_udfs prs_udfs;
};

struct mv_sys_dma_mem_region;
struct pp2_hif;

struct pp2_hif_params
{
  u8 id;
  u32 out_size;
  struct mv_sys_dma_mem_region *mem;
};

struct pp2_bpool
{
  int pp2_id;
  int id;
  void *internal_param;
};

struct pp2_bpool_params
{
  u8 pp2_id;
  u8 id;
  u32 buff_len;
  int dummy_short_pool;
  struct mv_sys_dma_mem_region *likely_buffer_mem;
};

struct pp2_buff_inf
{
  dma_addr_t addr;
  u64 cookie;
};

struct buff_release_entry
{
  struct pp2_buff_inf buff;
  struct pp2_bpool *bpool;
};

struct pp2_port;

struct pp2_cls_plcr;

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
  struct mv_sys_dma_mem_region *mem;
  u8 tc_pools_mem_id_index;
};

struct pp2_ppio_tc_params
{
  u16 pkt_offset;
  u16 num_in_qs;
  struct pp2_ppio_inq_params *inqs_params;
  struct pp2_bpool *pools[MV_SYS_DMA_MAX_NUM_MEM_ID][PP2_PPIO_TC_CLUSTER_MAX_POOLS];
  enum pp2_ppio_color default_color;
};

struct pp2_ppio_inqs_params
{
  u16 num_tcs;
  struct pp2_ppio_tc_params tcs_params[PP2_PPIO_MAX_NUM_TCS];
  enum pp2_ppio_hash_type hash_type;
  struct pp2_cls_plcr *plcr;
};

enum pp2_ppio_outq_sched_mode
{
  PP2_PPIO_SCHED_M_WRR = 0,
  PP2_PPIO_SCHED_M_SP,
};

struct pp2_ppio_rate_limit_params
{
  u32 cbs;
  u32 cir;
};

struct pp2_ppio_rate_limit
{
  int rate_limit_enable;
  struct pp2_ppio_rate_limit_params rate_limit_params;
};

struct pp2_ppio_outq_params
{
  u32 size;
  enum pp2_ppio_outq_sched_mode sched_mode;
  u8 weight;
  struct pp2_ppio_rate_limit rate_limit;
};

struct pp2_ppio_outqs_params
{
  u16 num_outqs;
  struct pp2_ppio_outq_params outqs_params[PP2_PPIO_MAX_NUM_OUTQS];
  int sched_enable;
};

enum pp2_ppio_log_port_rule_type
{
  PP2_RULE_TYPE_PROTO = 0,
  PP2_RULE_TYPE_PROTO_FIELD,
};

enum pp2_ppio_cls_target
{
  PP2_CLS_TARGET_LOCAL_PPIO = 0,
  PP2_CLS_TARGET_OTHER,
};

struct pp2_ppio_log_port_rule_params
{
  enum pp2_ppio_log_port_rule_type rule_type;
  union
  {
    struct
    {
      enum mv_net_proto proto;
      int val;
    } proto_params;
    struct
    {
      struct pp2_proto_field proto_field;
      u8 val;
    } proto_field_params;
  } u;
};

struct pp2_ppio_log_port_params
{
  struct
  {
    enum pp2_ppio_cls_target target;
    u8 num_proto_rule_sets;
    struct
    {
      u8 num_rules;
      struct pp2_ppio_log_port_rule_params rules[PP2_MAX_PROTO_SUPPORTED];
    } rule_sets[PP2_MAX_PROTO_SUPPORTED];
  } proto_based_target;
  u32 first_inq;
};

struct pp2_ppio_nic_params
{
  u16 override_mtu;
  u16 override_mru;
};

struct pp2_ppio_params
{
  u8 pp2_id;
  u8 id;
  struct pp2_ppio_inqs_params inqs_params;
  struct pp2_ppio_outqs_params outqs_params;
  union
  {
    struct pp2_ppio_log_port_params log_port_params;
    struct pp2_ppio_nic_params nic_params;
  } specific_type_params;
  enum pp2_ppio_eth_start_hdr eth_start_hdr;
  struct pp2_ppio_rate_limit rate_limit;
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

int pp2_init (struct pp2_init_params *params);
void pp2_deinit (void);
int pp2_netdev_get_ifname (u8 pp_id, u8 ppio_id, char *ifname);
int pp2_ppio_available (int pp_id, int ppio_id);

int pp2_hif_init (struct pp2_hif_params *params, struct pp2_hif **hif);
void pp2_hif_deinit (struct pp2_hif *hif);

int pp2_bpool_init (struct pp2_bpool_params *params, struct pp2_bpool **bpool);
void pp2_bpool_deinit (struct pp2_bpool *pool);
int pp2_bpool_get_buff (struct pp2_hif *hif, struct pp2_bpool *pool, struct pp2_buff_inf *buff);
int pp2_bpool_put_buffs (struct pp2_hif *hif, struct buff_release_entry buff_entry[], u16 *num);
int pp2_bpool_get_num_buffs (struct pp2_bpool *pool, u32 *num_buffs);

int pp2_ppio_init (vnet_dev_port_t *port, struct pp2_ppio_params *params);
void pp2_ppio_deinit (vnet_dev_port_t *port);
int pp2_ppio_enable (vnet_dev_port_t *port);
int pp2_ppio_disable (vnet_dev_port_t *port);
int pp2_ppio_set_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
int pp2_ppio_add_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
int pp2_ppio_remove_mac_addr (vnet_dev_port_t *port, const eth_addr_t addr);
int pp2_ppio_set_promisc (vnet_dev_port_t *port, int en);
int pp2_ppio_get_link_info (vnet_dev_port_t *port, struct pp2_ppio_link_info *link_info);
int pp2_ppio_get_num_outq_done (vnet_dev_port_t *port, struct pp2_hif *hif, u8 qid, u16 *num);
