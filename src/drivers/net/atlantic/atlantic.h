/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>

#include <atlantic_regs.h>

#define PCI_VENDOR_ID_AQUANTIA 0x1d6a
#define ATL_RX_REFILL_BATCH_SZ 8
#define ATL_RX_TRACE_N_DESC    5

typedef union
{
  struct
  {
    u32 major : 8;
    u32 minor : 8;
    u32 build : 16;
  };
  u32 as_u32;
} atl_fw_version_t;

typedef union
{
  struct
  {
    u32 iface_ver : 4;
    u32 _reserved_4_31 : 28;
  };
  u32 as_u32;
} atl_iface_ver_t;

typedef union
{
  struct
  {
    u8 l2_base_index : 6;
    u8 flexible_filter_mask : 2;
    u8 l2_count;
    u8 ethertype_base_index;
    u8 ethertype_count;
    u8 vlan_base_index;
    u8 vlan_count;
    u8 l3_ip4_base_index : 4;
    u8 l3_ip4_count : 4;
    u8 l3_ip6_base_index : 4;
    u8 l3_ip6_count : 4;
    u8 l4_base_index : 4;
    u8 l4_count : 4;
    u8 l4_flex_base_index : 4;
    u8 l4_flex_count : 4;
    u8 resolver_base_index;
    u8 resolver_count;
  };
  u32 as_u32[3];
} atl_fw_filter_caps_t;

typedef union
{
  u64 qwords[2];
  struct
  {
    u64 addr;
    union
    {
      u32 ctl1;
      struct
      {
	u32 type_txd : 1;
	u32 type_txc : 1;
	u32 _reserved_2_3 : 2;
	u32 blen : 16; /* bytes >> 4 */
	u32 dd : 1;
	u32 eop : 1;
	u32 vlan : 1;
	u32 fcs : 1;
	u32 ip4csum : 1;
	u32 l4csum : 1;
	u32 lso : 1;
	u32 wb : 1;
	u32 vxlan : 1;
	u32 _reserved_29_31 : 3;
      };
    };
    union
    {
      u32 ctl2;
      struct
      {
	u32 _reserved_0_11 : 12;
	u32 ctx_idx : 1;
	u32 ctx_en : 1;
	u32 len : 18; /* shifted by 14 in HW */
      };
    };
  };
  struct
  {
    u64 wb_addr;
    u32 wb_ctl;
    u32 wb_status;
  };
} atl_tx_desc_t;

typedef union
{
  u64 qwords[2];
  struct
  {
    u32 _reserved0;
    u32 len;
    union
    {
      u32 ctl;
      struct
      {
	u32 type_txd : 1;
	u32 type_txc : 1;
	u32 tcp : 1;
	u32 _reserved_3_20 : 18;
	u32 ipv6 : 1;
	u32 _reserved_22_30 : 9;
	u32 cmd : 1;
      };
    };
    union
    {
      u32 len2;
      struct
      {
	u32 l2_len : 7;
	u32 l3_len : 9;
	u32 l4_len : 8;
	u32 mss : 8;
      };
    };
  };
} atl_tx_ctx_desc_t;

STATIC_ASSERT_SIZEOF (atl_tx_ctx_desc_t, 16);

STATIC_ASSERT_SIZEOF (atl_tx_desc_t, 16);

typedef union
{
  u64 as_u64;
  struct
  {
    union
    {
      u32 type;
      struct
      {
	u32 rss_type : 4;
	u32 l3_type : 2;
	u32 l4_type : 3;
	u32 pkt_vlan : 1;
	u32 pkt_vlan2 : 1;
	u32 _reserved_pkt_type_7 : 1;
	u32 dma_err : 1;
	u32 _reserved_13_18 : 6;
	u32 rx_ctrl : 2;
	u32 spl_hdr : 1;
	u32 hdr_len : 10;
      };
    };
    u32 rss_hash;
  };
} atl_rx_desc_qw0_t;

STATIC_ASSERT_SIZEOF (atl_rx_desc_qw0_t, 8);

typedef union
{
  u64 as_u64;
  struct
  {
    union
    {
      u16 status;
      struct
      {
	u16 dd : 1;
	u16 eop : 1;
	u16 mac_err : 1;
	u16 v4_sum_ng : 1;
	u16 l4_sum_err : 1;
	u16 l4_sum_ok : 1;
	u16 rx_estat : 6;
	u16 rsc_cnt : 4;
      };
    };
    u16 pkt_len;
    u16 next_desc_ptr;
    u16 vlan;
  };
} atl_rx_desc_qw1_t;

STATIC_ASSERT_SIZEOF (atl_rx_desc_qw1_t, 8);

typedef union
{
  u64x2 as_u64x2;
  u64 qwords[2];
  struct
  {
    u64 buf_addr;
    u64 hdr_addr;
  };
  struct
  {
    atl_rx_desc_qw0_t qw0;
    atl_rx_desc_qw1_t qw1;
  };
} atl_rx_desc_t;

STATIC_ASSERT_SIZEOF (atl_rx_desc_t, 16);

typedef struct
{
  void *bar0;
  atl_fw_version_t fw_version;
  u32 mbox_addr;
  u8 mac[6];
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
  atl_fw_filter_caps_t caps;
} atl_device_t;

typedef struct
{
  atl_reg_aq2_fw_interface_out_link_status_t last_link_status;
  u8 link_status_fail : 1;
  u8 stats_fetch_fail : 1;
} atl_port_t;

typedef struct
{
  atl_rx_desc_t *descs;
  u32 *buffer_indices;
  u32 *tail_reg;
  u16 head;
  u16 tail;
  u16 next_index;
  u64 stats_rx_packets;
  u64 stats_rx_bytes;
} atl_rxq_t;

typedef struct
{
  atl_tx_desc_t *descs;
  u32 *buffer_indices;
  u32 *wb;
  u32 *tail_reg;
  u16 head_index;
  u16 tail_index;
} atl_txq_t;

#define AQ_HW_MAC_OWN 0

typedef struct
{
  u32 sw_if_index;
  u8 queue_id;
  u16 head_slot;
  atl_rx_desc_t desc[ATL_RX_TRACE_N_DESC];
  u32 buffer_index;
} atl_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  u8 queue_id;
  atl_tx_desc_t desc;
  u32 buffer_index;
} atl_tx_trace_t;

#define foreach_atl_tx_node_counter                                                                \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free TX slots")                                      \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "packet dropped: TX chain too long")
#define foreach_atl_rx_node_counter                                                                \
  _ (RX_DESC_ERROR_DROP, rx_desc_error_drop, ERROR, "buffers dropped due to mac_err/dma_err")

typedef enum
{
  ATL_FW_LINK_RATE_INVALID,
  ATL_FW_LINK_RATE_10M,
  ATL_FW_LINK_RATE_100M,
  ATL_FW_LINK_RATE_1G,
  ATL_FW_LINK_RATE_2G5,
  ATL_FW_LINK_RATE_5G,
  ATL_FW_LINK_RATE_10G,
} atl_fw_link_rate_t;

typedef enum
{
#define _(f, n, s, d) ATL_RX_NODE_CTR_##f,
  foreach_atl_rx_node_counter
#undef _
} atl_rx_node_counter_t;

typedef enum
{
#define _(f, n, s, d) ATL_TX_NODE_CTR_##f,
  foreach_atl_tx_node_counter
#undef _
} atl_tx_node_counter_t;

vnet_dev_rv_t atl_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t atl_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void atl_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t atl_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t atl_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t atl_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t atl_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void atl_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void atl_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
vnet_dev_rv_t atl_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port);
void atl_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port);
void atl_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t atl_aq2_interface_buffer_read (vnet_dev_t *dev, u32 reg0, u32 *data0, u32 n_dwords);
vnet_dev_rv_t atl_fw_mbox_read (vnet_dev_t *dev, u32 offset, u32 *val);
format_function_t format_atl_port_status;
format_function_t format_atl_l2uc;
format_function_t format_atl_dev_info;
format_function_t format_atl_fw_version;
format_function_t format_atl_iface_version;
format_function_t format_atl_regs;
format_function_t format_atl_aq2_art_action;
format_function_t format_atl_rpf_info;
format_function_t format_atl_mac_addr_table;
format_function_t format_atl_cable_diag;
format_function_t format_atl_rss_info;
format_function_t format_atl_link_capa;
format_function_t format_atl_partner_link_capa;
format_function_t atl_rx_trace;
format_function_t atl_tx_trace;
format_function_t format_atl_rx_wb_desc;
format_function_t format_atl_tx_desc;

extern vnet_dev_node_t atl_rx_node;
extern vnet_dev_node_t atl_tx_node;

void atl_reg_wr_u32 (vnet_dev_t *dev, u32 reg, u32 val);
u32 atl_reg_rd_u32 (vnet_dev_t *dev, u32 reg);
void atl_reg_wr (vnet_dev_t *dev, u32 reg, atl_reg_t val);
atl_reg_t atl_reg_rd (vnet_dev_t *dev, u32 reg);

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, atl_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "atl_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, atl_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, atl_log.class, "%U: " f, format_vnet_dev_addr, dev,             \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, atl_log.class, "%U: " f, format_vnet_dev_addr, dev,            \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, atl_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
