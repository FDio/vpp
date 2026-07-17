/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vnet/dev/dev.h>
#include <ice_hw.h>

#define ICE_AQ_LEN	    32
#define ICE_AQ_BUF_SIZE	    4096
#define ICE_RX_REFILL_BATCH 8

typedef struct ice_aq_mem ice_aq_mem_t;

#define foreach_ice_family                                                                         \
  _ (E810, "E810")                                                                                 \
  _ (E830, "E830")                                                                                 \
  _ (E835, "E835")

typedef enum
{
#define _(n, s) ICE_DEVICE_FAMILY_##n,
  foreach_ice_family
#undef _
} ice_device_family_t;

typedef struct
{
  void *bar0;
  ice_aq_mem_t *aq;
  u64 atq_dma;
  u64 arq_dma;
  ice_device_family_t family;
  u32 rom_ver;
  u32 fw_build;
  u16 atq_next;
  u8 pf_id;
  u8 lport;
  u8 sw_id;
  u16 vsi_num;
  u16 rxq_base;
  u16 txq_base;
  u16 rxq_count;
  u16 txq_count;
  u32 tx_parent_teid;
  u8 mac[6];
  u8 fw_branch;
  u8 fw_major;
  u8 fw_minor;
  u8 fw_patch;
  u8 api_branch;
  u8 api_major;
  u8 api_minor;
  u8 api_patch;
  u8 nvm_major;
  u8 nvm_minor;
  ice_pkg_ver_t ddp_ver;
  ice_aqc_vsi_props_t vsi_props;
  ice_sw_rule_t mac_rules[2];
  u8 aq_active : 1;
  u8 aq_alive : 1;
  u8 vsi_added : 1;
  u8 mac_rules_added : 1;
  u8 txq_enabled : 1;
} ice_dev_t;

typedef struct
{
  u64 rx_bytes;
  u64 rx_unicast;
  u64 rx_multicast;
  u64 rx_broadcast;
  u64 rx_discards;
  u64 rx_unknown_protocol;
  u64 tx_bytes;
  u64 tx_unicast;
  u64 tx_multicast;
  u64 tx_broadcast;
  u64 tx_errors;
  u64 mac_rx_bytes;
  u64 mac_rx_unicast;
  u64 mac_rx_multicast;
  u64 mac_rx_broadcast;
  u64 mac_rx_discards;
  u64 mac_rx_unknown_protocol;
  u64 mac_tx_bytes;
  u64 mac_tx_unicast;
  u64 mac_tx_multicast;
  u64 mac_tx_broadcast;
  u64 mac_tx_dropped_link_down;
  u64 crc_errors;
  u64 illegal_bytes;
  u64 mac_local_faults;
  u64 mac_remote_faults;
  u64 rx_len_errors;
  u64 link_xon_rx;
  u64 link_xoff_rx;
  u64 link_xon_tx;
  u64 link_xoff_tx;
  u64 priority_xon_rx[8];
  u64 priority_xoff_rx[8];
  u64 priority_xon_tx[8];
  u64 priority_xoff_tx[8];
  u64 priority_xon_2_xoff[8];
  u64 rx_size_64;
  u64 rx_size_127;
  u64 rx_size_255;
  u64 rx_size_511;
  u64 rx_size_1023;
  u64 rx_size_1522;
  u64 rx_size_big;
  u64 rx_undersize;
  u64 rx_fragments;
  u64 rx_oversize;
  u64 rx_jabber;
  u64 tx_size_64;
  u64 tx_size_127;
  u64 tx_size_255;
  u64 tx_size_511;
  u64 tx_size_1023;
  u64 tx_size_1522;
  u64 tx_size_big;
} ice_port_stats_t;

typedef struct
{
  ice_port_stats_t stats_prev;
  ice_port_stats_t stats_total;
  u8 last_link_up : 1;
  u8 stats_valid : 1;
} ice_port_t;

typedef struct
{
  ice_rx_desc_t *descs;
  u32 *buffer_indices;
  u32 *tail_reg;
  ice_rxq_ctx_t ctx;
  u16 head;
  u16 tail;
  u8 ctx_valid : 1;
} ice_rxq_t;

typedef struct
{
  ice_tx_desc_t *descs;
  u32 *buffer_indices;
  u32 *tail_reg;
  ice_txq_ctx_t ctx;
  u16 head;
  u16 tail;
  u8 ctx_valid : 1;
} ice_txq_t;

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u16 queue_id;
  ice_rx_desc_t desc;
} ice_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u16 queue_id;
  ice_tx_desc_t desc;
} ice_tx_trace_t;

vnet_dev_rv_t ice_aq_alloc (vlib_main_t *, vnet_dev_t *);
void ice_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_start (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_configure (vlib_main_t *, vnet_dev_t *);
void ice_aq_stop (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_get_link_state (vlib_main_t *, vnet_dev_port_t *, u8 *);
vnet_dev_rv_t ice_aq_add_txq (vlib_main_t *, vnet_dev_tx_queue_t *, const ice_txq_ctx_t *);
vnet_dev_rv_t ice_aq_dis_txq (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t ice_hw_init (vlib_main_t *, vnet_dev_t *);
void ice_hw_deinit (vlib_main_t *, vnet_dev_t *);

vnet_dev_rv_t ice_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_port_start (vlib_main_t *, vnet_dev_port_t *);
void ice_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ice_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ice_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void ice_port_counter_poll (vlib_main_t *, vnet_dev_port_t *);

vnet_dev_rv_t ice_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ice_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void ice_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void ice_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

format_function_t format_ice_port_status;
format_function_t format_ice_dev_info;
format_function_t format_ice_family;
format_function_t format_ice_adminq_opcode;
format_function_t format_ice_rx_trace;
format_function_t format_ice_tx_trace;

extern vnet_dev_node_t ice_rx_node;
extern vnet_dev_node_t ice_tx_node;

static_always_inline u32
ice_reg_read (vnet_dev_t *dev, u32 reg)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  return __atomic_load_n ((u32 *) ((u8 *) id->bar0 + reg), __ATOMIC_RELAXED);
}

static_always_inline void
ice_reg_write (vnet_dev_t *dev, u32 reg, u32 value)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  __atomic_store_n ((u32 *) ((u8 *) id->bar0 + reg), value, __ATOMIC_RELEASE);
}

static_always_inline void
ice_reg_flush (vnet_dev_t *dev)
{
  (void) ice_reg_read (dev, ICE_GLGEN_RSTAT);
}

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ice_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "ice_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev),             \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define foreach_ice_tx_node_counter                                                                \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                                      \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "buffer chain too long")

typedef enum
{
#define _(f, n, s, d) ICE_TX_NODE_CTR_##f,
  foreach_ice_tx_node_counter
#undef _
} ice_tx_node_counter_t;

#define foreach_ice_rx_node_counter                                                                \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer allocation failed")                                \
  _ (DESC_ERROR, desc_error, ERROR, "receive descriptor error")

typedef enum
{
#define _(f, n, s, d) ICE_RX_NODE_CTR_##f,
  foreach_ice_rx_node_counter
#undef _
} ice_rx_node_counter_t;
