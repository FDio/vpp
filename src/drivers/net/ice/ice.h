/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#define ICE_RX_REFILL_BATCH_SIZE     32
#define ICE_RX_DESC_MAX_CHAIN_LENGTH 8

#include <vnet/dev/dev.h>
#include <ice_hw.h>
#include <vnet/flow/flow.h>

#define ICE_AQ_LEN	    32
#define ICE_AQ_BUF_SIZE	    4096
#define ICE_ITR_INTERVAL_US 250
#define ICE_RX_ITR0_VALUE   2

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
  u32 rom_ver;
  u32 fw_build;
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
  ice_aqc_list_caps_elem_t *dev_caps;
  ice_aqc_pkg_info_t *pkg_info;
} ice_dev_info_t;

typedef struct
{
  u8 lport;
  ice_aqc_link_status_t link;
  ice_aqc_get_phy_caps_data_t phy[4];
  ice_aqc_port_option_t options[16];
  ice_aq_params_t options_params;
  vnet_dev_rv_t link_rv, phy_rv[4], options_rv;
} ice_port_status_t;

typedef struct
{
  void *bar0;
  ice_aq_mem_t *aq;
  ice_device_family_t family;
  u16 fdir_rxq, fdir_txq;
  u8 valid_functions;
  u8 pf_id;
  u16 atq_next;
  u16 arq_next;
  u8 aq_alive : 1;
  u8 arq_active : 1;
  u8 arq_irq_enabled : 1;
} ice_dev_t;

typedef struct
{
  ice_aqc_vsi_props_t props;
  ice_sw_rule_t *sw_rules;
  u16 num;
  u8 added : 1;
} ice_vsi_t;

/* fdir.c */
#define ICE_FDIR_MAX_WORDS   24
#define ICE_FDIR_PACKET_SIZE 512
#define ICE_FDIR_PTYPE_COUNT 1024

typedef struct
{
  u16 offset;
  u16 mask;
  u8 protocol;
  u8 reserved;
} ice_flow_word_t;

typedef struct
{
  ice_flow_word_t words[ICE_FDIR_MAX_WORDS];
  u16 values[ICE_FDIR_MAX_WORDS];
  u8 packet[ICE_FDIR_PACKET_SIZE];
  uword ptypes[ICE_FDIR_PTYPE_COUNT / uword_bits];
  u16 packet_length;
  u8 n_words;
} ice_flow_pattern_t;

typedef struct
{
  ice_flow_pattern_t pattern;
  u32 flow_index;
  u32 hw_if_index;
  u32 profile_index;
  u16 queue;
  u16 counter;
  u64 counter_base;
  u8 queue_region;
  u8 queue_priority;
  u8 drop : 1;
  u8 installed : 1;
  u8 pending : 1;
} ice_flow_entry_t;

#define ICE_FDIR_RING_SIZE 64

/* Programming queues belong to a separate VSI and are never exposed to the
 * dataplane. A timeout quarantines their DMA memory until queue shutdown. */
typedef struct
{
  ice_tx_desc_t tx[ICE_FDIR_RING_SIZE] __clib_aligned (128);
  ice_rx_desc_t rx[ICE_FDIR_RING_SIZE] __clib_aligned (128);
  u8 packet[ICE_FDIR_PACKET_SIZE] __clib_aligned (128);
  u8 buffers[ICE_FDIR_RING_SIZE][256] __clib_aligned (128);
} ice_fdir_dma_t;

typedef struct
{
  ice_flow_word_t words[ICE_FDIR_MAX_WORDS];
  u16 *tcam;
  u8 ptg[256];
  u32 masks;
  u32 references;
  u16 id;
  u8 n_words;
  u8 allocated : 1;
} ice_fdir_profile_t;

typedef struct
{
  ice_fdir_dma_t *dma;
  ice_fdir_profile_t *profiles;
  uword counters[ICE_FDIR_COUNTERS / uword_bits];
  u8 xlt1[ICE_FDIR_PTYPE_COUNT];
  struct
  {
    u16 mask;
    u8 word;
    u32 references;
  } masks[32];
  u16 vsi, vsig, saved_vsig;
  u16 counter_block, guaranteed, shared;
  u16 tx_tail, rx_head;
  u16 ptg_owner[256];
  u8 mask_first, mask_count;
  u8 vsi_added : 1;
  u8 tx_started : 1;
  u8 rx_started : 1;
  u8 counter_allocated : 1;
  u8 guaranteed_allocated : 1;
  u8 shared_allocated : 1;
  u8 mapped : 1;
  u8 enabled : 1;
  u8 failed : 1;
} ice_fdir_t;

/* rss.c */
#define ICE_RSS_PROFILE_LIMIT 16

#define foreach_ice_rss_full_tuple_ptype                                                           \
  _ (ICE_PTYPE_IPV4_UDP, VNET_FLOW_RSS_TYPES_IPV4_UDP)                                             \
  _ (ICE_PTYPE_IPV4_TCP, VNET_FLOW_RSS_TYPES_IPV4_TCP)                                             \
  _ (ICE_PTYPE_IPV4_SCTP, VNET_FLOW_RSS_TYPES_IPV4_SCTP)                                           \
  _ (ICE_PTYPE_IPV6_UDP, VNET_FLOW_RSS_TYPES_IPV6_UDP)                                             \
  _ (ICE_PTYPE_IPV6_TCP, VNET_FLOW_RSS_TYPES_IPV6_TCP)                                             \
  _ (ICE_PTYPE_IPV6_SCTP, VNET_FLOW_RSS_TYPES_IPV6_SCTP)

typedef struct
{
  ice_profile_fv_t words[ICE_PROFILE_FV_WORDS];
  uword groups[256 / uword_bits];
  u8 n_words;
} ice_rss_profile_plan_t;

typedef struct
{
  ice_rss_profile_plan_t profiles[ICE_RSS_PROFILE_LIMIT];
  u8 n_profiles;
  u64 full_tuple_types;
} ice_rss_plan_t;

typedef struct
{
  u16 id;
  u16 *tcam;
  u8 allocated : 1;
} ice_rss_profile_resource_t;

typedef struct
{
  ice_rss_profile_resource_t *profiles;
  u16 vsig, saved_vsig;
  u64 full_tuple_types;
  u8 queues[ICE_RSS_MAX_QUEUES];
  u16 n_queues;
  u8 user_lut : 1;
  u8 active : 1;
  u8 failed : 1;
} ice_rss_t;

typedef struct
{
  ice_vsi_t vsi;
  u32 tx_parent_teid;
  u16 n_rx_vectors;
  u8 lport;
  ice_fdir_t *fdir;
  ice_flow_entry_t *flows;
  ice_rss_t *rss;
  u8 rss_config_failed : 1;
} ice_port_t;

typedef struct
{
  ice_rx_desc_t *descs;
  u32 *buffer_indices;
  u32 *tail_reg;
  u32 head;
  u32 tail;
  u8 maybe_chained : 1;
} ice_rxq_t;

typedef struct
{
  ice_tx_desc_t *descs;
  u32 *buffer_indices;
  u32 *tail_reg;
  u16 *rs_slots;
  u32 head;
  u32 tail;
  u8 started : 1;
} ice_txq_t;

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u16 queue_id;
  u16 n_desc;
  u32 packet_length;
  ice_rx_desc_t descs[];
} ice_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u16 queue_id;
  u8 n_descs;
  vlib_error_t error;
  ice_tx_desc_t descs[];
} ice_tx_trace_t;

/* adminq.c */
vnet_dev_rv_t ice_aq_alloc (vlib_main_t *, vnet_dev_t *);
void ice_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_events_start (vlib_main_t *, vnet_dev_t *);
void ice_aq_events_stop (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_start (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ice_aq_use_active_ddp (vlib_main_t *, vnet_dev_t *);
vnet_dev_op_with_ptr_t ice_aq_get_dev_info;
vnet_dev_rv_t ice_aq_get_dev_caps (vlib_main_t *, vnet_dev_t *, ice_dev_info_t *);
vnet_dev_op_with_ptr_t ice_aq_get_sensor_reading;
vnet_dev_op_with_ptr_t ice_aq_get_port_status;
vnet_dev_rv_t ice_aq_sff_eeprom (vlib_main_t *, vnet_dev_t *, u8, u8, u16, u8, u8 *, u8);
vnet_dev_rv_t ice_aq_configure (vlib_main_t *, vnet_dev_t *, ice_port_t *, u16, u8 *);
void ice_aq_stop (vlib_main_t *, vnet_dev_t *, ice_port_t *);
vnet_dev_rv_t ice_aq_get_link_state (vlib_main_t *, vnet_dev_port_t *, u8, u8 *, u32 *);
vnet_dev_rv_t ice_aq_set_link_speed (vlib_main_t *, vnet_dev_port_t *, u32);
vnet_dev_rv_t ice_aq_request_resource (vlib_main_t *, vnet_dev_t *, u16, u16, u32);
vnet_dev_rv_t ice_aq_release_resource (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ice_aq_add_vsi (vlib_main_t *, vnet_dev_t *, ice_aqc_vsi_props_t *, u16 *);
vnet_dev_rv_t ice_aq_update_vsi (vlib_main_t *, vnet_dev_t *, u16, ice_aqc_vsi_props_t *);
vnet_dev_rv_t ice_aq_get_vsi (vlib_main_t *, vnet_dev_t *, u16, ice_aqc_vsi_props_t *);
vnet_dev_rv_t ice_aq_free_vsi (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ice_aq_upload_section (vlib_main_t *, vnet_dev_t *, void *, u16);
vnet_dev_rv_t ice_aq_add_txq_group (vlib_main_t *, vnet_dev_t *, ice_aqc_add_txq_group_t *);
vnet_dev_rv_t ice_aq_dis_txq_item (vlib_main_t *, vnet_dev_t *, ice_aqc_dis_txq_item_t *);
vnet_dev_rv_t ice_aq_alloc_free_resource (vlib_main_t *, vnet_dev_t *, u16, u16, u16 *, int);
vnet_dev_rv_t ice_aq_get_rss_key (vlib_main_t *, vnet_dev_port_t *, ice_aq_rss_key_t *);
vnet_dev_rv_t ice_aq_set_rss_key (vlib_main_t *, vnet_dev_port_t *, const ice_aq_rss_key_t *);
vnet_dev_rv_t ice_aq_get_rss_lut (vlib_main_t *, vnet_dev_port_t *, ice_aq_rss_lut_t *);
vnet_dev_rv_t ice_aq_set_rss_lut (vlib_main_t *, vnet_dev_port_t *, const ice_aq_rss_lut_t *);
vnet_dev_rv_t ice_aq_update_package (vlib_main_t *, vnet_dev_t *, void *, u16, u8);
vnet_dev_rv_t ice_aq_add_mac_rule (vlib_main_t *, vnet_dev_port_t *, const u8 *);
vnet_dev_rv_t ice_aq_remove_mac_rule (vlib_main_t *, vnet_dev_port_t *, const u8 *);
vnet_dev_rv_t ice_aq_change_primary_mac (vlib_main_t *, vnet_dev_port_t *, const u8 *);
vnet_dev_rv_t ice_aq_set_promisc (vlib_main_t *, vnet_dev_port_t *, u8);
vnet_dev_rv_t ice_aq_add_txq (vlib_main_t *, vnet_dev_tx_queue_t *, const ice_txq_ctx_t *);
vnet_dev_rv_t ice_aq_dis_txq (vlib_main_t *, vnet_dev_tx_queue_t *);

/* counters.c */
vnet_dev_rv_t ice_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void ice_port_counter_poll (vlib_main_t *, vnet_dev_port_t *);

/* format.c */
vnet_dev_op_with_ptr_t ice_dump_capabilities;
format_function_t format_ice_port_status;
format_function_t format_ice_dev_info;
format_function_t format_ice_family;
format_function_t format_ice_adminq_opcode;
format_function_t format_ice_rx_queue_info;
format_function_t format_ice_rx_trace;
format_function_t format_ice_tx_queue_info;
format_function_t format_ice_tx_desc;
format_function_t format_ice_tx_trace;

/* phy_format.c */
format_function_t format_ice_phy_status;

/* phy.c */
vnet_dev_rv_t ice_phy_type_for_speed (u32, ice_phy_type_low_t *, ice_phy_type_high_t *);

/* port.c */
void ice_port_update_link_state (vlib_main_t *, vnet_dev_port_t *, u8, u32);
vnet_dev_rv_t ice_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_port_start (vlib_main_t *, vnet_dev_port_t *);
void ice_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ice_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_cfg_change_req_t *);
vnet_dev_port_op_with_ptr_t ice_port_get_module_eeprom;

/* queue.c */
vnet_dev_rv_t ice_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ice_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void ice_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void ice_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

/* vsi_format.c */
format_function_t format_ice_vsi_summary;
vnet_dev_op_with_ptr_t ice_dump_vsi;

/* fdir_format.c */
vnet_dev_op_with_ptr_t ice_dump_fdir;

/* rss_format.c */
vnet_dev_op_with_ptr_t ice_dump_rss;

/* fdir.c */
vnet_dev_rv_t ice_flow_parse (const vnet_flow_t *, ice_flow_pattern_t *);
vnet_dev_rv_t ice_flow_validate (vnet_dev_port_t *, vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ice_flow_config (vlib_main_t *, vnet_dev_port_t *, vnet_dev_port_cfg_change_req_t *);
void ice_flow_free (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_fdir_init (vlib_main_t *, vnet_dev_port_t *);
void ice_fdir_free (vlib_main_t *, vnet_dev_port_t *);
void ice_fdir_cleanup (vnet_dev_port_t *);
vnet_dev_rv_t ice_fdir_add (vlib_main_t *, vnet_dev_port_t *, ice_flow_entry_t *);
vnet_dev_rv_t ice_fdir_del (vlib_main_t *, vnet_dev_port_t *, ice_flow_entry_t *);
u64 ice_fdir_counter_read (vnet_dev_port_t *, u16);
u16 ice_fdir_control_vsi (vnet_dev_port_t *);

/* profile_format.c */
format_function_t format_ice_protocol_name_by_id;

/* profile.c */
u32 ice_profile_inset_word (u32, u32, u32);
vnet_dev_rv_t ice_profile_section (vlib_main_t *, vnet_dev_t *, u32, void *, u16, int);
vnet_dev_rv_t ice_profile_map_vsi (vlib_main_t *, vnet_dev_t *, u32, u16, u16);
vnet_dev_rv_t ice_profile_find_vsig (vlib_main_t *, vnet_dev_t *, u32, u32, u16, u16 *, u16 *);
vnet_dev_rv_t ice_profile_read_xlt1 (vlib_main_t *, vnet_dev_t *, u32, u8 *);
vnet_dev_rv_t ice_profile_write_tcam (vlib_main_t *, vnet_dev_t *, u32, u16, u8, u8, u16, int);
vnet_dev_rv_t ice_profile_release_tcam (vlib_main_t *, vnet_dev_t *, u32, u16, u16 *);
vnet_dev_rv_t ice_profile_release_id (vlib_main_t *, vnet_dev_t *, u16, u16 *);
vnet_dev_rv_t ice_profile_dump (vlib_main_t *, vnet_dev_t *, u32, u16, u8 **);
vnet_dev_rv_t ice_profile_dump_tcam (vlib_main_t *, vnet_dev_t *, u32, u16 *, u8 **);
vnet_dev_rv_t ice_profile_dump_xlt2 (vlib_main_t *, vnet_dev_t *, u32, u16, u8 **);

/* rss.c */
vnet_dev_rv_t ice_rss_make_plan (const u8 *, ice_rss_plan_t *);
vnet_dev_rv_t ice_rss_prepare_lut (const u8 *, u16, const vnet_dev_rss_config_t *, u8 *);
void ice_rss_free (vlib_main_t *, vnet_dev_port_t *);
void ice_rss_cleanup (vnet_dev_port_t *);
u64 ice_rss_flow_types (vnet_dev_port_t *);

vnet_dev_rv_t ice_rss_get_config (vlib_main_t *, vnet_dev_port_t *, ice_aq_rss_key_t *,
				  ice_aq_rss_lut_t *);
vnet_dev_rv_t ice_rss_configure (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ice_rss_set_config (vlib_main_t *, vnet_dev_port_t *, const vnet_dev_rss_config_t *);
vnet_dev_rv_t ice_rss_validate_config (vnet_dev_port_t *, const vnet_dev_rss_config_t *);

/* rx_node.c */
extern vnet_dev_node_t ice_rx_node;

/* tx_node.c */
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
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev),           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, ice_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#ifdef ICE_DEBUG_NOISY
#define log_debug_noisy(dev, f, ...) log_debug (dev, f, ##__VA_ARGS__)
#else
#define log_debug_noisy(dev, f, ...)
#endif

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
