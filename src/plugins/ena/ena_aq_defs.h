/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_AQ_DEFS_H_
#define _ENA_AQ_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define foreach_ena_aq_opcode                                                 \
  _ (1, CREATE_SQ)                                                            \
  _ (2, DESTROY_SQ)                                                           \
  _ (3, CREATE_CQ)                                                            \
  _ (4, DESTROY_CQ)                                                           \
  _ (8, GET_FEATURE)                                                          \
  _ (9, SET_FEATURE)                                                          \
  _ (11, GET_STATS)

#define foreach_ena_aq_feat_id                                                \
  _ (1, 0, DEVICE_ATTRIBUTES, ena_admin_device_attr_feature_desc_t)           \
  _ (2, 0, MAX_QUEUES_NUM, u8)                                                \
  _ (3, 0, HW_HINTS, u8)                                                      \
  _ (4, 0, LLQ, u8)                                                           \
  _ (5, 0, EXTRA_PROPERTIES_STRINGS, u8)                                      \
  _ (6, 0, EXTRA_PROPERTIES_FLAGS, u8)                                        \
  _ (7, 1, MAX_QUEUES_EXT, ena_admin_max_queue_ext_feature_desc_t)            \
  _ (10, 0, RSS_HASH_FUNCTION, u8)                                            \
  _ (11, 0, STATELESS_OFFLOAD_CONFIG,                                         \
     ena_admin_stateless_offload_config_feature_desc_t)                       \
  _ (12, 0, RSS_INDIRECTION_TABLE_CONFIG, u8)                                 \
  _ (14, 0, MTU, u8)                                                          \
  _ (18, 0, RSS_HASH_INPUT, u8)                                               \
  _ (20, 0, INTERRUPT_MODERATION, u8)                                         \
  _ (26, 0, AENQ_CONFIG, ena_admin_aenq_config_feature_desc_t)                \
  _ (27, 0, LINK_CONFIG, u8)                                                  \
  _ (28, 0, HOST_ATTR_CONFIG, ena_admin_host_attr_config_feature_desc_t)

typedef enum
{
#define _(v, n) ENA_AQ_OPCODE_##n = (v),
  foreach_ena_aq_opcode
#undef _
} ena_aq_opcode_t;

typedef enum
{
#define _(v, ver, n, s) ENA_AQ_FEAT_ID_##n = (v),
  foreach_ena_aq_feat_id
#undef _
} ena_aq_feature_id_t;

typedef struct
{
  u32 addr_lo;
  u16 addr_hi;
  u16 reserved_16;
} ena_mem_addr_t;

typedef struct
{
  u32 length;
  ena_mem_addr_t addr;
} ena_aq_ctrl_buff_info_t;

typedef struct
{
  u32 impl_id;
  u32 device_version;
  u32 supported_features;
  u32 reserved3;
  u32 phys_addr_width;
  u32 virt_addr_width;
  u8 mac_addr[6];
  u8 reserved7[2];
  u32 max_mtu;
} ena_admin_device_attr_feature_desc_t;

typedef struct
{
  u32 supported_groups;
  u32 enabled_groups;
} ena_admin_aenq_config_feature_desc_t;

typedef struct
{
  u32 tx;
  u32 rx_supported;
  u32 rx_enabled;
} ena_admin_stateless_offload_config_feature_desc_t;

typedef struct
{
  u8 version;
  u8 reserved1[3];
  u32 max_tx_sq_num;
  u32 max_tx_cq_num;
  u32 max_rx_sq_num;
  u32 max_rx_cq_num;
  u32 max_tx_sq_depth;
  u32 max_tx_cq_depth;
  u32 max_rx_sq_depth;
  u32 max_rx_cq_depth;
  u32 max_tx_header_size;
  u16 max_per_packet_tx_descs;
  u16 max_per_packet_rx_descs;
} ena_admin_max_queue_ext_feature_desc_t;

typedef struct
{
  ena_mem_addr_t os_info_ba;
  ena_mem_addr_t debug_ba;
  u32 debug_area_size;
} ena_admin_host_attr_config_feature_desc_t;

typedef struct
{
  u32 max_llq_num;
  u32 max_llq_depth;
  u16 header_location_ctrl_supported;
  u16 header_location_ctrl_enabled;
  u16 entry_size_ctrl_supported;
  u16 entry_size_ctrl_enabled;
  u16 desc_num_before_header_supported;
  u16 desc_num_before_header_enabled;
  u16 descriptors_stride_ctrl_supported;
  u16 descriptors_stride_ctrl_enabled;
  union
  {
    struct
    {
      u16 supported_flags;
      u16 max_tx_burst_size;
    } get;
    struct
    {
      u16 enabled_flags;
    } set;
  } accel_mode;
} ena_admin_llq_feature_desc_t;

typedef struct
{
  ena_aq_ctrl_buff_info_t control_buffer;
  /* feat common */
  u8 flags;
  ena_aq_feature_id_t feature_id : 8;
  u8 feature_version;
  u8 reserved;
  u32 data[11];
} ena_aq_feature_data_t;

STATIC_ASSERT_SIZEOF (ena_aq_feature_data_t, 60);

typedef struct
{
  /* common desc */
  u16 command_id;
  ena_aq_opcode_t opcode : 8;

  union
  {
    struct
    {
      u8 phase : 1;
      u8 ctrl_data : 1;
      u8 ctrl_data_indirect : 1;
    };
    u8 flags;
  };

  union
  {
    u32 data[15];
    ena_aq_feature_data_t feat;

    /*
    struct
    {
      u8 sq_identity;
      u8 reserved8_w1;
      u8 sq_caps_2;
      u8 sq_caps_3;
      u16 cq_idx;
      u16 sq_depth;
      u64 sq_ba;
      u64 sq_head_writeback;
    } __clib_packed create_sq;
    */
  };
} ena_aq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aq_entry_t, 64);

typedef struct
{
  u32 os_type;
  u8 os_dist_str[128];
  u32 os_dist;
  u8 kernel_ver_str[32];
  u32 kernel_ver;

  struct
  {
    u8 major;
    u8 minor;
    u8 sub_minor;
    u8 module_type;
  } driver_version;

  u32 supported_network_features[2];
  u16 ena_spec_version;

  struct
  {
    u16 function : 3;
    u16 device : 5;
    u16 bus : 8;
  } bdf;

  u16 num_cpus;
  u16 reserved;

  union
  {
    struct
    {
      u32 reserved : 1;
      u32 rx_offset : 1;
      u32 interrupt_moderation : 1;
      u32 rx_buf_mirroring : 1;
      u32 rss_configurable_function_key : 1;
    };
    u32 as_u32;
  } driver_supported_features;

} ena_host_info_t;

STATIC_ASSERT_SIZEOF (ena_host_info_t, 196);

#endif /* _ENA_AQ_DEFS_H_ */
