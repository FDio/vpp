/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_ADMIN_DEFS_H_
#define _ENA_ADMIN_DEFS_H_

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

typedef enum
{
#define _(v, n) ENA_AQ_OPCODE_##n = (v),
  foreach_ena_aq_opcode
#undef _
} __clib_packed ena_aq_opcode_t;

#define foreach_ena_aq_compl_status                                           \
  _ (0, SUCCESS)                                                              \
  _ (1, RESOURCE_ALLOCATION_FAILURE)                                          \
  _ (2, BAD_OPCODE)                                                           \
  _ (3, UNSUPPORTED_OPCODE)                                                   \
  _ (4, MALFORMED_REQUEST)                                                    \
  _ (5, ILLEGAL_PARAMETER)                                                    \
  _ (6, UNKNOWN_ERROR)                                                        \
  _ (7, RESOURCE_BUSY)

typedef enum
{
#define _(v, n) ENA_ADMIN_COMPL_STATUS_##n = (v),
  foreach_ena_aq_compl_status
#undef _
} __clib_packed ena_aq_compl_status_t;

/* id, versiom, get, set, name, struct */
#define foreach_ena_aq_feature_id                                             \
  _ (1, 0, 1, 0, DEVICE_ATTRIBUTES, ena_aq_feat_device_attr_t)                \
  _ (2, 0, 1, 0, MAX_QUEUES_NUM, ena_aq_feat_max_queue_num_t)                 \
  _ (3, 0, 1, 0, HW_HINTS, ena_aq_feat_hw_hints_t)                            \
  _ (4, 0, 1, 1, LLQ, ena_aq_feat_llq_t)                                      \
  _ (5, 0, 1, 0, EXTRA_PROPERTIES_STRINGS,                                    \
     ena_aq_feat_extra_properties_strings_t)                                  \
  _ (6, 0, 1, 0, EXTRA_PROPERTIES_FLAGS,                                      \
     ena_aq_feat_extra_properties_flags_t)                                    \
  _ (7, 1, 1, 0, MAX_QUEUES_EXT, ena_aq_feat_max_queue_ext_t)                 \
  _ (10, 0, 1, 1, RSS_HASH_FUNCTION, ena_aq_feat_rss_hash_function_t)         \
  _ (11, 0, 1, 0, STATELESS_OFFLOAD_CONFIG,                                   \
     ena_aq_feat_stateless_offload_config_t)                                  \
  _ (12, 0, 1, 1, RSS_INDIRECTION_TABLE_CONFIG,                               \
     ena_aq_feat_rss_ind_table_config_t)                                      \
  _ (14, 0, 0, 1, MTU, ena_aq_feat_mtu_t)                                     \
  _ (18, 0, 1, 1, RSS_HASH_INPUT, ena_aq_feat_rss_hash_input_t)               \
  _ (20, 0, 1, 0, INTERRUPT_MODERATION, ena_aq_feat_intr_moder_t)             \
  _ (26, 0, 1, 1, AENQ_CONFIG, ena_aq_feat_aenq_config_t)                     \
  _ (27, 0, 1, 0, LINK_CONFIG, ena_aq_feat_link_config_t)                     \
  _ (28, 0, 0, 1, HOST_ATTR_CONFIG, ena_aq_feat_host_attr_config_t)           \
  _ (29, 0, 1, 1, PHC_CONFIG, ena_aq_feat_phc_config_t)

typedef enum
{
#define _(v, ver, r, w, n, s) ENA_ADMIN_FEAT_ID_##n = (v),
  foreach_ena_aq_feature_id
#undef _
} __clib_packed ena_aq_feature_id_t;

#define foreach_ena_aq_stats_type                                             \
  _ (0, BASIC)                                                                \
  _ (1, EXTENDED)                                                             \
  _ (2, ENI)

#define foreach_ena_aq_stats_scope                                            \
  _ (0, SPECIFIC_QUEUE)                                                       \
  _ (1, ETH_TRAFFIC)

typedef enum
{
#define _(v, n) ENA_ADMIN_STATS_TYPE_##n = (v),
  foreach_ena_aq_stats_type
#undef _
} __clib_packed ena_aq_stats_type_t;

typedef enum
{
#define _(v, n) ENA_ADMIN_STATS_SCOPE_##n = (v),
  foreach_ena_aq_stats_scope
#undef _
} __clib_packed ena_aq_stats_scope_t;

typedef struct
{
  u32 addr_lo;
  u16 addr_hi;
  u16 _reserved_16;
} ena_mem_addr_t;

#define foreach_ena_aq_aenq_groups                                            \
  _ (link_change)                                                             \
  _ (fatal_error)                                                             \
  _ (warning)                                                                 \
  _ (notification)                                                            \
  _ (keep_alive)

typedef union
{
  struct
  {
#define _(g) u32 g : 1;
    foreach_ena_aq_aenq_groups
#undef _
  };
  u32 as_u32;
} ena_aq_aenq_groups_t;

STATIC_ASSERT_SIZEOF (ena_aq_aenq_groups_t, 4);

typedef struct
{
  u32 length;
  ena_mem_addr_t addr;
} ena_aq_aq_ctrl_buff_info_t;

typedef struct
{
  u32 impl_id;
  u32 device_version;
  u32 supported_features;
  u32 _reserved3;
  u32 phys_addr_width;
  u32 virt_addr_width;
  u8 mac_addr[6];
  u8 _reserved7[2];
  u32 max_mtu;
} ena_aq_feat_device_attr_t;

typedef struct
{
  union
  {
    struct
    {
      u16 l3_sort : 1;
      u16 l4_sort : 1;
    };
    u16 supported_input_sort;
  };
  union
  {
    struct
    {
      u16 enable_l3_sort : 1;
      u16 enable_l4_sort : 1;
    };
    u16 enabled_input_sort;
  };
} ena_aq_feat_rss_hash_input_t;

STATIC_ASSERT_SIZEOF (ena_aq_feat_rss_hash_input_t, 4);

typedef struct
{
  u16 intr_delay_resolution;
  u16 reserved;
} ena_aq_feat_intr_moder_t;

typedef struct
{
  ena_aq_aenq_groups_t supported_groups;
  ena_aq_aenq_groups_t enabled_groups;
} ena_aq_feat_aenq_config_t;

#define foreach_ena_aq_link_types                                             \
  _ (0, 1000, 1G)                                                             \
  _ (1, 2500, 2_5G)                                                           \
  _ (2, 5000, 5G)                                                             \
  _ (3, 10000, 10G)                                                           \
  _ (4, 25000, 25G)                                                           \
  _ (5, 40000, 40G)                                                           \
  _ (6, 50000, 50G)                                                           \
  _ (7, 100000, 100G)                                                         \
  _ (8, 200000, 200G)                                                         \
  _ (9, 400000, 400G)

typedef enum
{
#define _(b, v, n) ENA_ADMIN_LINK_TYPE_##n = (1U << b),
  foreach_ena_aq_link_types
#undef _
} ena_aq_link_types_t;

typedef struct
{
  u32 speed;
  ena_aq_link_types_t supported;
  u32 autoneg : 1;
  u32 duplex : 1;
} ena_aq_feat_link_config_t;

STATIC_ASSERT_SIZEOF (ena_aq_feat_link_config_t, 12);

typedef struct
{
  u32 tx;
  u32 rx_supported;
  u32 rx_enabled;
} ena_aq_feat_stateless_offload_config_t;

typedef struct
{
  u16 cq_idx;
  u16 reserved;
} ena_aq_feat_rss_ind_table_entry_t;

typedef struct
{
  u16 min_size;
  u16 max_size;
  u16 size;
  u8 one_entry_update : 1;
  u8 reserved;
  u32 inline_index;
  ena_aq_feat_rss_ind_table_entry_t inline_entry;
} ena_aq_feat_rss_ind_table_config_t;

typedef struct
{
  u32 mtu;
} ena_aq_feat_mtu_t;

typedef struct
{
  u32 count;
} ena_aq_feat_extra_properties_strings_t;

typedef struct
{
  u32 flags;
} ena_aq_feat_extra_properties_flags_t;

typedef struct
{
  u32 max_sq_num;
  u32 max_sq_depth;
  u32 max_cq_num;
  u32 max_cq_depth;
  u32 max_legacy_llq_num;
  u32 max_legacy_llq_depth;
  u32 max_header_size;
  u16 max_packet_tx_descs;
  u16 max_packet_rx_descs;
} ena_aq_feat_max_queue_num_t;

typedef struct
{
  u16 mmio_read_timeout;
  u16 driver_watchdog_timeout;
  u16 missing_tx_completion_timeout;
  u16 missed_tx_completion_count_threshold_to_reset;
  u16 admin_completion_tx_timeout;
  u16 netdev_wd_timeout;
  u16 max_tx_sgl_size;
  u16 max_rx_sgl_size;
  u16 reserved[8];
} ena_aq_feat_hw_hints_t;

typedef struct
{
  u8 version;
  u8 _reserved1[3];
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
} ena_aq_feat_max_queue_ext_t;

typedef struct
{
  u32 supported_func;
  u32 selected_func;
  u32 init_val;
} ena_aq_feat_rss_hash_function_t;

typedef struct
{
  ena_mem_addr_t os_info_ba;
  ena_mem_addr_t debug_ba;
  u32 debug_area_size;
} ena_aq_feat_host_attr_config_t;

typedef struct
{
  u8 type;
  u8 reserved1[3];
  u32 doorbell_offset;
  u32 expire_timeout_usec;
  u32 block_timeout_usec;
  ena_mem_addr_t output_address;
  u32 output_length;
} ena_aq_feat_phc_config_t;

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
} ena_aq_feat_llq_t;

typedef struct
{
  /* feat common */
  u8 flags;
  ena_aq_feature_id_t feature_id;
  u8 feature_version;
  u8 _reserved;
} ena_aq_get_set_feature_common_desc_t;

STATIC_ASSERT_SIZEOF (ena_aq_get_set_feature_common_desc_t, 4);

typedef struct
{
  ena_aq_aq_ctrl_buff_info_t control_buffer;
  ena_aq_stats_type_t type;
  ena_aq_stats_scope_t scope;
  u16 _reserved3;
  u16 queue_idx;
  u16 device_id;
} ena_aq_get_stats_cmd_t;
STATIC_ASSERT_SIZEOF (ena_aq_get_stats_cmd_t, 20);

typedef enum
{
  ENA_ADMIN_SQ_DIRECTION_TX = 1,
  ENA_ADMIN_SQ_DIRECTION_RX = 2,
} ena_aq_sq_direction_t;

typedef enum
{
  ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST = 1,
  ENA_ADMIN_SQ_PLACEMENT_POLICY_DEVICE = 3,
} ena_aq_sq_placement_policy_t;

typedef enum
{
  ENA_ADMIN_SQ_COMPLETION_POLICY_DESC = 0,
  ENA_ADMIN_SQ_COMPLETION_POLICY_DESC_ON_DEMAND = 1,
  ENA_ADMIN_SQ_COMPLETION_POLICY_HEAD_ON_DEMAND = 2,
  ENA_ADMIN_SQ_COMPLETION_POLICY_HEAD = 3,
} ena_aq_completion_policy_t;

typedef struct
{
  union
  {
    struct
    {
      u8 _reserved0_0 : 5;
      u8 sq_direction : 3; /* ena_aq_sq_direction_t */
    };
    u8 sq_identity;
  };

  u8 _reserved1;

  union
  {
    struct
    {
      u8 placement_policy : 4;	/* ena_aq_sq_placement_policy_t */
      u8 completion_policy : 3; /* ena_aq_completion_policy_t */
      u8 _reserved2_7 : 1;
    };
    u8 sq_caps_2;
  };

  union
  {
    struct
    {
      u8 is_physically_contiguous : 1;
      u8 _reserved3_1 : 7;
    };
    u8 sq_caps_3;
  };

  u16 cq_idx;
  u16 sq_depth;
  ena_mem_addr_t sq_ba;
  ena_mem_addr_t sq_head_writeback; /* used if completion_policy is 2 or 3 */
  u32 _reserved0_w7;
  u32 _reserved0_w8;
} ena_aq_create_sq_cmd_t;

typedef struct
{
  u16 sq_idx;
  u16 _reserved;
  u32 sq_doorbell_offset;     /* REG BAR offset of queue dorbell */
  u32 llq_descriptors_offset; /* LLQ MEM BAR offset of descriptors */
  u32 llq_headers_offset;     /* LLQ MEM BAR offset of headers mem */
} ena_aq_create_sq_resp_t;

typedef struct
{
  union
  {
    struct
    {
      u8 _reserved0_0 : 5;
      u8 interrupt_mode_enabled : 1;
      u8 _reserved0_6 : 2;
    };
    u8 cq_caps_1;
  };

  union
  {
    struct
    {
      u8 cq_entry_size_words : 4;
      u8 _reserved1_4 : 4;
    };
    u8 cq_caps_2;
  };

  u16 cq_depth;
  u32 msix_vector;
  ena_mem_addr_t cq_ba;
} ena_aq_create_cq_cmd_t;

typedef struct
{
  u16 cq_idx;
  u16 cq_actual_depth;
  u32 numa_node_register_offset;
  u32 cq_head_db_register_offset;
  u32 cq_interrupt_unmask_register_offset;
} ena_aq_create_cq_resp_t;

typedef struct
{
  u16 sq_idx;
  union
  {
    struct
    {
      u8 _reserved : 5;
      u8 sq_direction : 3; /* ena_aq_sq_direction_t */
    };
    u8 sq_identity;
  };
  u8 _reserved1;
} ena_aq_destroy_sq_cmd_t;

typedef struct
{
  u16 cq_idx;
  u16 _reserved1;
} ena_aq_destroy_cq_cmd_t;

STATIC_ASSERT_SIZEOF (ena_aq_create_sq_cmd_t, 32);
STATIC_ASSERT_SIZEOF (ena_aq_create_sq_resp_t, 16);
STATIC_ASSERT_SIZEOF (ena_aq_create_cq_cmd_t, 16);
STATIC_ASSERT_SIZEOF (ena_aq_create_cq_resp_t, 16);
STATIC_ASSERT_SIZEOF (ena_aq_destroy_sq_cmd_t, 4);
STATIC_ASSERT_SIZEOF (ena_aq_destroy_cq_cmd_t, 4);

typedef struct
{
  /* common desc */
  u16 command_id;
  ena_aq_opcode_t opcode;

  union
  {
    struct
    {
      u8 phase : 1;
      u8 ctrl_data : 1;
      u8 ctrl_data_indirect : 1;
      u8 _reserved_3_3 : 5;
    };
    u8 flags;
  };

  u32 data[15];
} ena_aq_sq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aq_sq_entry_t, 64);

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

  struct
  {
    u16 minor : 8;
    u16 major : 8;
  } ena_spec_version;

  struct
  {
    u16 function : 3;
    u16 device : 5;
    u16 bus : 8;
  } bdf;

  u16 num_cpus;
  u16 _reserved;

  union
  {
    struct
    {
      u32 _reserved0 : 1;
      u32 rx_offset : 1;
      u32 interrupt_moderation : 1;
      u32 rx_buf_mirroring : 1;
      u32 rss_configurable_function_key : 1;
      u32 _reserved5 : 1;
      u32 rx_page_reuse : 1;
      u32 _reserved7 : 25;
    };
    u32 as_u32;
  } driver_supported_features;

} ena_aq_host_info_t;

STATIC_ASSERT_SIZEOF (ena_aq_host_info_t, 196);

typedef struct
{
  union
  {
    u64 tx_bytes;
    struct
    {
      u32 tx_bytes_low;
      u32 tx_bytes_high;
    };
  };
  union
  {
    u64 tx_pkts;
    struct
    {
      u32 tx_pkts_low;
      u32 tx_pkts_high;
    };
  };
  union
  {
    u64 rx_bytes;
    struct
    {
      u32 rx_bytes_low;
      u32 rx_bytes_high;
    };
  };
  union
  {
    u64 rx_pkts;
    struct
    {
      u32 rx_pkts_low;
      u32 rx_pkts_high;
    };
  };
  union
  {
    u64 rx_drops;
    struct
    {
      u32 rx_drops_low;
      u32 rx_drops_high;
    };
  };
  union
  {
    u64 tx_drops;
    struct
    {
      u32 tx_drops_low;
      u32 tx_drops_high;
    };
  };
} ena_aq_basic_stats_t;

#define foreach_ena_aq_basic_counter                                          \
  _ (rx_pkts, "RX Packets")                                                   \
  _ (tx_pkts, "TX Packets")                                                   \
  _ (rx_bytes, "RX Bytes")                                                    \
  _ (tx_bytes, "TX Bytes")                                                    \
  _ (rx_drops, "RX Packet Drops")                                             \
  _ (tx_drops, "TX Packet Drops")

typedef struct
{
  u64 bw_in_allowance_exceeded;
  u64 bw_out_allowance_exceeded;
  u64 pps_allowance_exceeded;
  u64 conntrack_allowance_exceeded;
  u64 linklocal_allowance_exceeded;
} ena_aq_eni_stats_t;

#define foreach_ena_aq_eni_counter                                            \
  _ (bw_in_allowance_exceeded, "Input BW Allowance Exceeded")                 \
  _ (bw_out_allowance_exceeded, "Output BW Allowance Exceeded")               \
  _ (pps_allowance_exceeded, "PPS Allowance Exceeded")                        \
  _ (conntrack_allowance_exceeded, "ConnTrack Allowance Exceeded")            \
  _ (linklocal_allowance_exceeded, "LinkLocal Allowance Exceeded")

typedef struct
{
  /* common desc */
  u16 command;
  ena_aq_compl_status_t status;
  union
  {
    struct
    {
      u8 phase : 1;
      u8 _reserved3_1 : 7;
    };
    u8 flags;
  };
  u16 extended_status;
  u16 sq_head_indx;

  u32 data[14];
} ena_aq_cq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aq_cq_entry_t, 64);

#endif /* _ENA_ADMIN_DEFS_H_ */
