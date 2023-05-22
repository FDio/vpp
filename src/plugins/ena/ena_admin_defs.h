/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_ADMIN_DEFS_H_
#define _ENA_ADMIN_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define foreach_ena_admin_opcode                                              \
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
  foreach_ena_admin_opcode
#undef _
} ena_admin_opcode_t;

#define foreach_ena_admin_compl_status                                        \
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
  foreach_ena_admin_compl_status
#undef _
} ena_admin_compl_status_t;

#define foreach_ena_admin_feature_id                                          \
  _ (1, 0, DEVICE_ATTRIBUTES, ena_admin_device_attr_feature_desc_t)           \
  _ (2, 0, MAX_QUEUES_NUM, u8)                                                \
  _ (3, 0, HW_HINTS, u8)                                                      \
  _ (4, 0, LLQ, ena_admin_llq_feature_desc_t)                                 \
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
#define _(v, ver, n, s) ENA_ADMIN_FEAT_ID_##n = (v),
  foreach_ena_admin_feature_id
#undef _
} ena_admin_feature_id_t;

#define foreach_ena_admin_stats_type                                          \
  _ (0, BASIC)                                                                \
  _ (1, EXTENDED)                                                             \
  _ (2, ENI)

#define foreach_ena_admin_stats_scope                                         \
  _ (0, SPECIFIC_QUEUE)                                                       \
  _ (1, ETH_TRAFFIC)

typedef enum
{
#define _(v, n) ENA_ADMIN_STATS_TYPE_##n = (v),
  foreach_ena_admin_stats_type
#undef _
} ena_admin_stats_type_t;

typedef enum
{
#define _(v, n) ENA_ADMIN_STATS_SCOPE_##n = (v),
  foreach_ena_admin_stats_scope
#undef _
} ena_admin_stats_scope_t;

typedef struct
{
  u32 addr_lo;
  u16 addr_hi;
  u16 _reserved_16;
} ena_mem_addr_t;

#define foreach_ena_admin_aenq_groups                                         \
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
    foreach_ena_admin_aenq_groups
#undef _
  };
  u32 as_u32;
} ena_admin_aenq_groups_t;

STATIC_ASSERT_SIZEOF (ena_admin_aenq_groups_t, 4);

typedef struct
{
  u32 length;
  ena_mem_addr_t addr;
} ena_admin_aq_ctrl_buff_info_t;

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
} ena_admin_device_attr_feature_desc_t;

typedef struct
{
  ena_admin_aenq_groups_t supported_groups;
  ena_admin_aenq_groups_t enabled_groups;
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
  /* feat common */
  u8 flags;
  ena_admin_feature_id_t feature_id : 8;
  u8 feature_version;
  u8 _reserved;
} ena_admin_get_set_feature_common_desc_t;

typedef struct
{
  ena_admin_aq_ctrl_buff_info_t control_buffer;
  ena_admin_stats_type_t type : 8;
  ena_admin_stats_scope_t scope : 8;
  u16 _reserved3;
  u16 queue_idx;
  u16 device_id;
} ena_admin_get_stats_cmd_t;
STATIC_ASSERT_SIZEOF (ena_admin_get_stats_cmd_t, 20);

typedef enum
{
  ENA_ADMIN_SQ_DIRECTION_TX = 1,
  ENA_ADMIN_SQ_DIRECTION_RX = 2,
} ena_admin_sq_direction_t;

typedef enum
{
  ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST = 1,
  ENA_ADMIN_SQ_PLACEMENT_POLICY_DEVICE = 3,
} ena_admin_sq_placement_policy_t;

typedef enum
{
  ENA_ADMIN_SQ_COMPLETION_POLICY_DESC = 0,
  ENA_ADMIN_SQ_COMPLETION_POLICY_DESC_ON_DEMAND = 1,
  ENA_ADMIN_SQ_COMPLETION_POLICY_HEAD_ON_DEMAND = 2,
  ENA_ADMIN_SQ_COMPLETION_POLICY_HEAD = 3,
} ena_admin_completion_policy_t;

typedef struct
{
  union
  {
    struct
    {
      u8 _reserved : 5;
      u8 sq_direction : 3; /* ena_admin_sq_direction_t */
    };
    u8 sq_identity;
  };

  u8 _reserved8_w1;

  union
  {
    struct
    {
      u8 placement_policy : 4;	/* ena_admin_sq_placement_policy_t */
      u8 completion_policy : 3; /* ena_admin_completion_policy_t */
    };
    u8 sq_caps_2;
  };

  union
  {
    struct
    {
      u8 is_physically_contiguous : 1;
    };
    u8 sq_caps_3;
  };

  u16 cq_idx;
  u16 sq_depth;
  ena_mem_addr_t sq_ba;
  ena_mem_addr_t sq_head_writeback; /* used if completion_policy is 2 or 3 */
  u32 _reserved0_w7;
  u32 _reserved0_w8;
} ena_admin_create_sq_cmd_t;

typedef struct
{
  u16 sq_idx;
  u16 _reserved;
  u32 sq_doorbell_offset;     /* REG BAR offset of queue dorbell */
  u32 llq_descriptors_offset; /* LLQ MEM BAR offset of descriptors */
  u32 llq_headers_offset;     /* LLQ MEM BAR offset of headers mem */
} ena_admin_create_sq_resp_t;

typedef struct
{
  union
  {
    struct
    {
      u8 _reserved : 5;
      u8 interrupt_mode_enabled : 1;
    };
    u8 cq_caps_1;
  };

  union
  {
    struct
    {
      u8 cq_entry_size_words : 4;
    };
    u8 cq_caps_2;
  };

  u16 cq_depth;
  u32 msix_vector;
  ena_mem_addr_t cq_ba;
} ena_admin_create_cq_cmd_t;

typedef struct
{
  u16 cq_idx;
  u16 cq_actual_depth;
  u32 numa_node_register_offset;
  u32 cq_head_db_register_offset;
  u32 cq_interrupt_unmask_register_offset;
} ena_admin_create_cq_resp_t;

typedef struct
{
  u16 sq_idx;
  union
  {
    struct
    {
      u8 _reserved : 5;
      u8 sq_direction : 3; /* ena_admin_sq_direction_t */
    };
    u8 sq_identity;
  };
  u8 _reserved1;
} ena_admin_destroy_sq_cmd_t;

typedef struct
{
  u16 cq_idx;
  u16 _reserved1;
} ena_admin_destroy_cq_cmd_t;

STATIC_ASSERT_SIZEOF (ena_admin_create_sq_cmd_t, 32);
STATIC_ASSERT_SIZEOF (ena_admin_create_sq_resp_t, 16);
STATIC_ASSERT_SIZEOF (ena_admin_create_cq_cmd_t, 16);
STATIC_ASSERT_SIZEOF (ena_admin_create_cq_resp_t, 16);
STATIC_ASSERT_SIZEOF (ena_admin_destroy_sq_cmd_t, 4);
STATIC_ASSERT_SIZEOF (ena_admin_destroy_cq_cmd_t, 4);

typedef struct
{
  /* common desc */
  u16 command_id;
  ena_admin_opcode_t opcode : 8;

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

  u32 data[15];
} ena_admin_sq_entry_t;

STATIC_ASSERT_SIZEOF (ena_admin_sq_entry_t, 64);

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
  u16 _reserved;

  union
  {
    struct
    {
      u32 _reserved : 1;
      u32 rx_offset : 1;
      u32 interrupt_moderation : 1;
      u32 rx_buf_mirroring : 1;
      u32 rss_configurable_function_key : 1;
    };
    u32 as_u32;
  } driver_supported_features;

} ena_admin_host_info_t;

STATIC_ASSERT_SIZEOF (ena_admin_host_info_t, 196);

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
} ena_admin_basic_stats_t;

typedef struct
{
  u64 bw_in_allowance_exceeded;
  u64 bw_out_allowance_exceeded;
  u64 pps_allowance_exceeded;
  u64 conntrack_allowance_exceeded;
  u64 linklocal_allowance_exceeded;
} ena_admin_eni_stats_t;

typedef struct
{
  /* common desc */
  u16 command;
  u8 status;
  union
  {
    struct
    {
      u8 phase : 1;
    };
    u8 flags;
  };
  u16 extended_status;
  u16 sq_head_indx;

  u32 data[14];
} ena_admin_cq_entry_t;

STATIC_ASSERT_SIZEOF (ena_admin_cq_entry_t, 64);

#endif /* _ENA_ADMIN_DEFS_H_ */
