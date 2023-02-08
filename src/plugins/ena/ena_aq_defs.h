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
  _ (1, 0, DEVICE_ATTRIBUTES)                                                 \
  _ (2, 0, MAX_QUEUES_NUM)                                                    \
  _ (3, 0, HW_HINTS)                                                          \
  _ (4, 0, LLQ)                                                               \
  _ (5, 0, EXTRA_PROPERTIES_STRINGS)                                          \
  _ (6, 0, EXTRA_PROPERTIES_FLAGS)                                            \
  _ (7, 1, MAX_QUEUES_EXT)                                                    \
  _ (10, 0, RSS_HASH_FUNCTION)                                                \
  _ (11, 0, STATELESS_OFFLOAD_CONFIG)                                         \
  _ (12, 0, RSS_INDIRECTION_TABLE_CONFIG)                                     \
  _ (14, 0, MTU)                                                              \
  _ (18, 0, RSS_HASH_INPUT)                                                   \
  _ (20, 0, INTERRUPT_MODERATION)                                             \
  _ (26, 0, AENQ_CONFIG)                                                      \
  _ (27, 0, LINK_CONFIG)                                                      \
  _ (28, 0, HOST_ATTR_CONFIG)                                                 \
  _ (32, 0, FEATURES_OPCODE_NUM)

typedef enum
{
#define _(v, n) ENA_AQ_OPCODE_##n = (v),
  foreach_ena_aq_opcode
#undef _
} ena_aq_opcode_t;

typedef enum
{
#define _(v, ver, n) ENA_AQ_FEAT_ID_##n = (v),
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

    struct
    {
      ena_aq_ctrl_buff_info_t control_buffer;
      /* feat common */
      u8 flags;
      ena_aq_feature_id_t feature_id : 8;
      u8 feature_version;
      u8 reserved;
      union
      {
	u32 raw[11];
      };
    } get_feat;

    struct
    {
      ena_aq_ctrl_buff_info_t control_buffer;
      /* feat common */
      u8 flags;
      ena_aq_feature_id_t feature_id : 8;
      u8 feature_version;
      u8 reserved;
      union
      {
	u32 raw[11];

	/* host attr */
	struct
	{
	  ena_mem_addr_t os_info_ba;
	  ena_mem_addr_t debug_ba;
	  u32 debug_area_size;
	} host_attr;
      };

    } set_feat;

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
