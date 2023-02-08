/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_DEFS_H_
#define _ENA_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define PCI_VENDOR_ID_AMAZON		   0x1d0f
#define PCI_DEVICE_ID_AMAZON_ENA_PF	   0x0ec2
#define PCI_DEVICE_ID_AMAZON_ENA_PF_RSERV0 0x1ec2
#define PCI_DEVICE_ID_AMAZON_ENA_VF	   0xec20
#define PCI_DEVICE_ID_AMAZON_ENA_VF_RSERV0 0xec21

#define ena_reg_version_t_fields                                              \
  __ (8, minor)                                                               \
  __ (8, major)

#define ena_reg_controller_version_t_fields                                   \
  __ (8, subminor)                                                            \
  __ (8, minor)                                                               \
  __ (8, major)                                                               \
  __ (8, impl_id)

#define ena_reg_caps_t_fields                                                 \
  __ (1, contiguous_queue_required)                                           \
  __ (5, reset_timeout)                                                       \
  __ (2, _unused)                                                             \
  __ (8, dma_addr_width)                                                      \
  __ (4, admin_cmd_to)

#define ena_reg_aq_caps_t_fields                                              \
  __ (16, depth)                                                              \
  __ (16, entry_size)

#define ena_reg_acq_caps_t_fields                                             \
  __ (16, depth)                                                              \
  __ (16, entry_size)

#define ena_reg_aenq_caps_t_fields                                            \
  __ (16, depth)                                                              \
  __ (16, entry_size)

#define ena_reg_dev_ctl_t_fields                                              \
  __ (1, dev_reset)                                                           \
  __ (1, aq_restart)                                                          \
  __ (1, quiescent)                                                           \
  __ (1, io_resume)                                                           \
  __ (24, _unused)                                                            \
  __ (4, reset_reason)

#define ena_reg_dev_sts_t_fields                                              \
  __ (1, ready)                                                               \
  __ (1, aq_restart_in_progress)                                              \
  __ (1, aq_restart_finished)                                                 \
  __ (1, reset_in_progress)                                                   \
  __ (1, reset_finished)                                                      \
  __ (1, fatal_error)                                                         \
  __ (1, quiescent_state_in_progress)                                         \
  __ (1, quiescent_state_achieved)

#define ena_reg_mmio_reg_read_t_fields                                        \
  __ (16, req_id)                                                             \
  __ (16, reg_off)

#define ena_reg_rss_ind_entry_update_t_fields                                 \
  __ (16, index)                                                              \
  __ (16, cx_idx)

#define __(l, f) u32 f : l;
#define _(n)                                                                  \
  typedef union                                                               \
  {                                                                           \
    struct                                                                    \
    {                                                                         \
      n##_fields;                                                             \
    };                                                                        \
    u32 as_u32;                                                               \
  } n;

_ (ena_reg_version_t)
_ (ena_reg_controller_version_t)
_ (ena_reg_caps_t)
_ (ena_reg_aq_caps_t)
_ (ena_reg_acq_caps_t)
_ (ena_reg_aenq_caps_t)
_ (ena_reg_dev_ctl_t)
_ (ena_reg_dev_sts_t)
_ (ena_reg_mmio_reg_read_t)
_ (ena_reg_rss_ind_entry_update_t)
#undef _
#undef __

#define foreach_ena_reg                                                       \
  _ (0x00, 1, VERSION, ena_reg_version_t_fields)                              \
  _ (0x04, 1, CONTROLLER_VERSION, ena_reg_controller_version_t_fields)        \
  _ (0x08, 1, CAPS, ena_reg_caps_t_fields)                                    \
  _ (0x0c, 1, EXT_CAPS, )                                                     \
  _ (0x10, 1, AQ_BASE_LO, )                                                   \
  _ (0x14, 1, AQ_BASE_HI, )                                                   \
  _ (0x18, 1, AQ_CAPS, ena_reg_aq_caps_t_fields)                              \
  _ (0x20, 1, ACQ_BASE_LO, )                                                  \
  _ (0x24, 1, ACQ_BASE_HI, )                                                  \
  _ (0x28, 1, ACQ_CAPS, ena_reg_acq_caps_t_fields)                            \
  _ (0x2c, 0, AQ_DB, )                                                        \
  _ (0x30, 0, ACQ_TAIL, )                                                     \
  _ (0x34, 1, AENQ_CAPS, ena_reg_aenq_caps_t_fields)                          \
  _ (0x38, 0, AENQ_BASE_LO, )                                                 \
  _ (0x3c, 0, AENQ_BASE_HI, )                                                 \
  _ (0x40, 0, AENQ_HEAD_DB, )                                                 \
  _ (0x44, 0, AENQ_TAIL, )                                                    \
  _ (0x4c, 1, INTR_MASK, )                                                    \
  _ (0x54, 0, DEV_CTL, ena_reg_dev_ctl_t_fields)                              \
  _ (0x58, 1, DEV_STS, ena_reg_dev_sts_t_fields)                              \
  _ (0x5c, 0, MMIO_REG_READ, ena_reg_mmio_reg_read_t_fields)                  \
  _ (0x60, 0, MMIO_RESP_LO, )                                                 \
  _ (0x64, 0, MMIO_RESP_HI, )                                                 \
  _ (0x68, 0, RSS_IND_ENTRY_UPDATE, ena_reg_rss_ind_entry_update_t_fields)

typedef enum
{
#define _(o, r, n, f) ENA_REG_##n = o,
  foreach_ena_reg
#undef _
} ena_reg_t;

#define foreach_ena_reg_reset_reason                                          \
  _ (0, NORMAL)                                                               \
  _ (1, KEEP_ALIVE_TO)                                                        \
  _ (2, ADMIN_TO)                                                             \
  _ (3, MISS_TX_CMPL)                                                         \
  _ (4, INV_RX_REQ_ID)                                                        \
  _ (5, INV_TX_REQ_ID)                                                        \
  _ (6, TOO_MANY_RX_DESCS)                                                    \
  _ (7, INIT_ERR)                                                             \
  _ (8, DRIVER_INVALID_STATE)                                                 \
  _ (9, OS_TRIGGER)                                                           \
  _ (10, OS_NETDEV_WD)                                                        \
  _ (11, SHUTDOWN)                                                            \
  _ (12, USER_TRIGGER)                                                        \
  _ (13, GENERIC)                                                             \
  _ (14, MISS_INTERRUPT)

typedef enum
{
#define _(o, n) ENA_REG_RESET_REASON_##n = o,
  foreach_ena_reg_reset_reason
#undef _
} ena_reg_reset_reason_t;

#define foreach_ena_admin_aq_opcode                                           \
  _ (CREATE_SQ, 1)                                                            \
  _ (DESTROY_SQ, 2)                                                           \
  _ (CREATE_CQ, 3)                                                            \
  _ (DESTROY_CQ, 4)                                                           \
  _ (GET_FEATURE, 8)                                                          \
  _ (SET_FEATURE, 9)                                                          \
  _ (GET_STATS, 11)

typedef enum
{
#define _(n, v) ENA_ADMIN_##n = (v),
  foreach_ena_admin_aq_opcode
#undef _
} ena_admin_aq_opcode_t;

/*
 * MMIO Response
 */
typedef struct
{
  u16 req_id;
  u16 reg_off;
  u32 reg_val;
} ena_mmio_resp_t;

/*
 * Admin Queue
 */

typedef struct
{
  /* common desc */
  u16 command_id;
  u8 opcode;
  u8 flags;
  union
  {
    u32 data[15];

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
  };
} __clib_packed ena_aq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aq_entry_t, 64);

typedef struct
{
  /* common desc */
  u16 command;
  u8 status;
  u8 flags;
  u16 extended_status;
  u16 sq_head_indx;

  union
  {
    u32 data[14];

    struct
    {
      u16 sq_idx;
      u16 reserved;
      u32 sq_doorbell_offset;
      u32 llq_descriptors_offset;
      u32 llq_headers_offset;
    } __clib_packed create_sq_resp;

    struct
    {
      u16 cq_idx;
      u16 cq_actual_depth;
      u32 numa_node_register_offset;
      u32 cq_head_db_register_offset;
      u32 cq_interrupt_unmask_register_offset;
    } __clib_packed create_cq_resp;
  };
} __clib_packed ena_acq_entry_t;

STATIC_ASSERT_SIZEOF (ena_acq_entry_t, 64);

typedef struct
{
  u16 group;
  u16 syndrome;
  u8 flags;
  u8 reserved1[3];
  u32 timestamp_low;
  u32 timestamp_high;

  union
  {
    u32 data[12];
  };
} __clib_packed ena_aenq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aenq_entry_t, 64);

#endif /* ENA_DEFS_H */
