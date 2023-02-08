/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_REG_DEFS_H_
#define _ENA_REG_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

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

#define foreach_ena_reset_reason                                              \
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
#define _(o, n) ENA_RESET_REASON_##n = o,
  foreach_ena_reset_reason
#undef _
} ena_reset_reason_t;

#endif /* _ENA_REG_DEFS_H_ */
