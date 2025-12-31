/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define mhi_reg_no_fields

#define mhi_reg_cfg_t_fields                                                  \
  __ (8, nch) __ (8, nhwch) __ (8, ner) __ (8, nhwer)
#define mhi_reg_ctrl_t_fields                                                 \
  __ (1, _reserved0)                                                          \
  __ (1, reset) __ (6, _reserved2) __ (8, mhi_state) __ (16, _reserved16)
#define mhi_reg_status_t_fields                                               \
  __ (1, ready)                                                               \
  __ (1, _reserved1)                                                          \
  __ (1, sys_err) __ (5, _reserved3) __ (8, mhi_state) __ (16, _reserved16)
#define bhi_reg_execenv_t_fields __ (32, execenv)
#define bhi_reg_status_t_fields	 __ (32, status)
#define bhi_reg_errcode_t_fields __ (32, errcode)
#define bhi_reg_errdbg_t_fields	 __ (32, errdbg)

#define MHI_REG_STRUCT(_type)                                                 \
  typedef union                                                               \
  {                                                                           \
    struct                                                                    \
    {                                                                         \
      _type##_fields;                                                         \
    };                                                                        \
    u32 as_u32;                                                               \
  } _type;                                                                    \
  STATIC_ASSERT_SIZEOF (_type, 4)

#define __(n, f) u32 f : n;
MHI_REG_STRUCT (mhi_reg_cfg_t);
MHI_REG_STRUCT (mhi_reg_ctrl_t);
MHI_REG_STRUCT (mhi_reg_status_t);
MHI_REG_STRUCT (bhi_reg_execenv_t);
MHI_REG_STRUCT (bhi_reg_status_t);
MHI_REG_STRUCT (bhi_reg_errcode_t);
MHI_REG_STRUCT (bhi_reg_errdbg_t);
#undef __

/* MHI Registers Offsets */
#define foreach_mhi_reg                                                       \
  MHI_REG_DEF (0x00, REGLEN, mhi_reg_no_fields)                               \
  MHI_REG_DEF (0x08, VER, mhi_reg_no_fields)                                  \
  MHI_REG_DEF (0x10, CFG, mhi_reg_cfg_t_fields)                               \
  MHI_REG_DEF (0x18, CHDBOFF, mhi_reg_no_fields)                              \
  MHI_REG_DEF (0x20, ERDBOFF, mhi_reg_no_fields)                              \
  MHI_REG_DEF (0x28, BHIOFF, mhi_reg_no_fields)                               \
  MHI_REG_DEF (0x2C, BHIEOFF, mhi_reg_no_fields)                              \
  MHI_REG_DEF (0x30, DEBUGOFF, mhi_reg_no_fields)                             \
  MHI_REG_DEF (0x38, CTRL, mhi_reg_ctrl_t_fields)                             \
  MHI_REG_DEF (0x48, STATUS, mhi_reg_status_t_fields)                         \
  MHI_REG_DEF (0x58, CCABAP_LOWER, mhi_reg_no_fields)                         \
  MHI_REG_DEF (0x5C, CCABAP_HIGHER, mhi_reg_no_fields)                        \
  MHI_REG_DEF (0x60, ECABAP_LOWER, mhi_reg_no_fields)                         \
  MHI_REG_DEF (0x64, ECABAP_HIGHER, mhi_reg_no_fields)                        \
  MHI_REG_DEF (0x68, CRCBAP_LOWER, mhi_reg_no_fields)                         \
  MHI_REG_DEF (0x6C, CRCBAP_HIGHER, mhi_reg_no_fields)                        \
  MHI_REG_DEF (0x70, CRDB_LOWER, mhi_reg_no_fields)                           \
  MHI_REG_DEF (0x74, CRDB_HIGHER, mhi_reg_no_fields)                          \
  MHI_REG_DEF (0x80, MHICTRLBASE_LOWER, mhi_reg_no_fields)                    \
  MHI_REG_DEF (0x84, MHICTRLBASE_HIGHER, mhi_reg_no_fields)                   \
  MHI_REG_DEF (0x88, MHICTRLLIMIT_LOWER, mhi_reg_no_fields)                   \
  MHI_REG_DEF (0x8C, MHICTRLLIMIT_HIGHER, mhi_reg_no_fields)                  \
  MHI_REG_DEF (0x98, MHIDATABASE_LOWER, mhi_reg_no_fields)                    \
  MHI_REG_DEF (0x9C, MHIDATABASE_HIGHER, mhi_reg_no_fields)                   \
  MHI_REG_DEF (0xA0, MHIDATALIMIT_LOWER, mhi_reg_no_fields)                   \
  MHI_REG_DEF (0xA4, MHIDATALIMIT_HIGHER, mhi_reg_no_fields)                  \
  MHI_REG_DEF (0xB0, SOC_RESET_REQ, mhi_reg_no_fields)

/* BHI Registers Offsets (relative to BHI base) */
#define foreach_bhi_reg                                                       \
  MHI_REG_DEF (0x00, VER_MINOR, mhi_reg_no_fields)                            \
  MHI_REG_DEF (0x04, VER_MAJOR, mhi_reg_no_fields)                            \
  MHI_REG_DEF (0x20, INTVEC, mhi_reg_no_fields)                               \
  MHI_REG_DEF (0x28, EXECENV, bhi_reg_execenv_t_fields)                       \
  MHI_REG_DEF (0x2C, STATUS, bhi_reg_status_t_fields)                         \
  MHI_REG_DEF (0x30, ERRCODE, bhi_reg_errcode_t_fields)                       \
  MHI_REG_DEF (0x34, ERRDBG1, bhi_reg_errdbg_t_fields)                        \
  MHI_REG_DEF (0x40, SERIALNU, mhi_reg_no_fields)                             \
  MHI_REG_DEF (0x44, SBLANTIROLLVER, mhi_reg_no_fields)                       \
  MHI_REG_DEF (0x48, NUMSEG, mhi_reg_no_fields)                               \
  MHI_REG_DEF (0x4C, MSMHWID0, mhi_reg_no_fields)

typedef enum
{
#define MHI_REG_DEF(o, n, f) MHI_REG_##n = (o),
  foreach_mhi_reg
#undef MHI_REG_DEF
} mhi_reg_t;

typedef enum
{
#define MHI_REG_DEF(o, n, f) BHI_REG_##n = (o),
  foreach_bhi_reg
#undef MHI_REG_DEF
} bhi_reg_t;
