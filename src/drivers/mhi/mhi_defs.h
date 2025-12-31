/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

typedef struct
{
  u32 chcfg;
  u32 chtype;
  u32 erindex;
  u64 rbase __clib_packed __clib_aligned (4);
  u64 rlen __clib_packed __clib_aligned (4);
  u64 rp __clib_packed __clib_aligned (4);
  u64 wp __clib_packed __clib_aligned (4);
} mhi_chan_ctxt_t;
STATIC_ASSERT_SIZEOF (mhi_chan_ctxt_t, 44);

typedef struct
{
  u32 intmod;
  u32 ertype;
  u32 msivec;
  u64 rbase __clib_packed __clib_aligned (4);
  u64 rlen __clib_packed __clib_aligned (4);
  u64 rp __clib_packed __clib_aligned (4);
  u64 wp __clib_packed __clib_aligned (4);
} mhi_event_ctxt_t;
STATIC_ASSERT_SIZEOF (mhi_event_ctxt_t, 44);

typedef struct
{
  u32 reserved[3];
  u64 rbase __clib_packed __clib_aligned (4);
  u64 rlen __clib_packed __clib_aligned (4);
  u64 rp __clib_packed __clib_aligned (4);
  u64 wp __clib_packed __clib_aligned (4);
} mhi_cmd_ctxt_t;
STATIC_ASSERT_SIZEOF (mhi_cmd_ctxt_t, 44);

#define foreach_mhi_pkt_type                                                  \
  _ (0x01, NOOP, "No-op")                                                     \
  _ (0x02, TRANSFER, "Transfer")                                              \
  _ (0x08, COALESCING, "Coalescing")                                          \
  _ (0x10, RESET_CHAN, "Reset Channel")                                       \
  _ (0x11, STOP_CHAN, "Stop Channel")                                         \
  _ (0x12, START_CHAN, "Start Channel")                                       \
  _ (0x20, STATE_CHANGE, "State Change")                                      \
  _ (0x21, CMD_COMPLETION, "Command Completion")                              \
  _ (0x22, TX, "Transfer Completion")                                         \
  _ (0x28, RSC_TX, "RSC Transfer Completion")                                 \
  _ (0x40, EE, "Execution Environment")                                       \
  _ (0x48, TSYNC, "Time Sync")                                                \
  _ (0x50, BW_REQ, "Bandwidth Request")

typedef enum
{
#define _(_v, _n, _d) MHI_PKT_TYPE_##_n = (_v),
  foreach_mhi_pkt_type
#undef _
} mhi_pkt_type_t;

typedef struct
{
  u64 ptr;
  union
  {
    struct
    {
      u32 dword0;
      u32 dword1;
    };
    struct
    {
      u32 len : 16;
      u32 res0 : 8;
      u32 state : 8;
      u32 res1 : 16;
      mhi_pkt_type_t type : 8;
      u32 code : 8;
    };
    /* Transfer View */
    struct
    {
      u32 t_len : 16;
      u32 t_res0 : 16;
      u32 chain : 1;
      u32 t_res1 : 7;
      u32 ieob : 1;
      u32 ieot : 1;
      u32 bei : 1;
      u32 t_res2 : 5;
      mhi_pkt_type_t t_type : 8;
      u32 t_res3 : 8;
    };
    /* Command View */
    struct
    {
      u32 c_res0 : 32;
      u32 c_res1 : 16;
      mhi_pkt_type_t c_type : 8;
      u32 chid : 8;
    };
  };
} __clib_packed mhi_tre_t;

STATIC_ASSERT_SIZEOF (mhi_tre_t, 16);

#define foreach_mhi_ee                                                        \
  _ (0, PBL, "Primary Bootloader (PBL)")                                      \
  _ (1, SBL, "Secondary Bootloader (SBL)")                                    \
  _ (2, AMSS, "Mission Mode (AMSS)")                                          \
  _ (3, RDDM, "Ramdump Download Mode (RDDM)")                                 \
  _ (4, WFW, "WLAN Firmware (WFW)")                                           \
  _ (5, PTHRU, "Pass Through (PTHRU)")                                        \
  _ (6, EDL, "Emergency Download (EDL)")                                      \
  _ (7, FP, "Flash Programmer (FP)")

typedef enum
{
#define _(_v, _n, _d) MHI_EE_##_n = (_v),
  foreach_mhi_ee
#undef _
    MHI_EE_MAX,
} mhi_ee_t;

/* Command Types */
#define MHI_CMD_RESET_CHAN 16
#define MHI_CMD_STOP_CHAN  17
#define MHI_CMD_START_CHAN 18

#define foreach_mhi_state                                                     \
  _ (0, RESET, "Reset")                                                       \
  _ (1, READY, "Ready")                                                       \
  _ (2, M0, "M0")                                                             \
  _ (3, M1, "M1")                                                             \
  _ (4, M2, "M2")                                                             \
  _ (5, M3, "M3")

typedef enum
{
#define _(_v, _n, _d) MHI_STATE_##_n = (_v),
  foreach_mhi_state
#undef _
    MHI_STATE_MAX,
} mhi_state_t;

#define foreach_mhi_ch_state                                                  \
  _ (0, DISABLED, "Disabled")                                                 \
  _ (1, ENABLED, "Enabled")                                                   \
  _ (2, RUNNING, "Running")                                                   \
  _ (3, SUSPENDED, "Suspended")                                               \
  _ (4, STOP, "Stop")                                                         \
  _ (5, ERROR, "Error")

typedef enum
{
#define _(_v, _n, _d) MHI_CH_STATE_##_n = (_v),
  foreach_mhi_ch_state
#undef _
} mhi_ch_state_t;
