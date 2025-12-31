/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#pragma once

#include <vppinfra/clib.h>

typedef struct
{
  u32 chcfg;
  u32 chtype;
  u32 erindex;
  u32 rbase_lo;
  u32 rbase_hi;
  u32 rlen_lo;
  u32 rlen_hi;
  u32 rp_lo;
  u32 rp_hi;
  u32 wp_lo;
  u32 wp_hi;
} __clib_packed mhi_chan_ctxt_t;

typedef struct
{
  u32 intmod;
  u32 ertype;
  u32 msivec;
  u32 rbase_lo;
  u32 rbase_hi;
  u32 rlen_lo;
  u32 rlen_hi;
  u32 rp_lo;
  u32 rp_hi;
  u32 wp_lo;
  u32 wp_hi;
} __clib_packed mhi_event_ctxt_t;

typedef struct
{
  u32 reserved[3];
  u32 rbase_lo;
  u32 rbase_hi;
  u32 rlen_lo;
  u32 rlen_hi;
  u32 rp_lo;
  u32 rp_hi;
  u32 wp_lo;
  u32 wp_hi;
} __clib_packed mhi_cmd_ctxt_t;

typedef struct
{
  u64 ptr;
  u32 dword[2];
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

/* TRE Macros */
#define MHI_TRE_CMD_DWORD1(chid, type) ((chid << 24) | (type << 16))
