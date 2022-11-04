/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#ifndef __dma_intel_dsa_pci_h__
#define __dma_intel_dsa_pci_h__

#include <vlib/vlib.h>
#include <vlib/dma/dma.h>
#include <vlib/pci/pci.h>
#include <vppinfra/format.h>
#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/lock.h>

#define DSA_CMD_SHIFT 20

typedef enum
{
  DSA_PCI_ENABLE_DEVICE = 1,
  DSA_PCI_DISABLE_DEVICE,
  DSA_PCI_DRAIN_ALL,
  DSA_PCI_ABORT_ALL,
  DSA_PCI_RESET_DEVICE,
  DSA_PCI_ENABLE_WQ,
  DSA_PCI_DISABLE_WQ,
  DSA_PCI_DRAIN_WQ,
  DSA_PCI_ABORT_WQ,
  DSA_PCI_RESET_WQ,
  DSA_PCI_DRAIN_PASID,
  DSA_PCI_ABORT_PASID,
} intel_dsa_command_t;

typedef struct
{
  u32 __clib_aligned (CLIB_CACHE_LINE_BYTES)
  version;
  u64 __clib_aligned (0x10)
  gencap; /* offset 0x10 */
  u64 __clib_aligned (0x10)
  wqcap; /* offset 0x20 */
  u64 __clib_aligned (0x10)
  grpcap; /* offset 0x30 */
  u64 __clib_aligned (0x08)
  engcap; /* offset 0x38 */
  u64 __clib_aligned (0x10)
  opcap; /* offset 0x40 */
  u64 __clib_aligned (0x20)
  offsets[2]; /* offset 0x60 */
  u32 __clib_aligned (0x20)
  gencfg; /* offset 0x80 */
  u32 __clib_aligned (0x08)
  genctrl; /* offset 0x88 */
  u32 __clib_aligned (0x10)
  gensts; /* offset 0x90 */
  u32 __clib_aligned (0x08)
  intcause; /* offset 0x98 */
  u32 __clib_aligned (0x10)
  cmd; /* offset 0xA0 */
  u32 __clib_aligned (0x08)
  cmdstatus; /* offset 0xA8 */
  u64 __clib_aligned (0x20)
  swerror[4]; /* offset 0xC0 */
} intel_dsa_config_contorl_t;

/* workqueue config is provided by array of u32. */
enum intel_dsa_wqcfg
{
  wq_size_idx,	    /* WQ size is the first 32-bits */
  wq_threshold_idx, /* WQ threshold */
  wq_mode_idx,	    /* WQ mode and other flags */
  wq_sizes_idx,	    /* WQ transfer and batch sizes */
  wq_occ_int_idx,   /* WQ occupancy interrupt handle */
  wq_occ_limit_idx, /* WQ occupancy limit */
  wq_state_idx,	    /* WQ state and occupancy state */
};

typedef struct
{
  u64 __clib_aligned (CLIB_CACHE_LINE_BYTES)
  grpwqcfg[4];
  u64 grpengcfg; /* offset 32 */
  u32 grpflags;	 /* offset 40 */
} intel_dsa_group_config_t;

typedef struct
{
  volatile intel_dsa_config_contorl_t *regs;
  volatile u32 *wq_regs_base;
  volatile intel_dsa_group_config_t *grp_regs;
  u8 wq_cfg_sz;
} intel_dsa_pci_common_t;

#define GENSTS_DEV_STATE_MASK  0x03
#define CMDSTATUS_ACTIVE_SHIFT 31
#define CMDSTATUS_ACTIVE_MASK  (1 << 31)
#define CMDSTATUS_ERR_MASK     0xFF

#define WQ_MODE_SHARED	  0
#define WQ_MODE_DEDICATED 1
#define WQ_BLOCK_ON_FAULT 2
#define WQ_PRIORITY_SHIFT 4
#define WQ_BATCH_SZ_SHIFT 5
#define WQ_STATE_SHIFT	  30
#define WQ_STATE_MASK	  0x3

#define IDXD_PORTAL_SIZE 4096 * 4
#endif