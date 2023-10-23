/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_roc_util_h
#define included_onp_drv_roc_util_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/unix/unix.h>
#include <vlib/log.h>
#include <vnet/devices/devices.h>
#include <vlib/pci/pci.h>
#include <vppinfra/xxhash.h>

#define __cnxk_cache_aligned __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)));

static_always_inline void
cnxk_prefetch_non_temporal (const volatile void *p)
{
#if defined(__aarch64__)
  asm volatile("PRFM PLDL1STRM, [%0]" ::"r"(p));
#endif
}

static_always_inline void
cnxk_mb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb osh" ::: "memory");
#endif
}

static_always_inline void
cnxk_wmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb oshst" ::: "memory");
#endif
}

static_always_inline void
cnxk_rmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb oshld" ::: "memory");
#endif
}

static_always_inline void
cnxk_smp_mb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ish" ::: "memory");
#endif
}

static_always_inline void
cnxk_smp_wmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ishst" ::: "memory");
#endif
}

static_always_inline void
cnxk_smp_rmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ishld" ::: "memory");
#endif
}

#endif /* included_onp_drv_roc_util_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
