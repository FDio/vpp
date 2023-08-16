/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_BAR_H_
#define _CNXK_BAR_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_cnxk/cnxk.h>

static_always_inline void *
cnxk_bar_get_ptr (vnet_dev_t *dev, u8 bar)
{
  cnxk_device_t *id = vnet_dev_get_data (dev);
  switch (bar)
    {
    case 2:
      return id->bar2;
    case 4:
      return id->bar4;
    default:
      ASSERT (0);
      return 0;
    }
}

static_always_inline u64
cnxk_bar_reg64_read (vnet_dev_t *dev, u8 bar, u32 reg)
{
  u64 *ptr = (u64 *) ((u8 *) cnxk_bar_get_ptr (dev, bar) + reg);
  return __atomic_load_n (ptr, __ATOMIC_RELAXED);
}

static_always_inline void
cnxk_bar_reg64_write (vnet_dev_t *dev, u8 bar, u32 reg, u64 val)
{
  u64 *ptr = (u64 *) ((u8 *) cnxk_bar_get_ptr (dev, bar) + reg);
  __atomic_store_n (ptr, val, __ATOMIC_RELAXED);
}



#endif /* _CNXK_BAR_H_ */
