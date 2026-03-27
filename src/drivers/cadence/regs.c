/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <cadence.h>

VLIB_REGISTER_LOG_CLASS (cdn_log, static) = {
  .class_name = "cadence",
  .subclass_name = "regs",
};

u32
cdn_reg_rd (vnet_dev_t *dev, cdn_device_t *cd, uword reg)
{
  u32 value;

  value = __atomic_load_n ((u32 *) ((u8 *) cd->regs + reg), __ATOMIC_RELAXED);
  log_debug (dev, "%U is 0x%08x", format_cdn_reg_name, reg, value);

  return value;
}

void
cdn_reg_wr (vnet_dev_t *dev, cdn_device_t *cd, uword reg, u32 value)
{
  u32 old;

  old = __atomic_load_n ((u32 *) ((u8 *) cd->regs + reg), __ATOMIC_RELAXED);
  log_debug (dev, "%U changed from 0x%08x to 0x%08x", format_cdn_reg_name, reg, old, value);
  cdn_reg_wr_raw (cd, reg, value);
}
