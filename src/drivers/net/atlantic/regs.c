/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "reg",
};

void
atl_reg_wr_u32 (vnet_dev_t *dev, u32 reg, u32 val)
{
  atl_device_t *ad = vnet_dev_get_data (dev);

  __atomic_store_n ((u32 *) ((u8 *) ad->bar0 + reg), val, __ATOMIC_RELEASE);
}

u32
atl_reg_rd_u32 (vnet_dev_t *dev, u32 reg)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  u32 val = __atomic_load_n ((u32 *) ((u8 *) ad->bar0 + reg), __ATOMIC_ACQUIRE);

  return val;
}

void
atl_reg_wr (vnet_dev_t *dev, u32 reg, atl_reg_t val)
{
  atl_reg_wr_u32 (dev, reg, val.as_u32);
}

atl_reg_t
atl_reg_rd (vnet_dev_t *dev, u32 reg)
{
  return (atl_reg_t){
    .as_u32 = atl_reg_rd_u32 (dev, reg),
  };
}
