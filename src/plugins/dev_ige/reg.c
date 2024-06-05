/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "reg",
};

vnet_dev_rv_t
ige_reg_poll (vlib_main_t *vm, vnet_dev_t *dev, u32 reg, u32 mask, u32 match,
	      f64 intial_delay, f64 timeout)
{
  f64 t0 = vlib_time_now (vm);
  u32 val;

  for (f64 delay = intial_delay, total_time = delay; total_time < timeout;
       delay *= 2, total_time += delay)
    {
      ige_reg_rd (dev, reg, &val);
      if ((val & mask) == match)
	{
	  log_debug (dev, "reg %05x (suspend %.6f)", reg,
		     vlib_time_now (vm) - t0);
	  return 1;
	}
      vlib_process_suspend (vm, delay);
    }
  log_debug (dev, "reg %05x timeout", reg);
  return 0;
}

void
ige_reg_sw_fw_sync_release (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_swsm_t swsm;
  log_debug (dev, "");
  ige_reg_rd (dev, IGE_REG_SWSM, &swsm.as_u32);
  swsm.smbi = 0;
  swsm.swesmbi = 0;
  ige_reg_wr (dev, IGE_REG_SWSM, swsm.as_u32);
}

int
ige_reg_sw_fw_sync_acquire (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_swsm_t swsm;
  int i, timeout = 10;

  log_debug (dev, "");
  for (i = 0; i < timeout * 2; i++)
    {
      if (i == timeout)
	{
	  log_debug (dev, "timeout, attempt to cleor SWSM");
	  swsm.smbi = 0;
	  swsm.swesmbi = 0;
	  ige_reg_wr (dev, IGE_REG_SWSM, swsm.as_u32);
	}
      ige_reg_rd (dev, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.smbi == 0)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      log_debug (dev, "timeout acquiring SWSM");
      return 0;
    }

  for (i = 0; i < timeout; i++)
    {
      swsm.swesmbi = 1;
      ige_reg_wr (dev, IGE_REG_SWSM, swsm.as_u32);
      ige_reg_rd (dev, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.swesmbi == 1)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      swsm.smbi = 0;
      swsm.swesmbi = 0;
      ige_reg_wr (dev, IGE_REG_SWSM, swsm.as_u32);
      log_debug (dev, "timeout acquring SWSMBI");
      return 0;
    }

  log_debug (dev, "acquired");
  return 1;
}
