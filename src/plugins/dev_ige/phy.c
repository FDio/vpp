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
  .subclass_name = "phy",
};

static vnet_dev_rv_t
ige_phy_acquire (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;
  int n_tries = 5;

  log_debug (dev, "phy_acquire:");

  while (n_tries-- > 0)
    {
      if (ige_reg_sw_fw_sync_acquire (vm, dev))
	{
	  ige_reg_rd (dev, IGE_REG_SW_FW_SYNC, &sw_fw_sync.as_u32);
	  log_debug (dev, "phy_acquire: sw_fw_sync 0x%04x");

	  if (sw_fw_sync.fw_phy_sm == 0)
	    {
	      sw_fw_sync.sw_phy_sm = 1;
	      ige_reg_wr (dev, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
	      ige_reg_sw_fw_sync_release (vm, dev);
	      return 0;
	    }

	  ige_reg_sw_fw_sync_release (vm, dev);
	}
      vlib_process_suspend (vm, 1e-4);
    }

  log_err (dev, "failed to acquire PHY");
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ige_phy_release (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;

  log_debug (dev, "phy_release:");

  /* release phy */
  if (ige_reg_sw_fw_sync_acquire (vm, dev) == 0)
    {
      log_err (dev, "sw_fw_sync ownership timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  sw_fw_sync.sw_phy_sm = 0;
  ige_reg_wr (dev, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
  ige_reg_sw_fw_sync_release (vm, dev);

  return 0;
}

static vnet_dev_rv_t
ige_phy_read (vlib_main_t *vm, vnet_dev_t *dev, u16 addr, u16 *data)
{
  ige_reg_mdic_t mdic = { .regadd = addr, .opcode = 2 };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  ige_reg_wr (dev, IGE_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (dev, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    {
      log_err (dev, "phy read timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  log_debug (dev, "phy_read: addr 0x%02x data 0x%04x", addr, mdic.data);
  *data = mdic.data;
  return 0;
}

vnet_dev_rv_t
ige_phy_rw (vlib_main_t *vm, vnet_dev_t *dev, ige_phy_rw_t *rw, u32 num_rw)
{
  vnet_dev_rv_t rv;

  if ((rv = ige_phy_acquire (vm, dev)))
    return rv;

  for (u32 i = 0; i < num_rw; i++)
    {
      u16 data;
      if ((rv = ige_phy_read (vm, dev, rw[i].addr, &data)))
	return rv;
      rw[i].data = data;
    }

  return ige_phy_release (vm, dev);
}
