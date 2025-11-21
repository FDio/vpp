/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "utils",
};

vnet_dev_rv_t
atl_aq2_interface_buffer_read (vnet_dev_t *dev, u32 reg0, u32 *data0, u32 n_dwords)
{
  vlib_main_t *vm = vlib_get_main ();
  atl_reg_aq2_fw_interface_out_transaction_id_t tid0, tid1;
  f64 t0;
  u32 reg, sz;
  u32 *data;

  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 0.1)
    {
      tid0.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_TRANSACTION_ID);
      if (tid0.id_a != tid0.id_b)
	goto wait;

      for (reg = reg0, data = data0, sz = n_dwords; sz; reg += 4, data++, sz--)

	*data = atl_reg_rd_u32 (dev, reg);
      tid1.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_TRANSACTION_ID);
      if (tid0.as_u32 == tid1.as_u32)
	return VNET_DEV_OK;

    wait:
      vlib_process_suspend (vm, 1e-5);
    }

  log_err (dev, "interface buffer read timeout");
  return VNET_DEV_ERR_TIMEOUT;
}

vnet_dev_rv_t
atl_fw_mbox_read (vnet_dev_t *dev, u32 offset, u32 *val)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  vlib_main_t *vm = vlib_get_main ();
  u32 mbox_addr = ad->mbox_addr;
  f64 t0;

  atl_reg_wr_u32 (dev, ATL_REG_FW_MBOX_ADDR, mbox_addr + offset);
  atl_reg_wr_u32 (dev, ATL_REG_FW_MBOX_CMD, 0x00008000);

  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 0.01)
    {
      if ((atl_reg_rd_u32 (dev, ATL_REG_FW_MBOX_CMD) & 0x100) == 0)
	{
	  *val = atl_reg_rd_u32 (dev, ATL_REG_FW_MBOX_VAL);
	  return VNET_DEV_OK;
	}
      vlib_process_suspend (vm, 1e-5);
    }

  return VNET_DEV_ERR_TIMEOUT;
}
