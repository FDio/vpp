/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mhi.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "channel",
};

vnet_dev_rv_t
mhi_channel_init (vlib_main_t *vm, vnet_dev_t *dev, u32 ch_id)
{
  /* Allocate Transfer Ring for channel */
  /* Placeholder for now */
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mhi_channel_start (vlib_main_t *vm, vnet_dev_t *dev, u32 ch_id)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  mhi_tre_t cmd = {};
  vnet_dev_rv_t rv;

  /* Configure Channel Context */
  md->chan_ctxt[ch_id].chcfg = 1;  /* ENABLED (simplified) */
  md->chan_ctxt[ch_id].chtype = 2; /* DMA_FROM_DEVICE (Inbound) for example */
  /* ... populate other fields ... */

  /* Queue Start Command */
  cmd.dword[1] = MHI_TRE_CMD_DWORD1 (ch_id, MHI_CMD_START_CHAN);

  rv = mhi_queue_cmd (dev, &cmd);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "Started channel %u", ch_id);
  return VNET_DEV_OK;
}
