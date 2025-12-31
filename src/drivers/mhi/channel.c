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
  mhi_tre_t cmd = {
    .c_type = MHI_PKT_TYPE_START_CHAN,
    .chid = ch_id,
  };
  vnet_dev_rv_t rv;

  rv = mhi_queue_cmd (dev, &cmd);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "Started channel %u", ch_id);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mhi_queue_transfer (vnet_dev_t *dev, u32 ch_id, mhi_tre_t *tre)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  mhi_chan_ctxt_t *ctx = &md->chan_ctxt[ch_id];
  mhi_tre_t *ring = md->chan_rings[ch_id];
  u64 rbase = ctx->rbase;
  u32 rbase_lo = rbase;
  u32 rlen = ctx->rlen;
  /* Host is Producer for Channel Rings */
  u32 wp = ctx->wp; /* Offset 0x28 (Host Producer) */
  u32 rp = ctx->rp; /* Offset 0x20 (Device Consumer) */

  /* Check for full ring */
  u32 next_wp = wp + sizeof (mhi_tre_t);
  if (next_wp == rbase_lo + rlen)
    next_wp = rbase_lo;

  if (next_wp == rp)
    return VNET_DEV_ERR_BUS;

  /* Copy TRE */
  mhi_tre_t *slot = (mhi_tre_t *) ((u8 *) ring + (wp - rbase_lo));
  *slot = *tre;

  log_debug (dev, "Queue Chan %u TRE: %U", ch_id, format_mhi_tre, tre);

  /* Update WP */
  ctx->wp = next_wp;

  /* Ring Doorbell */
  void *db_addr = md->ch_db[ch_id];
  if (db_addr)
    __atomic_store_n ((u64 *) db_addr, next_wp, __ATOMIC_RELEASE);

  return VNET_DEV_OK;
}
