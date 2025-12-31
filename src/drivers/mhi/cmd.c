/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mhi.h>
#include <mhi_regs.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "cmd",
};

static void
mhi_ring_cmd_db (vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  u64 wp = md->cmd_ctxt[0].wp_lo | ((u64) md->cmd_ctxt[0].wp_hi << 32);

  mhi_reg_wr64 (dev, MHI_REG_CRDB_LOWER, wp);
}

static mhi_tre_t *
mhi_get_free_cmd_desc (mhi_dev_t *md)
{
  /* Simple ring logic: Check if ring is full */
  /* For simplicity in this skeleton, we assume single-threaded command usage
     and don't track RP updates from device yet (handled in event).
     We just check if we have space relative to cached RP?
     Actually, we need to read RP from memory (updated by device) to know free
     space. But for initialization commands, we rarely wrap.
  */
  /* TODO: Implement full ring wrap/full check */

  u64 rbase =
    md->cmd_ctxt[0].rbase_lo | ((u64) md->cmd_ctxt[0].rbase_hi << 32);
  u64 wp = md->cmd_ctxt[0].wp_lo | ((u64) md->cmd_ctxt[0].wp_hi << 32);

  /* Calculate index from address */
  u32 idx = (wp - rbase) / sizeof (mhi_tre_t);

  if (idx >= MHI_CMD_RING_SIZE - 1)
    return 0; /* Ring full or wrap needed */

  return &md->cmd_ring[idx];
}

vnet_dev_rv_t
mhi_queue_cmd (vnet_dev_t *dev, mhi_tre_t *cmd)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  mhi_tre_t *ring_entry;

  ring_entry = mhi_get_free_cmd_desc (md);
  if (!ring_entry)
    return VNET_DEV_ERR_NO_AVAIL_QUEUES; /* Reusing error code */

  clib_memcpy (ring_entry, cmd, sizeof (mhi_tre_t));

  /* Update WP */
  u64 wp = md->cmd_ctxt[0].wp_lo | ((u64) md->cmd_ctxt[0].wp_hi << 32);
  wp += sizeof (mhi_tre_t);

  md->cmd_ctxt[0].wp_lo = (u32) wp;
  md->cmd_ctxt[0].wp_hi = (u32) (wp >> 32);

  /* Ring Doorbell */
  mhi_ring_cmd_db (dev);

  return VNET_DEV_OK;
}
