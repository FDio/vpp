/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mhi.h>
#include <mhi_regs.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "event",
};

void
mhi_process_event_ring (vlib_main_t *vm, vnet_dev_t *dev, u16 er_index)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  mhi_event_ctxt_t *ctx = &md->event_ctxt[er_index];
  mhi_tre_t *ring = md->event_rings[er_index];
  u64 new_wp, rbase = ctx->rbase;
  u32 rbase_lo = rbase;
  u32 rlen = ctx->rlen;
  u32 rp, wp = ctx->wp;

  /* Note: We use 32-bit arithmetic for WP/RP comparison because the ring is
   * allocated with alignment >= size, which guarantees it won't cross a 4GB
   * boundary. This allows for safe reads of the lower 32-bits. */

  rp = __atomic_load_n ((u32 *) &ctx->rp, __ATOMIC_ACQUIRE);

  if (wp == rp)
    return;

  log_debug (dev, "ER %u: rp 0x%x wp 0x%x", er_index, rp, wp);

  while (wp != rp)
    {
      mhi_tre_t *e = (mhi_tre_t *) ((u8 *) ring + (wp - rbase_lo));

      log_notice (dev, "Event [offset %u]: %U", wp - rbase_lo, format_mhi_tre,
		  e);

      wp += sizeof (mhi_tre_t);
      if (wp == rbase_lo + rlen)
	wp = rbase_lo;
    }

  ctx->wp = new_wp = rbase + (wp - rbase_lo);

  __atomic_store_n (md->er_db + er_index, new_wp, __ATOMIC_RELEASE);
}

void
mhi_process_events (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  u8 i;

  for (i = 0; i < md->n_events; i++)
    mhi_process_event_ring (vm, dev, i);
}
