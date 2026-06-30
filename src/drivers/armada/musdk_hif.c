/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <errno.h>
#include <string.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
#include <musdk_internal.h>
#include <pp2/pp2.h>
#include <pp2/pp2_regs.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "musdk-hif",
};

#define PP2_MAX_NUM_PUT_BUFFS 8192
#define TXD_DEST_QID_MASK     0x0000ff00

static_always_inline u32
pp2_hif_reg_read (uintptr_t hif_base, u32 offset)
{
  volatile u32 *addr = (void *) (hif_base + offset);
  u32 value;

  value = __atomic_load_n (addr, __ATOMIC_RELAXED);
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
pp2_hif_reg_write (uintptr_t hif_base, u32 offset, u32 value)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

static void
pp2_dm_aggr_queue_config (mvpp2_dev_thread_t *thread, uintptr_t addr, u32 size)
{
  asm volatile ("dsb st" : : : "memory");
  pp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_INIT (thread->hif_id), 0x01);
  pp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_DESC_ADDR_REG (thread->hif_id),
		     addr >> MVPP22_DESC_ADDR_SHIFT);
  pp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_DESC_SIZE_REG (thread->hif_id), size);
}

void
musdk_release_descs (vlib_main_t *vm, vnet_dev_t *dev, u16 num_buffs, struct pp2_ppio_desc descs[])
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u32 thread_index = vm->thread_index;
  mvpp2_dev_thread_t *thread = md->threads + thread_index;
  struct pp2_dm_if *dm_if = &thread->dm_if;
  u32 *desc_rsrvd = md->lbk_desc_rsrvd + thread_index;
  u16 sent = 0;

  do
    {
      struct pp2_desc *tx_desc;
      u16 num_txds = num_buffs - sent;
      u16 block_size;

      if (dm_if->free_count < num_txds)
	{
	  u32 occ_desc =
	    pp2_hif_reg_read (thread->hif_base, MVPP2_AGGR_TXQ_STATUS_REG (thread->hif_id));

	  dm_if->free_count = dm_if->desc_total - (occ_desc & MVPP2_AGGR_TXQ_PENDING_MASK);
	  num_txds = clib_min (num_txds, dm_if->free_count);
	}

      if (*desc_rsrvd < num_txds)
	{
	  u32 needed = num_txds - *desc_rsrvd;
	  u32 res_req = clib_max (needed, MVPP2_CPU_DESC_CHUNK);
	  u32 req_val = PP2_LOOPBACK_TXQ_ID << MVPP2_TXQ_RSVD_REQ_Q_OFFSET | res_req;

	  pp2_hif_reg_write (thread->hif_base, MVPP2_TXQ_RSVD_REQ_REG, req_val);
	  asm volatile ("dsb sy" : : : "memory");
	  *desc_rsrvd +=
	    pp2_hif_reg_read (thread->hif_base, MVPP2_TXQ_RSVD_RSLT_REG) & MVPP2_TXQ_RSVD_RSLT_MASK;
	  num_txds = clib_min (num_txds, *desc_rsrvd);
	}

      if (!num_txds)
	continue;

      block_size = clib_min (num_txds, dm_if->desc_total - dm_if->desc_next_idx);
      tx_desc = dm_if->desc_virt_arr + dm_if->desc_next_idx;
      dm_if->desc_next_idx = block_size == dm_if->desc_total - dm_if->desc_next_idx ?
			       0 :
			       dm_if->desc_next_idx + block_size;
      for (u16 i = 0; i < block_size; i++)
	{
	  descs[sent + i].cmds[1] = (descs[sent + i].cmds[1] & ~TXD_DEST_QID_MASK) |
				    (PP2_LOOPBACK_TXQ_ID << 8 & TXD_DEST_QID_MASK);
	  __builtin_memcpy (tx_desc + i, descs + sent + i, sizeof (*tx_desc));
	}

      if (block_size < num_txds)
	{
	  u16 index = block_size;

	  block_size = num_txds - index;
	  tx_desc = dm_if->desc_virt_arr;
	  dm_if->desc_next_idx = block_size;
	  for (u16 i = 0; i < block_size; i++)
	    {
	      descs[sent + index + i].cmds[1] =
		(descs[sent + index + i].cmds[1] & ~TXD_DEST_QID_MASK) |
		(PP2_LOOPBACK_TXQ_ID << 8 & TXD_DEST_QID_MASK);
	      __builtin_memcpy (tx_desc + i, descs + sent + index + i, sizeof (*tx_desc));
	    }
	}

      asm volatile ("dsb st" : : : "memory");
      pp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, num_txds);
      dm_if->free_count -= num_txds;
      *desc_rsrvd -= num_txds;
      sent += num_txds;
    }
  while (sent != num_buffs);
}

vnet_dev_rv_t
pp2_hif_init (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index, u8 id, u32 out_size)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u8 hif_slot = id;
  mvpp2_dev_thread_t *thread;
  struct pp2_dm_if *dm_if;
  struct pp2_ppio_desc *descs;
  uintptr_t desc_phys;
  vnet_dev_rv_t rv;

  ASSERT (thread_index < MVPP2_MAX_THREADS);
  ASSERT (hif_slot < MVPP2_NUM_HIFS);
  ASSERT (!(md->hif_reserved_map & (1 << hif_slot)));
  thread = md->threads + thread_index;
  dm_if = &thread->dm_if;
  if (dm_if->desc_virt_arr)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  descs = clib_mem_alloc (PP2_MAX_NUM_PUT_BUFFS * sizeof (*descs));
  clib_memset (descs, 0, PP2_MAX_NUM_PUT_BUFFS * sizeof (*descs));
  md->rel_descs[thread_index] = descs;

  *thread = (mvpp2_dev_thread_t) {
    .hif_id = hif_slot,
    .hif_base = mvpp2_hif_base (md, hif_slot),
    .dm_if = {
      .desc_total = out_size,
    },
  };
  dm_if->desc_virt_arr =
    vlib_physmem_alloc_aligned (vm, out_size * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN);
  if (!dm_if->desc_virt_arr)
    {
      log_err (dev, "DM: cannot allocate DM region");
      rv = VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
      goto error;
    }

  desc_phys = vlib_physmem_get_pa (vm, dm_if->desc_virt_arr);
  if (desc_phys & (MVPP2_DESC_Q_ALIGN - 1))
    {
      log_err (dev, "DM: Descriptor array must be %u-byte aligned", MVPP2_DESC_Q_ALIGN);
      vlib_physmem_free (vm, dm_if->desc_virt_arr);
      rv = VNET_DEV_ERR_INVALID_DATA;
      goto error;
    }

  pp2_dm_aggr_queue_config (thread, desc_phys, dm_if->desc_total);
  dm_if->desc_next_idx =
    pp2_hif_reg_read (thread->hif_base, MVPP2_AGGR_TXQ_INDEX_REG (thread->hif_id));
  md->lbk_desc_rsrvd[thread_index] = 0;
  log_debug (dev, "DM:(AQ%u)(PP%u) created\n", hif_slot, md->pp_id);

  return VNET_DEV_OK;

error:
  *thread = (mvpp2_dev_thread_t) {};
  clib_mem_free (md->rel_descs[thread_index]);
  md->rel_descs[thread_index] = 0;
  return rv;
}

void
pp2_hif_deinit (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_dev_thread_t *thread = md->threads + thread_index;
  struct pp2_dm_if *dm_if = &thread->dm_if;

  if (dm_if->desc_virt_arr)
    {
      pp2_dm_aggr_queue_config (thread, 0, 0);
      log_debug (dev, "DM: (AQ%u)(PP%u) destroyed\n", thread->hif_id, md->pp_id);
      vlib_physmem_free (vm, dm_if->desc_virt_arr);
      *thread = (mvpp2_dev_thread_t) {};
    }
  clib_mem_free (md->rel_descs[thread_index]);
  md->rel_descs[thread_index] = 0;
}
