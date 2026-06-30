/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "hif",
};

static_always_inline u32
mvpp2_hif_reg_read (uintptr_t hif_base, u32 offset)
{
  volatile u32 *addr = (void *) (hif_base + offset);
  u32 value;

  value = __atomic_load_n (addr, __ATOMIC_RELAXED);
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
mvpp2_hif_reg_write (uintptr_t hif_base, u32 offset, u32 value)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

static void
mvpp2_dm_aggr_queue_config (mvpp2_dev_thread_t *thread, uintptr_t addr, u32 size)
{
  asm volatile ("dsb st" : : : "memory");
  mvpp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_INIT (thread->hif_id), 0x01);
  mvpp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_DESC_ADDR_REG (thread->hif_id),
		       addr >> MVPP22_DESC_ADDR_SHIFT);
  mvpp2_hif_reg_write (thread->hif_base, MVPP2_AGGR_TXQ_DESC_SIZE_REG (thread->hif_id), size);
}

vnet_dev_rv_t
mvpp2_hif_init (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index, u8 id, u32 out_size)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u8 hif_slot = id;
  mvpp2_dev_thread_t *thread;
  mvpp2_dm_if_t *dm_if;
  uintptr_t desc_phys;
  vnet_dev_rv_t rv;

  ASSERT (thread_index < MVPP2_MAX_THREADS);
  ASSERT (hif_slot < MVPP2_NUM_HIFS);
  ASSERT (!(md->hif_reserved_map & (1 << hif_slot)));
  thread = md->threads + thread_index;
  dm_if = &thread->dm_if;
  if (dm_if->desc_virt_arr)
    return VNET_DEV_ERR_ALREADY_EXISTS;

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

  mvpp2_dm_aggr_queue_config (thread, desc_phys, dm_if->desc_total);
  dm_if->desc_next_idx =
    mvpp2_hif_reg_read (thread->hif_base, MVPP2_AGGR_TXQ_INDEX_REG (thread->hif_id));
  md->lbk_desc_rsrvd[thread_index] = 0;
  log_debug (dev, "DM:(AQ%u)(PP%u) created\n", hif_slot, md->pp_id);

  return VNET_DEV_OK;

error:
  *thread = (mvpp2_dev_thread_t) {};
  return rv;
}

void
mvpp2_hif_deinit (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_dev_thread_t *thread = md->threads + thread_index;
  mvpp2_dm_if_t *dm_if = &thread->dm_if;

  if (dm_if->desc_virt_arr)
    {
      mvpp2_dm_aggr_queue_config (thread, 0, 0);
      log_debug (dev, "DM: (AQ%u)(PP%u) destroyed\n", thread->hif_id, md->pp_id);
      vlib_physmem_free (vm, dm_if->desc_virt_arr);
      *thread = (mvpp2_dev_thread_t) {};
    }
}
