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

static void
mvpp2_hif_aggr_queue_config (mvpp2_hif_t *hif, uintptr_t addr, u32 size)
{
  asm volatile ("dsb st" : : : "memory");
  mvpp2_hif_reg_wr_relax (hif, MVPP2_AGGR_TXQ_INIT (hif->id), 0x01);
  mvpp2_hif_reg_wr_relax (hif, MVPP2_AGGR_TXQ_DESC_ADDR_REG (hif->id),
			  addr >> MVPP22_DESC_ADDR_SHIFT);
  mvpp2_hif_reg_wr_relax (hif, MVPP2_AGGR_TXQ_DESC_SIZE_REG (hif->id), size);
}

vnet_dev_rv_t
mvpp2_hif_alloc (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_hif_t *hif, u32 sz)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  void *desc_mem;
  uintptr_t desc_phys;
  vnet_dev_rv_t rv;
  u16 free_hifs;
  u8 hif_slot;

  ASSERT (!hif->descs);

  free_hifs = pow2_mask (MVPP2_NUM_HIFS) ^ md->hif_reserved_map;
  if (!free_hifs)
    {
      log_err (dev, "no free HIF");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  hif_slot = get_lowest_set_bit_index (free_hifs);

  *hif = (mvpp2_hif_t) {
    .id = hif_slot,
    .base = md->pp_base + hif_slot * MVPP2_REGSPACE_SIZE,
    .n_desc = sz,
  };
  rv = vnet_dev_dma_mem_alloc (vm, dev, sz * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN, &desc_mem,
			       "HIF %u descriptors", hif_slot);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot allocate descriptor ring");
      goto error;
    }
  hif->descs = desc_mem;

  desc_phys = vnet_dev_get_dma_addr (vm, dev, hif->descs);
  mvpp2_hif_aggr_queue_config (hif, desc_phys, hif->n_desc);
  hif->next = mvpp2_hif_reg_rd (hif, MVPP2_AGGR_TXQ_INDEX_REG (hif->id));
  md->hif_reserved_map |= 1 << hif_slot;
  log_debug (dev, "HIF %u on PP %u created, desc va %p pa 0x%lx", hif_slot, md->pp_id, hif->descs,
	     desc_phys);

  return VNET_DEV_OK;

error:
  *hif = (mvpp2_hif_t) {};
  return rv;
}

void
mvpp2_hif_free (vlib_main_t *vm, vnet_dev_t *dev, u32 thread_index)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_dev_thread_t *thread = md->threads + thread_index;
  mvpp2_hif_t *hif = &thread->hif;

  if (hif->descs)
    {
      mvpp2_hif_aggr_queue_config (hif, 0, 0);
      log_debug (dev, "HIF %u on PP %u destroyed", hif->id, md->pp_id);
      vnet_dev_dma_mem_free (vm, dev, hif->descs);
      md->hif_reserved_map &= ~(1 << hif->id);
      *thread = (mvpp2_dev_thread_t) {};
    }
}
