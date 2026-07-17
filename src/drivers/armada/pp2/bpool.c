/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "bpool",
};

static_always_inline uintptr_t
mvpp2_bm_hw_buf_get (vnet_dev_t *dev, u32 pool_id)
{
  mvpp22_bm_phy_virt_high_reg_t high;
  uintptr_t vaddr;

  mvpp2_dev_reg_rd (dev, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  high.as_u32 = mvpp2_dev_reg_rd (dev, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr = high.virt_addr;
  vaddr <<= 32;
  vaddr |= mvpp2_dev_reg_rd (dev, MVPP2_BM_VIRT_ALLOC_REG);
  return vaddr;
}

static_always_inline void
mvpp2_bm_pool_bufsize_set (vnet_dev_t *dev, u32 pool_id, u32 buf_size)
{
  u32 align = 1 << MVPP2_POOL_BUF_SIZE_OFFSET;
  u32 value = (buf_size + align - 1) & ~(align - 1);

  mvpp2_dev_reg_wr (dev, MVPP2_POOL_BUF_SIZE_REG (pool_id), value);
}

static u32
mvpp2_bm_pool_flush (vnet_dev_t *dev, u32 pool_id)
{
  u32 j, pool_bufs, resid_bufs;

  resid_bufs =
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) & MVPP22_BM_POOL_PTRS_NUM_MASK) +
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);
  if (resid_bufs == 0)
    return 0;

  pool_bufs = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (pool_bufs && resid_bufs + 1 > pool_bufs)
    log_warn (dev, "BM: number of buffers in pool #%u (%u) is more than pool size (%u)", pool_id,
	      resid_bufs, pool_bufs);

  for (j = 0; j < resid_bufs + 1; j++)
    mvpp2_bm_hw_buf_get (dev, pool_id);

  return (mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
	  MVPP22_BM_POOL_PTRS_NUM_MASK) +
	 (mvpp2_dev_reg_rd (dev, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) &
	  MVPP2_BM_BPPI_PTR_NUM_MASK);
}

static void
mvpp2_bm_hw_pool_destroy (vnet_dev_t *dev, u32 pool_id)
{
  mvpp22_bm_pool_ctrl_reg_t control = {
    .as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id)),
  };

  if (control.state)
    {
      control.stop = 1;
      mvpp2_dev_reg_wr (dev, MVPP2_BM_POOL_CTRL_REG (pool_id), control.as_u32);
      do
	control.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id));
      while (control.state);
    }

  mvpp2_dev_reg_wr (dev, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
  mvpp2_dev_reg_wr (dev, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
  mvpp2_dev_reg_wr (dev, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), 0);
  mvpp2_bm_pool_bufsize_set (dev, pool_id, 0);
}

static int
mvpp2_bm_get_8pool_mode (vnet_dev_t *dev)
{
  mvpp22_bm_pool_base_addr_high_reg_t base_high = {
    .as_u32 = mvpp2_dev_reg_rd (dev, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG),
  };

  return base_high.mode_8pool;
}

static u32
mvpp2_bm_hw_pool_create (vnet_dev_t *dev, u32 pool_id, u32 bppe_num, uintptr_t pool_phys_addr)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp22_bm_pool_ctrl_reg_t control;
  mvpp22_bm_pool_base_addr_high_reg_t base_high;
  u32 pool_bufs;
  u32 phys_lo = (u32) pool_phys_addr & MVPP2_BM_POOL_BASE_ADDR_MASK;
  u32 phys_hi = (u64) pool_phys_addr >> 32;

  control.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id));
  if (control.state)
    return 1;

  base_high.as_u32 = mvpp2_dev_reg_rd (dev, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  if (base_high.addr != phys_hi)
    {
      if (!md->force_bppe_addr || md->bppe_window_set || phys_hi > 0xff)
	{
	  log_err (dev, "pool %u DMA address is outside shared BPPE address window", pool_id);
	  return 1;
	}

      log_warn (dev, "forcing shared BPPE address window from 0x%02x to 0x%02x", base_high.addr,
		phys_hi);
      base_high.addr = phys_hi;
      mvpp2_dev_reg_wr (dev, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, base_high.as_u32);
    }

  if (md->bppe_window_set && md->bppe_window_addr != phys_hi)
    {
      log_err (dev, "pool %u DMA address differs from existing VPP BPPE window", pool_id);
      return 1;
    }
  md->bppe_window_addr = phys_hi;
  md->bppe_window_set = 1;

  mvpp2_dev_reg_wr (dev, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), phys_lo);

  pool_bufs = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (!pool_bufs)
    mvpp2_dev_reg_wr (dev, MVPP2_BM_POOL_SIZE_REG (pool_id), bppe_num);
  else if (pool_bufs != bppe_num)
    return 1;

  control.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id));
  control.start = 1;
  if (mvpp2_bm_get_8pool_mode (dev))
    {
      control.low_threshold = MVPP23_BM_BPPI_8POOL_LOW_THRESH;
      control.high_threshold = MVPP23_BM_BPPI_8POOL_HIGH_THRESH;
    }
  else
    {
      control.low_threshold = MVPP2_BM_BPPI_LOW_THRESH;
      control.high_threshold = MVPP2_BM_BPPI_HIGH_THRESH;
    }
  mvpp2_dev_reg_wr (dev, MVPP2_BM_POOL_CTRL_REG (pool_id), control.as_u32);
  do
    control.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id));
  while (!control.state);
  return VNET_DEV_OK;
}

static int
mvpp2_bm_pool_create (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  void *mem;
  int rv;
  u32 bppe_num, bppe_region_size;

  if (pool->buf_sz < PP2_BUFFER_OFFSET || pool->buf_sz % PP2_BUFFER_OFFSET_GRAN)
    return -EACCES;

  bppe_num = MVPP2_BM_POOL_SIZE_MAX;
  bppe_region_size = bppe_num * 2 * sizeof (u64);
  rv = vnet_dev_dma_mem_alloc (vm, dev, bppe_region_size, MVPP2_BM_POOL_PTR_ALIGN, &mem,
			       "Buffer pool %u pointers", pool->id);
  if (rv != VNET_DEV_OK)
    return rv;

  pool->virt_base = pointer_to_uword (mem);
  pool->phys_base = vnet_dev_get_dma_addr (vm, dev, mem);
  if (pool->phys_base & (MVPP2_BM_POOL_PTR_ALIGN - 1))
    goto bad_region;

  if (mvpp2_bm_hw_pool_create (dev, pool->id, bppe_num, pool->phys_base))
    goto bad_region;
  mvpp2_bm_pool_bufsize_set (dev, pool->id, pool->buf_sz);
  pool->is_initialized = 1;
  return 0;

bad_region:
  vnet_dev_dma_mem_free (vm, dev, (void *) pool->virt_base);
  pool->virt_base = 0;
  pool->phys_base = 0;
  return -EIO;
}

static int
mvpp2_bm_pool_destroy (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  mvpp2_bm_pool_flush (dev, pool->id);
  mvpp2_bm_hw_pool_destroy (dev, pool->id);
  vnet_dev_dma_mem_free (vm, dev, (void *) pool->virt_base);
  *pool = (mvpp2_bpool_t) {};
  return 0;
}

static void
mvpp2_bm_pool_reset_fc (vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  mvpp22_fc_com_reg_t fc = {
    .as_u32 = mvpp2_cm3_reg_rd (dev, MSS_CP_FC_COM_REG),
  };
  u8 was_enabled = fc.enable;

  fc.enable = 0;
  mvpp2_cm3_reg_wr (dev, MSS_CP_FC_COM_REG, fc.as_u32);
  mvpp2_cm3_reg_wr (dev, MSS_CP_CM3_BUF_POOL_BASE + pool->id * MSS_CP_CM3_BUF_POOL_OFFS, 0);
  fc.as_u32 = mvpp2_cm3_reg_rd (dev, MSS_CP_FC_COM_REG);
  fc.update = 1;
  fc.enable = was_enabled;
  mvpp2_cm3_reg_wr (dev, MSS_CP_FC_COM_REG, fc.as_u32);
}

static vnet_dev_rv_t
mvpp2_bpool_get_num_buffs (vnet_dev_t *dev, mvpp2_bpool_t *pool, u32 *num_buffs)
{
  u32 num;

  num =
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_PTRS_NUM_REG (pool->id)) & MVPP22_BM_POOL_PTRS_NUM_MASK) +
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_BPPI_PTRS_NUM_REG (pool->id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);
  *num_buffs = num ? num + 1 : 0;
  return VNET_DEV_OK;
}

void
mvpp2_bpool_deinit (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  u32 buf_num;

  mvpp2_bpool_get_num_buffs (dev, pool, &buf_num);
  if (buf_num)
    log_warn (dev, "cannot free all buffers in pool %d, buf_num left %u", pool->id, buf_num);

  if (pool->is_initialized)
    {
      mvpp2_bm_pool_reset_fc (dev, pool);
      mvpp2_bm_pool_destroy (vm, dev, pool);
    }
}

vnet_dev_rv_t
mvpp2_bpool_get_buff (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool,
		      mvpp2_buff_info_t *buff)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_hif_t *hif = &md->threads[vm->thread_index].hif;
  mvpp22_bm_phy_virt_high_reg_t high;
  u64 paddr, vaddr, high_addr;

  paddr = mvpp2_hif_reg_rd (hif, MVPP2_BM_PHY_ALLOC_REG (pool->id));
  if (!paddr)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  vaddr = mvpp2_hif_reg_rd (hif, MVPP2_BM_VIRT_ALLOC_REG);
  high.as_u32 = mvpp2_hif_reg_rd (hif, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  high_addr = high.virt_addr;
  vaddr |= high_addr << 32;
  high_addr = high.phys_addr;
  paddr |= high_addr << 32;
  buff->addr = paddr;
  buff->cookie = vaddr;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_bpool_init (vlib_main_t *vm, vnet_dev_t *dev, u8 pool_id, u32 buff_len, mvpp2_bpool_t *pool)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  int rc;

  if (pool_id >= MVPP2_NUM_BPOOLS)
    return VNET_DEV_ERR_INVALID_ARG;
  if (md->bm_pool_reserved_map & (1 << pool_id))
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  if (pool->is_initialized)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  *pool = (mvpp2_bpool_t) {
    .id = pool_id,
    .buf_sz = buff_len,
  };
  rc = mvpp2_bm_pool_create (vm, dev, pool);
  if (rc)
    {
      *pool = (mvpp2_bpool_t) {};
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mvpp2_bm_pool_reset_fc (dev, pool);
  return VNET_DEV_OK;
}

void
mvpp2_bm_flush_pools (vnet_dev_t *dev, u16 bm_pool_reserved_map)
{
  for (u32 pool_id = 0; pool_id < MVPP2_NUM_BPOOLS; pool_id++)
    {
      if (bm_pool_reserved_map & (1 << pool_id))
	continue;
      mvpp2_bm_pool_flush (dev, pool_id);
      mvpp2_bm_hw_pool_destroy (dev, pool_id);
      mvpp2_dev_reg_wr (dev, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
      mvpp2_dev_reg_wr (dev, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
    }
  mvpp2_dev_reg_wr (dev, MVPP2_BM_PRIO_CTRL_REG, 0);
  mvpp2_dev_reg_wr (dev, MVPP22_BM_PHY_VIRT_HIGH_RLS_REG, 0);
}

void
mvpp2_bpool_assign (vnet_dev_port_t *port, u32 pool_id, u32 rxq_id)
{
  vnet_dev_t *dev = port->dev;
  mvpp22_rxq_config_reg_t config;

  config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq_id));
  config.short_pool = pool_id;
  config.long_pool = pool_id;
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_CONFIG_REG (rxq_id), config.as_u32);
}
