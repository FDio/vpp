/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "bpool",
};

#define MVPP2_BPOOL_NUM_POOLS	  16
#define MVPP2_DUMMY_POOL_BUF_SIZE 64

static_always_inline u32
mvpp2_bm_reg_read_relaxed (uintptr_t hif_base, u32 offset)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  return __atomic_load_n (addr, __ATOMIC_RELAXED);
}

static_always_inline u32
mvpp2_bm_reg_read (uintptr_t hif_base, u32 offset)
{
  u32 value = mvpp2_bm_reg_read_relaxed (hif_base, offset);

  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
mvpp2_bm_reg_write (uintptr_t hif_base, u32 offset, u32 value)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  asm volatile ("dsb st" : : : "memory");
  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

static_always_inline uintptr_t
mvpp2_bm_hw_buf_get (uintptr_t hif_base, u32 pool_id)
{
  uintptr_t vaddr;

  mvpp2_bm_reg_read (hif_base, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  vaddr = mvpp2_bm_reg_read (hif_base, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr &= MVPP22_BM_VIRT_HIGH_ALLOC_MASK;
  vaddr <<= 32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET;
  vaddr |= mvpp2_bm_reg_read (hif_base, MVPP2_BM_VIRT_ALLOC_REG);
  return vaddr;
}

static_always_inline void
mvpp2_bm_pool_bufsize_set (uintptr_t hif_base, u32 pool_id, u32 buf_size)
{
  u32 align = 1 << MVPP2_POOL_BUF_SIZE_OFFSET;
  u32 value = (buf_size + align - 1) & ~(align - 1);

  mvpp2_bm_reg_write (hif_base, MVPP2_POOL_BUF_SIZE_REG (pool_id), value);
}

static u32
mvpp2_bm_pool_flush (vnet_dev_t *dev, uintptr_t hif_base, u32 pool_id)
{
  u32 j, pool_bufs, resid_bufs;

  resid_bufs = (mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
		MVPP22_BM_POOL_PTRS_NUM_MASK) +
	       (mvpp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) &
		MVPP2_BM_BPPI_PTR_NUM_MASK);
  if (resid_bufs == 0)
    return 0;

  pool_bufs = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (pool_bufs && resid_bufs + 1 > pool_bufs)
    log_warn (dev, "BM: number of buffers in pool #%u (%u) is more than pool size (%u)", pool_id,
	      resid_bufs, pool_bufs);

  for (j = 0; j < resid_bufs + 1; j++)
    mvpp2_bm_hw_buf_get (hif_base, pool_id);

  return (mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
	  MVPP22_BM_POOL_PTRS_NUM_MASK) +
	 (mvpp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) &
	  MVPP2_BM_BPPI_PTR_NUM_MASK);
}

static void
mvpp2_bm_hw_pool_destroy (uintptr_t hif_base, u32 pool_id)
{
  u32 value = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));

  if (value & MVPP2_BM_STATE_MASK)
    {
      value |= MVPP2_BM_STOP_MASK;
      mvpp2_bm_reg_write (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
      do
	value = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
      while (value & MVPP2_BM_STATE_MASK);
    }

  mvpp2_bm_reg_write (hif_base, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
  mvpp2_bm_reg_write (hif_base, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
  mvpp2_bm_reg_write (hif_base, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), 0);
  value = mvpp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  mvpp2_bm_reg_write (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);
  mvpp2_bm_pool_bufsize_set (hif_base, pool_id, 0);
}

static int
mvpp2_bm_get_8pool_mode (uintptr_t hif_base)
{
  return mvpp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG) & MVPP23_BM_8POOL_MODE;
}

static u32
mvpp2_bm_hw_pool_create (uintptr_t hif_base, u32 pool_id, u32 bppe_num, uintptr_t pool_phys_addr)
{
  u32 value, pool_bufs;
  u32 phys_lo = (u32) pool_phys_addr & MVPP2_BM_POOL_BASE_ADDR_MASK;
  u32 phys_hi = (u64) pool_phys_addr >> 32;

  value = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  if (value & MVPP2_BM_STATE_MASK)
    return 1;

  mvpp2_bm_reg_write (hif_base, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), phys_lo);
  value = mvpp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  value |= phys_hi & MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  mvpp2_bm_reg_write (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);

  pool_bufs = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (!pool_bufs)
    mvpp2_bm_reg_write (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id), bppe_num);
  else if (pool_bufs != bppe_num)
    return 1;

  value = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  value |= MVPP2_BM_START_MASK;
  value &= ~(MVPP2_BM_LOW_THRESH_MASK | MVPP2_BM_HIGH_THRESH_MASK);
  if (mvpp2_bm_get_8pool_mode (hif_base))
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_HIGH_THRESH);
  else
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP2_BM_BPPI_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP2_BM_BPPI_HIGH_THRESH);
  mvpp2_bm_reg_write (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
  do
    value = mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  while (!(value & MVPP2_BM_STATE_MASK));
  return VNET_DEV_OK;
}

static int
mvpp2_bm_pool_create (vlib_main_t *vm, mvpp2_device_t *md, mvpp2_bpool_t *pool)
{
  u32 bppe_num, bppe_region_size;
  uintptr_t hif_base;

  if (pool->buf_sz < PP2_BUFFER_OFFSET || pool->buf_sz % PP2_BUFFER_OFFSET_GRAN)
    return -EACCES;

  bppe_num = MVPP2_BM_POOL_SIZE_MAX;
  bppe_region_size = bppe_num * 2 * sizeof (u64);
  pool->virt_base =
    (uintptr_t) vlib_physmem_alloc_aligned (vm, bppe_region_size, MVPP2_BM_POOL_PTR_ALIGN);
  if (!pool->virt_base)
    return -ENOMEM;

  pool->phys_base = vlib_physmem_get_pa (vm, (void *) pool->virt_base);
  if (pool->phys_base & (MVPP2_BM_POOL_PTR_ALIGN - 1))
    goto bad_region;

  hif_base = md->pp_base;
  if (mvpp2_bm_hw_pool_create (hif_base, pool->id, bppe_num, pool->phys_base))
    goto bad_region;
  mvpp2_bm_pool_bufsize_set (hif_base, pool->id, pool->buf_sz);
  pool->is_initialized = 1;
  return 0;

bad_region:
  vlib_physmem_free (vm, (void *) pool->virt_base);
  pool->virt_base = 0;
  pool->phys_base = 0;
  return -EIO;
}

static int
mvpp2_bm_pool_destroy (vlib_main_t *vm, vnet_dev_t *dev, uintptr_t hif_base, mvpp2_bpool_t *pool)
{
  mvpp2_bm_pool_flush (dev, hif_base, pool->id);
  mvpp2_bm_hw_pool_destroy (hif_base, pool->id);
  vlib_physmem_free (vm, (void *) pool->virt_base);
  *pool = (mvpp2_bpool_t) {};
  return 0;
}

static_always_inline u32
mvpp2_bm_cm3_read (uintptr_t base, u32 offset)
{
  return mvpp2_bm_reg_read (base, offset);
}

static_always_inline void
mvpp2_bm_cm3_write (uintptr_t base, u32 offset, u32 value)
{
  mvpp2_bm_reg_write (base, offset, value);
}

static void
mvpp2_bm_pool_reset_fc (uintptr_t base, mvpp2_bpool_t *pool)
{
  u32 value = mvpp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  u32 cm3_state = value & FLOW_CONTROL_ENABLE_BIT;

  value &= ~FLOW_CONTROL_ENABLE_BIT;
  mvpp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
  mvpp2_bm_cm3_write (base, MSS_CP_CM3_BUF_POOL_BASE + pool->id * MSS_CP_CM3_BUF_POOL_OFFS, 0);
  value = mvpp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  value |= FLOW_CONTROL_UPD_COM_BIT | cm3_state;
  mvpp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
}

static vnet_dev_rv_t
mvpp2_bpool_get_num_buffs (vnet_dev_t *dev, mvpp2_bpool_t *pool, u32 *num_buffs)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->pp_base;
  u32 num;

  num = (mvpp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool->id)) &
	 MVPP22_BM_POOL_PTRS_NUM_MASK) +
	(mvpp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool->id)) &
	 MVPP2_BM_BPPI_PTR_NUM_MASK);
  *num_buffs = num ? num + 1 : 0;
  return VNET_DEV_OK;
}

void
mvpp2_bpool_deinit (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->pp_base;
  u32 buf_num;

  mvpp2_bpool_get_num_buffs (dev, pool, &buf_num);
  if (buf_num)
    log_warn (dev, "cannot free all buffers in pool %d, buf_num left %u", pool->id, buf_num);

  if (pool->is_initialized)
    {
      mvpp2_bm_pool_reset_fc (md->cm3_base, pool);
      mvpp2_bm_pool_destroy (vm, dev, hif_base, pool);
    }
}

vnet_dev_rv_t
mvpp2_bpool_get_buff (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool,
		      mvpp2_buff_info_t *buff)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->threads[vm->thread_index].hif_base;
  u64 paddr, vaddr, high;

  paddr = mvpp2_bm_reg_read (hif_base, MVPP2_BM_PHY_ALLOC_REG (pool->id));
  if (!paddr)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  vaddr = mvpp2_bm_reg_read (hif_base, MVPP2_BM_VIRT_ALLOC_REG);
  high = mvpp2_bm_reg_read (hif_base, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr |= (high & MVPP22_BM_VIRT_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET);
  paddr |= (high & MVPP22_BM_PHY_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_PHY_HIGH_ALLOC_OFFSET);
  buff->addr = paddr;
  buff->cookie = vaddr;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_bpool_init (mvpp2_bpool_params_t *params, mvpp2_bpool_t *pool)
{
  mvpp2_device_t *md = vnet_dev_get_data (params->dev);
  int pool_id = params->id;
  int rc;

  if (pool_id >= MVPP2_BPOOL_NUM_POOLS)
    return VNET_DEV_ERR_INVALID_ARG;
  if (md->bm_pool_reserved_map & (1 << pool_id))
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  if (pool->is_initialized)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  *pool = (mvpp2_bpool_t) {
    .id = pool_id,
    .buf_sz = params->dummy_short_pool ? MVPP2_DUMMY_POOL_BUF_SIZE : params->buff_len,
    .fc_not_supported = params->dummy_short_pool != 0,
  };
  rc = mvpp2_bm_pool_create (params->vm, md, pool);
  if (rc)
    {
      *pool = (mvpp2_bpool_t) {};
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mvpp2_bm_pool_reset_fc (md->cm3_base, pool);
  return VNET_DEV_OK;
}

void
mvpp2_bm_flush_pools (vnet_dev_t *dev, uintptr_t hif_base, u16 bm_pool_reserved_map)
{
  for (u32 pool_id = 0; pool_id < MVPP2_BPOOL_NUM_POOLS; pool_id++)
    {
      if (bm_pool_reserved_map & (1 << pool_id))
	continue;
      mvpp2_bm_pool_flush (dev, hif_base, pool_id);
      mvpp2_bm_hw_pool_destroy (hif_base, pool_id);
      mvpp2_bm_reg_write (hif_base, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
      mvpp2_bm_reg_write (hif_base, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
    }
  mvpp2_bm_reg_write (hif_base, MVPP2_BM_PRIO_CTRL_REG, 0);
  mvpp2_bm_reg_write (hif_base, MVPP22_BM_PHY_VIRT_HIGH_RLS_REG, 0);
}

void
mvpp2_bm_pool_assign (vnet_dev_port_t *port, u32 pool_id, u32 rxq_id, mvpp2_bm_pool_type_t type)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;
  u32 mask =
    type == MVPP2_BM_POOL_TYPE_LONG ? MVPP22_RXQ_POOL_LONG_MASK : MVPP22_RXQ_POOL_SHORT_MASK;
  u32 offset =
    type == MVPP2_BM_POOL_TYPE_LONG ? MVPP22_RXQ_POOL_LONG_OFFS : MVPP22_RXQ_POOL_SHORT_OFFS;
  u32 value = mvpp2_bm_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (rxq_id));

  value = (value & ~mask) | (pool_id << offset & mask);
  mvpp2_bm_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (rxq_id), value);
}
