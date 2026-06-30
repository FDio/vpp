/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk.h>
#include <musdk_internal.h>
#include <pp2/pp2.h>
#include <pp2/pp2_regs.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "musdk-bm",
};

#define PP2_BPOOL_NUM_POOLS	 16
#define PP2_DUMMY_POOL_BUF_SIZE	 64
#define PP2_BUFFER_OFFSET	 32
#define PP2_BUFFER_OFFSET_GRAN	 32
#define PP2_BM_BUF_DEBUG	 0
#define DUMMY_PKT_EFEC_OFFS	 (64 + MV_MH_SIZE)
#define TXD_ERR_SUM_MASK	 0x04000000
#define TXD_BUFMODE_MASK	 0x00000080
#define TXD_BUF_VIRT_HI_MASK	 0x000000ff
#define TXD_POOL_ID_MASK	 0x000f0000
#define MSS_CP_FC_COM_REG	 0
#define MSS_CP_CM3_BUF_POOL_BASE 0x40
#define MSS_CP_CM3_BUF_POOL_OFFS 4
#define BM_TYPE_SHORT_BUF_POOL	 0
#define BM_TYPE_LONG_BUF_POOL	 1

static_always_inline u32
pp2_bm_reg_read_relaxed (uintptr_t hif_base, u32 offset)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  return __atomic_load_n (addr, __ATOMIC_RELAXED);
}

static_always_inline u32
pp2_bm_reg_read (uintptr_t hif_base, u32 offset)
{
  u32 value = pp2_bm_reg_read_relaxed (hif_base, offset);

  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
pp2_bm_reg_write (uintptr_t hif_base, u32 offset, u32 value)
{
  volatile u32 *addr = (void *) (hif_base + offset);

  asm volatile ("dsb st" : : : "memory");
  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

static_always_inline uintptr_t
pp2_bm_hw_buf_get (uintptr_t hif_base, u32 pool_id)
{
  uintptr_t vaddr;

  pp2_bm_reg_read (hif_base, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  vaddr = pp2_bm_reg_read (hif_base, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr &= MVPP22_BM_VIRT_HIGH_ALLOC_MASK;
  vaddr <<= 32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET;
  vaddr |= pp2_bm_reg_read (hif_base, MVPP2_BM_VIRT_ALLOC_REG);
  return vaddr;
}

static_always_inline void
pp2_bm_pool_bufsize_set (uintptr_t hif_base, u32 pool_id, u32 buf_size)
{
  u32 align = 1 << MVPP2_POOL_BUF_SIZE_OFFSET;
  u32 value = (buf_size + align - 1) & ~(align - 1);

  pp2_bm_reg_write (hif_base, MVPP2_POOL_BUF_SIZE_REG (pool_id), value);
}

static u32
pp2_bm_pool_flush (vnet_dev_t *dev, uintptr_t hif_base, u32 pool_id)
{
  u32 j, pool_bufs, resid_bufs;

  resid_bufs =
    (pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
     MVPP22_BM_POOL_PTRS_NUM_MASK) +
    (pp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);
  if (resid_bufs == 0)
    return 0;

  pool_bufs = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (pool_bufs && resid_bufs + 1 > pool_bufs)
    log_warn (dev, "BM: number of buffers in pool #%u (%u) is more than pool size (%u)", pool_id,
	      resid_bufs, pool_bufs);

  for (j = 0; j < resid_bufs + 1; j++)
    pp2_bm_hw_buf_get (hif_base, pool_id);

  return (pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
	  MVPP22_BM_POOL_PTRS_NUM_MASK) +
	 (pp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) &
	  MVPP2_BM_BPPI_PTR_NUM_MASK);
}

static void
pp2_bm_hw_pool_destroy (uintptr_t hif_base, u32 pool_id)
{
  u32 value = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));

  if (value & MVPP2_BM_STATE_MASK)
    {
      value |= MVPP2_BM_STOP_MASK;
      pp2_bm_reg_write (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
      do
	value = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
      while (value & MVPP2_BM_STATE_MASK);
    }

  pp2_bm_reg_write (hif_base, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
  pp2_bm_reg_write (hif_base, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
  pp2_bm_reg_write (hif_base, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), 0);
  value = pp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_bm_reg_write (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);
  pp2_bm_pool_bufsize_set (hif_base, pool_id, 0);
}

static int
pp2_bm_get_8pool_mode (uintptr_t hif_base)
{
  return pp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG) & MVPP23_BM_8POOL_MODE;
}

static u32
pp2_bm_hw_pool_create (uintptr_t hif_base, u32 pool_id, u32 bppe_num, uintptr_t pool_phys_addr)
{
  u32 value, pool_bufs;
  u32 phys_lo = (u32) pool_phys_addr & MVPP2_BM_POOL_BASE_ADDR_MASK;
  u32 phys_hi = (u64) pool_phys_addr >> 32;

  value = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  if (value & MVPP2_BM_STATE_MASK)
    return 1;

  pp2_bm_reg_write (hif_base, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), phys_lo);
  value = pp2_bm_reg_read (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  value |= phys_hi & MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_bm_reg_write (hif_base, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);

  pool_bufs = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (!pool_bufs)
    pp2_bm_reg_write (hif_base, MVPP2_BM_POOL_SIZE_REG (pool_id), bppe_num);
  else if (pool_bufs != bppe_num)
    return 1;

  value = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  value |= MVPP2_BM_START_MASK;
  value &= ~(MVPP2_BM_LOW_THRESH_MASK | MVPP2_BM_HIGH_THRESH_MASK);
  if (pp2_bm_get_8pool_mode (hif_base))
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_HIGH_THRESH);
  else
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP2_BM_BPPI_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP2_BM_BPPI_HIGH_THRESH);
  pp2_bm_reg_write (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
  do
    value = pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_CTRL_REG (pool_id));
  while (!(value & MVPP2_BM_STATE_MASK));
  return VNET_DEV_OK;
}

static int
pp2_bm_pool_create (vlib_main_t *vm, mvpp2_device_t *md, mvpp2_bpool_t *pool)
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
  if (pp2_bm_hw_pool_create (hif_base, pool->id, bppe_num, pool->phys_base))
    goto bad_region;
  pp2_bm_pool_bufsize_set (hif_base, pool->id, pool->buf_sz);
  pool->is_initialized = 1;
  return 0;

bad_region:
  vlib_physmem_free (vm, (void *) pool->virt_base);
  pool->virt_base = 0;
  pool->phys_base = 0;
  return -EIO;
}

static int
pp2_bm_pool_destroy (vlib_main_t *vm, vnet_dev_t *dev, uintptr_t hif_base, mvpp2_bpool_t *pool)
{
  pp2_bm_pool_flush (dev, hif_base, pool->id);
  pp2_bm_hw_pool_destroy (hif_base, pool->id);
  vlib_physmem_free (vm, (void *) pool->virt_base);
  *pool = (mvpp2_bpool_t) {};
  return 0;
}

static_always_inline u32
pp2_bm_cm3_read (uintptr_t base, u32 offset)
{
  return pp2_bm_reg_read (base, offset);
}

static_always_inline void
pp2_bm_cm3_write (uintptr_t base, u32 offset, u32 value)
{
  pp2_bm_reg_write (base, offset, value);
}

static void
pp2_bm_pool_reset_fc (uintptr_t base, mvpp2_bpool_t *pool)
{
  u32 value = pp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  u32 cm3_state = value & FLOW_CONTROL_ENABLE_BIT;

  value &= ~FLOW_CONTROL_ENABLE_BIT;
  pp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
  pp2_bm_cm3_write (base, MSS_CP_CM3_BUF_POOL_BASE + pool->id * MSS_CP_CM3_BUF_POOL_OFFS, 0);
  value = pp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  value |= FLOW_CONTROL_UPD_COM_BIT | cm3_state;
  pp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
}

static vnet_dev_rv_t
pp2_bpool_get_num_buffs (vnet_dev_t *dev, mvpp2_bpool_t *pool, u32 *num_buffs)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->pp_base;
  u32 num;

  num = (pp2_bm_reg_read (hif_base, MVPP2_BM_POOL_PTRS_NUM_REG (pool->id)) &
	 MVPP22_BM_POOL_PTRS_NUM_MASK) +
	(pp2_bm_reg_read (hif_base, MVPP2_BM_BPPI_PTRS_NUM_REG (pool->id)) &
	 MVPP2_BM_BPPI_PTR_NUM_MASK);
  *num_buffs = num ? num + 1 : 0;
  return VNET_DEV_OK;
}

void
pp2_bpool_deinit (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->pp_base;
  u32 buf_num;

  pp2_bpool_get_num_buffs (dev, pool, &buf_num);
  if (buf_num)
    log_warn (dev, "cannot free all buffers in pool %d, buf_num left %u", pool->id, buf_num);

  if (pool->is_initialized)
    {
      pp2_bm_pool_reset_fc (md->cm3_base, pool);
      pp2_bm_pool_destroy (vm, dev, hif_base, pool);
    }
}

vnet_dev_rv_t
pp2_bpool_get_buff (vlib_main_t *vm, vnet_dev_t *dev, mvpp2_bpool_t *pool,
		    struct pp2_buff_inf *buff)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t hif_base = md->threads[vm->thread_index].hif_base;
  u64 paddr, vaddr, high;

  paddr = pp2_bm_reg_read (hif_base, MVPP2_BM_PHY_ALLOC_REG (pool->id));
  if (!paddr)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  vaddr = pp2_bm_reg_read (hif_base, MVPP2_BM_VIRT_ALLOC_REG);
  high = pp2_bm_reg_read (hif_base, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr |= (high & MVPP22_BM_VIRT_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET);
  paddr |= (high & MVPP22_BM_PHY_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_PHY_HIGH_ALLOC_OFFSET);
  buff->addr = paddr;
  buff->cookie = vaddr;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
pp2_bpool_init (struct pp2_bpool_params *params, mvpp2_bpool_t *pool)
{
  mvpp2_device_t *md = vnet_dev_get_data (params->dev);
  int pool_id = params->id;
  int rc;

  if (pool_id >= PP2_BPOOL_NUM_POOLS)
    return VNET_DEV_ERR_INVALID_ARG;
  if (md->bm_pool_reserved_map & (1 << pool_id))
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  if (pool->is_initialized)
    return VNET_DEV_ERR_ALREADY_EXISTS;

  *pool = (mvpp2_bpool_t) {
    .id = pool_id,
    .buf_sz = params->dummy_short_pool ? PP2_DUMMY_POOL_BUF_SIZE : params->buff_len,
    .fc_not_supported = params->dummy_short_pool != 0,
  };
  rc = pp2_bm_pool_create (params->vm, md, pool);
  if (rc)
    {
      *pool = (mvpp2_bpool_t) {};
      return VNET_DEV_ERR_INIT_FAILED;
    }

  pp2_bm_pool_reset_fc (md->cm3_base, pool);
  return VNET_DEV_OK;
}

static_always_inline void
pp2_bpool_desc_set_cookie (struct pp2_ppio_desc *desc, u64 cookie)
{
  desc->cmds[6] = (u32) cookie;
  desc->cmds[7] = (desc->cmds[7] & ~TXD_BUF_VIRT_HI_MASK) | (cookie >> 32 & TXD_BUF_VIRT_HI_MASK);
}

static_always_inline void
pp2_bpool_desc_set_pool (struct pp2_ppio_desc *desc, mvpp2_bpool_t *pool)
{
  desc->cmds[0] = (desc->cmds[0] & ~(TXD_POOL_ID_MASK | TXD_BUFMODE_MASK)) |
		  (pool->id << 16 & TXD_POOL_ID_MASK) | (1 << 7 & TXD_BUFMODE_MASK);
}

vnet_dev_rv_t
pp2_bpool_put_buffs (vlib_main_t *vm, vnet_dev_t *dev, struct buff_release_entry buff_entry[],
		     u16 *num)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  struct pp2_ppio_desc *descs = md->rel_descs[vm->thread_index];

  for (u32 i = 0; i < *num; i++)
    {
      struct pp2_ppio_desc *desc = descs + i;

      desc->cmds[0] = desc->cmds[1] = desc->cmds[2] = desc->cmds[3] = desc->cmds[5] =
	desc->cmds[7] = 0;
      desc->cmds[0] = TXD_IP_CHK_DISABLE << 15;
      desc->cmds[0] |= TXD_L4_CHK_DISABLE << 13;
      desc->cmds[0] |= TXD_FIRST_LAST << 28;
      desc->cmds[4] = buff_entry[i].buff.addr;
      desc->cmds[5] = buff_entry[i].buff.addr >> 32 & TXD_BUF_PHYS_HI_MASK;
      desc->cmds[1] = DUMMY_PKT_EFEC_OFFS;
      pp2_bpool_desc_set_cookie (desc, buff_entry[i].buff.cookie);
      pp2_bpool_desc_set_pool (desc, buff_entry[i].bpool);
      desc->cmds[3] = TXD_ERR_SUM_MASK;
    }

  musdk_release_descs (vm, dev, *num, descs);
  return VNET_DEV_OK;
}

void
pp2_bm_flush_pools (vnet_dev_t *dev, uintptr_t hif_base, u16 bm_pool_reserved_map)
{
  for (u32 pool_id = 0; pool_id < PP2_BPOOL_NUM_POOLS; pool_id++)
    {
      if (bm_pool_reserved_map & (1 << pool_id))
	continue;
      pp2_bm_pool_flush (dev, hif_base, pool_id);
      pp2_bm_hw_pool_destroy (hif_base, pool_id);
      pp2_bm_reg_write (hif_base, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
      pp2_bm_reg_write (hif_base, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
    }
  pp2_bm_reg_write (hif_base, MVPP2_BM_PRIO_CTRL_REG, 0);
  pp2_bm_reg_write (hif_base, MVPP22_BM_PHY_VIRT_HIGH_RLS_REG, 0);
}

void
pp2_bm_pool_assign (vnet_dev_port_t *port, u32 pool_id, u32 rxq_id, u32 type)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  uintptr_t hif_base = mp->hif_base;
  u32 mask = type == BM_TYPE_LONG_BUF_POOL ? MVPP22_RXQ_POOL_LONG_MASK : MVPP22_RXQ_POOL_SHORT_MASK;
  u32 offset =
    type == BM_TYPE_LONG_BUF_POOL ? MVPP22_RXQ_POOL_LONG_OFFS : MVPP22_RXQ_POOL_SHORT_OFFS;
  u32 value = pp2_bm_reg_read (hif_base, MVPP2_RXQ_CONFIG_REG (rxq_id));

  value = (value & ~mask) | (pool_id << offset & mask);
  pp2_bm_reg_write (hif_base, MVPP2_RXQ_CONFIG_REG (rxq_id), value);
}
