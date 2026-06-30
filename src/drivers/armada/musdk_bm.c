/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <cma.h>
#include <musdk.h>
#include <musdk_internal.h>
#include <pp2/pp2.h>
#include <pp2/pp2_regs.h>

#define PP2_NUM_PKT_PROC	 4
#define PP2_DEFAULT_REGSPACE	 0
#define PP2_BPOOL_NUM_POOLS	 16
#define PP2_MAX_NUM_PUT_BUFFS	 8192
#define PP2_DUMMY_POOL_BUF_SIZE	 64
#define PP2_BPPE_UNIT_SIZE	 8
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

#define pr_err(...)  clib_warning (__VA_ARGS__)
#define pr_warn(...) clib_warning (__VA_ARGS__)
#define pr_debug(...)

struct bm_pool_param
{
  u32 id;
  u32 pp2_id;
  u32 buf_num;
  u32 buf_size;
  int dummy_pool;
  struct mv_sys_dma_mem_region *likely_buffer_mem;
};

static struct pp2_bpool pp2_bpools[PP2_NUM_PKT_PROC][PP2_BPOOL_NUM_POOLS];

static_always_inline u32
pp2_bm_reg_read_relaxed (uintptr_t cpu_slot, u32 offset)
{
  uintptr_t addr = cpu_slot + offset;
  u32 value;

  asm volatile ("ldr %w0, [%1]" : "=r"(value) : "r"(addr));
  return value;
}

static_always_inline u32
pp2_bm_reg_read (uintptr_t cpu_slot, u32 offset)
{
  u32 value = pp2_bm_reg_read_relaxed (cpu_slot, offset);

  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
pp2_bm_reg_write (uintptr_t cpu_slot, u32 offset, u32 value)
{
  uintptr_t addr = cpu_slot + offset;

  asm volatile ("dsb st" : : : "memory");
  asm volatile ("str %w0, [%1]" : : "r"(value), "r"(addr));
}

static_always_inline uintptr_t
pp2_bm_hw_buf_get (uintptr_t cpu_slot, u32 pool_id)
{
  uintptr_t vaddr;

  pp2_bm_reg_read (cpu_slot, MVPP2_BM_PHY_ALLOC_REG (pool_id));
  vaddr = pp2_bm_reg_read (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr &= MVPP22_BM_VIRT_HIGH_ALLOC_MASK;
  vaddr <<= 32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET;
  vaddr |= pp2_bm_reg_read (cpu_slot, MVPP2_BM_VIRT_ALLOC_REG);
  return vaddr;
}

static_always_inline void
pp2_bm_pool_bufsize_set (uintptr_t cpu_slot, u32 pool_id, u32 buf_size)
{
  u32 align = 1 << MVPP2_POOL_BUF_SIZE_OFFSET;
  u32 value = (buf_size + align - 1) & ~(align - 1);

  pp2_bm_reg_write (cpu_slot, MVPP2_POOL_BUF_SIZE_REG (pool_id), value);
}

static u32
pp2_bm_pool_flush (uintptr_t cpu_slot, u32 pool_id)
{
  u32 j, pool_bufs, resid_bufs;

  resid_bufs =
    (pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
     MVPP22_BM_POOL_PTRS_NUM_MASK) +
    (pp2_bm_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);
  if (resid_bufs == 0)
    return 0;

  pool_bufs = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (pool_bufs && resid_bufs + 1 > pool_bufs)
    pr_warn ("BM: number of buffers in pool #%u (%u) is more than pool size (%u)", pool_id,
	     resid_bufs, pool_bufs);

  for (j = 0; j < resid_bufs + 1; j++)
    pp2_bm_hw_buf_get (cpu_slot, pool_id);

  return (pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) &
	  MVPP22_BM_POOL_PTRS_NUM_MASK) +
	 (pp2_bm_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) &
	  MVPP2_BM_BPPI_PTR_NUM_MASK);
}

static void
pp2_bm_hw_pool_destroy (uintptr_t cpu_slot, u32 pool_id)
{
  u32 value = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));

  if (value & MVPP2_BM_STATE_MASK)
    {
      value |= MVPP2_BM_STOP_MASK;
      pp2_bm_reg_write (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
      do
	value = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
      while (value & MVPP2_BM_STATE_MASK);
    }

  pp2_bm_reg_write (cpu_slot, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
  pp2_bm_reg_write (cpu_slot, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
  pp2_bm_reg_write (cpu_slot, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), 0);
  value = pp2_bm_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_bm_reg_write (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);
  pp2_bm_pool_bufsize_set (cpu_slot, pool_id, 0);
}

static int
pp2_bm_get_8pool_mode (uintptr_t cpu_slot)
{
  return pp2_bm_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG) & MVPP23_BM_8POOL_MODE;
}

static u32
pp2_bm_hw_pool_create (uintptr_t cpu_slot, u32 pool_id, u32 bppe_num, uintptr_t pool_phys_addr)
{
  u32 value, pool_bufs;
  u32 phys_lo = (u32) pool_phys_addr & MVPP2_BM_POOL_BASE_ADDR_MASK;
  u32 phys_hi = (u64) pool_phys_addr >> 32;

  value = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
  if (value & MVPP2_BM_STATE_MASK)
    return 1;

  pp2_bm_reg_write (cpu_slot, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id), phys_lo);
  value = pp2_bm_reg_read (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
  value &= ~MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  value |= phys_hi & MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK;
  pp2_bm_reg_write (cpu_slot, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG, value);

  pool_bufs = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id));
  if (!pool_bufs)
    pp2_bm_reg_write (cpu_slot, MVPP2_BM_POOL_SIZE_REG (pool_id), bppe_num);
  else if (pool_bufs != bppe_num)
    return 1;

  value = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
  value |= MVPP2_BM_START_MASK;
  value &= ~(MVPP2_BM_LOW_THRESH_MASK | MVPP2_BM_HIGH_THRESH_MASK);
  if (pp2_bm_get_8pool_mode (cpu_slot))
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP23_BM_BPPI_8POOL_HIGH_THRESH);
  else
    value |= MVPP2_BM_LOW_THRESH_VALUE (MVPP2_BM_BPPI_LOW_THRESH) |
	     MVPP2_BM_HIGH_THRESH_VALUE (MVPP2_BM_BPPI_HIGH_THRESH);
  pp2_bm_reg_write (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id), value);
  do
    value = pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_CTRL_REG (pool_id));
  while (!(value & MVPP2_BM_STATE_MASK));
  return 0;
}

static int
pp2_bm_pool_create (struct bm_pool_param *param)
{
  struct pp2_bm_pool *pool;
  u32 bppe_num, bppe_region_size;
  uintptr_t cpu_slot;

  if (param->buf_num % PP2_BPPE_UNIT_SIZE)
    return -EACCES;
  if (param->buf_size < PP2_BUFFER_OFFSET || param->buf_size % PP2_BUFFER_OFFSET_GRAN)
    return -EACCES;

  pool = clib_mem_alloc_or_null (sizeof (*pool));
  if (!pool)
    return -ENOMEM;
  memset (pool, 0, sizeof (*pool));
  pool->bm_pool_id = param->id;
  pool->bm_pool_buf_sz = param->buf_size;
  pool->pp2_id = param->pp2_id;
  pool->bm_pool_buf_num = param->buf_num;
  pool->fc_not_supported = param->dummy_pool != 0;
  pool->likely_buffer_mem = param->likely_buffer_mem;

  bppe_num = pool->bm_pool_buf_num;
  bppe_region_size = bppe_num * 2 * sizeof (u64);
  pool->bppe_mem = mv_sys_dma_mem_region_get (musdk_mem_id (pool->pp2_id));
  pool->bm_pool_virt_base = (uintptr_t) mv_sys_dma_mem_region_alloc (
    pool->bppe_mem, bppe_region_size, MVPP2_BM_POOL_PTR_ALIGN);
  if (!pool->bm_pool_virt_base)
    goto no_mem;

  pool->bm_pool_phys_base =
    (uintptr_t) mv_sys_dma_mem_region_virt2phys (pool->bppe_mem, (void *) pool->bm_pool_virt_base);
  if (pool->bm_pool_phys_base & (MVPP2_BM_POOL_PTR_ALIGN - 1))
    goto bad_region;

  cpu_slot = musdk_cpu_slot (pool->pp2_id, PP2_DEFAULT_REGSPACE);
  if (pp2_bm_hw_pool_create (cpu_slot, pool->bm_pool_id, bppe_num, pool->bm_pool_phys_base))
    goto bad_region;
  pp2_bm_pool_bufsize_set (cpu_slot, pool->bm_pool_id, pool->bm_pool_buf_sz);
  musdk_pool_slot_set (pool->pp2_id, pool->bm_pool_id, pool);
  return 0;

bad_region:
  mv_sys_dma_mem_region_free (pool->bppe_mem, (void *) pool->bm_pool_virt_base);
  clib_mem_free (pool);
  return -EIO;
no_mem:
  clib_mem_free (pool);
  return -ENOMEM;
}

static int
pp2_bm_pool_destroy (uintptr_t cpu_slot, struct pp2_bm_pool *pool)
{
  pp2_bm_pool_flush (cpu_slot, pool->bm_pool_id);
  pp2_bm_hw_pool_destroy (cpu_slot, pool->bm_pool_id);
  mv_sys_dma_mem_region_free (pool->bppe_mem, (void *) pool->bm_pool_virt_base);
  clib_mem_free (pool);
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
pp2_bm_pool_reset_fc (uintptr_t base, struct pp2_bm_pool *pool)
{
  u32 value = pp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  u32 cm3_state = value & FLOW_CONTROL_ENABLE_BIT;

  value &= ~FLOW_CONTROL_ENABLE_BIT;
  pp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
  pp2_bm_cm3_write (base, MSS_CP_CM3_BUF_POOL_BASE + pool->bm_pool_id * MSS_CP_CM3_BUF_POOL_OFFS,
		    0);
  value = pp2_bm_cm3_read (base, MSS_CP_FC_COM_REG);
  value |= FLOW_CONTROL_UPD_COM_BIT | cm3_state;
  pp2_bm_cm3_write (base, MSS_CP_FC_COM_REG, value);
}

int
pp2_bpool_get_num_buffs (struct pp2_bpool *pool, u32 *num_buffs)
{
  struct base_addr *base = pool->internal_param;
  uintptr_t cpu_slot = base[PP2_DEFAULT_REGSPACE].va;
  u32 num;

  num = (pp2_bm_reg_read (cpu_slot, MVPP2_BM_POOL_PTRS_NUM_REG (pool->id)) &
	 MVPP22_BM_POOL_PTRS_NUM_MASK) +
	(pp2_bm_reg_read (cpu_slot, MVPP2_BM_BPPI_PTRS_NUM_REG (pool->id)) &
	 MVPP2_BM_BPPI_PTR_NUM_MASK);
  *num_buffs = num ? num + 1 : 0;
  return 0;
}

void
pp2_bpool_deinit (struct pp2_bpool *pool)
{
  struct base_addr *base = pool->internal_param;
  struct pp2_bm_pool *bm_pool;
  uintptr_t cpu_slot = base[PP2_DEFAULT_REGSPACE].va;
  u32 buf_num;

  pp2_bpool_get_num_buffs (pool, &buf_num);
  if (buf_num)
    pr_warn ("cannot free all buffers in pool %d, buf_num left %u", pool->id, buf_num);

  bm_pool = musdk_pool_slot_get (pool->pp2_id, pool->id);
  if (bm_pool)
    pp2_bm_pool_reset_fc (musdk_cm3_base (pool->pp2_id), bm_pool);
  if (bm_pool && !pp2_bm_pool_destroy (cpu_slot, bm_pool))
    musdk_pool_slot_set (pool->pp2_id, pool->id, 0);
}

int
pp2_bpool_get_buff (struct pp2_hif *hif, struct pp2_bpool *pool, struct pp2_buff_inf *buff)
{
  struct base_addr *base = pool->internal_param;
  uintptr_t cpu_slot = base[hif->regspace_slot].va;
  u64 paddr, vaddr, high;

  paddr = pp2_bm_reg_read (cpu_slot, MVPP2_BM_PHY_ALLOC_REG (pool->id));
  if (!paddr)
    return -ENOBUFS;
  vaddr = pp2_bm_reg_read (cpu_slot, MVPP2_BM_VIRT_ALLOC_REG);
  high = pp2_bm_reg_read (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG);
  vaddr |= (high & MVPP22_BM_VIRT_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET);
  paddr |= (high & MVPP22_BM_PHY_HIGH_ALLOC_MASK) << (32 - MVPP22_BM_PHY_HIGH_ALLOC_OFFSET);
  buff->addr = paddr;
  buff->cookie = vaddr;
  return 0;
}

int
pp2_bpool_init (struct pp2_bpool_params *params, struct pp2_bpool **bpool)
{
  struct bm_pool_param param;
  int pool_id = params->id;
  int pp2_id = params->pp2_id;
  int rc;

  if (!musdk_is_init ())
    return -EPERM;
  if (pool_id >= PP2_BPOOL_NUM_POOLS || pp2_id >= musdk_num_instances ())
    return -ENXIO;
  if (musdk_reserved_pool_map () & (1 << pool_id))
    return -EFAULT;
  if (musdk_pool_slot_get (pp2_id, pool_id))
    return -EEXIST;

  param = (struct bm_pool_param) {
    .dummy_pool = params->dummy_short_pool,
    .buf_num = MVPP2_BM_POOL_SIZE_MAX,
    .buf_size = params->dummy_short_pool ? PP2_DUMMY_POOL_BUF_SIZE : params->buff_len,
    .id = pool_id,
    .pp2_id = pp2_id,
    .likely_buffer_mem = params->likely_buffer_mem,
  };
  rc = pp2_bm_pool_create (&param);
  if (rc)
    return rc;

  pp2_bpools[pp2_id][pool_id].id = pool_id;
  pp2_bpools[pp2_id][pool_id].pp2_id = pp2_id;
  pp2_bpools[pp2_id][pool_id].internal_param = musdk_regspaces (pp2_id);
  *bpool = &pp2_bpools[pp2_id][pool_id];
  pp2_bm_pool_reset_fc (musdk_cm3_base (pp2_id), musdk_pool_slot_get (pp2_id, pool_id));
  return 0;
}

static_always_inline void
pp2_bpool_desc_set_cookie (struct pp2_ppio_desc *desc, u64 cookie)
{
  desc->cmds[6] = (u32) cookie;
  desc->cmds[7] = (desc->cmds[7] & ~TXD_BUF_VIRT_HI_MASK) | (cookie >> 32 & TXD_BUF_VIRT_HI_MASK);
}

static_always_inline void
pp2_bpool_desc_set_pool (struct pp2_ppio_desc *desc, struct pp2_bpool *pool)
{
  desc->cmds[0] = (desc->cmds[0] & ~(TXD_POOL_ID_MASK | TXD_BUFMODE_MASK)) |
		  (pool->id << 16 & TXD_POOL_ID_MASK) | (1 << 7 & TXD_BUFMODE_MASK);
}

int
pp2_bpool_put_buffs (struct pp2_hif *hif, struct buff_release_entry buff_entry[], u16 *num)
{
  struct pp2_ppio_desc *desc;
  int pp_ind[PP2_NUM_PKT_PROC] = { 0 };

  for (u32 i = 0; i < *num; i++)
    {
      u32 pp2_id = buff_entry[i].bpool->pp2_id;

      desc = hif->rel_descs + PP2_MAX_NUM_PUT_BUFFS * pp2_id + pp_ind[pp2_id];
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
      pp_ind[pp2_id]++;
    }

  for (u32 i = 0; i < PP2_NUM_PKT_PROC; i++)
    if (pp_ind[i])
      musdk_release_descs (i, pp_ind[i], hif->regspace_slot,
			   hif->rel_descs + PP2_MAX_NUM_PUT_BUFFS * i);
  return 0;
}

void
pp2_bm_flush_pools (uintptr_t cpu_slot, u16 bm_pool_reserved_map)
{
  for (u32 pool_id = 0; pool_id < PP2_BPOOL_NUM_POOLS; pool_id++)
    {
      if (bm_pool_reserved_map & (1 << pool_id))
	continue;
      pp2_bm_pool_flush (cpu_slot, pool_id);
      pp2_bm_hw_pool_destroy (cpu_slot, pool_id);
      pp2_bm_reg_write (cpu_slot, MVPP2_BM_INTR_MASK_REG (pool_id), 0);
      pp2_bm_reg_write (cpu_slot, MVPP2_BM_INTR_CAUSE_REG (pool_id), 0);
    }
  pp2_bm_reg_write (cpu_slot, MVPP2_BM_PRIO_CTRL_REG, 0);
  pp2_bm_reg_write (cpu_slot, MVPP22_BM_PHY_VIRT_HIGH_RLS_REG, 0);
}

void
pp2_bm_pool_assign (struct pp2_port *port, u32 pool_id, u32 rxq_id, u32 type)
{
  uintptr_t cpu_slot = musdk_port_cpu_slot (port);
  u32 mask = type == BM_TYPE_LONG_BUF_POOL ? MVPP22_RXQ_POOL_LONG_MASK : MVPP22_RXQ_POOL_SHORT_MASK;
  u32 offset =
    type == BM_TYPE_LONG_BUF_POOL ? MVPP22_RXQ_POOL_LONG_OFFS : MVPP22_RXQ_POOL_SHORT_OFFS;
  u32 value = pp2_bm_reg_read (cpu_slot, MVPP2_RXQ_CONFIG_REG (rxq_id));

  value = (value & ~mask) | (pool_id << offset & mask);
  pp2_bm_reg_write (cpu_slot, MVPP2_RXQ_CONFIG_REG (rxq_id), value);
}
