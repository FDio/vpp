/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <unistd.h>
#include <linux/if_ether.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "loopback",
};

#define MVPP2_LOOPBACK_TXQ_SIZE	       4096
#define MVPP2_LOOPBACK_PREFETCH_SIZE   16
#define MVPP2_LOOPBACK_PREFETCH_COUNT  64
#define MVPP2_LOOPBACK_TCLK_FREQ       333000000
#define MVPP2_LOOPBACK_MTU	       1500
#define MVPP2_LOOPBACK_TXP_BUCKET_SIZE (MVPP2_TXP_TOKEN_SIZE_MAX - MVPP2_TXP_REFILL_TOKENS_MAX)
#define MVPP2_LOOPBACK_TXQ_BUCKET_SIZE (MVPP2_TXQ_TOKEN_SIZE_MAX - MVPP2_TXQ_REFILL_TOKENS_MAX)

static_always_inline u32
mvpp2_loopback_reg_read (uintptr_t base, u32 offset)
{
  volatile u32 *addr = (void *) (base + offset);
  u32 value;

  value = __atomic_load_n (addr, __ATOMIC_RELAXED);
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static void
mvpp2_loopback_egress_disable (uintptr_t base)
{
  u32 q_mask;
  u32 value;
  u32 timeout = 0;

  mvpp2_reg_write (base, MVPP2_TXP_SCHED_PORT_INDEX_REG, MVPP2_LOOPBACK_PORT + MVPP2_MAX_TCONT);
  q_mask = mvpp2_loopback_reg_read (base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK;
  if (q_mask)
    mvpp2_reg_write (base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

  do
    {
      if (timeout++ >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	break;
      usleep (1000);
      value = mvpp2_loopback_reg_read (base, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (value & q_mask);
}

vnet_dev_rv_t
mvpp2_loopback_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vlib_main_t *vm = vlib_get_main ();
  uintptr_t base = md->pp_base;
  uintptr_t desc_phys;
  u32 desc, mtu, ptxq, value;

  mvpp2_loopback_egress_disable (base);

  mvpp2_reg_write (base, MVPP2_TXP_SCHED_PORT_INDEX_REG, MVPP2_LOOPBACK_PORT + MVPP2_MAX_TCONT);
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_CMD_1_REG, 0);
  for (u32 qid = 0; qid < MVPP2_MAX_TXQ; qid++)
    {
      ptxq = (MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ + qid;
      mvpp2_reg_write (base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0);
    }
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_PERIOD_REG, MVPP2_LOOPBACK_TCLK_FREQ / 1000000);
  value = mvpp2_loopback_reg_read (base, MVPP2_TXP_SCHED_REFILL_REG);
  value &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  value |= MVPP2_TXP_REFILL_PERIOD_MASK (1) | MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_REFILL_REG, value);
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_TOKEN_SIZE_MAX);
  mvpp2_reg_write (base, MVPP2_RX_CTRL_REG (MVPP2_LOOPBACK_PORT),
		   MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		     MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  md->lbk_desc_virt_arr = vlib_physmem_alloc_aligned (
    vm, MVPP2_LOOPBACK_TXQ_SIZE * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN);
  if (!md->lbk_desc_virt_arr)
    return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
  desc_phys = vlib_physmem_get_pa (vm, md->lbk_desc_virt_arr);

  mvpp2_reg_write (base, MVPP2_TXQ_NUM_REG, MVPP2_LOOPBACK_TXQ_ID);
  mvpp2_reg_write (base, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		   ((u32) desc_phys) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  mvpp2_reg_write (base, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		   (desc_phys >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  mvpp2_reg_write (base, MVPP2_TXQ_DESC_SIZE_REG,
		   MVPP2_LOOPBACK_TXQ_SIZE & MVPP2_TXQ_DESC_SIZE_MASK);
  mvpp2_reg_write (base, MVPP2_TXQ_INDEX_REG, 0);
  mvpp2_reg_write (base, MVPP2_TXQ_RSVD_CLR_REG,
		   MVPP2_LOOPBACK_TXQ_ID << MVPP2_TXQ_RSVD_CLR_OFFSET);
  value = mvpp2_loopback_reg_read (base, MVPP2_TXQ_PENDING_REG) & ~MVPP2_TXQ_PENDING_MASK;
  mvpp2_reg_write (base, MVPP2_TXQ_PENDING_REG, value);

  desc = MVPP2_LOOPBACK_PORT * MVPP2_MAX_TXQ * MVPP2_LOOPBACK_PREFETCH_SIZE;
  mvpp2_reg_write (base, MVPP2_TXQ_PREF_BUF_REG,
		   MVPP2_PREF_BUF_PTR (desc) | MVPP2_PREF_BUF_SIZE_64 |
		     MVPP2_PREF_BUF_THRESH (MVPP2_LOOPBACK_PREFETCH_COUNT / 8));
  for (u32 i = 0; i < MVPP2_NUM_HIFS; i++)
    mvpp2_loopback_reg_read (mvpp2_hif_base (md, i), MVPP22_TXQ_SENT_REG (MVPP2_LOOPBACK_TXQ_ID));

  mtu = 3 * (MVPP2_LOOPBACK_MTU + ETH_HLEN) * 8;
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_PORT_INDEX_REG, MVPP2_TX_PORT_NUM (MVPP2_LOOPBACK_PORT));
  value = mvpp2_loopback_reg_read (base, MVPP2_TXP_SCHED_MTU_REG);
  value = (value & ~MVPP2_TXP_MTU_MAX) | clib_min (mtu, MVPP2_TXP_MTU_MAX);
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_MTU_REG, value);
  value = mvpp2_loopback_reg_read (base, MVPP2_TXP_SCHED_REFILL_REG);
  value &= ~(MVPP2_TXP_REFILL_TOKENS_ALL_MASK | MVPP2_TXP_REFILL_PERIOD_ALL_MASK);
  value |= MVPP2_TXP_REFILL_TOKENS_MASK (MVPP2_TXP_REFILL_TOKENS_MAX) |
	   MVPP2_TXP_REFILL_PERIOD_MASK (MVPP2_TXP_REFILL_PERIOD_MIN);
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_REFILL_REG, value);
  mvpp2_reg_write (base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_LOOPBACK_TXP_BUCKET_SIZE);
  mvpp2_reg_write (base, MVPP2_TXQ_SCHED_REFILL_REG (0),
		   MVPP2_TXQ_REFILL_TOKENS_MASK (MVPP2_TXQ_REFILL_TOKENS_MAX) |
		     MVPP2_TXQ_REFILL_PERIOD_MASK (MVPP2_TXQ_REFILL_PERIOD_MIN));
  mvpp2_reg_write (base, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (0), MVPP2_LOOPBACK_TXQ_BUCKET_SIZE);

  mvpp2_reg_write (base, MVPP2_TXP_SCHED_Q_CMD_REG, 1);
  md->lbk_is_initialized = 1;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_loopback_deinit (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  uintptr_t base = md->pp_base;
  u32 value;

  if (!md->lbk_is_initialized)
    return VNET_DEV_OK;

  mvpp2_loopback_egress_disable (base);
  value = mvpp2_loopback_reg_read (base, MVPP2_TX_PORT_FLUSH_REG) |
	  MVPP2_TX_PORT_FLUSH_MASK (MVPP2_LOOPBACK_PORT);
  mvpp2_reg_write (base, MVPP2_TX_PORT_FLUSH_REG, value);
  mvpp2_reg_write (base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (MVPP2_LOOPBACK_TXQ_ID), 0);
  mvpp2_reg_write (base, MVPP2_TXQ_NUM_REG, MVPP2_LOOPBACK_TXQ_ID);
  mvpp2_reg_write (base, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  mvpp2_reg_write (base, MVPP2_TXQ_DESC_SIZE_REG, 0);
  for (u32 i = 0; i < MVPP2_NUM_HIFS; i++)
    mvpp2_loopback_reg_read (mvpp2_hif_base (md, i), MVPP22_TXQ_SENT_REG (MVPP2_LOOPBACK_TXQ_ID));
  value &= ~MVPP2_TX_PORT_FLUSH_MASK (MVPP2_LOOPBACK_PORT);
  mvpp2_reg_write (base, MVPP2_TX_PORT_FLUSH_REG, value);
  vlib_physmem_free (vlib_get_main (), md->lbk_desc_virt_arr);
  md->lbk_desc_virt_arr = 0;
  md->lbk_is_initialized = 0;
  return VNET_DEV_OK;
}
