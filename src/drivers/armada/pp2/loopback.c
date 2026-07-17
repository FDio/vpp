/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vnet/ethernet/packet.h>

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

static void
mvpp2_loopback_egress_disable (vnet_dev_t *dev)
{
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT,
  };
  mvpp22_txp_sched_q_cmd_reg_t command = {};
  u32 q_mask;
  u32 timeout = 0;

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  command.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_Q_CMD_REG);
  q_mask = command.enable;
  if (q_mask)
    {
      command = (mvpp22_txp_sched_q_cmd_reg_t) {
	.disable = q_mask,
      };
      mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
    }

  do
    {
      if (timeout++ >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	break;
      usleep (1000);
      command.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (command.enable & q_mask);
}

vnet_dev_rv_t
mvpp2_loopback_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT,
  };
  mvpp22_txp_sched_refill_reg_t port_refill;
  mvpp22_txq_sched_refill_reg_t queue_refill = {
    .tokens = MVPP2_TXQ_REFILL_TOKENS_MAX,
    .period = MVPP2_TXQ_REFILL_PERIOD_MIN,
  };
  mvpp22_rx_ctrl_reg_t rx_ctrl = {
    .gem_port_id_src = 2,
    .low_latency_pkt_size = 256,
    .use_pseudo_for_csum = 1,
  };
  mvpp22_txq_pref_buf_reg_t prefetch = {
    .size = 7, /* 64 descriptors */
    .threshold = MVPP2_LOOPBACK_PREFETCH_COUNT / 8,
  };
  mvpp22_txp_sched_q_cmd_reg_t command = {
    .enable = 1,
  };
  vnet_dev_rv_t rv;
  void *desc_mem;
  uintptr_t desc_phys;
  u32 desc, mtu, ptxq, value;

  mvpp2_loopback_egress_disable (dev);

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_CMD_1_REG, 0);
  for (u32 qid = 0; qid < MVPP2_MAX_TXQ; qid++)
    {
      ptxq = (MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ + qid;
      mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0);
    }
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PERIOD_REG, MVPP2_LOOPBACK_TCLK_FREQ / 1000000);
  port_refill.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_REFILL_REG);
  port_refill.period = 1;
  port_refill.tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_REFILL_REG, port_refill.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_TOKEN_SIZE_MAX);
  mvpp2_dev_reg_wr (dev, MVPP2_RX_CTRL_REG (MVPP2_LOOPBACK_PORT), rx_ctrl.as_u32);

  rv = vnet_dev_dma_mem_alloc (vm, dev, MVPP2_LOOPBACK_TXQ_SIZE * MVPP2_DESC_ALIGNED_SIZE,
			       MVPP2_DESC_Q_ALIGN, &desc_mem, "Loopback TX queue descriptors");
  if (rv != VNET_DEV_OK)
    return rv;
  md->lbk_desc_virt_arr = desc_mem;
  desc_phys = vnet_dev_get_dma_addr (vm, dev, md->lbk_desc_virt_arr);

  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_NUM_REG, MVPP2_LOOPBACK_TXQ_ID);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		    ((u32) desc_phys) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  mvpp2_dev_reg_wr (dev, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		    (desc_phys >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_SIZE_REG,
		    MVPP2_LOOPBACK_TXQ_SIZE & MVPP2_TXQ_DESC_SIZE_MASK);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_INDEX_REG, 0);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_RSVD_CLR_REG,
		    MVPP2_LOOPBACK_TXQ_ID << MVPP2_TXQ_RSVD_CLR_OFFSET);
  value = mvpp2_dev_reg_rd (dev, MVPP2_TXQ_PENDING_REG) & ~MVPP2_TXQ_PENDING_MASK;
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_PENDING_REG, value);

  desc = MVPP2_LOOPBACK_PORT * MVPP2_MAX_TXQ * MVPP2_LOOPBACK_PREFETCH_SIZE;
  prefetch.ptr = desc;
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_PREF_BUF_REG, prefetch.as_u32);
  for (u32 i = 0; i < ARRAY_LEN (md->threads); i++)
    if (md->threads[i].hif.descs)
      mvpp2_hif_reg_rd (&md->threads[i].hif, MVPP22_TXQ_SENT_REG (MVPP2_LOOPBACK_TXQ_ID));

  mtu = 3 * (MVPP2_LOOPBACK_MTU + sizeof (ethernet_header_t)) * 8;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  value = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_MTU_REG);
  value = (value & ~MVPP2_TXP_MTU_MAX) | clib_min (mtu, MVPP2_TXP_MTU_MAX);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_MTU_REG, value);
  port_refill.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_REFILL_REG);
  port_refill.tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
  port_refill.period = MVPP2_TXP_REFILL_PERIOD_MIN;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_REFILL_REG, port_refill.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_LOOPBACK_TXP_BUCKET_SIZE);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_REFILL_REG (0), queue_refill.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (0), MVPP2_LOOPBACK_TXQ_BUCKET_SIZE);

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
  md->lbk_is_initialized = 1;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_loopback_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u32 value;

  if (!md->lbk_is_initialized)
    return VNET_DEV_OK;

  mvpp2_loopback_egress_disable (dev);
  value = mvpp2_dev_reg_rd (dev, MVPP2_TX_PORT_FLUSH_REG) |
	  MVPP2_TX_PORT_FLUSH_MASK (MVPP2_LOOPBACK_PORT);
  mvpp2_dev_reg_wr (dev, MVPP2_TX_PORT_FLUSH_REG, value);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (MVPP2_LOOPBACK_TXQ_ID), 0);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_NUM_REG, MVPP2_LOOPBACK_TXQ_ID);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_SIZE_REG, 0);
  for (u32 i = 0; i < ARRAY_LEN (md->threads); i++)
    if (md->threads[i].hif.descs)
      mvpp2_hif_reg_rd (&md->threads[i].hif, MVPP22_TXQ_SENT_REG (MVPP2_LOOPBACK_TXQ_ID));
  value &= ~MVPP2_TX_PORT_FLUSH_MASK (MVPP2_LOOPBACK_PORT);
  mvpp2_dev_reg_wr (dev, MVPP2_TX_PORT_FLUSH_REG, value);
  vnet_dev_dma_mem_free (vm, dev, md->lbk_desc_virt_arr);
  md->lbk_desc_virt_arr = 0;
  md->lbk_is_initialized = 0;
  return VNET_DEV_OK;
}
