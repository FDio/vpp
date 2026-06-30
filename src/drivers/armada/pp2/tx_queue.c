/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <endian.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "tx-queue",
};

static_always_inline u32
mvpp2_tx_queue_reg_read (uintptr_t base, u32 offset)
{
  volatile u32 *addr = (void *) (base + offset);
  u32 value;

  value = le32toh (__atomic_load_n (addr, __ATOMIC_RELAXED));
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static u32
mvpp2_txq_pend_desc_num_get (vnet_dev_tx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  u32 val;

  mvpp2_reg_write (mp->hif_base, MVPP2_TXQ_NUM_REG, txq->hw_id);
  val = mvpp2_tx_queue_reg_read (mp->hif_base, MVPP2_TXQ_PENDING_REG);

  return val & MVPP2_TXQ_PENDING_MASK;
}

vnet_dev_rv_t
mvpp2_port_set_txq_state (vnet_dev_tx_queue_t *q, int en)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  uintptr_t hif_base = mp->hif_base;
  int tx_port_num = MVPP2_MAX_TCONT + mp->id;
  u32 val = 0, mask;

  /* TODO: add lock to protect MVPP2_TXP_SCHED_PORT_INDEX_REG */
  /* Get active channels mask */
  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  val = (mvpp2_tx_queue_reg_read (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK);
  mask = 1 << q->queue_id;

  if (en)
    {
      if (!(val & mask))
	{
	  /* Enable transmit packets to aggregation queue */
	  txq->disabled = 0;

	  /* Enable Tx queue */
	  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, mask);
	}
    }
  else
    {
      if (val & mask)
	{
	  u32 delay = 0;
	  u32 pending;

	  /* Disable transmit packets to aggregation queue */
	  txq->disabled = 1;

	  /* Flush Tx queue */
	  do
	    {
	      if (delay >= MVPP2_TX_PENDING_TIMEOUT_USEC)
		{
		  log_warn (dev, "Port%u: TXQ=%u clean timed out\n", mp->id, q->queue_id);
		  break;
		}
	      /* Sleep for 1 microsecond */
	      usleep (1);
	      delay++;
	      pending = mvpp2_txq_pend_desc_num_get (q);
	      log_debug (dev, "port %u txq %u has %d pending descriptors\n", mp->id, q->queue_id,
			 pending);
	    }
	  while (pending);

	  /* Disable Tx queue */
	  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
	  mvpp2_reg_write (hif_base, MVPP2_TXP_SCHED_Q_CMD_REG,
			   mask << MVPP2_TXP_SCHED_DISQ_OFFSET);
	}
    }

  return VNET_DEV_OK;
}

void
mvpp2_txq_init (vnet_dev_tx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  void *desc_mem;
  uintptr_t hif_base;
  u32 j, val, desc_per_txq, pref_buf_size, desc;

  hif_base = mp->hif_base;
  txq->hif_base = hif_base;

  desc_per_txq = PP2_ETH_PORT_TXQ_PREFETCH;

  /* FS_A8K Table 1542: The SWF ring size + a prefetch size for HWF */
  txq->desc_total = q->size;
  if (vnet_dev_dma_mem_alloc (vlib_get_main (), dev, txq->desc_total * MVPP2_DESC_ALIGNED_SIZE,
			      MVPP2_DESC_Q_ALIGN, &desc_mem) != VNET_DEV_OK)
    desc_mem = 0;

  if (PREDICT_FALSE (!desc_mem))
    {
      log_err (dev, "PP: cannot allocate egress descriptor array\n");
      return;
    }
  txq->desc_virt_arr = desc_mem;
  txq->desc_phys_arr = vnet_dev_get_dma_addr (vlib_get_main (), dev, txq->desc_virt_arr);
  if (txq->desc_phys_arr & (MVPP2_DESC_Q_ALIGN - 1))
    {
      log_err (dev, "PP: egress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vlib_get_main (), dev, txq->desc_virt_arr);
      return;
    }

  log_debug (dev, "port[%d:%d] tx desc_phys_addr(0x%lx)\n", md->pp_id, mp->id, txq->desc_phys_arr);

  /* Set Tx descriptors queue starting address - indirect access */
  mvpp2_reg_write (hif_base, MVPP2_TXQ_NUM_REG, txq->hw_id);
  mvpp2_reg_write (hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		   ((uint32_t) txq->desc_phys_arr) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  mvpp2_reg_write (hif_base, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		   (txq->desc_phys_arr >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  mvpp2_reg_write (hif_base, MVPP2_TXQ_DESC_SIZE_REG, txq->desc_total & MVPP2_TXQ_DESC_SIZE_MASK);
  mvpp2_reg_write (hif_base, MVPP2_TXQ_INDEX_REG, 0x0);
  mvpp2_reg_write (hif_base, MVPP2_TXQ_RSVD_CLR_REG, txq->hw_id << MVPP2_TXQ_RSVD_CLR_OFFSET);
  val = mvpp2_tx_queue_reg_read (hif_base, MVPP2_TXQ_PENDING_REG);
  val &= ~MVPP2_TXQ_PENDING_MASK;
  mvpp2_reg_write (hif_base, MVPP2_TXQ_PENDING_REG, val);

  /* Calculate base address in prefetch buffer. We reserve 16 descriptors
   * for each existing TXQ.
   * - TCONTS for PON port must be continuous from 0 to MVPP2_MAX_TCONT
   * - GBE ports assumed to be continious from 0 to MVPP2_MAX_PORTS
   */
  if (desc_per_txq == PP2_TXQ_PREFETCH_64)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_64;
  else if (desc_per_txq == PP2_TXQ_PREFETCH_32)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_32;
  else if (desc_per_txq == PP2_TXQ_PREFETCH_16)
    pref_buf_size = MVPP2_PREF_BUF_SIZE_16;
  else
    pref_buf_size = MVPP2_PREF_BUF_SIZE_4;

  /* Since the loopback port is the last port, below calc. is always correct */
  desc = (mp->id * MVPP2_MAX_TXQ * PP2_ETH_PORT_TXQ_PREFETCH) + (q->queue_id * desc_per_txq);

  /* Set desc prefetch threshold to 8 units of 2 descriptors */
  mvpp2_reg_write (hif_base, MVPP2_TXQ_PREF_BUF_REG,
		   MVPP2_PREF_BUF_PTR (desc) | pref_buf_size |
		     MVPP2_PREF_BUF_THRESH (PP2_TXQ_PREFETCH_16 / 2));

  /* Lastly, clear all ETH_TXQS for all future DM-IFs */
  for (j = 0; j < MVPP2_NUM_HIFS; j++)
    {
      hif_base = mvpp2_hif_base (md, j);
      mvpp2_tx_queue_reg_read (hif_base, MVPP22_TXQ_SENT_REG (txq->hw_id));
    }
}

static void
mvpp2_txq_deinit (vnet_dev_tx_queue_t *q)
{
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

  /* Set minimum bandwidth for disabled TXQs */
  mvpp2_reg_write (txq->hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (txq->hw_id), 0);

  /* Set Tx descriptors queue starting address and size */
  mvpp2_reg_write (txq->hif_base, MVPP2_TXQ_NUM_REG, txq->hw_id);
  mvpp2_reg_write (txq->hif_base, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  mvpp2_reg_write (txq->hif_base, MVPP2_TXQ_DESC_SIZE_REG, 0);
}

void
mvpp2_port_txq_deinit (vnet_dev_tx_queue_t *q)
{
  mvpp2_device_t *md = vnet_dev_get_data (q->port->dev);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  u32 j;

  mvpp2_port_set_txq_state (q, 0);
  mvpp2_txq_deinit (q);

  for (j = 0; j < MVPP2_NUM_HIFS; j++)
    mvpp2_tx_queue_reg_read (mvpp2_hif_base (md, j), MVPP22_TXQ_SENT_REG (txq->hw_id));
}
