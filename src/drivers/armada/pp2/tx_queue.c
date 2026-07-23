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
  .subclass_name = "tx-queue",
};

vnet_dev_rv_t
mvpp2_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  log_debug (txq->port->dev, "");

  ASSERT (mtq->buffers == 0);
  if (mtq->buffers == 0)
    {
      u32 sz = txq->size;

      ASSERT (sz && (sz & (sz - 1)) == 0);
      sz *= sizeof (u32);
      mtq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      clib_memset (mtq->buffers, 0, sz);
    }

  return rv;
}

void
mvpp2_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);

  log_debug (txq->port->dev, "");
  if (mtq->buffers)
    {
      clib_mem_free (mtq->buffers);
      mtq->buffers = 0;
    }
}

static u32
mvpp2_txq_pend_desc_num_get (vnet_dev_tx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  u32 val;

  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_NUM_REG, txq->hw_id);
  val = mvpp2_dev_reg_rd (dev, MVPP2_TXQ_PENDING_REG);

  return val & MVPP2_TXQ_PENDING_MASK;
}

vnet_dev_rv_t
mvpp2_port_set_txq_state (vnet_dev_tx_queue_t *q, int en)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  mvpp22_txp_sched_q_cmd_reg_t command;
  u32 mask;

  /* TODO: add lock to protect MVPP2_TXP_SCHED_PORT_INDEX_REG */
  /* Get active channels mask */
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  command.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_Q_CMD_REG);
  mask = 1 << q->queue_id;

  if (en)
    {
      if (!(command.enable & mask))
	{
	  /* Enable Tx queue */
	  command = (mvpp22_txp_sched_q_cmd_reg_t) {
	    .enable = mask,
	  };
	  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
	  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
	}
    }
  else
    {
      if (command.enable & mask)
	{
	  u32 delay = 0;
	  u32 pending;

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
	  command = (mvpp22_txp_sched_q_cmd_reg_t) {
	    .disable = mask,
	  };
	  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
	  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
	}
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_txq_init (vlib_main_t *vm, vnet_dev_tx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  mvpp22_txq_pref_buf_reg_t prefetch = {
    .threshold = PP2_ETH_PORT_TXQ_PREFETCH / 2,
    .size = 5,
  };
  vnet_dev_rv_t rv;
  void *desc_mem;
  u32 j, val, desc;

  /* FS_A8K Table 1542: The SWF ring size + a prefetch size for HWF */
  txq->desc_total = q->size;
  rv =
    vnet_dev_dma_mem_alloc (vm, dev, txq->desc_total * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
			    &desc_mem, "TX queue %u descriptors", q->queue_id);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "PP: cannot allocate egress descriptor array\n");
      return rv;
    }
  txq->desc_virt_arr = desc_mem;
  txq->desc_phys_arr = vnet_dev_get_dma_addr (vm, dev, txq->desc_virt_arr);

  log_debug (dev, "port[%d:%d] tx desc_phys_addr(0x%lx)\n", md->pp_id, mp->id, txq->desc_phys_arr);

  /* Set Tx descriptors queue starting address - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_NUM_REG, txq->hw_id);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_ADDR_LOW_REG,
		    ((uint32_t) txq->desc_phys_arr) >> MVPP2_TXQ_DESC_ADDR_LOW_SHIFT);
  mvpp2_dev_reg_wr (dev, MVPP22_TXQ_DESC_ADDR_HIGH_REG,
		    (txq->desc_phys_arr >> 32) & MVPP22_TXQ_DESC_ADDR_HIGH_MASK);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_SIZE_REG, txq->desc_total & MVPP2_TXQ_DESC_SIZE_MASK);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_INDEX_REG, 0x0);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_RSVD_CLR_REG, txq->hw_id << MVPP2_TXQ_RSVD_CLR_OFFSET);
  val = mvpp2_dev_reg_rd (dev, MVPP2_TXQ_PENDING_REG);
  val &= ~MVPP2_TXQ_PENDING_MASK;
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_PENDING_REG, val);

  /* Calculate base address in prefetch buffer. We reserve 16 descriptors
   * for each existing TXQ.
   * - TCONTS for PON port must be continuous from 0 to MVPP2_MAX_TCONT
   * - GBE ports assumed to be continious from 0 to MVPP2_MAX_PORTS
   */
  /* Since the loopback port is the last port, below calc. is always correct */
  desc = (mp->id * MVPP2_MAX_TXQ + q->queue_id) * PP2_ETH_PORT_TXQ_PREFETCH;

  /* Set desc prefetch threshold to 8 units of 2 descriptors */
  prefetch.ptr = desc;
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_PREF_BUF_REG, prefetch.as_u32);

  /* Lastly, clear the TXQ for every active HIF. */
  for (j = 0; j < ARRAY_LEN (md->threads); j++)
    if (md->threads[j].hif.descs)
      mvpp2_hif_reg_rd (&md->threads[j].hif, MVPP22_TXQ_SENT_REG (txq->hw_id));
  return VNET_DEV_OK;
}

static void
mvpp2_txq_deinit (vnet_dev_tx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

  /* Set minimum bandwidth for disabled TXQs */
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (txq->hw_id), 0);

  /* Set Tx descriptors queue starting address and size */
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_NUM_REG, txq->hw_id);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_ADDR_LOW_REG, 0);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_DESC_SIZE_REG, 0);
}

void
mvpp2_port_txq_deinit (vnet_dev_tx_queue_t *q)
{
  mvpp2_device_t *md = vnet_dev_get_data (q->port->dev);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  u32 j;

  mvpp2_port_set_txq_state (q, 0);
  mvpp2_txq_deinit (q);

  for (j = 0; j < ARRAY_LEN (md->threads); j++)
    if (md->threads[j].hif.descs)
      mvpp2_hif_reg_rd (&md->threads[j].hif, MVPP22_TXQ_SENT_REG (txq->hw_id));
}
