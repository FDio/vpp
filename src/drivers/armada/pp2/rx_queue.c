/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <endian.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "rx-queue",
};

static_always_inline u32
mvpp2_rx_queue_reg_read (uintptr_t base, u32 offset)
{
  volatile u32 *addr = (void *) (base + offset);
  u32 value;

  value = le32toh (__atomic_load_n (addr, __ATOMIC_RELAXED));
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static mvpp2_tc_t *
mvpp2_rxq_tc_get (vnet_dev_rx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  u8 i;

  for (i = 0; i < mp->num_tcs; i++)
    {
      u8 first_rxq = mp->tc.tc_config.first_rxq;

      if (rxq->hw_id >= first_rxq && rxq->hw_id < (first_rxq + mp->tc.tc_config.num_in_qs))
	return &mp->tc;
    }
  return NULL;
}

static void
mvpp2_rxq_offset_set (vnet_dev_rx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  int offset = mp->tc.tc_config.pkt_offset;
  u32 val;

  /* Convert offset from bytes to units of 32 bytes */
  offset = offset >> 5;

  val = mvpp2_rx_queue_reg_read (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
  val &= ~MVPP2_RXQ_PACKET_OFFSET_MASK;

  /* Offset is in */
  val |= ((offset << MVPP2_RXQ_PACKET_OFFSET_OFFS) & MVPP2_RXQ_PACKET_OFFSET_MASK);

  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), val);
}

static void
mvpp2_rxq_resid_pkts (vnet_dev_rx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  u32 val;
  u32 rx_resid;

  val = mvpp2_rx_queue_reg_read (mp->hif_base, MVPP2_RXQ_STATUS_REG (rxq->hw_id));
  rx_resid = val & MVPP2_RXQ_OCCUPIED_MASK;
  if (!rx_resid)
    return;

  log_warn (dev, "RXQ has %u residual packets\n", rx_resid);

  /* Cleanup for dangling RXDs can be done here by getting
   * the BM-IF associated to the BM poool associated to this
   * RXQ, but it would not be correct.
   *
   * No indirect access to BM pools assigned to this RXQ.
   * Client should handle cleanup before/after destroying the
   * interface
   */
}

void
mvpp2_rxqs_create (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 qid, tc, id = 0;

  for (tc = 0; tc < mp->num_tcs; tc++)
    {
      struct mvpp2_tc_config *tc_cfg = &mp->tc.tc_config;

      for (qid = 0; qid < mp->tc.tc_config.num_in_qs; qid++)
	{
	  vnet_dev_rx_queue_t *q = vnet_dev_get_port_rx_queue_by_id (port, id);
	  mvpp2_rxq_t *rxq;

	  ASSERT (q);
	  rxq = vnet_dev_get_rx_queue_data (q);
	  rxq->hw_id = tc_cfg->first_rxq + qid;
	  rxq->desc_total = q->size;
	  rxq->desc_received = 0;
	  rxq->desc_next_idx = 0;
	  rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_SHORT] =
	    tc_cfg->pools[0][MVPP2_BM_POOL_TYPE_SHORT]->id;
	  rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_LONG] = tc_cfg->pools[0][MVPP2_BM_POOL_TYPE_LONG]->id;

	  log_debug (port->dev, "port[%d:%d] tc%d rxq%d", md->pp_id, mp->id, tc, rxq->hw_id);
	  id++;
	}
    }
}

void
mvpp2_rxq_init (vnet_dev_rx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  mvpp2_tc_t *tc;
  void *desc_mem;
  u32 val;

  if (vnet_dev_dma_mem_alloc (vlib_get_main (), dev, rxq->desc_total * MVPP2_DESC_ALIGNED_SIZE,
			      MVPP2_DESC_Q_ALIGN, &desc_mem) != VNET_DEV_OK)
    {
      log_err (dev, "PP: cannot allocate ingress descriptor array\n");
      return;
    }
  rxq->hw_descs = desc_mem;
  rxq->desc_phys_arr = vnet_dev_get_dma_addr (vlib_get_main (), dev, rxq->hw_descs);
  if (rxq->desc_phys_arr & (MVPP2_DESC_Q_ALIGN - 1))
    {
      log_err (dev, "PP: ingress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vlib_get_main (), dev, rxq->hw_descs);
      return;
    }
  log_debug (dev, "port[%d:%d] rxq[%d], desc_phys_addr(0x%lx)\n", md->pp_id, mp->id, rxq->hw_id,
	     rxq->desc_phys_arr);

  /* Zero occupied and non-occupied counters - direct access */
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_STATUS_REG (rxq->hw_id), 0x0);

  /* Set Rx descriptors queue starting address - indirect access */
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_NUM_REG, rxq->hw_id);

  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_DESC_ADDR_REG,
		   (rxq->desc_phys_arr >> MVPP22_DESC_ADDR_SHIFT));
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_DESC_SIZE_REG, rxq->desc_total);
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_INDEX_REG, 0x0);

  tc = mvpp2_rxq_tc_get (q);
  if (!tc)
    {
      log_err (dev, "port(%d) phy_rxq(%d), not found in tc range\n", mp->id, rxq->hw_id);
      return;
    }
  /* Set Offset */
  mvpp2_rxq_offset_set (q);

  mvpp2_bm_pool_assign (port, rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_SHORT], rxq->hw_id,
			MVPP2_BM_POOL_TYPE_SHORT);
  mvpp2_bm_pool_assign (port, rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_LONG], rxq->hw_id,
			MVPP2_BM_POOL_TYPE_LONG);
  log_debug (dev, "port[%d:%d] rxq[%d], short_pool(%d), long_pool(%d)\n", md->pp_id, mp->id,
	     rxq->hw_id, rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_SHORT],
	     rxq->bm_pool_id[MVPP2_BM_POOL_TYPE_LONG]);

  /* Add number of descriptors ready for receiving packets */
  val = rxq->desc_total << MVPP2_RXQ_NUM_NEW_OFFSET;
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->hw_id), val);
}

void
mvpp2_rxq_deinit (vnet_dev_rx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

  mvpp2_rxq_resid_pkts (q);

  /* Clear Rx descriptors queue starting address and size;
   * free descriptor number
   */
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_STATUS_REG (rxq->hw_id), 0);
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_NUM_REG, rxq->hw_id);
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_DESC_ADDR_REG, 0);
  mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_DESC_SIZE_REG, 0);
}
