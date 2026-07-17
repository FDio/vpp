/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "rx-queue",
};

static void
mvpp2_rxq_offset_set (vnet_dev_rx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  mvpp22_rxq_config_reg_t config;
  int offset = MVPP2_RX_PACKET_OFFSET_BYTES;

  /* Convert offset from bytes to units of 32 bytes */
  offset = offset >> 5;

  config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));

  /* Set packet offset and enable buffer-header snooping. */
  config.packet_offset = offset;
  config.snoop_pkt_size = MVPP2_SNOOP_PKT_SIZE_MAX;
  config.snoop_buf_hdr = 1;

  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), config.as_u32);
}

static void
mvpp2_rxq_resid_pkts (vnet_dev_rx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  mvpp22_rxq_status_reg_t status;
  u32 rx_resid;

  status.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_STATUS_REG (rxq->hw_id));
  rx_resid = status.occupied;
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

vnet_dev_rv_t
mvpp2_rxq_init (vlib_main_t *vm, vnet_dev_rx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  mvpp22_rxq_status_reg_t status = {};
  vnet_dev_rv_t rv;
  uintptr_t desc_phys;
  void *desc_mem;

  rv = vnet_dev_dma_mem_alloc (vm, dev, q->size * MVPP2_DESC_ALIGNED_SIZE, MVPP2_DESC_Q_ALIGN,
			       &desc_mem, "RX queue %u descriptors", q->queue_id);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "PP: cannot allocate ingress descriptor array\n");
      return rv;
    }
  rxq->hw_descs = desc_mem;
  desc_phys = vnet_dev_get_dma_addr (vm, dev, rxq->hw_descs);
  if (desc_phys & (MVPP2_DESC_Q_ALIGN - 1))
    {
      log_err (dev, "PP: ingress descriptor array must be %u-byte aligned\n", MVPP2_DESC_Q_ALIGN);
      vnet_dev_dma_mem_free (vm, dev, rxq->hw_descs);
      rxq->hw_descs = 0;
      return VNET_DEV_ERR_BUG;
    }
  log_debug (dev, "port[%d:%d] rxq[%d], desc_phys_addr(0x%lx)\n", md->pp_id, mp->id, rxq->hw_id,
	     desc_phys);

  /* Zero occupied and non-occupied counters - direct access */
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_STATUS_REG (rxq->hw_id), 0x0);

  /* Set Rx descriptors queue starting address - indirect access */
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_NUM_REG, rxq->hw_id);

  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_DESC_ADDR_REG, (desc_phys >> MVPP22_DESC_ADDR_SHIFT));
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_DESC_SIZE_REG, q->size);
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_INDEX_REG, 0x0);

  /* Set Offset */
  mvpp2_rxq_offset_set (q);

  mvpp2_bpool_assign (port, mp->bpool.id, rxq->hw_id);
  log_debug (dev, "port[%d:%d] rxq[%d], short_pool(%d), long_pool(%d)\n", md->pp_id, mp->id,
	     rxq->hw_id, mp->bpool.id, mp->bpool.id);

  /* Add number of descriptors ready for receiving packets */
  status.available = q->size;
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->hw_id), status.as_u32);
  return VNET_DEV_OK;
}

void
mvpp2_rxq_deinit (vnet_dev_rx_queue_t *q)
{
  vnet_dev_t *dev = q->port->dev;
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

  mvpp2_rxq_resid_pkts (q);

  /* Clear Rx descriptors queue starting address and size;
   * free descriptor number
   */
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_STATUS_REG (rxq->hw_id), 0);
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_NUM_REG, rxq->hw_id);
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_DESC_ADDR_REG, 0);
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_DESC_SIZE_REG, 0);
}
