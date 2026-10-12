/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/bitmap.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "edma",
};

vnet_dev_rv_t
qppe_edma_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_edma_port_control_t port_control;
  u32 version;

  version = qppe_edma_reg_rd (qd, EDMA_REG_MAS_CTRL_ADDR);
  log_debug (dev, "read EDMA version at offset 0x%x: %u (0x%08x)",
	     EDMA_BASE_OFFSET + EDMA_REG_MAS_CTRL_ADDR, version, version);
  if (version == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA version returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  port_control.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_PORT_CTRL_ADDR);
  log_debug (dev, "read EDMA port control at offset 0x%x: 0x%08x, EDMA %s, TX padding %s",
	     EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR, port_control.as_u32,
	     port_control.edma_enable ? "enabled" : "disabled",
	     port_control.tx_padding_enable ? "enabled" : "disabled");
  if (port_control.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA port control returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }
  qd->edma_enabled = port_control.edma_enable;

  /* Unused queue mappings point to ring 0; CPU mappings are installed later. */
  for (u32 q = 0; q < EDMA_QUEUE_MAP_COUNT; q += 4)
    {
      u32 reg = EDMA_REG_QID2RID_TABLE (q);

      qppe_edma_reg_wr (qd, reg, 0);
      if (qppe_edma_reg_rd (qd, reg) != 0)
	{
	  log_err (dev, "EDMA queue-to-ring map clear failed at offset 0x%x",
		   EDMA_BASE_OFFSET + reg);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  return VNET_DEV_OK;
}

void
qppe_edma_rx_ring_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  ASSERT (!qr->started);
  if (qr->descs)
    vnet_dev_dma_mem_free (vm, dev, qr->descs);
  if (qr->preheader_descs)
    vnet_dev_dma_mem_free (vm, dev, qr->preheader_descs);
  qr->descs = 0;
  qr->preheader_descs = 0;
  if (qr->fill_ring_index < ARRAY_LEN (qd->rxfill_rings))
    {
      qppe_edma_rxfill_free (vm, dev, qd->rxfill_rings + qr->fill_ring_index);
      qr->fill_ring_index = EDMA_RXFILL_RING_COUNT;
    }
}

static u8
qppe_edma_rx_queues_started (vnet_dev_t *dev)
{
  foreach_vnet_dev_port (port, dev)
    foreach_vnet_dev_port_rx_queue (rxq, port)
      {
	qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

	if (qr->started)
	  return 1;
      }

  return 0;
}

static u8
qppe_edma_tx_queues_started (vnet_dev_t *dev)
{
  foreach_vnet_dev_port (port, dev)
    foreach_vnet_dev_port_tx_queue (txq, port)
      {
	qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

	if (tq->started)
	  return 1;
      }

  return 0;
}

static vnet_dev_rv_t
qppe_edma_rx_queue_mapping_configure (vnet_dev_rx_queue_t *rxq, u8 first_queue)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
  vnet_dev_rx_queue_t *queues[EDMA_RX_QUEUES_PER_PORT] = {};
  u32 profile = qp->source_profile;
  u32 queue_base = profile * EDMA_RX_QUEUES_PER_RING;
  u32 mcast_base = QPPE_CPU_MCAST_QUEUE_START + profile * QPPE_CPU_MCAST_QUEUES_PER_PROFILE;
  u32 n_queues = 0;
  u32 offset, value;

  ASSERT (profile < QPPE_RX_PROFILE_COUNT);
  foreach_vnet_dev_port_rx_queue (q, rxq->port)
    if (q->enabled)
      {
	ASSERT (n_queues < ARRAY_LEN (queues));
	queues[n_queues++] = q;
      }
  ASSERT (n_queues);

  if (first_queue)
    {
      ppe_reg_port_bridge_ctrl_t bridge_ctrl = {
	.port_isolation_bitmap = ((1u << QPPE_MAX_PORTS) - 1) & ~(1u << EDMA_CPU_PORT_ID),
	.txmac_en = 1,
      };

      offset = HPPE_REG_PORT_BRIDGE_CTRL (EDMA_CPU_PORT_ID);
      qppe_mmio_write32 (qd, offset, bridge_ctrl.as_u32);
      if (qppe_mmio_read32 (qd, offset) != bridge_ctrl.as_u32)
	{
	  log_err (
	    dev,
	    "CPU bridge control readback mismatch at offset 0x%x: expected 0x%08x, read 0x%08x",
	    offset, bridge_ctrl.as_u32, qppe_mmio_read32 (qd, offset));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  /* Multicast stays on the port's first enabled queue. */
  for (u32 i = 0; i < n_queues; i++)
    {
      qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (queues[i]);
      u32 ring_id = qr->desc_ring_id;
      u32 bitmap[EDMA_RING_Q_MAP_WORDS] = {};
      u32 queue_id = queue_base + queues[i]->queue_id;
      u32 shift = (queue_id % 4) * 8;
      u32 reg = EDMA_REG_QID2RID_TABLE (queue_id);

      bitmap[queue_id / 32] |= 1u << (queue_id % 32);
      value = qppe_edma_reg_rd (qd, reg);
      value = (value & ~(0xffu << shift)) | (ring_id << shift);
      qppe_edma_reg_wr (qd, reg, value);
      if (qppe_edma_reg_rd (qd, reg) != value)
	{
	  log_err (dev,
		   "queue %u to ring %u mapping readback mismatch at offset 0x%x: expected 0x%08x, "
		   "read 0x%08x",
		   queue_id, ring_id, EDMA_BASE_OFFSET + reg, value, qppe_edma_reg_rd (qd, reg));
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      if (i == 0)
	for (u32 j = 0; j < QPPE_CPU_MCAST_QUEUES_PER_PROFILE; j++)
	  {
	    u32 mcast_id = mcast_base + j;
	    u32 mcast_shift = (mcast_id % 4) * 8;
	    u32 mcast_reg = EDMA_REG_QID2RID_TABLE (mcast_id);

	    bitmap[mcast_id / 32] |= 1u << (mcast_id % 32);
	    value = qppe_edma_reg_rd (qd, mcast_reg);
	    value = (value & ~(0xffu << mcast_shift)) | (ring_id << mcast_shift);
	    qppe_edma_reg_wr (qd, mcast_reg, value);
	    if (qppe_edma_reg_rd (qd, mcast_reg) != value)
	      {
		log_err (dev,
			 "multicast queue %u to ring %u mapping readback mismatch at offset 0x%x: "
			 "expected 0x%08x, read 0x%08x",
			 mcast_id, ring_id, EDMA_BASE_OFFSET + mcast_reg, value,
			 qppe_edma_reg_rd (qd, mcast_reg));
		return VNET_DEV_ERR_INIT_FAILED;
	      }
	  }
      for (u32 j = 0; j < ARRAY_LEN (bitmap); j++)
	{
	  offset = HPPE_REG_RING_Q_MAP_TBL (qr->desc_ring_id) + j * sizeof (u32);
	  qppe_mmio_write32 (qd, offset, bitmap[j]);
	}
      for (u32 j = 0; j < ARRAY_LEN (bitmap); j++)
	{
	  offset = HPPE_REG_RING_Q_MAP_TBL (qr->desc_ring_id) + j * sizeof (u32);
	  if (qppe_mmio_read32 (qd, offset) != bitmap[j])
	    {
	      log_err (dev,
		       "ring %u queue bitmap readback mismatch at offset 0x%x: expected 0x%08x, "
		       "read 0x%08x",
		       ring_id, offset, bitmap[j], qppe_mmio_read32 (qd, offset));
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}
    }

  if (qppe_qm_port_queue_map_configure (rxq->port, &rxq->port->rss_config) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

  return qppe_vsi_port_configure (rxq);
}

vnet_dev_rv_t
qppe_edma_rx_ring_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv = qppe_edma_rxfill_alloc (vm, rxq);

  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, rxq->size * sizeof (*qr->descs),
					CLIB_CACHE_LINE_BYTES, (void **) &qr->descs,
					"EDMA RX descriptors");
  if (rv != VNET_DEV_OK)
    goto error;
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, rxq->size * sizeof (*qr->preheader_descs),
					CLIB_CACHE_LINE_BYTES, (void **) &qr->preheader_descs,
					"EDMA RX secondary descriptors");
  if (rv != VNET_DEV_OK)
    goto error;

  return VNET_DEV_OK;

error:
  qppe_edma_rx_ring_free (vm, rxq);
  return rv;
}

vnet_dev_rv_t
qppe_edma_rx_ring_configure (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_rxfill_ring_t *rfr = qd->rxfill_rings + qr->fill_ring_index;
  uword rx_dma = vnet_dev_get_dma_addr (vm, dev, qr->descs);
  uword secondary_dma = vnet_dev_get_dma_addr (vm, dev, qr->preheader_descs);
  ppe_reg_edma_rxdesc_ring_size_t rxdesc_size = {
    .ring_size = rxq->size,
  };
  const qppe_reg_val_t regs[] = {
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_BA (qr->desc_ring_id),
      .val = rx_dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_PREHEADER_BA (qr->desc_ring_id),
      .val = secondary_dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_RING_SIZE (qr->desc_ring_id),
      .val = rxdesc_size.as_u32,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RX_MOD_TIMER (qr->desc_ring_id),
      .val = EDMA_RX_MOD_TIMER_VALUE,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_UGT_THRE (qr->desc_ring_id),
      .val = EDMA_RX_MITIGATION_PKT_CNT,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RX_INT_CTRL (qr->desc_ring_id),
      .val = EDMA_RX_NE_INT_EN,
    },
  };

  if (qd->edma_enabled)
    return VNET_DEV_ERR_PORT_STARTED;
  if (rx_dma > 0xffffffff || secondary_dma > 0xffffffff)
    return VNET_DEV_ERR_INIT_FAILED;

  if (qppe_edma_rxfill_configure (vm, dev, rfr) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

  return qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
}

static vnet_dev_rv_t
qppe_edma_enable (vnet_dev_t *dev, ppe_reg_edma_port_control_t port_control)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 offset = EDMA_REG_PORT_CTRL_ADDR;

  if (port_control.edma_enable)
    return VNET_DEV_OK;

  port_control.edma_enable = 1;
  qppe_edma_reg_wr (qd, offset, port_control.as_u32);
  if (!((ppe_reg_edma_port_control_t) { .as_u32 = qppe_edma_reg_rd (qd, offset) }).edma_enable)
    {
      log_err (dev, "EDMA did not enable at offset 0x%x", offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  qd->edma_enabled = 1;
  log_debug (dev, "enabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_rxfill_ring_t *rfr = qd->rxfill_rings + qr->fill_ring_index;
  ppe_reg_edma_port_control_t port_control;
  ppe_reg_edma_rxdesc_control_t control;
  qppe_bm_port_config_t bm = {
    .ceil = HPPE_BM_PHYS_PORT_CEIL,
    .weight = HPPE_BM_PHYS_PORT_WEIGHT,
    .resume_offset = HPPE_BM_PHYS_PORT_RESUME_OFFSET,
    .dynamic = 1,
    .react_limit = HPPE_BM_PHYS_PORT_REACT_LIMIT,
    .enable = 1,
  };
  vnet_dev_rv_t rv;
  u32 offset, value, shift;
  u8 first_queue = !qppe_edma_rx_queues_started (dev);

  if (qr->started)
    return VNET_DEV_OK;
  ASSERT (rfr && rfr->n_rx_queues);
  ASSERT (rfr == &qd->rxfill_rings[rxq->rx_thread_index]);
  if (rfr->buffer_pool_index != vnet_dev_get_rx_queue_buffer_pool_index (rxq))
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if (qr->descs == 0 || qr->preheader_descs == 0)
    return VNET_DEV_ERR_INIT_FAILED;

  qr->desc_cons = qppe_mmio_read32 (qd, qr->rxdesc_prod_mmio_off) & (rxq->size - 1);
  rv = qppe_edma_rxfill_start (vm, dev, rfr);
  if (rv != VNET_DEV_OK)
    return rv;
  qr->started = 1;

  rv = qppe_edma_rx_queue_mapping_configure (rxq, first_queue);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_bm_port_configure (dev, HPPE_BM_PORT_ID_PHYS_BASE + rxq->port->port_id, &bm);
  if (rv != VNET_DEV_OK)
    goto error;

  offset = EDMA_REG_RXDESC2FILL_MAP_0 + (qr->desc_ring_id / 10) * sizeof (u32);
  shift = (qr->desc_ring_id % 10) * 3;
  value = qppe_edma_reg_rd (qd, offset);
  value = (value & ~(7u << shift)) | (rfr->ring_id << shift);
  qppe_edma_reg_wr (qd, offset, value);
  if (qppe_edma_reg_rd (qd, offset) != value)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto error;
    }

  qr->desc_cons = qppe_mmio_read32 (qd, qr->rxdesc_prod_mmio_off) & (rxq->size - 1);
  qppe_mmio_write32 (qd, qr->rxdesc_cons_mmio_off, qr->desc_cons);

  control.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_CTRL (qr->desc_ring_id));
  control.rx_enable = 1;
  qppe_edma_reg_wr (qd, EDMA_REG_RXDESC_CTRL (qr->desc_ring_id), control.as_u32);
  if (!((ppe_reg_edma_rxdesc_control_t) {
	  .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_CTRL (qr->desc_ring_id)),
	})
	 .rx_enable)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto error;
    }

  port_control.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_PORT_CTRL_ADDR);
  rv = qppe_edma_enable (dev, port_control);
  if (rv != VNET_DEV_OK)
    goto error;

  return VNET_DEV_OK;

error:
  qppe_edma_rx_ring_stop (rxq);
  return rv;
}

static void
qppe_edma_disable_if_idle (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_edma_port_control_t port_control;
  u32 offset;

  if (qd->edma_enabled && !qppe_edma_rx_queues_started (dev) && !qppe_edma_tx_queues_started (dev))
    {
      offset = EDMA_REG_PORT_CTRL_ADDR;
      port_control.as_u32 = qppe_edma_reg_rd (qd, offset);
      port_control.edma_enable = 0;
      qppe_edma_reg_wr (qd, offset, port_control.as_u32);
      qd->edma_enabled = 0;
      log_debug (dev, "disabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }
}

void
qppe_edma_rx_ring_stop (vnet_dev_rx_queue_t *rxq)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_rxfill_ring_t *rfr = qd->rxfill_rings + qr->fill_ring_index;
  ppe_reg_edma_rxdesc_control_t control;
  qppe_bm_port_config_t bm = {};
  u32 offset, prod, cons, mask = rxq->size - 1;

  if (!qr->started)
    return;
  offset = EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  control.as_u32 = qppe_edma_reg_rd (qd, offset);
  control.rx_enable = 0;
  qppe_edma_reg_wr (qd, offset, control.as_u32);
  qppe_edma_reg_rd (qd, offset);

  /* Return buffers still waiting in this descriptor ring. */
  prod = qppe_mmio_read32 (qd, qr->rxdesc_prod_mmio_off) & mask;
  cons = qr->desc_cons & mask;
  while (cons != prod)
    {
      edma_rx_desc_t desc = qr->descs[cons];
      u32 bi = desc.opaque_low;

      vlib_buffer_free (vm, &bi, 1);
      rfr->n_refill++;
      cons = (cons + 1) & mask;
    }
  qr->desc_cons = cons;
  qppe_mmio_write32 (qd, qr->rxdesc_cons_mmio_off, cons);
  qr->started = 0;
  qppe_edma_rxfill_stop (vm, dev, rfr);

  for (u32 i = 0; i < EDMA_RING_Q_MAP_WORDS; i++)
    qppe_mmio_write32 (qd, HPPE_REG_RING_Q_MAP_TBL (qr->desc_ring_id) + i * sizeof (u32), 0);
  qppe_edma_disable_if_idle (dev);

  foreach_vnet_dev_port_rx_queue (q, rxq->port)
    {
      qppe_rxq_t *other = vnet_dev_get_rx_queue_data (q);

      if (other->started)
	return;
    }
  qppe_bm_port_configure (dev, HPPE_BM_PORT_ID_PHYS_BASE + rxq->port->port_id, &bm);
}

void
qppe_edma_tx_ring_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  if (tq->descs)
    vnet_dev_dma_mem_free (vm, dev, tq->descs);
  if (tq->sec_descs)
    vnet_dev_dma_mem_free (vm, dev, tq->sec_descs);
  if (tq->cmpl_descs)
    vnet_dev_dma_mem_free (vm, dev, tq->cmpl_descs);
  tq->descs = 0;
  tq->sec_descs = 0;
  tq->cmpl_descs = 0;
}

vnet_dev_rv_t
qppe_edma_tx_ring_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;
  u32 desc_size;

  desc_size = txq->size * sizeof (edma_tx_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &tq->descs, "EDMA TX descriptors");
  if (rv != VNET_DEV_OK)
    return rv;

  desc_size = txq->size * sizeof (edma_tx_sec_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &tq->sec_descs, "EDMA TX secondary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_free (vm, txq);
      return rv;
    }

  desc_size = txq->size * sizeof (edma_txcmpl_desc_t);
  rv =
    vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
				     (void **) &tq->cmpl_descs, "EDMA TX completion descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_free (vm, txq);
      return rv;
    }

  log_debug (dev,
	     "allocated TX ring storage: %u descriptors, TX VA %p, secondary VA %p, "
	     "completion VA %p; hardware remains disabled and unconfigured",
	     txq->size, tq->descs, tq->sec_descs, tq->cmpl_descs);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_tx_ring_configure (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  uword desc_dma = vnet_dev_get_dma_addr (vm, dev, tq->descs);
  uword sec_dma = vnet_dev_get_dma_addr (vm, dev, tq->sec_descs);
  uword cmpl_dma = vnet_dev_get_dma_addr (vm, dev, tq->cmpl_descs);
  const qppe_reg_val_t regs[] = {
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_BA (tq->desc_ring_id),
      .val = desc_dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_BA2 (tq->desc_ring_id),
      .val = sec_dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_RING_SIZE (tq->desc_ring_id),
      .val = txq->size,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_BA (tq->cmpl_ring_id),
      .val = cmpl_dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_RING_SIZE (tq->cmpl_ring_id),
      .val = txq->size,
    },
  };
  vnet_dev_rv_t rv;
  u32 offset;

  tq->desc_template = (edma_tx_desc_t) {
    .service_code = EDMA_SC_BYPASS_ID,
    .int_pri_valid = 1,
    .destination_type = EDMA_TX_DST_PORT_TYPE,
    .destination_port_id = txq->port->port_id,
  };

  if (qd->edma_enabled)
    {
      log_err (dev, "cannot configure TX rings while EDMA is enabled");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (desc_dma > 0xffffffff || sec_dma > 0xffffffff || cmpl_dma > 0xffffffff)
    {
      log_err (dev, "TX descriptor DMA addresses exceed EDMA's 32-bit ring base fields");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rv = qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
  if (rv != VNET_DEV_OK)
    return rv;

  offset = EDMA_REG_TXCMPL_CTRL (tq->cmpl_ring_id);
  qppe_edma_reg_wr (qd, offset, EDMA_TXCMPL_RETMODE_OPAQUE);

  offset = EDMA_REG_TX_INT_CTRL (tq->cmpl_ring_id);
  qppe_edma_reg_wr (qd, offset, EDMA_TX_NE_INT_EN);

  log_debug (dev,
	     "TX descriptor ring %u and TX completion ring %u base/size and opaque return mode "
	     "configured; neither ring enabled, no producer index written, EDMA port control "
	     "unchanged",
	     tq->desc_ring_id, tq->cmpl_ring_id);

  return VNET_DEV_OK;
}

static void
qppe_edma_servcode_init (vnet_dev_t *dev, qppe_device_t *qd)
{
  u32 sc = EDMA_SC_BYPASS_ID;
  ppe_reg_service_tbl_bypass_bitmap_t ingress_bypass = { .as_u32 = ~0 };
  ppe_reg_eg_bypass_bitmap_t egress_bypass = { .as_u32 = ~0 };
  ppe_reg_in_l2_service_tbl_w0_t in_l2;
  u32 offset;

  ingress_bypass.my_mac_check_byp = 0;
  ingress_bypass.service_code_byp = 0;
  ingress_bypass.fake_l2_proto_byp = 0;

  egress_bypass.acl_post_routing_check_byp = 0;
  in_l2 = (ppe_reg_in_l2_service_tbl_w0_t) {
    .egress_bypass_bitmap = egress_bypass.as_u32,
  };

  offset = HPPE_REG_IN_L2_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, in_l2.as_u32);

  offset = HPPE_REG_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, ingress_bypass.as_u32);
  qppe_mmio_write32 (qd, offset + 4, 0);

  offset = HPPE_REG_EG_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, 0);
  qppe_mmio_write32 (qd, offset + 4, 0);

  offset = APPE_REG_TL_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, 0);

  log_debug (dev, "initialized PPE service code %u for bypassed CPU-originated TX (0x%08x/0x%08x)",
	     sc, in_l2.as_u32, ingress_bypass.as_u32);
}

vnet_dev_rv_t
qppe_edma_tx_ring_start (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  ppe_reg_edma_port_control_t port_control;
  ppe_reg_edma_txdesc_ctrl_t txdesc_ctrl;
  vnet_dev_rv_t rv;
  u32 offset, value;

  if (tq->started)
    return VNET_DEV_OK;
  port_control.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_PORT_CTRL_ADDR);

  if (tq->descs == 0 || tq->sec_descs == 0 || tq->cmpl_descs == 0)
    {
      log_err (dev, "cannot start TX queue %u: ring storage is incomplete", txq->queue_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (!qppe_edma_tx_queues_started (dev))
    {
      for (u32 i = 0; i < 6; i++)
	qppe_edma_reg_wr (qd, EDMA_REG_TXDESC2CMPL_MAP_0 + i * 4, 0);

      qppe_edma_servcode_init (dev, qd);
    }

  offset = EDMA_REG_TXDESC2CMPL_MAP_0 +
	   (tq->desc_ring_id / EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * sizeof (u32);
  value = qppe_edma_reg_rd (qd, offset);
  value |=
    (tq->cmpl_ring_id & ((1u << EDMA_TXDESC2CMPL_MAP_RING_BITS) - 1))
    << ((tq->desc_ring_id % EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * EDMA_TXDESC2CMPL_MAP_RING_BITS);
  qppe_edma_reg_wr (qd, offset, value);
  log_debug (dev, "mapped TX descriptor ring %u to TX completion ring %u at offset 0x%x: 0x%08x",
	     tq->desc_ring_id, tq->cmpl_ring_id, offset, value);

  tq->prod = 0;
  tq->cmpl_cons = 0;
  tq->avail_desc = 0;

  offset = EDMA_REG_TXDESC_PROD_IDX (tq->desc_ring_id);
  qppe_edma_reg_wr (qd, offset, 0);

  offset = EDMA_REG_TXCMPL_CONS_IDX (tq->cmpl_ring_id);
  qppe_edma_reg_wr (qd, offset, 0);

  offset = EDMA_REG_TXDESC_CTRL (tq->desc_ring_id);
  txdesc_ctrl.as_u32 = qppe_edma_reg_rd (qd, offset);
  txdesc_ctrl.fc_grp_id = txq->port->port_id;
  txdesc_ctrl.tx_enable = 1;
  qppe_edma_reg_wr (qd, offset, txdesc_ctrl.as_u32);
  if (!((ppe_reg_edma_txdesc_ctrl_t) { .as_u32 = qppe_edma_reg_rd (qd, offset) }).tx_enable)
    {
      log_err (dev, "TX descriptor ring %u did not enable at offset 0x%x", tq->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled TX descriptor ring %u at offset 0x%x: 0x%08x", tq->desc_ring_id, offset,
	     txdesc_ctrl.as_u32);

  rv = qppe_edma_enable (dev, port_control);
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_stop (txq);
      return rv;
    }
  tq->started = 1;

  return VNET_DEV_OK;
}

void
qppe_edma_tx_ring_stop (vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  ppe_reg_edma_txdesc_ctrl_t txdesc_ctrl;
  u32 offset;

  offset = EDMA_REG_TXDESC_CTRL (tq->desc_ring_id);
  txdesc_ctrl.as_u32 = qppe_edma_reg_rd (qd, offset);
  txdesc_ctrl.tx_enable = 0;
  qppe_edma_reg_wr (qd, offset, txdesc_ctrl.as_u32);
  txdesc_ctrl.as_u32 = qppe_edma_reg_rd (qd, offset);
  log_debug (dev, "disabled TX descriptor ring %u at offset 0x%x: 0x%08x", tq->desc_ring_id, offset,
	     txdesc_ctrl.as_u32);

  tq->started = 0;

  qppe_edma_disable_if_idle (dev);
}
