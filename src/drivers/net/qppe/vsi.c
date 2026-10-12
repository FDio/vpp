/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "vsi",
};

vnet_dev_rv_t
qppe_vsi_port_configure (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 vsi = rxq->port->port_id;
  u32 vp = EDMA_VP_BASE + rxq->port->port_id;
  u32 port_bitmap = 1u << rxq->port->port_id;
  u32 member_bitmap = port_bitmap | (1u << EDMA_CPU_PORT_ID);
  u32 offset, value;

  offset = HPPE_REG_XLT_RULE_TBL (rxq->port->port_id);
  value = 1u | (port_bitmap << 1);
  qppe_mmio_write32 (qd, offset, value);
  qppe_mmio_write32 (qd, offset + 4, 0);
  qppe_mmio_write32 (qd, offset + 8, 0);
  qppe_mmio_write32 (qd, offset + 12, 0);
  if (qppe_mmio_read32 (qd, offset) != value || qppe_mmio_read32 (qd, offset + 4) != 0 ||
      qppe_mmio_read32 (qd, offset + 8) != 0 || qppe_mmio_read32 (qd, offset + 12) != 0)
    {
      log_err (dev, "PPE XLT rule readback failed at offset 0x%x", offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = HPPE_REG_XLT_ACTION_TBL (rxq->port->port_id);
  value = (1u << 11) | (vsi << 12);
  {
    u32 w2_marker = rxq->port->port_id << 4;
    u32 w2_read;

    qppe_mmio_write32 (qd, offset, 0);
    qppe_mmio_write32 (qd, offset + 4, value);
    qppe_mmio_write32 (qd, offset + 8, w2_marker);
    qppe_mmio_write32 (qd, offset + 12, 0);
    if (qppe_mmio_read32 (qd, offset) != 0 || qppe_mmio_read32 (qd, offset + 4) != value ||
	qppe_mmio_read32 (qd, offset + 12) != 0)
      {
	log_err (dev, "PPE XLT action readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
    w2_read = qppe_mmio_read32 (qd, offset + 8);
    if (w2_read != w2_marker)
      log_debug (dev, "port %u: XLT action word2 readback 0x%08x != wrote 0x%08x (RAZ?)",
		 rxq->port->port_id, w2_read, w2_marker);
  }
  log_debug (dev, "port %u (vsi %u): wrote XLT action at offset 0x%x word1 0x%08x",
	     rxq->port->port_id, vsi, offset, value);

  {
    u32 flood_bitmap = 1u << EDMA_CPU_PORT_ID;
    ppe_reg_vsi_tbl_w0_t vsi_tbl = {
      .member_port_bitmap = member_bitmap,
      .uuc_bitmap = flood_bitmap,
      .umc_bitmap = flood_bitmap,
      .bc_bitmap = flood_bitmap,
    };
    ppe_reg_vsi_tbl_w1_t vsi_tbl_w1 = {
      .new_addr_lrn_en = 1,
      .station_move_lrn_en = 1,
    };

    offset = HPPE_REG_VSI_TBL_W0 (vsi);
    qppe_mmio_write32 (qd, offset, vsi_tbl.as_u32);
    qppe_mmio_write32 (qd, offset + 4, vsi_tbl_w1.as_u32);
    if (qppe_mmio_read32 (qd, offset) != vsi_tbl.as_u32 ||
	qppe_mmio_read32 (qd, offset + 4) != vsi_tbl_w1.as_u32)
      {
	log_err (dev, "PPE VSI flood membership readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  /* Resolves this VSI's CPU-bound (flooded) delivery to our own virtual port. */
  {
    ppe_reg_port_vsi_enqueue_map_t enqueue_map = {
      .enqueue_vp = vp,
      .enqueue_valid = 1,
    };

    offset = APPE_REG_PORT_VSI_ENQUEUE_MAP (EDMA_CPU_PORT_ID, vsi);
    qppe_mmio_write32 (qd, offset, enqueue_map.as_u32);
    if (qppe_mmio_read32 (qd, offset) != enqueue_map.as_u32)
      {
	log_err (dev, "PPE port VSI enqueue map readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  {
    qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
    qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
    u32 queue_base = qp->source_profile * EDMA_RX_QUEUES_PER_RING;
    vnet_dev_rv_t rv;

    rv = qppe_qm_ucast_queue_map_set (dev, vp, queue_base, qp->source_profile);
    if (rv != VNET_DEV_OK)
      return rv;
    log_debug (dev,
	       "mapped port %u to PPE VSI %u, VP %u, CPU queue IDs %u-%u, EDMA descriptor "
	       "ring %u",
	       rxq->port->port_id, vsi, vp, queue_base, queue_base + EDMA_RX_QUEUES_PER_RING - 1,
	       qr->desc_ring_id);
  }

  offset = APPE_REG_L2_VP_PORT_TBL_W0 (rxq->port->port_id);
  {
    ppe_reg_l2_vp_port_tbl_w0_t l2_vp = {
      .as_u32 = qppe_mmio_read32 (qd, offset),
    };
    ppe_reg_l2_vp_port_tbl_w1_t l2_vp_w1 = {
      .as_u32 = qppe_mmio_read32 (qd, offset + 4),
    };
    u32 w2 = qppe_mmio_read32 (qd, offset + 8);
    u32 w3 = qppe_mmio_read32 (qd, offset + 12);

    l2_vp.invalid_vsi_forwarding_en = 1;
    l2_vp.dst_info = vp;
    l2_vp_w1.port_isolation_bitmap = 1u << EDMA_CPU_PORT_ID;
    qppe_mmio_write32 (qd, offset, l2_vp.as_u32);
    qppe_mmio_write32 (qd, offset + 4, l2_vp_w1.as_u32);
    qppe_mmio_write32 (qd, offset + 8, w2);
    qppe_mmio_write32 (qd, offset + 12, w3);
    if (qppe_mmio_read32 (qd, offset) != l2_vp.as_u32 ||
	qppe_mmio_read32 (qd, offset + 4) != l2_vp_w1.as_u32 ||
	qppe_mmio_read32 (qd, offset + 8) != w2 || qppe_mmio_read32 (qd, offset + 12) != w3)
      {
	log_err (dev, "PPE invalid-VSI fallback readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  return VNET_DEV_OK;
}
