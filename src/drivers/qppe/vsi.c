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

/* Give this port its own VSI instead of sharing one with every other port (the
 * reset-default state). Assignment goes through XLT_RULE_TBL/XLT_ACTION_TBL, the
 * ingress VLAN classification stage actually consulted for L2 bridging/flood-
 * domain membership - not L3_VP_PORT_TBL, which only feeds L3-routing VP lookups
 * qppe never uses. SRC_PROFILE/UCAST_QUEUE_MAP_TBL(profile, CPU) dispatch is gone
 * entirely: both unicast and multicast now have to reach their ring purely
 * through this VSI -> enqueue_vp -> UCAST_QUEUE_MAP_TBL(0, vp) path. */
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

  /* XLT_RULE_TBL word0: valid (bit 0) + physical ingress port_bitmap (bits 1-8, PPORT port_type).
   * Every tag/pcp/dei/frame-type/protocol match field is left at "don't care" (0),
   * so this matches any frame ingressing on this port regardless of VLAN state.
   * Words 1-3 hold only those match fields plus port_type (0 == PPORT), all 0. */
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

  /* XLT_ACTION_TBL word1: vsi_cmd (bit 43 overall, bit 11 of this word) = 1, vsi
   * (bits 44-49 overall, bits 12-17 of this word) = this port's VSI.
   *
   * Confirmed empirically: with word0/word2/word3 all zero across every
   * port's entry, every idx's vsi read back as whichever port was
   * configured last - the rows were aliasing onto one physical action
   * slot. Giving word2 a distinct, non-zero value per port (shifted
   * into its genuinely reserved bits 4-31, per the vendor SSDK's
   * struct xlt_action_tbl - counter_id_1 lives in bits 0-3 and
   * counter_en is never set, so this touches nothing functional)
   * breaks that aliasing and each port keeps its own vsi. word0 is
   * left at 0 deliberately: every one of its bits is a real VLAN-tag-
   * rewrite field (vid_swap_cmd, xlt_svid_cmd/svid, etc.), so it's not
   * a safe place for a marker. */
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
    /* word2's reserved bits 4-31 may read back as zero regardless of
     * what was written (RAZ), so this field alone isn't verified
     * strictly - just logged, so we can tell from the log whether the
     * write ever stuck at all. */
    w2_read = qppe_mmio_read32 (qd, offset + 8);
    if (w2_read != w2_marker)
      log_debug (dev, "port %u: XLT action word2 readback 0x%08x != wrote 0x%08x (RAZ?)",
		 rxq->port->port_id, w2_read, w2_marker);
  }
  log_debug (dev, "port %u (vsi %u): wrote XLT action at offset 0x%x word1 0x%08x",
	     rxq->port->port_id, vsi, offset, value);

  /* VSI_TBL is a two-word entry (member/uuc/umc/bc bitmaps in word0, learn and
   * station-move control in word1); the row doesn't commit unless every word of
   * it is written.
   *
   * This driver uses per-port VSIs to deliver ingress traffic to the CPU and
   * to retain the physical port as a valid member for CPU-directed egress.
   * QSDK's non-bridge port/VSI mapping includes both the CPU and that physical
   * port. Keep the broadcast flood bitmap CPU-only here, since this driver
   * has no hardware bridging between ports.
   *
   * uuc_bitmap/umc_bitmap (unknown-unicast/multicast flood) always include
   * the CPU here, matching the reference driver (qca_ppe_main.c ORs the CPU
   * port bit into both unconditionally, for every port, bridged or not).
   * They don't gate non-promiscuous admission - that's PORT_BRIDGE_CTRL.
   * promisc_en, which drops unmatched unicast before FDB/VSI forwarding is
   * even consulted (see qppe_port_set_promisc_mode in port.c); once a frame
   * is admitted, any FDB miss should still flood to the CPU like any other
   * member, promiscuous or not.
   *
   * word1 previously went in as flat 0 (new-address learning
   * disabled). Since the host's source MAC then never gets learned,
   * every single packet is forever treated as "new address" by
   * hardware - mainline's ppe_bridge_init() always enables learning
   * with a FORWARD action as the correct default for every VSI, which
   * this driver was deviating from. */
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

  /* Our virtual port's own queue base, the same table unicast used to use
   * directly via SRC_PROFILE - now reached only through enqueue_vp above. */
  {
    qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
    qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
    u32 queue_base = qp->source_profile * EDMA_RX_QUEUES_PER_RING;
    vnet_dev_rv_t rv;

    rv = qppe_qm_ucast_queue_map_set (dev, vp, queue_base);
    if (rv != VNET_DEV_OK)
      return rv;
    log_debug (dev,
	       "mapped port %u to PPE VSI %u, VP %u, CPU queue IDs %u-%u, EDMA descriptor "
	       "ring %u",
	       rxq->port->port_id, vsi, vp, queue_base, queue_base + EDMA_RX_QUEUES_PER_RING - 1,
	       qr->desc_ring_id);
  }

  /* L2_VP_PORT_TBL has a separate per-port VP membership bitmap. This port
   * only needs CPU egress; exclude the physical port itself to prevent a
   * hardware hairpin. Also point invalid-VSI fallback traffic at our own VP. */
  offset = APPE_REG_L2_VP_PORT_TBL_W0 (rxq->port->port_id);
  {
    /* L2_VP_PORT_TBL is a four-word entry; like VSI_TBL, the row doesn't commit
     * unless every word of it is written back, so preserve unrelated fields. */
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
