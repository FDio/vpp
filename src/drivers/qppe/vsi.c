/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "vsi",
};

/* SKEY_FMT/CKEY_FMT are a bitmask of acceptable tag states for that key, not
 * a sequential enum - confirmed via vendor FAL's s_tagged/c_tagged comment:
 * "bit0-untagged/bit1-pri_tagged/bit2-tagged". More than one bit may be set
 * (e.g. "match untagged or tagged"). */
static u8 *
format_qppe_key_fmt (u8 *s, va_list *args)
{
  u32 fmt = va_arg (*args, u32);

  if (!fmt)
    return format (s, "any");

  if (fmt & (1 << 0))
    s = format (s, "untagged");
  if (fmt & (1 << 1))
    s = format (s, "%spri-tagged", (fmt & (1 << 0)) ? "," : "");
  if (fmt & (1 << 2))
    s = format (s, "%stagged", (fmt & ((1 << 0) | (1 << 1))) ? "," : "");

  return s;
}

/* port_type selects how to interpret the raw "ports" field value. Verified
 * against the vendor SSDK's adpt_port_type_convert() (adpt.h), the actual
 * HSL<->FAL port-type mapping used by the real driver:
 *   0 = FAL_PORT_TYPE_PPORT    - physical port, "ports" is a port bitmap
 *   1 = FAL_PORT_TYPE_VPORT    - virtual port, "ports" is a single VP id
 *   2 = FAL_PORT_TYPE_VP_GROUP - "ports" is a VP group/profile id
 *   3 = FAL_PORT_TYPE_GEM_PORT - GPON GEM port, not used by this driver
 * Decode both together instead of printing port_type on its own next to a
 * value that was decoded without ever consulting it. */
static u8 *
format_qppe_xlt_ports (u8 *s, va_list *args)
{
  u32 port_type = va_arg (*args, u32);
  u32 raw = va_arg (*args, u32);

  switch (port_type)
    {
    case 0:
      {
	uword *bitmap = clib_bitmap_set_multiple (0, 0, raw, 32);
	s = format (s, "ports=%U", format_bitmap_list, bitmap);
	clib_bitmap_free (bitmap);
	return s;
      }
    case 1:
      return format (s, "vp_id=%u", raw);
    case 2:
      return format (s, "vp_group=%u", raw);
    case 3:
      return format (s, "gem_port=%u", raw);
    default:
      return format (s, "unknown(port_type=%u, raw=0x%x)", port_type, raw);
    }
}

/* fal_vid_xlt_cmd_t */
static u8 *
format_qppe_vid_xlt_cmd (u8 *s, va_list *args)
{
  u32 cmd = va_arg (*args, u32);

  switch (cmd)
    {
    case 0:
      return format (s, "unchanged");
    case 1:
      return format (s, "add-or-replace");
    case 2:
      return format (s, "delete");
    case 3:
      return format (s, "copy-from-svid");
    case 4:
      return format (s, "copy-from-cvid");
    default:
      return format (s, "unknown(%u)", cmd);
    }
}

/* fal_pcp_xlt_cmd_t */
static u8 *
format_qppe_pcp_xlt_cmd (u8 *s, va_list *args)
{
  u32 cmd = va_arg (*args, u32);

  switch (cmd)
    {
    case 0:
      return format (s, "unchanged");
    case 1:
      return format (s, "replace");
    case 2:
      return format (s, "copy-from-spcp");
    case 3:
      return format (s, "copy-from-cpcp");
    case 4:
      return format (s, "map-from-dscp");
    case 5:
      return format (s, "add-tag+replace");
    case 6:
      return format (s, "add-tag+copy-from-spcp");
    case 7:
      return format (s, "add-tag+copy-from-cpcp");
    case 8:
      return format (s, "add-tag+map-from-dscp");
    default:
      return format (s, "unknown(%u)", cmd);
    }
}

/* fal_dei_xlt_cmd_t */
static u8 *
format_qppe_dei_xlt_cmd (u8 *s, va_list *args)
{
  u32 cmd = va_arg (*args, u32);

  switch (cmd)
    {
    case 0:
      return format (s, "unchanged");
    case 1:
      return format (s, "replace");
    case 2:
      return format (s, "copy-from-sdei");
    case 3:
      return format (s, "copy-from-cdei");
    default:
      return format (s, "unknown(%u)", cmd);
    }
}

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)

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
  offset = PPE_REG_XLT_RULE_TBL (rxq->port->port_id);
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
  offset = PPE_REG_XLT_ACTION_TBL (rxq->port->port_id);
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
   * port. Keep broadcast and unknown-destination flood bitmaps CPU-only here,
   * since this driver has no hardware bridging between ports.
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

    offset = PPE_REG_VSI_TBL_W0 (vsi);
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

    offset = PPE_REG_PORT_VSI_ENQUEUE_MAP (EDMA_CPU_PORT_ID, vsi);
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
    ppe_reg_ucast_queue_map_t queue_map = {
      .queue_id = queue_base,
    };

    offset = PPE_REG_UCAST_QUEUE_MAP_TBL (0, vp);
    qppe_mmio_write32 (qd, offset, queue_map.as_u32);
    if (qppe_mmio_read32 (qd, offset) != queue_map.as_u32)
      {
	log_err (dev, "PPE VP queue base readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
    log_debug (dev,
	       "mapped port %u to PPE VSI %u, VP %u, CPU queue IDs %u-%u, EDMA descriptor "
	       "ring %u",
	       rxq->port->port_id, vsi, vp, queue_base, queue_base + EDMA_RX_QUEUES_PER_RING - 1,
	       qr->desc_ring_id);
  }

  /* L2_VP_PORT_TBL has a separate per-port VP membership bitmap. This port
   * only needs CPU egress; exclude the physical port itself to prevent a
   * hardware hairpin. Also point invalid-VSI fallback traffic at our own VP. */
  offset = PPE_REG_L2_VP_PORT_TBL_W0 (rxq->port->port_id);
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

u8 *
format_qppe_rule_and_action_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  indent = format_get_indent (s);
  s = format (s, "PPE XLT Rule and Action Table:");

  for (u32 idx = 0; idx < PPE_XLT_RULE_TBL_ENTRIES; idx++)
    {
      u32 rule_offset = PPE_REG_XLT_RULE_TBL (idx);
      ppe_reg_xlt_rule_tbl_w0_t rw0 = { .as_u32 = qppe_mmio_read32 (qd, rule_offset) };
      ppe_reg_xlt_rule_tbl_w1_t rw1;
      ppe_reg_xlt_rule_tbl_w2_t rw2;
      ppe_reg_xlt_rule_tbl_w3_t rw3;
      u32 action_offset = PPE_REG_XLT_ACTION_TBL (idx);
      ppe_reg_xlt_action_tbl_w0_t aw0;
      ppe_reg_xlt_action_tbl_w1_t aw1;
      ppe_reg_xlt_action_tbl_w2_t aw2;
      u32 ckey_fmt, prot_value, vni_resv, xlt_spcp, counter_id;
      u8 *key = 0, *action = 0;

      if (!rw0.valid)
	continue;

      rw1.as_u32 = qppe_mmio_read32 (qd, rule_offset + 4);
      rw2.as_u32 = qppe_mmio_read32 (qd, rule_offset + 8);
      rw3.as_u32 = qppe_mmio_read32 (qd, rule_offset + 12);
      aw0.as_u32 = qppe_mmio_read32 (qd, action_offset);
      aw1.as_u32 = qppe_mmio_read32 (qd, action_offset + 4);
      aw2.as_u32 = qppe_mmio_read32 (qd, action_offset + 8);

      ckey_fmt = rw0.ckey_fmt_0 | (rw1.ckey_fmt_1 << 1);
      prot_value = rw1.prot_value_0 | (rw2.prot_value_1 << 7);
      vni_resv = rw2.vni_resv_0 | (rw3.vni_resv_1 << 19);
      xlt_spcp = aw0.xlt_spcp_0 | (aw1.xlt_spcp_1 << 1);
      counter_id = aw1.counter_id_0 | (aw2.counter_id_1 << 3);

      s = format_newline (s, indent + 2);
      s = format (s, "Index %u:", idx);

      s = format_newline (s, indent + 4);
      s = format (s, "Rule:");

      /* ports has no "_incl" gate of its own the way the other match-key
       * fields do, but a raw value of 0 is just as much "nothing meaningful
       * here" as an unset _incl bit, so it must not be a mandatory leading
       * clause either - a rule can legitimately match on other criteria
       * alone. Likewise skey_fmt/ckey_fmt below - qppe's own rules never
       * set any of these, so listing each unconditionally would mean up to
       * 11 fields that are always absent. Fold them all into one free-form
       * tail that only grows when a rule actually uses one. */
      if (rw0.port_bitmap)
	key = format (key, "%U", format_qppe_xlt_ports, rw2.port_type, rw0.port_bitmap);
      if (rw0.skey_fmt)
	key = format (key, "%sskey_fmt=%U", key ? ", " : "", format_qppe_key_fmt, rw0.skey_fmt);
      if (ckey_fmt)
	key = format (key, "%sckey_fmt=%U", key ? ", " : "", format_qppe_key_fmt, ckey_fmt);
      if (rw0.skey_vid_incl)
	key = format (key, "%sskey_vid=%u", key ? ", " : "", rw0.skey_vid);
      if (rw0.skey_pcp_incl)
	key = format (key, "%sskey_pcp=%u", key ? ", " : "", rw0.skey_pcp);
      if (rw0.skey_dei_incl)
	key = format (key, "%sskey_dei=%u", key ? ", " : "", rw0.skey_dei);
      if (rw1.ckey_vid_incl)
	key = format (key, "%sckey_vid=%u", key ? ", " : "", rw1.ckey_vid);
      if (rw1.ckey_pcp_incl)
	key = format (key, "%sckey_pcp=%u", key ? ", " : "", rw1.ckey_pcp);
      if (rw1.ckey_dei_incl)
	key = format (key, "%sckey_dei=%u", key ? ", " : "", rw1.ckey_dei);
      if (rw1.frm_type_incl)
	key = format (key, "%sfrm_type=%u", key ? ", " : "", rw1.frm_type);
      if (rw1.prot_incl)
	key = format (key, "%sprot_value=%u", key ? ", " : "", prot_value);
      if (rw2.vni_resv_incl)
	key = format (key, "%svni_resv=%u, vni_resv_type=%u", key ? ", " : "", vni_resv,
		      rw2.vni_resv_type);
      if (key)
	s = format (s, " %v", key);
      else
	s = format (s, " (none)");
      vec_free (key);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);

      s = format_newline (s, indent + 4);
      s = format (s, "Action:");

      /* vsi is just as individually optional as every other action field
       * below - a row's real action may have nothing to do with VSI at all
       * (vsi_cmd=0 with some other field set), so it must not be a
       * mandatory leading statement. */
      if (aw1.vsi_cmd)
	action = format (action, "vsi=%u", aw1.vsi);
      if (aw0.vid_swap_cmd)
	action = format (action, "%svid_swap", action ? ", " : "");
      if (aw0.xlt_svid_cmd)
	action = format (action, "%ssvid_cmd=%U, svid=%u", action ? ", " : "",
			 format_qppe_vid_xlt_cmd, aw0.xlt_svid_cmd, aw0.xlt_svid);
      if (aw0.xlt_cvid_cmd)
	action = format (action, "%scvid_cmd=%U, cvid=%u", action ? ", " : "",
			 format_qppe_vid_xlt_cmd, aw0.xlt_cvid_cmd, aw0.xlt_cvid);
      if (aw0.pcp_swap_cmd)
	action = format (action, "%spcp_swap", action ? ", " : "");
      if (aw0.xlt_spcp_cmd)
	action = format (action, "%sspcp_cmd=%U, spcp=%u", action ? ", " : "",
			 format_qppe_pcp_xlt_cmd, aw0.xlt_spcp_cmd, xlt_spcp);
      if (aw1.xlt_cpcp_cmd)
	action = format (action, "%scpcp_cmd=%U, cpcp=%u", action ? ", " : "",
			 format_qppe_pcp_xlt_cmd, aw1.xlt_cpcp_cmd, aw1.xlt_cpcp);
      if (aw1.dei_swap_cmd)
	action = format (action, "%sdei_swap", action ? ", " : "");
      if (aw1.xlt_sdei_cmd)
	action = format (action, "%ssdei_cmd=%U, sdei=%u", action ? ", " : "",
			 format_qppe_dei_xlt_cmd, aw1.xlt_sdei_cmd, aw1.xlt_sdei);
      if (aw1.xlt_cdei_cmd)
	action = format (action, "%scdei_cmd=%U, cdei=%u", action ? ", " : "",
			 format_qppe_dei_xlt_cmd, aw1.xlt_cdei_cmd, aw1.xlt_cdei);
      if (aw1.counter_en)
	action = format (action, "%scounter_id=%u", action ? ", " : "", counter_id);
      if (aw1.src_info_valid)
	action = format (action, "%ssrc_info=%u(type=%u)", action ? ", " : "", aw1.src_info,
			 aw1.src_info_type);
      if (action)
	s = format (s, " %v", action);
      else
	s = format (s, " (none)");
      vec_free (action);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
    }
  return s;
}

u8 *
format_qppe_vsi_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 9, "vsi", "Mbr", "UUC", "UMC", "BC", "new_addr_lrn_en",
		     "new_addr_fwd_cmd", "station_move_lrn_en", "station_move_fwd_cmd");
  for (u32 vsi = 0; vsi < PPE_VSI_TBL_ENTRIES; vsi++)
    {
      ppe_reg_vsi_tbl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, PPE_REG_VSI_TBL_W0 (vsi)) };
      ppe_reg_vsi_tbl_w1_t w1;

      /* VSI_TBL has no dedicated valid bit; an all-zero word0 (no flood
       * membership at all) is the closest thing to "never configured". */
      if (w0.as_u32 == 0)
	continue;

      uword *member_bitmap = clib_bitmap_set_multiple (0, 0, w0.member_port_bitmap, 32);

      w1.as_u32 = qppe_mmio_read32 (qd, PPE_REG_VSI_TBL_W0 (vsi) + sizeof (u32));

      table_format_cell (&table, row, 0, "%u", vsi);
      table_format_cell (&table, row, 1, "%U", format_bitmap_list, member_bitmap);
      clib_bitmap_free (member_bitmap);
      table_format_cell (&table, row, 2, "%u", w0.uuc_bitmap);
      table_format_cell (&table, row, 3, "%u", w0.umc_bitmap);
      table_format_cell (&table, row, 4, "%u", w0.bc_bitmap);
      table_format_cell (&table, row, 5, "%u", w1.new_addr_lrn_en);
      table_format_cell (&table, row, 6, "%u", w1.new_addr_fwd_cmd);
      table_format_cell (&table, row, 7, "%u", w1.station_move_lrn_en);
      table_format_cell (&table, row, 8, "%u", w1.station_move_fwd_cmd);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE VSI_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_vsi_remap_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "vsi", "member VPs", "br_vsi");
  for (u32 vsi = 0; vsi < PPE_VSI_REMAP_TBL_ENTRIES; vsi++)
    {
      u32 offset = PPE_REG_VSI_REMAP_TBL (vsi);
      ppe_reg_vsi_remap_tbl_w8_t w8 = { .as_u32 =
					  qppe_mmio_read32 (qd, offset + 8 * sizeof (u32)) };

      /* vsi_remap_en gates whether this row is consulted at all; this
       * driver never enables it, so every row is expected to read 0
       * here unless something else on the chip set it. */
      if (!w8.vsi_remap_en)
	continue;

      uword *member_bitmap = 0;

      for (u32 w = 0; w < 8; w++)
	member_bitmap = clib_bitmap_set_multiple (
	  member_bitmap, w * 32, qppe_mmio_read32 (qd, offset + w * sizeof (u32)), 32);

      table_format_cell (&table, row, 0, "%u", vsi);
      table_format_cell (&table, row, 1, "%U", format_bitmap_list, member_bitmap);
      clib_bitmap_free (member_bitmap);
      table_format_cell (&table, row, 2, "%u", w8.br_vsi);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE VSI_REMAP_TBL (APPE extension):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_port_vsi_enqueue_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "vsi", "Enq VP");
  for (u32 vsi = 0; vsi < PPE_VSI_TBL_ENTRIES; vsi++)
    {
      ppe_reg_port_vsi_enqueue_map_t enqueue_map = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_PORT_VSI_ENQUEUE_MAP (EDMA_CPU_PORT_ID, vsi)),
      };

      if (!enqueue_map.enqueue_valid)
	continue;

      table_format_cell (&table, row, 0, "%u", vsi);
      table_format_cell (&table, row, 1, "%u", enqueue_map.enqueue_vp);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE PORT_VSI_ENQUEUE_MAP (CPU port):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ucast_queue_map_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "vp", "Q profile", "Q id");
  /* UCAST_QUEUE_MAP_TBL has no dedicated valid bit, unlike the tables
   * above, and unlike those an all-zero row here is NOT a reliable
   * "never configured" signal: a legitimate profile-0/queue-0 entry
   * (e.g. a port whose own source profile is 0) reads back as exactly
   * 0x00000000 too, so skipping zero rows would silently hide real,
   * correctly-configured entries. Shown in full. */
  for (u32 vp = 0; vp < 256; vp++)
    {
      ppe_reg_ucast_queue_map_t queue_map = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_UCAST_QUEUE_MAP_TBL (0, vp)),
      };

      table_format_cell (&table, row, 0, "%u", vp);
      table_format_cell (&table, row, 1, "%u", queue_map.profile_id);
      table_format_cell (&table, row, 2, "%u", queue_map.queue_id);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE UCAST_QUEUE_MAP_TBL (profile 0):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_l2_vp_port_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 25, "idx", "invalid_vsi_fwd_en", "promisc_en", "dst_info (VP)",
		     "physical_port", "new_addr_lrn_en", "new_addr_fwd_cmd", "station_move_lrn_en",
		     "station_move_fwd_cmd", "lrn_lmt_cnt", "lrn_lmt_en", "lrn_lmt_exceed_fwd",
		     "isolation_bitmap", "isol_profile", "isol_profile_en", "policer_en",
		     "policer_index", "vp_state_check_en", "vp_type", "vp_context_active",
		     "vp_eg_data_valid", "enq_service_code_en", "enq_service_code", "enq_phy_port",
		     "app_ctrl_profile");
  /* No dedicated valid bit; an all-zero word0 doesn't work as the
   * "never touched" signal here like it does for VSI_TBL, because
   * promisc_en reads 1 for every single index regardless of whether
   * qppe has configured this row at all - apparently a hardware
   * default baseline, not something tied to configuration state.
   * Filter on the two fields qppe actually writes instead. */
  for (u32 idx = 0; idx < PPE_L2_VP_PORT_TBL_ENTRIES; idx++)
    {
      u32 offset = PPE_REG_L2_VP_PORT_TBL_W0 (idx);
      ppe_reg_l2_vp_port_tbl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_l2_vp_port_tbl_w1_t w1;
      ppe_reg_l2_vp_port_tbl_w2_t w2;
      ppe_reg_l2_vp_port_tbl_w3_t w3;
      u32 app_ctrl_profile;

      if (!w0.invalid_vsi_forwarding_en && w0.dst_info == 0)
	continue;

      uword *isolation_bitmap;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      w3.as_u32 = qppe_mmio_read32 (qd, offset + 12);
      app_ctrl_profile = w2.app_ctrl_profile_0 | (w3.app_ctrl_profile_1 << 6);
      isolation_bitmap = clib_bitmap_set_multiple (0, 0, w1.port_isolation_bitmap, 32);

      table_format_cell (&table, row, 0, "%u", idx);
      table_format_cell (&table, row, 1, "%u", w0.invalid_vsi_forwarding_en);
      table_format_cell (&table, row, 2, "%u", w0.promisc_en);
      table_format_cell (&table, row, 3, "%u", w0.dst_info);
      table_format_cell (&table, row, 4, "%u", w0.physical_port);
      table_format_cell (&table, row, 5, "%u", w0.new_addr_lrn_en);
      table_format_cell (&table, row, 6, "%u", w0.new_addr_fwd_cmd);
      table_format_cell (&table, row, 7, "%u", w0.station_move_lrn_en);
      table_format_cell (&table, row, 8, "%u", w0.station_move_fwd_cmd);
      table_format_cell (&table, row, 9, "%u", w0.lrn_lmt_cnt);
      table_format_cell (&table, row, 10, "%u", w0.lrn_lmt_en);
      table_format_cell (&table, row, 11, "%u", w1.lrn_lmt_exceed_fwd);
      table_format_cell (&table, row, 12, "%U", format_bitmap_list, isolation_bitmap);
      clib_bitmap_free (isolation_bitmap);
      table_format_cell (&table, row, 13, "%u", w1.isol_profile);
      table_format_cell (&table, row, 14, "%u", w1.isol_profile_en);
      table_format_cell (&table, row, 15, "%u", w1.policer_en);
      table_format_cell (&table, row, 16, "%u", w1.policer_index);
      table_format_cell (&table, row, 17, "%u", w1.vp_state_check_en);
      table_format_cell (&table, row, 18, "%u", w1.vp_type);
      table_format_cell (&table, row, 19, "%u", w1.vp_context_active);
      table_format_cell (&table, row, 20, "%u", w1.vp_eg_data_valid);
      table_format_cell (&table, row, 21, "%u", w2.enq_service_code_en);
      table_format_cell (&table, row, 22, "%u", w2.enq_service_code);
      table_format_cell (&table, row, 23, "%u", w2.enq_phy_port);
      table_format_cell (&table, row, 24, "%u", app_ctrl_profile);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE L2_VP_PORT_TBL (per-port VP membership/fallback):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}
