/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define HPPE_ACL_ACTION_DROP		  1
#define HPPE_ACL_ACTION_COPYCPU		  2
#define HPPE_ACL_ACTION_RDTCPU		  3
#define APPE_ACL_PRI_DENY		  0
#define APPE_PRE_ACL_BCAST_ROW(port_id)	  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT)
#define APPE_PRE_ACL_PRIMARY_ROW(port_id) ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 1)
#define APPE_PRE_ACL_DENY_ROW(port_id)                                                             \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + APPE_PRE_ACL_SECONDARY_MAX)
#define APPE_PRE_ACL_ROWS_RESERVED (QPPE_MAX_PORTS * APPE_PRE_ACL_ROWS_PER_PORT)

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "acl",
};

#define HPPE_REG_IPO_RULE_REG(index) (0x0b0000 + (0x10 * (index)))
#define HPPE_REG_IPO_MASK_REG(index) (0x0b2000 + (0x10 * (index)))
#define HPPE_REG_IPO_ACTION(index)   (0x0b8000 + (0x20 * (index)))
#define HPPE_REG_IPO_CNT_TBL(index)  (0x074000 + (0x10 * (index)))
#define HPPE_ACL_ACTION_WORDS	     8
#define HPPE_ACL_RULE_TYPE_MAC_DA    0
#define HPPE_ACL_SRC_TYPE_PORTBITMAP 0
#define HPPE_ACL_TOTAL_ROWS	     512

#define APPE_REG_PRE_IPO_RULE_REG(index)    (0x180000 + (0x10 * (index)))
#define APPE_REG_PRE_IPO_MASK_REG(index)    (0x182000 + (0x10 * (index)))
#define APPE_REG_PRE_IPO_ACTION(index)	    (0x188000 + (0x40 * (index)))
#define APPE_REG_PRE_IPO_GLB_HIT_COUNTER    0x18430c
#define APPE_REG_PRE_IPO_GLB_MISS_COUNTER   0x184310
#define APPE_REG_PRE_IPO_GLB_BYPASS_COUNTER 0x184314
#define APPE_REG_PRE_IPO_CNT_TBL(index)	    (0x176000 + (0x10 * (index)))
#define APPE_PRE_ACL_ACTION_WORDS	    16
#define APPE_PRE_ACL_TOTAL_ROWS		    512

typedef union
{
  u32 val[3];
  struct
  {
    u32 mac_addr_0 : 32;
    u32 mac_addr_1 : 16;
    u32 is_ip : 1;
    u32 is_ipv6 : 1;
    u32 is_ethernet : 1;
    u32 is_snap : 1;
    u32 fake_mac_header : 1;
    u32 range_en : 1;
    u32 inverse_en : 1;
    u32 rule_type : 5;
    u32 src_type : 3;
    u32 src_0 : 1;
    u32 src_1 : 7;
    u32 pri : 9;
    u32 res_chain : 1;
    u32 post_routing_en : 1;
    u32 reserved_82_95 : 14;
  } bf;
} ppe_reg_ipo_rule_reg_t;

typedef union
{
  u32 val[2];
  struct
  {
    u32 mac_addr_mask_0 : 32;
    u32 mac_addr_mask_1 : 16;
    u32 is_ip_mask : 1;
    u32 is_ipv6_mask : 1;
    u32 is_ethernet_mask : 1;
    u32 is_snap_mask : 1;
    u32 fake_mac_header_mask : 1;
    u32 reserved_21_31 : 11;
  } bf;
} ppe_reg_ipo_mask_reg_t;

typedef union
{
  u32 val[5];
  struct
  {
    u32 dest_info_change_en : 1;
    u32 fwd_cmd : 2;
    u32 dest_info : 14;
    u32 mirror_en : 1;
    u32 bypass_bitmap_0 : 14;
    u32 bypass_bitmap_1 : 18;
    u32 svid_change_en : 1;
    u32 stag_fmt : 1;
    u32 svid : 12;
    u32 cvid_change_en : 1;
    u32 ctag_fmt : 1;
    u32 cvid : 12;
    u32 dscp_tc_change_en : 1;
    u32 dscp_tc : 8;
    u32 stag_pcp_change_en : 1;
    u32 stag_pcp : 3;
    u32 stag_dei_change_en : 1;
    u32 stag_dei : 1;
    u32 ctag_pcp_change_en : 1;
    u32 ctag_pcp_0 : 2;
    u32 ctag_pcp_1 : 1;
    u32 ctag_dei_change_en : 1;
    u32 ctag_dei : 1;
    u32 enqueue_pri_change_en : 1;
    u32 enqueue_pri : 4;
    u32 int_dp_change_en : 1;
    u32 int_dp : 2;
    u32 policer_en : 1;
    u32 policer_index : 9;
    u32 qid_en : 1;
    u32 qid : 8;
    u32 service_code_en : 1;
    u32 service_code_0 : 1;
    u32 service_code_1 : 7;
    u32 syn_toggle : 1;
    u32 cpu_code_en : 1;
    u32 cpu_code : 8;
    u32 metadata_en : 1;
    u32 dscp_tc_mask : 8;
    u32 qos_res_prec : 3;
    u32 reserved_157_159 : 3;
  } bf;
} ppe_reg_ipo_action_t;

/* The IPO TCAM is not reset by anything in the EDMA/BM/QM bring-up this
 * driver already does, and it survives a VPP process restart untouched -
 * any row written by a previous boot (or firmware) stays live in hardware
 * until something explicitly overwrites it. Nothing in this driver writes
 * IPO rows any more (see the comment above HPPE_REG_IPO_RULE_REG), so this
 * just ensures format_qppe_acl_ipo_tbl's read-only dump starts from a
 * known-empty state instead of showing stale rows forever. */
vnet_dev_rv_t
qppe_acl_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 index;

  for (index = 0; index < HPPE_ACL_TOTAL_ROWS; index++)
    {
      u32 rule_offset = HPPE_REG_IPO_RULE_REG (index);
      u32 mask_offset = HPPE_REG_IPO_MASK_REG (index);
      u32 action_offset = HPPE_REG_IPO_ACTION (index);
      u32 i;

      qppe_mmio_write32 (qd, rule_offset, 0);
      qppe_mmio_write32 (qd, rule_offset + 4, 0);
      qppe_mmio_write32 (qd, rule_offset + 8, 0);
      qppe_mmio_write32 (qd, mask_offset, 0);
      qppe_mmio_write32 (qd, mask_offset + 4, 0);
      for (i = 0; i < HPPE_ACL_ACTION_WORDS; i++)
	qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

      if (qppe_mmio_read32 (qd, rule_offset) != 0 || qppe_mmio_read32 (qd, mask_offset) != 0 ||
	  qppe_mmio_read32 (qd, action_offset) != 0)
	{
	  log_err (dev, "ACL row %u clear readback failed at offset 0x%x", index, rule_offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  log_debug (dev, "cleared all %u ACL (IPO) TCAM rows", HPPE_ACL_TOTAL_ROWS);
  return VNET_DEV_OK;
}

u8 *
format_qppe_acl_ipo_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  const char *const qppe_acl_rule_type_names[] = {
    "MAC_DA",
  };
  const char *const qppe_acl_action_names[] = {
    [HPPE_ACL_ACTION_FWD] = "Forward",
    [HPPE_ACL_ACTION_DROP] = "Drop",
    [HPPE_ACL_ACTION_COPYCPU] = "Copy-to-cpu",
    [HPPE_ACL_ACTION_RDTCPU] = "Redirect-to-cpu",
  };
  table_t table = {};
  u32 row = 0;
  u32 indent;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 8, "Idx", "Ports", "Type", "Mac", "Mask", "Pri", "Action", "Hit");

  for (u32 index = 0; index < HPPE_ACL_TOTAL_ROWS; index++)
    {
      u32 rule_offset = HPPE_REG_IPO_RULE_REG (index);
      u32 mask_offset = HPPE_REG_IPO_MASK_REG (index);
      u32 action_offset = HPPE_REG_IPO_ACTION (index);
      u32 hit_pkt_cnt = qppe_mmio_read32 (qd, HPPE_REG_IPO_CNT_TBL (index));
      ppe_reg_ipo_rule_reg_t rule = {
	.val = {
	  qppe_mmio_read32 (qd, rule_offset),
	  qppe_mmio_read32 (qd, rule_offset + 4),
	  qppe_mmio_read32 (qd, rule_offset + 8),
	},
      };
      ppe_reg_ipo_mask_reg_t mask = {
	.val = {
	  qppe_mmio_read32 (qd, mask_offset),
	  qppe_mmio_read32 (qd, mask_offset + 4),
	},
      };
      ppe_reg_ipo_action_t action = {
	.val = {
	  qppe_mmio_read32 (qd, action_offset),
	  qppe_mmio_read32 (qd, action_offset + 4),
	  qppe_mmio_read32 (qd, action_offset + 8),
	  qppe_mmio_read32 (qd, action_offset + 12),
	  qppe_mmio_read32 (qd, action_offset + 16),
	},
      };
      u32 port_bitmap = rule.bf.src_0 | (rule.bf.src_1 << 1);
      u32 ctag_pcp = action.bf.ctag_pcp_0 | (action.bf.ctag_pcp_1 << 2);
      u32 service_code = action.bf.service_code_0 | (action.bf.service_code_1 << 1);
      u32 bypass_bitmap = action.bf.bypass_bitmap_0 | (action.bf.bypass_bitmap_1 << 14);
      u8 *action_str = 0;

      /* A port bitmap of 0 can never match any real ingress port, which is
       * the hardware reset state and the closest thing to "row not
       * configured". */
      if (port_bitmap == 0)
	continue;

      /* Same gating logic as format_qppe_acl_pre_ipo_tbl - see the
       * identical comment there. */
      if (action.bf.dest_info_change_en)
	{
	  action_str = format (action_str, "%s (%u)",
			       action.bf.fwd_cmd < ARRAY_LEN (qppe_acl_action_names) ?
				 qppe_acl_action_names[action.bf.fwd_cmd] :
				 "Other",
			       action.bf.fwd_cmd);
	  if (action.bf.fwd_cmd == HPPE_ACL_ACTION_COPYCPU ||
	      action.bf.fwd_cmd == HPPE_ACL_ACTION_RDTCPU)
	    action_str = format (action_str, ", dest_info=0x%x", action.bf.dest_info);
	}
      else
	action_str = format (action_str, "(no forwarding override)");
      if (action.bf.mirror_en)
	action_str = format (action_str, ", mirror");
      if (bypass_bitmap)
	action_str =
	  format (action_str, ", bypass_bitmap=%U", format_qppe_port_bitmap, bypass_bitmap);
      if (action.bf.svid_change_en)
	action_str =
	  format (action_str, ", svid=0x%x, stag_fmt=%u", action.bf.svid, action.bf.stag_fmt);
      if (action.bf.cvid_change_en)
	action_str =
	  format (action_str, ", cvid=0x%x, ctag_fmt=%u", action.bf.cvid, action.bf.ctag_fmt);
      if (action.bf.dscp_tc_change_en)
	action_str = format (action_str, ", dscp_tc=0x%x", action.bf.dscp_tc);
      if (action.bf.stag_pcp_change_en)
	action_str = format (action_str, ", stag_pcp=%u", action.bf.stag_pcp);
      if (action.bf.stag_dei_change_en)
	action_str = format (action_str, ", stag_dei=%u", action.bf.stag_dei);
      if (action.bf.ctag_pcp_change_en)
	action_str = format (action_str, ", ctag_pcp=%u", ctag_pcp);
      if (action.bf.ctag_dei_change_en)
	action_str = format (action_str, ", ctag_dei=%u", action.bf.ctag_dei);
      if (action.bf.enqueue_pri_change_en)
	action_str = format (action_str, ", enqueue_pri=%u", action.bf.enqueue_pri);
      if (action.bf.int_dp_change_en)
	action_str = format (action_str, ", int_dp=%u", action.bf.int_dp);
      if (action.bf.policer_en)
	action_str = format (action_str, ", policer_index=%u", action.bf.policer_index);
      if (action.bf.qid_en)
	action_str = format (action_str, ", qid=%u", action.bf.qid);
      if (action.bf.service_code_en)
	action_str = format (action_str, ", service_code=%u", service_code);
      if (action.bf.syn_toggle)
	action_str = format (action_str, ", syn_toggle");
      if (action.bf.cpu_code_en)
	action_str = format (action_str, ", cpu_code=%u", action.bf.cpu_code);
      if (action.bf.metadata_en)
	action_str = format (action_str, ", metadata_en");
      if (action.bf.dscp_tc_mask)
	action_str = format (action_str, ", dscp_tc_mask=0x%x", action.bf.dscp_tc_mask);
      if (action.bf.qos_res_prec)
	action_str = format (action_str, ", qos_res_prec=%u", action.bf.qos_res_prec);

      table_format_cell (&table, row, 0, "%u", index);
      table_format_cell (&table, row, 1, "%U", format_qppe_port_bitmap, port_bitmap);
      table_format_cell (&table, row, 2, "%s (%u)",
			 rule.bf.rule_type < ARRAY_LEN (qppe_acl_rule_type_names) ?
			   qppe_acl_rule_type_names[rule.bf.rule_type] :
			   "unknown",
			 rule.bf.rule_type);
      table_format_cell (&table, row, 3, "%02x:%02x:%02x:%02x:%02x:%02x", rule.bf.mac_addr_1 >> 8,
			 rule.bf.mac_addr_1 & 0xff, rule.bf.mac_addr_0 >> 24,
			 (rule.bf.mac_addr_0 >> 16) & 0xff, (rule.bf.mac_addr_0 >> 8) & 0xff,
			 rule.bf.mac_addr_0 & 0xff);
      table_format_cell (&table, row, 4, "%02x:%02x:%02x:%02x:%02x:%02x",
			 mask.bf.mac_addr_mask_1 >> 8, mask.bf.mac_addr_mask_1 & 0xff,
			 mask.bf.mac_addr_mask_0 >> 24, (mask.bf.mac_addr_mask_0 >> 16) & 0xff,
			 (mask.bf.mac_addr_mask_0 >> 8) & 0xff, mask.bf.mac_addr_mask_0 & 0xff);
      table_format_cell (&table, row, 5, "%u", rule.bf.pri);
      table_format_cell (&table, row, 6, "%v", action_str);
      vec_free (action_str);
      table_format_cell (&table, row, 7, "%u", hit_pkt_cnt);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      table_set_cell_align (&table, row, 2, TTAA_LEFT);
      table_set_cell_align (&table, row, 6, TTAA_LEFT);
      row++;
    }

  indent = format_get_indent (s);
  s = format (s, "ACL (IPO) rules:");
  if (row)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &table);
    }
  else
    s = format (s, " none configured");

  table_free (&table);
  return s;
}

typedef union
{
  u32 val[3];
  struct
  {
    u32 rule_field_0 : 32;
    u32 rule_field_1 : 20;
    u32 fake_mac_header : 1;
    u32 range_en : 1;
    u32 inverse_en : 1;
    u32 rule_type : 5;
    u32 src_type : 3;
    u32 src_0 : 1;
    u32 src_1 : 7;
    u32 pri : 9;
    u32 res_chain : 1;
    u32 inner_outer_sel : 1;
    u32 reserved_82_95 : 14;
  } bf;
} ppe_reg_pre_ipo_rule_reg_t;

typedef union
{
  u32 val[2];
  struct
  {
    u32 maskfield_0 : 32;
    u32 maskfield_1 : 21;
    u32 reserved_53_63 : 11;
  } bf;
} ppe_reg_pre_ipo_mask_reg_t;

typedef union
{
  u32 val[7];
  struct
  {
    u32 dest_info_change_en : 1;
    u32 fwd_cmd : 2;
    u32 dest_info : 14;
    u32 mirror_en : 1;
    u32 svid_change_en : 1;
    u32 stag_fmt : 1;
    u32 svid : 12;
    u32 cvid_change_en : 1;
    u32 ctag_fmt : 1;
    u32 cvid : 12;
    u32 dscp_tc_change_en : 1;
    u32 dscp_tc : 8;
    u32 stag_pcp_change_en : 1;
    u32 stag_pcp : 3;
    u32 stag_dei_change_en : 1;
    u32 stag_dei : 1;
    u32 ctag_pcp_change_en : 1;
    u32 ctag_pcp_0 : 2;
    u32 ctag_pcp_1 : 1;
    u32 ctag_dei_change_en : 1;
    u32 ctag_dei : 1;
    u32 enqueue_pri_change_en : 1;
    u32 enqueue_pri : 4;
    u32 int_dp_change_en : 1;
    u32 int_dp : 2;
    u32 policer_en : 1;
    u32 policer_index : 9;
    u32 qid_en : 1;
    u32 qid : 8;
    u32 service_code_en : 1;
    u32 service_code_0 : 1;
    u32 service_code_1 : 7;
    u32 syn_toggle : 1;
    u32 cpu_code_en : 1;
    u32 cpu_code : 8;
    u32 dscp_tc_mask : 8;
    u32 qos_res_prec : 3;
    u32 cascade_en : 1;
    u32 cascade_data_0 : 3;
    u32 cascade_data_1 : 4;
    u32 metadata_en : 1;
    u32 reserved_132 : 1;
    u32 nat_action : 3;
    u32 l4_port : 16;
    u32 vpn_valid : 1;
    u32 vpn_type : 1;
    u32 vpn_id_0 : 5;
    u32 vpn_id_1 : 1;
    u32 learn_dis : 1;
    u32 reserved_162_193 : 32;
    u32 reserved_194_223 : 30;
  } bf;
} ppe_reg_pre_ipo_action_t;

vnet_dev_rv_t
qppe_acl_pre_ipo_write_row (vnet_dev_t *dev, u32 row, const vnet_dev_hw_addr_t *addr,
			    u8 exact_match, u32 pri, u32 fwd_cmd, u32 port_bitmap)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (row);
  u32 mask_offset = APPE_REG_PRE_IPO_MASK_REG (row);
  u32 action_offset = APPE_REG_PRE_IPO_ACTION (row);
  u32 mac_mask = exact_match ? 0xffffffff : 0;
  ppe_reg_pre_ipo_rule_reg_t rule = {
    .bf = {
      .rule_field_0 = ((u32) addr->eth_mac[2] << 24) | ((u32) addr->eth_mac[3] << 16) |
		      ((u32) addr->eth_mac[4] << 8) | addr->eth_mac[5],
      .rule_field_1 = ((u32) addr->eth_mac[0] << 8) | addr->eth_mac[1],
      .rule_type = HPPE_ACL_RULE_TYPE_MAC_DA,
      .src_type = HPPE_ACL_SRC_TYPE_PORTBITMAP,
      .src_0 = port_bitmap & 1,
      .src_1 = port_bitmap >> 1,
      .pri = pri,
    },
  };
  /* bits 16-20 of maskfield_1 are the is_ip/is_ipv6/is_ethernet/is_snap/
   * fake_mac_header equivalents (unnamed here, but at the same bit
   * positions IPO's named mask fields occupy) - left at 0 (don't-care, per
   * this register's documented "1 = must match" mask convention) so this
   * stage only ever matches on the MAC_DA field; setting them to 1 would
   * require is_ethernet (etc.) to match rule_field_1's default-0 value
   * exactly, which no real Ethernet II frame satisfies. */
  ppe_reg_pre_ipo_mask_reg_t mask = {
    .bf = {
      .maskfield_0 = mac_mask,
      .maskfield_1 = mac_mask & 0xffff,
    },
  };
  /* dest_info_change_en set unconditionally, matching the vendor's own
   * action_sw_2_hw. Confirmed empirically: without it, fwd_cmd (forward or
   * drop) has no effect at all, hardware-side; dest_info's own value is
   * irrelevant for FORWARD/DROP, only consulted for COPYCPU/RDTCPU. */
  ppe_reg_pre_ipo_action_t action = {
    .bf = {
      .dest_info_change_en = 1,
      .fwd_cmd = fwd_cmd,
    },
  };
  u32 i;

  qppe_mmio_write32 (qd, rule_offset, rule.val[0]);
  qppe_mmio_write32 (qd, rule_offset + 4, rule.val[1]);
  qppe_mmio_write32 (qd, rule_offset + 8, rule.val[2]);
  qppe_mmio_write32 (qd, mask_offset, mask.val[0]);
  qppe_mmio_write32 (qd, mask_offset + 4, mask.val[1]);
  qppe_mmio_write32 (qd, action_offset, action.val[0]);
  for (i = 1; i < APPE_PRE_ACL_ACTION_WORDS; i++)
    qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

  if (qppe_mmio_read32 (qd, rule_offset) != rule.val[0] ||
      qppe_mmio_read32 (qd, rule_offset + 4) != rule.val[1] ||
      qppe_mmio_read32 (qd, rule_offset + 8) != rule.val[2] ||
      qppe_mmio_read32 (qd, mask_offset) != mask.val[0] ||
      qppe_mmio_read32 (qd, mask_offset + 4) != mask.val[1] ||
      qppe_mmio_read32 (qd, action_offset) != action.val[0])
    {
      log_err (dev, "Pre-IPO row %u readback failed at offset 0x%x", row, rule_offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "Pre-IPO row %u: dest MAC %U %s port bitmap 0x%x fwd_cmd %u pri %u", row,
	     format_vnet_dev_hw_addr, addr, exact_match ? "(exact)" : "(any)", port_bitmap, fwd_cmd,
	     pri);
  return VNET_DEV_OK;
}

/* Same TCAM-reset problem as IPO's qppe_acl_init - nothing else in this
 * driver's bring-up clears the Pre-IPO TCAM, so it must be done explicitly
 * before any port writes into it. */
vnet_dev_rv_t
qppe_acl_pre_ipo_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 index;

  for (index = 0; index < APPE_PRE_ACL_TOTAL_ROWS; index++)
    {
      u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (index);
      u32 mask_offset = APPE_REG_PRE_IPO_MASK_REG (index);
      u32 action_offset = APPE_REG_PRE_IPO_ACTION (index);
      u32 i;

      qppe_mmio_write32 (qd, rule_offset, 0);
      qppe_mmio_write32 (qd, rule_offset + 4, 0);
      qppe_mmio_write32 (qd, rule_offset + 8, 0);
      qppe_mmio_write32 (qd, mask_offset, 0);
      qppe_mmio_write32 (qd, mask_offset + 4, 0);
      for (i = 0; i < APPE_PRE_ACL_ACTION_WORDS; i++)
	qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

      if (qppe_mmio_read32 (qd, rule_offset) != 0 || qppe_mmio_read32 (qd, mask_offset) != 0 ||
	  qppe_mmio_read32 (qd, action_offset) != 0)
	{
	  log_err (dev, "Pre-IPO row %u clear readback failed at offset 0x%x", index, rule_offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  log_debug (dev, "cleared all %u Pre-IPO TCAM rows", APPE_PRE_ACL_TOTAL_ROWS);
  return VNET_DEV_OK;
}

/* Permit broadcast, permit this port's own primary MAC, deny everything
 * else - see the APPE_PRE_ACL_ROWS_PER_PORT comment above for the full
 * per-port row layout. Secondary MACs (qppe_port_secondary_mac_add/del in
 * port.c) and the promiscuous override row (written directly by port.c via
 * qppe_acl_pre_ipo_write_row) are managed separately, since they change
 * independently of the primary address. */
vnet_dev_rv_t
qppe_acl_pre_ipo_port_configure (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  static const vnet_dev_hw_addr_t bcast = {
    .eth_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
  };
  u32 port_bitmap = 1u << port->port_id;
  vnet_dev_rv_t rv;

  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_BCAST_ROW (port->port_id), &bcast,
				   /* exact_match */ 1, APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
				   port_bitmap);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_PRIMARY_ROW (port->port_id), addr,
				   /* exact_match */ 1, APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
				   port_bitmap);
  if (rv != VNET_DEV_OK)
    return rv;

  return qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_DENY_ROW (port->port_id), addr,
				     /* exact_match */ 0, APPE_ACL_PRI_DENY, HPPE_ACL_ACTION_DROP,
				     port_bitmap);
}

/* Reads back a Pre-IPO row's port bitmap and exact-match MAC - low-level
 * counterpart to qppe_acl_pre_ipo_write_row, used by port.c's secondary-MAC
 * slot scans. Mirrors the same decode format_qppe_acl_pre_ipo_tbl uses. */
void
qppe_acl_pre_ipo_read_row (vnet_dev_t *dev, u32 row, u32 *port_bitmap, vnet_dev_hw_addr_t *addr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (row);
  ppe_reg_pre_ipo_rule_reg_t rule = {
    .val = {
      qppe_mmio_read32 (qd, rule_offset),
      qppe_mmio_read32 (qd, rule_offset + 4),
      qppe_mmio_read32 (qd, rule_offset + 8),
    },
  };

  *port_bitmap = rule.bf.src_0 | (rule.bf.src_1 << 1);
  addr->eth_mac[0] = rule.bf.rule_field_1 >> 8;
  addr->eth_mac[1] = rule.bf.rule_field_1 & 0xff;
  addr->eth_mac[2] = rule.bf.rule_field_0 >> 24;
  addr->eth_mac[3] = (rule.bf.rule_field_0 >> 16) & 0xff;
  addr->eth_mac[4] = (rule.bf.rule_field_0 >> 8) & 0xff;
  addr->eth_mac[5] = rule.bf.rule_field_0 & 0xff;
}

u8 *
format_qppe_acl_pre_ipo_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  const char *const qppe_acl_rule_type_names[] = {
    "MAC_DA",
  };
  const char *const qppe_acl_action_names[] = {
    [HPPE_ACL_ACTION_FWD] = "Forward",
    [HPPE_ACL_ACTION_DROP] = "Drop",
    [HPPE_ACL_ACTION_COPYCPU] = "Copy-to-cpu",
    [HPPE_ACL_ACTION_RDTCPU] = "Redirect-to-cpu",
  };
  table_t table = {};
  u32 row = 0;
  u32 indent;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 8, "Idx", "Ports", "Type", "Mac", "Mask", "Pri", "Action", "Hit");

  for (u32 index = 0; index < APPE_PRE_ACL_ROWS_RESERVED; index++)
    {
      u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (index);
      u32 mask_offset = APPE_REG_PRE_IPO_MASK_REG (index);
      u32 action_offset = APPE_REG_PRE_IPO_ACTION (index);
      ppe_reg_pre_ipo_rule_reg_t rule = {
	.val = {
	  qppe_mmio_read32 (qd, rule_offset),
	  qppe_mmio_read32 (qd, rule_offset + 4),
	  qppe_mmio_read32 (qd, rule_offset + 8),
	},
      };
      ppe_reg_pre_ipo_mask_reg_t mask = {
	.val = {
	  qppe_mmio_read32 (qd, mask_offset),
	  qppe_mmio_read32 (qd, mask_offset + 4),
	},
      };
      ppe_reg_pre_ipo_action_t action = {
	.val = {
	  qppe_mmio_read32 (qd, action_offset),
	  qppe_mmio_read32 (qd, action_offset + 4),
	  qppe_mmio_read32 (qd, action_offset + 8),
	  qppe_mmio_read32 (qd, action_offset + 12),
	  qppe_mmio_read32 (qd, action_offset + 16),
	  qppe_mmio_read32 (qd, action_offset + 20),
	  qppe_mmio_read32 (qd, action_offset + 24),
	},
      };
      u32 hit_pkt_cnt = qppe_mmio_read32 (qd, APPE_REG_PRE_IPO_CNT_TBL (index));
      u32 port_bitmap = rule.bf.src_0 | (rule.bf.src_1 << 1);
      u32 ctag_pcp = action.bf.ctag_pcp_0 | (action.bf.ctag_pcp_1 << 2);
      u32 service_code = action.bf.service_code_0 | (action.bf.service_code_1 << 1);
      u32 cascade_data = action.bf.cascade_data_0 | (action.bf.cascade_data_1 << 3);
      u32 vpn_id = action.bf.vpn_id_0 | (action.bf.vpn_id_1 << 5);
      u8 *action_str = 0;

      if (port_bitmap == 0)
	continue;

      if (action.bf.dest_info_change_en)
	{
	  action_str = format (action_str, "%s (%u)",
			       action.bf.fwd_cmd < ARRAY_LEN (qppe_acl_action_names) ?
				 qppe_acl_action_names[action.bf.fwd_cmd] :
				 "Other",
			       action.bf.fwd_cmd);
	  if (action.bf.fwd_cmd == HPPE_ACL_ACTION_COPYCPU ||
	      action.bf.fwd_cmd == HPPE_ACL_ACTION_RDTCPU)
	    action_str = format (action_str, ", dest_info=0x%x", action.bf.dest_info);
	}
      else
	action_str = format (action_str, "(no forwarding override)");
      if (action.bf.mirror_en)
	action_str = format (action_str, ", mirror");
      if (action.bf.svid_change_en)
	action_str =
	  format (action_str, ", svid=0x%x, stag_fmt=%u", action.bf.svid, action.bf.stag_fmt);
      if (action.bf.cvid_change_en)
	action_str =
	  format (action_str, ", cvid=0x%x, ctag_fmt=%u", action.bf.cvid, action.bf.ctag_fmt);
      if (action.bf.dscp_tc_change_en)
	action_str = format (action_str, ", dscp_tc=0x%x", action.bf.dscp_tc);
      if (action.bf.stag_pcp_change_en)
	action_str = format (action_str, ", stag_pcp=%u", action.bf.stag_pcp);
      if (action.bf.stag_dei_change_en)
	action_str = format (action_str, ", stag_dei=%u", action.bf.stag_dei);
      if (action.bf.ctag_pcp_change_en)
	action_str = format (action_str, ", ctag_pcp=%u", ctag_pcp);
      if (action.bf.ctag_dei_change_en)
	action_str = format (action_str, ", ctag_dei=%u", action.bf.ctag_dei);
      if (action.bf.enqueue_pri_change_en)
	action_str = format (action_str, ", enqueue_pri=%u", action.bf.enqueue_pri);
      if (action.bf.int_dp_change_en)
	action_str = format (action_str, ", int_dp=%u", action.bf.int_dp);
      if (action.bf.policer_en)
	action_str = format (action_str, ", policer_index=%u", action.bf.policer_index);
      if (action.bf.qid_en)
	action_str = format (action_str, ", qid=%u", action.bf.qid);
      if (action.bf.service_code_en)
	action_str = format (action_str, ", service_code=%u", service_code);
      if (action.bf.syn_toggle)
	action_str = format (action_str, ", syn_toggle");
      if (action.bf.cpu_code_en)
	action_str = format (action_str, ", cpu_code=%u", action.bf.cpu_code);
      if (action.bf.dscp_tc_mask)
	action_str = format (action_str, ", dscp_tc_mask=0x%x", action.bf.dscp_tc_mask);
      if (action.bf.qos_res_prec)
	action_str = format (action_str, ", qos_res_prec=%u", action.bf.qos_res_prec);
      if (action.bf.cascade_en)
	action_str = format (action_str, ", cascade_data=%u", cascade_data);
      if (action.bf.metadata_en)
	action_str = format (action_str, ", metadata_en");
      if (action.bf.nat_action)
	action_str = format (action_str, ", nat_action=%u", action.bf.nat_action);
      if (action.bf.l4_port)
	action_str = format (action_str, ", l4_port=%u", action.bf.l4_port);
      if (action.bf.vpn_valid)
	action_str = format (action_str, ", vpn_type=%u, vpn_id=%u", action.bf.vpn_type, vpn_id);
      if (action.bf.learn_dis)
	action_str = format (action_str, ", learn_dis");

      table_format_cell (&table, row, 0, "%u", index);
      table_format_cell (&table, row, 1, "%U", format_qppe_port_bitmap, port_bitmap);
      table_format_cell (&table, row, 2, "%s (%u)",
			 rule.bf.rule_type < ARRAY_LEN (qppe_acl_rule_type_names) ?
			   qppe_acl_rule_type_names[rule.bf.rule_type] :
			   "unknown",
			 rule.bf.rule_type);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      table_set_cell_align (&table, row, 2, TTAA_LEFT);
      table_set_cell_align (&table, row, 6, TTAA_LEFT);
      table_format_cell (&table, row, 3, "%02x:%02x:%02x:%02x:%02x:%02x", rule.bf.rule_field_1 >> 8,
			 rule.bf.rule_field_1 & 0xff, rule.bf.rule_field_0 >> 24,
			 (rule.bf.rule_field_0 >> 16) & 0xff, (rule.bf.rule_field_0 >> 8) & 0xff,
			 rule.bf.rule_field_0 & 0xff);
      table_format_cell (&table, row, 4, "%02x:%02x:%02x:%02x:%02x:%02x",
			 (mask.bf.maskfield_1 >> 8) & 0xff, mask.bf.maskfield_1 & 0xff,
			 mask.bf.maskfield_0 >> 24, (mask.bf.maskfield_0 >> 16) & 0xff,
			 (mask.bf.maskfield_0 >> 8) & 0xff, mask.bf.maskfield_0 & 0xff);
      table_format_cell (&table, row, 5, "%u", rule.bf.pri);
      table_format_cell (&table, row, 6, "%v", action_str);
      vec_free (action_str);
      table_format_cell (&table, row, 7, "%u", hit_pkt_cnt);
      row++;
    }

  indent = format_get_indent (s);
  s = format (s, "Pre-IPO rules (hit %u miss %u bypass %u):",
	      qppe_mmio_read32 (qd, APPE_REG_PRE_IPO_GLB_HIT_COUNTER),
	      qppe_mmio_read32 (qd, APPE_REG_PRE_IPO_GLB_MISS_COUNTER),
	      qppe_mmio_read32 (qd, APPE_REG_PRE_IPO_GLB_BYPASS_COUNTER));
  if (row)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &table);
    }
  else
    s = format (s, " none configured");

  table_free (&table);
  return s;
}
