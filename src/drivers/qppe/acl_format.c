/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static u8 *
format_qppe_acl_rule_type_name (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);

  if (type == HPPE_ACL_RULE_TYPE_MAC_DA)
    return format (s, "MAC_DA (%u)", type);

  return format (s, "Unknown(%u)", type);
}

static u8 *
format_qppe_acl_action_name (u8 *s, va_list *args)
{
  u32 action = va_arg (*args, u32);
  static const char *const names[] = {
    [HPPE_ACL_ACTION_FWD] = "Forward",
    [HPPE_ACL_ACTION_DROP] = "Drop",
    [HPPE_ACL_ACTION_COPYCPU] = "Copy-to-cpu",
    [HPPE_ACL_ACTION_RDTCPU] = "Redirect-to-cpu",
  };

  if (action < ARRAY_LEN (names))
    return format (s, "%s (%u)", names[action], action);

  return format (s, "Unknown(%u)", action);
}

static u8 *
format_qppe_acl_forwarding (u8 *s, va_list *args)
{
  u32 dest_info_change_en = va_arg (*args, u32);
  u32 fwd_cmd = va_arg (*args, u32);
  u32 dest_info = va_arg (*args, u32);
  u32 mirror_en = va_arg (*args, u32);

  if (dest_info_change_en)
    {
      s = format (s, "%U", format_qppe_acl_action_name, fwd_cmd);
      if (fwd_cmd == HPPE_ACL_ACTION_COPYCPU || fwd_cmd == HPPE_ACL_ACTION_RDTCPU)
	s = format (s, ", dest_info=0x%x", dest_info);
    }
  else
    s = format (s, "(no forwarding override)");
  if (mirror_en)
    s = format (s, ", mirror");

  return s;
}

u8 *
format_qppe_acl_ipo_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
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

      if (port_bitmap == 0)
	continue;

      action_str =
	format (action_str, "%U", format_qppe_acl_forwarding, action.bf.dest_info_change_en,
		action.bf.fwd_cmd, action.bf.dest_info, action.bf.mirror_en);
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
      table_format_cell (&table, row, 2, "%U", format_qppe_acl_rule_type_name, rule.bf.rule_type);
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
  s = format (s, "IPO rules:");
  s = format_newline (s, indent + 2);
  if (row)
    s = format (s, "%U", format_table, &table);
  else
    s = format (s, "none configured");

  table_free (&table);
  return s;
}

u8 *
format_qppe_acl_pre_ipo_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
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

      action_str =
	format (action_str, "%U", format_qppe_acl_forwarding, action.bf.dest_info_change_en,
		action.bf.fwd_cmd, action.bf.dest_info, action.bf.mirror_en);
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
      table_format_cell (&table, row, 2, "%U", format_qppe_acl_rule_type_name, rule.bf.rule_type);
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
  s = format_newline (s, indent + 2);
  if (row)
    s = format (s, "%U", format_table, &table);
  else
    s = format (s, "none configured");

  table_free (&table);
  return s;
}
