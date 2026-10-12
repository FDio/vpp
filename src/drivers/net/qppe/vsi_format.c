/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static u8 *
format_qppe_vsi_forward_cmd (u8 *s, va_list *args)
{
  u32 cmd = va_arg (*args, u32);
  const char *const names[] = {
    "forward",
    "drop",
    "copy-to-cpu",
    "redirect-to-cpu",
  };

  if (cmd < ARRAY_LEN (names))
    return format (s, "%s (%u)", names[cmd], cmd);
  return format (s, "Unknown(%u)", cmd);
}

static void
qppe_vsi_read_words (qppe_device_t *qd, u32 base, u32 *words, u32 n_words)
{
  for (u32 w = 0; w < n_words; w++)
    words[w] = qppe_mmio_read32 (qd, base + w * sizeof (u32));
}

static void
qppe_vsi_table_range (table_t *table, u32 row, u32 col, u32 first, u32 last)
{
  if (first == last)
    table_format_cell (table, row, col, "%u", first);
  else
    table_format_cell (table, row, col, "%u-%u", first, last);
}

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

static u8 *
format_qppe_xlt_ports (u8 *s, va_list *args)
{
  u32 port_type = va_arg (*args, u32);
  u32 raw = va_arg (*args, u32);

  switch (port_type)
    {
    case 0:
      return format (s, "ports=%U", format_qppe_port_bitmap, raw);
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

static u8 *
format_qppe_vsi_frame_type (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);
  const char *const names[] = {
    "Ethernet",
    "RFC1024",
    "LLC-other",
    "Ethernet-or-RFC1024",
  };

  if (type < ARRAY_LEN (names))
    return format (s, "%s (%u)", names[type], type);
  return format (s, "Unknown(%u)", type);
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
      return format (s, "Unknown(%u)", cmd);
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
      return format (s, "Unknown(%u)", cmd);
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
      return format (s, "Unknown(%u)", cmd);
    }
}

u8 *
format_qppe_rule_and_action_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent, n_rules = 0;
  u32 entries[HPPE_XLT_RULE_TBL_ENTRIES][7];

  if (!qd->regs)
    return s;

  indent = format_get_indent (s);
  s = format (s, "XLT_RULE_TBL/XLT_ACTION_TBL:");

  for (u32 idx = 0; idx < HPPE_XLT_RULE_TBL_ENTRIES; idx++)
    {
      qppe_vsi_read_words (qd, HPPE_REG_XLT_RULE_TBL (idx), entries[idx], 4);
      qppe_vsi_read_words (qd, HPPE_REG_XLT_ACTION_TBL (idx), entries[idx] + 4, 3);
      entries[idx][3] &= 0x1fff;
      entries[idx][6] &= 0xf;
    }

  for (u32 idx = 0; idx < HPPE_XLT_RULE_TBL_ENTRIES; idx++)
    {
      u32 first = idx;
      ppe_reg_xlt_rule_tbl_w0_t rw0 = { .as_u32 = entries[idx][0] };
      ppe_reg_xlt_rule_tbl_w1_t rw1;
      ppe_reg_xlt_rule_tbl_w2_t rw2;
      ppe_reg_xlt_rule_tbl_w3_t rw3;
      ppe_reg_xlt_action_tbl_w0_t aw0;
      ppe_reg_xlt_action_tbl_w1_t aw1;
      ppe_reg_xlt_action_tbl_w2_t aw2;
      u32 ckey_fmt, prot_value, vni_resv, xlt_spcp, counter_id;
      u8 *key = 0, *action = 0;

      if (!rw0.valid)
	continue;

      rw1.as_u32 = entries[idx][1];
      rw2.as_u32 = entries[idx][2];
      rw3.as_u32 = entries[idx][3];
      aw0.as_u32 = entries[idx][4];
      aw1.as_u32 = entries[idx][5];
      aw2.as_u32 = entries[idx][6];

      while (idx + 1 < HPPE_XLT_RULE_TBL_ENTRIES &&
	     !memcmp (entries[first], entries[idx + 1], sizeof (entries[first])))
	idx++;
      n_rules++;
      ckey_fmt = rw0.ckey_fmt_0 | (rw1.ckey_fmt_1 << 1);
      prot_value = rw1.prot_value_0 | (rw2.prot_value_1 << 7);
      vni_resv = rw2.vni_resv_0 | (rw3.vni_resv_1 << 19);
      xlt_spcp = aw0.xlt_spcp_0 | (aw1.xlt_spcp_1 << 1);
      counter_id = aw1.counter_id_0 | (aw2.counter_id_1 << 3);

      s = format_newline (s, indent + 2);
      if (first == idx)
	s = format (s, "Index %u:", first);
      else
	s = format (s, "Index %u-%u:", first, idx);

      s = format_newline (s, indent + 4);
      s = format (s, "Rule:");

      /* Port/VP zero is meaningful; other key fields have explicit include gates. */
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
	key =
	  format (key, "%sfrm_type=%U", key ? ", " : "", format_qppe_vsi_frame_type, rw1.frm_type);
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
	action = format (action, "%ssrc_info=%s:%u", action ? ", " : "",
			 aw1.src_info_type ? "l3_if" : "vp", aw1.src_info);
      if (action)
	s = format (s, " %v", action);
      else
	s = format (s, " (none)");
      vec_free (action);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
    }
  if (!n_rules)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "none configured");
    }
  return s;
}

u8 *
format_qppe_vsi_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 9, "vsi", "member", "unknown", "unknown", "broadcast", "new_addr",
		     "new_addr", "station_move", "station_move");
  table_add_hdr_row (&table, 9, "", "ports", "unicast", "multicast", "ports", "lrn_en", "fwd_cmd",
		     "lrn_en", "fwd_cmd");
  for (u32 vsi = 0; vsi < HPPE_VSI_TBL_ENTRIES; vsi++)
    {
      u32 first = vsi;
      ppe_reg_vsi_tbl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_VSI_TBL_W0 (vsi)) };
      ppe_reg_vsi_tbl_w1_t w1;

      w1.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_VSI_TBL_W0 (vsi) + sizeof (u32));
      w1.reserved_6_31 = 0;

      while (vsi + 1 < HPPE_VSI_TBL_ENTRIES)
	{
	  ppe_reg_vsi_tbl_w0_t next_w0 = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_VSI_TBL_W0 (vsi + 1)),
	  };
	  ppe_reg_vsi_tbl_w1_t next_w1;

	  next_w1.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_VSI_TBL_W0 (vsi + 1) + sizeof (u32));
	  next_w1.reserved_6_31 = 0;
	  if (next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32)
	    break;
	  vsi++;
	}

      if (first == vsi)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, vsi);
      table_format_cell (&table, row, 1, "%U", format_qppe_port_bitmap, w0.member_port_bitmap);
      table_format_cell (&table, row, 2, "%U", format_qppe_port_bitmap, w0.uuc_bitmap);
      table_format_cell (&table, row, 3, "%U", format_qppe_port_bitmap, w0.umc_bitmap);
      table_format_cell (&table, row, 4, "%U", format_qppe_port_bitmap, w0.bc_bitmap);
      table_format_cell (&table, row, 5, "%u", w1.new_addr_lrn_en);
      table_format_cell (&table, row, 6, "%U", format_qppe_vsi_forward_cmd, w1.new_addr_fwd_cmd);
      table_format_cell (&table, row, 7, "%u", w1.station_move_lrn_en);
      table_format_cell (&table, row, 8, "%U", format_qppe_vsi_forward_cmd,
			 w1.station_move_fwd_cmd);
      row++;
    }
  s = format (s, "VSI_TBL:");
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
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "vsi", "remap_en", "member VPs", "br_vsi");
  for (u32 vsi = 0; vsi < APPE_VSI_REMAP_TBL_ENTRIES; vsi++)
    {
      u32 first = vsi, words[9];
      uword *member_bitmap = 0;
      ppe_reg_vsi_remap_tbl_w8_t w8;

      qppe_vsi_read_words (qd, APPE_REG_VSI_REMAP_TBL (vsi), words, ARRAY_LEN (words));
      words[8] &= 0x7f;
      while (vsi + 1 < APPE_VSI_REMAP_TBL_ENTRIES)
	{
	  u32 next[9];

	  qppe_vsi_read_words (qd, APPE_REG_VSI_REMAP_TBL (vsi + 1), next, ARRAY_LEN (next));
	  next[8] &= 0x7f;
	  if (memcmp (words, next, sizeof (words)))
	    break;
	  vsi++;
	}
      w8.as_u32 = words[8];
      for (u32 w = 0; w < 8; w++)
	member_bitmap = clib_bitmap_set_multiple (member_bitmap, w * 32, words[w], 32);
      qppe_vsi_table_range (&table, row, 0, first, vsi);
      table_format_cell (&table, row, 1, "%u", w8.vsi_remap_en);
      table_format_cell (&table, row, 2, "%U", format_bitmap_list, member_bitmap);
      table_format_cell (&table, row, 3, "%u", w8.br_vsi);
      clib_bitmap_free (member_bitmap);
      row++;
    }
  s = format (s, "VSI_REMAP_TBL:");
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
  u32 words[APPE_PORT_VSI_ENQUEUE_MAP_ENTRIES];
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  for (u32 i = 0; i < ARRAY_LEN (words); i++)
    words[i] = qppe_mmio_read32 (qd, APPE_REG_PORT_VSI_ENQUEUE_MAP_INDEX (i)) & 0x1ff;
  table_add_hdr_row (&table, 5, "key", "port", "VSI/profile", "en", "enqueue VP");
  for (u32 port = 0; port < QPPE_MAX_PORTS; port++)
    {
      u32 first_port = port;
      u32 *entries = words + port * HPPE_VSI_TBL_ENTRIES;

      while (port + 1 < QPPE_MAX_PORTS &&
	     !memcmp (entries, words + (port + 1) * HPPE_VSI_TBL_ENTRIES,
		      HPPE_VSI_TBL_ENTRIES * sizeof (words[0])))
	port++;
      for (u32 vsi = 0; vsi < HPPE_VSI_TBL_ENTRIES; vsi++)
	{
	  u32 first = vsi;
	  ppe_reg_port_vsi_enqueue_map_t value = {
	    .as_u32 = entries[vsi],
	  };

	  while (vsi + 1 < HPPE_VSI_TBL_ENTRIES && entries[vsi + 1] == entries[first])
	    vsi++;
	  table_format_cell (&table, row, 0, "VSI");
	  qppe_vsi_table_range (&table, row, 1, first_port, port);
	  qppe_vsi_table_range (&table, row, 2, first, vsi);
	  table_format_cell (&table, row, 3, "%u", value.enqueue_valid);
	  table_format_cell (&table, row, 4, "%u", value.enqueue_vp);
	  row++;
	}
    }
  for (u32 i = APPE_FLOW_ENQUEUE_MAP_BASE; i < ARRAY_LEN (words); i++)
    {
      u32 first = i;
      ppe_reg_port_vsi_enqueue_map_t value = {
	.as_u32 = words[i],
      };

      while (i + 1 < ARRAY_LEN (words) && words[i + 1] == words[first])
	i++;
      table_format_cell (&table, row, 0, "flow");
      table_format_cell (&table, row, 1, "-");
      qppe_vsi_table_range (&table, row, 2, first - APPE_FLOW_ENQUEUE_MAP_BASE,
			    i - APPE_FLOW_ENQUEUE_MAP_BASE);
      table_format_cell (&table, row, 3, "%u", value.enqueue_valid);
      table_format_cell (&table, row, 4, "%u", value.enqueue_vp);
      row++;
    }
  s = format (s, "PORT_VSI_ENQUEUE_MAP:");
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
  u32 indent;

  if (!qd->regs)
    return s;

  indent = format_get_indent (s);
  s = format (s, "L2_VP_PORT_TBL (per-port VP membership/fallback):");

  for (u32 idx = 0; idx < APPE_L2_VP_PORT_TBL_ENTRIES; idx++)
    {
      u32 first = idx;
      u32 offset = APPE_REG_L2_VP_PORT_TBL_W0 (idx);
      ppe_reg_l2_vp_port_tbl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_l2_vp_port_tbl_w1_t w1;
      ppe_reg_l2_vp_port_tbl_w2_t w2;
      ppe_reg_l2_vp_port_tbl_w3_t w3;
      u32 app_ctrl_profile;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      w3.as_u32 = qppe_mmio_read32 (qd, offset + 12);
      w3.reserved_2_31 = 0;
      while (idx + 1 < APPE_L2_VP_PORT_TBL_ENTRIES)
	{
	  u32 next[4];

	  qppe_vsi_read_words (qd, APPE_REG_L2_VP_PORT_TBL_W0 (idx + 1), next, ARRAY_LEN (next));
	  next[3] &= 3;
	  if (next[0] != w0.as_u32 || next[1] != w1.as_u32 || next[2] != w2.as_u32 ||
	      next[3] != w3.as_u32)
	    break;
	  idx++;
	}
      app_ctrl_profile = w2.app_ctrl_profile_0 | (w3.app_ctrl_profile_1 << 6);

      s = format_newline (s, indent + 2);
      if (first == idx)
	s = format (s, "Index %u:", first);
      else
	s = format (s, "Index %u-%u:", first, idx);

      s = format_newline (s, indent + 4);
      s = format (s,
		  "VSI fallback: invalid_vsi_fwd_en=%u, promisc_en=%u, dst_info(VP)=%u, "
		  "physical_port=%u",
		  w0.invalid_vsi_forwarding_en, w0.promisc_en, w0.dst_info, w0.physical_port);

      s = format_newline (s, indent + 4);
      s =
	format (s,
		"Learning: new_addr_lrn_en=%u, new_addr_fwd_cmd=%U, station_move_lrn_en=%u, "
		"station_move_fwd_cmd=%U, lrn_lmt_cnt=%u, lrn_lmt_en=%u, "
		"lrn_lmt_exceed_fwd=%U",
		w0.new_addr_lrn_en, format_qppe_vsi_forward_cmd, w0.new_addr_fwd_cmd,
		w0.station_move_lrn_en, format_qppe_vsi_forward_cmd, w0.station_move_fwd_cmd,
		w0.lrn_lmt_cnt, w0.lrn_lmt_en, format_qppe_vsi_forward_cmd, w1.lrn_lmt_exceed_fwd);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);

      s = format_newline (s, indent + 4);
      s = format (s, "Isolation: ports=%U, isol_profile=%u, isol_profile_en=%u",
		  format_qppe_port_bitmap, w1.port_isolation_bitmap, w1.isol_profile,
		  w1.isol_profile_en);

      s = format_newline (s, indent + 4);
      s = format (s, "Policer: policer_en=%u, policer_index=%u", w1.policer_en, w1.policer_index);

      s = format_newline (s, indent + 4);
      s = format (s,
		  "VP state: vp_state_check_en=%u, vp_type=%s, vp_context_active=%u, "
		  "vp_eg_data_valid=%u",
		  w1.vp_state_check_en, w1.vp_type ? "normal" : "tunnel", w1.vp_context_active,
		  w1.vp_eg_data_valid);

      s = format_newline (s, indent + 4);
      s = format (s, "MTU: physical_port_mtu_check_en=%u, mtu_check_type=%s, extra_header_len=%u",
		  w2.physical_port_mtu_check_en, w2.mtu_check_type ? "IP" : "Ethernet",
		  w2.extra_header_len);
      s = format_newline (s, indent + 4);
      s = format (s,
		  "VLAN: eg_vlan_fltr_cmd=%u, eg_vlan_fmt_valid=%u, eg_stag_fmt=%u, "
		  "eg_ctag_fmt=%u, exception_fmt_ctrl=%u",
		  w1.eg_vlan_fltr_cmd, w2.eg_vlan_fmt_valid, w2.eg_stag_fmt, w2.eg_ctag_fmt,
		  w2.exception_fmt_ctrl);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
      s = format_newline (s, indent + 4);
      s = format (s,
		  "Enqueue: enq_service_code_en=%u, enq_service_code=%u, enq_phy_port=%u, "
		  "app_ctrl_profile=%u",
		  w2.enq_service_code_en, w2.enq_service_code, w2.enq_phy_port, app_ctrl_profile);
    }
  return s;
}

u8 *
format_qppe_vsi_vp_learning (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "VP", "learned");
  for (u32 vp = 0; vp < APPE_L2_VP_PORT_TBL_ENTRIES; vp++)
    {
      u32 first = vp;
      u32 value = qppe_mmio_read32 (qd, APPE_REG_VP_LRN_LIMIT_COUNTER (vp)) & 0xfff;

      while (vp + 1 < APPE_L2_VP_PORT_TBL_ENTRIES &&
	     (qppe_mmio_read32 (qd, APPE_REG_VP_LRN_LIMIT_COUNTER (vp + 1)) & 0xfff) == value)
	vp++;
      qppe_vsi_table_range (&table, row, 0, first, vp);
      table_format_cell (&table, row, 1, "%u", value);
      row++;
    }
  s = format (s, "VP_LRN_LIMIT_COUNTER:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_vsi_vp_isolation (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "profile", "VP profiles");
  for (u32 profile = 0; profile < APPE_VP_ISOL_TBL_ENTRIES; profile++)
    {
      u32 first = profile, words[2];
      uword *bitmap = 0;

      qppe_vsi_read_words (qd, APPE_REG_VP_ISOL_TBL (profile), words, ARRAY_LEN (words));
      while (profile + 1 < APPE_VP_ISOL_TBL_ENTRIES)
	{
	  u32 next[2];

	  qppe_vsi_read_words (qd, APPE_REG_VP_ISOL_TBL (profile + 1), next, ARRAY_LEN (next));
	  if (memcmp (words, next, sizeof (words)))
	    break;
	  profile++;
	}
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	bitmap = clib_bitmap_set_multiple (bitmap, w * 32, words[w], 32);
      qppe_vsi_table_range (&table, row, 0, first, profile);
      table_format_cell (&table, row, 1, "%U", format_bitmap_list, bitmap);
      clib_bitmap_free (bitmap);
      row++;
    }
  s = format (s, "VP_ISOL_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

/* Two bits per port; APPE stores eight VPs per word and 32 words per VSI. */
static u8 *
qppe_vsi_format_egress_tags (u8 *s, vnet_dev_t *dev, u32 is_vp)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u16 maps[HPPE_VSI_TBL_ENTRIES][APPE_L2_VP_PORT_TBL_ENTRIES / 8];
  const char *const modes[] = {
    "untagged",
    "tagged",
    "unmodified",
    "untouched",
  };
  u32 n_ports = is_vp ? APPE_L2_VP_PORT_TBL_ENTRIES : QPPE_MAX_PORTS;
  u32 n_words = n_ports / 8;
  u32 row = 0, indent = format_get_indent (s);

  for (u32 vsi = 0; vsi < HPPE_VSI_TBL_ENTRIES; vsi++)
    for (u32 w = 0; w < n_words; w++)
      {
	u32 reg = is_vp ? APPE_REG_EG_VSI_VP_TAG (vsi * n_words + w) : HPPE_REG_EG_VSI_TAG (vsi);

	maps[vsi][w] = qppe_mmio_read32 (qd, reg);
      }
  table_add_hdr_row (&table, 3, "VSI", is_vp ? "VP" : "port", "tag mode");
  for (u32 vsi = 0; vsi < HPPE_VSI_TBL_ENTRIES; vsi++)
    {
      u32 first_vsi = vsi;

      while (vsi + 1 < HPPE_VSI_TBL_ENTRIES &&
	     !memcmp (maps[first_vsi], maps[vsi + 1], n_words * sizeof (maps[0][0])))
	vsi++;
      for (u32 port = 0; port < n_ports; port++)
	{
	  u32 first_port = port;
	  u32 mode = (maps[first_vsi][port / 8] >> (2 * (port % 8))) & 3;

	  while (port + 1 < n_ports &&
		 ((maps[first_vsi][(port + 1) / 8] >> (2 * ((port + 1) % 8))) & 3) == mode)
	    port++;
	  qppe_vsi_table_range (&table, row, 0, first_vsi, vsi);
	  qppe_vsi_table_range (&table, row, 1, first_port, port);
	  table_format_cell (&table, row, 2, "%s (%u)", modes[mode], mode);
	  row++;
	}
    }
  s = format (s, "%s:", is_vp ? "EG_VSI_VP_TAG" : "EG_VSI_TAG");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_vsi_egress_tags (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  s = qppe_vsi_format_egress_tags (s, dev, 0);
  s = format (s, "\n");
  s = format_newline (s, indent);
  return qppe_vsi_format_egress_tags (s, dev, 1);
}

u8 *
format_qppe_vsi_l3_vp_port_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  s = format (s, "L3_VP_PORT_TBL:");
  for (u32 vp = 0; vp < HPPE_L3_VP_PORT_TBL_ENTRIES; vp++)
    {
      ppe_reg_vsi_l3_vp_port_t value;
      u32 first = vp;
      u64 mac;

      qppe_vsi_read_words (qd, HPPE_REG_L3_VP_PORT_TBL (vp), value.words, ARRAY_LEN (value.words));
      value._reserved0 = 0;
      while (vp + 1 < HPPE_L3_VP_PORT_TBL_ENTRIES)
	{
	  ppe_reg_vsi_l3_vp_port_t next;

	  qppe_vsi_read_words (qd, HPPE_REG_L3_VP_PORT_TBL (vp + 1), next.words,
			       ARRAY_LEN (next.words));
	  next._reserved0 = 0;
	  if (memcmp (value.words, next.words, sizeof (value.words)))
	    break;
	  vp++;
	}
      s = format_newline (s, indent + 2);
      if (first == vp)
	s = format (s, "VP %u:", first);
      else
	s = format (s, "VP %u-%u:", first, vp);
      s = format_newline (s, indent + 4);
      s = format (s, "l3_if_valid=%u, l3_if_index=%u, vsi_valid=%u, vsi=%u, ipo_vp_profile=%u",
		  value.l3_if_valid, value.l3_if_index, value.vsi_valid, value.vsi,
		  value.ipo_vp_profile);
      mac = value.mac_da_0 | ((u64) value.mac_da_1 << 15) | ((u64) value.mac_da_2 << 47);
      {
	vnet_dev_hw_addr_t addr;

	for (u32 i = 0; i < ARRAY_LEN (addr.eth_mac); i++)
	  addr.eth_mac[i] = mac >> (8 * (5 - i));
	s = format_newline (s, indent + 4);
	s = format (s, "mac_valid=%u, mac_da=%U", value.mac_valid, format_vnet_dev_hw_addr, &addr);
      }
      s = format_newline (s, indent + 4);
      s = format (s,
		  "IPv4: sg_en=%u, sg_vio_cmd=%U, sg_port_en=%u, sg_svlan_en=%u, "
		  "sg_cvlan_en=%u, src_unk_cmd=%U",
		  value.ipv4_sg_en, format_qppe_vsi_forward_cmd, value.ipv4_sg_vio_cmd,
		  value.ipv4_sg_port_en, value.ipv4_sg_svlan_en, value.ipv4_sg_cvlan_en,
		  format_qppe_vsi_forward_cmd, value.ipv4_src_unk_cmd);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
      s = format_newline (s, indent + 4);
      s = format (s,
		  "IPv6: sg_en=%u, sg_vio_cmd=%U, sg_port_en=%u, sg_svlan_en=%u, "
		  "sg_cvlan_en=%u, src_unk_cmd=%U",
		  value.ipv6_sg_en, format_qppe_vsi_forward_cmd, value.ipv6_sg_vio_cmd,
		  value.ipv6_sg_port_en, value.ipv6_sg_svlan_en, value.ipv6_sg_cvlan_en,
		  format_qppe_vsi_forward_cmd, value.ipv6_src_unk_cmd);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
      s = format_newline (s, indent + 4);
      s = format (s,
		  "ARP: sg_en=%u, sg_vio_cmd=%U, sg_port_en=%u, sg_svlan_en=%u, "
		  "sg_cvlan_en=%u, src_unk_cmd=%U",
		  value.ip_arp_sg_en, format_qppe_vsi_forward_cmd, value.ip_arp_sg_vio_cmd,
		  value.ip_arp_sg_port_en, value.ip_arp_sg_svlan_en, value.ip_arp_sg_cvlan_en,
		  format_qppe_vsi_forward_cmd, value.ip_arp_src_unk_cmd);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
      s = format_newline (s, indent + 4);
      s = format (s,
		  "ND: sg_en=%u, sg_vio_cmd=%U, sg_port_en=%u, sg_svlan_en=%u, "
		  "sg_cvlan_en=%u, src_unk_cmd=%U",
		  value.ip_nd_sg_en, format_qppe_vsi_forward_cmd, value.ip_nd_sg_vio_cmd,
		  value.ip_nd_sg_port_en, value.ip_nd_sg_svlan_en, value.ip_nd_sg_cvlan_en,
		  format_qppe_vsi_forward_cmd, value.ip_nd_src_unk_cmd);
      s = format_word_wrap_last_line_with_indent (s, 100, 2);
    }
  return s;
}

/* These tables are not maintained by the driver's per-port counters. */
u8 *
format_qppe_vsi_counters (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  for (u32 egress = 0; egress < 2; egress++)
    {
      table_t table = {};
      u32 count = egress ? HPPE_VSI_TBL_ENTRIES : HPPE_VLAN_CNT_TBL_ENTRIES;
      u32 row = 0;

      table_add_hdr_row (&table, 3, "VSI", egress ? "TX packets" : "RX packets",
			 egress ? "TX bytes" : "RX bytes");
      for (u32 i = 0; i < count; i++)
	{
	  u32 first = i, words[3];
	  u32 reg = egress ? HPPE_REG_EG_VSI_COUNTER_TBL (i) : HPPE_REG_VLAN_CNT_TBL (i);
	  u64 bytes;

	  qppe_vsi_read_words (qd, reg, words, ARRAY_LEN (words));
	  words[2] &= 0xff;
	  while (i + 1 < count)
	    {
	      u32 next[3];
	      u32 next_reg =
		egress ? HPPE_REG_EG_VSI_COUNTER_TBL (i + 1) : HPPE_REG_VLAN_CNT_TBL (i + 1);

	      qppe_vsi_read_words (qd, next_reg, next, ARRAY_LEN (next));
	      next[2] &= 0xff;
	      if (memcmp (words, next, sizeof (words)))
		break;
	      i++;
	    }
	  bytes = words[1] | ((u64) words[2] << 32);
	  qppe_vsi_table_range (&table, row, 0, first, i);
	  table_format_cell (&table, row, 1, "%u", words[0]);
	  table_format_cell (&table, row, 2, "%llu", bytes);
	  row++;
	}
      if (egress)
	{
	  s = format (s, "\n");
	  s = format_newline (s, indent);
	}
      s = format (s, "%s:", egress ? "EG_VSI_COUNTER_TBL" : "VLAN_CNT_TBL");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &table);
      table_free (&table);
    }
  return s;
}
