/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/format_table.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "format",
};

format_function_t format_indent;

u8 *
format_ice_family (u8 *s, va_list *args)
{
  ice_device_family_t family = va_arg (*args, int);

#define _(n, v)                                                                                    \
  if (family == ICE_DEVICE_FAMILY_##n)                                                             \
    return format (s, v);
  foreach_ice_family
#undef _
    return format (s, "unknown (%u)", family);
}

u8 *
format_ice_adminq_opcode (u8 *s, va_list *args)
{
  u32 opcode = va_arg (*args, u32);

#define _(v, n)                                                                                    \
  if (opcode == ICE_AQC_OP_##n)                                                                    \
    return format (s, #n " (0x%04x)", opcode);
  foreach_ice_adminq_opcode
#undef _
    return format (s, "UNKNOWN (0x%04x)", opcode);
}

static u8 *
format_ice_indent (u8 *s, u8 *v, u32 indent)
{
  s = format (s, "%U", format_indent, v, indent);
  vec_free (v);
  return s;
}

static u8 *
format_ice_table_section (u8 *s, table_t *t, u32 indent, char *title)
{
  s = format_ice_indent (s, format (0, "\n%s:\n  %U", title, format_table, t), indent);
  table_free (t);
  return s;
}

static u8 *
format_ice_sw_rule_type (u8 *s, va_list *args)
{
  ice_aqc_sw_rule_type_t type = va_arg (*args, int);

#define _(v, n)                                                                                    \
  if (type == ICE_AQC_SW_RULE_##n)                                                                 \
    return format (s, #n);
  foreach_ice_aqc_sw_rule_type
#undef _
    return format (s, "unknown (%u)", type);
}

static u8 *
format_ice_aqc_capability (u8 *s, va_list *args)
{
  ice_aqc_capability_t cap = va_arg (*args, int);

#define _(v, n)                                                                                    \
  if (cap == ICE_AQC_CAPS_##n)                                                                     \
    return format (s, #n " (0x%04x)", cap);
  foreach_ice_aqc_capability
#undef _
    return format (s, "unknown (0x%04x)", cap);
}

static u8 *
format_ice_sw_recipe (u8 *s, va_list *args)
{
  ice_sw_lkup_type_t recipe = va_arg (*args, int);

#define _(v, n)                                                                                    \
  if (recipe == ICE_SW_LKUP_##n)                                                                   \
    return format (s, #n);
  foreach_ice_sw_lkup_type
#undef _
    return format (s, "unknown (%u)", recipe);
}

u8 *
format_ice_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);
  ice_dev_info_t info = {};
  vnet_dev_rv_t rv;

  rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), dev, ice_aq_get_dev_info, &info);
  if (rv != VNET_DEV_OK)
    return format (s, "family %U, device information unavailable: %U", format_ice_family,
		   id->family, format_vnet_dev_rv, rv);

  s = format (s, "family %U FW %u.%u.%u (branch %u build 0x%08x) API %u.%u.%u (branch %u)",
	      format_ice_family, id->family, info.fw_major, info.fw_minor, info.fw_patch,
	      info.fw_branch, info.fw_build, info.api_major, info.api_minor, info.api_patch,
	      info.api_branch);
  s = format_ice_indent (s,
			 format (0, "\nNVM %x.%02x DDP %u.%u.%u.%u ROM ID 0x%08x", info.nvm_major,
				 info.nvm_minor, info.ddp_ver.major, info.ddp_ver.minor,
				 info.ddp_ver.update, info.ddp_ver.draft, info.rom_ver),
			 indent);
  for (u32 i = 0; i < vec_len (info.dev_caps); i++)
    if (info.dev_caps[i].cap == ICE_AQC_CAPS_SENSOR_READING && (info.dev_caps[i].number & 1))
      {
	ice_aqc_sensor_reading_t reading;

	rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), dev, ice_aq_get_sensor_reading,
						&reading);
	if (rv == VNET_DEV_OK)
	  s = format_ice_indent (
	    s,
	    format (0, "\nTemperature %d °C (warning %u °C, critical %u °C, fatal %u °C)",
		    reading.temp, reading.temp_warning_threshold, reading.temp_critical_threshold,
		    reading.temp_fatal_threshold),
	    indent);
	else
	  s = format_ice_indent (
	    s, format (0, "\nTemperature unavailable: %U", format_vnet_dev_rv, rv), indent);
	break;
      }

  if (a->debug == 0)
    {
      vec_free (info.dev_caps);
      vec_free (info.pkg_info);
      return s;
    }

  s = format_ice_indent (s, format (0, "\nPF %u, TX parent TEID %u", id->pf_id, ip->tx_parent_teid),
			 indent);

  if (vec_len (info.dev_caps))
    {
      table_t caps = {};
      table_add_hdr_row (&caps, 5, "capability", "version", "number", "logical ID", "physical ID");
      table_set_cell_align (&caps, -1, 0, TTAA_LEFT);
      for (u32 i = 0; i < vec_len (info.dev_caps); i++)
	{
	  ice_aqc_list_caps_elem_t *cap = info.dev_caps + i;
	  table_format_cell (&caps, i, 0, "%U", format_ice_aqc_capability, cap->cap);
	  table_format_cell (&caps, i, 1, "%u.%u", cap->major_ver, cap->minor_ver);
	  table_format_cell (&caps, i, 2, "%u", cap->number);
	  table_format_cell (&caps, i, 3, "0x%08x", cap->logical_id);
	  table_format_cell (&caps, i, 4, "0x%08x", cap->phys_id);
	  table_set_cell_align (&caps, i, 0, TTAA_LEFT);
	}
      s = format_ice_table_section (s, &caps, indent, "Device capability entries");
    }

  if (vec_len (info.pkg_info))
    {
      table_t packages = {};
      table_add_hdr_row (&packages, 7, "name", "version", "track ID", "NVM", "active", "boot",
			 "modified");
      table_set_cell_align (&packages, -1, 0, TTAA_LEFT);
      for (u32 i = 0; i < vec_len (info.pkg_info); i++)
	{
	  ice_aqc_pkg_info_t *pkg = info.pkg_info + i;
	  u8 name[sizeof (pkg->name) + 1] = {};
	  clib_memcpy (name, pkg->name, sizeof (pkg->name));
	  table_format_cell (&packages, i, 0, "%s", name);
	  table_format_cell (&packages, i, 1, "%u.%u.%u.%u", pkg->ver.major, pkg->ver.minor,
			     pkg->ver.update, pkg->ver.draft);
	  table_format_cell (&packages, i, 2, "0x%08x", pkg->track_id);
	  table_format_cell (&packages, i, 3, "%s", pkg->is_in_nvm ? "yes" : "no");
	  table_format_cell (&packages, i, 4, "%s", pkg->is_active ? "yes" : "no");
	  table_format_cell (&packages, i, 5, "%s", pkg->is_active_at_boot ? "yes" : "no");
	  table_format_cell (&packages, i, 6, "%s", pkg->is_modified ? "yes" : "no");
	  table_set_cell_align (&packages, i, 0, TTAA_LEFT);
	}
      s = format_ice_table_section (s, &packages, indent, "Package info entries");
    }

  vec_free (info.dev_caps);
  vec_free (info.pkg_info);

  ice_reg_mdet_tx_pqm_t mdet_pqm = {
    .as_u32 = ice_reg_read (dev, ICE_GL_MDET_TX_PQM),
  };
  ice_reg_mdet_tx_tclan_t mdet_tclan = {
    .as_u32 = ice_reg_read (dev, ICE_GL_MDET_TX_TCLAN),
  };
  ice_reg_mdet_tx_tdpu_t mdet_tdpu = {
    .as_u32 = ice_reg_read (dev, ICE_GL_MDET_TX_TDPU),
  };
  ice_reg_e830_mdet_tx_tclan_fifo_t mdet_fifo = {
    .as_u32 = ice_reg_read (dev, ICE_E830_GL_MDET_TX_TCLAN_FIFO),
  };
  ice_reg_e830_mdet_tx_tdpu_fifo_t mdet_tdpu_fifo = {
    .as_u32 = ice_reg_read (dev, ICE_E830_GL_MDET_TX_TDPU_FIFO),
  };
  ice_reg_prtdcb_tdpuc_t tdpuc = {
    .as_u32 = ice_reg_read (dev, ICE_PRTDCB_TDPUC),
  };
  table_t mdd = {};
  u32 mdd_row = 0;

  table_add_hdr_row (&mdd, 3, "source", "event", "details");
  table_set_cell_align (&mdd, -1, 0, TTAA_LEFT);
  table_set_cell_align (&mdd, -1, 2, TTAA_LEFT);
  if (mdet_pqm.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "PQM");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_pqm.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "PF %u, VF %u, queue %u", mdet_pqm.pf_num,
			 mdet_pqm.vf_num, mdet_pqm.queue_num);
    }
  if (mdet_tclan.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TCLAN");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_tclan.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "PF %u, VF %u, queue %u", mdet_tclan.pf_num,
			 mdet_tclan.vf_num, mdet_tclan.queue_num);
    }
  if (mdet_tdpu.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TDPU");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_tdpu.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "PF %u, VF %u, queue %u", mdet_tdpu.pf_num,
			 mdet_tdpu.vf_num, mdet_tdpu.queue_num);
    }
  if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_fifo.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TCLAN FIFO");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_fifo.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "count %u, PF %u, function %u, type %u",
			 mdet_fifo.event_count, mdet_fifo.pf_num, mdet_fifo.function_num,
			 mdet_fifo.function_type);
    }
  if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_tdpu_fifo.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TDPU FIFO");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_tdpu_fifo.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "count %u, PF %u, function %u, type %u",
			 mdet_tdpu_fifo.event_count, mdet_tdpu_fifo.pf_num,
			 mdet_tdpu_fifo.function_num, mdet_tdpu_fifo.function_type);
    }
  if (mdd_row)
    s = format_ice_table_section (s, &mdd, indent, "MDD TX events");
  else
    table_free (&mdd);
  if (tdpuc.malformed_length || tdpuc.malformed_command || tdpuc.ttl_drop ||
      tdpuc.unsupported_request_drop || tdpuc.big_packet_size || tdpuc.l2_accept_fail ||
      tdpuc.dscp_check_fail || tdpuc.rcu_antispoof || tdpuc.nic_dsi || tdpuc.nic_ipsec)
    {
      table_t status = {};

      table_add_hdr_row (&status, 2, "field", "value");
      table_set_cell_align (&status, -1, 0, TTAA_LEFT);
      table_format_cell (&status, 0, 0, "max frame");
      table_format_cell (&status, 0, 1, "%u", tdpuc.max_tx_frame);
      table_format_cell (&status, 1, 0, "malformed length");
      table_format_cell (&status, 1, 1, "%u", tdpuc.malformed_length);
      table_format_cell (&status, 2, 0, "malformed command");
      table_format_cell (&status, 2, 1, "%u", tdpuc.malformed_command);
      table_format_cell (&status, 3, 0, "TTL drop");
      table_format_cell (&status, 3, 1, "%u", tdpuc.ttl_drop);
      table_format_cell (&status, 4, 0, "unsupported request");
      table_format_cell (&status, 4, 1, "%u", tdpuc.unsupported_request_drop);
      table_format_cell (&status, 5, 0, "big packet");
      table_format_cell (&status, 5, 1, "%u", tdpuc.big_packet_size);
      table_format_cell (&status, 6, 0, "L2 accept fail");
      table_format_cell (&status, 6, 1, "%u", tdpuc.l2_accept_fail);
      table_format_cell (&status, 7, 0, "DSCP check fail");
      table_format_cell (&status, 7, 1, "%u", tdpuc.dscp_check_fail);
      table_format_cell (&status, 8, 0, "RCU antispoof");
      table_format_cell (&status, 8, 1, "%u", tdpuc.rcu_antispoof);
      table_format_cell (&status, 9, 0, "NIC DSI");
      table_format_cell (&status, 9, 1, "%u", tdpuc.nic_dsi);
      table_format_cell (&status, 10, 0, "NIC IPsec");
      table_format_cell (&status, 10, 1, "%u", tdpuc.nic_ipsec);
      s = format_ice_table_section (s, &status, indent, "TDPU status");
    }

  if (a->clear)
    {
      if (mdet_pqm.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_PQM, CLIB_U32_MAX);
      if (mdet_tclan.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_TCLAN, CLIB_U32_MAX);
      if (mdet_tdpu.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_TDPU, CLIB_U32_MAX);
      if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_fifo.valid)
	ice_reg_write (dev, ICE_E830_GL_MDET_TX_TCLAN_FIFO, CLIB_U32_MAX);
      if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_tdpu_fifo.valid)
	ice_reg_write (dev, ICE_E830_GL_MDET_TX_TDPU_FIFO, CLIB_U32_MAX);
      if (tdpuc.malformed_length || tdpuc.malformed_command || tdpuc.ttl_drop ||
	  tdpuc.unsupported_request_drop || tdpuc.big_packet_size || tdpuc.l2_accept_fail ||
	  tdpuc.dscp_check_fail || tdpuc.rcu_antispoof || tdpuc.nic_dsi || tdpuc.nic_ipsec)
	{
	  tdpuc.clear_drop = 1;
	  ice_reg_write (dev, ICE_PRTDCB_TDPUC, tdpuc.as_u32);
	}
    }

  table_t aq = {};
  table_add_hdr_row (&aq, 6, "ring", "entries", "DMA address", "head", "tail", "enabled");
  ice_reg_aq_len_t atq_len = { .as_u32 = ice_reg_read (dev, ICE_PF_FW_ATQLEN) };
  ice_reg_aq_len_t arq_len = { .as_u32 = ice_reg_read (dev, ICE_PF_FW_ARQLEN) };
  table_format_cell (&aq, 0, 0, "ATQ");
  table_format_cell (&aq, 0, 1, "%u", atq_len.length);
  table_format_cell (&aq, 0, 2, "0x%016lx",
		     (u64) ice_reg_read (dev, ICE_PF_FW_ATQBAH) << 32 |
		       ice_reg_read (dev, ICE_PF_FW_ATQBAL));
  table_format_cell (&aq, 0, 3, "%u", ice_reg_read (dev, ICE_PF_FW_ATQH));
  table_format_cell (&aq, 0, 4, "%u", ice_reg_read (dev, ICE_PF_FW_ATQT));
  table_format_cell (&aq, 0, 5, "%u", atq_len.enable);
  table_format_cell (&aq, 1, 0, "ARQ");
  table_format_cell (&aq, 1, 1, "%u", arq_len.length);
  table_format_cell (&aq, 1, 2, "0x%016lx",
		     (u64) ice_reg_read (dev, ICE_PF_FW_ARQBAH) << 32 |
		       ice_reg_read (dev, ICE_PF_FW_ARQBAL));
  table_format_cell (&aq, 1, 3, "%u", ice_reg_read (dev, ICE_PF_FW_ARQH));
  table_format_cell (&aq, 1, 4, "%u", ice_reg_read (dev, ICE_PF_FW_ARQT));
  table_format_cell (&aq, 1, 5, "%u", arq_len.enable);
  s = format_ice_table_section (s, &aq, indent, "AdminQ rings");

  if (vec_len (ip->vsi.sw_rules))
    {
      table_t rules = {};
      table_add_hdr_row (&rules, 8, "rule", "direction", "recipe", "source VSI", "target VSI",
			 "loopback", "LAN", "destination MAC");
      for (u32 i = 0; i < vec_len (ip->vsi.sw_rules); i++)
	{
	  ice_sw_rule_t *r = ip->vsi.sw_rules + i;
	  ice_sw_rule_action_t action = { .as_u32 = r->act };
	  table_format_cell (&rules, i, 0, "%u", r->index);
	  table_format_cell (&rules, i, 1, "%U", format_ice_sw_rule_type, r->type);
	  table_format_cell (&rules, i, 2, "%U", format_ice_sw_recipe, r->recipe_id);
	  table_format_cell (&rules, i, 3, "%u", r->src);
	  table_format_cell (&rules, i, 4, "%u", action.vsi_id);
	  table_format_cell (&rules, i, 5, "%s", action.loopback_enable ? "yes" : "no");
	  table_format_cell (&rules, i, 6, "%s", action.lan_enable ? "yes" : "no");
	  if (r->recipe_id == ICE_SW_LKUP_MAC)
	    table_format_cell (&rules, i, 7, "%U", format_ethernet_address, r->hdr_data);
	  else if (r->recipe_id == ICE_SW_LKUP_PROMISC)
	    table_format_cell (&rules, i, 7, "any %s",
			       ethernet_address_cast (r->hdr_data) ? "multicast" : "unicast");
	  else
	    table_format_cell (&rules, i, 7, "-");
	}
      s = format_ice_table_section (s, &rules, indent, "Programmed switch rules");
    }

  return s;
}

static u8 *
format_ice_phy_types (u8 *s, va_list *args)
{
  u64 types[2] = {
    va_arg (*args, u64),
    va_arg (*args, u64),
  };
  static const char *low[] = {
    [0] = "100BASE-TX",		[1] = "100M-SGMII",	     [2] = "1000BASE-T",
    [3] = "1000BASE-SX",	[4] = "1000BASE-LX",	     [5] = "1000BASE-KX",
    [6] = "1G-SGMII",		[7] = "2500BASE-T",	     [8] = "2500BASE-X",
    [9] = "2500BASE-KX",	[10] = "5GBASE-T",	     [11] = "5GBASE-KR",
    [12] = "10GBASE-T",		[13] = "10G-SFI-DA",	     [14] = "10GBASE-SR",
    [15] = "10GBASE-LR",	[16] = "10GBASE-KR-CR1",     [17] = "10G-SFI-AOC-ACC",
    [18] = "10G-SFI-C2C",	[19] = "25GBASE-T",	     [20] = "25GBASE-CR",
    [21] = "25GBASE-CR-S",	[22] = "25GBASE-CR1",	     [23] = "25GBASE-SR",
    [24] = "25GBASE-LR",	[25] = "25GBASE-KR",	     [26] = "25GBASE-KR-S",
    [27] = "25GBASE-KR1",	[28] = "25G-AUI-AOC-ACC",    [29] = "25G-AUI-C2C",
    [30] = "40GBASE-CR4",	[31] = "40GBASE-SR4",	     [32] = "40GBASE-LR4",
    [33] = "40GBASE-KR4",	[34] = "40G-XLAUI-AOC-ACC",  [35] = "40G-XLAUI",
    [36] = "50GBASE-CR2",	[37] = "50GBASE-SR2",	     [38] = "50GBASE-LR2",
    [39] = "50GBASE-KR2",	[40] = "50G-LAUI2-AOC-ACC",  [41] = "50G-LAUI2",
    [42] = "50G-AUI2-AOC-ACC",	[43] = "50G-AUI2",	     [44] = "50GBASE-CP",
    [45] = "50GBASE-SR",	[46] = "50GBASE-FR",	     [47] = "50GBASE-LR",
    [48] = "50GBASE-KR-PAM4",	[49] = "50G-AUI1-AOC-ACC",   [50] = "50G-AUI1",
    [51] = "100GBASE-CR4",	[52] = "100GBASE-SR4",	     [53] = "100GBASE-LR4",
    [54] = "100GBASE-KR4",	[55] = "100G-CAUI4-AOC-ACC", [56] = "100G-CAUI4",
    [57] = "100G-AUI4-AOC-ACC", [58] = "100G-AUI4",	     [59] = "100GBASE-CR-PAM4",
    [60] = "100GBASE-KR-PAM4",	[61] = "100GBASE-CP2",	     [62] = "100GBASE-SR2",
    [63] = "100GBASE-DR",
  };
  static const char *high[] = {
    [0] = "100GBASE-KR2-PAM4", [1] = "100G-CAUI2-AOC-ACC", [2] = "100G-CAUI2",
    [3] = "100G-AUI2-AOC-ACC", [4] = "100G-AUI2",	   [5] = "200G-CR4-PAM4",
    [6] = "200G-SR4",	       [7] = "200G-FR4",	   [8] = "200G-LR4",
    [9] = "200G-DR4",	       [10] = "200G-KR4-PAM4",	   [11] = "200G-AUI4-AOC-ACC",
    [12] = "200G-AUI4",	       [13] = "200G-AUI8-AOC-ACC", [14] = "200G-AUI8",
    [15] = "400GBASE-FR8",
  };
  const char **names[] = {
    low,
    high,
  };
  u32 counts[] = {
    ARRAY_LEN (low),
    ARRAY_LEN (high),
  };
  u8 separator = 0;

  for (u32 half = 0; half < ARRAY_LEN (types); half++)
    for (u32 bit = 0; bit < 64; bit++)
      if (types[half] & (1ULL << bit))
	{
	  if (separator)
	    s = format (s, ", ");
	  if (bit < counts[half])
	    s = format (s, "%s", names[half][bit]);
	  else
	    s = format (s, "unknown-%s-%u", half ? "high" : "low", bit);
	  separator = 1;
	}
  return separator ? s : format (s, "none");
}

static u8 *
format_ice_phy_flags (u8 *s, ice_port_status_t *status, u32 indent, char *title, const char **names,
		      u32 n_names, u8 values[4])
{
  table_t t = {};

  table_add_hdr_col (&t, 1, "");
  table_add_hdr_row (&t, 5, "field", "Topology", "Media", "Configured", "Default");
  for (u32 bit = 0; bit < n_names; bit++)
    {
      table_format_cell (&t, bit, -1, "%s", names[bit]);
      table_set_cell_align (&t, bit, -1, TTAA_LEFT);
      for (u32 i = 0; i < ARRAY_LEN (status->phy); i++)
	{
	  char *value = "-";

	  if (status->phy_rv[i] == VNET_DEV_OK)
	    value = values[i] & (1 << bit) ? "yes" : "no";
	  table_format_cell (&t, bit, i, "%s", value);
	}
    }
  return format_ice_table_section (s, &t, indent, title);
}

static u8 *
format_ice_port_diagnostics (u8 *s, ice_port_status_t *status, u32 indent)
{
  static const char *sources[] = {
    "Topology",
    "Media",
    "Configured",
    "Default",
  };
  static const char *lane_speeds[] = {
    "100M", "1G", "2.5G", "5G", "10G", "25G", "50G", "100G", "200G", "40G",
  };
  ice_aqc_link_status_t *link = &status->link;
  table_t phy = {}, options = {};
  static const char *fec_names[] = {
    "BASE-R enabled",	"BASE-R requested", "RS-528 requested", "25G BASE-R requested",
    "RS-544 requested", "disabled",	    "RS-528 enabled",	"25G BASE-R enabled",
  };
  static const char *caps_names[] = {
    "pause TX", "pause RX", "low power", "link enabled", "autoneg", "module qualification",
    "LESM",	"auto FEC",
  };
  u8 fec[ARRAY_LEN (status->phy)], caps[ARRAY_LEN (status->phy)];
  u64 modes[2] = {};
  u32 n_modes = 0;

  if (status->link_rv != VNET_DEV_OK)
    s = format_ice_indent (
      s, format (0, "\nLink diagnostics unavailable: %U", format_vnet_dev_rv, status->link_rv),
      indent);
  else
    {
      u8 faults = 0;
      u8 *v = format (0, "\nLink: %s, media %s, signal %s, max frame %u",
		      link->link_info.link_up ? "up" : "down",
		      link->link_info.media_available ? "present" : "absent",
		      link->link_info.signal_detect ? "detected" : "absent", link->max_frame_size);
      v =
	format (v, "\nAutonegotiation: %s, partner ability %u, pause TX %u RX %u",
		link->an_info.completed ? "complete" : "incomplete",
		link->an_info.link_partner_ability, link->an_info.pause_tx, link->an_info.pause_rx);
      v = format (v, "\nActive FEC: enabled %u, BASE-R %u, RS-528 %u, RS-544 %u, RS-272 %u",
		  link->an_info.fec_enabled, link->cfg.kr_25g_fec, link->cfg.rs_528_fec,
		  link->cfg.rs_544_fec, link->ext_fec_status.rs_272_fec);
      v = format (v, "\nActive PHY: %U", format_ice_phy_types, link->phy_type_low,
		  link->phy_type_high);
      v = format (v, "\nLink faults:");
#define _(member, label)                                                                           \
  if (link->member)                                                                                \
    {                                                                                              \
      v = format (v, " %s", label);                                                                \
      faults = 1;                                                                                  \
    }
      _ (link_info.link_fault, "link")
      _ (link_info.tx_fault, "TX")
      _ (link_info.rx_fault, "RX")
      _ (link_info.remote_fault, "remote")
      _ (an_info.parallel_detection_fault, "parallel-detection")
      _ (ext_info.phy_temperature_alarm, "PHY-temperature")
      _ (ext_info.excessive_errors, "excessive-errors")
      _ (topo_media_conflict.topology_conflict, "topology-conflict")
      _ (topo_media_conflict.media_conflict, "media-conflict")
      _ (topo_media_conflict.topology_corrupt, "topology-corrupt")
      _ (topo_media_conflict.topology_unreachable, "port-unreachable")
      _ (topo_media_conflict.unsupported_media, "unsupported-media")
      _ (link_cfg_err.config_error, "configuration")
      _ (link_cfg_err.invalid_port_option, "invalid-port-option")
      _ (link_cfg_err.invalid_feature_or_config, "invalid-feature-or-config")
      _ (link_cfg_err.critical_sdp_error, "critical-SDP")
      _ (link_cfg_err.unsupported_module_power, "unsupported-module-power")
      _ (link_cfg_err.external_phy_load_failure, "PHY-load-failure")
      _ (link_cfg_err.invalid_max_power_limit, "invalid-power-limit")
#undef _
      if (!faults)
	v = format (v, " none");
      s = format_ice_indent (s, v, indent);
    }

  if (status->phy_rv[1] == VNET_DEV_OK)
    {
      ice_aqc_get_phy_caps_data_t *p = status->phy + 1;

      s = format_ice_indent (s,
			     format (0,
				     "\nPHY ID %02x:%02x:%02x:%02x, firmware %U"
				     "\nmodule type %02x:%02x:%02x, compliance 0x%02x",
				     p->phy_id_oui[0], p->phy_id_oui[1], p->phy_id_oui[2],
				     p->phy_id_oui[3], format_hex_bytes, p->phy_fw_ver,
				     sizeof (p->phy_fw_ver), p->module_type[0], p->module_type[1],
				     p->module_type[2], p->extended_compliance_code),
			     indent);
    }

  table_add_hdr_col (&phy, 1, "");
  table_add_hdr_row (&phy, 5, "field", sources[0], sources[1], sources[2], sources[3]);
  for (u32 i = 0; i < ARRAY_LEN (status->phy); i++)
    if (status->phy_rv[i] == VNET_DEV_OK)
      {
	modes[0] |= status->phy[i].phy_type_low;
	modes[1] |= status->phy[i].phy_type_high;
      }
  for (u32 half = 0; half < ARRAY_LEN (modes); half++)
    for (u32 bit = 0; bit < 64; bit++)
      {
	u64 mode = 1ULL << bit;

	if (!(modes[half] & mode))
	  continue;
	table_format_cell (&phy, n_modes, -1, "%U", format_ice_phy_types, half == 0 ? mode : 0ULL,
			   half == 1 ? mode : 0ULL);
	table_set_cell_align (&phy, n_modes, -1, TTAA_LEFT);
	for (u32 i = 0; i < ARRAY_LEN (status->phy); i++)
	  {
	    u64 supported = status->phy[i].phy_type_low;
	    char *value = "-";

	    if (half)
	      supported = status->phy[i].phy_type_high;
	    if (status->phy_rv[i] == VNET_DEV_OK)
	      value = supported & mode ? "yes" : "no";
	    table_format_cell (&phy, n_modes, i, "%s", value);
	  }
	n_modes++;
      }
  s = format_ice_table_section (s, &phy, indent, "PHY modes");

  for (u32 i = 0; i < ARRAY_LEN (status->phy); i++)
    {
      fec[i] = status->phy[i].link_fec_options;
      caps[i] = status->phy[i].caps;
      if (status->phy_rv[i] != VNET_DEV_OK)
	s = format_ice_indent (
	  s,
	  format (0, "\n%s PHY unavailable: %U", sources[i], format_vnet_dev_rv, status->phy_rv[i]),
	  indent);
    }
  s = format_ice_phy_flags (s, status, indent, "PHY FEC options", fec_names, ARRAY_LEN (fec_names),
			    fec);
  s = format_ice_phy_flags (s, status, indent, "PHY capabilities", caps_names,
			    ARRAY_LEN (caps_names), caps);

  if (status->options_rv != VNET_DEV_OK)
    return format_ice_indent (
      s, format (0, "\nPort options unavailable: %U", format_vnet_dev_rv, status->options_rv),
      indent);

  table_add_hdr_col (&options, 1, "");
  table_add_hdr_row (&options, 6, "option", "active", "pending", "PMDs", "PMD width",
		     "max lane speed");
  for (u32 i = 0; i < (status->options_params.port_options.count & 0xf); i++)
    {
      ice_aqc_port_option_t *p = status->options + i;
      char *active = "-", *pending = "-";

      if (status->options_params.port_options.active.valid &&
	  status->options_params.port_options.active.index == i)
	active = "yes";
      if (status->options_params.port_options.pending.valid &&
	  status->options_params.port_options.pending.index == i)
	pending = "yes";
      table_format_cell (&options, i, -1, "%u", i);
      table_format_cell (&options, i, 0, "%s", active);
      table_format_cell (&options, i, 1, "%s", pending);
      table_format_cell (&options, i, 2, "%u", p->pmd_count);
      table_format_cell (&options, i, 3, "%u", p->pmd_width);
      if (p->max_lane_speed < ARRAY_LEN (lane_speeds))
	table_format_cell (&options, i, 4, "%s", lane_speeds[p->max_lane_speed]);
      else
	table_format_cell (&options, i, 4, "unknown (%u)", p->max_lane_speed);
    }
  return format_ice_table_section (s, &options, indent, "Port options");
}

u8 *
format_ice_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);
  ice_port_status_t status = {
    .lport = ip->lport,
  };
  vnet_dev_rv_t rv;

  s = format (s, "vsi %u, lport %u", ip->vsi.num, ip->lport);
  rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), port->dev, ice_aq_get_port_status,
					  &status);
  if (rv == VNET_DEV_OK)
    s = format_ice_port_diagnostics (s, &status, indent);
  else
    s = format_ice_indent (
      s, format (0, "\nPort diagnostics unavailable: %U", format_vnet_dev_rv, rv), indent);
  if (a->debug == 0)
    return s;
  s = format_ice_indent (
    s,
    format (0, "\nprogrammed VSI: switch %u, valid sections 0x%04x, LAN %u, RX queues %u-%u",
	    ip->vsi.props.sw_id, ip->vsi.props.valid_sections.as_u16,
	    ip->vsi.props.sw_flags2.lan_enable, ip->vsi.props.q_mapping[0],
	    ip->vsi.props.q_mapping[0] + ip->vsi.props.q_mapping[1] - 1),
    indent);
  s = format_ice_indent (
    s,
    format (0,
	    "\nfeatures: loopback %u, local loopback %u, source prune %u, "
	    "destination override %u",
	    ip->vsi.props.sw_flags.allow_loopback, ip->vsi.props.sw_flags.local_loopback,
	    ip->vsi.props.sw_flags.source_prune, ip->vsi.props.sec_flags.allow_dest_override),
    indent);
  return format_ice_indent (s,
			    format (0, "\nVLAN: TX mode %u, egress mode %u",
				    ip->vsi.props.inner_vlan_flags.tx_mode,
				    ip->vsi.props.inner_vlan_flags.egress_mode),
			    indent);
}

u8 *
format_ice_rx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  vnet_dev_t *dev = rxq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_rxq_ctx_t ctx = {};
  ice_reg_qrx_ctrl_t ctrl;
  u16 q = id->rxq_base + rxq->queue_id;

  if (a->debug == 0)
    return s;
  ctrl.as_u32 = ice_reg_read (dev, ICE_QRX_CTRL (q));
  for (u32 i = 0; i < ARRAY_LEN (ctx.as_u32); i++)
    ctx.as_u32[i] = ice_reg_read (dev, ICE_QRX_CONTEXT (i, q));
  return format (s,
		 "hw queue ID is %u, enabled %u, head %u, descriptors %u, buffer size %u, "
		 "max frame %u, CRC strip %u, L2 %u, prefetch %u",
		 q, ctrl.enable_status, ctx.head, ctx.qlen, ctx.dbuf << 7, ctx.rxmax, ctx.crcstrip,
		 ctx.l2tsel, ctx.prefena);
}

typedef struct
{
  u16 queue_id;
  union
  {
    ice_txq_ctx_t ctx;
    u32 words[6];
  };
} ice_txq_ctx_query_t;

static vnet_dev_rv_t
ice_read_tx_queue_context (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  ice_txq_ctx_query_t *query = data;
  ice_reg_glcomm_qtx_cntx_ctl_t ctrl = {
    .queue_id = query->queue_id,
    .cmd_exec = 1,
  };
  ice_reg_glcomm_qtx_cntx_stat_t stat;
  f64 start = vlib_time_now (vm);

  for (;;)
    {
      stat.as_u32 = ice_reg_read (dev, ICE_GLCOMM_QTX_CNTX_STAT);
      if (!stat.cmd_in_prog)
	break;
      if (vlib_time_now (vm) - start > 0.01)
	{
	  log_err (dev, "TX queue %u context query timed out waiting for idle: status 0x%08x",
		   query->queue_id, stat.as_u32);
	  return VNET_DEV_ERR_TIMEOUT;
	}
      vlib_process_suspend (vm, 1e-6);
    }
  ice_reg_write (dev, ICE_GLCOMM_QTX_CNTX_CTL, ctrl.as_u32);
  ice_reg_flush (dev);
  for (;;)
    {
      stat.as_u32 = ice_reg_read (dev, ICE_GLCOMM_QTX_CNTX_STAT);
      if (!stat.cmd_in_prog)
	break;
      if (vlib_time_now (vm) - start > 0.01)
	{
	  log_err (dev, "TX queue %u context query timed out: control 0x%08x status 0x%08x",
		   query->queue_id, ctrl.as_u32, stat.as_u32);
	  return VNET_DEV_ERR_TIMEOUT;
	}
      vlib_process_suspend (vm, 1e-6);
    }
  for (u32 i = 0; i < ARRAY_LEN (query->words); i++)
    query->words[i] = ice_reg_read (dev, ICE_GLCOMM_QTX_CNTX_DATA (i));
  log_debug (dev, "txq %u hw context: %U", query->queue_id, format_hex_bytes, query->words,
	     sizeof (query->words));
  return VNET_DEV_OK;
}

u8 *
format_ice_tx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  ice_dev_t *id = vnet_dev_get_data (txq->port->dev);
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  ice_reg_qtx_comm_head_t hw_head;
  ice_tx_cmd_t head_cmd = {};
  u16 q = id->txq_base + txq->queue_id;
  ice_txq_ctx_query_t query = {
    .queue_id = q,
  };
  vnet_dev_rv_t rv;

  if (a->debug == 0)
    return s;
  s = format (s, "hw queue ID is %u", q);
  if (!iq->started)
    return format (s, ", queue not started");
  hw_head.as_u32 = ice_reg_read (txq->port->dev, ICE_QTX_COMM_HEAD (q));
  if (iq->head != iq->tail)
    head_cmd = iq->descs[iq->head & (txq->size - 1)].cmd;
  s = format (s, ", head %u, tail %u, hw head %u, descriptor type %u", iq->head, iq->tail,
	      hw_head.head, head_cmd.descriptor_type);
  rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), txq->port->dev,
					  ice_read_tx_queue_context, &query);
  if (rv != VNET_DEV_OK)
    return format (s, ", context unavailable: %U", format_vnet_dev_rv, rv);
  return format (s, ", descriptors %u, TSO %u, legacy interrupt %u", query.ctx.qlen,
		 query.ctx.tso_ena, query.ctx.legacy_int);
}

u8 *
format_ice_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm __clib_unused = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  ice_rx_trace_t *tr = va_arg (*args, ice_rx_trace_t *);
  u32 indent = format_get_indent (s);
  u16 i;

  s = format (s, "ice-rx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  s = format_ice_indent (
    s, format (0, "\npacket length %u descriptors %u", tr->packet_length, tr->n_desc), indent + 2);
  for (i = 0; i < tr->n_desc; i++)
    {
      ice_rx_desc_t *d = tr->descs + i;

      s = format_ice_indent (
	s,
	format (0,
		"\ndescriptor %u: RXDID %u status 0x%04x packet type %u length %u "
		"RSS 0x%08x",
		i, d->wb.rxdid, d->wb.status.as_u16, d->wb.packet_type.packet_type,
		d->wb.packet_length.length, d->wb.rss_hash),
	indent + 2);
    }
  return s;
}

u8 *
format_ice_tx_desc (u8 *s, va_list *args)
{
  ice_tx_desc_t *d = va_arg (*args, ice_tx_desc_t *);
  static char *ip_type_names[] = { "non-ip", "ipv6", "ipv4", "ipv4-cksum" };
  static char *l4_type_names[] = { "reserved", "tcp", "sctp", "udp" };
  u8 *v;

  if (d->cmd.descriptor_type == ICE_TX_DESC_TYPE_CTX)
    {
      ice_tx_ctx_desc_t *cd = (ice_tx_ctx_desc_t *) d;

      v = format (s, "context: tunnel-params 0x%016lx tso %u tso-len %u mss %u", cd->tunnel_params,
		  cd->cmd.tso, cd->cmd.tso_len, cd->cmd.mss);
      return format_word_wrap_last_line_with_indent (v, 100, 2);
    }

  if (d->cmd.descriptor_type == ICE_TX_DESC_TYPE_DONE)
    return format (s, "done: addr 0x%016lx command 0x%016lx", d->buf_addr, d->cmd.as_u64);

  v = format (s,
	      "data: addr 0x%016lx eop %u rs %u rc %u l2tag-ins %u ip-type %s l4-type %s "
	      "mac-len %u ip-len %u l4-len %u buffer-size %u l2-tag 0x%04x",
	      d->buf_addr, d->cmd.end_of_packet, d->cmd.report_status, d->cmd.reserved_command,
	      d->cmd.insert_l2_tag, ip_type_names[d->cmd.ip_type], l4_type_names[d->cmd.l4_type],
	      d->cmd.mac_length, d->cmd.ip_length, d->cmd.l4_length, d->cmd.buffer_size,
	      d->cmd.l2_tag);
  return format_word_wrap_last_line_with_indent (v, 100, 2);
}

u8 *
format_ice_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  ice_tx_trace_t *tr = va_arg (*args, ice_tx_trace_t *);
  u32 indent = format_get_indent (s);
  u8 i;

  s = format (s, "ice-tx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  if (tr->n_descs == 0)
    s = format_ice_indent (
      s, format (0, "\ndropped (%s)", vm->error_main.counters_heap[tr->error].name), indent + 2);
  else
    s = format_ice_indent (s, format (0, "\ndescriptors %u", tr->n_descs), indent + 2);
  for (i = 0; i < tr->n_descs; i++)
    s = format_ice_indent (
      s, format (0, "\ndescriptor %u: %U", i, format_ice_tx_desc, tr->descs + i), indent + 2);
  return s;
}
