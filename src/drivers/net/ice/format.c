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

u8 *
format_ice_family (u8 *s, va_list *args)
{
  ice_device_family_t family = va_arg (*args, int);
  static const char *names[] = {
#define _(n, v) [ICE_DEVICE_FAMILY_##n] = v,
    foreach_ice_family
#undef _
  };

  if (family < ARRAY_LEN (names))
    return format (s, "%s", names[family]);

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

vnet_dev_rv_t
ice_dump_capabilities (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;
  u32 indent = format_get_indent (*s) + 2;
  ice_dev_info_t info = {};

  vnet_dev_rv_t rv = ice_aq_get_dev_caps (vm, dev, &info);
  if (rv)
    {
      vec_free (info.dev_caps);
      return rv;
    }

  if (vec_len (info.dev_caps))
    {
      table_t caps = {};
      table_add_hdr_row (&caps, 5, "capability", "version", "number", "logical ID", "physical ID");
      table_set_cell_align (&caps, -1, 0, TTAA_LEFT);

      for (int i = 0; i < vec_len (info.dev_caps); i++)
	{
	  ice_aqc_list_caps_elem_t *cap = info.dev_caps + i;
	  table_format_cell (&caps, i, 0, "%U", format_ice_aqc_capability, cap->cap);
	  table_format_cell (&caps, i, 1, "%u.%u", cap->major_ver, cap->minor_ver);
	  table_format_cell (&caps, i, 2, "%u", cap->number);
	  table_format_cell (&caps, i, 3, "0x%08x", cap->logical_id);
	  table_format_cell (&caps, i, 4, "0x%08x", cap->phys_id);
	  table_set_cell_align (&caps, i, 0, TTAA_LEFT);
	}

      *s = format (*s, "%UDevice capability entries:", format_white_space, indent);
      *s = format_newline (*s, indent + 2);
      *s = format (*s, "%U", format_table, &caps);
      *s = format_newline (*s, 0);
      table_free (&caps);
    }

  vec_free (info.dev_caps);
  return VNET_DEV_OK;
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
  s = format_word_wrap_last_line (s, 100);
  s = format (format_newline (s, indent), "NVM %x.%02x DDP %u.%u.%u.%u ROM ID 0x%08x",
	      info.nvm_major, info.nvm_minor, info.ddp_ver.major, info.ddp_ver.minor,
	      info.ddp_ver.update, info.ddp_ver.draft, info.rom_ver);

  for (u32 i = 0; i < vec_len (info.dev_caps); i++)
    if (info.dev_caps[i].cap == ICE_AQC_CAPS_SENSOR_READING && (info.dev_caps[i].number & 1))
      {
	ice_aqc_sensor_reading_t reading;

	rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), dev, ice_aq_get_sensor_reading,
						&reading);

	if (rv == VNET_DEV_OK)
	  s = format (format_newline (s, indent),
		      "Temperature %d °C (warning %u °C, critical %u °C, fatal %u °C)",
		      reading.temp, reading.temp_warning_threshold, reading.temp_critical_threshold,
		      reading.temp_fatal_threshold);
	else
	  s = format (format_newline (s, indent), "Temperature unavailable: %U", format_vnet_dev_rv,
		      rv);

	break;
      }

  if (a->debug == 0)
    {
      vec_free (info.dev_caps);
      vec_free (info.pkg_info);
      return s;
    }

  s =
    format (format_newline (s, indent), "PF %u, TX parent TEID %u", id->pf_id, ip->tx_parent_teid);

  if (vec_len (info.pkg_info))
    {
      table_t packages = {};
      table_add_hdr_row (&packages, 7, "name", "version", "track ID", "NVM", "active", "boot",
			 "modified");
      table_set_cell_align (&packages, -1, 0, TTAA_LEFT);

      for (int i = 0; i < vec_len (info.pkg_info); i++)
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

      s = format_newline (s, indent);
      s = format (s, "Package info entries:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &packages);
      table_free (&packages);
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
  ice_reg_e830_mdet_tx_tclan_fifo_t mdet_fifo = {};
  ice_reg_e830_mdet_tx_tdpu_fifo_t mdet_tdpu_fifo = {};
  ice_reg_prtdcb_tdpuc_t tdpuc = {
    .as_u32 = ice_reg_read (dev, ICE_PRTDCB_TDPUC),
  };
  table_t mdd = {};
  int mdd_row = 0;

  if (id->config.has_mdd_fifo)
    {
      mdet_fifo.as_u32 = ice_reg_read (dev, ICE_E830_GL_MDET_TX_TCLAN_FIFO);
      mdet_tdpu_fifo.as_u32 = ice_reg_read (dev, ICE_E830_GL_MDET_TX_TDPU_FIFO);
    }

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

  if (mdet_fifo.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TCLAN FIFO");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_fifo.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "count %u, PF %u, function %u, type %u",
			 mdet_fifo.event_count, mdet_fifo.pf_num, mdet_fifo.function_num,
			 mdet_fifo.function_type);
    }

  if (mdet_tdpu_fifo.valid)
    {
      table_format_cell (&mdd, mdd_row, 0, "TDPU FIFO");
      table_format_cell (&mdd, mdd_row, 1, "%u", mdet_tdpu_fifo.event_type);
      table_format_cell (&mdd, mdd_row++, 2, "count %u, PF %u, function %u, type %u",
			 mdet_tdpu_fifo.event_count, mdet_tdpu_fifo.pf_num,
			 mdet_tdpu_fifo.function_num, mdet_tdpu_fifo.function_type);
    }

  if (mdd_row)
    {
      s = format_newline (s, indent);
      s = format (s, "MDD TX events:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &mdd);
      table_free (&mdd);
    }
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
      s = format_newline (s, indent);
      s = format (s, "TDPU status:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &status);
      table_free (&status);
    }

  if (a->clear)
    {
      if (mdet_pqm.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_PQM, CLIB_U32_MAX);

      if (mdet_tclan.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_TCLAN, CLIB_U32_MAX);

      if (mdet_tdpu.valid)
	ice_reg_write (dev, ICE_GL_MDET_TX_TDPU, CLIB_U32_MAX);

      if (mdet_fifo.valid)
	ice_reg_write (dev, ICE_E830_GL_MDET_TX_TCLAN_FIFO, CLIB_U32_MAX);

      if (mdet_tdpu_fifo.valid)
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
  s = format_newline (s, indent);
  s = format (s, "AdminQ rings:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &aq);
  table_free (&aq);

  if (vec_len (ip->vsi.sw_rules))
    {
      table_t rules = {};
      table_add_hdr_row (&rules, 8, "rule", "direction", "recipe", "source VSI", "target VSI",
			 "loopback", "LAN", "destination MAC");

      for (int i = 0; i < vec_len (ip->vsi.sw_rules); i++)
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

      s = format_newline (s, indent);
      s = format (s, "Programmed switch rules:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &rules);
      table_free (&rules);
    }

  return s;
}

static u8 *
format_ice_port_diagnostics (u8 *s, va_list *args)
{
  ice_port_status_t *status = va_arg (*args, ice_port_status_t *);
  u32 indent = format_get_indent (s);
  static const char *lane_speeds[] = {
    "100M", "1G", "2.5G", "5G", "10G", "25G", "50G", "100G", "200G", "40G",
  };
  ice_aqc_link_status_t *link = &status->link;
  table_t options = {};

  if (status->link_rv != VNET_DEV_OK)
    s = format (s, "Link diagnostics unavailable: %U", format_vnet_dev_rv, status->link_rv);
  else
    {
      u8 faults = 0;
      s = format (s, "Link: %s, media %s, signal %s, max frame %u",
		  link->link_info.link_up ? "up" : "down",
		  link->link_info.media_available ? "present" : "absent",
		  link->link_info.signal_detect ? "detected" : "absent", link->max_frame_size);
      s = format (
	format_newline (s, indent), "Autonegotiation: %s, partner ability %u, pause TX %u RX %u",
	link->an_info.completed ? "complete" : "incomplete", link->an_info.link_partner_ability,
	link->an_info.pause_tx, link->an_info.pause_rx);
      s = format (format_newline (s, indent),
		  "Active FEC: enabled %u, BASE-R %u, RS-528 %u, RS-544 %u, RS-272 %u",
		  link->an_info.fec_enabled, link->cfg.kr_25g_fec, link->cfg.rs_528_fec,
		  link->cfg.rs_544_fec, link->ext_fec_status.rs_272_fec);
      s = format (format_newline (s, indent), "Link faults:");
#define _(member, label)                                                                           \
  if (link->member)                                                                                \
    {                                                                                              \
      s = format (s, " %s", label);                                                                \
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
	s = format (s, " none");

      s = format_word_wrap_last_line (s, 100);
    }

  if (status->options_rv != VNET_DEV_OK)
    return format (format_newline (s, indent), "Port options unavailable: %U", format_vnet_dev_rv,
		   status->options_rv);

  table_add_hdr_col (&options, 1, "");
  table_add_hdr_row (&options, 6, "option", "active", "pending", "PMDs", "PMD width",
		     "max lane speed");

  for (int i = 0; i < status->options_params.port_options.count; i++)
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

  s = format_newline (s, indent);
  s = format (s, "Port options:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &options);
  table_free (&options);
  return s;
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
    s = format (format_newline (s, indent), "%U", format_ice_port_diagnostics, &status);
  else
    s = format (format_newline (s, indent), "Port diagnostics unavailable: %U", format_vnet_dev_rv,
		rv);

  if (a->debug == 0)
    return s;

  return format (format_newline (s, indent), "%U", format_ice_vsi_summary, port);
}

u8 *
format_ice_rx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  vnet_dev_t *dev = rxq->port->dev;
  ice_rxq_ctx_t ctx = {};
  ice_reg_qrx_ctrl_t ctrl;
  u16 q = rxq->queue_id;

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
  s = format (format_newline (s, indent + 2), "packet length %u descriptors %u", tr->packet_length,
	      tr->n_desc);

  for (i = 0; i < tr->n_desc; i++)
    {
      ice_rx_desc_t *d = tr->descs + i;

      s = format (format_newline (s, indent + 2),
		  "descriptor %u: RXDID %u status 0x%04x packet type %u length %u "
		  "RSS 0x%08x",
		  i, d->wb.rxdid, d->wb.status.as_u16, d->wb.packet_type.packet_type,
		  d->wb.packet_length.length, d->wb.rss_hash);
    }

  return s;
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
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  ice_reg_qtx_comm_head_t hw_head;
  ice_tx_cmd_t head_cmd = {};
  u16 q = txq->queue_id;
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
    s = format (format_newline (s, indent + 2), "dropped (%s)",
		vm->error_main.counters_heap[tr->error].name);
  else
    s = format (format_newline (s, indent + 2), "descriptors %u", tr->n_descs);

  for (i = 0; i < tr->n_descs; i++)
    s = format (format_newline (s, indent + 2), "descriptor %u: %U", i, format_ice_tx_desc,
		tr->descs + i);

  return s;
}
