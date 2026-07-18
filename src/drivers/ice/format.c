/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/format_table.h>

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
  u32 indent = format_get_indent (s);

  s =
    format (s, "family %U FW %u.%u.%u (branch %u build 0x%08x) API %u.%u.%u (branch %u)",
	    format_ice_family, id->family, id->fw_major, id->fw_minor, id->fw_patch, id->fw_branch,
	    id->fw_build, id->api_major, id->api_minor, id->api_patch, id->api_branch);
  s = format_ice_indent (s,
			 format (0, "\nNVM %x.%02x DDP %u.%u.%u.%u ROM ID 0x%08x", id->nvm_major,
				 id->nvm_minor, id->ddp_ver.major, id->ddp_ver.minor,
				 id->ddp_ver.update, id->ddp_ver.draft, id->rom_ver),
			 indent);
  if (a->debug == 0)
    return s;

  s = format_ice_indent (s, format (0, "\nPF %u, TX parent TEID %u", id->pf_id, id->tx_parent_teid),
			 indent);

  if (vec_len (id->dev_caps))
    {
      table_t caps = {};
      table_add_hdr_row (&caps, 5, "capability", "version", "number", "logical ID", "physical ID");
      table_set_cell_align (&caps, -1, 0, TTAA_LEFT);
      for (u32 i = 0; i < vec_len (id->dev_caps); i++)
	{
	  ice_aqc_list_caps_elem_t *cap = id->dev_caps + i;
	  table_format_cell (&caps, i, 0, "%U", format_ice_aqc_capability, cap->cap);
	  table_format_cell (&caps, i, 1, "%u.%u", cap->major_ver, cap->minor_ver);
	  table_format_cell (&caps, i, 2, "%u", cap->number);
	  table_format_cell (&caps, i, 3, "0x%08x", cap->logical_id);
	  table_format_cell (&caps, i, 4, "0x%08x", cap->phys_id);
	  table_set_cell_align (&caps, i, 0, TTAA_LEFT);
	}
      s = format_ice_table_section (s, &caps, indent, "Device capability entries");
    }

  if (vec_len (id->pkg_info))
    {
      table_t packages = {};
      table_add_hdr_row (&packages, 7, "name", "version", "track ID", "NVM", "active", "boot",
			 "modified");
      table_set_cell_align (&packages, -1, 0, TTAA_LEFT);
      for (u32 i = 0; i < vec_len (id->pkg_info); i++)
	{
	  ice_aqc_pkg_info_t *pkg = id->pkg_info + i;
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
  if (mdet_pqm.valid)
    s = format_ice_indent (s,
			   format (0, "\nMDD TX PQM event %u, PF %u VF %u queue %u",
				   mdet_pqm.event_type, mdet_pqm.pf_num, mdet_pqm.vf_num,
				   mdet_pqm.queue_num),
			   indent);
  if (mdet_tclan.valid)
    s = format_ice_indent (s,
			   format (0, "\nMDD TX TCLAN event %u, PF %u VF %u queue %u",
				   mdet_tclan.event_type, mdet_tclan.pf_num, mdet_tclan.vf_num,
				   mdet_tclan.queue_num),
			   indent);
  if (mdet_tdpu.valid)
    s = format_ice_indent (s,
			   format (0, "\nMDD TX TDPU event %u, PF %u VF %u queue %u",
				   mdet_tdpu.event_type, mdet_tdpu.pf_num, mdet_tdpu.vf_num,
				   mdet_tdpu.queue_num),
			   indent);
  if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_fifo.valid)
    s = format_ice_indent (
      s,
      format (0, "\nMDD TX TCLAN FIFO event %u, count %u, PF %u function %u type %u",
	      mdet_fifo.event_type, mdet_fifo.event_count, mdet_fifo.pf_num, mdet_fifo.function_num,
	      mdet_fifo.function_type),
      indent);
  if (id->family != ICE_DEVICE_FAMILY_E810 && mdet_tdpu_fifo.valid)
    s = format_ice_indent (
      s,
      format (0, "\nMDD TX TDPU FIFO event %u, count %u, PF %u function %u type %u",
	      mdet_tdpu_fifo.event_type, mdet_tdpu_fifo.event_count, mdet_tdpu_fifo.pf_num,
	      mdet_tdpu_fifo.function_num, mdet_tdpu_fifo.function_type),
      indent);
  if (tdpuc.malformed_length || tdpuc.malformed_command || tdpuc.ttl_drop ||
      tdpuc.unsupported_request_drop || tdpuc.big_packet_size || tdpuc.l2_accept_fail ||
      tdpuc.dscp_check_fail)
    s = format_ice_indent (
      s,
      format (0,
	      "\nTDPU status: max frame %u, malformed length %u, malformed command %u, "
	      "TTL drop %u, unsupported request %u, big packet %u, L2 accept fail %u, "
	      "DSCP check fail %u",
	      tdpuc.max_tx_frame, tdpuc.malformed_length, tdpuc.malformed_command, tdpuc.ttl_drop,
	      tdpuc.unsupported_request_drop, tdpuc.big_packet_size, tdpuc.l2_accept_fail,
	      tdpuc.dscp_check_fail),
      indent);

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

  table_t vsi = {};
  table_add_hdr_row (&vsi, 7, "VSI", "switch", "valid sections", "LAN", "RX base", "RX count",
		     "features");
  table_set_cell_align (&vsi, -1, 6, TTAA_LEFT);
  table_format_cell (&vsi, 0, 0, "%u", id->vsi_num);
  table_format_cell (&vsi, 0, 1, "%u", id->vsi_props.sw_id);
  table_format_cell (&vsi, 0, 2, "0x%04x", id->vsi_props.valid_sections.as_u16);
  table_format_cell (&vsi, 0, 3, "%u", id->vsi_props.sw_flags2.lan_enable);
  table_format_cell (&vsi, 0, 4, "%u", id->vsi_props.q_mapping[0]);
  table_format_cell (&vsi, 0, 5, "%u", id->vsi_props.q_mapping[1]);
  table_format_cell (
    &vsi, 0, 6,
    "loopback %u, local loopback %u, source prune %u, destination override %u, "
    "TX VLAN mode %u, egress mode %u",
    id->vsi_props.sw_flags.allow_loopback, id->vsi_props.sw_flags.local_loopback,
    id->vsi_props.sw_flags.source_prune, id->vsi_props.sec_flags.allow_dest_override,
    id->vsi_props.inner_vlan_flags.tx_mode, id->vsi_props.inner_vlan_flags.egress_mode);
  table_set_cell_align (&vsi, 0, 6, TTAA_LEFT);
  s = format_ice_table_section (s, &vsi, indent, "Programmed VSI");

  table_t queues = {};
  u32 row = 0;
  table_add_hdr_row (&queues, 8, "type", "queue", "DMA base", "length", "buffer", "VSI",
		     "max frame", "features");
  table_set_cell_align (&queues, -1, 7, TTAA_LEFT);
  foreach_vnet_dev_port (port, dev)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
	  if (!iq->ctx_valid)
	    continue;
	  table_format_cell (&queues, row, 0, "RX");
	  table_format_cell (&queues, row, 1, "%u", id->rxq_base + rxq->queue_id);
	  table_format_cell (&queues, row, 2, "0x%016lx", iq->ctx.base << 7);
	  table_format_cell (&queues, row, 3, "%u", iq->ctx.qlen);
	  table_format_cell (&queues, row, 4, "%u", iq->ctx.dbuf << 7);
	  table_format_cell (&queues, row, 5, "-");
	  table_format_cell (&queues, row, 6, "%u", iq->ctx.rxmax);
	  table_format_cell (&queues, row, 7, "CRC strip %u, L2 %u, prefetch %u", iq->ctx.crcstrip,
			     iq->ctx.l2tsel, iq->ctx.prefena);
	  table_set_cell_align (&queues, row, 7, TTAA_LEFT);
	  row++;
	}
      foreach_vnet_dev_port_tx_queue (txq, port)
	{
	  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
	  u16 q = id->txq_base + txq->queue_id;
	  ice_reg_qtx_comm_head_t hw_head = {
	    .as_u32 = ice_reg_read (dev, ICE_QTX_COMM_HEAD (q)),
	  };
	  ice_tx_cmd_t head_cmd = {};
	  if (!iq->ctx_valid)
	    continue;
	  if (iq->head != iq->tail)
	    head_cmd = iq->descs[iq->head & (txq->size - 1)].cmd;
	  table_format_cell (&queues, row, 0, "TX");
	  table_format_cell (&queues, row, 1, "%u", q);
	  table_format_cell (&queues, row, 2, "0x%016lx", iq->ctx.base << 7);
	  table_format_cell (&queues, row, 3, "%u", iq->ctx.qlen);
	  table_format_cell (&queues, row, 4, "-");
	  table_format_cell (&queues, row, 5, "%u", iq->ctx.src_vsi);
	  table_format_cell (&queues, row, 6, "-");
	  table_format_cell (&queues, row, 7,
			     "TEID %u, head %u, tail %u, HW head %u, descriptor type %u, "
			     "TSO %u, legacy interrupt %u",
			     iq->q_teid, iq->head, iq->tail, hw_head.head, head_cmd.descriptor_type,
			     iq->ctx.tso_ena, iq->ctx.legacy_int);
	  table_set_cell_align (&queues, row, 7, TTAA_LEFT);
	  row++;
	}
    }
  if (row)
    s = format_ice_table_section (s, &queues, indent, "Programmed LAN queue contexts");
  else
    table_free (&queues);

  if (vec_len (id->sw_rules))
    {
      table_t rules = {};
      table_add_hdr_row (&rules, 8, "rule", "direction", "recipe", "source VSI", "target VSI",
			 "loopback", "LAN", "destination MAC");
      for (u32 i = 0; i < vec_len (id->sw_rules); i++)
	{
	  ice_sw_rule_t *r = id->sw_rules + i;
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

u8 *
format_ice_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "vsi %u, lport %u, rxq %u, txq %u", id->vsi_num, id->lport, id->rxq_base,
	      id->txq_base);
  if (!ip->rss_configured)
    return s;

  s =
    format (s, ", RSS enabled, %u queues, %u-entry VSI LUT", ip->rss_queue_count, ICE_RSS_LUT_SIZE);
  if (a->debug == 0)
    return s;

  s = format_ice_indent (
    s,
    format (0, "\nRSS key %U", format_hex_bytes_no_wrap, port->rss_key.key, port->rss_key.length),
    indent);
  {
    table_t lut = {};

    for (u32 row = 0; row < 4; row++)
      for (u32 column = 0; column < 16; column++)
	table_format_cell (&lut, row, column, "%u", ip->rss_lut.entries[row * 16 + column]);
    return format_ice_table_section (s, &lut, indent, "RSS LUT");
  }
}

u8 *
format_ice_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm __clib_unused = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  ice_rx_trace_t *tr = va_arg (*args, ice_rx_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "ice-rx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  return format_ice_indent (
    s,
    format (0, "\nRXDID %u status 0x%04x packet type %u length %u descriptors %u RSS 0x%08x",
	    tr->desc.wb.rxdid, tr->desc.wb.status.as_u16, tr->desc.wb.packet_type.packet_type,
	    tr->packet_length, tr->n_desc, tr->desc.wb.rss_hash),
    indent + 2);
}

u8 *
format_ice_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm __clib_unused = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  ice_tx_trace_t *tr = va_arg (*args, ice_tx_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "ice-tx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  return format_ice_indent (s,
			    format (0, "\naddr 0x%016lx command 0x%016lx descriptors %u",
				    tr->desc.buf_addr, tr->desc.cmd.as_u64, tr->n_desc),
			    indent + 2);
}
