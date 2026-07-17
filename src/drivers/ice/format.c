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
format_ice_table (u8 *s, table_t *t, u32 indent)
{
  s = format_ice_indent (s, format (0, "\n%U", format_table, t), indent);
  table_free (t);
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

  table_t aq = {};
  table_add_hdr_row (&aq, 6, "ring", "entries", "DMA address", "head", "tail", "enabled");
  ice_reg_aq_len_t atq_len = { .as_u32 = ice_reg_read (dev, ICE_PF_FW_ATQLEN) };
  ice_reg_aq_len_t arq_len = { .as_u32 = ice_reg_read (dev, ICE_PF_FW_ARQLEN) };
  table_format_cell (&aq, 0, 0, "ATQ");
  table_format_cell (&aq, 0, 1, "%u", atq_len.length);
  table_format_cell (&aq, 0, 2, "0x%016lx", id->atq_dma);
  table_format_cell (&aq, 0, 3, "%u", ice_reg_read (dev, ICE_PF_FW_ATQH));
  table_format_cell (&aq, 0, 4, "%u", ice_reg_read (dev, ICE_PF_FW_ATQT));
  table_format_cell (&aq, 0, 5, "%u", atq_len.enable);
  table_format_cell (&aq, 1, 0, "ARQ");
  table_format_cell (&aq, 1, 1, "%u", arq_len.length);
  table_format_cell (&aq, 1, 2, "0x%016lx", id->arq_dma);
  table_format_cell (&aq, 1, 3, "%u", ice_reg_read (dev, ICE_PF_FW_ARQH));
  table_format_cell (&aq, 1, 4, "%u", ice_reg_read (dev, ICE_PF_FW_ARQT));
  table_format_cell (&aq, 1, 5, "%u", arq_len.enable);
  s = format_ice_table_section (s, &aq, indent, "AdminQ rings");

  table_t vsi = {};
  table_add_hdr_row (&vsi, 6, "VSI", "switch", "valid sections", "LAN", "RX base", "RX count");
  table_format_cell (&vsi, 0, 0, "%u", id->vsi_num);
  table_format_cell (&vsi, 0, 1, "%u", id->vsi_props.sw_id);
  table_format_cell (&vsi, 0, 2, "0x%04x", id->vsi_props.valid_sections.as_u16);
  table_format_cell (&vsi, 0, 3, "%u", id->vsi_props.sw_flags2.lan_enable);
  table_format_cell (&vsi, 0, 4, "%u", id->vsi_props.q_mapping[0]);
  table_format_cell (&vsi, 0, 5, "%u", id->vsi_props.q_mapping[1]);
  s = format_ice_table_section (s, &vsi, indent, "Programmed VSI");

  table_t queues = {};
  u32 row = 0;
  table_format_title (&queues, "Programmed LAN queue contexts");
  table_add_hdr_row (&queues, 8, "type", "queue", "DMA base", "length", "buffer", "VSI",
		     "max frame", "features");
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
	  row++;
	}
      foreach_vnet_dev_port_tx_queue (txq, port)
	{
	  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
	  if (!iq->ctx_valid)
	    continue;
	  table_format_cell (&queues, row, 0, "TX");
	  table_format_cell (&queues, row, 1, "%u", id->txq_base + txq->queue_id);
	  table_format_cell (&queues, row, 2, "0x%016lx", iq->ctx.base << 7);
	  table_format_cell (&queues, row, 3, "%u", iq->ctx.qlen);
	  table_format_cell (&queues, row, 4, "-");
	  table_format_cell (&queues, row, 5, "%u", iq->ctx.src_vsi);
	  table_format_cell (&queues, row, 6, "-");
	  table_format_cell (&queues, row, 7, "TSO %u, legacy interrupt %u", iq->ctx.tso_ena,
			     iq->ctx.legacy_int);
	  row++;
	}
    }
  if (row)
    s = format_ice_table (s, &queues, indent);
  else
    table_free (&queues);

  if (id->mac_rules_added)
    {
      table_t rules = {};
      table_add_hdr_row (&rules, 8, "rule", "direction", "recipe", "source VSI", "target VSI",
			 "loopback", "LAN", "destination MAC");
      for (u32 i = 0; i < ARRAY_LEN (id->mac_rules); i++)
	{
	  ice_sw_rule_t *r = id->mac_rules + i;
	  ice_sw_rule_action_t action = { .as_u32 = r->act };
	  table_format_cell (&rules, i, 0, "%u", i);
	  table_format_cell (&rules, i, 1, "%U", format_ice_sw_rule_type, r->type);
	  table_format_cell (&rules, i, 2, "%U", format_ice_sw_recipe, r->recipe_id);
	  table_format_cell (&rules, i, 3, "%u", r->src);
	  table_format_cell (&rules, i, 4, "%u", action.vsi_id);
	  table_format_cell (&rules, i, 5, "%s", action.loopback_enable ? "yes" : "no");
	  table_format_cell (&rules, i, 6, "%s", action.lan_enable ? "yes" : "no");
	  table_format_cell (&rules, i, 7, "%U", format_ethernet_address, r->hdr_data);
	}
      s = format_ice_table_section (s, &rules, indent, "Programmed MAC switch rules");
    }

  return s;
}

u8 *
format_ice_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ice_dev_t *id = vnet_dev_get_data (port->dev);
  return format (s, "vsi %u, lport %u, rxq %u, txq %u", id->vsi_num, id->lport, id->rxq_base,
		 id->txq_base);
}

u8 *
format_ice_rx_trace (u8 *s, va_list *args)
{
  (void) va_arg (*args, vlib_main_t *);
  (void) va_arg (*args, vlib_node_t *);
  ice_rx_trace_t *tr = va_arg (*args, ice_rx_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "ice-rx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  return format_ice_indent (s,
			    format (0, "\nstatus 0x%016lx length %u", tr->desc.wb.status.as_u64,
				    tr->desc.wb.status.packet_length),
			    indent + 2);
}

u8 *
format_ice_tx_trace (u8 *s, va_list *args)
{
  (void) va_arg (*args, vlib_main_t *);
  (void) va_arg (*args, vlib_node_t *);
  ice_tx_trace_t *tr = va_arg (*args, ice_tx_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "ice-tx: sw_if_index %u queue %u buffer %u", tr->sw_if_index, tr->queue_id,
	      tr->buffer_index);
  return format_ice_indent (
    s, format (0, "\naddr 0x%016lx command 0x%016lx", tr->desc.buf_addr, tr->desc.cmd.as_u64),
    indent + 2);
}
