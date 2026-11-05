/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vppinfra/format_table.h>

static vnet_dev_rv_t
ice_vsi_dump (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, u8 **s)
{
  ice_aqc_vsi_props_t props = {};
  table_t properties = {}, queues = {}, traffic_classes = {};
  u32 indent = format_get_indent (*s) + 4;
  int row = 0;

  vnet_dev_rv_t rv = ice_aq_get_vsi (vm, dev, vsi, &props);
  if (rv)
    return rv;

  table_add_hdr_col (&properties, 1, "");
  table_add_hdr_row (&properties, 2, "field", "value");
  table_set_cell_align (&properties, -1, -1, TTAA_LEFT);
#define _(field, fmt, label)                                                                       \
  table_format_cell (&properties, row, -1, "%s", label);                                           \
  table_set_cell_align (&properties, row, -1, TTAA_LEFT);                                          \
  table_format_cell (&properties, row++, 0, fmt, props.field);
  _ (valid_sections.as_u16, "0x%04x", "valid sections");
  _ (sw_id, "%u", "switch ID");
  _ (sw_flags.as_u8, "0x%02x", "switch flags");
  _ (sw_flags2.as_u8, "0x%02x", "switch flags 2");
  _ (sec_flags.as_u8, "0x%02x", "security flags");
  _ (port_based_inner_vlan, "%u", "inner VLAN");
  _ (inner_vlan_flags.as_u8, "0x%02x", "inner VLAN flags");
  _ (port_based_outer_vlan, "%u", "outer VLAN");
  _ (outer_vlan_flags, "0x%02x", "outer VLAN flags");
  _ (ingress_table, "0x%08x", "ingress UP table");
  _ (egress_table, "0x%08x", "egress UP table");
  _ (outer_up_table, "0x%08x", "outer UP table");
  _ (mapping_flags.as_u16, "0x%04x", "RX queue mapping flags");
  _ (q_opt_rss.lut_type, "%u", "RSS LUT type");
  _ (q_opt_rss.global_lut_index, "%u", "RSS global LUT index");
  _ (q_opt_rss.hash_type, "%u", "RSS hash type");
  _ (q_opt_tc, "0x%02x", "queue TC");
  _ (q_opt_flags, "0x%02x", "queue flags");
  _ (acl_def_act, "0x%04x", "ACL default action");
  _ (pasid_id, "0x%08x", "PASID");
#undef _
  *s = format (*s, "%UVSI %u:", format_white_space, indent, vsi);
  *s = format_newline (*s, indent + 2);
  *s = format (*s, "Properties:");
  *s = format_newline (*s, indent + 4);
  *s = format (*s, "%U", format_table, &properties);
  table_free (&properties);

  row = 0;
  table_add_hdr_col (&queues, 1, "");
  table_add_hdr_row (&queues, 2, "entry", "value");

  for (u32 first = 0; first < ARRAY_LEN (props.q_mapping); row++)
    {
      u32 last = first;

      while (last + 1 < ARRAY_LEN (props.q_mapping) &&
	     props.q_mapping[last + 1] == props.q_mapping[first])
	last++;

      if (first == last)
	table_format_cell (&queues, row, -1, "%u", first);
      else
	table_format_cell (&queues, row, -1, "%u-%u", first, last);

      table_format_cell (&queues, row, 0, "%u", props.q_mapping[first]);
      first = last + 1;
    }

  *s = format_newline (*s, indent + 2);
  *s = format (*s, "RX queue mapping:");
  *s = format_newline (*s, indent + 4);
  *s = format (*s, "%U", format_table, &queues);
  table_free (&queues);

  row = 0;
  table_add_hdr_col (&traffic_classes, 1, "");
  table_add_hdr_row (&traffic_classes, 3, "TC", "queue offset", "queue count log2");

  for (u32 first = 0; first < ARRAY_LEN (props.tc_mapping); row++)
    {
      u32 last = first;

      while (last + 1 < ARRAY_LEN (props.tc_mapping) &&
	     props.tc_mapping[last + 1].queue_offset == props.tc_mapping[first].queue_offset &&
	     props.tc_mapping[last + 1].queue_count_log2 ==
	       props.tc_mapping[first].queue_count_log2)
	last++;

      if (first == last)
	table_format_cell (&traffic_classes, row, -1, "%u", first);
      else
	table_format_cell (&traffic_classes, row, -1, "%u-%u", first, last);

      table_format_cell (&traffic_classes, row, 0, "%u", props.tc_mapping[first].queue_offset);
      table_format_cell (&traffic_classes, row, 1, "%u", props.tc_mapping[first].queue_count_log2);
      first = last + 1;
    }

  *s = format_newline (*s, indent + 2);
  *s = format (*s, "Traffic classes:");
  *s = format_newline (*s, indent + 4);
  *s = format (*s, "%U", format_table, &traffic_classes);
  *s = format_newline (*s, 0);
  table_free (&traffic_classes);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_dump_vsi (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;
  vnet_dev_rv_t rv;

  foreach_vnet_dev_port (port, dev)
    {
      ice_port_t *ip = vnet_dev_get_port_data (port);

      *s = format (*s, "  port %u:\n", port->port_id);

      if (ip->vsi.added)
	{
	  rv = ice_vsi_dump (vm, dev, ip->vsi.num, s);
	  if (rv)
	    return rv;
	}
      else
	*s = format (*s, "    no dataplane VSI\n");
    }

  return VNET_DEV_OK;
}

u8 *
format_ice_vsi_summary (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "programmed VSI: switch %u, valid sections 0x%04x, LAN %u, RX queues %u-%u",
	      ip->vsi.props.sw_id, ip->vsi.props.valid_sections.as_u16,
	      ip->vsi.props.sw_flags2.lan_enable, ip->vsi.props.q_mapping[0],
	      ip->vsi.props.q_mapping[0] + ip->vsi.props.q_mapping[1] - 1);
  s = format_word_wrap_last_line (s, 100);
  s = format (format_newline (s, indent),
	      "features: loopback %u, local loopback %u, source prune %u, "
	      "destination override %u",
	      ip->vsi.props.sw_flags.allow_loopback, ip->vsi.props.sw_flags.local_loopback,
	      ip->vsi.props.sw_flags.source_prune, ip->vsi.props.sec_flags.allow_dest_override);
  s = format_word_wrap_last_line (s, 100);
  return format (format_newline (s, indent), "VLAN: TX mode %u, egress mode %u",
		 ip->vsi.props.inner_vlan_flags.tx_mode,
		 ip->vsi.props.inner_vlan_flags.egress_mode);
}
