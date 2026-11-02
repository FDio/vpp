/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

static vnet_dev_rv_t
ice_vsi_dump (vlib_main_t *vm, vnet_dev_t *dev, u16 vsi, u8 **s)
{
  ice_aqc_vsi_props_t props = {};
  vnet_dev_rv_t rv = ice_aq_get_vsi (vm, dev, vsi, &props);

  if (rv)
    return rv;
  *s =
    format (*s, "    VSI %u: valid sections 0x%04x, switch %u, switch flags 0x%02x/0x%02x\n", vsi,
	    props.valid_sections.as_u16, props.sw_id, props.sw_flags.as_u8, props.sw_flags2.as_u8);
  *s =
    format (*s, "      security 0x%02x, inner VLAN %u flags 0x%02x, outer VLAN %u flags 0x%02x\n",
	    props.sec_flags.as_u8, props.port_based_inner_vlan, props.inner_vlan_flags.as_u8,
	    props.port_based_outer_vlan, props.outer_vlan_flags);
  *s = format (*s, "      UP tables: ingress 0x%08x, egress 0x%08x, outer 0x%08x\n",
	       props.ingress_table, props.egress_table, props.outer_up_table);
  *s = format (*s, "      RX queue mapping flags 0x%04x:", props.mapping_flags.as_u16);
  for (u32 i = 0; i < ARRAY_LEN (props.q_mapping); i++)
    *s = format (*s, " %u", props.q_mapping[i]);
  *s = format (*s, "\n      TC  queue offset  queue count log2\n");
  for (u32 i = 0; i < ARRAY_LEN (props.tc_mapping); i++)
    *s = format (*s, "      %2u  %12u  %16u\n", i, props.tc_mapping[i].queue_offset,
		 props.tc_mapping[i].queue_count_log2);
  *s =
    format (*s, "      RSS LUT type %u, global index %u, hash type %u\n", props.q_opt_rss.lut_type,
	    props.q_opt_rss.global_lut_index, props.q_opt_rss.hash_type);
  *s = format (*s, "      queue TC 0x%02x, queue flags 0x%02x, ACL action 0x%04x, PASID 0x%08x\n",
	       props.q_opt_tc, props.q_opt_flags, props.acl_def_act, props.pasid_id);
  *s = format (
    *s, "      FDIR options 0x%04x, dedicated %u, shared %u, default queue %u, report 0x%04x\n",
    props.fd_options, props.max_fd_fltr_dedicated, props.max_fd_fltr_shared, props.fd_def_q,
    props.fd_report_opt);
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
      u16 control = ice_fdir_control_vsi (port);

      *s = format (*s, "  port %u:\n", port->port_id);
      if (ip->vsi.added)
	{
	  if ((rv = ice_vsi_dump (vm, dev, ip->vsi.num, s)))
	    return rv;
	}
      else
	*s = format (*s, "    no dataplane VSI\n");
      if (control != (u16) ~0)
	{
	  *s = format (*s, "    FDIR programming VSI:\n");
	  if ((rv = ice_vsi_dump (vm, dev, control, s)))
	    return rv;
	}
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
