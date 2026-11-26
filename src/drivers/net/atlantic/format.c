/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <atlantic.h>

static u8 *
_format_atl_reg (u8 *s, u32 offset, u32 val, int no_zero, u32 mask)
{
  u32 indent = format_get_indent (s);
  u32 rv = 0, f, v;
  u8 *s2 = 0;
  int line = 0;

#define _(o, rn, m)                                                                                \
  if (offset == o)                                                                                 \
    {                                                                                              \
      if (line++)                                                                                  \
	s = format (s, "\n%U", format_white_space, indent);                                        \
      vec_reset_length (s2);                                                                       \
      s2 = format (s2, "[0x%05x] %s:", o, #rn);                                                    \
      rv = val;                                                                                    \
      s = format (s, "%-32v = 0x%08x", s2, rv);                                                    \
      f = 0;                                                                                       \
      m                                                                                            \
    }

#define __(l, fn)                                                                                  \
  v = (rv >> f) & pow2_mask (l);                                                                   \
  if ((pow2_mask (l) << f) & mask)                                                                 \
    if (v || (!no_zero && #fn[0] != '_'))                                                          \
      {                                                                                            \
	vec_reset_length (s2);                                                                     \
	s = format (s, "\n%U", format_white_space, indent + 2);                                    \
	s2 = format (s2, "[%2u:%2u] %s", f + l - 1, f, #fn);                                       \
	s = format (s, "%-30v = ", s2);                                                            \
	if (l < 3)                                                                                 \
	  s = format (s, "%u", v);                                                                 \
	else if (l <= 8)                                                                           \
	  s = format (s, "0x%02x (%u)", v, v);                                                     \
	else if (l <= 16)                                                                          \
	  s = format (s, "0x%04x", v);                                                             \
	else                                                                                       \
	  s = format (s, "0x%08x", v);                                                             \
      }                                                                                            \
  f += l;

  foreach_atl_reg;
#undef _
#undef __

  if (line == 0)
    s = format (s, "[0x%05x] 0x%08x", offset, val);

  vec_free (s2);

  return s;
}

u8 *
format_atl_regs (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_atl_reg (s, offset, val, 0, 0xffffffff);
}

u8 *
format_atl_fw_version (u8 *s, va_list *args)
{
  atl_fw_version_t v = { .as_u32 = va_arg (*args, u32) };
  return format (s, "%u.%u.%u", v.major, v.minor, v.build);
}

u8 *
format_atl_iface_version (u8 *s, va_list *args)
{
  atl_iface_ver_t v = { .as_u32 = va_arg (*args, u32) };
  switch (v.iface_ver)
    {
    case 0:
      return format (s, "A0");
    case 1:
      return format (s, "B0");
    default:
      return format (s, "unknown (%u)", v.iface_ver);
    }
}

u8 *
format_atl_aq2_art_action (u8 *s, va_list *args)
{
  static const char *const action_names[] = {
#define _(v, n) [ATL_AQ2_ART_ACTION_##n] = #n,
    foreach_atl_aq2_art_action
#undef _
  };
  u32 action = va_arg (*args, u32);
  const char *name = "UNKNOWN";

  if (action < ARRAY_LEN (action_names) && action_names[action])
    name = action_names[action];

  return format (s, "%s(%u)", name, action);
}

#define foreach_atl_rx_wb_l3_type                                                                  \
  _ (0, IPv4)                                                                                      \
  _ (1, IPv6)                                                                                      \
  _ (3, NonIP)

#define foreach_atl_rx_wb_l4_type                                                                  \
  _ (0, TCP)                                                                                       \
  _ (1, UDP)                                                                                       \
  _ (3, ICMPv4)                                                                                    \
  _ (4, Other)

static const char *const atl_rx_wb_l3_type_names[] = {
#define _(v, n) [v] = #n,
  foreach_atl_rx_wb_l3_type
#undef _
};

static const char *const atl_rx_wb_l4_type_names[] = {
#define _(v, n) [v] = #n,
  foreach_atl_rx_wb_l4_type
#undef _
};

u8 *
format_atl_rx_wb_desc (u8 *s, va_list *args)
{
  const atl_rx_desc_t *d = va_arg (*args, const atl_rx_desc_t *);
  u32 indent = format_get_indent (s);
  const char *l3_name = "Unknown";
  const char *l4_name = "Unknown";

#define _(b) ((b) ? '+' : '-')

  if (d->qw0.l3_type < ARRAY_LEN (atl_rx_wb_l3_type_names) &&
      atl_rx_wb_l3_type_names[d->qw0.l3_type])
    l3_name = atl_rx_wb_l3_type_names[d->qw0.l3_type];
  if (d->qw0.l4_type < ARRAY_LEN (atl_rx_wb_l4_type_names) &&
      atl_rx_wb_l4_type_names[d->qw0.l4_type])
    l4_name = atl_rx_wb_l4_type_names[d->qw0.l4_type];

  s = format (s, "type 0x%08x rss 0x%08x status 0x%04x len %u next %u vlan %u", d->qw0.type,
	      d->qw0.rss_hash, d->qw1.status, d->qw1.pkt_len, d->qw1.next_desc_ptr, d->qw1.vlan);

  s = format_newline (s, indent);
  s = format (s,
	      "flags: rss_type 0x%x l3_type %s(%u) l4_type %s(%u) vlan%c vlan2%c dma_err%c "
	      "rx_ctrl 0x%x spl_hdr%c hdr_len %u",
	      d->qw0.rss_type, l3_name, d->qw0.l3_type, l4_name, d->qw0.l4_type,
	      _ (d->qw0.pkt_vlan), _ (d->qw0.pkt_vlan2), _ (d->qw0.dma_err), d->qw0.rx_ctrl,
	      _ (d->qw0.spl_hdr), d->qw0.hdr_len);

  s = format_newline (s, indent);
  s = format (
    s,
    "status: dd%c eop%c mac_err%c v4_sum_ng%c l4_sum_err%c l4_sum_ok%c rx_estat 0x%x rsc_cnt 0x%x",
    _ (d->qw1.dd), _ (d->qw1.eop), _ (d->qw1.mac_err), _ (d->qw1.v4_sum_ng), _ (d->qw1.l4_sum_err),
    _ (d->qw1.l4_sum_ok), d->qw1.rx_estat, d->qw1.rsc_cnt);

#undef _

  return s;
}

u8 *
atl_rx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_rx_trace_t *t = va_arg (*args, atl_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface_api_visible_or_null (vnm, t->sw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "atl: %v (%u) qid %u head_slot %u buffer %u", hi ? hi->name : (u8 *) "(unknown)",
	      hi ? hi->hw_if_index : t->sw_if_index, t->queue_id, t->head_slot, t->buffer_index);
  s = format_newline (s, indent + 2);
  s = format (s, "packet length %u descriptors %u", t->packet_length, t->n_desc);

  for (u32 i = 0; i < t->n_desc; i++)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "descriptor %u: %U", i, format_atl_rx_wb_desc, &t->desc[i]);
    }
  return s;
}

u8 *
atl_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_tx_trace_t *t = va_arg (*args, atl_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "atl-tx: sw_if_index %u queue %u buffer %u", t->sw_if_index, t->queue_id,
	      t->buffer_index);
  s = format_newline (s, indent + 2);
  if (t->n_desc == 0)
    s = format (s, "dropped (%s)", vm->error_main.counters_heap[t->error].name);
  else
    s = format (s, "descriptors %u", t->n_desc);

  for (u32 i = 0; i < t->n_desc; i++)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "descriptor %u: %U", i, format_atl_tx_desc, &t->desc[i]);
    }
  return s;
}

void
styled_format_atl_dev_caps (styled_text_t *st, va_list *args)
{
  va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  atl_reg_aq2_device_caps_t device_caps;
  vnet_dev_rv_t rv;

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_DEVICE_CAPS,
				      &device_caps.as_u32, 1);
  if (rv == VNET_DEV_OK)
    styled_text_add_marked (
      st, ST_R_VALUE, "flashless %{%u%} cable_diag %{%u%} ncsi %{%u%} avb %{%u%}",
      device_caps.finite_flashless, device_caps.cable_diag, device_caps.ncsi, device_caps.avb);
  else
    styled_text_add_marked (st, ST_R_ERROR, "device caps read failed: %{%U%}", format_vnet_dev_rv,
			    rv);
}

void
styled_format_atl_dev_info (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  u32 v;
  atl_reg_glb_mif_id_t hwrev;
  atl_reg_aq2_phy_health_monitor_t phy_health;
  atl_reg_aq2_mac_health_monitor_t mac_health;
  atl_aq2_management_status_t mgmt_status;
  vnet_dev_rv_t rv;

  hwrev.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_HW_REVISION);
  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_IFACE, &v, 1);
  styled_text_add_marked (st, ST_R_VALUE, "Chip: Atlantic2 %{%U%} revision %{0x%x%}",
			  format_atl_iface_version, v, hwrev.mif_id);

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE, &v, 1);
  if (rv == VNET_DEV_OK)
    styled_text_add_marked (st, ST_R_VALUE, " bundle fw %{%U%}", format_atl_fw_version, v);

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_MAC, &v, 1);
  if (rv == VNET_DEV_OK)
    styled_text_add_marked (st, ST_R_VALUE, "\nMAC: fw %{%U%}", format_atl_fw_version, v);
  else
    styled_text_add_marked (st, ST_R_VALUE, "\nMAC: fw %{n/a%}");

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_MAC_HEALTH_MONITOR, &mac_health.as_u32, 1);
  if (rv == VNET_DEV_OK)
    {
      styled_text_add_marked (st, ST_R_VALUE, " ready %{%u%}", mac_health.mac_ready);
      styled_text_add_marked (st, ST_R_VALUE,
			      " fault %{%u%} flashless_done %{%u%} temp %{%u%} heartbeat %{%u%}",
			      mac_health.mac_fault, mac_health.mac_flashless_finished,
			      mac_health.mac_temperature, mac_health.mac_heart_beat);
    }

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_PHY, &v, 1);
  if (rv == VNET_DEV_OK)
    styled_text_add_marked (st, ST_R_VALUE, "\nPHY: fw %{%U%}", format_atl_fw_version, v);
  else
    styled_text_add_marked (st, ST_R_VALUE, "\nPHY: fw %{n/a%}");

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_PHY_HEALTH_MONITOR, &phy_health.as_u32, 1);
  if (rv == VNET_DEV_OK)
    {
      styled_text_add_marked (st, ST_R_VALUE, " ready %{%u%}", phy_health.phy_ready);
      styled_text_add_marked (st, ST_R_VALUE,
			      " fault %{%u%} warn %{%u%} temp %{%u%} heartbeat %{%u%}",
			      phy_health.phy_fault, phy_health.phy_hot_warning,
			      phy_health.phy_temperature, phy_health.phy_heart_beat);
    }

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_MANAGEMENT_STATUS,
				      (u32 *) &mgmt_status, sizeof (mgmt_status) / sizeof (u32));
  if (rv == VNET_DEV_OK)
    {
      styled_text_add_marked (
	st, ST_R_VALUE, "\nManagement Status: mac %{%U%} vlan %{%u%} enable %{%u%}",
	format_ethernet_address, mgmt_status.mac, mgmt_status.vlan, mgmt_status.flags & 1);
    }
}

/* address and name of a register, then its value */
static void
styled_atl_add_reg (styled_text_t *st, u32 addr, char *name, u32 value)
{
  styled_text_add_marked (st, ST_R_VALUE, "0x%05x %-24s: %{0x%08x%}", addr, name, value);
}

void
styled_format_atl_rpf_info (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  atl_reg_rpf_l2bc_t rpf_l2bc = atl_reg_rd (dev, ATL_REG_RPF_L2BC).rpf_l2bc;
  atl_reg_aq2_rpf_l2bc_tag_t rpf_l2bc_tag =
    atl_reg_rd (dev, ATL_REG_AQ2_RPF_L2BC_TAG).aq2_rpf_l2bc_tag;
  u32 rpf_mcast_filter_mask = atl_reg_rd_u32 (dev, ATL_REG_RPF_MCAST_FILTER_MASK);
  atl_reg_rpf_l3_v6_v4_select_t rpf_l3_v6_v4_select =
    atl_reg_rd (dev, ATL_REG_RPF_L3_V6_V4_SELECT).rpf_l3_v6_v4_select;
  atl_reg_aq2_rpf_new_ctrl_t rpf_new_ctrl =
    atl_reg_rd (dev, ATL_REG_AQ2_RPF_NEW_CTRL).aq2_rpf_new_ctrl;
  u32 rpf_rx_tc_upt = atl_reg_rd_u32 (dev, ATL_REG_RPF_RPB_RX_TC_UPT);
  atl_reg_rpb_rpf_rx_t rpf_rpb_rx = atl_reg_rd (dev, ATL_REG_RPB_RPF_RX).rpb_rpf_rx;
  atl_reg_rx_flr_rss_control1_t rpf_rss_ctrl1 =
    atl_reg_rd (dev, ATL_REG_RX_FLR_RSS_CONTROL1).rx_flr_rss_control1;
  atl_reg_aq2_rpf_redir2_t rpf_redir2 = atl_reg_rd (dev, ATL_REG_AQ2_RPF_REDIR2).aq2_rpf_redir2;
  struct
  {
    char *name;
    u8 on;
  } hashes[] = {
    { "ip", rpf_redir2.hashtype_ip },	      { "tcp4", rpf_redir2.hashtype_tcp4 },
    { "udp4", rpf_redir2.hashtype_udp4 },     { "ip6", rpf_redir2.hashtype_ip6 },
    { "tcp6", rpf_redir2.hashtype_tcp6 },     { "udp6", rpf_redir2.hashtype_udp6 },
    { "ip6ex", rpf_redir2.hashtype_ip6ex },   { "tcp6ex", rpf_redir2.hashtype_tcp6ex },
    { "udp6ex", rpf_redir2.hashtype_udp6ex },
  };

  styled_atl_add_reg (st, ATL_REG_RPF_L2BC, "RPF_L2BC", rpf_l2bc.as_u32);
  styled_text_add_marked (st, ST_R_VALUE,
			  " (en %{%u%} promisc %{%u%} action %{%u%} threshold %{0x%04x%})\n",
			  rpf_l2bc.en, rpf_l2bc.promisc, rpf_l2bc.action, rpf_l2bc.threshold);
  styled_atl_add_reg (st, ATL_REG_AQ2_RPF_L2BC_TAG, "AQ2_RPF_L2BC_TAG", rpf_l2bc_tag.as_u32);
  styled_text_add_marked (st, ST_R_VALUE, " (tag %{0x%02x%})\n", rpf_l2bc_tag.tag);
  styled_atl_add_reg (st, ATL_REG_RPF_MCAST_FILTER_MASK, "RPF_MCAST_FILTER_MASK",
		      rpf_mcast_filter_mask);
  styled_text_add (st, "\n");
  styled_atl_add_reg (st, ATL_REG_RPF_L3_V6_V4_SELECT, "RPF_L3_V6_V4_SELECT",
		      rpf_l3_v6_v4_select.as_u32);
  styled_text_add_marked (st, ST_R_VALUE, " (v6_v4_select %{%u%})\n",
			  rpf_l3_v6_v4_select.v6_v4_select);
  styled_atl_add_reg (st, ATL_REG_AQ2_RPF_NEW_CTRL, "AQ2_RPF_NEW_CTRL", rpf_new_ctrl.as_u32);
  styled_text_add_marked (st, ST_R_VALUE, " (enable %{%u%})\n", rpf_new_ctrl.enable);
  styled_atl_add_reg (st, ATL_REG_RPF_RPB_RX_TC_UPT, "RPF_RPB_RX_TC_UPT", rpf_rx_tc_upt);

  for (u32 tc = 0; tc < 8; tc++)
    {
      styled_text_add_marked (st, ST_R_VALUE, "%stc%u %{%u%}", tc ? " " : " (", tc,
			      (rpf_rx_tc_upt >> (4 * tc)) & 0x7);
    }

  styled_text_add (st, ")\n");
  styled_atl_add_reg (st, ATL_REG_RPB_RPF_RX, "RPB_RPF_RX", rpf_rpb_rx.as_u32);
  styled_text_add_marked (st, ST_R_VALUE, " (buf_en %{%u%} fc_mode %{%u%} tc_mode %{%u%})\n",
			  rpf_rpb_rx.buf_en, rpf_rpb_rx.fc_mode, rpf_rpb_rx.tc_mode);
  styled_atl_add_reg (st, ATL_REG_RX_FLR_RSS_CONTROL1, "RX_FLR_RSS_CONTROL1", rpf_rss_ctrl1.as_u32);
  styled_text_add_marked (st, ST_R_VALUE, " (queues %{0x%08x%} en %{%u%})\n", rpf_rss_ctrl1.queues,
			  rpf_rss_ctrl1.en);
  styled_atl_add_reg (st, ATL_REG_AQ2_RPF_REDIR2, "AQ2_RPF_REDIR2", rpf_redir2.as_u32);
  styled_text_add (st, " (");

  for (u32 i = 0; i < ARRAY_LEN (hashes); i++)
    {
      styled_text_add_marked (st, ST_R_VALUE, "%s%{%c%} ", hashes[i].name,
			      hashes[i].on ? '+' : '-');
    }

  styled_text_add_marked (st, ST_R_VALUE, "index %{%u%})", rpf_redir2.index);
}

void
styled_format_atl_link_capa (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  atl_reg_aq2_fw_interface_out_device_link_caps_t *caps =
    va_arg (*args, atl_reg_aq2_fw_interface_out_device_link_caps_t *);

#define ATL_PM(b) ((b) ? '+' : '-')

  styled_text_add_marked (st, ST_R_VALUE, "PauseRX%{%c%}", ATL_PM (caps->pause_rx));
  styled_text_add_marked (st, ST_R_VALUE, " PauseTX%{%c%} PFC%{%c%} Downshift%{%c%}",
			  ATL_PM (caps->pause_tx), ATL_PM (caps->pfc), ATL_PM (caps->downshift));
  styled_text_add_marked (st, ST_R_VALUE, " DownshiftRetries %{%u%} IntLoop%{%c%} ExtLoop%{%c%}",
			  caps->downshift_retry, ATL_PM (caps->internal_loopback),
			  ATL_PM (caps->external_loopback));
  styled_text_add_marked (st, ST_R_VALUE,
			  "\nRates: 10M%{%c%} 10M/HD%{%c%} 100M%{%c%} 100M/HD%{%c%}",
			  ATL_PM (caps->rate_10m), ATL_PM (caps->rate_10m_hd),
			  ATL_PM (caps->rate_100m), ATL_PM (caps->rate_100m_hd));
  styled_text_add_marked (st, ST_R_VALUE, " 1G%{%c%} 1G/HD%{%c%} 2.5G%{%c%} N2.5G%{%c%}",
			  ATL_PM (caps->rate_1g), ATL_PM (caps->rate_1g_hd),
			  ATL_PM (caps->rate_2p5g), ATL_PM (caps->rate_n2p5g));
  styled_text_add_marked (st, ST_R_VALUE, " 5G%{%c%} N5G%{%c%} 10G%{%c%}", ATL_PM (caps->rate_5g),
			  ATL_PM (caps->rate_n5g), ATL_PM (caps->rate_10g));
  styled_text_add_marked (st, ST_R_VALUE, "\nEEE: 100M%{%c%} 1G%{%c%} 2.5G%{%c%}",
			  ATL_PM (caps->eee_100m), ATL_PM (caps->eee_1g), ATL_PM (caps->eee_2p5g));
  styled_text_add_marked (st, ST_R_VALUE, " 5G%{%c%} 10G%{%c%}", ATL_PM (caps->eee_5g),
			  ATL_PM (caps->eee_10g));

#undef ATL_PM
}

void
styled_format_atl_partner_link_capa (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  atl_reg_aq2_fw_interface_out_lkp_link_caps_t *caps =
    va_arg (*args, atl_reg_aq2_fw_interface_out_lkp_link_caps_t *);

#define ATL_PM(b) ((b) ? '+' : '-')

  styled_text_add_marked (st, ST_R_VALUE, "Rates: 10M%{%c%}", ATL_PM (caps->rate_10m));
  styled_text_add_marked (st, ST_R_VALUE, " 10M/HD%{%c%} 100M%{%c%} 100M/HD%{%c%} 1G%{%c%}",
			  ATL_PM (caps->rate_10m_hd), ATL_PM (caps->rate_100m),
			  ATL_PM (caps->rate_100m_hd), ATL_PM (caps->rate_1g));
  styled_text_add_marked (st, ST_R_VALUE, " 1G/HD%{%c%} 2.5G%{%c%} N2.5G%{%c%} 5G%{%c%}",
			  ATL_PM (caps->rate_1g_hd), ATL_PM (caps->rate_2p5g),
			  ATL_PM (caps->rate_n2p5g), ATL_PM (caps->rate_5g));
  styled_text_add_marked (st, ST_R_VALUE, " N5G%{%c%} 10G%{%c%}", ATL_PM (caps->rate_n5g),
			  ATL_PM (caps->rate_10g));
  styled_text_add_marked (st, ST_R_VALUE, "\nEEE: 100M%{%c%} 1G%{%c%} 2.5G%{%c%}",
			  ATL_PM (caps->eee_100m), ATL_PM (caps->eee_1g), ATL_PM (caps->eee_2p5g));
  styled_text_add_marked (st, ST_R_VALUE, " 5G%{%c%} 10G%{%c%}", ATL_PM (caps->eee_5g),
			  ATL_PM (caps->eee_10g));
  styled_text_add_marked (st, ST_R_VALUE, "\nPause: TX%{%c%} RX%{%c%}", ATL_PM (caps->pause_tx),
			  ATL_PM (caps->pause_rx));

#undef ATL_PM
}

void
styled_format_atl_mac_addr_table (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  u32 l2_base_index = ad->caps.l2_base_index;
  u32 l2_count = ad->caps.l2_count;
  u32 l2_idx, l2uc_lsw, i;
  int first = 1;
  atl_reg_rpf_l2uc_msw_t l2uc_msw;

  if (l2_count == 0)
    l2_count = AQ_HW_MAC_NUM;

  for (i = 0; i < l2_count; i++)
    {
      l2_idx = l2_base_index + i;
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (l2_idx)).rpf_l2uc_msw;
      if (l2uc_msw.en == 0)
	continue;
      l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (l2_idx));
      if (!first)
	styled_text_add (st, "\n");
      styled_text_add_role (st, ST_R_VALUE, "%U", format_atl_l2uc, &l2uc_msw, l2uc_lsw);
      first = 0;
    }

  if (l2_base_index != 0)
    {
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (0)).rpf_l2uc_msw;
      if (l2uc_msw.en)
	{
	  l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (0));
	  if (!first)
	    styled_text_add (st, "\n");
	  styled_text_add_role (st, ST_R_VALUE, "%U", format_atl_l2uc, &l2uc_msw, l2uc_lsw);
	}
    }
}

void
styled_format_atl_cable_diag (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;
  atl_reg_aq2_cable_diag_lane_data_t lane_data;
  atl_reg_aq2_cable_diag_status_t status;
  u32 cable_diag_words[5];
  u32 lane;

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_CABLE_DIAG_LANE0,
				      cable_diag_words, ARRAY_LEN (cable_diag_words));
  if (rv != VNET_DEV_OK)
    {
      styled_text_add_marked (st, ST_R_ERROR, "read failed (rv %{%d%})", rv);
      return;
    }

  status.as_u32 = cable_diag_words[4];
  styled_text_add_marked (st, ST_R_VALUE, "status %{%u%} transact_id %{%u%}", status.status,
			  status.transact_id);

  for (lane = 0; lane < 4; lane++)
    {
      lane_data.as_u32 = cable_diag_words[lane];
      styled_text_add_marked (
	st, ST_R_VALUE, "\nlane %{%u%}: result %{%u%}, distance: %{%um%}, far distance %{%um%}",
	lane, lane_data.result_code, lane_data.dist, lane_data.far_dist);
    }
}

void
styled_format_atl_rss_info (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  u32 rss_ctrl1 = atl_reg_rd_u32 (dev, ATL_REG_RX_FLR_RSS_CONTROL1);
  u32 rpf_redir2 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_REDIR2);
  u32 rss_key_addr = atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR);
  u32 rss_key_wr = atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_WR_DATA);
  u32 rss_key_rd = atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_RD_DATA);
  u32 rss_key_words[10];
  u32 rx_tc_upt = atl_reg_rd_u32 (dev, ATL_REG_RPF_RPB_RX_TC_UPT);
  u32 rpb_rpf_rx = atl_reg_rd_u32 (dev, ATL_REG_RPB_RPF_RX);
  u32 rx_q_tc_map;
  u32 tx_q_tc_map;
  u32 rss_redir_val;
  u32 i;
  u32 tc;

  styled_atl_add_reg (st, ATL_REG_RX_FLR_RSS_CONTROL1, "RX_FLR_RSS_CONTROL1", rss_ctrl1);
  styled_text_add (st, "\n");
  styled_atl_add_reg (st, ATL_REG_AQ2_RPF_REDIR2, "AQ2_RPF_REDIR2", rpf_redir2);
  styled_text_add (st, "\n");
  styled_atl_add_reg (st, ATL_REG_RPF_RSS_KEY_ADDR, "RPF_RSS_KEY_ADDR", rss_key_addr);
  styled_text_add (st, "\n");
  styled_atl_add_reg (st, ATL_REG_RPF_RSS_KEY_WR_DATA, "RPF_RSS_KEY_WR_DATA", rss_key_wr);
  styled_text_add (st, "\n");
  styled_atl_add_reg (st, ATL_REG_RPF_RSS_KEY_RD_DATA, "RPF_RSS_KEY_RD_DATA", rss_key_rd);

  for (i = 0; i < ARRAY_LEN (rss_key_words); i++)
    {
      atl_reg_wr_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR, i);
      rss_key_words[i] = atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_RD_DATA);
    }

  styled_text_add_marked (st, ST_R_VALUE, "\nrss key:\n  %{%U%}", format_hex_bytes_no_wrap,
			  (u8 *) rss_key_words, sizeof (rss_key_words));

  styled_text_add (st, "\naq2 rss redir:");
  for (tc = 0; tc < 4; tc++)
    {
      styled_text_add (st, "\n  tc%u:", tc);
      for (i = 0; i < 64; i++)
	{
	  rss_redir_val = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_RSS_REDIR (i));
	  if (i == 32)
	    styled_text_add (st, "\n      ");
	  styled_text_add_marked (st, ST_R_VALUE, " %{%u%}", (rss_redir_val >> (5 * tc)) & 0x1f);
	}
    }

  styled_text_add (st, "\nTraffic Classes\n  ");
  styled_atl_add_reg (st, ATL_REG_RPF_RPB_RX_TC_UPT, "RPF_RPB_RX_TC_UPT", rx_tc_upt);
  styled_text_add (st, "\n  ");
  styled_atl_add_reg (st, ATL_REG_RPB_RPF_RX, "RPB_RPF_RX", rpb_rpf_rx);

  for (i = 0; i < 4; i++)
    {
      rx_q_tc_map = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RX_Q_TC_MAP (i));
      styled_text_add_marked (st, ST_R_VALUE, "\n  rx_q_tc_map[%u] %{0x%08x%}", i, rx_q_tc_map);
    }

  for (i = 0; i < 8; i++)
    {
      tx_q_tc_map = atl_reg_rd_u32 (dev, ATL_REG_AQ2_TX_Q_TC_MAP (i));
      styled_text_add_marked (st, ST_R_VALUE, "\n  tx_q_tc_map[%u] %{0x%08x%}", i, tx_q_tc_map);
    }
}

void
styled_format_atl_port_status (styled_text_t *st, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  atl_reg_aq2_fw_interface_out_link_status_t link;
  atl_reg_aq2_fw_interface_out_device_link_caps_t dev_caps;
  atl_reg_aq2_fw_interface_out_lkp_link_caps_t lkp_caps;
  u32 dev_caps_raw;
  u32 lkp_caps_raw;
  u32 link_speed;
  static const u32 rate_lut[] = {
    0, 10000, 100000, 1000000, 2500000, 5000000, 10000000,
  };

  rv =
    atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_LINK_STATUS, &link.as_u32, 1);
  if (rv != VNET_DEV_OK)
    {
      styled_text_add_marked (st, ST_R_ERROR, "link status read failed (rv %{%d%})", rv);
      return;
    }

  link_speed = (link.link_rate < ARRAY_LEN (rate_lut)) ? rate_lut[link.link_rate] : 0;

  styled_text_add_marked (st, ST_R_VALUE, "link state %{%u%} link speed %{%u kbps%} duplex %{%s%}",
			  link.link_state, link_speed, link.duplex ? "full" : "half");
  styled_text_add_marked (st, ST_R_VALUE, " pause rx %{%u%} tx %{%u%} eee %{%u%}", link.pause_rx,
			  link.pause_tx, link.eee);

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_DEVICE_LINK_CAPS,
				      &dev_caps_raw, 1);
  if (rv == VNET_DEV_OK)
    {
      dev_caps.as_u32 = dev_caps_raw;
      styled_text_add (st, "\nLink capabilities:\n  %T", styled_format_atl_link_capa, a, &dev_caps);
    }
  else
    {
      styled_text_add_marked (st, ST_R_ERROR, "\nLink capabilities: %{read failed (rv %d)%}", rv);
    }

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_LKP_LINK_CAPS,
				      &lkp_caps_raw, 1);
  if (rv == VNET_DEV_OK)
    {
      lkp_caps.as_u32 = lkp_caps_raw;
      styled_text_add (st, "\nLink partner capabilities:\n  %T",
		       styled_format_atl_partner_link_capa, a, &lkp_caps);
    }
  else
    {
      styled_text_add_marked (st, ST_R_ERROR,
			      "\nLink partner capabilities: %{read failed (rv %d)%}", rv);
    }

  styled_text_add (st, "\nLast Cable Diagnostics:\n  %T", styled_format_atl_cable_diag, a, port);

  if (a->debug > 0)
    {
      u32 l2_count = ad->caps.l2_count;
      u32 base, n_entries, total_entries;
      atl_reg_rpf_l2uc_msw_t l2uc_msw __clib_unused;

      if (l2_count == 0)
	l2_count = AQ_HW_MAC_NUM;

      styled_text_add (st, "\nMAC Address Table:\n  %T", styled_format_atl_mac_addr_table, a, port);
      styled_text_add (st, "\nReceive Packet Filter:\n  %T", styled_format_atl_rpf_info, a, port);

      base = 8 * ad->caps.resolver_base_index;
      n_entries = 8 * ad->caps.resolver_count;
      total_entries = base + n_entries;

      styled_text_add_marked (st, ST_R_VALUE,
			      "\n  ART table (base %{%u%} count %{%u%} resolver_base %{%u%})", base,
			      n_entries, 8 * ad->caps.resolver_base_index);

      /* the columns of the table have to stay under their headings */
      styled_text_begin (st, (styled_text_style_t) { .wrap = ST_A_OFF });
      styled_text_add_marked (
	st, ST_R_TABLE_COL_HEADING,
	"\n    %{        tag        mask      action   index rss  enabled    action     "
	"match%}");

      for (u32 idx = 0; idx < total_entries; idx++)
	{
	  u32 tag = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (idx));
	  u32 mask = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (idx));
	  u32 action_raw = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (idx));
	  atl_aq2_art_action_t act = { .as_u32 = action_raw };
	  atl_aq2_art_tag_t mask_f = { .as_u32 = mask };
	  atl_aq2_art_tag_t match = { .as_u32 = tag & mask };
	  if (tag == 0 && mask == 0 && action_raw == 0)
	    {
	      u32 run_start = idx;
	      u32 run_end = idx + 1;
	      for (; run_end < total_entries; run_end++)
		{
		  u32 next_tag = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (run_end));
		  u32 next_mask = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (run_end));
		  u32 next_action =
		    atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (run_end));
		  if (next_tag != 0 || next_mask != 0 || next_action != 0)
		    break;
		}

	      if (run_end - run_start > 1)
		{
		  styled_text_add (st, "\n          [ entries %u-%u skipped (all zero) ]",
				   run_start, run_end - 1);
		  idx = run_end - 1;
		  continue;
		}
	    }
	  u8 *action_str = 0;
	  u32 action_len;
	  u32 action_pad;
	  char rss = act.rss ? 'Y' : 'N';
	  char en = act.enable ? 'Y' : 'N';

	  action_str = format (0, "%U", format_atl_aq2_art_action, act.action);
	  action_len = vec_len (action_str);
	  action_pad = (action_len < 11) ? (11 - action_len) : 1;
	  styled_text_add_marked (st, ST_R_TABLE_CELL,
				  "\n    %{%3u: 0x%08x 0x%08x 0x%08x %4u   %c      %c     %v%U%}",
				  idx, tag, mask, action_raw, act.index, rss, en, action_str,
				  format_white_space, action_pad);
	  vec_free (action_str);
#define _(n, w)                                                                                    \
  if (mask_f.n)                                                                                    \
    styled_text_add_marked (st, ST_R_VALUE, " " #n " %{%u%}", match.n);
	  foreach_atl_aq2_art_tag_t_field
#undef _
	}

      styled_text_end (st);

      styled_text_add (st, "\nReceive Side Scaling\n  %T", styled_format_atl_rss_info, a, port);

      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  u32 qid = rxq->queue_id;
	  u32 base_lsw = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (qid));
	  u32 base_msw = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRMSW (qid));
	  u32 head = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_HEAD_PTR (qid));
	  u32 tail = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_TAIL_PTR (qid));
	  u32 stat = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_STAT (qid));
	  u32 tc_map = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RX_Q_TC_MAP (qid));
	  atl_reg_rx_dma_desc_len_t desc_len =
	    atl_reg_rd (dev, ATL_REG_RX_DMA_DESC_LEN (qid)).rx_dma_desc_len;
	  atl_reg_rx_dma_desc_data_hdr_size_t hdr =
	    atl_reg_rd (dev, ATL_REG_RX_DMA_DESC_DATA_HDR_SIZE (qid)).rx_dma_desc_data_hdr_size;

	  styled_text_add_marked (st, ST_R_VALUE,
				  "\n  RXQ[%{%u%}] size %{%u%} en %{%u%} len %{%u%}", qid,
				  rxq->size, desc_len.en, desc_len.len);
	  styled_text_add_marked (st, ST_R_VALUE,
				  " hdr_split %{%u%} vlan_strip %{%u%} tc_map %{0x%08x%}",
				  desc_len.header_split, desc_len.vlan_strip, tc_map);
	  styled_text_add_marked (st, ST_R_VALUE,
				  "\n    base %{0x%08x%08x%} head %{%u%} tail %{%u%}", base_msw,
				  base_lsw, head, tail);
	  styled_text_add_marked (st, ST_R_VALUE, " stat %{0x%08x%} data_sz %{%u%} hdr_sz %{%u%}",
				  stat, hdr.data_size, hdr.hdr_size);
	}
    }
}

u8 *
format_atl_l2uc (u8 *s, va_list *args)
{
  atl_reg_rpf_l2uc_msw_t *l2uc_msw = va_arg (*args, atl_reg_rpf_l2uc_msw_t *);
  u32 l2uc_lsw = va_arg (*args, u32);
  vnet_dev_hw_addr_t l2uc_addr = {};

  l2uc_addr.eth_mac[0] = l2uc_msw->macaddr_hi >> 8;
  l2uc_addr.eth_mac[1] = l2uc_msw->macaddr_hi;
  l2uc_addr.eth_mac[2] = l2uc_lsw >> 24;
  l2uc_addr.eth_mac[3] = l2uc_lsw >> 16;
  l2uc_addr.eth_mac[4] = l2uc_lsw >> 8;
  l2uc_addr.eth_mac[5] = l2uc_lsw;

  return format (s, "%U action %u, tag %u, %s", format_vnet_dev_hw_addr, &l2uc_addr,
		 l2uc_msw->action, l2uc_msw->tag, l2uc_msw->en ? "enabled" : "disabled");
}

u8 *
format_atl_tx_desc (u8 *s, va_list *args)
{
  const atl_tx_desc_t *d = va_arg (*args, const atl_tx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  if (d->type_txc)
    {
      const atl_tx_ctx_desc_t *c = (const void *) d;

      return format (s, "context l2_len %u l3_len %u l4_len %u mss %u ipv6%c tcp%c", c->l2_len,
		     c->l3_len_hi << 1 | c->l3_len_lo, c->l4_len, c->mss, _ (c->ipv6), _ (c->tcp));
    }

  s = format (s, "addr 0x%016llx len %u ctx_en %u", d->addr, d->len, d->ctx_en);
  s =
    format (s,
	    "\n%Uflags type_txd%c type_txc%c dd%c eop%c vlan%c fcs%c "
	    "ip4csum%c l4csum%c lso%c wb%c blen %u",
	    format_white_space, indent, _ (d->type_txd), _ (d->type_txc), _ (d->dd), _ (d->eop),
	    _ (d->vlan), _ (d->fcs), _ (d->ip4csum), _ (d->l4csum), _ (d->lso), _ (d->wb), d->blen);

#undef _

  return s;
}
