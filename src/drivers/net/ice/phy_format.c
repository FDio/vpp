/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vppinfra/format_table.h>

u8 *
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
format_ice_phy_flags (u8 *s, va_list *args)
{
  ice_port_status_t *status = va_arg (*args, ice_port_status_t *);
  char *title = va_arg (*args, char *);
  const char **names = va_arg (*args, const char **);
  uword n_names = va_arg (*args, uword);
  u8 *values = va_arg (*args, u8 *);
  table_t t = {};
  u32 indent = format_get_indent (s);

  table_add_hdr_col (&t, 1, "");
  table_add_hdr_row (&t, 5, "field", "Topology", "Media", "Configured", "Default");

  for (int bit = 0; bit < n_names; bit++)
    {
      table_format_cell (&t, bit, -1, "%s", names[bit]);
      table_set_cell_align (&t, bit, -1, TTAA_LEFT);

      for (int i = 0; i < ARRAY_LEN (status->phy); i++)
	{
	  char *value = "-";

	  if (status->phy_rv[i] == VNET_DEV_OK)
	    value = values[i] & (1 << bit) ? "yes" : "no";

	  table_format_cell (&t, bit, i, "%s", value);
	}
    }

  s = format (s, "%s:", title);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &t);
  table_free (&t);
  return s;
}

static u8 *
format_ice_phy_diagnostics (u8 *s, va_list *args)
{
  ice_port_status_t *status = va_arg (*args, ice_port_status_t *);
  u32 indent = format_get_indent (s);
  static const char *sources[] = {
    "Topology",
    "Media",
    "Configured",
    "Default",
  };
  static const char *fec_names[] = {
    "BASE-R enabled",	"BASE-R requested", "RS-528 requested", "25G BASE-R requested",
    "RS-544 requested", "disabled",	    "RS-528 enabled",	"25G BASE-R enabled",
  };
  static const char *caps_names[] = {
    "pause TX", "pause RX", "low power", "link enabled", "autoneg", "module qualification",
    "LESM",	"auto FEC",
  };
  u8 fec[ARRAY_LEN (status->phy)], caps[ARRAY_LEN (status->phy)];
  table_t phy = {};
  u64 modes[2] = {};
  int n_modes = 0;

  if (status->phy_rv[1] == VNET_DEV_OK)
    {
      ice_aqc_get_phy_caps_data_t *p = status->phy + 1;

      s = format (s, "PHY ID %02x:%02x:%02x:%02x, firmware %U", p->phy_id_oui[0], p->phy_id_oui[1],
		  p->phy_id_oui[2], p->phy_id_oui[3], format_hex_bytes, p->phy_fw_ver,
		  sizeof (p->phy_fw_ver));
      s = format_newline (s, indent);
      s = format (s, "module type %02x:%02x:%02x, compliance 0x%02x", p->module_type[0],
		  p->module_type[1], p->module_type[2], p->extended_compliance_code);
    }

  table_add_hdr_col (&phy, 1, "");
  table_add_hdr_row (&phy, 5, "field", sources[0], sources[1], sources[2], sources[3]);

  for (int i = 0; i < ARRAY_LEN (status->phy); i++)
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

	for (int i = 0; i < ARRAY_LEN (status->phy); i++)
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

  if (status->phy_rv[1] == VNET_DEV_OK)
    s = format_newline (s, indent);

  s = format (s, "PHY modes:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &phy);
  table_free (&phy);

  for (int i = 0; i < ARRAY_LEN (status->phy); i++)
    {
      fec[i] = status->phy[i].link_fec_options;
      caps[i] = status->phy[i].caps;

      if (status->phy_rv[i] != VNET_DEV_OK)
	s = format (format_newline (s, indent), "%s PHY unavailable: %U", sources[i],
		    format_vnet_dev_rv, status->phy_rv[i]);
    }

  s = format (format_newline (s, indent), "%U", format_ice_phy_flags, status, "PHY FEC options",
	      fec_names, ARRAY_LEN (fec_names), fec);
  return format (format_newline (s, indent), "%U", format_ice_phy_flags, status, "PHY capabilities",
		 caps_names, ARRAY_LEN (caps_names), caps);
}

u8 *
format_ice_phy_status (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_port_status_t status = { .lport = ip->lport };
  u32 indent = format_get_indent (s);
  vnet_dev_rv_t rv;

  rv = vnet_dev_process_call_op_with_ptr (vlib_get_main (), port->dev, ice_aq_get_port_status,
					  &status);
  if (rv != VNET_DEV_OK)
    return format (s, "PHY diagnostics unavailable: %U", format_vnet_dev_rv, rv);

  if (status.link_rv == VNET_DEV_OK)
    {
      s = format (s, "Active PHY: %U", format_ice_phy_types, status.link.phy_type_low,
		  status.link.phy_type_high);
      s = format_word_wrap_last_line (s, 100);
      s = format_newline (s, indent);
    }

  return format (s, "%U", format_ice_phy_diagnostics, &status);
}
