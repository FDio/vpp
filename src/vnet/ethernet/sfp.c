/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <vnet/ethernet/sfp.h>
#include <vppinfra/format_table.h>

u8 *
format_sfp_id (u8 *s, va_list *args)
{
  u32 id = va_arg (*args, u32);
  char *t = 0;
  switch (id)
    {
#define _(v, f, str)                                                                               \
  case SFP_ID_##f:                                                                                 \
    t = str;                                                                                       \
    break;
      foreach_sfp_id
#undef _
    default:
      return format (s, "unknown 0x%x", id);
    }
  return format (s, "%s", t);
}

u8 *
format_sfp_connector (u8 *s, va_list *args)
{
  u32 connector = va_arg (*args, u32);
  char *t = 0;
  switch (connector)
    {
#define _(v, str)                                                             \
  case v:                                                                     \
    t = str;                                                                  \
    break;
      foreach_sfp_connector
#undef _
	default : return format (s, "unknown 0x%x", connector);
    }
  return format (s, "%s", t);
}

u8 *
format_sfp_encoding (u8 *s, va_list *args)
{
  u32 encoding = va_arg (*args, u32);
  char *t = 0;
  switch (encoding)
    {
#define _(v, str)                                                             \
  case v:                                                                     \
    t = str;                                                                  \
    break;
      foreach_sfp_encoding
#undef _
	default : return format (s, "unknown 0x%x", encoding);
    }
  return format (s, "%s", t);
}

static void
styled_format_sfp_eeprom_base (styled_text_t *st, va_list *args)
{
  sfp_eeprom_t *se = va_arg (*args, sfp_eeprom_t *);
  u8 is_terse = va_arg (*args, u32);
  vnet_interface_eeprom_type_t eeprom_type = va_arg (*args, u32);
  table_t table = {};
  u32 row = 0;
  u8 vendor_name[17] = { 0 };
  u8 vendor_pn[17] = { 0 };
  u8 vendor_rev[5] = { 0 };
  u8 vendor_sn[17] = { 0 };
  u8 date_code[9] = { 0 };
  u16 wavelength;

  table_add_hdr_col (&table, 0);

  /* Vendor information */
  clib_memcpy (vendor_name, se->vendor_name, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_name[i] == ' '; i--)
    vendor_name[i] = '\0';
  table_format_cell (&table, row, -1, "Vendor Name");
  table_format_cell (&table, row, 0, "%s", vendor_name);
  table_set_cell_align (&table, row, 0, TTAA_LEFT);
  row++;

  table_format_cell (&table, row, -1, "Vendor OUI");
  table_format_cell (&table, row, 0, "%02x:%02x:%02x", se->vendor_oui[0], se->vendor_oui[1],
		     se->vendor_oui[2]);
  table_set_cell_align (&table, row, 0, TTAA_LEFT);
  row++;

  clib_memcpy (vendor_pn, se->vendor_part_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_pn[i] == ' '; i--)
    vendor_pn[i] = '\0';
  table_format_cell (&table, row, -1, "Vendor Part Number");
  table_format_cell (&table, row, 0, "%s", vendor_pn);
  table_set_cell_align (&table, row, 0, TTAA_LEFT);
  row++;

  clib_memcpy (vendor_sn, se->vendor_serial_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_sn[i] == ' '; i--)
    vendor_sn[i] = '\0';
  table_format_cell (&table, row, -1, "Vendor Serial Number");
  table_format_cell (&table, row, 0, "%s", vendor_sn);
  table_set_cell_align (&table, row, 0, TTAA_LEFT);
  row++;

  if (!is_terse)
    {
      table_format_cell (&table, row, -1, "Identifier");
      table_format_cell (&table, row, 0, "0x%02x (%U)", se->id, format_sfp_id, se->id);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      table_format_cell (&table, row, -1, "Extended Identifier");
      table_format_cell (&table, row, 0, "0x%02x", se->extended_id);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      table_format_cell (&table, row, -1, "Connector");
      table_format_cell (&table, row, 0, "0x%02x (%U)", se->connector_type, format_sfp_connector,
			 se->connector_type);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      table_format_cell (&table, row, -1, "Compliance");
      if (eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8472)
	table_format_cell (&table, row, 0, "%U", format_sff8472_compliance, se->compatibility);
      else
	table_format_cell (&table, row, 0, "%U", format_sff8636_compliance, se->compatibility);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      table_format_cell (&table, row, -1, "Encoding");
      table_format_cell (&table, row, 0, "0x%02x (%U)", se->encoding, format_sfp_encoding,
			 se->encoding);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      table_format_cell (&table, row, -1, "Nominal Bit Rate");
      table_format_cell (&table, row, 0, "%u00 Mbps", se->nominal_bit_rate_100mbits_per_sec);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;

      /* Length information */
      if (se->length[0])
	{
	  table_format_cell (&table, row, -1, "Length (SMF)");
	  table_format_cell (&table, row, 0, "%u km", se->length[0]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;
	}
      if (se->length[1])
	{
	  table_format_cell (&table, row, -1, "Length (SMF)");
	  table_format_cell (&table, row, 0, "%u00 m", se->length[1]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;
	}
      if (se->length[2])
	{
	  table_format_cell (&table, row, -1, "Length (OM2 50um)");
	  table_format_cell (&table, row, 0, "%u0 m", se->length[2]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;
	}
      if (se->length[3])
	{
	  table_format_cell (&table, row, -1, "Length (OM1 62.5um)");
	  table_format_cell (&table, row, 0, "%u0 m", se->length[3]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;
	}
      if (se->length[4])
	{
	  table_format_cell (&table, row, -1, "Length (Copper/OM3)");
	  table_format_cell (&table, row, 0, "%u m", se->length[4]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;
	}

      /* NOTE(pim): SFF8472 specifies a 4 byte vendor revision followed by a
       * 2-byte wavelength_or_att. However SFF8636 specifies a 2 byte vendor
       * revision followed by a 2 byte wavelength_or_att, followed by a 2
       * byte wavelength_tolerance */
      if (eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8472)
	{
	  clib_memcpy (vendor_rev, se->vendor_revision, 4);
	  /* Trim trailing spaces */
	  for (int i = 3; i >= 0 && vendor_rev[i] == ' '; i--)
	    vendor_rev[i] = '\0';
	  table_format_cell (&table, row, -1, "Vendor Revision");
	  table_format_cell (&table, row, 0, "%s", vendor_rev);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;

	  wavelength = clib_net_to_host_u16 (se->wavelength_or_att);
	  if (wavelength)
	    {
	      table_format_cell (&table, row, -1, "Wavelength");
	      table_format_cell (&table, row, 0, "%u nm", wavelength);
	      table_set_cell_align (&table, row, 0, TTAA_LEFT);
	      row++;
	    }
	}
      if (eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8636 ||
	  eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8436)
	{
	  clib_memcpy (vendor_rev, se->vendor_revision, 2);
	  /* Trim trailing spaces */
	  for (int i = 1; i >= 0 && vendor_rev[i] == ' '; i--)
	    vendor_rev[i] = '\0';
	  table_format_cell (&table, row, -1, "Vendor Revision");
	  table_format_cell (&table, row, 0, "%s", vendor_rev);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;

	  u8 transmitter_tech = se->device_tech >> 4;
	  table_format_cell (&table, row, -1, "Transmitter Technology");
	  table_format_cell (&table, row, 0, "0x%x (%U)", transmitter_tech,
			     format_sff8636_transmitter_tech, transmitter_tech);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  row++;

	  if (sff8636_transmitter_tech_is_copper (se->device_tech))
	    {
	      table_format_cell (&table, row, -1, "Copper Cable Attenuation");
	      table_format_cell (&table, row, 0, "%u dB at 2.5 GHz, %u dB at 5.0 GHz",
				 se->vendor_revision[2], se->vendor_revision[3]);
	      table_set_cell_align (&table, row, 0, TTAA_LEFT);
	      row++;
	    }
	  else
	    {
	      u16 sff8636_wavelength_or_att =
		(se->vendor_revision[2] << 8) + se->vendor_revision[3];
	      f64 wl_nm = ((f64) sff8636_wavelength_or_att) * 0.05;
	      table_format_cell (&table, row, -1, "Wavelength");
	      table_format_cell (&table, row, 0, "%.3f nm", wl_nm);
	      table_set_cell_align (&table, row, 0, TTAA_LEFT);
	      row++;
	    }
	}

      clib_memcpy (date_code, se->vendor_date_code, 8);
      table_format_cell (&table, row, -1, "Date Code");
      table_format_cell (&table, row, 0, "%.8s", date_code);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      row++;
    }

  styled_text_add (st, "%T", format_styled_table, &table);
  table_free (&table);
}

__clib_export void
styled_format_sfp_eeprom_module (styled_text_t *st, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u8 is_terse = va_arg (*args, u32);
  sfp_eeprom_t *se = (sfp_eeprom_t *) eeprom->eeprom_raw;

  if (eeprom->eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8636 ||
      eeprom->eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8436)
    se = (sfp_eeprom_t *) (eeprom->eeprom_raw + 0x80);

  styled_text_add (st, "%T", styled_format_sfp_eeprom_base, se, is_terse, eeprom->eeprom_type);
}

u8 *
format_sfp_eeprom_module (u8 *s, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u32 is_terse = va_arg (*args, u32);
  styled_text_t st = {};

  styled_text_add (&st, "%T", styled_format_sfp_eeprom_module, eeprom, is_terse);
  s = format (s, "%U", format_styled_text, &st);
  styled_text_free (&st);

  return s;
}

u8 *
format_sfp_temperature (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);

  return format (s, "%.2f °C", v);
}

u8 *
format_sfp_voltage (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);

  return format (s, "%.4f V", v);
}

u8 *
format_sfp_current (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);

  return format (s, "%.2f mA", v);
}

u8 *
format_sfp_power (u8 *s, va_list *args)
{
  f64 v = va_arg (*args, f64);

  return format (s, "%.4f mW (%.2f dBm)", v, sfp_sff_mw_to_dbm (v));
}

void
styled_sfp_add_value (styled_text_t *st, u32 indent, char *label, format_function_t *f, f64 value)
{
  styled_text_add_marked (st, ST_R_VALUE, "\n%U%s: %{%U%}", format_white_space, indent, label, f,
			  value);
}

void
styled_sfp_add_range (styled_text_t *st, u32 indent, char *label, format_function_t *f, f64 high,
		      f64 low)
{
  styled_text_add_marked (st, ST_R_VALUE, "\n%U%s High: %{%U%}, Low: %{%U%}", format_white_space,
			  indent, label, f, high, f, low);
}

void
styled_format_sfp_eeprom_diagnostics (styled_text_t *st, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u32 is_terse = va_arg (*args, u32);

  switch (eeprom->eeprom_type)
    {
    case VNET_INTERFACE_EEPROM_TYPE_SFF8472:
      styled_text_add (st, "%T", styled_format_sff8472_diagnostics, eeprom, is_terse);
      break;
    case VNET_INTERFACE_EEPROM_TYPE_SFF8436:
    case VNET_INTERFACE_EEPROM_TYPE_SFF8636:
      styled_text_add (st, "%T", styled_format_sff8636_diagnostics, eeprom, is_terse);
      break;
    default:
      styled_text_add (st, "not available");
    }
}
