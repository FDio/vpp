/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/ethernet/sfp.h>
#include <vnet/ethernet/sfp_sff8472.h>

static u8 *
format_space_terminated (u8 * s, va_list * args)
{
  u32 l = va_arg (*args, u32);
  u8 *v = va_arg (*args, u8 *);
  u8 *p;

  for (p = v + l - 1; p >= v && p[0] == ' '; p--)
    ;
  vec_add (s, v, clib_min (p - v + 1, l));
  return s;
}

u8 *
format_sfp_id (u8 *s, va_list *args)
{
  u32 id = va_arg (*args, u32);
  char *t = 0;
  switch (id)
    {
#define _(f,str) case SFP_ID_##f: t = str; break;
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

static u8 *
format_sfp_compatibility (u8 * s, va_list * args)
{
  u32 c = va_arg (*args, u32);
  char *t = 0;
  switch (c)
    {
#define _(a,b,f) case SFP_COMPATIBILITY_##f: t = #f; break;
      foreach_sfp_compatibility
#undef _
    default:
      return format (s, "unknown 0x%x", c);
    }
  return format (s, "%s", t);
}

static u32
sfp_is_compatible (sfp_eeprom_t *e, sfp_compatibility_t c)
{
  static struct
  {
    u8 byte, bit;
  } t[] =
  {
#define _(a,b,f) { .byte = a, .bit = b, },
    foreach_sfp_compatibility
#undef _
  };

  ASSERT (c < ARRAY_LEN (t));
  return (e->compatibility[t[c].byte] & (1 << t[c].bit)) != 0;
}

u8 *
format_sfp_eeprom (u8 * s, va_list * args)
{
  sfp_eeprom_t *e = va_arg (*args, sfp_eeprom_t *);
  u32 indent = format_get_indent (s);
  int i;

  s = format (s, "id %U, ", format_sfp_id, e->id);

  s = format (s, "compatibility:");
  for (i = 0; i < SFP_N_COMPATIBILITY; i++)
    if (sfp_is_compatible (e, i))
      s = format (s, " %U", format_sfp_compatibility, i);

  s = format (s, "\n%Uvendor: %U, part %U",
	      format_white_space, indent,
	      format_space_terminated, sizeof (e->vendor_name),
	      e->vendor_name, format_space_terminated,
	      sizeof (e->vendor_part_number), e->vendor_part_number);
  s =
    format (s, "\n%Urevision: %U, serial: %U, date code: %U",
	    format_white_space, indent, format_space_terminated,
	    sizeof (e->vendor_revision), e->vendor_revision,
	    format_space_terminated, sizeof (e->vendor_serial_number),
	    e->vendor_serial_number, format_space_terminated,
	    sizeof (e->vendor_date_code), e->vendor_date_code);

  if (e->length[4])
    s = format (s, "\n%Ucable length: %um", format_white_space, indent,
		e->length[4]);

  return s;
}

void
sfp_eeprom_decode_base (vlib_main_t *vm, sfp_eeprom_t *se, u8 is_terse)
{
  u8 vendor_name[17] = { 0 };
  u8 vendor_pn[17] = { 0 };
  u8 vendor_rev[3] = { 0 };
  u8 vendor_sn[17] = { 0 };
  u8 date_code[9] = { 0 };
  u16 wavelength;

  vlib_cli_output (vm, "  Module Base Information:");
  /* Vendor information */
  clib_memcpy (vendor_name, se->vendor_name, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_name[i] == ' '; i--)
    vendor_name[i] = '\0';
  vlib_cli_output (vm, "    Vendor Name: %s", vendor_name);

  vlib_cli_output (vm, "    Vendor OUI: %02x:%02x:%02x", se->vendor_oui[0],
		   se->vendor_oui[1], se->vendor_oui[2]);

  clib_memcpy (vendor_pn, se->vendor_part_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_pn[i] == ' '; i--)
    vendor_pn[i] = '\0';
  vlib_cli_output (vm, "    Vendor Part Number: %s", vendor_pn);

  clib_memcpy (vendor_sn, se->vendor_serial_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_sn[i] == ' '; i--)
    vendor_sn[i] = '\0';
  vlib_cli_output (vm, "    Vendor Serial Number: %s", vendor_sn);

  if (is_terse)
    return;

  vlib_cli_output (vm, "    Identifier: 0x%02x (%U)", se->id, format_sfp_id,
		   se->id);
  vlib_cli_output (vm, "    Extended Identifier: 0x%02x", se->extended_id);
  vlib_cli_output (vm, "    Connector: 0x%02x (%U)", se->connector_type,
		   format_sfp_connector, se->connector_type);
  vlib_cli_output (vm, "    Encoding: 0x%02x (%U)", se->encoding,
		   format_sfp_encoding, se->encoding);
  vlib_cli_output (vm, "    Nominal Bit Rate: %u00 Mbps",
		   se->nominal_bit_rate_100mbits_per_sec);

  /* Length information */
  if (se->length[0])
    vlib_cli_output (vm, "    Length (SMF): %u km", se->length[0]);
  if (se->length[1])
    vlib_cli_output (vm, "    Length (SMF): %u00 m", se->length[1]);
  if (se->length[2])
    vlib_cli_output (vm, "    Length (OM2 50um): %u0 m", se->length[2]);
  if (se->length[3])
    vlib_cli_output (vm, "    Length (OM1 62.5um): %u0 m", se->length[3]);
  if (se->length[4])
    vlib_cli_output (vm, "    Length (Copper/OM3): %u m", se->length[4]);

  clib_memcpy (vendor_rev, se->vendor_revision, 2);
  /* Trim trailing spaces */
  for (int i = 1; i >= 0 && vendor_rev[i] == ' '; i--)
    vendor_rev[i] = '\0';
  vlib_cli_output (vm, "    Vendor Revision: %s", vendor_rev);

  /* Wavelength */
  wavelength = (se->wavelength_or_att[0] << 8) | se->wavelength_or_att[1];
  if (wavelength)
    vlib_cli_output (vm, "    Wavelength: %u nm", wavelength);

  clib_memcpy (date_code, se->vendor_date_code, 8);
  vlib_cli_output (vm, "    Date Code: %.8s", date_code);

  /* Options and compliance */
  vlib_cli_output (vm, "    Link Codes: 0x%02x", se->link_codes);
  vlib_cli_output (vm, "    Options: 0x%02x%02x%02x", se->options[0],
		   se->options[1], se->options[2]);
}

void
sfp_eeprom_module (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
		   u8 is_terse)
{
  sfp_eeprom_t *se = (sfp_eeprom_t *) eeprom->eeprom_raw;
  if (eeprom->eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8636 ||
      eeprom->eeprom_type == VNET_INTERFACE_EEPROM_TYPE_SFF8436)
    {
      se = (sfp_eeprom_t *) (eeprom->eeprom_raw + 0x80);
    }

  return sfp_eeprom_decode_base (vm, se, is_terse);
}

void
sfp_eeprom_diagnostics (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
			u8 is_terse)
{

  return sff8472_decode_diagnostics (vm, eeprom->eeprom_raw,
				     eeprom->eeprom_len, is_terse);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
