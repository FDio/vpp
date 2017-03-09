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

static u8 *
format_sfp_id (u8 * s, va_list * args)
{
  u32 id = va_arg (*args, u32);
  char *t = 0;
  switch (id)
    {
#define _(f) case SFP_ID_##f: t = #f; break;
      foreach_sfp_id
#undef _
    default:
      return format (s, "unknown 0x%x", id);
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

u32
sfp_is_comatible (sfp_eeprom_t * e, sfp_compatibility_t c)
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
  uword indent = format_get_indent (s);
  int i;

  if (e->id != SFP_ID_sfp)
    s = format (s, "id %U, ", format_sfp_id, e->id);

  s = format (s, "compatibility:");
  for (i = 0; i < SFP_N_COMPATIBILITY; i++)
    if (sfp_is_comatible (e, i))
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

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
