/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Text and size of API messages by interpreting API descriptors. The text is
 * the same as the one of the generated vl_api_<msg>_t_format functions, the
 * size the same as the one of the generated vl_api_<msg>_t_calc_size
 * functions. */

#include <vlibapi/api_common.h>
#include <vlibapi/api_desc.h>
#include <vlibapi/api_desc_internal.h>
#include <vlibapi/api_types.h>
#include <vlibapi/jsonformat.h>
#include <vnet/ip/ip_format_fns.h>

u8 *
vl_api_desc_format_manual (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int *handled,
			   int for_text)
{
  const char *n = t->name;

  *handled = 1;
  if (!strcmp (n, "ip4_address"))
    return format (s, "%U", format_vl_api_ip4_address_t, p, 0);

  if (!strcmp (n, "ip6_address"))
    return format (s, "%U", format_vl_api_ip6_address_t, p, 0);

  if (!strcmp (n, "ip4_prefix") || !strcmp (n, "ip4_address_with_prefix"))
    return format (s, "%U", format_vl_api_ip4_prefix_t, p, 0);

  if (!strcmp (n, "ip6_prefix") || !strcmp (n, "ip6_address_with_prefix"))
    return format (s, "%U", format_vl_api_ip6_prefix_t, p, 0);

  if (!strcmp (n, "address"))
    return format (s, "%U", format_vl_api_address_t, p, 0);

  if (!strcmp (n, "prefix") || !strcmp (n, "address_with_prefix"))
    return format (s, "%U", format_vl_api_prefix_t, p, 0);

  if (!strcmp (n, "mac_address"))
    {
      /* the text of a message has the MAC address as aabb.ccdd.eeff */
      if (for_text)
	return format (s, "%02x%02x.%02x%02x.%02x%02x", p[0], p[1], p[2], p[3], p[4], p[5]);

      return format (s, "%U", format_vl_api_mac_address_t, p, 0);
    }

  *handled = 0;
  return s;
}

static const char *desc_format_strings[] = {
  [VL_API_DK_U8] = "%u",    [VL_API_DK_BOOL] = "%u",  [VL_API_DK_I8] = "%d",
  [VL_API_DK_U16] = "%u",   [VL_API_DK_I16] = "%d",   [VL_API_DK_U32] = "%u",
  [VL_API_DK_I32] = "%ld",  [VL_API_DK_U64] = "%llu", [VL_API_DK_I64] = "%lld",
  [VL_API_DK_F64] = "%.2f",
};

/* text of an alias, as the generated format function of the alias does it */
u8 *
vl_api_desc_format_alias (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int for_text)
{
  static const struct
  {
    const char *name;
    u8 kind;
  } base[] = {
    { "u8", VL_API_DK_U8 },	{ "i8", VL_API_DK_I8 },	  { "u16", VL_API_DK_U16 },
    { "i16", VL_API_DK_I16 },	{ "u32", VL_API_DK_U32 }, { "i32", VL_API_DK_I32 },
    { "u64", VL_API_DK_U64 },	{ "i64", VL_API_DK_I64 }, { "f64", VL_API_DK_F64 },
    { "bool", VL_API_DK_BOOL },
  };
  int handled;

  s = vl_api_desc_format_manual (s, t, p, &handled, for_text);

  if (handled)
    return s;

  if (t->alias_length && !strcmp (t->alias_type, "u8"))
    return format (s, "%U", format_hex_bytes, p, t->alias_length);

  for (u32 i = 0; i < ARRAY_LEN (base); i++)
    if (!strcmp (t->alias_type, base[i].name))
      {
	u32 k = base[i].kind;

	switch (k)
	  {
	  case VL_API_DK_U8:
	  case VL_API_DK_BOOL:
	    return format (s, desc_format_strings[k], (u32) *p);
	  case VL_API_DK_I8:
	    return format (s, desc_format_strings[k], (i32) (i8) *p);
	  case VL_API_DK_U16:
	    return format (s, desc_format_strings[k], (u32) desc_read_uint (p, k));
	  case VL_API_DK_I16:
	    return format (s, desc_format_strings[k], (i32) (i16) desc_read_uint (p, k));
	  case VL_API_DK_U32:
	    return format (s, desc_format_strings[k], (u32) desc_read_uint (p, k));
	  case VL_API_DK_I32:
	    return format (s, desc_format_strings[k], (long) (i32) desc_read_uint (p, k));
	  case VL_API_DK_U64:
	    return format (s, desc_format_strings[k], desc_read_uint (p, k));
	  case VL_API_DK_I64:
	    return format (s, desc_format_strings[k], (i64) desc_read_uint (p, k));
	  default:
	    return format (s, desc_format_strings[k], desc_read_number (p, k));
	  }
      }

  return format (s, "%s (print not implemented)", t->name);
}

/* ---- text of messages, as the generated format functions print them */

static u8 *desc_format_fields (u8 *s, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
			       const u8 *base, u32 indent);

static u8 *
desc_format_scalar (u8 *s, u32 kind, const u8 *p)
{
  switch (kind)
    {
    case VL_API_DK_U8:
    case VL_API_DK_BOOL:
      return format (s, "%u", *p);
    case VL_API_DK_I8:
      return format (s, "%d", (i8) *p);
    case VL_API_DK_U16:
      return format (s, "%u", (u16) desc_read_uint (p, kind));
    case VL_API_DK_I16:
      return format (s, "%d", (i16) desc_read_uint (p, kind));
    case VL_API_DK_U32:
      return format (s, "%u", (u32) desc_read_uint (p, kind));
    case VL_API_DK_I32:
      return format (s, "%ld", (long) (u32) desc_read_uint (p, kind));
    case VL_API_DK_U64:
      return format (s, "%llu", desc_read_uint (p, kind));
    case VL_API_DK_I64:
      return format (s, "%lld", (i64) desc_read_uint (p, kind));
    default:
      return format (s, "%.2f", desc_read_number (p, kind));
    }
}

static u8 *
desc_format_value (u8 *s, const vl_api_desc_file_t *df, const vl_api_desc_field_t *f, const u8 *p,
		   u32 indent)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);
  u64 v;
  int handled;

  switch (f->kind)
    {
    case VL_API_DK_U8 ... VL_API_DK_BOOL:
      return desc_format_scalar (s, f->kind, p);
    case VL_API_DK_ENUM:
    case VL_API_DK_ENUMFLAG:
      v = desc_read_uint (p, r->base);

      for (u32 i = 0; i < r->n_fields; i++)
	if ((i64) (r->base == VL_API_DK_U32 ? (u32) v : v) == vl_api_desc_values (df, r)[i].value)
	  return format (s, "%s", vl_api_desc_values (df, r)[i].name);

      return s;
    case VL_API_DK_STRUCT:
    case VL_API_DK_UNION:
      if (r->flags & VL_API_DTF_MANUAL_PRINT)
	{
	  s = vl_api_desc_format_manual (s, r, p, &handled, 1);

	  if (handled)
	    return s;
	}

      return desc_format_fields (s, df, r, p, indent + 2);
    case VL_API_DK_NAMED:
      return vl_api_desc_format_alias (s, r, p, 1);
    default:
      return s;
    }
}

static u8 *
desc_format_fields (u8 *s, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		    const u8 *base, u32 indent)
{
  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];
      const u8 *p = base + f->offset;
      u32 n;

      if (desc_is_noprint (f->name))
	continue;

      if (!(f->flags & VL_API_DF_ARRAY))
	{
	  s = format (s, "\n%U%s: ", format_white_space, indent, f->name);
	  s = desc_format_value (s, df, f, p, indent);
	  continue;
	}

      n = (f->flags & VL_API_DF_VLA) ? desc_length_of (df, t, f, base) : f->length;

      if (f->flags & VL_API_DF_MODERN_VLA)
	{
	  u32 len = clib_net_to_host_u32 (*(u32 *) p);

	  if (len > 0)
	    s = format (s, "\n%U%s: %U", format_white_space, indent, f->name, vl_api_format_string,
			(vl_api_string_t *) p);
	  else
	    s = format (s, "\n%U%s:", format_white_space, indent, f->name);
	}
      else if (f->kind == VL_API_DK_FSTRING)
	s = format (s, "\n%U%s: %.*s", format_white_space, indent, f->name,
		    (int) strnlen ((char *) p, f->length), p);
      else if (vl_api_desc_field_is_u8 (f))
	{
	  /* a fixed array is printed from the start of the type, not of the field */
	  if (f->flags & VL_API_DF_VLA)
	    s =
	      format (s, "\n%U%s: %U", format_white_space, indent, f->name, format_hex_bytes, p, n);
	  else
	    s = format (s, "\n%U%s: %U", format_white_space, indent, f->name, format_hex_bytes,
			base, n);
	}
      else
	for (u32 k = 0; k < n; k++)
	  {
	    s = format (s, "\n%U%s: ", format_white_space, indent, f->name);
	    s = desc_format_value (s, df, f, p + (u64) k * f->size, indent);
	  }
    }

  return s;
}

u8 *
vl_api_desc_msg_format (u8 *s, const vl_api_desc_msg_t *m, const void *msg)
{
  const vl_api_desc_type_t *t = m->type;

  s = format (s, "vl_api_%s_t:", t->name);
  return desc_format_fields (s, m->file, t, msg, 2);
}

/* ---- the size of messages */

/* A variable length part is always the last field of a type, including the
 * type of the last field, so this is all there is to look at. The message is
 * in network byte order. */
static uword
desc_calc_size (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t, const void *msg)
{
  const vl_api_desc_field_t *f;
  const u8 *p;
  uword size = t->size;

  if (!(t->flags & VL_API_DTF_VLA))
    return size;

  f = &vl_api_desc_fields (df, t)[t->n_fields - 1];
  p = msg + f->offset;

  if (f->flags & VL_API_DF_VLA)
    {
      const vl_api_desc_field_t *lf = &vl_api_desc_fields (df, t)[f->related];
      u64 n = desc_read_uint (msg + lf->offset, lf->kind);

      if (lf->kind == VL_API_DK_U16 || lf->kind == VL_API_DK_I16)
	n = clib_net_to_host_u16 (n);
      else if (lf->kind == VL_API_DK_U32 || lf->kind == VL_API_DK_I32)
	n = clib_net_to_host_u32 (n);
      else if (lf->kind == VL_API_DK_U64 || lf->kind == VL_API_DK_I64)
	n = clib_net_to_host_u64 (n);

      size += n * f->size;
    }
  else if (f->flags & VL_API_DF_MODERN_VLA)
    size += clib_net_to_host_u32 (*(u32 *) p);
  else if ((f->kind == VL_API_DK_STRUCT || f->kind == VL_API_DK_UNION) &&
	   (vl_api_desc_ref (df, f)->flags & VL_API_DTF_VLA))
    size += desc_calc_size (df, vl_api_desc_ref (df, f), p) - vl_api_desc_ref (df, f)->size;

  return size;
}

uword
vl_api_desc_msg_calc_size (const vl_api_desc_msg_t *m, const void *msg)
{
  return desc_calc_size (m->file, m->type, msg);
}
