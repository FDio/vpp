/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Conversion of API messages to JSON by interpreting API descriptors. The
 * JSON is the same as the one of the generated vl_api_<msg>_t_tojson
 * functions: _msgname and _crc, then the fields. */

#include <vlibapi/api_common.h>
#include <vlibapi/api_desc.h>
#include <vlibapi/api_types.h>
#include <vppinfra/pool.h>
#include <vlibapi/jsonformat.h>
#include <vnet/ip/ip_format_fns.h>

static const char *desc_noprint[] = {
  "_vl_msg_id",
  "client_index",
  "context",
};

static int
desc_is_noprint (const char *name)
{
  for (u32 i = 0; i < ARRAY_LEN (desc_noprint); i++)
    if (!strcmp (name, desc_noprint[i]))
      return 1;

  return 0;
}

static u32
desc_kind_size (u32 kind)
{
  switch (kind)
    {
    case VL_API_DK_U8:
    case VL_API_DK_I8:
    case VL_API_DK_BOOL:
      return 1;
    case VL_API_DK_U16:
    case VL_API_DK_I16:
      return 2;
    case VL_API_DK_U32:
    case VL_API_DK_I32:
      return 4;
    default:
      return 8;
    }
}

/* unsigned value of an integer, host endian */
static u64
desc_read_uint (const u8 *p, u32 kind)
{
  u64 v = 0;

  memcpy (&v, p, desc_kind_size (kind));
  return v;
}

static f64
desc_read_number (const u8 *p, u32 kind)
{
  switch (kind)
    {
    case VL_API_DK_U8:
      return *p;
    case VL_API_DK_I8:
      return (i8) *p;
    case VL_API_DK_U16:
      return desc_read_uint (p, kind);
    case VL_API_DK_I16:
      return (i16) desc_read_uint (p, kind);
    case VL_API_DK_U32:
      return desc_read_uint (p, kind);
    case VL_API_DK_I32:
      return (i32) desc_read_uint (p, kind);
    case VL_API_DK_U64:
      return desc_read_uint (p, kind);
    case VL_API_DK_I64:
      return (i64) desc_read_uint (p, kind);
    case VL_API_DK_F64:
      {
	f64 d;

	memcpy (&d, p, sizeof (d));
	return d;
      }
    }
  return 0;
}

/* ---- builders, the name is 0 for array elements */

static void
put_number (clib_json_text_t *j, const char *name, f64 v)
{
  if (name)
    clib_json_add_number (j, "%s", v, name);
  else
    clib_json_add_number (j, 0, v);
}

static void
put_bool (clib_json_text_t *j, const char *name, int v)
{
  if (v)
    {
      if (name)
	clib_json_add_true (j, "%s", name);
      else
	clib_json_add_true (j, 0);
    }
  else
    {
      if (name)
	clib_json_add_false (j, "%s", name);
      else
	clib_json_add_false (j, 0);
    }
}

/* s is a vector, not nul terminated */
static void
put_string (clib_json_text_t *j, const char *name, u8 *s)
{
  if (name)
    clib_json_add_string (j, "%s", "%v", name, s);
  else
    clib_json_add_string (j, 0, "%v", s);
}

static void
put_cstring (clib_json_text_t *j, const char *name, const char *s)
{
  if (name)
    clib_json_add_string (j, "%s", "%s", name, s);
  else
    clib_json_add_string (j, 0, "%s", s);
}

static void
begin_object (clib_json_text_t *j, const char *name)
{
  if (name)
    clib_json_add_object (j, "%s", name);
  else
    clib_json_add_object (j, 0);
}

static void
begin_array (clib_json_text_t *j, const char *name)
{
  if (name)
    clib_json_add_array (j, "%s", name);
  else
    clib_json_add_array (j, 0);
}

static void desc_tojson_fields (clib_json_text_t *j, const vl_api_desc_file_t *df,
				const vl_api_desc_type_t *t, const u8 *base);

/* ---- types which are formatted by hand */

static u8 *
desc_format_manual (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int *handled, int for_text)
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
static u8 *
desc_format_alias (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int for_text)
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

  s = desc_format_manual (s, t, p, &handled, for_text);

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

/* ---- values */

static void
desc_tojson_enum (clib_json_text_t *j, const vl_api_desc_file_t *df, const char *name,
		  const vl_api_desc_type_t *t, const u8 *p)
{
  u64 v = desc_read_uint (p, t->base);

  if (t->kind == VL_API_DT_ENUMFLAG)
    {
      begin_array (j, name);

      for (u32 i = 0; i < t->n_fields; i++)
	if (vl_api_desc_values (df, t)[i].value != 0 && (v & vl_api_desc_values (df, t)[i].value))
	  put_cstring (j, 0, vl_api_desc_values (df, t)[i].name);

      clib_json_parent (j);
      return;
    }

  for (u32 i = 0; i < t->n_fields; i++)
    if ((i64) (t->base == VL_API_DK_U32 ? (u32) v : v) == vl_api_desc_values (df, t)[i].value)
      {
	put_cstring (j, name, vl_api_desc_values (df, t)[i].name);
	return;
      }

  put_cstring (j, name, "Invalid ENUM");
}

/* a value of a field, or an element of an array field */
static void
desc_tojson_value (clib_json_text_t *j, const vl_api_desc_file_t *df, const char *name,
		   const vl_api_desc_field_t *f, const u8 *p, int in_array)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);
  u8 *s;
  int handled;

  switch (f->kind)
    {
    case VL_API_DK_U8 ... VL_API_DK_BOOL:
      /* an alias of a base type is a number, except in an array or when
       * it is a bool, there it is the text of the alias */
      if (r && r->kind == VL_API_DT_ALIAS && (in_array || f->kind == VL_API_DK_BOOL))
	{
	  s = desc_format_alias (0, r, p, 0);
	  put_string (j, name, s);
	  vec_free (s);
	}
      else if (f->kind == VL_API_DK_BOOL)
	put_bool (j, name, *p != 0);
      else
	put_number (j, name, desc_read_number (p, f->kind));

      break;
    case VL_API_DK_ENUM:
    case VL_API_DK_ENUMFLAG:
      desc_tojson_enum (j, df, name, r, p);
      break;
    case VL_API_DK_STRUCT:
    case VL_API_DK_UNION:
      if (r->flags & VL_API_DTF_MANUAL_PRINT)
	{
	  s = desc_format_manual (0, r, p, &handled, 0);

	  if (handled)
	    {
	      put_string (j, name, s);
	      vec_free (s);
	      break;
	    }

	  vec_free (s);
	}

      begin_object (j, name);
      desc_tojson_fields (j, df, r, p);
      clib_json_parent (j);
      break;
    case VL_API_DK_NAMED:
      s = desc_format_alias (0, r, p, 0);
      put_string (j, name, s);
      vec_free (s);
      break;
    default:
      break;
    }
}

/* value of a length field of the type */
static u32
desc_length_of (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		const vl_api_desc_field_t *f, const u8 *base)
{
  const vl_api_desc_field_t *lf = &vl_api_desc_fields (df, t)[f->related];

  return desc_read_uint (base + lf->offset, lf->kind);
}

static void
desc_tojson_array (clib_json_text_t *j, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		   const vl_api_desc_field_t *f, const u8 *base)
{
  const u8 *p = base + f->offset;
  u32 n = (f->flags & VL_API_DF_VLA) ? desc_length_of (df, t, f, base) : f->length;

  if (f->flags & VL_API_DF_MODERN_VLA)
    {
      u32 len = clib_net_to_host_u32 (*(u32 *) p);
      u8 *s = 0;

      vec_add (s, p + sizeof (u32), len);
      put_string (j, f->name, s);
      vec_free (s);
      return;
    }

  if (f->kind == VL_API_DK_FSTRING)
    {
      u8 *s = 0;

      vec_add (s, p, strnlen ((char *) p, f->length));
      put_string (j, f->name, s);
      vec_free (s);
      return;
    }

  if (vl_api_desc_field_is_u8 (f))
    {
      u8 *s = format (0, "0x%U", format_hex_bytes_no_wrap, p, n);

      put_string (j, f->name, s);
      vec_free (s);
      return;
    }

  begin_array (j, f->name);

  for (u32 i = 0; i < n; i++)
    desc_tojson_value (j, df, 0, f, p + (u64) i * f->size, 1);

  clib_json_parent (j);
}

static void
desc_tojson_fields (clib_json_text_t *j, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		    const u8 *base)
{
  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];

      if (desc_is_noprint (f->name))
	continue;

      if (f->flags & VL_API_DF_ARRAY)
	desc_tojson_array (j, df, t, f, base);
      else
	desc_tojson_value (j, df, f->name, f, base + f->offset, 0);
    }
}

int
vl_api_desc_msg_to_json (const vl_api_desc_msg_t *m, const void *msg, clib_json_text_t *j)
{
  const vl_api_desc_type_t *t = m->type;

  if (t->kind != VL_API_DT_MESSAGE)
    return -1;

  clib_json_init (j);

  if (clib_json_add_object (j, 0) < 0)
    return -1;

  clib_json_add_string (j, "_msgname", "%s", t->name);
  clib_json_add_string (j, "_crc", "%08x", t->crc);
  desc_tojson_fields (j, m->file, t, msg);
  clib_json_parent (j);
  return 0;
}

/* ---- JSON to messages */

typedef struct
{
  clib_json_text_t *j;
  /* the file which the types of the message are in */
  const vl_api_desc_file_t *df;
  /* the message, fixed part first, the variable length parts are appended */
  u8 *msg;
} desc_fromjson_t;

static int desc_fromjson_fields (desc_fromjson_t *c, const vl_api_desc_type_t *t, u32 off, int obj);

static int
desc_item (desc_fromjson_t *c, int obj, const char *name)
{
  int i;

  if (!clib_json_value_is_object (c->j, obj))
    return -1;

  i = clib_json_find_object_value_by_name (c->j, obj, "%s", name);
  return i < 0 ? -1 : i;
}

/* text of a JSON string, up to the first nul as for a C string */
static int
desc_get_string (desc_fromjson_t *c, int item, u8 **s, u32 *len)
{
  clib_json_value_t *v;

  if (item < 0 || !clib_json_value_is_string (c->j, item))
    return -1;

  v = pool_elt_at_index (c->j->values, item);

  *s = v->string;
  *len = vec_len (v->string);
  for (u32 i = 0; i < *len; i++)
    if (v->string[i] == 0)
      {
	*len = i;
	break;
      }

  return 0;
}

static void
desc_store_number (u8 *p, u32 kind, f64 d)
{
  switch (kind)
    {
    case VL_API_DK_U8:
      *p = d;
      break;
    case VL_API_DK_I8:
      *(i8 *) p = d;
      break;
    case VL_API_DK_U16:
      {
	u16 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_I16:
      {
	i16 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_U32:
      {
	u32 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_I32:
      {
	i32 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_U64:
      {
	u64 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_I64:
      {
	i64 v = d;
	memcpy (p, &v, sizeof (v));
      }
      break;
    case VL_API_DK_F64:
      memcpy (p, &d, sizeof (d));
      break;
    }
}

static void
desc_store_uint (u8 *p, u32 size, u64 v)
{
  memcpy (p, &v, size);
}

/* parse of the types which are text in JSON, returns 0 if t is not one */
static int
desc_fromjson_manual (desc_fromjson_t *c, const vl_api_desc_type_t *t, u32 off, int item, int *rv)
{
  const char *n = t->name;
  unformat_input_t input;
  u8 *s;
  u32 len;
  u8 *p = c->msg + off;
  int plen = 0;

  if (strcmp (n, "ip4_address") && strcmp (n, "ip6_address") && strcmp (n, "ip4_prefix") &&
      strcmp (n, "ip6_prefix") && strcmp (n, "address") && strcmp (n, "prefix") &&
      strcmp (n, "mac_address") && strcmp (n, "ip4_address_with_prefix") &&
      strcmp (n, "ip6_address_with_prefix") && strcmp (n, "address_with_prefix"))
    return 0;

  *rv = -1;
  if (desc_get_string (c, item, &s, &len) < 0)
    return 1;

  unformat_init_string (&input, (char *) s, len);

  if (!strcmp (n, "ip4_address"))
    *rv = unformat (&input, "%U", unformat_ip4_address, p) ? 0 : -1;
  else if (!strcmp (n, "ip6_address"))
    *rv = unformat (&input, "%U", unformat_ip6_address, p) ? 0 : -1;
  else if (!strcmp (n, "ip4_prefix") || !strcmp (n, "ip4_address_with_prefix"))
    {
      vl_api_ip4_prefix_t *a = (vl_api_ip4_prefix_t *) p;

      if (unformat (&input, "%U/%d", unformat_ip4_address, &a->address, &plen))
	{
	  a->len = plen;
	  *rv = 0;
	}
    }
  else if (!strcmp (n, "ip6_prefix") || !strcmp (n, "ip6_address_with_prefix"))
    {
      vl_api_ip6_prefix_t *a = (vl_api_ip6_prefix_t *) p;

      if (unformat (&input, "%U/%d", unformat_ip6_address, &a->address, &plen))
	{
	  a->len = plen;
	  *rv = 0;
	}
    }
  else if (!strcmp (n, "address"))
    {
      vl_api_address_t *a = (vl_api_address_t *) p;

      if (unformat (&input, "%U", unformat_ip4_address, &a->un.ip4))
	{
	  a->af = ADDRESS_IP4;
	  *rv = 0;
	}
      else if (unformat (&input, "%U", unformat_ip6_address, &a->un.ip6))
	{
	  a->af = ADDRESS_IP6;
	  *rv = 0;
	}
    }
  else if (!strcmp (n, "prefix") || !strcmp (n, "address_with_prefix"))
    {
      vl_api_prefix_t *a = (vl_api_prefix_t *) p;

      if (unformat (&input, "%U/%d", unformat_ip4_address, &a->address.un.ip4, &plen))
	{
	  a->address.af = ADDRESS_IP4;
	  a->len = plen;
	  *rv = 0;
	}
      else if (unformat (&input, "%U/%d", unformat_ip6_address, &a->address.un.ip6, &plen))
	{
	  a->address.af = ADDRESS_IP6;
	  a->len = plen;
	  *rv = 0;
	}
    }
  else if (!strcmp (n, "mac_address"))
    *rv = unformat (&input, "%U", unformat_mac_address, p) ? 0 : -1;

  unformat_free (&input);
  return 1;
}

static int
desc_fromjson_enum (desc_fromjson_t *c, const vl_api_desc_type_t *t, u32 off, int item)
{
  u8 *s;
  u32 len, size = desc_kind_size (t->base);

  if (t->kind == VL_API_DT_ENUMFLAG)
    {
      u64 v = 0;
      int *e;

      if (clib_json_value_is_array (c->j, item))
	vec_foreach (e, pool_elt_at_index (c->j->values, item)->array_val_indices)
	  {
	    if (desc_get_string (c, *e, &s, &len) < 0)
	      return -1;

	    for (u32 i = 0; i < t->n_fields; i++)
	      if (strlen (vl_api_desc_values (c->df, t)[i].name) == len &&
		  !memcmp (vl_api_desc_values (c->df, t)[i].name, s, len))
		v |= vl_api_desc_values (c->df, t)[i].value;
	  }
      desc_store_uint (c->msg + off, size, v);

      return 0;
    }

  if (desc_get_string (c, item, &s, &len) < 0)
    return -1;

  for (u32 i = 0; i < t->n_fields; i++)
    if (strlen (vl_api_desc_values (c->df, t)[i].name) == len &&
	!memcmp (vl_api_desc_values (c->df, t)[i].name, s, len))
      {
	desc_store_uint (c->msg + off, size, vl_api_desc_values (c->df, t)[i].value);
	return 0;
      }

  desc_store_uint (c->msg + off, size, 0);
  return -1;
}

/* a value of a field or an element of an array */
static int
desc_fromjson_value (desc_fromjson_t *c, const vl_api_desc_field_t *f, u32 off, int item)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (c->df, f);
  int rv;

  switch (f->kind)
    {
    case VL_API_DK_U8 ... VL_API_DK_F64:
      if (clib_json_value_is_number (c->j, item))
	desc_store_number (c->msg + off, f->kind, pool_elt_at_index (c->j->values, item)->number);
      else if (r && r->kind == VL_API_DT_ALIAS && clib_json_value_is_string (c->j, item))
	{
	  /* the elements of an array of an alias are text in the JSON */
	  u8 *text = format (0, "%v%c", pool_elt_at_index (c->j->values, item)->string, 0);

	  desc_store_number (c->msg + off, f->kind, strtod ((char *) text, 0));
	  vec_free (text);
	}

      return 0;
    case VL_API_DK_BOOL:
      if (clib_json_value_is_true (c->j, item))
	c->msg[off] = 1;
      else if (clib_json_value_is_false (c->j, item))
	c->msg[off] = 0;

      return 0;
    case VL_API_DK_ENUM:
    case VL_API_DK_ENUMFLAG:
      return desc_fromjson_enum (c, r, off, item);
    case VL_API_DK_STRUCT:
    case VL_API_DK_UNION:
      if ((r->flags & VL_API_DTF_MANUAL_PRINT) && desc_fromjson_manual (c, r, off, item, &rv))
	return rv;

      return desc_fromjson_fields (c, r, off, item);
    case VL_API_DK_NAMED:
      if (desc_fromjson_manual (c, r, off, item, &rv))
	return rv;

      return 0;
    }
  return 0;
}

static int
desc_fromjson_array (desc_fromjson_t *c, const vl_api_desc_type_t *t, const vl_api_desc_field_t *f,
		     u32 off, int item)
{
  u32 foff = off + f->offset;

  if (f->flags & VL_API_DF_MODERN_VLA)
    {
      u8 *s;
      u32 len, at, be;

      if (desc_get_string (c, item, &s, &len) < 0)
	return -1;

      at = vec_len (c->msg);
      be = clib_host_to_net_u32 (len);
      memcpy (c->msg + foff, &be, sizeof (be));
      vec_add2 (c->msg, s, 0);
      vec_resize (c->msg, len);
      memset (c->msg + at, 0, len);
      memcpy (c->msg + at, pool_elt_at_index (c->j->values, item)->string, len);
      return 0;
    }

  if (f->kind == VL_API_DK_FSTRING)
    {
      u8 *s;
      u32 len;

      if (desc_get_string (c, item, &s, &len) < 0)
	return -1;

      if (len > f->length - 1)
	len = f->length ? f->length - 1 : 0;

      memcpy (c->msg + foff, s, len);
      return 0;
    }

  if (vl_api_desc_field_is_u8 (f))
    {
      unformat_input_t input;
      u8 *s, *bytes = 0;
      u32 len;
      int ok;

      if (desc_get_string (c, item, &s, &len) < 0)
	return -1;

      unformat_init_string (&input, (char *) s, len);
      ok = unformat (&input, "0x%U", unformat_hex_string, &bytes);
      unformat_free (&input);

      if (!ok || !bytes)
	return -1;

      if (f->flags & VL_API_DF_VLA)
	{
	  u32 at = vec_len (c->msg);

	  desc_store_uint (c->msg + off + vl_api_desc_fields (c->df, t)[f->related].offset,
			   desc_kind_size (vl_api_desc_fields (c->df, t)[f->related].kind),
			   vec_len (bytes));

	  vec_resize (c->msg, vec_len (bytes));
	  memcpy (c->msg + at, bytes, vec_len (bytes));
	}
      else
	{
	  if (vec_len (bytes) > f->length)
	    {
	      vec_free (bytes);
	      return -1;
	    }

	  memcpy (c->msg + foff, bytes, vec_len (bytes));
	}

      vec_free (bytes);
      return 0;
    }

  {
    int *e, n;
    u32 i = 0, at;

    if (!clib_json_value_is_array (c->j, item))
      return -1;

    n = vec_len (pool_elt_at_index (c->j->values, item)->array_val_indices);

    if (f->flags & VL_API_DF_VLA)
      {
	desc_store_uint (c->msg + off + vl_api_desc_fields (c->df, t)[f->related].offset,
			 desc_kind_size (vl_api_desc_fields (c->df, t)[f->related].kind), n);

	at = vec_len (c->msg);
	vec_resize (c->msg, n * f->size);
	memset (c->msg + at, 0, n * f->size);
      }
    else
      {
	if (n != f->length)
	  return -1;

	at = foff;
      }

    vec_foreach (e, pool_elt_at_index (c->j->values, item)->array_val_indices)
      {
	/* the array may move while parsing, take the index of the element
	 * from the item again */
	if (desc_fromjson_value (c, f, at + i * f->size, *e) < 0)
	  return -1;

	i++;
      }
  }
  return 0;
}

static int
desc_fromjson_fields (desc_fromjson_t *c, const vl_api_desc_type_t *t, u32 off, int obj)
{
  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (c->df, t)[i];
      int item;

      /* messages do not have these in JSON */
      if (t->kind == VL_API_DT_MESSAGE && desc_is_noprint (f->name))
	continue;

      if (f->flags & VL_API_DF_LENGTH)
	continue;

      item = desc_item (c, obj, f->name);
      if (item < 0)
	{
	  /* all the arms of an union are optional */
	  if (t->kind == VL_API_DT_UNION)
	    continue;

	  return -1;
	}

      if (f->flags & VL_API_DF_ARRAY)
	{
	  if (desc_fromjson_array (c, t, f, off, item) < 0)
	    return -1;
	}
      else if (desc_fromjson_value (c, f, off + f->offset, item) < 0)
	return -1;
    }

  return 0;
}

u8 *
vl_api_desc_msg_from_json (const vl_api_desc_msg_t *m, clib_json_text_t *j, int value_index)
{
  const vl_api_desc_type_t *t = m->type;
  desc_fromjson_t c = { .j = j, .df = m->file };

  if (t->kind != VL_API_DT_MESSAGE)
    return 0;

  vec_validate (c.msg, t->size - 1);
  memset (c.msg, 0, t->size);

  if (desc_fromjson_fields (&c, t, 0, value_index) < 0)
    {
      vec_free (c.msg);
      return 0;
    }

  return c.msg;
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
	  s = desc_format_manual (s, r, p, &handled, 1);

	  if (handled)
	    return s;
	}

      return desc_format_fields (s, df, r, p, indent + 2);
    case VL_API_DK_NAMED:
      return desc_format_alias (s, r, p, 1);
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
