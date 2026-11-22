/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* What the code which interprets the API descriptors shares. */

#ifndef included_vlibapi_api_desc_internal_h
#define included_vlibapi_api_desc_internal_h

#include <vlibapi/api_desc.h>

always_inline int
desc_is_noprint (const char *name)
{
  static const char *const desc_noprint[] = {
    "_vl_msg_id",
    "client_index",
    "context",
  };

  for (u32 i = 0; i < ARRAY_LEN (desc_noprint); i++)
    if (!strcmp (name, desc_noprint[i]))
      return 1;

  return 0;
}

always_inline u32
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
always_inline u64
desc_read_uint (const u8 *p, u32 kind)
{
  u64 v = 0;

  memcpy (&v, p, desc_kind_size (kind));
  return v;
}

always_inline f64
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

/* value of a length field of the type */
always_inline u32
desc_length_of (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		const vl_api_desc_field_t *f, const u8 *base)
{
  const vl_api_desc_field_t *lf = &vl_api_desc_fields (df, t)[f->related];

  return desc_read_uint (base + lf->offset, lf->kind);
}

/* text of the types which are formatted by hand, *handled is 0 if t is none
 * of them. The text of a message has a MAC address as aabb.ccdd.eeff, the
 * JSON as aa:bb:cc:dd:ee:ff. */
u8 *vl_api_desc_format_manual (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int *handled,
			       int for_text);

/* text of an alias, as the generated format function of the alias does it */
u8 *vl_api_desc_format_alias (u8 *s, const vl_api_desc_type_t *t, const u8 *p, int for_text);

#endif /* included_vlibapi_api_desc_internal_h */
