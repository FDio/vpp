/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* api_desc.h: API descriptors.
 *
 * vppapigen emits, for every .api file which defines messages, a const
 * description of its messages and types and registers it with
 * vl_api_desc_register (). It carries the binary layout of the C structures
 * (packed, field offsets, array and VLA rules) and the metadata of the .api
 * file, so that generic code can convert messages from and to JSON, and can
 * render the .api.json text when it is needed, without per message
 * generated functions or an embedded copy of that text.
 *
 * A descriptor is self contained: all the types of the files it imports are
 * included in it (marked imported), exactly as in the .api.json file, it does
 * not depend on other files being registered.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/json.h>

/* Kind of a field (of its element type for arrays) */
typedef enum
{
  VL_API_DK_U8,
  VL_API_DK_I8,
  VL_API_DK_U16,
  VL_API_DK_I16,
  VL_API_DK_U32,
  VL_API_DK_I32,
  VL_API_DK_U64,
  VL_API_DK_I64,
  VL_API_DK_F64,
  VL_API_DK_BOOL,
  VL_API_DK_STRING,  /* vl_api_string_t, variable length */
  VL_API_DK_FSTRING, /* u8 [N], nul terminated */
  VL_API_DK_ENUM,
  VL_API_DK_ENUMFLAG,
  VL_API_DK_STRUCT,
  VL_API_DK_UNION,
  VL_API_DK_NAMED, /* alias which is not a base type, see ref */
} vl_api_desc_field_kind_t;

/* Field flags */
#define VL_API_DF_ARRAY	     (1 << 0) /* fixed (length) or variable (VLA) array */
#define VL_API_DF_VLA	     (1 << 1) /* length is in the field which related is the index of */
#define VL_API_DF_MODERN_VLA (1 << 2) /* string, vl_api_string_t */
#define VL_API_DF_LENGTH     (1 << 3) /* this is the length field of a VLA */
/* a union selected by the field which related is the index of, the union is tagged */
#define VL_API_DF_TAGGED (1 << 4)
/* the arm of a union which is selected when the tag is the value of case_name */
#define VL_API_DF_CASE (1 << 5)

typedef enum
{
  VL_API_DT_MESSAGE,
  VL_API_DT_TYPEDEF,
  VL_API_DT_UNION,
  VL_API_DT_ENUM,
  VL_API_DT_ENUMFLAG,
  VL_API_DT_ALIAS,
} vl_api_desc_type_kind_t;

/* Type flags */
#define VL_API_DTF_MANUAL_PRINT	 (1 << 0)
#define VL_API_DTF_MANUAL_ENDIAN (1 << 1)
#define VL_API_DTF_VLA		 (1 << 2) /* ends with a variable length part */
#define VL_API_DTF_DONT_TRACE	 (1 << 3)
#define VL_API_DTF_AUTOENDIAN	 (1 << 4)
#define VL_API_DTF_SERVICE	 (1 << 5) /* a request, it has a reply and maybe details */
#define VL_API_DTF_STREAM	 (1 << 6) /* the reply is a stream of details */

struct vl_api_desc_type;

/* name and value of an option of a file or a message, the value is 0 for an
 * option which has none */
typedef struct
{
  const char *name;
  const char *value;
} vl_api_desc_option_t;

/* The kind of the default value of a field */
typedef enum
{
  VL_API_DD_NONE,
  VL_API_DD_INT,
  VL_API_DD_BOOL,
  VL_API_DD_FLOAT,
  VL_API_DD_STRING,
} vl_api_desc_default_kind_t;

typedef struct vl_api_desc_field
{
  const char *name;
  /* the value of the field when it is not given, see default_kind */
  union
  {
    i64 i; /* an integer, 1 or 0 for a bool */
    f64 f;
    const char *s;
  } default_value;
  /* the name of the enum value for which this is the arm, for VL_API_DF_CASE */
  const char *case_name;
  /* what the comment of the message or the type says about the field */
  const char *description;
  /* type of the field (of the elements for arrays), for kinds which have
   * one: enum, enumflag, struct, union, alias */
  const struct vl_api_desc_type *ref;
  u32 length; /* number of elements of a fixed array */
  u16 offset; /* offset in the packed C structure */
  u16 size;   /* size of one element */
  /* index of the field which has the tag of a tagged union, or the length of
   * a VLA */
  u16 related;
  u8 kind;	   /* vl_api_desc_field_kind_t */
  u8 flags;	   /* VL_API_DF_* */
  u8 default_kind; /* vl_api_desc_default_kind_t */
} vl_api_desc_field_t;

typedef struct
{
  const char *name;
  i64 value;
} vl_api_desc_enum_val_t;

typedef struct vl_api_desc_type
{
  const char *name; /* without vl_api_ and _t */
  const char *brief;
  /* the options of a message */
  const vl_api_desc_option_t *options;
  /* of a request message, VL_API_DTF_SERVICE: the message which answers it, 0
   * if there is none, and the message of the details of a stream or a dump, 0
   * if there is none */
  const struct vl_api_desc_type *reply;
  const struct vl_api_desc_type *details;
  /* fields of messages, typedefs and unions */
  const vl_api_desc_field_t *fields;
  /* values of enums and enumflags, n_fields of them */
  const vl_api_desc_enum_val_t *values;
  /* alias of: type name as written in the .api file */
  const char *alias_type;
  u32 alias_length; /* alias of an array, 0 if not */
  u32 crc;	    /* messages */
  u32 size;	    /* size of the fixed part of the C structure */
  u16 id;	    /* message id, relative to the first id of the file */
  u16 n_fields;
  u16 n_options;
  u8 kind;     /* vl_api_desc_type_kind_t */
  u8 flags;    /* VL_API_DTF_* */
  u8 base;     /* enums: kind of the underlying type */
  u8 imported; /* defined in another file */
} vl_api_desc_type_t;

typedef struct vl_api_desc_file
{
  u32 file_crc; /* of the file, it covers the imported files too */
  const char *module;
  /* types of the file in the order of the .api file, the messages */
  const vl_api_desc_type_t *const *types;
  const vl_api_desc_type_t *const *msgs;
  u32 n_types;
  u32 n_msgs;
  const vl_api_desc_option_t *options;
  u32 n_options;
} vl_api_desc_file_t;

struct api_main_t;

/* The type of a field as it is written in the .api file, u32, string,
 * vl_api_address_t..., for the field which is the argument. */
format_function_t format_vl_api_desc_field_type;

/* The name of the field which has the length of a variable length array. */
static inline const char *
vl_api_desc_len_field_name (const vl_api_desc_type_t *t, const vl_api_desc_field_t *f)
{
  return t->fields[f->related].name;
}

/* The elements of the array are the bytes of the type u8, and not of an alias
 * of it. */
static inline int
vl_api_desc_field_is_u8 (const vl_api_desc_field_t *f)
{
  return f->kind == VL_API_DK_U8 && !f->ref;
}

/* Registers the descriptor of a file, msg_id_base is the first message id
 * of the file. */
void vl_api_desc_register (struct api_main_t *am, const vl_api_desc_file_t *f, u16 msg_id_base);

/* Registers the descriptor of one message of a file whose message ids are not
 * a range which starts at a base, for the files which are registered by hand. */
void vl_api_desc_register_msg (struct api_main_t *am, const vl_api_desc_file_t *f, const char *name,
			       u32 msg_id);

/* Descriptor of the message with the given id, 0 if none. */
const vl_api_desc_type_t *vl_api_desc_find_msg (struct api_main_t *am, u32 msg_id);

/* Converts a message in host byte order to JSON, the same JSON as the
 * generated vl_api_<msg>_t_tojson function creates. t is the descriptor of
 * the message. Returns 0 or a negative value on error. */
int vl_api_desc_msg_to_json (const vl_api_desc_type_t *t, const void *msg, clib_json_text_t *j);
