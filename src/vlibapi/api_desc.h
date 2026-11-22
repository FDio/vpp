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

struct api_main_t;

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
/* not converted to and from network byte order */
#define VL_API_DF_NO_ENDIAN (1 << 6)

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
  /* the value of the tag for which this is the arm, for VL_API_DF_CASE */
  i64 case_value;
  u32 length; /* number of elements of a fixed array */
  u16 offset; /* offset in the packed C structure */
  u16 size;   /* size of one element */
  /* index of the field which has the tag of a tagged union, or the length of
   * a VLA */
  u16 related;
  /* type of the field (of the elements for arrays), for kinds which have
   * one: enum, enumflag, struct, union, alias. One more than its index in the
   * types of the file, 0 if there is none, see vl_api_desc_ref (). */
  u16 ref;
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
  /* alias of: type name as written in the .api file */
  const char *alias_type;
  u32 alias_length; /* alias of an array, 0 if not */
  u32 crc;	    /* messages */
  u32 size;	    /* size of the fixed part of the C structure */
  u16 id;	    /* message id, relative to the first id of the file */
  /* the first of the n_fields fields of a message, a typedef or a union, or
   * of the values of an enum, in the arrays of the file */
  u16 first;
  /* the first of the n_options options of a message in the options of the file */
  u16 first_option;
  /* of a request message, VL_API_DTF_SERVICE: the message which answers it,
   * and the message of the details of a stream or a dump. One more than their
   * index in the messages of the file, 0 if there is none, see
   * vl_api_desc_reply () and vl_api_desc_details (). */
  u16 reply;
  u16 details;
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
  const vl_api_desc_type_t *types;
  const vl_api_desc_type_t *msgs;
  u32 n_types;
  u32 n_msgs;
  /* the fields of all the messages, typedefs and unions, a type has its own
   * range of it, and the values of all the enums */
  const vl_api_desc_field_t *fields;
  const vl_api_desc_enum_val_t *values;
  /* the first n_options are the options of the file, then the ones of the
   * messages follow */
  const vl_api_desc_option_t *options;
  u32 n_options;
} vl_api_desc_file_t;

/* A message with the file it is in, which has what the descriptor refers to */
typedef struct vl_api_desc_msg
{
  const vl_api_desc_file_t *file;
  const vl_api_desc_type_t *type;
} vl_api_desc_msg_t;

/* The fields of a message, a typedef or a union, the values of an enum, and
 * the options of a message, of the file which the type is in. */
static inline const vl_api_desc_field_t *
vl_api_desc_fields (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  return df->fields + t->first;
}

static inline const vl_api_desc_enum_val_t *
vl_api_desc_values (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  return df->values + t->first;
}

/* The type of a field, 0 if it has none. */
static inline const vl_api_desc_type_t *
vl_api_desc_ref (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f)
{
  return f->ref ? &df->types[f->ref - 1] : 0;
}

/* The message which answers a request, 0 if there is none. */
static inline const vl_api_desc_type_t *
vl_api_desc_reply (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  return t->reply ? &df->msgs[t->reply - 1] : 0;
}

/* The message of the details of a stream or a dump, 0 if there is none. */
static inline const vl_api_desc_type_t *
vl_api_desc_details (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  return t->details ? &df->msgs[t->details - 1] : 0;
}

static inline const vl_api_desc_option_t *
vl_api_desc_options (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  return df->options + t->first_option;
}

struct api_main_t;

/* The type of a field as it is written in the .api file, u32, string,
 * vl_api_address_t..., for the field which is the argument, arguments are the
 * file and the field. */
format_function_t format_vl_api_desc_field_type;

/* The name of the field which has the length of a variable length array. */
static inline const char *
vl_api_desc_len_field_name (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
			    const vl_api_desc_field_t *f)
{
  return vl_api_desc_fields (df, t)[f->related].name;
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
const vl_api_desc_msg_t *vl_api_desc_find_msg (struct api_main_t *am, u32 msg_id);

/* Renders the content of the .api.json file of a file into j, as a
 * single object. Returns 0 or a negative value on error. */
int vl_api_desc_schema_to_json (const vl_api_desc_file_t *f, clib_json_text_t *j);

/* Converts a message in host byte order to JSON, the same JSON as the
 * generated vl_api_<msg>_t_tojson function creates. t is the descriptor of
 * the message. Returns 0 or a negative value on error. */
int vl_api_desc_msg_to_json (const vl_api_desc_msg_t *m, const void *msg, clib_json_text_t *j);

/* Converts a JSON object to a message in host byte order, as the generated
 * vl_api_<msg>_t_fromjson function does. Returns a vector with the
 * message, or 0 if the JSON does not match the message. */
u8 *vl_api_desc_msg_from_json (const vl_api_desc_msg_t *m, clib_json_text_t *j, int value_index);

/* Appends the text of a message in host byte order, the same text as the
 * generated vl_api_<msg>_t_format function creates. */
u8 *vl_api_desc_msg_format (u8 *s, const vl_api_desc_msg_t *m, const void *msg);

/* The size of a message in network byte order, including its variable length
 * parts, the same as the generated vl_api_<msg>_t_calc_size function. */
uword vl_api_desc_msg_calc_size (const vl_api_desc_msg_t *m, const void *msg);

/* Converts a message to network byte order, or from it, in place, the same as
 * the generated vl_api_<msg>_t_endian function does. Fields of types which are
 * not tagged unions are converted by their kind, a tagged union by the arm
 * which its tag selects. Does nothing on a big endian host. */
void vl_api_desc_msg_endian (const vl_api_desc_msg_t *m, void *msg, int to_net);

/* Converts the message with the id to or from network byte order, by its
 * descriptor, or by the endian handler it was registered with if it has no
 * descriptor. Does nothing for an unknown id. */
/* Whether vl_api_msg_endian converts the message of the id. */
int vl_api_msg_has_endian (struct api_main_t *am, u32 msg_id);
void vl_api_msg_endian (struct api_main_t *am, u32 msg_id, void *msg, int to_net);

/* Creates the descriptors of a file from its .api.json text, the JSON object
 * with the "messages", "types"... which get_api_json returns for each file.
 * It is for the programs which do not have the descriptors compiled in. The
 * descriptors are the same as the ones vppapigen creates, except for what the
 * JSON does not have: the flags of the types which tell how they are
 * converted by hand (they are set for the types which are known), which
 * types were imported and which messages use autoendian. Free the result with
 * vl_api_desc_file_free (). */
clib_error_t *vl_api_desc_file_from_json (clib_json_text_t *j, int value_index,
					  const vl_api_desc_file_t **file);
void vl_api_desc_file_free (const vl_api_desc_file_t *f);
