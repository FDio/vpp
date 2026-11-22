/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vlibapi/api_common.h>
#include <vlibapi/api_desc.h>

void
vl_api_desc_register (api_main_t *am, const vl_api_desc_file_t *f, u16 msg_id_base)
{
  vec_add1 (am->desc_files, f);

  for (u32 i = 0; i < f->n_msgs; i++)
    {
      u32 id = f->msgs[i].id + msg_id_base;

      vec_validate (am->desc_by_msg_id, id);
      am->desc_by_msg_id[id] = (vl_api_desc_msg_t) { .file = f, .type = &f->msgs[i] };
    }
}

void
vl_api_desc_register_msg (api_main_t *am, const vl_api_desc_file_t *f, const char *name, u32 msg_id)
{
  for (u32 i = 0; i < f->n_msgs; i++)
    if (!strcmp (f->msgs[i].name, name))
      {
	vec_validate (am->desc_by_msg_id, msg_id);
	am->desc_by_msg_id[msg_id] = (vl_api_desc_msg_t) { .file = f, .type = &f->msgs[i] };
	break;
      }

  for (u32 i = 0; i < vec_len (am->desc_files); i++)
    if (am->desc_files[i] == f)
      return;

  vec_add1 (am->desc_files, f);
}

/* ---- the type of a field */

u8 *
format_vl_api_desc_field_type (u8 *s, va_list *args)
{
  static const char *base_names[] = {
    [VL_API_DK_U8] = "u8",     [VL_API_DK_I8] = "i8",	      [VL_API_DK_U16] = "u16",
    [VL_API_DK_I16] = "i16",   [VL_API_DK_U32] = "u32",	      [VL_API_DK_I32] = "i32",
    [VL_API_DK_U64] = "u64",   [VL_API_DK_I64] = "i64",	      [VL_API_DK_F64] = "f64",
    [VL_API_DK_BOOL] = "bool", [VL_API_DK_STRING] = "string", [VL_API_DK_FSTRING] = "string",
  };
  const vl_api_desc_file_t *df = va_arg (*args, const vl_api_desc_file_t *);
  const vl_api_desc_field_t *f = va_arg (*args, const vl_api_desc_field_t *);

  if (f->ref)
    return format (s, "vl_api_%s_t", vl_api_desc_ref (df, f)->name);

  return format (s, "%s", f->kind < ARRAY_LEN (base_names) ? base_names[f->kind] : "?");
}

const vl_api_desc_msg_t *
vl_api_desc_find_msg (api_main_t *am, u32 msg_id)
{
  if (msg_id >= vec_len (am->desc_by_msg_id) || !am->desc_by_msg_id[msg_id].type)
    return 0;

  return &am->desc_by_msg_id[msg_id];
}

/* ---- .api.json rendering */

/* an object with the options */
static void
desc_add_options (clib_json_text_t *j, char *name, const vl_api_desc_option_t *o, u32 n)
{
  clib_json_add_object (j, name ? "%s" : 0, name);

  for (u32 i = 0; i < n; i++)
    if (o[i].value)
      clib_json_add_string (j, "%s", "%s", o[i].name, o[i].value);
    else
      clib_json_add_null (j, "%s", o[i].name);

  clib_json_parent (j);
}

static int
desc_add_field (clib_json_text_t *j, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t,
		const vl_api_desc_field_t *f)
{
  if (clib_json_add_array (j, 0) < 0)
    return -1;

  clib_json_add_string (j, 0, "%U", format_vl_api_desc_field_type, df, f);
  clib_json_add_string (j, 0, "%s", f->name);

  if (f->flags & VL_API_DF_ARRAY)
    {
      clib_json_add_number (j, 0, f->length);

      if (f->flags & VL_API_DF_VLA)
	clib_json_add_string (j, 0, "%s", vl_api_desc_len_field_name (df, t, f));
    }
  else if (f->default_kind != VL_API_DD_NONE || (f->flags & (VL_API_DF_TAGGED | VL_API_DF_CASE)))
    {
      clib_json_add_object (j, 0);

      switch (f->default_kind)
	{
	case VL_API_DD_INT:
	  clib_json_add_number (j, "default", (f64) f->default_value.i);
	  break;
	case VL_API_DD_BOOL:
	  if (f->default_value.i)
	    clib_json_add_true (j, "default");
	  else
	    clib_json_add_false (j, "default");
	  break;
	case VL_API_DD_FLOAT:
	  clib_json_add_number (j, "default", f->default_value.f);
	  break;
	case VL_API_DD_STRING:
	  clib_json_add_string (j, "default", "%s", f->default_value.s);
	  break;
	}

      if (f->flags & VL_API_DF_TAGGED)
	clib_json_add_string (j, "discriminator", "%s",
			      vl_api_desc_fields (df, t)[f->related].name);

      if (f->flags & VL_API_DF_CASE)
	clib_json_add_string (j, "case", "%s", f->case_name);

      clib_json_parent (j);
    }

  clib_json_parent (j);
  return 0;
}

/* [name, fields..., {meta}] */
static int
desc_add_def (clib_json_text_t *j, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  if (clib_json_add_array (j, 0) < 0)
    return -1;

  clib_json_add_string (j, 0, "%s", t->name);

  for (u32 i = 0; i < t->n_fields; i++)
    desc_add_field (j, df, t, &vl_api_desc_fields (df, t)[i]);

  if (t->kind == VL_API_DT_MESSAGE)
    {
      clib_json_add_object (j, 0);
      clib_json_add_string (j, "crc", "0x%08x", t->crc);
      desc_add_options (j, "options", vl_api_desc_options (df, t), t->n_options);
      clib_json_parent (j);
    }

  clib_json_parent (j);
  return 0;
}

/* [name, [id, value]..., {"enumtype": T}] */
static int
desc_add_enum (clib_json_text_t *j, const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  static const char *base_name[] = {
    [VL_API_DK_U8] = "u8",   [VL_API_DK_I8] = "i8",   [VL_API_DK_U16] = "u16",
    [VL_API_DK_I16] = "i16", [VL_API_DK_U32] = "u32", [VL_API_DK_I32] = "i32",
    [VL_API_DK_U64] = "u64", [VL_API_DK_I64] = "i64",
  };

  if (clib_json_add_array (j, 0) < 0)
    return -1;

  clib_json_add_string (j, 0, "%s", t->name);

  for (u32 i = 0; i < t->n_fields; i++)
    {
      clib_json_add_array (j, 0);
      clib_json_add_string (j, 0, "%s", vl_api_desc_values (df, t)[i].name);
      clib_json_add_number (j, 0, vl_api_desc_values (df, t)[i].value);
      clib_json_parent (j);
    }

  clib_json_add_object (j, 0);
  clib_json_add_string (j, "enumtype", "%s",
			t->base < ARRAY_LEN (base_name) && base_name[t->base] ? base_name[t->base] :
										"u32");
  clib_json_parent (j);
  clib_json_parent (j);
  return 0;
}

int
vl_api_desc_schema_to_json (const vl_api_desc_file_t *f, clib_json_text_t *j)
{
  u32 i;

  clib_json_init (j);

  if (clib_json_add_object (j, 0) < 0)
    return -1;

  clib_json_add_string (j, "module", "%s", f->module);

  /* typedefs, messages, unions, enums, enumflags, services, options,
   * aliases, ... in the order of the .api.json files */
  clib_json_add_array (j, "types");

  for (i = 0; i < f->n_types; i++)
    if (f->types[i].kind == VL_API_DT_TYPEDEF)
      desc_add_def (j, f, &f->types[i]);

  clib_json_parent (j);

  clib_json_add_array (j, "messages");

  for (i = 0; i < f->n_msgs; i++)
    desc_add_def (j, f, &f->msgs[i]);

  clib_json_parent (j);

  clib_json_add_array (j, "unions");

  for (i = 0; i < f->n_types; i++)
    if (f->types[i].kind == VL_API_DT_UNION)
      desc_add_def (j, f, &f->types[i]);

  clib_json_parent (j);

  clib_json_add_array (j, "enums");

  for (i = 0; i < f->n_types; i++)
    if (f->types[i].kind == VL_API_DT_ENUM)
      desc_add_enum (j, f, &f->types[i]);

  clib_json_parent (j);

  clib_json_add_array (j, "enumflags");

  for (i = 0; i < f->n_types; i++)
    if (f->types[i].kind == VL_API_DT_ENUMFLAG)
      desc_add_enum (j, f, &f->types[i]);

  clib_json_parent (j);

  clib_json_add_object (j, "services");

  for (i = 0; i < f->n_msgs; i++)
    {
      const vl_api_desc_type_t *m = &f->msgs[i];

      if (!(m->flags & VL_API_DTF_SERVICE))
	continue;

      clib_json_add_object (j, "%s", m->name);
      clib_json_add_string (j, "reply", "%s", m->reply ? vl_api_desc_reply (f, m)->name : "null");

      if (m->flags & VL_API_DTF_STREAM)
	clib_json_add_true (j, "stream");

      if (m->details)
	clib_json_add_string (j, "stream_msg", "%s", vl_api_desc_details (f, m)->name);

      clib_json_parent (j);
    }

  clib_json_parent (j);

  desc_add_options (j, "options", f->options, f->n_options);

  clib_json_add_object (j, "aliases");

  for (i = 0; i < f->n_types; i++)
    {
      const vl_api_desc_type_t *t = &f->types[i];

      if (t->kind != VL_API_DT_ALIAS)
	continue;

      /* an alias which is imported by more than one file is listed
       * more than once, the JSON has it once */
      if (clib_json_find_object_value_by_name (j, j->current_value, "%s", t->name) >= 0)
	continue;

      clib_json_add_object (j, "%s", t->name);
      clib_json_add_string (j, "type", "%s", t->alias_type);

      if (t->alias_length)
	clib_json_add_number (j, "length", t->alias_length);

      clib_json_parent (j);
    }

  clib_json_parent (j);

  clib_json_add_string (j, "vl_api_version", "0x%x", f->file_crc);
  clib_json_parent (j);
  return 0;
}
