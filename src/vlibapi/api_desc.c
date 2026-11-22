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
