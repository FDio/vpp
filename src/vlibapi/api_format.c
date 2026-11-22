/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vlibapi/api.h>
#include <vlibapi/api_desc.h>

u8 *
format_vl_api_msg_text (u8 *s, va_list *args)
{
  api_main_t *am = va_arg (*args, api_main_t *);
  u32 msg_id = va_arg (*args, u32);
  void *msg = va_arg (*args, void *);
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);

  if (m->format_fn)
    s = format (s, "%U", m->format_fn, msg);
  else
    s = format (s, "[format handler missing for `%s`]", m->name);
  return s;
}

int
vl_api_msg_to_json_text (api_main_t *am, u32 msg_id, void *msg, u8 **s)
{
  const vl_api_desc_msg_t *d = vl_api_desc_find_msg (am, msg_id);
  clib_json_text_t j;

  if (!d || vl_api_desc_msg_to_json (d, msg, &j))
    return -1;

  *s = format (*s, "%U", format_clib_json_text, &j);
  clib_json_free (&j);
  return 0;
}

u8 *
format_vl_api_msg_json (u8 *s, va_list *args)
{
  api_main_t *am = va_arg (*args, api_main_t *);
  u32 msg_id = va_arg (*args, u32);
  void *msg = va_arg (*args, void *);

  if (vl_api_msg_to_json_text (am, msg_id, msg, &s))
    s = format (s, "[no registered tojson fn]");
  return s;
}
