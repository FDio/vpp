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
  const vl_api_desc_msg_t *d = vl_api_desc_find_msg (am, msg_id);
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);

  if (d)
    return vl_api_desc_msg_format (s, d, msg);

  return format (s, "[format handler missing for `%s`]", m ? m->name : "unknown");
}

u8 *
format_vl_api_msg_json (u8 *s, va_list *args)
{
  api_main_t *am = va_arg (*args, api_main_t *);
  u32 msg_id = va_arg (*args, u32);
  void *msg = va_arg (*args, void *);
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);

  cJSON *o = m->tojson_handler (msg);
  char *out = cJSON_Print (o);

  s = format (s, "%s", out);

  cJSON_Delete (o);
  cJSON_free (out);
  return s;
}
