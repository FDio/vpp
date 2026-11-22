/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#ifndef included_vat2_json_h
#define included_vat2_json_h

#include <vlibapi/api_desc.h>
#include <vppinfra/cJSON.h>
#include <vppinfra/json.h>

/* Converts the JSON of a message of a file to the message in host byte order,
 * allocated by malloc (), its length is returned in *len. Returns 0 if the
 * JSON is not the message. */
static inline void *
vat2_json_to_msg (const vl_api_desc_file_t *f, const char *name, cJSON *o, int *len)
{
  vl_api_desc_msg_t m;
  clib_json_text_t j;
  clib_error_t *err;
  char *text;
  u8 *msg;
  void *rv;

  if (!vl_api_desc_file_find (f, name, &m))
    return 0;

  text = cJSON_PrintUnformatted (o);
  err = clib_json_init_from_string (&j, text, strlen (text));
  cJSON_free (text);

  if (err)
    {
      clib_error_free (err);
      return 0;
    }

  msg = vl_api_desc_msg_from_json (&m, &j, j.root_value);
  clib_json_free (&j);

  if (!msg)
    return 0;

  *len = vec_len (msg);
  rv = malloc (*len);
  memcpy (rv, msg, *len);
  vec_free (msg);
  return rv;
}

/* Converts a message of a file in host byte order to JSON */
static inline cJSON *
vat2_msg_to_json (const vl_api_desc_file_t *f, const char *name, void *msg)
{
  vl_api_desc_msg_t m;
  clib_json_text_t j;
  cJSON *o;
  u8 *s;

  if (!vl_api_desc_file_find (f, name, &m) || vl_api_desc_msg_to_json (&m, msg, &j))
    return 0;

  s = format (0, "%U%c", format_clib_json_text, &j, 0);
  clib_json_free (&j);
  o = cJSON_Parse ((char *) s);
  vec_free (s);
  return o;
}

#endif
