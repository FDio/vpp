/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_STATUS_CODES_H_
#define SRC_PLUGINS_HTTP_HTTP_STATUS_CODES_H_

#include <http/http.h>

const char *http_status_code_str[] = {
#define _(c, s, str) str,
  foreach_http_status_code
#undef _
};

static inline u8 *
format_http_status_code (u8 *s, va_list *va)
{
  http_status_code_t status_code = va_arg (*va, http_status_code_t);
  if (status_code < HTTP_N_STATUS)
    s = format (s, "%s", http_status_code_str[status_code]);
  else
    s = format (s, "invalid status code %d", status_code);
  return s;
}

#endif /* SRC_PLUGINS_HTTP_HTTP_STATUS_CODES_H_ */
