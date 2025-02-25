/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_
#define SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_

#include <http/http.h>

static http_token_t http_header_names[] = {
#define _(sym, str_canonical, str_lower, hpack_index)                         \
  { http_token_lit (str_canonical) },
  foreach_http_header_name
#undef _
};

#define http_header_name_token(e)                                             \
  http_header_names[e].base, http_header_names[e].len

#define http_header_name_str(e) http_header_names[e].base

#endif /* SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_ */
