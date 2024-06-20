/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_CONTENT_TYPES_H_
#define SRC_PLUGINS_HTTP_HTTP_CONTENT_TYPES_H_

#include <http/http.h>

static http_token_t http_content_types[] = {
#define _(s, ext, str) { http_token_lit (str) },
  foreach_http_content_type
#undef _
};

#define http_content_type_token(e)                                            \
  http_content_types[e].base, http_content_types[e].len

#endif /* SRC_PLUGINS_HTTP_HTTP_CONTENT_TYPES_H_ */
