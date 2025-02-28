/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP2_H_
#define SRC_PLUGINS_HTTP_HTTP2_H_

#include <vppinfra/format.h>
#include <vppinfra/types.h>

/* RFC9113 section 7 */
#define foreach_http2_error                                                   \
  _ (NO_ERROR, "NO_ERROR")                                                    \
  _ (PROTOCOL_ERROR, "PROTOCOL_ERROR")                                        \
  _ (INTERNAL_ERROR, "INTERNAL_ERROR")                                        \
  _ (FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR")                                \
  _ (SETTINGS_TIMEOUT, "SETTINGS_TIMEOUT")                                    \
  _ (STREAM_CLOSED, "STREAM_CLOSED")                                          \
  _ (FRAME_SIZE_ERROR, "FRAME_SIZE_ERROR")                                    \
  _ (REFUSED_STREAM, "REFUSED_STREAM")                                        \
  _ (CANCEL, "CANCEL")                                                        \
  _ (COMPRESSION_ERROR, "COMPRESSION_ERROR")                                  \
  _ (CONNECT_ERROR, "CONNECT_ERROR")                                          \
  _ (ENHANCE_YOUR_CALM, "ENHANCE_YOUR_CALM")                                  \
  _ (INADEQUATE_SECURITY, "INADEQUATE_SECURITY")                              \
  _ (HTTP_1_1_REQUIRED, "HTTP_1_1_REQUIRED")

typedef enum http2_error_
{
#define _(s, str) HTTP2_ERROR_##s,
  foreach_http2_error
#undef _
} http2_error_t;

static inline u8 *
format_http2_error (u8 *s, va_list *va)
{
  http2_error_t e = va_arg (*va, http2_error_t);
  u8 *t = 0;

  switch (e)
    {
#define _(s, str)                                                             \
  case HTTP2_ERROR_##s:                                                       \
    t = (u8 *) str;                                                           \
    break;
      foreach_http2_error
#undef _
	default : return format (s, "BUG: unknown");
    }
  return format (s, "%s", t);
}

#define foreach_http2_pseudo_header                                           \
  _ (0, METHOD, "method")                                                     \
  _ (1, SCHEME, "scheme")                                                     \
  _ (2, AUTHORITY, "authority")                                               \
  _ (3, PATH, "path")                                                         \
  _ (4, STATUS, "status")

/* value, label, member, min, max, default_value, err_code */
#define foreach_http2_settings                                                \
  _ (1, HEADER_TABLE_SIZE, header_table_size, 0, CLIB_U32_MAX, 4096,          \
     HTTP2_ERROR_NO_ERROR)                                                    \
  _ (2, ENABLE_PUSH, enable_push, 0, 1, 1, HTTP2_ERROR_PROTOCOL_ERROR)        \
  _ (3, MAX_CONCURRENT_STREAMS, max_concurrent_streams, 0, CLIB_U32_MAX,      \
     CLIB_U32_MAX, HTTP2_ERROR_NO_ERROR)                                      \
  _ (4, INITIAL_WINDOW_SIZE, initial_window_size, 0, 0x7FFFFFFF, 65535,       \
     HTTP2_ERROR_FLOW_CONTROL_ERROR)                                          \
  _ (5, MAX_FRAME_SIZE, max_frame_size, 16384, 16777215, 16384,               \
     HTTP2_ERROR_PROTOCOL_ERROR)                                              \
  _ (6, MAX_HEADER_LIST_SIZE, max_header_list_size, 0, CLIB_U32_MAX,          \
     CLIB_U32_MAX, HTTP2_ERROR_NO_ERROR)

typedef enum
{
#define _(value, label, member, min, max, default_value, err_code)            \
  HTTP2_SETTINGS_##label = value,
  foreach_http2_settings
#undef _
} http_settings_t;

typedef struct
{
#define _(value, label, member, min, max, default_value, err_code) u32 member;
  foreach_http2_settings
#undef _
} http2_conn_settings_t;

static const http2_conn_settings_t http2_default_conn_settings = {
#define _(value, label, member, min, max, default_value, err_code)            \
  default_value,
  foreach_http2_settings
#undef _
};

#endif /* SRC_PLUGINS_HTTP_HTTP2_H_ */
