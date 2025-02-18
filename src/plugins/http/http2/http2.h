/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP2_H_
#define SRC_PLUGINS_HTTP_HTTP2_H_

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

#endif /* SRC_PLUGINS_HTTP_HTTP2_H_ */
