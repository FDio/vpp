/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP3_H_
#define SRC_PLUGINS_HTTP_HTTP3_H_

#include <vppinfra/format.h>
#include <vppinfra/types.h>

#define foreach_http3_errors                                                  \
  _ (NO_ERROR, "NO_ERROR", 0x0100)                                            \
  _ (GENERAL_PROTOCOL_ERROR, "GENERAL_PROTOCOL_ERROR", 0x0101)                \
  _ (INTERNAL_ERROR, "INTERNAL_ERROR", 0x0102)                                \
  _ (STREAM_CREATION_ERROR, "STREAM_CREATION_ERROR", 0x0103)                  \
  _ (CLOSED_CRITICAL_STREAM, "CLOSED_CRITICAL_STREAM", 0x0104)                \
  _ (FRAME_UNEXPECTED, "FRAME_UNEXPECTED", 0x0105)                            \
  _ (FRAME_ERROR, "FRAME_ERROR", 0x0106)                                      \
  _ (EXCESSIVE_LOAD, "EXCESSIVE_LOAD", 0x0107)                                \
  _ (ID_ERROR, "ID_ERROR", 0x0108)                                            \
  _ (SETTINGS_ERROR, "SETTINGS_ERROR", 0x0109)                                \
  _ (MISSING_SETTINGS, "MISSING_SETTINGS", 0x010a)                            \
  _ (REQUEST_REJECTED, "REQUEST_REJECTED", 0x010b)                            \
  _ (REQUEST_CANCELLED, "REQUEST_CANCELLED", 0x010c)                          \
  _ (REQUEST_INCOMPLETE, "REQUEST_INCOMPLETE", 0x010d)                        \
  _ (MESSAGE_ERROR, "MESSAGE_ERROR", 0x010e)                                  \
  _ (CONNECT_ERROR, "CONNECT_ERROR", 0x010f)                                  \
  _ (VERSION_FALLBACK, "VERSION_FALLBACK", 0x0110)                            \
  _ (QPACK_DECOMPRESSION_FAILED, "QPACK_DECOMPRESSION_FAILED", 0x0200)        \
  _ (QPACK_ENCODER_STREAM_ERROR, "QPACK_ENCODER_STREAM_ERROR", 0x0201)        \
  _ (QPACK_DECODER_STREAM_ERROR, "QPACK_DECODER_STREAM_ERROR", 0x0202)

typedef enum
{
#define _(sym, str, val) HTTP3_ERROR_##sym = val,
  foreach_http3_errors
#undef _
} http3_error_t;

static inline u8 *
format_http3_error (u8 *s, va_list *va)
{
  http3_error_t e = va_arg (*va, http3_error_t);
  u8 *t = 0;

  switch (e)
    {
#define _(sym, str, val)                                                      \
  case HTTP3_ERROR_##sym:                                                     \
    t = (u8 *) str;                                                           \
    break;
      foreach_http3_errors
#undef _
	default : return format (s, "BUG: unknown");
    }
  return format (s, "%s", t);
}

#endif /* SRC_PLUGINS_HTTP_HTTP3_H_ */
