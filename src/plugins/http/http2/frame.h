/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP2_FRAME_H_
#define SRC_PLUGINS_HTTP_HTTP2_FRAME_H_

#include <vppinfra/error.h>
#include <vppinfra/types.h>
#include <http/http2/http2.h>

#define HTTP2_FRAME_HEADER_SIZE 9

#define foreach_http2_frame_type                                              \
  _ (0x00, DATA, "DATA")                                                      \
  _ (0x01, HEADERS, "HEADERS")                                                \
  _ (0x02, PRIORITY, "PRIORITY")                                              \
  _ (0x03, RST_STREAM, "RST_STREAM")                                          \
  _ (0x04, SETTINGS, "SETTINGS")                                              \
  _ (0x05, PUSH_PROMISE, "PUSH_PROMISE")                                      \
  _ (0x06, PING, "PING")                                                      \
  _ (0x07, GOAWAY, "GOAWAY")                                                  \
  _ (0x08, WINDOW_UPDATE, "WINDOW_UPDATE")                                    \
  _ (0x09, CONTINUATION, "CONTINUATION")

typedef enum
{
#define _(v, n, s) HTTP2_FRAME_TYPE_##n = v,
  foreach_http2_frame_type
#undef _
} __clib_packed http2_frame_type_t;

STATIC_ASSERT_SIZEOF (http2_frame_type_t, 1);

#define foreach_http2_frame_flag                                              \
  _ (0, NONE)                                                                 \
  _ (1, END_STREAM)                                                           \
  _ (1, ACK)                                                                  \
  _ (1 << 2, END_HEADERS)                                                     \
  _ (1 << 3, PADED)                                                           \
  _ (1 << 5, PRIORITY)

typedef enum
{
#define _(v, n) HTTP2_FRAME_FLAG_##n = v,
  foreach_http2_frame_flag
#undef _
} __clib_packed http2_frame_flag_t;

STATIC_ASSERT_SIZEOF (http2_frame_flag_t, 1);

typedef struct
{
  u32 length;
  http2_frame_type_t type;
  u8 flags;
  u32 stream_id;
} http2_frame_header_t;

typedef struct
{
  u16 identifier;
  u32 value;
} __clib_packed http2_settings_entry_t;

void http2_frame_header_read (u8 *src, http2_frame_header_t *fh);

http2_error_t http2_frame_read_settings (http2_conn_settings_t *settings,
					 u8 *payload, u32 payload_len);

void http2_frame_write_settings_ack (u8 **dst);

void http2_frame_write_settings (http2_settings_entry_t *settings, u8 **dst);

#endif /* SRC_PLUGINS_HTTP_HTTP2_FRAME_H_ */
