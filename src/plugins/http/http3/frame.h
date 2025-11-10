/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP3_FRAME_H_
#define SRC_PLUGINS_HTTP_HTTP3_FRAME_H_

#include <http/http3/http3.h>

#define HTTP3_FRAME_HEADER_MAX_LEN (HTTP_VARINT_MAX_LEN * 2)

/* value, label, ctrl_stream, req_stream, push_stream */
#define foreach_http3_frame_type                                              \
  _ (0x00, DATA, 0, 1, 1)                                                     \
  _ (0x01, HEADERS, 0, 1, 1)                                                  \
  _ (0x03, CANCEL_PUSH, 1, 0, 0)                                              \
  _ (0x04, SETTINGS, 1, 0, 0)                                                 \
  _ (0x05, PUSH_PROMISE, 0, 1, 0)                                             \
  _ (0x07, GOAWAY, 1, 0, 0)                                                   \
  _ (0x0D, MAX_PUSH_ID, 1, 0, 0)

typedef enum
{
#define _(value, label, ctrl_stream, req_stream, push_stream)                 \
  HTTP3_FRAME_TYPE_##label = value,
  foreach_http3_frame_type
#undef _
} http3_frame_type_t;

typedef struct
{
  u64 type;
  u64 length;
  u8 *payload;
  u8 header_len;
} http3_frame_header_t;

/**
 * Parse frame header
 *
 * @param src         Pointer to the beginning of the frame
 * @param src_len     Length of data available for parsing
 * @param stream_type Current stream type
 * @param fh          Parsed frame header
 *
 * @return @c HTTP3_ERROR_NO_ERROR on success
 */
http3_error_t http3_frame_header_read (u8 *src, u64 src_len,
				       http3_stream_type_t stream_type,
				       http3_frame_header_t *fh);

/**
 * Write frame header
 * @param type   Frame type
 * @param length Frame payload length
 * @param dst    Buffer pointer where frame header will be written
 *
 * @return Frame header length
 */
always_inline u8
http3_frame_header_write (http3_frame_type_t type, u64 length, u8 *dst)
{
  *dst++ = (u8) type;
  http_encode_varint (dst, length);
  return http_varint_len (length) + 1;
}

/**
 * Parse GOAWAY frame payload
 *
 * @param payload           Payload to parse
 * @param len               Payload length
 * @param stream_or_push_id Parsed stream ID or push ID
 *
 * @return @c HTTP3_ERROR_NO_ERROR on success
 */
http3_error_t http3_frame_goaway_read (u8 *payload, u64 len,
				       u64 *stream_or_push_id);

/**
 * Write GOAWAY frame to the end of given vector
 *
 * @param stream_or_push_id Stream ID or push ID
 * @param dst               Vector where GOAWAY frame will be written
 */
void http3_frame_goaway_write (u64 stream_or_push_id, u8 **dst);

/**
 * Parse SETTINGS frame payload
 *
 * @param payload  Payload to parse
 * @param len      Payload length
 * @param settings HTTP/3 settings where parsed values are stored
 *
 * @return @c HTTP3_ERROR_NO_ERROR on success
 */
http3_error_t http3_frame_settings_read (u8 *payload, u64 len,
					 http3_conn_settings_t *settings);

/**
 * Write SETTINGS frame to the end of given vector
 *
 * @param settings HTTP/3 settings used for payload
 * @param dst      Vector where SETTINGS frame will be written
 */
void http3_frame_settings_write (http3_conn_settings_t *settings, u8 **dst);

#endif /* SRC_PLUGINS_HTTP_HTTP3_FRAME_H_ */
