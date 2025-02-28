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

/**
 * Parse frame header
 *
 * @param src Pointer to the beginning of the frame
 * @param fh  Parsed frame header
 */
void http2_frame_header_read (u8 *src, http2_frame_header_t *fh);

/**
 * Add 9 bytes (frame header size) to the end of given vector
 *
 * @param dst Pointer to vector
 *
 * @return Pointer to the frame header beginning
 */
static_always_inline u8 *
http2_frame_header_alloc (u8 **dst)
{
  u8 *p;

  vec_add2 (*dst, p, HTTP2_FRAME_HEADER_SIZE);
  return p;
}

/**
 * Parse SETTINGS frame payload
 *
 * @param settings    Vector of HTTP/2 settings
 * @param payload     Payload to parse
 * @param payload_len Payload length
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_settings (http2_conn_settings_t *settings,
					 u8 *payload, u32 payload_len);

/**
 * Write SETTINGS ACK frame to the end of given vector
 *
 * @param dst Vector where SETTINGS ACK frame will be written
 */
void http2_frame_write_settings_ack (u8 **dst);

/**
 * Write SETTINGS frame to the end of given vector
 *
 * @param settings Vector of HTTP/2 settings
 * @param dst      Vector where SETTINGS frame will be written
 */
void http2_frame_write_settings (http2_settings_entry_t *settings, u8 **dst);

/**
 * Parse WINDOW_UPDATE frame payload
 *
 * @param increment   Parsed window increment value
 * @param payload     Payload to parse
 * @param payload_len Payload length
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_window_update (u32 *increment, u8 *payload,
					      u32 payload_len);

/**
 * Write WINDOW_UPDATE frame to the end of given vector
 *
 * @param increment Window increment value
 * @param stream_id Stream ID
 * @param dst       Vector where WINDOW_UPDATE frame will be written
 */
void http2_frame_write_window_update (u32 increment, u32 stream_id, u8 **dst);

/**
 * Parse RST_STREAM frame payload
 *
 * @param error_code  Parsed error code
 * @param payload     Payload to parse
 * @param payload_len Payload length
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_rst_stream (u32 *error_code, u8 *payload,
					   u32 payload_len);

/**
 * Write RST_STREAM frame to the end of given vector
 *
 * @param error_code Error code
 * @param stream_id  Stream ID, except 0
 * @param dst        Vector where RST_STREAM frame will be written
 */
void http2_frame_write_rst_stream (http2_error_t error_code, u32 stream_id,
				   u8 **dst);

/**
 * Parse GOAWAY frame payload
 *
 * @param last_stream_id Parsed last stream ID
 * @param error_code     Parsed error code
 * @param payload        Payload to parse
 * @param payload_len    Payload length
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_goaway (u32 *last_stream_id, u32 *error_code,
				       u8 *payload, u32 payload_len);

/**
 * Write GOAWAY frame to the end of given vector
 * @param error_code     Error code
 * @param last_stream_id Last stream ID
 * @param dst            Vector where GOAWAY frame will be written
 */
void http2_frame_write_goaway (http2_error_t error_code, u32 last_stream_id,
			       u8 **dst);

/**
 * Parse HEADERS frame payload
 *
 * @param headers     Pointer to header block fragment
 * @param headers_len Header block fragment length
 * @param payload     Payload to parse
 * @param payload_len Payload length
 * @param flags       Flag field of frame header
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_headers (u8 **headers, u32 *headers_len,
					u8 *payload, u32 payload_len,
					u8 flags);

/**
 * Write HEADERS frame header
 *
 * @param headers_len Header block fragment length
 * @param stream_id   Stream ID, except 0
 * @param flags       Frame header flags
 * @param dst         Pointer where frame header will be written
 *
 * @note Use @c http2_frame_header_alloc before
 */
void http2_frame_write_headers_header (u32 headers_len, u32 stream_id,
				       u8 flags, u8 *dst);

/**
 * Parse DATA frame payload
 *
 * @param headers     Pointer to data
 * @param headers_len Data length
 * @param payload     Payload to parse
 * @param payload_len Payload length
 * @param flags       Flag field of frame header
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, error otherwise
 */
http2_error_t http2_frame_read_data (u8 **data, u32 *data_len, u8 *payload,
				     u32 payload_len, u8 flags);

/**
 * Write DATA frame header
 *
 * @param data_len  Data length
 * @param stream_id Stream ID, except 0
 * @param flags     Frame header flags
 * @param dst       Pointer where frame header will be written
 */
void http2_frame_write_data_header (u32 data_len, u32 stream_id, u8 flags,
				    u8 *dst);

#endif /* SRC_PLUGINS_HTTP_HTTP2_FRAME_H_ */
