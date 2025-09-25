/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HPACK_H_
#define SRC_PLUGINS_HTTP_HPACK_H_

#include <vppinfra/types.h>
#include <http/http2/http2.h>
#include <http/http.h>

#define HPACK_INVALID_INT CLIB_UWORD_MAX
#if uword_bits == 64
#define HPACK_ENCODED_INT_MAX_LEN 10
#else
#define HPACK_ENCODED_INT_MAX_LEN 6
#endif

#define HPACK_DEFAULT_HEADER_TABLE_SIZE	   4096
#define HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD 32
#define HPACK_ENCODER_SKIP_CONTENT_LEN	   ((u64) ~0)

typedef struct
{
  u8 *buf;
  uword name_len;
} hpack_dynamic_table_entry_t;

typedef struct
{
  /* SETTINGS_HEADER_TABLE_SIZE */
  u32 max_size;
  /* dynamic table size update */
  u32 size;
  /* current usage (each entry = 32 + name len + value len) */
  u32 used;
  /* ring buffer */
  hpack_dynamic_table_entry_t *entries;
} hpack_dynamic_table_t;

enum
{
#define _(bit, name, str) HPACK_PSEUDO_HEADER_##name##_PARSED = (1 << bit),
  foreach_http2_pseudo_header
#undef _
};

typedef struct
{
  http_req_method_t method;
  http_url_scheme_t scheme;
  u8 *authority;
  u32 authority_len;
  u8 *path;
  u32 path_len;
  u8 *headers;
  u8 *protocol;
  u32 protocol_len;
  u8 *user_agent;
  u32 user_agent_len;
  uword content_len_header_index;
  u32 headers_len;
  u32 control_data_len;
  u16 parsed_bitmap;
  u64 content_len;
} hpack_request_control_data_t;

typedef struct
{
  http_status_code_t sc;
  u64 content_len;
  u8 *server_name;
  u32 server_name_len;
  u8 *date;
  u32 date_len;
  u16 parsed_bitmap;
  uword content_len_header_index;
  u8 *headers;
  u32 headers_len;
  u32 control_data_len;
} hpack_response_control_data_t;

/**
 * Initialize HPACK dynamic table
 *
 * @param table    Dynamic table to initialize
 * @param max_size Maximum table size (SETTINGS_HEADER_TABLE_SIZE)
 */
void hpack_dynamic_table_init (hpack_dynamic_table_t *table, u32 max_size);

/**
 * Free HPACK dynamic table
 *
 * @param table Dynamic table to free
 */
void hpack_dynamic_table_free (hpack_dynamic_table_t *table);

u8 *format_hpack_dynamic_table (u8 *s, va_list *args);

/**
 * Request parser
 *
 * @param src           Header block to parse
 * @param src_len       Length of header block
 * @param dst           Buffer where headers will be decoded
 * @param dst_len       Length of buffer for decoded headers
 * @param control_data  Preparsed pseudo-headers
 * @param headers       List of regular headers
 * @param dynamic_table Decoder dynamic table
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, connection error otherwise
 */
http2_error_t hpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
				   hpack_request_control_data_t *control_data,
				   http_field_line_t **headers,
				   hpack_dynamic_table_t *dynamic_table);

/**
 * Response parser
 *
 * @param src           Header block to parse
 * @param src_len       Length of header block
 * @param dst           Buffer where headers will be decoded
 * @param dst_len       Length of buffer for decoded headers
 * @param control_data  Preparsed pseudo-headers
 * @param headers       List of regular headers
 * @param dynamic_table Decoder dynamic table
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success, connection error otherwise
 */
http2_error_t
hpack_parse_response (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_response_control_data_t *control_data,
		      http_field_line_t **headers,
		      hpack_dynamic_table_t *dynamic_table);

/**
 * Serialize response
 *
 * @param app_headers     App header list
 * @param app_headers_len App header list length
 * @param control_data    Header values set by protocol layer
 * @param dst             Vector where serialized headers will be added
 */
void hpack_serialize_response (u8 *app_headers, u32 app_headers_len,
			       hpack_response_control_data_t *control_data,
			       u8 **dst);

/**
 * Serialize request
 *
 * @param app_headers     App header list
 * @param app_headers_len App header list length
 * @param control_data    Header values set by protocol layer
 * @param dst             Vector where serialized headers will be added
 */
void hpack_serialize_request (u8 *app_headers, u32 app_headers_len,
			      hpack_request_control_data_t *control_data,
			      u8 **dst);

#endif /* SRC_PLUGINS_HTTP_HPACK_H_ */
