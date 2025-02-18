/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HPACK_H_
#define SRC_PLUGINS_HTTP_HPACK_H_

#include <vppinfra/types.h>
#include <http/http2/http2.h>

#define HPACK_INVALID_INT CLIB_UWORD_MAX
#if uword_bits == 64
#define HPACK_ENCODED_INT_MAX_LEN 10
#else
#define HPACK_ENCODED_INT_MAX_LEN 6
#endif

#define HPACK_DEFAULT_HEADER_TABLE_SIZE	   4096
#define HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD 32

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
  u16 parsed_bitmap;
} hpack_request_control_data_t;

/**
 * Decode unsigned variable-length integer (RFC7541 section 5.1)
 *
 * @param src        Pointer to source buffer which will be advanced
 * @param end        End of the source buffer
 * @param prefix_len Number of bits of the prefix (between 1 and 8)
 *
 * @return Decoded integer or @c HPACK_INVALID_INT in case of error
 */
uword hpack_decode_int (u8 **src, u8 *end, u8 prefix_len);

/**
 * Encode given value as unsigned variable-length integer (RFC7541 section 5.1)
 *
 * @param dst        Pointer to destination buffer, should have enough space
 * @param value      Integer value to encode (up to @c CLIB_WORD_MAX)
 * @param prefix_len Number of bits of the prefix (between 1 and 8)
 *
 * @return Advanced pointer to the destination buffer
 *
 * @note Encoded integer will take maximum @c HPACK_ENCODED_INT_MAX_LEN bytes
 */
u8 *hpack_encode_int (u8 *dst, uword value, u8 prefix_len);

/**
 * Decode
 *
 * @param src Pointer to source buffer which will be advanced
 * @param end End of the source buffer
 * @param buf     Pointer to the buffer where string is decoded which will be
 *                advanced by number of written bytes
 * @param buf_len Length the buffer, will be decreased
 *
 * @return @c HTTP2_ERROR_NO_ERROR on success
 *
 * @note Caller is responsible to check if there is somthing left in source
 * buffer first
 */
http2_error_t hpack_decode_huffman (u8 **src, u8 *end, u8 **buf,
				    uword *buf_len);

/**
 * Encode given string in Huffman codes.
 *
 * @param dst       Pointer to destination buffer, should have enough space
 * @param value     String to encode
 * @param value_len Length of the string
 *
 * @return Advanced pointer to the destination buffer
 */
u8 *hpack_encode_huffman (u8 *dst, const u8 *value, uword value_len);

/**
 * Number of bytes required to encode given string in Huffman codes
 *
 * @param value     Pointer to buffer with string to encode
 * @param value_len Length of the string
 *
 * @return number of bytes required to encode string in Huffman codes, round up
 * to byte boundary
 */
uword hpack_huffman_encoded_len (const u8 *value, uword value_len);

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
 *
 * @param src
 * @param src_len
 * @param dst
 * @param dst_len
 * @param control_data
 * @param headers
 * @param dynamic_table
 *
 * @return
 */
http2_error_t hpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
				   hpack_request_control_data_t *control_data,
				   http_field_line_t *headers,
				   hpack_dynamic_table_t *dynamic_table);

#endif /* SRC_PLUGINS_HTTP_HPACK_H_ */
