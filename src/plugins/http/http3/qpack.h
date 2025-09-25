/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_QPACK_H_
#define SRC_PLUGINS_HTTP_QPACK_H_

#include <http/http.h>
#include <http/http2/hpack.h>
#include <http/http3/http3.h>

typedef struct
{
  uword req_insert_count;
  uword delta_base;
  u8 delta_base_sign;
} qpack_decoder_ctx_t;

/**
 * Request parser
 *
 * @param src          Header block to parse
 * @param src_len      Length of header block
 * @param dst          Buffer where headers will be decoded
 * @param dst_len      Length of buffer for decoded headers
 * @param control_data Preparsed pseudo-headers
 * @param headers      List of regular headers
 * @param decoder_ctx  Decoder context
 *
 * @return @c HTTP3_ERROR_NO_ERROR on success
 */
http3_error_t qpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
				   hpack_request_control_data_t *control_data,
				   http_field_line_t **headers,
				   qpack_decoder_ctx_t *decoder_ctx);

/**
 * Response parser
 *
 * @param src          Header block to parse
 * @param src_len      Length of header block
 * @param dst          Buffer where headers will be decoded
 * @param dst_len      Length of buffer for decoded headers
 * @param control_data Preparsed pseudo-headers
 * @param headers      List of regular headers
 * @param decoder_ctx  Decoder context
 *
 * @return @c HTTP3_ERROR_NO_ERROR on success
 */
http3_error_t
qpack_parse_response (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_response_control_data_t *control_data,
		      http_field_line_t **headers,
		      qpack_decoder_ctx_t *decoder_ctx);

#endif /* SRC_PLUGINS_HTTP_QPACK_H_ */
