/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP1_CHUNKED_H_
#define SRC_PLUGINS_HTTP_HTTP1_CHUNKED_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define HTTP1_CHUNKED_MAX_LINE_SIZE    8192
#define HTTP1_CHUNKED_MAX_TRAILER_SIZE 65536

typedef enum
{
  HTTP1_CHUNKED_INVALID = -1,
  HTTP1_CHUNKED_TOO_LARGE = -2,
  HTTP1_CHUNKED_MORE = 0,
  HTTP1_CHUNKED_DATA,
  HTTP1_CHUNKED_DONE,
} http1_chunked_result_t;

typedef struct
{
  u64 chunk_bytes_left;
  u32 syntax_bytes;
  u8 state;
} http1_chunked_decoder_t;

/**
 * Decode framing up to the next contiguous payload span or the end of the body.
 *
 * @param decoder  Incremental decoder state.
 * @param src      Input bytes (may be NULL if len is zero).
 * @param len      Available input length.
 * @param consumed Framing bytes consumed, excluding payload and any invalid byte.
 * @param data_len On DATA, payload available at src + consumed; zero otherwise.
 *
 * @return @c HTTP1_CHUNKED_DATA leaves the payload unconsumed, @c HTTP1_CHUNKED_MORE requires more
 * input, @c HTTP1_CHUNKED_DONE includes the terminating empty trailer line and leaves subsequent
 * input untouched.
 */
http1_chunked_result_t http1_chunked_decode (http1_chunked_decoder_t *decoder, const u8 *src,
					     u32 len, u32 *consumed, u32 *data_len);

/**
 * Acknowledge payload bytes delivered to the application after a DATA result.
 *
 * Partial consumption is supported. Acknowledge only bytes actually delivered,
 * then resume decoding with the remaining input.
 *
 * @param decoder Incremental decoder state.
 * @param len     Bytes consumed from the payload span returned by the decoder.
 */
static_always_inline void
http1_chunked_consume_data (http1_chunked_decoder_t *decoder, u32 len)
{
  ASSERT (len <= decoder->chunk_bytes_left);
  decoder->chunk_bytes_left -= len;
}

#endif /* SRC_PLUGINS_HTTP_HTTP1_CHUNKED_H_ */
