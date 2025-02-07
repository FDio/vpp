/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HPACK_H_
#define SRC_PLUGINS_HTTP_HPACK_H_

#include <vppinfra/types.h>

#define HPACK_INVALID_INT CLIB_UWORD_MAX
#if uword_bits == 64
#define HPACK_ENCODED_INT_MAX_LEN 10
#else
#define HPACK_ENCODED_INT_MAX_LEN 6
#endif

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
 * @return @c 0 on success.
 */
int hpack_decode_huffman (u8 **src, u8 *end, u8 **buf, uword *buf_len);

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

#endif /* SRC_PLUGINS_HTTP_HPACK_H_ */
