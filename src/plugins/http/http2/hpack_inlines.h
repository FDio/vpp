/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HPACK_INLINES_H_
#define SRC_PLUGINS_HTTP_HPACK_INLINES_H_

#include <vppinfra/error.h>
#include <http/http_private.h>
#include <http/http2/hpack.h>
#include <http/http2/huffman_table.h>

typedef enum
{
  HPACK_ERROR_NONE,
  HPACK_ERROR_COMPRESSION,
  HPACK_ERROR_PROTOCOL,
  HPACK_ERROR_UNKNOWN,
} hpack_error_t;

typedef hpack_error_t (hpack_header_decoder_fn) (u8 **src, u8 *end, u8 **buf, uword *buf_len,
						 u32 *name_len, u32 *value_len, void *decoder_ctx,
						 u8 *never_index);

typedef struct
{
  char *base;
  uword len;
  u8 static_table_index;
} hpack_token_t;

static const hpack_token_t hpack_headers[] = {
#define _(sym, str_canonical, str_lower, hpack_index, flags)                                       \
  { http_token_lit (str_lower), hpack_index },
  foreach_http_header_name
#undef _
};

/**
 * Decode unsigned variable-length integer (RFC7541 section 5.1)
 *
 * @param src        Pointer to source buffer which will be advanced
 * @param end        End of the source buffer
 * @param prefix_len Number of bits of the prefix (between 1 and 8)
 *
 * @return Decoded integer or @c HPACK_INVALID_INT in case of error
 */
always_inline uword
hpack_decode_int (u8 **src, u8 *end, u8 prefix_len)
{
  uword value, new_value;
  u8 *p, shift = 0, byte;
  u16 prefix_max;

  ASSERT (*src < end);
  ASSERT (prefix_len >= 1 && prefix_len <= 8);

  p = *src;
  prefix_max = (1 << prefix_len) - 1;
  value = *p & (u8) prefix_max;
  p++;
  /* if integer value is less than 2^prefix_len-1 it's encoded within prefix */
  if (value != prefix_max)
    {
      *src = p;
      return value;
    }

  while (p != end)
    {
      byte = *p;
      p++;
      new_value = value + ((uword) (byte & 0x7F) << shift);
      shift += 7;
      /* check for overflow */
      if (new_value < value)
	return HPACK_INVALID_INT;
      value = new_value;
      /* MSB of the last byte is zero */
      if ((byte & 0x80) == 0)
	{
	  *src = p;
	  return value;
	}
    }

  return HPACK_INVALID_INT;
}

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
always_inline u8 *
hpack_encode_int (u8 *dst, uword value, u8 prefix_len)
{
  u16 prefix_max;

  ASSERT (prefix_len >= 1 && prefix_len <= 8);

  prefix_max = (1 << prefix_len) - 1;

  /* if integer value is less than 2^prefix_len-1 it's encoded within prefix */
  if (value < prefix_max)
    {
      *dst++ |= (u8) value;
      return dst;
    }

  /* otherwise all bits of the prefix are set to 1 */
  *dst++ |= (u8) prefix_max;
  /* and the value is decreased by 2^prefix_len-1 */
  value -= prefix_max;
  /* MSB of each byte is used as continuation flag */
  for (; value >= 0x80; value >>= 7)
    *dst++ = 0x80 | (value & 0x7F);
  /* except for the last byte */
  *dst++ = (u8) value;

  return dst;
}

/**
 * Decode
 *
 * @param src Pointer to source buffer which will be advanced
 * @param end End of the source buffer
 * @param buf     Pointer to the buffer where string is decoded which will be
 *                advanced by number of written bytes
 * @param buf_len Length the buffer, will be decreased
 *
 * @return @c HPACK_ERROR_NONE on success
 *
 * @note Caller is responsible to check if there is somthing left in source
 * buffer first
 */
always_inline hpack_error_t
hpack_decode_huffman (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u64 accumulator = 0;
  u8 accumulator_len = 0;
  u8 *p;
  hpack_huffman_code_t *code;

  p = *src;
  while (1)
    {
      /* out of space?  */
      if (*buf_len == 0)
	return HPACK_ERROR_UNKNOWN;
      /* refill */
      while (p < end && accumulator_len <= 56)
	{
	  accumulator <<= 8;
	  accumulator_len += 8;
	  accumulator |= (u64) *p++;
	}
      /* first try short codes (5 - 8 bits) */
      code =
	&huff_code_table_fast[(u8) (accumulator >> (accumulator_len - 8))];
      /* zero code length mean no luck */
      if (PREDICT_TRUE (code->code_len))
	{
	  **buf = code->symbol;
	  (*buf)++;
	  (*buf_len)--;
	  accumulator_len -= code->code_len;
	}
      else
	{
	  /* slow path / long codes (10 - 30 bits) */
	  u32 tmp;
	  /* group boundaries are aligned to 32 bits */
	  if (accumulator_len < 32)
	    tmp = accumulator << (32 - accumulator_len);
	  else
	    tmp = accumulator >> (accumulator_len - 32);
	  /* figure out which interval code falls into, this is possible
	   * because HPACK use canonical Huffman codes
	   * see Schwartz, E. and B. Kallick, “Generating a canonical prefix
	   * encoding”
	   */
	  hpack_huffman_group_t *hg = hpack_huffman_get_group (tmp);
	  /* this might happen with invalid EOS (longer than 7 bits) */
	  if (hg->code_len > accumulator_len)
	    return HPACK_ERROR_COMPRESSION;
	  /* trim code to correct length */
	  u32 code = (accumulator >> (accumulator_len - hg->code_len)) &
		     ((1 << hg->code_len) - 1);
	  if (!code)
	    return HPACK_ERROR_COMPRESSION;
	  /* find symbol in the list */
	  **buf = hg->symbols[code - hg->first_code];
	  (*buf)++;
	  (*buf_len)--;
	  accumulator_len -= hg->code_len;
	}
      /* all done */
      if (p == end && accumulator_len < 8)
	{
	  /* there might be one more symbol encoded with short code */
	  if (accumulator_len >= 5)
	    {
	      /* first check EOS case */
	      if (((1 << accumulator_len) - 1) ==
		  (accumulator & ((1 << accumulator_len) - 1)))
		break;

	      /* out of space?  */
	      if (*buf_len == 0)
		return HPACK_ERROR_UNKNOWN;

	      /* if bogus EOF check bellow will fail */
	      code = &huff_code_table_fast[(u8) (accumulator
						 << (8 - accumulator_len))];
	      **buf = code->symbol;
	      (*buf)++;
	      (*buf_len)--;
	      accumulator_len -= code->code_len;
	      /* end at byte boundary? */
	      if (accumulator_len == 0)
		break;
	    }
	  /* we must end with EOS here */
	  if (((1 << accumulator_len) - 1) !=
	      (accumulator & ((1 << accumulator_len) - 1)))
	    return HPACK_ERROR_COMPRESSION;
	  break;
	}
    }
  return HPACK_ERROR_NONE;
}

/**
 * Number of bytes required to encode given string in Huffman codes
 *
 * @param value     Pointer to buffer with string to encode
 * @param value_len Length of the string
 *
 * @return number of bytes required to encode string in Huffman codes, round up
 * to byte boundary
 */
always_inline uword
hpack_huffman_encoded_len (const u8 *value, uword value_len)
{
  uword len = 0;
  u8 *end;
  hpack_huffman_symbol_t *sym;

  end = (u8 *) value + value_len;
  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      len += sym->code_len;
    }
  /* round up to byte boundary */
  return (len + 7) / 8;
}

/**
 * Encode given string in Huffman codes.
 *
 * @param dst       Pointer to destination buffer, should have enough space
 * @param value     String to encode
 * @param value_len Length of the string
 *
 * @return Advanced pointer to the destination buffer
 */
always_inline u8 *
hpack_encode_huffman (u8 *dst, const u8 *value, uword value_len)
{
  u8 *end;
  hpack_huffman_symbol_t *sym;
  u8 accumulator_len = 40; /* leftover (1 byte) + max code_len (4 bytes) */
  u64 accumulator = 0;	   /* to fit leftover and current code */

  end = (u8 *) value + value_len;

  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      /* add current code to leftover of previous one */
      accumulator |= (u64) sym->code << (accumulator_len - sym->code_len);
      accumulator_len -= sym->code_len;
      /* write only fully occupied bytes (max 4) */
      switch (accumulator_len)
	{
	case 1 ... 8:
#define WRITE_BYTE()                                                          \
  *dst = (u8) (accumulator >> 32);                                            \
  accumulator_len += 8;                                                       \
  accumulator <<= 8;                                                          \
  dst++;
	  WRITE_BYTE ();
	case 9 ... 16:
	  WRITE_BYTE ();
	case 17 ... 24:
	  WRITE_BYTE ();
	case 25 ... 32:
	  WRITE_BYTE ();
	default:
	  break;
	}
    }

  /* padding (0-7 bits)*/
  ASSERT (accumulator_len > 32 && accumulator_len <= 40);
  if (accumulator_len != 40)
    {
      accumulator |= (u64) 0x7F << (accumulator_len - 7);
      *dst = (u8) (accumulator >> 32);
      dst++;
    }
  return dst;
}

always_inline u8
hpack_header_name_is_valid (u8 *name, u32 name_len)
{
  u32 i;
  static uword tchar[4] = {
    /* !#$%'*+-.0123456789 */
    0x03ff6cba00000000,
    /* ^_`abcdefghijklmnopqrstuvwxyz|~ */
    0x57ffffffc0000000,
    0x0000000000000000,
    0x0000000000000000,
  };
  for (i = 0; i < name_len; i++)
    {
      if (!clib_bitmap_get_no_check (tchar, name[i]))
	return 0;
    }
  return 1;
}

always_inline u8
hpack_header_value_is_valid (u8 *value, u32 value_len)
{
  u32 i;
  /* VCHAR / SP / HTAB / %x80-FF */
  static uword tchar[4] = {
    0xffffffff00000200,
    0x7fffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
  };

  if (value_len == 0)
    return 1;

  /* must not start or end with SP or HTAB */
  if ((value[0] == 0x20 || value[0] == 0x09 || value[value_len - 1] == 0x20 ||
       value[value_len - 1] == 0x09))
    return 0;

  for (i = 0; i < value_len; i++)
    {
      if (!clib_bitmap_get_no_check (tchar, value[i]))
	return 0;
    }
  return 1;
}

always_inline http_req_method_t
hpack_parse_method (u8 *value, u32 value_len)
{
  switch (value_len)
    {
    case 3:
      if (!memcmp (value, "GET", 3))
	return HTTP_REQ_GET;
      break;
    case 4:
      if (!memcmp (value, "POST", 4))
	return HTTP_REQ_POST;
      break;
    case 7:
      if (!memcmp (value, "CONNECT", 7))
	return HTTP_REQ_CONNECT;
      break;
    default:
      break;
    }
  /* HPACK should return only connection errors, this one is stream error */
  return HTTP_REQ_UNKNOWN;
}

always_inline http_url_scheme_t
hpack_parse_scheme (u8 *value, u32 value_len)
{
  switch (value_len)
    {
    case 4:
      if (!memcmp (value, "http", 4))
	return HTTP_URL_SCHEME_HTTP;
      break;
    case 5:
      if (!memcmp (value, "https", 5))
	return HTTP_URL_SCHEME_HTTPS;
      break;
    default:
      break;
    }
  /* HPACK should return only connection errors, this one is stream error */
  return HTTP_URL_SCHEME_UNKNOWN;
}

always_inline hpack_error_t
hpack_parse_status_code (u8 *value, u32 value_len, http_status_code_t *sc)
{
  u16 status_code = 0;
  u8 *p;

  if (value_len != 3)
    return HPACK_ERROR_PROTOCOL;

  p = value;
  parse_int (status_code, 100);
  parse_int (status_code, 10);
  parse_int (status_code, 1);
  if (status_code < 100 || status_code > 599)
    {
      HTTP_DBG (1, "invalid status code %d", status_code);
      return HPACK_ERROR_PROTOCOL;
    }
  HTTP_DBG (1, "status code: %d", status_code);
  *sc = http_sc_by_u16 (status_code);

  return HPACK_ERROR_NONE;
}

always_inline hpack_error_t
hpack_parse_req_pseudo_header (u8 *name, u32 name_len, u8 *value,
			       u32 value_len,
			       hpack_request_control_data_t *control_data)
{
  HTTP_DBG (2, "%U: %U", format_http_bytes, name, name_len, format_http_bytes,
	    value, value_len);
  switch (name_len)
    {
    case 5:
      if (!memcmp (name + 1, "path", 4))
	{
	  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED ||
	      value_len == 0)
	    return HPACK_ERROR_PROTOCOL;
	  control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
	  control_data->path = value;
	  control_data->path_len = value_len;
	  break;
	}
      return HPACK_ERROR_PROTOCOL;
    case 7:
      switch (name[1])
	{
	case 'm':
	  if (!memcmp (name + 2, "ethod", 5))
	    {
	      if (control_data->parsed_bitmap &
		  HPACK_PSEUDO_HEADER_METHOD_PARSED)
		return HPACK_ERROR_PROTOCOL;
	      control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_METHOD_PARSED;
	      control_data->method = hpack_parse_method (value, value_len);
	      break;
	    }
	  return HPACK_ERROR_PROTOCOL;
	case 's':
	  if (!memcmp (name + 2, "cheme", 5))
	    {
	      if (control_data->parsed_bitmap &
		  HPACK_PSEUDO_HEADER_SCHEME_PARSED)
		return HPACK_ERROR_PROTOCOL;
	      control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
	      control_data->scheme = hpack_parse_scheme (value, value_len);
	      break;
	    }
	  return HPACK_ERROR_PROTOCOL;
	default:
	  return HPACK_ERROR_PROTOCOL;
	}
      break;
    case 9:
      if (!memcmp (name + 1, "protocol", 8))
	{
	  if (control_data->parsed_bitmap &
	      HPACK_PSEUDO_HEADER_PROTOCOL_PARSED)
	    return HPACK_ERROR_PROTOCOL;
	  control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_PROTOCOL_PARSED;
	  control_data->protocol = value;
	  control_data->protocol_len = value_len;
	  break;
	}
      break;
    case 10:
      if (!memcmp (name + 1, "authority", 9))
	{
	  if (control_data->parsed_bitmap &
	      HPACK_PSEUDO_HEADER_AUTHORITY_PARSED)
	    return HPACK_ERROR_PROTOCOL;
	  control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
	  control_data->authority = value;
	  control_data->authority_len = value_len;
	  break;
	}
      return HPACK_ERROR_PROTOCOL;
    default:
      return HPACK_ERROR_PROTOCOL;
    }

  return HPACK_ERROR_NONE;
}

always_inline hpack_error_t
hpack_parse_resp_pseudo_header (u8 *name, u32 name_len, u8 *value,
				u32 value_len,
				hpack_response_control_data_t *control_data)
{
  HTTP_DBG (2, "%U: %U", format_http_bytes, name, name_len, format_http_bytes,
	    value, value_len);
  switch (name_len)
    {
    case 7:
      if (!memcmp (name + 1, "status", 6))
	{
	  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_STATUS_PARSED)
	    return HPACK_ERROR_PROTOCOL;
	  control_data->parsed_bitmap |= HPACK_PSEUDO_HEADER_STATUS_PARSED;
	  return hpack_parse_status_code (value, value_len, &control_data->sc);
	}
      break;
    default:
      return HPACK_ERROR_PROTOCOL;
    }
  return HPACK_ERROR_NONE;
}

/* Special treatment for headers like:
 *
 * RFC9113 8.2.2: any message containing connection-specific header
 * fields MUST be treated as malformed (connection, upgrade, keep-alive,
 * proxy-connection, transfer-encoding), TE header MUST NOT contain any value
 * other than "trailers"
 *
 * find headers that will be used later in preprocessing (content-length)
 */
always_inline hpack_error_t
hpack_preprocess_header (u8 *name, u32 name_len, u8 *value, u32 value_len,
			 uword index, uword *content_len_header_index)
{
  switch (name_len)
    {
    case 2:
      if (name[0] == 't' && name[1] == 'e' &&
	  !http_token_is_case ((const char *) value, value_len,
			       http_token_lit ("trailers")))
	return HPACK_ERROR_PROTOCOL;
      break;
    case 7:
      if (!memcmp (name, "upgrade", 7))
	return HPACK_ERROR_PROTOCOL;
      break;
    case 10:
      switch (name[0])
	{
	case 'c':
	  if (!memcmp (name + 1, "onnection", 9))
	    return HPACK_ERROR_PROTOCOL;
	  break;
	case 'k':
	  if (!memcmp (name + 1, "eep-alive", 9))
	    return HPACK_ERROR_PROTOCOL;
	  break;
	default:
	  break;
	}
      break;
    case 14:
      if (!memcmp (name, "content-length", 14) &&
	  *content_len_header_index == ~0)
	*content_len_header_index = index;
      break;
    case 16:
      if (!memcmp (name, "proxy-connection", 16))
	return HPACK_ERROR_PROTOCOL;
      break;
    case 17:
      if (!memcmp (name, "transfer-encoding", 17))
	return HPACK_ERROR_PROTOCOL;
      break;
    default:
      break;
    }
  return HPACK_ERROR_NONE;
}

always_inline hpack_error_t
hpack_decode_request (u8 *src, u8 *end, u8 *dst, u32 dst_len,
		      hpack_request_control_data_t *control_data,
		      http_field_line_t **headers, void *decoder_ctx,
		      hpack_header_decoder_fn *decoder_fn)
{
  u8 *p, *b, *name, *value;
  u8 regular_header_parsed = 0, never_index;
  u32 name_len, value_len;
  uword b_left;
  http_field_line_t *header;
  hpack_error_t rv;

  p = src;
  b = dst;
  b_left = dst_len;
  control_data->parsed_bitmap = 0;
  control_data->headers_len = 0;
  control_data->content_len_header_index = ~0;

  while (p != end)
    {
      never_index = 0;
      name = b;
      rv = decoder_fn (&p, end, &b, &b_left, &name_len, &value_len, decoder_ctx, &never_index);
      if (rv)
	{
	  HTTP_DBG (1, "decode_header: %d", rv);
	  return rv;
	}
      value = name + name_len;

      /* pseudo header */
      if (name[0] == ':')
	{
	  /* all pseudo-headers must be before regular headers */
	  if (regular_header_parsed)
	    {
	      HTTP_DBG (1, "pseudo-headers after regular header");
	      return HPACK_ERROR_PROTOCOL;
	    }
	  rv = hpack_parse_req_pseudo_header (name, name_len, value, value_len,
					      control_data);
	  if (rv)
	    {
	      HTTP_DBG (1, "hpack_parse_req_pseudo_header: %d", rv);
	      return rv;
	    }
	  continue;
	}
      else
	{
	  if (!hpack_header_name_is_valid (name, name_len))
	    return HPACK_ERROR_PROTOCOL;
	  if (!regular_header_parsed)
	    {
	      regular_header_parsed = 1;
	      control_data->headers = name;
	    }
	}
      if (!hpack_header_value_is_valid (value, value_len))
	return HPACK_ERROR_PROTOCOL;
      vec_add2 (*headers, header, 1);
      HTTP_DBG (2, "%U: %U", format_http_bytes, name, name_len,
		format_http_bytes, value, value_len);
      header->name_offset = name - control_data->headers;
      header->name_len = name_len;
      header->value_offset = value - control_data->headers;
      header->value_len = value_len;
      header->flags = never_index ? HTTP_FIELD_LINE_F_NEVER_INDEX : 0;
      control_data->headers_len += name_len;
      control_data->headers_len += value_len;
      if (regular_header_parsed)
	{
	  rv = hpack_preprocess_header (
	    name, name_len, value, value_len, header - *headers,
	    &control_data->content_len_header_index);
	  if (rv)
	    {
	      HTTP_DBG (1, "connection-specific header present");
	      return rv;
	    }
	}
    }
  control_data->control_data_len = dst_len - b_left;
  return HPACK_ERROR_NONE;
}

always_inline hpack_error_t
hpack_decode_response (u8 *src, u8 *end, u8 *dst, u32 dst_len,
		       hpack_response_control_data_t *control_data,
		       http_field_line_t **headers, void *decoder_ctx,
		       hpack_header_decoder_fn *decoder_fn)
{
  u8 *p, *b, *name, *value;
  u8 regular_header_parsed = 0, never_index;
  u32 name_len, value_len;
  uword b_left;
  http_field_line_t *header;
  hpack_error_t rv;

  p = src;
  b = dst;
  b_left = dst_len;
  control_data->parsed_bitmap = 0;
  control_data->headers_len = 0;
  control_data->content_len_header_index = ~0;

  while (p != end)
    {
      never_index = 0;
      name = b;
      rv = decoder_fn (&p, end, &b, &b_left, &name_len, &value_len, decoder_ctx, &never_index);
      if (rv)
	{
	  HTTP_DBG (1, "decode_header: %d", rv);
	  return rv;
	}
      value = name + name_len;

      /* pseudo header */
      if (name[0] == ':')
	{
	  /* all pseudo-headers must be before regular headers */
	  if (regular_header_parsed)
	    {
	      HTTP_DBG (1, "pseudo-headers after regular header");
	      return HPACK_ERROR_PROTOCOL;
	    }
	  rv = hpack_parse_resp_pseudo_header (name, name_len, value,
					       value_len, control_data);
	  if (rv)
	    {
	      HTTP_DBG (1, "hpack_parse_resp_pseudo_header: %d", rv);
	      return rv;
	    }
	  continue;
	}
      else
	{
	  if (!hpack_header_name_is_valid (name, name_len))
	    return HPACK_ERROR_PROTOCOL;
	  if (!regular_header_parsed)
	    {
	      regular_header_parsed = 1;
	      control_data->headers = name;
	    }
	}
      if (!hpack_header_value_is_valid (value, value_len))
	return HPACK_ERROR_PROTOCOL;
      vec_add2 (*headers, header, 1);
      HTTP_DBG (2, "%U: %U", format_http_bytes, name, name_len,
		format_http_bytes, value, value_len);
      header->name_offset = name - control_data->headers;
      header->name_len = name_len;
      header->value_offset = value - control_data->headers;
      header->value_len = value_len;
      header->flags = never_index ? HTTP_FIELD_LINE_F_NEVER_INDEX : 0;
      control_data->headers_len += name_len;
      control_data->headers_len += value_len;
      if (regular_header_parsed)
	{
	  rv = hpack_preprocess_header (
	    name, name_len, value, value_len, header - *headers,
	    &control_data->content_len_header_index);
	  if (rv)
	    {
	      HTTP_DBG (1, "connection-specific header present");
	      return rv;
	    }
	}
    }
  control_data->control_data_len = dst_len - b_left;
  return HPACK_ERROR_NONE;
}

#endif /* SRC_PLUGINS_HTTP_HPACK_INLINES_H_ */
