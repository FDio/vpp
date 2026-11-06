/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <http/http.h>
#include <http/http1/chunked.h>

typedef enum http1_chunked_state_ : u8
{
  CHUNK_SIZE_FIRST,
  CHUNK_SIZE,
  CHUNK_SIZE_BWS,
  CHUNK_EXT_NAME_FIRST,
  CHUNK_EXT_NAME,
  CHUNK_EXT_NAME_BWS,
  CHUNK_EXT_VALUE_FIRST,
  CHUNK_EXT_TOKEN,
  CHUNK_EXT_QUOTED,
  CHUNK_EXT_ESCAPE,
  CHUNK_EXT_QUOTED_END,
  CHUNK_EXT_BWS,
  CHUNK_SIZE_LF,
  CHUNK_DATA,
  CHUNK_DATA_CR,
  CHUNK_DATA_LF,
  CHUNK_TRAILER_FIRST,
  CHUNK_TRAILER_NAME,
  CHUNK_TRAILER_VALUE,
  CHUNK_TRAILER_LF,
  CHUNK_END_LF,
  CHUNK_DONE,
  CHUNK_INVALID,
  CHUNK_TOO_LARGE,
} http1_chunked_state_t;

static_always_inline int
http1_chunked_hex_digit (u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static_always_inline u8
http1_chunked_is_field_char (u8 c)
{
  return c == '\t' || (c >= 0x20 && c != 0x7f);
}

__clib_export http1_chunked_result_t
http1_chunked_decode (http1_chunked_decoder_t *decoder, const u8 *src, u32 len, u32 *consumed,
		      u32 *data_len)
{
  http1_chunked_result_t result = HTTP1_CHUNKED_MORE;
  u32 offset = 0, limit;
  int digit;
  u8 c;

  *data_len = 0;
  while (1)
    {
      if (decoder->state == CHUNK_DONE)
	{
	  result = HTTP1_CHUNKED_DONE;
	  break;
	}
      if (decoder->state == CHUNK_INVALID)
	{
	  result = HTTP1_CHUNKED_INVALID;
	  break;
	}
      if (decoder->state == CHUNK_TOO_LARGE)
	{
	  result = HTTP1_CHUNKED_TOO_LARGE;
	  break;
	}
      if (decoder->state == CHUNK_DATA)
	{
	  if (!decoder->chunk_bytes_left)
	    decoder->state = CHUNK_DATA_CR;
	  else if (offset < len)
	    {
	      *data_len = clib_min (decoder->chunk_bytes_left, len - offset);
	      result = HTTP1_CHUNKED_DATA;
	      break;
	    }
	}
      if (offset == len)
	break;

      limit = decoder->state >= CHUNK_TRAILER_FIRST ? HTTP1_CHUNKED_MAX_TRAILER_SIZE :
						      HTTP1_CHUNKED_MAX_LINE_SIZE;
      if (decoder->syntax_bytes == limit)
	{
	  decoder->state = CHUNK_TOO_LARGE;
	  result = HTTP1_CHUNKED_TOO_LARGE;
	  break;
	}
      decoder->syntax_bytes++;
      c = src[offset];
      switch (decoder->state)
	{
	case CHUNK_SIZE_FIRST:
	  digit = http1_chunked_hex_digit (c);
	  if (digit < 0)
	    goto invalid;
	  decoder->chunk_bytes_left = digit;
	  decoder->state = CHUNK_SIZE;
	  break;
	case CHUNK_SIZE:
	  digit = http1_chunked_hex_digit (c);
	  if (digit >= 0)
	    {
	      if (decoder->chunk_bytes_left > (CLIB_U64_MAX - digit) / 16)
		goto invalid;
	      decoder->chunk_bytes_left = decoder->chunk_bytes_left * 16 + digit;
	    }
	  else if (c == ';')
	    decoder->state = CHUNK_EXT_NAME_FIRST;
	  else if (c == ' ' || c == '\t')
	    decoder->state = CHUNK_SIZE_BWS;
	  else if (c == '\r')
	    decoder->state = CHUNK_SIZE_LF;
	  else
	    goto invalid;
	  break;
	case CHUNK_SIZE_BWS:
	case CHUNK_EXT_BWS:
	  if (c == ';')
	    decoder->state = CHUNK_EXT_NAME_FIRST;
	  else if (c != ' ' && c != '\t')
	    goto invalid;
	  break;
	case CHUNK_EXT_NAME_FIRST:
	  if (http_token_char_is_valid (c))
	    decoder->state = CHUNK_EXT_NAME;
	  else if (c != ' ' && c != '\t')
	    goto invalid;
	  break;
	case CHUNK_EXT_NAME:
	  if (http_token_char_is_valid (c))
	    break;
	  if (c == '=')
	    decoder->state = CHUNK_EXT_VALUE_FIRST;
	  else if (c == ' ' || c == '\t')
	    decoder->state = CHUNK_EXT_NAME_BWS;
	  else if (c == ';')
	    decoder->state = CHUNK_EXT_NAME_FIRST;
	  else if (c == '\r')
	    decoder->state = CHUNK_SIZE_LF;
	  else
	    goto invalid;
	  break;
	case CHUNK_EXT_NAME_BWS:
	  if (c == '=')
	    decoder->state = CHUNK_EXT_VALUE_FIRST;
	  else if (c == ';')
	    decoder->state = CHUNK_EXT_NAME_FIRST;
	  else if (c != ' ' && c != '\t')
	    goto invalid;
	  break;
	case CHUNK_EXT_VALUE_FIRST:
	  if (http_token_char_is_valid (c))
	    decoder->state = CHUNK_EXT_TOKEN;
	  else if (c == '"')
	    decoder->state = CHUNK_EXT_QUOTED;
	  else if (c != ' ' && c != '\t')
	    goto invalid;
	  break;
	case CHUNK_EXT_TOKEN:
	  if (http_token_char_is_valid (c))
	    break;
	  __attribute__ ((fallthrough));
	case CHUNK_EXT_QUOTED_END:
	  if (c == ';')
	    decoder->state = CHUNK_EXT_NAME_FIRST;
	  else if (c == ' ' || c == '\t')
	    decoder->state = CHUNK_EXT_BWS;
	  else if (c == '\r')
	    decoder->state = CHUNK_SIZE_LF;
	  else
	    goto invalid;
	  break;
	case CHUNK_EXT_QUOTED:
	  if (c == '"')
	    decoder->state = CHUNK_EXT_QUOTED_END;
	  else if (c == '\\')
	    decoder->state = CHUNK_EXT_ESCAPE;
	  else if (!http1_chunked_is_field_char (c))
	    goto invalid;
	  break;
	case CHUNK_EXT_ESCAPE:
	  if (!http1_chunked_is_field_char (c))
	    goto invalid;
	  decoder->state = CHUNK_EXT_QUOTED;
	  break;
	case CHUNK_SIZE_LF:
	  if (c != '\n')
	    goto invalid;
	  decoder->syntax_bytes = 0;
	  decoder->state = decoder->chunk_bytes_left ? CHUNK_DATA : CHUNK_TRAILER_FIRST;
	  break;
	case CHUNK_DATA_CR:
	  if (c != '\r')
	    goto invalid;
	  decoder->state = CHUNK_DATA_LF;
	  break;
	case CHUNK_DATA_LF:
	  if (c != '\n')
	    goto invalid;
	  decoder->syntax_bytes = 0;
	  decoder->state = CHUNK_SIZE_FIRST;
	  break;
	case CHUNK_TRAILER_FIRST:
	  if (c == '\r')
	    decoder->state = CHUNK_END_LF;
	  else if (http_token_char_is_valid (c))
	    decoder->state = CHUNK_TRAILER_NAME;
	  else
	    goto invalid;
	  break;
	case CHUNK_TRAILER_NAME:
	  if (c == ':')
	    decoder->state = CHUNK_TRAILER_VALUE;
	  else if (!http_token_char_is_valid (c))
	    goto invalid;
	  break;
	case CHUNK_TRAILER_VALUE:
	  if (c == '\r')
	    decoder->state = CHUNK_TRAILER_LF;
	  else if (!http1_chunked_is_field_char (c))
	    goto invalid;
	  break;
	case CHUNK_TRAILER_LF:
	  if (c != '\n')
	    goto invalid;
	  decoder->state = CHUNK_TRAILER_FIRST;
	  break;
	case CHUNK_END_LF:
	  if (c != '\n')
	    goto invalid;
	  decoder->state = CHUNK_DONE;
	  break;
	default:
	  goto invalid;
	}
      offset++;
    }
  goto done;

invalid:
  decoder->state = CHUNK_INVALID;
  result = HTTP1_CHUNKED_INVALID;
done:
  *consumed = offset;
  return result;
}
