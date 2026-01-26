/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/frame.h>

/*
 * RFC9114 section 7.1
 *
 * HTTP/3 Frame Format {
 *   Type (i),
 *   Length (i),
 *   Frame Payload (..),
 * }
 */

__clib_export http3_error_t
http3_frame_header_read (u8 *src, u64 src_len, http3_stream_type_t stream_type,
			 http3_frame_header_t *fh)
{
  u8 *p = src;
  u8 *end = src + src_len;

  /* parse frame header */
  fh->type = http_decode_varint (&p, end);
  if (fh->type == HTTP_INVALID_VARINT || p == end)
    return HTTP3_ERROR_INCOMPLETE;
  fh->length = http_decode_varint (&p, end);
  if (fh->length == HTTP_INVALID_VARINT)
    return HTTP3_ERROR_INCOMPLETE;
  fh->payload = p;
  fh->header_len = (u8) (p - src);

  /* validate if received on correct stream type */
  switch (fh->type)
    {
#define _(value, label, ctrl_stream, req_stream, push_stream)                 \
  case HTTP3_FRAME_TYPE_##label:                                              \
    {                                                                         \
      switch (stream_type)                                                    \
	{                                                                     \
	case HTTP3_STREAM_TYPE_CONTROL:                                       \
	  if (!ctrl_stream)                                                   \
	    return HTTP3_ERROR_FRAME_UNEXPECTED;                              \
	  break;                                                              \
	case HTTP3_STREAM_TYPE_PUSH:                                          \
	  if (!push_stream)                                                   \
	    return HTTP3_ERROR_FRAME_UNEXPECTED;                              \
	  break;                                                              \
	case HTTP3_STREAM_TYPE_REQUEST:                                       \
	  if (!req_stream)                                                    \
	    return HTTP3_ERROR_FRAME_UNEXPECTED;                              \
	  break;                                                              \
	default:                                                              \
	  ASSERT (0);                                                         \
	  break;                                                              \
	}                                                                     \
    }                                                                         \
    break;
    foreach_http3_frame_type
#undef _
      /* clang-format off */
    /* reserved frame types */
    case 0x02:
    case 0x06:
    case 0x08:
    case 0x09:
      return HTTP3_ERROR_FRAME_UNEXPECTED;
    default :
      /* ignore unknown frame type */
      break;
      /* clang-format on */
    }
  return HTTP3_ERROR_NO_ERROR;
}

__clib_export http3_error_t
http3_frame_goaway_read (u8 *payload, u64 len, u64 *stream_or_push_id)
{
  u8 *p = payload;
  u8 *end = payload + len;

  if (len == 0)
    return HTTP3_ERROR_FRAME_ERROR;

  *stream_or_push_id = http_decode_varint (&p, end);
  if (*stream_or_push_id == HTTP_INVALID_VARINT || p != end)
    return HTTP3_ERROR_FRAME_ERROR;

  return HTTP3_ERROR_NO_ERROR;
}

__clib_export void
http3_frame_goaway_write (u64 stream_or_push_id, u8 **dst)
{
  u8 *p;
  u8 payload_len = http_varint_len (stream_or_push_id);

  vec_add2 (*dst, p, 2 + payload_len);
  *p++ = (u8) HTTP3_FRAME_TYPE_GOAWAY;
  *p++ = payload_len;
  p = http_encode_varint (p, stream_or_push_id);
}

__clib_export http3_error_t
http3_frame_settings_read (u8 *payload, u64 len,
			   http3_conn_settings_t *settings)
{
  u8 *p = payload;
  u8 *end = payload + len;
  u64 identifier, value;

  if (len == 0)
    return HTTP3_ERROR_NO_ERROR;

  while (p != end)
    {
      identifier = http_decode_varint (&p, end);
      if (identifier == HTTP_INVALID_VARINT || p == end)
	return HTTP3_ERROR_FRAME_ERROR;
      value = http_decode_varint (&p, end);
      if (value == HTTP_INVALID_VARINT)
	return HTTP3_ERROR_FRAME_ERROR;
      switch (identifier)
	{
#define _(v, label, member, min, max, default_value, server, client)          \
  case HTTP3_SETTINGS_##label:                                                \
    if (!(value >= min && value <= max))                                      \
      return HTTP3_ERROR_SETTINGS_ERROR;                                      \
    settings->member = value;                                                 \
    break;
	  foreach_http3_settings
#undef _
	    default :
	      /* ignore unknown or unsupported identifier */
	      break;
	}
    }

  return HTTP3_ERROR_NO_ERROR;
}

__clib_export void
http3_frame_settings_write (http3_conn_settings_t *settings, u8 **dst)
{
  u64 payload_len = 0;
  u8 *p;

#define _(v, label, member, min, max, default_value, server, client)          \
  if (settings->member != default_value)                                      \
    payload_len += http_varint_len (settings->member) +                       \
		   http_varint_len (HTTP3_SETTINGS_##label);
  foreach_http3_settings
#undef _

    vec_add2 (*dst, p, 1 + http_varint_len (payload_len) + payload_len);
  *p++ = (u8) HTTP3_FRAME_TYPE_SETTINGS;
  p = http_encode_varint (p, payload_len);

  if (payload_len == 0)
    return;

#define _(v, label, member, min, max, default_value, server, client)          \
  if (settings->member != default_value)                                      \
    {                                                                         \
      p = http_encode_varint (p, HTTP3_SETTINGS_##label);                     \
      p = http_encode_varint (p, settings->member);                           \
    }
  foreach_http3_settings
#undef _
}
