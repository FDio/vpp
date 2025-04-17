/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/string.h>
#include <http/http2/frame.h>

#define MAX_U24 0xFFFFFF

static_always_inline u8 *
http2_decode_u24 (u8 *src, u32 *value)
{
  *value = 0;
  *value = (u32) (src[0] << 16) | (u32) (src[1] << 8) | (u32) src[2];
  return src + 3;
}

static_always_inline u8 *
http2_encode_u24 (u8 *dst, u32 value)
{
  ASSERT (value <= MAX_U24);
  *dst++ = (value >> 16) & 0xFF;
  *dst++ = (value >> 8) & 0xFF;
  *dst++ = value & 0xFF;
  return dst;
}

/*
 * RFC9113 section 4.1
 *
 * HTTP Frame {
 *   Length (24),
 *   Type (8),
 *   Flags (8),
 *   Reserved (1),
 *   Stream Identifier (31),
 *   Frame Payload (..),
 * }
 */

__clib_export void
http2_frame_header_read (u8 *src, http2_frame_header_t *fh)
{
  u32 *stream_id;
  src = http2_decode_u24 (src, &fh->length);
  fh->type = *src++;
  fh->flags = *src++;
  stream_id = (u32 *) src;
  fh->stream_id = clib_net_to_host_u32 (*stream_id) & 0x7FFFFFFF;
}

static void
http2_frame_header_write (http2_frame_header_t *fh, u8 *dst)
{
  u32 stream_id;

  dst = http2_encode_u24 (dst, fh->length);
  *dst++ = fh->type;
  *dst++ = fh->flags;
  stream_id = clib_host_to_net_u32 (fh->stream_id);
  clib_memcpy_fast (dst, &stream_id, sizeof (stream_id));
}

__clib_export http2_error_t
http2_frame_read_settings (http2_conn_settings_t *settings, u8 *payload,
			   u32 payload_len)
{
  http2_settings_entry_t *entry;
  u32 value;

  while (payload_len >= sizeof (*entry))
    {
      entry = (http2_settings_entry_t *) payload;
      switch (clib_net_to_host_u16 (entry->identifier))
	{
#define _(v, label, member, min, max, default_value, err_code)                \
  case HTTP2_SETTINGS_##label:                                                \
    value = clib_net_to_host_u32 (entry->value);                              \
    if (!(value >= min && value <= max))                                      \
      return err_code;                                                        \
    settings->member = value;                                                 \
    break;
	  foreach_http2_settings
#undef _
	    /* ignore unknown or unsupported identifier */
	    default : break;
	}
      payload_len -= sizeof (*entry);
      payload += sizeof (*entry);
    }

  if (payload_len != 0)
    return HTTP2_ERROR_FRAME_SIZE_ERROR;

  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_settings_ack (u8 **dst)
{
  http2_frame_header_t fh = { .flags = HTTP2_FRAME_FLAG_ACK,
			      .type = HTTP2_FRAME_TYPE_SETTINGS };
  u8 *p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);
}

__clib_export void
http2_frame_write_settings (http2_settings_entry_t *settings, u8 **dst)
{
  u8 *p;
  u32 length;
  http2_settings_entry_t *entry, e;

  ASSERT (settings);
  ASSERT (vec_len (settings) > 0);

  length = vec_len (settings) * sizeof (*entry);
  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_SETTINGS,
			      .length = length };
  p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);

  vec_add2 (*dst, p, length);
  vec_foreach (entry, settings)
    {
      e.identifier = clib_host_to_net_u16 (entry->identifier);
      e.value = clib_host_to_net_u32 (entry->value);
      clib_memcpy_fast (p, &e, sizeof (e));
      p += sizeof (e);
    }
}

#define WINDOW_UPDATE_LENGTH 4

__clib_export http2_error_t
http2_frame_read_window_update (u32 *increment, u8 *payload, u32 payload_len)
{
  u32 *value;

  if (payload_len != WINDOW_UPDATE_LENGTH)
    return HTTP2_ERROR_FRAME_SIZE_ERROR;

  value = (u32 *) payload;

  if (*value == 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  *increment = clib_net_to_host_u32 (*value) & 0x7FFFFFFF;
  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_window_update (u32 increment, u32 stream_id, u8 **dst)
{
  u8 *p;
  u32 value;

  ASSERT (increment > 0 && increment <= 0x7FFFFFFF);

  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_WINDOW_UPDATE,
			      .length = WINDOW_UPDATE_LENGTH,
			      .stream_id = stream_id };
  p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);

  vec_add2 (*dst, p, WINDOW_UPDATE_LENGTH);
  value = clib_host_to_net_u32 (increment);
  clib_memcpy_fast (p, &value, WINDOW_UPDATE_LENGTH);
}

#define RST_STREAM_LENGTH 4

__clib_export http2_error_t
http2_frame_read_rst_stream (u32 *error_code, u8 *payload, u32 payload_len)
{
  u32 *value;

  if (payload_len != RST_STREAM_LENGTH)
    return HTTP2_ERROR_FRAME_SIZE_ERROR;

  value = (u32 *) payload;

  *error_code = clib_net_to_host_u32 (*value);
  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_rst_stream (http2_error_t error_code, u32 stream_id,
			      u8 **dst)
{
  u8 *p;
  u32 value;

  ASSERT (stream_id > 0 && stream_id <= 0x7FFFFFFF);

  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_RST_STREAM,
			      .length = RST_STREAM_LENGTH,
			      .stream_id = stream_id };
  p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);

  vec_add2 (*dst, p, RST_STREAM_LENGTH);
  value = clib_host_to_net_u32 ((u32) error_code);
  clib_memcpy_fast (p, &value, RST_STREAM_LENGTH);
}

#define GOAWAY_MIN_SIZE 8

__clib_export http2_error_t
http2_frame_read_goaway (u32 *error_code, u32 *last_stream_id, u8 *payload,
			 u32 payload_len)
{
  u32 *value;

  if (payload_len < GOAWAY_MIN_SIZE)
    return HTTP2_ERROR_FRAME_SIZE_ERROR;

  value = (u32 *) payload;
  *last_stream_id = clib_net_to_host_u32 (*value) & 0x7FFFFFFF;
  payload += 4;

  value = (u32 *) payload;
  *error_code = clib_net_to_host_u32 (*value);

  /* TODO: Additional Debug Data */
  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_goaway (http2_error_t error_code, u32 last_stream_id,
			  u8 **dst)
{
  u8 *p;
  u32 value;

  ASSERT (last_stream_id <= 0x7FFFFFFF);

  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_GOAWAY,
			      .length = GOAWAY_MIN_SIZE };
  p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);

  vec_add2 (*dst, p, GOAWAY_MIN_SIZE);
  value = clib_host_to_net_u32 (last_stream_id);
  clib_memcpy_fast (p, &value, 4);
  p += 4;
  value = clib_host_to_net_u32 ((u32) error_code);
  clib_memcpy_fast (p, &value, 4);
  /* TODO: Additional Debug Data */
}

void
http2_frame_write_ping (u8 is_resp, u8 *payload, u8 **dst)
{
  u8 *p;
  http2_frame_header_t fh = {
    .type = HTTP2_FRAME_TYPE_PING,
    .length = HTTP2_PING_PAYLOAD_LEN,
    .flags = is_resp ? HTTP2_FRAME_FLAG_ACK : 0,
  };

  p = http2_frame_header_alloc (dst);
  http2_frame_header_write (&fh, p);
  vec_add2 (*dst, p, HTTP2_PING_PAYLOAD_LEN);
  clib_memcpy_fast (p, payload, HTTP2_PING_PAYLOAD_LEN);
}

#define PRIORITY_DATA_LEN 5

__clib_export http2_error_t
http2_frame_read_headers (u8 **headers, u32 *headers_len, u8 *payload,
			  u32 payload_len, u8 flags)
{
  *headers_len = payload_len;

  if (flags & HTTP2_FRAME_FLAG_PADED)
    {
      u8 pad_len = *payload++;
      if ((u32) pad_len >= payload_len)
	return HTTP2_ERROR_PROTOCOL_ERROR;
      *headers_len -= (pad_len + 1);
    }

  if (flags & HTTP2_FRAME_FLAG_PRIORITY)
    {
      if (*headers_len <= PRIORITY_DATA_LEN)
	return HTTP2_ERROR_FRAME_SIZE_ERROR;
      /* just skip, priority scheme defined in RFC7540 is deprecated */
      *headers_len -= PRIORITY_DATA_LEN;
      payload += PRIORITY_DATA_LEN;
    }

  *headers = payload;

  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_headers_header (u32 headers_len, u32 stream_id, u8 flags,
				  u8 *dst)
{
  ASSERT (stream_id > 0 && stream_id <= 0x7FFFFFFF);

  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_HEADERS,
			      .length = headers_len,
			      .flags = flags,
			      .stream_id = stream_id };
  http2_frame_header_write (&fh, dst);
}

__clib_export http2_error_t
http2_frame_read_data (u8 **data, u32 *data_len, u8 *payload, u32 payload_len,
		       u8 flags)
{
  *data_len = payload_len;

  if (flags & HTTP2_FRAME_FLAG_PADED)
    {
      u8 pad_len = *payload++;
      if ((u32) pad_len >= payload_len)
	return HTTP2_ERROR_PROTOCOL_ERROR;
      *data_len -= (pad_len + 1);
    }

  *data = payload;
  return HTTP2_ERROR_NO_ERROR;
}

__clib_export void
http2_frame_write_data_header (u32 data_len, u32 stream_id, u8 flags, u8 *dst)
{
  ASSERT (stream_id > 0 && stream_id <= 0x7FFFFFFF);

  http2_frame_header_t fh = { .type = HTTP2_FRAME_TYPE_DATA,
			      .length = data_len,
			      .flags = flags,
			      .stream_id = stream_id };
  http2_frame_header_write (&fh, dst);
}
