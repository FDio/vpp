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
http2_frame_header_write (http2_frame_header_t *fh, u8 **dst)
{
  u32 stream_id;
  u8 *d, *p;

  d = *dst;
  vec_add2 (d, p, HTTP2_FRAME_HEADER_SIZE);
  p = http2_encode_u24 (p, fh->length);
  *p++ = fh->type;
  *p++ = fh->flags;
  stream_id = clib_host_to_net_u32 (fh->stream_id);
  clib_memcpy_fast (p, &stream_id, sizeof (stream_id));
  *dst = d;
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
  http2_frame_header_write (&fh, dst);
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
  http2_frame_header_write (&fh, dst);

  vec_add2 (*dst, p, length);
  vec_foreach (entry, settings)
    {
      e.identifier = clib_host_to_net_u16 (entry->identifier);
      e.value = clib_host_to_net_u32 (entry->value);
      clib_memcpy_fast (p, &e, sizeof (e));
      p += sizeof (e);
    }
}
