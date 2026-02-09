/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/ring.h>
#include <http/http2/hpack.h>
#include <http/http_status_codes.h>
#include <http/http_private.h>
#include <http/http2/hpack_inlines.h>

#define HPACK_STATIC_TABLE_SIZE 61

typedef struct
{
  char *name;
  uword name_len;
  char *value;
  uword value_len;
} hpack_static_table_entry_t;

#define name_val_token_lit(name, value)                                       \
  (name), sizeof (name) - 1, (value), sizeof (value) - 1

static hpack_static_table_entry_t
  hpack_static_table[HPACK_STATIC_TABLE_SIZE] = {
    { name_val_token_lit (":authority", "") },
    { name_val_token_lit (":method", "GET") },
    { name_val_token_lit (":method", "POST") },
    { name_val_token_lit (":path", "/") },
    { name_val_token_lit (":path", "/index.html") },
    { name_val_token_lit (":scheme", "http") },
    { name_val_token_lit (":scheme", "https") },
    { name_val_token_lit (":status", "200") },
    { name_val_token_lit (":status", "204") },
    { name_val_token_lit (":status", "206") },
    { name_val_token_lit (":status", "304") },
    { name_val_token_lit (":status", "400") },
    { name_val_token_lit (":status", "404") },
    { name_val_token_lit (":status", "500") },
    { name_val_token_lit ("accept-charset", "") },
    { name_val_token_lit ("accept-encoding", "gzip, deflate") },
    { name_val_token_lit ("accept-language", "") },
    { name_val_token_lit ("accept-ranges", "") },
    { name_val_token_lit ("accept", "") },
    { name_val_token_lit ("access-control-allow-origin", "") },
    { name_val_token_lit ("age", "") },
    { name_val_token_lit ("allow", "") },
    { name_val_token_lit ("authorization", "") },
    { name_val_token_lit ("cache-control", "") },
    { name_val_token_lit ("content-disposition", "") },
    { name_val_token_lit ("content-encoding", "") },
    { name_val_token_lit ("content-language", "") },
    { name_val_token_lit ("content-length", "") },
    { name_val_token_lit ("content-location", "") },
    { name_val_token_lit ("content-range", "") },
    { name_val_token_lit ("content-type", "") },
    { name_val_token_lit ("cookie", "") },
    { name_val_token_lit ("date", "") },
    { name_val_token_lit ("etag", "") },
    { name_val_token_lit ("etag", "") },
    { name_val_token_lit ("expires", "") },
    { name_val_token_lit ("from", "") },
    { name_val_token_lit ("host", "") },
    { name_val_token_lit ("if-match", "") },
    { name_val_token_lit ("if-modified-since", "") },
    { name_val_token_lit ("if-none-match", "") },
    { name_val_token_lit ("if-range", "") },
    { name_val_token_lit ("if-unmodified-since", "") },
    { name_val_token_lit ("last-modified", "") },
    { name_val_token_lit ("link", "") },
    { name_val_token_lit ("location", "") },
    { name_val_token_lit ("max-forwards", "") },
    { name_val_token_lit ("proxy-authenticate", "") },
    { name_val_token_lit ("proxy-authorization", "") },
    { name_val_token_lit ("range", "") },
    { name_val_token_lit ("referer", "") },
    { name_val_token_lit ("refresh", "") },
    { name_val_token_lit ("retry-after", "") },
    { name_val_token_lit ("server", "") },
    { name_val_token_lit ("set-cookie", "") },
    { name_val_token_lit ("strict-transport-security", "") },
    { name_val_token_lit ("transfer-encoding", "") },
    { name_val_token_lit ("user-agent", "") },
    { name_val_token_lit ("vary", "") },
    { name_val_token_lit ("via", "") },
    { name_val_token_lit ("www-authenticate", "") },
  };

static http_token_t http_methods[] = {
#define _(s, str) { http_token_lit (str) },
  foreach_http_method
#undef _
};

#define http_method_token(e) http_methods[e].base, http_methods[e].len

__clib_export hpack_error_t
hpack_decode_string (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u8 *p, is_huffman;
  uword len;

  if (*src == end)
    return HPACK_ERROR_COMPRESSION;

  p = *src;
  /* H flag in first bit */
  is_huffman = *p & 0x80;

  /* length is integer with 7 bit prefix */
  len = hpack_decode_int (&p, end, 7);
  if (PREDICT_FALSE (len == HPACK_INVALID_INT))
    return HPACK_ERROR_COMPRESSION;

  /* do we have everything? */
  if (len > (end - p))
    return HPACK_ERROR_COMPRESSION;

  if (is_huffman)
    {
      *src = (p + len);
      return hpack_decode_huffman (&p, p + len, buf, buf_len);
    }
  else
    {
      /* enough space? */
      if (len > *buf_len)
	return HPACK_ERROR_UNKNOWN;

      clib_memcpy (*buf, p, len);
      *buf_len -= len;
      *buf += len;
      *src = (p + len);
      return HPACK_ERROR_NONE;
    }
}

__clib_export u8 *
hpack_encode_string (u8 *dst, const u8 *value, uword value_len)
{
  uword huff_len;

  huff_len = hpack_huffman_encoded_len (value, value_len);
  /* raw bytes might take fewer bytes */
  if (huff_len >= value_len)
    {
      *dst = 0; /* clear H flag */
      dst = hpack_encode_int (dst, value_len, 7);
      clib_memcpy (dst, value, value_len);
      return dst + value_len;
    }

  *dst = 0x80; /* set H flag */
  dst = hpack_encode_int (dst, huff_len, 7);
  dst = hpack_encode_huffman (dst, value, value_len);

  return dst;
}

__clib_export void
hpack_dynamic_table_init (hpack_dynamic_table_t *table, u32 max_size)
{
  table->max_size = max_size;
  table->size = max_size;
  table->used = 0;
  clib_ring_new (table->entries,
		 max_size / HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD);
}

__clib_export void
hpack_dynamic_table_free (hpack_dynamic_table_t *table)
{
  hpack_dynamic_table_entry_t *e;

  while ((e = clib_ring_deq (table->entries)) != 0)
    vec_free (e->buf);

  clib_ring_free (table->entries);
}

#define hpack_dynamic_table_entry_value_base(e)                               \
  ((char *) ((e)->buf + (e)->name_len))
#define hpack_dynamic_table_entry_value_len(e)                                \
  (vec_len ((e)->buf) - (e)->name_len)

always_inline hpack_dynamic_table_entry_t *
hpack_dynamic_table_get (hpack_dynamic_table_t *table, uword index)
{
  if (index > clib_ring_n_enq (table->entries))
    return 0;

  hpack_dynamic_table_entry_t *first = clib_ring_get_first (table->entries);
  u32 first_index = first - table->entries;
  u32 entry_index =
    (first_index + (clib_ring_n_enq (table->entries) - 1 - (u32) index)) %
    vec_len (table->entries);
  return table->entries + entry_index;
}

__clib_export u8 *
format_hpack_dynamic_table (u8 *s, va_list *args)
{
  hpack_dynamic_table_t *table = va_arg (*args, hpack_dynamic_table_t *);
  u32 i;
  hpack_dynamic_table_entry_t *e;

  s = format (s, "HPACK dynamic table:\n");
  for (i = 0; i < clib_ring_n_enq (table->entries); i++)
    {
      e = hpack_dynamic_table_get (table, i);
      s = format (s, "\t[%u] %U: %U\n", i, format_http_bytes, e->buf,
		  e->name_len, format_http_bytes,
		  hpack_dynamic_table_entry_value_base (e),
		  hpack_dynamic_table_entry_value_len (e));
    }
  return s;
}

static inline void
hpack_dynamic_table_evict_one (hpack_dynamic_table_t *table)
{
  u32 entry_size;
  hpack_dynamic_table_entry_t *e;

  e = clib_ring_deq (table->entries);
  ASSERT (e);
  HTTP_DBG (2, "%U: %U", format_http_bytes, e->buf, e->name_len,
	    format_http_bytes, hpack_dynamic_table_entry_value_base (e),
	    hpack_dynamic_table_entry_value_len (e));
  entry_size = vec_len (e->buf) + HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD;
  table->used -= entry_size;
  vec_reset_length (e->buf);
}

static void
hpack_dynamic_table_add (hpack_dynamic_table_t *table, http_token_t *name,
			 http_token_t *value)
{
  u32 entry_size;
  hpack_dynamic_table_entry_t *e;

  entry_size = name->len + value->len + HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD;

  /* make space or evict all */
  while (clib_ring_n_enq (table->entries) &&
	 (table->used + entry_size > table->size))
    hpack_dynamic_table_evict_one (table);

  /* attempt to add entry larger than the maximum size is not error */
  if (entry_size > table->size)
    return;

  e = clib_ring_enq (table->entries);
  ASSERT (e);
  vec_validate (e->buf, name->len + value->len - 1);
  clib_memcpy (e->buf, name->base, name->len);
  clib_memcpy (e->buf + name->len, value->base, value->len);
  e->name_len = name->len;
  table->used += entry_size;

  HTTP_DBG (2, "%U: %U", format_http_bytes, e->buf, e->name_len,
	    format_http_bytes, hpack_dynamic_table_entry_value_base (e),
	    hpack_dynamic_table_entry_value_len (e));
}

static hpack_error_t
hpack_get_table_entry (uword index, http_token_t *name, http_token_t *value,
		       u8 value_is_indexed, hpack_dynamic_table_t *dt)
{
  if (index <= HPACK_STATIC_TABLE_SIZE)
    {
      hpack_static_table_entry_t *e = &hpack_static_table[index - 1];
      name->base = e->name;
      name->len = e->name_len;
      if (value_is_indexed)
	{
	  value->base = e->value;
	  value->len = e->value_len;
	}
      HTTP_DBG (2, "[%llu] %U: %U", index, format_http_bytes, e->name,
		e->name_len, format_http_bytes, e->value, e->value_len);
      return HPACK_ERROR_NONE;
    }
  else
    {
      hpack_dynamic_table_entry_t *e =
	hpack_dynamic_table_get (dt, index - HPACK_STATIC_TABLE_SIZE - 1);
      if (PREDICT_FALSE (!e))
	{
	  HTTP_DBG (1, "index %llu not in dynamic table", index);
	  return HPACK_ERROR_COMPRESSION;
	}
      name->base = (char *) e->buf;
      name->len = e->name_len;
      value->base = hpack_dynamic_table_entry_value_base (e);
      value->len = hpack_dynamic_table_entry_value_len (e);
      HTTP_DBG (2, "[%llu] %U: %U", index, format_http_bytes, name->base,
		name->len, format_http_bytes, value->base, value->len);
      return HPACK_ERROR_NONE;
    }
}

__clib_export hpack_error_t
hpack_decode_header (u8 **src, u8 *end, u8 **buf, uword *buf_len, u32 *name_len, u32 *value_len,
		     void *decoder_ctx, u8 *never_index)
{
  hpack_dynamic_table_t *dt = (hpack_dynamic_table_t *) decoder_ctx;
  u8 *p;
  u8 value_is_indexed = 0, add_new_entry = 0;
  uword old_len, new_max, index = 0;
  http_token_t name, value;
  hpack_error_t rv;

  ASSERT (*src < end);
  p = *src;

  /* dynamic table size update */
  while ((*p & 0xE0) == 0x20)
    {
      new_max = hpack_decode_int (&p, end, 5);
      if (p == end || new_max > (uword) dt->max_size)
	{
	  HTTP_DBG (1, "invalid dynamic table size update");
	  return HPACK_ERROR_COMPRESSION;
	}
      while (clib_ring_n_enq (dt->entries) && new_max > dt->used)
	hpack_dynamic_table_evict_one (dt);
      dt->size = (u32) new_max;
    }

  if (*p & 0x80) /* indexed header field */
    {
      index = hpack_decode_int (&p, end, 7);
      /* index value of 0 is not used */
      if (index == 0 || index == HPACK_INVALID_INT)
	{
	  HTTP_DBG (1, "invalid index");
	  return HPACK_ERROR_COMPRESSION;
	}
      value_is_indexed = 1;
    }
  else if (*p > 0x40) /* incremental indexing - indexed name */
    {
      index = hpack_decode_int (&p, end, 6);
      /* index value of 0 is not used */
      if (index == 0 || index == HPACK_INVALID_INT)
	{
	  HTTP_DBG (1, "invalid index");
	  return HPACK_ERROR_COMPRESSION;
	}
      add_new_entry = 1;
    }
  else if (*p == 0x40) /* incremental indexing - new name */
    {
      add_new_entry = 1;
      p++;
    }
  else /* without indexing / never indexed */
    {
      *never_index = *p >> 4;
      if ((*p & 0x0F) == 0) /* new name */
	p++;
      else /* indexed name */
	{
	  index = hpack_decode_int (&p, end, 4);
	  /* index value of 0 is not used */
	  if (index == 0 || index == HPACK_INVALID_INT)
	    {
	      HTTP_DBG (1, "invalid index");
	      return HPACK_ERROR_COMPRESSION;
	    }
	}
    }

  if (index)
    {
      rv = hpack_get_table_entry (index, &name, &value, value_is_indexed, dt);
      if (rv)
	{
	  HTTP_DBG (1, "entry index %llu error", index);
	  return rv;
	}
      if (name.len > *buf_len)
	{
	  HTTP_DBG (1, "not enough space");
	  return HPACK_ERROR_UNKNOWN;
	}
      clib_memcpy (*buf, name.base, name.len);
      *buf_len -= name.len;
      *buf += name.len;
      *name_len = name.len;
      if (value_is_indexed)
	{
	  if (value.len > *buf_len)
	    {
	      HTTP_DBG (1, "not enough space");
	      return HPACK_ERROR_UNKNOWN;
	    }
	  clib_memcpy (*buf, value.base, value.len);
	  *buf_len -= value.len;
	  *buf += value.len;
	  *value_len = value.len;
	}
    }
  else
    {
      old_len = *buf_len;
      name.base = (char *) *buf;
      rv = hpack_decode_string (&p, end, buf, buf_len);
      if (rv)
	{
	  HTTP_DBG (1, "invalid header name");
	  return rv;
	}
      *name_len = old_len - *buf_len;
      name.len = *name_len;
    }

  if (!value_is_indexed)
    {
      old_len = *buf_len;
      value.base = (char *) *buf;
      rv = hpack_decode_string (&p, end, buf, buf_len);
      if (rv)
	{
	  HTTP_DBG (1, "invalid header value");
	  return rv;
	}
      *value_len = old_len - *buf_len;
      value.len = *value_len;
    }

  if (add_new_entry)
    hpack_dynamic_table_add (dt, &name, &value);

  *src = p;
  return HPACK_ERROR_NONE;
}

static const http2_error_t hpack_error_to_http2_error[] = {
  [HPACK_ERROR_NONE] = HTTP2_ERROR_NO_ERROR,
  [HPACK_ERROR_COMPRESSION] = HTTP2_ERROR_COMPRESSION_ERROR,
  [HPACK_ERROR_PROTOCOL] = HTTP2_ERROR_PROTOCOL_ERROR,
  [HPACK_ERROR_UNKNOWN] = HTTP2_ERROR_INTERNAL_ERROR,
};

__clib_export http2_error_t
hpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		     hpack_request_control_data_t *control_data,
		     http_field_line_t **headers,
		     hpack_dynamic_table_t *dynamic_table)
{
  hpack_error_t rv;
  rv = hpack_decode_request (src, src + src_len, dst, dst_len, control_data,
			     headers, (void *) dynamic_table,
			     hpack_decode_header);
  HTTP_DBG (3, "%U", format_hpack_dynamic_table, dynamic_table);
  return hpack_error_to_http2_error[rv];
}

__clib_export http2_error_t
hpack_parse_response (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_response_control_data_t *control_data,
		      http_field_line_t **headers,
		      hpack_dynamic_table_t *dynamic_table)
{
  hpack_error_t rv;
  rv = hpack_decode_response (src, src + src_len, dst, dst_len, control_data,
			      headers, (void *) dynamic_table,
			      hpack_decode_header);
  HTTP_DBG (3, "%U", format_hpack_dynamic_table, dynamic_table);
  return hpack_error_to_http2_error[rv];
}

static inline u8 *
hpack_encode_header (u8 *dst, http_header_name_t name, const u8 *value, u32 value_len,
		     u8 never_index)
{
  u8 *a, *b;
  u32 orig_len, actual_size;

  orig_len = vec_len (dst);
  const hpack_token_t *name_token = &hpack_headers[name];
  if (name_token->static_table_index)
    {
      /* static table index with 4 bit prefix is max 2 bytes */
      vec_add2 (dst, a, 2 + value_len + HPACK_ENCODED_INT_MAX_LEN);
      /* Literal Header Field without Indexing — Indexed Name */
      *a = never_index ? 0x10 : 0x00;
      b = hpack_encode_int (a, name_token->static_table_index, 4);
    }
  else
    {
      /* one extra byte for 4 bit prefix */
      vec_add2 (dst, a,
		name_token->len + value_len + HPACK_ENCODED_INT_MAX_LEN * 2 +
		  1);
      b = a;
      /* Literal Header Field without Indexing — New Name */
      *b++ = never_index ? 0x10 : 0x00;
      b = hpack_encode_string (b, (const u8 *) name_token->base,
			       name_token->len);
    }
  b = hpack_encode_string (b, value, value_len);

  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);
  return dst;
}

static inline u8 *
hpack_encode_custom_header (u8 *dst, const u8 *name, u32 name_len, const u8 *value, u32 value_len,
			    u8 never_index)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  orig_len = vec_len (dst);
  /* one extra byte for 4 bit prefix */
  vec_add2 (dst, a, name_len + value_len + HPACK_ENCODED_INT_MAX_LEN * 2 + 1);
  b = a;
  /* Literal Header Field without Indexing — New Name */
  *b++ = never_index ? 0x10 : 0x00;
  b = hpack_encode_string (b, name, name_len);
  b = hpack_encode_string (b, value, value_len);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);
  return dst;
}

#define encode_indexed_static_entry(_index)                                   \
  vec_add2 (dst, a, 1);                                                       \
  *a++ = 0x80 | _index;

static inline u8 *
hpack_encode_status_code (u8 *dst, http_status_code_t sc)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  switch (sc)
    {
    case HTTP_STATUS_OK:
      encode_indexed_static_entry (8);
      break;
    case HTTP_STATUS_NO_CONTENT:
      encode_indexed_static_entry (9);
      break;
    case HTTP_STATUS_PARTIAL_CONTENT:
      encode_indexed_static_entry (10);
      break;
    case HTTP_STATUS_NOT_MODIFIED:
      encode_indexed_static_entry (11);
      break;
    case HTTP_STATUS_BAD_REQUEST:
      encode_indexed_static_entry (12);
      break;
    case HTTP_STATUS_NOT_FOUND:
      encode_indexed_static_entry (13);
      break;
    case HTTP_STATUS_INTERNAL_ERROR:
      encode_indexed_static_entry (14);
      break;
    default:
      orig_len = vec_len (dst);
      vec_add2 (dst, a, 5);
      b = a;
      /* Literal Header Field without Indexing — Indexed Name */
      *b++ = 8;
      b = hpack_encode_string (b, (const u8 *) http_status_code_str[sc], 3);
      actual_size = b - a;
      vec_set_len (dst, orig_len + actual_size);
      break;
    }
  return dst;
}

static inline u8 *
hpack_encode_method (u8 *dst, http_req_method_t method)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  switch (method)
    {
    case HTTP_REQ_GET:
      encode_indexed_static_entry (2);
      break;
    case HTTP_REQ_POST:
      encode_indexed_static_entry (3);
      break;
    default:
      orig_len = vec_len (dst);
      vec_add2 (dst, a, 9);
      b = a;
      /* Literal Header Field without Indexing — Indexed Name */
      *b++ = 2;
      b = hpack_encode_string (b, (const u8 *) http_method_token (method));
      actual_size = b - a;
      vec_set_len (dst, orig_len + actual_size);
      break;
    }
  return dst;
}

static inline u8 *
hpack_encode_scheme (u8 *dst, http_url_scheme_t scheme)
{
  u8 *a;

  switch (scheme)
    {
    case HTTP_URL_SCHEME_HTTP:
      encode_indexed_static_entry (6);
      break;
    case HTTP_URL_SCHEME_HTTPS:
      encode_indexed_static_entry (7);
      break;
    default:
      ASSERT (0);
      break;
    }
  return dst;
}

static inline u8 *
hpack_encode_path (u8 *dst, u8 *path, u32 path_len)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  switch (path_len)
    {
    case 1:
      if (path[0] == '/')
	{
	  encode_indexed_static_entry (4);
	  return dst;
	}
      break;
    case 11:
      if (!memcmp (path, "/index.html", 11))
	{
	  encode_indexed_static_entry (5);
	  return dst;
	}
      break;
    default:
      break;
    }

  orig_len = vec_len (dst);
  vec_add2 (dst, a, path_len + 2);
  b = a;
  /* Literal Header Field without Indexing — Indexed Name */
  *b++ = 4;
  b = hpack_encode_string (b, path, path_len);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);

  return dst;
}

static inline u8 *
hpack_encode_authority (u8 *dst, u8 *authority, u32 authority_len)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  orig_len = vec_len (dst);
  vec_add2 (dst, a, authority_len + 2);
  b = a;
  /* Literal Header Field without Indexing — Indexed Name */
  *b++ = 1;
  b = hpack_encode_string (b, authority, authority_len);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);

  return dst;
}

static inline u8 *
hpack_encode_content_len (u8 *dst, u64 content_len)
{
  u8 digit_buffer[20];
  u8 *d = digit_buffer + sizeof (digit_buffer);
  u32 orig_len, actual_size;
  u8 *a, *b;

  orig_len = vec_len (dst);
  vec_add2 (dst, a, 3 + sizeof (digit_buffer));
  b = a;

  /* static table index 28 */
  *b++ = 0x0F;
  *b++ = 0x0D;
  do
    {
      *--d = '0' + content_len % 10;
      content_len /= 10;
    }
  while (content_len);

  b = hpack_encode_string (b, d, digit_buffer + sizeof (digit_buffer) - d);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);
  return dst;
}

__clib_export void
hpack_serialize_response (u8 *app_headers, u32 app_headers_len,
			  hpack_response_control_data_t *control_data,
			  u8 **dst)
{
  u8 *p, *end;

  p = *dst;

  /* status code must be first since it is pseudo-header */
  p = hpack_encode_status_code (p, control_data->sc);

  /* server name */
  p = hpack_encode_header (p, HTTP_HEADER_SERVER, control_data->server_name,
			   control_data->server_name_len, 0);

  /* date */
  p = hpack_encode_header (p, HTTP_HEADER_DATE, control_data->date, control_data->date_len, 0);

  /* content length if any */
  if (control_data->content_len != HPACK_ENCODER_SKIP_CONTENT_LEN)
    p = hpack_encode_content_len (p, control_data->content_len);

  if (!app_headers_len)
    {
      *dst = p;
      return;
    }

  end = app_headers + app_headers_len;
  while (app_headers < end)
    {
      /* custom header name? */
      http_app_header_name_t *name = (http_app_header_name_t *) app_headers;
      if (PREDICT_FALSE (name->flags & HTTP_FIELD_LINE_F_CUSTOM_NAME))
	{
	  http_custom_token_t *value;
	  app_headers += sizeof (http_custom_token_t) + name->len;
	  value = (http_custom_token_t *) app_headers;
	  app_headers += sizeof (http_custom_token_t) + value->len;
	  p = hpack_encode_custom_header (p, name->token, name->len, value->token, value->len,
					  name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  http_app_header_t *header;
	  header = (http_app_header_t *) app_headers;
	  app_headers += sizeof (http_app_header_t) + header->value.len;
	  p = hpack_encode_header (p, header->name.name, header->value.token, header->value.len,
				   name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
    }

  *dst = p;
}

__clib_export void
hpack_serialize_request (u8 *app_headers, u32 app_headers_len,
			 hpack_request_control_data_t *control_data, u8 **dst)
{
  u8 *p, *end;

  p = *dst;

  /* pseudo-headers must go first */
  p = hpack_encode_method (p, control_data->method);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED)
    p = hpack_encode_scheme (p, control_data->scheme);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
    p = hpack_encode_path (p, control_data->path, control_data->path_len);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_PROTOCOL_PARSED)
    p = hpack_encode_custom_header (p, (u8 *) ":protocol", 9, control_data->protocol,
				    control_data->protocol_len, 0);

  p = hpack_encode_authority (p, control_data->authority,
			      control_data->authority_len);

  /* user agent */
  if (control_data->user_agent_len)
    p = hpack_encode_header (p, HTTP_HEADER_USER_AGENT, control_data->user_agent,
			     control_data->user_agent_len, 0);

  /* content length if any */
  if (control_data->content_len != HPACK_ENCODER_SKIP_CONTENT_LEN)
    p = hpack_encode_content_len (p, control_data->content_len);

  end = app_headers + app_headers_len;
  while (app_headers < end)
    {
      /* custom header name? */
      http_app_header_name_t *name = (http_app_header_name_t *) app_headers;
      if (PREDICT_FALSE (name->flags & HTTP_FIELD_LINE_F_CUSTOM_NAME))
	{
	  http_custom_token_t *value;
	  app_headers += sizeof (http_custom_token_t) + name->len;
	  value = (http_custom_token_t *) app_headers;
	  app_headers += sizeof (http_custom_token_t) + value->len;
	  p = hpack_encode_custom_header (p, name->token, name->len, value->token, value->len,
					  name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  http_app_header_t *header;
	  header = (http_app_header_t *) app_headers;
	  app_headers += sizeof (http_app_header_t) + header->value.len;
	  p = hpack_encode_header (p, header->name.name, header->value.token, header->value.len,
				   name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
    }

  *dst = p;
}
