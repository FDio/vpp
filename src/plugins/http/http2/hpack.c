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

static_always_inline hpack_error_t
hpack_read_string (u8 **src, u8 *end, http_token_t *encoded, u8 *is_huffman)
{
  u8 *p = *src;
  uword len;

  if (p == end)
    return HPACK_ERROR_COMPRESSION;

  *is_huffman = *p & 0x80;
  len = hpack_decode_int (&p, end, 7);
  if (PREDICT_FALSE (len == HPACK_INVALID_INT || len > end - p))
    return HPACK_ERROR_COMPRESSION;

  encoded->base = (char *) p;
  encoded->len = len;
  *src = p + len;
  return HPACK_ERROR_NONE;
}

__clib_export hpack_error_t
hpack_decode_string (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u8 *p = *src, is_huffman;
  http_token_t encoded;
  hpack_error_t rv = hpack_read_string (&p, end, &encoded, &is_huffman);

  if (rv)
    return rv;
  if (is_huffman)
    {
      u8 *data = (u8 *) encoded.base;
      *src = p;
      return hpack_decode_huffman (&data, p, buf, buf_len);
    }
  if (encoded.len > *buf_len)
    return HPACK_ERROR_UNKNOWN;

  clib_memcpy (*buf, encoded.base, encoded.len);
  *buf_len -= encoded.len;
  *buf += encoded.len;
  *src = p;
  return HPACK_ERROR_NONE;
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

  /* Evicted slots retain their buffers for reuse. */
  vec_foreach (e, table->entries)
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
  if (index >= clib_ring_n_enq (table->entries))
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
hpack_dynamic_table_evict_to_size (hpack_dynamic_table_t *table, u32 size)
{
  while (table->used > size)
    hpack_dynamic_table_evict_one (table);
}

static void
hpack_dynamic_table_add (hpack_dynamic_table_t *table, http_token_t *name,
			 http_token_t *value)
{
  u64 payload_len = (u64) name->len + value->len;
  u64 entry_size = payload_len + HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD;
  hpack_dynamic_table_entry_t *e;
  u8 *buf;

  /* An oversized entry empties the table without being inserted. */
  if (entry_size > table->size)
    {
      hpack_dynamic_table_evict_to_size (table, 0);
      return;
    }

  /* Copy before eviction since an indexed name may point into an entry being evicted. */
  buf = vec_new (u8, payload_len);
  if (name->len)
    clib_memcpy (buf, name->base, name->len);
  if (value->len)
    clib_memcpy (buf + name->len, value->base, value->len);
  hpack_dynamic_table_evict_to_size (table, table->size - entry_size);

  e = clib_ring_enq (table->entries);
  ASSERT (e);
  vec_resize (e->buf, payload_len);
  clib_memcpy (e->buf, buf, payload_len);
  e->name_len = name->len;
  table->used += entry_size;
  vec_free (buf);

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

static hpack_error_t
hpack_decode_table_size_updates (u8 **src, u8 *end, hpack_dynamic_table_t *dt)
{
  u8 *p = *src;

  while (p != end && (*p & 0xe0) == 0x20)
    {
      uword size = hpack_decode_int (&p, end, 5);
      if (size == HPACK_INVALID_INT || size > dt->max_size)
	{
	  HTTP_DBG (1, "invalid dynamic table size update");
	  return HPACK_ERROR_COMPRESSION;
	}
      hpack_dynamic_table_evict_to_size (dt, size);
      dt->size = size;
    }

  *src = p;
  return HPACK_ERROR_NONE;
}

typedef enum
{
  HPACK_FIELD_INVALID,
  HPACK_FIELD_INDEXED,
  HPACK_FIELD_INCREMENTAL,
  HPACK_FIELD_LITERAL,
  HPACK_FIELD_NEVER_INDEXED,
} hpack_field_type_t;

static_always_inline hpack_field_type_t
hpack_decode_field_prefix (u8 **src, u8 *end, uword *index)
{
  u8 prefix = **src, prefix_len;
  hpack_field_type_t type;

  if (prefix & 0x80)
    {
      type = HPACK_FIELD_INDEXED;
      prefix_len = 7;
    }
  else if (prefix & 0x40)
    {
      type = HPACK_FIELD_INCREMENTAL;
      prefix_len = 6;
    }
  else if (prefix & 0x20)
    {
      /* The field block parser handles leading size updates. */
      HTTP_DBG (1, "dynamic table size update after first field");
      return HPACK_FIELD_INVALID;
    }
  else
    {
      type = (prefix & 0x10) ? HPACK_FIELD_NEVER_INDEXED : HPACK_FIELD_LITERAL;
      prefix_len = 4;
    }

  *index = hpack_decode_int (src, end, prefix_len);
  if (*index == HPACK_INVALID_INT || (type == HPACK_FIELD_INDEXED && !*index))
    {
      HTTP_DBG (1, "invalid index");
      return HPACK_FIELD_INVALID;
    }
  return type;
}

__clib_export hpack_error_t
hpack_decode_header (u8 **src, u8 *end, u8 **buf, uword *buf_len, u32 *name_len, u32 *value_len,
		     void *decoder_ctx, u8 *never_index)
{
  hpack_dynamic_table_t *dt = (hpack_dynamic_table_t *) decoder_ctx;
  u8 *p = *src;
  uword old_len, index;
  http_token_t name = { 0 }, value = { 0 };
  hpack_field_type_t type;
  hpack_error_t rv;

  ASSERT (p < end);
  type = hpack_decode_field_prefix (&p, end, &index);
  if (type == HPACK_FIELD_INVALID)
    return HPACK_ERROR_COMPRESSION;
  *never_index = type == HPACK_FIELD_NEVER_INDEXED;

  if (index)
    {
      rv = hpack_get_table_entry (index, &name, &value, type == HPACK_FIELD_INDEXED, dt);
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
      if (type == HPACK_FIELD_INDEXED)
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

  if (type != HPACK_FIELD_INDEXED)
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

  if (type == HPACK_FIELD_INCREMENTAL)
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
hpack_parse_trailers (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_dynamic_table_t *dynamic_table)
{
  u8 *end = src + src_len;
  hpack_error_t rv;

  rv = hpack_decode_table_size_updates (&src, end, dynamic_table);
  if (!rv)
    rv = hpack_decode_trailers (src, end, dst, dst_len, dynamic_table, hpack_decode_header);
  return hpack_error_to_http2_error[rv];
}

static hpack_error_t
hpack_decode_discarded_string (u8 **src, u8 *end, http_token_t *token, u8 **scratch, uword capacity,
			       uword offset)
{
  u8 is_huffman, *buf = 0, *data;
  uword buf_len = 0;
  hpack_error_t rv = hpack_read_string (src, end, token, &is_huffman);

  /* Raw strings can reference the input block. */
  if (rv || !is_huffman)
    return rv;

  data = (u8 *) token->base;
  if (offset < capacity && token->len)
    {
      if (!*scratch)
	*scratch = vec_new (u8, capacity);
      buf = *scratch + offset;
      buf_len = capacity - offset;
    }
  token->base = (char *) buf;
  return hpack_decode_huffman_inline (data, *src, &buf, &buf_len, &token->len);
}

static hpack_error_t
hpack_discard_header (u8 **src, u8 *end, hpack_dynamic_table_t *dt, u8 **scratch)
{
  uword index, capacity = 0;
  hpack_field_type_t type = hpack_decode_field_prefix (src, end, &index);
  http_token_t name = { 0 }, value = { 0 };
  hpack_error_t rv = HPACK_ERROR_NONE;

  if (type == HPACK_FIELD_INVALID ||
      index > HPACK_STATIC_TABLE_SIZE + clib_ring_n_enq (dt->entries))
    return HPACK_ERROR_COMPRESSION;
  if (type == HPACK_FIELD_INDEXED)
    return HPACK_ERROR_NONE;

  /* Only literals that update the table need decoded bytes. */
  if (type == HPACK_FIELD_INCREMENTAL && dt->size > HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD)
    capacity = dt->size - HPACK_DYNAMIC_TABLE_ENTRY_OVERHEAD;

  if (index && type == HPACK_FIELD_INCREMENTAL)
    rv = hpack_get_table_entry (index, &name, &value, 0, dt);
  else if (!index)
    rv = hpack_decode_discarded_string (src, end, &name, scratch, capacity, 0);
  if (rv)
    return rv;

  rv = hpack_decode_discarded_string (src, end, &value, scratch, capacity, name.len);
  if (!rv && type == HPACK_FIELD_INCREMENTAL)
    hpack_dynamic_table_add (dt, &name, &value);
  return rv;
}

/* Requests whose headers don't fit the buffer are rejected without closing the connection, so the
 * rest of their field block must still be decoded to keep the dynamic table in sync with the peer's
 * encoder (RFC 9113 Section 10.5.1). */
static hpack_error_t
hpack_decode_request_header (u8 **src, u8 *end, u8 **buf, uword *buf_len, u32 *name_len,
			     u32 *value_len, void *decoder_ctx, u8 *never_index)
{
  u8 *p = *src, *scratch = 0;
  hpack_error_t rv;

  rv = hpack_decode_header (src, end, buf, buf_len, name_len, value_len, decoder_ctx, never_index);
  if (rv != HPACK_ERROR_UNKNOWN)
    return rv;

  /* Retry the field that overflowed, then discard the remaining fields. */
  do
    rv = hpack_discard_header (&p, end, decoder_ctx, &scratch);
  while (!rv && p != end);
  vec_free (scratch);

  /* Still too large for the request */
  return rv ? rv : HPACK_ERROR_UNKNOWN;
}

__clib_export http2_error_t
hpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		     hpack_request_control_data_t *control_data,
		     http_field_line_t **headers,
		     hpack_dynamic_table_t *dynamic_table)
{
  u8 *end = src + src_len;
  hpack_error_t rv;

  rv = hpack_decode_table_size_updates (&src, end, dynamic_table);
  if (!rv)
    rv = hpack_decode_request (src, end, dst, dst_len, control_data, headers, dynamic_table,
			       hpack_decode_request_header);
  HTTP_DBG (3, "%U", format_hpack_dynamic_table, dynamic_table);
  return hpack_error_to_http2_error[rv];
}

__clib_export http2_error_t
hpack_parse_response (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_response_control_data_t *control_data,
		      http_field_line_t **headers,
		      hpack_dynamic_table_t *dynamic_table)
{
  u8 *end = src + src_len;
  hpack_error_t rv;

  rv = hpack_decode_table_size_updates (&src, end, dynamic_table);
  if (!rv)
    rv = hpack_decode_response (src, end, dst, dst_len, control_data, headers, dynamic_table,
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
      vec_add2 (dst, a, 13);
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
  u32 orig_len, actual_size;
  u8 *a, *b;

  switch (scheme)
    {
    case HTTP_URL_SCHEME_HTTP:
      encode_indexed_static_entry (6);
      break;
    case HTTP_URL_SCHEME_HTTPS:
      encode_indexed_static_entry (7);
      break;
    case HTTP_URL_SCHEME_MASQUE:
      orig_len = vec_len (dst);
      vec_add2 (dst, a, 8);
      b = a;
      /* Literal Header Field without Indexing — Indexed Name */
      *b++ = 6;
      b = hpack_encode_string (b, (const u8 *) http_token_lit ("masque"));
      actual_size = b - a;
      vec_set_len (dst, orig_len + actual_size);
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
  u8 digit_buffer[HTTP_U64_MAX_DECIMAL_DIGITS];
  u8 *d = http_encode_u64_decimal (digit_buffer + sizeof (digit_buffer), content_len);
  u32 orig_len, actual_size;
  u8 *a, *b;

  orig_len = vec_len (dst);
  vec_add2 (dst, a, 3 + sizeof (digit_buffer));
  b = a;

  /* static table index 28 */
  *b++ = 0x0F;
  *b++ = 0x0D;
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
  if (control_data->send_content_length)
    p = hpack_encode_content_len (p, control_data->content_len);

  /* ALT-SVC */
  if (control_data->alt_svc)
    p = hpack_encode_header (p, HTTP_HEADER_ALT_SVC, control_data->alt_svc,
			     control_data->alt_svc_len, 0);

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
