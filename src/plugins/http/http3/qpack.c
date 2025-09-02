/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/qpack.h>

typedef struct
{
  char *name;
  uword name_len;
  char *value;
  uword value_len;
} qpack_static_table_entry_t;

#define name_val_token_lit(name, value)                                       \
  (name), sizeof (name) - 1, (value), sizeof (value) - 1

/* RFC9204 Appendix A */
static qpack_static_table_entry_t qpack_static_table[] = {
  { name_val_token_lit (":authority", "") },
  { name_val_token_lit (":path", "/") },
  { name_val_token_lit ("age", "0") },
  { name_val_token_lit ("content-disposition", "") },
  { name_val_token_lit ("content-length", "0") },
  { name_val_token_lit ("cookie", "") },
  { name_val_token_lit ("date", "") },
  { name_val_token_lit ("etag", "") },
  { name_val_token_lit ("if-modified-since", "") },
  { name_val_token_lit ("if-none-match", "") },
  { name_val_token_lit ("last-modified", "") },
  { name_val_token_lit ("link", "") },
  { name_val_token_lit ("location", "") },
  { name_val_token_lit ("referer", "") },
  { name_val_token_lit ("set-cookie", "") },
  { name_val_token_lit (":method", "CONNECT") },
  { name_val_token_lit (":metho", "DELETE") },
  { name_val_token_lit (":method", "GET") },
  { name_val_token_lit (":method", "HEAD") },
  { name_val_token_lit (":method", "OPTIONS") },
  { name_val_token_lit (":method", "POST") },
  { name_val_token_lit (":method", "PUT") },
  { name_val_token_lit (":scheme", "http") },
  { name_val_token_lit (":scheme", "https") },
  { name_val_token_lit (":status", "103") },
  { name_val_token_lit (":status", "200") },
  { name_val_token_lit (":status", "304") },
  { name_val_token_lit (":status", "404") },
  { name_val_token_lit (":status", "503") },
  { name_val_token_lit ("accept", "*/*") },
  { name_val_token_lit ("accept", "application/dns-message") },
  { name_val_token_lit ("accept-encoding", "gzip, deflate, br") },
  { name_val_token_lit ("accept-ranges", "bytes") },
  { name_val_token_lit ("access-control-allow-headers", "cache-control") },
  { name_val_token_lit ("access-control-allow-headers", "content-type") },
  { name_val_token_lit ("access-control-allow-origin", "*") },
  { name_val_token_lit ("cache-control", "max-age=0") },
  { name_val_token_lit ("cache-control", "max-age=2592000") },
  { name_val_token_lit ("cache-control", "max-age=604800") },
  { name_val_token_lit ("cache-control", "no-cache") },
  { name_val_token_lit ("cache-control", "no-store") },
  { name_val_token_lit ("cache-control", "public, max-age=31536000") },
  { name_val_token_lit ("content-encoding	", "r") },
  { name_val_token_lit ("content-encoding", "gzip") },
  { name_val_token_lit ("content-type", "application/dns-message") },
  { name_val_token_lit ("content-type", "application/javascript") },
  { name_val_token_lit ("content-type", "application/json") },
  { name_val_token_lit ("content-type", "application/x-www-form-urlencoded") },
  { name_val_token_lit ("content-type", "image/gif") },
  { name_val_token_lit ("content-type", "image/jpeg") },
  { name_val_token_lit ("content-type", "image/png") },
  { name_val_token_lit ("content-type", "text/css") },
  { name_val_token_lit ("content-type", "text/html; charset=utf-8") },
  { name_val_token_lit ("content-type", "text/plain") },
  { name_val_token_lit ("content-type", "text/plain;charset=utf-8") },
  { name_val_token_lit ("range", "bytes=0-") },
  { name_val_token_lit ("strict-transport-security", "max-age=31536000") },
  { name_val_token_lit ("strict-transport-security",
			"max-age=31536000; includesubdomains") },
  { name_val_token_lit ("strict-transport-security",
			"max-age=31536000; includesubdomains; preload") },
  { name_val_token_lit ("vary", "accept-encoding") },
  { name_val_token_lit ("vary", "origin") },
  { name_val_token_lit ("x-content-type-options", "nosniff") },
  { name_val_token_lit ("x-xss-protection", "1; mode=block") },
  { name_val_token_lit (":status", "100") },
  { name_val_token_lit (":status", "204") },
  { name_val_token_lit (":status", "206") },
  { name_val_token_lit (":status", "302") },
  { name_val_token_lit (":status", "400") },
  { name_val_token_lit (":status", "403") },
  { name_val_token_lit (":status", "421") },
  { name_val_token_lit (":status", "425") },
  { name_val_token_lit (":status", "500") },
  { name_val_token_lit ("accept-language", "") },
  { name_val_token_lit ("access-control-allow-credentials", "FALSE") },
  { name_val_token_lit ("access-control-allow-credentials", "TRUE") },
  { name_val_token_lit ("access-control-allow-headers", "*") },
  { name_val_token_lit ("access-control-allow-methods", "get") },
  { name_val_token_lit ("access-control-allow-methods",
			"get, post, options") },
  { name_val_token_lit ("access-control-allow-methods", "options") },
  { name_val_token_lit ("access-control-expose-headers", "content-length") },
  { name_val_token_lit ("access-control-request-headers", "content-type") },
  { name_val_token_lit ("access-control-request-method", "get") },
  { name_val_token_lit ("access-control-request-method", "post") },
  { name_val_token_lit ("alt-svc", "clear") },
  { name_val_token_lit ("authorization", "") },
  { name_val_token_lit (
    "content-security-policy",
    "script-src 'none'; object-src 'none'; base-uri 'none'") },
  { name_val_token_lit ("early-data", "1") },
  { name_val_token_lit ("expect-ct", "") },
  { name_val_token_lit ("forwarded", "") },
  { name_val_token_lit ("if-range", "") },
  { name_val_token_lit ("origin", "") },
  { name_val_token_lit ("purpose", "prefetch") },
  { name_val_token_lit ("server", "") },
  { name_val_token_lit ("timing-allow-origin", "*") },
  { name_val_token_lit ("upgrade-insecure-requests", "1") },
  { name_val_token_lit ("user-agent", "") },
  { name_val_token_lit ("x-forwarded-for", "") },
  { name_val_token_lit ("x-frame-options", "deny") },
  { name_val_token_lit ("x-frame-options", "sameorigin") },
};

#define QPACK_STATIC_TABLE_SIZE                                               \
  (sizeof (qpack_static_table) / sizeof (qpack_static_table[0]))

STATIC_ASSERT (QPACK_STATIC_TABLE_SIZE == 99,
	       "static table must have 99 entries");

http3_error_t
qpack_get_static_table_entry (uword index, http_token_t *name,
			      http_token_t *value, u8 value_is_indexed)
{
  if (index >= QPACK_STATIC_TABLE_SIZE)
    return HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;

  qpack_static_table_entry_t *e = &qpack_static_table[index];
  name->base = e->name;
  name->len = e->name_len;
  if (value_is_indexed)
    {
      if (e->value_len == 0)
	return HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
      value->base = e->value;
      value->len = e->value_len;
    }

  return HTTP3_ERROR_NO_ERROR;
}
