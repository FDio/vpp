/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/qpack.h>
#include <http/http2/hpack_inlines.h>
#include <http/http_status_codes.h>

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
  { name_val_token_lit ("content-encoding", "br") },
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
  { name_val_token_lit ("strict-transport-security", "max-age=31536000; includesubdomains") },
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
  { name_val_token_lit ("access-control-allow-methods", "get, post, options") },
  { name_val_token_lit ("access-control-allow-methods", "options") },
  { name_val_token_lit ("access-control-expose-headers", "content-length") },
  { name_val_token_lit ("access-control-request-headers", "content-type") },
  { name_val_token_lit ("access-control-request-method", "get") },
  { name_val_token_lit ("access-control-request-method", "post") },
  { name_val_token_lit ("alt-svc", "clear") },
  { name_val_token_lit ("authorization", "") },
  { name_val_token_lit ("content-security-policy",
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

typedef int (*qpack_static_table_lookup_fn) (const char *value, u32 value_len,
					     u8 *full_match);

static int
qpack_lookup_no_match (const char *value, u32 value_len, u8 *full_match)
{
  return -1;
}

static int
qpack_lookup_accept_encoding (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[31].value,
			       qpack_static_table[31].value_len);
  return 31;
}

static int
qpack_lookup_accept_language (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 72;
}

static int
qpack_lookup_accept_ranges (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[32].value,
			       qpack_static_table[32].value_len);
  return 32;
}

static int
qpack_lookup_accept (const char *value, u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[29].value,
		     qpack_static_table[29].value_len))
    {
      *full_match = 1;
      return 29;
    }
  if (http_token_is (value, value_len, qpack_static_table[30].value,
		     qpack_static_table[30].value_len))
    {
      *full_match = 1;
      return 30;
    }

  *full_match = 0;
  return 29;
}

static int
qpack_lookup_access_control_allow_credentials (const char *value,
					       u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[73].value,
		     qpack_static_table[73].value_len))
    {
      *full_match = 1;
      return 73;
    }
  if (http_token_is (value, value_len, qpack_static_table[74].value,
		     qpack_static_table[74].value_len))
    {
      *full_match = 1;
      return 74;
    }

  *full_match = 0;
  return 73;
}

static int
qpack_lookup_access_control_allow_headers (const char *value, u32 value_len,
					   u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[33].value,
		     qpack_static_table[33].value_len))
    {
      *full_match = 1;
      return 33;
    }
  if (http_token_is (value, value_len, qpack_static_table[34].value,
		     qpack_static_table[34].value_len))
    {
      *full_match = 1;
      return 34;
    }
  if (http_token_is (value, value_len, qpack_static_table[75].value,
		     qpack_static_table[75].value_len))
    {
      *full_match = 1;
      return 75;
    }

  *full_match = 0;
  return 33;
}

static int
qpack_lookup_access_control_allow_methods (const char *value, u32 value_len,
					   u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[76].value,
		     qpack_static_table[76].value_len))
    {
      *full_match = 1;
      return 76;
    }
  if (http_token_is (value, value_len, qpack_static_table[77].value,
		     qpack_static_table[77].value_len))
    {
      *full_match = 1;
      return 77;
    }
  if (http_token_is (value, value_len, qpack_static_table[78].value,
		     qpack_static_table[78].value_len))
    {
      *full_match = 1;
      return 78;
    }

  *full_match = 0;
  return 76;
}

static int
qpack_lookup_access_control_allow_origin (const char *value, u32 value_len,
					  u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[35].value,
			       qpack_static_table[35].value_len);
  return 35;
}

static int
qpack_lookup_access_control_expose_headers (const char *value, u32 value_len,
					    u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[79].value,
		     qpack_static_table[79].value_len))
    {
      *full_match = 1;
      return 79;
    }
  if (http_token_is (value, value_len, qpack_static_table[80].value,
		     qpack_static_table[80].value_len))
    {
      *full_match = 1;
      return 80;
    }

  *full_match = 0;
  return 79;
}

static int
qpack_lookup_access_control_request_method (const char *value, u32 value_len,
					    u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[81].value,
		     qpack_static_table[81].value_len))
    {
      *full_match = 1;
      return 81;
    }
  if (http_token_is (value, value_len, qpack_static_table[82].value,
		     qpack_static_table[82].value_len))
    {
      *full_match = 1;
      return 82;
    }

  *full_match = 0;
  return 81;
}

static int
qpack_lookup_age (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[2].value,
			       qpack_static_table[2].value_len);
  return 2;
}

static int
qpack_lookup_alt_svc (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[83].value,
			       qpack_static_table[83].value_len);
  return 83;
}

static int
qpack_lookup_authorization (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 84;
}

static int
qpack_lookup_cache_control (const char *value, u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[36].value,
		     qpack_static_table[36].value_len))
    {
      *full_match = 1;
      return 36;
    }
  if (http_token_is (value, value_len, qpack_static_table[37].value,
		     qpack_static_table[37].value_len))
    {
      *full_match = 1;
      return 37;
    }
  if (http_token_is (value, value_len, qpack_static_table[38].value,
		     qpack_static_table[38].value_len))
    {
      *full_match = 1;
      return 38;
    }
  if (http_token_is (value, value_len, qpack_static_table[39].value,
		     qpack_static_table[39].value_len))
    {
      *full_match = 1;
      return 39;
    }
  if (http_token_is (value, value_len, qpack_static_table[40].value,
		     qpack_static_table[40].value_len))
    {
      *full_match = 1;
      return 40;
    }
  if (http_token_is (value, value_len, qpack_static_table[41].value,
		     qpack_static_table[41].value_len))
    {
      *full_match = 1;
      return 41;
    }

  *full_match = 0;
  return 36;
}

static int
qpack_lookup_content_disposition (const char *value, u32 value_len,
				  u8 *full_match)
{
  *full_match = 0;
  return 3;
}

static int
qpack_lookup_content_encoding (const char *value, u32 value_len,
			       u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[42].value,
		     qpack_static_table[42].value_len))
    {
      *full_match = 1;
      return 42;
    }
  if (http_token_is (value, value_len, qpack_static_table[43].value,
		     qpack_static_table[43].value_len))
    {
      *full_match = 1;
      return 43;
    }

  *full_match = 0;
  return 42;
}

static int
qpack_lookup_content_length (const char *value, u32 value_len, u8 *full_match)
{
  /* "content-length: 0" is encoded directly in qpack_encode_content_len */
  *full_match = 0;
  return 4;
}

static int
qpack_lookup_content_security_policy (const char *value, u32 value_len,
				      u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[85].value,
			       qpack_static_table[85].value_len);
  return 85;
}

static int
qpack_lookup_content_type (const char *value, u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[44].value,
		     qpack_static_table[44].value_len))
    {
      *full_match = 1;
      return 44;
    }
  if (http_token_is (value, value_len, qpack_static_table[45].value,
		     qpack_static_table[45].value_len))
    {
      *full_match = 1;
      return 45;
    }
  if (http_token_is (value, value_len, qpack_static_table[46].value,
		     qpack_static_table[46].value_len))
    {
      *full_match = 1;
      return 46;
    }
  if (http_token_is (value, value_len, qpack_static_table[47].value,
		     qpack_static_table[47].value_len))
    {
      *full_match = 1;
      return 47;
    }
  if (http_token_is (value, value_len, qpack_static_table[48].value,
		     qpack_static_table[48].value_len))
    {
      *full_match = 1;
      return 48;
    }
  if (http_token_is (value, value_len, qpack_static_table[49].value,
		     qpack_static_table[49].value_len))
    {
      *full_match = 1;
      return 49;
    }
  if (http_token_is (value, value_len, qpack_static_table[50].value,
		     qpack_static_table[50].value_len))
    {
      *full_match = 1;
      return 50;
    }
  if (http_token_is (value, value_len, qpack_static_table[51].value,
		     qpack_static_table[51].value_len))
    {
      *full_match = 1;
      return 51;
    }
  if (http_token_is (value, value_len, qpack_static_table[52].value,
		     qpack_static_table[52].value_len))
    {
      *full_match = 1;
      return 52;
    }
  if (http_token_is (value, value_len, qpack_static_table[53].value,
		     qpack_static_table[53].value_len))
    {
      *full_match = 1;
      return 53;
    }
  if (http_token_is (value, value_len, qpack_static_table[54].value,
		     qpack_static_table[54].value_len))
    {
      *full_match = 1;
      return 54;
    }

  *full_match = 0;
  return 44;
}

static int
qpack_lookup_cookie (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 5;
}

static int
qpack_lookup_date (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 6;
}

static int
qpack_lookup_early_data (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[86].value,
			       qpack_static_table[86].value_len);
  return 86;
}

static int
qpack_lookup_etag (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 7;
}

static int
qpack_lookup_expect_ct (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 87;
}

static int
qpack_lookup_forwarded (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 88;
}

static int
qpack_lookup_if_modified_since (const char *value, u32 value_len,
				u8 *full_match)
{
  *full_match = 0;
  return 8;
}

static int
qpack_lookup_if_none_match (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 9;
}

static int
qpack_lookup_if_range (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 89;
}

static int
qpack_lookup_last_modified (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 10;
}

static int
qpack_lookup_link (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 11;
}

static int
qpack_lookup_location (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 12;
}

static int
qpack_lookup_origin (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 90;
}

static int
qpack_lookup_purpose (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[91].value,
			       qpack_static_table[91].value_len);
  return 91;
}

static int
qpack_lookup_range (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[55].value,
			       qpack_static_table[55].value_len);
  return 55;
}

static int
qpack_lookup_referer (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 13;
}

static int
qpack_lookup_server (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 92;
}

static int
qpack_lookup_set_cookie (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 14;
}

static int
qpack_lookup_strict_transport_security (const char *value, u32 value_len,
					u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[56].value,
		     qpack_static_table[56].value_len))
    {
      *full_match = 1;
      return 56;
    }
  if (http_token_is (value, value_len, qpack_static_table[57].value,
		     qpack_static_table[57].value_len))
    {
      *full_match = 1;
      return 57;
    }
  if (http_token_is (value, value_len, qpack_static_table[58].value,
		     qpack_static_table[58].value_len))
    {
      *full_match = 1;
      return 58;
    }

  *full_match = 0;
  return 56;
}

static int
qpack_lookup_timing_allow_origin (const char *value, u32 value_len,
				  u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[93].value,
			       qpack_static_table[93].value_len);
  return 93;
}

static int
qpack_lookup_upgrade_insecure_requests (const char *value, u32 value_len,
					u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[94].value,
			       qpack_static_table[94].value_len);
  return 94;
}

static int
qpack_lookup_user_agent (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 95;
}

static int
qpack_lookup_vary (const char *value, u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[59].value,
		     qpack_static_table[59].value_len))
    {
      *full_match = 1;
      return 59;
    }
  if (http_token_is (value, value_len, qpack_static_table[60].value,
		     qpack_static_table[60].value_len))
    {
      *full_match = 1;
      return 60;
    }

  *full_match = 0;
  return 59;
}

static int
qpack_lookup_x_content_type_options (const char *value, u32 value_len,
				     u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[61].value,
			       qpack_static_table[61].value_len);
  return 61;
}

static int
qpack_lookup_x_forwarded_for (const char *value, u32 value_len, u8 *full_match)
{
  *full_match = 0;
  return 96;
}

static int
qpack_lookup_x_frame_options (const char *value, u32 value_len, u8 *full_match)
{
  if (http_token_is (value, value_len, qpack_static_table[97].value,
		     qpack_static_table[97].value_len))
    {
      *full_match = 1;
      return 97;
    }
  if (http_token_is (value, value_len, qpack_static_table[98].value,
		     qpack_static_table[98].value_len))
    {
      *full_match = 1;
      return 98;
    }

  *full_match = 0;
  return 97;
}

static int
qpack_lookup_x_xss_protection (const char *value, u32 value_len,
			       u8 *full_match)
{
  *full_match = http_token_is (value, value_len, qpack_static_table[62].value,
			       qpack_static_table[62].value_len);
  return 62;
}

static qpack_static_table_lookup_fn qpack_static_table_lookup[] = {
  [HTTP_HEADER_ACCEPT_CHARSET] = qpack_lookup_no_match,
  [HTTP_HEADER_ACCEPT_ENCODING] = qpack_lookup_accept_encoding,
  [HTTP_HEADER_ACCEPT_LANGUAGE] = qpack_lookup_accept_language,
  [HTTP_HEADER_ACCEPT_RANGES] = qpack_lookup_accept_ranges,
  [HTTP_HEADER_ACCEPT] = qpack_lookup_accept,
  [HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] =
    qpack_lookup_access_control_allow_credentials,
  [HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS] =
    qpack_lookup_access_control_allow_headers,
  [HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS] =
    qpack_lookup_access_control_allow_methods,
  [HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN] =
    qpack_lookup_access_control_allow_origin,
  [HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS] =
    qpack_lookup_access_control_expose_headers,
  [HTTP_HEADER_ACCESS_CONTROL_MAX_AGE] = qpack_lookup_no_match,
  [HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS] = qpack_lookup_no_match,
  [HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD] =
    qpack_lookup_access_control_request_method,
  [HTTP_HEADER_AGE] = qpack_lookup_age,
  [HTTP_HEADER_ALLOW] = qpack_lookup_no_match,
  [HTTP_HEADER_ALPN] = qpack_lookup_no_match,
  [HTTP_HEADER_ALT_SVC] = qpack_lookup_alt_svc,
  [HTTP_HEADER_ALT_USED] = qpack_lookup_no_match,
  [HTTP_HEADER_ALTERNATES] = qpack_lookup_no_match,
  [HTTP_HEADER_AUTHENTICATION_CONTROL] = qpack_lookup_no_match,
  [HTTP_HEADER_AUTHENTICATION_INFO] = qpack_lookup_no_match,
  [HTTP_HEADER_AUTHORIZATION] = qpack_lookup_authorization,
  [HTTP_HEADER_CACHE_CONTROL] = qpack_lookup_cache_control,
  [HTTP_HEADER_CACHE_STATUS] = qpack_lookup_no_match,
  [HTTP_HEADER_CAPSULE_PROTOCOL] = qpack_lookup_no_match,
  [HTTP_HEADER_CDN_CACHE_CONTROL] = qpack_lookup_no_match,
  [HTTP_HEADER_CDN_LOOP] = qpack_lookup_no_match,
  [HTTP_HEADER_CLIENT_CERT] = qpack_lookup_no_match,
  [HTTP_HEADER_CLIENT_CERT_CHAIN] = qpack_lookup_no_match,
  [HTTP_HEADER_CLOSE] = qpack_lookup_no_match,
  [HTTP_HEADER_CONNECTION] = qpack_lookup_no_match,
  [HTTP_HEADER_CONTENT_DIGEST] = qpack_lookup_no_match,
  [HTTP_HEADER_CONTENT_DISPOSITION] = qpack_lookup_content_disposition,
  [HTTP_HEADER_CONTENT_ENCODING] = qpack_lookup_content_encoding,
  [HTTP_HEADER_CONTENT_LANGUAGE] = qpack_lookup_no_match,
  [HTTP_HEADER_CONTENT_LENGTH] = qpack_lookup_content_length,
  [HTTP_HEADER_CONTENT_LOCATION] = qpack_lookup_no_match,
  [HTTP_HEADER_CONTENT_RANGE] = qpack_lookup_no_match,
  [HTTP_HEADER_CONTENT_SECURITY_POLICY] = qpack_lookup_content_security_policy,
  [HTTP_HEADER_CONTENT_TYPE] = qpack_lookup_content_type,
  [HTTP_HEADER_COOKIE] = qpack_lookup_cookie,
  [HTTP_HEADER_DATE] = qpack_lookup_date,
  [HTTP_HEADER_DIGEST] = qpack_lookup_no_match,
  [HTTP_HEADER_DPOP] = qpack_lookup_no_match,
  [HTTP_HEADER_DPOP_NONCE] = qpack_lookup_no_match,
  [HTTP_HEADER_EARLY_DATA] = qpack_lookup_early_data,
  [HTTP_HEADER_ETAG] = qpack_lookup_etag,
  [HTTP_HEADER_EXPECT] = qpack_lookup_no_match,
  [HTTP_HEADER_EXPECT_CT] = qpack_lookup_expect_ct,
  [HTTP_HEADER_EXPIRES] = qpack_lookup_no_match,
  [HTTP_HEADER_FORWARDED] = qpack_lookup_forwarded,
  [HTTP_HEADER_FROM] = qpack_lookup_no_match,
  [HTTP_HEADER_HOST] = qpack_lookup_no_match,
  [HTTP_HEADER_IF_MATCH] = qpack_lookup_no_match,
  [HTTP_HEADER_IF_MODIFIED_SINCE] = qpack_lookup_if_modified_since,
  [HTTP_HEADER_IF_NONE_MATCH] = qpack_lookup_if_none_match,
  [HTTP_HEADER_IF_RANGE] = qpack_lookup_if_range,
  [HTTP_HEADER_IF_UNMODIFIED_SINCE] = qpack_lookup_no_match,
  [HTTP_HEADER_KEEP_ALIVE] = qpack_lookup_no_match,
  [HTTP_HEADER_LAST_MODIFIED] = qpack_lookup_last_modified,
  [HTTP_HEADER_LINK] = qpack_lookup_link,
  [HTTP_HEADER_LOCATION] = qpack_lookup_location,
  [HTTP_HEADER_MAX_FORWARDS] = qpack_lookup_no_match,
  [HTTP_HEADER_ORIGIN] = qpack_lookup_origin,
  [HTTP_HEADER_PRIORITY] = qpack_lookup_no_match,
  [HTTP_HEADER_PROXY_AUTHENTICATE] = qpack_lookup_no_match,
  [HTTP_HEADER_PROXY_AUTHENTICATION_INFO] = qpack_lookup_no_match,
  [HTTP_HEADER_PROXY_AUTHORIZATION] = qpack_lookup_no_match,
  [HTTP_HEADER_PROXY_STATUS] = qpack_lookup_no_match,
  [HTTP_HEADER_PURPOSE] = qpack_lookup_purpose,
  [HTTP_HEADER_RANGE] = qpack_lookup_range,
  [HTTP_HEADER_REFERER] = qpack_lookup_referer,
  [HTTP_HEADER_REFRESH] = qpack_lookup_no_match,
  [HTTP_HEADER_REPR_DIGEST] = qpack_lookup_no_match,
  [HTTP_HEADER_RETRY_AFTER] = qpack_lookup_no_match,
  [HTTP_HEADER_SERVER] = qpack_lookup_server,
  [HTTP_HEADER_SET_COOKIE] = qpack_lookup_set_cookie,
  [HTTP_HEADER_SIGNATURE] = qpack_lookup_no_match,
  [HTTP_HEADER_SIGNATURE_INPUT] = qpack_lookup_no_match,
  [HTTP_HEADER_STRICT_TRANSPORT_SECURITY] =
    qpack_lookup_strict_transport_security,
  [HTTP_HEADER_TE] = qpack_lookup_no_match,
  [HTTP_HEADER_TIMING_ALLOW_ORIGIN] = qpack_lookup_timing_allow_origin,
  [HTTP_HEADER_TRAILER] = qpack_lookup_no_match,
  [HTTP_HEADER_TRANSFER_ENCODING] = qpack_lookup_no_match,
  [HTTP_HEADER_UPGRADE] = qpack_lookup_no_match,
  [HTTP_HEADER_UPGRADE_INSECURE_REQUESTS] =
    qpack_lookup_upgrade_insecure_requests,
  [HTTP_HEADER_USER_AGENT] = qpack_lookup_user_agent,
  [HTTP_HEADER_VARY] = qpack_lookup_vary,
  [HTTP_HEADER_VIA] = qpack_lookup_no_match,
  [HTTP_HEADER_WANT_CONTENT_DIGEST] = qpack_lookup_no_match,
  [HTTP_HEADER_WANT_REPR_DIGEST] = qpack_lookup_no_match,
  [HTTP_HEADER_WWW_AUTHENTICATE] = qpack_lookup_no_match,
  [HTTP_HEADER_X_CONTENT_TYPE_OPTIONS] = qpack_lookup_x_content_type_options,
  [HTTP_HEADER_X_FORWARDED_FOR] = qpack_lookup_x_forwarded_for,
  [HTTP_HEADER_X_FRAME_OPTIONS] = qpack_lookup_x_frame_options,
  [HTTP_HEADER_X_XSS_PROTECTION] = qpack_lookup_x_xss_protection,
};

static hpack_error_t
qpack_get_static_table_entry (uword index, http_token_t *name,
			      http_token_t *value, u8 value_is_indexed)
{
  if (index >= QPACK_STATIC_TABLE_SIZE)
    return HPACK_ERROR_COMPRESSION;

  qpack_static_table_entry_t *e = &qpack_static_table[index];
  name->base = e->name;
  name->len = e->name_len;
  if (value_is_indexed)
    {
      if (e->value_len == 0)
	return HPACK_ERROR_COMPRESSION;
      value->base = e->value;
      value->len = e->value_len;
    }

  return HPACK_ERROR_NONE;
}

static hpack_error_t
qpack_decode_string (u8 **src, u8 *end, u8 **buf, uword *buf_len,
		     u8 prefix_len)
{
  u8 *p, is_huffman;
  uword len;

  ASSERT (prefix_len >= 2 && prefix_len <= 8);
  if (*src == end)
    return HPACK_ERROR_COMPRESSION;

  p = *src;
  /* first bit for H flag */
  is_huffman = (*p >> (prefix_len - 1)) & 0x01;

  /* length is integer with (N-1) bit prefix */
  len = hpack_decode_int (&p, end, prefix_len - 1);
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

static_always_inline u8 *
qpack_encode_string (u8 *dst, const u8 *value, uword value_len, u8 prefix_len)
{
  uword huff_len;

  ASSERT (prefix_len >= 2 && prefix_len <= 8);

  huff_len = hpack_huffman_encoded_len (value, value_len);
  /* raw bytes might take fewer bytes */
  if (huff_len >= value_len)
    {
      /* clear H flag and rest of the bits */
      *dst &= (u8) ~((1 << (prefix_len)) - 1);
      dst = hpack_encode_int (dst, value_len, prefix_len - 1);
      clib_memcpy (dst, value, value_len);
      return dst + value_len;
    }

  /* set H flag */
  *dst |= 1 << (prefix_len - 1);
  /* clear rest of the prefix bits */
  *dst &= (u8) ~((1 << (prefix_len - 1)) - 1);
  dst = hpack_encode_int (dst, huff_len, prefix_len - 1);
  dst = hpack_encode_huffman (dst, value, value_len);

  return dst;
}

__clib_export hpack_error_t
qpack_decode_header (u8 **src, u8 *end, u8 **buf, uword *buf_len, u32 *name_len, u32 *value_len,
		     void *decoder_ctx, u8 *never_index)
{
  u8 *p;
  uword index, old_len;
  http_token_t name, value;
  hpack_error_t rv;

  ASSERT (*src < end);
  p = *src;

#define COPY_TOKEN(_token)                                                    \
  if (_token.len > *buf_len)                                                  \
    return HPACK_ERROR_COMPRESSION;                                           \
  clib_memcpy (*buf, _token.base, _token.len);                                \
  *buf_len -= _token.len;                                                     \
  *buf += _token.len;

  switch (*p >> 4)
    {
    case 12 ... 15:
      /* indexed field line, static table */
      index = hpack_decode_int (&p, end, 6);
      if (index == HPACK_INVALID_INT)
	return HPACK_ERROR_COMPRESSION;
      rv = qpack_get_static_table_entry (index, &name, &value, 1);
      if (rv)
	return rv;
      COPY_TOKEN (name);
      *name_len = name.len;
      COPY_TOKEN (value);
      *value_len = value.len;
      break;
    case 8 ... 11:
      /* TODO: indexed field line, dynamic table */
      return HPACK_ERROR_COMPRESSION;
    case 7:
      *never_index = 1;
      __attribute__ ((fallthrough));
    case 5:
      /* literal field line with name reference, static table */
      index = hpack_decode_int (&p, end, 4);
      if (index == HPACK_INVALID_INT)
	return HPACK_ERROR_COMPRESSION;
      rv = qpack_get_static_table_entry (index, &name, &value, 0);
      if (rv)
	return rv;
      COPY_TOKEN (name);
      *name_len = name.len;
      old_len = *buf_len;
      rv = qpack_decode_string (&p, end, buf, buf_len, 8);
      if (rv)
	return rv;
      *value_len = old_len - *buf_len;
      break;
    case 6:
    case 4:
      /* TODO: literal field line with name reference, dynamic table */
      return HPACK_ERROR_COMPRESSION;
    case 3:
      *never_index = 1;
      __attribute__ ((fallthrough));
    case 2:
      /* literal field line with literal name */
      old_len = *buf_len;
      rv = qpack_decode_string (&p, end, buf, buf_len, 4);
      if (rv)
	return rv;
      *name_len = old_len - *buf_len;
      old_len = *buf_len;
      rv = qpack_decode_string (&p, end, buf, buf_len, 8);
      if (rv)
	return rv;
      *value_len = old_len - *buf_len;
      break;
    case 1:
      /* TODO: indexed field line with post-base index */
      return HPACK_ERROR_COMPRESSION;
    case 0:
      /* TODO: literal field line with post-base name reference */
      return HPACK_ERROR_COMPRESSION;
    default:
      ASSERT (0);
      break;
    }

  *src = p;
  return HPACK_ERROR_NONE;
}

__clib_export u8 *
qpack_encode_header (u8 *dst, http_header_name_t name, const u8 *value, u32 value_len,
		     u8 never_index)
{
  int index;
  u8 *a, *b, full_match;
  u32 orig_len, actual_size;

  orig_len = vec_len (dst);
  index = qpack_static_table_lookup[name]((const char *) value, value_len,
					  &full_match);
  if (index > -1)
    {
      if (full_match)
	{
	  /* indexed field line, static table */
	  vec_add2 (dst, a, 2);
	  *a = 0xC0;
	  b = hpack_encode_int (a, index, 6);
	}
      else
	{
	  /* literal field line with name reference, static table */
	  vec_add2 (dst, a, 2 + value_len + HPACK_ENCODED_INT_MAX_LEN);
	  *a = never_index ? 0x70 : 0x50;
	  b = hpack_encode_int (a, index, 4);
	  b = qpack_encode_string (b, value, value_len, 8);
	}
    }
  else
    {
      /* literal field line with literal name */
      const hpack_token_t *name_token = &hpack_headers[name];
      vec_add2 (dst, a,
		name_token->len + value_len + HPACK_ENCODED_INT_MAX_LEN * 2 +
		  1);
      *a = never_index ? 0x30 : 0x20;
      b = qpack_encode_string (a, (const u8 *) name_token->base,
			       name_token->len, 4);
      b = qpack_encode_string (b, value, value_len, 8);
    }

  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);
  return dst;
}

__clib_export u8 *
qpack_encode_custom_header (u8 *dst, const u8 *name, u32 name_len, const u8 *value, u32 value_len,
			    u8 never_index)
{
  u8 *a, *b;
  u32 orig_len, actual_size;

  orig_len = vec_len (dst);
  /* literal field line with literal name */
  vec_add2 (dst, a, name_len + value_len + HPACK_ENCODED_INT_MAX_LEN * 2 + 1);
  *a = never_index ? 0x30 : 0x20;
  b = qpack_encode_string (a, name, name_len, 4);
  b = qpack_encode_string (b, value, value_len, 8);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);
  return dst;
}

static const http3_error_t hpack_error_to_http3_error[] = {
  [HPACK_ERROR_NONE] = HTTP3_ERROR_NO_ERROR,
  [HPACK_ERROR_COMPRESSION] = HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
  [HPACK_ERROR_PROTOCOL] = HTTP3_ERROR_MESSAGE_ERROR,
  [HPACK_ERROR_UNKNOWN] = HTTP3_ERROR_INTERNAL_ERROR,
};

#define encode_static_entry(_index)                                           \
  vec_add2 (dst, a, 1);                                                       \
  *a++ = 0xC0 | _index;

static u8 *
qpack_encode_status_code (u8 *dst, http_status_code_t sc)
{
  u32 orig_len, actual_size;
  u8 *a, *b;

  switch (sc)
    {
    case HTTP_STATUS_EARLY_HINTS:
      encode_static_entry (24);
      break;
    case HTTP_STATUS_OK:
      encode_static_entry (25);
      break;
    case HTTP_STATUS_NOT_MODIFIED:
      encode_static_entry (26);
      break;
    case HTTP_STATUS_NOT_FOUND:
      encode_static_entry (27);
      break;
    case HTTP_STATUS_SERVICE_UNAVAILABLE:
      encode_static_entry (28);
      break;
    case HTTP_STATUS_CONTINUE:
      encode_static_entry (63);
      break;
    case HTTP_STATUS_NO_CONTENT:
      encode_static_entry (64);
      break;
    case HTTP_STATUS_PARTIAL_CONTENT:
      encode_static_entry (65);
      break;
    case HTTP_STATUS_FOUND:
      encode_static_entry (66);
      break;
    case HTTP_STATUS_BAD_REQUEST:
      encode_static_entry (67);
      break;
    case HTTP_STATUS_FORBIDDEN:
      encode_static_entry (68);
      break;
    case HTTP_STATUS_MISDIRECTED_REQUEST:
      encode_static_entry (69);
      break;
    case HTTP_STATUS_TOO_EARLY:
      encode_static_entry (70);
      break;
    case HTTP_STATUS_INTERNAL_ERROR:
      encode_static_entry (71);
      break;
    default:
      orig_len = vec_len (dst);
      vec_add2 (dst, a, 5);
      *a = 0x50;
      b = hpack_encode_int (a, 24, 4);
      b = qpack_encode_string (b, (const u8 *) http_status_code_str[sc], 3, 8);
      actual_size = b - a;
      vec_set_len (dst, orig_len + actual_size);
      break;
    }
  return dst;
}

static u8 *
qpack_encode_content_len (u8 *dst, u64 content_len)
{
  u8 digit_buffer[20];
  u8 *d = digit_buffer + sizeof (digit_buffer);
  u8 *a;

  /* save some cycles and encode "content-length: 0" directly */
  if (content_len == 0)
    {
      vec_add2 (dst, a, 1);
      /* static table index 4 */
      *a = 0xC4;
      return dst;
    }

  do
    {
      *--d = '0' + content_len % 10;
      content_len /= 10;
    }
  while (content_len);

  dst = qpack_encode_header (dst, HTTP_HEADER_CONTENT_LENGTH, d,
			     digit_buffer + sizeof (digit_buffer) - d, 0);
  return dst;
}

static u8 *
qpack_encode_method (u8 *dst, http_req_method_t method)
{
  u8 *a;

  switch (method)
    {
    case HTTP_REQ_CONNECT:
      encode_static_entry (15);
      break;
    case HTTP_REQ_GET:
      encode_static_entry (17);
      break;
    case HTTP_REQ_POST:
      encode_static_entry (20);
      break;
    case HTTP_REQ_PUT:
      encode_static_entry (21);
      break;
    default:
      ASSERT (0);
      break;
    }
  return dst;
}

static u8 *
qpack_encode_scheme (u8 *dst, http_url_scheme_t scheme)
{
  u8 *a;

  switch (scheme)
    {
    case HTTP_URL_SCHEME_HTTP:
      encode_static_entry (22);
      break;
    case HTTP_URL_SCHEME_HTTPS:
      encode_static_entry (23);
      break;
    default:
      ASSERT (0);
      break;
    }
  return dst;
}

static u8 *
qpack_encode_path (u8 *dst, u8 *path, u32 path_len)
{
  u8 *a, *b;
  u32 orig_len, actual_size;

  if (path_len == 1 && path[0] == '/')
    {
      encode_static_entry (1);
    }
  else
    {
      orig_len = vec_len (dst);
      vec_add2 (dst, a, path_len + 1 + HPACK_ENCODED_INT_MAX_LEN);
      b = a;
      *b++ = 0x51;
      b = qpack_encode_string (b, path, path_len, 8);
      actual_size = b - a;
      vec_set_len (dst, orig_len + actual_size);
    }

  return dst;
}

static u8 *
qpack_encode_authority (u8 *dst, u8 *authority, u32 authority_len)
{
  u8 *a, *b;
  u32 orig_len, actual_size;

  orig_len = vec_len (dst);
  vec_add2 (dst, a, authority_len + 1 + HPACK_ENCODED_INT_MAX_LEN);
  b = a;
  *b++ = 0x50;
  b = qpack_encode_string (b, authority, authority_len, 8);
  actual_size = b - a;
  vec_set_len (dst, orig_len + actual_size);

  return dst;
}

static inline hpack_error_t
qpack_parse_headers_prefix (u8 **src, u8 *end, qpack_decoder_ctx_t *ctx)
{
  u8 *p;

  ASSERT (*src < end);
  p = *src;

  ctx->req_insert_count = hpack_decode_int (&p, end, 8);
  if (ctx->req_insert_count == HPACK_INVALID_INT || p == end)
    return HPACK_ERROR_COMPRESSION;

  ctx->delta_base_sign = *p & 0x80;
  ctx->delta_base = hpack_decode_int (&p, end, 7);
  if (ctx->req_insert_count == HPACK_INVALID_INT)
    return HPACK_ERROR_COMPRESSION;

  *src = p;
  return HPACK_ERROR_NONE;
}

__clib_export http3_error_t
qpack_parse_request (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		     hpack_request_control_data_t *control_data,
		     http_field_line_t **headers,
		     qpack_decoder_ctx_t *decoder_ctx)
{
  hpack_error_t rv;
  u8 *p, *end;

  if (src_len < 3)
    return HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;

  p = src;
  end = src + src_len;

  /* encoded field section prefix */
  rv = qpack_parse_headers_prefix (&p, end, decoder_ctx);
  if (rv || p == end)
    return hpack_error_to_http3_error[rv];

  rv = hpack_decode_request (p, end, dst, dst_len, control_data, headers,
			     decoder_ctx, (void *) qpack_decode_header);
  return hpack_error_to_http3_error[rv];
}

__clib_export http3_error_t
qpack_parse_response (u8 *src, u32 src_len, u8 *dst, u32 dst_len,
		      hpack_response_control_data_t *control_data,
		      http_field_line_t **headers,
		      qpack_decoder_ctx_t *decoder_ctx)
{
  hpack_error_t rv;
  u8 *p, *end;

  if (src_len < 3)
    return HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;

  p = src;
  end = src + src_len;

  /* encoded field section prefix */
  rv = qpack_parse_headers_prefix (&p, end, decoder_ctx);
  if (rv || p == end)
    return hpack_error_to_http3_error[rv];

  rv = hpack_decode_response (p, end, dst, dst_len, control_data, headers,
			      decoder_ctx, qpack_decode_header);
  return hpack_error_to_http3_error[rv];
}

__clib_export void
qpack_serialize_response (u8 *app_headers, u32 app_headers_len,
			  hpack_response_control_data_t *control_data,
			  u8 **dst)
{
  u8 *a, *p, *end;

  p = *dst;
  /* encoded field section prefix, two zero bytes because we don't use dynamic
   * table */
  vec_add2 (p, a, 2);
  a[0] = 0;
  a[1] = 0;

  /* status code must be first since it is pseudo-header */
  p = qpack_encode_status_code (p, control_data->sc);

  /* server name */
  p = qpack_encode_header (p, HTTP_HEADER_SERVER, control_data->server_name,
			   control_data->server_name_len, 0);

  /* date */
  p = qpack_encode_header (p, HTTP_HEADER_DATE, control_data->date, control_data->date_len, 0);

  /* content length if any */
  if (control_data->content_len != HPACK_ENCODER_SKIP_CONTENT_LEN)
    p = qpack_encode_content_len (p, control_data->content_len);

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
	  p = qpack_encode_custom_header (p, name->token, name->len, value->token, value->len,
					  name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  http_app_header_t *header;
	  header = (http_app_header_t *) app_headers;
	  app_headers += sizeof (http_app_header_t) + header->value.len;
	  p = qpack_encode_header (p, header->name.name, header->value.token, header->value.len,
				   name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
    }

  *dst = p;
}

__clib_export void
qpack_serialize_request (u8 *app_headers, u32 app_headers_len,
			 hpack_request_control_data_t *control_data, u8 **dst)
{
  u8 *a, *p, *end;

  p = *dst;
  /* encoded field section prefix, two zero bytes because we don't use dynamic
   * table */
  vec_add2 (p, a, 2);
  a[0] = 0;
  a[1] = 0;

  /* pseudo-headers must go first */
  p = qpack_encode_method (p, control_data->method);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED)
    p = qpack_encode_scheme (p, control_data->scheme);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
    p = qpack_encode_path (p, control_data->path, control_data->path_len);

  if (control_data->parsed_bitmap & HPACK_PSEUDO_HEADER_PROTOCOL_PARSED)
    p = qpack_encode_custom_header (p, (u8 *) ":protocol", 9, control_data->protocol,
				    control_data->protocol_len, 0);

  p = qpack_encode_authority (p, control_data->authority,
			      control_data->authority_len);

  /* user agent */
  if (control_data->user_agent_len)
    p = qpack_encode_header (p, HTTP_HEADER_USER_AGENT, control_data->user_agent,
			     control_data->user_agent_len, 0);

  /* content length if any */
  if (control_data->content_len != HPACK_ENCODER_SKIP_CONTENT_LEN)
    p = qpack_encode_content_len (p, control_data->content_len);

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
	  p = qpack_encode_custom_header (p, name->token, name->len, value->token, value->len,
					  name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  http_app_header_t *header;
	  header = (http_app_header_t *) app_headers;
	  app_headers += sizeof (http_app_header_t) + header->value.len;
	  p = qpack_encode_header (p, header->name.name, header->value.token, header->value.len,
				   name->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
    }

  *dst = p;
}
