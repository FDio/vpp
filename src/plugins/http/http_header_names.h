/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_
#define SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_

#include <http/http.h>

typedef struct http_header_name_token_
{
  http_token_t buf;
  http_field_line_flags_t flags;
} http_header_name_token_t;

static http_header_name_token_t http_header_names[] = {
#define _(sym, str_canonical, str_lower, hpack_index, flags)                                       \
  { { http_token_lit (str_canonical) }, flags },
  foreach_http_header_name
#undef _
};

#define http_header_name_token(e) http_header_names[e].buf.base, http_header_names[e].buf.len

#define http_header_name_str(e) http_header_names[e].buf.base

#define http_header_name_flags(e) http_header_names[e].flags

static u8
_http_memcmp_case (const char *actual, const char *expected, uword len)
{
  uword i, last_a = 0, last_e = 0;
  uword *a, *e;
  ASSERT (actual != 0);

  i = len;
  a = (uword *) actual;
  e = (uword *) expected;
  while (i >= sizeof (uword))
    {
      if (http_tolower_word (*a) != *e)
	return 1;
      a++;
      e++;
      i -= sizeof (uword);
    }
  if (i > 0)
    {
      clib_memcpy_fast (&last_a, a, i);
      clib_memcpy_fast (&last_e, e, i);
      if (http_tolower_word (last_a) != last_e)
	return 1;
    }
  return 0;
}

static http_header_name_t
http_lookup_header_name (const char *name, uword name_len)
{
  switch (name_len)
    {
    case 2:
      if (!_http_memcmp_case (name, "te", 2))
	return HTTP_HEADER_TE;
      break;
    case 3:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "ge", 2))
	    return HTTP_HEADER_AGE;
	  break;
	case 'v':
	  if (!_http_memcmp_case (name + 1, "ia", 2))
	    return HTTP_HEADER_VIA;
	  break;
	}
      break;
    case 4:
      switch (tolower (name[3]))
	{
	case 'n':
	  if (!_http_memcmp_case (name, "alp", 3))
	    return HTTP_HEADER_ALPN;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name, "dat", 3))
	    return HTTP_HEADER_DATE;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name, "dpo", 3))
	    return HTTP_HEADER_DPOP;
	  break;
	case 'g':
	  if (!_http_memcmp_case (name, "eta", 3))
	    return HTTP_HEADER_ETAG;
	  break;
	case 'm':
	  if (!_http_memcmp_case (name, "fro", 3))
	    return HTTP_HEADER_FROM;
	  break;
	case 't':
	  if (!_http_memcmp_case (name, "hos", 3))
	    return HTTP_HEADER_HOST;
	  break;
	case 'k':
	  if (!_http_memcmp_case (name, "lin", 3))
	    return HTTP_HEADER_LINK;
	  break;
	case 'y':
	  if (!_http_memcmp_case (name, "var", 3))
	    return HTTP_HEADER_VARY;
	  break;
	}
      break;
    case 5:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "llow", 4))
	    return HTTP_HEADER_ALLOW;
	  break;
	case 'c':
	  if (!_http_memcmp_case (name + 1, "lose", 4))
	    return HTTP_HEADER_CLOSE;
	  break;
	case 'r':
	  if (!_http_memcmp_case (name + 1, "ange", 4))
	    return HTTP_HEADER_RANGE;
	  break;
	}
      break;
    case 6:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "ccept", 5))
	    return HTTP_HEADER_ACCEPT;
	  break;
	case 'c':
	  if (!_http_memcmp_case (name + 1, "ookie", 5))
	    return HTTP_HEADER_COOKIE;
	  break;
	case 'd':
	  if (!_http_memcmp_case (name + 1, "igest", 5))
	    return HTTP_HEADER_DIGEST;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name + 1, "xpect", 5))
	    return HTTP_HEADER_EXPECT;
	  break;
	case 'o':
	  if (!_http_memcmp_case (name + 1, "rigin", 5))
	    return HTTP_HEADER_ORIGIN;
	  break;
	case 's':
	  if (!_http_memcmp_case (name + 1, "erver", 5))
	    return HTTP_HEADER_SERVER;
	  break;
	}
      break;
    case 7:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "lt-svc", 6))
	    return HTTP_HEADER_ALT_SVC;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name + 1, "xpires", 6))
	    return HTTP_HEADER_EXPIRES;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name + 1, "urpose", 6))
	    return HTTP_HEADER_PURPOSE;
	  break;
	case 'r':
	  if (!_http_memcmp_case (name + 1, "eferer", 6))
	    return HTTP_HEADER_REFERER;
	  if (!_http_memcmp_case (name + 1, "efresh", 6))
	    return HTTP_HEADER_REFRESH;
	  break;
	case 't':
	  if (!_http_memcmp_case (name + 1, "railer", 6))
	    return HTTP_HEADER_TRAILER;
	  break;
	case 'u':
	  if (!_http_memcmp_case (name + 1, "pgrade", 6))
	    return HTTP_HEADER_UPGRADE;
	  break;
	}
      break;
    case 8:
      switch (tolower (name[7]))
	{
	case 'd':
	  if (!_http_memcmp_case (name, "alt-use", 7))
	    return HTTP_HEADER_ALT_USED;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name, "cdn-loo", 7))
	    return HTTP_HEADER_CDN_LOOP;
	  break;
	case 'h':
	  if (!_http_memcmp_case (name, "if-matc", 7))
	    return HTTP_HEADER_IF_MATCH;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name, "if-rang", 7))
	    return HTTP_HEADER_IF_RANGE;
	  break;
	case 'n':
	  if (!_http_memcmp_case (name, "locatio", 7))
	    return HTTP_HEADER_LOCATION;
	  break;
	case 'y':
	  if (!_http_memcmp_case (name, "priorit", 7))
	    return HTTP_HEADER_PRIORITY;
	  break;
	}
      break;
    case 9:
      switch (tolower (name[0]))
	{
	case 'e':
	  if (!_http_memcmp_case (name + 1, "xpect-ct", 8))
	    return HTTP_HEADER_EXPECT_CT;
	  break;
	case 'f':
	  if (!_http_memcmp_case (name + 1, "orwarded", 8))
	    return HTTP_HEADER_FORWARDED;
	  break;
	case 's':
	  if (!_http_memcmp_case (name + 1, "ignature", 8))
	    return HTTP_HEADER_SIGNATURE;
	  break;
	}
      break;
    case 10:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "lternates", 9))
	    return HTTP_HEADER_ALTERNATES;
	  break;
	case 'c':
	  if (!_http_memcmp_case (name + 1, "onnection", 9))
	    return HTTP_HEADER_CONNECTION;
	  break;
	case 'd':
	  if (!_http_memcmp_case (name + 1, "pop-nonce", 9))
	    return HTTP_HEADER_DPOP_NONCE;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name + 1, "arly-data", 9))
	    return HTTP_HEADER_EARLY_DATA;
	  break;
	case 'k':
	  if (!_http_memcmp_case (name + 1, "eep-alive", 9))
	    return HTTP_HEADER_KEEP_ALIVE;
	  break;
	case 's':
	  if (!_http_memcmp_case (name + 1, "et-cookie", 9))
	    return HTTP_HEADER_SET_COOKIE;
	  break;
	case 'u':
	  if (!_http_memcmp_case (name + 1, "ser-agent", 9))
	    return HTTP_HEADER_USER_AGENT;
	  break;
	}
      break;
    case 11:
      switch (tolower (name[0]))
	{
	case 'c':
	  if (!_http_memcmp_case (name + 1, "lient-cert", 10))
	    return HTTP_HEADER_CLIENT_CERT;
	  break;
	case 'r':
	  if (!_http_memcmp_case (name + 1, "epr-digest", 10))
	    return HTTP_HEADER_REPR_DIGEST;
	  if (!_http_memcmp_case (name + 1, "etry-after", 10))
	    return HTTP_HEADER_RETRY_AFTER;
	  break;
	}
      break;
    case 12:
      switch (tolower (name[0]))
	{
	case 'c':
	  if (!_http_memcmp_case (name + 1, "ache-status", 11))
	    return HTTP_HEADER_CACHE_STATUS;
	  if (!_http_memcmp_case (name + 1, "ontent-type", 11))
	    return HTTP_HEADER_CONTENT_TYPE;
	  break;
	case 'm':
	  if (!_http_memcmp_case (name + 1, "ax-forwards", 11))
	    return HTTP_HEADER_MAX_FORWARDS;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name + 1, "roxy-status", 11))
	    return HTTP_HEADER_PROXY_STATUS;
	  break;
	}
      break;
    case 13:
      switch (tolower (name[12]))
	{
	case 's':
	  if (!_http_memcmp_case (name, "accept-range", 12))
	    return HTTP_HEADER_ACCEPT_RANGES;
	  break;
	case 'n':
	  if (!_http_memcmp_case (name, "authorizatio", 12))
	    return HTTP_HEADER_AUTHORIZATION;
	  break;
	case 'l':
	  if (!_http_memcmp_case (name, "cache-contro", 12))
	    return HTTP_HEADER_CACHE_CONTROL;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name, "content-rang", 12))
	    return HTTP_HEADER_CONTENT_RANGE;
	  break;
	case 'h':
	  if (!_http_memcmp_case (name, "if-none-matc", 12))
	    return HTTP_HEADER_IF_NONE_MATCH;
	  break;
	case 'd':
	  if (!_http_memcmp_case (name, "last-modifie", 12))
	    return HTTP_HEADER_LAST_MODIFIED;
	  break;
	}
      break;
    case 14:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "ccept-charset", 13))
	    return HTTP_HEADER_ACCEPT_CHARSET;
	  break;
	case 'c':
	  if (!_http_memcmp_case (name + 1, "ontent-digest", 13))
	    return HTTP_HEADER_CONTENT_DIGEST;
	  if (!_http_memcmp_case (name + 1, "ontent-length", 13))
	    return HTTP_HEADER_CONTENT_LENGTH;
	  break;
	}
      break;
    case 15:
      switch (tolower (name[14]))
	{
	case 'g':
	  if (!_http_memcmp_case (name, "accept-encodin", 14))
	    return HTTP_HEADER_ACCEPT_ENCODING;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name, "accept-languag", 14))
	    return HTTP_HEADER_ACCEPT_LANGUAGE;
	  break;
	case 't':
	  if (!_http_memcmp_case (name, "signature-inpu", 14))
	    return HTTP_HEADER_SIGNATURE_INPUT;
	  break;
	case 'r':
	  if (!_http_memcmp_case (name, "x-forwarded-fo", 14))
	    return HTTP_HEADER_X_FORWARDED_FOR;
	  break;
	case 's':
	  if (!_http_memcmp_case (name, "x-frame-option", 14))
	    return HTTP_HEADER_X_FRAME_OPTIONS;
	  break;
	}
      break;
    case 16:
      switch (tolower (name[0]))
	{
	case 'c':
	  if (!_http_memcmp_case (name + 1, "apsule-protocol", 15))
	    return HTTP_HEADER_CAPSULE_PROTOCOL;
	  if (!_http_memcmp_case (name + 1, "ontent-encoding", 15))
	    return HTTP_HEADER_CONTENT_ENCODING;
	  if (!_http_memcmp_case (name + 1, "ontent-language", 15))
	    return HTTP_HEADER_CONTENT_LANGUAGE;
	  if (!_http_memcmp_case (name + 1, "ontent-location", 15))
	    return HTTP_HEADER_CONTENT_LOCATION;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name + 1, "roxy-connection", 15))
	    return HTTP_HEADER_PROXY_CONNECTION;
	  break;
	case 'w':
	  if (!_http_memcmp_case (name + 1, "ant-repr-digest", 15))
	    return HTTP_HEADER_WANT_REPR_DIGEST;
	  if (!_http_memcmp_case (name + 1, "ww-authenticate", 15))
	    return HTTP_HEADER_WWW_AUTHENTICATE;
	  break;
	case 'x':
	  if (!_http_memcmp_case (name + 1, "-xss-protection", 15))
	    return HTTP_HEADER_X_XSS_PROTECTION;
	  break;
	}
      break;
    case 17:
      switch (tolower (name[16]))
	{
	case 'l':
	  if (!_http_memcmp_case (name, "cdn-cache-contro", 16))
	    return HTTP_HEADER_CDN_CACHE_CONTROL;
	  break;
	case 'n':
	  if (!_http_memcmp_case (name, "client-cert-chai", 16))
	    return HTTP_HEADER_CLIENT_CERT_CHAIN;
	  break;
	case 'e':
	  if (!_http_memcmp_case (name, "if-modified-sinc", 16))
	    return HTTP_HEADER_IF_MODIFIED_SINCE;
	  break;
	case 'g':
	  if (!_http_memcmp_case (name, "transfer-encodin", 16))
	    return HTTP_HEADER_TRANSFER_ENCODING;
	  break;
	}
      break;
    case 18:
      if (!_http_memcmp_case (name, "proxy-authenticate", 18))
	return HTTP_HEADER_PROXY_AUTHENTICATE;
      break;
    case 19:
      switch (tolower (name[0]))
	{
	case 'a':
	  if (!_http_memcmp_case (name + 1, "uthentication-info", 18))
	    return HTTP_HEADER_AUTHENTICATION_INFO;
	  break;
	case 'c':
	  if (!_http_memcmp_case (name + 1, "ontent-disposition", 18))
	    return HTTP_HEADER_CONTENT_DISPOSITION;
	  break;
	case 'i':
	  if (!_http_memcmp_case (name + 1, "f-unmodified-since", 18))
	    return HTTP_HEADER_IF_UNMODIFIED_SINCE;
	  break;
	case 'p':
	  if (!_http_memcmp_case (name + 1, "roxy-authorization", 18))
	    return HTTP_HEADER_PROXY_AUTHORIZATION;
	  break;
	case 't':
	  if (!_http_memcmp_case (name + 1, "iming-allow-origin", 18))
	    return HTTP_HEADER_TIMING_ALLOW_ORIGIN;
	  break;
	case 'w':
	  if (!_http_memcmp_case (name + 1, "ant-content-digest", 18))
	    return HTTP_HEADER_WANT_CONTENT_DIGEST;
	  break;
	}
      break;
    case 22:
      switch (tolower (name[21]))
	{
	case 'e':
	  if (!_http_memcmp_case (name, "access-control-max-ag", 21))
	    return HTTP_HEADER_ACCESS_CONTROL_MAX_AGE;
	  break;
	case 'l':
	  if (!_http_memcmp_case (name, "authentication-contro", 21))
	    return HTTP_HEADER_AUTHENTICATION_CONTROL;
	  break;
	case 's':
	  if (!_http_memcmp_case (name, "x-content-type-option", 21))
	    return HTTP_HEADER_X_CONTENT_TYPE_OPTIONS;
	  break;
	}
      break;
    case 23:
      if (!_http_memcmp_case (name, "content-security-policy", 23))
	return HTTP_HEADER_CONTENT_SECURITY_POLICY;
      break;
    case 25:
      switch (tolower (name[0]))
	{
	case 'p':
	  if (!_http_memcmp_case (name + 1, "roxy-authentication-info", 24))
	    return HTTP_HEADER_PROXY_AUTHENTICATION_INFO;
	  break;
	case 's':
	  if (!_http_memcmp_case (name + 1, "trict-transport-security", 24))
	    return HTTP_HEADER_STRICT_TRANSPORT_SECURITY;
	  break;
	case 'u':
	  if (!_http_memcmp_case (name + 1, "pgrade-insecure-requests", 24))
	    return HTTP_HEADER_UPGRADE_INSECURE_REQUESTS;
	  break;
	}
      break;
    case 27:
      if (!_http_memcmp_case (name, "access-control-allow-origin", 27))
	return HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN;
      break;
    case 28:
      if (!_http_memcmp_case (name, "access-control-allow-headers", 28))
	return HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS;
      if (!_http_memcmp_case (name, "access-control-allow-methods", 28))
	return HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS;
      break;
    case 29:
      switch (tolower (name[28]))
	{
	case 's':
	  if (!_http_memcmp_case (name, "access-control-expose-header", 28))
	    return HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS;
	  break;
	case 'd':
	  if (!_http_memcmp_case (name, "access-control-request-method", 28))
	    return HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD;
	  break;
	}
      break;
    case 30:
      if (!_http_memcmp_case (name, "access-control-request-headers", 30))
	return HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS;
      break;
    case 32:
      if (!_http_memcmp_case (name, "access-control-allow-credentials", 32))
	return HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS;
      break;
    }
  return HTTP_HEADER_UNKNOWN;
}

static inline void
http_headers_rx_to_tx (http_msg_t msg, const u8 *rx_buf, http_headers_ctx_t *ctx)
{
  http_field_line_t *field_lines, *field_line;
  http_token_t name, value;
  http_header_name_t header_name;
  http_field_line_flags_t flags;

  field_lines = uword_to_pointer (msg.data.headers_ctx, http_field_line_t *);
  vec_foreach (field_line, field_lines)
    {
      name.base = (char *) (rx_buf + field_line->name_offset);
      name.len = field_line->name_len;
      value.base = (char *) (rx_buf + field_line->value_offset);
      value.len = field_line->value_len;
      header_name = http_lookup_header_name (name.base, name.len);
      if (header_name != HTTP_HEADER_UNKNOWN)
	{
	  flags = http_header_name_flags (header_name);
	  if (flags & (HTTP_FIELD_LINE_F_INTERNAL | HTTP_FIELD_LINE_F_HOP_BY_HOP))
	    continue;
	  http_add_header2 (ctx, header_name, value.base, value.len,
			    field_line->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  http_add_custom_header2 (ctx, name.base, name.len, value.base, value.len,
				   field_line->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
    }
}

#endif /* SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_ */
