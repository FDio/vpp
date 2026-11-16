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

static __clib_noinline u8
_http_memcmp_case (const char *actual, const char *expected, uword len)
{
  ASSERT (actual != 0);
#ifdef CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
  /* Bounded partial loads also handle short names at the end of a buffer. */
  while (len)
    {
      uword n = clib_min (len, 16);
      u8x16 a = u8x16_load_partial ((u8 *) actual, n);
      u8x16 e = u8x16_load_partial ((u8 *) expected, n);
      a |= ((a >= u8x16_splat ('A')) & (a <= u8x16_splat ('Z'))) & u8x16_splat (0x20);
      if (!u8x16_is_equal (a, e))
	return 1;
      actual += n;
      expected += n;
      len -= n;
    }
#else
  /* Keep the fallback small on targets without the vector load helpers. */
  for (uword i = 0; i < len; i++)
    {
      u8 a = actual[i];
      if (a >= 'A' && a <= 'Z')
	a |= 0x20;
      if (a != (u8) expected[i])
	return 1;
    }
#endif
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[3] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[7] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[12] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[14] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[16] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[21] | 0x20)
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
      switch ((u8) name[0] | 0x20)
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
      switch ((u8) name[28] | 0x20)
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

static inline http_token_t *
_http_connection_option_add (char *start, char *end, uword *known, http_token_t *custom)
{
  if (start)
    {
      http_token_t option = { start, end - start };
      http_header_name_t name = http_lookup_header_name (option.base, option.len);
      if (name != HTTP_HEADER_UNKNOWN)
	clib_bitmap_set_no_check (known, name, 1);
      else
	vec_add1 (custom, option);
    }
  return custom;
}

static __clib_noinline http_token_t *
_http_connection_options_parse (char *p, char *end, uword *known, http_token_t *custom)
{
#ifdef CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
  /* Keep token bounds across vector chunks, whitespace trims element, comma ends it, so embedded
   * whitespace cannot create extra names */
  char *start = 0, *last = 0;
  while (p < end)
    {
      uword n = clib_min (end - p, 16);
      u8x16 v = u8x16_load_partial ((u8 *) p, n);
      u32 valid = pow2_mask (n);
      u8x16 comma_lanes = v == u8x16_splat (',');
      u32 special =
	u8x16_msb_mask (comma_lanes | (v == u8x16_splat (' ')) | (v == u8x16_splat ('\t'))) & valid;
      if (!special)
	{
	  if (!start)
	    start = p;
	  last = p + n;
	  p += n;
	  continue;
	}
      u32 commas = u8x16_msb_mask (comma_lanes) & valid;
      u32 nonspace = valid & ~special;
      while (start || nonspace)
	{
	  if (!start)
	    {
	      start = p + count_trailing_zeros (nonspace);
	      commas &= ~pow2_mask (count_trailing_zeros (nonspace));
	    }
	  if (!commas)
	    {
	      if (nonspace)
		last = p + min_log2 (nonspace) + 1;
	      break;
	    }
	  u32 comma = count_trailing_zeros (commas);
	  u32 segment = nonspace & pow2_mask (comma);
	  if (segment)
	    last = p + min_log2 (segment) + 1;
	  custom = _http_connection_option_add (start, last, known, custom);
	  start = last = 0;
	  u32 tail = ~pow2_mask (comma + 1);
	  commas &= tail;
	  nonspace &= tail;
	}
      p += n;
    }
  custom = _http_connection_option_add (start, last, known, custom);
#else
  while (p < end)
    {
      while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
	p++;
      char *start = p;
      while (p < end && *p != ',')
	p++;
      char *last = p;
      while (last > start && (last[-1] == ' ' || last[-1] == '\t'))
	last--;
      if (last > start)
	custom = _http_connection_option_add (start, last, known, custom);
    }
#endif
  return custom;
}

static __clib_noinline void
_http_copy_header_name_lowercase (u8 *dst, const u8 *src, uword len)
{
#ifdef CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
  /* Overlap the final accesses to keep every load and store within the name. */
  if (len >= 16)
    {
      for (;;)
	{
	  u8x16 v = u8x16_load_unaligned ((void *) src);
	  v |= ((v >= u8x16_splat ('A')) & (v <= u8x16_splat ('Z'))) & u8x16_splat (0x20);
	  u8x16_store_unaligned (v, dst);
	  if (len == 16)
	    break;
	  uword step = clib_min (len - 16, 16);
	  src += step;
	  dst += step;
	  len -= step;
	}
    }
  else if (len >= 8)
    {
      u8x16 v = (u8x16) (u64x2) { *(u64u *) src, *(u64u *) (src + len - 8) };
      v |= ((v >= u8x16_splat ('A')) & (v <= u8x16_splat ('Z'))) & u8x16_splat (0x20);
      *(u64u *) dst = ((u64x2) v)[0];
      *(u64u *) (dst + len - 8) = ((u64x2) v)[1];
    }
  else if (len >= 4)
    {
      u8x16 v = (u8x16) (u32x4) { *(u32u *) src, *(u32u *) (src + len - 4), 0, 0 };
      v |= ((v >= u8x16_splat ('A')) & (v <= u8x16_splat ('Z'))) & u8x16_splat (0x20);
      *(u32u *) dst = ((u32x4) v)[0];
      *(u32u *) (dst + len - 4) = ((u32x4) v)[1];
    }
  else if (len >= 2)
    {
      u8x16 v = (u8x16) (u16x8) { *(u16u *) src, *(u16u *) (src + len - 2), 0, 0, 0, 0, 0, 0 };
      v |= ((v >= u8x16_splat ('A')) & (v <= u8x16_splat ('Z'))) & u8x16_splat (0x20);
      *(u16u *) dst = ((u16x8) v)[0];
      *(u16u *) (dst + len - 2) = ((u16x8) v)[1];
    }
  else if (len)
    {
      u8 c = src[0];
      dst[0] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
#else
  for (uword i = 0; i < len; i++)
    {
      u8 c = src[i];
      dst[i] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
#endif
}

/**
 * Headers processing for intermediary app.
 *
 * Convert format used on receive side to format ready for sending. Headers used in http transport
 * layer, hop-by-hop headers and headers named by Connection fields are excluded. If needed
 * additional headers can be added by @c http_add_header and @c http_add_custom_header.
 * Copied custom field names are normalized to lowercase for HTTP/2 and HTTP/3.
 *
 * @param msg    HTTP transport message metadata.
 * @param rx_buf Buffer which store rx headers received from http transport.
 * @param tx_ctx Headers list context for tx.
 *
 * @return @c 0 if in case of success, @c -1 otherwise (buffer in @c tx_ctx is not big enough).
 */
static inline int
http_headers_rx_to_tx (http_msg_t msg, const u8 *rx_buf, http_headers_ctx_t *tx_ctx)
{
  http_field_line_t *field_lines, *field_line;
  http_token_t name, value;
  http_token_t *connection_options = 0;
  uword connection_headers[(HTTP_HEADER_UNKNOWN + uword_bits - 1) / uword_bits] = {};
  http_header_name_t header_name;
  http_field_line_flags_t flags;
  u32 i;
  int rv = 0;

  field_lines = uword_to_pointer (msg.data.headers_ctx, http_field_line_t *);
  /* Collect all options first, nominated fields may precede Connection. */
  vec_foreach (field_line, field_lines)
    {
      char *p, *end;

      if (!http_token_is_case ((const char *) rx_buf + field_line->name_offset,
			       field_line->name_len, http_token_lit ("connection")))
	continue;

      p = (char *) rx_buf + field_line->value_offset;
      end = p + field_line->value_len;
      connection_options =
	_http_connection_options_parse (p, end, connection_headers, connection_options);
    }

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
	  if ((flags & (HTTP_FIELD_LINE_F_INTERNAL | HTTP_FIELD_LINE_F_HOP_BY_HOP)) ||
	      clib_bitmap_get_no_check (connection_headers, header_name))
	    continue;
	  rv = http_add_header2 (tx_ctx, header_name, value.base, value.len,
				 field_line->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	}
      else
	{
	  for (i = 0; i < vec_len (connection_options); i++)
	    if (http_token_is_case (name.base, name.len, connection_options[i].base,
				    connection_options[i].len))
	      break;
	  if (i < vec_len (connection_options))
	    continue;

	  u32 name_offset = tx_ctx->tail_offset;
	  rv = http_add_custom_header2 (tx_ctx, name.base, name.len, value.base, value.len,
					field_line->flags & HTTP_FIELD_LINE_F_NEVER_INDEX);
	  if (!rv)
	    {
	      u8 *tx_name = tx_ctx->buf + name_offset + sizeof (http_app_header_name_t);
	      /* Read RX rather than reloading the freshly copied, unaligned TX name. */
	      _http_copy_header_name_lowercase (tx_name, (const u8 *) name.base, name.len);
	    }
	}
      if (rv)
	break;
    }
  vec_free (connection_options);
  return rv;
}

#endif /* SRC_PLUGINS_HTTP_HTTP_HEADER_NAMES_H_ */
