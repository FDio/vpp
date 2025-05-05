/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_H_
#define SRC_PLUGINS_HTTP_HTTP_H_

#include <ctype.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip46_address.h>

#define HTTP_DEBUG 3

#if HTTP_DEBUG
#define HTTP_DBG(_lvl, _fmt, _args...)                                        \
  if (_lvl <= HTTP_DEBUG)                                                     \
  clib_warning (_fmt, ##_args)
#else
#define HTTP_DBG(_lvl, _fmt, _args...)
#endif

typedef enum http_udp_tunnel_mode_
{
  HTTP_UDP_TUNNEL_CAPSULE, /**< app receive raw capsule */
  HTTP_UDP_TUNNEL_DGRAM,   /**< convert capsule to datagram (zc proxy) */
} http_udp_tunnel_mode_t;

typedef struct transport_endpt_cfg_http
{
  u32 timeout; /**< HTTP session timeout in seconds */
  http_udp_tunnel_mode_t udp_tunnel_mode; /**< connect-udp mode */
} transport_endpt_cfg_http_t;

typedef struct
{
  char *base;
  uword len;
} http_token_t;

#define http_token_lit(s) (s), sizeof (s) - 1

typedef enum http_req_method_
{
  HTTP_REQ_GET = 0,
  HTTP_REQ_POST,
  HTTP_REQ_CONNECT,
  HTTP_REQ_UNKNOWN, /* for internal use */
} http_req_method_t;

typedef enum http_msg_type_
{
  HTTP_MSG_REQUEST,
  HTTP_MSG_REPLY
} http_msg_type_t;

#define foreach_http_content_type                                             \
  _ (APP_7Z, ".7z", "application/x-7z-compressed")                            \
  _ (APP_DOC, ".doc", "application/msword")                                   \
  _ (APP_DOCX, ".docx",                                                       \
     "application/vnd.openxmlformats-"                                        \
     "officedocument.wordprocessingml.document")                              \
  _ (APP_EPUB, ".epub", "application/epub+zip")                               \
  _ (APP_FONT, ".eot", "application/vnd.ms-fontobject")                       \
  _ (APP_JAR, ".jar", "application/java-archive")                             \
  _ (APP_JSON, ".json", "application/json")                                   \
  _ (APP_JSON_LD, ".jsonld", "application/ld+json")                           \
  _ (APP_MPKG, ".mpkg", "application/vnd.apple.installer+xml")                \
  _ (APP_ODP, ".odp", "application/vnd.oasis.opendocument.presentation")      \
  _ (APP_ODS, ".ods", "application/vnd.oasis.opendocument.spreadsheet")       \
  _ (APP_ODT, ".odt", "application/vnd.oasis.opendocument.text")              \
  _ (APP_OGX, ".ogx", "application/ogg")                                      \
  _ (APP_PDF, ".pdf", "application/pdf")                                      \
  _ (APP_PHP, ".php", "application/x-httpd-php")                              \
  _ (APP_PPT, ".ppt", "application/vnd.ms-powerpoint")                        \
  _ (APP_PPTX, ".pptx", "application/vnd.ms-powerpoint")                      \
  _ (APP_RAR, ".rar", "application/vnd.rar")                                  \
  _ (APP_RTF, ".rtf", "application/rtf")                                      \
  _ (APP_SH, ".sh", "application/x-sh")                                       \
  _ (APP_TAR, ".tar", "application/x-tar")                                    \
  _ (APP_VSD, ".vsd", "application/vnd.visio")                                \
  _ (APP_XHTML, ".xhtml", "application/xhtml+xml")                            \
  _ (APP_XLS, ".xls", "application/vnd.ms-excel")                             \
  _ (APP_XML, ".xml", "application/xml")                                      \
  _ (APP_XSLX, ".xlsx",                                                       \
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")     \
  _ (APP_XUL, ".xul", "application/vnd.mozilla.xul+xml")                      \
  _ (APP_X_WWW_FORM_URLENCODED, ".invalid",                                   \
     "application/x-www-form-urlencoded")                                     \
  _ (APP_ZIP, ".zip", "application/zip")                                      \
  _ (AUDIO_AAC, ".aac", "audio/aac")                                          \
  _ (AUDIO_CD, ".cda", "application/x-cdf")                                   \
  _ (AUDIO_WAV, ".wav", "audio/wav")                                          \
  _ (AUDIO_WEBA, ".weba", "audio/webm")                                       \
  _ (AUDO_MIDI, ".midi", "audio/midi")                                        \
  _ (AUDO_MID, ".mid", "audo/midi")                                           \
  _ (AUDO_MP3, ".mp3", "audio/mpeg")                                          \
  _ (AUDO_OGA, ".oga", "audio/ogg")                                           \
  _ (AUDO_OPUS, ".opus", "audio/opus")                                        \
  _ (APP_OCTET_STREAM, ".bin", "application/octet-stream")                    \
  _ (BZIP2, ".bz2", "application/x-bzip2")                                    \
  _ (BZIP, ".bz", "application/x-bzip")                                       \
  _ (FONT_OTF, ".otf", "font/otf")                                            \
  _ (FONT_TTF, ".ttf", "font/ttf")                                            \
  _ (FONT_WOFF2, ".woff2", "font/woff2")                                      \
  _ (FONT_WOFF, ".woff", "font/woff")                                         \
  _ (GZIP, ".gz", "application/gzip")                                         \
  _ (IMAGE_AVIF, ".avif", "image/avif")                                       \
  _ (IMAGE_BMP, ".bmp", "image/bmp")                                          \
  _ (IMAGE_GIF, ".gif", "image/gif")                                          \
  _ (IMAGE_ICON, ".ico", "image/vnd.microsoft.icon")                          \
  _ (IMAGE_JPEG, ".jpeg", "image/jpeg")                                       \
  _ (IMAGE_JPG, ".jpg", "image/jpeg")                                         \
  _ (IMAGE_PNG, ".png", "image/png")                                          \
  _ (IMAGE_SVG, ".svg", "image/svg+xml")                                      \
  _ (IMAGE_TIFF, ".tiff", "image/tiff")                                       \
  _ (IMAGE_TIF, ".tif", "image/tiff")                                         \
  _ (IMAGE_WEBP, ".webp", "image/webp")                                       \
  _ (SCRIPT_CSH, ".csh", "application/x-csh")                                 \
  _ (TEXT_ABIWORD, ".abw", "application/x-abiword")                           \
  _ (TEXT_ARCHIVE, ".arc", "application/x-freearc")                           \
  _ (TEXT_AZW, ".azw", "application/vnd.amazon.ebook")                        \
  _ (TEXT_CALENDAR, ".ics", "text/calendar")                                  \
  _ (TEXT_CSS, ".css", "text/css")                                            \
  _ (TEXT_CSV, ".csv", "text/csv")                                            \
  _ (TEXT_HTM, ".htm", "text/html")                                           \
  _ (TEXT_HTML, ".html", "text/html")                                         \
  _ (TEXT_JS, ".js", "text/javascript")                                       \
  _ (TEXT_MJS, ".mjs", "text/javascript")                                     \
  _ (TEXT_PLAIN, ".txt", "text/plain")                                        \
  _ (VIDEO_3GP2, ".3g2", "video/3gpp2")                                       \
  _ (VIDEO_3GP, ".3gp", "video/3gpp")                                         \
  _ (VIDEO_AVI, ".avi", "video/x-msvideo")                                    \
  _ (VIDEO_MP4, ".mp4", "video/mp4")                                          \
  _ (VIDEO_MPEG, ".mpeg", "video/mpeg")                                       \
  _ (VIDEO_OGG, ".ogv", "video/ogg")                                          \
  _ (VIDEO_TS, ".ts", "video/mp2t")                                           \
  _ (VIDEO_WEBM, ".webm", "video/webm")

typedef enum http_content_type_
{
#define _(s, ext, str) HTTP_CONTENT_##s,
  foreach_http_content_type
#undef _
} http_content_type_t;

#define foreach_http_status_code                                              \
  _ (100, CONTINUE, "100 Continue")                                           \
  _ (101, SWITCHING_PROTOCOLS, "101 Switching Protocols")                     \
  _ (200, OK, "200 OK")                                                       \
  _ (201, CREATED, "201 Created")                                             \
  _ (202, ACCEPTED, "202 Accepted")                                           \
  _ (203, NON_UTHORITATIVE_INFORMATION, "203 Non-Authoritative Information")  \
  _ (204, NO_CONTENT, "204 No Content")                                       \
  _ (205, RESET_CONTENT, "205 Reset Content")                                 \
  _ (206, PARTIAL_CONTENT, "206 Partial Content")                             \
  _ (300, MULTIPLE_CHOICES, "300 Multiple Choices")                           \
  _ (301, MOVED, "301 Moved Permanently")                                     \
  _ (302, FOUND, "302 Found")                                                 \
  _ (303, SEE_OTHER, "303 See Other")                                         \
  _ (304, NOT_MODIFIED, "304 Not Modified")                                   \
  _ (305, USE_PROXY, "305 Use Proxy")                                         \
  _ (307, TEMPORARY_REDIRECT, "307 Temporary Redirect")                       \
  _ (308, PERMANENT_REDIRECT, "308 Permanent Redirect")                       \
  _ (400, BAD_REQUEST, "400 Bad Request")                                     \
  _ (401, UNAUTHORIZED, "401 Unauthorized")                                   \
  _ (402, PAYMENT_REQUIRED, "402 Payment Required")                           \
  _ (403, FORBIDDEN, "403 Forbidden")                                         \
  _ (404, NOT_FOUND, "404 Not Found")                                         \
  _ (405, METHOD_NOT_ALLOWED, "405 Method Not Allowed")                       \
  _ (406, NOT_ACCEPTABLE, "406 Not Acceptable")                               \
  _ (407, PROXY_AUTHENTICATION_REQUIRED, "407 Proxy Authentication Required") \
  _ (408, REQUEST_TIMEOUT, "408 Request Timeout")                             \
  _ (409, CONFLICT, "409 Conflict")                                           \
  _ (410, GONE, "410 Gone")                                                   \
  _ (411, LENGTH_REQUIRED, "411 Length Required")                             \
  _ (412, PRECONDITION_FAILED, "412 Precondition Failed")                     \
  _ (413, CONTENT_TOO_LARGE, "413 Content Too Large")                         \
  _ (414, URI_TOO_LONG, "414 URI Too Long")                                   \
  _ (415, UNSUPPORTED_MEDIA_TYPE, "415 Unsupported Media Type")               \
  _ (416, RANGE_NOT_SATISFIABLE, "416 Range Not Satisfiable")                 \
  _ (417, EXPECTATION_FAILED, "417 Expectation Failed")                       \
  _ (421, MISDIRECTED_REQUEST, "421 Misdirected Request")                     \
  _ (422, UNPROCESSABLE_CONTENT, "422 Unprocessable_Content")                 \
  _ (426, UPGRADE_REQUIRED, "426 Upgrade Required")                           \
  _ (500, INTERNAL_ERROR, "500 Internal Server Error")                        \
  _ (501, NOT_IMPLEMENTED, "501 Not Implemented")                             \
  _ (502, BAD_GATEWAY, "502 Bad Gateway")                                     \
  _ (503, SERVICE_UNAVAILABLE, "503 Service Unavailable")                     \
  _ (504, GATEWAY_TIMEOUT, "504 Gateway Timeout")                             \
  _ (505, HTTP_VERSION_NOT_SUPPORTED, "505 HTTP Version Not Supported")

typedef enum http_status_code_
{
#define _(c, s, str) HTTP_STATUS_##s,
  foreach_http_status_code
#undef _
    HTTP_N_STATUS
} http_status_code_t;

#define foreach_http_header_name                                              \
  _ (ACCEPT_CHARSET, "Accept-Charset", "accept-charset", 15)                  \
  _ (ACCEPT_ENCODING, "Accept-Encoding", "accept-encoding", 16)               \
  _ (ACCEPT_LANGUAGE, "Accept-Language", "accept-language", 17)               \
  _ (ACCEPT_RANGES, "Accept-Ranges", "accept-ranges", 18)                     \
  _ (ACCEPT, "Accept", "accept", 19)                                          \
  _ (ACCESS_CONTROL_ALLOW_CREDENTIALS, "Access-Control-Allow-Credentials",    \
     "access-control-allow-credentials", 0)                                   \
  _ (ACCESS_CONTROL_ALLOW_HEADERS, "Access-Control-Allow-Headers",            \
     "access-control-allow-headers", 0)                                       \
  _ (ACCESS_CONTROL_ALLOW_METHODS, "Access-Control-Allow-Methods",            \
     "access-control-allow-methods", 0)                                       \
  _ (ACCESS_CONTROL_ALLOW_ORIGIN, "Access-Control-Allow-Origin",              \
     "access-control-allow-origin", 20)                                       \
  _ (ACCESS_CONTROL_EXPOSE_HEADERS, "Access-Control-Expose-Headers",          \
     "access-control-expose-headers", 0)                                      \
  _ (ACCESS_CONTROL_MAX_AGE, "Access-Control-Max-Age",                        \
     "access-control-max-age", 0)                                             \
  _ (ACCESS_CONTROL_REQUEST_HEADERS, "Access-Control-Request-Headers",        \
     "access-control-request-headers", 0)                                     \
  _ (ACCESS_CONTROL_REQUEST_METHOD, "Access-Control-Request-Method",          \
     "access-control-request-method", 0)                                      \
  _ (AGE, "Age", "age", 21)                                                   \
  _ (ALLOW, "Allow", "allow", 22)                                             \
  _ (ALPN, "ALPN", "alpn", 0)                                                 \
  _ (ALT_SVC, "Alt-Svc", "alt-svc", 0)                                        \
  _ (ALT_USED, "Alt-Used", "alt-used", 0)                                     \
  _ (ALTERNATES, "Alternates", "alternates", 0)                               \
  _ (AUTHENTICATION_CONTROL, "Authentication-Control",                        \
     "authentication-control", 0)                                             \
  _ (AUTHENTICATION_INFO, "Authentication-Info", "authentication-info", 0)    \
  _ (AUTHORIZATION, "Authorization", "authorization", 23)                     \
  _ (CACHE_CONTROL, "Cache-Control", "cache-control", 24)                     \
  _ (CACHE_STATUS, "Cache-Status", "cache-status", 0)                         \
  _ (CAPSULE_PROTOCOL, "Capsule-Protocol", "capsule-protocol", 0)             \
  _ (CDN_CACHE_CONTROL, "CDN-Cache-Control", "cdn-cache-control", 0)          \
  _ (CDN_LOOP, "CDN-Loop", "cdn-loop", 0)                                     \
  _ (CLIENT_CERT, "Client-Cert", "client-cert", 0)                            \
  _ (CLIENT_CERT_CHAIN, "Client-Cert-Chain", "client-cert-chain", 0)          \
  _ (CLOSE, "Close", "close", 0)                                              \
  _ (CONNECTION, "Connection", "connection", 0)                               \
  _ (CONTENT_DIGEST, "Content-Digest", "content-digest", 0)                   \
  _ (CONTENT_DISPOSITION, "Content-Disposition", "content-disposition", 25)   \
  _ (CONTENT_ENCODING, "Content-Encoding", "content-encoding", 26)            \
  _ (CONTENT_LANGUAGE, "Content-Language", "content-language", 27)            \
  _ (CONTENT_LENGTH, "Content-Length", "content-length", 28)                  \
  _ (CONTENT_LOCATION, "Content-Location", "content-location", 29)            \
  _ (CONTENT_RANGE, "Content-Range", "content-range", 30)                     \
  _ (CONTENT_TYPE, "Content-Type", "content-type", 31)                        \
  _ (COOKIE, "Cookie", "cookie", 32)                                          \
  _ (DATE, "Date", "date", 33)                                                \
  _ (DIGEST, "Digest", "digest", 0)                                           \
  _ (DPOP, "DPoP", "dpop", 0)                                                 \
  _ (DPOP_NONCE, "DPoP-Nonce", "dpop-nonce", 0)                               \
  _ (EARLY_DATA, "Early-Data", "early-data", 0)                               \
  _ (ETAG, "ETag", "etag", 34)                                                \
  _ (EXPECT, "Expect", "expect", 35)                                          \
  _ (EXPIRES, "Expires", "expires", 36)                                       \
  _ (FORWARDED, "Forwarded", "forwarded", 0)                                  \
  _ (FROM, "From", "from", 37)                                                \
  _ (HOST, "Host", "host", 38)                                                \
  _ (IF_MATCH, "If-Match", "if-match", 39)                                    \
  _ (IF_MODIFIED_SINCE, "If-Modified-Since", "if-modified-since", 40)         \
  _ (IF_NONE_MATCH, "If-None-Match", "if-none-match", 41)                     \
  _ (IF_RANGE, "If-Range", "if-range", 42)                                    \
  _ (IF_UNMODIFIED_SINCE, "If-Unmodified-Since", "if-unmodified-since", 43)   \
  _ (KEEP_ALIVE, "Keep-Alive", "keep-alive", 0)                               \
  _ (LAST_MODIFIED, "Last-Modified", "last-modified", 44)                     \
  _ (LINK, "Link", "link", 45)                                                \
  _ (LOCATION, "Location", "location", 46)                                    \
  _ (MAX_FORWARDS, "Max-Forwards", "max-forwards", 47)                        \
  _ (ORIGIN, "Origin", "origin", 0)                                           \
  _ (PRIORITY, "Priority", "priority", 0)                                     \
  _ (PROXY_AUTHENTICATE, "Proxy-Authenticate", "proxy-authenticate", 48)      \
  _ (PROXY_AUTHENTICATION_INFO, "Proxy-Authentication-Info",                  \
     "proxy-authentication-info", 0)                                          \
  _ (PROXY_AUTHORIZATION, "Proxy-Authorization", "proxy-authorization", 49)   \
  _ (PROXY_STATUS, "Proxy-Status", "proxy-status", 0)                         \
  _ (RANGE, "Range", "range", 50)                                             \
  _ (REFERER, "Referer", "referer", 51)                                       \
  _ (REFRESH, "Refresh", "refresh", 52)                                       \
  _ (REPR_DIGEST, "Repr-Digest", "repr-digest", 0)                            \
  _ (RETRY_AFTER, "Retry-After", "retry-after", 53)                           \
  _ (SERVER, "Server", "server", 54)                                          \
  _ (SET_COOKIE, "Set-Cookie", "set-cookie", 55)                              \
  _ (SIGNATURE, "Signature", "signature", 0)                                  \
  _ (SIGNATURE_INPUT, "Signature-Input", "signature-input", 0)                \
  _ (STRICT_TRANSPORT_SECURITY, "Strict-Transport-Security",                  \
     "strict-transport-security", 56)                                         \
  _ (TE, "TE", "te", 0)                                                       \
  _ (TRAILER, "Trailer", "trailer", 0)                                        \
  _ (TRANSFER_ENCODING, "Transfer-Encoding", "transfer-encoding", 57)         \
  _ (UPGRADE, "Upgrade", "upgrade", 0)                                        \
  _ (USER_AGENT, "User-Agent", "user-agent", 58)                              \
  _ (VARY, "Vary", "vary", 59)                                                \
  _ (VIA, "Via", "via", 60)                                                   \
  _ (WANT_CONTENT_DIGEST, "Want-Content-Digest", "want-content-digest", 0)    \
  _ (WANT_REPR_DIGEST, "Want-Repr-Digest", "want-repr-digest", 0)             \
  _ (WWW_AUTHENTICATE, "WWW-Authenticate", "www-authenticate", 61)

typedef enum http_header_name_
{
#define _(sym, str_canonical, str_lower, hpack_index) HTTP_HEADER_##sym,
  foreach_http_header_name
#undef _
} http_header_name_t;

#define HTTP_BOOLEAN_TRUE "?1"

#define foreach_http_upgrade_proto                                            \
  _ (CONNECT_UDP, "connect-udp")                                              \
  _ (CONNECT_IP, "connect-ip")                                                \
  _ (WEBSOCKET, "websocket")

typedef enum http_upgrade_proto_
{
  HTTP_UPGRADE_PROTO_NA =
    0, /* indicating standard CONNECT where protocol is omitted */
#define _(sym, str) HTTP_UPGRADE_PROTO_##sym,
  foreach_http_upgrade_proto
#undef _
} http_upgrade_proto_t;

typedef enum http_msg_data_type_
{
  HTTP_MSG_DATA_INLINE,
  HTTP_MSG_DATA_PTR
} http_msg_data_type_t;

typedef struct http_field_line_
{
  u32 name_offset;
  u32 name_len;
  u32 value_offset;
  u32 value_len;
} http_field_line_t;

typedef enum http_url_scheme_
{
  HTTP_URL_SCHEME_HTTP,
  HTTP_URL_SCHEME_HTTPS,
  HTTP_URL_SCHEME_UNKNOWN, /* for internal use */
} http_url_scheme_t;

typedef struct http_msg_data_
{
  http_msg_data_type_t type;
  u64 len;
  http_url_scheme_t scheme;
  u32 target_authority_offset;
  u32 target_authority_len;
  u32 target_path_offset;
  u32 target_path_len;
  u32 target_query_offset;
  u32 target_query_len;
  u32 headers_offset;
  u32 headers_len;
  u32 body_offset;
  u64 body_len;
  uword headers_ctx;
  http_upgrade_proto_t upgrade_proto;
  u8 data[0];
} http_msg_data_t;

typedef struct http_msg_
{
  http_msg_type_t type;
  union
  {
    http_req_method_t method_type;
    http_status_code_t code;
  };
  http_msg_data_t data;
} http_msg_t;

always_inline u8 *
format_http_bytes (u8 *s, va_list *va)
{
  u8 *bytes = va_arg (*va, u8 *);
  int n_bytes = va_arg (*va, int);
  uword i;

  if (n_bytes == 0)
    return s;

  for (i = 0; i < n_bytes; i++)
    {
      if (isprint (bytes[i]))
	s = format (s, "%c", bytes[i]);
      else
	s = format (s, "\\x%02x", bytes[i]);
    }

  return s;
}

always_inline int
http_validate_target_syntax (u8 *target, u32 len, int is_query,
			     int *is_encoded)
{
  int encoded = 0;
  u32 i;

  static uword valid_chars[4] = {
    /* !$&'()*+,-./0123456789:;= */
    0x2fffffd200000000,
    /* @ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~ */
    0x47fffffe87ffffff,
    0x0000000000000000,
    0x0000000000000000,
  };

  for (i = 0; i < len; i++)
    {
      if (clib_bitmap_get_no_check (valid_chars, target[i]))
	continue;
      /* target was already split after first question mark,
       * for query it is valid character */
      if (is_query && target[i] == '?')
	continue;
      /* pct-encoded = "%" HEXDIG HEXDIG */
      if (target[i] == '%')
	{
	  if ((i + 2) >= len)
	    return -1;
	  if (!isxdigit (target[i + 1]) || !isxdigit (target[i + 2]))
	    return -1;
	  i += 2;
	  encoded = 1;
	  continue;
	}
      clib_warning ("invalid character %d", target[i]);
      return -1;
    }
  if (is_encoded)
    *is_encoded = encoded;
  return 0;
}

/**
 * An "absolute-path" rule validation (RFC9110 section 4.1).
 *
 * @param path       Vector of target path to validate.
 * @param is_encoded Return flag that indicates if percent-encoded (optional).
 *
 * @return @c 0 on success.
 */
always_inline int
http_validate_abs_path_syntax (u8 *path, int *is_encoded)
{
  return http_validate_target_syntax (path, vec_len (path), 0, is_encoded);
}

/**
 * A "query" rule validation (RFC3986 section 2.1).
 *
 * @param query      Target query to validate.
 * @param is_encoded Return flag that indicates if percent-encoded (optional).
 *
 * @return @c 0 on success.
 */
always_inline int
http_validate_query_syntax (u8 *query, int *is_encoded)
{
  return http_validate_target_syntax (query, vec_len (query), 1, is_encoded);
}

#define htoi(x) (isdigit (x) ? (x - '0') : (tolower (x) - 'a' + 10))

/**
 * Decode percent-encoded data.
 *
 * @param src Data to decode.
 * @param len Length of data to decode.
 *
 * @return New vector with decoded data.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_percent_decode (u8 *src, u32 len)
{
  u32 i;
  u8 *decoded_uri = 0;

  for (i = 0; i < len; i++)
    {
      if (src[i] == '%')
	{
	  u8 c = (htoi (src[i + 1]) << 4) | htoi (src[i + 2]);
	  vec_add1 (decoded_uri, c);
	  i += 2;
	}
      else
	vec_add1 (decoded_uri, src[i]);
    }
  return decoded_uri;
}

/**
 * Sanitize HTTP path by squashing repeating slashes and removing
 * dot segments from path (RFC3986 section 5.2.4)
 *
 * @param path Path to sanitize.
 *
 * @return New vector with sanitized path.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_path_sanitize (u8 *path)
{
  u32 *segments = 0, *segments_len = 0, segment_len;
  u8 *new_path = 0;
  int i, ii;

  if (!path || vec_len (path) == 0)
    return vec_new (u8, 0);

  segments = vec_new (u32, 1);
  /* first segment */
  segments[0] = (path[0] == '/' ? 1 : 0);
  /* find all segments */
  for (i = 1; i < (vec_len (path) - 1); i++)
    {
      if (path[i] == '/')
	vec_add1 (segments, i + 1);
    }
  /* dummy tail */
  vec_add1 (segments, vec_len (path));

  /* scan all segments for "." and ".." */
  segments_len = vec_new (u32, vec_len (segments) - 1);
  for (i = 0; i < vec_len (segments_len); i++)
    {
      segment_len = segments[i + 1] - segments[i];
      /* aside from dots, skip empty segments (double slashes) */
      if ((segment_len == 2 && path[segments[i]] == '.') || segment_len == 1)
	segment_len = 0;
      else if (segment_len == 3 && path[segments[i]] == '.' &&
	       path[segments[i] + 1] == '.')
	{
	  segment_len = 0;
	  /* remove parent (if any) */
	  for (ii = i - 1; ii >= 0; ii--)
	    {
	      if (segments_len[ii])
		{
		  segments_len[ii] = 0;
		  break;
		}
	    }
	}
      segments_len[i] = segment_len;
    }

  /* we might end with empty path, so return at least empty vector */
  new_path = vec_new (u8, 0);
  /* append all valid segments */
  for (i = 0; i < vec_len (segments_len); i++)
    {
      if (segments_len[i])
	vec_add (new_path, path + segments[i], segments_len[i]);
    }
  vec_free (segments);
  vec_free (segments_len);
  return new_path;
}

typedef struct
{
  http_token_t name;
  http_token_t value;
} http_header_t;

typedef struct
{
  http_token_t *values;
  uword *value_by_name;
  u8 *buf;
  char **concatenated_values;
} http_header_table_t;

#define HTTP_HEADER_TABLE_NULL                                                \
  {                                                                           \
    .values = 0, .value_by_name = 0, .buf = 0, .concatenated_values = 0,      \
  }

/**
 * Case-sensitive comparison of two tokens.
 *
 * @param actual       Pointer to the first token.
 * @param actual_len   Length of the first token.
 * @param expected     Pointer to the second token.
 * @param expected_len Length of the second token.
 *
 * @return @c 1 if tokens are same, @c 0 otherwise.
 */
always_inline u8
http_token_is (const char *actual, uword actual_len, const char *expected,
	       uword expected_len)
{
  ASSERT (actual != 0);
  if (actual_len != expected_len)
    return 0;
  return memcmp (actual, expected, expected_len) == 0 ? 1 : 0;
}

/* Based on searching for a value in a given range from Hacker's Delight */
always_inline uword
http_tolower_word (uword x)
{
#if uword_bits == 64
  uword all_bytes = 0x0101010101010101;
#else
  uword all_bytes = 0x01010101;
#endif
  uword d, y;
  d = (x | (0x80 * all_bytes)) - (0x41 * all_bytes);
  d = ~((x | (0x7F * all_bytes)) ^ d);
  y = (d & (0x7F * all_bytes)) + (0x66 * all_bytes);
  y = y | d;
  y = y | (0x7F * all_bytes);
  y = ~y;
  y = (y >> 2) & (0x20 * all_bytes);
  return (x | y);
}

/**
 * Case-insensitive comparison of two tokens.
 *
 * @param actual       Pointer to the first token.
 * @param actual_len   Length of the first token.
 * @param expected     Pointer to the second token.
 * @param expected_len Length of the second token.
 *
 * @return @c 1 if tokens are same, @c 0 otherwise.
 */
always_inline u8
http_token_is_case (const char *actual, uword actual_len, const char *expected,
		    uword expected_len)
{
  uword i, last_a = 0, last_e = 0;
  uword *a, *e;
  ASSERT (actual != 0);
  if (actual_len != expected_len)
    return 0;

  i = expected_len;
  a = (uword *) actual;
  e = (uword *) expected;
  while (i >= sizeof (uword))
    {
      if (http_tolower_word (*a) != http_tolower_word (*e))
	return 0;
      a++;
      e++;
      i -= sizeof (uword);
    }
  if (i > 0)
    {
      clib_memcpy_fast (&last_a, a, i);
      clib_memcpy_fast (&last_e, e, i);
      if (http_tolower_word (last_a) != http_tolower_word (last_e))
	return 0;
    }
  return 1;
}

/**
 * Check if there is occurrence of token in another token.
 *
 * @param haystack     Pointer to the token being searched.
 * @param haystack_len Length of the token being searched.
 * @param needle       The token to search for.
 * @param needle_len   Length of the token to search for.
 *
 * @return @c 1 if in case of success, @c 0 otherwise.
 */
always_inline u8
http_token_contains (const char *haystack, uword haystack_len,
		     const char *needle, uword needle_len)
{
  uword end_index, i;
  ASSERT (haystack != 0);
  if (haystack_len < needle_len)
    return 0;
  end_index = haystack_len - needle_len;
  for (i = 0; i <= end_index; i++)
    {
      if (!memcmp (haystack + i, needle, needle_len))
	return 1;
    }
  return 0;
}

/**
 * Reset header table before reuse.
 *
 * @param ht Header table to reset.
 */
always_inline void
http_reset_header_table (http_header_table_t *ht)
{
  int i;
  for (i = 0; i < vec_len (ht->concatenated_values); i++)
    vec_free (ht->concatenated_values[i]);
  vec_reset_length (ht->concatenated_values);
  vec_reset_length (ht->values);
  vec_reset_length (ht->buf);
  hash_free (ht->value_by_name);
}

/**
 * Initialize header table input buffer.
 * @param ht  Header table.
 * @param msg HTTP transport message metadata.
 */
always_inline void
http_init_header_table_buf (http_header_table_t *ht, http_msg_t msg)
{
  vec_validate (ht->buf, msg.data.headers_len - 1);
}

/**
 * Free header table's memory.
 *
 * @param ht Header table to free.
 */
always_inline void
http_free_header_table (http_header_table_t *ht)
{
  int i;
  for (i = 0; i < vec_len (ht->concatenated_values); i++)
    vec_free (ht->concatenated_values[i]);
  vec_free (ht->concatenated_values);
  vec_free (ht->values);
  vec_free (ht->buf);
  hash_free (ht->value_by_name);
}

static uword
_http_ht_hash_key_sum (hash_t *h, uword key)
{
  http_token_t *name = uword_to_pointer (key, http_token_t *);
  uword last[3] = {};
  uwordu *q = (uword *) name->base;
  u64 a, b, c, n;

  a = b = (uword_bits == 64) ? 0x9e3779b97f4a7c13LL : 0x9e3779b9;
  c = 0;
  n = name->len;

  while (n >= 3 * sizeof (uword))
    {
      a += http_tolower_word (q[0]);
      b += http_tolower_word (q[1]);
      c += http_tolower_word (q[2]);
      hash_mix (a, b, c);
      n -= 3 * sizeof (uword);
      q += 3;
    }

  c += name->len;

  if (n > 0)
    {
      clib_memcpy_fast (&last, q, n);
      a += http_tolower_word (last[0]);
      b += http_tolower_word (last[1]);
      c += http_tolower_word (last[2]);
    }

  hash_mix (a, b, c);

  return c;
}

static uword
_http_ht_hash_key_equal (hash_t *h, uword key1, uword key2)
{
  http_token_t *name1 = uword_to_pointer (key1, http_token_t *);
  http_token_t *name2 = uword_to_pointer (key2, http_token_t *);
  return name1 && name2 &&
	 http_token_is_case (name1->base, name1->len, name2->base, name2->len);
}

static u8 *
_http_ht_format_pair (u8 *s, va_list *args)
{
  http_header_table_t *ht = va_arg (*args, http_header_table_t *);
  void *CLIB_UNUSED (*v) = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  http_token_t *name = uword_to_pointer (p->key, http_token_t *);
  http_token_t *value = vec_elt_at_index (ht->values, p->value[0]);

  s = format (s, "%U: %U", format_http_bytes, name->base, name->len,
	      format_http_bytes, value->base, value->len);

  return s;
}

/**
 * Build header table.
 *
 * @param header_table Header table with loaded buffer.
 * @param msg HTTP transport message metadata.
 *
 * @note If reusing already allocated header table use
 * @c http_reset_header_table first.
 */
always_inline void
http_build_header_table (http_header_table_t *ht, http_msg_t msg)
{
  http_token_t name, *value;
  http_field_line_t *field_lines, *field_line;
  uword *p;

  ASSERT (ht);
  field_lines = uword_to_pointer (msg.data.headers_ctx, http_field_line_t *);
  ht->value_by_name = hash_create2 (
    0, sizeof (http_token_t), sizeof (uword), _http_ht_hash_key_sum,
    _http_ht_hash_key_equal, _http_ht_format_pair, ht);

  vec_foreach (field_line, field_lines)
    {
      name.base = (char *) (ht->buf + field_line->name_offset);
      name.len = field_line->name_len;
      /* check if header is repeated */
      p = hash_get_mem (ht->value_by_name, &name);
      if (p)
	{
	  char *new_value = 0;
	  value = vec_elt_at_index (ht->values, p[0]);
	  u32 new_len = value->len + field_line->value_len + 2;
	  vec_validate (new_value, new_len - 1);
	  clib_memcpy (new_value, value->base, value->len);
	  new_value[value->len] = ',';
	  new_value[value->len + 1] = ' ';
	  clib_memcpy (new_value + value->len + 2,
		       ht->buf + field_line->value_offset,
		       field_line->value_len);
	  vec_add1 (ht->concatenated_values, new_value);
	  value->base = new_value;
	  value->len = new_len;
	  continue;
	}
      /* or create new record */
      vec_add2 (ht->values, value, 1);
      value->base = (char *) (ht->buf + field_line->value_offset);
      value->len = field_line->value_len;
      hash_set_mem_alloc (&ht->value_by_name, &name, value - ht->values);
    }
}

/**
 * Try to find given header name in header table.
 *
 * @param header_table Header table to search.
 * @param name Header name to match.
 *
 * @return Header value in case of success, @c 0 otherwise.
 */
always_inline const http_token_t *
http_get_header (http_header_table_t *header_table, const char *name,
		 uword name_len)
{
  uword *p;
  http_token_t *value;
  http_token_t name_token = { (char *) name, name_len };

  p = hash_get_mem (header_table->value_by_name, &name_token);
  if (p)
    {
      value = vec_elt_at_index (header_table->values, p[0]);
      return value;
    }

  return 0;
}

typedef struct
{
  u32 len;	   /**< length of the header data buffer */
  u32 tail_offset; /**< current tail in header data */
  u8 *buf;	   /**< start of header data */
} http_headers_ctx_t;

typedef struct
{
  u32 len;
  u8 token[0];
} http_custom_token_t;

typedef struct
{
  u32 name;
  http_custom_token_t value;
} http_app_header_t;

/* Use high bit of header name length as custom header name bit. */
#define HTTP_CUSTOM_HEADER_NAME_BIT (1 << 31)

/**
 * Initialize headers list context.
 *
 * @param ctx Headers list context.
 * @param buf Buffer, which store headers list, provided by app.
 * @param len Length of headers list buffer.
 */
always_inline void
http_init_headers_ctx (http_headers_ctx_t *ctx, u8 *buf, u32 len)
{
  ctx->len = len;
  ctx->tail_offset = 0;
  ctx->buf = buf;
}

/**
 * Add header with predefined name to the headers list.
 *
 * @param ctx       Headers list context.
 * @param name      Header name ID (see @ref http_header_name_t).
 * @param value     Header value pointer.
 * @param value_len Header value length.
 *
 * @return @c 0 if in case of success, @c -1 otherwise.
 */
always_inline int
http_add_header (http_headers_ctx_t *ctx, http_header_name_t name,
		 const char *value, uword value_len)
{
  http_app_header_t *header;

  if ((ctx->tail_offset + sizeof (http_app_header_t) + value_len) > ctx->len)
    return -1;

  header = (http_app_header_t *) (ctx->buf + ctx->tail_offset);
  header->name = (u32) name;
  header->value.len = (u32) value_len;
  clib_memcpy (header->value.token, (u8 *) value, value_len);
  ctx->tail_offset += sizeof (http_app_header_t) + value_len;
  return 0;
}

/**
 * Add header with custom name to the headers list.
 *
 * @param ctx       Headers list context.
 * @param name      Header name pointer.
 * @param name_len  Header name length.
 * @param value     Header value pointer.
 * @param value_len Header value length.
 *
 * @return @c 0 if in case of success, @c -1 otherwise.
 */
always_inline int
http_add_custom_header (http_headers_ctx_t *ctx, const char *name,
			uword name_len, const char *value, uword value_len)
{
  http_custom_token_t *token;

  if ((ctx->tail_offset + 2 * sizeof (http_custom_token_t) + name_len +
       value_len) > ctx->len)
    return -1;

  /* name */
  token = (http_custom_token_t *) (ctx->buf + ctx->tail_offset);
  token->len = (u32) name_len;
  clib_memcpy (token->token, (u8 *) name, token->len);
  token->len |= HTTP_CUSTOM_HEADER_NAME_BIT;
  ctx->tail_offset += sizeof (http_custom_token_t) + name_len;
  /* value */
  token = (http_custom_token_t *) (ctx->buf + ctx->tail_offset);
  token->len = (u32) value_len;
  clib_memcpy (token->token, (u8 *) value, token->len);
  ctx->tail_offset += sizeof (http_custom_token_t) + value_len;
  return 0;
}

/**
 * Truncate the header list
 *
 * @param ctx Headers list context.
 */
always_inline void
http_truncate_headers_list (http_headers_ctx_t *ctx)
{
  ctx->tail_offset = 0;
}

typedef enum http_uri_host_type_
{
  HTTP_URI_HOST_TYPE_IP4,
  HTTP_URI_HOST_TYPE_IP6,
  HTTP_URI_HOST_TYPE_REG_NAME
} http_uri_host_type_t;

typedef struct
{
  http_uri_host_type_t host_type;
  union
  {
    ip46_address_t ip;
    http_token_t reg_name;
  };
  u16 port;
} http_uri_authority_t;

always_inline int
_http_parse_ip4 (u8 **p, u8 *end, ip4_address_t *ip4)
{
  u8 n_octets = 0, digit, n_digits = 0;
  u16 dec_octet = 0;
  int rv = 0;

  while (*p != end)
    {
      if (**p >= '0' && **p <= '9')
	{
	  digit = **p - '0';
	  dec_octet = dec_octet * 10 + digit;
	  n_digits++;
	  /* must fit in 8 bits */
	  if (dec_octet > 255)
	    return -1;
	}
      else if (**p == '.' && n_digits)
	{
	  ip4->as_u8[n_octets++] = (u8) dec_octet;
	  dec_octet = 0;
	  n_digits = 0;
	  /* too many octets */
	  if (n_octets >= ARRAY_LEN (ip4->as_u8))
	    return -1;
	}
      else
	{
	  /* probably more data (delimiter) after IPv4 address */
	  rv = **p;
	  break;
	}

      (*p)++;
    }

  /* must end with octet */
  if (!n_digits)
    return -1;

  ip4->as_u8[n_octets++] = (u8) dec_octet;

  /* too few octets */
  if (n_octets < ARRAY_LEN (ip4->as_u8))
    return -1;

  return rv;
}

/* modified unformat_ip6_address */
always_inline int
_http_parse_ip6 (u8 **p, u8 *end, ip6_address_t *ip6)
{
  u8 n_hex_digits = 0, n_colon = 0, n_hex_quads = 0;
  u8 double_colon_index = ~0, i;
  u16 hex_digit;
  u32 hex_quad = 0;
  int rv = 0;

  while (*p != end)
    {
      hex_digit = 16;
      if (**p >= '0' && **p <= '9')
	hex_digit = **p - '0';
      else if (**p >= 'a' && **p <= 'f')
	hex_digit = **p + 10 - 'a';
      else if (**p >= 'A' && **p <= 'F')
	hex_digit = **p + 10 - 'A';
      else if (**p == ':' && n_colon < 2)
	n_colon++;
      else
	{
	  /* probably more data (delimiter) after IPv6 address */
	  rv = **p;
	  break;
	}

      /* too many hex quads */
      if (n_hex_quads >= ARRAY_LEN (ip6->as_u16))
	return -1;

      if (hex_digit < 16)
	{
	  hex_quad = (hex_quad << 4) | hex_digit;

	  /* must fit in 16 bits */
	  if (n_hex_digits >= 4)
	    return -1;

	  n_colon = 0;
	  n_hex_digits++;
	}

      /* save position of :: */
      if (n_colon == 2)
	{
	  /* more than one :: ? */
	  if (double_colon_index < ARRAY_LEN (ip6->as_u16))
	    return -1;
	  double_colon_index = n_hex_quads;
	}

      if (n_colon > 0 && n_hex_digits > 0)
	{
	  ip6->as_u16[n_hex_quads++] = clib_host_to_net_u16 ((u16) hex_quad);
	  hex_quad = 0;
	  n_hex_digits = 0;
	}

      (*p)++;
    }

  if (n_hex_digits > 0)
    ip6->as_u16[n_hex_quads++] = clib_host_to_net_u16 ((u16) hex_quad);

  /* expand :: to appropriate number of zero hex quads */
  if (double_colon_index < ARRAY_LEN (ip6->as_u16))
    {
      u8 n_zero = ARRAY_LEN (ip6->as_u16) - n_hex_quads;

      for (i = n_hex_quads - 1; i >= double_colon_index; i--)
	ip6->as_u16[n_zero + i] = ip6->as_u16[i];

      for (i = 0; i < n_zero; i++)
	{
	  ASSERT ((double_colon_index + i) < ARRAY_LEN (ip6->as_u16));
	  ip6->as_u16[double_colon_index + i] = 0;
	}

      n_hex_quads = ARRAY_LEN (ip6->as_u16);
    }

  /* too few hex quads */
  if (n_hex_quads < ARRAY_LEN (ip6->as_u16))
    return -1;

  return rv;
}

always_inline int
_http_parse_port (u8 **pos, u8 *end, u16 *port)
{
  u32 value = 0;
  u8 *p = *pos;

  if (!isdigit (*p))
    return -1;
  value = *p - '0';
  p++;

  while (p != end)
    {
      if (!isdigit (*p))
	break;
      value = value * 10 + *p - '0';
      if (value > CLIB_U16_MAX)
	return -1;
      p++;
    }
  *pos = p;
  *port = clib_host_to_net_u16 ((u16) value);
  return 0;
}

/**
 * Parse authority to components.
 *
 * @param authority     Target URL to parse.
 * @param authority_len Length of URL.
 * @param parsed        Parsed authority (port is se to 0 if not present).
 *
 * @return @c 0 on success.
 */
always_inline int
http_parse_authority (u8 *authority, u32 authority_len,
		      http_uri_authority_t *parsed)
{
  u8 *token_start, *p, *end;
  int rv;

  static uword valid_chars[4] = {
    /* -.0123456789 */
    0x03ff600000000000,
    /* ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz */
    0x07fffffe07fffffe,
    0x0000000000000000,
    0x0000000000000000,
  };

  /* reg-name max 255 chars + colon + port max 5 chars */
  if (authority_len > 261)
    return -1;

  end = authority + authority_len;
  token_start = authority;
  parsed->port = 0;

  /* parse host */
  if (*token_start == '[')
    {
      /* IPv6 address */
      if (authority_len < 4)
	return -1;

      p = ++token_start;
      rv = _http_parse_ip6 (&p, end, &parsed->ip.ip6);
      if (rv != ']')
	return -1;

      parsed->host_type = HTTP_URI_HOST_TYPE_IP6;
      token_start = ++p;
    }
  else if (isdigit (*token_start))
    {
      /* maybe IPv4 address */
      p = token_start;

      if (authority_len < 7)
	goto reg_name;

      rv = _http_parse_ip4 (&p, end, &parsed->ip.ip4);
      if (rv == 0 || rv == ':')
	{
	  parsed->host_type = HTTP_URI_HOST_TYPE_IP4;
	  token_start = p;
	}
      else
	goto reg_name;
    }
  else
    {
      /* registered name */
      p = token_start;
    reg_name:
      while (p != end && *p != ':')
	{
	  if (!clib_bitmap_get_no_check (valid_chars, *p))
	    {
	      clib_warning ("invalid character '%u'", *p);
	      return -1;
	    }
	  p++;
	}
      parsed->reg_name.len = p - token_start;
      if (parsed->reg_name.len > 255)
	{
	  clib_warning ("reg-name too long");
	  return -1;
	}
      parsed->host_type = HTTP_URI_HOST_TYPE_REG_NAME;
      parsed->reg_name.base = (char *) token_start;
      token_start = p;
    }

  /* parse port, if any */
  if ((end - token_start) > 1 && *token_start == ':')
    {
      token_start++;
      if (_http_parse_port (&token_start, end, &parsed->port))
	{
	  clib_warning ("invalid port");
	  return -1;
	}
    }

  return token_start == end ? 0 : -1;
}

/**
 * Format given authority (RFC3986 section 3.2)
 *
 * @param authority Authority to format.
 *
 * @return New vector with formated authority.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_serialize_authority (http_uri_authority_t *authority)
{
  u8 *s;

  if (authority->host_type == HTTP_URI_HOST_TYPE_IP4)
    s = format (0, "%U", format_ip4_address, &authority->ip.ip4);
  else if (authority->host_type == HTTP_URI_HOST_TYPE_IP6)
    s = format (0, "[%U]", format_ip6_address, &authority->ip.ip6);
  else
    s = format (0, "%U", format_http_bytes, authority->reg_name.base,
		authority->reg_name.len);

  if (authority->port)
    s = format (s, ":%d", clib_net_to_host_u16 (authority->port));

  return s;
}

/**
 * Parse target host and port of UDP tunnel over HTTP.
 *
 * @param path     Path in format "{target_host}/{target_port}/".
 * @param path_len Length of given path.
 * @param parsed   Parsed target in case of success..
 *
 * @return @c 0 on success.
 *
 * @note Only IPv4 literals and IPv6 literals supported.
 */
always_inline int
http_parse_masque_host_port (u8 *path, u32 path_len,
			     http_uri_authority_t *parsed)
{
  u8 *p, *end, *decoded_host, *p4, *p6;
  u32 host_len;

  p = path;
  end = path + path_len;
  clib_memset (parsed, 0, sizeof (*parsed));

  while (p != end && *p != '/')
    p++;

  host_len = p - path;
  if (!host_len || (host_len == path_len) || (host_len + 1 == path_len))
    return -1;
  decoded_host = http_percent_decode (path, host_len);
  p4 = p6 = decoded_host;
  if (0 == _http_parse_ip6 (&p6, p6 + vec_len (decoded_host), &parsed->ip.ip6))
    parsed->host_type = HTTP_URI_HOST_TYPE_IP6;
  else if (0 ==
	   _http_parse_ip4 (&p4, p4 + vec_len (decoded_host), &parsed->ip.ip4))
    parsed->host_type = HTTP_URI_HOST_TYPE_IP4;
  else
    {
      vec_free (decoded_host);
      clib_warning ("unsupported target_host format");
      return -1;
    }
  vec_free (decoded_host);

  p++;
  if (_http_parse_port (&p, end, &parsed->port))
    {
      clib_warning ("invalid port");
      return -1;
    }

  if (p == end || *p != '/')
    return -1;

  return 0;
}

#define HTTP_INVALID_VARINT			 ((u64) ~0)
#define HTTP_CAPSULE_HEADER_MAX_SIZE		 8
#define HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD 5
#define HTTP_UDP_PAYLOAD_MAX_LEN		 65527

#define foreach_http_capsule_type _ (0, DATAGRAM)

typedef enum http_capsule_type_
{
#define _(n, s) HTTP_CAPSULE_TYPE_##s = n,
  foreach_http_capsule_type
#undef _
} __clib_packed http_capsule_type_t;

/* variable-length integer (RFC9000 section 16) */
always_inline u64
_http_decode_varint (u8 **pos, u8 *end)
{
  u8 first_byte, bytes_left, *p;
  u64 value;

  p = *pos;

  ASSERT (p < end);

  first_byte = *p;
  p++;

  if (first_byte <= 0x3F)
    {
      *pos = p;
      return first_byte;
    }

  /* remove length bits, encoded in the first two bits of the first byte */
  value = first_byte & 0x3F;
  bytes_left = (1 << (first_byte >> 6)) - 1;

  if (PREDICT_FALSE ((end - p) < bytes_left))
    return HTTP_INVALID_VARINT;

  do
    {
      value = (value << 8) | *p;
      p++;
    }
  while (--bytes_left);

  *pos = p;
  return value;
}

always_inline u8 *
_http_encode_varint (u8 *dst, u64 value)
{
  ASSERT (value <= 0x3FFFFFFFFFFFFFFF);
  if (value <= 0x3f)
    {
      *dst++ = (u8) value;
      return dst;
    }
  else if (value <= 0x3FFF)
    {
      *dst++ = (0b01 << 6) | (u8) (value >> 8);
      *dst++ = (u8) value;
      return dst;
    }
  else if (value <= 0x3FFFFFFF)
    {
      *dst++ = (0b10 << 6) | (u8) (value >> 24);
      *dst++ = (u8) (value >> 16);
      *dst++ = (u8) (value >> 8);
      *dst++ = (u8) value;
      return dst;
    }
  else
    {
      *dst++ = (0b11 << 6) | (u8) (value >> 56);
      *dst++ = (u8) (value >> 48);
      *dst++ = (u8) (value >> 40);
      *dst++ = (u8) (value >> 32);
      *dst++ = (u8) (value >> 24);
      *dst++ = (u8) (value >> 16);
      *dst++ = (u8) (value >> 8);
      *dst++ = (u8) value;
      return dst;
    }
}

always_inline int
_http_parse_capsule (u8 *data, u64 len, u64 *type, u8 *value_offset,
		     u64 *value_len)
{
  u64 capsule_type, capsule_value_len;
  u8 *p = data;
  u8 *end = data + len;

  capsule_type = _http_decode_varint (&p, end);
  if (capsule_type == HTTP_INVALID_VARINT)
    {
      clib_warning ("failed to parse capsule type");
      return -1;
    }

  if (p == end)
    {
      clib_warning ("capsule length missing");
      return -1;
    }

  capsule_value_len = _http_decode_varint (&p, end);
  if (capsule_value_len == HTTP_INVALID_VARINT)
    {
      clib_warning ("failed to parse capsule length");
      return -1;
    }

  *type = capsule_type;
  *value_offset = p - data;
  *value_len = capsule_value_len;
  return 0;
}

/**
 * Decapsulate UDP payload from datagram capsule.
 *
 * @param data           Input buffer.
 * @param len            Length of given buffer.
 * @param payload_offset Offset of the UDP proxying payload (ignore if capsule
 *                       should be skipped).
 * @param payload_len    Length of the UDP proxying payload (or number of bytes
 *                       to skip).
 *
 * @return @c -1 if capsule datagram is invalid (session need to be aborted)
 * @return @c 0 if capsule contains UDP payload
 * @return @c 1 if capsule should be skipped
 */
always_inline int
http_decap_udp_payload_datagram (u8 *data, u64 len, u8 *payload_offset,
				 u64 *payload_len)
{
  int rv;
  u8 *p = data;
  u8 *end = data + len;
  u64 capsule_type, value_len, context_id;
  u8 value_offset;

  rv = _http_parse_capsule (p, len, &capsule_type, &value_offset, &value_len);
  if (rv)
    return rv;

  /* skip unknown capsule type or empty capsule */
  if ((capsule_type != HTTP_CAPSULE_TYPE_DATAGRAM) || (value_len == 0))
    {
      *payload_len = value_len + value_offset;
      return 1;
    }

  p += value_offset;
  if (p == end)
    {
      clib_warning ("context ID missing");
      return -1;
    }

  /* context ID field should be zero (RFC9298 section 4) */
  context_id = _http_decode_varint (&p, end);
  if (context_id != 0)
    {
      *payload_len = value_len + value_offset;
      return 1;
    }

  *payload_offset = p - data;
  *payload_len = value_len - 1;

  /* payload longer than 65527 is considered as error (RFC9298 section 5) */
  if (*payload_len > HTTP_UDP_PAYLOAD_MAX_LEN)
    {
      clib_warning ("UDP payload length too long");
      return -1;
    }

  return 0;
}

/**
 * Encapsulate UDP payload to datagram capsule.
 *
 * @param buf         Capsule buffer under construction.
 * @param payload_len Length of the UDP proxying payload.
 *
 * @return Pointer to the UDP payload in capsule buffer.
 *
 * @note Capsule buffer need extra @c HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD
 * bytes to be allocated.
 */
always_inline u8 *
http_encap_udp_payload_datagram (u8 *buf, u64 payload_len)
{
  /* capsule type */
  *buf++ = HTTP_CAPSULE_TYPE_DATAGRAM;

  /* capsule length */
  buf = _http_encode_varint (buf, payload_len + 1);

  /* context ID */
  *buf++ = 0;

  return buf;
}

#endif /* SRC_PLUGINS_HTTP_HTTP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
