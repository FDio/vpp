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
#include <vpp/app/version.h>

#include <vppinfra/time_range.h>

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <http/http_buffer.h>

#define HTTP_DEBUG 0

#if HTTP_DEBUG
#define HTTP_DBG(_lvl, _fmt, _args...)                                        \
  if (_lvl <= HTTP_DEBUG)                                                     \
  clib_warning (_fmt, ##_args)
#else
#define HTTP_DBG(_lvl, _fmt, _args...)
#endif

typedef struct http_conn_id_
{
  union
  {
    session_handle_t app_session_handle;
    u32 parent_app_api_ctx;
  };
  session_handle_t tc_session_handle;
  u32 parent_app_wrk_index;
} http_conn_id_t;

STATIC_ASSERT (sizeof (http_conn_id_t) <= TRANSPORT_CONN_ID_LEN,
	       "ctx id must be less than TRANSPORT_CONN_ID_LEN");

typedef struct
{
  char *base;
  uword len;
} http_token_t;

#define http_token_lit(s) (s), sizeof (s) - 1

typedef enum http_conn_state_
{
  HTTP_CONN_STATE_LISTEN,
  HTTP_CONN_STATE_CONNECTING,
  HTTP_CONN_STATE_ESTABLISHED,
  HTTP_CONN_STATE_TRANSPORT_CLOSED,
  HTTP_CONN_STATE_APP_CLOSED,
  HTTP_CONN_STATE_CLOSED
} http_conn_state_t;

typedef enum http_state_
{
  HTTP_STATE_IDLE = 0,
  HTTP_STATE_WAIT_APP_METHOD,
  HTTP_STATE_WAIT_CLIENT_METHOD,
  HTTP_STATE_WAIT_SERVER_REPLY,
  HTTP_STATE_WAIT_APP_REPLY,
  HTTP_STATE_CLIENT_IO_MORE_DATA,
  HTTP_STATE_APP_IO_MORE_DATA,
  HTTP_N_STATES,
} http_state_t;

typedef enum http_req_method_
{
  HTTP_REQ_GET = 0,
  HTTP_REQ_POST,
} http_req_method_t;

typedef enum http_msg_type_
{
  HTTP_MSG_REQUEST,
  HTTP_MSG_REPLY
} http_msg_type_t;

typedef enum http_target_form_
{
  HTTP_TARGET_ORIGIN_FORM,
  HTTP_TARGET_ABSOLUTE_FORM,
  HTTP_TARGET_AUTHORITY_FORM,
  HTTP_TARGET_ASTERISK_FORM
} http_target_form_t;

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
  _ (ACCEPT, "Accept")                                                        \
  _ (ACCEPT_CHARSET, "Accept-Charset")                                        \
  _ (ACCEPT_ENCODING, "Accept-Encoding")                                      \
  _ (ACCEPT_LANGUAGE, "Accept-Language")                                      \
  _ (ACCEPT_RANGES, "Accept-Ranges")                                          \
  _ (ACCESS_CONTROL_ALLOW_CREDENTIALS, "Access-Control-Allow-Credentials")    \
  _ (ACCESS_CONTROL_ALLOW_HEADERS, "Access-Control-Allow-Headers")            \
  _ (ACCESS_CONTROL_ALLOW_METHODS, "Access-Control-Allow-Methods")            \
  _ (ACCESS_CONTROL_ALLOW_ORIGIN, "Access-Control-Allow-Origin")              \
  _ (ACCESS_CONTROL_EXPOSE_HEADERS, "Access-Control-Expose-Headers")          \
  _ (ACCESS_CONTROL_MAX_AGE, "Access-Control-Max-Age")                        \
  _ (ACCESS_CONTROL_REQUEST_HEADERS, "Access-Control-Request-Headers")        \
  _ (ACCESS_CONTROL_REQUEST_METHOD, "Access-Control-Request-Method")          \
  _ (AGE, "Age")                                                              \
  _ (ALLOW, "Allow")                                                          \
  _ (ALPN, "ALPN")                                                            \
  _ (ALT_SVC, "Alt-Svc")                                                      \
  _ (ALT_USED, "Alt-Used")                                                    \
  _ (ALTERNATES, "Alternates")                                                \
  _ (AUTHENTICATION_CONTROL, "Authentication-Control")                        \
  _ (AUTHENTICATION_INFO, "Authentication-Info")                              \
  _ (AUTHORIZATION, "Authorization")                                          \
  _ (CACHE_CONTROL, "Cache-Control")                                          \
  _ (CACHE_STATUS, "Cache-Status")                                            \
  _ (CAPSULE_PROTOCOL, "Capsule-Protocol")                                    \
  _ (CDN_CACHE_CONTROL, "CDN-Cache-Control")                                  \
  _ (CDN_LOOP, "CDN-Loop")                                                    \
  _ (CLIENT_CERT, "Client-Cert")                                              \
  _ (CLIENT_CERT_CHAIN, "Client-Cert-Chain")                                  \
  _ (CLOSE, "Close")                                                          \
  _ (CONNECTION, "Connection")                                                \
  _ (CONTENT_DIGEST, "Content-Digest")                                        \
  _ (CONTENT_DISPOSITION, "Content-Disposition")                              \
  _ (CONTENT_ENCODING, "Content-Encoding")                                    \
  _ (CONTENT_LANGUAGE, "Content-Language")                                    \
  _ (CONTENT_LENGTH, "Content-Length")                                        \
  _ (CONTENT_LOCATION, "Content-Location")                                    \
  _ (CONTENT_RANGE, "Content-Range")                                          \
  _ (CONTENT_TYPE, "Content-Type")                                            \
  _ (COOKIE, "Cookie")                                                        \
  _ (DATE, "Date")                                                            \
  _ (DIGEST, "Digest")                                                        \
  _ (DPOP, "DPoP")                                                            \
  _ (DPOP_NONCE, "DPoP-Nonce")                                                \
  _ (EARLY_DATA, "Early-Data")                                                \
  _ (ETAG, "ETag")                                                            \
  _ (EXPECT, "Expect")                                                        \
  _ (EXPIRES, "Expires")                                                      \
  _ (FORWARDED, "Forwarded")                                                  \
  _ (FROM, "From")                                                            \
  _ (HOST, "Host")                                                            \
  _ (IF_MATCH, "If-Match")                                                    \
  _ (IF_MODIFIED_SINCE, "If-Modified-Since")                                  \
  _ (IF_NONE_MATCH, "If-None-Match")                                          \
  _ (IF_RANGE, "If-Range")                                                    \
  _ (IF_UNMODIFIED_SINCE, "If-Unmodified-Since")                              \
  _ (KEEP_ALIVE, "Keep-Alive")                                                \
  _ (LAST_MODIFIED, "Last-Modified")                                          \
  _ (LINK, "Link")                                                            \
  _ (LOCATION, "Location")                                                    \
  _ (MAX_FORWARDS, "Max-Forwards")                                            \
  _ (ORIGIN, "Origin")                                                        \
  _ (PRIORITY, "Priority")                                                    \
  _ (PROXY_AUTHENTICATE, "Proxy-Authenticate")                                \
  _ (PROXY_AUTHENTICATION_INFO, "Proxy-Authentication-Info")                  \
  _ (PROXY_AUTHORIZATION, "Proxy-Authorization")                              \
  _ (PROXY_STATUS, "Proxy-Status")                                            \
  _ (RANGE, "Range")                                                          \
  _ (REFERER, "Referer")                                                      \
  _ (REPR_DIGEST, "Repr-Digest")                                              \
  _ (SET_COOKIE, "Set-Cookie")                                                \
  _ (SIGNATURE, "Signature")                                                  \
  _ (SIGNATURE_INPUT, "Signature-Input")                                      \
  _ (STRICT_TRANSPORT_SECURITY, "Strict-Transport-Security")                  \
  _ (RETRY_AFTER, "Retry-After")                                              \
  _ (SERVER, "Server")                                                        \
  _ (TE, "TE")                                                                \
  _ (TRAILER, "Trailer")                                                      \
  _ (TRANSFER_ENCODING, "Transfer-Encoding")                                  \
  _ (UPGRADE, "Upgrade")                                                      \
  _ (USER_AGENT, "User-Agent")                                                \
  _ (VARY, "Vary")                                                            \
  _ (VIA, "Via")                                                              \
  _ (WANT_CONTENT_DIGEST, "Want-Content-Digest")                              \
  _ (WANT_REPR_DIGEST, "Want-Repr-Digest")                                    \
  _ (WWW_AUTHENTICATE, "WWW-Authenticate")

typedef enum http_header_name_
{
#define _(sym, str) HTTP_HEADER_##sym,
  foreach_http_header_name
#undef _
} http_header_name_t;

typedef enum http_msg_data_type_
{
  HTTP_MSG_DATA_INLINE,
  HTTP_MSG_DATA_PTR
} http_msg_data_type_t;

typedef struct http_msg_data_
{
  http_msg_data_type_t type;
  u64 len;
  http_target_form_t target_form;
  u32 target_path_offset;
  u32 target_path_len;
  u32 target_query_offset;
  u32 target_query_len;
  u32 headers_offset;
  u32 headers_len;
  u32 body_offset;
  u64 body_len;
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

typedef struct http_tc_
{
  union
  {
    transport_connection_t connection;
    http_conn_id_t c_http_conn_id;
  };
#define h_tc_session_handle c_http_conn_id.tc_session_handle
#define h_pa_wrk_index	    c_http_conn_id.parent_app_wrk_index
#define h_pa_session_handle c_http_conn_id.app_session_handle
#define h_pa_app_api_ctx    c_http_conn_id.parent_app_api_ctx
#define h_hc_index	    connection.c_index

  http_conn_state_t state;
  u32 timer_handle;
  u8 pending_timer;
  u8 *app_name;
  u8 *host;
  u8 is_server;

  /*
   * Current request
   */
  http_state_t http_state;
  http_req_method_t method;
  u8 *rx_buf;
  u32 rx_buf_offset;
  http_buffer_t tx_buf;
  u64 to_recv;
  u32 bytes_dequeued;
  u32 control_data_len; /* start line + headers + empty line */
  http_target_form_t target_form;
  u32 target_path_offset;
  u32 target_path_len;
  u32 target_query_offset;
  u32 target_query_len;
  u32 headers_offset;
  u32 headers_len;
  u32 body_offset;
  u64 body_len;
  u16 status_code;
} http_conn_t;

typedef struct http_worker_
{
  http_conn_t *conn_pool;
} http_worker_t;

typedef struct http_main_
{
  http_worker_t *wrk;
  http_conn_t *listener_pool;
  u32 app_index;

  clib_timebase_t timebase;

  u16 *sc_by_u16;
  /*
   * Runtime config
   */
  u8 debug_level;
  u8 is_init;

  /*
   * Config
   */
  u64 first_seg_size;
  u64 add_seg_size;
  u32 fifo_size;
} http_main_t;

always_inline int
_validate_target_syntax (u8 *target, int is_query, int *is_encoded)
{
  int i, encoded = 0;

  static uword valid_chars[4] = {
    /* !$&'()*+,-./0123456789:;= */
    0x2fffffd200000000,
    /* @ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~ */
    0x47fffffe87ffffff,
    0x0000000000000000,
    0x0000000000000000,
  };

  for (i = 0; i < vec_len (target); i++)
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
	  if ((i + 2) > vec_len (target))
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
 * @param path       Target path to validate.
 * @param is_encoded Return flag that indicates if percent-encoded (optional).
 *
 * @return @c 0 on success.
 */
always_inline int
http_validate_abs_path_syntax (u8 *path, int *is_encoded)
{
  return _validate_target_syntax (path, 0, is_encoded);
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
  return _validate_target_syntax (query, 1, is_encoded);
}

#define htoi(x) (isdigit (x) ? (x - '0') : (tolower (x) - 'a' + 10))

/**
 * Decode percent-encoded data.
 *
 * @param src Data to decode.
 *
 * @return New vector with decoded data.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_percent_decode (u8 *src)
{
  int i;
  u8 *decoded_uri = 0;

  for (i = 0; i < vec_len (src); i++)
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
 * Remove dot segments from path (RFC3986 section 5.2.4)
 *
 * @param path Path to sanitize.
 *
 * @return New vector with sanitized path.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_path_remove_dot_segments (u8 *path)
{
  u32 *segments = 0, *segments_len = 0, segment_len;
  u8 *new_path = 0;
  int i, ii;

  if (!path)
    return vec_new (u8, 0);

  segments = vec_new (u32, 1);
  /* first segment */
  segments[0] = 0;
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
      if (segment_len == 2 && path[segments[i]] == '.')
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

always_inline int
_parse_field_name (u8 **pos, u8 *end, u8 **field_name_start,
		   u32 *field_name_len)
{
  u32 name_len = 0;
  u8 *p;

  static uword tchar[4] = {
    /* !#$%'*+-.0123456789 */
    0x03ff6cba00000000,
    /* ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~ */
    0x57ffffffc7fffffe,
    0x0000000000000000,
    0x0000000000000000,
  };

  p = *pos;

  *field_name_start = p;
  while (p != end)
    {
      if (clib_bitmap_get_no_check (tchar, *p))
	{
	  name_len++;
	  p++;
	}
      else if (*p == ':')
	{
	  if (name_len == 0)
	    {
	      clib_warning ("empty field name");
	      return -1;
	    }
	  *field_name_len = name_len;
	  p++;
	  *pos = p;
	  return 0;
	}
      else
	{
	  clib_warning ("invalid character %d", *p);
	  return -1;
	}
    }
  clib_warning ("field name end not found");
  return -1;
}

always_inline int
_parse_field_value (u8 **pos, u8 *end, u8 **field_value_start,
		    u32 *field_value_len)
{
  u32 value_len = 0;
  u8 *p;

  p = *pos;

  /* skip leading whitespace */
  while (1)
    {
      if (p == end)
	{
	  clib_warning ("field value not found");
	  return -1;
	}
      else if (*p != ' ' && *p != '\t')
	{
	  break;
	}
      p++;
    }

  *field_value_start = p;
  while (p != end)
    {
      if (*p == '\r')
	{
	  if ((end - p) < 1)
	    {
	      clib_warning ("incorrect field line end");
	      return -1;
	    }
	  p++;
	  if (*p == '\n')
	    {
	      if (value_len == 0)
		{
		  clib_warning ("empty field value");
		  return -1;
		}
	      p++;
	      *pos = p;
	      /* skip trailing whitespace */
	      p = *field_value_start + value_len - 1;
	      while (*p == ' ' || *p == '\t')
		{
		  p--;
		  value_len--;
		}
	      *field_value_len = value_len;
	      return 0;
	    }
	  clib_warning ("CR without LF");
	  return -1;
	}
      if (*p < ' ' && *p != '\t')
	{
	  clib_warning ("invalid character %d", *p);
	  return -1;
	}
      p++;
      value_len++;
    }

  clib_warning ("field value end not found");
  return -1;
}

typedef struct
{
  u8 *name;
  u8 *value;
} http_header_ht_t;

typedef struct
{
  http_token_t name;
  http_token_t value;
} http_header_t;

typedef struct
{
  http_header_ht_t *headers;
  uword *value_by_name;
} http_header_table_t;

/**
 * Free header table's memory.
 *
 * @param ht Header table to free.
 */
always_inline void
http_free_header_table (http_header_table_t *ht)
{
  http_header_ht_t *header;
  vec_foreach (header, ht->headers)
    {
      vec_free (header->name);
      vec_free (header->value);
    }
  vec_free (ht->headers);
  hash_free (ht->value_by_name);
  clib_mem_free (ht);
}

/**
 * Parse headers in given vector.
 *
 * @param headers Vector to parse.
 * @param [out] header_table Parsed headers in case of success.
 *
 * @return @c 0 on success.
 *
 * The caller is responsible to free the returned @c header_table
 * using @c http_free_header_table .
 */
always_inline int
http_parse_headers (u8 *headers, http_header_table_t **header_table)
{
  u8 *pos, *end, *name_start, *value_start, *name;
  u32 name_len, value_len;
  int rv;
  http_header_ht_t *header;
  http_header_table_t *ht;
  uword *p;

  end = headers + vec_len (headers);
  pos = headers;

  ht = clib_mem_alloc (sizeof (*ht));
  ht->value_by_name = hash_create_string (0, sizeof (uword));
  ht->headers = 0;
  do
    {
      rv = _parse_field_name (&pos, end, &name_start, &name_len);
      if (rv != 0)
	{
	  http_free_header_table (ht);
	  return rv;
	}
      rv = _parse_field_value (&pos, end, &value_start, &value_len);
      if (rv != 0)
	{
	  http_free_header_table (ht);
	  return rv;
	}
      name = vec_new (u8, name_len);
      clib_memcpy (name, name_start, name_len);
      vec_terminate_c_string (name);
      /* check if header is repeated */
      p = hash_get_mem (ht->value_by_name, name);
      if (p)
	{
	  /* if yes combine values */
	  header = vec_elt_at_index (ht->headers, p[0]);
	  vec_pop (header->value); /* drop null byte */
	  header->value = format (header->value, ", %U%c", format_ascii_bytes,
				  value_start, value_len, 0);
	  vec_free (name);
	  continue;
	}
      /* or create new record */
      vec_add2 (ht->headers, header, sizeof (*header));
      header->name = name;
      header->value = vec_new (u8, value_len);
      clib_memcpy (header->value, value_start, value_len);
      vec_terminate_c_string (header->value);
      hash_set_mem (ht->value_by_name, header->name, header - ht->headers);
    }
  while (pos != end);

  *header_table = ht;

  return 0;
}

/**
 * Try to find given header name in header table.
 *
 * @param header_table Header table to search.
 * @param name Header name to match.
 *
 * @return Header's value in case of success, @c 0 otherwise.
 */
always_inline const char *
http_get_header (http_header_table_t *header_table, const char *name)
{
  uword *p;
  http_header_ht_t *header;

  p = hash_get_mem (header_table->value_by_name, name);
  if (p)
    {
      header = vec_elt_at_index (header_table->headers, p[0]);
      return (const char *) header->value;
    }

  return 0;
}

/**
 * Add header to the list.
 *
 * @param headers Header list.
 * @param name Pointer to header's name buffer.
 * @param name_len Length of the name.
 * @param value Pointer to header's value buffer.
 * @param value_len Length of the value.
 *
 * @note Headers added at protocol layer: Date, Server, Content-Length
 */
always_inline void
http_add_header (http_header_t **headers, const char *name, uword name_len,
		 const char *value, uword value_len)
{
  http_header_t *header;
  vec_add2 (*headers, header, 1);
  header->name.base = (char *) name;
  header->name.len = name_len;
  header->value.base = (char *) value;
  header->value.len = value_len;
}

/**
 * Serialize the header list.
 *
 * @param headers Header list to serialize.
 *
 * @return New vector with serialized headers.
 *
 * The caller is always responsible to free the returned vector.
 */
always_inline u8 *
http_serialize_headers (http_header_t *headers)
{
  u8 *headers_buf = 0, *dst;
  u32 headers_buf_len = 2;
  http_header_t *header;

  vec_foreach (header, headers)
    headers_buf_len += header->name.len + header->value.len + 4;

  vec_validate (headers_buf, headers_buf_len - 1);
  dst = headers_buf;

  vec_foreach (header, headers)
    {
      clib_memcpy (dst, header->name.base, header->name.len);
      dst += header->name.len;
      *dst++ = ':';
      *dst++ = ' ';
      clib_memcpy (dst, header->value.base, header->value.len);
      dst += header->value.len;
      *dst++ = '\r';
      *dst++ = '\n';
    }
  *dst++ = '\r';
  *dst = '\n';
  return headers_buf;
}

typedef struct
{
  ip46_address_t ip;
  u16 port;
  u8 is_ip4;
} http_uri_t;

always_inline int
http_parse_authority_form_target (u8 *target, http_uri_t *authority)
{
  unformat_input_t input;
  u32 port;
  int rv = 0;

  unformat_init_vector (&input, vec_dup (target));
  if (unformat (&input, "[%U]:%d", unformat_ip6_address, &authority->ip.ip6,
		&port))
    {
      authority->port = clib_host_to_net_u16 (port);
      authority->is_ip4 = 0;
    }
  else if (unformat (&input, "%U:%d", unformat_ip4_address, &authority->ip.ip4,
		     &port))
    {
      authority->port = clib_host_to_net_u16 (port);
      authority->is_ip4 = 1;
    }
  /* TODO reg-name resolution */
  else
    {
      clib_warning ("unsupported format '%v'", target);
      rv = -1;
    }
  unformat_free (&input);
  return rv;
}

always_inline u8 *
http_serialize_authority_form_target (http_uri_t *authority)
{
  u8 *s;

  if (authority->is_ip4)
    s = format (0, "%U:%d", format_ip4_address, &authority->ip.ip4,
		clib_net_to_host_u16 (authority->port));
  else
    s = format (0, "[%U]:%d", format_ip6_address, &authority->ip.ip6,
		clib_net_to_host_u16 (authority->port));

  return s;
}

#endif /* SRC_PLUGINS_HTTP_HTTP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
