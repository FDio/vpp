/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/tcp/tcp.h>

#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_private.h>
#include <http/http_status_codes.h>
#include <http/http_timer.h>

const char *http1_upgrade_proto_str[] = { "",
#define _(sym, str) str,
					  foreach_http_upgrade_proto
#undef _
};

/* estimated http response/request overhead, excluded app headers and target */
#define HTTP1_MESSAGE_OVERHEAD 256

/* HTTP/1 parser results; only request-line parsing can upgrade to HTTP/2. */
typedef enum http1_parse_result_ : i8
{
  HTTP1_PARSE_ERROR = -1,
  HTTP1_PARSE_OK = 0,
  HTTP1_PARSE_INCOMPLETE = 1,
  HTTP1_PARSE_UPGRADE_HTTP2 = 2,
} http1_parse_result_t;

typedef enum http1_parse_state_ : u8
{
  HTTP1_PARSE_STATE_IDLE,
  HTTP1_PARSE_STATE_REQUEST_LINE,
  HTTP1_PARSE_STATE_STATUS_LINE,
  HTTP1_PARSE_STATE_HEADER_CHECK,
  HTTP1_PARSE_STATE_HEADER_NAME,
  HTTP1_PARSE_STATE_HEADER_VALUE_START,
  HTTP1_PARSE_STATE_HEADER_VALUE,
  HTTP1_PARSE_STATE_DONE,
} http1_parse_state_t;

/**
 * http error boilerplate
 */
static const char *error_template = "HTTP/1.1 %s\r\n"
				    "Date: %U GMT\r\n"
				    "Connection: close\r\n"
				    "Content-Length: 0\r\n\r\n";

/**
 * http response boilerplate
 */
static const char *response_template = "HTTP/1.1 %s\r\n"
				       "Date: %U GMT\r\n"
				       "Server: %v\r\n";

static const char *content_len_template = "Content-Length: %llu\r\n";

static const char *alt_svc_template = "Alt-Svc: %v\r\n";

static const char *connection_upgrade_template = "Connection: upgrade\r\n"
						 "Upgrade: %s\r\n";

/**
 * http request boilerplate
 */
static const char *get_request_template = "GET %U HTTP/1.1\r\n"
					  "Host: %v\r\n"
					  "User-Agent: %v\r\n";

static const char *post_request_template = "POST %U HTTP/1.1\r\n"
					   "Host: %v\r\n"
					   "User-Agent: %v\r\n"
					   "Content-Length: %llu\r\n";

static const char *put_request_template = "PUT %U HTTP/1.1\r\n"
					  "Host: %v\r\n"
					  "User-Agent: %v\r\n"
					  "Content-Length: %llu\r\n";

static const char *put_chunked_request_template =
  "PUT %U HTTP/1.1\r\n"
  "Host: %v\r\n"
  "User-Agent: %v\r\n"
  "Transfer-Encoding: chunked\r\n";

always_inline http_ctx_t *
http1_conn_alloc_req (u32 hc_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req, *hc;
  u32 req_index;
  http_req_handle_t hr_handle;

  req_index = http_ctx_alloc_w_thread (thread_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  req->c_s_index = SESSION_INVALID_INDEX;
  hr_handle.version = HTTP_VERSION_1;
  hr_handle.req_index = req_index;
  req->hr_req_handle = hr_handle.as_u32;
  req->hr_hc_index = hc->hc_hc_index;
  req->c_thread_index = hc->c_thread_index;
  req->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  hc->hc_parent_req_index = req_index;
  hc->flags |= HTTP_CONN_F_HAS_REQUEST;
  return req;
}

always_inline http_ctx_t *
http1_conn_get_req (http_ctx_t *hc)
{
  return http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
}

always_inline void
http1_conn_free_req (http_ctx_t *hc)
{
  http_ctx_t *req;

  req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
  vec_free (req->headers);
  vec_free (req->target);
  http_buffer_free (&req->tx_buf);
  http_ctx_free (req);
  hc->flags &= ~HTTP_CONN_F_HAS_REQUEST;
}

/* Deschedule http session and wait for deq notification if underlying ts tx
 * fifo almost full */
static_always_inline void
http1_check_and_deschedule (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  if (http_io_ts_check_write_thresh (hc))
    {
      http_req_deschedule (req, sp);
      http_io_ts_add_want_deq_ntf (hc);
    }
}

static void
http1_send_error (http_ctx_t *hc, http_status_code_t ec, transport_send_params_t *sp)
{
  u8 *data;

  if (ec >= HTTP_N_STATUS)
    ec = HTTP_STATUS_INTERNAL_ERROR;

  data = format (0, error_template, http_status_code_str[ec],
		 format_http_time_now, hc);
  HTTP_DBG (3, "%v", data);
  /* if ts tx fifo can't buffer bytes we just close connecton */
  if (PREDICT_TRUE (http_io_ts_write (hc, data, vec_len (data), sp, 1)))
    http_io_ts_after_write (hc, 0);
  vec_free (data);
}

static u8 *
http1_peek_range (http_ctx_t *hc, u32 offset, u32 len)
{
  session_t *ts = session_get_from_handle (hc->hc_tc_session_handle);
  u8 *rx_buf;
  int n_read;

  rx_buf = http_get_rx_buf_len (hc, len);
  n_read = svm_fifo_peek (ts->rx_fifo, offset, len, rx_buf);
  ASSERT (n_read == len);
  return rx_buf;
}

static u8 *
http1_read_message (http_ctx_t *hc)
{
  u32 available = http_io_ts_max_read (hc);
  if (PREDICT_FALSE (available == 0))
    return 0;

  return http1_peek_range (hc, 0, available);
}

static void
http1_parse_state_reset (http_ctx_t *req)
{
  req->http1_parse_state = HTTP1_PARSE_STATE_IDLE;
  req->rx_buf_offset = 0;
}

static int
http1_can_read_more (http_ctx_t *hc, u32 n_read)
{
  session_t *ts = session_get_from_handle (hc->hc_tc_session_handle);
  u32 min_space = 1;

  if (session_get_transport_proto (ts) == TRANSPORT_PROTO_TCP)
    {
      tcp_connection_t *tc = (tcp_connection_t *) session_get_transport (ts);

      /* TCP rounds the receive window down to a scale unit, then advertises
       * zero if it is smaller than the peer's MSS. The FIFO can therefore
       * stop receiving before it reaches its exact capacity. */
      min_space = round_pow2 (clib_max (tc->rcv_opts.mss, 1), 1U << tc->rcv_wscale);
    }

  return svm_fifo_size (ts->rx_fifo) - n_read >= min_space;
}

static http1_parse_result_t
http1_parse_target (http_ctx_t *req, u8 *rx_buf)
{
  u32 i;
  u8 *p, *end;

  /* asterisk-form  = "*" */
  if ((rx_buf[req->target_path_offset] == '*') && (req->target_path_len == 1))
    {
      req->target_form = HTTP_TARGET_ASTERISK_FORM;
      /* we do not support OPTIONS request */
      return HTTP1_PARSE_ERROR;
    }

  /* origin-form = 1*( "/" segment ) [ "?" query ] */
  if (rx_buf[req->target_path_offset] == '/')
    {
      /* drop leading slash */
      req->target_path_len--;
      req->target_path_offset++;
      req->target_form = HTTP_TARGET_ORIGIN_FORM;
      http_identify_optional_query (req, rx_buf);
      /* can't be CONNECT method */
      return req->method == HTTP_REQ_CONNECT ? HTTP1_PARSE_ERROR : HTTP1_PARSE_OK;
    }

  /* absolute-form =
   * scheme "://" host [ ":" port ] *( "/" segment ) [ "?" query ] */
  if (req->target_path_len > 8 &&
      !memcmp (rx_buf + req->target_path_offset, "http", 4))
    {
      req->scheme = HTTP_URL_SCHEME_HTTP;
      p = rx_buf + req->target_path_offset + 4;
      if (*p == 's')
	{
	  p++;
	  req->scheme = HTTP_URL_SCHEME_HTTPS;
	}
      if (*p++ == ':')
	{
	  expect_char ('/');
	  expect_char ('/');
	  req->target_form = HTTP_TARGET_ABSOLUTE_FORM;
	  req->target_authority_offset = p - rx_buf;
	  req->target_authority_len = 0;
	  end = rx_buf + req->target_path_offset + req->target_path_len;
	  while (p < end)
	    {
	      if (*p == '/')
		{
		  p++; /* drop leading slash */
		  req->target_path_offset = p - rx_buf;
		  req->target_path_len = end - p;
		  break;
		}
	      req->target_authority_len++;
	      p++;
	    }
	  if (!req->target_path_len)
	    {
	      clib_warning ("zero length host");
	      return HTTP1_PARSE_ERROR;
	    }
	  http_identify_optional_query (req, rx_buf);
	  /* can't be CONNECT method */
	  return req->method == HTTP_REQ_CONNECT ? HTTP1_PARSE_ERROR : HTTP1_PARSE_OK;
	}
    }

  /* masque-connect-udp-draft-03 masque://host:port/ */
  if (req->target_path_len > 10 && !memcmp (rx_buf + req->target_path_offset, "masque://", 9))
    {
      p = rx_buf + req->target_path_offset + req->target_path_len - 1;
      expect_char ('/');
      req->scheme = HTTP_URL_SCHEME_MASQUE;
      req->target_form = HTTP_TARGET_ABSOLUTE_FORM;
      req->target_authority_offset = 9;
      req->target_authority_len = req->target_path_len - 10;
      req->target_path_len = 0;
      req->target_path_offset = 0;
      /* can be CONNECT-UDP method only */
      return req->method == HTTP_REQ_CONNECT_UDP ? HTTP1_PARSE_OK : HTTP1_PARSE_ERROR;
    }

  /* authority-form = host ":" port */
  for (i = req->target_path_offset;
       i < (req->target_path_offset + req->target_path_len); i++)
    {
      if ((rx_buf[i] == ':') && (isdigit (rx_buf[i + 1])))
	{
	  req->target_authority_len = req->target_path_len;
	  req->target_path_len = 0;
	  req->target_authority_offset = req->target_path_offset;
	  req->target_path_offset = 0;
	  req->target_form = HTTP_TARGET_AUTHORITY_FORM;
	  /* "authority-form" is only used for CONNECT requests */
	  return req->method == HTTP_REQ_CONNECT ? HTTP1_PARSE_OK : HTTP1_PARSE_ERROR;
	}
    }

  return HTTP1_PARSE_ERROR;
}

static http1_parse_result_t
http1_find_line_end (http_ctx_t *hc, http_ctx_t *req, u8 is_request, u32 *line_end)
{
  u32 available = http_io_ts_max_read (hc), start = req->rx_buf_offset, i;
  session_t *ts = session_get_from_handle (hc->hc_tc_session_handle);
  u8 prefix[2], *rx_buf;

  /* A request may start with one optional empty line. */
  if (is_request && start == 0 && available)
    {
      int n_read = svm_fifo_peek (ts->rx_fifo, 0, 1, prefix);
      ASSERT (n_read == 1);
      if (prefix[0] == '\r' && available < 2)
	return HTTP1_PARSE_INCOMPLETE;
      if (prefix[0] == '\r')
	{
	  n_read = svm_fifo_peek (ts->rx_fifo, 0, 2, prefix);
	  ASSERT (n_read == 2);
	  if (prefix[1] == '\n')
	    start = 2;
	}
    }

  if (start >= available)
    {
      req->rx_buf_offset = start;
      return HTTP1_PARSE_INCOMPLETE;
    }

  rx_buf = http1_peek_range (hc, start, available - start);
  for (i = 0; i + 1 < available - start; i++)
    {
      if (rx_buf[i] == '\r' && rx_buf[i + 1] == '\n')
	{
	  *line_end = start + i;
	  req->rx_buf_offset = start + i + 2;
	  return HTTP1_PARSE_OK;
	}
    }

  /* Keep a trailing CR so the next byte can complete CRLF. */
  req->rx_buf_offset = rx_buf[available - start - 1] == '\r' ? available - 1 : available;
  return HTTP1_PARSE_INCOMPLETE;
}

static http1_parse_result_t
http1_parse_request_line (http_ctx_t *hc, http_ctx_t *req, u8 *rx_buf, u32 line_end,
			  http_status_code_t *ec)
{
  int i, target_len;
  u32 next_line_offset, method_offset;

  /* Ignore one optional leading CRLF (RFC9112 2.2). */
  method_offset = vec_len (rx_buf) >= 2 && rx_buf[0] == '\r' && rx_buf[1] == '\n' ? 2 : 0;

  /* request-line = method SP request-target SP HTTP-version CRLF */
  i = line_end;
  HTTP_DBG (2, "request line length: %d", i);
  req->control_data_len = i + 2;
  next_line_offset = req->control_data_len;

  /* A complete line must be long enough for method and version parsing. */
  if (i - method_offset < 10)
    {
      clib_warning ("request line too short");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }

  /* parse method */
  if (!memcmp (rx_buf + method_offset, "GET ", 4))
    {
      HTTP_DBG (1, "GET method");
      req->method = HTTP_REQ_GET;
      req->target_path_offset = method_offset + 4;
    }
  else if (!memcmp (rx_buf + method_offset, "POST ", 5))
    {
      HTTP_DBG (1, "POST method");
      req->method = HTTP_REQ_POST;
      req->target_path_offset = method_offset + 5;
    }
  else if (!memcmp (rx_buf + method_offset, "PUT ", 4))
    {
      HTTP_DBG (1, "PUT method");
      req->method = HTTP_REQ_PUT;
      req->target_path_offset = method_offset + 4;
    }
  else if (!memcmp (rx_buf + method_offset, "CONNECT ", 8))
    {
      HTTP_DBG (1, "CONNECT method");
      req->method = HTTP_REQ_CONNECT;
      req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
      req->target_path_offset = method_offset + 8;
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
    }
  else if (!memcmp (rx_buf + method_offset, "CONNECT-UDP ", 12) &&
	   (hc->flags & HTTP_CONN_F_CONNECT_UDP_DRAFT03))
    {
      HTTP_DBG (1, "CONNECT-UDP method");
      req->method = HTTP_REQ_CONNECT_UDP;
      req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
      req->target_path_offset = method_offset + 12;
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->req_flags |= HTTP_REQ_F_CONNECT_UDP_DRAFT03;
    }
  else if (!memcmp (rx_buf + method_offset, "PRI ", 4))
    {
      HTTP_DBG (1, "request start with PRI, upgrading to http/2");
      return HTTP1_PARSE_UPGRADE_HTTP2;
    }
  else
    {
      if (rx_buf[method_offset] >= 'A' && rx_buf[method_offset] <= 'Z')
	{
	  *ec = HTTP_STATUS_NOT_IMPLEMENTED;
	  return HTTP1_PARSE_ERROR;
	}
      else
	{
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return HTTP1_PARSE_ERROR;
	}
    }

  /* find version */
  i = http_v_find_index (rx_buf, next_line_offset - 11, 11, " HTTP/");
  if (i < 0)
    {
      clib_warning ("HTTP version not present");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }
  /* verify major version */
  if (isdigit (rx_buf[i + 6]))
    {
      if (rx_buf[i + 6] != '1')
	{
	  clib_warning ("HTTP major version '%c' not supported",
			rx_buf[i + 6]);
	  *ec = HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
	  return HTTP1_PARSE_ERROR;
	}
    }
  else
    {
      clib_warning ("HTTP major version '%c' is not digit", rx_buf[i + 6]);
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }

  /* parse request-target */
  HTTP_DBG (2, "http at %d", i);
  target_len = i - req->target_path_offset;
  HTTP_DBG (2, "target_len %d", target_len);
  if (target_len < 1)
    {
      clib_warning ("request-target not present");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }
  if (target_len > UINT16_MAX)
    {
      clib_warning ("request-target too long");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }
  req->target_path_len = target_len;
  req->target_query_offset = 0;
  req->target_query_len = 0;
  req->target_authority_len = 0;
  req->target_authority_offset = 0;
  if (http1_parse_target (req, rx_buf) != HTTP1_PARSE_OK)
    {
      clib_warning ("invalid target");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }
  HTTP_DBG (2, "request-target path length: %u", req->target_path_len);
  HTTP_DBG (2, "request-target path offset: %u", req->target_path_offset);
  HTTP_DBG (2, "request-target query length: %u", req->target_query_len);
  HTTP_DBG (2, "request-target query offset: %u", req->target_query_offset);

  /* set buffer offset to nex line start */
  req->rx_buf_offset = next_line_offset;

  return HTTP1_PARSE_OK;
}

static http1_parse_result_t
http1_parse_status_line (http_ctx_t *req, u8 *rx_buf, u32 line_end)
{
  int i = line_end;
  u32 next_line_offset;
  u8 *p, *end;
  u16 status_code = 0;

  /* status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF */
  HTTP_DBG (2, "status line length: %d", i);
  if (i < 12)
    {
      clib_warning ("status line too short (%d)", i);
      return HTTP1_PARSE_ERROR;
    }
  req->control_data_len = i + 2;
  next_line_offset = req->control_data_len;
  p = rx_buf;
  end = rx_buf + i;

  /* parse version */
  expect_char ('H');
  expect_char ('T');
  expect_char ('T');
  expect_char ('P');
  expect_char ('/');
  expect_char ('1');
  expect_char ('.');
  if (!isdigit (*p++))
    {
      clib_warning ("invalid HTTP minor version");
      return HTTP1_PARSE_ERROR;
    }

  /* skip space(s) */
  if (*p != ' ')
    {
      clib_warning ("no space after HTTP version");
      return HTTP1_PARSE_ERROR;
    }
  do
    {
      p++;
      if (p == end)
	{
	  clib_warning ("no status code");
	  return HTTP1_PARSE_ERROR;
	}
    }
  while (*p == ' ');

  /* parse status code */
  if ((end - p) < 3)
    {
      clib_warning ("not enough characters for status code");
      return HTTP1_PARSE_ERROR;
    }
  parse_int (status_code, 100);
  parse_int (status_code, 10);
  parse_int (status_code, 1);
  if (status_code < 100 || status_code > 599)
    {
      clib_warning ("invalid status code %d", status_code);
      return HTTP1_PARSE_ERROR;
    }
  req->status_code = http_sc_by_u16 (status_code);
  HTTP_DBG (0, "status code: %d", status_code);

  /* set buffer offset to nex line start */
  req->rx_buf_offset = next_line_offset;

  return HTTP1_PARSE_OK;
}

static void
http1_parse_headers_start (http_ctx_t *req)
{
  vec_reset_length (req->headers);
  req->content_len_header_index = ~0;
  req->connection_header_index = ~0;
  req->upgrade_header_index = ~0;
  req->host_header_index = ~0;
  req->headers_offset = req->rx_buf_offset;
  req->http1_parse_state = HTTP1_PARSE_STATE_HEADER_CHECK;
}

static int
http1_header_name_is (http_ctx_t *hc, u32 name_offset, u32 name_len, const char *expected,
		      uword expected_len)
{
  u8 name_buf[32];
  session_t *ts;
  int n_read;

  if (name_len != expected_len || expected_len > sizeof (name_buf))
    return 0;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  n_read = svm_fifo_peek (ts->rx_fifo, name_offset, name_len, name_buf);
  ASSERT (n_read == name_len);
  return http_token_is_case ((const char *) name_buf, name_len, expected, expected_len);
}

static http1_parse_result_t
http1_identify_headers (http_ctx_t *hc, http_ctx_t *req, http_status_code_t *ec)
{
  u32 available = http_io_ts_max_read (hc), base = req->rx_buf_offset;
  u32 len, name_len, header_index;
  u8 *rx_buf;
  http_field_line_t *field_line;

  static uword tchar[4] = {
    /* !#$%'*+-.0123456789 */
    0x03ff6cba00000000,
    /* ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~ */
    0x57ffffffc7fffffe,
    0x0000000000000000,
    0x0000000000000000,
  };

  if (base >= available)
    return HTTP1_PARSE_INCOMPLETE;

  len = available - base;
  rx_buf = http1_peek_range (hc, base, len);

  while (1)
    {
      switch (req->http1_parse_state)
	{
	case HTTP1_PARSE_STATE_HEADER_CHECK:
	  if (req->rx_buf_offset == available)
	    return HTTP1_PARSE_INCOMPLETE;
	  if (rx_buf[req->rx_buf_offset - base] == '\r')
	    {
	      if (available - req->rx_buf_offset < 2)
		return HTTP1_PARSE_INCOMPLETE;
	      if (rx_buf[req->rx_buf_offset - base + 1] == '\n')
		{
		  req->headers_len = req->rx_buf_offset - req->headers_offset;
		  req->control_data_len += req->headers_len + 2;
		  req->http1_parse_state = HTTP1_PARSE_STATE_DONE;
		  HTTP_DBG (2, "headers length: %u", req->headers_len);
		  HTTP_DBG (2, "headers offset: %u", req->headers_offset);
		  return HTTP1_PARSE_OK;
		}
	    }
	  vec_add2 (req->headers, field_line, 1);
	  field_line->name_offset = req->rx_buf_offset - req->headers_offset;
	  field_line->name_len = 0;
	  field_line->value_offset = 0;
	  field_line->value_len = 0;
	  req->http1_parse_state = HTTP1_PARSE_STATE_HEADER_NAME;
	  break;

	case HTTP1_PARSE_STATE_HEADER_NAME:
	  while (req->rx_buf_offset < available)
	    {
	      u8 c = rx_buf[req->rx_buf_offset - base];
	      if (clib_bitmap_get_no_check (tchar, c))
		{
		  req->rx_buf_offset++;
		  continue;
		}
	      if (c != ':')
		{
		  clib_warning ("invalid character %d", c);
		  *ec = HTTP_STATUS_BAD_REQUEST;
		  return HTTP1_PARSE_ERROR;
		}
	      field_line = vec_elt_at_index (req->headers, vec_len (req->headers) - 1);
	      name_len = req->rx_buf_offset - req->headers_offset - field_line->name_offset;
	      if (!name_len)
		{
		  clib_warning ("empty field name");
		  *ec = HTTP_STATUS_BAD_REQUEST;
		  return HTTP1_PARSE_ERROR;
		}
	      field_line->name_len = name_len;
	      req->rx_buf_offset++;
	      req->http1_parse_state = HTTP1_PARSE_STATE_HEADER_VALUE_START;
	      break;
	    }
	  if (req->http1_parse_state == HTTP1_PARSE_STATE_HEADER_NAME)
	    return HTTP1_PARSE_INCOMPLETE;
	  break;

	case HTTP1_PARSE_STATE_HEADER_VALUE_START:
	  while (req->rx_buf_offset < available && (rx_buf[req->rx_buf_offset - base] == ' ' ||
						    rx_buf[req->rx_buf_offset - base] == '\t'))
	    req->rx_buf_offset++;
	  if (req->rx_buf_offset == available)
	    return HTTP1_PARSE_INCOMPLETE;
	  if (rx_buf[req->rx_buf_offset - base] == '\r')
	    {
	      if (available - req->rx_buf_offset < 2)
		return HTTP1_PARSE_INCOMPLETE;
	      clib_warning ("empty field value");
	      *ec = HTTP_STATUS_BAD_REQUEST;
	      return HTTP1_PARSE_ERROR;
	    }
	  field_line = vec_elt_at_index (req->headers, vec_len (req->headers) - 1);
	  field_line->value_offset = req->rx_buf_offset - req->headers_offset;
	  req->http1_parse_state = HTTP1_PARSE_STATE_HEADER_VALUE;
	  break;

	case HTTP1_PARSE_STATE_HEADER_VALUE:
	  field_line = vec_elt_at_index (req->headers, vec_len (req->headers) - 1);
	  while (req->rx_buf_offset < available)
	    {
	      u8 c = rx_buf[req->rx_buf_offset - base];
	      if (c == '\r')
		{
		  if (available - req->rx_buf_offset < 2)
		    return HTTP1_PARSE_INCOMPLETE;
		  if (rx_buf[req->rx_buf_offset - base + 1] != '\n')
		    {
		      clib_warning ("CR without LF");
		      *ec = HTTP_STATUS_BAD_REQUEST;
		      return HTTP1_PARSE_ERROR;
		    }
		  if (!field_line->value_len)
		    {
		      clib_warning ("empty field value");
		      *ec = HTTP_STATUS_BAD_REQUEST;
		      return HTTP1_PARSE_ERROR;
		    }
		  name_len = field_line->name_len;
		  header_index = field_line - req->headers;

		  /* find headers that will be used later in preprocessing */
		  if (req->content_len_header_index == ~0 &&
		      http1_header_name_is (hc, req->headers_offset + field_line->name_offset,
					    name_len,
					    http_header_name_token (HTTP_HEADER_CONTENT_LENGTH)))
		    req->content_len_header_index = header_index;
		  else if (req->connection_header_index == ~0 &&
			   http1_header_name_is (hc, req->headers_offset + field_line->name_offset,
						 name_len,
						 http_header_name_token (HTTP_HEADER_CONNECTION)))
		    req->connection_header_index = header_index;
		  else if (req->upgrade_header_index == ~0 &&
			   http1_header_name_is (hc, req->headers_offset + field_line->name_offset,
						 name_len,
						 http_header_name_token (HTTP_HEADER_UPGRADE)))
		    req->upgrade_header_index = header_index;
		  else if (req->host_header_index == ~0 &&
			   http1_header_name_is (hc, req->headers_offset + field_line->name_offset,
						 name_len,
						 http_header_name_token (HTTP_HEADER_HOST)))
		    req->host_header_index = header_index;

		  req->rx_buf_offset += 2;
		  req->http1_parse_state = HTTP1_PARSE_STATE_HEADER_CHECK;
		  break;
		}
	      if (c < ' ' && c != '\t')
		{
		  clib_warning ("invalid character %d", c);
		  *ec = HTTP_STATUS_BAD_REQUEST;
		  return HTTP1_PARSE_ERROR;
		}
	      req->rx_buf_offset++;
	      if (c != ' ' && c != '\t')
		field_line->value_len =
		  req->rx_buf_offset - req->headers_offset - field_line->value_offset;
	    }
	  if (req->http1_parse_state == HTTP1_PARSE_STATE_HEADER_VALUE)
	    return HTTP1_PARSE_INCOMPLETE;
	  break;

	case HTTP1_PARSE_STATE_DONE:
	  return HTTP1_PARSE_OK;

	default:
	  ASSERT (0);
	  return HTTP1_PARSE_ERROR;
	}
    }
}

static http1_parse_result_t
http1_identify_message_body (http_ctx_t *req, u8 *rx_buf, http_status_code_t *ec)
{
  req->body_len = 0;

  if (req->headers_len == 0)
    {
      HTTP_DBG (2, "no header, no message-body");
      return HTTP1_PARSE_OK;
    }
  if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
    {
      HTTP_DBG (2, "tunnel, no message-body");
      return HTTP1_PARSE_OK;
    }

  /* TODO check for chunked transfer coding */

  if (req->content_len_header_index == ~0)
    {
      HTTP_DBG (2, "Content-Length header not present, no message-body");
      return HTTP1_PARSE_OK;
    }

  if (http_parse_content_length (req, rx_buf))
    {
      *ec = HTTP_STATUS_BAD_REQUEST;
      return HTTP1_PARSE_ERROR;
    }

  req->body_offset = req->headers_offset + req->headers_len + 2;
  HTTP_DBG (2, "body length: %llu", req->body_len);
  HTTP_DBG (2, "body offset: %u", req->body_offset);

  return HTTP1_PARSE_OK;
}

static void
http1_check_connection_upgrade (http_ctx_t *req, u8 *rx_buf)
{
  http_field_line_t *connection, *upgrade;
  u8 skip;

  skip = (req->method != HTTP_REQ_GET) + (req->connection_header_index == ~0) +
	 (req->upgrade_header_index == ~0);
  if (skip)
    return;

  connection = vec_elt_at_index (req->headers, req->connection_header_index);
  /* connection options are case-insensitive (RFC9110 7.6.1) */
  if (http_token_is_case (
	http_field_line_value_token (connection, req, rx_buf),
	http_token_lit ("upgrade")))
    {
      upgrade = vec_elt_at_index (req->headers, req->upgrade_header_index);

      /* check upgrade protocol, we want to ignore something like upgrade to
       * newer HTTP version, only tunnels are supported */
      if (0)
	;
#define _(sym, str)                                                           \
  else if (http_token_is_case (                                               \
	     http_field_line_value_token (upgrade, req, rx_buf),              \
	     http_token_lit (str))) req->upgrade_proto =                      \
    HTTP_UPGRADE_PROTO_##sym;
      foreach_http_upgrade_proto
#undef _
	else return;

      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->method = HTTP_REQ_CONNECT;
    }
}

static void
http1_target_fixup (http_ctx_t *hc, http_ctx_t *req)
{
  http_field_line_t *host;

  if (req->target_form == HTTP_TARGET_ABSOLUTE_FORM)
    return;

  /* scheme fixup */
  req->scheme = http_get_transport_proto (hc) == TRANSPORT_PROTO_TLS ?
		  HTTP_URL_SCHEME_HTTPS :
		  HTTP_URL_SCHEME_HTTP;

  if (req->target_form == HTTP_TARGET_AUTHORITY_FORM ||
      req->host_header_index == ~0)
    return;

  /* authority fixup */
  host = vec_elt_at_index (req->headers, req->host_header_index);
  req->target_authority_offset = req->headers_offset + host->value_offset;
  req->target_authority_len = host->value_len;
}

static void
http1_write_app_headers (http_ctx_t *req, http_msg_t *msg, u8 **tx_buf)
{
  u8 *app_headers, *p, *end;

  /* read app header list */
  app_headers = http_get_app_header_list (req, msg);

  /* serialize app headers to tx_buf */
  end = app_headers + msg->data.headers_len;
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
	  vec_add2 (*tx_buf, p, name->len + value->len + 4);
	  clib_memcpy (p, name->token, name->len);
	  p += name->len;
	  *p++ = ':';
	  *p++ = ' ';
	  clib_memcpy (p, value->token, value->len);
	  p += value->len;
	  *p++ = '\r';
	  *p++ = '\n';
	}
      else
	{
	  http_app_header_t *header;
	  header = (http_app_header_t *) app_headers;
	  app_headers += sizeof (http_app_header_t) + header->value.len;
	  http_token_t name = { http_header_name_token (header->name.name) };
	  vec_add2 (*tx_buf, p, name.len + header->value.len + 4);
	  clib_memcpy (p, name.base, name.len);
	  p += name.len;
	  *p++ = ':';
	  *p++ = ' ';
	  clib_memcpy (p, header->value.token, header->value.len);
	  p += header->value.len;
	  *p++ = '\r';
	  *p++ = '\n';
	}
    }
}

/*************************************/
/* request state machine handlers RX */
/*************************************/

static http_sm_result_t
http1_req_state_wait_transport_reply (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  http1_parse_result_t rv;
  http_msg_t msg = {};
  u32 len, max_enq, body_sent;
  http_status_code_t ec;
  u8 *rx_buf;

  /* Nothing yet, wait for data or timer expire */
  if (!http_io_ts_max_read (hc))
    {
      HTTP_DBG (1, "no data to deq");
      return HTTP_SM_STOP;
    }

  if (req->http1_parse_state == HTTP1_PARSE_STATE_IDLE)
    {
      req->http1_parse_state = HTTP1_PARSE_STATE_STATUS_LINE;
      req->rx_buf_offset = 0;
    }

  if (req->http1_parse_state == HTTP1_PARSE_STATE_STATUS_LINE)
    {
      u32 line_end;
      rv = http1_find_line_end (hc, req, 0, &line_end);
      if (rv == HTTP1_PARSE_INCOMPLETE)
	goto incomplete;
      rx_buf = http1_peek_range (hc, 0, line_end + 2);
      rv = http1_parse_status_line (req, rx_buf, line_end);
      if (rv != HTTP1_PARSE_OK)
	goto error;
      http1_parse_headers_start (req);
    }

  rv = http1_identify_headers (hc, req, &ec);
  if (rv == HTTP1_PARSE_INCOMPLETE)
    goto incomplete;
  if (rv != HTTP1_PARSE_OK)
    goto error;

  rx_buf = http1_read_message (hc);
  ASSERT (rx_buf);
  HTTP_DBG (3, "%v", rx_buf);

  http_stats_responses_received_inc (hc->c_thread_index);

  rv = http1_identify_message_body (req, rx_buf, &ec);
  if (rv != HTTP1_PARSE_OK)
    goto error;

  /* send at least "control data" which is necessary minimum,
   * if there is some space send also portion of body */
  max_enq = http_io_as_max_write (req);
  max_enq -= sizeof (msg);
  if (max_enq < req->control_data_len)
    {
      clib_warning ("not enough room for control data in app's rx fifo");
      goto error;
    }
  len = clib_min (max_enq, vec_len (rx_buf));

  msg.type = HTTP_MSG_REPLY;
  msg.code = req->status_code;
  msg.data.headers_offset = req->headers_offset;
  msg.data.headers_len = req->headers_len;
  msg.data.body_offset = req->body_offset;
  msg.data.body_len = req->body_len;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = len;
  msg.data.headers_ctx = pointer_to_uword (req->headers);

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) }, { rx_buf, len } };

  http_io_as_write_segs (req, segs, 2);

  body_sent = len - req->control_data_len;
  req->to_recv = req->body_len - body_sent;
  if (req->to_recv == 0)
    {
      /* all sent, we are done */
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
    }
  else
    {
      /* stream rest of the response body */
      http_req_state_change (req, HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA);
    }

  http_io_ts_drain (hc, len);
  http1_parse_state_reset (req);
  http_io_ts_after_read (hc, 1);
  http_app_worker_rx_notify (req);
  return HTTP_SM_STOP;

incomplete:
  /* Keep the message in the transport FIFO until the next RX event. */
  if (http1_can_read_more (hc, http_io_ts_max_read (hc)))
    return HTTP_SM_STOP;
  clib_warning ("incomplete response fills transport rx fifo");

error:
  http_io_ts_drain_all (hc);
  http1_parse_state_reset (req);
  http_io_ts_after_read (hc, 1);
  session_transport_closing_notify (&req->connection);
  session_transport_closed_notify (&req->connection);
  http_disconnect_transport (hc);
  http_stats_proto_errors_inc (hc->c_thread_index);
  return HTTP_SM_ERROR;
}

static http_sm_result_t
http1_req_state_wait_transport_method (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  http_status_code_t ec = HTTP_STATUS_BAD_REQUEST;
  http_msg_t msg;
  http1_parse_result_t rv;
  u32 len, max_enq, body_sent;
  u64 max_deq;
  u8 *rx_buf;

  /* Nothing yet, wait for data or timer expire */
  if (!http_io_ts_max_read (hc))
    return HTTP_SM_STOP;

  if (req->http1_parse_state == HTTP1_PARSE_STATE_IDLE)
    {
      req->http1_parse_state = HTTP1_PARSE_STATE_REQUEST_LINE;
      req->rx_buf_offset = 0;
    }

  if (req->http1_parse_state == HTTP1_PARSE_STATE_REQUEST_LINE)
    {
      u32 line_end;
      rv = http1_find_line_end (hc, req, 1, &line_end);
      if (rv == HTTP1_PARSE_INCOMPLETE)
	goto incomplete;
      rx_buf = http1_peek_range (hc, 0, line_end + 2);
      rv = http1_parse_request_line (hc, req, rx_buf, line_end, &ec);
      if (rv == HTTP1_PARSE_UPGRADE_HTTP2)
	{
	  http1_conn_free_req (hc);
	  hc->hc_parent_req_index = SESSION_INVALID_INDEX;
	  http_conn_upgrade_version (hc, HTTP_VERSION_2);
	  hc->rx_expect = HTTP2_RX_EXPECT_CLIENT_PREFACE;
	  return HTTP_SM_STOP;
	}
      if (rv != HTTP1_PARSE_OK)
	goto error;
      http1_parse_headers_start (req);
    }

  rv = http1_identify_headers (hc, req, &ec);
  if (rv == HTTP1_PARSE_INCOMPLETE)
    goto incomplete;
  if (rv != HTTP1_PARSE_OK)
    goto error;

  rx_buf = http1_read_message (hc);
  ASSERT (rx_buf);
  HTTP_DBG (3, "%v", rx_buf);

  http_stats_requests_received_inc (hc->c_thread_index);

  /* RFC9112 3.2: Host is required even for absolute and authority-form */
  if (req->host_header_index == ~0)
    {
      HTTP_DBG (1, "Host header missing");
      ec = HTTP_STATUS_BAD_REQUEST;
      goto error;
    }

  http1_target_fixup (hc, req);
  http1_check_connection_upgrade (req, rx_buf);

  rv = http1_identify_message_body (req, rx_buf, &ec);
  if (rv != HTTP1_PARSE_OK)
    goto error;

  if (hc->flags & HTTP_CONN_F_NO_APP_SESSION)
    {
      /* notify app about new conn */
      if (http_conn_accept_request (hc, req, 0))
	goto error;
      http_stats_connections_accepted_inc (hc->c_thread_index);
      hc->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
    }
  /* send at least "control data" which is necessary minimum,
   * if there is some space send also portion of body */
  max_enq = http_io_as_max_write (req);
  max_enq -= sizeof (msg);
  if (max_enq < req->control_data_len)
    {
      clib_warning ("not enough room for control data in app's rx fifo");
      ec = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }
  /* do not dequeue more than one HTTP request, we do not support pipelining */
  max_deq = clib_min (req->control_data_len + req->body_len, vec_len (rx_buf));
  len = clib_min (max_enq, max_deq);

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = req->method;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = len;
  msg.data.scheme = req->scheme;
  msg.data.target_authority_offset = req->target_authority_offset;
  msg.data.target_authority_len = req->target_authority_len;
  msg.data.target_path_offset = req->target_path_offset;
  msg.data.target_path_len = req->target_path_len;
  msg.data.target_query_offset = req->target_query_offset;
  msg.data.target_query_len = req->target_query_len;
  msg.data.headers_offset = req->headers_offset;
  msg.data.headers_len = req->headers_len;
  msg.data.body_offset = req->body_offset;
  msg.data.body_len = req->body_len;
  msg.data.headers_ctx = pointer_to_uword (req->headers);
  msg.data.upgrade_proto = req->upgrade_proto;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) }, { rx_buf, len } };

  http_io_as_write_segs (req, segs, 2);

  body_sent = len - req->control_data_len;
  req->to_recv = req->body_len - body_sent;
  if (req->to_recv == 0)
    {
      /* drop everything, we do not support pipelining */
      http_io_ts_drain_all (hc);
      /* all sent, we are done */
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
    }
  else
    {
      http_io_ts_drain (hc, len);
      /* stream rest of the response body */
      http_req_state_change (req, HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA);
    }

  http1_parse_state_reset (req);
  http_io_ts_after_read (hc, 1);
  http_app_worker_rx_notify (req);

  return HTTP_SM_STOP;

incomplete:
  /* No more header bytes can arrive once the usable FIFO space is exhausted. */
  if (http1_can_read_more (hc, http_io_ts_max_read (hc)))
    return HTTP_SM_STOP;
  clib_warning ("incomplete request fills transport rx fifo");

error:
  http_io_ts_drain_all (hc);
  http1_parse_state_reset (req);
  http_io_ts_after_read (hc, 1);
  http1_send_error (hc, ec, 0);
  if (!(hc->flags & HTTP_CONN_F_NO_APP_SESSION))
    session_transport_closing_notify (&req->connection);
  http_stats_proto_errors_inc (hc->c_thread_index);
  http_disconnect_transport (hc);

  return HTTP_SM_ERROR;
}

static http_sm_result_t
http1_req_state_transport_io_more_data (http_ctx_t *hc, http_ctx_t *req,
					transport_send_params_t *sp)
{
  u32 n_written, max_len, max_deq, max_enq, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];

  max_deq = http_io_ts_max_read (hc);
  if (max_deq == 0)
    {
      HTTP_DBG (1, "no data to deq");
      return HTTP_SM_STOP;
    }

  max_enq = http_io_as_max_write (req);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_stats_as_fifo_efull_inc (hc->c_thread_index);
      http_io_as_add_want_deq_ntf (req);
      return HTTP_SM_STOP;
    }

  max_len = clib_min (max_enq, max_deq);
  http_io_ts_read_segs (hc, segs, &n_segs, max_len);

  n_written = http_io_as_write_segs (req, segs, n_segs);

  if (n_written > req->to_recv)
    {
      clib_warning ("http protocol error: received more data than expected");
      session_transport_closing_notify (&req->connection);
      http_disconnect_transport (hc);
      http_stats_proto_errors_inc (hc->c_thread_index);
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
      return HTTP_SM_ERROR;
    }
  req->to_recv -= n_written;
  http_io_ts_drain (hc, n_written);
  HTTP_DBG (1, "drained %d from ts; remains %lu", n_written, req->to_recv);

  /* Finished transaction:
   * server back to HTTP_REQ_STATE_WAIT_APP_REPLY
   * client to HTTP_REQ_STATE_WAIT_APP_METHOD */
  if (req->to_recv == 0)
    http_req_state_change (req, (hc->flags & HTTP_CONN_F_IS_SERVER) ?
				  HTTP_REQ_STATE_WAIT_APP_REPLY :
				  HTTP_REQ_STATE_WAIT_APP_METHOD);

  http_app_worker_rx_notify (req);

  http_io_ts_after_read (hc, 0);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_tunnel_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  u32 n_written, max_deq, max_enq, max_read, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];

  HTTP_DBG (1, "tunnel received data from client");

  max_deq = http_io_ts_max_read (hc);
  if (PREDICT_FALSE (max_deq == 0))
    {
      HTTP_DBG (1, "max_deq == 0");
      return HTTP_SM_STOP;
    }
  max_enq = http_io_as_max_write (req);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_stats_as_fifo_efull_inc (hc->c_thread_index);
      http_io_as_add_want_deq_ntf (req);
      return HTTP_SM_STOP;
    }
  max_read = clib_min (max_enq, max_deq);
  http_io_ts_read_segs (hc, segs, &n_segs, max_read);
  n_written = http_io_as_write_segs (req, segs, n_segs);
  http_io_ts_drain (hc, n_written);
  HTTP_DBG (1, "transfered %u bytes", n_written);
  http_app_worker_rx_notify (req);
  http_io_ts_after_read (hc, 0);

  return HTTP_SM_STOP;
}

static_always_inline http_sm_result_t
http1_req_state_udp_tunnel_rx_inline (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				      u8 is_draft03)
{
  u32 to_deq, capsule_size, dgram_size, n_read, n_written = 0;
  http_capsule_error_t rv;
  u8 payload_offset = 0;
  u64 payload_len = 0;
  session_dgram_hdr_t hdr;
  u8 *buf = 0;

  HTTP_DBG (1, "udp tunnel received data from client");

  buf = http_get_rx_buf (hc);
  to_deq = http_io_ts_max_read (hc);

  while (to_deq > 0)
    {
      /* some bytes remaining to skip? */
      if (PREDICT_FALSE (req->capsule_ctx_rx.state == HTTP_CAPSULE_STATE_SKIP))
	{
	  if (req->capsule_ctx_rx.len >= to_deq)
	    {
	      http_io_ts_drain (hc, to_deq);
	      req->capsule_ctx_rx.len -= to_deq;
	      goto done;
	    }
	  else
	    {
	      http_io_ts_drain (hc, req->capsule_ctx_rx.len);
	      req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	      req->capsule_ctx_rx.len = 0;
	    }
	}
      n_read = http_io_ts_read (hc, buf, HTTP_CAPSULE_HEADER_MAX_SIZE, 1);
      rv = http_decap_udp_payload_datagram (buf, n_read, &payload_offset, &payload_len, is_draft03);
      HTTP_DBG (1, "rv=%d, payload_offset=%u, payload_len=%llu", rv,
		payload_offset, payload_len);
      if (PREDICT_FALSE (rv != HTTP_CAPSULE_NO_ERROR))
	{
	  if (rv == HTTP_CAPSULE_INVALID)
	    {
	      /* capsule datagram is invalid (session need to be aborted) */
	      http_io_ts_drain_all (hc);
	      session_transport_closing_notify (&req->connection);
	      session_transport_closed_notify (&req->connection);
	      http_disconnect_transport (hc);
	      http_stats_proto_errors_inc (hc->c_thread_index);
	      return HTTP_SM_STOP;
	    }
	  else if (rv == HTTP_CAPSULE_INCOMPLETE)
	    {
	      HTTP_DBG (1, "capsule header not complete");
	      goto done;
	    }
	  else
	    {
	      /* unknown capsule should be skipped */
	      if (payload_len <= to_deq)
		{
		  http_io_ts_drain (hc, payload_len);
		  to_deq -= payload_len;
		  continue;
		}
	      else
		{
		  http_io_ts_drain (hc, to_deq);
		  req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_SKIP;
		  req->capsule_ctx_rx.len = payload_len - to_deq;
		  goto done;
		}
	    }
	}
      capsule_size = payload_offset + payload_len;
      /* check if we have the full capsule */
      if (PREDICT_FALSE (to_deq < capsule_size))
	{
	  HTTP_DBG (1, "capsule not complete");
	  goto done;
	}

      dgram_size = sizeof (hdr) + payload_len;
      if (http_io_as_max_write (req) < dgram_size)
	{
	  HTTP_DBG (1, "app's rx fifo full");
	  http_stats_as_fifo_efull_inc (hc->c_thread_index);
	  http_io_as_add_want_deq_ntf (req);
	  goto done;
	}

      http_io_ts_drain (hc, payload_offset);

      /* read capsule payload */
      http_io_ts_read (hc, buf, payload_len, 0);

      hdr.data_length = payload_len;
      hdr.data_offset = 0;
      hdr.gso_size = 0;

      /* send datagram header and payload */
      svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
				 { buf, payload_len } };
      http_io_as_write_segs (req, segs, 2);

      n_written += dgram_size;
      to_deq -= capsule_size;
    }

done:
  HTTP_DBG (1, "written %lu bytes", n_written);

  if (n_written)
    http_app_worker_rx_notify (req);

  http_io_ts_after_read (hc, 0);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_udp_tunnel_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  return http1_req_state_udp_tunnel_rx_inline (hc, req, sp, 0);
}

static http_sm_result_t
http1_req_state_udp_tunnel_draft03_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  return http1_req_state_udp_tunnel_rx_inline (hc, req, sp, 1);
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http1_req_state_wait_app_reply (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  u32 max_enq;
  http_status_code_t sc;
  http_msg_t msg;
  http_sm_result_t sm_result = HTTP_SM_ERROR;
  http_req_state_t next_state = HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD;

  http_get_app_msg (req, &msg, 1);

  ASSERT (msg.data.type < HTTP_MSG_DATA_N_TYPES);
  ASSERT (msg.type == HTTP_MSG_REPLY);
  ASSERT (msg.code < HTTP_N_STATUS);

  /* make sure ts tx fifo can actually buffer response message, this should be overestimated since
   * not all app header names are in text format, cap it up to fifo size */
  if (PREDICT_FALSE (http_io_ts_provision_chunks (
	hc, clib_min (HTTP1_MESSAGE_OVERHEAD + (msg.data.headers_len << 1),
		      http_io_ts_fifo_size (hc, 0)))))
    {
      HTTP_DBG (1, "http_io_ts_provision_chunks failed");
      http_stats_ts_fifo_egrow_inc (hc->c_thread_index);
      return HTTP_SM_STOP;
    }

  http_io_as_drain (req, sizeof (msg));

  vec_reset_length (http_tx_buf (hc));
  /*
   * Add "protocol layer" headers:
   * - current time
   * - server name
   * - data length
   */
  http_tx_buf (hc) = format (http_tx_buf (hc), response_template, http_status_code_str[msg.code],
			     /* Date */
			     format_http_time_now, hc,
			     /* Server */
			     hc->app_name);

  if (hc->h3_alt_svc_port)
    http_tx_buf (hc) = format (http_tx_buf (hc), alt_svc_template, hc->h3_alt_svc_port);

  /* RFC9110 8.6: A server MUST NOT send Content-Length header field in a
   * 2xx (Successful) response to CONNECT or with a status code of 101
   * (Switching Protocols). */
  if ((req->req_flags & HTTP_REQ_F_IS_TUNNEL) &&
      (http_status_code_str[msg.code][0] == '2' || msg.code == HTTP_STATUS_SWITCHING_PROTOCOLS))
    {
      ASSERT (msg.data.body_len == 0);
      next_state = (req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03) ?
		     HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03 :
		     HTTP_REQ_STATE_TUNNEL;
      if (req->upgrade_proto > HTTP_UPGRADE_PROTO_NA)
	{
	  http_tx_buf (hc) = format (http_tx_buf (hc), connection_upgrade_template,
				     http1_upgrade_proto_str[req->upgrade_proto]);
	  if (req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
	      (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM))
	    next_state = HTTP_REQ_STATE_UDP_TUNNEL;
	}
      /* cleanup some stuff we don't need anymore in tunnel mode */
      vec_free (req->headers);
      http_buffer_free (&req->tx_buf);
      req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
      req->capsule_ctx_rx.len = 0;
    }
  else
    http_tx_buf (hc) = format (http_tx_buf (hc), content_len_template, msg.data.body_len);

  /* Add headers from app (if any) */
  if (msg.data.headers_len)
    {
      HTTP_DBG (0, "got headers from app, len %d", msg.data.headers_len);
      http1_write_app_headers (req, &msg, &http_tx_buf (hc));
    }
  /* Add empty line after headers */
  http_tx_buf (hc) = format (http_tx_buf (hc), "\r\n");
  HTTP_DBG (3, "%v", http_tx_buf (hc));

  max_enq = http_io_ts_max_write (hc, sp);
  if (max_enq < vec_len (http_tx_buf (hc)))
    {
      clib_warning ("sending status-line and headers failed!");
      sc = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }
  /* if this assert adjust formula in the beginning where we try to provision ts fifo chunks */
  ASSERT ((HTTP1_MESSAGE_OVERHEAD + (msg.data.headers_len << 1)) > vec_len (http_tx_buf (hc)));
  http_io_ts_write (hc, http_tx_buf (hc), vec_len (http_tx_buf (hc)), sp, 0);

  if (msg.data.body_len)
    {
      /* Start sending the actual data */
      http_req_tx_buffer_init (req, &msg);
      next_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
      sm_result = HTTP_SM_CONTINUE;
    }
  else
    {
      /* No response body, we are done */
      sm_result = HTTP_SM_STOP;
    }

  http_req_state_change (req, next_state);

  http_io_ts_after_write (hc, 0);
  http_stats_responses_sent_inc (hc->c_thread_index);
  return sm_result;

error:
  http1_send_error (hc, sc, sp);
  session_transport_closing_notify (&req->connection);
  http_disconnect_transport (hc);
  http_stats_proto_errors_inc (hc->c_thread_index);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_wait_app_method (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  http_msg_t msg;
  u8 *target;
  u32 max_enq;
  http_sm_result_t sm_result = HTTP_SM_ERROR;
  http_req_state_t next_state;

  http_get_app_msg (req, &msg, 1);

  ASSERT (msg.data.type < HTTP_MSG_DATA_N_TYPES);
  ASSERT (msg.type == HTTP_MSG_REQUEST);

  /* make sure ts tx fifo can actually buffer request message, this should be overestimated since
   * not all app header names are in text format, cap it up to fifo size */
  if (PREDICT_FALSE (http_io_ts_provision_chunks (
	hc,
	clib_min (HTTP1_MESSAGE_OVERHEAD + (msg.data.headers_len << 1) + msg.data.target_path_len,
		  http_io_ts_fifo_size (hc, 0)))))
    {
      HTTP_DBG (1, "http_io_ts_provision_chunks failed");
      http_stats_ts_fifo_egrow_inc (hc->c_thread_index);
      return HTTP_SM_STOP;
    }

  http_io_as_drain (req, sizeof (msg));

  /* read request target */
  target = http_get_app_target (req, &msg);

  vec_reset_length (http_tx_buf (hc));
  /* currently we support only GET and POST method */
  if (msg.method_type == HTTP_REQ_GET)
    {
      if (msg.data.body_len)
	{
	  clib_warning ("GET request shouldn't include data");
	  goto error;
	}
      /*
       * Add "protocol layer" headers:
       * - host
       * - user agent
       */
      http_tx_buf (hc) = format (http_tx_buf (hc), get_request_template,
				 /* target */
				 format_http_bytes, target, msg.data.target_path_len,
				 /* Host */
				 hc->host,
				 /* User-Agent */
				 hc->app_name);

      next_state = HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY;
      sm_result = HTTP_SM_STOP;
    }
  else if (msg.method_type == HTTP_REQ_POST)
    {
      /*
       * Add "protocol layer" headers:
       * - host
       * - user agent
       * - content length
       */
      http_tx_buf (hc) = format (http_tx_buf (hc), post_request_template,
				 /* target */
				 format_http_bytes, target, msg.data.target_path_len,
				 /* Host */
				 hc->host,
				 /* User-Agent */
				 hc->app_name,
				 /* Content-Length */
				 msg.data.body_len);

      next_state =
	msg.data.body_len ? HTTP_REQ_STATE_APP_IO_MORE_DATA : HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY;
      sm_result = msg.data.body_len ? HTTP_SM_CONTINUE : HTTP_SM_STOP;
    }
  else if (msg.method_type == HTTP_REQ_PUT)
    {
      /* Check if this is a streaming PUT */
      if (msg.data.type == HTTP_MSG_DATA_STREAMING)
	{
	  /*
	   * Streaming PUT with chunked transfer encoding
	   */
	  http_tx_buf (hc) = format (http_tx_buf (hc), put_chunked_request_template,
				     /* target */
				     format_http_bytes, target, msg.data.target_path_len,
				     /* Host */
				     hc->host,
				     /* User-Agent */
				     hc->app_name);

	  /* For streaming, we need a different state */
	  next_state = HTTP_REQ_STATE_APP_IO_MORE_STREAMING_DATA;
	  sm_result = HTTP_SM_CONTINUE;
	}
      else
	{
	  if (!msg.data.body_len)
	    {
	      clib_warning ("PUT request should include data");
	      goto error;
	    }
	  /*
	   * Regular PUT with Content-Length
	   */
	  http_tx_buf (hc) = format (http_tx_buf (hc), put_request_template,
				     /* target */
				     format_http_bytes, target, msg.data.target_path_len,
				     /* Host */
				     hc->host,
				     /* User-Agent */
				     hc->app_name,
				     /* Content-Length */
				     msg.data.body_len);

	  next_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
	  sm_result = HTTP_SM_CONTINUE;
	}
    }

  else
    {
      clib_warning ("unsupported method %d", msg.method_type);
      goto error;
    }

  /* Add headers from app (if any) */
  if (msg.data.headers_len)
    {
      HTTP_DBG (0, "got headers from app, len %d", msg.data.headers_len);
      http1_write_app_headers (req, &msg, &http_tx_buf (hc));
    }
  /* Add empty line after headers */
  http_tx_buf (hc) = format (http_tx_buf (hc), "\r\n");
  HTTP_DBG (3, "%v", http_tx_buf (hc));

  max_enq = http_io_ts_max_write (hc, sp);
  if (max_enq < vec_len (http_tx_buf (hc)))
    {
      clib_warning ("sending request-line and headers failed!");
      sm_result = HTTP_SM_ERROR;
      goto error;
    }
  /* if this assert adjust formula in the beginning where we try to provision ts fifo chunks */
  ASSERT ((HTTP1_MESSAGE_OVERHEAD + (msg.data.headers_len << 1) + msg.data.target_path_len) >
	  vec_len (http_tx_buf (hc)));
  http_io_ts_write (hc, http_tx_buf (hc), vec_len (http_tx_buf (hc)), sp, 0);

  if (next_state != HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY)
    http_req_tx_buffer_init (req, &msg);

  http_req_state_change (req, next_state);

  http_io_ts_after_write (hc, 0);
  http_stats_requests_sent_inc (hc->c_thread_index);
  goto done;

error:
  http_io_as_drain_all (req);
  session_transport_closing_notify (&req->connection);
  session_transport_closed_notify (&req->connection);
  http_disconnect_transport (hc);
  http_stats_proto_errors_inc (hc->c_thread_index);

done:
  return sm_result;
}

static http_sm_result_t
http1_req_state_app_io_more_data (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  u32 max_write, n_read, n_segs, n_written = 0;
  http_buffer_t *hb = &req->tx_buf;
  svm_fifo_seg_t *seg;
  u8 finished = 0;

  ASSERT (http_buffer_bytes_left (hb) > 0);
  max_write = http_io_ts_max_write (hc, sp);
  if (max_write == 0)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_stats_ts_fifo_efull_inc (hc->c_thread_index);
      goto check_fifo;
    }

  n_read = http_buffer_get_segs (hb, max_write, &seg, &n_segs);
  if (n_read == 0)
    {
      HTTP_DBG (1, "no data to deq");
      goto check_fifo;
    }

  n_written = http_io_ts_write_segs (hc, seg, n_segs, sp, 1);
  if (PREDICT_FALSE (!n_written))
    goto check_fifo;

  http_buffer_drain (hb, n_written);
  finished = http_buffer_bytes_left (hb) == 0;

  if (finished)
    {
      /* Finished transaction:
       * server back to HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD
       * client to HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY */
      http_req_state_change (req, (hc->flags & HTTP_CONN_F_IS_SERVER) ?
				    HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD :
				    HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
      http_buffer_free (hb);
    }
  http_io_ts_after_write (hc, finished);

check_fifo:
  http1_check_and_deschedule (hc, req, sp);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_app_io_more_streaming_data (http_ctx_t *hc, http_ctx_t *req,
					    transport_send_params_t *sp)
{
  u32 max_write, chunk_size, n_segs, n_written = 0;
  http_buffer_t *hb = &req->tx_buf;
  svm_fifo_seg_t *seg;
  int finished = 0;
  int chunk_sz_value_headroom = 20;
  u8 chunk_hdr[32];
  int hdr_len;

  ASSERT (hb->type == HTTP_BUFFER_STREAMING);

  /* For streaming, check if we have data available */
  max_write = http_io_ts_max_write (hc, sp);
  /*
   * do not drain more than we are going to write at a max - which
   * is max_write minus chunk_sz_value_headroom (overhead for the chunk
   * size value) bytes to leave the room for chunk headers.
   */
  if (max_write < chunk_sz_value_headroom)
    {
      HTTP_DBG (1, "ts tx fifo full - before write");
      http_stats_ts_fifo_efull_inc (hc->c_thread_index);
      goto check_fifo;
    }
  chunk_size = http_buffer_get_segs (hb, max_write - chunk_sz_value_headroom,
				     &seg, &n_segs);
  if (chunk_size == 0)
    {
      /* No data available right now, wait for more */
      HTTP_DBG (1, "streaming: no data available");
      return HTTP_SM_STOP;
    }
  /* make sure ts tx fifo can actually buffer chunk */
  if (PREDICT_FALSE (http_io_ts_provision_chunks (hc, chunk_size + chunk_sz_value_headroom)))
    {
      http_stats_ts_fifo_egrow_inc (hc->c_thread_index);
      goto check_fifo;
    }

  /* Write chunk size in hex */
  hdr_len = snprintf ((char *) chunk_hdr, sizeof (chunk_hdr), "%x\r\n", chunk_size);
  http_io_ts_write (hc, chunk_hdr, hdr_len, sp, 0);

  /* Write chunk data */
  n_written = http_io_ts_write_segs (hc, seg, n_segs, sp, 0);

  /* Write chunk trailer */
  http_io_ts_write (hc, (u8 *) "\r\n", 2, sp, 0);

  http_buffer_drain (hb, n_written);

  finished = http_buffer_bytes_left (hb) == 0;
  if (finished)
    {
      /* Send final chunk (0-sized) */
      http_io_ts_write (hc, (u8 *) "0\r\n\r\n", 5, sp, 0);

      /* Finished transaction:
       * server back to HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD
       * client to HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY */
      http_req_state_change (req, (hc->flags & HTTP_CONN_F_IS_SERVER) ?
				    HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD :
				    HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
      http_buffer_free (hb);
    }
  http_io_ts_after_write (hc, finished);

check_fifo:
  http1_check_and_deschedule (hc, req, sp);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_tunnel_tx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  u32 n_written, max_deq, max_enq, max_read, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];

  HTTP_DBG (1, "tunnel received data from target");

  max_deq = http_io_as_max_read (req);
  if (PREDICT_FALSE (max_deq == 0))
    {
      HTTP_DBG (1, "max_deq == 0");
      goto check_fifo;
    }
  max_enq = http_io_ts_max_write (hc, sp);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_stats_ts_fifo_efull_inc (hc->c_thread_index);
      goto check_fifo;
    }
  max_read = clib_min (max_enq, max_deq);
  http_io_as_read_segs (req, segs, &n_segs, max_read);
  n_written = http_io_ts_write_segs (hc, segs, n_segs, sp, 1);
  if (PREDICT_FALSE (!n_written))
    goto check_fifo;
  http_io_as_drain (req, n_written);
  http_io_ts_after_write (hc, 0);

check_fifo:
  http1_check_and_deschedule (hc, req, sp);
  return HTTP_SM_STOP;
}

static_always_inline http_sm_result_t
http1_req_state_udp_tunnel_tx_inline (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				      u8 is_draft03)
{
  u32 to_deq, capsule_size, dgram_size;
  u8 written = 0;
  session_dgram_hdr_t hdr;
  u8 *buf;
  u8 *payload;

  HTTP_DBG (1, "udp tunnel received data from target");

  buf = http_tx_buf (hc);
  to_deq = http_io_as_max_read (req);

  while (to_deq > sizeof (hdr))
    {
      /* read datagram header */
      http_io_as_peek (req, (u8 *) &hdr, sizeof (hdr), 0);
      ASSERT (hdr.data_length <= HTTP_UDP_PAYLOAD_MAX_LEN);
      dgram_size = hdr.data_length + SESSION_CONN_HDR_LEN;
      if (PREDICT_FALSE (to_deq < dgram_size))
	{
	  HTTP_DBG (2, "datagram incomplete");
	  goto done;
	}

      if (http_io_ts_max_write (hc, sp) <
	  (hdr.data_length + HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD))
	{
	  HTTP_DBG (1, "ts tx fifo full");
	  http_stats_ts_fifo_efull_inc (hc->c_thread_index);
	  goto done;
	}
      /* make sure ts tx fifo can actually buffer capsule */
      if (PREDICT_FALSE (http_io_ts_provision_chunks (
	    hc, hdr.data_length + HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD)))
	{
	  http_stats_ts_fifo_egrow_inc (hc->c_thread_index);
	  goto done;
	}

      /* create capsule header */
      payload = http_encap_udp_payload_datagram (buf, hdr.data_length, is_draft03);
      capsule_size = (payload - buf) + hdr.data_length;
      /* read payload */
      http_io_as_peek (req, payload, hdr.data_length, sizeof (hdr));
      http_io_as_drain (req, dgram_size);
      /* send capsule */
      http_io_ts_write (hc, buf, capsule_size, sp, 0);

      written = 1;
      to_deq -= dgram_size;
    }

done:
  if (written)
    http_io_ts_after_write (hc, 0);
  http1_check_and_deschedule (hc, req, sp);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_udp_tunnel_tx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  return http1_req_state_udp_tunnel_tx_inline (hc, req, sp, 0);
}

static http_sm_result_t
http1_req_state_udp_tunnel_draft03_tx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp)
{
  return http1_req_state_udp_tunnel_tx_inline (hc, req, sp, 1);
}

/*************************/
/* request state machine */
/*************************/

static http_sm_handler tx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  http1_req_state_wait_app_method,
  0, /* wait transport reply */
  0, /* transport io more data */
  0, /* wait transport method */
  http1_req_state_wait_app_reply,
  http1_req_state_app_io_more_data,
  http1_req_state_tunnel_tx,
  http1_req_state_udp_tunnel_tx,
  http1_req_state_udp_tunnel_draft03_tx,
  http1_req_state_app_io_more_streaming_data,
};

static http_sm_handler rx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  http1_req_state_wait_transport_reply,
  http1_req_state_transport_io_more_data,
  http1_req_state_wait_transport_method,
  0, /* wait app reply */
  0, /* app io more data */
  http1_req_state_tunnel_rx,
  http1_req_state_udp_tunnel_rx,
  http1_req_state_udp_tunnel_draft03_rx,
  0, /* app io more streaming data */
};

static_always_inline int
http1_req_state_is_tx_valid (http_ctx_t *req)
{
  return tx_state_funcs[req->req_state] ? 1 : 0;
}

static_always_inline int
http1_req_state_is_rx_valid (http_ctx_t *req)
{
  return rx_state_funcs[req->req_state] ? 1 : 0;
}

static_always_inline void
http1_req_run_state_machine (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp, u8 is_tx)
{
  http_sm_result_t res;

  do
    {
      if (is_tx)
	res = tx_state_funcs[req->req_state](hc, req, sp);
      else
	res = rx_state_funcs[req->req_state](hc, req, 0);
      if (res == HTTP_SM_ERROR)
	{
	  HTTP_DBG (1, "error in state machine %d", res);
	  return;
	}
    }
  while (res == HTTP_SM_CONTINUE);

  /* Reset the session expiration timer */
  http_conn_timer_update (hc);
}

/*****************/
/* http core VFT */
/*****************/

static transport_connection_t *
http1_req_get_connection (u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  req = http_ctx_get_w_thread (req_index, thread_index);
  return &req->connection;
}

static u8 *
format_http1_req (u8 *s, va_list *args)
{
  http_ctx_t *req = va_arg (*args, http_ctx_t *);
  http_ctx_t *hc = va_arg (*args, http_ctx_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  s = format (s, "[%d:%d][H1] app_wrk %u hc_index %u ts %d:%d",
	      req->c_thread_index, req->c_s_index, req->hr_pa_wrk_index,
	      req->hr_hc_index, ts->thread_index, ts->session_index);

  return s;
}

static u8 *
http1_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  http_ctx_t *hc = va_arg (*args, http_ctx_t *);
  transport_fmt_req_t fmt = { .as_u32 = va_arg (*args, u32) };
  http_ctx_t *req;

  req = http_ctx_get_w_thread (req_index, thread_index);

  if (!transport_fmt_req_is_explicit (fmt))
    {
      s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http1_req, req, hc);
      if (fmt.level)
	{
	  s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, hc);
	  if (fmt.level > 1)
	    s = format (s, "\n conn_flags: %U\n", format_http_conn_flags, hc);
	}
      return s;
    }

  if (fmt.conn_id)
    s = format (s, "%U", format_http1_req, req, hc);
  if (fmt.transport_state)
    {
      if (fmt.conn_id)
	s = format (s, "\t");
      s = format (s, "%U", format_http_conn_state, hc);
    }
  if (fmt.transport_detail)
    s = format (s, "\n conn_flags: %U\n", format_http_conn_flags, hc);

  return s;
}

static void
http1_app_tx_callback (http_ctx_t *hc, u32 req_index, transport_send_params_t *sp)
{
  http_ctx_t *req;

  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);

  if (!http1_req_state_is_tx_valid (req))
    {
      /* Sometimes the server apps can send the response earlier
       * than expected (e.g when rejecting a bad request)*/
      if (req->req_state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  (hc->flags & HTTP_CONN_F_IS_SERVER))
	{
	  http_io_ts_drain_all (hc);
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			hc->c_thread_index, hc->hc_hc_index, format_http_req_state, req->req_state,
			format_http_conn_state, hc);
	  http_io_as_drain_all (req);
	  return;
	}
    }

  HTTP_DBG (1, "run state machine");
  http1_req_run_state_machine (hc, req, sp, 1);
}

static void
http1_app_rx_evt_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;

  req = http_ctx_get_w_thread (req_index, thread_index);

  if (req->req_state == HTTP_REQ_STATE_TUNNEL)
    http1_req_state_tunnel_rx (hc, req, 0);
}

static void
http1_app_close_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index,
			  u8 is_shutdown)
{
  http_ctx_t *req;

  req = http_ctx_get_w_thread_if_valid (req_index, thread_index);
  if (!req)
    {
      HTTP_DBG (1, "req already deleted");
      return;
    }
  /* Nothing more to send, confirm close */
  if (!http_io_as_max_read (req) || hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "nothing more to send, confirm close");
      session_transport_closed_notify (&req->connection);
      http_disconnect_transport (hc);
    }
  else
    {
      /* Wait for all data to be written to ts */
      hc->state = HTTP_CONN_STATE_APP_CLOSED;
    }
}

static void
http1_app_reset_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  req = http_ctx_get_w_thread (req_index, thread_index);
  session_transport_closed_notify (&req->connection);
  http_disconnect_transport (hc);
  http_stats_connections_reset_by_app_inc (hc->c_thread_index);
}

static int
http1_transport_connected_callback (http_ctx_t *hc)
{
  http_ctx_t *req;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  ASSERT (hc->flags & HTTP_CONN_F_NO_APP_SESSION);

  req = http1_conn_alloc_req (hc_index, thread_index);
  /* pool grow, regrab connection */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
  http_stats_connections_established_inc (hc->c_thread_index);
  return http_conn_established (hc, req, hc->hc_pa_app_api_ctx);
}

static void
http1_transport_rx_callback (http_ctx_t *hc)
{
  http_ctx_t *req;

  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    {
      u32 hc_index = hc->hc_hc_index;
      clib_thread_index_t thread_index = hc->c_thread_index;
      ASSERT (hc->flags & HTTP_CONN_F_IS_SERVER);
      /* first request - create request ctx */
      req = http1_conn_alloc_req (hc_index, thread_index);
      /* pool grow, regrab connection */
      hc = http_ctx_get_w_thread (hc_index, thread_index);
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
    }
  else
    req = http1_conn_get_req (hc);

  if (!http1_req_state_is_rx_valid (req))
    {
      if (http_io_ts_max_read (hc))
	{
	  if (req->req_state == HTTP_REQ_STATE_APP_IO_MORE_DATA &&
	      !(hc->flags & HTTP_CONN_F_IS_SERVER))
	    {
	      /* client can receive error response from server when still
	       * sending content */
	      /* TODO: 100 continue support */
	      HTTP_DBG (1, "server send response while client sending data");
	      http_io_as_drain_all (req);
	      hc->state = HTTP_CONN_STATE_CLOSED;
	      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	      goto run_sm;
	    }
	  clib_warning ("hc [%u]%x invalid rx state: http req state "
			"'%U', session state '%U'",
			hc->c_thread_index, hc->hc_hc_index, format_http_req_state, req->req_state,
			format_http_conn_state, hc);
	  http_io_ts_drain_all (hc);
	}
      return;
    }

run_sm:
  HTTP_DBG (1, "run state machine");
  http1_req_run_state_machine (hc, req, 0, 0);
}

static void
http1_transport_close_callback (http_ctx_t *hc)
{
  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;
  /* Nothing more to rx, propagate to app */
  if (!http_io_ts_max_read (hc))
    {
      http_ctx_t *req = http1_conn_get_req (hc);
      session_transport_closing_notify (&req->connection);
    }
}

static void
http1_transport_reset_callback (http_ctx_t *hc)
{
  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;
  http_ctx_t *req = http1_conn_get_req (hc);
  session_transport_reset_notify (&req->connection);
  http_stats_connections_reset_by_peer_inc (hc->c_thread_index);
}

static void
http1_transport_conn_reschedule_callback (http_ctx_t *hc)
{
  ASSERT (hc->flags & HTTP_CONN_F_HAS_REQUEST);
  http_ctx_t *req = http1_conn_get_req (hc);
  transport_connection_reschedule (&req->connection);
}

static void
http1_conn_accept_callback (http_ctx_t *hc)
{
  /* nothing to do */
}

static void
http1_conn_cleanup_callback (http_ctx_t *hc)
{
  http_ctx_t *req;
  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;

  req = http1_conn_get_req (hc);
  /* do not notify if accept or connect failed */
  if (req->c_s_index != SESSION_INVALID_INDEX)
    session_transport_delete_notify (&req->connection);
  http1_conn_free_req (hc);
}

const static http_engine_vft_t http1_engine = {
  .name = "http1",
  .req_get_connection = http1_req_get_connection,
  .format_req = http1_format_req,
  .app_tx_callback = http1_app_tx_callback,
  .app_rx_evt_callback = http1_app_rx_evt_callback,
  .app_close_callback = http1_app_close_callback,
  .app_reset_callback = http1_app_reset_callback,
  .transport_connected_callback = http1_transport_connected_callback,
  .transport_rx_callback = http1_transport_rx_callback,
  .transport_close_callback = http1_transport_close_callback,
  .transport_conn_reschedule_callback = http1_transport_conn_reschedule_callback,
  .transport_reset_callback = http1_transport_reset_callback,
  .conn_accept_callback = http1_conn_accept_callback,
  .conn_cleanup_callback = http1_conn_cleanup_callback,
};

static clib_error_t *
http1_init (vlib_main_t *vm)
{
  http_register_engine (&http1_engine, HTTP_VERSION_1);
  return 0;
}

VLIB_INIT_FUNCTION (http1_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
