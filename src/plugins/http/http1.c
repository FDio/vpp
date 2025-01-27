/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>

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

static const char *connection_upgrade_template = "Connection: upgrade\r\n"
						 "Upgrade: %s\r\n";

/**
 * http request boilerplate
 */
static const char *get_request_template = "GET %s HTTP/1.1\r\n"
					  "Host: %v\r\n"
					  "User-Agent: %v\r\n";

static const char *post_request_template = "POST %s HTTP/1.1\r\n"
					   "Host: %v\r\n"
					   "User-Agent: %v\r\n"
					   "Content-Length: %llu\r\n";

static void
http1_send_error (http_conn_t *hc, http_status_code_t ec)
{
  u8 *data;

  if (ec >= HTTP_N_STATUS)
    ec = HTTP_STATUS_INTERNAL_ERROR;

  data = format (0, error_template, http_status_code_str[ec],
		 format_http_time_now, hc);
  HTTP_DBG (3, "%v", data);
  http_send_data (hc, data, vec_len (data));
  vec_free (data);
}

static void
http1_identify_optional_query (http_req_t *req)
{
  int i;
  for (i = req->target_path_offset;
       i < (req->target_path_offset + req->target_path_len); i++)
    {
      if (req->rx_buf[i] == '?')
	{
	  req->target_query_offset = i + 1;
	  req->target_query_len = req->target_path_offset +
				  req->target_path_len -
				  req->target_query_offset;
	  req->target_path_len =
	    req->target_path_len - req->target_query_len - 1;
	  break;
	}
    }
}

static int
http1_parse_target (http_req_t *req)
{
  int i;
  u8 *p, *end;

  /* asterisk-form  = "*" */
  if ((req->rx_buf[req->target_path_offset] == '*') &&
      (req->target_path_len == 1))
    {
      req->target_form = HTTP_TARGET_ASTERISK_FORM;
      /* we do not support OPTIONS request */
      return -1;
    }

  /* origin-form = 1*( "/" segment ) [ "?" query ] */
  if (req->rx_buf[req->target_path_offset] == '/')
    {
      /* drop leading slash */
      req->target_path_len--;
      req->target_path_offset++;
      req->target_form = HTTP_TARGET_ORIGIN_FORM;
      http1_identify_optional_query (req);
      /* can't be CONNECT method */
      return req->method == HTTP_REQ_CONNECT ? -1 : 0;
    }

  /* absolute-form =
   * scheme "://" host [ ":" port ] *( "/" segment ) [ "?" query ] */
  if (req->target_path_len > 8 &&
      !memcmp (req->rx_buf + req->target_path_offset, "http", 4))
    {
      req->scheme = HTTP_URL_SCHEME_HTTP;
      p = req->rx_buf + req->target_path_offset + 4;
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
	  req->target_authority_offset = p - req->rx_buf;
	  req->target_authority_len = 0;
	  end = req->rx_buf + req->target_path_offset + req->target_path_len;
	  while (p < end)
	    {
	      if (*p == '/')
		{
		  p++; /* drop leading slash */
		  req->target_path_offset = p - req->rx_buf;
		  req->target_path_len = end - p;
		  break;
		}
	      req->target_authority_len++;
	      p++;
	    }
	  if (!req->target_path_len)
	    {
	      clib_warning ("zero length host");
	      return -1;
	    }
	  http1_identify_optional_query (req);
	  /* can't be CONNECT method */
	  return req->method == HTTP_REQ_CONNECT ? -1 : 0;
	}
    }

  /* authority-form = host ":" port */
  for (i = req->target_path_offset;
       i < (req->target_path_offset + req->target_path_len); i++)
    {
      if ((req->rx_buf[i] == ':') && (isdigit (req->rx_buf[i + 1])))
	{
	  req->target_authority_len = req->target_path_len;
	  req->target_path_len = 0;
	  req->target_authority_offset = req->target_path_offset;
	  req->target_path_offset = 0;
	  req->target_form = HTTP_TARGET_AUTHORITY_FORM;
	  /* "authority-form" is only used for CONNECT requests */
	  return req->method == HTTP_REQ_CONNECT ? 0 : -1;
	}
    }

  return -1;
}

static int
http1_parse_request_line (http_req_t *req, http_status_code_t *ec)
{
  int i, target_len;
  u32 next_line_offset, method_offset;

  /* request-line = method SP request-target SP HTTP-version CRLF */
  i = v_find_index (req->rx_buf, 8, 0, "\r\n");
  if (i < 0)
    {
      clib_warning ("request line incomplete");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }
  HTTP_DBG (2, "request line length: %d", i);
  req->control_data_len = i + 2;
  next_line_offset = req->control_data_len;

  /* there should be at least one more CRLF */
  if (vec_len (req->rx_buf) < (next_line_offset + 2))
    {
      clib_warning ("malformed message, too short");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }

  /*
   * RFC9112 2.2:
   * In the interest of robustness, a server that is expecting to receive and
   * parse a request-line SHOULD ignore at least one empty line (CRLF)
   * received prior to the request-line.
   */
  method_offset = req->rx_buf[0] == '\r' && req->rx_buf[1] == '\n' ? 2 : 0;
  /* parse method */
  if (!memcmp (req->rx_buf + method_offset, "GET ", 4))
    {
      HTTP_DBG (0, "GET method");
      req->method = HTTP_REQ_GET;
      req->target_path_offset = method_offset + 4;
    }
  else if (!memcmp (req->rx_buf + method_offset, "POST ", 5))
    {
      HTTP_DBG (0, "POST method");
      req->method = HTTP_REQ_POST;
      req->target_path_offset = method_offset + 5;
    }
  else if (!memcmp (req->rx_buf + method_offset, "CONNECT ", 8))
    {
      HTTP_DBG (0, "CONNECT method");
      req->method = HTTP_REQ_CONNECT;
      req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
      req->target_path_offset = method_offset + 8;
      req->is_tunnel = 1;
    }
  else
    {
      if (req->rx_buf[method_offset] - 'A' <= 'Z' - 'A')
	{
	  clib_warning ("method not implemented: %8v", req->rx_buf);
	  *ec = HTTP_STATUS_NOT_IMPLEMENTED;
	  return -1;
	}
      else
	{
	  clib_warning ("not method name: %8v", req->rx_buf);
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return -1;
	}
    }

  /* find version */
  i = v_find_index (req->rx_buf, next_line_offset - 11, 11, " HTTP/");
  if (i < 0)
    {
      clib_warning ("HTTP version not present");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }
  /* verify major version */
  if (isdigit (req->rx_buf[i + 6]))
    {
      if (req->rx_buf[i + 6] != '1')
	{
	  clib_warning ("HTTP major version '%c' not supported",
			req->rx_buf[i + 6]);
	  *ec = HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
	  return -1;
	}
    }
  else
    {
      clib_warning ("HTTP major version '%c' is not digit",
		    req->rx_buf[i + 6]);
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }

  /* parse request-target */
  HTTP_DBG (2, "http at %d", i);
  target_len = i - req->target_path_offset;
  HTTP_DBG (2, "target_len %d", target_len);
  if (target_len < 1)
    {
      clib_warning ("request-target not present");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }
  req->target_path_len = target_len;
  req->target_query_offset = 0;
  req->target_query_len = 0;
  req->target_authority_len = 0;
  req->target_authority_offset = 0;
  if (http1_parse_target (req))
    {
      clib_warning ("invalid target");
      *ec = HTTP_STATUS_BAD_REQUEST;
      return -1;
    }
  HTTP_DBG (2, "request-target path length: %u", req->target_path_len);
  HTTP_DBG (2, "request-target path offset: %u", req->target_path_offset);
  HTTP_DBG (2, "request-target query length: %u", req->target_query_len);
  HTTP_DBG (2, "request-target query offset: %u", req->target_query_offset);

  /* set buffer offset to nex line start */
  req->rx_buf_offset = next_line_offset;

  return 0;
}

static int
http1_parse_status_line (http_req_t *req)
{
  int i;
  u32 next_line_offset;
  u8 *p, *end;
  u16 status_code = 0;

  i = v_find_index (req->rx_buf, 0, 0, "\r\n");
  /* status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF */
  if (i < 0)
    {
      clib_warning ("status line incomplete");
      return -1;
    }
  HTTP_DBG (2, "status line length: %d", i);
  if (i < 12)
    {
      clib_warning ("status line too short (%d)", i);
      return -1;
    }
  req->control_data_len = i + 2;
  next_line_offset = req->control_data_len;
  p = req->rx_buf;
  end = req->rx_buf + i;

  /* there should be at least one more CRLF */
  if (vec_len (req->rx_buf) < (next_line_offset + 2))
    {
      clib_warning ("malformed message, too short");
      return -1;
    }

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
      return -1;
    }

  /* skip space(s) */
  if (*p != ' ')
    {
      clib_warning ("no space after HTTP version");
      return -1;
    }
  do
    {
      p++;
      if (p == end)
	{
	  clib_warning ("no status code");
	  return -1;
	}
    }
  while (*p == ' ');

  /* parse status code */
  if ((end - p) < 3)
    {
      clib_warning ("not enough characters for status code");
      return -1;
    }
  parse_int (status_code, 100);
  parse_int (status_code, 10);
  parse_int (status_code, 1);
  if (status_code < 100 || status_code > 599)
    {
      clib_warning ("invalid status code %d", status_code);
      return -1;
    }
  req->status_code = http_sc_by_u16 (status_code);
  HTTP_DBG (0, "status code: %d", status_code);

  /* set buffer offset to nex line start */
  req->rx_buf_offset = next_line_offset;

  return 0;
}

always_inline int
http1_parse_field_name (u8 **pos, u8 *end, u8 **field_name_start,
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
http1_parse_field_value (u8 **pos, u8 *end, u8 **field_value_start,
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

static int
http1_identify_headers (http_req_t *req, http_status_code_t *ec)
{
  int rv;
  u8 *p, *end, *name_start, *value_start;
  u32 name_len, value_len;
  http_field_line_t *field_line;
  uword header_index;

  vec_reset_length (req->headers);
  req->content_len_header_index = ~0;
  req->connection_header_index = ~0;
  req->upgrade_header_index = ~0;
  req->host_header_index = ~0;
  req->headers_offset = req->rx_buf_offset;

  /* check if we have any header */
  if ((req->rx_buf[req->rx_buf_offset] == '\r') &&
      (req->rx_buf[req->rx_buf_offset + 1] == '\n'))
    {
      /* just another CRLF -> no headers */
      HTTP_DBG (2, "no headers");
      req->headers_len = 0;
      req->control_data_len += 2;
      return 0;
    }

  end = req->rx_buf + vec_len (req->rx_buf);
  p = req->rx_buf + req->rx_buf_offset;

  while (1)
    {
      rv = http1_parse_field_name (&p, end, &name_start, &name_len);
      if (rv != 0)
	{
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return -1;
	}
      rv = http1_parse_field_value (&p, end, &value_start, &value_len);
      if (rv != 0 || (end - p) < 2)
	{
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return -1;
	}

      vec_add2 (req->headers, field_line, 1);
      field_line->name_offset =
	(name_start - req->rx_buf) - req->headers_offset;
      field_line->name_len = name_len;
      field_line->value_offset =
	(value_start - req->rx_buf) - req->headers_offset;
      field_line->value_len = value_len;
      header_index = field_line - req->headers;

      /* find headers that will be used later in preprocessing */
      /* names are case-insensitive (RFC9110 section 5.1) */
      if (req->content_len_header_index == ~0 &&
	  http_token_is_case (
	    (const char *) name_start, name_len,
	    http_header_name_token (HTTP_HEADER_CONTENT_LENGTH)))
	req->content_len_header_index = header_index;
      else if (req->connection_header_index == ~0 &&
	       http_token_is_case (
		 (const char *) name_start, name_len,
		 http_header_name_token (HTTP_HEADER_CONNECTION)))
	req->connection_header_index = header_index;
      else if (req->upgrade_header_index == ~0 &&
	       http_token_is_case (
		 (const char *) name_start, name_len,
		 http_header_name_token (HTTP_HEADER_UPGRADE)))
	req->upgrade_header_index = header_index;
      else if (req->host_header_index == ~0 &&
	       http_token_is_case ((const char *) name_start, name_len,
				   http_header_name_token (HTTP_HEADER_HOST)))
	req->host_header_index = header_index;

      /* are we done? */
      if (*p == '\r' && *(p + 1) == '\n')
	break;
    }

  req->headers_len = p - (req->rx_buf + req->headers_offset);
  req->control_data_len += (req->headers_len + 2);
  HTTP_DBG (2, "headers length: %u", req->headers_len);
  HTTP_DBG (2, "headers offset: %u", req->headers_offset);

  return 0;
}

static int
http1_identify_message_body (http_req_t *req, http_status_code_t *ec)
{
  int i;
  u8 *p;
  u64 body_len = 0, digit;
  http_field_line_t *field_line;

  req->body_len = 0;

  if (req->headers_len == 0)
    {
      HTTP_DBG (2, "no header, no message-body");
      return 0;
    }
  if (req->is_tunnel)
    {
      HTTP_DBG (2, "tunnel, no message-body");
      return 0;
    }

  /* TODO check for chunked transfer coding */

  if (req->content_len_header_index == ~0)
    {
      HTTP_DBG (2, "Content-Length header not present, no message-body");
      return 0;
    }
  field_line = vec_elt_at_index (req->headers, req->content_len_header_index);

  p = req->rx_buf + req->headers_offset + field_line->value_offset;
  for (i = 0; i < field_line->value_len; i++)
    {
      /* check for digit */
      if (!isdigit (*p))
	{
	  clib_warning ("expected digit");
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return -1;
	}
      digit = *p - '0';
      u64 new_body_len = body_len * 10 + digit;
      /* check for overflow */
      if (new_body_len < body_len)
	{
	  clib_warning ("too big number, overflow");
	  *ec = HTTP_STATUS_BAD_REQUEST;
	  return -1;
	}
      body_len = new_body_len;
      p++;
    }

  req->body_len = body_len;

  req->body_offset = req->headers_offset + req->headers_len + 2;
  HTTP_DBG (2, "body length: %llu", req->body_len);
  HTTP_DBG (2, "body offset: %u", req->body_offset);

  return 0;
}

static void
http1_check_connection_upgrade (http_req_t *req)
{
  http_field_line_t *connection, *upgrade;
  u8 skip;

  skip = (req->method != HTTP_REQ_GET) + (req->connection_header_index == ~0) +
	 (req->upgrade_header_index == ~0);
  if (skip)
    return;

  connection = vec_elt_at_index (req->headers, req->connection_header_index);
  /* connection options are case-insensitive (RFC9110 7.6.1) */
  if (http_token_is_case (http_field_line_value_token (connection, req),
			  http_token_lit ("upgrade")))
    {
      upgrade = vec_elt_at_index (req->headers, req->upgrade_header_index);

      /* check upgrade protocol, we want to ignore something like upgrade to
       * newer HTTP version, only tunnels are supported */
      if (0)
	;
#define _(sym, str)                                                           \
  else if (http_token_is_case (http_field_line_value_token (upgrade, req),    \
			       http_token_lit (str))) req->upgrade_proto =    \
    HTTP_UPGRADE_PROTO_##sym;
      foreach_http_upgrade_proto
#undef _
	else return;

      HTTP_DBG (1, "connection upgrade: %U", format_http_bytes,
		req->rx_buf + req->headers_offset + upgrade->value_offset,
		upgrade->value_len);
      req->is_tunnel = 1;
      req->method = HTTP_REQ_CONNECT;
    }
}

static void
http1_target_fixup (http_conn_t *hc)
{
  http_field_line_t *host;

  if (hc->req.target_form == HTTP_TARGET_ABSOLUTE_FORM)
    return;

  /* scheme fixup */
  hc->req.scheme = session_get_transport_proto (session_get_from_handle (
		     hc->h_tc_session_handle)) == TRANSPORT_PROTO_TLS ?
		     HTTP_URL_SCHEME_HTTPS :
		     HTTP_URL_SCHEME_HTTP;

  if (hc->req.target_form == HTTP_TARGET_AUTHORITY_FORM ||
      hc->req.connection_header_index == ~0)
    return;

  /* authority fixup */
  host = vec_elt_at_index (hc->req.headers, hc->req.connection_header_index);
  hc->req.target_authority_offset = host->value_offset;
  hc->req.target_authority_len = host->value_len;
}

static void
http1_write_app_headers (http_conn_t *hc, http_msg_t *msg, u8 **tx_buf)
{
  session_t *as;
  u8 *app_headers, *p, *end;
  u32 *tmp;
  int rv;

  as = session_get_from_handle (hc->h_pa_session_handle);

  /* read app header list */
  if (msg->data.type == HTTP_MSG_DATA_PTR)
    {
      uword app_headers_ptr;
      rv = svm_fifo_dequeue (as->tx_fifo, sizeof (app_headers_ptr),
			     (u8 *) &app_headers_ptr);
      ASSERT (rv == sizeof (app_headers_ptr));
      app_headers = uword_to_pointer (app_headers_ptr, u8 *);
    }
  else
    {
      app_headers = http_get_app_header_list_buf (hc);
      rv = svm_fifo_dequeue (as->tx_fifo, msg->data.headers_len, app_headers);
      ASSERT (rv == msg->data.headers_len);
    }

  /* serialize app headers to tx_buf */
  end = app_headers + msg->data.headers_len;
  while (app_headers < end)
    {
      /* custom header name? */
      tmp = (u32 *) app_headers;
      if (PREDICT_FALSE (*tmp & HTTP_CUSTOM_HEADER_NAME_BIT))
	{
	  http_custom_token_t *name, *value;
	  name = (http_custom_token_t *) app_headers;
	  u32 name_len = name->len & ~HTTP_CUSTOM_HEADER_NAME_BIT;
	  app_headers += sizeof (http_custom_token_t) + name_len;
	  value = (http_custom_token_t *) app_headers;
	  app_headers += sizeof (http_custom_token_t) + value->len;
	  vec_add2 (*tx_buf, p, name_len + value->len + 4);
	  clib_memcpy (p, name->token, name_len);
	  p += name_len;
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
	  http_token_t name = { http_header_name_token (header->name) };
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

/* request state machine handlers */

static http_sm_result_t
http1_req_state_wait_transport_reply (http_conn_t *hc,
				      transport_send_params_t *sp)
{
  int rv;
  http_msg_t msg = {};
  app_worker_t *app_wrk;
  session_t *as;
  u32 len, max_enq, body_sent;
  http_status_code_t ec;

  rv = http_read_message (hc);

  /* Nothing yet, wait for data or timer expire */
  if (rv)
    {
      HTTP_DBG (1, "no data to deq");
      return HTTP_SM_STOP;
    }

  HTTP_DBG (3, "%v", hc->req.rx_buf);

  if (vec_len (hc->req.rx_buf) < 8)
    {
      clib_warning ("response buffer too short");
      goto error;
    }

  rv = http1_parse_status_line (&hc->req);
  if (rv)
    goto error;

  rv = http1_identify_headers (&hc->req, &ec);
  if (rv)
    goto error;

  rv = http1_identify_message_body (&hc->req, &ec);
  if (rv)
    goto error;

  /* send at least "control data" which is necessary minimum,
   * if there is some space send also portion of body */
  as = session_get_from_handle (hc->h_pa_session_handle);
  max_enq = svm_fifo_max_enqueue (as->rx_fifo);
  max_enq -= sizeof (msg);
  if (max_enq < hc->req.control_data_len)
    {
      clib_warning ("not enough room for control data in app's rx fifo");
      goto error;
    }
  len = clib_min (max_enq, vec_len (hc->req.rx_buf));

  msg.type = HTTP_MSG_REPLY;
  msg.code = hc->req.status_code;
  msg.data.headers_offset = hc->req.headers_offset;
  msg.data.headers_len = hc->req.headers_len;
  msg.data.body_offset = hc->req.body_offset;
  msg.data.body_len = hc->req.body_len;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = len;
  msg.data.headers_ctx = pointer_to_uword (hc->req.headers);

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { hc->req.rx_buf, len } };

  rv = svm_fifo_enqueue_segments (as->rx_fifo, segs, 2, 0 /* allow partial */);
  ASSERT (rv == (sizeof (msg) + len));

  http_read_message_drop (hc, len);

  body_sent = len - hc->req.control_data_len;
  hc->req.to_recv = hc->req.body_len - body_sent;
  if (hc->req.to_recv == 0)
    {
      /* all sent, we are done */
      http_req_state_change (hc, HTTP_REQ_STATE_WAIT_APP_METHOD);
    }
  else
    {
      /* stream rest of the response body */
      http_req_state_change (hc, HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA);
    }

  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  if (app_wrk)
    app_worker_rx_notify (app_wrk, as);
  return HTTP_SM_STOP;

error:
  http_read_message_drop_all (hc);
  session_transport_closing_notify (&hc->connection);
  session_transport_closed_notify (&hc->connection);
  http_disconnect_transport (hc);
  return HTTP_SM_ERROR;
}

static http_sm_result_t
http1_req_state_wait_transport_method (http_conn_t *hc,
				       transport_send_params_t *sp)
{
  http_status_code_t ec;
  app_worker_t *app_wrk;
  http_msg_t msg;
  session_t *as;
  int rv;
  u32 len, max_enq, body_sent;
  u64 max_deq;

  rv = http_read_message (hc);

  /* Nothing yet, wait for data or timer expire */
  if (rv)
    return HTTP_SM_STOP;

  HTTP_DBG (3, "%v", hc->req.rx_buf);

  if (vec_len (hc->req.rx_buf) < 8)
    {
      ec = HTTP_STATUS_BAD_REQUEST;
      goto error;
    }

  rv = http1_parse_request_line (&hc->req, &ec);
  if (rv)
    goto error;

  rv = http1_identify_headers (&hc->req, &ec);
  if (rv)
    goto error;

  http1_target_fixup (hc);
  http1_check_connection_upgrade (&hc->req);

  rv = http1_identify_message_body (&hc->req, &ec);
  if (rv)
    goto error;

  /* send at least "control data" which is necessary minimum,
   * if there is some space send also portion of body */
  as = session_get_from_handle (hc->h_pa_session_handle);
  max_enq = svm_fifo_max_enqueue (as->rx_fifo);
  if (max_enq < hc->req.control_data_len)
    {
      clib_warning ("not enough room for control data in app's rx fifo");
      ec = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }
  /* do not dequeue more than one HTTP request, we do not support pipelining */
  max_deq = clib_min (hc->req.control_data_len + hc->req.body_len,
		      vec_len (hc->req.rx_buf));
  len = clib_min (max_enq, max_deq);

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = hc->req.method;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = len;
  msg.data.scheme = hc->req.scheme;
  msg.data.target_authority_offset = hc->req.target_authority_offset;
  msg.data.target_authority_len = hc->req.target_authority_len;
  msg.data.target_path_offset = hc->req.target_path_offset;
  msg.data.target_path_len = hc->req.target_path_len;
  msg.data.target_query_offset = hc->req.target_query_offset;
  msg.data.target_query_len = hc->req.target_query_len;
  msg.data.headers_offset = hc->req.headers_offset;
  msg.data.headers_len = hc->req.headers_len;
  msg.data.body_offset = hc->req.body_offset;
  msg.data.body_len = hc->req.body_len;
  msg.data.headers_ctx = pointer_to_uword (hc->req.headers);
  msg.data.upgrade_proto = hc->req.upgrade_proto;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { hc->req.rx_buf, len } };

  rv = svm_fifo_enqueue_segments (as->rx_fifo, segs, 2, 0 /* allow partial */);
  ASSERT (rv == (sizeof (msg) + len));

  body_sent = len - hc->req.control_data_len;
  hc->req.to_recv = hc->req.body_len - body_sent;
  if (hc->req.to_recv == 0)
    {
      /* drop everything, we do not support pipelining */
      http_read_message_drop_all (hc);
      /* all sent, we are done */
      http_req_state_change (hc, HTTP_REQ_STATE_WAIT_APP_REPLY);
    }
  else
    {
      http_read_message_drop (hc, len);
      /* stream rest of the response body */
      http_req_state_change (hc, HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA);
    }

  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  if (app_wrk)
    app_worker_rx_notify (app_wrk, as);

  return HTTP_SM_STOP;

error:
  http_read_message_drop_all (hc);
  http1_send_error (hc, ec);
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);

  return HTTP_SM_ERROR;
}

static http_sm_result_t
http1_req_state_wait_app_reply (http_conn_t *hc, transport_send_params_t *sp)
{
  u8 *response;
  u32 sent;
  session_t *as;
  http_status_code_t sc;
  http_msg_t msg;
  int rv;
  http_sm_result_t sm_result = HTTP_SM_ERROR;
  http_req_state_t next_state = HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD;

  as = session_get_from_handle (hc->h_pa_session_handle);

  rv = svm_fifo_dequeue (as->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.data.type > HTTP_MSG_DATA_PTR)
    {
      clib_warning ("no data");
      sc = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }

  if (msg.type != HTTP_MSG_REPLY)
    {
      clib_warning ("unexpected message type %d", msg.type);
      sc = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }

  if (msg.code >= HTTP_N_STATUS)
    {
      clib_warning ("unsupported status code: %d", msg.code);
      return HTTP_SM_ERROR;
    }

  response = http_get_tx_buf (hc);
  vec_reset_length (response);
  /*
   * Add "protocol layer" headers:
   * - current time
   * - server name
   * - data length
   */
  response =
    format (response, response_template, http_status_code_str[msg.code],
	    /* Date */
	    format_http_time_now, hc,
	    /* Server */
	    hc->app_name);

  /* RFC9110 8.6: A server MUST NOT send Content-Length header field in a
   * 2xx (Successful) response to CONNECT or with a status code of 101
   * (Switching Protocols). */
  if (hc->req.is_tunnel && (http_status_code_str[msg.code][0] == '2' ||
			    msg.code == HTTP_STATUS_SWITCHING_PROTOCOLS))
    {
      ASSERT (msg.data.body_len == 0);
      next_state = HTTP_REQ_STATE_TUNNEL;
      if (hc->req.upgrade_proto > HTTP_UPGRADE_PROTO_NA)
	{
	  response = format (response, connection_upgrade_template,
			     http1_upgrade_proto_str[hc->req.upgrade_proto]);
	  if (hc->req.upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
	      hc->udp_tunnel_mode == HTTP_UDP_TUNNEL_DGRAM)
	    next_state = HTTP_REQ_STATE_UDP_TUNNEL;
	}
      /* cleanup some stuff we don't need anymore in tunnel mode */
      vec_free (hc->req.rx_buf);
      vec_free (hc->req.headers);
      http_buffer_free (&hc->req.tx_buf);
      hc->req.to_skip = 0;
    }
  else
    response = format (response, content_len_template, msg.data.body_len);

  /* Add headers from app (if any) */
  if (msg.data.headers_len)
    {
      HTTP_DBG (0, "got headers from app, len %d", msg.data.headers_len);
      http1_write_app_headers (hc, &msg, &response);
    }
  /* Add empty line after headers */
  response = format (response, "\r\n");
  HTTP_DBG (3, "%v", response);

  sent = http_send_data (hc, response, vec_len (response));
  if (sent != vec_len (response))
    {
      clib_warning ("sending status-line and headers failed!");
      sc = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }

  if (msg.data.body_len)
    {
      /* Start sending the actual data */
      http_buffer_init (&hc->req.tx_buf, msg_to_buf_type[msg.data.type],
			as->tx_fifo, msg.data.body_len);
      next_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
      sm_result = HTTP_SM_CONTINUE;
    }
  else
    {
      /* No response body, we are done */
      sm_result = HTTP_SM_STOP;
    }

  http_req_state_change (hc, next_state);

  ASSERT (sp->max_burst_size >= sent);
  sp->max_burst_size -= sent;
  return sm_result;

error:
  http1_send_error (hc, sc);
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_wait_app_method (http_conn_t *hc, transport_send_params_t *sp)
{
  http_msg_t msg;
  session_t *as;
  u8 *target_buff = 0, *request = 0, *target;
  u32 sent;
  int rv;
  http_sm_result_t sm_result = HTTP_SM_ERROR;
  http_req_state_t next_state;

  as = session_get_from_handle (hc->h_pa_session_handle);

  rv = svm_fifo_dequeue (as->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.data.type > HTTP_MSG_DATA_PTR)
    {
      clib_warning ("no data");
      goto error;
    }

  if (msg.type != HTTP_MSG_REQUEST)
    {
      clib_warning ("unexpected message type %d", msg.type);
      goto error;
    }

  /* read request target */
  if (msg.data.type == HTTP_MSG_DATA_PTR)
    {
      uword target_ptr;
      rv = svm_fifo_dequeue (as->tx_fifo, sizeof (target_ptr),
			     (u8 *) &target_ptr);
      ASSERT (rv == sizeof (target_ptr));
      target = uword_to_pointer (target_ptr, u8 *);
    }
  else
    {
      vec_validate (target_buff, msg.data.target_path_len - 1);
      rv =
	svm_fifo_dequeue (as->tx_fifo, msg.data.target_path_len, target_buff);
      ASSERT (rv == msg.data.target_path_len);
      target = target_buff;
    }

  request = http_get_tx_buf (hc);
  vec_reset_length (request);
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
      request = format (request, get_request_template,
			/* target */
			target,
			/* Host */
			hc->host,
			/* User-Agent */
			hc->app_name);

      next_state = HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY;
      sm_result = HTTP_SM_STOP;
    }
  else if (msg.method_type == HTTP_REQ_POST)
    {
      if (!msg.data.body_len)
	{
	  clib_warning ("POST request should include data");
	  goto error;
	}
      /*
       * Add "protocol layer" headers:
       * - host
       * - user agent
       * - content length
       */
      request = format (request, post_request_template,
			/* target */
			target,
			/* Host */
			hc->host,
			/* User-Agent */
			hc->app_name,
			/* Content-Length */
			msg.data.body_len);

      http_buffer_init (&hc->req.tx_buf, msg_to_buf_type[msg.data.type],
			as->tx_fifo, msg.data.body_len);

      next_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
      sm_result = HTTP_SM_CONTINUE;
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
      http1_write_app_headers (hc, &msg, &request);
    }
  /* Add empty line after headers */
  request = format (request, "\r\n");
  HTTP_DBG (3, "%v", request);

  sent = http_send_data (hc, request, vec_len (request));
  if (sent != vec_len (request))
    {
      clib_warning ("sending request-line and headers failed!");
      sm_result = HTTP_SM_ERROR;
      goto error;
    }

  http_req_state_change (hc, next_state);
  goto done;

error:
  svm_fifo_dequeue_drop_all (as->tx_fifo);
  session_transport_closing_notify (&hc->connection);
  session_transport_closed_notify (&hc->connection);
  http_disconnect_transport (hc);

done:
  vec_free (target_buff);
  return sm_result;
}

static http_sm_result_t
http1_req_state_transport_io_more_data (http_conn_t *hc,
					transport_send_params_t *sp)
{
  session_t *as, *ts;
  app_worker_t *app_wrk;
  svm_fifo_seg_t _seg, *seg = &_seg;
  u32 max_len, max_deq, max_enq, n_segs = 1;
  int rv, len;

  as = session_get_from_handle (hc->h_pa_session_handle);
  ts = session_get_from_handle (hc->h_tc_session_handle);

  max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (max_deq == 0)
    {
      HTTP_DBG (1, "no data to deq");
      return HTTP_SM_STOP;
    }

  max_enq = svm_fifo_max_enqueue (as->rx_fifo);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      svm_fifo_add_want_deq_ntf (as->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return HTTP_SM_STOP;
    }

  max_len = clib_min (max_enq, max_deq);
  len = svm_fifo_segments (ts->rx_fifo, 0, seg, &n_segs, max_len);
  if (len < 0)
    {
      HTTP_DBG (1, "svm_fifo_segments() len %d", len);
      return HTTP_SM_STOP;
    }

  rv = svm_fifo_enqueue_segments (as->rx_fifo, seg, 1, 0 /* allow partial */);
  if (rv < 0)
    {
      clib_warning ("data enqueue failed, rv: %d", rv);
      return HTTP_SM_ERROR;
    }

  svm_fifo_dequeue_drop (ts->rx_fifo, rv);
  if (rv > hc->req.to_recv)
    {
      clib_warning ("http protocol error: received more data than expected");
      session_transport_closing_notify (&hc->connection);
      http_disconnect_transport (hc);
      http_req_state_change (hc, HTTP_REQ_STATE_WAIT_APP_METHOD);
      return HTTP_SM_ERROR;
    }
  hc->req.to_recv -= rv;
  HTTP_DBG (1, "drained %d from ts; remains %lu", rv, hc->req.to_recv);

  /* Finished transaction:
   * server back to HTTP_REQ_STATE_WAIT_APP_REPLY
   * client to HTTP_REQ_STATE_WAIT_APP_METHOD */
  if (hc->req.to_recv == 0)
    http_req_state_change (hc, hc->is_server ? HTTP_REQ_STATE_WAIT_APP_REPLY :
					       HTTP_REQ_STATE_WAIT_APP_METHOD);

  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  if (app_wrk)
    app_worker_rx_notify (app_wrk, as);

  if (svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_enqueue_notify (ts);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_app_io_more_data (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 max_send = 64 << 10, n_segs;
  http_buffer_t *hb = &hc->req.tx_buf;
  svm_fifo_seg_t *seg;
  session_t *ts;
  int sent = 0;

  max_send = clib_min (max_send, sp->max_burst_size);
  ts = session_get_from_handle (hc->h_tc_session_handle);
  if ((seg = http_buffer_get_segs (hb, max_send, &n_segs)))
    sent = svm_fifo_enqueue_segments (ts->tx_fifo, seg, n_segs,
				      1 /* allow partial */);

  if (sent > 0)
    {
      /* Ask scheduler to notify app of deq event if needed */
      sp->bytes_dequeued += http_buffer_drain (hb, sent);
      sp->max_burst_size -= sent;
    }

  /* Not finished sending all data */
  if (!http_buffer_is_drained (hb))
    {
      if (sent && svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

      if (svm_fifo_max_enqueue (ts->tx_fifo) < HTTP_FIFO_THRESH)
	{
	  /* Deschedule http session and wait for deq notification if
	   * underlying ts tx fifo almost full */
	  svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  transport_connection_deschedule (&hc->connection);
	  sp->flags |= TRANSPORT_SND_F_DESCHED;
	}
    }
  else
    {
      if (sent && svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX_FLUSH);

      /* Finished transaction:
       * server back to HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD
       * client to HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY */
      http_req_state_change (hc, hc->is_server ?
				   HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD :
				   HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
      http_buffer_free (hb);
    }

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_tunnel_rx (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 max_deq, max_enq, max_read, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];
  int n_written = 0;
  session_t *as, *ts;
  app_worker_t *app_wrk;

  HTTP_DBG (1, "tunnel received data from client");

  as = session_get_from_handle (hc->h_pa_session_handle);
  ts = session_get_from_handle (hc->h_tc_session_handle);

  max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    {
      HTTP_DBG (1, "max_deq == 0");
      return HTTP_SM_STOP;
    }
  max_enq = svm_fifo_max_enqueue (as->rx_fifo);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      svm_fifo_add_want_deq_ntf (as->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return HTTP_SM_STOP;
    }
  max_read = clib_min (max_enq, max_deq);
  svm_fifo_segments (ts->rx_fifo, 0, segs, &n_segs, max_read);
  n_written = svm_fifo_enqueue_segments (as->rx_fifo, segs, n_segs, 0);
  ASSERT (n_written > 0);
  HTTP_DBG (1, "transfered %u bytes", n_written);
  svm_fifo_dequeue_drop (ts->rx_fifo, n_written);
  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  if (app_wrk)
    app_worker_rx_notify (app_wrk, as);
  if (svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_program_rx_io_evt (session_handle (ts));

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_tunnel_tx (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 max_deq, max_enq, max_read, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];
  session_t *as, *ts;
  int n_written = 0;

  HTTP_DBG (1, "tunnel received data from target");

  as = session_get_from_handle (hc->h_pa_session_handle);
  ts = session_get_from_handle (hc->h_tc_session_handle);

  max_deq = svm_fifo_max_dequeue_cons (as->tx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    {
      HTTP_DBG (1, "max_deq == 0");
      goto check_fifo;
    }
  max_enq = svm_fifo_max_enqueue_prod (ts->tx_fifo);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "ts tx fifo full");
      goto check_fifo;
    }
  max_read = clib_min (max_enq, max_deq);
  max_read = clib_min (max_read, sp->max_burst_size);
  svm_fifo_segments (as->tx_fifo, 0, segs, &n_segs, max_read);
  n_written = svm_fifo_enqueue_segments (ts->tx_fifo, segs, n_segs, 0);
  ASSERT (n_written > 0);
  HTTP_DBG (1, "transfered %u bytes", n_written);
  sp->bytes_dequeued += n_written;
  sp->max_burst_size -= n_written;
  svm_fifo_dequeue_drop (as->tx_fifo, n_written);
  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

check_fifo:
  /* Deschedule and wait for deq notification if ts fifo is almost full */
  if (svm_fifo_max_enqueue (ts->tx_fifo) < HTTP_FIFO_THRESH)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&hc->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_udp_tunnel_rx (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 to_deq, capsule_size, dgram_size, n_written = 0;
  int rv, n_read;
  session_t *as, *ts;
  app_worker_t *app_wrk;
  u8 payload_offset = 0;
  u64 payload_len = 0;
  session_dgram_hdr_t hdr;
  u8 *buf = 0;

  HTTP_DBG (1, "udp tunnel received data from client");

  as = session_get_from_handle (hc->h_pa_session_handle);
  ts = session_get_from_handle (hc->h_tc_session_handle);
  buf = http_get_rx_buf (hc);
  to_deq = svm_fifo_max_dequeue_cons (ts->rx_fifo);

  while (to_deq > 0)
    {
      /* some bytes remaining to skip? */
      if (PREDICT_FALSE (hc->req.to_skip))
	{
	  if (hc->req.to_skip >= to_deq)
	    {
	      svm_fifo_dequeue_drop (ts->rx_fifo, to_deq);
	      hc->req.to_skip -= to_deq;
	      goto done;
	    }
	  else
	    {
	      svm_fifo_dequeue_drop (ts->rx_fifo, hc->req.to_skip);
	      hc->req.to_skip = 0;
	    }
	}
      n_read =
	svm_fifo_peek (ts->rx_fifo, 0, HTTP_CAPSULE_HEADER_MAX_SIZE, buf);
      ASSERT (n_read > 0);
      rv = http_decap_udp_payload_datagram (buf, n_read, &payload_offset,
					    &payload_len);
      HTTP_DBG (1, "rv=%d, payload_offset=%u, payload_len=%llu", rv,
		payload_offset, payload_len);
      if (PREDICT_FALSE (rv != 0))
	{
	  if (rv < 0)
	    {
	      /* capsule datagram is invalid (session need to be aborted) */
	      svm_fifo_dequeue_drop_all (ts->rx_fifo);
	      session_transport_closing_notify (&hc->connection);
	      session_transport_closed_notify (&hc->connection);
	      http_disconnect_transport (hc);
	      return HTTP_SM_STOP;
	    }
	  else
	    {
	      /* unknown capsule should be skipped */
	      if (payload_len <= to_deq)
		{
		  svm_fifo_dequeue_drop (ts->rx_fifo, payload_len);
		  to_deq -= payload_len;
		  continue;
		}
	      else
		{
		  svm_fifo_dequeue_drop (ts->rx_fifo, to_deq);
		  hc->req.to_skip = payload_len - to_deq;
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
      if (svm_fifo_max_enqueue_prod (as->rx_fifo) < dgram_size)
	{
	  HTTP_DBG (1, "app's rx fifo full");
	  svm_fifo_add_want_deq_ntf (as->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  goto done;
	}

      /* read capsule payload */
      rv = svm_fifo_peek (ts->rx_fifo, payload_offset, payload_len, buf);
      ASSERT (rv == payload_len);
      svm_fifo_dequeue_drop (ts->rx_fifo, capsule_size);

      hdr.data_length = payload_len;
      hdr.data_offset = 0;

      /* send datagram header and payload */
      svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
				 { buf, payload_len } };
      rv = svm_fifo_enqueue_segments (as->rx_fifo, segs, 2, 0);
      ASSERT (rv > 0);

      n_written += dgram_size;
      to_deq -= capsule_size;
    }

done:
  HTTP_DBG (1, "written %lu bytes", n_written);

  if (n_written)
    {
      app_wrk = app_worker_get_if_valid (as->app_wrk_index);
      if (app_wrk)
	app_worker_rx_notify (app_wrk, as);
    }
  if (svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_program_rx_io_evt (session_handle (ts));

  return HTTP_SM_STOP;
}

static http_sm_result_t
http1_req_state_udp_tunnel_tx (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 to_deq, capsule_size, dgram_size, n_written = 0;
  session_t *as, *ts;
  int rv;
  session_dgram_pre_hdr_t hdr;
  u8 *buf;
  u8 *payload;

  HTTP_DBG (1, "udp tunnel received data from target");

  as = session_get_from_handle (hc->h_pa_session_handle);
  ts = session_get_from_handle (hc->h_tc_session_handle);
  buf = http_get_tx_buf (hc);
  to_deq = svm_fifo_max_dequeue_cons (as->tx_fifo);

  while (to_deq > 0)
    {
      /* read datagram header */
      rv = svm_fifo_peek (as->tx_fifo, 0, sizeof (hdr), (u8 *) &hdr);
      ASSERT (rv == sizeof (hdr) &&
	      hdr.data_length <= HTTP_UDP_PAYLOAD_MAX_LEN);
      ASSERT (to_deq >= hdr.data_length + SESSION_CONN_HDR_LEN);
      dgram_size = hdr.data_length + SESSION_CONN_HDR_LEN;

      if (svm_fifo_max_enqueue_prod (ts->tx_fifo) <
	  (hdr.data_length + HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD))
	{
	  HTTP_DBG (1, "ts tx fifo full");
	  goto done;
	}

      /* create capsule header */
      payload = http_encap_udp_payload_datagram (buf, hdr.data_length);
      capsule_size = (payload - buf) + hdr.data_length;
      /* read payload */
      rv = svm_fifo_peek (as->tx_fifo, SESSION_CONN_HDR_LEN, hdr.data_length,
			  payload);
      ASSERT (rv == hdr.data_length);
      svm_fifo_dequeue_drop (as->tx_fifo, dgram_size);
      /* send capsule */
      rv = svm_fifo_enqueue (ts->tx_fifo, capsule_size, buf);
      ASSERT (rv == capsule_size);

      n_written += capsule_size;
      to_deq -= dgram_size;
    }

done:
  HTTP_DBG (1, "written %lu bytes", n_written);
  if (n_written)
    {
      if (svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
    }

  /* Deschedule and wait for deq notification if ts fifo is almost full */
  if (svm_fifo_max_enqueue (ts->tx_fifo) < HTTP_FIFO_THRESH)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&hc->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }

  return HTTP_SM_STOP;
}

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
};

static_always_inline int
http1_req_state_is_tx_valid (http_conn_t *hc)
{
  return tx_state_funcs[hc->req.state] ? 1 : 0;
}

static_always_inline int
http1_req_state_is_rx_valid (http_conn_t *hc)
{
  return rx_state_funcs[hc->req.state] ? 1 : 0;
}

static_always_inline void
http1_req_run_state_machine (http_conn_t *hc, transport_send_params_t *sp,
			     u8 is_tx)
{
  http_sm_result_t res;

  do
    {
      if (is_tx)
	res = tx_state_funcs[hc->req.state](hc, sp);
      else
	res = rx_state_funcs[hc->req.state](hc, sp);
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

static void
http1_app_tx_callback (http_conn_t *hc, transport_send_params_t *sp)
{
  if (!http1_req_state_is_tx_valid (hc))
    {
      session_t *as = session_get_from_handle (hc->h_pa_session_handle);
      /* Sometimes the server apps can send the response earlier
       * than expected (e.g when rejecting a bad request)*/
      if (hc->req.state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  hc->is_server)
	{
	  svm_fifo_dequeue_drop_all (as->rx_fifo);
	  hc->req.state = HTTP_REQ_STATE_WAIT_APP_REPLY;
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			as->thread_index, as->connection_index,
			format_http_req_state, hc->req.state,
			format_http_conn_state, hc);
	  svm_fifo_dequeue_drop_all (as->tx_fifo);
	  return;
	}
    }

  HTTP_DBG (1, "run state machine");
  http1_req_run_state_machine (hc, sp, 1);
}

static void
http1_app_rx_evt_callback (http_conn_t *hc)
{
  if (hc->req.state == HTTP_REQ_STATE_TUNNEL)
    http1_req_state_tunnel_rx (hc, 0);
}

static void
http1_transport_rx_callback (http_conn_t *hc)
{
  if (!http1_req_state_is_rx_valid (hc))
    {
      session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
      clib_warning ("hc [%u]%x invalid rx state: http req state "
		    "'%U', session state '%U'",
		    ts->thread_index, ts->opaque, format_http_req_state,
		    hc->req.state, format_http_conn_state, hc);
      svm_fifo_dequeue_drop_all (ts->rx_fifo);
      return;
    }

  HTTP_DBG (1, "run state machine");
  http1_req_run_state_machine (hc, 0, 0);
}

const static http_engine_vft_t http1_engine = {
  .app_tx_callback = http1_app_tx_callback,
  .app_rx_evt_callback = http1_app_rx_evt_callback,
  .transport_rx_callback = http1_transport_rx_callback,
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
