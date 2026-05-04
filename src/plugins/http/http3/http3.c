/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/http3.h>
#include <http/http3/frame.h>
#include <http/http3/qpack.h>
#include <http/http_timer.h>
#include <http/http_status_codes.h>

#define HTTP3_SERVER_MAX_STREAM_ID (HTTP_VARINT_MAX - 3)

static http_token_t http3_ext_connect_proto[] = { { http_token_lit ("bug") },
#define _(sym, str) { http_token_lit (str) },
						  foreach_http_upgrade_proto
#undef _
};

static_always_inline void
http3_set_application_error_code (http_ctx_t *hc, http3_error_t err)
{
  ASSERT (err >= 0); /* negative values are for internal use only */
  session_t *ts = session_get_from_handle (hc->hc_tc_session_handle);
  transport_endpt_attr_t attr = { .type = TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE,
				  .app_proto_err_code = (u64) err };
  session_transport_attribute (ts, 0 /* is_set */, &attr);
}

static_always_inline http_ctx_t *
http3_stream_alloc_req (u32 stream_index, clib_thread_index_t thread_index, u8 is_parent)
{
  http_ctx_t *req, *hc, *stream;
  u32 req_index;
  http_req_handle_t sh;

  req_index = http_ctx_alloc_w_thread (thread_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  stream = http_ctx_get_w_thread (stream_index, thread_index);
  sh.version = HTTP_VERSION_3;
  sh.req_index = req_index;
  req->hr_req_handle = sh.as_u32;
  req->hr_hc_index = stream->hc_hc_index;
  req->c_s_index = SESSION_INVALID_INDEX;
  req->c_thread_index = stream->c_thread_index;
  req->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  req->stream_type = HTTP3_STREAM_TYPE_UNKNOWN;
  if (is_parent)
    {
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      ASSERT (hc->hc_parent_req_index == SESSION_INVALID_INDEX);
      req->req_flags |= HTTP_REQ_F_IS_PARENT;
      hc->hc_parent_req_index = req_index;
    }
  HTTP_DBG (1, "stream [%u]%x req_index %x", stream->c_thread_index, stream->hc_hc_index,
	    req_index);

  return req;
}

static_always_inline void
http3_stream_free_req (http_ctx_t *stream)
{
  http_ctx_t *req;
  http_ctx_t *hc;

  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
  HTTP_DBG (1, "req [%u]%x", stream->c_thread_index,
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  vec_free (req->headers);
  vec_free (req->target);
  http_buffer_free (&req->tx_buf);
  stream->http_req_index = SESSION_INVALID_INDEX;
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      hc->hc_parent_req_index = SESSION_INVALID_INDEX;
    }
  http_ctx_free (req);
}

static_always_inline void
http3_stream_free_req_w_index (u32 req_index, clib_thread_index_t thread_index, http_ctx_t *stream)
{
  http_ctx_t *hc;
  http_ctx_t *req = http_ctx_get_w_thread (req_index, thread_index);

  HTTP_DBG (1, "req [%u]%x", thread_index, ((http_req_handle_t) req->hr_req_handle).req_index);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      hc->hc_parent_req_index = SESSION_INVALID_INDEX;
    }
  http_ctx_free (req);
}

static_always_inline void
http3_stream_close (http_ctx_t *stream, http_ctx_t *req)
{
  http_ctx_t *hc;

  http_close_transport_stream (stream);
  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      http_stats_app_streams_closed_inc (stream->c_thread_index);
      if (req->req_flags & HTTP_REQ_F_APP_CLOSED)
	{
	  HTTP_DBG (1, "stream [%u]%x req %x app already closed, confirm", stream->c_thread_index,
		    stream->hc_hc_index, ((http_req_handle_t) req->hr_req_handle).req_index);
	  session_transport_closed_notify (&req->connection);
	}
      else
	{
	  HTTP_DBG (1, "stream [%u]%x req %x all done closing, notify app", stream->c_thread_index,
		    stream->hc_hc_index, ((http_req_handle_t) req->hr_req_handle).req_index);
	  session_transport_closing_notify (&req->connection);
	}
    }
  else
    {
      http_stats_ctrl_streams_closed_inc (stream->c_thread_index);
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      switch (req->stream_type)
	{
	case HTTP3_STREAM_TYPE_CONTROL:
	  hc->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
	  break;
	case HTTP3_STREAM_TYPE_DECODER:
	  hc->peer_decoder_stream_index = SESSION_INVALID_INDEX;
	  break;
	case HTTP3_STREAM_TYPE_ENCODER:
	  hc->peer_encoder_stream_index = SESSION_INVALID_INDEX;
	  break;
	default:
	  /* ignore */
	  break;
	}
    }
}

static_always_inline void
http3_stream_terminate (http_ctx_t *stream, http_ctx_t *req, http3_error_t err)
{
  /* this should not happen since we don't support server push */
  ASSERT (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM);

  http3_set_application_error_code (stream, err);
  if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED) || !(stream->flags & HTTP_CONN_F_NO_APP_SESSION))
    session_transport_reset_notify (&req->connection);
  http_reset_transport_stream (stream);
}

static_always_inline void
http3_conn_terminate (http_ctx_t *hc, http3_error_t err)
{
  http_ctx_t *parent_req;

  http3_set_application_error_code (hc, err);
  if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      parent_req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      if (!(parent_req->req_flags & HTTP_REQ_F_APP_CLOSED) ||
	  !(parent_req->req_flags & HTTP_CONN_F_NO_APP_SESSION))
	session_transport_reset_notify (&parent_req->connection);
    }
  http_disconnect_transport (hc);
}

static_always_inline void
http3_stream_error_terminate_conn (http_ctx_t *stream, http_ctx_t *req, http3_error_t err)
{
  http_ctx_t *hc;

  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  http3_conn_terminate (hc, err);
}

static_always_inline void
http3_stream_ctx_reset (http_ctx_t *old_stream, http_ctx_t *req)
{
  http_ctx_t *new_stream, *hc;
  u32 hc_index = old_stream->hc_http_conn_index;
  u32 req_index = ((http_req_handle_t) req->hr_req_handle).req_index;
  clib_thread_index_t thread_index = old_stream->c_thread_index;
  int rv;

  ASSERT (old_stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM);
  ASSERT (!(old_stream->flags & HTTP_CONN_F_IS_SERVER));

  /* confirm close if quic was waiting for us to read all data */
  if (old_stream->state == HTTP_CONN_STATE_TRANSPORT_CLOSED)
    http_close_transport_stream (old_stream);

  hc = http_ctx_get_w_thread (hc_index, thread_index);
  /* we don't need to open new quic stream if connection is closing */
  if (hc->state > HTTP_CONN_STATE_ESTABLISHED)
    return;

  old_stream->http_req_index = SESSION_INVALID_INDEX;
  /* open new quic stream */
  rv = http_connect_transport_stream (hc_index, thread_index, 0, &new_stream);
  /* pool grow, regrab connection and request */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  if (rv)
    {
      HTTP_DBG (1, "failed to open request stream");
      /* not much to do here, just notify app */
      if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
	session_transport_reset_notify (&req->connection);
      return;
    }
  new_stream->http_req_index = req_index;
  req->hr_hc_index = new_stream->hc_hc_index;
}

static_always_inline int
http3_conn_init (u32 parent_index, clib_thread_index_t thread_index, http_ctx_t *hc)
{
  http_main_t *hm = &http_main;
  http_ctx_t *ctrl_stream;
  u8 *buf, *p;
  u32 hc_index = hc->hc_hc_index;

  /* open control stream */
  if (http_connect_transport_stream (parent_index, thread_index, 1,
				     &ctrl_stream))
    {
      HTTP_DBG (1, "failed to open control stream");
      http3_conn_terminate (hc, HTTP3_ERROR_INTERNAL_ERROR);
      return -1;
    }
  ctrl_stream->http_req_index = SESSION_INVALID_INDEX;
  /* pool grow, regrab connection */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  hc->our_ctrl_stream_index = ctrl_stream->hc_hc_index;
  hc->settings = hm->h3_settings;
  /* adjust settings according to app rx_fifo size */
  hc->settings.max_field_section_size =
    clib_min (hc->settings.max_field_section_size, hc->hc_app_rx_fifo_size - sizeof (http_msg_t));
  http_stats_ctrl_streams_opened_inc (thread_index);

  buf = http_get_tx_buf (ctrl_stream);
  /* write stream type first */
  p = http_encode_varint (buf, HTTP3_STREAM_TYPE_CONTROL);
  vec_set_len (buf, (p - buf));
  /* write settings frame */
  http3_frame_settings_write (&hm->h3_settings, &buf);
  http_io_ts_write (ctrl_stream, buf, vec_len (buf), 0);
  http_io_ts_after_write (ctrl_stream, 1);
  return 0;
}

static_always_inline void
http3_send_goaway (http_ctx_t *hc)
{
  http_ctx_t *ctrl_stream;
  u8 *buf;
  /* for client set to 0 since we don't support push for server use max stream id */
  u64 stream_or_push_id = hc->flags & HTTP_CONN_F_IS_SERVER ? HTTP3_SERVER_MAX_STREAM_ID : 0;

  ctrl_stream = http_ctx_get_w_thread (hc->our_ctrl_stream_index, hc->c_thread_index);
  buf = http_get_tx_buf (ctrl_stream);
  http3_frame_goaway_write (stream_or_push_id, &buf);
  http_io_ts_write (ctrl_stream, buf, vec_len (buf), 0);
  http_io_ts_after_write (ctrl_stream, 1);
}

static void
http3_stream_app_close (http_ctx_t *req, http_ctx_t *stream, u8 is_shutdown)
{
  /* Wait for all data to be written to ts */
  if (http_io_as_max_read (req))
    {
      HTTP_DBG (1, "wait for all data to be written to ts");
      stream->state = HTTP_CONN_STATE_APP_CLOSED;
      return;
    }

  HTTP_DBG (1, "nothing more to send, confirm close");
  session_transport_closed_notify (&req->connection);
  http_stats_app_streams_closed_inc (stream->c_thread_index);
}

static void
http3_stream_app_close_parent (http_ctx_t *req, http_ctx_t *stream, u8 is_shutdown)
{
  http_ctx_t *hc;

  ASSERT (http_hc_is_valid (stream->hc_http_conn_index, stream->c_thread_index));
  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  /* send goaway if shutdown */
  if (is_shutdown)
    http3_send_goaway (hc);

  /* Wait for all data to be written to ts */
  if (http_io_as_max_read (req))
    {
      HTTP_DBG (1, "wait for all data to be written to ts");
      stream->state = HTTP_CONN_STATE_APP_CLOSED;
      return;
    }

  HTTP_DBG (1, "nothing more to send, confirm close");
  session_transport_closed_notify (&req->connection);
  http_stats_app_streams_closed_inc (stream->c_thread_index);
  HTTP_DBG (1, "app closed parent, closing connection");
  http3_set_application_error_code (hc, HTTP3_ERROR_NO_ERROR);
  http_disconnect_transport (hc);
}

static void
http3_stream_app_close_tunnel (http_ctx_t *req, http_ctx_t *stream, u8 is_shutdown)
{
  http_ctx_t *hc;

  req->req_flags |= is_shutdown ? HTTP_REQ_F_SHUTDOWN_TUNNEL : 0;
  /* Wait for all data to be written to ts */
  if (http_io_as_max_read (req))
    {
      HTTP_DBG (1, "wait for all data to be written to ts");
      stream->state = HTTP_CONN_STATE_APP_CLOSED;
      return;
    }

  switch (stream->state)
    {
    case HTTP_CONN_STATE_ESTABLISHED:
    case HTTP_CONN_STATE_APP_CLOSED: /* postponed cleanup */
      HTTP_DBG (1, "app want to close tunnel");
      if (!is_shutdown && http_io_ts_max_read (stream))
	{
	  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
	    {
	      HTTP_DBG (1, "app closed parent, going to reset connection");
	      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
	      session_reset (session_get_from_handle (hc->hc_tc_session_handle));
	      return;
	    }
	  HTTP_DBG (1, "app has unread data, going to reset stream");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_CONNECT_ERROR);
	  return;
	}
      HTTP_DBG (1, "nothing more to send, closing tunnel");
      http_half_close_transport_stream (stream);
      break;
    case HTTP_CONN_STATE_TRANSPORT_CLOSED:
      HTTP_DBG (1, "app confirmed tunnel close");
      http_stats_app_streams_closed_inc (stream->c_thread_index);
      http_close_transport_stream (stream);
      break;
    default:
      ASSERT (0);
      break;
    }
}

static_always_inline void
http3_stream_update_conn_timer (http_ctx_t *stream)
{
  ASSERT (http_hc_is_valid (stream->hc_http_conn_index, stream->c_thread_index));
  http_ctx_t *hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  http_conn_timer_update (hc);
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http3_req_state_wait_app_reply (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
				http3_error_t *error, u32 *n_deq)
{
  http_msg_t msg;
  hpack_response_control_data_t control_data;
  u8 *response, *date, *app_headers = 0;
  u32 headers_len, n_written;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  http_sm_result_t rv = HTTP_SM_STOP;
  http_req_state_t new_state;

  http_get_app_msg (req, &msg);
  ASSERT (msg.type == HTTP_MSG_REPLY);

  response = http_get_tx_buf (stream);
  date = format (0, "%U", format_http_time_now, stream);

  control_data.content_len = msg.data.body_len;
  control_data.server_name = stream->app_name;
  control_data.server_name_len = vec_len (stream->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);

  if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
    {
      switch (msg.code)
	{
	case HTTP_STATUS_SWITCHING_PROTOCOLS:
	  /* remap status code for extended connect response */
	  msg.code = HTTP_STATUS_OK;
	case HTTP_STATUS_OK:
	case HTTP_STATUS_CREATED:
	case HTTP_STATUS_ACCEPTED:
	  /* tunnel established if 2xx (Successful) response to CONNECT */
	  control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
	  new_state = (req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
		       (stream->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)) ?
			HTTP_REQ_STATE_UDP_TUNNEL :
			(((req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03) &&
			  (stream->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)) ?
			   HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03 :
			   HTTP_REQ_STATE_TUNNEL);
	  http_req_state_change (req, new_state);
	  req->app_closed_cb = http3_stream_app_close_tunnel;
	  break;
	default:
	  /* tunnel not established */
	  req->req_flags &= ~HTTP_REQ_F_IS_TUNNEL;
	  break;
	}
    }
  control_data.sc = msg.code;

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (req, &msg);

  qpack_serialize_response (app_headers, msg.data.headers_len, &control_data,
			    &response);
  vec_free (date);
  headers_len = vec_len (response);

  fh_len =
    http3_frame_header_write (HTTP3_FRAME_TYPE_HEADERS, headers_len, fh_buf);

  svm_fifo_seg_t segs[2] = { { fh_buf, fh_len }, { response, headers_len } };
  n_written = http_io_ts_write_segs (stream, segs, 2, 0);
  ASSERT (n_written == (fh_len + headers_len));

  if (msg.data.body_len)
    {
      ASSERT (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL));
      http_req_tx_buffer_init (req, &msg);
      http_req_state_change (req, HTTP_REQ_STATE_APP_IO_MORE_DATA);
      rv = HTTP_SM_CONTINUE;
    }
  else
    {
      /* all done, close stream */
      if (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL))
	http3_stream_close (stream, req);
    }

  http_io_ts_after_write (stream, 0);
  http_stats_responses_sent_inc (stream->c_thread_index);

  return rv;
}

static http_sm_result_t
http3_req_state_wait_app_method (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
				 http3_error_t *error, u32 *n_deq)
{
  http_msg_t msg;
  hpack_request_control_data_t control_data;
  u8 *request, *app_headers = 0;
  u32 headers_len, n_written;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY;

  http_get_app_msg (req, &msg);
  ASSERT (msg.type == HTTP_MSG_REQUEST);

  request = http_get_tx_buf (stream);

  control_data.method = msg.method_type;
  control_data.parsed_bitmap = HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  if (msg.method_type == HTTP_REQ_CONNECT || msg.method_type == HTTP_REQ_CONNECT_UDP)
    {
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->upgrade_proto = msg.data.upgrade_proto;
      /* deschedule until connect response, app might start enqueue tunneled data */
      http_req_deschedule (req, sp);
      if (msg.data.upgrade_proto != HTTP_UPGRADE_PROTO_NA)
	{
	  control_data.authority = stream->host;
	  control_data.authority_len = vec_len (stream->host);
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
	  control_data.scheme = HTTP_URL_SCHEME_HTTPS;
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
	  control_data.path = http_get_app_target (req, &msg);
	  control_data.path_len = msg.data.target_path_len;
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PROTOCOL_PARSED;
	  control_data.protocol = (u8 *) http3_ext_connect_proto[msg.data.upgrade_proto].base;
	  control_data.protocol_len = http3_ext_connect_proto[msg.data.upgrade_proto].len;
	  HTTP_DBG (1, "extended connect %s %U",
		    http3_ext_connect_proto[msg.data.upgrade_proto].base, format_http_bytes,
		    control_data.path, control_data.path_len);
	}
      else
	{
	  control_data.authority = http_get_app_target (req, &msg);
	  control_data.authority_len = msg.data.target_path_len;
	  HTTP_DBG (1, "opening %s tunnel to %U",
		    msg.method_type == HTTP_REQ_CONNECT_UDP ? "udp" : "tcp", format_http_bytes,
		    control_data.authority, control_data.authority_len);
	  if (msg.method_type == HTTP_REQ_CONNECT_UDP)
	    {
	      /* path is always "/", we set it here, app send us just authority part */
	      control_data.path = (u8 *) http_masque_draft03_path.base;
	      control_data.path_len = http_masque_draft03_path.len;
	      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
	      /* scheme is always masque */
	      control_data.scheme = HTTP_URL_SCHEME_MASQUE;
	      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
	      req->req_flags |= HTTP_REQ_F_CONNECT_UDP_DRAFT03;
	    }
	}
    }
  else
    {
      control_data.authority = stream->host;
      control_data.authority_len = vec_len (stream->host);
      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
      control_data.scheme = HTTP_URL_SCHEME_HTTPS;
      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
      control_data.path = http_get_app_target (req, &msg);
      control_data.path_len = msg.data.target_path_len;
      HTTP_DBG (1, "%U %U", format_http_method, control_data.method, format_http_bytes,
		control_data.path, control_data.path_len);
    }
  control_data.user_agent = stream->app_name;
  control_data.user_agent_len = vec_len (stream->app_name);
  control_data.content_len =
    msg.data.body_len ? msg.data.body_len : HPACK_ENCODER_SKIP_CONTENT_LEN;

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (req, &msg);

  qpack_serialize_request (app_headers, msg.data.headers_len, &control_data,
			   &request);

  headers_len = vec_len (request);

  fh_len =
    http3_frame_header_write (HTTP3_FRAME_TYPE_HEADERS, headers_len, fh_buf);

  svm_fifo_seg_t segs[2] = { { fh_buf, fh_len }, { request, headers_len } };
  n_written = http_io_ts_write_segs (stream, segs, 2, 0);
  ASSERT (n_written == (fh_len + headers_len));

  if (msg.data.body_len)
    {
      ASSERT (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL));
      http_req_tx_buffer_init (req, &msg);
      new_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
    }
  else if (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL))
    {
      /* all done, close stream for sending */
      http_half_close_transport_stream (stream);
    }

  http_io_ts_after_write (stream, 0);
  http_req_state_change (req, new_state);
  http_stats_requests_sent_inc (stream->c_thread_index);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_app_io_more_data (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
				  http3_error_t *error, u32 *n_deq)
{
  http_buffer_t *hb = &req->tx_buf;
  u32 max_write, n_read, n_segs, n_written;
  svm_fifo_seg_t *app_segs, *segs = 0;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len, finished;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  max_write = http_io_ts_max_write (stream, 0);
  if (max_write <= HTTP3_FRAME_HEADER_MAX_LEN)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_req_deschedule (req, sp);
      http_io_ts_add_want_deq_ntf (stream);
      return HTTP_SM_STOP;
    }
  max_write -= HTTP3_FRAME_HEADER_MAX_LEN;

  n_read = http_buffer_get_segs (hb, max_write, &app_segs, &n_segs);
  if (n_read == 0)
    {
      HTTP_DBG (1, "no data to deq");
      return HTTP_SM_STOP;
    }

  ASSERT (n_read);

  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_DATA, n_read, fh_buf);
  vec_validate (segs, 0);
  segs[0].len = fh_len;
  segs[0].data = fh_buf;
  vec_append (segs, app_segs);
  n_written = http_io_ts_write_segs (stream, segs, n_segs + 1, sp);
  n_written -= fh_len;
  ASSERT (n_written == n_read);
  vec_free (segs);
  http_buffer_drain (hb, n_written);
  finished = (http_buffer_bytes_left (hb) == 0);

  if (finished)
    {
      if (stream->flags & HTTP_CONN_F_IS_SERVER)
	{ /* all done, close stream */
	  http_buffer_free (hb);
	  http3_stream_close (stream, req);
	}
      else
	{
	  /* all done, close stream for sending */
	  http_half_close_transport_stream (stream);
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	}
    }
  http_io_ts_after_write (stream, finished);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_tunnel_tx (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
			   http3_error_t *error, u32 *n_deq)
{
  u32 max_write, max_read, n_read, n_segs = 2, n_written;
  svm_fifo_seg_t segs[n_segs + 1];
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;

  max_read = http_io_as_max_read (req);
  if (max_read == 0)
    {
      HTTP_DBG (2, "max_read == 0");
      return HTTP_SM_STOP;
    }
  max_write = http_io_ts_max_write (stream, 0);
  if (max_write <= HTTP3_FRAME_HEADER_MAX_LEN)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_req_deschedule (req, sp);
      http_io_ts_add_want_deq_ntf (stream);
      return HTTP_SM_STOP;
    }
  max_write -= HTTP3_FRAME_HEADER_MAX_LEN;
  max_read = clib_min (max_write, max_read);

  n_read = http_io_as_read_segs (req, segs + 1, &n_segs, max_read);

  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_DATA, n_read, fh_buf);
  segs[0].len = fh_len;
  segs[0].data = fh_buf;
  n_written = http_io_ts_write_segs (stream, segs, n_segs + 1, sp);
  n_written -= fh_len;
  HTTP_DBG (1, "written %lu", n_written);
  ASSERT (n_written == n_read);
  http_io_as_drain (req, n_written);
  http_io_ts_after_write (stream, 0);

  return HTTP_SM_STOP;
}

static_always_inline http_sm_result_t
http3_req_state_udp_tunnel_tx_inline (http_ctx_t *stream, http_ctx_t *req,
				      transport_send_params_t *sp, http3_error_t *error, u32 *n_deq,
				      u8 is_draft03)
{
  u32 max_read, max_write, n_written, dgram_size, capsule_size, n_segs = 2;
  session_dgram_hdr_t hdr;
  svm_fifo_seg_t segs[n_segs + 2]; /* 2 extra segments for frame and caspule headers */
  u8 *payload;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  u8 capsule_header[HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD];
  u8 capsule_header_len;

  max_read = http_io_as_max_read (req);
  if (max_read < sizeof (hdr))
    {
      HTTP_DBG (2, "max_read == 0");
      return HTTP_SM_STOP;
    }
  /* read datagram header */
  http_io_as_peek (req, (u8 *) &hdr, sizeof (hdr), 0);
  HTTP_DBG (1, "datagram len %lu", hdr.data_length);
  ASSERT (hdr.data_length <= HTTP_UDP_PAYLOAD_MAX_LEN);
  dgram_size = hdr.data_length + SESSION_CONN_HDR_LEN;
  if (PREDICT_FALSE (max_read < dgram_size))
    {
      HTTP_DBG (2, "datagram incomplete");
      return HTTP_SM_STOP;
    }
  ASSERT (max_read >= dgram_size);
  max_write = http_io_ts_max_write (stream, 0);
  if (PREDICT_FALSE (max_write < (hdr.data_length + HTTP3_FRAME_HEADER_MAX_LEN +
				  HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD)))
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_req_deschedule (req, sp);
      http_io_ts_add_want_deq_ntf (stream);
      return HTTP_SM_STOP;
    }
  http_io_as_drain (req, sizeof (hdr));
  /* create capsule header */
  payload = http_encap_udp_payload_datagram (capsule_header, hdr.data_length, is_draft03);
  capsule_header_len = payload - capsule_header;
  ASSERT (capsule_header_len <= HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD);
  capsule_size = capsule_header_len + hdr.data_length;
  /* read payload */
  http_io_as_read_segs (req, segs + 2, &n_segs, hdr.data_length);
  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_DATA, capsule_size, fh_buf);
  segs[0].len = fh_len;
  segs[0].data = fh_buf;
  segs[1].len = capsule_header_len;
  segs[1].data = capsule_header;
  n_written = http_io_ts_write_segs (stream, segs, n_segs + 2, 0);
  ASSERT (n_written == (fh_len + capsule_size));
  http_io_as_drain (req, hdr.data_length);
  http_io_ts_after_write (stream, 0);
  HTTP_DBG (1, "capsule payload len %lu", hdr.data_length);
  return (max_read - dgram_size) ? HTTP_SM_CONTINUE : HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_udp_tunnel_tx (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
			       http3_error_t *error, u32 *n_deq)
{
  return http3_req_state_udp_tunnel_tx_inline (stream, req, sp, error, n_deq, 0);
}

static http_sm_result_t
http3_req_state_udp_tunnel_draft03_tx (http_ctx_t *stream, http_ctx_t *req,
				       transport_send_params_t *sp, http3_error_t *error,
				       u32 *n_deq)
{
  return http3_req_state_udp_tunnel_tx_inline (stream, req, sp, error, n_deq, 1);
}

static_always_inline void
http3_stream_resp_not_implemented (http_ctx_t *stream, http_ctx_t *req)
{
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  u32 headers_len, n_written;
  u8 *response = http_get_tx_buf (stream);
  u8 *date = format (0, "%U", format_http_time_now, stream);
  hpack_response_control_data_t control_data = {
    .content_len = 0,
    .server_name = stream->app_name,
    .server_name_len = vec_len (stream->app_name),
    .date = date,
    .date_len = vec_len (date),
    .sc = HTTP_STATUS_NOT_IMPLEMENTED,
  };

  qpack_serialize_response (0, 0, &control_data, &response);
  vec_free (date);
  headers_len = vec_len (response);
  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_HEADERS, headers_len, fh_buf);
  svm_fifo_seg_t segs[2] = { { fh_buf, fh_len }, { response, headers_len } };
  n_written = http_io_ts_write_segs (stream, segs, 2, 0);
  ASSERT (n_written == (fh_len + headers_len));
  http3_stream_close (stream, req);
  http_io_ts_after_write (stream, 0);
  http_stats_responses_sent_inc (stream->c_thread_index);
}

#define http3_verify_port_in_authority()                                                           \
  do                                                                                               \
    {                                                                                              \
      p = control_data.authority + control_data.authority_len;                                     \
      p--;                                                                                         \
      if (!isdigit (*p))                                                                           \
	{                                                                                          \
	  HTTP_DBG (1, "port not present in authority");                                           \
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);                         \
	  return HTTP_SM_STOP;                                                                     \
	}                                                                                          \
      p--;                                                                                         \
      for (; p > control_data.authority; p--)                                                      \
	{                                                                                          \
	  if (!isdigit (*p))                                                                       \
	    break;                                                                                 \
	}                                                                                          \
      if (*p != ':')                                                                               \
	{                                                                                          \
	  HTTP_DBG (1, "port not present in authority");                                           \
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);                         \
	  return HTTP_SM_STOP;                                                                     \
	}                                                                                          \
    }                                                                                              \
  while (0);

static void
http3_send_431 (http_ctx_t *stream, http_ctx_t *req)
{
  hpack_response_control_data_t control_data;
  u8 *response, *date;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  u32 headers_len;

  ASSERT (stream->flags & HTTP_CONN_F_IS_SERVER);
  response = http_get_tx_buf (stream);
  date = format (0, "%U", format_http_time_now, stream);
  control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  control_data.server_name = stream->app_name;
  control_data.server_name_len = vec_len (stream->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);
  control_data.sc = HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
  qpack_serialize_response (0, 0, &control_data, &response);
  vec_free (date);
  headers_len = vec_len (response);
  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_HEADERS, headers_len, fh_buf);
  svm_fifo_seg_t segs[2] = { { fh_buf, fh_len }, { response, headers_len } };
  http_io_ts_write_segs (stream, segs, 2, 0);
  http_io_ts_after_write (stream, 0);
  http_stats_responses_sent_inc (stream->c_thread_index);
  /* notify app that nothing will happen */
  if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
    session_transport_reset_notify (&req->connection);
  http_close_transport_stream (stream);
  http_io_ts_after_write (stream, 0);
  http_stats_responses_sent_inc (stream->c_thread_index);
}

static http_sm_result_t
http3_req_state_wait_transport_method (http_ctx_t *stream, http_ctx_t *req,
				       transport_send_params_t *sp, http3_error_t *error,
				       u32 *n_deq)
{
  http_ctx_t *hc;
  hpack_request_control_data_t control_data;
  http_msg_t msg;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_REPLY;
  http_worker_t *wrk = http_worker_get (stream->c_thread_index);
  u8 *rx_buf, *p;
  http_sm_result_t res = HTTP_SM_STOP;

  if (http_io_ts_max_read (stream) < req->fh.length)
    {
      HTTP_DBG (1, "headers frame incomplete");
      if (stream->state == HTTP_CONN_STATE_HALF_CLOSED)
	http3_stream_terminate (stream, req, HTTP3_ERROR_REQUEST_INCOMPLETE);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  http_stats_requests_received_inc (stream->c_thread_index);

  rx_buf = http_get_rx_buf (stream);
  vec_validate (rx_buf, req->fh.length - 1);
  http_io_ts_read (stream, rx_buf, req->fh.length, 0);
  *n_deq = req->fh.length;

  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  *error = qpack_parse_request (rx_buf, req->fh.length, wrk->header_list,
				hc->settings.max_field_section_size, &control_data, &req->headers,
				&hc->qpack_decoder_ctx);
  if (*error != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "qpack_parse_request failed: %U", format_http3_error, *error);
      /* message error is only stream error */
      if (*error == HTTP3_ERROR_MESSAGE_ERROR)
	{
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      /* internal error is returned only when uncompressed headers exceeded maximum value, in this
       * case we should response with 431 (Request Header Fields Too Large) status code */
      else if (*error == HTTP3_ERROR_INTERNAL_ERROR)
	{
	  HTTP_DBG (1, "MAX_FIELD_SECTION_SIZE exceeded");
	  http3_send_431 (stream, req);
	  return HTTP_SM_STOP;
	}
      /* otherwise it's connection error */
      return HTTP_SM_ERROR;
    }

  req->control_data_len = control_data.control_data_len;
  req->headers_offset = control_data.headers - wrk->header_list;
  req->headers_len = control_data.headers_len;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_METHOD_PARSED))
    {
      HTTP_DBG (1, ":method pseudo-header missing in request");
      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported method");
      http3_stream_terminate (stream, req, HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":scheme pseudo-header missing in request");
      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.scheme == HTTP_URL_SCHEME_UNKNOWN && control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, "unsupported scheme");
      http3_stream_terminate (stream, req, HTTP3_ERROR_INTERNAL_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":path pseudo-header missing in request");
      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_AUTHORITY_PARSED))
    {
      HTTP_DBG (1, ":authority pseudo-header missing in request");
      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_CONNECT)
    {
      if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PROTOCOL_PARSED)
	{
	  /* extended CONNECT (RFC9220) */
	  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED) ||
	      !(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED))
	    {
	      HTTP_DBG (1, ":scheme and :path pseudo-header must be present for "
			   "extended CONNECT method");
	      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	      return HTTP_SM_STOP;
	    }
	  /* parse protocol header value */
	  if (0)
	    ;
#define _(sym, str)                                                                                \
  else if (http_token_is_case ((const char *) control_data.protocol, control_data.protocol_len,    \
			       http_token_lit (str))) req->upgrade_proto =                         \
    HTTP_UPGRADE_PROTO_##sym;
	  foreach_http_upgrade_proto
#undef _
	    else
	  {
	    HTTP_DBG (1, "unsupported extended connect protocol %U", format_http_bytes,
		      control_data.protocol, control_data.protocol_len);
	    http3_stream_resp_not_implemented (stream, req);
	    return HTTP_SM_STOP;
	  }
	}
      else
	{
	  if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED ||
	      control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
	    {
	      HTTP_DBG (1, ":scheme and :path pseudo-header must be omitted for "
			   "CONNECT method");
	      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	      return HTTP_SM_STOP;
	    }
	  /* quick check if port is present */
	  http3_verify_port_in_authority ();
	  req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
	}
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
    }
  else if (control_data.method == HTTP_REQ_CONNECT_UDP)
    {
      if (!(hc->flags & HTTP_CONN_F_CONNECT_UDP_DRAFT03))
	{
	  HTTP_DBG (1, "CONNECT-UDP method but masque-connect-udp-draft-03 not enabled");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
	  return HTTP_SM_STOP;
	}
      /* quick check if port is present */
      http3_verify_port_in_authority ();
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->req_flags |= HTTP_REQ_F_CONNECT_UDP_DRAFT03;
      req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
    }

  if (control_data.content_len_header_index != ~0)
    {
      req->content_len_header_index = control_data.content_len_header_index;
      if (http_parse_content_length (req, wrk->header_list))
	{
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      if (stream->state == HTTP_CONN_STATE_HALF_CLOSED && !http_io_ts_max_read (stream))
	{
	  HTTP_DBG (1, "request incomplete");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_REQUEST_INCOMPLETE);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      res = HTTP_SM_CONTINUE;
    }
  req->to_recv = req->body_len;

  req->target_query_offset = 0;
  req->target_query_len = 0;
  if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
    {
      req->target_path_len = control_data.path_len;
      req->target_path_offset = control_data.path - wrk->header_list;
      /* drop leading slash */
      req->target_path_offset++;
      req->target_path_len--;
      http_identify_optional_query (req, wrk->header_list);
    }
  else
    {
      req->target_path_len = 0;
      req->target_path_offset = 0;
    }

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = control_data.method;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = req->control_data_len;
  msg.data.scheme = control_data.scheme;
  msg.data.target_authority_offset = control_data.authority - wrk->header_list;
  msg.data.target_authority_len = control_data.authority_len;
  msg.data.target_path_offset = req->target_path_offset;
  msg.data.target_path_len = req->target_path_len;
  msg.data.target_query_offset = req->target_query_offset;
  msg.data.target_query_len = req->target_query_len;
  msg.data.headers_offset = req->headers_offset;
  msg.data.headers_len = req->headers_len;
  msg.data.headers_ctx = pointer_to_uword (req->headers);
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_NA;
  msg.data.body_offset = req->control_data_len;
  msg.data.body_len = req->body_len;
  msg.data.upgrade_proto = req->upgrade_proto;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { wrk->header_list, req->control_data_len } };
  HTTP_DBG (3, "%U", format_http_bytes, wrk->header_list, req->control_data_len);
  http_io_as_write_segs (req, segs, 2);
  http_req_state_change (req, new_state);
  http_app_worker_rx_notify (req);
  req->fh.length = 0;

  return res;
}

static http_sm_result_t
http3_req_state_wait_transport_reply (http_ctx_t *stream, http_ctx_t *req,
				      transport_send_params_t *sp, http3_error_t *error, u32 *n_deq)
{
  http_ctx_t *hc;
  hpack_response_control_data_t control_data;
  http_msg_t msg;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_METHOD;
  http_worker_t *wrk = http_worker_get (stream->c_thread_index);
  u8 *rx_buf;
  http_sm_result_t res = HTTP_SM_STOP;

  if (http_io_ts_max_read (stream) < req->fh.length)
    {
      HTTP_DBG (1, "headers frame incomplete");
      *error = HTTP3_ERROR_INCOMPLETE;
      *n_deq = 0;
      return HTTP_SM_ERROR;
    }

  http_stats_responses_received_inc (stream->c_thread_index);

  rx_buf = http_get_rx_buf (stream);
  vec_validate (rx_buf, req->fh.length - 1);
  http_io_ts_read (stream, rx_buf, req->fh.length, 0);
  *n_deq = req->fh.length;

  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);

  vec_reset_length (req->headers);
  *error = qpack_parse_response (rx_buf, req->fh.length, wrk->header_list,
				 hc->settings.max_field_section_size, &control_data, &req->headers,
				 &hc->qpack_decoder_ctx);
  if (*error != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "qpack_parse_response failed");
      /* message error is only stream error, otherwise it's connection error */
      if (*error == HTTP3_ERROR_MESSAGE_ERROR)
	{
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      return HTTP_SM_ERROR;
    }

  req->control_data_len = control_data.control_data_len;
  req->headers_offset = control_data.headers - wrk->header_list;
  req->headers_len = control_data.headers_len;
  req->status_code = control_data.sc;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_STATUS_PARSED))
    {
      HTTP_DBG (1, ":status pseudo-header missing in request");
      http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }

  if ((req->req_flags & HTTP_REQ_F_IS_TUNNEL) && http_status_code_str[req->status_code][0] == '2')
    {
      new_state = (req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
		   (stream->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)) ?
		    HTTP_REQ_STATE_UDP_TUNNEL :
		    (((req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03) &&
		      (stream->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)) ?
		       HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03 :
		       HTTP_REQ_STATE_TUNNEL);
      req->app_closed_cb = http3_stream_app_close_tunnel;
      /* reschedule, we can now transfer tunnel data */
      transport_connection_reschedule (&req->connection);
      /* cleanup some stuff we don't need anymore in tunnel mode */
      vec_free (req->headers);
    }
  else if (control_data.content_len_header_index != ~0)
    {
      req->content_len_header_index = control_data.content_len_header_index;
      if (http_parse_content_length (req, wrk->header_list))
	{
	  http3_stream_terminate (stream, req, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      res = HTTP_SM_CONTINUE;
    }
  else
    {
      /* we are done wait for the next app request */
      clib_thread_index_t thread_index = stream->c_thread_index;
      u32 req_index = ((http_req_handle_t) req->hr_req_handle).req_index;
      http3_stream_ctx_reset (stream, req);
      req = http_ctx_get_w_thread (req_index, thread_index);
    }
  req->to_recv = req->body_len;

  msg.type = HTTP_MSG_REPLY;
  msg.code = req->status_code;
  msg.data.headers_offset = req->headers_offset;
  msg.data.headers_len = req->headers_len;
  msg.data.headers_ctx = pointer_to_uword (req->headers);
  msg.data.body_offset = req->control_data_len;
  msg.data.body_len = req->body_len;
  msg.data.type = HTTP_MSG_DATA_INLINE;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { wrk->header_list, req->control_data_len } };
  HTTP_DBG (3, "%U", format_http_bytes, wrk->header_list, req->control_data_len);
  http_io_as_write_segs (req, segs, 2);
  http_req_state_change (req, new_state);
  http_app_worker_rx_notify (req);
  req->fh.length = 0;

  return res;
}

static http_sm_result_t
http3_req_state_transport_io_more_data (http_ctx_t *stream, http_ctx_t *req,
					transport_send_params_t *sp, http3_error_t *error,
					u32 *n_deq)
{
  u32 max_enq, max_deq, n_written, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];
  http_sm_result_t res = HTTP_SM_CONTINUE;

  max_deq = http_io_ts_max_read (stream);
  if (max_deq == 0)
    {
      HTTP_DBG (1, "nothing to deq");
      *n_deq = 0;
      return HTTP_SM_STOP;
    }
  max_deq = clib_min (max_deq, req->fh.length);

  if (req->fh.length > req->to_recv)
    {
      HTTP_DBG (1, "received more data than expected, fh.len %lu to_recv %lu", req->fh.length,
		req->to_recv);
      *error = HTTP3_ERROR_GENERAL_PROTOCOL_ERROR;
      *n_deq = 0;
      return HTTP_SM_ERROR;
    }

  max_enq = http_io_as_max_write (req);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_io_as_add_want_deq_ntf (req);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  http_io_ts_read_segs (stream, segs, &n_segs, clib_min (max_deq, max_enq));
  n_written = http_io_as_write_segs (req, segs, n_segs);
  ASSERT (req->fh.length >= n_written);
  req->to_recv -= n_written;
  req->fh.length -= n_written;
  http_io_ts_drain (stream, n_written);
  *n_deq = n_written;
  HTTP_DBG (2, "written %lu to recv %lu", n_written, req->to_recv);

  if (req->to_recv == 0)
    {
      if (stream->flags & HTTP_CONN_F_IS_SERVER)
	http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
      else
	{
	  /* we are done wait for the next app request */
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
	  clib_thread_index_t thread_index = stream->c_thread_index;
	  u32 req_index = ((http_req_handle_t) req->hr_req_handle).req_index;
	  http3_stream_ctx_reset (stream, req);
	  req = http_ctx_get_w_thread (req_index, thread_index);
	}
      res = HTTP_SM_STOP;
    }
  else
    {
      if (stream->flags & HTTP_CONN_F_IS_SERVER && stream->state == HTTP_CONN_STATE_HALF_CLOSED &&
	  !http_io_ts_max_read (stream))
	{
	  HTTP_DBG (1, "request incomplete");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_REQUEST_INCOMPLETE);
	  return HTTP_SM_STOP;
	}
    }
  http_app_worker_rx_notify (req);

  if (max_deq > n_written)
    {
      http_io_as_add_want_deq_ntf (req);
      res = HTTP_SM_STOP;
    }

  return res;
}

static http_sm_result_t
http3_req_state_tunnel_rx (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
			   http3_error_t *error, u32 *n_deq)
{
  u32 max_enq, max_deq, n_written, n_segs = 2;
  svm_fifo_seg_t segs[n_segs];
  http_sm_result_t res = HTTP_SM_CONTINUE;

  if ((req->req_flags & HTTP_REQ_F_APP_CLOSED) && !(req->req_flags & HTTP_REQ_F_SHUTDOWN_TUNNEL))
    {
      HTTP_DBG (1, "proxy app closed, going to reset stream");
      http3_stream_terminate (stream, req, HTTP3_ERROR_CONNECT_ERROR);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  max_deq = http_io_ts_max_read (stream);
  if (max_deq == 0)
    {
      HTTP_DBG (1, "nothing to deq");
      *n_deq = 0;
      return HTTP_SM_STOP;
    }
  max_deq = clib_min (max_deq, req->fh.length);

  max_enq = http_io_as_max_write (req);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_io_as_add_want_deq_ntf (req);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }
  http_io_ts_read_segs (stream, segs, &n_segs, clib_min (max_deq, max_enq));
  n_written = http_io_as_write_segs (req, segs, n_segs);
  ASSERT (req->fh.length >= n_written);
  req->fh.length -= n_written;
  http_io_ts_drain (stream, n_written);
  *n_deq = n_written;
  http_app_worker_rx_notify (req);
  HTTP_DBG (2, "written %lu", n_written);

  return res;
}

static http_sm_result_t
http3_req_state_udp_tunnel_rx_inline (http_ctx_t *stream, http_ctx_t *req,
				      transport_send_params_t *sp, http3_error_t *error, u32 *n_deq,
				      u8 is_draft03)
{
  u8 *rx_buf;
  int rv;
  u8 payload_offset = 0;
  u64 payload_len = 0;
  u32 dgram_size;
  session_dgram_hdr_t hdr;

  if (http_io_ts_max_read (stream) < req->fh.length)
    {
      HTTP_DBG (1, "data frame incomplete");
      *error = HTTP3_ERROR_INCOMPLETE;
      *n_deq = 0;
      return HTTP_SM_ERROR;
    }

  rx_buf = http_get_rx_buf (stream);
  vec_validate (rx_buf, req->fh.length - 1);
  http_io_ts_read (stream, rx_buf, req->fh.length, 1);
  rv = http_decap_udp_payload_datagram (rx_buf, req->fh.length, &payload_offset, &payload_len,
					is_draft03);
  HTTP_DBG (1, "rv=%d, payload_offset=%u, payload_len=%llu", rv, payload_offset, payload_len);
  if (PREDICT_FALSE (rv != 0))
    {
      if (rv < 0)
	{
	  /* capsule datagram is invalid (stream need to be aborted) */
	  HTTP_DBG (1, "invalid capsule");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_DATAGRAM_ERROR);
	  *n_deq = 0;
	  return HTTP_SM_STOP;
	}
      else
	{
	  /* unknown capsule should be skipped */
	  HTTP_DBG (1, "unknown capsule dropped");
	  http_io_ts_drain (stream, req->fh.length);
	  *n_deq = req->fh.length;
	  req->fh.length = 0;
	  return HTTP_SM_CONTINUE;
	}
    }
  /* check if we have the full capsule */
  if (PREDICT_FALSE (req->fh.length != (payload_offset + payload_len)))
    {
      HTTP_DBG (1, "capsule not complete, frame length: %lu, capsule size: %lu", req->fh.length,
		payload_offset + payload_len);
      http3_stream_terminate (stream, req, HTTP3_ERROR_DATAGRAM_ERROR);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }
  dgram_size = sizeof (hdr) + payload_len;
  if (http_io_as_max_write (req) < dgram_size)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_io_as_add_want_deq_ntf (req);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  hdr.data_length = payload_len;
  hdr.data_offset = 0;
  hdr.gso_size = 0;

  /* send datagram header and payload */
  svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
			     { rx_buf + payload_offset, payload_len } };
  http_io_as_write_segs (req, segs, 2);
  http_app_worker_rx_notify (req);
  http_io_ts_drain (stream, req->fh.length);
  *n_deq = req->fh.length;
  req->fh.length = 0;

  return HTTP_SM_CONTINUE;
}

static http_sm_result_t
http3_req_state_udp_tunnel_rx (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp,
			       http3_error_t *error, u32 *n_deq)
{
  return http3_req_state_udp_tunnel_rx_inline (stream, req, sp, error, n_deq, 0);
}

static http_sm_result_t
http3_req_state_udp_tunnel_draft03_rx (http_ctx_t *stream, http_ctx_t *req,
				       transport_send_params_t *sp, http3_error_t *error,
				       u32 *n_deq)
{
  return http3_req_state_udp_tunnel_rx_inline (stream, req, sp, error, n_deq, 1);
}

/*************************/
/* request state machine */
/*************************/

typedef http_sm_result_t (*http3_sm_handler) (http_ctx_t *hc, http_ctx_t *req,
					      transport_send_params_t *sp, http3_error_t *error,
					      u32 *n_deq);

static http3_sm_handler tx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  http3_req_state_wait_app_method,
  0, /* wait transport reply */
  0, /* transport io more data */
  0, /* wait transport method */
  http3_req_state_wait_app_reply,
  http3_req_state_app_io_more_data,
  http3_req_state_tunnel_tx,
  http3_req_state_udp_tunnel_tx,
  http3_req_state_udp_tunnel_draft03_tx,
  0, /* app io more streaming data */
};

static http3_sm_handler rx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  http3_req_state_wait_transport_reply,
  http3_req_state_transport_io_more_data,
  http3_req_state_wait_transport_method,
  0, /* wait app reply */
  0, /* app io more data */
  http3_req_state_tunnel_rx,
  http3_req_state_udp_tunnel_rx,
  http3_req_state_udp_tunnel_draft03_rx,
  0, /* app io more streaming data */
};

static_always_inline int
http3_req_state_is_tx_valid (http_ctx_t *req)
{
  return tx_state_funcs[req->req_state] ? 1 : 0;
}

static_always_inline http3_error_t
http3_req_run_tx_state_machine (http_ctx_t *stream, http_ctx_t *req, transport_send_params_t *sp)
{
  http_sm_result_t res;
  http3_error_t error;

  do
    {
      res = tx_state_funcs[req->req_state](stream, req, sp, &error, 0);
      if (res == HTTP_SM_ERROR)
	{
	  HTTP_DBG (1, "protocol error %U", format_http3_error, error);
	  return error;
	}
    }
  while (res == HTTP_SM_CONTINUE);

  return HTTP3_ERROR_NO_ERROR;
}

/******************/
/* frame handlers */
/******************/

static_always_inline int
http3_stream_read_frame_header (http_ctx_t *req, http_ctx_t *stream, u32 *to_deq,
				http3_frame_header_t *fh)
{
  http3_error_t err;
  u8 *rx_buf;
  u32 to_read, hdr_size;

  rx_buf = http_get_rx_buf (stream);
  to_read = clib_min (*to_deq, HTTP3_FRAME_HEADER_MAX_LEN);
  http_io_ts_read (stream, rx_buf, to_read, 1);
  err = http3_frame_header_read (rx_buf, to_read, req->stream_type, fh);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      if (err == HTTP3_ERROR_INCOMPLETE)
	{
	  HTTP_DBG (1, "frame header incomplete");
	  return 1;
	}
      else
	{
	  HTTP_DBG (1, "invalid frame: %U", format_http3_error, err);
	  http3_stream_error_terminate_conn (stream, req, err);
	  return 1;
	}
    }
  HTTP_DBG (1, "stream [%u]%x req %x, frame type: %x, payload len: %u", stream->c_thread_index,
	    stream->hc_hc_index, ((http_req_handle_t) req->hr_req_handle).req_index, fh->type,
	    fh->length);
  hdr_size = (fh->payload - rx_buf);
  *to_deq -= hdr_size;
  if (*to_deq < fh->length)
    {
      HTTP_DBG (1, "incomplete frame payload");
      return 1;
    }
  http_io_ts_drain (stream, hdr_size);
  return 0;
}

static_always_inline http3_error_t
http3_stream_peek_frame_header (http_ctx_t *req, http_ctx_t *stream)
{
  u8 *rx_buf;
  u32 n_read;

  rx_buf = http_get_rx_buf (stream);
  n_read = http_io_ts_read (stream, rx_buf, HTTP3_FRAME_HEADER_MAX_LEN, 1);
  return http3_frame_header_read (rx_buf, n_read, req->stream_type, &req->fh);
}

static_always_inline void
http3_stream_drop_frame_header (http_ctx_t *req, http_ctx_t *stream)
{
  http_io_ts_drain (stream, req->fh.header_len);
}

static_always_inline int
http3_stream_read_settings (http_ctx_t *req, http_ctx_t *stream, u32 *to_deq,
			    http3_frame_header_t *fh)
{
  http3_error_t err;
  http_ctx_t *hc;
  u8 *rx_buf;

  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  if (!(hc->flags & HTTP_CONN_F_EXPECT_PEER_SETTINGS))
    {
      HTTP_DBG (1, "second settings frame received");
      http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_FRAME_UNEXPECTED);
      return -1;
    }
  hc->flags &= ~HTTP_CONN_F_EXPECT_PEER_SETTINGS;
  if (fh->length == 0)
    return 0;
  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, fh->length, 0);
  *to_deq -= fh->length;
  err = http3_frame_settings_read (rx_buf, fh->length, &hc->peer_settings);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "settings error");
      http3_stream_error_terminate_conn (stream, req, err);
      return -1;
    }
  return 0;
}

static u32
http3_stream_transport_rx_drain (CLIB_UNUSED (http_ctx_t *req), http_ctx_t *stream)
{
  u32 n_deq = http_io_ts_max_read (stream);
  http_io_ts_drain_all (stream);
  return n_deq;
}

static_always_inline int
http3_stream_read_goaway (http_ctx_t *req, http_ctx_t *stream, u32 *to_deq,
			  http3_frame_header_t *fh)
{
  http3_error_t err;
  http_ctx_t *parent_req;
  http_ctx_t *hc;
  u8 *rx_buf;
  u64 stream_or_push_id;

  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, fh->length, 0);
  *to_deq -= fh->length;
  err = http3_frame_goaway_read (rx_buf, fh->length, &stream_or_push_id);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "invalid stream id/push id in goaway frame");
      http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_ID_ERROR);
      return -1;
    }
  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  /* graceful shutdown (no new streams for client) */
  if (!(stream->flags & HTTP_CONN_F_IS_SERVER) && hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      parent_req = http_ctx_get_w_thread (hc->hc_parent_req_index, stream->c_thread_index);
      session_transport_closing_notify (&parent_req->connection);
    }
  return 0;
}
static u32
http3_stream_transport_rx_ctrl (http_ctx_t *req, http_ctx_t *stream)
{
  u32 to_deq, max_deq;
  http_ctx_t *hc;

  max_deq = to_deq = http_io_ts_max_read (stream);
  while (to_deq)
    {
      http3_frame_header_t fh = {};
      if (PREDICT_FALSE (http3_stream_read_frame_header (req, stream, &to_deq, &fh)))
	goto done;
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      if (hc->flags & HTTP_CONN_F_EXPECT_PEER_SETTINGS && fh.type != HTTP3_FRAME_TYPE_SETTINGS)
	{
	  HTTP_DBG (1, "expected settings frame");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_MISSING_SETTINGS);
	  goto done;
	}
      switch (fh.type)
	{
	case HTTP3_FRAME_TYPE_SETTINGS:
	  HTTP_DBG (1, "settings received");
	  if (PREDICT_FALSE (http3_stream_read_settings (req, stream, &to_deq, &fh)))
	    goto done;
	  break;
	case HTTP3_FRAME_TYPE_GOAWAY:
	  HTTP_DBG (1, "goaway received");
	  if (PREDICT_FALSE (http3_stream_read_goaway (req, stream, &to_deq, &fh)))
	    goto done;
	  break;
	default:
	  /* discard payload of unknown frame */
	  if (fh.length)
	    {
	      http_io_ts_drain (stream, fh.length);
	      to_deq -= fh.length;
	    }
	  break;
	}
    }
done:
  return max_deq - to_deq;
}

static u32
http3_stream_transport_rx_unknown_type (http_ctx_t *req, http_ctx_t *stream)
{
  u32 max_deq, to_deq, n_deq;
  u8 *rx_buf, *p;
  u64 stream_type;
  http_ctx_t *hc;

  max_deq = http_io_ts_max_read (stream);
  ASSERT (max_deq > 0);
  to_deq = clib_min (max_deq, HTTP_VARINT_MAX_LEN);
  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, to_deq, 1);
  p = rx_buf;
  stream_type = http_decode_varint (&p, p + to_deq);
  if (stream_type == HTTP_INVALID_VARINT)
    {
      http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
      return 0;
    }
  n_deq = p - rx_buf;
  http_io_ts_drain (stream, n_deq);
  req->stream_type = stream_type;
  HTTP_DBG (1, "stream type %lx [%u]%x req %x", stream_type, stream->hc_hc_index,
	    req->c_thread_index, ((http_req_handle_t) req->hr_req_handle).req_index);

  hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);

  switch (stream_type)
    {
    case HTTP3_STREAM_TYPE_CONTROL:
      if (hc->peer_ctrl_stream_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second control stream opened");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return n_deq;
	}
      hc->peer_ctrl_stream_index = ((http_req_handle_t) req->hr_req_handle).req_index;
      req->transport_rx_cb = http3_stream_transport_rx_ctrl;
      break;
    case HTTP3_STREAM_TYPE_DECODER:
      if (hc->peer_decoder_stream_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second decoder stream opened");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return n_deq;
	}
      hc->peer_decoder_stream_index = ((http_req_handle_t) req->hr_req_handle).req_index;
      req->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    case HTTP3_STREAM_TYPE_ENCODER:
      if (hc->peer_encoder_stream_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second encoder stream opened");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return n_deq;
	}
      hc->peer_encoder_stream_index = ((http_req_handle_t) req->hr_req_handle).req_index;
      req->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    case HTTP3_STREAM_TYPE_PUSH:
      if (stream->flags & HTTP_CONN_F_IS_SERVER)
	{
	  HTTP_DBG (1, "client initiated push stream");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return n_deq;
	}
      /* push not supported (we do not send MAX_PUSH_ID frame)*/
      HTTP_DBG (1, "server initiated push stream, not supported");
      http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_ID_ERROR);
      return n_deq;
    default:
      req->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    }

  n_deq += req->transport_rx_cb (req, stream);
  return n_deq;
}

static u32
http3_stream_transport_rx_req (http_ctx_t *req, http_ctx_t *stream, http_req_state_t headers_state)
{
  http3_error_t err;
  http_sm_result_t res = HTTP_SM_CONTINUE;
  u32 max_deq, left_deq, n_deq;

  max_deq = http_io_ts_max_read (stream);
  left_deq = max_deq;

  while (res == HTTP_SM_CONTINUE && left_deq)
    {
      if (req->fh.length == 0)
	{
	  err = http3_stream_peek_frame_header (req, stream);
	  if (err != HTTP3_ERROR_NO_ERROR)
	    {
	      req->fh.length = 0;
	      goto error;
	    }
	  http3_stream_drop_frame_header (req, stream);
	  left_deq -= req->fh.header_len;
	}

      switch (req->fh.type)
	{
	case HTTP3_FRAME_TYPE_HEADERS:
	  HTTP_DBG (1, "headers received");
	  if (req->req_state != headers_state)
	    {
	      HTTP_DBG (1, "unexpected frame, state: %U", format_http_req_state, req->req_state);
	      err = HTTP3_ERROR_FRAME_UNEXPECTED;
	      goto error;
	    }
	  break;
	case HTTP3_FRAME_TYPE_DATA:
	  HTTP_DBG (1, "data received");
	  if (!(req->req_state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA ||
		req->req_state == HTTP_REQ_STATE_TUNNEL ||
		req->req_state == HTTP_REQ_STATE_UDP_TUNNEL ||
		req->req_state == HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03))
	    {
	      HTTP_DBG (1, "unexpected frame, state: %U", format_http_req_state, req->req_state);
	      err = HTTP3_ERROR_FRAME_UNEXPECTED;
	      goto error;
	    }
	  break;
	default:
	  /* discard payload of unknown frame */
	  if (req->fh.length)
	    req->fh.length -= http_io_ts_drain (stream, req->fh.length);
	  continue;
	}

      res = rx_state_funcs[req->req_state](stream, req, 0, &err, &n_deq);
      left_deq -= n_deq;
      ASSERT (left_deq == http_io_ts_max_read (stream));
    }

  if (res == HTTP_SM_ERROR)
    {
    error:
      if (err != HTTP3_ERROR_INCOMPLETE)
	http3_stream_error_terminate_conn (stream, req, err);
    }

  return max_deq - left_deq;
}

static u32
http3_stream_transport_rx_req_server (http_ctx_t *req, http_ctx_t *stream)
{
  return http3_stream_transport_rx_req (req, stream, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
}

static u32
http3_stream_transport_rx_req_client (http_ctx_t *req, http_ctx_t *stream)
{
  return http3_stream_transport_rx_req (req, stream, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
}

/*****************/
/* http core VFT */
/*****************/

static int
http3_update_settings (http3_settings_t type, u64 value)
{
  http_main_t *hm = &http_main;

  switch (type)
    {
#define _(v, label, member, min, max, default_value, server, client)                               \
  case HTTP3_SETTINGS_##label:                                                                     \
    if (!(value >= (min) && value <= (max)))                                                       \
      return -1;                                                                                   \
    hm->h3_settings.member = value;                                                                \
    return 0;
      foreach_http3_settings
#undef _
	default : return -1;
    }
}

static uword
http3_unformat_config_callback (unformat_input_t *input)
{
  u64 value;

  if (!input)
    return 0;

  unformat_skip_white_space (input);
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max-field-section-size %lu", &value))
	{
	  if (http3_update_settings (HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE,
				     value))
	    return 0;
	}
    }
  return 1;
}

static transport_connection_t *
http3_req_get_connection (u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  req = http_ctx_get_w_thread (req_index, thread_index);
  return &(req->connection);
}

static u8 *
format_http3_req (u8 *s, va_list *args)
{
  http_ctx_t *req = va_arg (*args, http_ctx_t *);
  http_ctx_t *stream = va_arg (*args, http_ctx_t *);
  session_t *ts;

  ts = session_get_from_handle (stream->hc_tc_session_handle);
  s = format (s, "[%d:%d][H3] app_wrk %u hc_index %u ts %u:%u", req->c_thread_index, req->c_s_index,
	      req->hr_pa_wrk_index, req->hr_hc_index, ts->thread_index, ts->session_index);

  return s;
}

static u8 *
format_http3_req_vars (u8 *s, va_list *args)
{
  http_ctx_t *req = va_arg (*args, http_ctx_t *);
  http_ctx_t *stream = va_arg (*args, http_ctx_t *);
  http_ctx_t *hc;
  http_ctx_t *c_req;
  http_ctx_t *c_stream;
  session_t *ts;

  if (!(stream->flags & HTTP_CONN_F_IS_SERVER && req->req_flags & HTTP_REQ_F_IS_PARENT))
    s = format (s, " %U\n", format_http3_stream_type, req->stream_type);
  s = format (s, " req state: %U\n", format_http_req_state, req->req_state);
  s = format (s, " flags: %U\n", format_http_req_flags, req);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      s = format (s, " hc_flags: %U\n", format_http_conn_flags, stream);
      if (hc->our_ctrl_stream_index != SESSION_INVALID_INDEX)
	{
	  c_stream = http_ctx_get_w_thread (hc->our_ctrl_stream_index, stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " our_ctrl_stream: hc_index %u ts %u:%u\n", hc->our_ctrl_stream_index,
		      ts->thread_index, ts->session_index);
	}
      else
	{
	  s = format (s, " our_ctrl_stream not opened\n");
	}
      if (hc->peer_ctrl_stream_index != SESSION_INVALID_INDEX)
	{
	  c_req = http_ctx_get_w_thread (hc->peer_ctrl_stream_index, stream->c_thread_index);
	  c_stream = http_ctx_get_w_thread (c_req->hr_hc_index, stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_ctrl_stream hc_index %u ts %u:%u\n", c_req->hr_hc_index,
		      ts->thread_index, ts->session_index);
	}
      else
	{
	  s = format (s, " peer_ctrl_stream not opened\n");
	}
      if (hc->peer_encoder_stream_index != SESSION_INVALID_INDEX)
	{
	  c_req = http_ctx_get_w_thread (hc->peer_encoder_stream_index, stream->c_thread_index);
	  c_stream = http_ctx_get_w_thread (c_req->hr_hc_index, stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_encoder_stream hc_index %u ts %u:%u\n", c_req->hr_hc_index,
		      ts->thread_index, ts->session_index);
	}
      else
	{
	  s = format (s, " peer_encoder_stream not opened\n");
	}
      if (hc->peer_decoder_stream_index != SESSION_INVALID_INDEX)
	{
	  c_req = http_ctx_get_w_thread (hc->peer_decoder_stream_index, stream->c_thread_index);
	  c_stream = http_ctx_get_w_thread (c_req->hr_hc_index, stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_decoder_stream hc_index %u ts %u:%u\n", c_req->hr_hc_index,
		      ts->thread_index, ts->session_index);
	}
      else
	{
	  s = format (s, " peer_decoder_stream not opened\n");
	}
    }
  return s;
}

static u8 *
http3_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  http_ctx_t *stream = va_arg (*args, http_ctx_t *);
  transport_fmt_req_t fmt = { .as_u32 = va_arg (*args, u32) };
  http_ctx_t *req;

  req = http_ctx_get_w_thread (req_index, thread_index);

  if (!transport_fmt_req_is_explicit (fmt))
    {
      s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http3_req, req, stream);
      if (fmt.level)
	{
	  s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, stream);
	  if (fmt.level > 1)
	    s = format (s, "\n%U", format_http3_req_vars, req, stream);
	}
      return s;
    }

  if (fmt.conn_id)
    s = format (s, "%U", format_http3_req, req, stream);
  if (fmt.transport_state)
    {
      if (fmt.conn_id)
	s = format (s, "\t");
      s = format (s, "%U", format_http_conn_state, stream);
    }
  if (fmt.transport_detail)
    s = format (s, "\n%U", format_http3_req_vars, req, stream);

  return s;
}

static void
http3_app_tx_callback (http_ctx_t *stream, u32 req_index, transport_send_params_t *sp)
{
  http_ctx_t *req;
  http3_error_t err;
  u32 stream_index = stream->hc_hc_index;
  clib_thread_index_t thread_index = stream->c_thread_index;

  req = http_ctx_get_w_thread (req_index, thread_index);
  HTTP_DBG (1, "stream [%u]%x req %x", thread_index, stream->hc_hc_index, req_index);
  if (!http3_req_state_is_tx_valid (req))
    {
      if (req->req_state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  (stream->flags & HTTP_CONN_F_IS_SERVER))
	{
	  /* server app might send error earlier */
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			thread_index, stream_index, format_http_req_state, req->req_state,
			format_http_conn_state, stream);
	  http3_stream_terminate (stream, req, HTTP3_ERROR_INTERNAL_ERROR);
	  return;
	}
    }
  err = http3_req_run_tx_state_machine (stream, req, sp);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      ASSERT (err != HTTP3_ERROR_INCOMPLETE);
      req = http_ctx_get_w_thread (req_index, thread_index);
      http3_stream_error_terminate_conn (stream, req, err);
      return;
    }

  /* reset http connection expiration timer */
  http3_stream_update_conn_timer (stream);
}

static void
http3_app_rx_evt_callback (http_ctx_t *stream, u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  u32 n_deq;

  HTTP_DBG (1, "stream [%u]%x req %x", stream->c_thread_index, stream->hc_hc_index, req_index);

  ASSERT (http_ctx_is_stream (stream));

  req = http_ctx_get_w_thread (req_index, thread_index);
  n_deq = req->transport_rx_cb (req, stream);
  http_io_ts_program_rx_evt (stream, n_deq);

  /* reset http connection expiration timer */
  http3_stream_update_conn_timer (stream);
}

static void
http3_app_close_callback (http_ctx_t *stream, u32 req_index, clib_thread_index_t thread_index,
			  u8 is_shutdown)
{
  http_ctx_t *req;

  HTTP_DBG (1, "stream [%u]%x req %x", stream->c_thread_index, stream->hc_hc_index, req_index);

  req = http_ctx_get_w_thread (req_index, thread_index);
  req->req_flags |= HTTP_REQ_F_APP_CLOSED;
  req->app_closed_cb (req, stream, is_shutdown);
}

static void
http3_app_reset_callback (http_ctx_t *stream, u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  http_ctx_t *hc;

  HTTP_DBG (1, "stream [%u]%x req %x", stream->c_thread_index, stream->hc_hc_index, req_index);
  http_stats_stream_reset_by_app_inc (thread_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  req->req_flags |= HTTP_REQ_F_APP_CLOSED;
  http3_stream_terminate (stream, req,
			  (req->req_flags & HTTP_REQ_F_IS_TUNNEL) ? HTTP3_ERROR_CONNECT_ERROR :
								    HTTP3_ERROR_REQUEST_CANCELLED);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      HTTP_DBG (1, "app closed parent, closing connection");
      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      http3_set_application_error_code (hc, HTTP3_ERROR_INTERNAL_ERROR);
      http_disconnect_transport (hc);
      http_stats_connections_reset_by_app_inc (thread_index);
    }
}

static int
http3_transport_connected_callback (http_ctx_t *hc)
{
  http_ctx_t *req;
  u32 stream_index, hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;
  http_ctx_t *stream;
  int rv;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  hc->hc_http_conn_index = hc->hc_hc_index;
  hc->our_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_decoder_stream_index = SESSION_INVALID_INDEX;
  hc->peer_encoder_stream_index = SESSION_INVALID_INDEX;
  hc->hc_parent_req_index = SESSION_INVALID_INDEX;
  hc->peer_settings = http3_default_conn_settings;
  hc->flags |= HTTP_CONN_F_EXPECT_PEER_SETTINGS;
  if (PREDICT_FALSE (http3_conn_init (hc_index, thread_index, hc)))
    {
      HTTP_DBG (1, "failed to initialize connection");
      hc = http_ctx_get_w_thread (hc_index, thread_index);
      /* not much to do here, just notify app */
      app_worker_t *app_wrk = app_worker_get_if_valid (hc->hc_pa_wrk_index);
      if (!app_wrk)
	{
	  HTTP_DBG (1, "no app worker");
	  return -1;
	}
      app_worker_connect_notify (app_wrk, 0, SESSION_E_UNKNOWN, hc->hc_pa_app_api_ctx);
      return -1;
    }

  /* open quic stream */
  rv = http_connect_transport_stream (hc_index, thread_index, 0, &stream);
  if (rv)
    {
      HTTP_DBG (1, "failed to open request stream");
      hc = http_ctx_get_w_thread (hc_index, thread_index);
      /* not much to do here, just notify app */
      app_worker_t *app_wrk = app_worker_get_if_valid (hc->hc_pa_wrk_index);
      if (!app_wrk)
	{
	  HTTP_DBG (1, "no app worker");
	  return -1;
	}
      app_worker_connect_notify (app_wrk, 0, SESSION_E_UNKNOWN, hc->hc_pa_app_api_ctx);
      return -1;
    }
  stream_index = stream->hc_hc_index;

  req = http3_stream_alloc_req (stream_index, thread_index, 1);
  /* pool grow, regrab connection and stream */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  stream = http_ctx_get_w_thread (stream_index, thread_index);
  stream->http_req_index = ((http_req_handle_t) req->hr_req_handle).req_index;
  req->hr_hc_index = stream_index;
  req->stream_type = HTTP3_STREAM_TYPE_REQUEST;
  req->transport_rx_cb = http3_stream_transport_rx_req_client;
  req->app_closed_cb = http3_stream_app_close_parent;
  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
  http_stats_connections_established_inc (thread_index);
  http_stats_app_streams_opened_inc (thread_index);
  return http_conn_established (hc, req, hc->hc_pa_app_api_ctx);
}

static void
http3_transport_rx_callback (http_ctx_t *stream)
{
  http_ctx_t *req;
  u32 n_deq;
  u32 stream_index = stream->hc_hc_index;
  clib_thread_index_t thread_index = stream->c_thread_index;

  ASSERT (http_ctx_is_stream (stream));

  HTTP_DBG (1, "stream [%u]%x req %x", stream->c_thread_index, stream->hc_hc_index,
	    stream->http_req_index);
  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
  n_deq = req->transport_rx_cb (req, stream);
  /* pool might grow, regrab stream */
  stream = http_ctx_get_w_thread (stream_index, thread_index);
  http_io_ts_program_rx_evt (stream, n_deq);

  /* reset http connection expiration timer */
  http3_stream_update_conn_timer (stream);
}

static void
http3_transport_close_callback (http_ctx_t *hc)
{
  http_ctx_t *parent_req;

  HTTP_DBG (1, "hc [%u]%x, error code: %U", hc->c_thread_index, hc->hc_hc_index, format_http3_error,
	    http3_get_application_error_code (hc));
  if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      parent_req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      session_transport_closing_notify (&parent_req->connection);
    }
  hc->our_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_decoder_stream_index = SESSION_INVALID_INDEX;
  hc->peer_encoder_stream_index = SESSION_INVALID_INDEX;
  if (hc->state != HTTP_CONN_STATE_CLOSED)
    http_disconnect_transport (hc);
}

static void
http3_transport_reset_callback (http_ctx_t *hc)
{
  http_ctx_t *parent_req;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      parent_req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      session_transport_reset_notify (&parent_req->connection);
    }
  hc->our_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_decoder_stream_index = SESSION_INVALID_INDEX;
  hc->peer_encoder_stream_index = SESSION_INVALID_INDEX;
}

static void
http3_transport_conn_reschedule_callback (http_ctx_t *stream)
{
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x", stream->c_thread_index, stream->hc_hc_index);
  ASSERT (http_ctx_is_stream (stream));
  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
  transport_connection_reschedule (&req->connection);
}

static int
http3_transport_stream_accept_callback (http_ctx_t *stream, http_ctx_t *hc)
{
  http_ctx_t *req;
  u32 stream_index = stream->hc_hc_index;
  clib_thread_index_t thread_index = stream->c_thread_index;

  req = http3_stream_alloc_req (stream_index, thread_index, 0);
  /* pool grow, regrab stream */
  stream = http_ctx_get_w_thread (stream_index, thread_index);
  stream->http_req_index = ((http_req_handle_t) req->hr_req_handle).req_index;

  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      if (!(stream->flags & HTTP_CONN_F_IS_SERVER))
	{
	  HTTP_DBG (1, "server initiated bidirectional stream");
	  http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 0;
	}
      req->stream_type = HTTP3_STREAM_TYPE_REQUEST;
      req->transport_rx_cb = http3_stream_transport_rx_req_server;
      req->app_closed_cb = http3_stream_app_close;
      HTTP_DBG (1, "new req stream accepted [%u]%x", req->c_thread_index,
		((http_req_handle_t) req->hr_req_handle).req_index);
      if (http_conn_accept_request (stream, req, 1))
	{
	  HTTP_DBG (1, "http_conn_accept_request failed");
	  http3_stream_terminate (stream, req, HTTP3_ERROR_REQUEST_REJECTED);
	  return 0;
	}
      stream->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
      http_stats_app_streams_opened_inc (stream->c_thread_index);
    }
  else
    {
      req->transport_rx_cb = http3_stream_transport_rx_unknown_type;
      HTTP_DBG (1, "new unidirectional stream accepted [%u]%x", req->c_thread_index,
		((http_req_handle_t) req->hr_req_handle).req_index);
      http_stats_ctrl_streams_opened_inc (stream->c_thread_index);
    }
  return 0;
}

static void
http3_transport_stream_close_callback (http_ctx_t *stream)
{
  http_ctx_t *req;
  http_ctx_t *hc;

  HTTP_DBG (1, "stream [%u]%x req %x state %U", stream->c_thread_index, stream->hc_hc_index,
	    stream->http_req_index, format_http_conn_state, stream);
  if (stream->state != HTTP_CONN_STATE_CLOSED)
    {
      if (stream->flags & HTTP_CONN_F_UNIDIRECTIONAL_STREAM)
	{
	  /* we don't allocate req for unidirectional streams initiated by us
	   */
	  if (stream->http_req_index == SESSION_INVALID_INDEX)
	    {
	      HTTP_DBG (1, "our control stream closed");
	      hc = http_ctx_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
	      hc->our_ctrl_stream_index = SESSION_INVALID_INDEX;
	      http_close_transport_stream (stream);
	      http_stats_ctrl_streams_closed_inc (stream->c_thread_index);
	      return;
	    }
	  HTTP_DBG (1, "peer control stream closed");
	  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
	  http3_stream_close (stream, req);
	}
      else
	{
	  /* client old stream, already doing request on new */
	  if (stream->http_req_index == SESSION_INVALID_INDEX)
	    {
	      HTTP_DBG (1, "no request closing");
	      http_close_transport_stream (stream);
	      return;
	    }
	  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
	  /* for tunnel peer can initiate or confirm tunnel close */
	  if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
	    {
	      if (req->req_flags & HTTP_REQ_F_APP_CLOSED)
		{
		  HTTP_DBG (1, "peer closed tunnel");
		  session_transport_closed_notify (&req->connection);
		  http_stats_app_streams_closed_inc (stream->c_thread_index);
		  http_close_transport_stream (stream);
		}
	      else
		{
		  HTTP_DBG (1, "peer want to close tunnel");
		  session_transport_closing_notify (&req->connection);
		}
	      return;
	    }
	  /* for server stream is closed for receiving */
	  if (stream->flags & HTTP_CONN_F_IS_SERVER)
	    {
	      if (req->req_state < HTTP_REQ_STATE_WAIT_APP_REPLY && !http_io_ts_max_read (stream))
		{
		  HTTP_DBG (1, "request incomplete");
		  http3_stream_terminate (stream, req, HTTP3_ERROR_REQUEST_INCOMPLETE);
		  return;
		}
	      HTTP_DBG (1, "server stream half-closed");
	      stream->state = HTTP_CONN_STATE_HALF_CLOSED;
	      return;
	    }
	  /* for client we can confirm close if app already close (read all data) */
	  if (req->req_flags & HTTP_REQ_F_APP_CLOSED)
	    {
	      HTTP_DBG (1, "app already closed confirm");
	      http_close_transport_stream (stream);
	    }
	}
    }
}

static void
http3_transport_stream_reset_callback (http_ctx_t *stream)
{
  http_ctx_t *req;

  HTTP_DBG (1, "stream [%u]%x req %x, error code: %U", stream->c_thread_index, stream->hc_hc_index,
	    stream->http_req_index, format_http3_error, http3_get_application_error_code (stream));
  req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
  if (stream->flags & HTTP_CONN_F_UNIDIRECTIONAL_STREAM)
    {
      /* this should not happen since we don't support server push */
      HTTP_DBG (1, "%U closed", format_http3_stream_type, req->stream_type);
      http3_stream_error_terminate_conn (stream, req, HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
    }
  else
    {
      http_stats_stream_reset_by_peer_inc (stream->c_thread_index);
      if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
	session_transport_reset_notify (&req->connection);
    }
}

static void
http3_conn_accept_callback (http_ctx_t *hc)
{
  http_ctx_t *parent_req;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  hc->hc_http_conn_index = hc->hc_hc_index;
  hc->our_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
  hc->peer_decoder_stream_index = SESSION_INVALID_INDEX;
  hc->peer_encoder_stream_index = SESSION_INVALID_INDEX;
  hc->hc_parent_req_index = SESSION_INVALID_INDEX;
  hc->peer_settings = http3_default_conn_settings;
  hc->flags |= HTTP_CONN_F_EXPECT_PEER_SETTINGS;
  if (PREDICT_FALSE (http3_conn_init (hc_index, thread_index, hc)))
    return;
  parent_req = http3_stream_alloc_req (hc_index, thread_index, 1);
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  if (http_conn_accept_request (hc, parent_req, 0))
    {
      http3_stream_free_req_w_index (hc->hc_parent_req_index, hc->c_thread_index, hc);
      http_disconnect_transport (hc);
      return;
    }
  parent_req->app_closed_cb = http3_stream_app_close_parent;
  hc->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
  http_stats_connections_accepted_inc (hc->c_thread_index);
}

static int
http3_conn_connect_stream_callback (http_ctx_t *parent_stream, u32 *req_handle)
{
  http_ctx_t *req;
  u32 pa_wrk_index = parent_stream->hc_pa_wrk_index;
  u32 hc_index = parent_stream->hc_http_conn_index;
  u32 stream_index;
  clib_thread_index_t thread_index = parent_stream->c_thread_index;
  http_ctx_t *stream;
  int rv;

  HTTP_DBG (1, "hc [%u]%x", thread_index, hc_index);

  /* open quic stream */
  rv = http_connect_transport_stream (hc_index, thread_index, 0, &stream);
  if (rv)
    {
      HTTP_DBG (1, "failed to open request stream");
      return SESSION_E_UNKNOWN;
    }
  stream_index = stream->hc_hc_index;
  req = http3_stream_alloc_req (stream_index, thread_index, 0);
  /* pool grow, regrab stream */
  stream = http_ctx_get_w_thread (stream_index, thread_index);
  stream->http_req_index = ((http_req_handle_t) req->hr_req_handle).req_index;
  req->hr_hc_index = stream_index;
  req->stream_type = HTTP3_STREAM_TYPE_REQUEST;
  req->transport_rx_cb = http3_stream_transport_rx_req_client;
  req->app_closed_cb = http3_stream_app_close;
  req->hr_pa_wrk_index = pa_wrk_index;
  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
  http_stats_app_streams_opened_inc (thread_index);
  *req_handle = req->hr_req_handle;
  return SESSION_E_NONE;
}

static void
http3_conn_cleanup_callback (http_ctx_t *hc)
{
  http_ctx_t *parent_req;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      parent_req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      session_transport_delete_notify (&parent_req->connection);
      http3_stream_free_req_w_index (hc->hc_parent_req_index, hc->c_thread_index, hc);
      hc->hc_parent_req_index = SESSION_INVALID_INDEX;
    }
}

static void
http3_stream_cleanup_callback (http_ctx_t *stream)
{
  http_ctx_t *req;

  HTTP_DBG (1, "stream [%u]%x req %x", stream->c_thread_index, stream->hc_hc_index,
	    stream->http_req_index);
  /* we don't allocate req for unidirectional streams initiated by us
   * or client is already doing another request on new stream */
  if (stream->http_req_index == SESSION_INVALID_INDEX)
    return;
  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      req = http_ctx_get_w_thread (stream->http_req_index, stream->c_thread_index);
      /* parent request will be deleted with connection */
      if (req->req_flags & HTTP_REQ_F_IS_PARENT)
	{
	  req->hr_hc_index = stream->hc_http_conn_index;
	  return;
	}
      if (!(stream->flags & HTTP_CONN_F_NO_APP_SESSION))
	session_transport_delete_notify (&req->connection);
    }
  http3_stream_free_req (stream);
}

const static http_engine_vft_t http3_engine = {
  .name = "http3",
  .unformat_cfg_callback = http3_unformat_config_callback,
  .req_get_connection = http3_req_get_connection,
  .format_req = http3_format_req,
  .app_tx_callback = http3_app_tx_callback,
  .app_rx_evt_callback = http3_app_rx_evt_callback,
  .app_close_callback = http3_app_close_callback,
  .app_reset_callback = http3_app_reset_callback,
  .transport_connected_callback = http3_transport_connected_callback,
  .transport_rx_callback = http3_transport_rx_callback,
  .transport_close_callback = http3_transport_close_callback,
  .transport_reset_callback = http3_transport_reset_callback,
  .transport_conn_reschedule_callback = http3_transport_conn_reschedule_callback,
  .transport_stream_accept_callback = http3_transport_stream_accept_callback,
  .transport_stream_close_callback = http3_transport_stream_close_callback,
  .transport_stream_reset_callback = http3_transport_stream_reset_callback,
  .conn_accept_callback = http3_conn_accept_callback,
  .conn_connect_stream_callback = http3_conn_connect_stream_callback,
  .conn_cleanup_callback = http3_conn_cleanup_callback,
  .stream_cleanup_callback = http3_stream_cleanup_callback,
};

clib_error_t *
http3_init (vlib_main_t *vm)
{
  http_main_t *hm = &http_main;

  hm->h3_settings = http3_default_conn_settings;
  hm->h3_settings.max_field_section_size = 1 << 14; /* by default unlimited */
  hm->h3_settings.enable_connect_protocol = 1;	    /* enable extended connect */
  http_register_engine (&http3_engine, HTTP_VERSION_3);

  return 0;
}

VLIB_INIT_FUNCTION (http3_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
