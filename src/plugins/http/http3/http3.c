/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/http3.h>
#include <http/http3/frame.h>
#include <http/http3/qpack.h>
#include <http/http_timer.h>
#include <http/http_status_codes.h>

#define HTTP3_SERVER_MAX_STREAM_ID (HTTP_VARINT_MAX - 3)

#define foreach_http3_stream_flags                                            \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (IS_PARENT, "is-parent")

typedef enum http3_req_flags_bit_
{
#define _(sym, str) HTTP3_STREAM_F_BIT_##sym,
  foreach_http3_stream_flags
#undef _
    HTTP3_STREAM_N_F_BITS
} http3_req_flags_bit_t;

typedef enum http3_req_flags_
{
#define _(sym, str) HTTP3_STREAM_F_##sym = 1 << HTTP3_STREAM_F_BIT_##sym,
  foreach_http3_stream_flags
#undef _
} http3_req_flags_t;

typedef struct http3_stream_ctx_
{
  http_req_t base;
  u32 h3c_index;
  http3_stream_type_t stream_type;
  http3_frame_header_t fh;
  http3_req_flags_t flags;
  u32 (*transport_rx_cb) (struct http3_stream_ctx_ *sctx, http_conn_t *stream);
} http3_stream_ctx_t;

#define foreach_http3_conn_flags                                              \
  _ (EXPECT_PEER_SETTINGS, "expect-peer-settings")

typedef enum http3_conn_flags_bit_
{
#define _(sym, str) HTTP3_CONN_F_BIT_##sym,
  foreach_http3_conn_flags
#undef _
} http3_conn_flags_bit_t;

typedef enum http3_conn_flags_
{
#define _(sym, str) HTTP3_CONN_F_##sym = 1 << HTTP3_CONN_F_BIT_##sym,
  foreach_http3_conn_flags
#undef _
} http3_conn_flags_t;

typedef struct
{
  u32 hc_index;
  u32 our_ctrl_stream_hc_index;
  u32 peer_ctrl_stream_sctx_index;
  u32 peer_decoder_stream_sctx_index;
  u32 peer_encoder_stream_sctx_index;
  u32 parent_sctx_index;
  http3_conn_flags_t flags;
  http3_conn_settings_t peer_settings;
  qpack_decoder_ctx_t qpack_decoder_ctx;
} http3_conn_ctx_t;

typedef struct
{
  http3_conn_ctx_t *conn_pool;
  http3_stream_ctx_t *stream_pool;
  u8 *header_list; /* buffer for headers decompression */
} http3_worker_ctx_t;

typedef struct
{
  http3_worker_ctx_t *workers;
  http3_conn_settings_t settings;
} http3_main_t;

static http3_main_t http3_main;

static_always_inline void
http3_set_application_error_code (http_conn_t *hc, http3_error_t err)
{
  ASSERT (err >= 0); /* negative values are for internal use only */
  session_t *ts = session_get_from_handle (hc->hc_tc_session_handle);
  transport_endpt_attr_t attr = { .type = TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE,
				  .app_proto_err_code = (u64) err };
  session_transport_attribute (ts, 0 /* is_set */, &attr);
}

static_always_inline http3_worker_ctx_t *
http3_worker_get (clib_thread_index_t thread_index)
{
  return &http3_main.workers[thread_index];
}

static_always_inline http3_conn_ctx_t *
http3_conn_ctx_alloc (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_worker_ctx_t *wrk = http3_worker_get (hc->c_thread_index);

  pool_get (wrk->conn_pool, h3c);
  h3c->hc_index = hc->hc_hc_index;
  h3c->our_ctrl_stream_hc_index = SESSION_INVALID_INDEX;
  h3c->peer_ctrl_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_decoder_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_encoder_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->parent_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_settings = http3_default_conn_settings;
  hc->opaque = uword_to_pointer (h3c - wrk->conn_pool, void *);
  HTTP_DBG (1, "h3c [%u]%x", hc->c_thread_index, h3c - wrk->conn_pool);

  return h3c;
}

static_always_inline http3_conn_ctx_t *
http3_conn_ctx_get (u32 conn_index, clib_thread_index_t thread_index)
{
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);
  return pool_elt_at_index (wrk->conn_pool, conn_index);
}

static_always_inline http3_conn_ctx_t *
http3_conn_ctx_get_if_valid (u32 conn_index, clib_thread_index_t thread_index)
{
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);
  if (pool_is_free_index (wrk->conn_pool, conn_index))
    return 0;
  return pool_elt_at_index (wrk->conn_pool, conn_index);
}

static_always_inline void
http3_conn_ctx_free (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_worker_ctx_t *wrk = http3_worker_get (hc->c_thread_index);

  HTTP_DBG (1, "h3c [%u]%x", hc->c_thread_index,
	    pointer_to_uword (hc->opaque));
  h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
  ASSERT (h3c->parent_sctx_index == SESSION_INVALID_INDEX);
  if (CLIB_DEBUG)
    memset (h3c, 0xba, sizeof (*h3c));
  pool_put (wrk->conn_pool, h3c);
}

static_always_inline http3_stream_ctx_t *
http3_stream_ctx_alloc (http_conn_t *stream, u8 is_parent)
{
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *sctx;
  u32 si;
  http_req_handle_t sh;
  http_conn_t *hc;

  pool_get_zero (wrk->stream_pool, sctx);
  si = sctx - wrk->stream_pool;
  sh.version = HTTP_VERSION_3;
  sh.req_index = si;
  sctx->base.hr_req_handle = sh.as_u32;
  sctx->base.hr_hc_index = stream->hc_hc_index;
  sctx->base.c_s_index = SESSION_INVALID_INDEX;
  sctx->base.c_thread_index = stream->c_thread_index;
  sctx->base.c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->stream_type = HTTP3_STREAM_TYPE_UNKNOWN;
  if (is_parent)
    {
      hc = stream;
      h3c =
	http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
      ASSERT (h3c->parent_sctx_index == SESSION_INVALID_INDEX);
      sctx->flags |= HTTP3_STREAM_F_IS_PARENT;
      h3c->parent_sctx_index = si;
    }
  else
    {
      hc = http_conn_get_w_thread (stream->hc_http_conn_index,
				   stream->c_thread_index);
    }
  sctx->h3c_index = pointer_to_uword (hc->opaque);
  HTTP_DBG (1, "stream [%u]%x sctx_index %x", stream->c_thread_index,
	    stream->hc_hc_index, si);

  return sctx;
}

static_always_inline http3_stream_ctx_t *
http3_stream_ctx_get (u32 stream_index, clib_thread_index_t thread_index)
{
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);
  return pool_elt_at_index (wrk->stream_pool, stream_index);
}

static_always_inline void
http3_stream_ctx_free (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;
  http3_conn_ctx_t *h3c;
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);

  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
			       stream->c_thread_index);
  HTTP_DBG (1, "sctx [%u]%x", stream->c_thread_index,
	    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);
  vec_free (sctx->base.headers);
  stream->opaque = uword_to_pointer (SESSION_INVALID_INDEX, void *);
  if (sctx->flags & HTTP3_STREAM_F_IS_PARENT)
    {
      h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);
      h3c->parent_sctx_index = SESSION_INVALID_INDEX;
    }
  if (CLIB_DEBUG)
    memset (sctx, 0xba, sizeof (*sctx));
  pool_put (wrk->stream_pool, sctx);
}

static_always_inline void
http3_stream_ctx_free_w_index (u32 stream_index,
			       clib_thread_index_t thread_index)
{
  http3_conn_ctx_t *h3c;
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);
  http3_stream_ctx_t *sctx =
    pool_elt_at_index (wrk->stream_pool, stream_index);

  HTTP_DBG (1, "sctx [%u]%x", thread_index,
	    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);
  if (sctx->flags & HTTP3_STREAM_F_IS_PARENT)
    {
      h3c = http3_conn_ctx_get (sctx->h3c_index, thread_index);
      h3c->parent_sctx_index = SESSION_INVALID_INDEX;
    }
  pool_put (wrk->stream_pool, sctx);
}

static_always_inline void
http3_stream_close (http_conn_t *stream, http3_stream_ctx_t *sctx)
{
  http3_conn_ctx_t *h3c;
  http_conn_t *hc;

  http_close_transport_stream (stream);
  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      http_stats_app_streams_closed_inc (stream->c_thread_index);
      if (sctx->flags & HTTP3_STREAM_F_APP_CLOSED)
	{
	  HTTP_DBG (1, "stream [%u]%x sctx %x app already closed, confirm",
		    stream->c_thread_index, stream->hc_hc_index,
		    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);
	  session_transport_closed_notify (&sctx->base.connection);
	}
      else
	{
	  HTTP_DBG (1, "stream [%u]%x sctx %x all done closing, notify app",
		    stream->c_thread_index, stream->hc_hc_index,
		    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);
	  session_transport_closing_notify (&sctx->base.connection);
	}
    }
  else
    {
      http_stats_ctrl_streams_closed_inc (stream->c_thread_index);
      hc = http_conn_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
      h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
      switch (sctx->stream_type)
	{
	case HTTP3_STREAM_TYPE_CONTROL:
	  h3c->peer_ctrl_stream_sctx_index = SESSION_INVALID_INDEX;
	  break;
	case HTTP3_STREAM_TYPE_DECODER:
	  h3c->peer_decoder_stream_sctx_index = SESSION_INVALID_INDEX;
	  break;
	case HTTP3_STREAM_TYPE_ENCODER:
	  h3c->peer_encoder_stream_sctx_index = SESSION_INVALID_INDEX;
	  break;
	default:
	  /* ignore */
	  break;
	}
    }
}

static_always_inline void
http3_stream_terminate (http_conn_t *stream, http3_stream_ctx_t *sctx, http3_error_t err)
{
  /* this should not happen since we don't support server push */
  ASSERT (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM);

  http3_set_application_error_code (stream, err);
  if (!(sctx->flags & HTTP3_STREAM_F_APP_CLOSED) || !(stream->flags & HTTP_CONN_F_NO_APP_SESSION))
    session_transport_reset_notify (&sctx->base.connection);
  http_reset_transport_stream (stream);
}

static_always_inline void
http3_conn_terminate (http_conn_t *hc, http3_conn_ctx_t *h3c, http3_error_t err)
{
  http3_stream_ctx_t *parent_sctx;

  http3_set_application_error_code (hc, err);
  if (h3c->parent_sctx_index != SESSION_INVALID_INDEX)
    {
      parent_sctx = http3_stream_ctx_get (h3c->parent_sctx_index, hc->c_thread_index);
      if (!(parent_sctx->flags & HTTP3_STREAM_F_APP_CLOSED) ||
	  !(parent_sctx->flags & HTTP_CONN_F_NO_APP_SESSION))
	session_transport_reset_notify (&parent_sctx->base.connection);
    }
  http_disconnect_transport (hc);
}

static_always_inline void
http3_stream_error_terminate_conn (http_conn_t *stream, http3_stream_ctx_t *sctx, http3_error_t err)
{
  http_conn_t *hc;
  http3_conn_ctx_t *h3c;

  h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);
  hc = http_conn_get_w_thread (h3c->hc_index, stream->c_thread_index);
  http3_conn_terminate (hc, h3c, err);
}

static_always_inline void
http3_stream_ctx_reset (http_conn_t *old_stream, http3_stream_ctx_t *sctx)
{
  ASSERT (old_stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM);
  ASSERT (!(old_stream->flags & HTTP_CONN_F_IS_SERVER));

  /* confirm close if quic was waiting for us to read all data */
  if (old_stream->state == HTTP_CONN_STATE_TRANSPORT_CLOSED)
    http_close_transport_stream (old_stream);

  old_stream->opaque = uword_to_pointer (SESSION_INVALID_INDEX, void *);
  sctx->base.hr_hc_index = old_stream->hc_http_conn_index;
}

static_always_inline int
http3_conn_init (u32 parent_index, clib_thread_index_t thread_index, http3_conn_ctx_t *h3c)
{
  http3_main_t *h3m = &http3_main;
  http_conn_t *ctrl_stream, *hc;
  u8 *buf, *p;

  /*open control stream */
  if (http_connect_transport_stream (parent_index, thread_index, 1,
				     &ctrl_stream))
    {
      HTTP_DBG (1, "failed to open control stream");
      hc = http_conn_get_w_thread (parent_index, thread_index);
      http3_conn_terminate (hc, h3c, HTTP3_ERROR_INTERNAL_ERROR);
      return -1;
    }
  ctrl_stream->opaque = uword_to_pointer (SESSION_INVALID_INDEX, void *);
  h3c->our_ctrl_stream_hc_index = ctrl_stream->hc_hc_index;
  http_stats_ctrl_streams_opened_inc (thread_index);

  buf = http_get_tx_buf (ctrl_stream);
  /* write stream type first */
  p = http_encode_varint (buf, HTTP3_STREAM_TYPE_CONTROL);
  vec_set_len (buf, (p - buf));
  /* write settings frame */
  http3_frame_settings_write (&h3m->settings, &buf);
  http_io_ts_write (ctrl_stream, buf, vec_len (buf), 0);
  http_io_ts_after_write (ctrl_stream, 1);
  return 0;
}

static_always_inline void
http3_send_goaway (http_conn_t *hc)
{
  http_conn_t *ctrl_stream;
  http3_conn_ctx_t *h3c;
  u8 *buf;
  /* for client set to 0 since we don't support push for server use max stream id */
  u64 stream_or_push_id = hc->flags & HTTP_CONN_F_IS_SERVER ? HTTP3_SERVER_MAX_STREAM_ID : 0;

  h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
  ASSERT (h3c->our_ctrl_stream_hc_index != SESSION_INVALID_INDEX);
  ctrl_stream = http_conn_get_w_thread (h3c->our_ctrl_stream_hc_index, hc->c_thread_index);
  buf = http_get_tx_buf (ctrl_stream);
  http3_frame_goaway_write (stream_or_push_id, &buf);
  http_io_ts_write (ctrl_stream, buf, vec_len (buf), 0);
  http_io_ts_after_write (ctrl_stream, 1);
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http3_req_state_wait_app_reply (http_conn_t *stream, http3_stream_ctx_t *sctx,
				transport_send_params_t *sp,
				http3_error_t *error, u32 *n_deq)
{
  http_msg_t msg;
  hpack_response_control_data_t control_data;
  u8 *response, *date, *app_headers = 0;
  u32 headers_len, n_written;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  http_sm_result_t rv = HTTP_SM_STOP;

  http_get_app_msg (&sctx->base, &msg);
  ASSERT (msg.type == HTTP_MSG_REPLY);

  response = http_get_tx_buf (stream);
  date = format (0, "%U", format_http_time_now, stream);

  control_data.content_len = msg.data.body_len;
  control_data.server_name = stream->app_name;
  control_data.server_name_len = vec_len (stream->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);

  if (sctx->base.is_tunnel)
    {
      switch (msg.code)
	{
	case HTTP_STATUS_OK:
	case HTTP_STATUS_CREATED:
	case HTTP_STATUS_ACCEPTED:
	  /* tunnel established if 2xx (Successful) response to CONNECT */
	  control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
	  break;
	default:
	  /* tunnel not established */
	  sctx->base.is_tunnel = 0;
	  break;
	}
    }
  control_data.sc = msg.code;

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (&sctx->base, &msg);

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
      ASSERT (sctx->base.is_tunnel == 0);
      http_req_tx_buffer_init (&sctx->base, &msg);
      http_req_state_change (&sctx->base, HTTP_REQ_STATE_APP_IO_MORE_DATA);
      rv = HTTP_SM_CONTINUE;
    }
  else
    {
      /* all done, close stream */
      http3_stream_close (stream, sctx);
    }

  http_io_ts_after_write (stream, 0);
  http_stats_responses_sent_inc (stream->c_thread_index);

  return rv;
}

static http_sm_result_t
http3_req_state_wait_app_method (http_conn_t *hc, http3_stream_ctx_t *sctx,
				 transport_send_params_t *sp,
				 http3_error_t *error, u32 *n_deq)
{
  http_msg_t msg;
  hpack_request_control_data_t control_data;
  u8 *request, *app_headers = 0;
  u32 headers_len, n_written;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY;
  http_conn_t *stream;

  /* open quic stream */
  if (http_connect_transport_stream (hc->hc_hc_index, hc->c_thread_index, 0,
				     &stream))
    {
      HTTP_DBG (1, "failed to open request stream");
      /* not much to do here, just notify app */
      if (!(sctx->flags & HTTP3_STREAM_F_APP_CLOSED) ||
	  !(stream->flags & HTTP_CONN_F_NO_APP_SESSION))
	session_transport_reset_notify (&sctx->base.connection);
      return HTTP_SM_STOP;
    }
  stream->opaque = uword_to_pointer (
    ((http_req_handle_t) sctx->base.hr_req_handle).req_index, void *);
  sctx->base.hr_hc_index = stream->hc_hc_index;

  http_get_app_msg (&sctx->base, &msg);
  ASSERT (msg.type == HTTP_MSG_REQUEST);

  request = http_get_tx_buf (stream);

  control_data.method = msg.method_type;
  control_data.parsed_bitmap = HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  if (msg.method_type == HTTP_REQ_CONNECT)
    {
      sctx->base.is_tunnel = 1;
      control_data.authority = http_get_app_target (&sctx->base, &msg);
      control_data.authority_len = msg.data.target_path_len;
    }
  else
    {
      control_data.authority = stream->host;
      control_data.authority_len = vec_len (stream->host);
      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
      control_data.scheme = HTTP_URL_SCHEME_HTTPS;
      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
      control_data.path = http_get_app_target (&sctx->base, &msg);
      control_data.path_len = msg.data.target_path_len;
    }
  control_data.user_agent = stream->app_name;
  control_data.user_agent_len = vec_len (stream->app_name);
  control_data.content_len =
    msg.data.body_len ? msg.data.body_len : HPACK_ENCODER_SKIP_CONTENT_LEN;

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (&sctx->base, &msg);

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
      ASSERT (sctx->base.is_tunnel == 0);
      http_req_tx_buffer_init (&sctx->base, &msg);
      new_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;
    }
  else if (!sctx->base.is_tunnel)
    {
      /* all done, close stream for sending */
      http_half_close_transport_stream (stream);
    }

  http_io_ts_after_write (stream, 0);
  http_req_state_change (&sctx->base, new_state);
  http_stats_requests_sent_inc (stream->c_thread_index);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_app_io_more_data (http_conn_t *stream,
				  http3_stream_ctx_t *sctx,
				  transport_send_params_t *sp,
				  http3_error_t *error, u32 *n_deq)
{
  http_buffer_t *hb = &sctx->base.tx_buf;
  u32 max_write, n_read, n_segs, n_written;
  svm_fifo_seg_t *app_segs, *segs = 0;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len, finished;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  max_write = http_io_ts_max_write (stream, 0);
  if (max_write <= HTTP3_FRAME_HEADER_MAX_LEN)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_req_deschedule (&sctx->base, sp);
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
	  http3_stream_close (stream, sctx);
	}
      else
	{
	  /* all done, close stream for sending */
	  http_half_close_transport_stream (stream);
	  http_req_state_change (&sctx->base,
				 HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	}
    }
  http_io_ts_after_write (stream, finished);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_tunnel_tx (http_conn_t *stream, http3_stream_ctx_t *sctx,
			   transport_send_params_t *sp, http3_error_t *error, u32 *n_deq)
{
  http_buffer_t *hb = &sctx->base.tx_buf;
  u32 max_write, n_read, n_segs, n_written;
  svm_fifo_seg_t *app_segs, *segs = 0;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  max_write = http_io_ts_max_write (stream, 0);
  if (max_write <= HTTP3_FRAME_HEADER_MAX_LEN)
    {
      HTTP_DBG (1, "ts tx fifo full");
      http_req_deschedule (&sctx->base, sp);
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
  http_io_ts_after_write (stream, 0);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_wait_transport_method (http_conn_t *stream,
				       http3_stream_ctx_t *sctx,
				       transport_send_params_t *sp,
				       http3_error_t *error, u32 *n_deq)
{
  http3_conn_ctx_t *h3c;
  hpack_request_control_data_t control_data;
  http_msg_t msg;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_REPLY;
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);
  u8 *rx_buf, *p;
  http_sm_result_t res = HTTP_SM_STOP;

  if (http_io_ts_max_read (stream) < sctx->fh.length)
    {
      HTTP_DBG (1, "headers frame incomplete");
      if (stream->state == HTTP_CONN_STATE_HALF_CLOSED)
	http3_stream_terminate (stream, sctx, HTTP3_ERROR_REQUEST_INCOMPLETE);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  http_stats_requests_received_inc (stream->c_thread_index);

  rx_buf = http_get_rx_buf (stream);
  vec_validate (rx_buf, sctx->fh.length - 1);
  http_io_ts_read (stream, rx_buf, sctx->fh.length, 0);
  *n_deq = sctx->fh.length;

  h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);
  *error = qpack_parse_request (rx_buf, sctx->fh.length, wrk->header_list,
				vec_len (wrk->header_list), &control_data,
				&sctx->base.headers, &h3c->qpack_decoder_ctx);
  if (*error != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "qpack_parse_request failed: %U", format_http3_error, *error);
      /* message error is only stream error, otherwise it's connection error */
      if (*error == HTTP3_ERROR_MESSAGE_ERROR)
	{
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      return HTTP_SM_ERROR;
    }

  sctx->base.control_data_len = control_data.control_data_len;
  sctx->base.headers_offset = control_data.headers - wrk->header_list;
  sctx->base.headers_len = control_data.headers_len;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_METHOD_PARSED))
    {
      HTTP_DBG (1, ":method pseudo-header missing in request");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported method");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":scheme pseudo-header missing in request");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.scheme == HTTP_URL_SCHEME_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported scheme");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_INTERNAL_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":path pseudo-header missing in request");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_AUTHORITY_PARSED))
    {
      HTTP_DBG (1, ":authority pseudo-header missing in request");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_CONNECT)
    {
      if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED ||
	  control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
	{
	  HTTP_DBG (1, ":scheme and :path pseudo-header must be omitted for "
		       "CONNECT method");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      /* quick check if port is present */
      p = control_data.authority + control_data.authority_len;
      p--;
      if (!isdigit (*p))
	{
	  HTTP_DBG (1, "port not present in authority");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      p--;
      for (; p > control_data.authority; p--)
	{
	  if (!isdigit (*p))
	    break;
	}
      if (*p != ':')
	{
	  HTTP_DBG (1, "port not present in authority");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      sctx->base.is_tunnel = 1;
    }
  if (control_data.content_len_header_index != ~0)
    {
      sctx->base.content_len_header_index =
	control_data.content_len_header_index;
      if (http_parse_content_length (&sctx->base, wrk->header_list))
	{
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      if (stream->state == HTTP_CONN_STATE_HALF_CLOSED && !http_io_ts_max_read (stream))
	{
	  HTTP_DBG (1, "request incomplete");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_REQUEST_INCOMPLETE);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      res = HTTP_SM_CONTINUE;
    }
  sctx->base.to_recv = sctx->base.body_len;

  sctx->base.target_query_offset = 0;
  sctx->base.target_query_len = 0;
  if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
    {
      sctx->base.target_path_len = control_data.path_len;
      sctx->base.target_path_offset = control_data.path - wrk->header_list;
      /* drop leading slash */
      sctx->base.target_path_offset++;
      sctx->base.target_path_len--;
      http_identify_optional_query (&sctx->base, wrk->header_list);
    }
  else
    {
      sctx->base.target_path_len = 0;
      sctx->base.target_path_offset = 0;
    }

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = control_data.method;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = sctx->base.control_data_len;
  msg.data.scheme = control_data.scheme;
  msg.data.target_authority_offset = control_data.authority - wrk->header_list;
  msg.data.target_authority_len = control_data.authority_len;
  msg.data.target_path_offset = sctx->base.target_path_offset;
  msg.data.target_path_len = sctx->base.target_path_len;
  msg.data.target_query_offset = sctx->base.target_query_offset;
  msg.data.target_query_len = sctx->base.target_query_len;
  msg.data.headers_offset = sctx->base.headers_offset;
  msg.data.headers_len = sctx->base.headers_len;
  msg.data.headers_ctx = pointer_to_uword (sctx->base.headers);
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_NA;
  msg.data.body_offset = sctx->base.control_data_len;
  msg.data.body_len = sctx->base.body_len;
  msg.data.upgrade_proto = sctx->base.upgrade_proto;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { wrk->header_list,
			       sctx->base.control_data_len } };
  HTTP_DBG (3, "%U", format_http_bytes, wrk->header_list,
	    sctx->base.control_data_len);
  http_io_as_write_segs (&sctx->base, segs, 2);
  http_req_state_change (&sctx->base, new_state);
  http_app_worker_rx_notify (&sctx->base);
  sctx->fh.length = 0;

  return res;
}

static http_sm_result_t
http3_req_state_wait_transport_reply (http_conn_t *stream,
				      http3_stream_ctx_t *sctx,
				      transport_send_params_t *sp,
				      http3_error_t *error, u32 *n_deq)
{
  http3_conn_ctx_t *h3c;
  hpack_response_control_data_t control_data;
  http_msg_t msg;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_METHOD;
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);
  u8 *rx_buf;
  http_sm_result_t res = HTTP_SM_STOP;

  if (http_io_ts_max_read (stream) < sctx->fh.length)
    {
      HTTP_DBG (1, "headers frame incomplete");
      *error = HTTP3_ERROR_INCOMPLETE;
      *n_deq = 0;
      return HTTP_SM_ERROR;
    }

  http_stats_responses_received_inc (stream->c_thread_index);

  rx_buf = http_get_rx_buf (stream);
  vec_validate (rx_buf, sctx->fh.length - 1);
  http_io_ts_read (stream, rx_buf, sctx->fh.length, 0);
  *n_deq = sctx->fh.length;

  h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);

  vec_reset_length (sctx->base.headers);
  *error = qpack_parse_response (rx_buf, sctx->fh.length, wrk->header_list,
				 vec_len (wrk->header_list), &control_data,
				 &sctx->base.headers, &h3c->qpack_decoder_ctx);
  if (*error != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "qpack_parse_response failed");
      /* message error is only stream error, otherwise it's connection error */
      if (*error == HTTP3_ERROR_MESSAGE_ERROR)
	{
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      return HTTP_SM_ERROR;
    }

  sctx->base.control_data_len = control_data.control_data_len;
  sctx->base.headers_offset = control_data.headers - wrk->header_list;
  sctx->base.headers_len = control_data.headers_len;
  sctx->base.status_code = control_data.sc;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_STATUS_PARSED))
    {
      HTTP_DBG (1, ":status pseudo-header missing in request");
      http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
      return HTTP_SM_STOP;
    }

  if (sctx->base.is_tunnel && http_status_code_str[sctx->base.status_code][0] == '2')
    {
      new_state = HTTP_REQ_STATE_TUNNEL;
      /* cleanup some stuff we don't need anymore in tunnel mode */
      vec_free (sctx->base.headers);
    }
  else if (control_data.content_len_header_index != ~0)
    {
      sctx->base.content_len_header_index =
	control_data.content_len_header_index;
      if (http_parse_content_length (&sctx->base, wrk->header_list))
	{
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_MESSAGE_ERROR);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      res = HTTP_SM_CONTINUE;
    }
  else
    {
      /* we are done wait for the next app request */
      http3_stream_ctx_reset (stream, sctx);
    }
  sctx->base.to_recv = sctx->base.body_len;

  msg.type = HTTP_MSG_REPLY;
  msg.code = sctx->base.status_code;
  msg.data.headers_offset = sctx->base.headers_offset;
  msg.data.headers_len = sctx->base.headers_len;
  msg.data.headers_ctx = pointer_to_uword (sctx->base.headers);
  msg.data.body_offset = sctx->base.control_data_len;
  msg.data.body_len = sctx->base.body_len;
  msg.data.type = HTTP_MSG_DATA_INLINE;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { wrk->header_list,
			       sctx->base.control_data_len } };
  HTTP_DBG (3, "%U", format_http_bytes, wrk->header_list,
	    sctx->base.control_data_len);
  http_io_as_write_segs (&sctx->base, segs, 2);
  http_req_state_change (&sctx->base, new_state);
  http_app_worker_rx_notify (&sctx->base);
  sctx->fh.length = 0;

  return res;
}

static http_sm_result_t
http3_req_state_transport_io_more_data (http_conn_t *stream,
					http3_stream_ctx_t *sctx,
					transport_send_params_t *sp,
					http3_error_t *error, u32 *n_deq)
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
  max_deq = clib_min (max_deq, sctx->fh.length);

  if (sctx->fh.length > sctx->base.to_recv)
    {
      HTTP_DBG (1, "received more data than expected, fh.len %lu to_recv %lu",
		sctx->fh.length, sctx->base.to_recv);
      *error = HTTP3_ERROR_GENERAL_PROTOCOL_ERROR;
      *n_deq = 0;
      return HTTP_SM_ERROR;
    }

  max_enq = http_io_as_max_write (&sctx->base);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_io_as_add_want_deq_ntf (&sctx->base);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }

  http_io_ts_read_segs (stream, segs, &n_segs, clib_min (max_deq, max_enq));
  n_written = http_io_as_write_segs (&sctx->base, segs, n_segs);
  ASSERT (sctx->fh.length >= n_written);
  sctx->base.to_recv -= n_written;
  sctx->fh.length -= n_written;
  http_io_ts_drain (stream, n_written);
  *n_deq = n_written;
  HTTP_DBG (2, "written %lu to recv %lu", n_written, sctx->base.to_recv);

  if (sctx->base.to_recv == 0)
    {
      if (stream->flags & HTTP_CONN_F_IS_SERVER)
	http_req_state_change (&sctx->base, HTTP_REQ_STATE_WAIT_APP_REPLY);
      else
	{
	  /* we are done wait for the next app request */
	  http_req_state_change (&sctx->base, HTTP_REQ_STATE_WAIT_APP_METHOD);
	  http3_stream_ctx_reset (stream, sctx);
	}
      res = HTTP_SM_STOP;
    }
  else
    {
      if (stream->flags & HTTP_CONN_F_IS_SERVER && stream->state == HTTP_CONN_STATE_HALF_CLOSED &&
	  !http_io_ts_max_read (stream))
	{
	  HTTP_DBG (1, "request incomplete");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_REQUEST_INCOMPLETE);
	  return HTTP_SM_STOP;
	}
    }
  http_app_worker_rx_notify (&sctx->base);

  if (max_deq > n_written)
    {
      http_io_as_add_want_deq_ntf (&sctx->base);
      res = HTTP_SM_STOP;
    }

  return res;
}

static http_sm_result_t
http3_req_state_tunnel_rx (http_conn_t *stream, http3_stream_ctx_t *sctx,
			   transport_send_params_t *sp, http3_error_t *error, u32 *n_deq)
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
  max_deq = clib_min (max_deq, sctx->fh.length);

  max_enq = http_io_as_max_write (&sctx->base);
  if (max_enq == 0)
    {
      HTTP_DBG (1, "app's rx fifo full");
      http_io_as_add_want_deq_ntf (&sctx->base);
      *n_deq = 0;
      return HTTP_SM_STOP;
    }
  http_io_ts_read_segs (stream, segs, &n_segs, clib_min (max_deq, max_enq));
  n_written = http_io_as_write_segs (&sctx->base, segs, n_segs);
  ASSERT (sctx->fh.length >= n_written);
  sctx->fh.length -= n_written;
  http_io_ts_drain (stream, n_written);
  *n_deq = n_written;
  http_app_worker_rx_notify (&sctx->base);
  HTTP_DBG (2, "written %lu", n_written);

  if (max_deq > n_written)
    {
      http_io_as_add_want_deq_ntf (&sctx->base);
      res = HTTP_SM_STOP;
    }

  return res;
}

/*************************/
/* request state machine */
/*************************/

typedef http_sm_result_t (*http3_sm_handler) (http_conn_t *hc,
					      http3_stream_ctx_t *sctx,
					      transport_send_params_t *sp,
					      http3_error_t *error,
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
  0, /* TODO: udp unnel tx */
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
  0, /* TODO: udp tunnel rx */
};

static_always_inline int
http3_req_state_is_tx_valid (http3_stream_ctx_t *sctx)
{
  return tx_state_funcs[sctx->base.state] ? 1 : 0;
}

static_always_inline http3_error_t
http3_req_run_tx_state_machine (http_conn_t *stream, http3_stream_ctx_t *sctx,
				transport_send_params_t *sp)
{
  http_sm_result_t res;
  http3_error_t error;

  do
    {
      res = tx_state_funcs[sctx->base.state](stream, sctx, sp, &error, 0);
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
http3_stream_read_frame_header (http3_stream_ctx_t *sctx, http_conn_t *stream,
				u32 *to_deq, http3_frame_header_t *fh)
{
  http3_error_t err;
  u8 *rx_buf;
  u32 to_read, hdr_size;

  rx_buf = http_get_rx_buf (stream);
  to_read = clib_min (*to_deq, HTTP3_FRAME_HEADER_MAX_LEN);
  http_io_ts_read (stream, rx_buf, to_read, 1);
  err = http3_frame_header_read (rx_buf, to_read, sctx->stream_type, fh);
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
	  http3_stream_error_terminate_conn (stream, sctx, err);
	  return 1;
	}
    }
  HTTP_DBG (1, "stream [%u]%x sctx %x, frame type: %x, payload len: %u",
	    stream->c_thread_index, stream->hc_hc_index,
	    ((http_req_handle_t) sctx->base.hr_req_handle).req_index, fh->type,
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
http3_stream_peek_frame_header (http3_stream_ctx_t *sctx, http_conn_t *stream)
{
  u8 *rx_buf;
  u32 n_read;

  rx_buf = http_get_rx_buf (stream);
  n_read = http_io_ts_read (stream, rx_buf, HTTP3_FRAME_HEADER_MAX_LEN, 1);
  return http3_frame_header_read (rx_buf, n_read, sctx->stream_type,
				  &sctx->fh);
}

static_always_inline void
http3_stream_drop_frame_header (http3_stream_ctx_t *sctx, http_conn_t *stream)
{
  http_io_ts_drain (stream, sctx->fh.header_len);
}

static_always_inline int
http3_stream_read_settings (http3_stream_ctx_t *sctx, http_conn_t *stream,
			    u32 *to_deq, http3_frame_header_t *fh)
{
  http3_error_t err;
  http3_conn_ctx_t *h3c;
  u8 *rx_buf;

  h3c = http3_conn_ctx_get (sctx->h3c_index, sctx->base.c_thread_index);
  if (!(h3c->flags & HTTP3_CONN_F_EXPECT_PEER_SETTINGS))
    {
      HTTP_DBG (1, "second settings frame received");
      http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_FRAME_UNEXPECTED);
      return -1;
    }
  h3c->flags &= ~HTTP3_CONN_F_EXPECT_PEER_SETTINGS;
  if (fh->length == 0)
    return 0;
  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, fh->length, 0);
  *to_deq -= fh->length;
  err = http3_frame_settings_read (rx_buf, fh->length, &h3c->peer_settings);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "settings error");
      http3_stream_error_terminate_conn (stream, sctx, err);
      return -1;
    }
  return 0;
}

static u32
http3_stream_transport_rx_drain (CLIB_UNUSED (http3_stream_ctx_t *sctx),
				 http_conn_t *stream)
{
  u32 n_deq = http_io_ts_max_read (stream);
  http_io_ts_drain_all (stream);
  return n_deq;
}

static u32
http3_stream_transport_rx_ctrl (http3_stream_ctx_t *sctx, http_conn_t *stream)
{
  u32 to_deq, max_deq;
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *parent_sctx;

  max_deq = to_deq = http_io_ts_max_read (stream);
  while (to_deq)
    {
      http3_frame_header_t fh = {};
      if (PREDICT_FALSE (
	    http3_stream_read_frame_header (sctx, stream, &to_deq, &fh)))
	goto done;
      h3c = http3_conn_ctx_get (sctx->h3c_index, sctx->base.c_thread_index);
      if (h3c->flags & HTTP3_CONN_F_EXPECT_PEER_SETTINGS && fh.type != HTTP3_FRAME_TYPE_SETTINGS)
	{
	  HTTP_DBG (1, "expected settings frame");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_MISSING_SETTINGS);
	  goto done;
	}
      switch (fh.type)
	{
	case HTTP3_FRAME_TYPE_SETTINGS:
	  HTTP_DBG (1, "settings received");
	  if (PREDICT_FALSE (
		http3_stream_read_settings (sctx, stream, &to_deq, &fh)))
	    goto done;
	  break;
	case HTTP3_FRAME_TYPE_GOAWAY:
	  HTTP_DBG (1, "goaway received");
	  /* graceful shutdown (no new streams for client) */
	  if (!(stream->flags & HTTP_CONN_F_IS_SERVER) &&
	      h3c->parent_sctx_index != SESSION_INVALID_INDEX)
	    {
	      parent_sctx = http3_stream_ctx_get (h3c->parent_sctx_index, stream->c_thread_index);
	      session_transport_closing_notify (&parent_sctx->base.connection);
	    }
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
http3_stream_transport_rx_unknown_type (http3_stream_ctx_t *sctx,
					http_conn_t *stream)
{
  u32 max_deq, to_deq;
  u8 *rx_buf, *p;
  u64 stream_type;
  http3_conn_ctx_t *h3c;

  max_deq = http_io_ts_max_read (stream);
  ASSERT (max_deq > 0);
  to_deq = clib_min (max_deq, HTTP_VARINT_MAX_LEN);
  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, to_deq, 1);
  p = rx_buf;
  stream_type = http_decode_varint (&p, p + to_deq);
  if (stream_type == HTTP_INVALID_VARINT)
    {
      http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
      return 0;
    }
  http_io_ts_drain (stream, p - rx_buf);
  sctx->stream_type = stream_type;
  HTTP_DBG (1, "stream type %lx [%u]%x sctx %x", stream_type,
	    stream->hc_hc_index, sctx->base.c_thread_index,
	    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);

  h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);

  switch (stream_type)
    {
    case HTTP3_STREAM_TYPE_CONTROL:
      if (h3c->peer_ctrl_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second control stream opened");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 1;
	}
      h3c->peer_ctrl_stream_sctx_index =
	((http_req_handle_t) sctx->base.hr_req_handle).req_index;
      sctx->transport_rx_cb = http3_stream_transport_rx_ctrl;
      break;
    case HTTP3_STREAM_TYPE_DECODER:
      if (h3c->peer_decoder_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second decoder stream opened");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 1;
	}
      h3c->peer_decoder_stream_sctx_index =
	((http_req_handle_t) sctx->base.hr_req_handle).req_index;
      sctx->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    case HTTP3_STREAM_TYPE_ENCODER:
      if (h3c->peer_encoder_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  HTTP_DBG (1, "second encoder stream opened");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 1;
	}
      h3c->peer_encoder_stream_sctx_index =
	((http_req_handle_t) sctx->base.hr_req_handle).req_index;
      sctx->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    case HTTP3_STREAM_TYPE_PUSH:
      if (stream->flags & HTTP_CONN_F_IS_SERVER)
	{
	  HTTP_DBG (1, "client initiated push stream");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 1;
	}
      /* push not supported (we do not send MAX_PUSH_ID frame)*/
      HTTP_DBG (1, "server initiated push stream, not supported");
      http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_ID_ERROR);
      return 1;
    default:
      sctx->transport_rx_cb = http3_stream_transport_rx_drain;
      break;
    }

  return sctx->transport_rx_cb (sctx, stream);
}

static u32
http3_stream_transport_rx_req (http3_stream_ctx_t *sctx, http_conn_t *stream,
			       http_req_state_t headers_state)
{
  http3_error_t err;
  http_sm_result_t res = HTTP_SM_CONTINUE;
  u32 max_deq, left_deq, n_deq;

  max_deq = http_io_ts_max_read (stream);
  left_deq = max_deq;

  do
    {
      if (sctx->fh.length == 0)
	{
	  err = http3_stream_peek_frame_header (sctx, stream);
	  if (err != HTTP3_ERROR_NO_ERROR)
	    {
	      sctx->fh.length = 0;
	      goto error;
	    }
	  http3_stream_drop_frame_header (sctx, stream);
	  left_deq -= sctx->fh.header_len;
	}

      switch (sctx->fh.type)
	{
	case HTTP3_FRAME_TYPE_HEADERS:
	  HTTP_DBG (1, "headers received");
	  if (sctx->base.state != headers_state)
	    {
	      err = HTTP3_ERROR_FRAME_UNEXPECTED;
	      goto error;
	    }
	  break;
	case HTTP3_FRAME_TYPE_DATA:
	  HTTP_DBG (1, "data received");
	  if (!(sctx->base.state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA ||
		sctx->base.state == HTTP_REQ_STATE_TUNNEL))
	    {
	      err = HTTP3_ERROR_FRAME_UNEXPECTED;
	      goto error;
	    }
	  break;
	default:
	  /* discard payload of unknown frame */
	  if (sctx->fh.length)
	    sctx->fh.length -= http_io_ts_drain (stream, sctx->fh.length);
	  continue;
	}

      res = rx_state_funcs[sctx->base.state](stream, sctx, 0, &err, &n_deq);
      left_deq -= n_deq;
    }
  while (res == HTTP_SM_CONTINUE && left_deq);

  if (res == HTTP_SM_ERROR)
    {
    error:
      if (err != HTTP3_ERROR_INCOMPLETE)
	http3_stream_error_terminate_conn (stream, sctx, err);
    }

  return max_deq - left_deq;
}

static u32
http3_stream_transport_rx_req_server (http3_stream_ctx_t *sctx,
				      http_conn_t *stream)
{
  return http3_stream_transport_rx_req (sctx, stream,
					HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
}

static u32
http3_stream_transport_rx_req_client (http3_stream_ctx_t *sctx,
				      http_conn_t *stream)
{
  return http3_stream_transport_rx_req (sctx, stream,
					HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
}

/*****************/
/* http core VFT */
/*****************/

static void
http3_enable_callback (void)
{
  http3_main_t *h3m = &http3_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, i;
  http3_worker_ctx_t *wrk;

  num_threads = 1 /* main thread */ + vtm->n_threads;

  vec_validate (h3m->workers, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    {
      wrk = &h3m->workers[i];
      vec_validate (wrk->header_list,
		    h3m->settings.max_field_section_size - 1);
    }
}

static int
http3_update_settings (http3_settings_t type, u64 value)
{
  http3_main_t *h3m = &http3_main;

  switch (type)
    {
#define _(v, label, member, min, max, default_value, server, client)          \
  case HTTP3_SETTINGS_##label:                                                \
    if (!(value >= (min) && value <= (max)))                                  \
      return -1;                                                              \
    h3m->settings.member = value;                                             \
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

static u32
http3_hc_index_get_by_req_index (u32 req_index,
				 clib_thread_index_t thread_index)
{
  http3_stream_ctx_t *req;

  req = http3_stream_ctx_get (req_index, thread_index);
  return req->base.hr_hc_index;
}

static transport_connection_t *
http3_req_get_connection (u32 req_index, clib_thread_index_t thread_index)
{
  http3_stream_ctx_t *req;
  req = http3_stream_ctx_get (req_index, thread_index);
  return &(req->base.connection);
}

static u8 *
format_http3_req (u8 *s, va_list *args)
{
  http3_stream_ctx_t *req = va_arg (*args, http3_stream_ctx_t *);
  http_conn_t *stream = va_arg (*args, http_conn_t *);
  session_t *ts;

  ts = session_get_from_handle (stream->hc_tc_session_handle);
  s = format (s, "[%d:%d][H3] app_wrk %u hc_index %u ts %u:%u",
	      req->base.c_thread_index, req->base.c_s_index,
	      req->base.hr_pa_wrk_index, req->base.hr_hc_index,
	      ts->thread_index, ts->session_index);

  return s;
}

const char *http3_stream_flags_str[] = {
#define _(sym, str) str,
  foreach_http3_stream_flags
#undef _
};

static u8 *
format_http3_stream_flags (u8 *s, va_list *args)
{
  http3_stream_ctx_t *sctx = va_arg (*args, http3_stream_ctx_t *);
  int i, last = -1;

  for (i = 0; i < HTTP3_STREAM_N_F_BITS; i++)
    {
      if (sctx->flags & (1 << i))
	last = i;
    }

  for (i = 0; i < last; i++)
    {
      if (sctx->flags & (1 << i))
	s = format (s, "%s | ", http3_stream_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", http3_stream_flags_str[i]);

  return s;
}

const char *http3_conn_flags_str[] = {
#define _(sym, str) str,
  foreach_http3_conn_flags
#undef _
};

static u8 *
format_http3_conn_flags (u8 *s, va_list *args)
{
  http3_conn_ctx_t *h3c = va_arg (*args, http3_conn_ctx_t *);
  int i, last = -1;

  for (i = 0; i < HTTP3_STREAM_N_F_BITS; i++)
    {
      if (h3c->flags & (1 << i))
	last = i;
    }

  for (i = 0; i < last; i++)
    {
      if (h3c->flags & (1 << i))
	s = format (s, "%s | ", http3_conn_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", http3_conn_flags_str[i]);

  return s;
}

static u8 *
format_http3_req_vars (u8 *s, va_list *args)
{
  http3_stream_ctx_t *sctx = va_arg (*args, http3_stream_ctx_t *);
  http_conn_t *stream = va_arg (*args, http_conn_t *);
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *c_sctx;
  http_conn_t *c_stream;
  session_t *ts;

  if (!(stream->flags & HTTP_CONN_F_IS_SERVER &&
	sctx->flags & HTTP3_STREAM_F_IS_PARENT))
    s = format (s, " %U is_tunnel %u\n", format_http3_stream_type,
		sctx->stream_type, sctx->base.is_tunnel);
  s = format (s, " flags: %U\n", format_http3_stream_flags, sctx);
  if (sctx->flags & HTTP3_STREAM_F_IS_PARENT)
    {
      h3c =
	http3_conn_ctx_get_if_valid (sctx->h3c_index, stream->c_thread_index);
      if (!h3c)
	return s;
      s = format (s, " hc_flags: %U\n", format_http_conn_flags, stream);
      s = format (s, " h3c_flags: %U\n", format_http3_conn_flags, h3c);
      if (h3c->our_ctrl_stream_hc_index != SESSION_INVALID_INDEX)
	{
	  c_stream = http_conn_get_w_thread (h3c->our_ctrl_stream_hc_index,
					     stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " our_ctrl_stream: hc_index %u ts %u:%u\n",
		      h3c->our_ctrl_stream_hc_index, ts->thread_index,
		      ts->session_index);
	}
      else
	{
	  s = format (s, " our_ctrl_stream not opened\n");
	}
      if (h3c->peer_ctrl_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  c_sctx = http3_stream_ctx_get (h3c->peer_ctrl_stream_sctx_index,
					 stream->c_thread_index);
	  c_stream = http_conn_get_w_thread (c_sctx->base.hr_hc_index,
					     stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_ctrl_stream hc_index %u ts %u:%u\n",
		      c_sctx->base.hr_hc_index, ts->thread_index,
		      ts->session_index);
	}
      else
	{
	  s = format (s, " peer_ctrl_stream not opened\n");
	}
      if (h3c->peer_encoder_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  c_sctx = http3_stream_ctx_get (h3c->peer_encoder_stream_sctx_index,
					 stream->c_thread_index);
	  c_stream = http_conn_get_w_thread (c_sctx->base.hr_hc_index,
					     stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_encoder_stream hc_index %u ts %u:%u\n",
		      c_sctx->base.hr_hc_index, ts->thread_index,
		      ts->session_index);
	}
      else
	{
	  s = format (s, " peer_encoder_stream not opened\n");
	}
      if (h3c->peer_decoder_stream_sctx_index != SESSION_INVALID_INDEX)
	{
	  c_sctx = http3_stream_ctx_get (h3c->peer_decoder_stream_sctx_index,
					 stream->c_thread_index);
	  c_stream = http_conn_get_w_thread (c_sctx->base.hr_hc_index,
					     stream->c_thread_index);
	  ts = session_get_from_handle (c_stream->hc_tc_session_handle);
	  s = format (s, " peer_decoder_stream hc_index %u ts %u:%u\n",
		      c_sctx->base.hr_hc_index, ts->thread_index,
		      ts->session_index);
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
  http_conn_t *stream = va_arg (*args, http_conn_t *);
  u32 verbose = va_arg (*args, u32);
  http3_stream_ctx_t *sctx;

  sctx = http3_stream_ctx_get (req_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http3_req, sctx, stream);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state,
		  stream);
      if (verbose > 1)
	s = format (s, "\n%U", format_http3_req_vars, sctx, stream);
    }

  return s;
}

static void
http3_app_tx_callback (http_conn_t *stream, u32 req_index,
		       transport_send_params_t *sp)
{
  http3_stream_ctx_t *sctx;
  http3_error_t err;

  sctx = http3_stream_ctx_get (req_index, stream->c_thread_index);
  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, req_index);
  if (!http3_req_state_is_tx_valid (sctx))
    {
      if (sctx->base.state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  (stream->flags & HTTP_CONN_F_IS_SERVER))
	{
	  /* server app might send error earlier */
	  http_req_state_change (&sctx->base, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			stream->c_thread_index, stream->hc_hc_index, format_http_req_state,
			sctx->base.state, format_http_conn_state, stream);
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_INTERNAL_ERROR);
	  return;
	}
    }
  err = http3_req_run_tx_state_machine (stream, sctx, sp);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      ASSERT (err != HTTP3_ERROR_INCOMPLETE);
      http3_stream_error_terminate_conn (stream, sctx, err);
      return;
    }

  /* reset http connection expiration timer */
  http_conn_timer_update (stream);
}

static void
http3_app_rx_evt_callback (http_conn_t *stream, u32 req_index,
			   clib_thread_index_t thread_index)
{
  http3_stream_ctx_t *sctx;
  u32 n_deq;

  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, req_index);

  ASSERT (http_conn_is_stream (stream));

  sctx = http3_stream_ctx_get (req_index, thread_index);
  n_deq = sctx->transport_rx_cb (sctx, stream);
  http_io_ts_program_rx_evt (stream, n_deq);

  /* reset http connection expiration timer */
  http_conn_timer_update (stream);
}

static void
http3_app_close_callback (http_conn_t *stream, u32 req_index,
			  clib_thread_index_t thread_index, u8 is_shutdown)
{
  http3_stream_ctx_t *sctx;
  http_conn_t *hc;

  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, req_index);

  sctx = http3_stream_ctx_get (req_index, thread_index);
  sctx->flags |= HTTP3_STREAM_F_APP_CLOSED;
  hc = http_conn_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
  /* send goaway if shutdown */
  if (is_shutdown)
    http3_send_goaway (hc);
  /* Nothing more to send, confirm close */
  if (!http_io_as_max_read (&sctx->base))
    {
      HTTP_DBG (1, "nothing more to send, confirm close");
      session_transport_closed_notify (&sctx->base.connection);
      http_stats_app_streams_closed_inc (thread_index);
      if (sctx->flags & HTTP3_STREAM_F_IS_PARENT)
	{
	  HTTP_DBG (1, "app closed parent, closing connection");
	  http3_set_application_error_code (hc, HTTP3_ERROR_NO_ERROR);
	  http_disconnect_transport (hc);
	}
      if (sctx->base.state == HTTP_REQ_STATE_WAIT_APP_METHOD)
	{
	  /* client session without request - no quic stream, delete it
	   * now */
	  session_transport_delete_notify (&sctx->base.connection);
	  http3_stream_ctx_free_w_index (req_index, thread_index);
	}
    }
  else
    {
      /* Wait for all data to be written to ts */
      stream->state = HTTP_CONN_STATE_APP_CLOSED;
    }
}

static void
http3_app_reset_callback (http_conn_t *stream, u32 req_index,
			  clib_thread_index_t thread_index)
{
  http3_stream_ctx_t *sctx;
  http_conn_t *hc;

  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, req_index);
  http_stats_stream_reset_by_app_inc (thread_index);
  sctx = http3_stream_ctx_get (req_index, thread_index);
  if (sctx->base.state == HTTP_REQ_STATE_WAIT_APP_METHOD)
    {
      /* client session without request - no quic stream, delete it
       * now */
      session_transport_delete_notify (&sctx->base.connection);
      http3_stream_ctx_free_w_index (req_index, thread_index);
    }
  else
    {
      sctx->flags |= HTTP3_STREAM_F_APP_CLOSED;
      http3_stream_terminate (stream, sctx,
			      sctx->base.is_tunnel ? HTTP3_ERROR_CONNECT_ERROR :
						     HTTP3_ERROR_REQUEST_CANCELLED);
    }
  if (sctx->flags & HTTP3_STREAM_F_IS_PARENT)
    {
      HTTP_DBG (1, "app closed parent, closing connection");
      hc = http_conn_get_w_thread (stream->hc_http_conn_index,
				   stream->c_thread_index);
      http3_set_application_error_code (hc, HTTP3_ERROR_INTERNAL_ERROR);
      http_disconnect_transport (hc);
      http_stats_connections_reset_by_app_inc (thread_index);
    }
}

static int
http3_transport_connected_callback (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *sctx;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h3c = http3_conn_ctx_alloc (hc);
  h3c->flags |= HTTP3_CONN_F_EXPECT_PEER_SETTINGS;
  if (PREDICT_FALSE (http3_conn_init (hc_index, thread_index, h3c)))
    return -1;

  sctx = http3_stream_ctx_alloc (hc, 1);
  sctx->stream_type = HTTP3_STREAM_TYPE_REQUEST;
  sctx->transport_rx_cb = http3_stream_transport_rx_req_client;
  http_req_state_change (&sctx->base, HTTP_REQ_STATE_WAIT_APP_METHOD);
  http_stats_connections_established_inc (thread_index);
  http_stats_app_streams_opened_inc (thread_index);

  hc = http_conn_get_w_thread (hc_index, thread_index);
  return http_conn_established (hc, &sctx->base, hc->hc_pa_app_api_ctx);
}

static void
http3_transport_rx_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;
  u32 n_deq;

  ASSERT (http_conn_is_stream (stream));

  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, pointer_to_uword (stream->opaque));
  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
			       stream->c_thread_index);
  n_deq = sctx->transport_rx_cb (sctx, stream);
  http_io_ts_program_rx_evt (stream, n_deq);

  /* reset http connection expiration timer */
  http_conn_timer_update (stream);
}

static void
http3_transport_close_callback (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *parent_sctx;

  HTTP_DBG (1, "hc [%u]%x, error code: %U", hc->c_thread_index, hc->hc_hc_index, format_http3_error,
	    http3_get_application_error_code (hc));
  h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
  if (h3c->parent_sctx_index != SESSION_INVALID_INDEX)
    {
      parent_sctx =
	http3_stream_ctx_get (h3c->parent_sctx_index, hc->c_thread_index);
      session_transport_closing_notify (&parent_sctx->base.connection);
    }
  h3c->our_ctrl_stream_hc_index = SESSION_INVALID_INDEX;
  h3c->peer_ctrl_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_decoder_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_encoder_stream_sctx_index = SESSION_INVALID_INDEX;
  if (hc->state != HTTP_CONN_STATE_CLOSED)
    http_disconnect_transport (hc);
}

static void
http3_transport_reset_callback (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *parent_sctx;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
  if (h3c->parent_sctx_index != SESSION_INVALID_INDEX)
    {
      parent_sctx =
	http3_stream_ctx_get (h3c->parent_sctx_index, hc->c_thread_index);
      session_transport_reset_notify (&parent_sctx->base.connection);
    }
  h3c->our_ctrl_stream_hc_index = SESSION_INVALID_INDEX;
  h3c->peer_ctrl_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_decoder_stream_sctx_index = SESSION_INVALID_INDEX;
  h3c->peer_encoder_stream_sctx_index = SESSION_INVALID_INDEX;
}

static void
http3_transport_conn_reschedule_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  HTTP_DBG (1, "hc [%u]%x", stream->c_thread_index, stream->hc_hc_index);
  ASSERT (http_conn_is_stream (stream));
  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
			       stream->c_thread_index);
  transport_connection_reschedule (&sctx->base.connection);
}

static int
http3_transport_stream_accept_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  sctx = http3_stream_ctx_alloc (stream, 0);
  stream->opaque = uword_to_pointer (
    ((http_req_handle_t) sctx->base.hr_req_handle).req_index, void *);

  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      if (!(stream->flags & HTTP_CONN_F_IS_SERVER))
	{
	  HTTP_DBG (1, "server initiated bidirectional stream");
	  http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_STREAM_CREATION_ERROR);
	  return 0;
	}
      sctx->stream_type = HTTP3_STREAM_TYPE_REQUEST;
      sctx->transport_rx_cb = http3_stream_transport_rx_req_server;
      HTTP_DBG (1, "new req stream accepted [%u]%x", sctx->base.c_thread_index,
		((http_req_handle_t) sctx->base.hr_req_handle).req_index);
      if (http_conn_accept_request (stream, &sctx->base))
	{
	  HTTP_DBG (1, "http_conn_accept_request failed");
	  http3_stream_terminate (stream, sctx, HTTP3_ERROR_REQUEST_REJECTED);
	  return 0;
	}
      stream->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
      http_req_state_change (&sctx->base,
			     HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
      http_stats_app_streams_opened_inc (stream->c_thread_index);
    }
  else
    {
      sctx->transport_rx_cb = http3_stream_transport_rx_unknown_type;
      HTTP_DBG (1, "new unidirectional stream accepted [%u]%x",
		sctx->base.c_thread_index,
		((http_req_handle_t) sctx->base.hr_req_handle).req_index);
      http_stats_ctrl_streams_opened_inc (stream->c_thread_index);
    }
  return 0;
}

static void
http3_transport_stream_close_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;
  http3_conn_ctx_t *h3c;
  http_conn_t *hc;

  HTTP_DBG (1, "stream [%u]%x sctx %x state %U", stream->c_thread_index,
	    stream->hc_hc_index, pointer_to_uword (stream->opaque),
	    format_http_conn_state, stream);
  if (stream->state != HTTP_CONN_STATE_CLOSED)
    {
      if (stream->flags & HTTP_CONN_F_UNIDIRECTIONAL_STREAM)
	{
	  /* we don't allocate sctx for unidirectional streams initiated by us
	   */
	  if (pointer_to_uword (stream->opaque) == SESSION_INVALID_INDEX)
	    {
	      HTTP_DBG (1, "our control stream closed");
	      hc = http_conn_get_w_thread (stream->hc_http_conn_index, stream->c_thread_index);
	      h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
	      h3c->our_ctrl_stream_hc_index = SESSION_INVALID_INDEX;
	      http_close_transport_stream (stream);
	      http_stats_ctrl_streams_closed_inc (stream->c_thread_index);
	      return;
	    }
	  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
				       stream->c_thread_index);
	  http3_stream_close (stream, sctx);
	}
      else
	{
	  /* for server stream is closed for receiving
	   * for client we can confirm close if we already read all data */
	  if (stream->flags & HTTP_CONN_F_IS_SERVER)
	    {
	      sctx =
		http3_stream_ctx_get (pointer_to_uword (stream->opaque), stream->c_thread_index);
	      if (sctx->base.state < HTTP_REQ_STATE_WAIT_APP_REPLY && !http_io_ts_max_read (stream))
		{
		  HTTP_DBG (1, "request incomplete");
		  http3_stream_terminate (stream, sctx, HTTP3_ERROR_REQUEST_INCOMPLETE);
		  return;
		}
	      stream->state = HTTP_CONN_STATE_HALF_CLOSED;
	    }
	  else if (pointer_to_uword (stream->opaque) == SESSION_INVALID_INDEX)
	    http_close_transport_stream (stream);
	}
    }
}

static void
http3_transport_stream_reset_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  HTTP_DBG (1, "stream [%u]%x sctx %x, error code: %U", stream->c_thread_index,
	    stream->hc_hc_index, pointer_to_uword (stream->opaque),
	    format_http3_error, http3_get_application_error_code (stream));
  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque), stream->c_thread_index);
  if (stream->flags & HTTP_CONN_F_UNIDIRECTIONAL_STREAM)
    {
      /* this should not happen since we don't support server push */
      HTTP_DBG (1, "%U closed", format_http3_stream_type, sctx->stream_type);
      http3_stream_error_terminate_conn (stream, sctx, HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
    }
  else
    {
      http_stats_stream_reset_by_peer_inc (stream->c_thread_index);
      if (!(sctx->flags & HTTP3_STREAM_F_APP_CLOSED))
	session_transport_reset_notify (&sctx->base.connection);
    }
}

static void
http3_conn_accept_callback (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *parent_sctx;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h3c = http3_conn_ctx_alloc (hc);
  h3c->flags |= HTTP3_CONN_F_EXPECT_PEER_SETTINGS;
  if (PREDICT_FALSE (http3_conn_init (hc_index, thread_index, h3c)))
    return;
  hc = http_conn_get_w_thread (hc_index, thread_index);
  parent_sctx = http3_stream_ctx_alloc (hc, 1);
  if (http_conn_accept_request (hc, &parent_sctx->base))
    {
      http3_stream_ctx_free_w_index (h3c->parent_sctx_index,
				     hc->c_thread_index);
      http_disconnect_transport (hc);
      return;
    }
  hc->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
  http_stats_connections_accepted_inc (hc->c_thread_index);
}

static int
http3_conn_connect_stream_callback (http_conn_t *hc, u32 *req_index)
{
  http3_stream_ctx_t *sctx;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  sctx = http3_stream_ctx_alloc (hc, 0);
  sctx->stream_type = HTTP3_STREAM_TYPE_REQUEST;
  sctx->transport_rx_cb = http3_stream_transport_rx_req_client;
  http_req_state_change (&sctx->base, HTTP_REQ_STATE_WAIT_APP_METHOD);
  http_stats_app_streams_opened_inc (thread_index);
  *req_index = sctx->base.hr_req_handle;
  return SESSION_E_NONE;
}

static void
http3_conn_cleanup_callback (http_conn_t *hc)
{
  http3_conn_ctx_t *h3c;
  http3_stream_ctx_t *parent_sctx;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h3c = http3_conn_ctx_get (pointer_to_uword (hc->opaque), hc->c_thread_index);
  if (h3c->parent_sctx_index != SESSION_INVALID_INDEX)
    {
      parent_sctx =
	http3_stream_ctx_get (h3c->parent_sctx_index, hc->c_thread_index);
      session_transport_delete_notify (&parent_sctx->base.connection);
      http3_stream_ctx_free_w_index (h3c->parent_sctx_index,
				     hc->c_thread_index);
      h3c->parent_sctx_index = SESSION_INVALID_INDEX;
    }

  http3_conn_ctx_free (hc);
}

static void
http3_stream_cleanup_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  HTTP_DBG (1, "stream [%u]%x sctx %x", stream->c_thread_index,
	    stream->hc_hc_index, pointer_to_uword (stream->opaque));
  /* we don't allocate sctx for unidirectional streams initiated by us
   * or client is already doing another request on new stream */
  if (pointer_to_uword (stream->opaque) == SESSION_INVALID_INDEX)
    return;
  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
				   stream->c_thread_index);
      ASSERT (sctx->base.to_recv == 0);
      if (!(stream->flags & HTTP_CONN_F_NO_APP_SESSION))
	{
	  clib_warning ("called");
	  session_transport_delete_notify (&sctx->base.connection);
	}
    }
  http3_stream_ctx_free (stream);
}

const static http_engine_vft_t http3_engine = {
  .name = "http3",
  .enable_callback = http3_enable_callback,
  .unformat_cfg_callback = http3_unformat_config_callback,
  .hc_index_get_by_req_index = http3_hc_index_get_by_req_index,
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
  .transport_conn_reschedule_callback =
    http3_transport_conn_reschedule_callback,
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
  http3_main_t *h3m = &http3_main;

  h3m->settings = http3_default_conn_settings;
  h3m->settings.max_field_section_size = 1 << 14; /* by default unlimited */
  http_register_engine (&http3_engine, HTTP_VERSION_3);

  return 0;
}

VLIB_INIT_FUNCTION (http3_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
