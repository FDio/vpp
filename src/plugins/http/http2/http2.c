/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/llist.h>
#include <http/http2/hpack.h>
#include <http/http2/frame.h>
#include <http/http_private.h>
#include <http/http_timer.h>

#ifndef HTTP_2_ENABLE
#define HTTP_2_ENABLE 0
#endif

#define HTTP2_WIN_SIZE_MAX 0x7FFFFFFF

#define foreach_http2_stream_state                                            \
  _ (IDLE, "IDLE")                                                            \
  _ (OPEN, "OPEN")                                                            \
  _ (HALF_CLOSED, "HALF-CLOSED")                                              \
  _ (CLOSED, "CLOSED")

typedef enum http2_stream_state_
{
#define _(s, str) HTTP2_STREAM_STATE_##s,
  foreach_http2_stream_state
#undef _
} http2_stream_state_t;

#define foreach_http2_req_flags                                               \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (NEED_WINDOW_UPDATE, "need-window-update")

typedef enum http2_req_flags_bit_
{
#define _(sym, str) HTTP2_REQ_F_BIT_##sym,
  foreach_http2_req_flags
#undef _
} http2_req_flags_bit_t;

typedef enum http2_req_flags_
{
#define _(sym, str) HTTP2_REQ_F_##sym = 1 << HTTP2_REQ_F_BIT_##sym,
  foreach_http2_req_flags
#undef _
} __clib_packed http2_req_flags_t;

typedef struct http2_req_
{
  http_req_t base;
  http2_stream_state_t stream_state;
  u8 flags;
  u32 stream_id;
  i32 peer_window; /* can become negative after settings change */
  u32 our_window;
  u8 *payload;
  u32 payload_len;
  clib_llist_anchor_t resume_list;
} http2_req_t;

#define foreach_http2_conn_flags                                              \
  _ (EXPECT_PREFACE, "expect-preface")                                        \
  _ (PREFACE_VERIFIED, "preface-verified")

typedef enum http2_conn_flags_bit_
{
#define _(sym, str) HTTP2_CONN_F_BIT_##sym,
  foreach_http2_conn_flags
#undef _
} http2_conn_flags_bit_t;

typedef enum http2_conn_flags_
{
#define _(sym, str) HTTP2_CONN_F_##sym = 1 << HTTP2_CONN_F_BIT_##sym,
  foreach_http2_conn_flags
#undef _
} __clib_packed http2_conn_flags_t;

typedef struct http2_conn_ctx_
{
  http2_conn_settings_t peer_settings;
  hpack_dynamic_table_t decoder_dynamic_table;
  u8 flags;
  u32 last_opened_stream_id;
  u32 last_processed_stream_id;
  u32 peer_window;
  u32 our_window;
  uword *req_by_stream_id;
  clib_llist_index_t streams_to_resume;
} http2_conn_ctx_t;

typedef struct http2_main_
{
  http2_conn_ctx_t **conn_pool;
  http2_req_t **req_pool;
  http2_conn_settings_t settings;
} http2_main_t;

static http2_main_t http2_main;

http2_conn_ctx_t *
http2_conn_ctx_alloc_w_thread (http_conn_t *hc)
{
  http2_main_t *h2m = &http2_main;
  http2_conn_ctx_t *h2c;

  pool_get_aligned_safe (h2m->conn_pool[hc->c_thread_index], h2c,
			 CLIB_CACHE_LINE_BYTES);
  clib_memset (h2c, 0, sizeof (*h2c));
  h2c->peer_settings = http2_default_conn_settings;
  h2c->peer_window = h2c->peer_settings.initial_window_size;
  h2c->our_window = h2m->settings.initial_window_size;
  h2c->req_by_stream_id = hash_create (0, sizeof (uword));
  h2c->streams_to_resume =
    clib_llist_make_head (h2m->req_pool[hc->c_thread_index], resume_list);
  hc->opaque =
    uword_to_pointer (h2c - h2m->conn_pool[hc->c_thread_index], void *);
  HTTP_DBG (1, "h2c [%u]%x", hc->c_thread_index,
	    h2c - h2m->conn_pool[hc->c_thread_index]);
  return h2c;
}

static inline http2_conn_ctx_t *
http2_conn_ctx_get_w_thread (http_conn_t *hc)
{
  http2_main_t *h2m = &http2_main;
  u32 h2c_index = pointer_to_uword (hc->opaque);
  return pool_elt_at_index (h2m->conn_pool[hc->c_thread_index], h2c_index);
}

static inline void
http2_conn_ctx_free (http_conn_t *hc)
{
  http2_main_t *h2m = &http2_main;
  http2_conn_ctx_t *h2c;

  h2c = http2_conn_ctx_get_w_thread (hc);
  HTTP_DBG (1, "h2c [%u]%x", hc->c_thread_index,
	    h2c - h2m->conn_pool[hc->c_thread_index]);
  hash_free (h2c->req_by_stream_id);
  if (hc->flags & HTTP_CONN_F_HAS_REQUEST)
    hpack_dynamic_table_free (&h2c->decoder_dynamic_table);
  if (CLIB_DEBUG)
    memset (h2c, 0xba, sizeof (*h2c));
  pool_put (h2m->conn_pool[hc->c_thread_index], h2c);
}

static inline http2_req_t *
http2_conn_alloc_req (http_conn_t *hc, u32 stream_id)
{
  http2_main_t *h2m = &http2_main;
  http2_conn_ctx_t *h2c;
  http2_req_t *req;
  u32 req_index;
  http_req_handle_t hr_handle;

  pool_get_aligned_safe (h2m->req_pool[hc->c_thread_index], req,
			 CLIB_CACHE_LINE_BYTES);
  clib_memset (req, 0, sizeof (*req));
  req->base.hr_pa_session_handle = SESSION_INVALID_HANDLE;
  req_index = req - h2m->req_pool[hc->c_thread_index];
  hr_handle.version = HTTP_VERSION_2;
  hr_handle.req_index = req_index;
  req->base.hr_req_handle = hr_handle.as_u32;
  req->base.hr_hc_index = hc->hc_hc_index;
  req->base.c_thread_index = hc->c_thread_index;
  req->stream_id = stream_id;
  req->stream_state = HTTP2_STREAM_STATE_IDLE;
  req->resume_list.next = CLIB_LLIST_INVALID_INDEX;
  req->resume_list.prev = CLIB_LLIST_INVALID_INDEX;
  h2c = http2_conn_ctx_get_w_thread (hc);
  HTTP_DBG (1, "h2c [%u]%x req_index %x stream_id %u", hc->c_thread_index,
	    h2c - h2m->conn_pool[hc->c_thread_index], req_index, stream_id);
  req->peer_window = h2c->peer_settings.initial_window_size;
  req->our_window = h2m->settings.initial_window_size;
  hash_set (h2c->req_by_stream_id, stream_id, req_index);
  return req;
}

static inline void
http2_conn_free_req (http2_conn_ctx_t *h2c, http2_req_t *req, u32 thread_index)
{
  http2_main_t *h2m = &http2_main;

  HTTP_DBG (1, "h2c [%u]%x req_index %x stream_id %u", thread_index,
	    h2c - h2m->conn_pool[thread_index],
	    ((http_req_handle_t) req->base.hr_req_handle).req_index,
	    req->stream_id);
  if (clib_llist_elt_is_linked (req, resume_list))
    clib_llist_remove (h2m->req_pool[thread_index], resume_list, req);
  vec_free (req->base.headers);
  vec_free (req->base.target);
  http_buffer_free (&req->base.tx_buf);
  hash_unset (h2c->req_by_stream_id, req->stream_id);
  if (CLIB_DEBUG)
    memset (req, 0xba, sizeof (*req));
  pool_put (h2m->req_pool[thread_index], req);
}

http2_req_t *
http2_conn_get_req (http_conn_t *hc, u32 stream_id)
{
  http2_main_t *h2m = &http2_main;
  http2_conn_ctx_t *h2c;
  uword *p;

  h2c = http2_conn_ctx_get_w_thread (hc);
  p = hash_get (h2c->req_by_stream_id, stream_id);
  if (p)
    {
      return pool_elt_at_index (h2m->req_pool[hc->c_thread_index], p[0]);
    }
  else
    {
      HTTP_DBG (1, "hc [%u]%x streamId %u not found", hc->c_thread_index,
		hc->hc_hc_index, stream_id);
      return 0;
    }
}

always_inline http2_req_t *
http2_req_get (u32 req_index, u32 thread_index)
{
  http2_main_t *h2m = &http2_main;

  return pool_elt_at_index (h2m->req_pool[thread_index], req_index);
}

always_inline int
http2_req_update_peer_window (http2_req_t *req, i64 delta)
{
  i64 new_value;

  new_value = (i64) req->peer_window + delta;
  if (new_value > HTTP2_WIN_SIZE_MAX)
    return -1;
  req->peer_window = (i32) new_value;
  HTTP_DBG (1, "new window size %d", req->peer_window);
  return 0;
}

always_inline void
http2_req_add_to_resume_list (http2_conn_ctx_t *h2c, http2_req_t *req)
{
  http2_main_t *h2m = &http2_main;
  http2_req_t *he;

  req->flags &= ~HTTP2_REQ_F_NEED_WINDOW_UPDATE;
  he = clib_llist_elt (h2m->req_pool[req->base.c_thread_index],
		       h2c->streams_to_resume);
  clib_llist_add_tail (h2m->req_pool[req->base.c_thread_index], resume_list,
		       req, he);
}

always_inline void
http2_resume_list_process (http_conn_t *hc)
{
  http2_main_t *h2m = &http2_main;
  http2_req_t *he, *req;
  http2_conn_ctx_t *h2c;

  h2c = http2_conn_ctx_get_w_thread (hc);
  he =
    clib_llist_elt (h2m->req_pool[hc->c_thread_index], h2c->streams_to_resume);

  /* check if something in list and reschedule first app session from list if
   * we have some space in connection window */
  if (h2c->peer_window > 0 &&
      !clib_llist_is_empty (h2m->req_pool[hc->c_thread_index], resume_list,
			    he))
    {
      req =
	clib_llist_next (h2m->req_pool[hc->c_thread_index], resume_list, he);
      clib_llist_remove (h2m->req_pool[hc->c_thread_index], resume_list, req);
      transport_connection_reschedule (&req->base.connection);
    }
}

/* send GOAWAY frame and close TCP connection */
always_inline void
http2_connection_error (http_conn_t *hc, http2_error_t error,
			transport_send_params_t *sp)
{
  u8 *response;
  u32 req_index, stream_id;
  http2_conn_ctx_t *h2c;
  http2_req_t *req;

  h2c = http2_conn_ctx_get_w_thread (hc);

  response = http_get_tx_buf (hc);
  http2_frame_write_goaway (error, h2c->last_processed_stream_id, &response);
  http_io_ts_write (hc, response, vec_len (response), sp);
  http_io_ts_after_write (hc, 1);

  hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		  req = http2_req_get (req_index, hc->c_thread_index);
		  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		    session_transport_reset_notify (&req->base.connection);
		}));
  http_shutdown_transport (hc);
}

always_inline void
http2_send_stream_error (http_conn_t *hc, u32 stream_id, http2_error_t error,
			 transport_send_params_t *sp)
{
  u8 *response;

  response = http_get_tx_buf (hc);
  http2_frame_write_rst_stream (error, stream_id, &response);
  http_io_ts_write (hc, response, vec_len (response), sp);
  http_io_ts_after_write (hc, 1);
}

/* send RST_STREAM frame and notify app */
always_inline void
http2_stream_error (http_conn_t *hc, http2_req_t *req, http2_error_t error,
		    transport_send_params_t *sp)
{
  ASSERT (req->stream_state > HTTP2_STREAM_STATE_IDLE);

  http2_send_stream_error (hc, req->stream_id, error, sp);
  req->stream_state = HTTP2_STREAM_STATE_CLOSED;
  if (req->flags & HTTP2_REQ_F_APP_CLOSED)
    session_transport_closed_notify (&req->base.connection);
  else
    session_transport_closing_notify (&req->base.connection);
}

always_inline void
http2_stream_close (http2_req_t *req)
{
  req->stream_state = HTTP2_STREAM_STATE_CLOSED;
  if (req->flags & HTTP2_REQ_F_APP_CLOSED)
    {
      HTTP_DBG (1, "req [%u]%x app already closed, confirm",
		req->base.c_thread_index,
		((http_req_handle_t) req->base.hr_req_handle).req_index);
      session_transport_closed_notify (&req->base.connection);
    }
  else
    {
      HTTP_DBG (1, "req [%u]%x all done closing, notify app",
		req->base.c_thread_index,
		((http_req_handle_t) req->base.hr_req_handle).req_index);
      session_transport_closing_notify (&req->base.connection);
    }
}

always_inline void
http2_send_server_preface (http_conn_t *hc)
{
  u8 *response;
  http2_main_t *h2m = &http2_main;
  http2_settings_entry_t *setting, *settings_list = 0;

#define _(v, label, member, min, max, default_value, err_code)                \
  if (h2m->settings.member != default_value)                                  \
    {                                                                         \
      vec_add2 (settings_list, setting, 1);                                   \
      setting->identifier = HTTP2_SETTINGS_##label;                           \
      setting->value = h2m->settings.member;                                  \
    }
  foreach_http2_settings
#undef _

    response = http_get_tx_buf (hc);
  http2_frame_write_settings (settings_list, &response);
  http_io_ts_write (hc, response, vec_len (response), 0);
  http_io_ts_after_write (hc, 1);
}

/*************************************/
/* request state machine handlers RX */
/*************************************/

static http_sm_result_t
http2_req_state_wait_transport_method (http_conn_t *hc, http2_req_t *req,
				       transport_send_params_t *sp,
				       http2_error_t *error)
{
  http2_conn_ctx_t *h2c;
  hpack_request_control_data_t control_data;
  u8 *buf = 0;
  http_msg_t msg;
  int rv;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_REPLY;

  h2c = http2_conn_ctx_get_w_thread (hc);

  /* TODO: configurable buf size with bigger default value */
  vec_validate_init_empty (buf, 1023, 0);
  *error = hpack_parse_request (req->payload, req->payload_len, buf, 1023,
				&control_data, &req->base.headers,
				&h2c->decoder_dynamic_table);
  if (*error != HTTP2_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "hpack_parse_request failed");
      return HTTP_SM_ERROR;
    }

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_METHOD_PARSED))
    {
      HTTP_DBG (1, ":method pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_UNKNOWN ||
      control_data.method == HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, "unsupported method");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":scheme pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (control_data.scheme == HTTP_URL_SCHEME_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported scheme");
      http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":path pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_AUTHORITY_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":path pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }

  req->base.control_data_len = control_data.control_data_len;
  req->base.headers_offset = control_data.headers - buf;
  req->base.headers_len = control_data.headers_len;
  if (control_data.content_len_header_index != ~0)
    {
      req->base.content_len_header_index =
	control_data.content_len_header_index;
      rv = http_parse_content_length (&req->base, buf);
      if (rv)
	{
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      http_io_as_add_want_read_ntf (&req->base);
    }
  /* TODO: message framing without content length using END_STREAM flag */
  if (req->base.body_len == 0 && req->stream_state == HTTP2_STREAM_STATE_OPEN)
    {
      HTTP_DBG (1, "no content-length and DATA frame expected");
      *error = HTTP2_ERROR_INTERNAL_ERROR;
      return HTTP_SM_ERROR;
    }
  req->base.to_recv = req->base.body_len;

  req->base.target_path_len = control_data.path_len;
  req->base.target_path_offset = control_data.path - buf;
  /* drop leading slash */
  req->base.target_path_offset++;
  req->base.target_path_len--;
  req->base.target_query_offset = 0;
  req->base.target_query_len = 0;
  http_identify_optional_query (&req->base, buf);

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = control_data.method;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = req->base.connection_header_index;
  msg.data.scheme = control_data.scheme;
  msg.data.target_authority_offset = control_data.authority - buf;
  msg.data.target_authority_len = control_data.authority_len;
  msg.data.target_path_offset = req->base.target_path_offset;
  msg.data.target_path_len = req->base.target_path_len;
  msg.data.target_query_offset = req->base.target_query_offset;
  msg.data.target_query_len = req->base.target_query_len;
  msg.data.headers_offset = req->base.headers_offset;
  msg.data.headers_len = req->base.headers_len;
  msg.data.headers_ctx = pointer_to_uword (req->base.headers);
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_NA;
  msg.data.body_offset = req->base.control_data_len;
  msg.data.body_len = req->base.body_len;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { buf, req->base.control_data_len } };
  HTTP_DBG (3, "%U", format_http_bytes, buf, req->base.control_data_len);
  http_io_as_write_segs (&req->base, segs, 2);
  http_req_state_change (&req->base, new_state);
  http_app_worker_rx_notify (&req->base);

  if (req->stream_id > h2c->last_processed_stream_id)
    h2c->last_processed_stream_id = req->stream_id;

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_transport_io_more_data (http_conn_t *hc, http2_req_t *req,
					transport_send_params_t *sp,
					http2_error_t *error)
{
  if (req->payload_len > req->base.to_recv)
    {
      HTTP_DBG (1, "received more data than expected");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  req->base.to_recv -= req->payload_len;
  if (req->stream_state == HTTP2_STREAM_STATE_HALF_CLOSED &&
      req->base.to_recv != 0)
    {
      HTTP_DBG (1, "peer closed stream but don't send all data");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (req->base.to_recv == 0)
    http_req_state_change (&req->base, HTTP_REQ_STATE_WAIT_APP_REPLY);
  http_io_as_write (&req->base, req->payload, req->payload_len);
  http_app_worker_rx_notify (&req->base);

  return HTTP_SM_STOP;
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http2_req_state_wait_app_reply (http_conn_t *hc, http2_req_t *req,
				transport_send_params_t *sp,
				http2_error_t *error)
{
  http_msg_t msg;
  u8 *response, *date, *app_headers = 0;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  hpack_response_control_data_t control_data;
  u8 flags = HTTP2_FRAME_FLAG_END_HEADERS;
  http_sm_result_t sm_result = HTTP_SM_ERROR;
  u32 n_written;
  http2_conn_ctx_t *h2c;

  http_get_app_msg (&req->base, &msg);
  ASSERT (msg.type == HTTP_MSG_REPLY);

  response = http_get_tx_buf (hc);
  date = format (0, "%U", format_http_time_now, hc);

  control_data.sc = msg.code;
  control_data.content_len = msg.data.body_len;
  control_data.server_name = hc->app_name;
  control_data.server_name_len = vec_len (hc->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (&req->base, &msg);

  hpack_serialize_response (app_headers, msg.data.headers_len, &control_data,
			    &response);
  vec_free (date);

  h2c = http2_conn_ctx_get_w_thread (hc);
  if (vec_len (response) > h2c->peer_settings.max_frame_size)
    {
      /* TODO: CONTINUATION (headers fragmentation) */
      clib_warning ("resp headers greater than SETTINGS_MAX_FRAME_SIZE");
      *error = HTTP2_ERROR_INTERNAL_ERROR;
      return HTTP_SM_ERROR;
    }

  if (msg.data.body_len)
    {
      /* start sending the actual data */
      http_req_tx_buffer_init (&req->base, &msg);
      http_req_state_change (&req->base, HTTP_REQ_STATE_APP_IO_MORE_DATA);
      sm_result = HTTP_SM_CONTINUE;
    }
  else
    {
      /* no response body, we are done */
      flags |= HTTP2_FRAME_FLAG_END_STREAM;
      sm_result = HTTP_SM_STOP;
      http2_stream_close (req);
    }

  http2_frame_write_headers_header (vec_len (response), req->stream_id, flags,
				    fh);
  svm_fifo_seg_t segs[2] = { { fh, HTTP2_FRAME_HEADER_SIZE },
			     { response, vec_len (response) } };
  n_written = http_io_ts_write_segs (hc, segs, 2, sp);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + vec_len (response)));
  http_io_ts_after_write (hc, 0);

  return sm_result;
}

static http_sm_result_t
http2_req_state_app_io_more_data (http_conn_t *hc, http2_req_t *req,
				  transport_send_params_t *sp,
				  http2_error_t *error)
{
  u32 max_write, max_read, n_segs, n_read, n_written = 0;
  svm_fifo_seg_t *app_segs, *segs = 0;
  http_buffer_t *hb = &req->base.tx_buf;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  u8 finished = 0, flags = 0;
  http2_conn_ctx_t *h2c;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  if (req->peer_window <= 0)
    {
      HTTP_DBG (1, "stream window is full");
      /* mark that we need window update on stream */
      req->flags |= HTTP2_REQ_F_NEED_WINDOW_UPDATE;
      http_req_deschedule (&req->base, sp);
      return HTTP_SM_STOP;
    }
  h2c = http2_conn_ctx_get_w_thread (hc);
  if (h2c->peer_window == 0)
    {
      HTTP_DBG (1, "connection window is full");
      /* add to waiting queue */
      http2_req_add_to_resume_list (h2c, req);
      http_req_deschedule (&req->base, sp);
      return HTTP_SM_STOP;
    }

  max_write = http_io_ts_max_write (hc, sp);
  if (max_write <= HTTP2_FRAME_HEADER_SIZE)
    {
      HTTP_DBG (1, "ts tx fifo full");
      goto check_fifo;
    }
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, (u32) req->peer_window);
  max_write = clib_min (max_write, h2c->peer_window);
  max_write = clib_min (max_write, h2c->peer_settings.max_frame_size);

  max_read = http_buffer_bytes_left (hb);

  n_read = http_buffer_get_segs (hb, max_write, &app_segs, &n_segs);
  if (n_read == 0)
    {
      HTTP_DBG (1, "no data to deq");
      goto check_fifo;
    }

  finished = (max_read - n_read) == 0;
  flags = finished ? HTTP2_FRAME_FLAG_END_STREAM : 0;
  http2_frame_write_data_header (n_read, req->stream_id, flags, fh);
  vec_validate (segs, 0);
  segs[0].len = HTTP2_FRAME_HEADER_SIZE;
  segs[0].data = fh;
  vec_append (segs, app_segs);

  n_written = http_io_ts_write_segs (hc, segs, n_segs + 1, sp);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + n_read));
  vec_free (segs);
  http_buffer_drain (hb, n_read);
  req->peer_window -= n_read;
  h2c->peer_window -= n_read;

  if (finished)
    {
      http_buffer_free (hb);
      if (hc->flags & HTTP_CONN_F_IS_SERVER)
	http2_stream_close (req);
      else
	req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
    }
  http_io_ts_after_write (hc, finished);

check_fifo:
  if (http_io_ts_check_write_thresh (hc))
    {
      http_io_ts_add_want_deq_ntf (hc);
      http_req_deschedule (&req->base, sp);
    }
  return HTTP_SM_STOP;
}

/*************************/
/* request state machine */
/*************************/

typedef http_sm_result_t (*http2_sm_handler) (http_conn_t *hc,
					      http2_req_t *req,
					      transport_send_params_t *sp,
					      http2_error_t *error);

static http2_sm_handler tx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  0, /* wait transport reply */
  0, /* transport io more data */
  0, /* wait transport method */
  http2_req_state_wait_app_reply,
  http2_req_state_app_io_more_data,
  0, /* tunnel */
  0, /* udp tunnel */
};

static http2_sm_handler rx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  0, /* wait transport reply */
  http2_req_state_transport_io_more_data,
  http2_req_state_wait_transport_method,
  0, /* wait app reply */
  0, /* app io more data */
  0, /* tunnel */
  0, /* udp tunnel */
};

static_always_inline int
http2_req_state_is_tx_valid (http2_req_t *req)
{
  return tx_state_funcs[req->base.state] ? 1 : 0;
}

static_always_inline http2_error_t
http2_req_run_state_machine (http_conn_t *hc, http2_req_t *req,
			     transport_send_params_t *sp, u8 is_tx)
{
  http_sm_result_t res;
  http2_error_t error;
  http2_conn_ctx_t *h2c;

  do
    {
      if (is_tx)
	res = tx_state_funcs[req->base.state](hc, req, sp, &error);
      else
	res = rx_state_funcs[req->base.state](hc, req, 0, &error);

      if (res == HTTP_SM_ERROR)
	{
	  HTTP_DBG (1, "protocol error %U", format_http2_error, error);
	  return error;
	}
    }
  while (res == HTTP_SM_CONTINUE);

  if (req->stream_state == HTTP2_STREAM_STATE_CLOSED)
    {
      h2c = http2_conn_ctx_get_w_thread (hc);
      session_transport_delete_notify (&req->base.connection);
      http2_conn_free_req (h2c, req, hc->c_thread_index);
    }

  return HTTP2_ERROR_NO_ERROR;
}

/******************/
/* frame handlers */
/******************/

static http2_error_t
http2_handle_headers_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  http2_main_t *h2m = &http2_main;
  http2_req_t *req;
  u8 *rx_buf;
  http2_error_t rv;
  http2_conn_ctx_t *h2c;

  if (!(fh->flags & HTTP2_FRAME_FLAG_END_HEADERS))
    {
      /* TODO: fragmented headers */
      return HTTP2_ERROR_INTERNAL_ERROR;
    }

  if (hc->flags & HTTP_CONN_F_IS_SERVER)
    {
      h2c = http2_conn_ctx_get_w_thread (hc);
      /* streams initiated by client must use odd-numbered stream id */
      if ((fh->stream_id & 1) == 0)
	{
	  HTTP_DBG (1, "invalid stream id %u", fh->stream_id);
	  return HTTP2_ERROR_PROTOCOL_ERROR;
	}
      /* stream id must be greater than all streams that client has opened */
      if (fh->stream_id <= h2c->last_opened_stream_id)
	{
	  HTTP_DBG (1, "closed stream id %u", fh->stream_id);
	  return HTTP2_ERROR_STREAM_CLOSED;
	}
      h2c->last_opened_stream_id = fh->stream_id;
      if (hash_elts (h2c->req_by_stream_id) ==
	  h2m->settings.max_concurrent_streams)
	{
	  HTTP_DBG (1, "SETTINGS_MAX_CONCURRENT_STREAMS exceeded");
	  http_io_ts_drain (hc, fh->length);
	  http2_send_stream_error (hc, fh->stream_id,
				   HTTP2_ERROR_REFUSED_STREAM, 0);
	  return HTTP2_ERROR_NO_ERROR;
	}
      req = http2_conn_alloc_req (hc, fh->stream_id);
      http_conn_accept_request (hc, &req->base);
      http_req_state_change (&req->base, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
      req->stream_state = HTTP2_STREAM_STATE_OPEN;
      hc->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
      if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
	{
	  hc->flags |= HTTP_CONN_F_HAS_REQUEST;
	  hpack_dynamic_table_init (
	    &h2c->decoder_dynamic_table,
	    http2_default_conn_settings.header_table_size);
	}
      if (fh->flags & HTTP2_FRAME_FLAG_END_STREAM)
	req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
    }
  else
    {
      /* TODO: client */
      return HTTP2_ERROR_INTERNAL_ERROR;
    }

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_headers (&req->payload, &req->payload_len, rx_buf,
				 fh->length, fh->flags);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  HTTP_DBG (1, "run state machine");
  return http2_req_run_state_machine (hc, req, 0, 0);
}

static http2_error_t
http2_handle_data_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  http2_req_t *req;
  u8 *rx_buf;
  http2_error_t rv;
  http2_conn_ctx_t *h2c;

  req = http2_conn_get_req (hc, fh->stream_id);
  if (!req)
    {
      if (fh->stream_id == 0)
	{
	  HTTP_DBG (1, "DATA frame with stream id 0");
	  return HTTP2_ERROR_PROTOCOL_ERROR;
	}
      h2c = http2_conn_ctx_get_w_thread (hc);
      if (fh->stream_id <= h2c->last_opened_stream_id)
	{
	  HTTP_DBG (1, "stream closed, ignoring frame");
	  http2_send_stream_error (hc, fh->stream_id,
				   HTTP2_ERROR_STREAM_CLOSED, 0);
	  return HTTP2_ERROR_NO_ERROR;
	}
      else
	return HTTP2_ERROR_PROTOCOL_ERROR;
    }

  /* bogus state */
  if (hc->flags & HTTP_CONN_F_IS_SERVER &&
      req->stream_state != HTTP2_STREAM_STATE_OPEN)
    {
      HTTP_DBG (1, "error: stream already half-closed");
      http2_stream_error (hc, req, HTTP2_ERROR_STREAM_CLOSED, 0);
      return HTTP2_ERROR_NO_ERROR;
    }

  if (fh->flags & HTTP2_FRAME_FLAG_END_STREAM)
    req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_data (&req->payload, &req->payload_len, rx_buf,
			      fh->length, fh->flags);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  HTTP_DBG (1, "run state machine");
  return http2_req_run_state_machine (hc, req, 0, 0);
}

static http2_error_t
http2_handle_window_update_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf;
  u32 win_increment;
  http2_error_t rv;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  h2c = http2_conn_ctx_get_w_thread (hc);

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_window_update (&win_increment, rx_buf, fh->length);
  if (rv != HTTP2_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "invalid WINDOW_UPDATE frame (stream id %u)",
		fh->stream_id);
      /* error on the connection flow-control window is connection error */
      if (fh->stream_id == 0)
	return rv;
      /* otherwise it is stream error */
      req = http2_conn_get_req (hc, fh->stream_id);
      if (!req)
	http2_send_stream_error (hc, fh->stream_id, rv, 0);
      else
	http2_stream_error (hc, req, rv, 0);
      return HTTP2_ERROR_NO_ERROR;
    }

  HTTP_DBG (1, "WINDOW_UPDATE %u (stream id %u)", win_increment,
	    fh->stream_id);
  if (fh->stream_id == 0)
    {
      if (win_increment > (HTTP2_WIN_SIZE_MAX - h2c->peer_window))
	return HTTP2_ERROR_FLOW_CONTROL_ERROR;
      h2c->peer_window += win_increment;
    }
  else
    {
      req = http2_conn_get_req (hc, fh->stream_id);
      if (!req)
	{
	  if (fh->stream_id > h2c->last_opened_stream_id)
	    {
	      HTTP_DBG (
		1,
		"received WINDOW_UPDATE frame on idle stream (stream id %u)",
		fh->stream_id);
	      return HTTP2_ERROR_PROTOCOL_ERROR;
	    }
	  /* ignore window update on closed stream */
	  return HTTP2_ERROR_NO_ERROR;
	}
      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
	{
	  if (http2_req_update_peer_window (req, win_increment))
	    {
	      http2_stream_error (hc, req, HTTP2_ERROR_FLOW_CONTROL_ERROR, 0);
	      return HTTP2_ERROR_NO_ERROR;
	    }
	  if (req->flags & HTTP2_REQ_F_NEED_WINDOW_UPDATE)
	    http2_req_add_to_resume_list (h2c, req);
	}
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_settings_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf, *resp = 0;
  http2_error_t rv;
  http2_conn_settings_t new_settings;
  http2_conn_ctx_t *h2c;
  http2_req_t *req;
  u32 stream_id, req_index;
  i32 win_size_delta;

  if (fh->stream_id != 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  if (fh->flags == HTTP2_FRAME_FLAG_ACK)
    {
      if (fh->length != 0)
	return HTTP2_ERROR_FRAME_SIZE_ERROR;
      /* TODO: we can start using non-default settings */
    }
  else
    {
      if (fh->length < sizeof (http2_settings_entry_t))
	return HTTP2_ERROR_FRAME_SIZE_ERROR;

      rx_buf = http_get_rx_buf (hc);
      vec_validate (rx_buf, fh->length - 1);
      http_io_ts_read (hc, rx_buf, fh->length, 0);

      h2c = http2_conn_ctx_get_w_thread (hc);
      new_settings = h2c->peer_settings;
      rv = http2_frame_read_settings (&new_settings, rx_buf, fh->length);
      if (rv != HTTP2_ERROR_NO_ERROR)
	return rv;

      /* ACK peer settings */
      http2_frame_write_settings_ack (&resp);
      http_io_ts_write (hc, resp, vec_len (resp), 0);
      vec_free (resp);
      http_io_ts_after_write (hc, 0);

      /* change of SETTINGS_INITIAL_WINDOW_SIZE, we must adjust the size of all
       * stream flow-control windows */
      if (h2c->peer_settings.initial_window_size !=
	  new_settings.initial_window_size)
	{
	  win_size_delta = (i32) new_settings.initial_window_size -
			   (i32) h2c->peer_settings.initial_window_size;
	  hash_foreach (
	    stream_id, req_index, h2c->req_by_stream_id, ({
	      req = http2_req_get (req_index, hc->c_thread_index);
	      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		{
		  if (http2_req_update_peer_window (req, win_size_delta))
		    http2_stream_error (hc, req,
					HTTP2_ERROR_FLOW_CONTROL_ERROR, 0);
		  if (req->flags & HTTP2_REQ_F_NEED_WINDOW_UPDATE)
		    http2_req_add_to_resume_list (h2c, req);
		}
	    }));
	}
      h2c->peer_settings = new_settings;
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_rst_stream_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf;
  http2_error_t rv;
  http2_req_t *req;
  u32 error_code;
  http2_conn_ctx_t *h2c;

  if (fh->stream_id == 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_rst_stream (&error_code, rx_buf, fh->length);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  req = http2_conn_get_req (hc, fh->stream_id);
  if (!req)
    {
      h2c = http2_conn_ctx_get_w_thread (hc);
      if (fh->stream_id <= h2c->last_opened_stream_id)
	{
	  /* we reset stream, but peer might send something meanwhile */
	  HTTP_DBG (1, "stream closed, ignoring frame");
	  return HTTP2_ERROR_NO_ERROR;
	}
      else
	return HTTP2_ERROR_PROTOCOL_ERROR;
    }

  req->stream_state = HTTP2_STREAM_STATE_CLOSED;
  session_transport_reset_notify (&req->base.connection);

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_goaway_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf;
  http2_error_t rv;
  u32 error_code, last_stream_id, req_index, stream_id;
  http2_conn_ctx_t *h2c;
  http2_req_t *req;

  if (fh->stream_id != 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv =
    http2_frame_read_goaway (&error_code, &last_stream_id, rx_buf, fh->length);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  if (error_code == HTTP2_ERROR_NO_ERROR)
    {
      /* TODO: graceful shutdown (no new streams) */
    }
  else
    {
      /* connection error */
      h2c = http2_conn_ctx_get_w_thread (hc);
      hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		      req = http2_req_get (req_index, hc->c_thread_index);
		      session_transport_reset_notify (&req->base.connection);
		    }));
      http_shutdown_transport (hc);
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_ping_frame (http_conn_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf, *resp = 0;

  if (fh->stream_id != 0 || fh->length != HTTP2_PING_PAYLOAD_LEN)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  /* RFC9113 6.7: The endpoint MUST NOT respond to PING frames with ACK */
  if (fh->flags & HTTP2_FRAME_FLAG_ACK)
    return HTTP2_ERROR_NO_ERROR;

  http2_frame_write_ping (1, rx_buf, &resp);
  http_io_ts_write (hc, resp, vec_len (resp), 0);
  vec_free (resp);
  http_io_ts_after_write (hc, 1);

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_push_promise (http_conn_t *hc, http2_frame_header_t *fh)
{
  if (hc->flags & HTTP_CONN_F_IS_SERVER)
    {
      HTTP_DBG (1, "error: server received PUSH_PROMISE");
      return HTTP2_ERROR_PROTOCOL_ERROR;
    }
  /* TODO: client */
  return HTTP2_ERROR_INTERNAL_ERROR;
}

static_always_inline int
http2_expect_preface (http_conn_t *hc, http2_conn_ctx_t *h2c)
{
  u8 *rx_buf;

  ASSERT (hc->flags & HTTP_CONN_F_IS_SERVER);
  h2c->flags &= ~HTTP2_CONN_F_EXPECT_PREFACE;

  /* already done in http core */
  if (h2c->flags & HTTP2_CONN_F_PREFACE_VERIFIED)
    return 0;

  rx_buf = http_get_rx_buf (hc);
  http_io_ts_read (hc, rx_buf, http2_conn_preface.len, 1);
  return memcmp (rx_buf, http2_conn_preface.base, http2_conn_preface.len);
}

/*****************/
/* http core VFT */
/*****************/

static u32
http2_hc_index_get_by_req_index (u32 req_index, u32 thread_index)
{
  http2_req_t *req;

  req = http2_req_get (req_index, thread_index);
  return req->base.hr_hc_index;
}

static transport_connection_t *
http2_req_get_connection (u32 req_index, u32 thread_index)
{
  http2_req_t *req;
  req = http2_req_get (req_index, thread_index);
  return &(req->base.connection);
}

static u8 *
format_http2_req (u8 *s, va_list *args)
{
  http2_req_t *req = va_arg (*args, http2_req_t *);
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  s = format (s, "[%d:%d][H2] stream_id %u app_wrk %u hc_index %u ts %d:%d",
	      req->base.c_thread_index, req->base.c_s_index, req->stream_id,
	      req->base.hr_pa_wrk_index, req->base.hr_hc_index,
	      ts->thread_index, ts->session_index);

  return s;
}

static u8 *
http2_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  u32 verbose = va_arg (*args, u32);
  http2_req_t *req;

  req = http2_req_get (req_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http2_req, req, hc);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, hc);
      if (verbose > 1)
	s = format (s, "\n");
    }

  return s;
}

static void
http2_app_tx_callback (http_conn_t *hc, u32 req_index,
		       transport_send_params_t *sp)
{
  http2_req_t *req;
  http2_error_t rv;

  HTTP_DBG (1, "hc [%u]%x req_index %u", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http2_req_get (req_index, hc->c_thread_index);

  if (!http2_req_state_is_tx_valid (req))
    {
      if (req->base.state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  (hc->flags & HTTP_CONN_F_IS_SERVER))
	{
	  /* server app might send error earlier */
	  http_req_state_change (&req->base, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			hc->c_thread_index, hc->hc_hc_index,
			format_http_req_state, req->base.state,
			format_http_conn_state, hc);
	  http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
	  return;
	}
    }

  /* peer reset stream, but app might send something meanwhile */
  if (req->stream_state == HTTP2_STREAM_STATE_CLOSED)
    {
      HTTP_DBG (1, "stream closed, ignoring app data");
      http_io_as_drain_all (&req->base);
      return;
    }

  HTTP_DBG (1, "run state machine");
  rv = http2_req_run_state_machine (hc, req, sp, 1);
  if (rv != HTTP2_ERROR_NO_ERROR)
    {
      http2_connection_error (hc, rv, sp);
      return;
    }

  /* maybe we can continue sending data on some stream */
  http2_resume_list_process (hc);

  /* reset http connection expiration timer */
  http_conn_timer_update (hc);
}

static void
http2_app_rx_evt_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  /* TODO: continue tunnel RX */
  http2_req_t *req;
  u8 *response;
  u32 increment;

  req = http2_req_get (req_index, thread_index);
  if (!req)
    {
      HTTP_DBG (1, "req already deleted");
      return;
    }
  HTTP_DBG (1, "received app read notification stream id %u", req->stream_id);
  if (req->stream_state == HTTP2_STREAM_STATE_OPEN)
    {
      http_io_as_reset_has_read_ntf (&req->base);
      response = http_get_tx_buf (hc);
      increment = http_io_as_max_write (&req->base);
      http2_frame_write_window_update (increment, req->stream_id, &response);
      http_io_ts_write (hc, response, vec_len (response), 0);
      http_io_ts_after_write (hc, 0);
    }
}

static void
http2_app_close_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  http2_req_t *req;

  HTTP_DBG (1, "hc [%u]%x req_index %u", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http2_req_get (req_index, thread_index);
  if (!req)
    {
      HTTP_DBG (1, "req already deleted");
      return;
    }

  if (req->stream_state == HTTP2_STREAM_STATE_CLOSED ||
      hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "nothing more to send, confirm close");
      session_transport_closed_notify (&req->base.connection);
    }
  else
    {
      HTTP_DBG (1, "wait for all data to be written to ts");
      req->flags |= HTTP2_REQ_F_APP_CLOSED;
    }
}

static void
http2_app_reset_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  http2_req_t *req;

  HTTP_DBG (1, "hc [%u]%x req_index %u", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http2_req_get (req_index, thread_index);
  req->flags |= HTTP2_REQ_F_APP_CLOSED;
  http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, 0);
}

static int
http2_transport_connected_callback (http_conn_t *hc)
{
  /* TODO */
  return -1;
}

static void
http2_transport_rx_callback (http_conn_t *hc)
{
  http2_main_t *h2m = &http2_main;
  http2_frame_header_t fh;
  u32 to_deq;
  u8 *rx_buf;
  http2_error_t rv;
  http2_conn_ctx_t *h2c;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  to_deq = http_io_ts_max_read (hc);

  if (PREDICT_FALSE (to_deq == 0))
    {
      HTTP_DBG (1, "no data to deq");
      return;
    }

  h2c = http2_conn_ctx_get_w_thread (hc);
  if (h2c->flags & HTTP2_CONN_F_EXPECT_PREFACE)
    {
      if (to_deq < http2_conn_preface.len)
	{
	  HTTP_DBG (1, "to_deq %u is less than conn preface size", to_deq);
	  http_disconnect_transport (hc);
	  return;
	}
      if (http2_expect_preface (hc, h2c))
	{
	  HTTP_DBG (1, "conn preface verification failed");
	  http_disconnect_transport (hc);
	  return;
	}
      http2_send_server_preface (hc);
      http_io_ts_drain (hc, http2_conn_preface.len);
      to_deq -= http2_conn_preface.len;
      if (to_deq == 0)
	return;
    }

  if (PREDICT_FALSE (to_deq < HTTP2_FRAME_HEADER_SIZE))
    {
      HTTP_DBG (1, "to_deq %u is less than frame header size", to_deq);
      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
      return;
    }

  while (to_deq >= HTTP2_FRAME_HEADER_SIZE)
    {
      rx_buf = http_get_rx_buf (hc);
      http_io_ts_read (hc, rx_buf, HTTP2_FRAME_HEADER_SIZE, 1);
      to_deq -= HTTP2_FRAME_HEADER_SIZE;
      http2_frame_header_read (rx_buf, &fh);
      if (fh.length > h2m->settings.max_frame_size)
	{
	  HTTP_DBG (1, "frame length %lu exceeded SETTINGS_MAX_FRAME_SIZE %lu",
		    fh.length, h2m->settings.max_frame_size);
	  http2_connection_error (hc, HTTP2_ERROR_FRAME_SIZE_ERROR, 0);
	  return;
	}
      if (fh.length > to_deq)
	{
	  HTTP_DBG (
	    1, "frame payload not yet received, to deq %lu, frame length %lu",
	    to_deq, fh.length);
	  if (http_io_ts_fifo_size (hc, 1) <
	      (fh.length + HTTP2_FRAME_HEADER_SIZE))
	    {
	      clib_warning ("ts rx fifo too small to hold frame (%u)",
			    fh.length + HTTP2_FRAME_HEADER_SIZE);
	      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
	    }
	  return;
	}
      http_io_ts_drain (hc, HTTP2_FRAME_HEADER_SIZE);
      to_deq -= fh.length;

      HTTP_DBG (1, "frame type 0x%02x", fh.type);
      switch (fh.type)
	{
	case HTTP2_FRAME_TYPE_HEADERS:
	  rv = http2_handle_headers_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_DATA:
	  rv = http2_handle_data_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
	  rv = http2_handle_window_update_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_SETTINGS:
	  rv = http2_handle_settings_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_RST_STREAM:
	  rv = http2_handle_rst_stream_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_GOAWAY:
	  rv = http2_handle_goaway_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_PING:
	  rv = http2_handle_ping_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_CONTINUATION:
	  /* TODO */
	  rv = HTTP2_ERROR_INTERNAL_ERROR;
	  break;
	case HTTP2_FRAME_TYPE_PUSH_PROMISE:
	  rv = http2_handle_push_promise (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_PRIORITY: /* deprecated */
	default:
	  /* ignore unknown frame type */
	  http_io_ts_drain (hc, fh.length);
	  rv = HTTP2_ERROR_NO_ERROR;
	  break;
	}

      if (rv != HTTP2_ERROR_NO_ERROR)
	{
	  http2_connection_error (hc, rv, 0);
	  return;
	}
    }

  /* maybe we can continue sending data on some stream */
  http2_resume_list_process (hc);

  /* reset http connection expiration timer */
  http_conn_timer_update (hc);
}

static void
http2_transport_close_callback (http_conn_t *hc)
{
  u32 req_index, stream_id, n_open_streams = 0;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    {
      HTTP_DBG (1, "no request");
      return;
    }

  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		  req = http2_req_get (req_index, hc->c_thread_index);
		  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		    {
		      HTTP_DBG (1, "req_index %u", req_index);
		      session_transport_closing_notify (&req->base.connection);
		      n_open_streams++;
		    }
		}));
  if (n_open_streams == 0)
    {
      HTTP_DBG (1, "no open stream disconnecting");
      http_disconnect_transport (hc);
    }
}

static void
http2_transport_reset_callback (http_conn_t *hc)
{
  u32 req_index, stream_id;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;

  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		  req = http2_req_get (req_index, hc->c_thread_index);
		  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		    {
		      HTTP_DBG (1, "req_index %u", req_index);
		      session_transport_reset_notify (&req->base.connection);
		    }
		}));
}

static void
http2_transport_conn_reschedule_callback (http_conn_t *hc)
{
  /* TODO */
}

static void
http2_conn_accept_callback (http_conn_t *hc)
{
  http2_conn_ctx_t *h2c;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h2c = http2_conn_ctx_alloc_w_thread (hc);
  h2c->flags |= HTTP2_CONN_F_EXPECT_PREFACE;
  /* already done in http core */
  if (http_get_transport_proto (hc) == TRANSPORT_PROTO_TCP)
    h2c->flags |= HTTP2_CONN_F_PREFACE_VERIFIED;
}

static void
http2_conn_cleanup_callback (http_conn_t *hc)
{
  u32 req_index, stream_id, *req_index_p, *req_indices = 0;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id,
		({ vec_add1 (req_indices, req_index); }));

  vec_foreach (req_index_p, req_indices)
    {
      req = http2_req_get (*req_index_p, hc->c_thread_index);
      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
	session_transport_delete_notify (&req->base.connection);
      http2_conn_free_req (h2c, req, hc->c_thread_index);
    }

  vec_free (req_indices);
  http2_conn_ctx_free (hc);
}

static void
http2_enable_callback (void)
{
  http2_main_t *h2m = &http2_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  num_threads = 1 /* main thread */ + vtm->n_threads;

  vec_validate (h2m->conn_pool, num_threads - 1);
  vec_validate (h2m->req_pool, num_threads - 1);
}

static int
http2_update_settings (http_settings_t type, u32 value)
{
  http2_main_t *h2m = &http2_main;

  switch (type)
    {
#define _(v, label, member, min, max, default_value, err_code)                \
  case HTTP2_SETTINGS_##label:                                                \
    if (!(value >= min && value <= max))                                      \
      return -1;                                                              \
    h2m->settings.member = value;                                             \
    return 0;
      foreach_http2_settings
#undef _
	default : return -1;
    }
}

static uword
http2_unformat_config_callback (unformat_input_t *input)
{
  u32 value;

  if (!input)
    return 0;

  unformat_skip_white_space (input);
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "initial-window-size %u", &value))
	{
	  if (http2_update_settings (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
				     value))
	    return 0;
	}
      else if (unformat (input, "max-frame-size %u", &value))
	{
	  if (http2_update_settings (HTTP2_SETTINGS_MAX_FRAME_SIZE, value))
	    return 0;
	}
      else if (unformat (input, "max-header-list-size %u", &value))
	{
	  if (http2_update_settings (HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
				     value))
	    return 0;
	}
      else if (unformat (input, "header-table-size %u", &value))
	{
	  if (http2_update_settings (HTTP2_SETTINGS_HEADER_TABLE_SIZE, value))
	    return 0;
	}
      else
	return 0;
    }
  return 1;
}

const static http_engine_vft_t http2_engine = {
  .name = "http2",
  .hc_index_get_by_req_index = http2_hc_index_get_by_req_index,
  .req_get_connection = http2_req_get_connection,
  .format_req = http2_format_req,
  .app_tx_callback = http2_app_tx_callback,
  .app_rx_evt_callback = http2_app_rx_evt_callback,
  .app_close_callback = http2_app_close_callback,
  .app_reset_callback = http2_app_reset_callback,
  .transport_connected_callback = http2_transport_connected_callback,
  .transport_rx_callback = http2_transport_rx_callback,
  .transport_close_callback = http2_transport_close_callback,
  .transport_reset_callback = http2_transport_reset_callback,
  .transport_conn_reschedule_callback =
    http2_transport_conn_reschedule_callback,
  .conn_accept_callback = http2_conn_accept_callback,
  .conn_cleanup_callback = http2_conn_cleanup_callback,
  .enable_callback = http2_enable_callback,
  .unformat_cfg_callback = http2_unformat_config_callback,
};

clib_error_t *
http2_init (vlib_main_t *vm)
{
  http2_main_t *h2m = &http2_main;

  clib_warning ("http/2 enabled");
  h2m->settings = http2_default_conn_settings;
  h2m->settings.max_concurrent_streams = 100; /* by default unlimited */
  http_register_engine (&http2_engine, HTTP_VERSION_2);

  return 0;
}

#if HTTP_2_ENABLE > 0
VLIB_INIT_FUNCTION (http2_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
#endif
