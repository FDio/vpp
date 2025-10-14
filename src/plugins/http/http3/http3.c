/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/http3.h>
#include <http/http3/frame.h>
#include <http/http3/qpack.h>
#include <http/http_private.h>
#include <http/http_timer.h>

typedef struct http3_stream_ctx_
{
  http_req_t base;
  u32 h3c_index;
  http3_stream_type_t stream_type;
  u8 *payload;
  u32 payload_len;
  void (*tranport_rx_cb) (struct http3_stream_ctx_ *sctx, http_conn_t *stream);
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
  u32 our_ctrl_stream_index;
  u32 peer_ctrl_stream_index;
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
  h3c->our_ctrl_stream_index = SESSION_INVALID_INDEX;
  h3c->peer_ctrl_stream_index = SESSION_INVALID_INDEX;
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

static_always_inline http3_stream_ctx_t *
http3_stream_ctx_alloc (http_conn_t *stream)
{
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);
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
  stream->opaque = uword_to_pointer (si, void *);
  hc = http_conn_get_w_thread (stream->hc_http_conn_index,
			       stream->c_thread_index);
  sctx->h3c_index = pointer_to_uword (hc->opaque);

  return sctx;
}

static_always_inline http3_stream_ctx_t *
http3_stream_ctx_get (u32 stream_index, clib_thread_index_t thread_index)
{
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);
  return pool_elt_at_index (wrk->stream_pool, stream_index);
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http3_req_state_wait_app_reply (http_conn_t *stream, http3_stream_ctx_t *sctx,
				transport_send_params_t *sp,
				http3_error_t *error)
{
  http_msg_t msg;
  hpack_response_control_data_t control_data;
  u8 *response, *date, *app_headers = 0;
  u32 headers_len, n_written;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len;

  http_get_app_msg (&sctx->base, &msg);
  ASSERT (msg.type == HTTP_MSG_REPLY);

  response = http_get_tx_buf (stream);
  date = format (0, "%U", format_http_time_now, stream);

  control_data.content_len = msg.data.body_len;
  control_data.server_name = stream->app_name;
  control_data.server_name_len = vec_len (stream->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);
  control_data.sc = msg.code;

  if (msg.data.headers_len)
    app_headers = http_get_app_header_list (&sctx->base, &msg);

  qpack_serialize_response (app_headers, msg.data.headers_len, &control_data,
			    &response);
  vec_free (date);
  headers_len = vec_len (response);

  if (msg.data.body_len)
    {
      ASSERT (sctx->base.is_tunnel == 0);
      http_req_tx_buffer_init (&sctx->base, &msg);
      http_req_state_change (&sctx->base, HTTP_REQ_STATE_APP_IO_MORE_DATA);
    }

  fh_len =
    http3_frame_header_write (HTTP3_FRAME_TYPE_HEADERS, headers_len, fh_buf);

  svm_fifo_seg_t segs[2] = { { fh_buf, fh_len }, { response, headers_len } };
  n_written = http_io_ts_write_segs (stream, segs, 2, 0);
  ASSERT (n_written == (fh_len + headers_len));
  http_io_ts_after_write (stream, 0);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_app_io_more_data (http_conn_t *stream,
				  http3_stream_ctx_t *sctx,
				  transport_send_params_t *sp,
				  http3_error_t *error)
{
  http_buffer_t *hb = &sctx->base.tx_buf;
  u32 max_write, max_read, n_read, n_segs, n_written;
  svm_fifo_seg_t *app_segs, *segs = 0;
  u8 fh_buf[HTTP3_FRAME_HEADER_MAX_LEN];
  u8 fh_len, finished;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  max_write = http_io_ts_max_write (stream, 0);
  max_write -= HTTP3_FRAME_HEADER_MAX_LEN;

  max_read = http_buffer_bytes_left (hb);

  n_read = http_buffer_get_segs (hb, max_write, &app_segs, &n_segs);
  ASSERT (n_read);
  finished = (max_read - n_read) == 0;

  fh_len = http3_frame_header_write (HTTP3_FRAME_TYPE_DATA, n_read, fh_buf);
  vec_validate (segs, 0);
  segs[0].len = fh_len;
  segs[0].data = fh_buf;
  vec_append (segs, app_segs);
  n_written = http_io_ts_write_segs (stream, segs, n_segs + 1, sp);
  n_written -= fh_len;
  vec_free (segs);
  http_buffer_drain (hb, n_written);

  if (finished)
    {
      /* all done, close stream */
      http_buffer_free (hb);
      /* FIXME: */
    }

  http_io_ts_after_write (stream, finished);
  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_wait_transport_method (http_conn_t *stream,
				       http3_stream_ctx_t *sctx,
				       transport_send_params_t *sp,
				       http3_error_t *error)
{
  http3_conn_ctx_t *h3c;
  hpack_request_control_data_t control_data;
  http_msg_t msg;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_REPLY;
  http3_worker_ctx_t *wrk = http3_worker_get (stream->c_thread_index);

  h3c = http3_conn_ctx_get (sctx->h3c_index, stream->c_thread_index);
  *error =
    qpack_parse_request (sctx->payload, sctx->payload_len, wrk->header_list,
			 vec_len (wrk->header_list), &control_data,
			 &sctx->base.headers, &h3c->qpack_decoder_ctx);
  if (*error != HTTP3_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "hpack_parse_request failed");
      return HTTP_SM_ERROR;
    }

  sctx->base.control_data_len = control_data.control_data_len;
  sctx->base.headers_offset = control_data.headers - wrk->header_list;
  sctx->base.headers_len = control_data.headers_len;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_METHOD_PARSED))
    {
      HTTP_DBG (1, ":method pseudo-header missing in request");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported method");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":scheme pseudo-header missing in request");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (control_data.scheme == HTTP_URL_SCHEME_UNKNOWN)
    {
      HTTP_DBG (1, "unsupported scheme");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED) &&
      control_data.method != HTTP_REQ_CONNECT)
    {
      HTTP_DBG (1, ":path pseudo-header missing in request");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_AUTHORITY_PARSED))
    {
      HTTP_DBG (1, ":authority pseudo-header missing in request");
      /* FIXME: */
      return HTTP_SM_STOP;
    }
  if (control_data.content_len_header_index != ~0)
    {
      sctx->base.content_len_header_index =
	control_data.content_len_header_index;
      if (http_parse_content_length (&sctx->base, wrk->header_list))
	{
	  /* FIXME: */
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
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

  return HTTP_SM_STOP;
}

static http_sm_result_t
http3_req_state_transport_io_more_data (http_conn_t *hc,
					http3_stream_ctx_t *sctx,
					transport_send_params_t *sp,
					http3_error_t *error)
{
  ASSERT (0); /* FIXME: */
  return HTTP_SM_STOP;
}

/*************************/
/* request state machine */
/*************************/

typedef http_sm_result_t (*http3_sm_handler) (http_conn_t *hc,
					      http3_stream_ctx_t *sctx,
					      transport_send_params_t *sp,
					      http3_error_t *error);

static http3_sm_handler tx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* FIXME: wait app method */
  0, /* wait transport reply */
  0, /* transport io more data */
  0, /* wait transport method */
  http3_req_state_wait_app_reply,
  http3_req_state_app_io_more_data,
  0, /* TODO: tunnel tx */
  0, /* TODO: udp unnel tx */
};

static http3_sm_handler rx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  0, /* FIXME: wait transport reply */
  http3_req_state_transport_io_more_data,
  http3_req_state_wait_transport_method,
  0, /* wait app reply */
  0, /* app io more data */
  0, /* TODO: tunnel rx */
  0, /* TODO: udp tunnel rx */
};

static_always_inline int
http3_req_state_is_tx_valid (http3_stream_ctx_t *sctx)
{
  return tx_state_funcs[sctx->base.state] ? 1 : 0;
}

static_always_inline int
http3_req_state_is_rx_valid (http3_stream_ctx_t *sctx)
{
  return rx_state_funcs[sctx->base.state] ? 1 : 0;
}

static_always_inline http3_error_t
http3_req_run_state_machine (http_conn_t *stream, http3_stream_ctx_t *sctx,
			     transport_send_params_t *sp, u8 is_tx)
{
  http_sm_result_t res;
  http3_error_t error;

  do
    {
      if (is_tx)
	res = tx_state_funcs[sctx->base.state](stream, sctx, sp, &error);
      else
	res = rx_state_funcs[sctx->base.state](stream, sctx, 0, &error);

      if (res == HTTP_SM_ERROR)
	{
	  HTTP_DBG (1, "protocol error %U", format_http2_error, error);
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
	  HTTP_DBG (1, "invalid frame header");
	  /* FIXME: handle as error */
	  return 1;
	}
    }
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

static void
http3_stream_transport_rx_drain (CLIB_UNUSED (http3_stream_ctx_t *sctx),
				 http_conn_t *stream)
{
  http_io_ts_drain_all (stream);
}

static void
http3_stream_transport_rx_ctrl (http3_stream_ctx_t *sctx, http_conn_t *stream)
{
  http3_error_t err;
  http3_conn_ctx_t *h3c;
  u32 to_deq;
  u8 *rx_buf;

  to_deq = http_io_ts_max_read (stream);
  while (to_deq)
    {
      http3_frame_header_t fh = {};
      if (PREDICT_FALSE (
	    http3_stream_read_frame_header (sctx, stream, &to_deq, &fh)))
	break;
      switch (fh.type)
	{
	case HTTP3_FRAME_TYPE_SETTINGS:
	  HTTP_DBG (1, "settings received");
	  h3c =
	    http3_conn_ctx_get (sctx->h3c_index, sctx->base.c_thread_index);
	  if (!(h3c->flags & HTTP3_CONN_F_EXPECT_PEER_SETTINGS))
	    {
	      /* FIXME: handle as error */
	      return;
	    }
	  h3c->flags &= ~HTTP3_CONN_F_EXPECT_PEER_SETTINGS;
	  if (fh.length == 0)
	    break;
	  rx_buf = http_get_rx_buf (stream);
	  http_io_ts_read (stream, rx_buf, fh.length, 0);
	  to_deq -= fh.length;
	  err =
	    http3_frame_settings_read (rx_buf, fh.length, &h3c->peer_settings);
	  if (err != HTTP3_ERROR_NO_ERROR)
	    {
	      /* FIXME: handle as error */
	      return;
	    }
	  break;
	case HTTP3_FRAME_TYPE_GOAWAY:
	  HTTP_DBG (1, "goaway received");
	  /* FIXME: */
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
}

static void
http3_stream_transport_rx_unknown_type (http3_stream_ctx_t *sctx,
					http_conn_t *stream)
{
  u32 max_deq, to_deq;
  u8 *rx_buf, *p;
  u64 stream_type;

  max_deq = http_io_ts_max_read (stream);
  ASSERT (max_deq > 0);
  to_deq = clib_min (max_deq, HTTP_VARINT_MAX_LEN);
  rx_buf = http_get_rx_buf (stream);
  http_io_ts_read (stream, rx_buf, to_deq, 1);
  p = rx_buf;
  stream_type = http_decode_varint (&p, p + to_deq);
  if (stream_type == HTTP_INVALID_VARINT)
    {
      /*FIXME:*/
      return;
    }
  http_io_ts_drain (stream, p - rx_buf);
  sctx->stream_type = stream_type;
  HTTP_DBG (1, "stream type %lx [%u]%x", stream_type,
	    sctx->base.c_thread_index,
	    ((http_req_handle_t) sctx->base.hr_req_handle).req_index);

  switch (stream_type)
    {
    case HTTP3_STREAM_TYPE_CONTROL:
      sctx->tranport_rx_cb = http3_stream_transport_rx_ctrl;
      break;
    default:
      sctx->tranport_rx_cb = http3_stream_transport_rx_drain;
      break;
    }

  sctx->tranport_rx_cb (sctx, stream);
}

static void
http3_stream_transport_rx_req (http3_stream_ctx_t *sctx, http_conn_t *stream)
{
  u32 to_deq;
  u8 *rx_buf;

  to_deq = http_io_ts_max_read (stream);
  while (to_deq)
    {
      http3_frame_header_t fh = {};
      rx_buf = http_get_rx_buf (stream);
      if (PREDICT_FALSE (
	    http3_stream_read_frame_header (sctx, stream, &to_deq, &fh)))
	return;
      switch (fh.type)
	{
	case HTTP3_FRAME_TYPE_HEADERS:
	  http_req_state_change (&sctx->base,
				 HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
	  vec_validate (rx_buf, fh.length - 1);
	  http_io_ts_read (stream, rx_buf, fh.length, 0);
	  to_deq -= fh.length;
	  sctx->payload = rx_buf;
	  sctx->payload_len = fh.length;
	  break;
	case HTTP3_FRAME_TYPE_DATA:
	  if (fh.length == 0)
	    continue;
	  vec_validate (rx_buf, fh.length - 1);
	  http_io_ts_read (stream, rx_buf, fh.length, 0);
	  to_deq -= fh.length;
	  sctx->payload = rx_buf;
	  sctx->payload_len = fh.length;
	  break;
	default:
	  /* discard payload of unknown frame */
	  if (fh.length)
	    {
	      http_io_ts_drain (stream, fh.length);
	      to_deq -= fh.length;
	    }
	  continue;
	}

      if (http3_req_state_is_rx_valid (sctx))
	http3_req_run_state_machine (stream, sctx, 0, 0);
      else
	ASSERT (0); /* FIXME: */
    }
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
    if (!(value >= min && value <= max))                                      \
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
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  s = format (s, "[%d:%d][H3] app_wrk %u hc_index %u ts %d:%d",
	      req->base.c_thread_index, req->base.c_s_index,
	      req->base.hr_pa_wrk_index, req->base.hr_hc_index,
	      ts->thread_index, ts->session_index);

  return s;
}

static u8 *
http3_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  u32 verbose = va_arg (*args, u32);
  http3_stream_ctx_t *req;

  req = http3_stream_ctx_get (req_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http3_req, req, hc);
  if (verbose)
    {
      /* FIXME: */
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
  if (!http3_req_state_is_tx_valid (sctx))
    {
      /* FIXME: */
      return;
    }
  err = http3_req_run_state_machine (stream, sctx, sp, 1);
  if (err != HTTP3_ERROR_NO_ERROR)
    {
      /* FIXME: */
      return;
    }

  /* reset http connection expiration timer */
  http_conn_timer_update (stream);
}

static void
http3_app_rx_evt_callback (http_conn_t *hc, u32 req_index,
			   clib_thread_index_t thread_index)
{
  /* FIXME: */
}

static void
http3_app_close_callback (http_conn_t *hc, u32 req_index,
			  clib_thread_index_t thread_index, u8 is_shutdown)
{
  /* FIXME: */
}

static void
http3_app_reset_callback (http_conn_t *hc, u32 req_index,
			  clib_thread_index_t thread_index)
{
  /* FIXME: */
}

static int
http3_transport_connected_callback (http_conn_t *hc)
{
  /* FIXME: */
  return 0;
}

static void
http3_transport_rx_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  ASSERT (http_conn_is_stream (stream));

  sctx = http3_stream_ctx_get (pointer_to_uword (stream->opaque),
			       stream->c_thread_index);
  sctx->tranport_rx_cb (sctx, stream);
}

static void
http3_transport_close_callback (http_conn_t *hc)
{
  /* FIXME: */
}

static void
http3_transport_reset_callback (http_conn_t *hc)
{
  /* FIXME: */
}

static void
http3_transport_conn_reschedule_callback (http_conn_t *hc)
{
  /* FIXME: */
}

static int
http3_transport_stream_accept_callback (http_conn_t *stream)
{
  http3_stream_ctx_t *sctx;

  sctx = http3_stream_ctx_alloc (stream);

  if (stream->flags & HTTP_CONN_F_BIDIRECTIONAL_STREAM)
    {
      sctx->stream_type = HTTP3_STREAM_TYPE_REQUEST;
      sctx->tranport_rx_cb = http3_stream_transport_rx_req;
      HTTP_DBG (1, "new req stream accepted [%u]%x", sctx->base.c_thread_index,
		((http_req_handle_t) sctx->base.hr_req_handle).req_index);
    }
  else
    {
      sctx->tranport_rx_cb = http3_stream_transport_rx_unknown_type;
      HTTP_DBG (1, "new unidirectional stream accepted [%u]%x",
		sctx->base.c_thread_index,
		((http_req_handle_t) sctx->base.hr_req_handle).req_index);
    }
  return 0;
}

static void
http3_transport_stream_close_callback (http_conn_t *stream)
{
  /* FIXME: */
}

static void
http3_transport_stream_reset_callback (http_conn_t *stream)
{
  /* FIXME: */
}

static void
http3_conn_accept_callback (http_conn_t *hc)
{
  http3_main_t *h3m = &http3_main;
  http3_conn_ctx_t *h3c;
  http_conn_t *ctrl_stream;
  u8 *buf, *p;

  h3c = http3_conn_ctx_alloc (hc);
  h3c->flags |= HTTP3_CONN_F_EXPECT_PEER_SETTINGS;

  /*open control stream */
  if (http_connect_transport_stream (hc, 1, &ctrl_stream))
    {
      HTTP_DBG (1, "failed to open control stream");
      /* FIXME:*/
      return;
    }
  h3c->our_ctrl_stream_index = ctrl_stream->hc_hc_index;

  buf = http_get_tx_buf (ctrl_stream);
  /* write stream type first */
  p = http_encode_varint (buf, HTTP3_STREAM_TYPE_CONTROL);
  vec_set_len (buf, (p - buf));
  /* write settings frame */
  http3_frame_settings_write (&h3m->settings, &buf);
  http_io_ts_write (ctrl_stream, buf, vec_len (buf), 0);
  http_io_ts_after_write (ctrl_stream, 1);
}

static int
http3_conn_connect_stream_callback (http_conn_t *hc, u32 *req_index)
{
  /* FIXME: */
  return 0;
}

static void
http3_conn_cleanup_callback (http_conn_t *hc)
{
  /* FIXME: */
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
