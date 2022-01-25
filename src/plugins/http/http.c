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

#include <http/http.h>
#include <vnet/session/session.h>
#include <http/http_timer.h>

static http_main_t http_main;

#define HTTP_FIFO_THRESH (16 << 10)

const char *http_status_code_str[] = {
#define _(c, s, str) str,
  foreach_http_status_code
#undef _
};

const char *http_content_type_str[] = {
#define _(s, str) str,
  foreach_http_content_type
#undef _
};

const http_buffer_type_t msg_to_buf_type[] = {
  [HTTP_MSG_DATA_INLINE] = HTTP_BUFFER_FIFO,
  [HTTP_MSG_DATA_PTR] = HTTP_BUFFER_PTR,
};

static inline http_worker_t *
http_worker_get (u32 thread_index)
{
  return &http_main.wrk[thread_index];
}

static inline u32
http_conn_alloc_w_thread (u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  http_conn_t *hc;

  pool_get_zero (wrk->conn_pool, hc);
  hc->c_thread_index = thread_index;
  hc->h_hc_index = hc - wrk->conn_pool;
  hc->h_pa_session_handle = SESSION_INVALID_HANDLE;
  hc->h_tc_session_handle = SESSION_INVALID_HANDLE;
  return hc->h_hc_index;
}

static inline http_conn_t *
http_conn_get_w_thread (u32 hc_index, u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  return pool_elt_at_index (wrk->conn_pool, hc_index);
}

void
http_conn_free (http_conn_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  pool_put (wrk->conn_pool, hc);
}

static u32
http_listener_alloc (void)
{
  http_main_t *hm = &http_main;
  http_conn_t *ctx;

  pool_get_zero (hm->listener_ctx_pool, ctx);
  ctx->c_c_index = ctx - hm->listener_ctx_pool;
  return ctx->c_c_index;
}

http_conn_t *
http_listener_get (u32 ctx_index)
{
  return pool_elt_at_index (http_main.listener_ctx_pool, ctx_index);
}

void
http_disconnect_transport (http_conn_t *hc)
{
  vnet_disconnect_args_t a = {
    .handle = hc->h_tc_session_handle,
    .app_index = http_main.app_index,
  };

  hc->state = HTTP_CONN_STATE_CLOSED;

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect returned");
}

static void
http_conn_timeout_cb (void *hc_handlep)
{
  http_conn_t *hc;
  uword hs_handle;

  hs_handle = pointer_to_uword (hc_handlep);
  hc = http_conn_get_w_thread (hs_handle & 0x00FFFFFF, hs_handle >> 24);

  HTTP_DBG (1, "terminate thread %d index %d hs %llx", hs_handle >> 24,
	    hs_handle & 0x00FFFFFF, hc);
  if (!hc)
    return;

  hc->timer_handle = ~0;
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);
}

int
http_ts_accept_callback (session_t *ts)
{
  session_t *ts_listener, *as, *asl;
  app_worker_t *app_wrk;
  http_conn_t *lhc, *hc;
  u32 hc_index, thresh;
  int rv;

  ts_listener = listen_session_get_from_handle (ts->listener_handle);
  lhc = http_listener_get (ts_listener->opaque);

  hc_index = http_conn_alloc_w_thread (ts->thread_index);
  hc = http_conn_get_w_thread (hc_index, ts->thread_index);
  clib_memcpy_fast (hc, lhc, sizeof (*lhc));
  hc->c_thread_index = vlib_get_thread_index ();
  hc->h_hc_index = hc_index;

  hc->h_tc_session_handle = session_handle (ts);
  hc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  hc->state = HTTP_CONN_STATE_ESTABLISHED;
  hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;

  ts->session_state = SESSION_STATE_READY;
  ts->opaque = hc_index;

  /*
   * Alloc session and initialize
   */
  as = session_alloc (hc->c_thread_index);
  as->session_state = SESSION_STATE_CREATED;
  hc->c_s_index = as->session_index;

  as->app_wrk_index = hc->h_pa_wrk_index;
  as->connection_index = hc->c_c_index;
  as->session_state = SESSION_STATE_ACCEPTING;

  asl = listen_session_get_from_handle (lhc->h_pa_session_handle);
  as->session_type = asl->session_type;
  as->listener_handle = lhc->h_pa_session_handle;

  /*
   * Init session fifos and notify app
   */
  if ((rv = app_worker_init_accepted (as)))
    {
      HTTP_DBG (1, "failed to allocate fifos");
      session_free (as);
      return rv;
    }

  hc->h_pa_session_handle = session_handle (as);
  hc->h_pa_wrk_index = as->app_wrk_index;
  app_wrk = app_worker_get (as->app_wrk_index);

  HTTP_DBG (1, "Accepted on listener %u new connection [%u]%x",
	    ts_listener->opaque, vlib_get_thread_index (), hc_index);

  if ((rv = app_worker_accept_notify (app_wrk, as)))
    {
      HTTP_DBG (0, "app accept returned");
      session_free (as);
      return rv;
    }

  /* Avoid enqueuing small chunks of data on transport tx notifications. If
   * the fifo is small (under 16K) we set the threshold to it's size, meaning
   * a notification will be given when the fifo empties.
   */
  thresh = clib_min (svm_fifo_size (ts->tx_fifo), HTTP_FIFO_THRESH);
  svm_fifo_set_deq_thresh (ts->tx_fifo, thresh);

  http_conn_timer_start (hc);

  return 0;
}

static int
http_ts_connected_callback (u32 http_app_index, u32 hc_index, session_t *ts,
			    session_error_t err)
{
  clib_warning ("not supported");
  return 0;
}

static void
http_ts_disconnect_callback (session_t *ts)
{
  http_conn_t *hc;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (hc->state < HTTP_CONN_STATE_TRANSPORT_CLOSED)
    hc->state = HTTP_CONN_STATE_TRANSPORT_CLOSED;

  if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_transport_closing_notify (&hc->connection);
}

static void
http_ts_reset_callback (session_t *ts)
{
  http_conn_t *ctx;

  ctx = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (ctx->state < HTTP_CONN_STATE_TRANSPORT_CLOSED)
    ctx->state = HTTP_CONN_STATE_TRANSPORT_CLOSED;

  if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_transport_reset_notify (&ctx->connection);
}

/**
 * http error boilerplate
 */
static const char *http_error_template = "HTTP/1.1 %s\r\n"
					 "Date: %U GMT\r\n"
					 "Content-Type: text/html\r\n"
					 "Connection: close\r\n"
					 "Pragma: no-cache\r\n"
					 "Content-Length: 0\r\n\r\n";

/**
 * http response boilerplate
 */
static const char *http_response_template = "HTTP/1.1 200 OK\r\n"
					    "Date: %U GMT\r\n"
					    "Expires: %U GMT\r\n"
					    "Server: VPP Static\r\n"
					    "Content-Type: %s\r\n"
					    "Content-Length: %d\r\n\r\n";

static u32
send_data (http_conn_t *hc, u8 *data, u32 length, u32 offset)
{
  const u32 max_burst = 64 << 10;
  session_t *ts;
  u32 to_send;
  int sent;

  ts = session_get_from_handle (hc->h_tc_session_handle);

  to_send = clib_min (length - offset, max_burst);
  sent = svm_fifo_enqueue (ts->tx_fifo, to_send, data + offset);

  if (sent <= 0)
    return offset;

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return (offset + sent);
}

static void
send_error (http_conn_t *hc, http_status_code_t ec)
{
  http_main_t *hm = &http_main;
  u8 *data;
  f64 now;

  if (ec >= HTTP_N_STATUS)
    ec = HTTP_STATUS_INTERNAL_ERROR;

  now = clib_timebase_now (&hm->timebase);
  data = format (0, http_error_template, http_status_code_str[ec],
		 format_clib_timebase_time, now);
  send_data (hc, data, vec_len (data), 0);
  vec_free (data);
}

static int
read_request (http_conn_t *hc)
{
  u32 max_deq, cursize;
  session_t *ts;
  int n_read;

  ts = session_get_from_handle (hc->h_tc_session_handle);

  cursize = vec_len (hc->rx_buf);
  max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    return -1;

  vec_validate (hc->rx_buf, cursize + max_deq - 1);
  n_read = svm_fifo_dequeue (ts->rx_fifo, max_deq, hc->rx_buf + cursize);
  ASSERT (n_read == max_deq);

  if (svm_fifo_is_empty (ts->rx_fifo))
    svm_fifo_unset_event (ts->rx_fifo);

  _vec_len (hc->rx_buf) = cursize + n_read;
  return 0;
}

static int
v_find_index (u8 *vec, u32 offset, char *str)
{
  int start_index = offset;
  u32 slen = (u32) strnlen_s_inline (str, 8);
  u32 vlen = vec_len (vec);

  ASSERT (slen > 0);

  if (vlen <= slen)
    return -1;

  for (; start_index < (vlen - slen); start_index++)
    {
      if (!memcmp (vec + start_index, str, slen))
	return start_index;
    }

  return -1;
}

/**
 * waiting for request method from peer - parse request method and data
 */
static int
state_wait_method (http_conn_t *hc, transport_send_params_t *sp)
{
  http_status_code_t ec;
  app_worker_t *app_wrk;
  http_msg_t msg;
  session_t *as;
  int i, rv;
  u32 len;
  u8 *buf;

  rv = read_request (hc);

  /* Nothing yet, wait for data or timer expire */
  if (rv)
    return 0;

  if (vec_len (hc->rx_buf) < 8)
    {
      ec = HTTP_STATUS_BAD_REQUEST;
      goto error;
    }

  if ((i = v_find_index (hc->rx_buf, 0, "GET ")) >= 0)
    {
      hc->method = HTTP_REQ_GET;
      hc->rx_buf_offset = i + 5;

      i = v_find_index (hc->rx_buf, hc->rx_buf_offset, "HTTP");
      if (i < 0)
	{
	  ec = HTTP_STATUS_BAD_REQUEST;
	  goto error;
	}

      len = i - hc->rx_buf_offset - 1;
    }
  else if ((i = v_find_index (hc->rx_buf, 0, "POST ")) >= 0)
    {
      hc->method = HTTP_REQ_POST;
      hc->rx_buf_offset = i + 6;
      len = vec_len (hc->rx_buf) - hc->rx_buf_offset - 1;
    }
  else
    {
      HTTP_DBG (0, "Unknown http method");
      ec = HTTP_STATUS_METHOD_NOT_ALLOWED;
      goto error;
    }

  buf = &hc->rx_buf[hc->rx_buf_offset];

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = hc->method;
  msg.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = len;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) }, { buf, len } };

  as = session_get_from_handle (hc->h_pa_session_handle);
  rv = svm_fifo_enqueue_segments (as->rx_fifo, segs, 2, 0 /* allow partial */);
  if (rv < 0 || rv != sizeof (msg) + len)
    {
      clib_warning ("failed app enqueue");
      /* This should not happen as we only handle 1 request per session,
       * and fifo is allocated, but going forward we should consider
       * rescheduling */
      return -1;
    }

  vec_free (hc->rx_buf);
  hc->req_state = HTTP_REQ_STATE_WAIT_APP;

  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  app_worker_lock_and_send_event (app_wrk, as, SESSION_IO_EVT_RX);

  return 0;

error:

  send_error (hc, ec);
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);

  return -1;
}

/**
 * waiting for data from app
 */
static int
state_wait_app (http_conn_t *hc, transport_send_params_t *sp)
{
  http_main_t *hm = &http_main;
  http_status_code_t ec;
  http_msg_t msg;
  session_t *as;
  u8 *header;
  u32 offset;
  f64 now;
  int rv;

  as = session_get_from_handle (hc->h_pa_session_handle);

  rv = svm_fifo_dequeue (as->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REPLY || msg.data.type > HTTP_MSG_DATA_PTR)
    {
      clib_warning ("unexpected msg type from app %u", msg.type);
      ec = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }

  if (msg.code != HTTP_STATUS_OK)
    {
      ec = msg.code;
      goto error;
    }

  http_buffer_init (&hc->tx_buf, msg_to_buf_type[msg.data.type], as->tx_fifo,
		    msg.data.len);

  /*
   * Add headers. For now:
   * - current time
   * - expiration time
   * - content type
   * - data length
   */
  now = clib_timebase_now (&hm->timebase);
  header = format (0, http_response_template,
		   /* Date */
		   format_clib_timebase_time, now,
		   /* Expires */
		   format_clib_timebase_time, now + 600.0,
		   /* Content type */
		   http_content_type_str[msg.content_type],
		   /* Length */
		   msg.data.len);

  offset = send_data (hc, header, vec_len (header), 0);
  if (offset != vec_len (header))
    {
      clib_warning ("couldn't send response header!");
      ec = HTTP_STATUS_INTERNAL_ERROR;
      goto error;
    }
  vec_free (header);

  /* Start sending the actual data */
  hc->req_state = HTTP_REQ_STATE_SEND_MORE_DATA;

  return 1;

error:

  send_error (hc, ec);
  hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);

  /* stop state machine processing */
  return 0;
}

static int
state_send_more_data (http_conn_t *hc, transport_send_params_t *sp)
{
  u32 max_send = 64 << 10, n_segs;
  http_buffer_t *hb = &hc->tx_buf;
  svm_fifo_seg_t *seg;
  session_t *ts;
  int sent = 0;

  ts = session_get_from_handle (hc->h_tc_session_handle);
  if ((seg = http_buffer_get_segs (hb, max_send, &n_segs)))
    sent = svm_fifo_enqueue_segments (ts->tx_fifo, seg, n_segs,
				      1 /* allow partial */);

  if (sent > 0)
    {
      http_buffer_drain (hb, sent);

      /* Ask scheduler to notify app of deq event if needed */
      sp->max_burst_size = sent;
    }
  else
    {
      sp->max_burst_size = 0;
    }

  /* Not finished sending all data */
  if (!http_buffer_is_drained (hb))
    {
      if (sent && svm_fifo_set_event (ts->tx_fifo))
	session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

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
	session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX_FLUSH);

      /* Finished transaction, back to HTTP_REQ_STATE_WAIT_METHOD */
      hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;
      http_buffer_free (&hc->tx_buf);
    }

  return 0;
}

typedef int (*http_sm_handler) (http_conn_t *, transport_send_params_t *sp);

static http_sm_handler req_state_funcs[HTTP_REQ_N_STATES] = {
  /* Waiting for GET, POST, etc. */
  state_wait_method,
  /* Wait for data from app */
  state_wait_app,
  /* Send more data */
  state_send_more_data,
};

static void
http_req_run_state_machine (http_conn_t *hc, transport_send_params_t *sp)
{
  int rv;

  do
    {
      rv = req_state_funcs[hc->req_state](hc, sp);
      if (rv < 0)
	return;
    }
  while (rv);

  /* Reset the session expiration timer */
  http_conn_timer_update (hc);
}

static int
http_ts_rx_callback (session_t *ts)
{
  http_conn_t *hc;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (hc->req_state != HTTP_REQ_STATE_WAIT_METHOD)
    {
      clib_warning ("tcp data in req state %u", hc->req_state);
      return 0;
    }

  http_req_run_state_machine (hc, 0);

  if (hc->state == HTTP_CONN_STATE_TRANSPORT_CLOSED)
    {
      if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
	session_transport_closing_notify (&hc->connection);
    }
  return 0;
}

int
http_ts_builtin_tx_callback (session_t *ts)
{
  http_conn_t *hc;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);
  transport_connection_reschedule (&hc->connection);

  return 0;
}

static void
http_ts_cleanup_callback (session_t *ts, session_cleanup_ntf_t ntf)
{
  http_conn_t *hc;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);
  if (!hc)
    {
      clib_warning ("no http connection for %u", ts->session_index);
      return;
    }

  vec_free (hc->rx_buf);

  http_buffer_free (&hc->tx_buf);
  http_conn_timer_stop (hc);

  session_transport_delete_notify (&hc->connection);
  http_conn_free (hc);
}

int
http_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
http_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t http_app_cb_vft = {
  .session_accept_callback = http_ts_accept_callback,
  .session_disconnect_callback = http_ts_disconnect_callback,
  .session_connected_callback = http_ts_connected_callback,
  .session_reset_callback = http_ts_reset_callback,
  .session_cleanup_callback = http_ts_cleanup_callback,
  .add_segment_callback = http_add_segment_callback,
  .del_segment_callback = http_del_segment_callback,
  .builtin_app_rx_callback = http_ts_rx_callback,
  .builtin_app_tx_callback = http_ts_builtin_tx_callback,
};

static clib_error_t *
http_transport_enable (vlib_main_t *vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  http_main_t *hm = &http_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = hm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  vec_validate (hm->wrk, vlib_num_workers ());

  first_seg_size = hm->first_seg_size ? hm->first_seg_size : first_seg_size;
  fifo_size = hm->fifo_size ? hm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &http_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "http");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    return clib_error_return (0, "failed to attach http app");

  hm->app_index = a->app_index;
  vec_free (a->name);

  clib_timebase_init (&hm->timebase, 0 /* GMT */, CLIB_TIMEBASE_DAYLIGHT_NONE,
		      &vm->clib_time /* share the system clock */);

  http_timers_init (vm, http_conn_timeout_cb);

  return 0;
}

static int
http_transport_connect (transport_endpoint_cfg_t *tep)
{
  return -1;
}

static u32
http_start_listen (u32 app_listener_index, transport_endpoint_t *tep)
{
  vnet_listen_args_t _args = {}, *args = &_args;
  session_t *tc_listener, *app_listener;
  http_main_t *hm = &http_main;
  session_endpoint_cfg_t *sep;
  app_worker_t *app_wrk;
  transport_proto_t tp;
  app_listener_t *al;
  application_t *app;
  http_conn_t *lhc;
  u32 lhc_index;

  sep = (session_endpoint_cfg_t *) tep;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  args->app_index = hm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  tp = sep->ext_cfg ? TRANSPORT_PROTO_TLS : TRANSPORT_PROTO_TCP;
  args->sep_ext.transport_proto = tp;

  if (vnet_listen (args))
    return SESSION_INVALID_INDEX;

  lhc_index = http_listener_alloc ();
  lhc = http_listener_get (lhc_index);

  /* Grab transport connection listener and link to http listener */
  lhc->h_tc_session_handle = args->handle;
  al = app_listener_get_w_handle (lhc->h_tc_session_handle);
  tc_listener = app_listener_get_session (al);
  tc_listener->opaque = lhc_index;

  /* Grab application listener and link to http listener */
  app_listener = listen_session_get (app_listener_index);
  lhc->h_pa_wrk_index = sep->app_wrk_index;
  lhc->h_pa_session_handle = listen_session_get_handle (app_listener);
  lhc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  return lhc_index;
}

static void
http_transport_close (u32 hc_index, u32 thread_index)
{
  session_t *as;
  http_conn_t *hc;

  HTTP_DBG (1, "App disconnecting %x", hc_index);

  hc = http_conn_get_w_thread (hc_index, thread_index);
  as = session_get_from_handle (hc->h_pa_session_handle);

  /* Nothing more to send, confirm close */
  if (!svm_fifo_max_dequeue_cons (as->tx_fifo))
    {
      session_transport_closed_notify (&hc->connection);
      http_disconnect_transport (hc);
    }
  else
    {
      /* Wait for all data to be written to ts */
      hc->state = HTTP_CONN_STATE_APP_CLOSED;
    }
}

static transport_connection_t *
http_transport_get_connection (u32 hc_index, u32 thread_index)
{
  http_conn_t *hc = http_conn_get_w_thread (hc_index, thread_index);
  return &hc->connection;
}

static transport_connection_t *
http_transport_get_listener (u32 listener_index)
{
  http_conn_t *lhc = http_listener_get (listener_index);
  return &lhc->connection;
}

static int
http_app_tx_callback (void *session, transport_send_params_t *sp)
{
  session_t *as = (session_t *) session;
  http_conn_t *hc;

  sp->flags = 0;

  hc = http_conn_get_w_thread (as->connection_index, as->thread_index);
  if (hc->req_state < HTTP_REQ_STATE_WAIT_APP)
    {
      clib_warning ("app data in req state %u", hc->req_state);
      return 0;
    }

  http_req_run_state_machine (hc, sp);

  if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      if (!svm_fifo_max_dequeue_cons (as->rx_fifo))
	http_disconnect_transport (hc);
    }
  return 0;
}

static void
http_transport_get_endpoint (u32 hc_index, u32 thread_index,
			     transport_endpoint_t *tep, u8 is_lcl)
{
  http_conn_t *hc = http_conn_get_w_thread (hc_index, thread_index);
  session_t *ts;

  ts = session_get_from_handle (hc->h_tc_session_handle);
  session_get_endpoint (ts, tep, is_lcl);
}

static u8 *
format_http_connection (u8 *s, va_list *args)
{
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->h_tc_session_handle);
  s = format (s, "[%d:%d][H] app_wrk %u ts %d:%d", hc->c_thread_index,
	      hc->c_s_index, hc->h_pa_wrk_index, ts->thread_index,
	      ts->session_index);

  return s;
}

static u8 *
format_http_listener (u8 *s, va_list *args)
{
  http_conn_t *lhc = va_arg (*args, http_conn_t *);
  app_listener_t *al;
  session_t *lts;

  al = app_listener_get_w_handle (lhc->h_tc_session_handle);
  lts = app_listener_get_session (al);
  s = format (s, "[%d:%d][H] app_wrk %u ts %d:%d", lhc->c_thread_index,
	      lhc->c_s_index, lhc->h_pa_wrk_index, lts->thread_index,
	      lts->session_index);

  return s;
}

static u8 *
format_http_conn_state (u8 *s, va_list *args)
{
  http_conn_t *hc = va_arg (*args, http_conn_t *);

  switch (hc->state)
    {
    case HTTP_CONN_STATE_LISTEN:
      s = format (s, "LISTEN");
      break;
    case HTTP_CONN_STATE_CONNECTING:
      s = format (s, "CONNECTING");
      break;
    case HTTP_CONN_STATE_ESTABLISHED:
      s = format (s, "ESTABLISHED");
      break;
    case HTTP_CONN_STATE_TRANSPORT_CLOSED:
      s = format (s, "TRANSPORT_CLOSED");
      break;
    case HTTP_CONN_STATE_APP_CLOSED:
      s = format (s, "APP_CLOSED");
      break;
    case HTTP_CONN_STATE_CLOSED:
      s = format (s, "CLOSED");
      break;
    }

  return s;
}

static u8 *
format_http_transport_connection (u8 *s, va_list *args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  http_conn_t *hc;

  hc = http_conn_get_w_thread (tc_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http_connection, hc);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, hc);
      if (verbose > 1)
	s = format (s, "\n");
    }

  return s;
}

static u8 *
format_http_transport_listener (u8 *s, va_list *args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  http_conn_t *lhc = http_listener_get (tc_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http_listener, lhc);
  if (verbose)
    s =
      format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, lhc);
  return s;
}

static const transport_proto_vft_t http_proto = {
  .enable = http_transport_enable,
  .connect = http_transport_connect,
  .start_listen = http_start_listen,
  .close = http_transport_close,
  .custom_tx = http_app_tx_callback,
  .get_connection = http_transport_get_connection,
  .get_listener = http_transport_get_listener,
  .get_transport_endpoint = http_transport_get_endpoint,
  .format_connection = format_http_transport_connection,
  .format_listener = format_http_transport_listener,
  .transport_options = {
    .name = "http",
    .short_name = "H",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
http_transport_init (vlib_main_t *vm)
{
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (http_transport_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Hypertext Transfer Protocol (HTTP)",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
