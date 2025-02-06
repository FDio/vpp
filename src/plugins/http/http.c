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

#include <vpp/app/version.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>

#include <http/http.h>
#include <http/http_private.h>
#include <http/http_timer.h>

static http_main_t http_main;
static http_engine_vft_t *http_vfts;

const http_buffer_type_t msg_to_buf_type[] = {
  [HTTP_MSG_DATA_INLINE] = HTTP_BUFFER_FIFO,
  [HTTP_MSG_DATA_PTR] = HTTP_BUFFER_PTR,
};

void
http_register_engine (const http_engine_vft_t *vft, http_version_t version)
{
  vec_validate (http_vfts, version);
  http_vfts[version] = *vft;
}

always_inline http_version_t
http_version_from_handle (http_conn_handle_t hc_handle)
{
  /* the first 3 bits are http version */
  return hc_handle >> 29;
}

always_inline u32
http_conn_index_from_handle (http_conn_handle_t hc_handle)
{
  return hc_handle & 0x1FFFFFFF;
}

always_inline http_conn_handle_t
http_make_handle (u32 hc_index, http_version_t version)
{
  ASSERT (hc_index <= 0x1FFFFFFF);
  return (version << 29) | hc_index;
}

int
http_v_find_index (u8 *vec, u32 offset, u32 num, char *str)
{
  int start_index = offset;
  u32 slen = (u32) strnlen_s_inline (str, 16);
  u32 vlen = vec_len (vec);

  ASSERT (slen > 0);

  if (vlen <= slen)
    return -1;

  int end_index = vlen - slen;
  if (num)
    {
      if (num < slen)
	return -1;
      end_index = clib_min (end_index, offset + num - slen);
    }

  for (; start_index <= end_index; start_index++)
    {
      if (!memcmp (vec + start_index, str, slen))
	return start_index;
    }

  return -1;
}

u8 *
format_http_req_state (u8 *s, va_list *va)
{
  http_req_state_t state = va_arg (*va, http_req_state_t);
  u8 *t = 0;

  switch (state)
    {
#define _(n, s, str)                                                          \
  case HTTP_REQ_STATE_##s:                                                    \
    t = (u8 *) str;                                                           \
    break;
      foreach_http_req_state
#undef _
	default : return format (s, "unknown");
    }
  return format (s, "%s", t);
}

u8 *
format_http_conn_state (u8 *s, va_list *args)
{
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  u8 *t = 0;

  switch (hc->state)
    {
#define _(s, str)                                                             \
  case HTTP_CONN_STATE_##s:                                                   \
    t = (u8 *) str;                                                           \
    break;
      foreach_http_conn_state
#undef _
	default : return format (s, "unknown");
    }
  return format (s, "%s", t);
}

u8 *
format_http_time_now (u8 *s, va_list *args)
{
  http_conn_t __clib_unused *hc = va_arg (*args, http_conn_t *);
  http_main_t *hm = &http_main;
  f64 now = clib_timebase_now (&hm->timebase);
  return format (s, "%U", format_clib_timebase_time, now);
}

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

  pool_get_aligned_safe (wrk->conn_pool, hc, CLIB_CACHE_LINE_BYTES);
  clib_memset (hc, 0, sizeof (*hc));
  hc->c_thread_index = thread_index;
  hc->h_hc_index = hc - wrk->conn_pool;
  hc->h_pa_session_handle = SESSION_INVALID_HANDLE;
  hc->h_tc_session_handle = SESSION_INVALID_HANDLE;
  hc->version = HTTP_VERSION_NA;
  return hc->h_hc_index;
}

static inline http_conn_t *
http_conn_get_w_thread (u32 hc_index, u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  return pool_elt_at_index (wrk->conn_pool, hc_index);
}

static inline http_conn_t *
http_conn_get_w_thread_if_valid (u32 hc_index, u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  if (pool_is_free_index (wrk->conn_pool, hc_index))
    return 0;
  return pool_elt_at_index (wrk->conn_pool, hc_index);
}

static void
http_conn_free (http_conn_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  if (CLIB_DEBUG)
    memset (hc, 0xba, sizeof (*hc));
  pool_put (wrk->conn_pool, hc);
}

static inline http_conn_t *
http_ho_conn_get (u32 ho_hc_index)
{
  http_main_t *hm = &http_main;
  return pool_elt_at_index (hm->ho_conn_pool, ho_hc_index);
}

static void
http_ho_conn_free (http_conn_t *ho_hc)
{
  http_main_t *hm = &http_main;
  if (CLIB_DEBUG)
    memset (ho_hc, 0xba, sizeof (*ho_hc));
  pool_put (hm->ho_conn_pool, ho_hc);
}

static inline u32
http_ho_conn_alloc (void)
{
  http_main_t *hm = &http_main;
  http_conn_t *hc;

  pool_get_aligned_safe (hm->ho_conn_pool, hc, CLIB_CACHE_LINE_BYTES);
  clib_memset (hc, 0, sizeof (*hc));
  hc->h_hc_index = hc - hm->ho_conn_pool;
  hc->h_pa_session_handle = SESSION_INVALID_HANDLE;
  hc->h_tc_session_handle = SESSION_INVALID_HANDLE;
  hc->timeout = HTTP_CONN_TIMEOUT;
  hc->version = HTTP_VERSION_NA;
  return hc->h_hc_index;
}

static u32
http_listener_alloc (void)
{
  http_main_t *hm = &http_main;
  http_conn_t *lhc;

  pool_get_zero (hm->listener_pool, lhc);
  lhc->h_hc_index = lhc - hm->listener_pool;
  lhc->timeout = HTTP_CONN_TIMEOUT;
  lhc->version = HTTP_VERSION_NA;
  return lhc->h_hc_index;
}

static http_conn_t *
http_listener_get (u32 lhc_index)
{
  return pool_elt_at_index (http_main.listener_pool, lhc_index);
}

static void
http_listener_free (http_conn_t *lhc)
{
  http_main_t *hm = &http_main;

  vec_free (lhc->app_name);
  if (CLIB_DEBUG)
    memset (lhc, 0xfc, sizeof (*lhc));
  pool_put (hm->listener_pool, lhc);
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

http_status_code_t
http_sc_by_u16 (u16 status_code)
{
  http_main_t *hm = &http_main;
  return hm->sc_by_u16[status_code];
}

u8 *
http_get_app_header_list (http_conn_t *hc, http_msg_t *msg)
{
  http_main_t *hm = &http_main;
  session_t *as;
  u8 *app_headers;
  int rv;

  as = session_get_from_handle (hc->h_pa_session_handle);

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
      app_headers = hm->app_header_lists[hc->c_thread_index];
      rv = svm_fifo_dequeue (as->tx_fifo, msg->data.headers_len, app_headers);
      ASSERT (rv == msg->data.headers_len);
    }

  return app_headers;
}

u8 *
http_get_app_target (http_req_t *req, http_msg_t *msg)
{
  session_t *as;
  u8 *target;
  int rv;

  as = session_get_from_handle (req->app_session_handle);

  if (msg->data.type == HTTP_MSG_DATA_PTR)
    {
      uword target_ptr;
      rv = svm_fifo_dequeue (as->tx_fifo, sizeof (target_ptr),
			     (u8 *) &target_ptr);
      ASSERT (rv == sizeof (target_ptr));
      target = uword_to_pointer (target_ptr, u8 *);
    }
  else
    {
      vec_reset_length (req->target);
      vec_validate (req->target, msg->data.target_path_len - 1);
      rv =
	svm_fifo_dequeue (as->tx_fifo, msg->data.target_path_len, req->target);
      ASSERT (rv == msg->data.target_path_len);
      target = req->target;
    }
  return target;
}

u8 *
http_get_tx_buf (http_conn_t *hc)
{
  http_main_t *hm = &http_main;
  u8 *buf = hm->tx_bufs[hc->c_thread_index];
  vec_reset_length (buf);
  return buf;
}

u8 *
http_get_rx_buf (http_conn_t *hc)
{
  http_main_t *hm = &http_main;
  u8 *buf = hm->rx_bufs[hc->c_thread_index];
  vec_reset_length (buf);
  return buf;
}

void
http_req_tx_buffer_init (http_req_t *req, http_msg_t *msg)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  http_buffer_init (&req->tx_buf, msg_to_buf_type[msg->data.type], as->tx_fifo,
		    msg->data.body_len);
}

static void
http_conn_invalidate_timer_cb (u32 hs_handle)
{
  http_conn_t *hc;

  hc =
    http_conn_get_w_thread_if_valid (hs_handle & 0x00FFFFFF, hs_handle >> 24);

  HTTP_DBG (1, "hc [%u]%x", hs_handle >> 24, hs_handle & 0x00FFFFFF);
  if (!hc)
    {
      HTTP_DBG (1, "already deleted");
      return;
    }

  hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
  hc->pending_timer = 1;
}

static void
http_conn_timeout_cb (void *hc_handlep)
{
  http_conn_t *hc;
  uword hs_handle;

  hs_handle = pointer_to_uword (hc_handlep);
  hc =
    http_conn_get_w_thread_if_valid (hs_handle & 0x00FFFFFF, hs_handle >> 24);

  HTTP_DBG (1, "hc [%u]%x", hs_handle >> 24, hs_handle & 0x00FFFFFF);
  if (!hc)
    {
      HTTP_DBG (1, "already deleted");
      return;
    }

  if (!hc->pending_timer)
    {
      HTTP_DBG (1, "timer not pending");
      return;
    }

  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);
}

/*************************/
/* session VFT callbacks */
/*************************/

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
  hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
  hc->c_thread_index = ts->thread_index;
  hc->h_hc_index = hc_index;

  hc->h_tc_session_handle = session_handle (ts);
  hc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  hc->state = HTTP_CONN_STATE_ESTABLISHED;

  ts->session_state = SESSION_STATE_READY;
  /* TODO: TLS set by ALPN result, TCP: first try HTTP/1 */
  hc->version = HTTP_VERSION_1;
  ts->opaque = http_make_handle (hc_index, hc->version);

  /*
   * Alloc session and initialize
   */
  as = session_alloc (hc->c_thread_index);
  hc->c_s_index = as->session_index;

  as->app_wrk_index = hc->h_pa_wrk_index;
  as->connection_index = hc->h_hc_index;
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
      hc->h_pa_session_handle = SESSION_INVALID_HANDLE;
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
  ts = session_get_from_handle (hc->h_tc_session_handle);
  thresh = clib_min (svm_fifo_size (ts->tx_fifo), HTTP_FIFO_THRESH);
  svm_fifo_set_deq_thresh (ts->tx_fifo, thresh);

  http_conn_timer_start (hc);

  return 0;
}

static int
http_ts_connected_callback (u32 http_app_index, u32 ho_hc_index, session_t *ts,
			    session_error_t err)
{
  u32 new_hc_index;
  session_t *as;
  http_conn_t *hc, *ho_hc;
  app_worker_t *app_wrk;
  int rv;

  ho_hc = http_ho_conn_get (ho_hc_index);
  ASSERT (ho_hc->state == HTTP_CONN_STATE_CONNECTING);

  if (err)
    {
      clib_warning ("half-open hc index %d, error: %U", ho_hc_index,
		    format_session_error, err);
      app_wrk = app_worker_get_if_valid (ho_hc->h_pa_wrk_index);
      if (app_wrk)
	app_worker_connect_notify (app_wrk, 0, err, ho_hc->h_pa_app_api_ctx);
      return 0;
    }

  new_hc_index = http_conn_alloc_w_thread (ts->thread_index);
  hc = http_conn_get_w_thread (new_hc_index, ts->thread_index);

  clib_memcpy_fast (hc, ho_hc, sizeof (*hc));

  hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
  hc->c_thread_index = ts->thread_index;
  hc->h_tc_session_handle = session_handle (ts);
  hc->h_hc_index = new_hc_index;
  hc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  hc->state = HTTP_CONN_STATE_ESTABLISHED;
  ts->session_state = SESSION_STATE_READY;
  /* TODO: TLS set by ALPN result, TCP: prior knowledge (set in ho) */
  ts->opaque = http_make_handle (new_hc_index, hc->version);

  /* allocate app session and initialize */

  as = session_alloc (hc->c_thread_index);
  hc->c_s_index = as->session_index;
  as->connection_index = new_hc_index;
  as->app_wrk_index = hc->h_pa_wrk_index;
  as->session_state = SESSION_STATE_READY;
  as->opaque = hc->h_pa_app_api_ctx;
  as->session_type = session_type_from_proto_and_ip (
    TRANSPORT_PROTO_HTTP, session_type_is_ip4 (ts->session_type));

  HTTP_DBG (1, "half-open hc index %x,  hc [%u]%x", ho_hc_index,
	    ts->thread_index, new_hc_index);

  app_wrk = app_worker_get (hc->h_pa_wrk_index);
  if (!app_wrk)
    {
      clib_warning ("no app worker");
      return -1;
    }

  if ((rv = app_worker_init_connected (app_wrk, as)))
    {
      HTTP_DBG (1, "failed to allocate fifos");
      session_free (as);
      return rv;
    }
  app_worker_connect_notify (app_wrk, as, err, hc->h_pa_app_api_ctx);
  hc->h_pa_session_handle = session_handle (as);
  http_conn_timer_start (hc);

  return 0;
}

static void
http_ts_disconnect_callback (session_t *ts)
{
  http_conn_t *hc;
  u32 hc_index = http_conn_index_from_handle (ts->opaque);

  HTTP_DBG (1, "hc [%u]%x", ts->thread_index, hc_index);

  hc = http_conn_get_w_thread (hc_index, ts->thread_index);

  if (hc->state < HTTP_CONN_STATE_TRANSPORT_CLOSED)
    hc->state = HTTP_CONN_STATE_TRANSPORT_CLOSED;

  http_vfts[hc->version].transport_close_callback (hc);
}

static void
http_ts_reset_callback (session_t *ts)
{
  http_conn_t *hc;
  u32 hc_index = http_conn_index_from_handle (ts->opaque);

  HTTP_DBG (1, "hc [%u]%x", ts->thread_index, hc_index);

  hc = http_conn_get_w_thread (hc_index, ts->thread_index);

  hc->state = HTTP_CONN_STATE_CLOSED;
  session_transport_reset_notify (&hc->connection);

  http_disconnect_transport (hc);
}

static int
http_ts_rx_callback (session_t *ts)
{
  http_conn_t *hc;
  u32 hc_index = http_conn_index_from_handle (ts->opaque);

  HTTP_DBG (1, "hc [%u]%x", ts->thread_index, hc_index);

  hc = http_conn_get_w_thread (hc_index, ts->thread_index);

  if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "conn closed");
      svm_fifo_dequeue_drop_all (ts->rx_fifo);
      return 0;
    }

  http_vfts[http_version_from_handle (ts->opaque)].transport_rx_callback (hc);

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

  hc = http_conn_get_w_thread (http_conn_index_from_handle (ts->opaque),
			       ts->thread_index);
  HTTP_DBG (1, "transport connection reschedule");
  transport_connection_reschedule (&hc->connection);

  return 0;
}

static void
http_ts_cleanup_callback (session_t *ts, session_cleanup_ntf_t ntf)
{
  http_conn_t *hc;
  http_req_t *req;
  u32 hc_index;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hc_index = http_conn_index_from_handle (ts->opaque);
  hc = http_conn_get_w_thread (hc_index, ts->thread_index);

  HTTP_DBG (1, "going to free hc [%u]%x", ts->thread_index, hc_index);

  pool_foreach (req, hc->req_pool)
    {
      vec_free (req->headers);
      vec_free (req->target);
      http_buffer_free (&req->tx_buf);
    }
  pool_free (hc->req_pool);

  if (hc->pending_timer == 0)
    http_conn_timer_stop (hc);

  session_transport_delete_notify (&hc->connection);

  if (!hc->is_server)
    {
      vec_free (hc->app_name);
      vec_free (hc->host);
    }
  http_conn_free (hc);
}

static void
http_ts_ho_cleanup_callback (session_t *ts)
{
  http_conn_t *ho_hc;
  u32 ho_hc_index = http_conn_index_from_handle (ts->opaque);
  HTTP_DBG (1, "half open: %x", ho_hc_index);
  ho_hc = http_ho_conn_get (ho_hc_index);
  session_half_open_delete_notify (&ho_hc->connection);
  http_ho_conn_free (ho_hc);
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
  .half_open_cleanup_callback = http_ts_ho_cleanup_callback,
  .add_segment_callback = http_add_segment_callback,
  .del_segment_callback = http_del_segment_callback,
  .builtin_app_rx_callback = http_ts_rx_callback,
  .builtin_app_tx_callback = http_ts_builtin_tx_callback,
};

/*********************************/
/* transport proto VFT callbacks */
/*********************************/

static clib_error_t *
http_transport_enable (vlib_main_t *vm, u8 is_en)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  http_main_t *hm = &http_main;
  u32 num_threads, i;

  if (!is_en)
    {
      da->app_index = hm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  num_threads = 1 /* main thread */ + vtm->n_threads;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &http_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "http");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = hm->first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = hm->add_seg_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = hm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = hm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    return clib_error_return (0, "failed to attach http app");

  hm->app_index = a->app_index;
  vec_free (a->name);

  if (hm->is_init)
    return 0;

  vec_validate (hm->wrk, num_threads - 1);
  vec_validate (hm->rx_bufs, num_threads - 1);
  vec_validate (hm->tx_bufs, num_threads - 1);
  vec_validate (hm->app_header_lists, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    {
      vec_validate (hm->rx_bufs[i],
		    HTTP_UDP_PAYLOAD_MAX_LEN +
		      HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD);
      vec_validate (hm->tx_bufs[i],
		    HTTP_UDP_PAYLOAD_MAX_LEN +
		      HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD);
      vec_validate (hm->app_header_lists[i], 32 << 10);
    }

  clib_timebase_init (&hm->timebase, 0 /* GMT */, CLIB_TIMEBASE_DAYLIGHT_NONE,
		      &vm->clib_time /* share the system clock */);

  http_timers_init (vm, http_conn_timeout_cb, http_conn_invalidate_timer_cb);
  hm->is_init = 1;

  return 0;
}

static int
http_transport_connect (transport_endpoint_cfg_t *tep)
{
  vnet_connect_args_t _cargs, *cargs = &_cargs;
  http_main_t *hm = &http_main;
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) tep;
  application_t *app;
  http_conn_t *hc;
  int error;
  u32 hc_index;
  session_t *ho;
  transport_endpt_ext_cfg_t *ext_cfg;
  app_worker_t *app_wrk = app_worker_get (sep->app_wrk_index);

  clib_memset (cargs, 0, sizeof (*cargs));
  clib_memcpy (&cargs->sep_ext, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_TCP;
  cargs->app_index = hm->app_index;
  app = application_get (app_wrk->app_index);
  cargs->sep_ext.ns_index = app->ns_index;

  hc_index = http_ho_conn_alloc ();
  hc = http_ho_conn_get (hc_index);
  hc->h_pa_wrk_index = sep->app_wrk_index;
  hc->h_pa_app_api_ctx = sep->opaque;
  hc->state = HTTP_CONN_STATE_CONNECTING;
  /* TODO: set to HTTP_VERSION_NA in case of TLS (when supported) */
  hc->version = HTTP_VERSION_1;
  cargs->api_context = hc_index;

  ext_cfg = session_endpoint_get_ext_cfg (sep, TRANSPORT_ENDPT_EXT_CFG_HTTP);
  if (ext_cfg)
    {
      transport_endpt_cfg_http_t *http_cfg =
	(transport_endpt_cfg_http_t *) ext_cfg->data;
      HTTP_DBG (1, "app set timeout %u", http_cfg->timeout);
      hc->timeout = http_cfg->timeout;
    }

  hc->is_server = 0;

  if (vec_len (app->name))
    hc->app_name = vec_dup (app->name);
  else
    hc->app_name = format (0, "VPP HTTP client");

  if (sep->is_ip4)
    hc->host = format (0, "%U:%d", format_ip4_address, &sep->ip.ip4,
		       clib_net_to_host_u16 (sep->port));
  else
    hc->host = format (0, "%U:%d", format_ip6_address, &sep->ip.ip6,
		       clib_net_to_host_u16 (sep->port));

  HTTP_DBG (1, "hc ho_index %x", hc_index);

  if ((error = vnet_connect (cargs)))
    return error;

  ho = session_alloc_for_half_open (&hc->connection);
  ho->app_wrk_index = app_wrk->wrk_index;
  ho->ho_index = app_worker_add_half_open (app_wrk, session_handle (ho));
  ho->opaque = sep->opaque;
  ho->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_HTTP, sep->is_ip4);
  hc->h_tc_session_handle = cargs->sh;
  hc->c_s_index = ho->session_index;

  return 0;
}

static u32
http_start_listen (u32 app_listener_index, transport_endpoint_cfg_t *tep)
{
  vnet_listen_args_t _args = {}, *args = &_args;
  session_t *ts_listener, *app_listener;
  http_main_t *hm = &http_main;
  session_endpoint_cfg_t *sep;
  app_worker_t *app_wrk;
  transport_proto_t tp = TRANSPORT_PROTO_TCP;
  app_listener_t *al;
  application_t *app;
  http_conn_t *lhc;
  u32 lhc_index;
  transport_endpt_ext_cfg_t *ext_cfg;

  sep = (session_endpoint_cfg_t *) tep;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  args->app_index = hm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;

  ext_cfg = session_endpoint_get_ext_cfg (sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
  if (ext_cfg)
    {
      HTTP_DBG (1, "app set tls");
      tp = TRANSPORT_PROTO_TLS;
    }
  args->sep_ext.transport_proto = tp;

  if (vnet_listen (args))
    return SESSION_INVALID_INDEX;

  lhc_index = http_listener_alloc ();
  lhc = http_listener_get (lhc_index);

  ext_cfg = session_endpoint_get_ext_cfg (sep, TRANSPORT_ENDPT_EXT_CFG_HTTP);
  if (ext_cfg && ext_cfg->opaque)
    {
      transport_endpt_cfg_http_t *http_cfg =
	(transport_endpt_cfg_http_t *) ext_cfg->data;
      HTTP_DBG (1, "app set timeout %u", http_cfg->timeout);
      lhc->timeout = http_cfg->timeout;
      lhc->udp_tunnel_mode = http_cfg->udp_tunnel_mode;
    }

  /* Grab transport connection listener and link to http listener */
  lhc->h_tc_session_handle = args->handle;
  al = app_listener_get_w_handle (lhc->h_tc_session_handle);
  ts_listener = app_listener_get_session (al);
  ts_listener->opaque = lhc_index;

  /* Grab application listener and link to http listener */
  app_listener = listen_session_get (app_listener_index);
  lhc->h_pa_wrk_index = sep->app_wrk_index;
  lhc->h_pa_session_handle = listen_session_get_handle (app_listener);
  lhc->c_s_index = app_listener_index;
  lhc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  lhc->is_server = 1;

  if (vec_len (app->name))
    lhc->app_name = vec_dup (app->name);
  else
    lhc->app_name = format (0, "VPP server app");

  return lhc_index;
}

static u32
http_stop_listen (u32 listener_index)
{
  http_conn_t *lhc;
  int rv;

  lhc = http_listener_get (listener_index);

  vnet_unlisten_args_t a = {
    .handle = lhc->h_tc_session_handle,
    .app_index = http_main.app_index,
    .wrk_map_index = 0 /* default wrk */
  };

  if ((rv = vnet_unlisten (&a)))
    clib_warning ("unlisten returned %d", rv);

  http_listener_free (lhc);

  return 0;
}

static void
http_transport_close (u32 hc_index, u32 thread_index)
{
  http_conn_t *hc;

  HTTP_DBG (1, "App disconnecting [%u]%x", thread_index, hc_index);

  hc = http_conn_get_w_thread (hc_index, thread_index);
  if (hc->state == HTTP_CONN_STATE_CONNECTING)
    {
      hc->state = HTTP_CONN_STATE_APP_CLOSED;
      http_disconnect_transport (hc);
      return;
    }
  else if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "nothing to do, already closed");
      return;
    }

  http_vfts[hc->version].app_close_callback (hc);
}

static void
http_transport_reset (u32 hc_index, u32 thread_index)
{
  http_conn_t *hc;

  HTTP_DBG (1, "App disconnecting [%u]%x", thread_index, hc_index);

  hc = http_conn_get_w_thread (hc_index, thread_index);
  if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "nothing to do, already closed");
      return;
    }

  http_vfts[hc->version].app_reset_callback (hc);
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
  u32 max_burst_sz, sent;
  http_conn_t *hc;

  HTTP_DBG (1, "hc [%u]%x", as->thread_index, as->connection_index);

  hc = http_conn_get_w_thread (as->connection_index, as->thread_index);

  if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      HTTP_DBG (1, "conn closed");
      svm_fifo_dequeue_drop_all (as->tx_fifo);
      return 0;
    }

  max_burst_sz = sp->max_burst_size * TRANSPORT_PACER_MIN_MSS;
  sp->max_burst_size = max_burst_sz;

  http_vfts[hc->version].app_tx_callback (hc, sp);

  if (hc->state == HTTP_CONN_STATE_APP_CLOSED)
    {
      if (!svm_fifo_max_dequeue_cons (as->tx_fifo))
	{
	  session_transport_closed_notify (&hc->connection);
	  http_disconnect_transport (hc);
	}
    }

  sent = max_burst_sz - sp->max_burst_size;

  return sent > 0 ? clib_max (sent / TRANSPORT_PACER_MIN_MSS, 1) : 0;
}

static int
http_app_rx_evt_cb (transport_connection_t *tc)
{
  http_conn_t *hc = (http_conn_t *) tc;
  HTTP_DBG (1, "hc [%u]%x", vlib_get_thread_index (), hc->h_hc_index);

  http_vfts[hc->version].app_rx_evt_callback (hc);

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

static u8 *
format_http_transport_half_open (u8 *s, va_list *args)
{
  u32 ho_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  http_conn_t *ho_hc;
  session_t *tcp_ho;

  ho_hc = http_ho_conn_get (ho_index);
  tcp_ho = session_get_from_handle (ho_hc->h_tc_session_handle);

  s = format (s, "[%d:%d][H] half-open app_wrk %u ts %d:%d",
	      ho_hc->c_thread_index, ho_hc->c_s_index, ho_hc->h_pa_wrk_index,
	      tcp_ho->thread_index, tcp_ho->session_index);
  return s;
}

static transport_connection_t *
http_transport_get_ho (u32 ho_hc_index)
{
  http_conn_t *ho_hc;

  HTTP_DBG (1, "half open: %x", ho_hc_index);
  ho_hc = http_ho_conn_get (ho_hc_index);
  return &ho_hc->connection;
}

static void
http_transport_cleanup_ho (u32 ho_hc_index)
{
  http_conn_t *ho_hc;

  HTTP_DBG (1, "half open: %x", ho_hc_index);
  ho_hc = http_ho_conn_get (ho_hc_index);
  session_cleanup_half_open (ho_hc->h_tc_session_handle);
  http_ho_conn_free (ho_hc);
}

static const transport_proto_vft_t http_proto = {
  .enable = http_transport_enable,
  .connect = http_transport_connect,
  .start_listen = http_start_listen,
  .stop_listen = http_stop_listen,
  .close = http_transport_close,
  .reset = http_transport_reset,
  .cleanup_ho = http_transport_cleanup_ho,
  .custom_tx = http_app_tx_callback,
  .app_rx_evt = http_app_rx_evt_cb,
  .get_connection = http_transport_get_connection,
  .get_listener = http_transport_get_listener,
  .get_half_open = http_transport_get_ho,
  .get_transport_endpoint = http_transport_get_endpoint,
  .format_connection = format_http_transport_connection,
  .format_listener = format_http_transport_listener,
  .format_half_open = format_http_transport_half_open,
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
  http_main_t *hm = &http_main;
  int i;

  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP6, ~0);

  /* Default values, configurable via startup conf */
  hm->add_seg_size = 256 << 20;
  hm->first_seg_size = 32 << 20;
  hm->fifo_size = 512 << 10;

  /* Setup u16 to http_status_code_t map */
  /* Unrecognized status code is equivalent to the x00 status */
  vec_validate (hm->sc_by_u16, 599);
  for (i = 100; i < 200; i++)
    hm->sc_by_u16[i] = HTTP_STATUS_CONTINUE;
  for (i = 200; i < 300; i++)
    hm->sc_by_u16[i] = HTTP_STATUS_OK;
  for (i = 300; i < 400; i++)
    hm->sc_by_u16[i] = HTTP_STATUS_MULTIPLE_CHOICES;
  for (i = 400; i < 500; i++)
    hm->sc_by_u16[i] = HTTP_STATUS_BAD_REQUEST;
  for (i = 500; i < 600; i++)
    hm->sc_by_u16[i] = HTTP_STATUS_INTERNAL_ERROR;

    /* Registered status codes */
#define _(c, s, str) hm->sc_by_u16[c] = HTTP_STATUS_##s;
  foreach_http_status_code
#undef _

    return 0;
}

VLIB_INIT_FUNCTION (http_transport_init);

static clib_error_t *
http_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  http_main_t *hm = &http_main;
  uword mem_sz;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "first-segment-size %U", unformat_memory_size,
		    &mem_sz))
	{
	  hm->first_seg_size = clib_max (mem_sz, 1 << 20);
	  if (hm->first_seg_size != mem_sz)
	    clib_warning ("first seg size too small %u", mem_sz);
	}
      else if (unformat (input, "add-segment-size %U", unformat_memory_size,
			 &mem_sz))
	{
	  hm->add_seg_size = clib_max (mem_sz, 1 << 20);
	  if (hm->add_seg_size != mem_sz)
	    clib_warning ("add seg size too small %u", mem_sz);
	}
      else if (unformat (input, "fifo-size %U", unformat_memory_size, &mem_sz))
	{
	  hm->fifo_size = clib_clamp (mem_sz, 4 << 10, 2 << 30);
	  if (hm->fifo_size != mem_sz)
	    clib_warning ("invalid fifo size %lu", mem_sz);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (http_config_fn, "http");

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
