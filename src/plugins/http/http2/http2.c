/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/llist.h>
#include <vppinfra/ring.h>
#include <http/http2/hpack.h>
#include <http/http2/frame.h>
#include <http/http_timer.h>
#include <http/http_status_codes.h>

#define HTTP2_WIN_SIZE_MAX     0x7FFFFFFF
#define HTTP2_INITIAL_WIN_SIZE 65535
/* connection-level flow control window kind of mirrors TCP flow control */
/* TODO: configurable? */
#define HTTP2_CONNECTION_WINDOW_SIZE (10 << 20)

typedef enum
{
  HTTP2_SCHED_WEIGHT_DATA_PTR = 1,
  HTTP2_SCHED_WEIGHT_HEADERS_CONTINUATION = 1,
  HTTP2_SCHED_WEIGHT_DATA_INLINE = 2,
  HTTP2_SCHED_WEIGHT_HEADERS_PTR = 3,
  HTTP2_SCHED_WEIGHT_HEADERS_INLINE = 4,
} http2_sched_weight_t;

#define HTTP2_SCHED_MAX_EMISSIONS 32

static http_token_t http2_ext_connect_proto[] = { { http_token_lit ("bug") },
#define _(sym, str) { http_token_lit (str) },
						  foreach_http_upgrade_proto
#undef _
};

typedef void (*http2_rx_expect_cb) (http_ctx_t *hc);

static void http2_update_time_callback (f64 now, u8 thread_index);

always_inline void
http2_send_client_preface (http_ctx_t *hc)
{
  u8 *response, *p;
  http2_settings_entry_t *setting, *settings_list = 0;

  response = http_get_tx_buf (hc);
  vec_add2 (response, p, http2_conn_preface.len);
  clib_memcpy_fast (p, http2_conn_preface.base, http2_conn_preface.len);

#define _(v, label, member, min, max, default_value, err_code, server, client)                     \
  if (hc->settings.member != (default_value) && (client))                                          \
    {                                                                                              \
      vec_add2 (settings_list, setting, 1);                                                        \
      setting->identifier = HTTP2_SETTINGS_##label;                                                \
      setting->value = hc->settings.member;                                                        \
    }
  foreach_http2_settings
#undef _

    http2_frame_write_settings (settings_list, &response);
  /* send also connection window update */
  http2_frame_write_window_update (hc->our_window - HTTP2_INITIAL_WIN_SIZE, 0, &response);
  http_io_ts_write (hc, response, vec_len (response), 0);
  http_io_ts_after_write (hc, 1);
  vec_free (settings_list);
}

static_always_inline void
http2_conn_init (http_ctx_t *hc, u8 is_client)
{
  http_main_t *hm = &http_main;
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *new_head, *old_head;
  u32 new_head_index, old_head_index, cnt, hc_index;
  clib_thread_index_t thread_index;

  hc->peer_settings = http2_default_conn_settings;
  hc->peer_window = HTTP2_INITIAL_WIN_SIZE;
  hc->our_window = HTTP2_CONNECTION_WINDOW_SIZE;
  hc->settings = hm->h2_settings;
  /* adjust settings according to app rx_fifo size */
  hc->settings.max_header_list_size =
    clib_min (hc->settings.max_header_list_size, (hc->hc_app_rx_fifo_size >> 1));
  hc->settings.initial_window_size =
    clib_min (hc->settings.initial_window_size,
	      (hc->hc_app_rx_fifo_size - hc->settings.max_header_list_size));
  hc->req_by_stream_id = hash_create (0, sizeof (uword));
  hc->hc_parent_req_index = SESSION_INVALID_INDEX;
  hc_index = hc->hc_hc_index;
  thread_index = hc->c_thread_index;
  new_head_index = http_ctx_alloc_w_thread (thread_index);
  old_head_index = http_ctx_alloc_w_thread (thread_index);
  new_head = http_ctx_get_w_thread (new_head_index, thread_index);
  old_head = http_ctx_get_w_thread (old_head_index, thread_index);
  /* pool grow, regrab connection */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  clib_llist_anchor_init (wrk->ctx_pool, stream_sched_list, new_head);
  hc->new_tx_streams = (clib_llist_index_t) (new_head_index);
  clib_llist_anchor_init (wrk->ctx_pool, stream_sched_list, old_head);
  hc->old_tx_streams = (clib_llist_index_t) (old_head_index);
  hc->sched_list.next = CLIB_LLIST_INVALID_INDEX;
  hc->sched_list.prev = CLIB_LLIST_INVALID_INDEX;
  cnt = wrk->h2_n_sessions++;
  /* (re)start stream tx scheduler if this is first connection */
  if (cnt == 0)
    session_register_update_time_fn_w_thread (http2_update_time_callback, 1, thread_index);
  if (is_client)
    {
      http2_send_client_preface (hc);
      hc->rx_expect = HTTP2_RX_EXPECT_SERVER_PREFACE;
    }
  else
    hc->rx_expect = HTTP2_RX_EXPECT_CLIENT_PREFACE;
}

static inline void
http2_conn_destroy (http_ctx_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u32 cnt;

  ASSERT (hc->hc_parent_req_index == SESSION_INVALID_INDEX);
  ASSERT (!clib_llist_elt_is_linked (hc, sched_list));
  ASSERT (hc->req_num == 0);
  http_ctx_free_w_index (hc->new_tx_streams, hc->c_thread_index);
  http_ctx_free_w_index (hc->old_tx_streams, hc->c_thread_index);
  hash_free (hc->req_by_stream_id);
  vec_free (hc->pending_win_updates);
  vec_free (hc->pending_rst_stream);
  if (hc->flags & HTTP_CONN_F_HAS_REQUEST)
    hpack_dynamic_table_free (&hc->decoder_dynamic_table);
  cnt = wrk->h2_n_sessions--;
  ASSERT (cnt > 0);
  /* stop stream tx scheduler if this was last active connection so we are not
   * running empty */
  if (cnt == 1)
    session_register_update_time_fn_w_thread (http2_update_time_callback, 0, hc->c_thread_index);
}

static inline http_ctx_t *
http2_conn_alloc_req (u32 hc_index, clib_thread_index_t thread_index, u8 is_parent)
{
  http_ctx_t *req, *hc;
  u32 req_index;
  http_req_handle_t hr_handle;

  req_index = http_ctx_alloc_w_thread (thread_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  req->c_s_index = SESSION_INVALID_INDEX;
  hr_handle.version = HTTP_VERSION_2;
  hr_handle.req_index = req_index;
  req->hr_req_handle = hr_handle.as_u32;
  req->hr_hc_index = hc->hc_hc_index;
  req->c_thread_index = hc->c_thread_index;
  req->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  req->stream_state = HTTP2_STREAM_STATE_IDLE;
  req->stream_sched_list.next = CLIB_LLIST_INVALID_INDEX;
  req->stream_sched_list.prev = CLIB_LLIST_INVALID_INDEX;
  HTTP_DBG (1, "hc [%u]%x req_index %x", hc->c_thread_index, hc->hc_hc_index, req_index);
  req->peer_stream_window = hc->peer_settings.initial_window_size;
  req->our_stream_window = hc->settings.initial_window_size;
  if (!(is_parent && hc->flags & HTTP_CONN_F_IS_SERVER))
    {
      hc->req_num++;
      http_stats_app_streams_opened_inc (hc->c_thread_index);
    }
  if (is_parent)
    {
      HTTP_DBG (1, "is parent");
      ASSERT (hc->hc_parent_req_index == SESSION_INVALID_INDEX);
      req->req_flags |= HTTP_REQ_F_IS_PARENT;
      hc->hc_parent_req_index = req_index;
    }
  return req;
}

static_always_inline void
http2_req_set_stream_id (http_ctx_t *req, http_ctx_t *hc, u32 stream_id, u8 unset_old)
{
  HTTP_DBG (1, "req_index [%u]%x stream_id %u", req->c_thread_index,
	    ((http_req_handle_t) req->hr_req_handle).req_index, stream_id);
  if (unset_old && req->stream_id)
    hash_unset (hc->req_by_stream_id, req->stream_id);
  req->stream_id = stream_id;
  hash_set (hc->req_by_stream_id, stream_id, ((http_req_handle_t) req->hr_req_handle).req_index);
}

static inline void
http2_conn_free_req (http_ctx_t *hc, http_ctx_t *req, clib_thread_index_t thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);

  HTTP_DBG (1, "h2c [%u]%x req_index %x stream_id %u", thread_index, hc->hc_hc_index,
	    ((http_req_handle_t) req->hr_req_handle).req_index, req->stream_id);
  if (clib_llist_elt_is_linked (req, stream_sched_list))
    clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
  vec_free (req->headers);
  vec_free (req->target);
  http_buffer_free (&req->tx_buf);
  if (req->stream_id)
    hash_unset (hc->req_by_stream_id, req->stream_id);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    hc->hc_parent_req_index = SESSION_INVALID_INDEX;
  if (!(hc->flags & HTTP_CONN_F_IS_SERVER && req->req_flags & HTTP_REQ_F_IS_PARENT))
    {
      hc->req_num--;
      http_stats_app_streams_closed_inc (thread_index);
    }
  http_ctx_free (req);
}

static inline void
http2_conn_reset_req (http_ctx_t *hc, http_ctx_t *req, clib_thread_index_t thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);

  if (clib_llist_elt_is_linked (req, stream_sched_list))
    clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
  http_buffer_free (&req->tx_buf);
  req->req_flags &= ~HTTP_REQ_F_NEED_WINDOW_UPDATE;
  req->stream_state = HTTP2_STREAM_STATE_IDLE;
  req->peer_stream_window = hc->peer_settings.initial_window_size;
  req->our_stream_window = hc->settings.initial_window_size;
}

http_ctx_t *
http2_conn_get_req (http_ctx_t *hc, u32 stream_id)
{
  uword *p;

  p = hash_get (hc->req_by_stream_id, stream_id);
  if (p)
    {
      return http_ctx_get_w_thread (p[0], hc->c_thread_index);
    }
  else
    {
      HTTP_DBG (1, "hc [%u]%x streamId %u not found", hc->c_thread_index,
		hc->hc_hc_index, stream_id);
      return 0;
    }
}

always_inline u32
http2_conn_get_next_stream_id (http_ctx_t *hc)
{
  if (hc->last_opened_stream_id)
    hc->last_opened_stream_id += 2;
  else
    hc->last_opened_stream_id = 1;
  return clib_host_to_net_u32 (hc->last_opened_stream_id);
}

always_inline void
http2_conn_schedule (http_ctx_t *hc, clib_thread_index_t thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  http_ctx_t *he;

  if (!clib_llist_elt_is_linked (hc, sched_list) && !(hc->flags & HTTP_CONN_F_TS_DESCHED))
    {
      he = clib_llist_elt (wrk->ctx_pool, wrk->sched_head);
      clib_llist_add_tail (wrk->ctx_pool, sched_list, hc, he);
    }
}

always_inline void
http2_req_schedule_data_tx (http_ctx_t *hc, http_ctx_t *req)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *he;

  ASSERT (!clib_llist_elt_is_linked (req, stream_sched_list));
  he = clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams);
  clib_llist_add_tail (wrk->ctx_pool, stream_sched_list, req, he);
}

always_inline int
http2_req_update_peer_window (http_ctx_t *hc, http_ctx_t *req, i64 delta)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  i64 new_value;

  new_value = (i64) req->peer_stream_window + delta;
  if (new_value > HTTP2_WIN_SIZE_MAX)
    return -1;
  req->peer_stream_window = (i32) new_value;
  HTTP_DBG (1, "new window size %ld", req->peer_stream_window);
  /* settings change can make stream window negative */
  if (req->peer_stream_window <= 0)
    {
      HTTP_DBG (1, "descheduling need stream window update");
      req->req_flags |= HTTP_REQ_F_NEED_WINDOW_UPDATE;
      if (clib_llist_elt_is_linked (req, stream_sched_list))
	clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      return 0;
    }
  if (req->req_flags & HTTP_REQ_F_NEED_WINDOW_UPDATE)
    {
      req->req_flags &= ~HTTP_REQ_F_NEED_WINDOW_UPDATE;
      http2_req_schedule_data_tx (hc, req);
      if (hc->peer_window > 0)
	http2_conn_schedule (hc, hc->c_thread_index);
    }
  return 0;
}

/* send GOAWAY frame and close TCP connection */
static void
http2_connection_error (http_ctx_t *hc, http2_error_t error, transport_send_params_t *sp)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u8 *response;
  u32 req_index, stream_id;
  http_ctx_t *req;
  app_worker_t *app_wrk;

  HTTP_DBG (1, "hc [%u]%x connection error %U (last streamId %u)", hc->c_thread_index,
	    hc->hc_hc_index, format_http2_error, error, hc->last_processed_stream_id);
  /* check if we have enough space in fifo, otherwise just close connection */
  if (http_io_ts_max_write (hc, 0) >= (HTTP2_FRAME_HEADER_SIZE + HTTP2_GOAWAY_MIN_SIZE))
    {
      response = http_get_tx_buf (hc);
      http2_frame_write_goaway (error, hc->last_processed_stream_id, &response);
      http_io_ts_write (hc, response, vec_len (response), sp);
      http_io_ts_after_write (hc, 1);
    }

  if (hc->flags & HTTP_CONN_F_IS_SERVER)
    {
      hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
		      req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
		      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
			session_transport_reset_notify (&req->connection);
		    }));
      if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
	{
	  req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
	  session_transport_reset_notify (&req->connection);
	}
    }
  else
    {
      if (hc->flags & HTTP_CONN_F_EXPECT_SERVER_SETTINGS)
	{
	  HTTP_DBG (1, "error before server preface received");
	  app_wrk = app_worker_get_if_valid (hc->hc_pa_wrk_index);
	  if (app_wrk)
	    app_worker_connect_notify (app_wrk, 0, SESSION_E_UNKNOWN,
				       hc->hc_pa_app_api_ctx);
	}
      else if (!(hc->flags & HTTP_CONN_F_NO_APP_SESSION))
	{
	  req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
	  session_transport_reset_notify (&req->connection);
	}
      else
	{
	  http_disconnect_transport (hc);
	  return;
	}
    }
  if (clib_llist_elt_is_linked (hc, sched_list))
    clib_llist_remove (wrk->ctx_pool, sched_list, hc);
  http_shutdown_transport (hc);
  http_stats_proto_errors_inc (hc->c_thread_index);
}

static void
http2_send_stream_error (http_ctx_t *hc, u32 stream_id, http2_error_t error,
			 transport_send_params_t *sp)
{
  u8 *response;
  http2_rst_stream_t *rst_stream;

  /* check if we have enough space in fifo */
  if (http_io_ts_max_write (hc, 0) < HTTP2_RST_STREAM_FRAME_SIZE)
    {
      HTTP_DBG (1, "transport fifo full postponing stream %d reset", stream_id);
      http_io_ts_add_want_deq_ntf (hc);
      vec_add2 (hc->pending_rst_stream, rst_stream, 1);
      rst_stream->stream_id = stream_id;
      rst_stream->error = error;
      return;
    }

  HTTP_DBG (1, "hc [%u]%x streamId %u error %U", hc->c_thread_index,
	    hc->hc_hc_index, stream_id, format_http2_error, error);
  response = http_get_tx_buf (hc);
  http2_frame_write_rst_stream (error, stream_id, &response);
  http_io_ts_write (hc, response, vec_len (response), sp);
  http_io_ts_after_write (hc, 1);
}

always_inline void
http2_tunnel_send_close (http_ctx_t *hc, http_ctx_t *req)
{
  u8 *response;

  response = http_get_tx_buf (hc);
  http2_frame_write_data_header (0, req->stream_id,
				 HTTP2_FRAME_FLAG_END_STREAM, response);
  http_io_ts_write (hc, response, HTTP2_FRAME_HEADER_SIZE, 0);
  http_io_ts_after_write (hc, 1);
}

/* send RST_STREAM frame and notify app */
static void
http2_stream_error (http_ctx_t *hc, http_ctx_t *req, http2_error_t error,
		    transport_send_params_t *sp)
{
  ASSERT (req->stream_state > HTTP2_STREAM_STATE_IDLE);

  http2_send_stream_error (hc, req->stream_id, error, sp);
  req->stream_state = HTTP2_STREAM_STATE_CLOSED;

  if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
    session_transport_reset_notify (&req->connection);
  session_transport_delete_notify (&req->connection);
  http2_conn_free_req (hc, req, hc->c_thread_index);
}

always_inline void
http2_stream_close (http_ctx_t *req, http_ctx_t *hc)
{
  req->stream_state = HTTP2_STREAM_STATE_CLOSED;
  if (req->req_flags & HTTP_REQ_F_APP_CLOSED)
    {
      HTTP_DBG (1, "req [%u]%x app already closed, confirm", req->c_thread_index,
		((http_req_handle_t) req->hr_req_handle).req_index);
      session_transport_closed_notify (&req->connection);
    }
  else
    {
      HTTP_DBG (1, "req [%u]%x all done closing, notify app", req->c_thread_index,
		((http_req_handle_t) req->hr_req_handle).req_index);
      session_transport_closing_notify (&req->connection);
    }

  session_transport_delete_notify (&req->connection);
  http2_conn_free_req (hc, req, hc->c_thread_index);
}

always_inline void
http2_send_window_update (http_ctx_t *hc, u32 increment, u32 stream_id)
{
  u8 *tx_buf;

  tx_buf = http_get_tx_buf (hc);
  http2_frame_write_window_update (increment, stream_id, &tx_buf);
  http_io_ts_write (hc, tx_buf, vec_len (tx_buf), 0);
  http_io_ts_after_write (hc, 1);
}

always_inline u32
http2_req_get_win_increment (http_ctx_t *req, http_ctx_t *hc)
{
  u32 increment;
  u32 max_write = http_io_as_max_write (req);

  /* keep some space for dgram headers */
  if ((req->req_flags & HTTP_REQ_F_IS_TUNNEL) && (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM))
    {
      max_write = max_write >> 1;
      if (max_write <= req->our_stream_window)
	return 0;
    }
  ASSERT (max_write >= req->our_stream_window);
  increment = max_write - req->our_stream_window;
  HTTP_DBG (1, "stream %u window increment %u", req->stream_id, increment);
  ASSERT ((req->our_stream_window + increment) <= HTTP2_WIN_SIZE_MAX);
  return increment;
}

always_inline void
http2_send_server_preface (http_ctx_t *hc)
{
  u8 *response;
  http2_settings_entry_t *setting, *settings_list = 0;

#define _(v, label, member, min, max, default_value, err_code, server, client)                     \
  if (hc->settings.member != (default_value) && (server))                                          \
    {                                                                                              \
      vec_add2 (settings_list, setting, 1);                                                        \
      setting->identifier = HTTP2_SETTINGS_##label;                                                \
      setting->value = hc->settings.member;                                                        \
    }
  foreach_http2_settings
#undef _

    response = http_get_tx_buf (hc);
  http2_frame_write_settings (settings_list, &response);
  /* send also connection window update */
  http2_frame_write_window_update (hc->our_window - HTTP2_INITIAL_WIN_SIZE, 0, &response);
  http_io_ts_write (hc, response, vec_len (response), 0);
  http_io_ts_after_write (hc, 1);
  vec_free (settings_list);
}

/***********************/
/* stream TX scheduler */
/***********************/

static void
http2_sched_dispatch_data (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions)
{
  u32 max_write, n_segs, n_read, n_written = 0;
  u64 max_read;
  svm_fifo_seg_t *app_segs, *segs = 0;
  http_buffer_t *hb = &req->tx_buf;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  u8 finished = 0, flags = 0;

  ASSERT (http_buffer_bytes_left (hb) > 0);

  *n_emissions += hb->type == HTTP_BUFFER_PTR ? HTTP2_SCHED_WEIGHT_DATA_PTR :
						HTTP2_SCHED_WEIGHT_DATA_INLINE;

  max_write = http_io_ts_max_write (hc, 0);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, (u32) req->peer_stream_window);
  max_write = clib_min (max_write, hc->peer_window);
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  max_read = http_buffer_bytes_left (hb);

  n_read = http_buffer_get_segs (hb, max_write, &app_segs, &n_segs);
  if (n_read == 0)
    {
      HTTP_DBG (1, "no data to deq");
      transport_connection_reschedule (&req->connection);
      return;
    }

  finished = (max_read - n_read) == 0;
  flags = finished ? HTTP2_FRAME_FLAG_END_STREAM : 0;
  http2_frame_write_data_header (n_read, req->stream_id, flags, fh);
  vec_validate (segs, 0);
  segs[0].len = HTTP2_FRAME_HEADER_SIZE;
  segs[0].data = fh;
  vec_append (segs, app_segs);

  n_written = http_io_ts_write_segs (hc, segs, n_segs + 1, 0);
  n_written -= HTTP2_FRAME_HEADER_SIZE;
  vec_free (segs);
  http_buffer_drain (hb, n_written);
  req->peer_stream_window -= (i32) n_written;
  hc->peer_window -= n_written;

  if (finished)
    {
      /* all done, close stream */
      http_buffer_free (hb);
      if (hc->flags & HTTP_CONN_F_IS_SERVER)
	http2_stream_close (req, hc);
      else
	{
	  req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	}
    }
  else
    {
      http_io_as_dequeue_notify (req, n_written);
      if (req->peer_stream_window == 0)
	{
	  /* mark that we need window update on stream */
	  HTTP_DBG (1, "stream window is full");
	  req->req_flags |= HTTP_REQ_F_NEED_WINDOW_UPDATE;
	}
      else
	{
	  /* schedule for next round */
	  HTTP_DBG (1, "adding to data queue req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  http2_req_schedule_data_tx (hc, req);
	}
    }

  http_io_ts_after_write (hc, finished);
}

static void
http2_sched_dispatch_tunnel (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions)
{
  u32 max_write, max_read, n_segs = 2, n_read, n_written = 0;
  svm_fifo_seg_t segs[n_segs + 1];
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  u8 flags = 0;

  *n_emissions += HTTP2_SCHED_WEIGHT_DATA_INLINE;

  max_read = http_io_as_max_read (req);
  if (max_read == 0)
    {
      HTTP_DBG (2, "max_read == 0");
      if (req->req_flags & HTTP_REQ_F_APP_CLOSED &&
	  req->stream_state == HTTP2_STREAM_STATE_HALF_CLOSED)
	{
	  HTTP_DBG (1, "closing tunnel");
	  http2_tunnel_send_close (hc, req);
	  http2_stream_close (req, hc);
	  return;
	}
      transport_connection_reschedule (&req->connection);
      return;
    }
  if (req->peer_stream_window == 0)
    {
      /* mark that we need window update on stream */
      HTTP_DBG (1, "stream window is full");
      req->req_flags |= HTTP_REQ_F_NEED_WINDOW_UPDATE;
      return;
    }
  max_write = http_io_ts_max_write (hc, 0);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, (u32) req->peer_stream_window);
  max_write = clib_min (max_write, hc->peer_window);
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  if ((req->req_flags & HTTP_REQ_F_APP_CLOSED) && (max_write >= max_read))
    flags = HTTP2_FRAME_FLAG_END_STREAM;

  max_read = clib_min (max_write, max_read);
  n_read = http_io_as_read_segs (req, segs + 1, &n_segs, max_read);

  http2_frame_write_data_header (n_read, req->stream_id, flags, fh);
  segs[0].len = HTTP2_FRAME_HEADER_SIZE;
  segs[0].data = fh;

  n_written = http_io_ts_write_segs (hc, segs, n_segs + 1, 0);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + n_read));
  n_written -= HTTP2_FRAME_HEADER_SIZE;
  http_io_as_drain (req, n_written);
  req->peer_stream_window -= (i32) n_written;
  hc->peer_window -= n_written;
  HTTP_DBG (1, "written %lu", n_written);

  if (max_read - n_written)
    {
      /* schedule for next round if we have more data */
      HTTP_DBG (1, "adding to data queue req_index %x",
		((http_req_handle_t) req->hr_req_handle).req_index);
      http2_req_schedule_data_tx (hc, req);
    }
  else
    transport_connection_reschedule (&req->connection);

  http_io_as_dequeue_notify (req, n_written);
  http_io_ts_after_write (hc, 0);

  if (flags & HTTP2_FRAME_FLAG_END_STREAM)
    {
      switch (req->stream_state)
	{
	case HTTP2_STREAM_STATE_OPEN:
	  HTTP_DBG (1, "tunnel half-closed");
	  req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
	  break;
	case HTTP2_STREAM_STATE_HALF_CLOSED:
	  HTTP_DBG (1, "tunnel closed");
	  http2_stream_close (req, hc);
	  break;
	default:
	  ASSERT (0);
	  break;
	}
    }
}

static_always_inline void
http2_sched_dispatch_udp_tunnel_inline (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions,
					u8 is_draft03)
{
  u32 dgram_size, max_write, max_read, n_written, n_read = 0, frame_size = 0, n_segs = 1,
						  n_app_segs = 5, n_deq = 0;
  session_dgram_hdr_t hdr;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  u8 *capsule_hdr_end;
  svm_fifo_seg_t segs[2 + n_app_segs];

  if (req->req_flags & HTTP_REQ_F_NEED_WINDOW_UPDATE)
    return;

  *n_emissions += HTTP2_SCHED_WEIGHT_DATA_INLINE;
  max_write = http_io_ts_max_write (hc, 0);
  /* we always keep free space in underlying transport fifo */
  ASSERT (max_write > HTTP2_FRAME_HEADER_SIZE);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  /* DATA frame size is limited only by SETTINGS_MAX_FRAME_SIZE and connection window, stream level
   * window check is done before we start sending capsule (this is not prohibited by RFC9113, we are
   * able to select any algorithm that suits our needs) */
  max_write = clib_min (max_write, hc->peer_window);
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  max_read = http_io_as_max_read (req);

  switch (req->capsule_ctx_tx.state)
    {
    case HTTP_CAPSULE_STATE_START:
      /* read datagram header */
      if (max_read < sizeof (hdr))
	{
	  HTTP_DBG (2, "max_read < session dgram hdr");
	  transport_connection_reschedule (&req->connection);
	  return;
	}
      http_io_as_peek (req, (u8 *) &hdr, sizeof (hdr), 0);
      HTTP_DBG (1, "datagram len %lu", hdr.data_length);
      ASSERT (hdr.data_length <= HTTP_UDP_PAYLOAD_MAX_LEN);
      dgram_size = hdr.data_length + SESSION_CONN_HDR_LEN;
      if (PREDICT_FALSE (max_read < dgram_size))
	{
	  HTTP_DBG (2, "datagram incomplete");
	  transport_connection_reschedule (&req->connection);
	  return;
	}
      /* check stream level window */
      if (req->peer_stream_window < (hdr.data_length + HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD))
	{
	  HTTP_DBG (1, "not enough space in stream window (%lu) for capsule",
		    req->peer_stream_window);
	  /* mark that we need window update on stream */
	  req->req_flags |= HTTP_REQ_F_NEED_WINDOW_UPDATE;
	  return;
	}
      http_io_as_drain (req, sizeof (hdr));
      n_deq += sizeof (hdr);
      max_read -= sizeof (hdr);
      /* create capsule header */
      capsule_hdr_end =
	http_encap_udp_payload_datagram (req->capsule_header_tx, hdr.data_length, is_draft03);
      req->capsule_ctx_tx.hdr_left = capsule_hdr_end - req->capsule_header_tx;
      req->capsule_ctx_tx.payload_left = hdr.data_length;
      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_HEADER;
      /* now we can start building frame(s) */
      __attribute__ ((fallthrough));
    case HTTP_CAPSULE_STATE_HEADER:
      ASSERT (max_write);
      frame_size += clib_min (req->capsule_ctx_tx.hdr_left, max_write);
      segs[n_segs].data = req->capsule_header_tx + req->capsule_ctx_tx.hdr_offset;
      segs[n_segs].len = frame_size;
      n_segs++;
      /* can we send full capsule header? */
      if (PREDICT_FALSE (frame_size < req->capsule_ctx_tx.hdr_left))
	{
	  req->capsule_ctx_tx.hdr_left -= frame_size;
	  req->capsule_ctx_tx.hdr_offset += req->capsule_ctx_tx.hdr_left;
	  break;
	}
      req->capsule_ctx_tx.hdr_left = 0;
      req->capsule_ctx_tx.hdr_offset = 0;
      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_PAYLOAD;
      max_write -= frame_size;
      if (PREDICT_FALSE (max_write == 0))
	break;
      /* we have some space for payload */
      __attribute__ ((fallthrough));
    case HTTP_CAPSULE_STATE_PAYLOAD:
      ASSERT (max_read);
      ASSERT (req->capsule_ctx_tx.payload_left);
      /* read app data */
      n_read = http_io_as_read_segs (req, segs + n_segs, &n_app_segs,
				     clib_min (req->capsule_ctx_tx.payload_left, max_write));
      n_segs += n_app_segs;
      frame_size += n_read;
      n_deq += n_read;
      max_read -= n_read;
      if (PREDICT_FALSE (n_read < req->capsule_ctx_tx.payload_left))
	{
	  req->capsule_ctx_tx.payload_left -= n_read;
	  break;
	}
      req->capsule_ctx_tx.payload_left = 0;
      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_START;
#if CLIB_DEBUG > 0
      break;
    default:
      clib_warning ("unknown state, bug");
      ASSERT (0);
      break;
#endif
    }

  /* create frame header */
  http2_frame_write_data_header (frame_size, req->stream_id, 0, fh);
  segs[0].len = HTTP2_FRAME_HEADER_SIZE;
  segs[0].data = fh;
  n_written = http_io_ts_write_segs (hc, segs, n_segs, 0);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + frame_size));

  if (PREDICT_TRUE (n_read))
    http_io_as_drain (req, n_read);
  if (PREDICT_TRUE (n_deq))
    http_io_as_dequeue_notify (req, n_deq);

  req->peer_stream_window -= (i32) frame_size;
  hc->peer_window -= frame_size;

  if (max_read)
    {
      /* schedule for next round if we have more data */
      HTTP_DBG (1, "adding to data queue req_index %x",
		((http_req_handle_t) req->hr_req_handle).req_index);
      http2_req_schedule_data_tx (hc, req);
    }
  else
    transport_connection_reschedule (&req->connection);

  http_io_ts_after_write (hc, 0);
}

static void
http2_sched_dispatch_udp_tunnel (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions)
{
  http2_sched_dispatch_udp_tunnel_inline (req, hc, n_emissions, 0);
}

static void
http2_sched_dispatch_udp_tunnel_draft03 (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions)
{
  http2_sched_dispatch_udp_tunnel_inline (req, hc, n_emissions, 1);
}

static void
http2_sched_dispatch_continuation (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions,
				   clib_llist_index_t *next_ri)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  u8 flags = 0;
  u32 n_written, stream_id, max_write, headers_len, headers_left;

  *n_emissions += HTTP2_SCHED_WEIGHT_HEADERS_CONTINUATION;

  max_write = http_io_ts_max_write (hc, 0);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  stream_id = req->stream_id;

  ASSERT (vec_len (hc->unsent_headers) > hc->unsent_headers_offset);
  headers_left = vec_len (hc->unsent_headers) - hc->unsent_headers_offset;
  headers_len = clib_min (max_write, headers_left);
  flags |= (headers_len == headers_left) ? HTTP2_FRAME_FLAG_END_HEADERS : 0;
  http2_frame_write_continuation_header (headers_len, stream_id, flags, fh);
  svm_fifo_seg_t segs[2] = { { fh, HTTP2_FRAME_HEADER_SIZE },
			     { hc->unsent_headers + hc->unsent_headers_offset, headers_len } };
  n_written = http_io_ts_write_segs (hc, segs, 2, 0);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + headers_len));
  http_io_ts_after_write (hc, 0);

  if (headers_len == headers_left)
    {
      HTTP_DBG (1, "sent last headers fragment");
      vec_free (hc->unsent_headers);
      *next_ri = clib_llist_next_index (req, stream_sched_list);
      clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      if (http_buffer_bytes_left (&req->tx_buf))
	{
	  /* start sending the actual data */
	  req->dispatch_data_cb = http2_sched_dispatch_data;
	  HTTP_DBG (1, "adding to data queue req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  http2_req_schedule_data_tx (hc, req);
	}
      else
	{
	  if (hc->flags & HTTP_CONN_F_IS_SERVER)
	    http2_stream_close (req, hc);
	  else
	    {
	      req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
	      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	    }
	}
    }
  else
    {
      HTTP_DBG (1, "need another headers fragment");
      *next_ri = clib_llist_entry_index (wrk->ctx_pool, req);
      hc->unsent_headers_offset += headers_len;
    }
}

static void
http_sched_dispatch_431 (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions,
			 clib_llist_index_t *next_ri)
{
  u8 *response, *date;
  u32 headers_len;
  hpack_response_control_data_t control_data;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];

  *n_emissions += HTTP2_SCHED_WEIGHT_HEADERS_PTR;
  *next_ri = clib_llist_next_index (req, stream_sched_list);
  response = http_get_tx_buf (hc);
  date = format (0, "%U", format_http_time_now, hc);
  control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  control_data.server_name = hc->app_name;
  control_data.server_name_len = vec_len (hc->app_name);
  control_data.date = date;
  control_data.date_len = vec_len (date);
  control_data.sc = HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
  hpack_serialize_response (0, 0, &control_data, &response);
  vec_free (date);
  headers_len = vec_len (response);
  http2_frame_write_headers_header (headers_len, req->stream_id,
				    HTTP2_FRAME_FLAG_END_HEADERS | HTTP2_FRAME_FLAG_END_STREAM, fh);
  svm_fifo_seg_t segs[2] = { { fh, HTTP2_FRAME_HEADER_SIZE }, { response, headers_len } };
  http_io_ts_write_segs (hc, segs, 2, 0);
  http_io_ts_after_write (hc, 0);
  http_stats_responses_sent_inc (hc->c_thread_index);
  /* notify app that nothing will happen and free request */
  if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
    session_transport_reset_notify (&req->connection);
  session_transport_delete_notify (&req->connection);
  http2_conn_free_req (hc, req, hc->c_thread_index);
}

static void
http2_sched_dispatch_resp_headers (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions,
				   clib_llist_index_t *next_ri)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_msg_t msg;
  u8 *response, *date, *app_headers = 0;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  hpack_response_control_data_t control_data;
  u8 flags = 0;
  u32 n_written, stream_id, n_deq, max_write, headers_len, headers_left;

  http_get_app_msg (req, &msg);
  ASSERT (msg.type == HTTP_MSG_REPLY);
  n_deq = sizeof (msg);
  *n_emissions += msg.data.type == HTTP_MSG_DATA_PTR ?
		    HTTP2_SCHED_WEIGHT_HEADERS_PTR :
		    HTTP2_SCHED_WEIGHT_HEADERS_INLINE;

  response = http_get_tx_buf (hc);
  date = format (0, "%U", format_http_time_now, hc);

  control_data.content_len = msg.data.body_len;
  control_data.server_name = hc->app_name;
  control_data.server_name_len = vec_len (hc->app_name);
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
	  break;
	default:
	  /* tunnel not established */
	  req->req_flags &= ~HTTP_REQ_F_IS_TUNNEL;
	  break;
	}
    }
  control_data.sc = msg.code;

  if (msg.data.headers_len)
    {
      n_deq += msg.data.type == HTTP_MSG_DATA_PTR ? sizeof (uword) :
						    msg.data.headers_len;
      app_headers = http_get_app_header_list (req, &msg);
    }

  hpack_serialize_response (app_headers, msg.data.headers_len, &control_data,
			    &response);
  vec_free (date);
  headers_len = vec_len (response);

  max_write = http_io_ts_max_write (hc, 0);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  stream_id = req->stream_id;

  /* END_STREAM flag need to be set in HEADERS frame */
  if (msg.data.body_len)
    {
      ASSERT (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL));
      http_req_tx_buffer_init (req, &msg);
      http_io_as_dequeue_notify (req, n_deq);
    }
  else
    flags |= (req->req_flags & HTTP_REQ_F_IS_TUNNEL) ? 0 : HTTP2_FRAME_FLAG_END_STREAM;

  if (headers_len <= max_write)
    {
      *next_ri = clib_llist_next_index (req, stream_sched_list);
      clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      flags |= HTTP2_FRAME_FLAG_END_HEADERS;
      if (msg.data.body_len)
	{
	  /* start sending the actual data */
	  req->dispatch_data_cb = http2_sched_dispatch_data;
	  HTTP_DBG (1, "adding to data queue req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  http2_req_schedule_data_tx (hc, req);
	}
      else if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
	{
	  if ((req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
	       (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)) ||
	      (req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03))
	    {
	      req->dispatch_data_cb = (req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03) ?
					http2_sched_dispatch_udp_tunnel_draft03 :
					http2_sched_dispatch_udp_tunnel;
	      req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	      req->capsule_ctx_rx.len = 0;
	      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_START;
	      req->capsule_ctx_tx.hdr_left = 0;
	      req->capsule_ctx_tx.hdr_offset = 0;
	      req->capsule_ctx_tx.payload_left = 0;
	    }
	  else
	    req->dispatch_data_cb = http2_sched_dispatch_tunnel;
	  transport_connection_reschedule (&req->connection);
	  /* cleanup some stuff we don't need anymore in tunnel mode */
	  vec_free (req->headers);
	}
      else
	{
	  /* otherwise we are done */
	  http2_stream_close (req, hc);
	}
    }
  else
    {
      /* we need to send CONTINUATION frame as next */
      HTTP_DBG (1, "response headers need to be fragmented");
      *next_ri = clib_llist_entry_index (wrk->ctx_pool, req);
      headers_len = max_write;
      headers_left = vec_len (response) - headers_len;
      req->dispatch_headers_cb = http2_sched_dispatch_continuation;
      /* move unsend portion of headers to connection ctx */
      ASSERT (hc->unsent_headers == 0);
      vec_validate (hc->unsent_headers, headers_left - 1);
      clib_memcpy_fast (hc->unsent_headers, response + headers_len, headers_left);
      hc->unsent_headers_offset = 0;
      *n_emissions += HTTP2_SCHED_WEIGHT_HEADERS_CONTINUATION;
    }

  http2_frame_write_headers_header (headers_len, stream_id, flags, fh);
  svm_fifo_seg_t segs[2] = { { fh, HTTP2_FRAME_HEADER_SIZE },
			     { response, headers_len } };
  n_written = http_io_ts_write_segs (hc, segs, 2, 0);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + headers_len));
  http_io_ts_after_write (hc, 0);
  http_stats_responses_sent_inc (hc->c_thread_index);
}

static void
http2_sched_dispatch_req_headers (http_ctx_t *req, http_ctx_t *hc, u8 *n_emissions,
				  clib_llist_index_t *next_ri)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_msg_t msg;
  u8 *request, *app_headers = 0;
  u8 fh[HTTP2_FRAME_HEADER_SIZE];
  hpack_request_control_data_t control_data;
  u8 flags = 0;
  u32 n_written, n_deq, max_write, headers_len, headers_left;

  req->stream_state = HTTP2_STREAM_STATE_OPEN;

  http_get_app_msg (req, &msg);
  ASSERT (msg.type == HTTP_MSG_REQUEST);
  n_deq = sizeof (msg);
  *n_emissions += msg.data.type == HTTP_MSG_DATA_PTR ?
		    HTTP2_SCHED_WEIGHT_HEADERS_PTR :
		    HTTP2_SCHED_WEIGHT_HEADERS_INLINE;

  request = http_get_tx_buf (hc);

  control_data.method = msg.method_type;
  control_data.parsed_bitmap = HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  if (msg.method_type == HTTP_REQ_CONNECT || msg.method_type == HTTP_REQ_CONNECT_UDP)
    {
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->dispatch_data_cb = http2_sched_dispatch_tunnel;
      req->upgrade_proto = msg.data.upgrade_proto;
      if (msg.data.upgrade_proto != HTTP_UPGRADE_PROTO_NA)
	{
	  if (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM)
	    {
	      req->dispatch_data_cb = http2_sched_dispatch_udp_tunnel;
	      req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	      req->capsule_ctx_rx.len = 0;
	      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_START;
	      req->capsule_ctx_tx.hdr_left = 0;
	      req->capsule_ctx_tx.hdr_offset = 0;
	      req->capsule_ctx_tx.payload_left = 0;
	    }
	  control_data.authority = hc->host;
	  control_data.authority_len = vec_len (hc->host);
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_SCHEME_PARSED;
	  control_data.scheme =
	    http_get_transport_proto (hc) == TRANSPORT_PROTO_TLS ?
	      HTTP_URL_SCHEME_HTTPS :
	      HTTP_URL_SCHEME_HTTP;
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
	  control_data.path = http_get_app_target (req, &msg);
	  control_data.path_len = msg.data.target_path_len;
	  control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PROTOCOL_PARSED;
	  control_data.protocol =
	    (u8 *) http2_ext_connect_proto[msg.data.upgrade_proto].base;
	  control_data.protocol_len =
	    http2_ext_connect_proto[msg.data.upgrade_proto].len;
	  HTTP_DBG (1, "extended connect %s %U",
		    http2_ext_connect_proto[msg.data.upgrade_proto].base,
		    format_http_bytes, control_data.path,
		    control_data.path_len);
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
	      req->dispatch_data_cb = http2_sched_dispatch_udp_tunnel_draft03;
	      req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	      req->capsule_ctx_rx.len = 0;
	      req->capsule_ctx_tx.state = HTTP_CAPSULE_STATE_START;
	      req->capsule_ctx_tx.hdr_left = 0;
	      req->capsule_ctx_tx.hdr_offset = 0;
	      req->capsule_ctx_tx.payload_left = 0;
	    }
	}
    }
  else
    {
      control_data.authority = hc->host;
      control_data.authority_len = vec_len (hc->host);
      control_data.parsed_bitmap = HPACK_PSEUDO_HEADER_SCHEME_PARSED;
      control_data.scheme =
	http_get_transport_proto (hc) == TRANSPORT_PROTO_TLS ?
	  HTTP_URL_SCHEME_HTTPS :
	  HTTP_URL_SCHEME_HTTP;
      control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
      control_data.path = http_get_app_target (req, &msg);
      control_data.path_len = msg.data.target_path_len;
      HTTP_DBG (1, "%U %U", format_http_method, control_data.method,
		format_http_bytes, control_data.path, control_data.path_len);
    }
  control_data.user_agent = hc->app_name;
  control_data.user_agent_len = vec_len (hc->app_name);

  if (msg.data.headers_len)
    {
      n_deq += msg.data.type == HTTP_MSG_DATA_PTR ? sizeof (uword) :
						    msg.data.headers_len;
      app_headers = http_get_app_header_list (req, &msg);
    }

  if (msg.data.body_len)
    {
      control_data.content_len = msg.data.body_len;
      http_req_tx_buffer_init (req, &msg);
    }
  else
    {
      control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
      flags |= (req->req_flags & HTTP_REQ_F_IS_TUNNEL) ? 0 : HTTP2_FRAME_FLAG_END_STREAM;
    }

  hpack_serialize_request (app_headers, msg.data.headers_len, &control_data,
			   &request);
  headers_len = vec_len (request);

  max_write = http_io_ts_max_write (hc, 0);
  max_write -= HTTP2_FRAME_HEADER_SIZE;
  max_write = clib_min (max_write, hc->peer_settings.max_frame_size);

  http_io_as_dequeue_notify (req, n_deq);

  if (headers_len <= max_write)
    {
      *next_ri = clib_llist_next_index (req, stream_sched_list);
      clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      flags |= HTTP2_FRAME_FLAG_END_HEADERS;
      if (msg.data.body_len)
	{
	  /* start sending the actual data */
	  req->dispatch_data_cb = http2_sched_dispatch_data;
	  HTTP_DBG (1, "adding to data queue req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  http2_req_schedule_data_tx (hc, req);
	}
      else
	{
	  if (!(req->req_flags & HTTP_REQ_F_IS_TUNNEL))
	    req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	}
    }
  else
    {
      /* we need to send CONTINUATION frame as next */
      HTTP_DBG (1, "response headers need to be fragmented");
      *next_ri = clib_llist_entry_index (wrk->ctx_pool, req);
      headers_len = max_write;
      headers_left = vec_len (request) - headers_len;
      req->dispatch_headers_cb = http2_sched_dispatch_continuation;
      /* move unsend portion of headers to connection ctx */
      ASSERT (hc->unsent_headers == 0);
      vec_validate (hc->unsent_headers, headers_left - 1);
      clib_memcpy_fast (hc->unsent_headers, request + headers_len, headers_left);
      hc->unsent_headers_offset = 0;
      *n_emissions += HTTP2_SCHED_WEIGHT_HEADERS_CONTINUATION;
    }

  http2_frame_write_headers_header (headers_len, req->stream_id, flags, fh);
  svm_fifo_seg_t segs[2] = { { fh, HTTP2_FRAME_HEADER_SIZE },
			     { request, headers_len } };
  n_written = http_io_ts_write_segs (hc, segs, 2, 0);
  ASSERT (n_written == (HTTP2_FRAME_HEADER_SIZE + headers_len));
  http_io_ts_after_write (hc, 0);
  http_stats_requests_sent_inc (hc->c_thread_index);
}

static void
http2_update_time_callback (f64 now, u8 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  http_ctx_t *hc;
  http_ctx_t *req, *new_he, *old_he;
  clib_llist_index_t ri, ci;
  u8 n_emissions = 0;

  /*
   * Run stream tx scheduler, we want to run for short time each heart-beat, so
   * only one stream is processed with cap on frames emission. Since not all
   * frames are equal, from CPU cycles or memory copy perspective, different
   * weights are assigned when incrementing emissions counter. In most of cases
   * connection is schedule only if it will be able to send data, same applies
   * to streams within connection.
   */
  ci = clib_llist_next_index (clib_llist_elt (wrk->ctx_pool, wrk->sched_head), sched_list);
  if (ci != wrk->sched_head)
    {
      hc = clib_llist_elt (wrk->ctx_pool, ci);
      ASSERT (!(hc->flags & HTTP_CONN_F_TS_DESCHED));
      ASSERT (hc->flags & HTTP_CONN_F_HAS_REQUEST);
      clib_llist_remove (wrk->ctx_pool, sched_list, hc);

      /* first handle new responses (headers frame) */
      new_he = clib_llist_elt (wrk->ctx_pool, hc->new_tx_streams);
      ri = clib_llist_next_index (new_he, stream_sched_list);
      while (ri != hc->new_tx_streams && !http_io_ts_check_write_thresh (hc) &&
	     n_emissions < HTTP2_SCHED_MAX_EMISSIONS)
	{
	  req = clib_llist_elt (wrk->ctx_pool, ri);
	  HTTP_DBG (1, "sending headers req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  req->dispatch_headers_cb (req, hc, &n_emissions, &ri);
	}

      /* handle old responses (data frames), if we had any prior to processing
       * new ones, each stream tx one frame for now */
      /* TODO RFC9218 Prioritization (urgency will be weight) */
      old_he = clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams);
      ri = clib_llist_next_index (old_he, stream_sched_list);
      while (ri != hc->old_tx_streams && !http_io_ts_check_write_thresh (hc) &&
	     hc->peer_window > 0 && n_emissions < HTTP2_SCHED_MAX_EMISSIONS)
	{
	  req = clib_llist_elt (wrk->ctx_pool, ri);
	  HTTP_DBG (1, "sending data req_index %x",
		    ((http_req_handle_t) req->hr_req_handle).req_index);
	  clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
	  req->dispatch_data_cb (req, hc, &n_emissions);
	  ri = clib_llist_next_index (old_he, stream_sched_list);
	}
      /* deschedule http connection and wait for deq notification if underlying
       * transport session tx fifo is almost full */
      if (http_io_ts_check_write_thresh (hc))
	{
	  hc->flags |= HTTP_CONN_F_TS_DESCHED;
	  http_io_ts_add_want_deq_ntf (hc);
	  if (clib_llist_elt_is_linked (hc, sched_list))
	    clib_llist_remove (wrk->ctx_pool, sched_list, hc);
	  return;
	}
      /* reschedule connection if something is waiting in queue */
      if (!clib_llist_is_empty (wrk->ctx_pool, stream_sched_list, new_he) ||
	  !clib_llist_is_empty (wrk->ctx_pool, stream_sched_list, old_he))
	http2_conn_schedule (hc, hc->c_thread_index);
    }
}

/*************************************/
/* request state machine handlers RX */
/*************************************/

static http_sm_result_t
http2_req_state_wait_transport_reply (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				      http2_error_t *error)
{
  hpack_response_control_data_t control_data;
  http_msg_t msg;
  int rv;
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_METHOD;

  http_stats_responses_received_inc (hc->c_thread_index);

  vec_reset_length (req->headers);
  *error = hpack_parse_response (req->payload, req->payload_len, wrk->header_list,
				 hc->settings.max_header_list_size, &control_data, &req->headers,
				 &hc->decoder_dynamic_table);
  if (*error != HTTP2_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "hpack_parse_response failed");
      return HTTP_SM_ERROR;
    }

  HTTP_DBG (1, "decompressed headers size %u", control_data.headers_len);
  HTTP_DBG (1, "dynamic table size %u", hc->decoder_dynamic_table.used);

  req->control_data_len = control_data.control_data_len;
  req->headers_offset = control_data.headers - wrk->header_list;
  req->headers_len = control_data.headers_len;
  req->status_code = control_data.sc;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_STATUS_PARSED))
    {
      HTTP_DBG (1, ":status pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }

  if ((req->req_flags & HTTP_REQ_F_IS_TUNNEL) && http_status_code_str[req->status_code][0] == '2')
    {
      if (req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
	  (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM))
	new_state = HTTP_REQ_STATE_UDP_TUNNEL;
      else if (req->req_flags & HTTP_REQ_F_CONNECT_UDP_DRAFT03)
	new_state = HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03;
      else
	new_state = HTTP_REQ_STATE_TUNNEL;
      http_io_as_add_want_read_ntf (req);
      transport_connection_reschedule (&req->connection);
      /* cleanup some stuff we don't need anymore in tunnel mode */
      vec_free (req->headers);
    }
  else if (control_data.content_len_header_index != ~0)
    {
      req->content_len_header_index = control_data.content_len_header_index;
      rv = http_parse_content_length (req, wrk->header_list);
      if (rv)
	{
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      http_io_as_add_want_read_ntf (req);
    }
  else
    {
      /* we are done wait for the next app request */
      transport_connection_reschedule (&req->connection);
      http2_conn_reset_req (hc, req, hc->c_thread_index);
    }

  /* TODO: message framing without content length using END_STREAM flag */
  if (req->body_len == 0 && req->stream_state == HTTP2_STREAM_STATE_HALF_CLOSED &&
      !(req->req_flags & HTTP_REQ_F_IS_TUNNEL))
    {
      HTTP_DBG (1, "no content-length and DATA frame expected");
      *error = HTTP2_ERROR_INTERNAL_ERROR;
      return HTTP_SM_ERROR;
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
  http_app_worker_rx_notify (req);
  http_req_state_change (req, new_state);

  return HTTP_SM_STOP;
}

#define http2_verify_port_in_authority()                                                           \
  do                                                                                               \
    {                                                                                              \
      p = control_data.authority + control_data.authority_len;                                     \
      p--;                                                                                         \
      if (!isdigit (*p))                                                                           \
	{                                                                                          \
	  HTTP_DBG (1, "port not present in authority");                                           \
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);                            \
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
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);                            \
	  return HTTP_SM_STOP;                                                                     \
	}                                                                                          \
    }                                                                                              \
  while (0);

static http_sm_result_t
http2_req_state_wait_transport_method (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				       http2_error_t *error)
{
  hpack_request_control_data_t control_data;
  http_msg_t msg;
  u8 *p;
  int rv;
  http_req_state_t new_state = HTTP_REQ_STATE_WAIT_APP_REPLY;
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *he;

  http_stats_requests_received_inc (hc->c_thread_index);

  *error = hpack_parse_request (req->payload, req->payload_len, wrk->header_list,
				hc->settings.max_header_list_size, &control_data, &req->headers,
				&hc->decoder_dynamic_table);
  if (*error != HTTP2_ERROR_NO_ERROR)
    {
      /* internal error is returned only when uncompressed headers exceeded maximum value, in this
       * case we should response with 431 (Request Header Fields Too Large) status code */
      if (*error == HTTP2_ERROR_INTERNAL_ERROR)
	{
	  HTTP_DBG (1, "MAX_HEADER_LIST_SIZE exceeded");
	  *error = HTTP2_ERROR_NO_ERROR;
	  req->dispatch_headers_cb = http_sched_dispatch_431;
	  /* in case we receive data meanwhile */
	  http_req_state_change (req, HTTP_REQ_STATE_TRANSPORT_IO_DROP);
	  /* schedule response */
	  he = clib_llist_elt (wrk->ctx_pool, hc->new_tx_streams);
	  clib_llist_add_tail (wrk->ctx_pool, stream_sched_list, req, he);
	  http2_conn_schedule (hc, hc->c_thread_index);
	  return HTTP_SM_STOP;
	}
      HTTP_DBG (1, "hpack_parse_request failed");
      return HTTP_SM_ERROR;
    }

  HTTP_DBG (1, "decompressed headers size %u", control_data.headers_len);
  HTTP_DBG (1, "dynamic table size %u", hc->decoder_dynamic_table.used);

  req->control_data_len = control_data.control_data_len;
  req->headers_offset = control_data.headers - wrk->header_list;
  req->headers_len = control_data.headers_len;

  req->app_reply_next_state = HTTP_REQ_STATE_APP_IO_MORE_DATA;

  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_METHOD_PARSED))
    {
      HTTP_DBG (1, ":method pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_UNKNOWN)
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
  if (control_data.scheme == HTTP_URL_SCHEME_UNKNOWN && control_data.method != HTTP_REQ_CONNECT)
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
  if (!(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_AUTHORITY_PARSED))
    {
      HTTP_DBG (1, ":authority pseudo-header missing in request");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (control_data.method == HTTP_REQ_CONNECT)
    {
      req->app_reply_next_state = HTTP_REQ_STATE_TUNNEL;
      if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PROTOCOL_PARSED)
	{
	  /* extended CONNECT (RFC8441) */
	  if (!(control_data.parsed_bitmap &
		HPACK_PSEUDO_HEADER_SCHEME_PARSED) ||
	      !(control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED))
	    {
	      HTTP_DBG (1,
			":scheme and :path pseudo-header must be present for "
			"extended CONNECT method");
	      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
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
	    HTTP_DBG (1, "unsupported extended connect protocol %U",
		      format_http_bytes, control_data.protocol,
		      control_data.protocol_len);
	    http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
	    return HTTP_SM_STOP;
	  }
	  if (req->upgrade_proto == HTTP_UPGRADE_PROTO_CONNECT_UDP &&
	      (hc->flags & HTTP_CONN_F_UDP_TUNNEL_DGRAM))
	    req->app_reply_next_state = HTTP_REQ_STATE_UDP_TUNNEL;
	}
      else
	{
	  if (control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_SCHEME_PARSED ||
	      control_data.parsed_bitmap & HPACK_PSEUDO_HEADER_PATH_PARSED)
	    {
	      HTTP_DBG (1,
			":scheme and :path pseudo-header must be omitted for "
			"CONNECT method");
	      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	      return HTTP_SM_STOP;
	    }
	  /* quick check if port is present */
	  http2_verify_port_in_authority ();
	  req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
	}

      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      http_io_as_add_want_read_ntf (req);
    }
  else if (control_data.method == HTTP_REQ_CONNECT_UDP)
    {
      if (!(hc->flags & HTTP_CONN_F_CONNECT_UDP_DRAFT03))
	{
	  HTTP_DBG (1, "CONNECT-UDP method but masque-connect-udp-draft-03 not enabled");
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	  return HTTP_SM_STOP;
	}
      /* quick check if port is present */
      http2_verify_port_in_authority ();
      req->req_flags |= HTTP_REQ_F_IS_TUNNEL;
      req->req_flags |= HTTP_REQ_F_CONNECT_UDP_DRAFT03;
      req->app_reply_next_state = HTTP_REQ_STATE_UDP_TUNNEL_DRAFT03;
      req->upgrade_proto = HTTP_UPGRADE_PROTO_NA;
      http_io_as_add_want_read_ntf (req);
    }

  if (control_data.content_len_header_index != ~0)
    {
      req->content_len_header_index = control_data.content_len_header_index;
      rv = http_parse_content_length (req, wrk->header_list);
      if (rv)
	{
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	  return HTTP_SM_STOP;
	}
      new_state = HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA;
      http_io_as_add_want_read_ntf (req);
    }
  /* TODO: message framing without content length using END_STREAM flag */
  if (req->body_len == 0 && req->stream_state == HTTP2_STREAM_STATE_OPEN &&
      (control_data.method != HTTP_REQ_CONNECT && control_data.method != HTTP_REQ_CONNECT_UDP))
    {
      HTTP_DBG (1, "no content-length and DATA frame expected");
      *error = HTTP2_ERROR_INTERNAL_ERROR;
      return HTTP_SM_ERROR;
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

  if (req->stream_id > hc->last_processed_stream_id)
    hc->last_processed_stream_id = req->stream_id;

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_transport_io_drop (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				   http2_error_t *error)
{
  ASSERT (hc->flags & HTTP_CONN_F_IS_SERVER);
  /* nothing to do here we just want drop data */
  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_transport_io_more_data (http_ctx_t *hc, http_ctx_t *req,
					transport_send_params_t *sp, http2_error_t *error)
{
  u32 max_enq;
  http2_stream_state_t expected_state;

  if (req->payload_len > req->to_recv)
    {
      HTTP_DBG (1, "received more data than expected");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  req->to_recv -= req->payload_len;
  expected_state = hc->flags & HTTP_CONN_F_IS_SERVER ?
		     HTTP2_STREAM_STATE_HALF_CLOSED :
		     HTTP2_STREAM_STATE_CLOSED;
  if (req->stream_state == expected_state && req->to_recv != 0)
    {
      HTTP_DBG (1, "peer closed stream but don't send all data");
      http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  max_enq = http_io_as_max_write (req);
  if (max_enq < req->payload_len)
    {
      clib_warning ("app's rx fifo full");
      http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  if (req->to_recv == 0)
    {
      if (hc->flags & HTTP_CONN_F_IS_SERVER)
	{
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  /* we are done wait for the next app request */
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
	  transport_connection_reschedule (&req->connection);
	  http2_conn_reset_req (hc, req, hc->c_thread_index);
	  http_io_as_del_want_read_ntf (req);
	}
    }
  http_io_as_write (req, req->payload, req->payload_len);
  http_app_worker_rx_notify (req);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_tunnel_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
			   http2_error_t *error)
{
  u32 max_enq;

  HTTP_DBG (1, "tunnel received data from peer %lu", req->payload_len);
  if (req->req_flags & HTTP_REQ_F_APP_CLOSED && !(req->req_flags & HTTP_REQ_F_SHUTDOWN_TUNNEL))
    {
      HTTP_DBG (1, "proxy app closed, going to reset stream");
      http2_stream_error (hc, req, HTTP2_ERROR_CONNECT_ERROR, sp);
      return HTTP_SM_STOP;
    }

  max_enq = http_io_as_max_write (req);
  if (max_enq < req->payload_len)
    {
      clib_warning ("not enough space in app fifo (%lu)", max_enq);
      http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
      return HTTP_SM_STOP;
    }
  http_io_as_write (req, req->payload, req->payload_len);
  http_app_worker_rx_notify (req);

  switch (req->stream_state)
    {
    case HTTP2_STREAM_STATE_HALF_CLOSED:
      HTTP_DBG (1, "peer want to close tunnel");
      session_transport_closing_notify (&req->connection);
      break;
    case HTTP2_STREAM_STATE_CLOSED:
      HTTP_DBG (1, "peer closed tunnel");
      http2_stream_close (req, hc);
      break;
    default:
      break;
    }

  return HTTP_SM_STOP;
}

static_always_inline http_sm_result_t
http2_req_state_udp_tunnel_rx_inline (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				      http2_error_t *error, u8 is_draft03)
{
  http_capsule_error_t rv;
  u8 payload_offset = 0;
  u64 payload_len = 0;
  session_dgram_hdr_t hdr;
  svm_fifo_seg_t segs[2];
  u8 n_segs = 0;
  u32 frame_left = req->payload_len, payload_enq = 0;

  HTTP_DBG (1, "udp tunnel received data from peer");

  /* according to RFC9297 section 3.1. this is "data stream" which consists of all bytes sent in
   * DATA frames, so capsule can span multiple DATA frames */
start:
  switch (req->capsule_ctx_rx.state)
    {
    case HTTP_CAPSULE_STATE_HEADER:
      ASSERT (sizeof (req->capsule_header_rx) > req->capsule_ctx_rx.len);
      /* store capsule header in request ctx to handle case when it spans multiple frames */
      clib_memcpy_fast (
	req->capsule_header_rx + req->capsule_ctx_rx.len, req->payload,
	clib_min (sizeof (req->capsule_header_rx) - req->capsule_ctx_rx.len, req->payload_len));
      rv = http_decap_udp_payload_datagram (req->capsule_header_rx,
					    req->capsule_ctx_rx.len + frame_left, &payload_offset,
					    &payload_len, is_draft03);
      ASSERT (payload_offset <= HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD);
      switch (rv)
	{
	case HTTP_CAPSULE_NO_ERROR:
	  HTTP_DBG (1, "payload_offset=%u, payload_len=%llu", payload_offset, payload_len);
	  req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_PAYLOAD;
	  break;
	case HTTP_CAPSULE_INVALID:
	  /* capsule datagram is invalid (stream need to be aborted) */
	  HTTP_DBG (1, "invalid capsule");
	  http2_stream_error (hc, req, HTTP2_ERROR_PROTOCOL_ERROR, sp);
	  return HTTP_SM_STOP;
	case HTTP_CAPSULE_INCOMPLETE:
	  /* capsule header is incomplete we are done for now */
	  HTTP_DBG (1, "capsule header not complete");
	  req->capsule_ctx_rx.len += req->payload_len;
	  goto check_fin;
	case HTTP_CAPSULE_SKIP:
	  /* unknow capsule type, just drop bytes */
	  HTTP_DBG (1, "unknown capsule, byte to skip %llu", payload_len);
	  req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_SKIP;
	  req->capsule_ctx_rx.len = payload_len - req->capsule_ctx_rx.len;
	  goto start;
	}
      ASSERT (payload_offset > req->capsule_ctx_rx.len);
      payload_offset -= req->capsule_ctx_rx.len;
      frame_left -= payload_offset;
      req->capsule_ctx_rx.len = payload_len;
      /* enqueue session dgram header */
      hdr.data_length = payload_len;
      hdr.data_offset = 0;
      hdr.gso_size = 0;
      segs[n_segs].data = (u8 *) &hdr;
      segs[n_segs].len = sizeof (hdr);
      n_segs++;
      if (frame_left == 0)
	break;
      /* we have also some payload bytes, continue processiong */
      __attribute__ ((fallthrough));
    case HTTP_CAPSULE_STATE_PAYLOAD:
      /* check if we have the full capsule */
      if (frame_left >= req->capsule_ctx_rx.len)
	{
	  payload_enq = req->capsule_ctx_rx.len;
	  frame_left -= payload_enq;
	  /* restart state for the next capsule */
	  req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	  req->capsule_ctx_rx.len = 0;
	}
      else
	{
	  /* enqueue what what we have now and wait for the next frame on our stream */
	  HTTP_DBG (1, "capsule payload not complete");
	  req->capsule_ctx_rx.len -= frame_left;
	  payload_enq = frame_left;
	  frame_left = 0;
	}
      ASSERT (payload_enq);
      segs[n_segs].data = req->payload + payload_offset;
      segs[n_segs].len = payload_enq;
      n_segs++;
      break;
    case HTTP_CAPSULE_STATE_SKIP:
      /* check if we have the full capsule */
      if (frame_left >= req->capsule_ctx_rx.len)
	{
	  frame_left -= req->capsule_ctx_rx.len;
	  /* restart state for the next capsule */
	  req->capsule_ctx_rx.state = HTTP_CAPSULE_STATE_HEADER;
	  req->capsule_ctx_rx.len = 0;
	  if (frame_left)
	    goto start;
	}
      else
	{
	  /* track remaining bytes */
	  req->capsule_ctx_rx.len -= frame_left;
	}
      return HTTP_SM_STOP;
    default:
      clib_warning ("unknown state, bug");
      ASSERT (0);
      break;
    }

  if (http_io_as_max_write (req) < (sizeof (hdr) + payload_enq))
    {
      /* should only happen when we don't keep enough space for dgram hdr */
      HTTP_DBG (1, "not enough space in app fifo (%lu) for dgram (%lu)", http_io_as_max_write (req),
		sizeof (hdr) + payload_len);
      http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
      return HTTP_SM_STOP;
    }

  http_io_as_write_segs (req, segs, n_segs);
  http_app_worker_rx_notify (req);

  if (frame_left)
    goto start;

check_fin:
  if (req->stream_state == HTTP2_STREAM_STATE_HALF_CLOSED)
    {
      HTTP_DBG (1, "peer want to close tunnel");
      session_transport_closing_notify (&req->connection);
    }

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_udp_tunnel_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
			       http2_error_t *error)
{
  return http2_req_state_udp_tunnel_rx_inline (hc, req, sp, error, 0);
}

static http_sm_result_t
http2_req_state_udp_tunnel_draft03_rx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				       http2_error_t *error)
{
  return http2_req_state_udp_tunnel_rx_inline (hc, req, sp, error, 1);
}

/*************************************/
/* request state machine handlers TX */
/*************************************/

static http_sm_result_t
http2_req_state_wait_app_reply (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				http2_error_t *error)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *he;

  ASSERT (!clib_llist_elt_is_linked (req, stream_sched_list));

  /* add response to stream scheduler */
  HTTP_DBG (1, "adding to headers queue req_index %x",
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  he = clib_llist_elt (wrk->ctx_pool, hc->new_tx_streams);
  clib_llist_add_tail (wrk->ctx_pool, stream_sched_list, req, he);
  http2_conn_schedule (hc, hc->c_thread_index);

  http_req_state_change (req, req->app_reply_next_state);
  http_req_deschedule (req, sp);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_app_io_more_data (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				  http2_error_t *error)
{
  ASSERT (!clib_llist_elt_is_linked (req, stream_sched_list));

  /* add data back to stream scheduler */
  HTTP_DBG (1, "adding to data queue req_index %x",
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  http2_req_schedule_data_tx (hc, req);
  if (hc->peer_window > 0)
    http2_conn_schedule (hc, hc->c_thread_index);

  http_req_deschedule (req, sp);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_wait_app_method (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
				 http2_error_t *error)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *he;

  ASSERT (!clib_llist_elt_is_linked (req, stream_sched_list));

  /* add response to stream scheduler */
  HTTP_DBG (1, "adding to headers queue req_index %x",
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  he = clib_llist_elt (wrk->ctx_pool, hc->new_tx_streams);
  clib_llist_add_tail (wrk->ctx_pool, stream_sched_list, req, he);
  http2_conn_schedule (hc, hc->c_thread_index);

  u32 stream_id = http2_conn_get_next_stream_id (hc);
  http2_req_set_stream_id (req, hc, stream_id, 1);

  req->dispatch_headers_cb = http2_sched_dispatch_req_headers;
  http_req_state_change (req, HTTP_REQ_STATE_APP_IO_MORE_DATA);
  http_req_deschedule (req, sp);

  return HTTP_SM_STOP;
}

static http_sm_result_t
http2_req_state_tunnel_tx (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp,
			   http2_error_t *error)
{
  HTTP_DBG (1, "tunnel received data from app");

  /* zero-copy proxy app can program new tx event before we were able to send
   * previous payload, because fifos are shared, UDP/TCP clears evt on rx and
   * proxy app program new tx evt for http */
  if (clib_llist_elt_is_linked (req, stream_sched_list))
    {
      http_req_deschedule (req, sp);
      return HTTP_SM_STOP;
    }

  /* add data back to stream scheduler */
  HTTP_DBG (1, "adding to data queue req_index %x",
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  http2_req_schedule_data_tx (hc, req);
  if (hc->peer_window > 0)
    http2_conn_schedule (hc, hc->c_thread_index);

  http_req_deschedule (req, sp);

  return HTTP_SM_STOP;
}

/*************************/
/* request state machine */
/*************************/

typedef http_sm_result_t (*http2_sm_handler) (http_ctx_t *hc, http_ctx_t *req,
					      transport_send_params_t *sp, http2_error_t *error);

static http2_sm_handler tx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  http2_req_state_wait_app_method,
  0, /* wait transport reply */
  0, /* transport io more data */
  0, /* wait transport method */
  http2_req_state_wait_app_reply,
  http2_req_state_app_io_more_data,
  http2_req_state_tunnel_tx, /* we use different scheduler data dispatch cb */
  http2_req_state_tunnel_tx, /* we use different scheduler data dispatch cb */
  http2_req_state_tunnel_tx, /* we use different scheduler data dispatch cb */
  0,			     /* app io more streaming data */
  0,			     /* transport io drop */
};

static http2_sm_handler rx_state_funcs[HTTP_REQ_N_STATES] = {
  0, /* idle */
  0, /* wait app method */
  http2_req_state_wait_transport_reply,
  http2_req_state_transport_io_more_data,
  http2_req_state_wait_transport_method,
  0, /* wait app reply */
  0, /* app io more data */
  http2_req_state_tunnel_rx,
  http2_req_state_udp_tunnel_rx,
  http2_req_state_udp_tunnel_draft03_rx,
  0, /* app io more streaming data */
  http2_req_state_transport_io_drop,
};

static_always_inline int
http2_req_state_is_tx_valid (http_ctx_t *req)
{
  return tx_state_funcs[req->req_state] ? 1 : 0;
}

static_always_inline int
http2_req_state_is_rx_valid (http_ctx_t *req)
{
  return rx_state_funcs[req->req_state] ? 1 : 0;
}

static_always_inline http2_error_t
http2_req_run_state_machine (http_ctx_t *hc, http_ctx_t *req, transport_send_params_t *sp, u8 is_tx)
{
  http_sm_result_t res;
  http2_error_t error;

  do
    {
      if (is_tx)
	res = tx_state_funcs[req->req_state](hc, req, sp, &error);
      else
	res = rx_state_funcs[req->req_state](hc, req, 0, &error);

      if (res == HTTP_SM_ERROR)
	{
	  HTTP_DBG (1, "protocol error %U", format_http2_error, error);
	  return error;
	}
    }
  while (res == HTTP_SM_CONTINUE);

  return HTTP2_ERROR_NO_ERROR;
}

/******************/
/* frame handlers */
/******************/

static http2_error_t
http2_handle_headers_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  http_ctx_t *req;
  u8 *rx_buf, *headers_start;
  u32 headers_len, stream_id_ho;
  uword n_del, n_dec;
  http2_error_t rv;

  if (fh->length < 1)
    {
      HTTP_DBG (1, "zero length payload");
      return HTTP2_ERROR_FRAME_SIZE_ERROR;
    }

  if (hc->flags & HTTP_CONN_F_IS_SERVER)
    {
      stream_id_ho = clib_net_to_host_u32 (fh->stream_id);
      /* streams initiated by client must use odd-numbered stream id */
      if ((stream_id_ho & 1) == 0)
	{
	  HTTP_DBG (1, "invalid stream id %u", stream_id_ho);
	  return HTTP2_ERROR_PROTOCOL_ERROR;
	}
      /* stream id must be greater than all streams that client has opened */
      if (stream_id_ho <= hc->last_opened_stream_id)
	{
	  HTTP_DBG (1, "closed stream id %u", stream_id_ho);
	  return HTTP2_ERROR_STREAM_CLOSED;
	}
      hc->last_opened_stream_id = stream_id_ho;
      if (hc->req_num == hc->settings.max_concurrent_streams)
	{
	  HTTP_DBG (1, "SETTINGS_MAX_CONCURRENT_STREAMS exceeded");
	  http_io_ts_drain (hc, fh->length);
	  http2_send_stream_error (hc, fh->stream_id,
				   HTTP2_ERROR_REFUSED_STREAM, 0);
	  return HTTP2_ERROR_NO_ERROR;
	}
      u32 hc_index = hc->hc_hc_index;
      clib_thread_index_t thread_index = hc->c_thread_index;
      req = http2_conn_alloc_req (hc_index, thread_index, 0);
      /* pool grow, regrab connection */
      hc = http_ctx_get_w_thread (hc_index, thread_index);
      http2_req_set_stream_id (req, hc, fh->stream_id, 0);
      req->dispatch_headers_cb = http2_sched_dispatch_resp_headers;
      if (http_conn_accept_request (hc, req, 1))
	{
	  http2_conn_free_req (hc, req, hc->c_thread_index);
	  return HTTP2_ERROR_INTERNAL_ERROR;
	}
      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);
      req->stream_state = HTTP2_STREAM_STATE_OPEN;
      if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
	{
	  hc->flags |= HTTP_CONN_F_HAS_REQUEST;
	  hpack_dynamic_table_init (&hc->decoder_dynamic_table,
				    http2_default_conn_settings.header_table_size);
	}
      if (fh->flags & HTTP2_FRAME_FLAG_END_STREAM)
	req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;

      if (!(fh->flags & HTTP2_FRAME_FLAG_END_HEADERS))
	{
	  HTTP_DBG (1, "fragmented headers stream id %u", stream_id_ho);
	  hc->rx_expect = HTTP2_RX_EXPECT_CONTINUATION;
	  vec_validate (hc->unparsed_headers, fh->length - 1);
	  http_io_ts_read (hc, hc->unparsed_headers, fh->length, 0);
	  rv = http2_frame_read_headers (&headers_start, &headers_len, hc->unparsed_headers,
					 fh->length, fh->flags);
	  if (rv != HTTP2_ERROR_NO_ERROR)
	    return rv;

	  /* in case frame has padding */
	  if (PREDICT_FALSE (headers_start != hc->unparsed_headers))
	    {
	      n_dec = fh->length - headers_len;
	      n_del = headers_start - hc->unparsed_headers;
	      n_dec -= n_del;
	      vec_delete (hc->unparsed_headers, n_del, 0);
	      vec_dec_len (hc->unparsed_headers, n_dec);
	    }

	  return HTTP2_ERROR_EXPECT_CONTINUATION;
	}
    }
  else
    {
      req = http2_conn_get_req (hc, fh->stream_id);
      if (!req)
	return HTTP2_ERROR_PROTOCOL_ERROR;

      if (!http2_req_state_is_rx_valid (req))
	{
	  if (req->req_state == HTTP_REQ_STATE_APP_IO_MORE_DATA)
	    {
	      /* client can receive error response from server when still
	       * sending content */
	      /* TODO: 100 continue support */
	      HTTP_DBG (1, "server send response while client sending data");
	      http_io_as_drain_all (req);
	      hc->state = HTTP_CONN_STATE_CLOSED;
	      http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_REPLY);
	    }
	  else
	    return HTTP2_ERROR_INTERNAL_ERROR;
	}

      if (fh->flags & HTTP2_FRAME_FLAG_END_STREAM)
	req->stream_state = HTTP2_STREAM_STATE_CLOSED;

      if (!(fh->flags & HTTP2_FRAME_FLAG_END_HEADERS))
	{
	  HTTP_DBG (1, "fragmented headers stream id %u", clib_net_to_host_u32 (fh->stream_id));
	  hc->rx_expect = HTTP2_RX_EXPECT_CONTINUATION;
	  vec_validate (hc->unparsed_headers, fh->length - 1);
	  http_io_ts_read (hc, hc->unparsed_headers, fh->length, 0);
	  rv = http2_frame_read_headers (&headers_start, &headers_len, hc->unparsed_headers,
					 fh->length, fh->flags);
	  if (rv != HTTP2_ERROR_NO_ERROR)
	    return rv;

	  /* in case frame has padding */
	  if (PREDICT_FALSE (headers_start != hc->unparsed_headers))
	    {
	      n_dec = fh->length - headers_len;
	      n_del = headers_start - hc->unparsed_headers;
	      n_dec -= n_del;
	      vec_delete (hc->unparsed_headers, n_del, 0);
	      vec_dec_len (hc->unparsed_headers, n_dec);
	    }

	  return HTTP2_ERROR_EXPECT_CONTINUATION;
	}
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
http2_handle_continuation_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  http_ctx_t *req;
  u8 *p;
  http2_error_t rv = HTTP2_ERROR_NO_ERROR;

  if (fh->length < 1)
    {
      HTTP_DBG (1, "zero length payload");
      return HTTP2_ERROR_FRAME_SIZE_ERROR;
    }

  if (clib_net_to_host_u32 (fh->stream_id) != hc->last_opened_stream_id)
    {
      HTTP_DBG (1, "invalid stream id %u", clib_net_to_host_u32 (fh->stream_id));
      return HTTP2_ERROR_PROTOCOL_ERROR;
    }

  vec_add2 (hc->unparsed_headers, p, fh->length);
  http_io_ts_read (hc, p, fh->length, 0);

  if (fh->flags & HTTP2_FRAME_FLAG_END_HEADERS)
    {
      req = http2_conn_get_req (hc, fh->stream_id);
      if (!req)
	return HTTP2_ERROR_PROTOCOL_ERROR;
      hc->rx_expect = HTTP2_RX_EXPECT_DEFAULT;
      req->payload = hc->unparsed_headers;
      req->payload_len = vec_len (hc->unparsed_headers);
      HTTP_DBG (1, "run state machine");
      rv = http2_req_run_state_machine (hc, req, 0, 0);
      vec_free (hc->unparsed_headers);
    }

  return rv;
}

static http2_error_t
http2_handle_data_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  http_ctx_t *req;
  u8 *rx_buf;
  http2_error_t rv;

  if (fh->stream_id == 0)
    {
      HTTP_DBG (1, "DATA frame with stream id 0");
      return HTTP2_ERROR_PROTOCOL_ERROR;
    }

  req = http2_conn_get_req (hc, fh->stream_id);

  if (!req)
    {
      if (clib_net_to_host_u32 (fh->stream_id) <= hc->last_opened_stream_id)
	{
	  HTTP_DBG (1, "stream closed, ignoring frame");
	  http_io_ts_drain (hc, fh->length);
	  http2_send_stream_error (hc, fh->stream_id,
				   HTTP2_ERROR_STREAM_CLOSED, 0);
	  return HTTP2_ERROR_NO_ERROR;
	}
      else
	return HTTP2_ERROR_PROTOCOL_ERROR;
    }

  /* bogus state */
  if (hc->flags & HTTP_CONN_F_IS_SERVER && req->stream_state != HTTP2_STREAM_STATE_OPEN &&
      !(req->req_flags & HTTP_REQ_F_IS_TUNNEL))
    {
      HTTP_DBG (1, "error: stream already half-closed");
      http2_stream_error (hc, req, HTTP2_ERROR_STREAM_CLOSED, 0);
      return HTTP2_ERROR_NO_ERROR;
    }

  if (fh->length > req->our_stream_window)
    {
      HTTP_DBG (1, "error: peer violated stream flow control, stream window %lu exceeded",
		req->our_stream_window);
      http2_stream_error (hc, req, HTTP2_ERROR_FLOW_CONTROL_ERROR, 0);
      return HTTP2_ERROR_NO_ERROR;
    }
  if (fh->length > hc->our_window)
    {
      HTTP_DBG (1, "error: peer violated connection flow control, connection window %lu exceeded",
		hc->our_window);
      return HTTP2_ERROR_FLOW_CONTROL_ERROR;
    }

  if (fh->flags & HTTP2_FRAME_FLAG_END_STREAM)
    {
      HTTP_DBG (1, "END_STREAM flag set");
      if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
	{
	  /* peer can initiate or confirm tunnel close */
	  req->stream_state =
	    req->stream_state == HTTP2_STREAM_STATE_HALF_CLOSED ?
	      HTTP2_STREAM_STATE_CLOSED :
	      HTTP2_STREAM_STATE_HALF_CLOSED;
	  /* final DATA frame could be empty */
	  if (fh->length == 0)
	    {
	      if (req->stream_state == HTTP2_STREAM_STATE_CLOSED)
		{
		  HTTP_DBG (1, "peer closed tunnel");
		  http2_stream_close (req, hc);
		}
	      else
		{
		  HTTP_DBG (1, "peer want to close tunnel");
		  session_transport_closing_notify (&req->connection);
		}
	      return HTTP2_ERROR_NO_ERROR;
	    }
	}
      else
	req->stream_state = hc->flags & HTTP_CONN_F_IS_SERVER ?
			      HTTP2_STREAM_STATE_HALF_CLOSED :
			      HTTP2_STREAM_STATE_CLOSED;
    }

  if (fh->length == 0)
    {
      HTTP_DBG (1, "zero length payload");
      return HTTP2_ERROR_NO_ERROR;
    }

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_data (&req->payload, &req->payload_len, rx_buf,
			      fh->length, fh->flags);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  req->our_stream_window -= fh->length;
  hc->our_window -= fh->length;

  HTTP_DBG (1, "run state machine '%U' req_index %x", format_http_req_state, req->req_state,
	    ((http_req_handle_t) req->hr_req_handle).req_index);
  return http2_req_run_state_machine (hc, req, 0, 0);
}

static http2_error_t
http2_handle_window_update_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u8 *rx_buf;
  u32 win_increment;
  http2_error_t rv;
  http_ctx_t *req;

  if (fh->length != HTTP2_WINDOW_UPDATE_LENGTH)
    {
      HTTP_DBG (1, "invalid payload length");
      return HTTP2_ERROR_FRAME_SIZE_ERROR;
    }

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv = http2_frame_read_window_update (&win_increment, rx_buf, fh->length);
  if (rv != HTTP2_ERROR_NO_ERROR)
    {
      HTTP_DBG (1, "invalid WINDOW_UPDATE frame (stream id %u)",
		clib_net_to_host_u32 (fh->stream_id));
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
	    clib_net_to_host_u32 (fh->stream_id));
  if (fh->stream_id == 0)
    {
      if (win_increment > (HTTP2_WIN_SIZE_MAX - hc->peer_window))
	return HTTP2_ERROR_FLOW_CONTROL_ERROR;
      hc->peer_window += win_increment;
      /* reschedule connection if we have pending data */
      if (!clib_llist_is_empty (wrk->ctx_pool, stream_sched_list,
				clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams)))
	http2_conn_schedule (hc, hc->c_thread_index);
    }
  else
    {
      req = http2_conn_get_req (hc, fh->stream_id);
      if (!req)
	{
	  if (clib_net_to_host_u32 (fh->stream_id) > hc->last_opened_stream_id)
	    {
	      HTTP_DBG (1, "received WINDOW_UPDATE frame on idle stream (stream id %u)",
			clib_net_to_host_u32 (fh->stream_id));
	      return HTTP2_ERROR_PROTOCOL_ERROR;
	    }
	  /* ignore window update on closed stream */
	  return HTTP2_ERROR_NO_ERROR;
	}
      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
	{
	  if (http2_req_update_peer_window (hc, req, win_increment))
	    {
	      http2_stream_error (hc, req, HTTP2_ERROR_FLOW_CONTROL_ERROR, 0);
	      return HTTP2_ERROR_NO_ERROR;
	    }
	}
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_settings_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf, *resp = 0;
  http2_error_t rv;
  http_conn_settings_t new_settings;
  http_ctx_t *req;
  u32 stream_id, req_index;
  i32 win_size_delta;

  if (fh->stream_id != 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  if (fh->flags == HTTP2_FRAME_FLAG_ACK)
    {
      if (hc->flags & HTTP_CONN_F_EXPECT_SERVER_SETTINGS)
	return HTTP2_ERROR_PROTOCOL_ERROR;
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

      new_settings = hc->peer_settings;
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
      if (hc->peer_settings.initial_window_size != new_settings.initial_window_size)
	{
	  win_size_delta =
	    (i32) new_settings.initial_window_size - (i32) hc->peer_settings.initial_window_size;
	  hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
			  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
			  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
			    {
			      if (http2_req_update_peer_window (hc, req, win_size_delta))
				http2_stream_error (hc, req, HTTP2_ERROR_FLOW_CONTROL_ERROR, 0);
			    }
			}));
	}
      hc->peer_settings = new_settings;

      if (hc->flags & HTTP_CONN_F_EXPECT_SERVER_SETTINGS)
	{
	  hc->flags &= ~HTTP_CONN_F_EXPECT_SERVER_SETTINGS;
	  HTTP_DBG (1, "client connection established");
	  u32 hc_index = hc->hc_hc_index;
	  clib_thread_index_t thread_index = hc->c_thread_index;
	  req = http2_conn_alloc_req (hc_index, thread_index, 1);
	  /* pool grow, regrab connection */
	  hc = http_ctx_get_w_thread (hc_index, thread_index);
	  hc->flags |= HTTP_CONN_F_HAS_REQUEST;
	  hpack_dynamic_table_init (&hc->decoder_dynamic_table,
				    http2_default_conn_settings.header_table_size);
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
	  http_stats_connections_established_inc (hc->c_thread_index);
	  if (http_conn_established (hc, req, hc->hc_pa_app_api_ctx))
	    return HTTP2_ERROR_INTERNAL_ERROR;
	}
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_rst_stream_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  u8 *rx_buf;
  http2_error_t rv;
  http_ctx_t *req;
  u32 error_code;

  if (fh->length != HTTP2_RST_STREAM_LENGTH)
    {
      HTTP_DBG (1, "invalid payload length");
      return HTTP2_ERROR_FRAME_SIZE_ERROR;
    }

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
      if (clib_net_to_host_u32 (fh->stream_id) <= hc->last_opened_stream_id)
	{
	  /* we reset stream, but peer might send something meanwhile */
	  HTTP_DBG (1, "stream closed, ignoring frame");
	  return HTTP2_ERROR_NO_ERROR;
	}
      else
	{
	  HTTP_DBG (1, "invalid stream-id");
	  return HTTP2_ERROR_PROTOCOL_ERROR;
	}
    }

  req->stream_state = HTTP2_STREAM_STATE_CLOSED;
  http_stats_stream_reset_by_peer_inc (hc->c_thread_index);

  if (!(req->req_flags & HTTP_REQ_F_APP_CLOSED))
    session_transport_reset_notify (&req->connection);
  session_transport_delete_notify (&req->connection);
  http2_conn_free_req (hc, req, hc->c_thread_index);
  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_goaway_frame (http_ctx_t *hc, http2_frame_header_t *fh)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u8 *rx_buf;
  http2_error_t rv;
  u32 error_code, last_stream_id, req_index, stream_id;
  http_ctx_t *req;

  if (fh->length < HTTP2_GOAWAY_MIN_SIZE)
    {
      HTTP_DBG (1, "invalid payload length");
      return HTTP2_ERROR_FRAME_SIZE_ERROR;
    }

  if (fh->stream_id != 0)
    return HTTP2_ERROR_PROTOCOL_ERROR;

  rx_buf = http_get_rx_buf (hc);
  vec_validate (rx_buf, fh->length - 1);
  http_io_ts_read (hc, rx_buf, fh->length, 0);

  rv =
    http2_frame_read_goaway (&error_code, &last_stream_id, rx_buf, fh->length);
  if (rv != HTTP2_ERROR_NO_ERROR)
    return rv;

  HTTP_DBG (1, "received GOAWAY %U, last stream id %u", format_http2_error,
	    error_code, last_stream_id);

  if (error_code == HTTP2_ERROR_NO_ERROR)
    {
      /* graceful shutdown (no new streams for client) */
      if (!(hc->flags & HTTP_CONN_F_IS_SERVER))
	{
	  ASSERT (hc->flags & HTTP_CONN_F_HAS_REQUEST);
	  hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
			  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
			  session_transport_closed_notify (&req->connection);
			}));
	}
    }
  else
    {
      http_stats_connections_reset_by_peer_inc (hc->c_thread_index);
      if (fh->length > HTTP2_GOAWAY_MIN_SIZE)
	clib_warning ("additional debug data: %U", format_http_bytes,
		      rx_buf + HTTP2_GOAWAY_MIN_SIZE,
		      fh->length - HTTP2_GOAWAY_MIN_SIZE);
      /* connection error */
      if (hc->flags & HTTP_CONN_F_IS_SERVER)
	{
	  hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
			  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
			  session_transport_reset_notify (&req->connection);
			}));
	}
      if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
	{
	  req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
	  session_transport_reset_notify (&req->connection);
	}
      if (clib_llist_elt_is_linked (hc, sched_list))
	clib_llist_remove (wrk->ctx_pool, sched_list, hc);
      http_shutdown_transport (hc);
    }

  return HTTP2_ERROR_NO_ERROR;
}

static http2_error_t
http2_handle_ping_frame (http_ctx_t *hc, http2_frame_header_t *fh)
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
http2_handle_push_promise (http_ctx_t *hc, http2_frame_header_t *fh)
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
http2_expect_preface (http_ctx_t *hc)
{
  u8 *rx_buf;

  ASSERT (hc->flags & HTTP_CONN_F_IS_SERVER);

  rx_buf = http_get_rx_buf (hc);
  http_io_ts_read (hc, rx_buf, http2_conn_preface.len, 1);
  return memcmp (rx_buf, http2_conn_preface.base, http2_conn_preface.len);
}

/*****************/
/* http core VFT */
/*****************/

static transport_connection_t *
http2_req_get_connection (u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  req = http_ctx_get_w_thread (req_index, thread_index);
  return &(req->connection);
}

static u8 *
format_http2_req (u8 *s, va_list *args)
{
  http_ctx_t *req = va_arg (*args, http_ctx_t *);
  http_ctx_t *hc = va_arg (*args, http_ctx_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  s = format (s, "[%d:%d][H2] stream_id %u app_wrk %u hc_index %u ts %d:%d", req->c_thread_index,
	      req->c_s_index, req->stream_id, req->hr_pa_wrk_index, req->hr_hc_index,
	      ts->thread_index, ts->session_index);

  return s;
}

static u8 *
format_http2_stream_state (u8 *s, va_list *args)
{
  http2_stream_state_t state = va_arg (*args, int);
  u8 *t = 0;

  switch (state)
    {
#define _(s, str)                                                                                  \
  case HTTP2_STREAM_STATE_##s:                                                                     \
    t = (u8 *) (str);                                                                              \
    break;
      foreach_http2_stream_state
#undef _
	default : return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static u8 *
format_http2_req_vars (u8 *s, va_list *args)
{
  http_ctx_t *req = va_arg (*args, http_ctx_t *);
  http_ctx_t *hc = va_arg (*args, http_ctx_t *);

  if (!(hc->flags & HTTP_CONN_F_IS_SERVER && req->req_flags & HTTP_REQ_F_IS_PARENT))
    s = format (s, " our_wnd %u peer_wnd %d scheduled %u\n", req->our_stream_window,
		req->peer_stream_window, clib_llist_elt_is_linked (req, stream_sched_list));
  s = format (s, " flags: %U\n", format_http_req_flags, req);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      s = format (s, " conn_state: %U\n", format_http_conn_state, hc);
      s = format (s, " hc_flags: %U\n", format_http_conn_flags, hc);
      s = format (s, " conn_wnd_our %u conn_wnd_peer %u scheduled %u\n", hc->our_window,
		  hc->peer_window, clib_llist_elt_is_linked (hc, sched_list));
      if (hc->flags & HTTP_CONN_F_HAS_REQUEST)
	s = format (s, " decoder table: %u entries %u bytes\n",
		    clib_ring_n_enq (hc->decoder_dynamic_table.entries),
		    hc->decoder_dynamic_table.used);
    }
  return s;
}

static u8 *
http2_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  http_ctx_t *hc = va_arg (*args, http_ctx_t *);
  transport_fmt_req_t fmt = { .as_u32 = va_arg (*args, u32) };
  http_ctx_t *req;

  req = http_ctx_get_w_thread (req_index, thread_index);

  if (!transport_fmt_req_is_explicit (fmt))
    {
      s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http2_req, req, hc);
      if (fmt.level)
	{
	  s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http2_stream_state,
		      req->stream_state);
	  if (fmt.level > 1)
	    s = format (s, "\n%U", format_http2_req_vars, req, hc);
	}
      return s;
    }

  if (fmt.conn_id)
    s = format (s, "%U", format_http2_req, req, hc);
  if (fmt.transport_state)
    {
      if (fmt.conn_id)
	s = format (s, "\t");
      s = format (s, "%U", format_http2_stream_state, req->stream_state);
    }
  if (fmt.transport_detail)
    s = format (s, "\n%U", format_http2_req_vars, req, hc);

  return s;
}

static void
http2_app_tx_callback (http_ctx_t *hc, u32 req_index, transport_send_params_t *sp)
{
  http_ctx_t *req;
  http2_error_t rv;

  HTTP_DBG (1, "hc [%u]%x req_index %x", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);

  if (!http2_req_state_is_tx_valid (req))
    {
      if (req->req_state == HTTP_REQ_STATE_TRANSPORT_IO_MORE_DATA &&
	  (hc->flags & HTTP_CONN_F_IS_SERVER))
	{
	  /* server app might send error earlier */
	  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_REPLY);
	}
      else
	{
	  clib_warning ("hc [%u]%x invalid tx state: http req state "
			"'%U', session state '%U'",
			hc->c_thread_index, hc->hc_hc_index, format_http_req_state, req->req_state,
			format_http_conn_state, hc);
	  http2_stream_error (hc, req, HTTP2_ERROR_INTERNAL_ERROR, sp);
	  return;
	}
    }

  /* peer reset stream, but app might send something meanwhile */
  if (req->stream_state == HTTP2_STREAM_STATE_CLOSED)
    {
      HTTP_DBG (1, "stream closed, ignoring app data");
      http_io_as_drain_all (req);
      return;
    }

  HTTP_DBG (1, "run state machine");
  rv = http2_req_run_state_machine (hc, req, sp, 1);
  if (rv != HTTP2_ERROR_NO_ERROR)
    {
      http2_connection_error (hc, rv, sp);
      return;
    }

  /* reset http connection expiration timer */
  http_conn_timer_update (hc);
}

static void
http2_app_rx_evt_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index)
{
  http_ctx_t *req;
  u32 increment;
  http2_stream_state_t expected_state;

  req = http_ctx_get_w_thread (req_index, thread_index);
  if (!req)
    {
      HTTP_DBG (1, "req already deleted");
      return;
    }
  HTTP_DBG (1, "received app read notification stream id %u", req->stream_id);
  /* send stream window update if app read data in rx fifo and we expect more
   * data (stream is still open) */
  expected_state =
    ((hc->flags & HTTP_CONN_F_IS_SERVER) || (req->req_flags & HTTP_REQ_F_IS_TUNNEL)) ?
      HTTP2_STREAM_STATE_OPEN :
      HTTP2_STREAM_STATE_HALF_CLOSED;
  if (req->stream_state == expected_state)
    {
      http_io_as_reset_has_read_ntf (req);
      increment = http2_req_get_win_increment (req, hc);
      if (increment == 0)
	return;
      /* check if we have enough space in fifo */
      if (http_io_ts_max_write (hc, 0) < HTTP2_WINDOW_UPDATE_FRAME_SIZE)
	{
	  HTTP_DBG (1,
		    "transport fifo full postponing stream %d window update",
		    req->stream_id);
	  if (!(req->req_flags & HTTP_REQ_F_PENDING_SND_WIN_UPDATE))
	    {
	      http_io_ts_add_want_deq_ntf (hc);
	      vec_add1 (hc->pending_win_updates, req->stream_id);
	    }
	  return;
	}
      req->our_stream_window += increment;
      http2_send_window_update (hc, increment, req->stream_id);
    }
}

static void
http2_app_close_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index,
			  u8 is_shutdown)
{
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x req_index %x", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  if (!req)
    {
      HTTP_DBG (1, "req already deleted");
      return;
    }

  req->req_flags |= HTTP_REQ_F_APP_CLOSED;

  if (req->stream_state == HTTP2_STREAM_STATE_CLOSED ||
      req->stream_state == HTTP2_STREAM_STATE_IDLE ||
      hc->state == HTTP_CONN_STATE_CLOSED)
    {
      u8 is_parent = req->req_flags & HTTP_REQ_F_IS_PARENT;
      HTTP_DBG (1, "nothing more to send, confirm close");
      http2_stream_close (req, hc);
      if (is_parent)
	{
	  HTTP_DBG (1, "app closed parent, closing connection");
	  http_shutdown_transport (hc);
	}
    }
  else if (req->req_flags & HTTP_REQ_F_IS_TUNNEL)
    {
      req->req_flags |= is_shutdown ? HTTP_REQ_F_SHUTDOWN_TUNNEL : 0;
      switch (req->stream_state)
	{
	case HTTP2_STREAM_STATE_OPEN:
	  HTTP_DBG (1, "app want to close tunnel");
	  if (http_io_as_max_read (req))
	    goto check_reschedule;
	  if (req->our_stream_window == 0 && !is_shutdown)
	    {
	      HTTP_DBG (1, "app has unread data, going to reset stream");
	      http2_stream_error (hc, req, HTTP2_ERROR_CONNECT_ERROR, 0);
	      return;
	    }
	  HTTP_DBG (1, "nothing more to send, closing tunnel");
	  req->stream_state = HTTP2_STREAM_STATE_HALF_CLOSED;
	  http2_tunnel_send_close (hc, req);
	  break;
	case HTTP2_STREAM_STATE_HALF_CLOSED:
	  HTTP_DBG (1, "app confirmed tunnel close");
	  if (http_io_as_max_read (req) == 0)
	    {
	      HTTP_DBG (1, "nothing more to send, closing tunnel and stream");
	      http2_tunnel_send_close (hc, req);
	      http2_stream_close (req, hc);
	      return;
	    }
	  goto check_reschedule;
	default:
	  ASSERT (0);
	  break;
	check_reschedule:
	  if (!clib_llist_elt_is_linked (req, stream_sched_list) &&
	      req->req_state == HTTP_REQ_STATE_TUNNEL)
	    {
	      http2_req_schedule_data_tx (hc, req);
	      if (hc->peer_window > 0)
		http2_conn_schedule (hc, hc->c_thread_index);
	    }
	}
    }
  HTTP_DBG (1, "wait for all data to be written to ts");
}

static void
http2_app_reset_callback (http_ctx_t *hc, u32 req_index, clib_thread_index_t thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x req_index %x", hc->c_thread_index, hc->hc_hc_index,
	    req_index);
  req = http_ctx_get_w_thread (req_index, thread_index);
  req->req_flags |= HTTP_REQ_F_APP_CLOSED;
  http_stats_stream_reset_by_app_inc (thread_index);
  http2_send_stream_error (hc, req->stream_id,
			   (req->req_flags & HTTP_REQ_F_IS_TUNNEL) ? HTTP2_ERROR_CONNECT_ERROR :
								     HTTP2_ERROR_INTERNAL_ERROR,
			   0);
  session_transport_delete_notify (&req->connection);
  if (req->req_flags & HTTP_REQ_F_IS_PARENT)
    {
      HTTP_DBG (1, "app closed parent, closing connection");
      http_disconnect_transport (hc);
      if (clib_llist_elt_is_linked (hc, sched_list))
	clib_llist_remove (wrk->ctx_pool, sched_list, hc);
      http_stats_connections_reset_by_app_inc (thread_index);
    }
  http2_conn_free_req (hc, req, hc->c_thread_index);
}

static int
http2_transport_connected_callback (http_ctx_t *hc)
{
  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  hc->flags |= HTTP_CONN_F_EXPECT_SERVER_SETTINGS;
  http2_conn_init (hc, 1);
  return 0;
}

void http2_rx_expect_client_preface (http_ctx_t *hc);
void http2_rx_expect_server_preface (http_ctx_t *hc);
void http2_rx_expect_default (http_ctx_t *hc);
void http2_rx_expect_continuation (http_ctx_t *hc);

static http2_rx_expect_cb http2_rx_expect_funcs[HTTP2_RX_EXPECT_STATE_NUM] = {
  http2_rx_expect_client_preface,
  http2_rx_expect_server_preface,
  http2_rx_expect_continuation,
  http2_rx_expect_default,
};

void
http2_rx_expect_client_preface (http_ctx_t *hc)
{
  u32 to_deq;
  http_ctx_t *req;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  if (hc->flags & HTTP_CONN_F_NEED_REINIT)
    {
      hc->flags &= ~HTTP_CONN_F_NEED_REINIT;
      http2_conn_init (hc, 0);
      /* pool grow, regrab connection */
      hc = http_ctx_get_w_thread (hc_index, thread_index);
    }

  to_deq = http_io_ts_max_read (hc);
  if (PREDICT_FALSE (to_deq < http2_conn_preface.len))
    {
      HTTP_DBG (1, "to_deq %u is less than conn preface size", to_deq);
      http_disconnect_transport (hc);
      http_stats_proto_errors_inc (hc->c_thread_index);
      return;
    }

  if (http2_expect_preface (hc))
    {
      HTTP_DBG (1, "conn preface verification failed");
      http_disconnect_transport (hc);
      http_stats_proto_errors_inc (hc->c_thread_index);
      return;
    }
  http2_send_server_preface (hc);
  http_io_ts_drain (hc, http2_conn_preface.len);
  to_deq -= http2_conn_preface.len;

  /* alloc parent session */
  req = http2_conn_alloc_req (hc_index, thread_index, 1);
  /* pool grow, regrab connection */
  hc = http_ctx_get_w_thread (hc_index, thread_index);
  if (http_conn_accept_request (hc, req, 0))
    {
      http2_conn_free_req (hc, req, hc->c_thread_index);
      hc->hc_parent_req_index = SESSION_INVALID_INDEX;
      http_disconnect_transport (hc);
      return;
    }
  http_req_state_change (req, HTTP_REQ_STATE_WAIT_TRANSPORT_METHOD);

  http_stats_connections_accepted_inc (hc->c_thread_index);
  hc->flags &= ~HTTP_CONN_F_NO_APP_SESSION;
  hc->rx_expect = HTTP2_RX_EXPECT_DEFAULT;

  if (to_deq != 0)
    http2_rx_expect_funcs[hc->rx_expect](hc);
}

void
http2_rx_expect_server_preface (http_ctx_t *hc)
{
  http2_error_t rv;
  u32 to_deq;
  u8 *rx_buf;
  http2_frame_header_t fh;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  to_deq = http_io_ts_max_read (hc);
  if (PREDICT_FALSE (to_deq < HTTP2_FRAME_HEADER_SIZE))
    {
      HTTP_DBG (1, "to_deq %u is less than frame header size", to_deq);
      return;
    }

  rx_buf = http_get_rx_buf (hc);
  http_io_ts_read (hc, rx_buf, HTTP2_FRAME_HEADER_SIZE, 1);
  to_deq -= HTTP2_FRAME_HEADER_SIZE;
  http2_frame_header_read (rx_buf, &fh);
  if (PREDICT_FALSE (fh.type != HTTP2_FRAME_TYPE_SETTINGS))
    {
      HTTP_DBG (1, "expected SETTINGS frame (server preface)");
      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
      return;
    }
  if (PREDICT_FALSE (fh.length > hc->settings.max_frame_size))
    {
      HTTP_DBG (1, "frame length %lu exceeded SETTINGS_MAX_FRAME_SIZE %lu", fh.length,
		hc->settings.max_frame_size);
      http2_connection_error (hc, HTTP2_ERROR_FRAME_SIZE_ERROR, 0);
      return;
    }
  if (PREDICT_FALSE (fh.length > to_deq))
    {
      HTTP_DBG (1, "frame payload not yet received, to deq %lu, frame length %lu", to_deq,
		fh.length);
      if (http_io_ts_fifo_size (hc, 1) < (fh.length + HTTP2_FRAME_HEADER_SIZE))
	{
	  clib_warning ("ts rx fifo too small to hold frame (%u)",
			fh.length + HTTP2_FRAME_HEADER_SIZE);
	  http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
	}
      return;
    }
  http_io_ts_drain (hc, HTTP2_FRAME_HEADER_SIZE);
  to_deq -= fh.length;
  rv = http2_handle_settings_frame (hc, &fh);
  if (PREDICT_FALSE (rv != HTTP2_ERROR_NO_ERROR))
    {
      http2_connection_error (hc, rv, 0);
      return;
    }
  hc->rx_expect = HTTP2_RX_EXPECT_DEFAULT;

  if (to_deq != 0)
    http2_rx_expect_funcs[hc->rx_expect](hc);
}

void
http2_rx_expect_continuation (http_ctx_t *hc)
{
  http2_error_t rv;
  u32 to_deq;
  u8 *rx_buf;
  http2_frame_header_t fh;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  to_deq = http_io_ts_max_read (hc);
  if (PREDICT_FALSE (to_deq < HTTP2_FRAME_HEADER_SIZE))
    {
      HTTP_DBG (1, "to_deq %u is less than frame header size", to_deq);
      return;
    }

  rx_buf = http_get_rx_buf (hc);
  http_io_ts_read (hc, rx_buf, HTTP2_FRAME_HEADER_SIZE, 1);
  to_deq -= HTTP2_FRAME_HEADER_SIZE;
  http2_frame_header_read (rx_buf, &fh);
  if (PREDICT_FALSE (fh.type != HTTP2_FRAME_TYPE_CONTINUATION))
    {
      HTTP_DBG (1, "expected CONTINUATION frame");
      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
      return;
    }
  if (PREDICT_FALSE (fh.length > hc->settings.max_frame_size))
    {
      HTTP_DBG (1, "frame length %lu exceeded SETTINGS_MAX_FRAME_SIZE %lu", fh.length,
		hc->settings.max_frame_size);
      http2_connection_error (hc, HTTP2_ERROR_FRAME_SIZE_ERROR, 0);
      return;
    }
  if (fh.length > to_deq)
    {
      HTTP_DBG (1, "frame payload not yet received, to deq %lu, frame length %lu", to_deq,
		fh.length);
      if (PREDICT_FALSE (http_io_ts_fifo_size (hc, 1) < (fh.length + HTTP2_FRAME_HEADER_SIZE)))
	{
	  clib_warning ("ts rx fifo too small to hold frame (%u)",
			fh.length + HTTP2_FRAME_HEADER_SIZE);
	  http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
	}
      return;
    }
  http_io_ts_drain (hc, HTTP2_FRAME_HEADER_SIZE);
  to_deq -= fh.length;
  rv = http2_handle_continuation_frame (hc, &fh);
  if (PREDICT_FALSE (rv != HTTP2_ERROR_NO_ERROR))
    {
      http2_connection_error (hc, rv, 0);
      return;
    }

  if (to_deq == 0)
    return;

  http2_rx_expect_funcs[hc->rx_expect](hc);
}

void
http2_rx_expect_default (http_ctx_t *hc)
{
  http2_frame_header_t fh;
  u32 to_deq;
  u8 *rx_buf;
  http2_error_t rv;
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  to_deq = http_io_ts_max_read (hc);
  rx_buf = http_get_rx_buf (hc);

  while (to_deq >= HTTP2_FRAME_HEADER_SIZE)
    {
      http_io_ts_read (hc, rx_buf, HTTP2_FRAME_HEADER_SIZE, 1);
      to_deq -= HTTP2_FRAME_HEADER_SIZE;
      http2_frame_header_read (rx_buf, &fh);
      if (PREDICT_FALSE (fh.length > hc->settings.max_frame_size))
	{
	  HTTP_DBG (1, "frame length %lu exceeded SETTINGS_MAX_FRAME_SIZE %lu", fh.length,
		    hc->settings.max_frame_size);
	  http2_connection_error (hc, HTTP2_ERROR_FRAME_SIZE_ERROR, 0);
	  return;
	}
      if (fh.length > to_deq)
	{
	  HTTP_DBG (1, "frame payload not yet received, to deq %lu, frame length %lu", to_deq,
		    fh.length);
	  if (PREDICT_FALSE (http_io_ts_fifo_size (hc, 1) < (fh.length + HTTP2_FRAME_HEADER_SIZE)))
	    {
	      clib_warning ("ts rx fifo too small to hold frame (%u)",
			    fh.length + HTTP2_FRAME_HEADER_SIZE);
	      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
	    }
	  return;
	}
      http_io_ts_drain (hc, HTTP2_FRAME_HEADER_SIZE);
      to_deq -= fh.length;

      HTTP_DBG (1, "frame type 0x%02x len %u stream-id %u flags 0x%01x", fh.type, fh.length,
		fh.stream_id, fh.flags);

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
	  /* to prevent information leakage, PING frames can be sent from any
	   * endpoint and is expected to be sent with higher priority */
	  if (to_deq && to_deq < HTTP2_FRAME_HEADER_SIZE)
	    {
	      HTTP_DBG (1, "to_deq %u is less than frame header size", to_deq);
	      http2_connection_error (hc, HTTP2_ERROR_PROTOCOL_ERROR, 0);
	      return;
	    }
	  rv = http2_handle_ping_frame (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_CONTINUATION:
	  HTTP_DBG (1, "unexpected CONTINUATION frame");
	  rv = HTTP2_ERROR_PROTOCOL_ERROR;
	  break;
	case HTTP2_FRAME_TYPE_PUSH_PROMISE:
	  rv = http2_handle_push_promise (hc, &fh);
	  break;
	case HTTP2_FRAME_TYPE_PRIORITY: /* deprecated */
	default:
	  /* ignore unknown frame type */
	  HTTP_DBG (1, "unknown frame type, dropped");
	  http_io_ts_drain (hc, fh.length);
	  rv = HTTP2_ERROR_NO_ERROR;
	  break;
	}

      /* pool might grow, regrab connection */
      hc = http_ctx_get_w_thread (hc_index, thread_index);

      if (PREDICT_FALSE (rv != HTTP2_ERROR_NO_ERROR))
	{
	  if (rv == HTTP2_ERROR_EXPECT_CONTINUATION)
	    return;
	  http2_connection_error (hc, rv, 0);
	  return;
	}
    }
}

static void
http2_transport_rx_callback (http_ctx_t *hc)
{
  u32 hc_index = hc->hc_hc_index;
  clib_thread_index_t thread_index = hc->c_thread_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  http2_rx_expect_funcs[hc->rx_expect](hc);

  /* pool might grow, regrab connection */
  hc = http_ctx_get_w_thread (hc_index, thread_index);

  /* send connection window update if more than half consumed */
  if (hc->our_window < HTTP2_CONNECTION_WINDOW_SIZE / 2)
    {
      /* check if we have enough space in fifo */
      if (http_io_ts_max_write (hc, 0) >= HTTP2_WINDOW_UPDATE_FRAME_SIZE)
	{
	  HTTP_DBG (1, "connection window increment %u",
		    HTTP2_CONNECTION_WINDOW_SIZE - hc->our_window);
	  http2_send_window_update (hc, HTTP2_CONNECTION_WINDOW_SIZE - hc->our_window, 0);
	  hc->our_window = HTTP2_CONNECTION_WINDOW_SIZE;
	}
      else
	{
	  HTTP_DBG (1,
		    "transport fifo full postponing connection window update");
	  http_io_ts_add_want_deq_ntf (hc);
	}
    }

  /* reset http connection expiration timer */
  http_conn_timer_update (hc);
}

static void
http2_transport_close_callback (http_ctx_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u32 req_index, stream_id, n_open_streams = 0;
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
		  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
		  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		    {
		      HTTP_DBG (1, "req_index %x", req_index);
		      session_transport_closing_notify (&req->connection);
		      n_open_streams++;
		    }
		}));
  if (n_open_streams == 0)
    {
      HTTP_DBG (1, "no open stream disconnecting");
      if (clib_llist_elt_is_linked (hc, sched_list))
	clib_llist_remove (wrk->ctx_pool, sched_list, hc);
      http_disconnect_transport (hc);
      /* Notify app that transport for parent req is closing to avoid
       * potentially deleting the connection in ready state on transport
       * cleanup */
      if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
	{
	  req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
	  session_transport_closing_notify (&req->connection);
	}
    }
}

static void
http2_transport_reset_callback (http_ctx_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  u32 req_index, stream_id;
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  hash_foreach (stream_id, req_index, hc->req_by_stream_id, ({
		  req = http_ctx_get_w_thread (req_index, hc->c_thread_index);
		  if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
		    {
		      HTTP_DBG (1, "req_index %x", req_index);
		      session_transport_reset_notify (&req->connection);
		    }
		}));

  if (hc->hc_parent_req_index != SESSION_INVALID_INDEX)
    {
      req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      session_transport_reset_notify (&req->connection);
    }

  if (clib_llist_elt_is_linked (hc, sched_list))
    clib_llist_remove (wrk->ctx_pool, sched_list, hc);
}

static void
http2_transport_conn_reschedule_callback (http_ctx_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  http_ctx_t *req;
  u32 max_write, need_write, increment, *stream_id = 0;
  u8 *tx_buf;
  http2_rst_stream_t *rst_stream;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  ASSERT (hc->flags & HTTP_CONN_F_HAS_REQUEST);

  max_write = http_io_ts_max_write (hc, 0);

  /* checkif we have some pending stream resets */
  if (vec_len (hc->pending_rst_stream))
    {
      need_write = vec_len (hc->pending_rst_stream) * HTTP2_RST_STREAM_FRAME_SIZE;
      if (max_write >= need_write)
	{
	  tx_buf = http_get_tx_buf (hc);
	  vec_foreach (rst_stream, hc->pending_rst_stream)
	    {
	      http2_frame_write_rst_stream (rst_stream->error, rst_stream->stream_id, &tx_buf);
	    }
	  vec_reset_length (hc->pending_rst_stream);
	  http_io_ts_write (hc, tx_buf, vec_len (tx_buf), 0);
	  http_io_ts_after_write (hc, 1);
	  max_write -= need_write;
	}
    }

  /* checkif we have some pending stream window updates */
  if (vec_len (hc->pending_win_updates))
    {
      need_write = vec_len (hc->pending_win_updates) * HTTP2_WINDOW_UPDATE_FRAME_SIZE;
      if (max_write >= need_write)
	{
	  tx_buf = http_get_tx_buf (hc);
	  vec_foreach (stream_id, hc->pending_win_updates)
	    {
	      req = http2_conn_get_req (hc, *stream_id);
	      if (!req)
		continue;
	      req->req_flags &= ~HTTP_REQ_F_PENDING_SND_WIN_UPDATE;
	      increment = http2_req_get_win_increment (req, hc);
	      if (!increment)
		continue;
	      req->our_stream_window += increment;
	      http2_frame_write_window_update (increment, req->stream_id,
					       &tx_buf);
	    }
	  vec_reset_length (hc->pending_win_updates);
	  http_io_ts_write (hc, tx_buf, vec_len (tx_buf), 0);
	  http_io_ts_after_write (hc, 1);
	  max_write -= need_write;
	}
    }
  /* maybe we need to update also connection window */
  if ((hc->our_window < HTTP2_CONNECTION_WINDOW_SIZE / 2) &&
      (max_write >= HTTP2_WINDOW_UPDATE_FRAME_SIZE))
    {
      http2_send_window_update (hc, HTTP2_CONNECTION_WINDOW_SIZE - hc->our_window, 0);
      hc->our_window = HTTP2_CONNECTION_WINDOW_SIZE;
    }

  /* last deschedule data sending */
  if (hc->flags & HTTP_CONN_F_TS_DESCHED)
    {
      /* do it only when we have still wnough space in fifo */
      if (http_io_ts_check_write_thresh (hc))
	http_io_ts_add_want_deq_ntf (hc);
      hc->flags &= ~HTTP_CONN_F_TS_DESCHED;
      /* reschedule connection if something is waiting in queue */
      if (!clib_llist_is_empty (wrk->ctx_pool, stream_sched_list,
				clib_llist_elt (wrk->ctx_pool, hc->new_tx_streams)) ||
	  !clib_llist_is_empty (wrk->ctx_pool, stream_sched_list,
				clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams)))
	http2_conn_schedule (hc, hc->c_thread_index);
    }
}

static void
http2_conn_accept_callback (http_ctx_t *hc)
{
  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  http2_conn_init (hc, 0);
}

static int
http2_conn_connect_stream_callback (http_ctx_t *hc, u32 *req_index)
{
  http_ctx_t *req;
  u32 pa_wrk_index = hc->hc_pa_wrk_index;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);
  ASSERT (!(hc->flags & HTTP_CONN_F_IS_SERVER));
  ASSERT (!(hc->flags & HTTP_CONN_F_EXPECT_SERVER_SETTINGS));
  if (hc->req_num == hc->settings.max_concurrent_streams)
    return SESSION_E_MAX_STREAMS_HIT;
  req = http2_conn_alloc_req (hc->hc_hc_index, hc->c_thread_index, 0);
  req->hr_pa_wrk_index = pa_wrk_index;
  http_req_state_change (req, HTTP_REQ_STATE_WAIT_APP_METHOD);
  *req_index = req->hr_req_handle;
  return SESSION_E_NONE;
}

static void
http2_conn_cleanup_callback (http_ctx_t *hc)
{
  u32 req_index, stream_id, *req_index_p, *req_indices = 0;
  http_ctx_t *req;

  HTTP_DBG (1, "hc [%u]%x", hc->c_thread_index, hc->hc_hc_index);

  if (hc->flags & HTTP_CONN_F_NEED_REINIT)
    return;

  hash_foreach (stream_id, req_index, hc->req_by_stream_id,
		({ vec_add1 (req_indices, req_index); }));

  vec_foreach (req_index_p, req_indices)
    {
      req = http_ctx_get_w_thread (*req_index_p, hc->c_thread_index);
      session_transport_delete_notify (&req->connection);
      http2_conn_free_req (hc, req, hc->c_thread_index);
    }
  if ((hc->hc_parent_req_index != SESSION_INVALID_INDEX))
    {
      req = http_ctx_get_w_thread (hc->hc_parent_req_index, hc->c_thread_index);
      if (req->stream_state != HTTP2_STREAM_STATE_CLOSED)
	session_transport_closing_notify (&req->connection);
      session_transport_delete_notify (&req->connection);
      http2_conn_free_req (hc, req, hc->c_thread_index);
    }

  vec_free (req_indices);
  http2_conn_destroy (hc);
}

static int
http2_update_settings (http_settings_t type, u32 value)
{
  http_main_t *hm = &http_main;

  switch (type)
    {
#define _(v, label, member, min, max, default_value, err_code, server, client)                     \
  case HTTP2_SETTINGS_##label:                                                                     \
    if (!(value >= (min) && value <= (max)))                                                       \
      return -1;                                                                                   \
    hm->h2_settings.member = value;                                                                \
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
  .transport_conn_reschedule_callback = http2_transport_conn_reschedule_callback,
  .conn_accept_callback = http2_conn_accept_callback,
  .conn_connect_stream_callback = http2_conn_connect_stream_callback,
  .conn_cleanup_callback = http2_conn_cleanup_callback,
  .unformat_cfg_callback = http2_unformat_config_callback,
};

clib_error_t *
http2_init (vlib_main_t *vm)
{
  http_main_t *hm = &http_main;

  hm->h2_settings = http2_default_conn_settings;
  hm->h2_settings.max_concurrent_streams = 100;	  /* by default unlimited */
  hm->h2_settings.max_header_list_size = 1 << 14; /* by default unlimited */
  hm->h2_settings.enable_connect_protocol = 1;	  /* enable extended connect */
  hm->h2_settings.enable_push = 0;		  /* by default enabled */
  http_register_engine (&http2_engine, HTTP_VERSION_2);

  return 0;
}

VLIB_INIT_FUNCTION (http2_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
