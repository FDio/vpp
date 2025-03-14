/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http2/hpack.h>
#include <http/http_private.h>

#ifndef HTTP_2_ENABLE
#define HTTP_2_ENABLE 0
#endif

typedef struct http2_req_
{
  http_req_t base;
  u32 stream_id;
  u64 peer_window;
} http2_req_t;

typedef struct http2_conn_ctx_
{
  http2_conn_settings_t peer_settings;
  hpack_dynamic_table_t decoder_dynamic_table;
  u64 peer_window;
  uword *req_by_stream_id;
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
  h2c->req_by_stream_id = hash_create (0, sizeof (uword));
  hc->opaque =
    uword_to_pointer (h2c - h2m->conn_pool[hc->c_thread_index], void *);
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
  hpack_dynamic_table_free (&h2c->decoder_dynamic_table);
  hash_free (h2c->req_by_stream_id);
  if (CLIB_DEBUG)
    memset (h2c, 0xba, sizeof (*h2c));
  pool_put (h2m->conn_pool[hc->c_thread_index], h2c);
}

http2_req_t *
http2_req_alloc (http_conn_t *hc, u32 stream_id)
{
  http2_main_t *h2m = &http2_main;
  http2_conn_ctx_t *h2c;
  http2_req_t *req;
  u32 req_index;

  pool_get_aligned_safe (h2m->req_pool[hc->c_thread_index], req,
			 CLIB_CACHE_LINE_BYTES);
  clib_memset (req, 0, sizeof (*req));
  req->base.hr_pa_session_handle = SESSION_INVALID_HANDLE;
  req_index = req - h2m->req_pool[hc->c_thread_index];
  req->base.hr_req_index = http_make_req_handle (req_index, HTTP_VERSION_2);
  req->base.hr_hc_index = hc->hc_hc_index;
  req->base.c_thread_index = hc->c_thread_index;
  req->stream_id = stream_id;
  h2c = http2_conn_ctx_get_w_thread (hc);
  req->peer_window = h2c->peer_settings.initial_window_size;
  hash_set (h2c->req_by_stream_id, stream_id, req_index);
  return req;
}

static inline void
http2_req_free (http2_conn_ctx_t *h2c, http2_req_t *req, u32 thread_index)
{
  http2_main_t *h2m = &http2_main;

  vec_free (req->base.headers);
  vec_free (req->base.target);
  http_buffer_free (&req->base.tx_buf);
  hash_unset (h2c->req_by_stream_id, req->stream_id);
  if (CLIB_DEBUG)
    memset (req, 0xba, sizeof (*req));
  pool_put (h2m->req_pool[thread_index], req);
}

http2_req_t *
http2_req_get_by_stream_id (http_conn_t *hc, u32 stream_id)
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
http2_get_connection (u32 req_index, u32 thread_index)
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
  /* TODO: run state machine */
}

static void
http2_app_rx_evt_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  /* TODO: continue tunnel RX */
}

static void
http2_app_close_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  /* TODO: confirm close or wait until all app data drained */
}

static void
http2_app_reset_callback (http_conn_t *hc, u32 req_index, u32 thread_index)
{
  /* TODO: send RST_STREAM frame */
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
  /* TODO: run state machine or handle control frames on stream 0 */
}

static void
http2_transport_close_callback (http_conn_t *hc)
{
  u32 req_index, stream_id;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;

  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		  req = http2_req_get (req_index, hc->c_thread_index);
		  session_transport_closing_notify (&req->base.connection);
		}));
}

static void
http2_transport_reset_callback (http_conn_t *hc)
{
  u32 req_index, stream_id;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  if (!(hc->flags & HTTP_CONN_F_HAS_REQUEST))
    return;

  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id, ({
		  req = http2_req_get (req_index, hc->c_thread_index);
		  session_transport_reset_notify (&req->base.connection);
		}));
}

static void
http2_transport_conn_reschedule_callback (http_conn_t *hc)
{
  /* TODO */
}

static void
http2_conn_cleanup_callback (http_conn_t *hc)
{
  u32 req_index, stream_id, *req_index_p, *req_indices = 0;
  http2_req_t *req;
  http2_conn_ctx_t *h2c;

  h2c = http2_conn_ctx_get_w_thread (hc);
  hash_foreach (stream_id, req_index, h2c->req_by_stream_id,
		({ vec_add1 (req_indices, req_index); }));

  vec_foreach (req_index_p, req_indices)
    {
      req = http2_req_get (*req_index_p, hc->c_thread_index);
      session_transport_delete_notify (&req->base.connection);
      http2_req_free (h2c, req, hc->c_thread_index);
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
  .get_connection = http2_get_connection,
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
  http_register_engine (&http2_engine, HTTP_VERSION_2);

  return 0;
}

#if HTTP_2_ENABLE > 0
VLIB_INIT_FUNCTION (http2_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
#endif
