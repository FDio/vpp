/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/http3.h>
#include <http/http3/frame.h>
#include <http/http_private.h>

typedef struct http3_stream_ctx_
{
  http_req_t base;
  u32 h3c_index;
  http3_stream_type_t stream_type;
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
  http3_conn_settings_t peer_settings;
  u32 our_ctrl_stream_index;
  u32 peer_ctrl_stream_index;
  http3_conn_flags_t flags;
} http3_conn_ctx_t;

typedef struct
{
  http3_conn_ctx_t *conn_pool;
  http3_stream_ctx_t *stream_pool;
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
  u32 to_deq, to_read, hdr_size;
  u8 *rx_buf;

  to_deq = http_io_ts_max_read (stream);
  while (to_deq)
    {
      http3_frame_header_t fh = {};
      rx_buf = http_get_rx_buf (stream);
      to_read = clib_min (to_deq, HTTP3_FRAME_HEADER_MAX_LEN);
      http_io_ts_read (stream, rx_buf, to_read, 1);
      err = http3_frame_header_read (rx_buf, to_read, sctx->stream_type, &fh);
      if (err != HTTP3_ERROR_NO_ERROR)
	{
	  if (err == HTTP3_ERROR_INCOMPLETE)
	    {
	      HTTP_DBG (1, "frame header incomplete");
	      break;
	    }
	  else
	    {
	      HTTP_DBG (1, "invalid frame header");
	      /* FIXME: handle as error */
	      break;
	    }
	}
      hdr_size = (fh.payload - rx_buf);
      to_deq -= hdr_size;
      if (to_deq < fh.length)
	{
	  HTTP_DBG (1, "incomplete frame payload");
	  break;
	}
      http_io_ts_drain (stream, hdr_size);
      http_io_ts_read (stream, rx_buf, fh.length, 0);
      switch (fh.type)
	{
	case HTTP3_FRAME_TYPE_SETTINGS:
	  h3c =
	    http3_conn_ctx_get (sctx->h3c_index, sctx->base.c_thread_index);
	  if (!(h3c->flags & HTTP3_CONN_F_EXPECT_PEER_SETTINGS))
	    {
	      /* FIXME: handle as error */
	      return;
	    }
	  err =
	    http3_frame_settings_read (rx_buf, fh.length, &h3c->peer_settings);
	  if (err != HTTP3_ERROR_NO_ERROR)
	    {
	      /* FIXME: handle as error */
	      return;
	    }
	  h3c->flags &= ~HTTP3_CONN_F_EXPECT_PEER_SETTINGS;
	  HTTP_DBG (1, "settings received");
	  break;
	default:
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
}

/*****************/
/* http core VFT */
/*****************/

static void
http3_enable_callback (void)
{
  http3_main_t *h3m = &http3_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  num_threads = 1 /* main thread */ + vtm->n_threads;

  vec_validate (h3m->workers, num_threads - 1);
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
http3_app_tx_callback (http_conn_t *hc, u32 req_index,
		       transport_send_params_t *sp)
{
}

static void
http3_app_rx_evt_callback (http_conn_t *hc, u32 req_index,
			   clib_thread_index_t thread_index)
{
}

static void
http3_app_close_callback (http_conn_t *hc, u32 req_index,
			  clib_thread_index_t thread_index, u8 is_shutdown)
{
}

static void
http3_app_reset_callback (http_conn_t *hc, u32 req_index,
			  clib_thread_index_t thread_index)
{
}

static int
http3_transport_connected_callback (http_conn_t *hc)
{
  return 0;
}

static void
http3_transport_rx_callback (http_conn_t *hc)
{
  ASSERT (http_conn_is_stream (hc));
}

static void
http3_transport_close_callback (http_conn_t *hc)
{
}

static void
http3_transport_reset_callback (http_conn_t *hc)
{
}

static void
http3_transport_conn_reschedule_callback (http_conn_t *hc)
{
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
}

static void
http3_transport_stream_reset_callback (http_conn_t *stream)
{
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
  return 0;
}

static void
http3_conn_cleanup_callback (http_conn_t *hc)
{
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
