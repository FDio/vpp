/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/session/application_interface.h>
#include <vppinfra/lock.h>
#include <vnet/tls/tls.h>

static tls_main_t tls_main;
static tls_engine_vft_t *tls_vfts;

#define TLS_INVALID_HANDLE 	~0
#define TLS_IDX_MASK 		0x00FFFFFF
#define TLS_ENGINE_TYPE_SHIFT 	29

void tls_disconnect (u32 ctx_handle, u32 thread_index);

static void
tls_disconnect_transport (tls_ctx_t * ctx)
{
  vnet_disconnect_args_t a = {
    .handle = ctx->tls_session_handle,
    .app_index = tls_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect returned");
}

tls_engine_type_t
tls_get_available_engine (void)
{
  int i;
  for (i = 0; i < vec_len (tls_vfts); i++)
    {
      if (tls_vfts[i].ctx_alloc)
	return i;
    }
  return TLS_ENGINE_NONE;
}

int
tls_add_vpp_q_rx_evt (stream_session_t * s)
{
  if (svm_fifo_set_event (s->server_rx_fifo))
    session_send_io_evt_to_thread (s->server_rx_fifo, FIFO_EVENT_APP_RX);
  return 0;
}

int
tls_add_vpp_q_builtin_rx_evt (stream_session_t * s)
{
  if (svm_fifo_set_event (s->server_rx_fifo))
    session_send_io_evt_to_thread (s->server_rx_fifo, FIFO_EVENT_BUILTIN_RX);
  return 0;
}

int
tls_add_vpp_q_tx_evt (stream_session_t * s)
{
  if (svm_fifo_set_event (s->server_tx_fifo))
    session_send_io_evt_to_thread (s->server_tx_fifo, FIFO_EVENT_APP_TX);
  return 0;
}

int
tls_add_vpp_q_builtin_tx_evt (stream_session_t * s)
{
  if (svm_fifo_set_event (s->server_tx_fifo))
    session_send_io_evt_to_thread_custom (s, s->thread_index,
					  FIFO_EVENT_BUILTIN_TX);
  return 0;
}

static inline int
tls_add_app_q_evt (app_worker_t * app, stream_session_t * app_session)
{
  return app_worker_lock_and_send_event (app, app_session, FIFO_EVENT_APP_RX);
}

u32
tls_listener_ctx_alloc (void)
{
  tls_main_t *tm = &tls_main;
  tls_ctx_t *ctx;

  pool_get (tm->listener_ctx_pool, ctx);
  clib_memset (ctx, 0, sizeof (*ctx));
  return ctx - tm->listener_ctx_pool;
}

void
tls_listener_ctx_free (tls_ctx_t * ctx)
{
  if (CLIB_DEBUG)
    memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (tls_main.listener_ctx_pool, ctx);
}

tls_ctx_t *
tls_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (tls_main.listener_ctx_pool, ctx_index);
}

u32
tls_listener_ctx_index (tls_ctx_t * ctx)
{
  return (ctx - tls_main.listener_ctx_pool);
}

u32
tls_ctx_half_open_alloc (void)
{
  tls_main_t *tm = &tls_main;
  u8 will_expand = 0;
  tls_ctx_t *ctx;
  u32 ctx_index;

  pool_get_aligned_will_expand (tm->half_open_ctx_pool, will_expand, 0);
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&tm->half_open_rwlock);
      pool_get (tm->half_open_ctx_pool, ctx);
      ctx_index = ctx - tm->half_open_ctx_pool;
      clib_rwlock_writer_unlock (&tm->half_open_rwlock);
    }
  else
    {
      /* reader lock assumption: only main thread will call pool_get */
      clib_rwlock_reader_lock (&tm->half_open_rwlock);
      pool_get (tm->half_open_ctx_pool, ctx);
      ctx_index = ctx - tm->half_open_ctx_pool;
      clib_rwlock_reader_unlock (&tm->half_open_rwlock);
    }
  clib_memset (ctx, 0, sizeof (*ctx));
  return ctx_index;
}

void
tls_ctx_half_open_free (u32 ho_index)
{
  tls_main_t *tm = &tls_main;
  clib_rwlock_writer_lock (&tm->half_open_rwlock);
  pool_put_index (tls_main.half_open_ctx_pool, ho_index);
  clib_rwlock_writer_unlock (&tm->half_open_rwlock);
}

tls_ctx_t *
tls_ctx_half_open_get (u32 ctx_index)
{
  tls_main_t *tm = &tls_main;
  clib_rwlock_reader_lock (&tm->half_open_rwlock);
  return pool_elt_at_index (tm->half_open_ctx_pool, ctx_index);
}

void
tls_ctx_half_open_reader_unlock ()
{
  clib_rwlock_reader_unlock (&tls_main.half_open_rwlock);
}

u32
tls_ctx_half_open_index (tls_ctx_t * ctx)
{
  return (ctx - tls_main.half_open_ctx_pool);
}

void
tls_notify_app_enqueue (tls_ctx_t * ctx, stream_session_t * app_session)
{
  app_worker_t *app;
  app = app_worker_get_if_valid (app_session->app_wrk_index);
  if (PREDICT_TRUE (app != 0))
    tls_add_app_q_evt (app, app_session);
}

int
tls_notify_app_accept (tls_ctx_t * ctx)
{
  stream_session_t *app_listener, *app_session;
  segment_manager_t *sm;
  app_worker_t *app_wrk;
  application_t *app;
  tls_ctx_t *lctx;
  int rv;

  app_wrk = app_worker_get_if_valid (ctx->parent_app_index);
  if (!app_wrk)
    {
      tls_disconnect (ctx->tls_ctx_handle, vlib_get_thread_index ());
      return -1;
    }

  app = application_get (app_wrk->app_index);
  lctx = tls_listener_ctx_get (ctx->listener_ctx_index);

  app_session = session_alloc (vlib_get_thread_index ());
  app_session->app_wrk_index = ctx->parent_app_index;
  app_session->connection_index = ctx->tls_ctx_handle;

  app_listener = listen_session_get_from_handle (lctx->app_session_handle);
  app_session->session_type = app_listener->session_type;
  app_session->listener_index = app_listener->session_index;
  sm = app_worker_get_listen_segment_manager (app_wrk, app_listener);
  app_session->t_app_index = tls_main.app_index;

  if ((rv = session_alloc_fifos (sm, app_session)))
    {
      TLS_DBG (1, "failed to allocate fifos");
      return rv;
    }
  ctx->c_s_index = app_session->session_index;
  ctx->app_session_handle = session_handle (app_session);
  session_lookup_add_connection (&ctx->connection,
				 session_handle (app_session));
  return app->cb_fns.session_accept_callback (app_session);
}

int
tls_notify_app_connected (tls_ctx_t * ctx, u8 is_failed)
{
  int (*cb_fn) (u32, u32, stream_session_t *, u8);
  stream_session_t *app_session;
  segment_manager_t *sm;
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get_if_valid (ctx->parent_app_index);
  if (!app_wrk)
    {
      tls_disconnect_transport (ctx);
      return -1;
    }

  app = application_get (app_wrk->app_index);
  cb_fn = app->cb_fns.session_connected_callback;

  if (is_failed)
    goto failed;

  sm = app_worker_get_connect_segment_manager (app_wrk);
  app_session = session_alloc (vlib_get_thread_index ());
  app_session->app_wrk_index = ctx->parent_app_index;
  app_session->connection_index = ctx->tls_ctx_handle;
  app_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_TLS, ctx->tcp_is_ip4);
  app_session->t_app_index = tls_main.app_index;

  if (session_alloc_fifos (sm, app_session))
    goto failed;

  ctx->app_session_handle = session_handle (app_session);
  ctx->c_s_index = app_session->session_index;
  app_session->session_state = SESSION_STATE_CONNECTING;
  if (cb_fn (ctx->parent_app_index, ctx->parent_app_api_context,
	     app_session, 0 /* not failed */ ))
    {
      TLS_DBG (1, "failed to notify app");
      tls_disconnect (ctx->tls_ctx_handle, vlib_get_thread_index ());
      return -1;
    }

  app_session->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (&ctx->connection,
				 session_handle (app_session));

  return 0;

failed:
  tls_disconnect (ctx->tls_ctx_handle, vlib_get_thread_index ());
  return cb_fn (ctx->parent_app_index, ctx->parent_app_api_context, 0,
		1 /* failed */ );
}

static inline void
tls_ctx_parse_handle (u32 ctx_handle, u32 * ctx_index, u32 * engine_type)
{
  *ctx_index = ctx_handle & TLS_IDX_MASK;
  *engine_type = ctx_handle >> TLS_ENGINE_TYPE_SHIFT;
}

static inline tls_engine_type_t
tls_get_engine_type (tls_engine_type_t preferred)
{
  if (!tls_vfts[preferred].ctx_alloc)
    return tls_get_available_engine ();
  return preferred;
}

static inline u32
tls_ctx_alloc (tls_engine_type_t engine_type)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_alloc ();
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline void
tls_ctx_free (tls_ctx_t * ctx)
{
  vec_free (ctx->srv_hostname);
  tls_vfts[ctx->tls_ctx_engine].ctx_free (ctx);
}

static inline tls_ctx_t *
tls_ctx_get (u32 ctx_handle)
{
  u32 ctx_index, engine_type;
  tls_ctx_parse_handle (ctx_handle, &ctx_index, &engine_type);
  return tls_vfts[engine_type].ctx_get (ctx_index);
}

static inline tls_ctx_t *
tls_ctx_get_w_thread (u32 ctx_handle, u8 thread_index)
{
  u32 ctx_index, engine_type;
  tls_ctx_parse_handle (ctx_handle, &ctx_index, &engine_type);
  return tls_vfts[engine_type].ctx_get_w_thread (ctx_index, thread_index);
}

static inline int
tls_ctx_init_server (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_init_server (ctx);
}

static inline int
tls_ctx_init_client (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_init_client (ctx);
}

static inline int
tls_ctx_write (tls_ctx_t * ctx, stream_session_t * app_session)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_write (ctx, app_session);
}

static inline int
tls_ctx_read (tls_ctx_t * ctx, stream_session_t * tls_session)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_read (ctx, tls_session);
}

static inline u8
tls_ctx_handshake_is_over (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_handshake_is_over (ctx);
}

void
tls_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

int
tls_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
tls_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

void
tls_session_disconnect_callback (stream_session_t * tls_session)
{
  stream_session_t *app_session;
  tls_ctx_t *ctx;
  app_worker_t *app_wrk;
  application_t *app;

  ctx = tls_ctx_get (tls_session->opaque);
  if (!tls_ctx_handshake_is_over (ctx))
    {
      session_close (tls_session);
      return;
    }
  ctx->is_passive_close = 1;
  app_wrk = app_worker_get (ctx->parent_app_index);
  app = application_get (app_wrk->app_index);
  app_session = session_get_from_handle (ctx->app_session_handle);
  app->cb_fns.session_disconnect_callback (app_session);
}

int
tls_session_accept_callback (stream_session_t * tls_session)
{
  stream_session_t *tls_listener;
  tls_ctx_t *lctx, *ctx;
  u32 ctx_handle;

  tls_listener = listen_session_get (tls_session->listener_index);
  lctx = tls_listener_ctx_get (tls_listener->opaque);

  ctx_handle = tls_ctx_alloc (lctx->tls_ctx_engine);
  ctx = tls_ctx_get (ctx_handle);
  memcpy (ctx, lctx, sizeof (*lctx));
  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->tls_ctx_handle = ctx_handle;
  tls_session->session_state = SESSION_STATE_READY;
  tls_session->opaque = ctx_handle;
  ctx->tls_session_handle = session_handle (tls_session);
  ctx->listener_ctx_index = tls_listener->opaque;

  TLS_DBG (1, "Accept on listener %u new connection [%u]%x",
	   tls_listener->opaque, vlib_get_thread_index (), ctx_handle);

  return tls_ctx_init_server (ctx);
}

int
tls_app_tx_callback (stream_session_t * app_session)
{
  tls_ctx_t *ctx;
  if (PREDICT_FALSE (app_session->session_state == SESSION_STATE_CLOSED))
    return 0;
  ctx = tls_ctx_get (app_session->connection_index);
  tls_ctx_write (ctx, app_session);
  return 0;
}

int
tls_app_rx_callback (stream_session_t * tls_session)
{
  tls_ctx_t *ctx;

  ctx = tls_ctx_get (tls_session->opaque);
  tls_ctx_read (ctx, tls_session);
  return 0;
}

int
tls_session_connected_callback (u32 tls_app_index, u32 ho_ctx_index,
				stream_session_t * tls_session, u8 is_fail)
{
  tls_ctx_t *ho_ctx, *ctx;
  u32 ctx_handle;

  ho_ctx = tls_ctx_half_open_get (ho_ctx_index);

  if (is_fail)
    {
      int (*cb_fn) (u32, u32, stream_session_t *, u8), rv = 0;
      u32 wrk_index, api_context;
      app_worker_t *app_wrk;
      application_t *app;

      wrk_index = ho_ctx->parent_app_index;
      app_wrk = app_worker_get_if_valid (ho_ctx->parent_app_index);
      if (app_wrk)
	{
	  api_context = ho_ctx->c_s_index;
	  app = application_get (app_wrk->app_index);
	  cb_fn = app->cb_fns.session_connected_callback;
	  rv = cb_fn (wrk_index, api_context, 0, 1 /* failed */ );
	}
      tls_ctx_half_open_reader_unlock ();
      tls_ctx_half_open_free (ho_ctx_index);
      return rv;
    }

  ctx_handle = tls_ctx_alloc (ho_ctx->tls_ctx_engine);
  ctx = tls_ctx_get (ctx_handle);
  clib_memcpy_fast (ctx, ho_ctx, sizeof (*ctx));
  tls_ctx_half_open_reader_unlock ();
  tls_ctx_half_open_free (ho_ctx_index);

  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->tls_ctx_handle = ctx_handle;

  TLS_DBG (1, "TCP connect for %u returned %u. New connection [%u]%x",
	   ho_ctx_index, is_fail, vlib_get_thread_index (),
	   (ctx) ? ctx_handle : ~0);

  ctx->tls_session_handle = session_handle (tls_session);
  tls_session->opaque = ctx_handle;
  tls_session->session_state = SESSION_STATE_READY;

  return tls_ctx_init_client (ctx);
}

/* *INDENT-OFF* */
static session_cb_vft_t tls_app_cb_vft = {
  .session_accept_callback = tls_session_accept_callback,
  .session_disconnect_callback = tls_session_disconnect_callback,
  .session_connected_callback = tls_session_connected_callback,
  .session_reset_callback = tls_session_reset_callback,
  .add_segment_callback = tls_add_segment_callback,
  .del_segment_callback = tls_del_segment_callback,
  .builtin_app_rx_callback = tls_app_rx_callback,
  .builtin_app_tx_callback = tls_app_tx_callback,
};
/* *INDENT-ON* */

int
tls_connect (transport_endpoint_cfg_t * tep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  session_endpoint_cfg_t *sep;
  tls_engine_type_t engine_type;
  tls_main_t *tm = &tls_main;
  app_worker_t *app_wrk;
  clib_error_t *error;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_index;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  engine_type = tls_get_engine_type (app->tls_engine);
  if (engine_type == TLS_ENGINE_NONE)
    {
      clib_warning ("No tls engine_type available");
      return -1;
    }

  ctx_index = tls_ctx_half_open_alloc ();
  ctx = tls_ctx_half_open_get (ctx_index);
  ctx->parent_app_index = sep->app_wrk_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->tcp_is_ip4 = sep->is_ip4;
  if (sep->hostname)
    {
      ctx->srv_hostname = format (0, "%v", sep->hostname);
      vec_terminate_c_string (ctx->srv_hostname);
    }
  tls_ctx_half_open_reader_unlock ();

  app_worker_alloc_connects_segment_manager (app_wrk);
  ctx->tls_ctx_engine = engine_type;

  clib_memcpy_fast (&cargs->sep, sep, sizeof (session_endpoint_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_TCP;
  cargs->app_index = tm->app_index;
  cargs->api_context = ctx_index;
  if ((error = vnet_connect (cargs)))
    return clib_error_get_code (error);

  TLS_DBG (1, "New connect request %u engine %d", ctx_index, engine_type);
  return 0;
}

void
tls_disconnect (u32 ctx_handle, u32 thread_index)
{
  tls_ctx_t *ctx;

  TLS_DBG (1, "Disconnecting %x", ctx_handle);

  ctx = tls_ctx_get (ctx_handle);
  tls_disconnect_transport (ctx);
  session_transport_delete_notify (&ctx->connection);
  tls_ctx_free (ctx);
}

u32
tls_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  vnet_bind_args_t _bargs, *args = &_bargs;
  app_worker_t *app_wrk;
  tls_main_t *tm = &tls_main;
  session_handle_t tls_handle;
  session_endpoint_cfg_t *sep;
  stream_session_t *tls_listener;
  stream_session_t *app_listener;
  tls_engine_type_t engine_type;
  application_t *app;
  tls_ctx_t *lctx;
  u32 lctx_index;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  engine_type = tls_get_engine_type (app->tls_engine);
  if (engine_type == TLS_ENGINE_NONE)
    {
      clib_warning ("No tls engine_type available");
      return -1;
    }

  sep->transport_proto = TRANSPORT_PROTO_TCP;
  clib_memset (args, 0, sizeof (*args));
  args->app_index = tm->app_index;
  args->sep_ext = *sep;
  if (vnet_bind (args))
    return -1;

  tls_handle = args->handle;
  lctx_index = tls_listener_ctx_alloc ();
  tls_listener = listen_session_get_from_handle (tls_handle);
  tls_listener->opaque = lctx_index;

  app_listener = listen_session_get (app_listener_index);

  lctx = tls_listener_ctx_get (lctx_index);
  lctx->parent_app_index = sep->app_wrk_index;
  lctx->tls_session_handle = tls_handle;
  lctx->app_session_handle = listen_session_get_handle (app_listener);
  lctx->tcp_is_ip4 = sep->is_ip4;
  lctx->tls_ctx_engine = engine_type;

  tls_vfts[engine_type].ctx_start_listen (lctx);

  TLS_DBG (1, "Started listening %d, engine type %d", lctx_index,
	   engine_type);
  return lctx_index;
}

u32
tls_stop_listen (u32 lctx_index)
{
  tls_engine_type_t engine_type;
  tls_ctx_t *lctx;

  lctx = tls_listener_ctx_get (lctx_index);
  vnet_unbind_args_t a = {
    .handle = lctx->tls_session_handle,
    .app_index = tls_main.app_index,
    .wrk_map_index = 0		/* default wrk */
  };
  if (vnet_unbind (&a))
    clib_warning ("unbind returned");

  engine_type = lctx->tls_ctx_engine;
  tls_vfts[engine_type].ctx_stop_listen (lctx);

  tls_listener_ctx_free (lctx);
  return 0;
}

transport_connection_t *
tls_connection_get (u32 ctx_index, u32 thread_index)
{
  tls_ctx_t *ctx;
  ctx = tls_ctx_get_w_thread (ctx_index, thread_index);
  return &ctx->connection;
}

transport_connection_t *
tls_listener_get (u32 listener_index)
{
  tls_ctx_t *ctx;
  ctx = tls_listener_ctx_get (listener_index);
  return &ctx->connection;
}

u8 *
format_tls_ctx (u8 * s, va_list * args)
{
  tls_ctx_t *ctx = va_arg (*args, tls_ctx_t *);
  u32 thread_index = va_arg (*args, u32);
  u32 child_si, child_ti;

  session_parse_handle (ctx->tls_session_handle, &child_si, &child_ti);
  if (thread_index != child_ti)
    clib_warning ("app and tls sessions are on different threads!");

  s = format (s, "[#%d][TLS] app %u child %u", child_ti,
	      ctx->parent_app_index, child_si);
  return s;
}

u8 *
format_tls_connection (u8 * s, va_list * args)
{
  u32 ctx_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tls_ctx_t *ctx;

  ctx = tls_ctx_get_w_thread (ctx_index, thread_index);
  if (!ctx)
    return s;

  s = format (s, "%-50U", format_tls_ctx, ctx, thread_index);
  if (verbose)
    {
      stream_session_t *ts;
      ts = session_get_from_handle (ctx->app_session_handle);
      s = format (s, "state: %-7u", ts->session_state);
      if (verbose > 1)
	s = format (s, "\n");
    }
  return s;
}

u8 *
format_tls_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_listener_ctx_get (tc_index);
  u32 listener_index, thread_index;

  listen_session_parse_handle (ctx->tls_session_handle, &listener_index,
			       &thread_index);
  return format (s, "[TLS] listener app %u child %u", ctx->parent_app_index,
		 listener_index);
}

u8 *
format_tls_half_open (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_ctx_half_open_get (tc_index);
  s = format (s, "[TLS] half-open app %u", ctx->parent_app_index);
  tls_ctx_half_open_reader_unlock ();
  return s;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tls_proto = {
  .open = tls_connect,
  .close = tls_disconnect,
  .bind = tls_start_listen,
  .get_connection = tls_connection_get,
  .get_listener = tls_listener_get,
  .unbind = tls_stop_listen,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_tls_connection,
  .format_half_open = format_tls_half_open,
  .format_listener = format_tls_listener,
};
/* *INDENT-ON* */

void
tls_register_engine (const tls_engine_vft_t * vft, tls_engine_type_t type)
{
  vec_validate (tls_vfts, type);
  tls_vfts[type] = *vft;
}

static clib_error_t *
tls_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u32 segment_size = 512 << 20;
  tls_main_t *tm = &tls_main;
  u32 fifo_size = 64 << 10;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &tls_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "tls");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach tls app");
      return clib_error_return (0, "failed to attach tls app");
    }

  if (!tm->ca_cert_path)
    tm->ca_cert_path = TLS_CA_CERT_PATH;

  tm->app_index = a->app_index;
  clib_rwlock_init (&tm->half_open_rwlock);

  vec_validate (tm->rx_bufs, num_threads - 1);
  vec_validate (tm->tx_bufs, num_threads - 1);

  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP6, ~0);
  vec_free (a->name);
  return 0;
}

VLIB_INIT_FUNCTION (tls_init);

static clib_error_t *
tls_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  tls_main_t *tm = &tls_main;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "use-test-cert-in-ca"))
	tm->use_test_cert_in_ca = 1;
      else if (unformat (input, "ca-cert-path %s", &tm->ca_cert_path))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (tls_config_fn, "tls");

tls_main_t *
vnet_tls_get_main (void)
{
  return &tls_main;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
