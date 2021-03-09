/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
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

void
tls_disconnect_transport (tls_ctx_t * ctx)
{
  vnet_disconnect_args_t a = {
    .handle = ctx->tls_session_handle,
    .app_index = tls_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect returned");
}

crypto_engine_type_t
tls_get_available_engine (void)
{
  int i;
  for (i = 0; i < vec_len (tls_vfts); i++)
    {
      if (tls_vfts[i].ctx_alloc)
	return i;
    }
  return CRYPTO_ENGINE_NONE;
}

int
tls_add_vpp_q_rx_evt (session_t * s)
{
  if (svm_fifo_set_event (s->rx_fifo))
    session_send_io_evt_to_thread (s->rx_fifo, SESSION_IO_EVT_RX);
  return 0;
}

int
tls_add_vpp_q_builtin_rx_evt (session_t * s)
{
  if (svm_fifo_set_event (s->rx_fifo))
    session_send_io_evt_to_thread (s->rx_fifo, SESSION_IO_EVT_BUILTIN_RX);
  return 0;
}

int
tls_add_vpp_q_tx_evt (session_t * s)
{
  if (svm_fifo_set_event (s->tx_fifo))
    session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);
  return 0;
}

static inline int
tls_add_app_q_evt (app_worker_t * app, session_t * app_session)
{
  return app_worker_lock_and_send_event (app, app_session, SESSION_IO_EVT_RX);
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
tls_notify_app_enqueue (tls_ctx_t * ctx, session_t * app_session)
{
  app_worker_t *app_wrk;
  app_wrk = app_worker_get_if_valid (app_session->app_wrk_index);
  if (PREDICT_TRUE (app_wrk != 0))
    tls_add_app_q_evt (app_wrk, app_session);
}

int
tls_notify_app_accept (tls_ctx_t * ctx)
{
  session_t *app_listener, *app_session;
  app_worker_t *app_wrk;
  tls_ctx_t *lctx;
  int rv;

  lctx = tls_listener_ctx_get (ctx->listener_ctx_index);
  app_listener = listen_session_get_from_handle (lctx->app_session_handle);

  app_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  app_session->app_wrk_index = ctx->parent_app_wrk_index;
  app_session->connection_index = ctx->tls_ctx_handle;
  app_session->session_type = app_listener->session_type;
  app_session->listener_handle = listen_session_get_handle (app_listener);
  app_session->session_state = SESSION_STATE_ACCEPTING;

  if ((rv = app_worker_init_accepted (app_session)))
    {
      TLS_DBG (1, "failed to allocate fifos");
      session_free (app_session);
      return rv;
    }
  ctx->app_session_handle = session_handle (app_session);
  ctx->parent_app_wrk_index = app_session->app_wrk_index;
  app_wrk = app_worker_get (app_session->app_wrk_index);
  return app_worker_accept_notify (app_wrk, app_session);
}

int
tls_notify_app_connected (tls_ctx_t * ctx, session_error_t err)
{
  session_t *app_session;
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_index);
  if (!app_wrk)
    {
      tls_disconnect_transport (ctx);
      return -1;
    }

  if (err)
    {
      /* Free app session pre-allocated when transport was established */
      if (ctx->tls_type == TRANSPORT_PROTO_TLS)
	session_free (session_get (ctx->c_s_index, ctx->c_thread_index));
      goto failed;
    }

  /* For DTLS the app session is not preallocated because the underlying udp
   * session might migrate to a different worker during the handshake */
  if (ctx->tls_type == TRANSPORT_PROTO_DTLS)
    {
      session_type_t st;
      app_session = session_alloc (ctx->c_thread_index);
      app_session->session_state = SESSION_STATE_CREATED;
      ctx->c_s_index = app_session->session_index;
      st =
	session_type_from_proto_and_ip (TRANSPORT_PROTO_DTLS, ctx->tcp_is_ip4);
      app_session->session_type = st;
      app_session->connection_index = ctx->tls_ctx_handle;
    }
  else
    {
      app_session = session_get (ctx->c_s_index, ctx->c_thread_index);
    }

  app_session->app_wrk_index = ctx->parent_app_wrk_index;

  if ((err = app_worker_init_connected (app_wrk, app_session)))
    goto failed;

  app_session->session_state = SESSION_STATE_READY;
  if (app_worker_connect_notify (app_wrk, app_session,
				 SESSION_E_NONE, ctx->parent_app_api_context))
    {
      TLS_DBG (1, "failed to notify app");
      app_session->session_state = SESSION_STATE_CONNECTING;
      tls_disconnect (ctx->tls_ctx_handle, vlib_get_thread_index ());
      return -1;
    }

  ctx->app_session_handle = session_handle (app_session);

  return 0;

failed:
  ctx->no_app_session = 1;
  tls_disconnect (ctx->tls_ctx_handle, vlib_get_thread_index ());
  return app_worker_connect_notify (app_wrk, 0, err,
				    ctx->parent_app_api_context);
}

static inline void
tls_ctx_parse_handle (u32 ctx_handle, u32 * ctx_index, u32 * engine_type)
{
  *ctx_index = ctx_handle & TLS_IDX_MASK;
  *engine_type = ctx_handle >> TLS_ENGINE_TYPE_SHIFT;
}

static inline crypto_engine_type_t
tls_get_engine_type (crypto_engine_type_t preferred)
{
  if (!tls_vfts[preferred].ctx_alloc)
    return tls_get_available_engine ();
  return preferred;
}

static inline u32
tls_ctx_alloc (crypto_engine_type_t engine_type)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_alloc ();
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline u32
tls_ctx_alloc_w_thread (crypto_engine_type_t engine_type, u32 thread_index)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_alloc_w_thread (thread_index);
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline u32
tls_ctx_attach (crypto_engine_type_t engine_type, u32 thread_index, void *ctx)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_attach (thread_index, ctx);
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline void *
tls_ctx_detach (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_detach (ctx);
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
tls_ctx_write (tls_ctx_t * ctx, session_t * app_session,
	       transport_send_params_t * sp)
{
  u32 n_wrote;

  sp->max_burst_size = sp->max_burst_size * TRANSPORT_PACER_MIN_MSS;
  n_wrote = tls_vfts[ctx->tls_ctx_engine].ctx_write (ctx, app_session, sp);
  sp->max_burst_size = n_wrote;
  return n_wrote > 0 ? clib_max (n_wrote / TRANSPORT_PACER_MIN_MSS, 1) : 0;
}

static inline int
tls_ctx_read (tls_ctx_t * ctx, session_t * tls_session)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_read (ctx, tls_session);
}

static inline int
tls_ctx_transport_close (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_transport_close (ctx);
}

static inline int
tls_ctx_app_close (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_app_close (ctx);
}

void
tls_ctx_free (tls_ctx_t * ctx)
{
  tls_vfts[ctx->tls_ctx_engine].ctx_free (ctx);
}

u8
tls_ctx_handshake_is_over (tls_ctx_t * ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_handshake_is_over (ctx);
}

void
tls_session_reset_callback (session_t * s)
{
  tls_ctx_t *ctx;
  transport_connection_t *tc;
  session_t *app_session;

  ctx = tls_ctx_get (s->opaque);
  ctx->is_passive_close = 1;
  tc = &ctx->connection;
  if (tls_ctx_handshake_is_over (ctx))
    {
      session_transport_reset_notify (tc);
      session_transport_closed_notify (tc);
      tls_disconnect_transport (ctx);
    }
  else
    if ((app_session =
	 session_get_if_valid (ctx->c_s_index, ctx->c_thread_index)))
    {
      session_free (app_session);
      ctx->c_s_index = SESSION_INVALID_INDEX;
      tls_disconnect_transport (ctx);
    }
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
tls_session_disconnect_callback (session_t * tls_session)
{
  tls_ctx_t *ctx;

  TLS_DBG (1, "TCP disconnecting handle %x session %u", tls_session->opaque,
	   tls_session->session_index);

  ASSERT (tls_session->thread_index == vlib_get_thread_index ()
	  || vlib_thread_is_main_w_barrier ());

  ctx = tls_ctx_get_w_thread (tls_session->opaque, tls_session->thread_index);
  ctx->is_passive_close = 1;
  tls_ctx_transport_close (ctx);
}

int
tls_session_accept_callback (session_t * tls_session)
{
  session_t *tls_listener, *app_session;
  tls_ctx_t *lctx, *ctx;
  u32 ctx_handle;

  tls_listener =
    listen_session_get_from_handle (tls_session->listener_handle);
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
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  ctx->ckpair_index = lctx->ckpair_index;

  /* Preallocate app session. Avoids allocating a session post handshake
   * on tls_session rx and potentially invalidating the session pool */
  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  ctx->c_s_index = app_session->session_index;

  TLS_DBG (1, "Accept on listener %u new connection [%u]%x",
	   tls_listener->opaque, vlib_get_thread_index (), ctx_handle);

  return tls_ctx_init_server (ctx);
}

int
tls_app_rx_callback (session_t * tls_session)
{
  tls_ctx_t *ctx;

  /* DTLS session migrating, wait for next notification */
  if (PREDICT_FALSE (tls_session->flags & SESSION_F_IS_MIGRATING))
    return 0;

  ctx = tls_ctx_get (tls_session->opaque);
  tls_ctx_read (ctx, tls_session);
  return 0;
}

int
tls_app_tx_callback (session_t * tls_session)
{
  tls_ctx_t *ctx;

  ctx = tls_ctx_get (tls_session->opaque);
  transport_connection_reschedule (&ctx->connection);

  return 0;
}

int
tls_session_connected_cb (u32 tls_app_index, u32 ho_ctx_index,
			  session_t *tls_session, session_error_t err)
{
  session_t *app_session;
  tls_ctx_t *ho_ctx, *ctx;
  session_type_t st;
  u32 ctx_handle;

  ho_ctx = tls_ctx_half_open_get (ho_ctx_index);

  if (err)
    {
      app_worker_t *app_wrk;
      u32 api_context;
      int rv = 0;

      app_wrk = app_worker_get_if_valid (ho_ctx->parent_app_wrk_index);
      if (app_wrk)
	{
	  api_context = ho_ctx->c_s_index;
	  app_worker_connect_notify (app_wrk, 0, err, api_context);
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
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  TLS_DBG (1, "TCP connect for %u returned %u. New connection [%u]%x",
	   ho_ctx_index, err, vlib_get_thread_index (),
	   (ctx) ? ctx_handle : ~0);

  ctx->tls_session_handle = session_handle (tls_session);
  tls_session->opaque = ctx_handle;
  tls_session->session_state = SESSION_STATE_READY;

  /* Preallocate app session. Avoids allocating a session post handshake
   * on tls_session rx and potentially invalidating the session pool */
  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  ctx->c_s_index = app_session->session_index;
  st = session_type_from_proto_and_ip (TRANSPORT_PROTO_TLS, ctx->tcp_is_ip4);
  app_session->session_type = st;
  app_session->connection_index = ctx->tls_ctx_handle;

  return tls_ctx_init_client (ctx);
}

int
dtls_session_connected_cb (u32 app_wrk_index, u32 ctx_handle, session_t *us,
			   session_error_t err)
{
  tls_ctx_t *ctx;

  ctx = tls_ctx_get_w_thread (ctx_handle, 1 /* udp allocs on thread 1 */);

  ctx->tls_session_handle = session_handle (us);
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  us->opaque = ctx_handle;

  /* We don't preallocate the app session because the udp session might
   * actually migrate to a different worker at the end of the handshake */

  return tls_ctx_init_client (ctx);
}

int
tls_session_connected_callback (u32 tls_app_index, u32 ho_ctx_index,
				session_t *tls_session, session_error_t err)
{
  if (session_get_transport_proto (tls_session) == TRANSPORT_PROTO_TCP)
    return tls_session_connected_cb (tls_app_index, ho_ctx_index, tls_session,
				     err);
  else
    return dtls_session_connected_cb (tls_app_index, ho_ctx_index, tls_session,
				      err);
}

static void
tls_app_session_cleanup (session_t * s, session_cleanup_ntf_t ntf)
{
  tls_ctx_t *ctx;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    {
      /* Allow cleanup of tcp session */
      if (s->session_state == SESSION_STATE_TRANSPORT_DELETED)
	session_close (s);
      return;
    }

  ctx = tls_ctx_get (s->opaque);
  if (!ctx->no_app_session)
    session_transport_delete_notify (&ctx->connection);
  tls_ctx_free (ctx);
}

static void
dtls_migrate_udp (void *arg)
{
  tls_ctx_t *ctx = (tls_ctx_t *) arg;
  u32 ctx_handle, thread_index;
  session_t *us;

  thread_index = session_thread_from_handle (ctx->tls_session_handle);
  ASSERT (thread_index == vlib_get_thread_index ());

  ctx_handle = tls_ctx_attach (ctx->tls_ctx_engine, thread_index, ctx);
  ctx = tls_ctx_get_w_thread (ctx_handle, thread_index);
  ctx->tls_ctx_handle = ctx_handle;

  us = session_get_from_handle (ctx->tls_session_handle);
  us->opaque = ctx_handle;
  us->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (us->tx_fifo))
    session_send_io_evt_to_thread (us->tx_fifo, SESSION_IO_EVT_TX);
}

static void
dtls_session_migrate_callback (session_t *us, session_handle_t new_sh)
{
  u32 new_thread = session_thread_from_handle (new_sh);
  tls_ctx_t *ctx;

  /* Migrate dtls context to new thread */
  ctx = tls_ctx_get_w_thread (us->opaque, us->thread_index);
  ctx->tls_session_handle = new_sh;
  ctx = tls_ctx_detach (ctx);
  ctx->is_migrated = 1;

  session_send_rpc_evt_to_thread (new_thread, dtls_migrate_udp, (void *) ctx);
}

static session_cb_vft_t tls_app_cb_vft = {
  .session_accept_callback = tls_session_accept_callback,
  .session_disconnect_callback = tls_session_disconnect_callback,
  .session_connected_callback = tls_session_connected_callback,
  .session_reset_callback = tls_session_reset_callback,
  .add_segment_callback = tls_add_segment_callback,
  .del_segment_callback = tls_del_segment_callback,
  .builtin_app_rx_callback = tls_app_rx_callback,
  .builtin_app_tx_callback = tls_app_tx_callback,
  .session_migrate_callback = dtls_session_migrate_callback,
  .session_cleanup_callback = tls_app_session_cleanup,
};

int
tls_connect (transport_endpoint_cfg_t * tep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  crypto_engine_type_t engine_type;
  session_endpoint_cfg_t *sep;
  tls_main_t *tm = &tls_main;
  app_worker_t *app_wrk;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  engine_type = tls_get_engine_type (app->tls_engine);
  if (engine_type == CRYPTO_ENGINE_NONE)
    {
      clib_warning ("No tls engine_type available");
      return -1;
    }

  ctx_index = tls_ctx_half_open_alloc ();
  ctx = tls_ctx_half_open_get (ctx_index);
  ctx->parent_app_wrk_index = sep->app_wrk_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->tcp_is_ip4 = sep->is_ip4;
  ctx->ckpair_index = sep->ckpair_index;
  ctx->tls_type = sep->transport_proto;
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
  cargs->sep_ext.ns_index = app->ns_index;
  if ((rv = vnet_connect (cargs)))
    return rv;

  TLS_DBG (1, "New connect request %u engine %d", ctx_index, engine_type);
  return 0;
}

void
tls_disconnect (u32 ctx_handle, u32 thread_index)
{
  tls_ctx_t *ctx;

  TLS_DBG (1, "Disconnecting %x", ctx_handle);

  ctx = tls_ctx_get (ctx_handle);
  tls_ctx_app_close (ctx);
}

u32
tls_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  vnet_listen_args_t _bargs, *args = &_bargs;
  app_worker_t *app_wrk;
  tls_main_t *tm = &tls_main;
  session_handle_t tls_al_handle;
  session_endpoint_cfg_t *sep;
  session_t *tls_listener;
  session_t *app_listener;
  crypto_engine_type_t engine_type;
  application_t *app;
  app_listener_t *al;
  tls_ctx_t *lctx;
  u32 lctx_index;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  engine_type = tls_get_engine_type (app->tls_engine);
  if (engine_type == CRYPTO_ENGINE_NONE)
    {
      clib_warning ("No tls engine_type available");
      return -1;
    }

  clib_memset (args, 0, sizeof (*args));
  args->app_index = tm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  args->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  if (sep->transport_proto == TRANSPORT_PROTO_DTLS)
    {
      args->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
      args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
    }
  if (vnet_listen (args))
    return -1;

  lctx_index = tls_listener_ctx_alloc ();
  tls_al_handle = args->handle;
  al = app_listener_get_w_handle (tls_al_handle);
  tls_listener = app_listener_get_session (al);
  tls_listener->opaque = lctx_index;

  app_listener = listen_session_get (app_listener_index);

  lctx = tls_listener_ctx_get (lctx_index);
  lctx->parent_app_wrk_index = sep->app_wrk_index;
  lctx->tls_session_handle = tls_al_handle;
  lctx->app_session_handle = listen_session_get_handle (app_listener);
  lctx->tcp_is_ip4 = sep->is_ip4;
  lctx->tls_ctx_engine = engine_type;
  lctx->ckpair_index = sep->ckpair_index;
  lctx->tls_type = sep->transport_proto;

  if (tls_vfts[engine_type].ctx_start_listen (lctx))
    {
      vnet_unlisten_args_t a = {
	.handle = lctx->tls_session_handle,
	.app_index = tls_main.app_index,
	.wrk_map_index = 0
      };
      if ((vnet_unlisten (&a)))
	clib_warning ("unlisten returned");
      tls_listener_ctx_free (lctx);
      lctx_index = SESSION_INVALID_INDEX;
    }

  TLS_DBG (1, "Started listening %d, engine type %d", lctx_index,
	   engine_type);
  return lctx_index;
}

u32
tls_stop_listen (u32 lctx_index)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  crypto_engine_type_t engine_type;
  transport_connection_t *lc;
  tls_ctx_t *lctx;
  session_t *ls;
  int rv;

  lctx = tls_listener_ctx_get (lctx_index);

  /* Cleanup listener from session lookup table */
  ls = session_get_from_handle (lctx->tls_session_handle);
  lc = session_get_transport (ls);

  sep.fib_index = lc->fib_index;
  sep.port = lc->lcl_port;
  sep.is_ip4 = lc->is_ip4;
  sep.transport_proto = lctx->tls_type;
  clib_memcpy (&sep.ip, &lc->lcl_ip, sizeof (lc->lcl_ip));
  session_lookup_del_session_endpoint2 (&sep);

  vnet_unlisten_args_t a = {
    .handle = lctx->tls_session_handle,
    .app_index = tls_main.app_index,
    .wrk_map_index = 0		/* default wrk */
  };
  if ((rv = vnet_unlisten (&a)))
    clib_warning ("unlisten returned %d", rv);

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

int
tls_custom_tx_callback (void *session, transport_send_params_t * sp)
{
  session_t *app_session = (session_t *) session;
  tls_ctx_t *ctx;

  if (PREDICT_FALSE (app_session->session_state
		     >= SESSION_STATE_TRANSPORT_CLOSED))
    return 0;

  sp->flags = 0;
  ctx = tls_ctx_get (app_session->connection_index);
  return tls_ctx_write (ctx, app_session, sp);
}

u8 *
format_tls_ctx (u8 * s, va_list * args)
{
  u32 tcp_si, tcp_ti, ctx_index, ctx_engine;
  tls_ctx_t *ctx = va_arg (*args, tls_ctx_t *);
  char *proto;

  proto = ctx->tls_type == TRANSPORT_PROTO_TLS ? "TLS" : "DTLS";
  session_parse_handle (ctx->tls_session_handle, &tcp_si, &tcp_ti);
  tls_ctx_parse_handle (ctx->tls_ctx_handle, &ctx_index, &ctx_engine);
  s =
    format (s, "[%d:%d][%s] app_wrk %u index %u engine %u ts %d:%d",
	    ctx->c_thread_index, ctx->c_s_index, proto,
	    ctx->parent_app_wrk_index, ctx_index, ctx_engine, tcp_ti, tcp_si);

  return s;
}

static u8 *
format_tls_listener_ctx (u8 * s, va_list * args)
{
  session_t *tls_listener;
  app_listener_t *al;
  tls_ctx_t *ctx;
  char *proto;

  ctx = va_arg (*args, tls_ctx_t *);

  proto = ctx->tls_type == TRANSPORT_PROTO_TLS ? "TLS" : "DTLS";
  al = app_listener_get_w_handle (ctx->tls_session_handle);
  tls_listener = app_listener_get_session (al);
  s = format (s, "[%d:%d][%s] app_wrk %u engine %u ts %d:%d",
	      ctx->c_thread_index, ctx->c_s_index, proto,
	      ctx->parent_app_wrk_index, ctx->tls_ctx_engine,
	      tls_listener->thread_index, tls_listener->session_index);

  return s;
}

static u8 *
format_tls_ctx_state (u8 * s, va_list * args)
{
  tls_ctx_t *ctx;
  session_t *ts;

  ctx = va_arg (*args, tls_ctx_t *);
  ts = session_get (ctx->c_s_index, ctx->c_thread_index);
  if (ts->session_state == SESSION_STATE_LISTENING)
    s = format (s, "%s", "LISTEN");
  else
    {
      if (ts->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
	s = format (s, "%s", "CLOSED");
      else if (ts->session_state == SESSION_STATE_APP_CLOSED)
	s = format (s, "%s", "APP-CLOSED");
      else if (ts->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	s = format (s, "%s", "CLOSING");
      else if (tls_ctx_handshake_is_over (ctx))
	s = format (s, "%s", "ESTABLISHED");
      else
	s = format (s, "%s", "HANDSHAKE");
    }

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

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_tls_ctx, ctx);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_tls_ctx_state,
		  ctx);
      if (verbose > 1)
	s = format (s, "\n");
    }
  return s;
}

u8 *
format_tls_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_listener_ctx_get (tc_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_tls_listener_ctx, ctx);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_tls_ctx_state, ctx);
  return s;
}

u8 *
format_tls_half_open (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_ctx_half_open_get (tc_index);
  s = format (s, "[TLS] half-open app %u", ctx->parent_app_wrk_index);
  tls_ctx_half_open_reader_unlock ();
  return s;
}

static void
tls_transport_endpoint_get (u32 ctx_handle, u32 thread_index,
			    transport_endpoint_t * tep, u8 is_lcl)
{
  tls_ctx_t *ctx = tls_ctx_get_w_thread (ctx_handle, thread_index);
  session_t *tcp_session;

  tcp_session = session_get_from_handle (ctx->tls_session_handle);
  session_get_endpoint (tcp_session, tep, is_lcl);
}

static void
tls_transport_listener_endpoint_get (u32 ctx_handle,
				     transport_endpoint_t * tep, u8 is_lcl)
{
  session_t *tls_listener;
  app_listener_t *al;
  tls_ctx_t *ctx = tls_listener_ctx_get (ctx_handle);

  al = app_listener_get_w_handle (ctx->tls_session_handle);
  tls_listener = app_listener_get_session (al);
  session_get_endpoint (tls_listener, tep, is_lcl);
}

static clib_error_t *
tls_enable (vlib_main_t * vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  tls_main_t *tm = &tls_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = tm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  first_seg_size = tm->first_seg_size ? tm->first_seg_size : first_seg_size;
  fifo_size = tm->fifo_size ? tm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &tls_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "tls");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
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

  tm->app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

static const transport_proto_vft_t tls_proto = {
  .enable = tls_enable,
  .connect = tls_connect,
  .close = tls_disconnect,
  .start_listen = tls_start_listen,
  .stop_listen = tls_stop_listen,
  .get_connection = tls_connection_get,
  .get_listener = tls_listener_get,
  .custom_tx = tls_custom_tx_callback,
  .format_connection = format_tls_connection,
  .format_half_open = format_tls_half_open,
  .format_listener = format_tls_listener,
  .get_transport_endpoint = tls_transport_endpoint_get,
  .get_transport_listener_endpoint = tls_transport_listener_endpoint_get,
  .transport_options = {
    .name = "tls",
    .short_name = "J",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

int
dtls_connect (transport_endpoint_cfg_t *tep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  crypto_engine_type_t engine_type;
  session_endpoint_cfg_t *sep;
  tls_main_t *tm = &tls_main;
  app_worker_t *app_wrk;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_handle;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  engine_type = tls_get_engine_type (app->tls_engine);
  if (engine_type == CRYPTO_ENGINE_NONE)
    {
      clib_warning ("No tls engine_type available");
      return -1;
    }

  ctx_handle = tls_ctx_alloc_w_thread (engine_type, 1 /* because of udp */);
  ctx = tls_ctx_get_w_thread (ctx_handle, 1);
  ctx->parent_app_wrk_index = sep->app_wrk_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->tcp_is_ip4 = sep->is_ip4;
  ctx->ckpair_index = sep->ckpair_index;
  ctx->tls_type = sep->transport_proto;
  ctx->tls_ctx_handle = ctx_handle;
  if (sep->hostname)
    {
      ctx->srv_hostname = format (0, "%v", sep->hostname);
      vec_terminate_c_string (ctx->srv_hostname);
    }

  app_worker_alloc_connects_segment_manager (app_wrk);
  ctx->tls_ctx_engine = engine_type;

  clib_memcpy_fast (&cargs->sep, sep, sizeof (session_endpoint_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDP;
  cargs->app_index = tm->app_index;
  cargs->api_context = ctx_handle;
  cargs->sep_ext.ns_index = app->ns_index;
  cargs->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if ((rv = vnet_connect (cargs)))
    return rv;

  TLS_DBG (1, "New DTLS connect request %x engine %d", ctx_handle,
	   engine_type);
  return 0;
}

static void
dtls_cleanup_callback (u32 ctx_index, u32 thread_index)
{
  /* No op */
}

static const transport_proto_vft_t dtls_proto = {
  .enable = 0,
  .connect = dtls_connect,
  .close = tls_disconnect,
  .start_listen = tls_start_listen,
  .stop_listen = tls_stop_listen,
  .get_connection = tls_connection_get,
  .get_listener = tls_listener_get,
  .custom_tx = tls_custom_tx_callback,
  .cleanup = dtls_cleanup_callback,
  .format_connection = format_tls_connection,
  .format_half_open = format_tls_half_open,
  .format_listener = format_tls_listener,
  .get_transport_endpoint = tls_transport_endpoint_get,
  .get_transport_listener_endpoint = tls_transport_listener_endpoint_get,
  .transport_options = {
    .name = "dtls",
    .short_name = "D",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

void
tls_register_engine (const tls_engine_vft_t * vft, crypto_engine_type_t type)
{
  vec_validate (tls_vfts, type);
  tls_vfts[type] = *vft;
}

static clib_error_t *
tls_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  tls_main_t *tm = &tls_main;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (!tm->ca_cert_path)
    tm->ca_cert_path = TLS_CA_CERT_PATH;

  clib_rwlock_init (&tm->half_open_rwlock);

  vec_validate (tm->rx_bufs, num_threads - 1);
  vec_validate (tm->tx_bufs, num_threads - 1);

  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP6, ~0);

  transport_register_protocol (TRANSPORT_PROTO_DTLS, &dtls_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_DTLS, &dtls_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (tls_init);

static clib_error_t *
tls_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  tls_main_t *tm = &tls_main;
  uword tmp;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "use-test-cert-in-ca"))
	tm->use_test_cert_in_ca = 1;
      else if (unformat (input, "ca-cert-path %s", &tm->ca_cert_path))
	;
      else if (unformat (input, "first-segment-size %U", unformat_memory_size,
			 &tm->first_seg_size))
	;
      else if (unformat (input, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      return clib_error_return
		(0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	    }
	  tm->fifo_size = tmp;
	}
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
