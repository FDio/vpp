/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <srtp/srtp.h>
#include <vnet/session/application_interface.h>

typedef struct srtp_main_
{
  u32 app_index;

  /*
   * Config
   */
  u64 first_seg_size;
  u32 fifo_size;
} srtp_main_t;

static srtp_main_t srtp_main;

void
srtp_session_reset_callback (session_t * s)
{
//  tls_ctx_t *ctx;
//  transport_connection_t *tc;
//  session_t *app_session;
//
//  ctx = tls_ctx_get (s->opaque);
//  ctx->is_passive_close = 1;
//  tc = &ctx->connection;
//  if (tls_ctx_handshake_is_over (ctx))
//    {
//      session_transport_reset_notify (tc);
//      session_transport_closed_notify (tc);
//      tls_disconnect_transport (ctx);
//    }
//  else
//    if ((app_session =
//	 session_get_if_valid (ctx->c_s_index, ctx->c_thread_index)))
//    {
//      session_free (app_session);
//      ctx->c_s_index = SESSION_INVALID_INDEX;
//      tls_disconnect_transport (ctx);
//    }
}

int
srtp_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
srtp_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

void
srtp_session_disconnect_callback (session_t * srtp_session)
{
//  tls_ctx_t *ctx;
//
//  TLS_DBG (1, "TCP disconnecting handle %x session %u", tls_session->opaque,
//	   tls_session->session_index);
//
//  ASSERT (tls_session->thread_index == vlib_get_thread_index ()
//	  || vlib_thread_is_main_w_barrier ());
//
//  ctx = tls_ctx_get_w_thread (tls_session->opaque, tls_session->thread_index);
//  ctx->is_passive_close = 1;
//  tls_ctx_transport_close (ctx);
}

int
srtp_session_accept_callback (session_t * srtp_session)
{
//  session_t *tls_listener, *app_session;
//  tls_ctx_t *lctx, *ctx;
//  u32 ctx_handle;
//
//  tls_listener =
//    listen_session_get_from_handle (tls_session->listener_handle);
//  lctx = tls_listener_ctx_get (tls_listener->opaque);
//
//  ctx_handle = tls_ctx_alloc (lctx->tls_ctx_engine);
//  ctx = tls_ctx_get (ctx_handle);
//  memcpy (ctx, lctx, sizeof (*lctx));
//  ctx->c_thread_index = vlib_get_thread_index ();
//  ctx->tls_ctx_handle = ctx_handle;
//  tls_session->session_state = SESSION_STATE_READY;
//  tls_session->opaque = ctx_handle;
//  ctx->tls_session_handle = session_handle (tls_session);
//  ctx->listener_ctx_index = tls_listener->opaque;
//  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
//  ctx->ckpair_index = lctx->ckpair_index;
//
//  /* Preallocate app session. Avoids allocating a session post handshake
//   * on tls_session rx and potentially invalidating the session pool */
//  app_session = session_alloc (ctx->c_thread_index);
//  app_session->session_state = SESSION_STATE_CREATED;
//  ctx->c_s_index = app_session->session_index;
//
//  TLS_DBG (1, "Accept on listener %u new connection [%u]%x",
//	   tls_listener->opaque, vlib_get_thread_index (), ctx_handle);
//
//  return tls_ctx_init_server (ctx);
}

int
srtp_app_rx_callback (session_t * srtp_session)
{
//  tls_ctx_t *ctx;
//
//  ctx = tls_ctx_get (tls_session->opaque);
//  tls_ctx_read (ctx, tls_session);
  return 0;
}

int
srtp_app_tx_callback (session_t * tls_session)
{
//  tls_ctx_t *ctx;
//
//  ctx = tls_ctx_get (tls_session->opaque);
//  transport_connection_reschedule (&ctx->connection);
//
  return 0;
}

static void
srtp_app_session_cleanup (session_t * s, session_cleanup_ntf_t ntf)
{
//  tls_ctx_t *ctx;
//
//  if (ntf == SESSION_CLEANUP_TRANSPORT)
//    {
//      /* Allow cleanup of tcp session */
//      if (s->session_state == SESSION_STATE_TRANSPORT_DELETED)
//	session_close (s);
//      return;
//    }
//
//  ctx = tls_ctx_get (s->opaque);
//  if (!ctx->no_app_session)
//    session_transport_delete_notify (&ctx->connection);
//  tls_ctx_free (ctx);
}


static session_cb_vft_t srtp_app_cb_vft = {
  .session_accept_callback = srtp_session_accept_callback,
  .session_disconnect_callback = srtp_session_disconnect_callback,
  .session_connected_callback = srtp_session_connected_callback,
  .session_reset_callback = srtp_session_reset_callback,
  .add_segment_callback = srtp_add_segment_callback,
  .del_segment_callback = srtp_del_segment_callback,
  .builtin_app_rx_callback = srtp_app_rx_callback,
  .builtin_app_tx_callback = srtp_app_tx_callback,
  .session_cleanup_callback = srtp_app_session_cleanup,
};

static clib_error_t *
srtp_enable (vlib_main_t * vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  srtp_main_t *sm = &srtp_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = sm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  first_seg_size = sm->first_seg_size ? sm->first_seg_size : first_seg_size;
  fifo_size = sm->fifo_size ? sm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &srtp_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "srtp");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach srtp app");
      return clib_error_return (0, "failed to attach srtp app");
    }

  sm->app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

int
srtp_connect (transport_endpoint_cfg_t * tep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  session_endpoint_cfg_t *sep;
  srtp_main_t *sm = &srtp_main;
  app_worker_t *app_wrk;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  ctx_index = tls_ctx_half_open_alloc ();
  ctx = tls_ctx_half_open_get (ctx_index);
  ctx->parent_app_wrk_index = sep->app_wrk_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->tcp_is_ip4 = sep->is_ip4;
  ctx->ckpair_index = sep->ckpair_index;
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
  cargs->app_index = sm->app_index;
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
  sep.transport_proto = TRANSPORT_PROTO_TLS;
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

  session_parse_handle (ctx->tls_session_handle, &tcp_si, &tcp_ti);
  tls_ctx_parse_handle (ctx->tls_ctx_handle, &ctx_index, &ctx_engine);
  s = format (s, "[%d:%d][TLS] app_wrk %u index %u engine %u tcp %d:%d",
	      ctx->c_thread_index, ctx->c_s_index,
	      ctx->parent_app_wrk_index, ctx_index,
	      ctx_engine, tcp_ti, tcp_si);

  return s;
}

static u8 *
format_tls_listener_ctx (u8 * s, va_list * args)
{
  session_t *tls_listener;
  app_listener_t *al;
  tls_ctx_t *ctx;

  ctx = va_arg (*args, tls_ctx_t *);

  al = app_listener_get_w_handle (ctx->tls_session_handle);
  tls_listener = app_listener_get_session (al);
  s = format (s, "[%d:%d][TLS] app_wrk %u engine %u tcp %d:%d",
	      ctx->c_thread_index, ctx->c_s_index,
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

static const transport_proto_vft_t srtp_proto = {
  .enable = srtp_enable,
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
    .name = "srtp",
    .short_name = "R",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
srtp_init (vlib_main_t * vm)
{
  transport_register_protocol (TRANSPORT_PROTO_SRTP, &srtp_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_TLS, &srtp_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (srtp_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Secure Real-time Transport Protocol (SRTP)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
