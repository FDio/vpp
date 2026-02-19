/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <sys/socket.h>
#include <sys/syscall.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>
#include <quic/quic_timer.h>
#include <quic/quic_eng_inline.h>

static vlib_error_desc_t quic_error_counters[] = {
#define quic_error(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
#include <quic/quic_error.def>
#undef quic_error
};

quic_main_t quic_main;
quic_engine_vft_t *quic_engine_vfts;

static_always_inline quic_engine_type_t
quic_get_engine_type (quic_engine_type_t requested,
		      quic_engine_type_t preferred)
{
  quic_engine_type_t engine_type = QUIC_ENGINE_NONE;

  if ((requested != QUIC_ENGINE_NONE) &&
      (vec_len (quic_engine_vfts) > requested) &&
      (quic_engine_vfts[requested].engine_init))
    {
      engine_type = requested;
    }
  else if ((preferred != QUIC_ENGINE_NONE) &&
	   (vec_len (quic_engine_vfts) > preferred) &&
	   (quic_engine_vfts[preferred].engine_init))
    {
      engine_type = preferred;
    }
  return engine_type;
}

__clib_export void
quic_register_engine (const quic_engine_vft_t *vft,
		      quic_engine_type_t engine_type)
{
  vec_validate (quic_engine_vfts, engine_type);
  quic_engine_vfts[engine_type] = *vft;
}

/* Transport proto functions */
static_always_inline void
quic_ctx_set_alpn_protos (quic_ctx_t *ctx, transport_endpt_crypto_cfg_t *ccfg)
{
  ctx->alpn_protos[0] = ccfg->alpn_protos[0];
  ctx->alpn_protos[1] = ccfg->alpn_protos[1];
  ctx->alpn_protos[2] = ccfg->alpn_protos[2];
  ctx->alpn_protos[3] = ccfg->alpn_protos[3];
}

static int
quic_connect_connection (transport_endpoint_cfg_t *tep)
{
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) tep;
  vnet_connect_args_t _cargs = {}, *cargs = &_cargs;
  transport_endpt_crypto_cfg_t *ccfg;
  quic_main_t *qm = &quic_main;
  u32 ctx_index, thread_index;
  quic_ctx_t *ctx;
  app_worker_t *app_wrk;
  application_t *app;
  transport_endpt_ext_cfg_t *ext_cfg;
  int error;

  ext_cfg = session_endpoint_get_ext_cfg (sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
  if (!ext_cfg)
    return SESSION_E_NOEXTCFG;

  /* Use pool on thread 1 if we have workers because of UDP */
  thread_index = transport_cl_thread ();
  ccfg = &ext_cfg->crypto;

  ctx_index = quic_ctx_alloc (qm, thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->parent_app_wrk_id = sep->app_wrk_index;
  ctx->c_s_index = SESSION_INVALID_INDEX;
  ctx->c_c_index = ctx_index;
  ctx->c_thread_index = thread_index;
  ctx->c_proto = TRANSPORT_PROTO_QUIC;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  ctx->udp_is_ip4 = sep->is_ip4;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
  ctx->listener_ctx_id = QUIC_CTX_INVALID_INDEX;
  ctx->client_opaque = sep->opaque;
  if (ccfg->hostname[0])
    ctx->srv_hostname = format (0, "%s", ccfg->hostname);
  else
    /*  needed by quic for crypto + determining client / server */
    ctx->srv_hostname =
      format (0, "%U", format_ip46_address, &sep->ip, sep->is_ip4);
  vec_terminate_c_string (ctx->srv_hostname);

  clib_memcpy (&cargs->sep_ext, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDP;
  cargs->app_index = qm->app_index;
  cargs->api_context = ctx_index;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  ctx->parent_app_id = app_wrk->app_index;
  cargs->sep_ext.ns_index = app->ns_index;
  cargs->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;

  quic_ctx_set_alpn_protos (ctx, ccfg);
  ctx->crypto_engine = ccfg->crypto_engine;
  ctx->verify_cfg = ccfg->verify_cfg;
  ctx->ckpair_index = ccfg->ckpair_index;
  error = quic_eng_crypto_context_acquire_connect (ctx);
  if (error)
    return error;

  error = vnet_connect (cargs);
  if (error)
    return error;

  return ctx_index;
}

static int
quic_connect_stream (transport_endpoint_cfg_t *tep, session_t *stream_session,
		     u32 *conn_index)
{
  quic_main_t *qm = &quic_main;
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) tep;
  session_t *quic_session;
  sep = (session_endpoint_cfg_t *) tep;
  u32 sctx_index;
  quic_ctx_t *qctx, *sctx;
  quic_stream_data_t *stream_data;
  void *conn;
  void *stream;
  u8 is_unidir;
  int rv;

  quic_session = session_get_from_handle (sep->parent_handle);

  /*  Find base session to which the user want to attach a stream */
  QUIC_DBG (2, "Connect stream: session 0x%lx", sep->parent_handle);
  if (session_type_transport_proto (quic_session->session_type) !=
      TRANSPORT_PROTO_QUIC)
    {
      QUIC_ERR ("received incompatible session");
      return SESSION_E_UNKNOWN;
    }

  sctx_index = quic_ctx_alloc (
    qm, quic_session->thread_index); /*  Allocate before we get pointers */
  sctx = quic_ctx_get (sctx_index, quic_session->thread_index);
  qctx =
    quic_ctx_get (quic_session->connection_index, quic_session->thread_index);
  if (quic_ctx_is_stream (qctx))
    {
      QUIC_ERR ("session is a stream");
      quic_ctx_free (qm, sctx);
      return SESSION_E_UNKNOWN;
    }

  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_index;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;
  sctx->udp_session_handle = qctx->udp_session_handle;
  sctx->crypto_context_index = qctx->crypto_context_index;

  if (!(conn = qctx->conn))
    return SESSION_E_UNKNOWN;

  is_unidir = sep->transport_flags & TRANSPORT_CFG_F_UNIDIRECTIONAL;
  rv = quic_eng_connect_stream (conn, &stream, &stream_data, is_unidir);
  if (rv)
    {
      QUIC_DBG (1,
		"Connect stream: failed %d, conn %p, stream %p, stream_data "
		"%p, unidir %d",
		rv, conn, &stream, &stream_data, is_unidir);
      return rv;
    }
  quic_increment_counter (qm, QUIC_ERROR_OPENED_STREAM, 1);

  sctx->stream = stream;
  stream_data->ctx_id = sctx->c_c_index;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  stream_data->app_tx_data_len = 0;

  *conn_index = sctx_index;

  QUIC_DBG (
    2, "Connect stream: stream_session handle 0x%lx, sctx_index %u, thread %u",
    session_handle (stream_session), sctx_index, qctx->c_thread_index);
  if (is_unidir)
    stream_session->flags |= SESSION_F_UNIDIRECTIONAL;
  svm_fifo_init_ooo_lookup (stream_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (stream_session->tx_fifo, 1 /* ooo deq */);
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			       SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  return SESSION_E_NONE;
}

static void
quic_proto_on_close (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_eng_proto_on_close (ctx_index, thread_index);
}

static void
quic_proto_on_half_close (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_eng_proto_on_half_close (ctx_index, thread_index);
}

static void
quic_proto_on_reset (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_eng_proto_on_reset (ctx_index, thread_index);
}

static u32
quic_start_listen (u32 quic_listen_session_index,
		   transport_endpoint_cfg_t *tep)
{
  vnet_listen_args_t _bargs, *args = &_bargs;
  transport_endpt_crypto_cfg_t *ccfg;
  quic_main_t *qm = &quic_main;
  session_handle_t udp_handle;
  session_endpoint_cfg_t *sep;
  session_t *udp_listen_session;
  app_worker_t *app_wrk;
  application_t *app;
  quic_ctx_t *lctx;
  u32 lctx_index;
  app_listener_t *app_listener;
  transport_endpt_ext_cfg_t *ext_cfg;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  ext_cfg = session_endpoint_get_ext_cfg (sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
  if (!ext_cfg)
    return SESSION_E_NOEXTCFG;

  ccfg = &ext_cfg->crypto;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  QUIC_DBG (2, "Called quic_start_listen for app %d", app_wrk->app_index);

  clib_memset (args, 0, sizeof (*args));
  args->app_index = qm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  args->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
  args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if ((rv = vnet_listen (args)))
    return rv;

  lctx_index = quic_ctx_alloc (qm, 0);
  udp_handle = args->handle;
  app_listener = app_listener_get_w_handle (udp_handle);
  udp_listen_session = app_listener_get_session (app_listener);
  udp_listen_session->opaque = lctx_index;

  lctx = quic_ctx_get (lctx_index, 0);
  lctx->flags |= QUIC_F_IS_LISTENER;

  clib_memcpy (&lctx->c_rmt_ip, &args->sep.peer.ip, sizeof (ip46_address_t));
  clib_memcpy (&lctx->c_lcl_ip, &args->sep.ip, sizeof (ip46_address_t));
  lctx->c_rmt_port = args->sep.peer.port;
  lctx->c_lcl_port = args->sep.port;
  lctx->c_is_ip4 = args->sep.is_ip4;
  lctx->c_fib_index = args->sep.fib_index;
  lctx->c_proto = TRANSPORT_PROTO_QUIC;
  lctx->parent_app_wrk_id = SESSION_INVALID_INDEX;
  lctx->parent_app_id = app_wrk->app_index;
  lctx->udp_session_handle = udp_handle;
  lctx->c_s_index = quic_listen_session_index;
  lctx->listener_ctx_id = lctx_index;
  quic_ctx_set_alpn_protos (lctx, ccfg);
  lctx->crypto_engine = ccfg->crypto_engine;
  lctx->verify_cfg = ccfg->verify_cfg;
  lctx->ckpair_index = ccfg->ckpair_index;
  if ((rv = quic_eng_crypto_context_acquire_listen (lctx)))
    {
      vnet_unlisten_args_t a = {
	.handle = udp_handle,
	.app_index = qm->app_index,
      };
      vnet_unlisten (&a);
      quic_ctx_free (qm, lctx);
      return rv;
    }

  QUIC_DBG (2, "Listening UDP session 0x%lx",
	    session_handle (udp_listen_session));
  QUIC_DBG (2, "Listening QUIC session 0x%lx", quic_listen_session_index);
  return lctx_index;
}

static u32
quic_stop_listen (u32 lctx_index)
{
  QUIC_DBG (2, "Called quic_stop_listen");
  if (PREDICT_TRUE (lctx_index))
    {
      quic_ctx_t *lctx;
      lctx = quic_ctx_get (lctx_index, 0);
      QUIC_ASSERT (quic_ctx_is_listener (lctx));
      vnet_unlisten_args_t a = {
	.handle = lctx->udp_session_handle,
	.app_index = quic_main.app_index,
	.wrk_map_index = 0 /* default wrk */
      };
      if (vnet_unlisten (&a))
	clib_warning ("unlisten errored");

      quic_eng_crypto_context_release (
	lctx->crypto_context_index,
	QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (lctx->crypto_context_index));
      quic_ctx_free (&quic_main, lctx);
    }
  return 0;
}

static transport_connection_t *
quic_connection_get (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  return &ctx->connection;
}

static transport_connection_t *
quic_listener_get (u32 listener_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (listener_index, 0);
  return &ctx->connection;
}

static transport_connection_t *
quic_half_open_get (u32 ho_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ho_index, transport_cl_thread ());
  return &ctx->connection;
}

/* Session layer callbacks */

static void
quic_transfer_connection (u32 ctx_index, u32 dest_thread)
{
  quic_ctx_t *ctx, *temp_ctx;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  quic_main_t *qm = &quic_main;

  QUIC_DBG (2, "Transferring conn %u to thread %u", ctx_index, dest_thread);

  temp_ctx = clib_mem_alloc (sizeof (quic_ctx_t));
  QUIC_ASSERT (temp_ctx != NULL);
  ctx = quic_ctx_get (ctx_index, thread_index);
  quic_eng_connection_migrate (ctx);

  clib_memcpy (temp_ctx, ctx, sizeof (quic_ctx_t));

  quic_stop_ctx_timer (
    &quic_wrk_ctx_get (qm, ctx->c_thread_index)->timer_wheel, ctx);
  QUIC_DBG (4, "Stopped timer for ctx %u", ctx->c_c_index);
  quic_eng_crypto_context_release (ctx->crypto_context_index, thread_index);
  quic_ctx_free (qm, ctx);

  /*  Send connection to destination thread */
  quic_eng_rpc_evt_to_thread_connection_migrate (dest_thread, temp_ctx);
}

static int
quic_udp_session_connected_callback (u32 quic_app_index, u32 ctx_index,
				     session_t *udp_session,
				     session_error_t err)
{
  /* This should always be called before quic_connect returns since UDP always
   * connects instantly. */
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  quic_ctx_t *ctx;
  clib_thread_index_t thread_index;
  int ret;

  QUIC_DBG (2, "UDP Session connected: session_index %u, thread %u",
	    udp_session->session_index, udp_session->thread_index);

  /* Allocate session on whatever thread udp used, i.e., probably first
   * worker, although this may be main thread. If it is main, it's done
   * with a worker barrier */
  thread_index = udp_session->thread_index;
  ASSERT (thread_index == transport_cl_thread ());
  ctx = quic_ctx_get (ctx_index, thread_index);
  if (err)
    {
      app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
      if (app_wrk)
	{
	  u32 api_context = ctx->c_s_index;
	  app_worker_connect_notify (app_wrk, 0, err, api_context);
	}
      return 0;
    }

  QUIC_DBG (2, "UDP Session connected: quic ctx_index %u, thread %u",
	    (ctx) ? ctx_index : ~0, thread_index);

  ctx->udp_session_handle = session_handle (udp_session);
  udp_session->opaque = ctx_index;

  /* Init QUIC lib connection
   * Generate required sockaddr & salen */
  tc = session_get_transport (udp_session);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  ret = quic_eng_connect (ctx, ctx_index, thread_index, sa);
  quic_eng_send_packets (ctx);

  return ret;
}

static void
quic_udp_session_disconnect_callback (session_t *ts)
{
  quic_ctx_t *ctx = quic_ctx_get (ts->opaque, ts->thread_index);
  QUIC_DBG (2, "UDP session closed: udp_handle %lx, ctx_index %u, thread %u",
	    session_handle (ts), ctx->c_c_index, ctx->c_thread_index);
  ctx->conn_state = QUIC_CONN_STATE_TRANSPORT_CLOSED;
  quic_eng_transport_closed (ctx);
}

static void
quic_udp_session_cleanup_callback (session_t *udp_session,
				   session_cleanup_ntf_t ntf)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  if (ntf != SESSION_CLEANUP_SESSION)
    return;

  ctx = quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  quic_stop_ctx_timer (
    &quic_wrk_ctx_get (qm, ctx->c_thread_index)->timer_wheel, ctx);
  QUIC_DBG (4, "Stopped timer for ctx %u", ctx->c_c_index);
  quic_eng_crypto_context_release (ctx->crypto_context_index,
				   ctx->c_thread_index);
  quic_ctx_free (qm, ctx);
}

static void
quic_udp_session_reset_callback (session_t *ts)
{
  quic_ctx_t *ctx = quic_ctx_get (ts->opaque, ts->thread_index);
  quic_eng_transport_closed (ctx);
}

static void
quic_udp_session_migrate_callback (session_t * s, session_handle_t new_sh)
{
  u32 new_thread = session_thread_from_handle (new_sh);
  quic_ctx_t *ctx;

  QUIC_DBG (2, "Session %x migrated to %lx", s->session_index, new_sh);
  QUIC_ASSERT (vlib_get_thread_index () == s->thread_index);
  ctx = quic_ctx_get (s->opaque, s->thread_index);
  QUIC_ASSERT (ctx->udp_session_handle == session_handle (s));

  ctx->udp_session_handle = new_sh;
#if QUIC_DEBUG >= 1
  s->opaque = 0xfeedface;
#endif
  session_half_open_migrate_notify (&ctx->connection);
  quic_transfer_connection (ctx->c_c_index, new_thread);
}

int
quic_udp_session_accepted_callback (session_t * udp_session)
{
  /* New UDP connection, try to accept it */
  u32 ctx_index;
  quic_ctx_t *ctx, *lctx;
  session_t *udp_listen_session;
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  udp_listen_session =
    listen_session_get_from_handle (udp_session->listener_handle);

  ctx_index = quic_ctx_alloc (&quic_main, thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->c_thread_index = udp_session->thread_index;
  ctx->c_c_index = ctx_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->udp_session_handle = session_handle (udp_session);
  QUIC_DBG (2, "ACCEPTED UDP 0x%lx", ctx->udp_session_handle);
  ctx->listener_ctx_id = udp_listen_session->opaque;
  lctx = quic_ctx_get (udp_listen_session->opaque,
		       udp_listen_session->thread_index);
  ctx->udp_is_ip4 = lctx->c_is_ip4;
  ctx->parent_app_id = lctx->parent_app_id;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_OPENED;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  ctx->crypto_engine = lctx->crypto_engine;
  ctx->ckpair_index = lctx->ckpair_index;
  quic_eng_crypto_context_acquire_accept (ctx);
  udp_session->opaque = ctx_index;
  udp_session->session_state = SESSION_STATE_READY;

  /* TODO timeout to delete these if they never connect */
  return 0;
}

static int
quic_add_segment_callback (u32 client_index, u64 seg_handle)
{
  /* No-op for builtin */
  return 0;
}

static int
quic_del_segment_callback (u32 client_index, u64 seg_handle)
{
  /* No-op for builtin */
  return 0;
}

static int
quic_custom_app_rx_callback (transport_connection_t * tc)
{
  session_t *stream_session = session_get (tc->s_index, tc->thread_index);

  QUIC_DBG (3, "Received app READ notification");
  svm_fifo_reset_has_deq_ntf (stream_session->rx_fifo);
  quic_eng_ack_rx_data (stream_session);

  return 0;
}

static int
quic_custom_tx_callback (void *s, transport_send_params_t * sp)
{
  session_t *stream_session = (session_t *) s;
  quic_ctx_t *ctx;

  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  if (PREDICT_FALSE (!quic_ctx_is_stream (ctx)))
    {
      /* this is invoked from quic_update_timer when we need to send
       * immediately */
      quic_eng_send_packets (ctx);
      return 0;
    }

  QUIC_DBG (3, "Stream TX event");

  /* Add stream to engine tx scheduler. This decides when stream is to send and
   * how much. If successful deschedule from session layer scheduler */
  if (quic_eng_stream_tx (ctx, stream_session))
    sp->flags |= TRANSPORT_SND_F_DESCHED;

  return 0;
}

static int
quic_udp_session_rx_callback (session_t * udp_session)
{
  return quic_eng_udp_session_rx_packets (udp_session);
}

static int
quic_udp_session_tx_callback (session_t *udp_session)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  return quic_eng_send_packets (ctx);
}

always_inline void
quic_common_get_transport_endpoint (quic_ctx_t *ctx,
				    transport_endpoint_t *tep_rmt,
				    transport_endpoint_t *tep_lcl)
{
  session_t *udp_session;
  if (!quic_ctx_is_stream (ctx))
    {
      udp_session = session_get_from_handle (ctx->udp_session_handle);
      session_get_endpoint (udp_session, tep_rmt, tep_lcl);
    }
}

static void
quic_get_transport_listener_endpoint (u32 listener_index,
				      transport_endpoint_t *tep_rmt,
				      transport_endpoint_t *tep_lcl)
{
  quic_ctx_t *ctx;
  app_listener_t *app_listener;
  session_t *udp_listen_session;
  ctx = quic_ctx_get (listener_index, vlib_get_thread_index ());
  if (quic_ctx_is_listener (ctx))
    {
      app_listener = app_listener_get_w_handle (ctx->udp_session_handle);
      udp_listen_session = app_listener_get_session (app_listener);
      return session_get_endpoint (udp_listen_session, tep_rmt, tep_lcl);
    }
  quic_common_get_transport_endpoint (ctx, tep_rmt, tep_lcl);
}

static void
quic_get_transport_endpoint (u32 ctx_index, clib_thread_index_t thread_index,
			     transport_endpoint_t *tep_rmt,
			     transport_endpoint_t *tep_lcl)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  quic_common_get_transport_endpoint (ctx, tep_rmt, tep_lcl);
}

static int
quic_session_attribute (u32 ctx_index, clib_thread_index_t thread_index,
			u8 is_get, transport_endpt_attr_t *attr)
{
  quic_ctx_t *ctx;

  ctx = quic_ctx_get (ctx_index, thread_index);

  if (!is_get)
    {
      switch (attr->type)
	{
	case TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE:
	  ctx->app_err_code = (quic_app_err_code_t) attr->app_proto_err_code;
	  break;
	default:
	  return -1;
	}
      return 0;
    }

  switch (attr->type)
    {
    case TRANSPORT_ENDPT_ATTR_TLS_ALPN:
      attr->tls_alpn = ctx->alpn_selected;
      break;
    case TRANSPORT_ENDPT_ATTR_NEXT_TRANSPORT:
      attr->next_transport = ctx->udp_session_handle;
      break;
    case TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE:
      attr->app_proto_err_code = (u64) ctx->app_err_code;
      break;
    case TRANSPORT_ENDPT_ATTR_TLS_PEER_CERT:
      if (quic_eng_ctx_attribute (ctx, 1 /* is_get */, attr) < 0)
	return -1;
      break;
    default:
      return -1;
    }
  return 0;
}

static session_cb_vft_t quic_app_cb_vft = {
  .session_accept_callback = quic_udp_session_accepted_callback,
  .session_disconnect_callback = quic_udp_session_disconnect_callback,
  .session_connected_callback = quic_udp_session_connected_callback,
  .session_reset_callback = quic_udp_session_reset_callback,
  .session_migrate_callback = quic_udp_session_migrate_callback,
  .add_segment_callback = quic_add_segment_callback,
  .del_segment_callback = quic_del_segment_callback,
  .builtin_app_rx_callback = quic_udp_session_rx_callback,
  .builtin_app_tx_callback = quic_udp_session_tx_callback,
  .session_cleanup_callback = quic_udp_session_cleanup_callback,
};

static clib_error_t *
quic_app_enable (quic_main_t *qm, u8 is_en)
{
  if (is_en && qm->app_index == APP_INVALID_INDEX)
    {
      vnet_app_attach_args_t _a = {}, *a = &_a;
      u64 options[APP_OPTIONS_N_OPTIONS];

      clib_memset (a, 0, sizeof (*a));
      clib_memset (options, 0, sizeof (options));

      a->session_cb_vft = &quic_app_cb_vft;
      a->api_client_index = APP_INVALID_INDEX;
      a->options = options;
      a->name = format (0, "quic");
      a->options[APP_OPTIONS_SEGMENT_SIZE] = qm->first_seg_size;
      a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = qm->add_seg_size;
      a->options[APP_OPTIONS_RX_FIFO_SIZE] = qm->udp_fifo_size;
      a->options[APP_OPTIONS_TX_FIFO_SIZE] = qm->udp_fifo_size;
      a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = qm->udp_fifo_prealloc;
      a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
      a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

      if (vnet_application_attach (a))
	{
	  clib_warning ("failed to attach quic app");
	  vec_free (a->name);
	  return clib_error_return (0, "failed to attach quic app");
	}
      qm->app_index = a->app_index;
      vec_free (a->name);
    }
  else if (!is_en && qm->app_index != APP_INVALID_INDEX)
    {
      vnet_app_detach_args_t _da = {}, *da = &_da;

      da->app_index = qm->app_index;
      if (vnet_application_detach (da))
	{
	  clib_warning ("failed to detach quic app");
	  return clib_error_return (0, "failed to detach quic app");
	}
      qm->app_index = APP_INVALID_INDEX;
    }

  return 0;
}

static clib_error_t *
quic_enable (vlib_main_t *vm, u8 is_en)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  quic_main_t *qm = &quic_main;
  quic_worker_ctx_t *qwc;
  clib_error_t *err;
  quic_ctx_t *ctx;
  u64 i;

  qm->engine_type =
    quic_get_engine_type (QUIC_ENGINE_QUICLY, QUIC_ENGINE_OPENSSL);
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      clib_warning (
	"ERROR: NO QUIC ENGINE PLUGIN ENABLED!"
	"\nEnable a quic engine plugin in the startup configuration.");
      return clib_error_return (0, "No QUIC engine plugin enabled");
    }

  if ((err = quic_app_enable (qm, is_en)))
    return err;

  QUIC_DBG (1, "QUIC engine %s init", quic_engine_type_str (qm->engine_type));
  if (!is_en || qm->engine_is_initialized[qm->engine_type])
    return 0;

  qm->quic_input_node = &quic_input_node;
  qm->num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (quic_main.wrk_ctx, qm->num_threads - 1);

  for (i = 0; i < qm->num_threads; i++)
    {
      qwc = quic_wrk_ctx_get (qm, i);
      pool_get_aligned_safe (qwc->ctx_pool, ctx, CLIB_CACHE_LINE_BYTES);
      pool_program_safe_realloc ((void **) &qwc->ctx_pool,
				 QUIC_CTX_POOL_PER_THREAD_SIZE,
				 CLIB_CACHE_LINE_BYTES);
    }

  QUIC_DBG (1, "Initializing quic engine to %s",
	    quic_engine_type_str (qm->engine_type));
  quic_eng_engine_init (qm);
  qm->engine_is_initialized[qm->engine_type] = 1;
  return 0;
}

static transport_proto_vft_t quic_proto = {
  .enable = quic_enable,
  .connect = quic_connect_connection,
  .connect_stream = quic_connect_stream,
  .close = quic_proto_on_close,
  .half_close = quic_proto_on_half_close,
  .reset = quic_proto_on_reset,
  .start_listen = quic_start_listen,
  .stop_listen = quic_stop_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .get_half_open = quic_half_open_get,
  .update_time = quic_update_time,
  .app_rx_evt = quic_custom_app_rx_callback,
  .custom_tx = quic_custom_tx_callback,
  .attribute = quic_session_attribute,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
  .get_transport_endpoint = quic_get_transport_endpoint,
  .get_transport_listener_endpoint = quic_get_transport_listener_endpoint,
  .transport_options = {
    .name = "quic",
    .short_name = "Q",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_VC,
  },
};

void
quic_update_fifo_size ()
{
  quic_main_t *qm = &quic_main;
  segment_manager_props_t *seg_mgr_props =
    application_get_segment_manager_properties (qm->app_index);

  if (!seg_mgr_props)
    {
      clib_warning (
	"error while getting segment_manager_props_t, can't update fifo-size");
      return;
    }

  seg_mgr_props->tx_fifo_size = qm->udp_fifo_size;
  seg_mgr_props->rx_fifo_size = qm->udp_fifo_size;
}

static clib_error_t *
quic_init (vlib_main_t * vm)
{
  quic_main_t *qm = &quic_main;

  QUIC_DBG (1, "QUIC plugin init");

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);

  qm->app_index = APP_INVALID_INDEX;

  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

static uword
quic_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return 0;
}

VLIB_REGISTER_NODE (quic_input_node) = {
  .function = quic_node_fn,
  .name = "quic-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (quic_error_counters),
  .error_counters = quic_error_counters,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "QUIC transport protocol",
};
