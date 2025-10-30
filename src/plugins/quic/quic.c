/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include "quic.h"
#include <sys/socket.h>
#include <sys/syscall.h>

#include <openssl/rand.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>
#include <quic/quic_timer.h>
#include <quic/quic_inlines.h>

static char *quic_error_strings[] = {
#define quic_error(n,s) s,
#include <quic/quic_error.def>
#undef quic_error
};

quic_main_t quic_main;
quic_engine_vft_t *quic_engine_vfts;

static void quic_proto_on_close (u32 ctx_index,
				 clib_thread_index_t thread_index);

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

static int
quic_app_cert_key_pair_delete_callback (app_cert_key_pair_t *ckpair)
{
  return quic_eng_app_cert_key_pair_delete (ckpair);
}

static clib_error_t *
quic_list_crypto_context_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  crypto_context_t *crctx;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, num_threads = 1 /* main thread */  + vtm->n_threads;
  quic_main_t *qm = &quic_main;

  session_cli_return_if_not_enabled ();
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      vlib_cli_output (vm, "No QUIC engine plugin enabled");
      return 0;
    }
  if (qm->engine_is_initialized[qm->engine_type] == 0)
    {
      vlib_cli_output (vm, "quic engine %s not initialized",
		       quic_engine_type_str (qm->engine_type));
      return 0;
    }

  for (i = 0; i < num_threads; i++)
    {
      pool_foreach (crctx, quic_wrk_ctx_get (&quic_main, i)->crypto_ctx_pool)
	{
	  vlib_cli_output (vm, "[%d][Q]%U", i, format_crypto_context, crctx);
	}
    }
  return 0;
}

static clib_error_t *
quic_set_max_packets_per_key_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
	{
	  quic_main.max_packets_per_key = tmp;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static clib_error_t *
quic_set_cc_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *e = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "reno"))
	qm->default_quic_cc = QUIC_CC_RENO;
      else if (unformat (line_input, "cubic"))
	qm->default_quic_cc = QUIC_CC_CUBIC;
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return e;
}

/*  Helper functions */

static_always_inline quic_ctx_t *
quic_ctx_get (u32 ctx_index, clib_thread_index_t thread_index)
{
  return pool_elt_at_index (
    quic_wrk_ctx_get (&quic_main, thread_index)->ctx_pool, ctx_index);
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
  vnet_connect_args_t _cargs, *cargs = &_cargs;
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

  clib_memset (cargs, 0, sizeof (*cargs));
  ctx_index = quic_ctx_alloc (qm, thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->parent_app_wrk_id = sep->app_wrk_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->c_c_index = ctx_index;
  ctx->udp_is_ip4 = sep->is_ip4;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
  ctx->client_opaque = sep->opaque;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
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
  ctx->ckpair_index = ccfg->ckpair_index;
  error = quic_eng_crypto_context_acquire (ctx);
  if (error)
    return error;

  error = vnet_connect (cargs);
  if (error)
    return error;

  return 0;
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
  sctx->crypto_context_index = qctx->crypto_context_index;
  sctx->c_s_index = stream_session->session_index;
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
  lctx->parent_app_wrk_id = sep->app_wrk_index;
  lctx->parent_app_id = app_wrk->app_index;
  lctx->udp_session_handle = udp_handle;
  lctx->c_s_index = quic_listen_session_index;
  lctx->listener_ctx_id = lctx_index;
  quic_ctx_set_alpn_protos (lctx, ccfg);
  lctx->crypto_engine = ccfg->crypto_engine;
  lctx->ckpair_index = ccfg->ckpair_index;
  if ((rv = quic_eng_crypto_context_acquire (lctx)))
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

static u8 *
format_quic_ctx_state (u8 *s, va_list *args)
{
  quic_ctx_t *ctx;
  session_t *as;

  ctx = va_arg (*args, quic_ctx_t *);
  as = session_get (ctx->c_s_index, ctx->c_thread_index);
  if (as->session_state == SESSION_STATE_LISTENING)
    s = format (s, "%s", "LISTEN");
  else
    {
      if (as->session_state == SESSION_STATE_READY)
	s = format (s, "%s", "ESTABLISHED");
      else if (as->session_state == SESSION_STATE_ACCEPTING)
	s = format (s, "%s", "ACCEPTING");
      else if (as->session_state == SESSION_STATE_CONNECTING)
	s = format (s, "%s", "CONNECTING");
      else if (as->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
	s = format (s, "%s", "CLOSED");
      else if (as->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	s = format (s, "%s", "CLOSING");
      else
	s = format (s, "UNHANDLED %u", as->session_state);
    }

  return s;
}

static u8 *
format_quic_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  u32 verbose = va_arg (*args, u32);
  u8 *str = 0;

  if (!ctx)
    return s;
  str = format (str, "[%d:%d][Q] ", ctx->c_thread_index, ctx->c_s_index);

  if (quic_ctx_is_listener (ctx))
    str = format (str, "Listener, UDP %ld", ctx->udp_session_handle);
  else if (quic_ctx_is_stream (ctx))
    str = format (str, "%U", quic_eng_format_stream_connection, ctx);
  else /* connection */
    str =
      format (str, "Conn %d UDP %d", ctx->c_c_index, ctx->udp_session_handle);

  str =
    format (str, " app %d wrk %d", ctx->parent_app_id, ctx->parent_app_wrk_id);

  if (verbose == 1)
    s = format (s, "%-" SESSION_CLI_ID_LEN "s%-" SESSION_CLI_STATE_LEN "U",
		str, format_quic_ctx_state, ctx);
  else
    s = format (s, "%s\n", str);
  vec_free (str);
  return s;
}

static u8 *
format_quic_connection (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
}

static u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s =
    format (s, "[#%d][Q] half-open app %u", thread_index, ctx->parent_app_id);
  return s;
}

/* TODO improve */
static u8 *
format_quic_listener (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (tci, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
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
  ASSERT (thread_index == 0 ||
	  thread_index ==
	    1); /* TODO: FIXME multi-worker support (e.g. thread > 1) */
  ctx = quic_ctx_get (ctx_index, thread_index);
  if (err)
    {
      u32 api_context;
      app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
      if (app_wrk)
	{
	  api_context = ctx->c_s_index;
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
quic_udp_session_disconnect_callback (session_t * s)
{
  clib_warning ("UDP session disconnected???");
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
quic_udp_session_reset_callback (session_t * s)
{
  clib_warning ("UDP session reset???");
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
  ctx->parent_app_wrk_id = lctx->parent_app_wrk_id;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_OPENED;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  ctx->crypto_engine = lctx->crypto_engine;
  ctx->ckpair_index = lctx->ckpair_index;
  quic_eng_crypto_context_acquire (ctx);
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
  quic_ctx_t *ctx;
  session_t *stream_session = session_get (tc->s_index, tc->thread_index);
  QUIC_DBG (3, "Received app READ notification");
  quic_eng_ack_rx_data (stream_session);
  svm_fifo_reset_has_deq_ntf (stream_session->rx_fifo);

  /* Need to send packets (acks may never be sent otherwise) */
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  quic_eng_send_packets (ctx);
  return 0;
}

static int
quic_custom_tx_callback (void *s, transport_send_params_t * sp)
{
  session_t *stream_session = (session_t *) s;
  quic_ctx_t *ctx;

  if (PREDICT_FALSE
      (stream_session->session_state >= SESSION_STATE_TRANSPORT_CLOSING))
    return 0;
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  if (PREDICT_FALSE (!quic_ctx_is_stream (ctx)))
    {
      QUIC_DBG (1, "NOT a stream: ctx_index %u, thread %u",
		stream_session->connection_index,
		stream_session->thread_index);
      goto tx_end; /* Most probably a reschedule */
    }

  QUIC_DBG (3, "Stream TX event");
  quic_eng_ack_rx_data (stream_session);
  if (PREDICT_FALSE (!quic_eng_stream_tx (ctx, stream_session)))
    return 0;

tx_end:
  return quic_eng_send_packets (ctx);
}

static int
quic_udp_session_rx_callback (session_t * udp_session)
{
  return quic_eng_udp_session_rx_packets (udp_session);
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

static tls_alpn_proto_t
quic_get_alpn_selected (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  return ctx->alpn_selected;
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
  .session_cleanup_callback = quic_udp_session_cleanup_callback,
  .app_cert_key_pair_delete_callback = quic_app_cert_key_pair_delete_callback,
};

static clib_error_t *quic_enable (vlib_main_t *vm, u8 is_en);

static transport_proto_vft_t quic_proto = {
  .enable = quic_enable,
  .connect = quic_connect_connection,
  .connect_stream = quic_connect_stream,
  .close = quic_proto_on_close,
  .start_listen = quic_start_listen,
  .stop_listen = quic_stop_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .update_time = quic_update_time,
  .app_rx_evt = quic_custom_app_rx_callback,
  .custom_tx = quic_custom_tx_callback,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
  .get_transport_endpoint = quic_get_transport_endpoint,
  .get_transport_listener_endpoint = quic_get_transport_listener_endpoint,
  .get_alpn_selected = quic_get_alpn_selected,
  .transport_options = {
    .name = "quic",
    .short_name = "Q",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
quic_enable (vlib_main_t *vm, u8 is_en)
{
  quic_main_t *qm = &quic_main;
  quic_worker_ctx_t *qwc;
  quic_ctx_t *ctx;
  crypto_context_t *crctx;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u64 i;

  qm->engine_type =
    quic_get_engine_type (QUIC_ENGINE_QUICLY, QUIC_ENGINE_OPENSSL);
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      /* Prevent crash in transport layer callbacks with no quic engine */
      quic_proto.connect = 0;
      quic_proto.start_listen = 0;
      transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
				   FIB_PROTOCOL_IP4, ~0);
      transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
				   FIB_PROTOCOL_IP6, ~0);

      clib_warning (
	"ERROR: NO QUIC ENGINE PLUGIN ENABLED!"
	"\nEnable a quic engine plugin in the startup configuration.");
      return clib_error_return (0, "No QUIC engine plugin enabled");
    }

  QUIC_DBG (1, "QUIC engine %s init", quic_engine_type_str (qm->engine_type));
  if (!is_en || qm->engine_is_initialized[qm->engine_type])
    return 0;

  qm->quic_input_node = &quic_input_node;
  qm->num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (quic_main.wrk_ctx, qm->num_threads - 1);

  for (i = 0; i < qm->num_threads; i++)
    {
      qwc = quic_wrk_ctx_get (qm, i);
      pool_get_aligned_safe (qwc->crypto_ctx_pool, crctx,
			     CLIB_CACHE_LINE_BYTES);
      pool_program_safe_realloc ((void **) &qwc->crypto_ctx_pool,
				 QUIC_CRYPTO_CTX_POOL_PER_THREAD_SIZE,
				 CLIB_CACHE_LINE_BYTES);
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

static void
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
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  /* TODO: Don't use hard-coded values for segment_size and seed[] */
  u32 segment_size = 256 << 20;
  u8 seed[32];

  QUIC_DBG (1, "QUIC plugin init");

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    return clib_error_return_unix (0, "getrandom() failed");
  RAND_seed (seed, sizeof (seed));

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &quic_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "quic");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = qm->udp_fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = qm->udp_fifo_size;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = qm->udp_fifo_prealloc;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach quic app");
      return clib_error_return (0, "failed to attach quic app");
    }
  qm->app_index = a->app_index;

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);

  vec_free (a->name);
  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

static clib_error_t *
quic_plugin_crypto_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *e = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "vpp"))
	{
	  qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
	  qm->vnet_crypto_init = 0;
	}
      else if (unformat (line_input, "engine-lib"))
	{
	  qm->default_crypto_engine =
	    (qm->engine_type == QUIC_ENGINE_QUICLY) ?
	      CRYPTO_ENGINE_PICOTLS :
	      ((qm->engine_type == QUIC_ENGINE_OPENSSL) ?
		 CRYPTO_ENGINE_OPENSSL :
		 CRYPTO_ENGINE_NONE);
	  if (qm->default_crypto_engine != CRYPTO_ENGINE_NONE)
	    {
	      qm->vnet_crypto_init = 0;
	    }
	  else
	    {
	      e = clib_error_return (0,
				     "No quic engine available, using default "
				     "crypto engine '%U' (%u)",
				     format_crypto_engine,
				     qm->default_crypto_engine,
				     qm->default_crypto_engine);
	      goto done;
	    }
	}
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return e;
}

u64 quic_fifosize = 0;
static clib_error_t *
quic_plugin_set_fifo_size_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  uword tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      return clib_error_return (0, "fifo-size %llu (0x%llx) too large",
					tmp, tmp);
	    }
	  quic_main.udp_fifo_size = tmp;
	  quic_update_fifo_size ();
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static inline u64
quic_get_counter_value (u32 event_code)
{
  vlib_node_t *n;
  vlib_main_t *vm;
  vlib_error_main_t *em;

  u32 code, i;
  u64 c, sum = 0;

  vm = vlib_get_main ();
  em = &vm->error_main;
  n = vlib_get_node (vm, quic_input_node.index);
  code = event_code;
  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;
      i = n->error_heap_index + code;
      c = em->counters[i];

      if (i < vec_len (em->counters_last_clear))
	c -= em->counters_last_clear[i];
      sum += c;
    }
  return sum;
}

static void
quic_show_aggregated_stats (vlib_main_t * vm)
{
  u32 num_workers = vlib_num_workers ();
  quic_ctx_t *ctx = NULL;
  quic_stats_t st, agg_stats;
  u32 i, nconn = 0, nstream = 0;

  clib_memset (&agg_stats, 0, sizeof (agg_stats));
  for (i = 0; i < num_workers + 1; i++)
    {
      pool_foreach (ctx, quic_main.wrk_ctx[i].ctx_pool)
	{
	  if (quic_ctx_is_conn (ctx) && ctx->conn)
	    {
	      quic_eng_connection_get_stats (ctx->conn, &st);
	      agg_stats.rtt_smoothed += st.rtt_smoothed;
	      agg_stats.rtt_minimum += st.rtt_minimum;
	      agg_stats.rtt_variance += st.rtt_variance;
	      agg_stats.num_packets_received += st.num_packets_received;
	      agg_stats.num_packets_sent += st.num_packets_sent;
	      agg_stats.num_packets_lost += st.num_packets_lost;
	      agg_stats.num_packets_ack_received +=
		st.num_packets_ack_received;
	      agg_stats.num_bytes_received += st.num_bytes_received;
	      agg_stats.num_bytes_sent += st.num_bytes_sent;
	      nconn++;
	    }
	  else if (quic_ctx_is_stream (ctx))
	    nstream++;
	}
    }
  vlib_cli_output (vm, "-------- Connections --------");
  vlib_cli_output (vm, "Current:         %u", nconn);
  vlib_cli_output (vm, "Opened:          %d",
		   quic_get_counter_value (QUIC_ERROR_OPENED_CONNECTION));
  vlib_cli_output (vm, "Closed:          %d",
		   quic_get_counter_value (QUIC_ERROR_CLOSED_CONNECTION));
  vlib_cli_output (vm, "---------- Streams ----------");
  vlib_cli_output (vm, "Current:         %u", nstream);
  vlib_cli_output (vm, "Opened:          %d",
		   quic_get_counter_value (QUIC_ERROR_OPENED_STREAM));
  vlib_cli_output (vm, "Closed:          %d",
		   quic_get_counter_value (QUIC_ERROR_CLOSED_STREAM));
  vlib_cli_output (vm, "---------- Packets ----------");
  vlib_cli_output (vm, "RX Total:        %d",
		   quic_get_counter_value (QUIC_ERROR_RX_PACKETS));
  vlib_cli_output (vm, "RX 0RTT:         %d",
		   quic_get_counter_value (QUIC_ERROR_ZERO_RTT_RX_PACKETS));
  vlib_cli_output (vm, "RX 1RTT:         %d",
		   quic_get_counter_value (QUIC_ERROR_ONE_RTT_RX_PACKETS));
  vlib_cli_output (vm, "TX Total:        %d",
		   quic_get_counter_value (QUIC_ERROR_TX_PACKETS));
  vlib_cli_output (vm, "----------- Stats -----------");
  vlib_cli_output (vm, "Min      RTT     %f",
		   nconn > 0 ? agg_stats.rtt_minimum / nconn : 0);
  vlib_cli_output (vm, "Smoothed RTT     %f",
		   nconn > 0 ? agg_stats.rtt_smoothed / nconn : 0);
  vlib_cli_output (vm, "Variance on RTT  %f",
		   nconn > 0 ? agg_stats.rtt_variance / nconn : 0);
  vlib_cli_output (vm, "Packets Received %lu", agg_stats.num_packets_received);
  vlib_cli_output (vm, "Packets Sent     %lu", agg_stats.num_packets_sent);
  vlib_cli_output (vm, "Packets Lost     %lu", agg_stats.num_packets_lost);
  vlib_cli_output (vm, "Packets Acks     %lu",
		   agg_stats.num_packets_ack_received);
  vlib_cli_output (vm, "RX bytes         %lu", agg_stats.num_bytes_received);
  vlib_cli_output (vm, "TX bytes         %lu", agg_stats.num_bytes_sent);
}

static u8 *
quic_format_listener_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  s = format (s, "[#%d][%x][Listener]", ctx->c_thread_index, ctx->c_c_index);
  return s;
}

static u8 *
quic_format_connection_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);

  s = format (s, "[#%d][%x]", ctx->c_thread_index, ctx->c_c_index);

  if (!ctx->conn)
    {
      s = format (s, "- no conn -\n");
      return s;
    }

  s = format (s, "%U", quic_eng_format_connection_stats, ctx);

  return s;
}

static u8 *
quic_format_stream_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  session_t *stream_session;
  u32 txs, rxs;

  s = format (s, "[#%d][%x]", ctx->c_thread_index, ctx->c_c_index);
  s = format (s, "[%U]", quic_eng_format_stream_ctx_stream_id, ctx);

  stream_session = session_get_if_valid (ctx->c_s_index, ctx->c_thread_index);
  if (!stream_session)
    {
      s = format (s, "- no session -\n");
      return s;
    }
  txs = svm_fifo_max_dequeue (stream_session->tx_fifo);
  rxs = svm_fifo_max_dequeue (stream_session->rx_fifo);
  s = format (s, "[rx %d tx %d]\n", rxs, txs);
  return s;
}

static clib_error_t *
quic_show_connections_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 show_listeners = 0, show_conn = 0, show_stream = 0;
  u32 num_workers = vlib_num_workers ();
  clib_error_t *error = 0;
  quic_ctx_t *ctx = NULL;
  quic_main_t *qm = &quic_main;

  session_cli_return_if_not_enabled ();
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      vlib_cli_output (vm, "No QUIC engine plugin enabled");
      return 0;
    }
  if (qm->engine_is_initialized[qm->engine_type] == 0)
    {
      vlib_cli_output (vm, "quic engine %s not initialized",
		       quic_engine_type_str (qm->engine_type));
      return 0;
    }

  vlib_cli_output (vm, "quic engine: %s",
		   quic_engine_type_str (qm->engine_type));
  vlib_cli_output (
    vm, "crypto engine: %s",
    qm->default_crypto_engine == CRYPTO_ENGINE_PICOTLS ?
      "picotls" :
      (qm->default_crypto_engine == CRYPTO_ENGINE_VPP ? "vpp" : "none"));
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      quic_show_aggregated_stats (vm);
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "listener"))
	show_listeners = 1;
      else if (unformat (line_input, "conn"))
	show_conn = 1;
      else if (unformat (line_input, "stream"))
	show_stream = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  for (int i = 0; i < num_workers + 1; i++)
    {
      pool_foreach (ctx, quic_main.wrk_ctx[i].ctx_pool)
	{
	  if (quic_ctx_is_stream (ctx) && show_stream)
	    vlib_cli_output (vm, "%U", quic_format_stream_ctx, ctx);
	  else if (quic_ctx_is_listener (ctx) && show_listeners)
	    vlib_cli_output (vm, "%U", quic_format_listener_ctx, ctx);
	  else if (quic_ctx_is_conn (ctx) && show_conn)
	    vlib_cli_output (vm, "%U", quic_format_connection_ctx, ctx);
	}
    }

done:
  unformat_free (line_input);
  return error;
}

/* TODO: This command should not be engine specific.
 * Current implementation is for quicly engine!
 * Fix quicly specific syntax (e.g. picotls) to be generic.
 */
VLIB_CLI_COMMAND (quic_plugin_crypto_command, static) = {
  .path = "quic set crypto api",
  .short_help = "quic set crypto api [engine-lib|vpp]",
  .function = quic_plugin_crypto_command_fn,
};
VLIB_CLI_COMMAND(quic_plugin_set_fifo_size_command, static)=
{
  .path = "quic set fifo-size",
  .short_help = "quic set fifo-size N[K|M|G] (default 64K)",
  .function = quic_plugin_set_fifo_size_command_fn,
};
VLIB_CLI_COMMAND(quic_show_ctx_command, static)=
{
  .path = "show quic",
  .short_help = "show quic",
  .function = quic_show_connections_command_fn,
};
VLIB_CLI_COMMAND (quic_list_crypto_context_command, static) =
{
  .path = "show quic crypto context",
  .short_help = "list quic crypto contextes",
  .function = quic_list_crypto_context_command_fn,
};
VLIB_CLI_COMMAND (quic_set_max_packets_per_key, static) =
{
  .path = "set quic max_packets_per_key",
  .short_help = "set quic max_packets_per_key 16777216",
  .function = quic_set_max_packets_per_key_fn,
};
VLIB_CLI_COMMAND (quic_set_cc, static) = {
  .path = "set quic cc",
  .short_help = "set quic cc [reno|cubic]",
  .function = quic_set_cc_fn,
};
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quic transport protocol",
};

static clib_error_t *
quic_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *error = 0;
  uword tmp;
  u32 i;

  qm->udp_fifo_size = QUIC_DEFAULT_FIFO_SIZE;
  qm->udp_fifo_prealloc = 0;
  qm->connection_timeout = QUIC_DEFAULT_CONN_TIMEOUT;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      error = clib_error_return (
		0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	      goto done;
	    }
	  qm->udp_fifo_size = tmp;
	}
      else if (unformat (line_input, "conn-timeout %u", &i))
	qm->connection_timeout = i;
      else if (unformat (line_input, "fifo-prealloc %u", &i))
	qm->udp_fifo_prealloc = i;
      /* TODO: add cli selection of quic_eng_<types> */
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return error;
}

VLIB_EARLY_CONFIG_FUNCTION (quic_config_fn, "quic");

static uword
quic_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return 0;
}

VLIB_REGISTER_NODE (quic_input_node) =
{
  .function = quic_node_fn,
  .name = "quic-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (quic_error_strings),
  .error_strings = quic_error_strings,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
