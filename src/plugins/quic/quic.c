/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <quic_quicly/quic_quicly.h>
#include <quic/quic.h>
#include <quic/quic_inlines.h>
#include <quic/certs.h>

#include <quic/quic_crypto.h>

static char *quic_error_strings[] = {
#define quic_error(n,s) s,
#include <quic/quic_error.def>
#undef quic_error
};

#define DEFAULT_MAX_PACKETS_PER_KEY 16777216

quic_main_t quic_main;
quic_lib_vft_t *quic_lib_vfts;

static void quic_proto_on_close (u32 ctx_index, u32 thread_index);

void
quic_register_lib_type (const quic_lib_vft_t *vft, quic_lib_type_t type)
{
  vec_validate (quic_vfts, type);
  quic_vfts[type] = *vft;
}

static_always_inline quic_lib_type_t
quic_get_first_avail_lib_type (void)
{
  int i;
  for (i = 0; i < vec_len (quic_vfts); i++)
    {
      if (quic_vfts[i].get_conn_ctx)
	return i;
    }
  return QUIC_LIB_NONE;
}

static quic_lib_type_t
quic_get_lib_type (quic_lib_type_t requested, quic_lib_type_t preferred)
{
  if (requested != QUIC_LIB_NONE)
    {
      if (quic_vfts[requested].get_conn_ctx)
	return requested;
      return QUIC_LIB_NONE;
    }
  if (!quic_vfts[preferred].get_conn_ctx)
    return quic_get_first_avail_lib_type ();
  return preferred;
}

quic_main_t *
get_quic_main (void)
{
  return (&quic_main);
}

/* Crypto contexts */

static_always_inline void
quic_crypto_context_make_key_from_ctx (clib_bihash_kv_24_8_t * kv,
                                       quic_ctx_t * ctx)
{
  application_t *app = application_get (ctx->parent_app_id);
  kv->key[0] = ((u64) ctx->ckpair_index) << 32 | (u64) ctx->crypto_engine;
  kv->key[1] = app->sm_properties.rx_fifo_size - 1;
  kv->key[2] = app->sm_properties.tx_fifo_size - 1;
}

static void
quic_crypto_context_free_if_needed (crypto_context_t * crctx, u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  clib_bihash_kv_24_8_t kv;
  if (crctx->n_subscribers)
    return;
  quic_lib_crypto_context_make_key_from_crctx (&kv, crctx);
  clib_bihash_add_del_24_8 (&qm->wrk_ctx[thread_index].crypto_context_hash,
			    &kv, 0 /* is_add */);
  clib_mem_free (crctx->data);
  pool_put (qm->wrk_ctx[thread_index].crypto_ctx_pool, crctx);
}

static int
quic_app_cert_key_pair_delete_callback (app_cert_key_pair_t * ckpair)
{
  quic_main_t *qm = &quic_main;
  crypto_context_t *crctx;
  clib_bihash_kv_24_8_t kv;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int num_threads = 1 /* main thread */  + vtm->n_threads;
  int i;

  for (i = 0; i < num_threads; i++)
    {
      pool_foreach (crctx, qm->wrk_ctx[i].crypto_ctx_pool)  {
	  if (crctx->ckpair_index == ckpair->cert_key_index)
	    {
	      quic_lib_crypto_context_make_key_from_crctx (&kv, crctx);
	      clib_bihash_add_del_24_8 (&qm->wrk_ctx[i].crypto_context_hash,
					&kv, 0 /* is_add */);
	    }
      }
    }
  return 0;
}

static crypto_context_t *
quic_crypto_context_alloc (u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  crypto_context_t *crctx;
  u32 idx;

  pool_get (qm->wrk_ctx[thread_index].crypto_ctx_pool, crctx);
  clib_memset (crctx, 0, sizeof (*crctx));
  idx = (crctx - qm->wrk_ctx[thread_index].crypto_ctx_pool);
  crctx->ctx_index = ((u32) thread_index) << 24 | idx;

  return crctx;
}

static clib_error_t *
quic_list_crypto_context_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  quic_main_t *qm = &quic_main;
  crypto_context_t *crctx;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, num_threads = 1 /* main thread */  + vtm->n_threads;
  for (i = 0; i < num_threads; i++)
    {
      pool_foreach (crctx, qm->wrk_ctx[i].crypto_ctx_pool)  {
	vlib_cli_output (vm, "[%d][Q]%U", i, format_crypto_context, crctx);
      }
    }
  return 0;
}

static clib_error_t *
quic_set_max_packets_per_key_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  quic_main_t *qm = &quic_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
      {
	qm->max_packets_per_key = tmp;
      }
      else
      return clib_error_return (0, "unknown input '%U'", format_unformat_error,
				line_input);
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
	e = clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	goto done;
      }
    }
done:
  unformat_free (line_input);
  return e;
}

static void
quic_release_crypto_context (u32 crypto_context_index, u8 thread_index)
{
  crypto_context_t *crctx;
  crctx = quic_crypto_context_get (crypto_context_index, thread_index);
  crctx->n_subscribers--;
  quic_crypto_context_free_if_needed (crctx, thread_index);
}

int
quic_acquire_crypto_context (quic_ctx_t * ctx)
{
  quic_main_t *qm = &quic_main;
  crypto_context_t *crctx;
  clib_bihash_kv_24_8_t kv;

  if (ctx->crypto_engine == CRYPTO_ENGINE_NONE)
    {
      QUIC_DBG (2, "No crypto engine specified, using %d",
		qm->default_crypto_engine);
      ctx->crypto_engine = qm->default_crypto_engine;
    }
  if (!clib_bitmap_get (qm->available_crypto_engines, ctx->crypto_engine))
    {
      QUIC_DBG (1, "Quic does not support crypto engine %d",
		ctx->crypto_engine);
      return SESSION_E_NOCRYPTOENG;
    }

  /* Check for exisiting crypto ctx */
  quic_crypto_context_make_key_from_ctx (&kv, ctx);
  if (clib_bihash_search_24_8
      (&qm->wrk_ctx[ctx->c_thread_index].crypto_context_hash, &kv, &kv) == 0)
    {
      crctx = quic_crypto_context_get (kv.value, ctx->c_thread_index);
      QUIC_DBG (2, "Found exisiting crypto context %d", kv.value);
      ctx->crypto_context_index = kv.value;
      crctx->n_subscribers++;
      return 0;
    }

  crctx = quic_crypto_context_alloc (ctx->c_thread_index);
  ctx->crypto_context_index = crctx->ctx_index;
  kv.value = crctx->ctx_index;
  crctx->crypto_engine = ctx->crypto_engine;
  crctx->ckpair_index = ctx->ckpair_index;
  if (quic_lib_init_crypto_context (crctx, ctx))
    goto error;
  if (vnet_app_add_cert_key_interest (ctx->ckpair_index, qm->app_index))
    goto error;
  crctx->n_subscribers++;
  clib_bihash_add_del_24_8 (
    &qm->wrk_ctx[ctx->c_thread_index].crypto_context_hash, &kv,
    1 /* is_add */);
  return 0;

error:
  quic_crypto_context_free_if_needed (crctx, ctx->c_thread_index);
  return SESSION_E_NOCRYPTOCKP;
}

/*  Helper functions */

u32
quic_ctx_alloc (u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get_aligned_safe (qm->ctx_pool[thread_index], ctx,
			 CLIB_CACHE_LINE_BYTES);

  clib_memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (3, "Allocated quic_ctx %u on thread %u",
	    ctx - qm->ctx_pool[thread_index], thread_index);
  return ctx - qm->ctx_pool[thread_index];
}

void
quic_ctx_free (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Free ctx %u %x", ctx->c_thread_index, ctx->c_c_index);
  u32 thread_index = ctx->c_thread_index;
  QUIC_ASSERT (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID);
  if (CLIB_DEBUG)
    clib_memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.ctx_pool[thread_index], ctx);
}

quic_ctx_t *
quic_ctx_get (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_index);
}

/* QUIC protocol actions */

void
quic_increment_counter (u8 evt, u8 val)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_increment_counter (vm, quic_input_node.index, evt, val);
}

/* Timer handling */

int64_t
quic_get_thread_time (u8 thread_index)
{
  return quic_main.wrk_ctx[thread_index].time_now;
}

static u32
quic_set_time_now (u32 thread_index)
{
  vlib_main_t *vlib_main = vlib_get_main ();
  f64 time = vlib_time_now (vlib_main);
  quic_main.wrk_ctx[thread_index].time_now = (int64_t) (time * 1000.f);
  return quic_main.wrk_ctx[thread_index].time_now;
}

/* Transport proto callback */
static void
quic_update_time (f64 now, u8 thread_index)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;

  tw = &quic_main.wrk_ctx[thread_index].timer_wheel;
  quic_set_time_now (thread_index);
  tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);
}

static void
quic_timer_expired (u32 conn_index)
{
  quic_ctx_t *ctx;
  QUIC_DBG (4, "Timer expired for conn %u at %ld", conn_index,
	    quic_get_time (NULL));
  ctx = quic_ctx_get (conn_index, vlib_get_thread_index ());
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_lib_send_packets (ctx);
}

static void
quic_expired_timers_dispatch (u32 * expired_timers)
{
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      quic_timer_expired (expired_timers[i]);
    }
}

/* Transport proto functions */
static int
quic_connect_stream (session_t * quic_session, session_endpoint_cfg_t * sep)
{
  uint64_t quic_session_handle;
  session_t *stream_session;
  quic_stream_data_t *stream_data;
  void *stream;
  void *conn;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_index;
  u8 is_unidir;
  int rv;

  /*  Find base session to which the user want to attach a stream */
  quic_session_handle = session_handle (quic_session);
  QUIC_DBG (2, "Opening new stream (qsession %u)", quic_session_handle);

  if (session_type_transport_proto (quic_session->session_type) !=
      TRANSPORT_PROTO_QUIC)
    {
      QUIC_ERR ("received incompatible session");
      return -1;
    }

  app_wrk = app_worker_get_if_valid (quic_session->app_wrk_index);
  if (!app_wrk)
    {
      QUIC_ERR ("Invalid app worker :(");
      return -1;
    }

  sctx_index = quic_ctx_alloc (
    quic_session->thread_index); /*  Allocate before we get pointers */
  sctx = quic_ctx_get (sctx_index, quic_session->thread_index);
  qctx =
    quic_ctx_get (quic_session->connection_index, quic_session->thread_index);
  if (quic_ctx_is_stream (qctx))
    {
      QUIC_ERR ("session is a stream");
      quic_ctx_free (sctx);
      return -1;
    }

  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_index;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;

  if (!(conn = qctx->conn))
    return -1;

  is_unidir = sep->transport_flags & TRANSPORT_CFG_F_UNIDIRECTIONAL;
  if (quic_lib_connect_stream (conn, &stream, &stream_data, is_unidir))
    {
      QUIC_DBG (2, "Stream open failed with %d", rv);
      return -1;
    }
  quic_increment_counter (QUIC_ERROR_OPENED_STREAM, 1);

  sctx->stream = stream;
  sctx->crypto_context_index = qctx->crypto_context_index;

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "Allocated stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_index);
  stream_session->app_wrk_index = app_wrk->wrk_index;
  stream_session->connection_index = sctx_index;
  stream_session->listener_handle = quic_session_handle;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, qctx->udp_is_ip4);
  if (is_unidir)
    stream_session->flags |= SESSION_F_UNIDIRECTIONAL;

  sctx->c_s_index = stream_session->session_index;
  stream_data->ctx_id = sctx->c_c_index;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  stream_data->app_tx_data_len = 0;
  stream_session->session_state = SESSION_STATE_READY;
  stream_session->opaque = sep->opaque;

  /* For now we only reset streams. Cleanup will be triggered by timers */
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to app_worker_init_connected");
      quic_lib_reset_stream_connect_error (stream);
      return app_worker_connect_notify (app_wrk, NULL, rv, sep->opaque);
    }

  svm_fifo_init_ooo_lookup (stream_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (stream_session->tx_fifo, 1 /* ooo deq */);
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			       SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  if (app_worker_connect_notify (app_wrk, stream_session, SESSION_E_NONE,
				 sep->opaque))
    {
      QUIC_ERR ("failed to notify app");
      quic_increment_counter (QUIC_ERROR_CLOSED_STREAM, 1);
      quic_lib_reset_stream_connect_error (stream);
      return -1;
    }

  return 0;
}

static int
quic_connect_connection (session_endpoint_cfg_t * sep)
{
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
  ctx_index = quic_ctx_alloc (thread_index);
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

  ctx->crypto_engine = ccfg->crypto_engine;
  ctx->ckpair_index = ccfg->ckpair_index;
  if ((error = quic_acquire_crypto_context (ctx)))
    return error;

  if ((error = vnet_connect (cargs)))
    return error;

  return 0;
}

static int
quic_connect (transport_endpoint_cfg_t * tep)
{
  QUIC_DBG (2, "Called quic_connect");
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) tep;
  session_t *quic_session;
  sep = (session_endpoint_cfg_t *) tep;

  quic_session = session_get_from_handle_if_valid (sep->parent_handle);
  if (quic_session)
    return quic_connect_stream (quic_session, sep);
  else
    return quic_connect_connection (sep);
}

static void
quic_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_lib_proto_on_close(ctx_index, thread_index);
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

  lctx_index = quic_ctx_alloc (0);
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
  lctx->crypto_engine = ccfg->crypto_engine;
  lctx->ckpair_index = ccfg->ckpair_index;
  if ((rv = quic_acquire_crypto_context (lctx)))
    return rv;

  QUIC_DBG (2, "Listening UDP session 0x%lx",
	    session_handle (udp_listen_session));
  QUIC_DBG (2, "Listening QUIC session 0x%lx", quic_listen_session_index);
  return lctx_index;
}

static u32
quic_stop_listen (u32 lctx_index)
{
  QUIC_DBG (2, "Called quic_stop_listen");
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

  quic_release_crypto_context (lctx->crypto_context_index,
			       0 /* thread_index */);
  quic_ctx_free (lctx);
  return 0;
}

static transport_connection_t *
quic_connection_get (u32 ctx_index, u32 thread_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  return &ctx->connection;
}

static transport_connection_t *
quic_listener_get (u32 listener_index)
{
  QUIC_DBG (2, "Called quic_listener_get");
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (listener_index, 0);
  return &ctx->connection;
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
    str = format (str, "%U", quic_lib_format_stream_connection, ctx);
  else /* connection */
    str =
      format (str, "Conn %d UDP %d", ctx->c_c_index, ctx->udp_session_handle);

  str =
    format (str, " app %d wrk %d", ctx->parent_app_id, ctx->parent_app_wrk_id);

  if (verbose == 1)
    s = format (s, "%-" SESSION_CLI_ID_LEN "s%-" SESSION_CLI_STATE_LEN "d",
		str, ctx->conn_state);
  else
    s = format (s, "%s\n", str);
  vec_free (str);
  return s;
}

static u8 *
format_quic_connection (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
}

static u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s =
    format (s, "[#%d][Q] half-open app %u", thread_index, ctx->parent_app_id);
  return s;
}

/*  TODO improve */
static u8 *
format_quic_listener (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (tci, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
}

/* Session layer callbacks */

static void
quic_on_quic_session_connected (quic_ctx_t * ctx)
{
  session_t *quic_session;
  app_worker_t *app_wrk;
  u32 ctx_id = ctx->c_c_index;
  u32 thread_index = ctx->c_thread_index;
  int rv;

  quic_session = session_alloc (thread_index);

  QUIC_DBG (2, "Allocated quic session 0x%lx", session_handle (quic_session));
  ctx->c_s_index = quic_session->session_index;
  quic_session->app_wrk_index = ctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->listener_handle = SESSION_INVALID_HANDLE;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);

  /* If quic session connected fails, immediatly close connection */
  app_wrk = app_worker_get (ctx->parent_app_wrk_id);
  if ((rv = app_worker_init_connected (app_wrk, quic_session)))
    {
      QUIC_ERR ("failed to app_worker_init_connected");
      quic_proto_on_close (ctx_id, thread_index);
      app_worker_connect_notify (app_wrk, NULL, rv, ctx->client_opaque);
      return;
    }

  svm_fifo_init_ooo_lookup (quic_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (quic_session->tx_fifo, 1 /* ooo deq */);

  quic_session->session_state = SESSION_STATE_CONNECTING;
  if ((rv = app_worker_connect_notify (app_wrk, quic_session, SESSION_E_NONE,
				       ctx->client_opaque)))
    {
      QUIC_ERR ("failed to notify app %d", rv);
      quic_proto_on_close (ctx_id, thread_index);
      return;
    }
}

void
quic_check_quic_session_connected (quic_ctx_t *ctx)
{
  /* Called when we need to trigger quic session connected
   * we may call this function on the server side / at
   * stream opening */
  quic_session_connected_t session_connected;

  /* Conn may be set to null if the connection is terminated */
  if (!ctx->conn || ctx->conn_state != QUIC_CONN_STATE_HANDSHAKE)
    return;

  session_connected = quic_lib_is_session_connected (ctx);
  if (session_connected == QUIC_SESSION_CONNECTED_NONE)
    return;
    
  ctx->conn_state = QUIC_CONN_STATE_READY;
  if (session_connected == QUIC_SESSION_CONNECTED_CLIENT)
    quic_on_quic_session_connected (ctx);
}

static void
quic_transfer_connection (u32 ctx_index, u32 dest_thread)
{
  quic_ctx_t *ctx, *temp_ctx;
  u32 thread_index = vlib_get_thread_index ();
  quic_main_t *qm = get_quic_main ();

  QUIC_DBG (2, "Transferring conn %u to thread %u", ctx_index, dest_thread);

  temp_ctx = clib_mem_alloc (sizeof (quic_ctx_t));
  QUIC_ASSERT (temp_ctx != NULL);
  ctx = quic_ctx_get (ctx_index, thread_index);

  clib_memcpy (temp_ctx, ctx, sizeof (quic_ctx_t));

  quic_stop_ctx_timer (ctx);
  quic_release_crypto_context (ctx->crypto_context_index, thread_index);
  quic_ctx_free (ctx);

  /*  Send connection to destination thread */
  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].receive_connection))
    {
      QUIC_DBG (1, "receive_connection() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  session_send_rpc_evt_to_thread (dest_thread, quic_vfts[qm->lib_type].receive_connection ,
				  (void *) temp_ctx);
}

static int
quic_udp_session_connected_callback (u32 quic_app_index, u32 ctx_index,
				     session_t *udp_session,
				     session_error_t err)
{
  QUIC_DBG (2, "UDP Session is now connected (id %u)",
	    udp_session->session_index);
  /* This should always be called before quic_connect returns since UDP always
   * connects instantly. */
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  quic_ctx_t *ctx;
  u32 thread_index;
  int ret;

  /* Allocate session on whatever thread udp used, i.e., probably first
   * worker, although this may be main thread. If it is main, it's done
   * with a worker barrier */
  thread_index = udp_session->thread_index;
  ASSERT (thread_index == 0 || thread_index == 1);
  ctx = quic_ctx_get (ctx_index, thread_index);
  if (err)
    {
      u32 api_context;
      app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
      if (app_wrk)
      {
	api_context = ctx->c_s_index;
	app_worker_connect_notify (app_wrk, 0, SESSION_E_NONE, api_context);
      }
      return 0;
    }

  QUIC_DBG (2, "New ctx [%u]%x", thread_index, (ctx) ? ctx_index : ~0);

  ctx->udp_session_handle = session_handle (udp_session);
  udp_session->opaque = ctx_index;

  /* Init QUIC lib connection
   * Generate required sockaddr & salen */
  tc = session_get_transport (udp_session);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  ret = quic_lib_connect (ctx, ctx_index, thread_index, sa);
  quic_lib_send_packets (ctx);

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
  quic_ctx_t *ctx;

  if (ntf != SESSION_CLEANUP_SESSION)
    return;

  ctx = quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  quic_stop_ctx_timer (ctx);
  quic_release_crypto_context (ctx->crypto_context_index, ctx->c_thread_index);
  quic_ctx_free (ctx);
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
  u32 thread_index = vlib_get_thread_index ();

  udp_listen_session =
    listen_session_get_from_handle (udp_session->listener_handle);

  ctx_index = quic_ctx_alloc (thread_index);
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
  quic_acquire_crypto_context (ctx);
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
  quic_lib_ack_rx_data (stream_session);
  svm_fifo_reset_has_deq_ntf (stream_session->rx_fifo);

  /* Need to send packets (acks may never be sent otherwise) */
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  quic_lib_send_packets (ctx);
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
      goto tx_end; /* Most probably a reschedule */
    }

  QUIC_DBG (3, "Stream TX event");
  quic_lib_ack_rx_data (stream_session);

  if (PREDICT_FALSE(!quic_lib_stream_tx (ctx, stream_session)))
  {
    QUIC_DBG("quic_lib_stream_tx(ctx=0x%lx) failed!", ctx);
    return 0;
  }

tx_end:
  return quic_lib_send_packets (ctx);
}

static int
quic_udp_session_rx_callback (session_t * udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quic_lib conn. */
  quic_ctx_t *ctx = NULL, *prev_ctx = NULL;
  svm_fifo_t *f = udp_session->rx_fifo;
  u32 max_deq;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  u32 thread_index = vlib_get_thread_index ();
  u32 cur_deq, fifo_offset, max_packets, i;
  // TODO: move packet buffer off of the stack and
  //       allocate a vector of packet_ct_t.
  quic_rx_packet_ctx_t packets_ctx[QUIC_RCV_MAX_PACKETS];

  if (udp_session->flags & SESSION_F_IS_MIGRATING)
    {
      QUIC_DBG (3, "RX on migrating udp session");
      return 0;
    }

rx_start:
  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq == 0)
    return 0;

  fifo_offset = 0;
  max_packets = QUIC_RCV_MAX_PACKETS;

#if CLIB_DEBUG > 0
  clib_memset (packets_ctx, 0xfa,
	       QUIC_RCV_MAX_PACKETS * sizeof (quic_rx_packet_ctx_t));
#endif
  for (i = 0; i < max_packets; i++)
    {
      packets_ctx[i].thread_index = UINT32_MAX;
      packets_ctx[i].ctx_index = UINT32_MAX;
      packets_ctx[i].ptype = QUIC_PACKET_TYPE_DROP;

      cur_deq = max_deq - fifo_offset;
      if (cur_deq == 0)
      {
	max_packets = i + 1;
	break;
      }
      if (cur_deq < SESSION_CONN_HDR_LEN)
      {
	fifo_offset = max_deq;
	max_packets = i + 1;
	QUIC_ERR ("Fifo %d < header size in RX", cur_deq);
	break;
      }
      rv = quic_lib_process_one_rx_packet (udp_session_handle, f, fifo_offset,
				       &packets_ctx[i]);
      if (packets_ctx[i].ptype != QUIC_PACKET_TYPE_MIGRATE)
      fifo_offset += SESSION_CONN_HDR_LEN + packets_ctx[i].ph.data_length;
      if (rv)
      {
	max_packets = i + 1;
	break;
      }
    }

  for (i = 0; i < max_packets; i++)
    {
      switch (packets_ctx[i].ptype)
      {
      case QUIC_PACKET_TYPE_RECEIVE:
	ctx = quic_ctx_get (packets_ctx[i].ctx_index, thread_index);
	// FIXME: Process return value and handle errors.
	quic_lib_receive_a_packet (ctx, &packets_ctx[i]);
	break;
      case QUIC_PACKET_TYPE_ACCEPT:
	// FIXME: Process return value and handle errors.
	quic_lib_accept_connection (&packets_ctx[i]);
	break;
      case QUIC_PACKET_TYPE_RESET:
	// FIXME: Process return value and handle errors.
	quic_lib_reset_connection (udp_session_handle, &packets_ctx[i]);
	break;
      }
    }
  ctx = prev_ctx = NULL;
  for (i = 0; i < max_packets; i++)
    {
      prev_ctx = ctx;
      switch (packets_ctx[i].ptype)
      {
      case QUIC_PACKET_TYPE_RECEIVE:
	ctx =
	  quic_ctx_get (packets_ctx[i].ctx_index, packets_ctx[i].thread_index);
	quic_check_quic_session_connected (ctx);
	ctx =
	  quic_ctx_get (packets_ctx[i].ctx_index, packets_ctx[i].thread_index);
	break;
      case QUIC_PACKET_TYPE_ACCEPT:
	ctx =
	  quic_ctx_get (packets_ctx[i].ctx_index, packets_ctx[i].thread_index);
	break;
      default:
	continue; /* this exits the for loop since other packet types are
	necessarily the last in the batch */
      }
      if (ctx != prev_ctx)
      quic_lib_send_packets (ctx);
    }

  udp_session = session_get_from_handle (
    udp_session_handle); /*  session alloc might have happened */
  f = udp_session->rx_fifo;
  svm_fifo_dequeue_drop (f, fifo_offset);

  if (svm_fifo_max_dequeue (f))
    goto rx_start;

  return 0;
}

always_inline void
quic_common_get_transport_endpoint (quic_ctx_t *ctx, transport_endpoint_t *tep,
				    u8 is_lcl)
{
  session_t *udp_session;
  if (!quic_ctx_is_stream (ctx))
    {
      udp_session = session_get_from_handle (ctx->udp_session_handle);
      session_get_endpoint (udp_session, tep, is_lcl);
    }
}

static void
quic_get_transport_listener_endpoint (u32 listener_index,
				      transport_endpoint_t *tep, u8 is_lcl)
{
  quic_ctx_t *ctx;
  app_listener_t *app_listener;
  session_t *udp_listen_session;
  ctx = quic_ctx_get (listener_index, vlib_get_thread_index ());
  if (quic_ctx_is_listener (ctx))
    {
      app_listener = app_listener_get_w_handle (ctx->udp_session_handle);
      udp_listen_session = app_listener_get_session (app_listener);
      return session_get_endpoint (udp_listen_session, tep, is_lcl);
    }
  quic_common_get_transport_endpoint (ctx, tep, is_lcl);
}

static void
quic_get_transport_endpoint (u32 ctx_index, u32 thread_index,
			     transport_endpoint_t *tep, u8 is_lcl)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  quic_common_get_transport_endpoint (ctx, tep, is_lcl);
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

static const transport_proto_vft_t quic_proto = {
  .connect = quic_connect,
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
  .transport_options = {
    .name = "quic",
    .short_name = "Q",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static void
quic_register_cipher_suite (crypto_engine_type_t type,
			    ptls_cipher_suite_t **ciphers)
{
  quic_main_t *qm = &quic_main;
  vec_validate (qm->quic_ciphers, type);
  clib_bitmap_set (qm->available_crypto_engines, type, 1);
  qm->quic_ciphers[type] = ciphers;
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
  u32 segment_size = 256 << 20;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  quic_main_t *qm = &quic_main;
  u32 num_threads, i;
  u8 seed[32];

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    return clib_error_return_unix (0, "getrandom() failed");
  RAND_seed (seed, sizeof (seed));

  num_threads = 1 /* main thread */  + vtm->n_threads;

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

  vec_validate (qm->ctx_pool, num_threads - 1);
  vec_validate (qm->wrk_ctx, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    {
      qm->wrk_ctx[i].next_cid.thread_id = i;
      tw = &qm->wrk_ctx[i].timer_wheel;
      tw_timer_wheel_init_1t_3w_1024sl_ov (tw, quic_expired_timers_dispatch,
					   1e-3 /* timer period 1ms */, ~0);
      tw->last_run_time = vlib_time_now (vlib_get_main ());
      clib_bihash_init_24_8 (&qm->wrk_ctx[i].crypto_context_hash,
			     "quic crypto contexts", 64, 128 << 10);
    }

  clib_bihash_init_16_8 (&qm->connection_hash, "quic connections", 1024,
			 4 << 20);

  qm->app_index = a->app_index;
  qm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / QUIC_TSTAMP_RESOLUTION;
  qm->session_cache.super.cb = quic_encrypt_ticket_cb;

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);

  quic_load_openssl3_legacy_provider ();
  clib_bitmap_alloc (qm->available_crypto_engines,
		     app_crypto_engine_n_types ());
  quic_register_cipher_suite (CRYPTO_ENGINE_PICOTLS,
			      ptls_openssl_cipher_suites);
  qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;

  vnet_crypto_main_t *cm = &crypto_main;
  if (vec_len (cm->engines) == 0)
    qm->vnet_crypto_enabled = 0;
  else
    qm->vnet_crypto_enabled = 1;
  if (qm->vnet_crypto_enabled == 1)
    {
      u8 empty_key[32] = {};
      quic_register_cipher_suite (CRYPTO_ENGINE_VPP,
				  quic_crypto_cipher_suites);
      qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
      vec_validate (qm->per_thread_crypto_key_indices, num_threads);
      for (i = 0; i < num_threads; i++)
      {
	qm->per_thread_crypto_key_indices[i] =
	  vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_AES_256_CTR, empty_key, 32);
      }
    }

  qm->max_packets_per_key = DEFAULT_MAX_PACKETS_PER_KEY;
  qm->default_quic_cc = QUIC_CC_RENO;

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
      qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
      else if (unformat (line_input, "picotls"))
      qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
      else
      {
	e = clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
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
  quic_main_t *qm = &quic_main;
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
	qm->udp_fifo_size = tmp;
	quic_update_fifo_size ();
      }
      else
      return clib_error_return (0, "unknown input '%U'", format_unformat_error,
				line_input);
    }

  return 0;
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

  s = format (s, "%U", quic_lib_format_connection_stats, ctx);
  
  return s;
}

static u8 *
quic_format_stream_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  session_t *stream_session;
  // quicly_stream_t *stream = ctx->stream;
  u32 txs, rxs;

  s = format (s, "[#%d][%x]", ctx->c_thread_index, ctx->c_c_index);
  s = format (s, "[%U]", quic_lib_format_stream_ctx_stream_id, ctx);

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
  quic_main_t *qm = &quic_main;
  clib_error_t *error = 0;
  quic_ctx_t *ctx = NULL;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      quic_lib_show_aggregated_stats (vm);
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
      pool_foreach (ctx, qm->ctx_pool[i])
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

VLIB_CLI_COMMAND (quic_plugin_crypto_command, static) = {
  .path = "quic set crypto api",
  .short_help = "quic set crypto api [picotls|vpp]",
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
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Quic transport protocol",
  .default_disabled = 1,
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
	    error = clib_error_return (0, "fifo-size %llu (0x%llx) too large",
				       tmp, tmp);
	    goto done;
	  }
	qm->udp_fifo_size = tmp;
       }
      else if (unformat (line_input, "conn-timeout %u", &i))
       qm->connection_timeout = i;
      else if (unformat (line_input, "fifo-prealloc %u", &i))
       qm->udp_fifo_prealloc = i;
      // TODO: add cli selection of QUIC_LIB_<types>
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
  quic_main_t *qm = &quic_main;

  // TODO: move this to appropriate plugin init function.
  qm->lib_type = quic_get_lib_type (QUIC_LIB_QUICLY, QUIC_LIB_OPENSSL);
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
