/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <sys/socket.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>
#include <quic/certs.h>
#include <quic/error.h>

#include <quicly/constants.h>
#include <quicly/defaults.h>
#include <picotls.h>

#include <quic/quic_crypto.h>

extern quicly_crypto_engine_t quic_crypto_engine;

static char *quic_error_strings[] = {
#define quic_error(n,s) s,
#include <quic/quic_error.def>
#undef quic_error
};

#define DEFAULT_MAX_PACKETS_PER_KEY 16777216

quic_main_t quic_main;
static void quic_update_timer (quic_ctx_t * ctx);
static void quic_check_quic_session_connected (quic_ctx_t * ctx);
static int quic_reset_connection (u64 udp_session_handle,
				  quic_rx_packet_ctx_t * pctx);
static void quic_proto_on_close (u32 ctx_index, u32 thread_index);

static quicly_stream_open_t on_stream_open;
static quicly_closed_by_remote_t on_closed_by_remote;
static quicly_now_t quicly_vpp_now_cb;

/* Crypto contexts */

static inline void
quic_crypto_context_make_key_from_ctx (clib_bihash_kv_24_8_t * kv,
				       quic_ctx_t * ctx)
{
  application_t *app = application_get (ctx->parent_app_id);
  kv->key[0] = ((u64) ctx->ckpair_index) << 32 | (u64) ctx->crypto_engine;
  kv->key[1] = app->sm_properties.rx_fifo_size - 1;
  kv->key[2] = app->sm_properties.tx_fifo_size - 1;
}

static inline void
quic_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t * kv,
					 crypto_context_t * crctx)
{
  quic_crypto_context_data_t *data =
    (quic_crypto_context_data_t *) crctx->data;
  kv->key[0] = ((u64) crctx->ckpair_index) << 32 | (u64) crctx->crypto_engine;
  kv->key[1] = data->quicly_ctx.transport_params.max_stream_data.bidi_local;
  kv->key[2] = data->quicly_ctx.transport_params.max_stream_data.bidi_remote;
}

static void
quic_crypto_context_free_if_needed (crypto_context_t * crctx, u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  clib_bihash_kv_24_8_t kv;
  if (crctx->n_subscribers)
    return;
  quic_crypto_context_make_key_from_crctx (&kv, crctx);
  clib_bihash_add_del_24_8 (&qm->wrk_ctx[thread_index].crypto_context_hash,
			    &kv, 0 /* is_add */ );
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
      /* *INDENT-OFF* */
      pool_foreach (crctx, qm->wrk_ctx[i].crypto_ctx_pool, ({
	if (crctx->ckpair_index == ckpair->cert_key_index)
	  {
	    quic_crypto_context_make_key_from_crctx (&kv, crctx);
	    clib_bihash_add_del_24_8 (&qm->wrk_ctx[i].crypto_context_hash, &kv, 0 /* is_add */ );
	  }
      }));
      /* *INDENT-ON* */
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

static crypto_context_t *
quic_crypto_context_get (u32 cr_index, u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  ASSERT (cr_index >> 24 == thread_index);
  return pool_elt_at_index (qm->wrk_ctx[thread_index].crypto_ctx_pool,
			    cr_index & 0x00ffffff);
}

static clib_error_t *
quic_list_crypto_context_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  quic_main_t *qm = &quic_main;
  crypto_context_t *crctx;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, num_threads = 1 /* main thread */  + vtm->n_threads;
  for (i = 0; i < num_threads; i++)
    {
      /* *INDENT-OFF* */
      pool_foreach (crctx, qm->wrk_ctx[i].crypto_ctx_pool, ({
	vlib_cli_output (vm, "[%d][Q]%U", i, format_crypto_context, crctx);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

static clib_error_t *
quic_set_max_packets_per_key_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
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
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static clib_error_t *
quic_set_cc_fn (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
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

static void
quic_release_crypto_context (u32 crypto_context_index, u8 thread_index)
{
  crypto_context_t *crctx;
  crctx = quic_crypto_context_get (crypto_context_index, thread_index);
  crctx->n_subscribers--;
  quic_crypto_context_free_if_needed (crctx, thread_index);
}

static int
quic_init_crypto_context (crypto_context_t * crctx, quic_ctx_t * ctx)
{
  quic_main_t *qm = &quic_main;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  app_cert_key_pair_t *ckpair;
  application_t *app;
  quic_crypto_context_data_t *data;
  ptls_context_t *ptls_ctx;

  QUIC_DBG (2, "Init quic crctx %d thread %d", crctx->ctx_index,
	    ctx->c_thread_index);

  data = clib_mem_alloc (sizeof (*data));
  /* picotls depends on data being zeroed */
  clib_memset (data, 0, sizeof (*data));
  crctx->data = (void *) data;
  quicly_ctx = &data->quicly_ctx;
  ptls_ctx = &data->ptls_ctx;

  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->get_time = &ptls_get_time;
  ptls_ctx->key_exchanges = ptls_openssl_key_exchanges;
  ptls_ctx->cipher_suites = qm->quic_ciphers[ctx->crypto_engine];
  ptls_ctx->certificates.list = NULL;
  ptls_ctx->certificates.count = 0;
  ptls_ctx->esni = NULL;
  ptls_ctx->on_client_hello = NULL;
  ptls_ctx->emit_certificate = NULL;
  ptls_ctx->sign_certificate = NULL;
  ptls_ctx->verify_certificate = NULL;
  ptls_ctx->ticket_lifetime = 86400;
  ptls_ctx->max_early_data_size = 8192;
  ptls_ctx->hkdf_label_prefix__obsolete = NULL;
  ptls_ctx->require_dhe_on_psk = 1;
  ptls_ctx->encrypt_ticket = &qm->session_cache.super;
  clib_memcpy (quicly_ctx, &quicly_spec_context, sizeof (quicly_context_t));

  quicly_ctx->max_packets_per_key = qm->max_packets_per_key;
  quicly_ctx->tls = ptls_ctx;
  quicly_ctx->stream_open = &on_stream_open;
  quicly_ctx->closed_by_remote = &on_closed_by_remote;
  quicly_ctx->now = &quicly_vpp_now_cb;
  quicly_amend_ptls_context (quicly_ctx->tls);

  if (qm->vnet_crypto_enabled
      && qm->default_crypto_engine == CRYPTO_ENGINE_VPP)
    quicly_ctx->crypto_engine = &quic_crypto_engine;
  else
    quicly_ctx->crypto_engine = &quicly_default_crypto_engine;

  quicly_ctx->transport_params.max_data = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_streams_uni = (uint64_t) 1 << 60;
  quicly_ctx->transport_params.max_streams_bidi = (uint64_t) 1 << 60;
  quicly_ctx->transport_params.max_idle_timeout = qm->connection_timeout;

  if (qm->default_quic_cc == QUIC_CC_CUBIC)
    quicly_ctx->init_cc = &quicly_cc_cubic_init;
  else if (qm->default_quic_cc == QUIC_CC_RENO)
    quicly_ctx->init_cc = &quicly_cc_reno_init;

  app = application_get (ctx->parent_app_id);
  quicly_ctx->transport_params.max_stream_data.bidi_local =
    app->sm_properties.rx_fifo_size - 1;
  quicly_ctx->transport_params.max_stream_data.bidi_remote =
    app->sm_properties.tx_fifo_size - 1;
  quicly_ctx->transport_params.max_stream_data.uni = QUIC_INT_MAX;

  quicly_ctx->transport_params.max_udp_payload_size = QUIC_MAX_PACKET_SIZE;
  if (!app->quic_iv_set)
    {
      ptls_openssl_random_bytes (app->quic_iv, QUIC_IV_LEN - 1);
      app->quic_iv[QUIC_IV_LEN - 1] = 0;
      app->quic_iv_set = 1;
    }

  clib_memcpy (data->cid_key, app->quic_iv, QUIC_IV_LEN);
  key_vec = ptls_iovec_init (data->cid_key, QUIC_IV_LEN);
  quicly_ctx->cid_encryptor =
    quicly_new_default_cid_encryptor (&ptls_openssl_bfecb,
				      &ptls_openssl_aes128ecb,
				      &ptls_openssl_sha256, key_vec);

  ckpair = app_cert_key_pair_get_if_valid (crctx->ckpair_index);
  if (!ckpair || !ckpair->key || !ckpair->cert)
    {
      QUIC_DBG (1, "Wrong ckpair id %d\n", crctx->ckpair_index);
      return -1;
    }
  if (load_bio_private_key (quicly_ctx->tls, (char *) ckpair->key))
    {
      QUIC_DBG (1, "failed to read private key from app configuration\n");
      return -1;
    }
  if (load_bio_certificate_chain (quicly_ctx->tls, (char *) ckpair->cert))
    {
      QUIC_DBG (1, "failed to load certificate\n");
      return -1;
    }
  return 0;

}

static int
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
      return VNET_API_ERROR_MISSING_CERT_KEY;
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
  if (quic_init_crypto_context (crctx, ctx))
    goto error;
  if (vnet_app_add_cert_key_interest (ctx->ckpair_index, qm->app_index))
    goto error;
  crctx->n_subscribers++;
  clib_bihash_add_del_24_8 (&qm->
			    wrk_ctx[ctx->c_thread_index].crypto_context_hash,
			    &kv, 1 /* is_add */ );
  return 0;

error:
  quic_crypto_context_free_if_needed (crctx, ctx->c_thread_index);
  return VNET_API_ERROR_MISSING_CERT_KEY;
}

/*  Helper functions */

static u32
quic_ctx_alloc (u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get (qm->ctx_pool[thread_index], ctx);

  clib_memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (3, "Allocated quic_ctx %u on thread %u",
	    ctx - qm->ctx_pool[thread_index], thread_index);
  return ctx - qm->ctx_pool[thread_index];
}

static void
quic_ctx_free (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Free ctx %u %x", ctx->c_thread_index, ctx->c_c_index);
  u32 thread_index = ctx->c_thread_index;
  QUIC_ASSERT (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID);
  if (CLIB_DEBUG)
    clib_memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.ctx_pool[thread_index], ctx);
}

static quic_ctx_t *
quic_ctx_get (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_index);
}

static quic_ctx_t *
quic_ctx_get_if_valid (u32 ctx_index, u32 thread_index)
{
  if (pool_is_free_index (quic_main.ctx_pool[thread_index], ctx_index))
    return 0;
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_index);
}

quic_ctx_t *
quic_get_conn_ctx (quicly_conn_t * conn)
{
  u64 conn_data;
  conn_data = (u64) * quicly_get_data (conn);
  return quic_ctx_get (conn_data & UINT32_MAX, conn_data >> 32);
}

static void
quic_store_conn_ctx (quicly_conn_t * conn, quic_ctx_t * ctx)
{
  *quicly_get_data (conn) =
    (void *) (((u64) ctx->c_thread_index) << 32 | (u64) ctx->c_c_index);
}

static inline int
quic_ctx_is_stream (quic_ctx_t * ctx)
{
  return (ctx->flags & QUIC_F_IS_STREAM);
}

static inline int
quic_ctx_is_listener (quic_ctx_t * ctx)
{
  return (ctx->flags & QUIC_F_IS_LISTENER);
}

static inline int
quic_ctx_is_conn (quic_ctx_t * ctx)
{
  return !(quic_ctx_is_listener (ctx) || quic_ctx_is_stream (ctx));
}

static inline session_t *
get_stream_session_and_ctx_from_stream (quicly_stream_t * stream,
					quic_ctx_t ** ctx)
{
  quic_stream_data_t *stream_data;

  stream_data = (quic_stream_data_t *) stream->data;
  *ctx = quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  return session_get ((*ctx)->c_s_index, stream_data->thread_index);
}

static inline void
quic_make_connection_key (clib_bihash_kv_16_8_t * kv,
			  const quicly_cid_plaintext_t * id)
{
  kv->key[0] = ((u64) id->master_id) << 32 | (u64) id->thread_id;
  kv->key[1] = id->node_id;
}

static int
quic_sendable_packet_count (session_t * udp_session)
{
  u32 max_enqueue;
  u32 packet_size = QUIC_MAX_PACKET_SIZE + SESSION_CONN_HDR_LEN;
  max_enqueue = svm_fifo_max_enqueue (udp_session->tx_fifo);
  return clib_min (max_enqueue / packet_size, QUIC_SEND_PACKET_VEC_SIZE);
}

static quicly_context_t *
quic_get_quicly_ctx_from_ctx (quic_ctx_t * ctx)
{
  crypto_context_t *crctx =
    quic_crypto_context_get (ctx->crypto_context_index, ctx->c_thread_index);
  quic_crypto_context_data_t *data =
    (quic_crypto_context_data_t *) crctx->data;
  return &data->quicly_ctx;
}

static quicly_context_t *
quic_get_quicly_ctx_from_udp (u64 udp_session_handle)
{
  session_t *udp_session = session_get_from_handle (udp_session_handle);
  quic_ctx_t *ctx =
    quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  return quic_get_quicly_ctx_from_ctx (ctx);
}

static inline void
quic_set_udp_tx_evt (session_t * udp_session)
{
  int rv = 0;
  if (svm_fifo_set_event (udp_session->tx_fifo))
    rv = session_send_io_evt_to_thread (udp_session->tx_fifo,
					SESSION_IO_EVT_TX);
  if (PREDICT_FALSE (rv))
    clib_warning ("Event enqueue errored %d", rv);
}

static inline void
quic_stop_ctx_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    return;
  tw = &quic_main.wrk_ctx[ctx->c_thread_index].timer_wheel;
  tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (4, "Stopping timer for ctx %u", ctx->c_c_index);
}

/* QUIC protocol actions */

static void
quic_ack_rx_data (session_t * stream_session)
{
  u32 max_deq;
  quic_ctx_t *sctx;
  svm_fifo_t *f;
  quicly_stream_t *stream;
  quic_stream_data_t *stream_data;

  sctx = quic_ctx_get (stream_session->connection_index,
		       stream_session->thread_index);
  QUIC_ASSERT (quic_ctx_is_stream (sctx));
  stream = sctx->stream;
  stream_data = (quic_stream_data_t *) stream->data;

  f = stream_session->rx_fifo;
  max_deq = svm_fifo_max_dequeue (f);

  QUIC_ASSERT (stream_data->app_rx_data_len >= max_deq);
  quicly_stream_sync_recvbuf (stream, stream_data->app_rx_data_len - max_deq);
  QUIC_DBG (3, "Acking %u bytes", stream_data->app_rx_data_len - max_deq);
  stream_data->app_rx_data_len = max_deq;
}

static void
quic_disconnect_transport (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Disconnecting transport 0x%lx", ctx->udp_session_handle);
  vnet_disconnect_args_t a = {
    .handle = ctx->udp_session_handle,
    .app_index = quic_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("UDP session 0x%lx disconnect errored",
		  ctx->udp_session_handle);
}

static void
quic_connection_delete (quic_ctx_t * ctx)
{
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;

  QUIC_DBG (2, "Deleting connection %u", ctx->c_c_index);

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));
  quic_stop_ctx_timer (ctx);

  /*  Delete the connection from the connection map */
  conn = ctx->conn;
  ctx->conn = NULL;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  QUIC_DBG (2, "Deleting conn with id %lu %lu from map", kv.key[0],
	    kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 0 /* is_add */ );

  quic_disconnect_transport (ctx);

  if (ctx->conn)
    quicly_free (ctx->conn);
  session_transport_delete_notify (&ctx->connection);
}

void
quic_increment_counter (u8 evt, u8 val)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_increment_counter (vm, quic_input_node.index, evt, val);
}

/**
 * Called when quicly return an error
 * This function interacts tightly with quic_proto_on_close
 */
static void
quic_connection_closed (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "QUIC connection %u/%u closed", ctx->c_thread_index,
	    ctx->c_c_index);

  /* TODO if connection is not established, just delete the session? */
  /* Actually should send connect or accept error */

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_READY:
      /* Error on an opened connection (timeout...)
         This puts the session in closing state, we should receive a notification
         when the app has closed its session */
      session_transport_reset_notify (&ctx->connection);
      /* This ensures we delete the connection when the app confirms the close */
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      /* quic_proto_on_close will eventually be called when the app confirms the close
         , we delete the connection at that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED:
      /* App already confirmed close, we can delete the connection */
      quic_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_OPENED:
    case QUIC_CONN_STATE_HANDSHAKE:
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      quic_connection_delete (ctx);
      break;
    default:
      QUIC_DBG (0, "BUG %d", ctx->conn_state);
      break;
    }
}

static int
quic_send_datagram (session_t * udp_session, struct iovec *packet,
		    quicly_address_t * dest, quicly_address_t * src)
{
  u32 max_enqueue;
  session_dgram_hdr_t hdr;
  u32 len, ret;
  svm_fifo_t *f;
  transport_connection_t *tc;

  len = packet->iov_len;
  f = udp_session->tx_fifo;
  tc = session_get_transport (udp_session);
  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue < SESSION_CONN_HDR_LEN + len)
    {
      QUIC_ERR ("Too much data to send, max_enqueue %u, len %u",
		max_enqueue, len + SESSION_CONN_HDR_LEN);
      return QUIC_ERROR_FULL_FIFO;
    }

  /*  Build packet header for fifo */
  hdr.data_length = len;
  hdr.data_offset = 0;
  hdr.is_ip4 = tc->is_ip4;
  clib_memcpy (&hdr.lcl_ip, &tc->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = tc->lcl_port;

  /*  Read dest address from quicly-provided sockaddr */
  if (hdr.is_ip4)
    {
      QUIC_ASSERT (dest->sa.sa_family == AF_INET);
      struct sockaddr_in *sa4 = (struct sockaddr_in *) &dest->sa;
      hdr.rmt_port = sa4->sin_port;
      hdr.rmt_ip.ip4.as_u32 = sa4->sin_addr.s_addr;
    }
  else
    {
      QUIC_ASSERT (dest->sa.sa_family == AF_INET6);
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &dest->sa;
      hdr.rmt_port = sa6->sin6_port;
      clib_memcpy (&hdr.rmt_ip.ip6, &sa6->sin6_addr, 16);
    }

  ret = svm_fifo_enqueue (f, sizeof (hdr), (u8 *) & hdr);
  if (ret != sizeof (hdr))
    {
      QUIC_ERR ("Not enough space to enqueue header");
      return QUIC_ERROR_FULL_FIFO;
    }
  ret = svm_fifo_enqueue (f, len, packet->iov_base);
  if (ret != len)
    {
      QUIC_ERR ("Not enough space to enqueue payload");
      return QUIC_ERROR_FULL_FIFO;
    }

  quic_increment_counter (QUIC_ERROR_TX_PACKETS, 1);

  return 0;
}

static int
quic_send_packets (quic_ctx_t * ctx)
{
  struct iovec packets[QUIC_SEND_PACKET_VEC_SIZE];
  uint8_t buf[QUIC_SEND_PACKET_VEC_SIZE *
	      quic_get_quicly_ctx_from_ctx (ctx)->
	      transport_params.max_udp_payload_size];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  quicly_address_t dest, src;

  num_packets = QUIC_SEND_PACKET_VEC_SIZE;

  int err = 0;

  /* We have sctx, get qctx */
  if (quic_ctx_is_stream (ctx))
    ctx = quic_ctx_get (ctx->quic_connection_ctx_id, ctx->c_thread_index);

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));

  udp_session = session_get_from_handle_if_valid (ctx->udp_session_handle);
  if (!udp_session)
    goto quicly_error;

  conn = ctx->conn;

  if (!conn)
    return 0;

  /* TODO : quicly can assert it can send min_packets up to 2 */
  if (quic_sendable_packet_count (udp_session) < 2)
    goto stop_sending;

  do
    {
      max_packets = quic_sendable_packet_count (udp_session);
      if (max_packets < 2)
	break;
      num_packets = max_packets;
      if ((err =
	   quicly_send (conn, &dest, &src, packets, &num_packets, buf,
			sizeof (buf))))
	goto quicly_error;

      for (i = 0; i != num_packets; ++i)
	{

	  if ((err =
	       quic_send_datagram (udp_session, &packets[i], &dest, &src)))
	    goto quicly_error;

	}
    }
  while (num_packets > 0 && num_packets == max_packets);

stop_sending:
  quic_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));
  quic_update_timer (ctx);
  return 0;

quicly_error:
  if (err && err != QUICLY_ERROR_PACKET_IGNORED
      && err != QUICLY_ERROR_FREE_CONNECTION)
    clib_warning ("Quic error '%U'.", quic_format_err, err);
  quic_connection_closed (ctx);
  return 1;
}

/* Quicly callbacks */

static void
quic_on_stream_destroy (quicly_stream_t * stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  QUIC_DBG (2, "DESTROYED_STREAM: session 0x%lx (%U)",
	    session_handle (stream_session), quic_format_err, err);

  stream_session->session_state = SESSION_STATE_CLOSED;
  session_transport_delete_notify (&sctx->connection);

  quic_increment_counter (QUIC_ERROR_CLOSED_STREAM, 1);
  quic_ctx_free (sctx);
  clib_mem_free (stream->data);
}

static void
quic_on_stop_sending (quicly_stream_t * stream, int err)
{
#if QUIC_DEBUG >= 2
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  clib_warning ("(NOT IMPLEMENTD) STOP_SENDING: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  /* TODO : handle STOP_SENDING */
}

static void
quic_on_receive_reset (quicly_stream_t * stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
#if QUIC_DEBUG >= 2
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  clib_warning ("RESET_STREAM: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  session_transport_closing_notify (&sctx->connection);
}

static void
quic_on_receive (quicly_stream_t * stream, size_t off, const void *src,
		 size_t len)
{
  QUIC_DBG (3, "received data: %lu bytes, offset %lu", len, off);
  u32 max_enq, rlen, rv;
  quic_ctx_t *sctx;
  session_t *stream_session;
  app_worker_t *app_wrk;
  svm_fifo_t *f;
  quic_stream_data_t *stream_data;

  if (!len)
    return;

  stream_data = (quic_stream_data_t *) stream->data;
  sctx = quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  stream_session = session_get (sctx->c_s_index, stream_data->thread_index);
  f = stream_session->rx_fifo;

  max_enq = svm_fifo_max_enqueue_prod (f);
  QUIC_DBG (3, "Enqueuing %u at off %u in %u space", len, off, max_enq);
  /* Handle duplicate packet/chunk from quicly */
  if (off < stream_data->app_rx_data_len)
    {
      QUIC_DBG (3, "Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"DUPLICATE PACKET (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index,
		stream_session->app_wrk_index,
		stream_session->thread_index, f,
		max_enq, len, stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return;
    }
  if (PREDICT_FALSE ((off - stream_data->app_rx_data_len + len) > max_enq))
    {
      QUIC_ERR ("Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"RX FIFO IS FULL (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index,
		stream_session->app_wrk_index,
		stream_session->thread_index, f,
		max_enq, len, stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return;			/* This shouldn't happen */
    }
  if (off == stream_data->app_rx_data_len)
    {
      /* Streams live on the same thread so (f, stream_data) should stay consistent */
      rlen = svm_fifo_enqueue (f, len, (u8 *) src);
      QUIC_DBG (3, "Session [idx %u, app_wrk %u, ti %u, rx-fifo 0x%llx]: "
		"Enqueuing %u (rlen %u) at off %u in %u space, ",
		stream_session->session_index,
		stream_session->app_wrk_index,
		stream_session->thread_index, f, len, rlen, off, max_enq);
      stream_data->app_rx_data_len += rlen;
      QUIC_ASSERT (rlen >= len);
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
	{
	  rv = app_worker_lock_and_send_event (app_wrk, stream_session,
					       SESSION_IO_EVT_RX);
	  if (rv)
	    QUIC_ERR ("Failed to ping app for RX");
	}
      quic_ack_rx_data (stream_session);
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (f,
					   off - stream_data->app_rx_data_len,
					   len, (u8 *) src);
      QUIC_ASSERT (rlen == 0);
    }
  return;
}

void
quic_fifo_egress_shift (quicly_stream_t * stream, size_t delta)
{
  quic_stream_data_t *stream_data;
  session_t *stream_session;
  quic_ctx_t *ctx;
  svm_fifo_t *f;
  u32 rv;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_session = get_stream_session_and_ctx_from_stream (stream, &ctx);
  f = stream_session->tx_fifo;

  QUIC_ASSERT (stream_data->app_tx_data_len >= delta);
  stream_data->app_tx_data_len -= delta;
  ctx->bytes_written += delta;
  rv = svm_fifo_dequeue_drop (f, delta);
  QUIC_ASSERT (rv == delta);

  rv = quicly_stream_sync_sendbuf (stream, 0);
  QUIC_ASSERT (!rv);
}

void
quic_fifo_egress_emit (quicly_stream_t * stream, size_t off, void *dst,
		       size_t * len, int *wrote_all)
{
  quic_stream_data_t *stream_data;
  quic_ctx_t *ctx;
  session_t *stream_session;
  svm_fifo_t *f;
  u32 deq_max;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_session = get_stream_session_and_ctx_from_stream (stream, &ctx);
  f = stream_session->tx_fifo;

  QUIC_DBG (3, "Emitting %u, offset %u", *len, off);

  deq_max = svm_fifo_max_dequeue_cons (f);
  QUIC_ASSERT (off <= deq_max);
  if (off + *len < deq_max)
    {
      *wrote_all = 0;
    }
  else
    {
      *wrote_all = 1;
      *len = deq_max - off;
    }
  QUIC_ASSERT (*len > 0);

  if (off + *len > stream_data->app_tx_data_len)
    stream_data->app_tx_data_len = off + *len;

  svm_fifo_peek (f, off, *len, dst);
}

static const quicly_stream_callbacks_t quic_stream_callbacks = {
  .on_destroy = quic_on_stream_destroy,
  .on_send_shift = quic_fifo_egress_shift,
  .on_send_emit = quic_fifo_egress_emit,
  .on_send_stop = quic_on_stop_sending,
  .on_receive = quic_on_receive,
  .on_receive_reset = quic_on_receive_reset
};

static int
quic_on_stream_open (quicly_stream_open_t * self, quicly_stream_t * stream)
{
  /* Return code for this function ends either
   * - in quicly_receive : if not QUICLY_ERROR_PACKET_IGNORED, will close connection
   * - in quicly_open_stream, returned directly
   */

  session_t *stream_session, *quic_session;
  quic_stream_data_t *stream_data;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_id;
  int rv;

  QUIC_DBG (2, "on_stream_open called");
  stream->data = clib_mem_alloc (sizeof (quic_stream_data_t));
  stream->callbacks = &quic_stream_callbacks;
  /* Notify accept on parent qsession, but only if this is not a locally
   * initiated stream */
  if (quicly_stream_is_self_initiated (stream))
    return 0;

  sctx_id = quic_ctx_alloc (vlib_get_thread_index ());
  qctx = quic_get_conn_ctx (stream->conn);

  /* Might need to signal that the connection is ready if the first thing the
   * server does is open a stream */
  quic_check_quic_session_connected (qctx);
  /* ctx might be invalidated */
  qctx = quic_get_conn_ctx (stream->conn);

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "ACCEPTED stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_id);
  sctx = quic_ctx_get (sctx_id, qctx->c_thread_index);
  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_id;
  sctx->c_s_index = stream_session->session_index;
  sctx->stream = stream;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;
  if (quicly_stream_is_unidirectional (stream->stream_id))
    stream_session->flags |= SESSION_F_UNIDIRECTIONAL;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx_id;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  stream_data->app_tx_data_len = 0;

  sctx->c_s_index = stream_session->session_index;
  stream_session->session_state = SESSION_STATE_CREATED;
  stream_session->app_wrk_index = sctx->parent_app_wrk_id;
  stream_session->connection_index = sctx->c_c_index;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, qctx->udp_is_ip4);
  quic_session = session_get (qctx->c_s_index, qctx->c_thread_index);
  stream_session->listener_handle = listen_session_get_handle (quic_session);

  app_wrk = app_worker_get (stream_session->app_wrk_index);
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to allocate fifos");
      quicly_reset_stream (stream, QUIC_APP_ALLOCATION_ERROR);
      return 0;			/* Frame is still valid */
    }
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  if ((rv = app_worker_accept_notify (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to notify accept worker app");
      quicly_reset_stream (stream, QUIC_APP_ACCEPT_NOTIFY_ERROR);
      return 0;			/* Frame is still valid */
    }

  return 0;
}

static void
quic_on_closed_by_remote (quicly_closed_by_remote_t * self,
			  quicly_conn_t * conn, int code, uint64_t frame_type,
			  const char *reason, size_t reason_len)
{
  quic_ctx_t *ctx = quic_get_conn_ctx (conn);
#if QUIC_DEBUG >= 2
  session_t *quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  clib_warning ("Session 0x%lx closed by peer (%U) %.*s ",
		session_handle (quic_session), quic_format_err, code,
		reason_len, reason);
#endif
  ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING;
  session_transport_closing_notify (&ctx->connection);
}

/* Timer handling */

static int64_t
quic_get_thread_time (u8 thread_index)
{
  return quic_main.wrk_ctx[thread_index].time_now;
}

static int64_t
quic_get_time (quicly_now_t * self)
{
  u8 thread_index = vlib_get_thread_index ();
  return quic_get_thread_time (thread_index);
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
  quic_send_packets (ctx);
}

static void
quic_update_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  int64_t next_timeout, next_interval;
  session_t *quic_session;
  int rv;

  /*  This timeout is in ms which is the unit of our timer */
  next_timeout = quicly_get_first_timeout (ctx->conn);
  next_interval = next_timeout - quic_get_time (NULL);

  if (next_timeout == 0 || next_interval <= 0)
    {
      if (ctx->c_s_index == QUIC_SESSION_INVALID)
	{
	  next_interval = 1;
	}
      else
	{
	  quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
	  if (svm_fifo_set_event (quic_session->tx_fifo))
	    {
	      rv = session_send_io_evt_to_thread_custom (quic_session,
							 quic_session->thread_index,
							 SESSION_IO_EVT_BUILTIN_TX);
	      if (PREDICT_FALSE (rv))
		QUIC_ERR ("Failed to enqueue builtin_tx %d", rv);
	    }
	  return;
	}
    }

  tw = &quic_main.wrk_ctx[vlib_get_thread_index ()].timer_wheel;

  QUIC_DBG (4, "Timer set to %ld (int %ld) for ctx %u", next_timeout,
	    next_interval, ctx->c_c_index);

  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
	{
	  QUIC_DBG (4, "timer for ctx %u already stopped", ctx->c_c_index);
	  return;
	}
      ctx->timer_handle = tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index,
							  0, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
	{
	  quic_stop_ctx_timer (ctx);
	}
      else
	tw_timer_update_1t_3w_1024sl_ov (tw, ctx->timer_handle,
					 next_interval);
    }
  return;
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
  quicly_stream_t *stream;
  quicly_conn_t *conn;
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

  sctx_index = quic_ctx_alloc (quic_session->thread_index);	/*  Allocate before we get pointers */
  sctx = quic_ctx_get (sctx_index, quic_session->thread_index);
  qctx = quic_ctx_get (quic_session->connection_index,
		       quic_session->thread_index);
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

  conn = qctx->conn;

  if (!conn || !quicly_connection_is_ready (conn))
    return -1;

  is_unidir = sep->transport_flags & TRANSPORT_CFG_F_UNIDIRECTIONAL;
  if ((rv = quicly_open_stream (conn, &stream, is_unidir)))
    {
      QUIC_DBG (2, "Stream open failed with %d", rv);
      return -1;
    }
  quic_increment_counter (QUIC_ERROR_OPENED_STREAM, 1);

  sctx->stream = stream;

  QUIC_DBG (2, "Opened stream %d, creating session", stream->stream_id);

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
  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx->c_c_index;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  stream_data->app_tx_data_len = 0;
  stream_session->session_state = SESSION_STATE_READY;

  /* For now we only reset streams. Cleanup will be triggered by timers */
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to app_worker_init_connected");
      quicly_reset_stream (stream, QUIC_APP_CONNECT_NOTIFY_ERROR);
      return app_worker_connect_notify (app_wrk, NULL, rv, sep->opaque);
    }

  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  if (app_worker_connect_notify (app_wrk, stream_session, SESSION_E_NONE,
				 sep->opaque))
    {
      QUIC_ERR ("failed to notify app");
      quic_increment_counter (QUIC_ERROR_CLOSED_STREAM, 1);
      quicly_reset_stream (stream, QUIC_APP_CONNECT_NOTIFY_ERROR);
      return -1;
    }

  return 0;
}

static int
quic_connect_connection (session_endpoint_cfg_t * sep)
{
  vnet_connect_args_t _cargs, *cargs = &_cargs;
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;
  app_worker_t *app_wrk;
  application_t *app;
  u32 ctx_index;
  u32 thread_index = vlib_get_thread_index ();
  int error;

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
  if (sep->hostname)
    ctx->srv_hostname = format (0, "%v", sep->hostname);
  else
    /*  needed by quic for crypto + determining client / server */
    ctx->srv_hostname = format (0, "%U", format_ip46_address,
				&sep->ip, sep->is_ip4);
  vec_terminate_c_string (ctx->srv_hostname);

  clib_memcpy (&cargs->sep, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDP;
  cargs->app_index = qm->app_index;
  cargs->api_context = ctx_index;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  ctx->parent_app_id = app_wrk->app_index;
  cargs->sep_ext.ns_index = app->ns_index;
  cargs->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;

  ctx->crypto_engine = sep->crypto_engine;
  ctx->ckpair_index = sep->ckpair_index;
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
  int err;
  quic_ctx_t *ctx = quic_ctx_get_if_valid (ctx_index, thread_index);
  if (!ctx)
    return;
  session_t *stream_session = session_get (ctx->c_s_index,
					   ctx->c_thread_index);
#if QUIC_DEBUG >= 2
  clib_warning ("Closing session 0x%lx", session_handle (stream_session));
#endif
  if (quic_ctx_is_stream (ctx))
    {
      quicly_stream_t *stream = ctx->stream;
      if (!quicly_stream_has_send_side (quicly_is_client (stream->conn),
					stream->stream_id))
	return;
      quicly_sendstate_shutdown (&stream->sendstate, ctx->bytes_written +
				 svm_fifo_max_dequeue
				 (stream_session->tx_fifo));
      err = quicly_stream_sync_sendbuf (stream, 1);
      if (err)
	{
	  QUIC_DBG (1, "sendstate_shutdown failed for stream session %lu",
		    session_handle (stream_session));
	  quicly_reset_stream (stream, QUIC_APP_ERROR_CLOSE_NOTIFY);
	}
      quic_send_packets (ctx);
      return;
    }

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_OPENED:
    case QUIC_CONN_STATE_HANDSHAKE:
    case QUIC_CONN_STATE_READY:
      ctx->conn_state = QUIC_CONN_STATE_ACTIVE_CLOSING;
      quicly_conn_t *conn = ctx->conn;
      /* Start connection closing. Keep sending packets until quicly_send
         returns QUICLY_ERROR_FREE_CONNECTION */

      quic_increment_counter (QUIC_ERROR_CLOSED_CONNECTION, 1);
      quicly_close (conn, QUIC_APP_ERROR_CLOSE_NOTIFY, "Closed by peer");
      /* This also causes all streams to be closed (and the cb called) */
      quic_send_packets (ctx);
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED;
      /* send_packets will eventually return an error, we delete the conn at
         that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED:
      quic_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      break;
    default:
      QUIC_ERR ("Trying to close conn in state %d", ctx->conn_state);
      break;
    }
}

static u32
quic_start_listen (u32 quic_listen_session_index, transport_endpoint_t * tep)
{
  vnet_listen_args_t _bargs, *args = &_bargs;
  quic_main_t *qm = &quic_main;
  session_handle_t udp_handle;
  session_endpoint_cfg_t *sep;
  session_t *udp_listen_session;
  app_worker_t *app_wrk;
  application_t *app;
  quic_ctx_t *lctx;
  u32 lctx_index;
  app_listener_t *app_listener;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  /* We need to call this because we call app_worker_init_connected in
   * quic_accept_stream, which assumes the connect segment manager exists */
  app_worker_alloc_connects_segment_manager (app_wrk);
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
  lctx->crypto_engine = sep->crypto_engine;
  lctx->ckpair_index = sep->ckpair_index;
  if (quic_acquire_crypto_context (lctx))
    return -1;

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
    .wrk_map_index = 0		/* default wrk */
  };
  if (vnet_unlisten (&a))
    clib_warning ("unlisten errored");

  quic_release_crypto_context (lctx->crypto_context_index,
			       0 /* thread_index */ );
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
  str = format (str, "[#%d][Q] ", ctx->c_thread_index);

  if (quic_ctx_is_listener (ctx))
    str = format (str, "Listener, UDP %ld", ctx->udp_session_handle);
  else if (quic_ctx_is_stream (ctx))
    str = format (str, "Stream %ld conn %d",
		  ctx->stream->stream_id, ctx->quic_connection_ctx_id);
  else				/* connection */
    str = format (str, "Conn %d UDP %d", ctx->c_c_index,
		  ctx->udp_session_handle);

  str = format (str, " app %d wrk %d", ctx->parent_app_id,
		ctx->parent_app_wrk_id);

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
  s = format (s, "[#%d][Q] half-open app %u", thread_index,
	      ctx->parent_app_id);
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

static inline void
quic_build_sockaddr (struct sockaddr *sa, socklen_t * salen,
		     ip46_address_t * addr, u16 port, u8 is_ip4)
{
  if (is_ip4)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;
      sa4->sin_family = AF_INET;
      sa4->sin_port = port;
      sa4->sin_addr.s_addr = addr->ip4.as_u32;
      *salen = sizeof (struct sockaddr_in);
    }
  else
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = port;
      clib_memcpy (&sa6->sin6_addr, &addr->ip6, 16);
      *salen = sizeof (struct sockaddr_in6);
    }
}

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

  quic_session->session_state = SESSION_STATE_CONNECTING;
  if ((rv = app_worker_connect_notify (app_wrk, quic_session,
				       SESSION_E_NONE, ctx->client_opaque)))
    {
      QUIC_ERR ("failed to notify app %d", rv);
      quic_proto_on_close (ctx_id, thread_index);
      return;
    }

  /*  If the app opens a stream in its callback it may invalidate ctx */
  ctx = quic_ctx_get (ctx_id, thread_index);
  /*
   * app_worker_connect_notify() might have reallocated pool, reload
   * quic_session pointer
   */
  quic_session = session_get (ctx->c_s_index, thread_index);
  quic_session->session_state = SESSION_STATE_LISTENING;
}

static void
quic_check_quic_session_connected (quic_ctx_t * ctx)
{
  /* Called when we need to trigger quic session connected
   * we may call this function on the server side / at
   * stream opening */

  /* Conn may be set to null if the connection is terminated */
  if (!ctx->conn || ctx->conn_state != QUIC_CONN_STATE_HANDSHAKE)
    return;
  if (!quicly_connection_is_ready (ctx->conn))
    return;
  ctx->conn_state = QUIC_CONN_STATE_READY;
  if (!quicly_is_client (ctx->conn))
    return;
  quic_on_quic_session_connected (ctx);
}

static inline void
quic_update_conn_ctx (quicly_conn_t * conn, quicly_context_t * quicly_context)
{
  /* we need to update the quicly_conn on migrate
   * as it contains a pointer to the crypto context */
  ptls_context_t **tls;
  quicly_context_t **_quicly_context;
  _quicly_context = (quicly_context_t **) conn;
  *_quicly_context = quicly_context;
  tls = (ptls_context_t **) quicly_get_tls (conn);
  *tls = quicly_context->tls;
}

static void
quic_receive_connection (void *arg)
{
  u32 new_ctx_id, thread_index = vlib_get_thread_index ();
  quic_ctx_t *temp_ctx, *new_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quicly_context_t *quicly_context;
  session_t *udp_session;

  temp_ctx = arg;
  new_ctx_id = quic_ctx_alloc (thread_index);
  new_ctx = quic_ctx_get (new_ctx_id, thread_index);

  QUIC_DBG (2, "Received conn %u (now %u)", temp_ctx->c_thread_index,
	    new_ctx_id);

  clib_memcpy (new_ctx, temp_ctx, sizeof (quic_ctx_t));
  clib_mem_free (temp_ctx);

  new_ctx->c_thread_index = thread_index;
  new_ctx->c_c_index = new_ctx_id;
  quic_acquire_crypto_context (new_ctx);

  conn = new_ctx->conn;
  quicly_context = quic_get_quicly_ctx_from_ctx (new_ctx);
  quic_update_conn_ctx (conn, quicly_context);

  quic_store_conn_ctx (conn, new_ctx);
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_id;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_update_timer (new_ctx);

  /*  Trigger write on this connection if necessary */
  udp_session = session_get_from_handle (new_ctx->udp_session_handle);
  udp_session->opaque = new_ctx_id;
  udp_session->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (udp_session->tx_fifo))
    quic_set_udp_tx_evt (udp_session);
}

static void
quic_transfer_connection (u32 ctx_index, u32 dest_thread)
{
  quic_ctx_t *ctx, *temp_ctx;
  u32 thread_index = vlib_get_thread_index ();

  QUIC_DBG (2, "Transferring conn %u to thread %u", ctx_index, dest_thread);

  temp_ctx = clib_mem_alloc (sizeof (quic_ctx_t));
  QUIC_ASSERT (temp_ctx != NULL);
  ctx = quic_ctx_get (ctx_index, thread_index);

  clib_memcpy (temp_ctx, ctx, sizeof (quic_ctx_t));

  quic_stop_ctx_timer (ctx);
  quic_release_crypto_context (ctx->crypto_context_index, thread_index);
  quic_ctx_free (ctx);

  /*  Send connection to destination thread */
  session_send_rpc_evt_to_thread (dest_thread, quic_receive_connection,
				  (void *) temp_ctx);
}

static int
quic_udp_session_connected_callback (u32 quic_app_index, u32 ctx_index,
				     session_t * udp_session,
				     session_error_t err)
{
  QUIC_DBG (2, "UDP Session is now connected (id %u)",
	    udp_session->session_index);
  /* This should always be called before quic_connect returns since UDP always
   * connects instantly. */
  clib_bihash_kv_16_8_t kv;
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  u32 thread_index = vlib_get_thread_index ();
  int ret;
  quicly_context_t *quicly_ctx;


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

  ctx->c_thread_index = thread_index;
  ctx->c_c_index = ctx_index;

  QUIC_DBG (2, "New ctx [%u]%x", thread_index, (ctx) ? ctx_index : ~0);

  ctx->udp_session_handle = session_handle (udp_session);
  udp_session->opaque = ctx_index;

  /* Init QUIC lib connection
   * Generate required sockaddr & salen */
  tc = session_get_transport (udp_session);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  quicly_ctx = quic_get_quicly_ctx_from_ctx (ctx);
  ret = quicly_connect (&ctx->conn, quicly_ctx, (char *) ctx->srv_hostname,
			sa, NULL, &quic_main.wrk_ctx[thread_index].next_cid,
			ptls_iovec_init (NULL, 0), &quic_main.hs_properties,
			NULL);
  ++quic_main.wrk_ctx[thread_index].next_cid.master_id;
  /*  Save context handle in quicly connection */
  quic_store_conn_ctx (ctx->conn, ctx);
  assert (ret == 0);

  /*  Register connection in connections map */
  conn = ctx->conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );

  /*  UDP stack quirk? preemptively transfer connection if that happens */
  if (udp_session->thread_index != thread_index)
    quic_transfer_connection (ctx_index, udp_session->thread_index);
  else
    quic_send_packets (ctx);

  return ret;
}

static void
quic_udp_session_disconnect_callback (session_t * s)
{
  clib_warning ("UDP session disconnected???");
}

static void
quic_udp_session_cleanup_callback (session_t * udp_session,
				   session_cleanup_ntf_t ntf)
{
  quic_ctx_t *ctx;

  if (ntf != SESSION_CLEANUP_SESSION)
    return;

  ctx = quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  quic_stop_ctx_timer (ctx);
  quic_release_crypto_context (ctx->crypto_context_index,
			       ctx->c_thread_index);
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
  quic_ack_rx_data (stream_session);
  svm_fifo_reset_has_deq_ntf (stream_session->rx_fifo);

  /* Need to send packets (acks may never be sent otherwise) */
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  quic_send_packets (ctx);
  return 0;
}

static int
quic_custom_tx_callback (void *s, transport_send_params_t * sp)
{
  session_t *stream_session = (session_t *) s;
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  quic_ctx_t *ctx;
  u32 max_deq;
  int rv;

  if (PREDICT_FALSE
      (stream_session->session_state >= SESSION_STATE_TRANSPORT_CLOSING))
    return 0;
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  if (PREDICT_FALSE (!quic_ctx_is_stream (ctx)))
    {
      goto tx_end;		/* Most probably a reschedule */
    }

  QUIC_DBG (3, "Stream TX event");
  quic_ack_rx_data (stream_session);
  stream = ctx->stream;
  if (!quicly_sendstate_is_open (&stream->sendstate))
    {
      QUIC_ERR ("Warning: tried to send on closed stream");
      return -1;
    }

  stream_data = (quic_stream_data_t *) stream->data;
  max_deq = svm_fifo_max_dequeue (stream_session->tx_fifo);
  QUIC_ASSERT (max_deq >= stream_data->app_tx_data_len);
  if (max_deq == stream_data->app_tx_data_len)
    {
      QUIC_DBG (3, "TX but no data %d / %d", max_deq,
		stream_data->app_tx_data_len);
      return 0;
    }
  stream_data->app_tx_data_len = max_deq;
  rv = quicly_stream_sync_sendbuf (stream, 1);
  QUIC_ASSERT (!rv);

tx_end:
  quic_send_packets (ctx);
  return 0;
}

/*
 * Returns 0 if a matching connection is found and is on the right thread.
 * Otherwise returns -1.
 * If a connection is found, even on the wrong thread, ctx_thread and ctx_index
 * will be set.
 */
static inline int
quic_find_packet_ctx (quic_rx_packet_ctx_t * pctx, u32 caller_thread_index)
{
  clib_bihash_kv_16_8_t kv;
  clib_bihash_16_8_t *h;
  quic_ctx_t *ctx;
  u32 index, thread_id;

  h = &quic_main.connection_hash;
  quic_make_connection_key (&kv, &pctx->packet.cid.dest.plaintext);
  QUIC_DBG (3, "Searching conn with id %lu %lu", kv.key[0], kv.key[1]);

  if (clib_bihash_search_16_8 (h, &kv, &kv))
    {
      QUIC_DBG (3, "connection not found");
      return QUIC_PACKET_TYPE_NONE;
    }

  index = kv.value & UINT32_MAX;
  thread_id = kv.value >> 32;
  /* Check if this connection belongs to this thread, otherwise
   * ask for it to be moved */
  if (thread_id != caller_thread_index)
    {
      QUIC_DBG (2, "Connection is on wrong thread");
      /* Cannot make full check with quicly_is_destination... */
      pctx->ctx_index = index;
      pctx->thread_index = thread_id;
      return QUIC_PACKET_TYPE_MIGRATE;
    }
  ctx = quic_ctx_get (index, vlib_get_thread_index ());
  if (!ctx->conn)
    {
      QUIC_ERR ("ctx has no conn");
      return QUIC_PACKET_TYPE_NONE;
    }
  if (!quicly_is_destination (ctx->conn, NULL, &pctx->sa, &pctx->packet))
    return QUIC_PACKET_TYPE_NONE;

  QUIC_DBG (3, "Connection found");
  pctx->ctx_index = index;
  pctx->thread_index = thread_id;
  return QUIC_PACKET_TYPE_RECEIVE;
}

static void
quic_accept_connection (quic_rx_packet_ctx_t * pctx)
{
  quicly_context_t *quicly_ctx;
  session_t *quic_session;
  clib_bihash_kv_16_8_t kv;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  quic_ctx_t *lctx;
  int rv;

  /* new connection, accept and create context if packet is valid
   * TODO: check if socket is actually listening? */
  ctx = quic_ctx_get (pctx->ctx_index, pctx->thread_index);
  if (ctx->c_s_index != QUIC_SESSION_INVALID)
    {
      QUIC_DBG (2, "already accepted ctx 0x%x", ctx->c_s_index);
      return;
    }

  quicly_ctx = quic_get_quicly_ctx_from_ctx (ctx);
  if ((rv = quicly_accept (&conn, quicly_ctx, NULL, &pctx->sa,
			   &pctx->packet, NULL,
			   &quic_main.wrk_ctx[pctx->thread_index].next_cid,
			   NULL)))
    {
      /* Invalid packet, pass */
      assert (conn == NULL);
      QUIC_ERR ("Accept failed with %U", quic_format_err, rv);
      /* TODO: cleanup created quic ctx and UDP session */
      return;
    }
  assert (conn != NULL);

  ++quic_main.wrk_ctx[pctx->thread_index].next_cid.master_id;
  /* Save ctx handle in quicly connection */
  quic_store_conn_ctx (conn, ctx);
  ctx->conn = conn;

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2, "Allocated quic_session, 0x%lx ctx %u",
	    session_handle (quic_session), ctx->c_c_index);
  quic_session->session_state = SESSION_STATE_LISTENING;
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_ctx_get (ctx->listener_ctx_id, 0);

  quic_session->app_wrk_index = lctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  quic_session->listener_handle = lctx->c_s_index;

  /* Register connection in connections map */
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) pctx->thread_index) << 32 | (u64) pctx->ctx_index;
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);

  /* If notify fails, reset connection immediatly */
  if ((rv = app_worker_init_accepted (quic_session)))
    {
      QUIC_ERR ("failed to allocate fifos");
      quic_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  app_wrk = app_worker_get (quic_session->app_wrk_index);
  if ((rv = app_worker_accept_notify (app_wrk, quic_session)))
    {
      QUIC_ERR ("failed to notify accept worker app");
      quic_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  ctx->conn_state = QUIC_CONN_STATE_READY;
}

static int
quic_reset_connection (u64 udp_session_handle, quic_rx_packet_ctx_t * pctx)
{
  /* short header packet; potentially a dead connection. No need to check the
   * length of the incoming packet, because loop is prevented by authenticating
   * the CID (by checking node_id and thread_id). If the peer is also sending a
   * reset, then the next CID is highly likely to contain a non-authenticating
   * CID, ... */
  QUIC_DBG (2, "Sending stateless reset");
  int rv;
  session_t *udp_session;
  quicly_context_t *quicly_ctx;
  if (pctx->packet.cid.dest.plaintext.node_id != 0
      || pctx->packet.cid.dest.plaintext.thread_id != 0)
    return 0;
  quicly_ctx = quic_get_quicly_ctx_from_udp (udp_session_handle);
  quic_ctx_t *qctx = quic_ctx_get (pctx->ctx_index, pctx->thread_index);

  quicly_address_t src;
  uint8_t payload[quicly_ctx->transport_params.max_udp_payload_size];
  size_t payload_len =
    quicly_send_stateless_reset (quicly_ctx, &src.sa, payload);
  if (payload_len == 0)
    return 1;

  struct iovec packet;
  packet.iov_len = payload_len;
  packet.iov_base = payload;

  struct _st_quicly_conn_public_t *conn =
    (struct _st_quicly_conn_public_t *) qctx->conn;

  udp_session = session_get_from_handle (udp_session_handle);
  rv =
    quic_send_datagram (udp_session, &packet, &conn->remote.address,
			&conn->local.address);
  quic_set_udp_tx_evt (udp_session);
  return rv;
}

static int
quic_process_one_rx_packet (u64 udp_session_handle, svm_fifo_t * f,
			    u32 fifo_offset, quic_rx_packet_ctx_t * pctx)
{
  size_t plen;
  u32 full_len, ret;
  u32 thread_index = vlib_get_thread_index ();
  u32 cur_deq = svm_fifo_max_dequeue (f) - fifo_offset;
  quicly_context_t *quicly_ctx;
  session_t *udp_session;
  int rv;

  ret = svm_fifo_peek (f, fifo_offset,
		       SESSION_CONN_HDR_LEN, (u8 *) & pctx->ph);
  QUIC_ASSERT (ret == SESSION_CONN_HDR_LEN);
  QUIC_ASSERT (pctx->ph.data_offset == 0);
  full_len = pctx->ph.data_length + SESSION_CONN_HDR_LEN;
  if (full_len > cur_deq)
    {
      QUIC_ERR ("Not enough data in fifo RX");
      return 1;
    }

  /* Quicly can read len bytes from the fifo at offset:
   * ph.data_offset + SESSION_CONN_HDR_LEN */
  ret = svm_fifo_peek (f, SESSION_CONN_HDR_LEN + fifo_offset,
		       pctx->ph.data_length, pctx->data);
  if (ret != pctx->ph.data_length)
    {
      QUIC_ERR ("Not enough data peeked in RX");
      return 1;
    }

  quic_increment_counter (QUIC_ERROR_RX_PACKETS, 1);
  quic_build_sockaddr (&pctx->sa, &pctx->salen, &pctx->ph.rmt_ip,
		       pctx->ph.rmt_port, pctx->ph.is_ip4);
  quicly_ctx = quic_get_quicly_ctx_from_udp (udp_session_handle);

  size_t off = 0;
  plen = quicly_decode_packet (quicly_ctx, &pctx->packet,
			       pctx->data, pctx->ph.data_length, &off);

  if (plen == SIZE_MAX)
    {
      return 1;
    }

  rv = quic_find_packet_ctx (pctx, thread_index);
  if (rv == QUIC_PACKET_TYPE_RECEIVE)
    {
      pctx->ptype = QUIC_PACKET_TYPE_RECEIVE;

      if (quic_main.vnet_crypto_enabled
	  && quic_main.default_crypto_engine == CRYPTO_ENGINE_VPP)
	{
	  quic_ctx_t *qctx = quic_ctx_get (pctx->ctx_index, thread_index);
	  quic_crypto_decrypt_packet (qctx, pctx);
	}
      return 0;
    }
  else if (rv == QUIC_PACKET_TYPE_MIGRATE)
    {
      pctx->ptype = QUIC_PACKET_TYPE_MIGRATE;
      /*  Connection found but on wrong thread, ask move */
    }
  else if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
    {
      pctx->ptype = QUIC_PACKET_TYPE_ACCEPT;
      udp_session = session_get_from_handle (udp_session_handle);
      pctx->ctx_index = udp_session->opaque;
      pctx->thread_index = thread_index;
    }
  else
    {
      pctx->ptype = QUIC_PACKET_TYPE_RESET;
    }
  return 1;
}

static int
quic_udp_session_rx_callback (session_t * udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quicly conn. */
  quic_ctx_t *ctx = NULL, *prev_ctx = NULL;
  svm_fifo_t *f = udp_session->rx_fifo;
  u32 max_deq;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  u32 thread_index = vlib_get_thread_index ();
  u32 cur_deq, fifo_offset, max_packets, i;

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
      rv = quic_process_one_rx_packet (udp_session_handle, f,
				       fifo_offset, &packets_ctx[i]);
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
	  rv = quicly_receive (ctx->conn, NULL, &packets_ctx[i].sa,
			       &packets_ctx[i].packet);
	  if (rv && rv != QUICLY_ERROR_PACKET_IGNORED)
	    {
	      QUIC_ERR ("quicly_receive return error %U",
			quic_format_err, rv);
	    }
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  quic_accept_connection (&packets_ctx[i]);
	  break;
	case QUIC_PACKET_TYPE_RESET:
	  quic_reset_connection (udp_session_handle, &packets_ctx[i]);
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
	  ctx = quic_ctx_get (packets_ctx[i].ctx_index,
			      packets_ctx[i].thread_index);
	  quic_check_quic_session_connected (ctx);
	  ctx = quic_ctx_get (packets_ctx[i].ctx_index,
			      packets_ctx[i].thread_index);
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  ctx = quic_ctx_get (packets_ctx[i].ctx_index,
			      packets_ctx[i].thread_index);
	  break;
	default:
	  continue;		/* this exits the for loop since other packet types are
				   necessarily the last in the batch */
	}
      if (ctx != prev_ctx)
	quic_send_packets (ctx);
    }

  udp_session = session_get_from_handle (udp_session_handle);	/*  session alloc might have happened */
  f = udp_session->rx_fifo;
  svm_fifo_dequeue_drop (f, fifo_offset);

  if (svm_fifo_max_dequeue (f))
    goto rx_start;

  return 0;
}

always_inline void
quic_common_get_transport_endpoint (quic_ctx_t * ctx,
				    transport_endpoint_t * tep, u8 is_lcl)
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
				      transport_endpoint_t * tep, u8 is_lcl)
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
			     transport_endpoint_t * tep, u8 is_lcl)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  quic_common_get_transport_endpoint (ctx, tep, is_lcl);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

static quicly_stream_open_t on_stream_open = { quic_on_stream_open };
static quicly_closed_by_remote_t on_closed_by_remote =
  { quic_on_closed_by_remote };
static quicly_now_t quicly_vpp_now_cb = { quic_get_time };

static void
quic_register_cipher_suite (crypto_engine_type_t type,
			    ptls_cipher_suite_t ** ciphers)
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
      clib_warning
	("error while getting segment_manager_props_t, can't update fifo-size");
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
					   1e-3 /* timer period 1ms */ , ~0);
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
      quic_register_cipher_suite (CRYPTO_ENGINE_VPP,
				  quic_crypto_cipher_suites);
      qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
    }

  qm->max_packets_per_key = DEFAULT_MAX_PACKETS_PER_KEY;
  clib_rwlock_init (&qm->crypto_keys_quic_rw_lock);

  qm->default_quic_cc = QUIC_CC_RENO;

  vec_free (a->name);
  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

static clib_error_t *
quic_plugin_crypto_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
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
quic_plugin_set_fifo_size_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
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
	      return clib_error_return
		(0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	    }
	  qm->udp_fifo_size = tmp;
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
  int index = 0;

  vm = vlib_get_main ();
  em = &vm->error_main;
  n = vlib_get_node (vm, quic_input_node.index);
  code = event_code;
  /* *INDENT-OFF* */
  foreach_vlib_main(({
    em = &this_vlib_main->error_main;
    i = n->error_heap_index + code;
    c = em->counters[i];

    if (i < vec_len (em->counters_last_clear))
       c -= em->counters_last_clear[i];
    sum += c;
    index++;
  }));
  /* *INDENT-ON* */
  return sum;
}

static void
quic_show_aggregated_stats (vlib_main_t * vm)
{
  u32 num_workers = vlib_num_workers ();
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx = NULL;
  quicly_stats_t st, agg_stats;
  u32 i, nconn = 0, nstream = 0;

  clib_memset (&agg_stats, 0, sizeof (agg_stats));
  for (i = 0; i < num_workers + 1; i++)
    {
      /* *INDENT-OFF* */
      pool_foreach (ctx, qm->ctx_pool[i],
      ({
	if (quic_ctx_is_conn (ctx) && ctx->conn)
	  {
	    quicly_get_stats (ctx->conn, &st);
	    agg_stats.rtt.smoothed += st.rtt.smoothed;
	    agg_stats.rtt.minimum += st.rtt.minimum;
	    agg_stats.rtt.variance += st.rtt.variance;
	    agg_stats.num_packets.received += st.num_packets.received;
	    agg_stats.num_packets.sent += st.num_packets.sent;
	    agg_stats.num_packets.lost += st.num_packets.lost;
	    agg_stats.num_packets.ack_received += st.num_packets.ack_received;
	    agg_stats.num_bytes.received += st.num_bytes.received;
	    agg_stats.num_bytes.sent += st.num_bytes.sent;
	    nconn++;
	  }
	else if (quic_ctx_is_stream (ctx))
	  nstream++;
      }));
      /* *INDENT-ON* */
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
		   nconn > 0 ? agg_stats.rtt.minimum / nconn : 0);
  vlib_cli_output (vm, "Smoothed RTT     %f",
		   nconn > 0 ? agg_stats.rtt.smoothed / nconn : 0);
  vlib_cli_output (vm, "Variance on RTT  %f",
		   nconn > 0 ? agg_stats.rtt.variance / nconn : 0);
  vlib_cli_output (vm, "Packets Received %lu",
		   agg_stats.num_packets.received);
  vlib_cli_output (vm, "Packets Sent     %lu", agg_stats.num_packets.sent);
  vlib_cli_output (vm, "Packets Lost     %lu", agg_stats.num_packets.lost);
  vlib_cli_output (vm, "Packets Acks     %lu",
		   agg_stats.num_packets.ack_received);
  vlib_cli_output (vm, "RX bytes         %lu", agg_stats.num_bytes.received);
  vlib_cli_output (vm, "TX bytes         %lu", agg_stats.num_bytes.sent);
}

static u8 *
quic_format_quicly_conn_id (u8 * s, va_list * args)
{
  quicly_cid_plaintext_t *mid = va_arg (*args, quicly_cid_plaintext_t *);
  s = format (s, "C%x_%x", mid->master_id, mid->thread_id);
  return s;
}

static u8 *
quic_format_quicly_stream_id (u8 * s, va_list * args)
{
  quicly_stream_t *stream = va_arg (*args, quicly_stream_t *);
  s =
    format (s, "%U S%lx", quic_format_quicly_conn_id,
	    quicly_get_master_id (stream->conn), stream->stream_id);
  return s;
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
  quicly_stats_t quicly_stats;

  s = format (s, "[#%d][%x]", ctx->c_thread_index, ctx->c_c_index);

  if (!ctx->conn)
    {
      s = format (s, "- no conn -\n");
      return s;
    }
  s = format (s, "[%U]",
	      quic_format_quicly_conn_id, quicly_get_master_id (ctx->conn));
  quicly_get_stats (ctx->conn, &quicly_stats);

  s = format (s, "[RTT >%3d, ~%3d, V%3d, last %3d]",
	      quicly_stats.rtt.minimum, quicly_stats.rtt.smoothed,
	      quicly_stats.rtt.variance, quicly_stats.rtt.latest);
  s = format (s, " TX:%d RX:%d loss:%d ack:%d",
	      quicly_stats.num_packets.sent,
	      quicly_stats.num_packets.received,
	      quicly_stats.num_packets.lost,
	      quicly_stats.num_packets.ack_received);
  s = format (s, "\ncwnd:%u ssthresh:%u recovery_end:%lu",
	      quicly_stats.cc.cwnd, quicly_stats.cc.ssthresh,
	      quicly_stats.cc.recovery_end);

  quicly_context_t *quicly_ctx = quic_get_quicly_ctx_from_ctx (ctx);
  if (quicly_ctx->init_cc == &quicly_cc_cubic_init)
    {
      s =
	format (s,
		"\nk:%d w_max:%u w_last_max:%u avoidance_start:%ld last_sent_time:%ld",
		quicly_stats.cc.state.cubic.k,
		quicly_stats.cc.state.cubic.w_max,
		quicly_stats.cc.state.cubic.w_last_max,
		quicly_stats.cc.state.cubic.avoidance_start,
		quicly_stats.cc.state.cubic.last_sent_time);
    }
  else if (quicly_ctx->init_cc == &quicly_cc_reno_init)
    {
      s = format (s, " stash:%u", quicly_stats.cc.state.reno.stash);
    }

  return s;
}

static u8 *
quic_format_stream_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  session_t *stream_session;
  quicly_stream_t *stream = ctx->stream;
  u32 txs, rxs;

  s = format (s, "[#%d][%x]", ctx->c_thread_index, ctx->c_c_index);
  s = format (s, "[%U]", quic_format_quicly_stream_id, stream);

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
quic_show_connections_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
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
      /* *INDENT-OFF* */
      pool_foreach (ctx, qm->ctx_pool[i],
      ({
        if (quic_ctx_is_stream (ctx) && show_stream)
          vlib_cli_output (vm, "%U", quic_format_stream_ctx, ctx);
        else if (quic_ctx_is_listener (ctx) && show_listeners)
          vlib_cli_output (vm, "%U", quic_format_listener_ctx, ctx);
	else if (quic_ctx_is_conn (ctx) && show_conn)
          vlib_cli_output (vm, "%U", quic_format_connection_ctx, ctx);
      }));
      /* *INDENT-ON* */
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (quic_plugin_crypto_command, static) =
{
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
VLIB_CLI_COMMAND (quic_set_cc, static) =
{
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
/* *INDENT-ON* */

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
      if (unformat (input, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      error = clib_error_return (0,
					 "fifo-size %llu (0x%llx) too large",
					 tmp, tmp);
	      goto done;
	    }
	  qm->udp_fifo_size = tmp;
	}
      else if (unformat (input, "conn-timeout %u", &i))
	qm->connection_timeout = i;
      else if (unformat (input, "fifo-prealloc %u", &i))
	qm->udp_fifo_prealloc = i;
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
quic_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (quic_input_node) =
{
  .function = quic_node_fn,
  .name = "quic-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (quic_error_strings),
  .error_strings = quic_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
