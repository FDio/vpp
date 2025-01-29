/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <quic/quic.h>
#include <quic_quicly/quic_quicly.h>
#include <vnet/session/application.h>

static const quicly_stream_callbacks_t quic_stream_callbacks = {
  .on_destroy = quic_on_stream_destroy,
  .on_send_shift = quic_fifo_egress_shift,
  .on_send_emit = quic_fifo_egress_emit,
  .on_send_stop = quic_on_stop_sending,
  .on_receive = quic_on_receive,
  .on_receive_reset = quic_on_receive_reset
};

static int
quic_quicly_on_stream_open (quicly_stream_open_t *self,
         quicly_stream_t *stream)
{
  /* Return code for this function ends either
   * - in quicly_receive : if not QUICLY_ERROR_PACKET_IGNORED, will close
   * connection
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
  sctx->crypto_context_index = qctx->crypto_context_index;
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
  /* Make sure quic session is in listening state */
  quic_session->session_state = SESSION_STATE_LISTENING;
  stream_session->listener_handle = listen_session_get_handle (quic_session);

  app_wrk = app_worker_get (stream_session->app_wrk_index);
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to allocate fifos");
      quicly_reset_stream (stream, QUIC_APP_ALLOCATION_ERROR);
      return 0; /* Frame is still valid */
    }
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
       SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
         SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);
  svm_fifo_init_ooo_lookup (stream_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (stream_session->tx_fifo, 1 /* ooo deq */);

  stream_session->session_state = SESSION_STATE_ACCEPTING;
  if ((rv = app_worker_accept_notify (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to notify accept worker app");
      quicly_reset_stream (stream, QUIC_APP_ACCEPT_NOTIFY_ERROR);
      return 0; /* Frame is still valid */
    }

  return 0;
}

static void
quic_quicly_on_closed_by_remote (quicly_closed_by_remote_t *self,
      quicly_conn_t *conn, int code,
      uint64_t frame_type, const char *reason,
      size_t reason_len)
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

static int64_t
quic_quicly_get_time (quicly_now_t *self)
{
  return quic_get_time ();
}

static quicly_stream_open_t on_stream_open = { quic_quicly_on_stream_open };
static quicly_closed_by_remote_t on_closed_by_remote = {
  quic_quicly_on_closed_by_remote
};
static quicly_now_t quicly_vpp_now_cb = { quic_quicly_get_time };

int
quic_quicly_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_main_t *qm = get_quic_main ();
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

  if (qm->vnet_crypto_enabled &&
      qm->default_crypto_engine == CRYPTO_ENGINE_VPP)
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
  quicly_ctx->cid_encryptor = quicly_new_default_cid_encryptor (
    &ptls_openssl_bfecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
    key_vec);

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

static quic_ctx_t *
quic_quicly_conn_ctx_get (void * conn)
{
  u64 conn_data;
  conn_data = (u64) * quicly_get_data ((quicly_conn_t *)conn);
  return quic_ctx_get (conn_data & UINT32_MAX, conn_data >> 32);
}

const static quic_lib_vft_t quic_quicly_vft = {
  .init_crypto_context = quic_quicly_init_crypto_context,
  .conn_ctx_get = quic_quicly_conn_ctx_get,
};

extern void quic_lib_register (const quic_lib_vft_t *ql_vft, quic_lib_type_t lib_type);
static clib_error_t *
quic_quicly_init (vlib_main_t * vm)
{
  // vlib_thread_main_t *vtm = vlib_get_thread_main ();
  // u32 num_threads;

  // num_threads = 1 /* main thread */  + vtm->n_threads;

  quic_lib_register (&quic_quicly_vft, QUIC_LIB_QUICLY);
  return 0;
}

VLIB_INIT_FUNCTION (quic_quicly_init) =
{
  .runs_after = VLIB_INITS("quic_init"),
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "QUIC library, quicly",
};
