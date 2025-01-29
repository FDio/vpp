/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <quic/quic.h>
#include <quic/error.h>
#include <quic_quicly/quic_quicly.h>
#include <vnet/session/application.h>

static quicly_context_t *
quic_quicly_get_quicly_ctx_from_ctx (quic_ctx_t * ctx)
{
  crypto_context_t *crctx =
    quic_crypto_context_get (ctx->crypto_context_index, ctx->c_thread_index);
  quic_quicly_crypto_context_data_t *data =
    (quic_quicly_crypto_context_data_t *) crctx->data;
  return &data->quicly_ctx;
}

static quicly_context_t *
quic_quicly_get_quicly_ctx_from_udp (u64 udp_session_handle)
{
  session_t *udp_session = session_get_from_handle (udp_session_handle);
  quic_ctx_t *ctx =
    quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  return quic_quicly_get_quicly_ctx_from_ctx (ctx);
}

static_always_inline void
quic_quicly_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
					 crypto_context_t *crctx)
{
  quic_quicly_crypto_context_data_t *data =
    (quic_quicly_crypto_context_data_t *) crctx->data;
  kv->key[0] = ((u64) crctx->ckpair_index) << 32 | (u64) crctx->crypto_engine;
  kv->key[1] = data->quicly_ctx.transport_params.max_stream_data.bidi_local;
  kv->key[2] = data->quicly_ctx.transport_params.max_stream_data.bidi_remote;
}

static inline session_t *
get_stream_session_and_ctx_from_stream (quicly_stream_t *stream,
					quic_ctx_t **ctx)
{
  quic_stream_data_t *stream_data;

  stream_data = (quic_stream_data_t *) stream->data;
  *ctx = quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  return session_get ((*ctx)->c_s_index, stream_data->thread_index);
}

/* Quicly callbacks */

static void
quic_quicly_on_stream_destroy (quicly_stream_t *stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  QUIC_DBG (2, "DESTROYED_STREAM: session 0x%lx (%U)",
	    session_handle (stream_session), quic_format_err, err);

  session_transport_closing_notify (&sctx->connection);
  session_transport_delete_notify (&sctx->connection);

  quic_increment_counter (QUIC_ERROR_CLOSED_STREAM, 1);
  quic_ctx_free (sctx);
  clib_mem_free (stream->data);
}

static void
quic_quicly_fifo_egress_shift (quicly_stream_t * stream, size_t delta)
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

static void
quic_quicly_fifo_egress_emit (quicly_stream_t *stream, size_t off, void *dst,
		       size_t *len, int *wrote_all)
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

static void
quic_quicly_on_stop_sending (quicly_stream_t *stream, int err)
{
#if QUIC_DEBUG >= 2
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  session_t *stream_session =
    session_get (sctx->c_s_index, sctx->c_thread_index);
  clib_warning ("(NOT IMPLEMENTD) STOP_SENDING: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  /* TODO : handle STOP_SENDING */
}

static void
quic_quicly_ack_rx_data (session_t * stream_session)
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
quic_quicly_on_receive (quicly_stream_t *stream, size_t off, const void *src,
		 size_t len)
{
  QUIC_DBG (3, "received data: %lu bytes, offset %lu", len, off);
  u32 max_enq;
  quic_ctx_t *sctx;
  session_t *stream_session;
  app_worker_t *app_wrk;
  svm_fifo_t *f;
  quic_stream_data_t *stream_data;
  int rlen;

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
      QUIC_DBG (3,
		"Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"DUPLICATE PACKET (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, max_enq, len,
		stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return;
    }
  if (PREDICT_FALSE ((off - stream_data->app_rx_data_len + len) > max_enq))
    {
      QUIC_ERR ("Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"RX FIFO IS FULL (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, max_enq, len,
		stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return; /* This shouldn't happen */
    }
  if (off == stream_data->app_rx_data_len)
    {
      /* Streams live on the same thread so (f, stream_data) should stay consistent */
      rlen = svm_fifo_enqueue (f, len, (u8 *) src);
      if (PREDICT_FALSE (rlen < 0))
      {
	/*
	 * drop, fifo full
	 * drop, fifo grow
	 */
	return;
      }
      QUIC_DBG (3,
		"Session [idx %u, app_wrk %u, ti %u, rx-fifo 0x%llx]: "
		"Enqueuing %u (rlen %u) at off %u in %u space, ",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, len, rlen, off, max_enq);
      stream_data->app_rx_data_len += rlen;
      QUIC_ASSERT (rlen >= len);
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
      {
	app_worker_rx_notify (app_wrk, stream_session);
      }
      quic_quicly_ack_rx_data (stream_session);
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (
	f, off - stream_data->app_rx_data_len, len, (u8 *) src);
      if (PREDICT_FALSE (rlen < 0))
      {
	/*
	 * drop, fifo full
	 * drop, fifo grow
	 */
	return;
      }
      QUIC_ASSERT (rlen == 0);
    }
  return;
}

static void
quic_quicly_on_receive_reset (quicly_stream_t *stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
#if QUIC_DEBUG >= 2
  session_t *stream_session =
    session_get (sctx->c_s_index, sctx->c_thread_index);
  clib_warning ("RESET_STREAM: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  session_transport_closing_notify (&sctx->connection);
}
static const quicly_stream_callbacks_t quic_stream_callbacks = {
  .on_destroy = quic_quicly_on_stream_destroy,
  .on_send_shift = quic_quicly_fifo_egress_shift,
  .on_send_emit = quic_quicly_fifo_egress_emit,
  .on_send_stop = quic_quicly_on_stop_sending,
  .on_receive = quic_quicly_on_receive,
  .on_receive_reset = quic_quicly_on_receive_reset
};

static quic_ctx_t *
quic_quicly_get_conn_ctx (void *conn)
{
  u64 conn_data;
  conn_data = (u64) *quicly_get_data ((quicly_conn_t *) conn);
  return quic_ctx_get (conn_data & UINT32_MAX, conn_data >> 32);
}

static void
quic_quicly_store_conn_ctx (void * conn, quic_ctx_t * ctx)
{
  *quicly_get_data ((quicly_conn_t *) conn) =
    (void *) (((u64) ctx->c_thread_index) << 32 | (u64) ctx->c_c_index);
}

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
  qctx = quic_quicly_get_conn_ctx (stream->conn);

  /* Might need to signal that the connection is ready if the first thing the
   * server does is open a stream */
  quic_check_quic_session_connected (qctx);
  /* ctx might be invalidated */
  qctx = quic_quicly_get_conn_ctx (stream->conn);

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
  quic_ctx_t *ctx = quic_quicly_get_conn_ctx (conn);
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

static int
quic_quicly_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_main_t *qm = get_quic_main ();
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  app_cert_key_pair_t *ckpair;
  application_t *app;
  quic_quicly_crypto_context_data_t *data;
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

static u32
quic_crypto_set_key (crypto_key_t *key)
{
  u8 thread_index = vlib_get_thread_index ();
  quic_main_t *qm = get_quic_main ();
  u32 key_id = qm->per_thread_crypto_key_indices[thread_index];
  vnet_crypto_key_t *vnet_key = vnet_crypto_get_key (key_id);
  vnet_crypto_engine_t *engine;

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_DEL, key_id);

  vnet_key->alg = key->algo;
  clib_memcpy (vnet_key->data, key->key, key->key_len);

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_ADD, key_id);

  return key_id;
}

static size_t
quic_quicly_crypto_aead_decrypt (quic_ctx_t *qctx, ptls_aead_context_t *_ctx,
			  void *_output, const void *input, size_t inlen,
			  uint64_t decrypted_pn, const void *aad,
			  size_t aadlen)
{
  vlib_main_t *vm = vlib_get_main ();

  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_op_init (&ctx->op, ctx->id);
  ctx->op.aad = (u8 *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.iv = ctx->iv;
  ptls_aead__build_iv (ctx->super.algo, ctx->op.iv, ctx->static_iv,
		       decrypted_pn);
  ctx->op.src = (u8 *) input;
  ctx->op.dst = _output;
  ctx->op.key_index = quic_crypto_set_key (&ctx->key);
  ctx->op.len = inlen - ctx->super.algo->tag_size;
  ctx->op.tag_len = ctx->super.algo->tag_size;
  ctx->op.tag = ctx->op.src + ctx->op.len;

  vnet_crypto_process_ops (vm, &(ctx->op), 1);

  return ctx->op.len;
}

static void
quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx, quic_rx_packet_ctx_t *pctx)
{
  ptls_cipher_context_t *header_protection = NULL;
  ptls_aead_context_t *aead = NULL;
  int pn;

  /* Long Header packets are not decrypted by vpp */
  if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
    return;

  uint64_t next_expected_packet_number =
    quicly_get_next_expected_packet_number (qctx->conn);
  if (next_expected_packet_number == UINT64_MAX)
    return;

  aead = qctx->ingress_keys.aead_ctx;
  header_protection = qctx->ingress_keys.hp_ctx;

  if (!aead || !header_protection)
    return;

  size_t encrypted_len = pctx->packet.octets.len - pctx->packet.encrypted_off;
  uint8_t hpmask[5] = { 0 };
  uint32_t pnbits = 0;
  size_t pnlen, ptlen, i;

  /* decipher the header protection, as well as obtaining pnbits, pnlen */
  if (encrypted_len < header_protection->algo->iv_size + QUICLY_MAX_PN_SIZE)
    return;
  ptls_cipher_init (header_protection, pctx->packet.octets.base +
					 pctx->packet.encrypted_off +
					 QUICLY_MAX_PN_SIZE);
  ptls_cipher_encrypt (header_protection, hpmask, hpmask, sizeof (hpmask));
  pctx->packet.octets.base[0] ^=
    hpmask[0] &
    (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]) ? 0xf : 0x1f);
  pnlen = (pctx->packet.octets.base[0] & 0x3) + 1;
  for (i = 0; i != pnlen; ++i)
    {
      pctx->packet.octets.base[pctx->packet.encrypted_off + i] ^=
	hpmask[i + 1];
      pnbits = (pnbits << 8) |
	       pctx->packet.octets.base[pctx->packet.encrypted_off + i];
    }

  size_t aead_off = pctx->packet.encrypted_off + pnlen;

  pn = quicly_determine_packet_number (pnbits, pnlen * 8,
				       next_expected_packet_number);

  int key_phase_bit =
    (pctx->packet.octets.base[0] & QUICLY_KEY_PHASE_BIT) != 0;

  if (key_phase_bit != (qctx->key_phase_ingress & 1))
    {
      pctx->packet.octets.base[0] ^=
	hpmask[0] &
	(QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]) ? 0xf :
									    0x1f);
      for (i = 0; i != pnlen; ++i)
	{
	  pctx->packet.octets.base[pctx->packet.encrypted_off + i] ^=
	    hpmask[i + 1];
	}
      return;
    }

  if ((ptlen = quic_quicly_crypto_aead_decrypt (
	 qctx, aead, pctx->packet.octets.base + aead_off,
	 pctx->packet.octets.base + aead_off,
	 pctx->packet.octets.len - aead_off, pn, pctx->packet.octets.base,
	 aead_off)) == SIZE_MAX)
    {
      fprintf (stderr, "%s: aead decryption failure (pn: %d)\n", __FUNCTION__,
	       pn);
      return;
    }

  pctx->packet.encrypted_off = aead_off;
  pctx->packet.octets.len = ptlen + aead_off;

  pctx->packet.decrypted.pn = pn;
  pctx->packet.decrypted.key_phase = qctx->key_phase_ingress;
}

static void
quic_quicly_crypto_encrypt_packet (struct st_quicly_crypto_engine_t *engine,
			    quicly_conn_t *conn,
			    ptls_cipher_context_t *header_protect_ctx,
			    ptls_aead_context_t *packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced)
{
  vlib_main_t *vm = vlib_get_main ();

  struct cipher_context_t *hp_ctx =
    (struct cipher_context_t *) header_protect_ctx;
  struct aead_crypto_context_t *aead_ctx =
    (struct aead_crypto_context_t *) packet_protect_ctx;

  void *input = datagram.base + payload_from;
  void *output = input;
  size_t inlen =
    datagram.len - payload_from - packet_protect_ctx->algo->tag_size;
  const void *aad = datagram.base + first_byte_at;
  size_t aadlen = payload_from - first_byte_at;

  /* Build AEAD encrypt crypto operation */
  vnet_crypto_op_init (&aead_ctx->op, aead_ctx->id);
  aead_ctx->op.aad = (u8 *) aad;
  aead_ctx->op.aad_len = aadlen;
  aead_ctx->op.iv = aead_ctx->iv;
  ptls_aead__build_iv (aead_ctx->super.algo, aead_ctx->op.iv,
		       aead_ctx->static_iv, packet_number);
  aead_ctx->op.key_index = quic_crypto_set_key (&aead_ctx->key);
  aead_ctx->op.src = (u8 *) input;
  aead_ctx->op.dst = output;
  aead_ctx->op.len = inlen;
  aead_ctx->op.tag_len = aead_ctx->super.algo->tag_size;
  aead_ctx->op.tag = aead_ctx->op.src + inlen;
  vnet_crypto_process_ops (vm, &(aead_ctx->op), 1);
  assert (aead_ctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

  /* Build Header protection crypto operation */
  ptls_aead_supplementary_encryption_t supp = {
    .ctx = header_protect_ctx,
    .input =
      datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE
  };

  /* Build Header protection crypto operation */
  vnet_crypto_op_init (&hp_ctx->op, hp_ctx->id);
  memset (supp.output, 0, sizeof (supp.output));
  hp_ctx->op.iv = (u8 *) supp.input;
  hp_ctx->op.key_index = quic_crypto_set_key (&hp_ctx->key);
  ;
  hp_ctx->op.src = (u8 *) supp.output;
  hp_ctx->op.dst = (u8 *) supp.output;
  hp_ctx->op.len = sizeof (supp.output);
  vnet_crypto_process_ops (vm, &(hp_ctx->op), 1);
  assert (hp_ctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

  datagram.base[first_byte_at] ^=
    supp.output[0] &
    (QUICLY_PACKET_IS_LONG_HEADER (datagram.base[first_byte_at]) ? 0xf : 0x1f);
  for (size_t i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
    datagram.base[payload_from + i - QUICLY_SEND_PN_SIZE] ^=
      supp.output[i + 1];
}

static inline void
quic_quicly_update_conn_ctx (quicly_conn_t * conn, quicly_context_t * quicly_context)
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
quic_quicly_update_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  int64_t next_timeout, next_interval;
  session_t *quic_session;
  quic_main_t *qm = get_quic_main ();
  int rv;

  /*  This timeout is in ms which is the unit of our timer */
  next_timeout = quicly_get_first_timeout (ctx->conn);
  next_interval = next_timeout - quic_get_time ();

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
	    rv = session_program_tx_io_evt (quic_session->handle,
					    SESSION_IO_EVT_TX);
	    if (PREDICT_FALSE (rv))
	      QUIC_ERR ("Failed to enqueue builtin_tx %d", rv);
	  }
	return;
      }
    }

  ASSERT (vlib_get_thread_index () == ctx->c_thread_index ||
	  vlib_get_thread_index () == 0);
  tw = &qm->wrk_ctx[ctx->c_thread_index].timer_wheel;

  QUIC_DBG (4, "Timer set to %ld (int %ld) for ctx %u", next_timeout,
	    next_interval, ctx->c_c_index);

  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
      {
	QUIC_DBG (4, "timer for ctx %u already stopped", ctx->c_c_index);
	return;
      }
      ctx->timer_handle =
	tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index, 0, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
      {
	quic_stop_ctx_timer (ctx);
      }
      else
      tw_timer_update_1t_3w_1024sl_ov (tw, ctx->timer_handle, next_interval);
    }
  return;
}

static inline void
quic_quicly_set_udp_tx_evt (session_t * udp_session)
{
  int rv = 0;
  if (svm_fifo_set_event (udp_session->tx_fifo))
    rv = session_program_tx_io_evt (udp_session->handle, SESSION_IO_EVT_TX);
  if (PREDICT_FALSE (rv))
    clib_warning ("Event enqueue errored %d", rv);
}

static int
quic_quicly_send_datagram (session_t *udp_session, struct iovec *packet, ip46_address_t *dest)
{
  u32 max_enqueue, len;
  session_dgram_hdr_t hdr;
  svm_fifo_t *f;
  transport_connection_t *tc;
  int ret;
  quicly_address_t quicly_dest;

  len = packet->iov_len;
  f = udp_session->tx_fifo;
  tc = session_get_transport (udp_session);
  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue < SESSION_CONN_HDR_LEN + len)
    {
      QUIC_ERR ("Too much data to send, max_enqueue %u, len %u", max_enqueue,
		len + SESSION_CONN_HDR_LEN);
      return QUIC_ERROR_FULL_FIFO;
    }

  /*  Build packet header for fifo */
  hdr.data_length = len;
  hdr.data_offset = 0;
  hdr.is_ip4 = tc->is_ip4;
  clib_memcpy (&hdr.lcl_ip, &tc->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = tc->lcl_port;
  hdr.gso_size = 0;

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
      clib_memcpy_fast (&hdr.rmt_ip.ip6, &sa6->sin6_addr, 16);
    }

  svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
			     { packet->iov_base, len } };

  ret = svm_fifo_enqueue_segments (f, segs, 2, 0 /* allow partial */);
  if (PREDICT_FALSE (ret < 0))
    {
      QUIC_ERR ("Not enough space to enqueue dgram");
      return QUIC_ERROR_FULL_FIFO;
    }

  quic_increment_counter (QUIC_ERROR_TX_PACKETS, 1);

  return 0;
}

static void
quic_quicly_receive_connection (void *arg)
{
  u32 new_ctx_id, thread_index = vlib_get_thread_index ();
  quic_ctx_t *temp_ctx, *new_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quicly_context_t *quicly_context;
  session_t *udp_session;
  quic_main_t *qm = get_quic_main ();

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
  quicly_context = quic_quicly_get_quicly_ctx_from_ctx (new_ctx);
  quic_quicly_update_conn_ctx (conn, quicly_context);

  quic_quicly_store_conn_ctx (conn, new_ctx);
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_id;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&qm->connection_hash, &kv, 1 /* is_add */ );
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_quicly_update_timer (new_ctx);

  /*  Trigger write on this connection if necessary */
  udp_session = session_get_from_handle (new_ctx->udp_session_handle);
  udp_session->opaque = new_ctx_id;
  udp_session->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (udp_session->tx_fifo))
    quic_quicly_set_udp_tx_evt (udp_session);
}

static int
quic_quicly_reset_connection (u64 udp_session_handle, quic_rx_packet_ctx_t * pctx)
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
  quicly_ctx = quic_quicly_get_quicly_ctx_from_udp (udp_session_handle);
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

  udp_session = session_get_from_handle (udp_session_handle);
  rv = quic_quicly_send_datagram (udp_session, &packet, &qctx->rmt_ip);
  quic_quicly_set_udp_tx_evt (udp_session);
  return rv;
}

static void
quic_quicly_connection_delete (quic_ctx_t * ctx)
{
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quic_main_t *qm = get_quic_main ();

  if (ctx->conn == NULL)
    {
      QUIC_DBG (2, "Skipping redundant delete of connection %u",
		ctx->c_c_index);
      return;
    }
  QUIC_DBG (2, "Deleting connection %u", ctx->c_c_index);

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));
  quic_stop_ctx_timer (ctx);

  /*  Delete the connection from the connection map */
  conn = ctx->conn;
  ctx->conn = NULL;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  QUIC_DBG (2, "Deleting conn with id %lu %lu from map", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&qm->connection_hash, &kv, 0 /* is_add */ );

  quic_disconnect_transport (ctx);

  if (conn)
    quicly_free (conn);
  session_transport_delete_notify (&ctx->connection);
}

/**
 * Called when quicly return an error
 * This function interacts tightly with quic_quicly_proto_on_close
 */
static void
quic_quicly_connection_closed (quic_ctx_t * ctx)
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
      /* quic_quicly_proto_on_close will eventually be called when the app confirms the close
         , we delete the connection at that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED:
      /* App already confirmed close, we can delete the connection */
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_OPENED:
    case QUIC_CONN_STATE_HANDSHAKE:
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      quic_quicly_connection_delete (ctx);
      break;
    default:
      QUIC_DBG (0, "BUG %d", ctx->conn_state);
      break;
    }
}

static int
quic_quicly_sendable_packet_count (session_t * udp_session)
{
  u32 max_enqueue;
  u32 packet_size = QUIC_MAX_PACKET_SIZE + SESSION_CONN_HDR_LEN;
  max_enqueue = svm_fifo_max_enqueue (udp_session->tx_fifo);
  return clib_min (max_enqueue / packet_size, QUIC_SEND_PACKET_VEC_SIZE);
}

static int
quic_quicly_send_packets (quic_ctx_t * ctx)
{
  struct iovec packets[QUIC_SEND_PACKET_VEC_SIZE];
  uint8_t
    buf[QUIC_SEND_PACKET_VEC_SIZE * quic_quicly_get_quicly_ctx_from_ctx (ctx)
				      ->transport_params.max_udp_payload_size];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  u32 n_sent = 0;
  int err = 0;
  quicly_address_t quicly_rmt_ip, quicly_lcl_ip;
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

  quic_quicly_ip46_addr_to_quicly_addr (&ctx->rmt_ip, &quicly_rmt_ip);
  quic_quicly_ip46_addr_to_quicly_addr (&ctx->lcl_ip, &quicly_lcl_ip);
  do
    {
      /* TODO : quicly can assert it can send min_packets up to 2 */
      max_packets = quic_quicly_sendable_packet_count (udp_session);
      if (max_packets < 2)
      break;

      num_packets = max_packets;
      if ((err = quicly_send (conn, &quicly_rmt_ip, &quicly_lcl_ip, packets,
			      &num_packets, buf, sizeof (buf))))
      goto quicly_error;

      for (i = 0; i != num_packets; ++i)
      {

	if ((err = quic_quicly_send_datagram (udp_session, &packets[i], &ctx->rmt_ip)))
	  goto quicly_error;
      }
      n_sent += num_packets;
    }
  while (num_packets > 0 && num_packets == max_packets);

  quic_quicly_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));
  quic_quicly_update_timer (ctx);
  return n_sent;

quicly_error:
  if (err && err != QUICLY_ERROR_PACKET_IGNORED
      && err != QUICLY_ERROR_FREE_CONNECTION)
    clib_warning ("Quic error '%U'.", quic_format_err, err);
  quic_quicly_connection_closed (ctx);
  return 0;
}

static void
quic_quicly_proto_on_close (u32 ctx_index, u32 thread_index)
{
  int err;
  quic_ctx_t *ctx = quic_ctx_get_if_valid (ctx_index, thread_index);
  if (!ctx)
    return;
  session_t *stream_session =
    session_get (ctx->c_s_index, ctx->c_thread_index);
#if QUIC_DEBUG >= 2
  clib_warning ("Closing session 0x%lx", session_handle (stream_session));
#endif
  if (quic_ctx_is_stream (ctx))
    {
      quicly_stream_t *stream = ctx->stream;
      if (!quicly_stream_has_send_side (quicly_is_client (stream->conn),
					stream->stream_id))
      return;
      quicly_sendstate_shutdown (
	&stream->sendstate,
	ctx->bytes_written + svm_fifo_max_dequeue (stream_session->tx_fifo));
      err = quicly_stream_sync_sendbuf (stream, 1);
      if (err)
      {
	QUIC_DBG (1, "sendstate_shutdown failed for stream session %lu",
		  session_handle (stream_session));
	quicly_reset_stream (stream, QUIC_APP_ERROR_CLOSE_NOTIFY);
      }
      quic_quicly_send_packets (ctx);
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
      quic_quicly_send_packets (ctx);
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED;
      /* send_packets will eventually return an error, we delete the conn at
         that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED:
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      break;
    default:
      QUIC_ERR ("Trying to close conn in state %d", ctx->conn_state);
      break;
    }
}

/*
 * Returns 0 if a matching connection is found and is on the right thread.
 * Otherwise returns -1.
 * If a connection is found, even on the wrong thread, ctx_thread and ctx_index
 * will be set.
 */
static inline int
quic_quicly_find_packet_ctx (quic_rx_packet_ctx_t * pctx, u32 caller_thread_index)
{ 
  clib_bihash_kv_16_8_t kv;
  clib_bihash_16_8_t *h;
  quic_ctx_t *ctx;
  u32 index, thread_id;
  quic_main_t *qm = get_quic_main ();

  h = &qm->connection_hash;
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
quic_quicly_accept_connection (quic_rx_packet_ctx_t * pctx)
{
  quicly_context_t *quicly_ctx;
  session_t *quic_session;
  clib_bihash_kv_16_8_t kv;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  quic_ctx_t *lctx;
  int rv;
  quic_main_t *qm = get_quic_main ();

  /* new connection, accept and create context if packet is valid
   * TODO: check if socket is actually listening? */
  ctx = quic_ctx_get (pctx->ctx_index, pctx->thread_index);
  if (ctx->c_s_index != QUIC_SESSION_INVALID)
    {
      QUIC_DBG (2, "already accepted ctx 0x%x", ctx->c_s_index);
      return;
    }

  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  if ((rv = quicly_accept (
	 &conn, quicly_ctx, NULL, &pctx->sa, &pctx->packet, NULL,
	 &qm->wrk_ctx[pctx->thread_index].next_cid, NULL, NULL)))
    {
      /* Invalid packet, pass */
      assert (conn == NULL);
      QUIC_ERR ("Accept failed with %U", quic_format_err, rv);
      /* TODO: cleanup created quic ctx and UDP session */
      return;
    }
  assert (conn != NULL);

  ++qm->wrk_ctx[pctx->thread_index].next_cid.master_id;
  /* Save ctx handle in quicly connection */
  quic_quicly_store_conn_ctx (conn, ctx);
  ctx->conn = conn;

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2, "Allocated quic_session, 0x%lx ctx %u",
	    session_handle (quic_session), ctx->c_c_index);
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
  clib_bihash_add_del_16_8 (&qm->connection_hash, &kv, 1 /* is_add */ );
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);

  /* If notify fails, reset connection immediatly */
  if ((rv = app_worker_init_accepted (quic_session)))
    {
      QUIC_ERR ("failed to allocate fifos");
      quic_quicly_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  svm_fifo_init_ooo_lookup (quic_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (quic_session->tx_fifo, 1 /* ooo deq */);

  app_wrk = app_worker_get (quic_session->app_wrk_index);
  quic_session->session_state = SESSION_STATE_ACCEPTING;
  if ((rv = app_worker_accept_notify (app_wrk, quic_session)))
    {
      QUIC_ERR ("failed to notify accept worker app");
      quic_quicly_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  ctx->conn_state = QUIC_CONN_STATE_READY;
}

static int
quic_quicly_process_one_rx_packet (u64 udp_session_handle, svm_fifo_t *f,
			    u32 fifo_offset, quic_rx_packet_ctx_t *pctx)
{
  size_t plen;
  u32 full_len, ret;
  u32 thread_index = vlib_get_thread_index ();
  u32 cur_deq = svm_fifo_max_dequeue (f) - fifo_offset;
  quicly_context_t *quicly_ctx;
  session_t *udp_session;
  int rv;
  quic_main_t *qm = get_quic_main ();

  ret = svm_fifo_peek (f, fifo_offset, SESSION_CONN_HDR_LEN, (u8 *) &pctx->ph);
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
  quicly_ctx = quic_quicly_get_quicly_ctx_from_udp (udp_session_handle);

  size_t off = 0;
  plen = quicly_decode_packet (quicly_ctx, &pctx->packet, pctx->data,
			       pctx->ph.data_length, &off);

  if (plen == SIZE_MAX)
    {
      return 1;
    }

  rv = quic_quicly_find_packet_ctx (pctx, thread_index);
  if (rv == QUIC_PACKET_TYPE_RECEIVE)
    {
      pctx->ptype = QUIC_PACKET_TYPE_RECEIVE;

      if (qm->vnet_crypto_enabled &&
	  qm->default_crypto_engine == CRYPTO_ENGINE_VPP)
      {
	quic_ctx_t *qctx = quic_ctx_get (pctx->ctx_index, thread_index);
	quic_quicly_crypto_decrypt_packet (qctx, pctx);
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
quic_quicly_connect (quic_ctx_t * ctx, u32 ctx_index, u32 thread_index, struct sockaddr *sa)
{
  clib_bihash_kv_16_8_t kv;
  quicly_context_t *quicly_ctx;
  quicly_conn_t *conn;
  quic_main_t *qm = get_quic_main();
  int ret;

  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  conn = ctx->conn;
  ret = quicly_connect (&conn, quicly_ctx, (char *) ctx->srv_hostname, sa,
			NULL, &qm->wrk_ctx[thread_index].next_cid,
			ptls_iovec_init (NULL, 0), &qm->hs_properties,
			NULL, NULL);
  ++qm->wrk_ctx[thread_index].next_cid.master_id;
  /*  save context handle in quicly connection */
  quic_quicly_store_conn_ctx (conn, ctx);
  assert (ret == 0);
  
  /*  Register connection in connections map */
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&qm->connection_hash, &kv, 1 /* is_add */ );
  
  return (ret);
}

static u8 *
quic_quicly_format_quicly_conn_id (u8 * s, va_list * args)
{
  quicly_cid_plaintext_t *mid = va_arg (*args, quicly_cid_plaintext_t *);
  s = format (s, "C%x_%x", mid->master_id, mid->thread_id);
  return s;
}

static u8 *
quic_quicly_format_stream_ctx_stream_id (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;
  
  s = format (s, "%U S%lx", quic_quicly_format_quicly_conn_id,
	      quicly_get_master_id (stream->conn), stream->stream_id);
  return s;
}

static u8 *
quic_quicly_format_stream_connection (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;
  
  s = format (s, "Stream %ld conn %d", stream->stream_id,
		  ctx->quic_connection_ctx_id);
  return s;
}

static u8 *
quic_quicly_format_connection_stats (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stats_t quicly_stats;

  s = format (s, "[%U]", quic_quicly_format_quicly_conn_id,
	      quicly_get_master_id (ctx->conn));

  quicly_get_stats (ctx->conn, &quicly_stats);

  s = format (s, "[RTT >%3d, ~%3d, V%3d, last %3d]", quicly_stats.rtt.minimum,
	      quicly_stats.rtt.smoothed, quicly_stats.rtt.variance,
	      quicly_stats.rtt.latest);
  s = format (s, " TX:%d RX:%d loss:%d ack:%d", quicly_stats.num_packets.sent,
	      quicly_stats.num_packets.received, quicly_stats.num_packets.lost,
	      quicly_stats.num_packets.ack_received);
  s =
    format (s, "\ncwnd:%u ssthresh:%u recovery_end:%lu", quicly_stats.cc.cwnd,
	    quicly_stats.cc.ssthresh, quicly_stats.cc.recovery_end);

  quicly_context_t *quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  if (quicly_ctx->init_cc == &quicly_cc_cubic_init)
    {
      s = format (
	s,
	"\nk:%d w_max:%u w_last_max:%u avoidance_start:%ld last_sent_time:%ld",
	quicly_stats.cc.state.cubic.k, quicly_stats.cc.state.cubic.w_max,
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

static_always_inline int
quic_quicly_receive_a_packet (quic_ctx_t *ctx, quic_rx_packet_ctx_t *pctx)
{
  int rv = quicly_receive (ctx->conn, NULL, &pctx->sa, &pctx->packet);
  if (rv && rv != QUICLY_ERROR_PACKET_IGNORED)
  {
    QUIC_ERR ("quicly_receive return error %U", quic_format_err, rv);
  }

  return rv;
}

static_always_inline int
quic_quicly_connect_stream (void * quic_conn, void ** quic_stream, quic_stream_data_t ** quic_stream_data, u8 is_unidir)
{
  quicly_conn_t *conn = quic_conn;
  quicly_stream_t *quicly_stream;

  if (!quicly_connection_is_ready (conn))
    return -1;

  if (quicly_open_stream (conn, (quicly_stream_t **)quic_stream, is_unidir))
    {
      QUIC_DBG (2, "quicly_open_stream() failed with %d", rv);
      return -1;
    }

  quicly_stream = *(quicly_stream_t **)quic_stream;
  *quic_stream_data = (quic_stream_data_t *) quicly_stream->data;

  QUIC_DBG (2, "Opened quicly_stream %d, creating session", quicly_stream->stream_id);

  return 0;
}

static_always_inline void
quic_quicly_reset_stream (void * quic_stream, int error)
{
  quicly_reset_stream ((quicly_stream_t *) quic_stream, error);
}

static_always_inline quic_session_connected_t
quic_quicly_is_session_connected (quic_ctx_t * ctx)
{
  quic_session_connected_t session_connected = QUIC_SESSION_CONNECTED_NONE;

  if (quicly_connection_is_ready (ctx->conn))
  {
    session_connected = quicly_is_client (ctx->conn) ?
      QUIC_SESSION_CONNECTED_CLIENT : QUIC_SESSION_CONNECTED_SERVER;
  }

  return (session_connected);
}

static_always_inline int
quic_quicly_stream_tx (quic_ctx_t * ctx, session_t * stream_session)
{
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  u32 max_deq;
  int rv = 0;

  stream = ctx->stream;
  if (!quicly_sendstate_is_open (&stream->sendstate))
    {
      QUIC_ERR ("Warning: tried to send on closed stream");
      return 0;
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

  return (rv);
}

const static quic_lib_vft_t quic_quicly_vft = {
  .init_crypto_context = quic_quicly_init_crypto_context,
  .crypto_context_make_key_from_crctx = quic_quicly_crypto_context_make_key_from_crctx,
  .crypto_decrypt_packet = quic_quicly_crypto_decrypt_packet,
  .crypto_encrypt_packet = quic_quicly_crypto_encrypt_packet,
  .accept_connection = quic_quicly_accept_connection,
  .receive_connection = quic_quicly_receive_connection,
  .reset_connection = quic_quicly_reset_connection,
  .connection_delete = quic_quicly_connection_delete,
  .format_connection_stats = quic_quicly_format_connection_stats,
  .format_stream_ctx_stream_id = quic_quicly_format_stream_ctx_stream_id,
  .format_stream_connection = quic_quicly_format_stream_connection,
  .connect = quic_quicly_connect,
  .connect_stream = quic_quicly_connect_stream,
  .stream_tx = quic_quicly_stream_tx,
  .is_session_connected = quic_quicly_is_session_connected,
  .reset_stream = quic_quicly_reset_stream,
  .ack_rx_data = quic_quicly_ack_rx_data,
  .store_conn_ctx = quic_quicly_store_conn_ctx,
  .send_packets = quic_quicly_send_packets,
  .process_one_rx_packet = quic_quicly_process_one_rx_packet,
  .receive_a_packet = quic_quicly_receive_a_packet,
};

extern void quic_lib_register (const quic_lib_vft_t *ql_vft,
			       quic_lib_type_t lib_type);
static clib_error_t *
quic_quicly_init (vlib_main_t *vm)
{
  // vlib_thread_main_t *vtm = vlib_get_thread_main ();
  // u32 num_threads;

  // num_threads = 1 /* main thread */  + vtm->n_threads;

  quic_lib_register (&quic_quicly_vft, QUIC_LIB_QUICLY);
  return 0;
}

VLIB_INIT_FUNCTION (quic_quicly_init) = {
  .runs_after = VLIB_INITS ("quic_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "QUIC library, quicly",
};
