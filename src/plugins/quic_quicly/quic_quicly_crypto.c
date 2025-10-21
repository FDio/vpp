/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly.h>
#include <quic_quicly/quic_quicly_error.h>
#include <quic_quicly/quic_quicly_crypto.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>

#include <quic/quic_timer.h>
#include <quicly.h>
#include <picotls/openssl.h>
#include <pthread.h>

#define QUICLY_EPOCH_1RTT 3

vnet_crypto_main_t *cm = &crypto_main;

static_always_inline void
quic_quicly_crypto_context_make_key_from_ctx (clib_bihash_kv_24_8_t *kv,
					      quic_ctx_t *ctx)
{
  application_t *app = application_get (ctx->parent_app_id);
  kv->key[0] = ((u64) ctx->ckpair_index) << 32 | (u64) ctx->crypto_engine;
  kv->key[1] = app->sm_properties.rx_fifo_size - 1;
  kv->key[2] = app->sm_properties.tx_fifo_size - 1;
}

void
quic_quicly_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
						crypto_context_t *crctx)
{
  quic_quicly_crypto_context_data_t *data =
    (quic_quicly_crypto_context_data_t *) crctx->data;
  kv->key[0] = ((u64) crctx->ckpair_index) << 32 | (u64) crctx->crypto_engine;
  kv->key[1] = data->quicly_ctx.transport_params.max_stream_data.bidi_local;
  kv->key[2] = data->quicly_ctx.transport_params.max_stream_data.bidi_remote;
}

int
quic_quicly_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair)
{
  quic_main_t *qm = quic_quicly_main.qm;
  clib_bihash_24_8_t *crctx_hash = quic_quicly_main.crypto_ctx_hash;
  crypto_context_t *crctx;
  clib_bihash_kv_24_8_t kv;
  int i;

  for (i = 0; i < qm->num_threads; i++)
    {
      pool_foreach (crctx, quic_wrk_ctx_get (qm, i)->crypto_ctx_pool)
	{
	  if (crctx->ckpair_index == ckpair->cert_key_index)
	    {
	      quic_quicly_crypto_context_make_key_from_crctx (&kv, crctx);
	      clib_bihash_add_del_24_8 (&crctx_hash[i], &kv, 0 /* is_add */);
	    }
	}
    }
  return 0;
}

static crypto_context_t *
quic_quicly_crypto_context_alloc (u8 thread_index)
{
  quic_worker_ctx_t *wc = quic_wrk_ctx_get (quic_quicly_main.qm, thread_index);
  crypto_context_t *crctx;
  u32 idx;

  pool_get_aligned_safe (wc->crypto_ctx_pool, crctx, CLIB_CACHE_LINE_BYTES);
  clib_memset (crctx, 0, sizeof (*crctx));
  idx = (crctx - wc->crypto_ctx_pool);
  crctx->ctx_index = QUIC_CRCTX_CTX_INDEX_ENCODE (thread_index, idx);
  QUIC_DBG (2, "Allocated crctx: crctx_ndx 0x%08lx, index %u, thread %u",
	    crctx->ctx_index, idx, thread_index);

  return crctx;
}

static void
quic_quicly_crypto_context_free_if_needed (crypto_context_t *crctx,
					   u8 thread_index)
{
  clib_bihash_24_8_t *crctx_hash = quic_quicly_main.crypto_ctx_hash;
  clib_bihash_kv_24_8_t kv;
  if (crctx->n_subscribers)
    return;
  quic_quicly_crypto_context_make_key_from_crctx (&kv, crctx);
  clib_bihash_add_del_24_8 (&crctx_hash[thread_index], &kv, 0 /* is_add */);
  clib_mem_free (crctx->data);
  pool_put (
    quic_wrk_ctx_get (quic_quicly_main.qm, thread_index)->crypto_ctx_pool,
    crctx);
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
  stream->callbacks = &quic_quicly_stream_callbacks;
  /* Notify accept on parent qsession, but only if this is not a locally
   * initiated stream */
  if (quicly_stream_is_self_initiated (stream))
    {
      QUIC_DBG (2, "Nothing to do on locally initiated stream");
      return 0;
    }

  sctx_id = quic_ctx_alloc (quic_quicly_main.qm, vlib_get_thread_index ());
  qctx = quic_quicly_get_conn_ctx (stream->conn);

  /* Might need to signal that the connection is ready if the first thing the
   * server does is open a stream */
  quic_quicly_check_quic_session_connected (qctx);
  /* ctx might be invalidated */
  qctx = quic_quicly_get_conn_ctx (stream->conn);
  QUIC_DBG (2, "qctx->c_s_index %u, qctx->c_c_index %u", qctx->c_s_index,
	    qctx->c_c_index);

  if (qctx->c_s_index == QUIC_SESSION_INVALID)
    {
      QUIC_DBG (2, "Invalid session index on quic c_index %u",
		qctx->c_c_index);
      return 0;
    }
  stream_session = session_alloc (qctx->c_thread_index);
  stream_session->flags |= SESSION_F_STREAM;
  QUIC_DBG (2, "ACCEPTED stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_id);
  sctx = quic_quicly_get_quic_ctx (sctx_id, qctx->c_thread_index);
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
      quicly_reset_stream (stream, QUIC_QUICLY_APP_ALLOCATION_ERROR);
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
      quicly_reset_stream (stream, QUIC_QUICLY_APP_ACCEPT_NOTIFY_ERROR);
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
  if (ctx->c_s_index == QUIC_SESSION_INVALID)
    {
      clib_warning ("Unopened Session closed by peer: error %U, reason %U, "
		    "ctx_index %u, thread %u",
		    quic_quicly_format_err, code, format_ascii_bytes, reason,
		    reason_len, ctx->c_c_index, ctx->c_thread_index);
    }
  else
    {
      session_t *quic_session =
	session_get (ctx->c_s_index, ctx->c_thread_index);
      clib_warning ("Session closed by peer: session 0x%lx, error %U, reason "
		    "%U, ctx_index %u, thread %u",
		    session_handle (quic_session), quic_quicly_format_err,
		    code, format_ascii_bytes, reason, reason_len,
		    ctx->c_c_index, ctx->c_thread_index);
    }
#endif
  if (ctx->conn_state == QUIC_CONN_STATE_HANDSHAKE)
    {
      QUIC_DBG (2, "Handshake failed: ctx_index %u, thread %u", ctx->c_c_index,
		ctx->c_thread_index);
      return;
    }
  ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING;
  if (ctx->c_s_index != QUIC_SESSION_INVALID)
    {
      session_transport_closing_notify (&ctx->connection);
    }
}

static int64_t
quic_quicly_get_time (quicly_now_t *self)
{
  return (int64_t) quic_wrk_ctx_get (quic_quicly_main.qm,
				     vlib_get_thread_index ())
    ->time_now;
}

static quicly_stream_open_t on_stream_open = { quic_quicly_on_stream_open };
static quicly_closed_by_remote_t on_closed_by_remote = {
  quic_quicly_on_closed_by_remote
};
static quicly_now_t quicly_vpp_now_cb = { quic_quicly_get_time };

static int
quic_quicly_on_client_hello_ptls (ptls_on_client_hello_t *self, ptls_t *tls,
				  ptls_on_client_hello_parameters_t *params)
{
  quic_quicly_on_client_hello_t *ch_ctx =
    (quic_quicly_on_client_hello_t *) self;
  quic_ctx_t *lctx;
  const tls_alpn_proto_id_t *alpn_proto;
  int i, j, ret;

  lctx = quic_quicly_get_quic_ctx (ch_ctx->lctx_index, 0);

  /* handle ALPN, both sides need to offer something */
  if (params->negotiated_protocols.count && lctx->alpn_protos[0])
    {
      for (i = 0; i < sizeof (lctx->alpn_protos) && lctx->alpn_protos[i]; i++)
	{
	  alpn_proto = &tls_alpn_proto_ids[lctx->alpn_protos[i]];
	  for (j = 0; j < params->negotiated_protocols.count; j++)
	    {
	      if (alpn_proto->len != params->negotiated_protocols.list[j].len)
		continue;
	      if (!memcmp (alpn_proto->base,
			   params->negotiated_protocols.list[j].base,
			   alpn_proto->len))
		goto alpn_proto_match;
	    }
	}
#if QUIC_DEBUG >= 2
      u8 *client_alpn_list = 0;
      for (j = 0; j < params->negotiated_protocols.count; j++)
	{
	  if (j > 0)
	    vec_add (client_alpn_list, ", ", 2);
	  vec_add (client_alpn_list, params->negotiated_protocols.list[j].base,
		   params->negotiated_protocols.list[j].len);
	}
      clib_warning (
	"unsupported alpn proto(s) requested by client: proto [%U], "
	"ctx_index %u, thread %u",
	format_ascii_bytes, client_alpn_list,
	(uword) vec_len (client_alpn_list), lctx->c_c_index,
	lctx->c_thread_index);
#endif
      return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    alpn_proto_match:
      if ((ret = ptls_set_negotiated_protocol (tls, (char *) alpn_proto->base,
					       alpn_proto->len)) != 0)
	{
	  QUIC_ERR ("ptls_set_negotiated_protocol failed: error %d, ctx_index "
		    "%u, thread %u",
		    ret, lctx->c_c_index, lctx->c_thread_index);
	  return ret;
	}
      QUIC_DBG (2, "alpn proto selected %U, ctx_index %u, thread %u",
		format_ascii_bytes, alpn_proto->base, (uword) alpn_proto->len,
		lctx->c_c_index, lctx->c_thread_index);
    }
  return 0;
}

static int
quic_quicly_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  app_cert_key_pair_t *ckpair;
  application_t *app;
  quic_quicly_crypto_context_data_t *data;
  ptls_context_t *ptls_ctx;

  ASSERT (QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (crctx->ctx_index) ==
	  ctx->c_thread_index);
  ASSERT (QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (crctx->ctx_index) ==
	  vlib_get_thread_index ());
  QUIC_DBG (2, "Init crctx: crctx_ndx 0x%08lx, thread %d", crctx->ctx_index,
	    ctx->c_thread_index);

  if (PREDICT_FALSE (!qm->vnet_crypto_init))
    {
      qm->vnet_crypto_init = 1;
      if ((vec_len (cm->engines) == 0) ||
	  (qm->default_crypto_engine == CRYPTO_ENGINE_PICOTLS))
	{
	  qqm->vnet_crypto_enabled = 0;
	  (void) quic_quicly_register_cipher_suite (
	    CRYPTO_ENGINE_PICOTLS, ptls_openssl_cipher_suites);
	}
      else
	{
	  qqm->vnet_crypto_enabled = 1;
	  if (quic_quicly_register_cipher_suite (
		CRYPTO_ENGINE_VPP, quic_quicly_crypto_cipher_suites))
	    {
	      u8 empty_key[32] = {};
	      u32 i;
	      qm->default_crypto_engine = ctx->crypto_engine =
		CRYPTO_ENGINE_VPP;
	      vec_validate (qqm->per_thread_crypto_key_indices,
			    qm->num_threads);
	      for (i = 0; i < qm->num_threads; i++)
		{
		  qqm->per_thread_crypto_key_indices[i] = vnet_crypto_key_add (
		    vlib_get_main (), VNET_CRYPTO_ALG_AES_256_CTR, empty_key,
		    32);
		}
	    }
	}

  /* TODO: Remove this and clean up legacy provider code in quicly */
  quic_quicly_load_openssl3_legacy_provider ();
    }

  data = clib_mem_alloc (sizeof (*data));
  /* picotls depends on data being zeroed */
  clib_memset (data, 0, sizeof (*data));
  crctx->data = (void *) data;
  quicly_ctx = &data->quicly_ctx;
  ptls_ctx = &data->ptls_ctx;

  data->client_hello_ctx.super.cb = quic_quicly_on_client_hello_ptls;
  data->client_hello_ctx.lctx_index = ctx->listener_ctx_id;

  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->get_time = &ptls_get_time;
  ptls_ctx->key_exchanges = ptls_openssl_key_exchanges;
  ptls_ctx->cipher_suites = qqm->quic_ciphers[ctx->crypto_engine];
  QUIC_DBG (2, "Init crctx: engine_type %U (%u), cipher_suites %p",
	    format_crypto_engine, ctx->crypto_engine, ctx->crypto_engine,
	    ptls_ctx->cipher_suites);
  ptls_ctx->certificates.list = NULL;
  ptls_ctx->certificates.count = 0;
  ptls_ctx->on_client_hello = &data->client_hello_ctx.super;
  ptls_ctx->emit_certificate = NULL;
  ptls_ctx->sign_certificate = NULL;
  ptls_ctx->verify_certificate = NULL;
  ptls_ctx->ticket_lifetime = 86400;
  ptls_ctx->max_early_data_size = 8192;
  ptls_ctx->hkdf_label_prefix__obsolete = NULL;
  ptls_ctx->require_dhe_on_psk = 1;
  ptls_ctx->encrypt_ticket = &qqm->session_cache.super;
  clib_memcpy (quicly_ctx, &quicly_spec_context, sizeof (quicly_context_t));

  quicly_ctx->max_packets_per_key = qm->max_packets_per_key;
  quicly_ctx->tls = ptls_ctx;
  quicly_ctx->stream_open = &on_stream_open;
  quicly_ctx->closed_by_remote = &on_closed_by_remote;
  quicly_ctx->now = &quicly_vpp_now_cb;
  quicly_amend_ptls_context (quicly_ctx->tls);

  if (qqm->vnet_crypto_enabled && ctx->crypto_engine == CRYPTO_ENGINE_VPP)
    {
  QUIC_DBG (2, "Init crctx: crypto engine vpp, crctx_ndx 0x%08lx, thread %d",
	    crctx->ctx_index, ctx->c_thread_index);
  quicly_ctx->crypto_engine = &quic_quicly_crypto_engine;
    }
  else
    {
  QUIC_DBG (2,
	    "Init crctx: crypto engine quicly, crctx_ndx 0x%08lx, thread %d",
	    crctx->ctx_index, ctx->c_thread_index);
  quicly_ctx->crypto_engine = &quicly_default_crypto_engine;
    }

  quicly_ctx->transport_params.max_data = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_streams_uni = (uint64_t) 1 << 60;
  quicly_ctx->transport_params.max_streams_bidi = (uint64_t) 1 << 60;
  quicly_ctx->transport_params.max_idle_timeout = qm->connection_timeout;

  quicly_ctx->init_cc = (qm->default_quic_cc == QUIC_CC_CUBIC) ?
			  &quicly_cc_cubic_init :
			  &quicly_cc_reno_init;

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

void
quic_quicly_crypto_context_release (u32 crctx_ndx, u8 thread_index)
{
  crypto_context_t *crctx;
  QUIC_DBG (3, "crctx_ndx 0x%x (%u), thread %u", crctx_ndx, crctx_ndx,
	    thread_index);
  crctx = quic_quicly_crypto_context_get (crctx_ndx, thread_index);
  crctx->n_subscribers--;
  quic_quicly_crypto_context_free_if_needed (crctx, thread_index);
}

int
quic_quicly_crypto_context_acquire (quic_ctx_t *ctx)
{
  /* import from src/vnet/session/application.c */
  extern u8 *format_crypto_engine (u8 * s, va_list * args);

  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;
  clib_bihash_24_8_t *crctx_hash = qqm->crypto_ctx_hash;
  crypto_context_t *crctx;
  clib_bihash_kv_24_8_t kv;

  ctx->crypto_engine = (ctx->crypto_engine == CRYPTO_ENGINE_NONE) ?
			 qm->default_crypto_engine :
			 ctx->crypto_engine;
  /* Check for exisiting crypto ctx */
  quic_quicly_crypto_context_make_key_from_ctx (&kv, ctx);
  if (clib_bihash_search_24_8 (&crctx_hash[ctx->c_thread_index], &kv, &kv) ==
      0)
    {
      crctx = quic_quicly_crypto_context_get (kv.value, ctx->c_thread_index);
      QUIC_DBG (
	2, "Found existing crypto context: crctx_ndx 0x%lx (%d), thread %u",
	kv.value, kv.value, ctx->c_thread_index);
      ctx->crypto_context_index = kv.value;
      crctx->n_subscribers++;
      return 0;
    }

  crctx = quic_quicly_crypto_context_alloc (ctx->c_thread_index);
  ctx->crypto_context_index = crctx->ctx_index;
  kv.value = crctx->ctx_index;
  crctx->crypto_engine = ctx->crypto_engine;
  crctx->ckpair_index = ctx->ckpair_index;
  if (quic_quicly_init_crypto_context (crctx, ctx))
    goto error;
  if (vnet_app_add_cert_key_interest (ctx->ckpair_index, qm->app_index))
    goto error;
  crctx->n_subscribers++;
  clib_bihash_add_del_24_8 (&crctx_hash[ctx->c_thread_index], &kv,
			    1 /* is_add */);
  return 0;

error:
  quic_quicly_crypto_context_free_if_needed (crctx, ctx->c_thread_index);
  return SESSION_E_NOCRYPTOCKP;
}

static int
quic_quicly_crypto_setup_cipher (quicly_crypto_engine_t *engine,
				 quicly_conn_t *conn, size_t epoch, int is_enc,
				 ptls_cipher_context_t **header_protect_ctx,
				 ptls_aead_context_t **packet_protect_ctx,
				 ptls_aead_algorithm_t *aead,
				 ptls_hash_algorithm_t *hash,
				 const void *secret)
{
  uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
  int ret;

  *packet_protect_ctx = NULL;
  /* generate new header protection key */
  if (header_protect_ctx != NULL)
    {
      *header_protect_ctx = NULL;
      ret =
	ptls_hkdf_expand_label (hash, hpkey, aead->ctr_cipher->key_size,
				ptls_iovec_init (secret, hash->digest_size),
				"quic hp", ptls_iovec_init (NULL, 0), NULL);
      if (ret)
	goto Exit;
      *header_protect_ctx = ptls_cipher_new (aead->ctr_cipher, is_enc, hpkey);
      if (NULL == *header_protect_ctx)
	{
	  ret = PTLS_ERROR_NO_MEMORY;
	  goto Exit;
	}
    }

  /* generate new AEAD context */
  *packet_protect_ctx =
    ptls_aead_new (aead, hash, is_enc, secret, QUICLY_AEAD_BASE_LABEL);
  if (NULL == *packet_protect_ctx)
    {
      ret = PTLS_ERROR_NO_MEMORY;
      goto Exit;
    }

  if (epoch == QUICLY_EPOCH_1RTT && !is_enc)
    {
      quic_ctx_t *qctx = quic_quicly_get_conn_ctx (conn);
      if (qctx->ingress_keys.aead_ctx != NULL)
	qctx->key_phase_ingress++;

      qctx->ingress_keys.aead_ctx = (void *) *packet_protect_ctx;
      if (header_protect_ctx != NULL)
	{
	  qctx->ingress_keys.hp_ctx = (void *) *header_protect_ctx;
	}
    }

  ret = 0;

Exit:
  if (ret)
    {
      if (*packet_protect_ctx != NULL)
	{
	  ptls_aead_free (*packet_protect_ctx);
	  *packet_protect_ctx = NULL;
	}
      if (header_protect_ctx && *header_protect_ctx != NULL)
	{
	  ptls_cipher_free (*header_protect_ctx);
	  *header_protect_ctx = NULL;
	}
    }
  ptls_clear_memory (hpkey, sizeof (hpkey));
  return ret;
}

static u32
quic_quicly_crypto_set_key (crypto_key_t *key)
{
  u8 thread_index = vlib_get_thread_index ();
  quic_quicly_main_t *qqm = &quic_quicly_main;
  u32 key_id = qqm->per_thread_crypto_key_indices[thread_index];
  vnet_crypto_key_t *vnet_key = vnet_crypto_get_key (key_id);
  vnet_crypto_engine_t *engine;

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_DEL, key_id);

  ASSERT (key->algo);
  ASSERT (key->key_len);
  vnet_key->alg = key->algo;
  clib_memcpy (vnet_key->data, key->key, key->key_len);

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_ADD, key_id);

  return key_id;
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
  struct aead_crypto_context_t *aead_crctx =
    (struct aead_crypto_context_t *) packet_protect_ctx;

  void *input = datagram.base + payload_from;
  void *output = input;
  size_t inlen =
    datagram.len - payload_from - packet_protect_ctx->algo->tag_size;
  const void *aad = datagram.base + first_byte_at;
  size_t aadlen = payload_from - first_byte_at;

  /* Build AEAD encrypt crypto operation */
  vnet_crypto_op_init (&aead_crctx->op, aead_crctx->id);
  aead_crctx->op.aad = (u8 *) aad;
  aead_crctx->op.aad_len = aadlen;
  aead_crctx->op.iv = aead_crctx->iv;
  ptls_aead__build_iv (aead_crctx->super.algo, aead_crctx->op.iv,
		       aead_crctx->static_iv, packet_number);
  QUIC_DBG (
    3, "id %u, key %p, algo %u, key_len %u, key 0x%llx 0x%llx 0x%llx 0x%llx ",
    aead_crctx->id, &aead_crctx->key, aead_crctx->key.algo,
    aead_crctx->key.key_len, *(u64 *) &aead_crctx->key.key[0],
    *(u64 *) &aead_crctx->key.key[8], *(u64 *) &aead_crctx->key.key[16],
    *(u64 *) &aead_crctx->key.key[24]);
  aead_crctx->op.key_index = quic_quicly_crypto_set_key (&aead_crctx->key);
  aead_crctx->op.src = (u8 *) input;
  aead_crctx->op.dst = output;
  aead_crctx->op.len = inlen;
  aead_crctx->op.tag_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag = aead_crctx->op.src + inlen;
  vnet_crypto_process_ops (vm, &(aead_crctx->op), 1);
  assert (aead_crctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

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
  hp_ctx->op.key_index = quic_quicly_crypto_set_key (&hp_ctx->key);
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

static size_t
quic_quicly_crypto_aead_decrypt (quic_ctx_t *qctx, ptls_aead_context_t *_ctx,
				 void *_output, const void *input,
				 size_t inlen, uint64_t decrypted_pn,
				 const void *aad, size_t aadlen)
{
  vlib_main_t *vm = vlib_get_main ();

  struct aead_crypto_context_t *aead_crctx =
    (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_op_init (&aead_crctx->op, aead_crctx->id);
  aead_crctx->op.aad = (u8 *) aad;
  aead_crctx->op.aad_len = aadlen;
  aead_crctx->op.iv = aead_crctx->iv;
  ptls_aead__build_iv (aead_crctx->super.algo, aead_crctx->op.iv,
		       aead_crctx->static_iv, decrypted_pn);
  aead_crctx->op.src = (u8 *) input;
  aead_crctx->op.dst = _output;
  QUIC_DBG (
    3, "id %u, key %p, algo %u, key_len %u, key 0x%llx 0x%llx 0x%llx 0x%llx ",
    aead_crctx->id, &aead_crctx->key, aead_crctx->key.algo,
    aead_crctx->key.key_len, *(u64 *) &aead_crctx->key.key[0],
    *(u64 *) &aead_crctx->key.key[8], *(u64 *) &aead_crctx->key.key[16],
    *(u64 *) &aead_crctx->key.key[24]);
  aead_crctx->op.key_index = quic_quicly_crypto_set_key (&aead_crctx->key);
  aead_crctx->op.len = inlen - aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag = aead_crctx->op.src + aead_crctx->op.len;

  vnet_crypto_process_ops (vm, &(aead_crctx->op), 1);

  return aead_crctx->op.len;
}

void
quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx,
				   quic_quicly_rx_packet_ctx_t *pctx)
{
  ptls_cipher_context_t *header_protection = NULL;
  ptls_aead_context_t *ptls_aead_ctx = NULL;
  int pn;

  /* Long Header packets are not decrypted by vpp */
  if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
    return;

  uint64_t next_expected_packet_number =
    quicly_get_next_expected_packet_number (qctx->conn);
  if (next_expected_packet_number == UINT64_MAX)
    return;

  ptls_aead_ctx = (ptls_aead_context_t *) qctx->ingress_keys.aead_ctx;
  header_protection = (ptls_cipher_context_t *) qctx->ingress_keys.hp_ctx;

  if (!ptls_aead_ctx || !header_protection)
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
	 qctx, ptls_aead_ctx, pctx->packet.octets.base + aead_off,
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

static int
quic_quicly_crypto_cipher_setup_crypto (ptls_cipher_context_t *_ctx,
					int is_enc, const void *key,
					const EVP_CIPHER *cipher)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_CTR;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_128_CTR_ENC :
			 VNET_CRYPTO_OP_AES_128_CTR_DEC;
      ptls_openssl_aes128ctr.setup_crypto (_ctx, is_enc, key);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_CTR;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_256_CTR_ENC :
			 VNET_CRYPTO_OP_AES_256_CTR_DEC;
      ptls_openssl_aes256ctr.setup_crypto (_ctx, is_enc, key);
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __func__, _ctx->algo->name);
      assert (0);
    }

  if (qqm->vnet_crypto_enabled)
    {
      ctx->key.algo = algo;
      ctx->key.key_len = _ctx->algo->key_size;
      assert (ctx->key.key_len <= 32);
      clib_memcpy (&ctx->key.key, key, ctx->key.key_len);
    }

  QUIC_DBG (
    2, "id %u, key %p, algo %u, key_len %u, key 0x%llx 0x%llx 0x%llx 0x%llx ",
    ctx->id, &ctx->key, ctx->key.algo, ctx->key.key_len,
    *(u64 *) &ctx->key.key[0], *(u64 *) &ctx->key.key[8],
    *(u64 *) &ctx->key.key[16], *(u64 *) &ctx->key.key[24]);
  return 0;
}

static int
quic_quicly_crypto_aes128ctr_setup_crypto (ptls_cipher_context_t *ctx,
					   int is_enc, const void *key)
{
  return quic_quicly_crypto_cipher_setup_crypto (ctx, 1, key,
						 EVP_aes_128_ctr ());
}

static int
quic_quicly_crypto_aes256ctr_setup_crypto (ptls_cipher_context_t *ctx,
					   int is_enc, const void *key)
{
  return quic_quicly_crypto_cipher_setup_crypto (ctx, 1, key,
						 EVP_aes_256_ctr ());
}

static int
quic_quicly_crypto_aead_setup_crypto (ptls_aead_context_t *_ctx, int is_enc,
				      const void *key, const void *iv,
				      const EVP_CIPHER *cipher)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_GCM;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_128_GCM_ENC :
			 VNET_CRYPTO_OP_AES_128_GCM_DEC;
      ptls_openssl_aes128gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_GCM;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_256_GCM_ENC :
			 VNET_CRYPTO_OP_AES_256_GCM_DEC;
      ptls_openssl_aes256gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else
    {
      QUIC_DBG (1, "%s, invalied aead cipher %s", __func__, _ctx->algo->name);
      assert (0);
    }

  if (qqm->vnet_crypto_enabled)
    {
      clib_memcpy (ctx->static_iv, iv, ctx->super.algo->iv_size);
      ctx->key.algo = algo;
      ctx->key.key_len = _ctx->algo->key_size;
      assert (ctx->key.key_len <= 32);
      clib_memcpy (&ctx->key.key, key, ctx->key.key_len);
    }

  QUIC_DBG (
    3, "id %u, key %p, algo %u, key_len %u, key 0x%llx 0x%llx 0x%llx 0x%llx ",
    ctx->id, &ctx->key, ctx->key.algo, ctx->key.key_len,
    *(u64 *) &ctx->key.key[0], *(u64 *) &ctx->key.key[8],
    *(u64 *) &ctx->key.key[16], *(u64 *) &ctx->key.key[24]);
  return 0;
}

static int
quic_quicly_crypto_aead_aes128gcm_setup_crypto (ptls_aead_context_t *ctx,
						int is_enc, const void *key,
						const void *iv)
{
  return quic_quicly_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					       EVP_aes_128_gcm ());
}

static int
quic_quicly_crypto_aead_aes256gcm_setup_crypto (ptls_aead_context_t *ctx,
						int is_enc, const void *key,
						const void *iv)
{
  return quic_quicly_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					       EVP_aes_256_gcm ());
}

int
quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self, ptls_t *tls,
			       int is_encrypt, ptls_buffer_t *dst,
			       ptls_iovec_t src)
{
  quic_quicly_session_cache_t *self = (void *) _self;
  int ret;

  if (is_encrypt)
    {

      /* replace the cached entry along with a newly generated session id */
      clib_mem_free (self->data.base);
      if ((self->data.base = clib_mem_alloc (src.len)) == NULL)
	return PTLS_ERROR_NO_MEMORY;

      ptls_get_context (tls)->random_bytes (self->id, sizeof (self->id));
      clib_memcpy (self->data.base, src.base, src.len);
      self->data.len = src.len;

      /* store the session id in buffer */
      if ((ret = ptls_buffer_reserve (dst, sizeof (self->id))) != 0)
	return ret;
      clib_memcpy (dst->base + dst->off, self->id, sizeof (self->id));
      dst->off += sizeof (self->id);
    }
  else
    {
      /* check if session id is the one stored in cache */
      if (src.len != sizeof (self->id))
	return PTLS_ERROR_SESSION_NOT_FOUND;
      if (clib_memcmp (self->id, src.base, sizeof (self->id)) != 0)
	return PTLS_ERROR_SESSION_NOT_FOUND;

      /* return the cached value */
      if ((ret = ptls_buffer_reserve (dst, self->data.len)) != 0)
	return ret;
      clib_memcpy (dst->base + dst->off, self->data.base, self->data.len);
      dst->off += self->data.len;
    }

  return 0;
}

ptls_cipher_algorithm_t quic_quicly_crypto_aes128ctr = {
  "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1,
  PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  quic_quicly_crypto_aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t quic_quicly_crypto_aes256ctr = {
  "AES256-CTR",
  PTLS_AES256_KEY_SIZE,
  1 /* block size */,
  PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  quic_quicly_crypto_aes256ctr_setup_crypto
};

#define PTLS_X86_CACHE_LINE_ALIGN_BITS 6
ptls_aead_algorithm_t quic_quicly_crypto_aes128gcm = {
  "AES128-GCM",
  PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
  PTLS_AESGCM_INTEGRITY_LIMIT,
  &quic_quicly_crypto_aes128ctr,
  &ptls_openssl_aes128ecb,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  { PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE },
  1,
  PTLS_X86_CACHE_LINE_ALIGN_BITS,
  sizeof (struct aead_crypto_context_t),
  quic_quicly_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_quicly_crypto_aes256gcm = {
  "AES256-GCM",
  PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
  PTLS_AESGCM_INTEGRITY_LIMIT,
  &quic_quicly_crypto_aes256ctr,
  &ptls_openssl_aes256ecb,
  PTLS_AES256_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  { PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE },
  1,
  PTLS_X86_CACHE_LINE_ALIGN_BITS,
  sizeof (struct aead_crypto_context_t),
  quic_quicly_crypto_aead_aes256gcm_setup_crypto
};

ptls_cipher_suite_t quic_quicly_crypto_aes128gcmsha256 = {
  PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &quic_quicly_crypto_aes128gcm,
  &ptls_openssl_sha256
};

ptls_cipher_suite_t quic_quicly_crypto_aes256gcmsha384 = {
  PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &quic_quicly_crypto_aes256gcm,
  &ptls_openssl_sha384
};

ptls_cipher_suite_t *quic_quicly_crypto_cipher_suites[] = {
  &quic_quicly_crypto_aes256gcmsha384, &quic_quicly_crypto_aes128gcmsha256,
  NULL
};

quicly_crypto_engine_t quic_quicly_crypto_engine = {
  quic_quicly_crypto_setup_cipher, quic_quicly_crypto_encrypt_packet
};
