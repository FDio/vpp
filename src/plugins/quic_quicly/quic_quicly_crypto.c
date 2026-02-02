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
#include <openssl/rand.h>
#include <pthread.h>

#define QUICLY_EPOCH_1RTT 3

vnet_crypto_main_t *cm = &crypto_main;
quic_quicly_crypto_main_t quic_quicly_crypto_main;

static_always_inline u8
quic_quicly_register_cipher_suite (crypto_engine_type_t type, ptls_cipher_suite_t **ciphers)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  u8 rv = 1;

  if (!qqcm->quic_ciphers)
    {
      vec_validate (qqcm->quic_ciphers, type);
    }
  if (!qqcm->quic_ciphers[type])
    {
      QUIC_DBG (3, "Register cipher suite: engine_type %U (%u), cipher_suites %p",
		format_crypto_engine, type, type, ciphers);
      clib_bitmap_set (qqcm->available_crypto_engines, type, 1);
      qqcm->quic_ciphers[type] = ciphers;
    }
  else
    {
      QUIC_DBG (3,
		"Cipher suite already registered: engine_type %U (%u), "
		"cipher_suites %p",
		format_crypto_engine, type, type, ciphers);
      rv = 0;
    }
  return rv;
}

void
quic_quicly_crypto_init (quic_quicly_main_t *qqm)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  u8 seed[32];

  QUIC_DBG (2, "quic_quicly_crypto init");
  qqcm->qqm = qqm;

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    clib_warning ("getrandom() failed");
  RAND_seed (seed, sizeof (seed));

  clib_bihash_init_24_8 (&qqcm->crypto_ctx_hash, "quic (quicly engine) crypto ctx", 64, 128 << 10);
  quic_quicly_register_cipher_suite (CRYPTO_ENGINE_PICOTLS, ptls_openssl_cipher_suites);
}

void
quic_quicly_crypto_context_list (vlib_main_t *vm)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  quic_quicly_crypto_ctx_t **crctx;

  pool_foreach (crctx, qqcm->crypto_ctx_pool)
    {
      vlib_cli_output (vm, "%U", format_quic_crypto_context, *crctx);
    }
}

static_always_inline void
quic_quicly_crypto_context_make_key_from_ctx (clib_bihash_kv_24_8_t *kv,
					      quic_ctx_t *ctx)
{
  application_t *app = application_get (ctx->parent_app_id);
  kv->key[0] =
    ((u64) ctx->ckpair_index) << 32 | (u64) (ctx->verify_cfg << 24) | (u64) ctx->crypto_engine;
  kv->key[1] = app->sm_properties.rx_fifo_size - 1;
  kv->key[2] = app->sm_properties.tx_fifo_size - 1;
}

static_always_inline void
quic_quicly_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
						quic_quicly_crypto_ctx_t *crctx)
{
  kv->key[0] = ((u64) crctx->ctx.ckpair_index) << 32 | (u64) (crctx->verify_cfg << 24) |
	       (u64) crctx->ctx.crypto_engine;
  kv->key[1] = crctx->quicly_ctx.transport_params.max_stream_data.bidi_local;
  kv->key[2] = crctx->quicly_ctx.transport_params.max_stream_data.bidi_remote;
}

static quic_quicly_crypto_ctx_t *
quic_quicly_crypto_context_alloc ()
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  quic_quicly_crypto_ctx_t **crctx;
  u32 idx;

  pool_get_aligned_safe (qqcm->crypto_ctx_pool, crctx, 0);

  if (!(*crctx))
    *crctx = clib_mem_alloc (sizeof (quic_quicly_crypto_ctx_t));

  clib_memset (*crctx, 0, sizeof (quic_quicly_crypto_ctx_t));
  idx = (crctx - qqcm->crypto_ctx_pool);
  (*crctx)->ctx.ctx_index = QUIC_CRCTX_CTX_INDEX_ENCODE (0, idx);
  QUIC_DBG (2, "Allocated crctx: crctx_ndx 0x%08lx, index %u", (*crctx)->ctx.ctx_index, idx);

  return *crctx;
}

static void
quic_quicly_crypto_context_free_if_needed (quic_quicly_crypto_ctx_t *crctx)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  clib_bihash_kv_24_8_t kv;
  u32 idx;

  /* crypto context is shared between threads */
  u32 cnt = clib_atomic_sub_fetch (&crctx->ctx.n_subscribers, 1);
  if (cnt)
    return;

  idx = QUIC_CRCTX_CTX_INDEX_DECODE_INDEX (crctx->ctx.ctx_index);
  QUIC_DBG (2, "Free crctx: crctx_ndx 0x%08lx, index %u", crctx->ctx.ctx_index, idx);
  quic_quicly_crypto_context_make_key_from_crctx (&kv, crctx);
  clib_bihash_add_del_24_8 (&qqcm->crypto_ctx_hash, &kv, 0 /* is_add */);
  if (CLIB_DEBUG)
    memset (crctx, 0xfe, sizeof (*crctx));
  pool_put_index (qqcm->crypto_ctx_pool, idx);
}

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

static void
quic_quicly_cleanup_certkey_int_ctx (app_certkey_int_ctx_t *cki)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  quic_quicly_crypto_ctx_t **crctx;
  clib_bihash_kv_24_8_t kv;

  pool_foreach (crctx, qqcm->crypto_ctx_pool)
    {
      if ((*crctx)->ctx.ckpair_index == cki->ckpair_index)
	{
	  quic_quicly_crypto_context_make_key_from_crctx (&kv, *crctx);
	  clib_bihash_add_del_24_8 (&qqcm->crypto_ctx_hash, &kv, 0 /* is_add */);
	}
    }
  EVP_PKEY_free (cki->key);
  clib_mem_free (cki->cert);
}

static int
quic_quicly_verify_cert_cb (ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
			    int (**verifier) (void *, uint16_t, ptls_iovec_t, ptls_iovec_t),
			    void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
  quic_quicly_verify_certificate_t *self = (quic_quicly_verify_certificate_t *) _self;
  int ret;

  /* Get the specific quicly connection from the TLS data pointer */
  void **data_ptr = ptls_get_data_ptr (tls);
  quicly_conn_t *conn = data_ptr ? (quicly_conn_t *) *data_ptr : NULL;
  quic_ctx_t *qctx = conn ? quic_quicly_get_conn_ctx (conn) : NULL;

  /* Call the original OpenSSL-based verification */
  ret = self->orig_cb (_self, tls, server_name, verifier, verify_data, certs, num_certs);

  /* If verification succeeded and we have certificates, store the peer cert */
  if (ret == 0 && num_certs > 0 && qctx)
    {
      ASSERT (qctx->peer_cert == NULL);

      /* Convert the first certificate (peer's certificate) to X509 */
      const uint8_t *p = certs[0].base;
      X509 *cert = d2i_X509 (NULL, &p, (long) certs[0].len);
      if (cert)
	{
	  qctx->peer_cert = cert;
	  QUIC_DBG (2, "Stored peer certificate for ctx %p (conn %p)", qctx, conn);
	}
    }

  return ret;
}

static app_certkey_int_ctx_t *
quic_quicly_certkey_init_ctx (app_cert_key_pair_t *ckpair,
			      clib_thread_index_t thread_index)
{
  quic_quicly_ptls_cert_list_t *cl;
  app_certkey_int_ctx_t *cki;
  EVP_PKEY *pkey;

  pkey = ptls_load_private_key ((char *) ckpair->key);
  if (pkey == NULL)
    return 0;

  cl = ptls_load_certificate_chain ((char *) ckpair->cert);
  if (!cl)
    return 0;

  cki =
    app_certkey_alloc_int_ctx (ckpair, thread_index, CRYPTO_ENGINE_PICOTLS);
  cki->key = pkey;
  cki->cert = cl;
  cki->cleanup_cb = quic_quicly_cleanup_certkey_int_ctx;

  return cki;
}

static int
quic_quicly_crypto_context_init_data (quic_quicly_crypto_ctx_t *crctx, quic_ctx_t *ctx)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  quic_quicly_main_t *qqm = qqcm->qqm;
  quic_main_t *qm = qqm->qm;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  app_cert_key_pair_t *ckpair;
  application_t *app;
  ptls_context_t *ptls_ctx;
  app_crypto_ctx_t *app_cctx;
  app_certkey_int_ctx_t *cki;

  QUIC_DBG (2, "Init crctx: crctx_ndx 0x%08lx", crctx->ctx.ctx_index);

  if (PREDICT_FALSE (!qm->vnet_crypto_init))
    {
      qm->vnet_crypto_init = 1;
      if ((vec_len (cm->engines) == 0) ||
	  (qm->default_crypto_engine == CRYPTO_ENGINE_PICOTLS))
	{
	  qqcm->vnet_crypto_enabled = 0;
	  (void) quic_quicly_register_cipher_suite (
	    CRYPTO_ENGINE_PICOTLS, ptls_openssl_cipher_suites);
	}
      else
	{
	  qqcm->vnet_crypto_enabled = 1;
	  if (quic_quicly_register_cipher_suite (
		CRYPTO_ENGINE_VPP, quic_quicly_crypto_cipher_suites))
	    {
	      u8 empty_key[32] = {};
	      u32 i;
	      qm->default_crypto_engine = ctx->crypto_engine =
		CRYPTO_ENGINE_VPP;
	      vec_validate (qqcm->per_thread_crypto_keys, qm->num_threads);
	      for (i = 0; i < qm->num_threads; i++)
		{
		  qqcm->per_thread_crypto_keys[i] =
		    vnet_crypto_key_add_ptr (VNET_CRYPTO_ALG_AES_256_CTR, empty_key, 32);
		}
	    }
	}
    }

  quicly_ctx = &crctx->quicly_ctx;
  ptls_ctx = &crctx->ptls_ctx;

  crctx->client_hello_ctx.super.cb = quic_quicly_on_client_hello_ptls;
  crctx->client_hello_ctx.lctx_index = ctx->listener_ctx_id;

  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->get_time = &ptls_get_time;
  ptls_ctx->key_exchanges = ptls_openssl_key_exchanges;
  ptls_ctx->cipher_suites = qqcm->quic_ciphers[ctx->crypto_engine];
  QUIC_DBG (2, "Init crctx: engine_type %U (%u), cipher_suites %p", format_crypto_engine,
	    ctx->crypto_engine, ctx->crypto_engine, ptls_ctx->cipher_suites);
  ptls_ctx->certificates.list = NULL;
  ptls_ctx->certificates.count = 0;
  ptls_ctx->on_client_hello = &crctx->client_hello_ctx.super;
  ptls_ctx->emit_certificate = NULL;
  ptls_ctx->sign_certificate = NULL;

  if (crctx->verify_cfg)
    {
      /* Set up custom verify certificate callback to capture peer certificates
       * Enable for both client and server (mutual TLS support) */
      /* Allocate verify certificate context (freed when crypto context is freed) */
      quic_quicly_verify_certificate_t *verify_cert = &crctx->verify_cert;
      ptls_openssl_init_verify_certificate (&verify_cert->super, NULL);
      /* Save the original callback and replace with our wrapper */
      verify_cert->orig_cb = verify_cert->super.super.cb;
      verify_cert->super.super.cb = quic_quicly_verify_cert_cb;
      ptls_ctx->verify_certificate = &verify_cert->super.super;

      /* Enable mutual TLS: server will request client certificates */
      ptls_ctx->require_client_authentication = (crctx->verify_cfg & TLS_VERIFY_F_PEER_CERT) != 0;
    }
  ptls_ctx->ticket_lifetime = 86400;
  ptls_ctx->max_early_data_size = 8192;
  ptls_ctx->hkdf_label_prefix__obsolete = NULL;
  ptls_ctx->require_dhe_on_psk = 1;
  ptls_ctx->encrypt_ticket = &qqm->session_cache.super;
  clib_memcpy (quicly_ctx, &quicly_spec_context, sizeof (quicly_context_t));

  quicly_ctx->max_packets_per_key = qm->max_packets_per_key;
  quicly_ctx->tls = ptls_ctx;
  quicly_ctx->enable_ratio.pacing = qm->enable_tx_pacing;

  quicly_amend_ptls_context (quicly_ctx->tls);

  if (quic_quicly_crypto_engine_is_vpp ())
    {
      QUIC_DBG (2, "Init crctx: crypto engine vpp, crctx_ndx 0x%08lx", crctx->ctx.ctx_index);
      quicly_ctx->crypto_engine = &quic_quicly_crypto_engine;
    }
  else
    {
      QUIC_DBG (2, "Init crctx: crypto engine quicly, crctx_ndx 0x%08lx", crctx->ctx.ctx_index);
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
  quicly_ctx->transport_params.max_stream_data.uni =
    clib_min (app->sm_properties.rx_fifo_size,
	      app->sm_properties.tx_fifo_size) -
    1;

  quicly_ctx->transport_params.max_udp_payload_size = QUIC_MAX_PACKET_SIZE;
  app_cctx = app_crypto_ctx_get (app);
  if (!app->crypto_ctx.quic_iv_set)
    {
      ptls_openssl_random_bytes (app_cctx->quic_iv, QUIC_IV_LEN - 1);
      app_cctx->quic_iv[QUIC_IV_LEN - 1] = 0;
      app_cctx->quic_iv_set = 1;
    }

  clib_memcpy (crctx->cid_key, app_cctx->quic_iv, QUIC_IV_LEN);
  key_vec = ptls_iovec_init (crctx->cid_key, QUIC_IV_LEN);
  quicly_ctx->cid_encryptor = quicly_new_default_cid_encryptor (
    &ptls_openssl_aes128ecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256, key_vec);

  ckpair = app_cert_key_pair_get_if_valid (crctx->ctx.ckpair_index);
  if (!ckpair || !ckpair->key || !ckpair->cert)
    {
      QUIC_DBG (1, "Wrong ckpair id %d\n", crctx->ctx.ckpair_index);
      return -1;
    }
  cki = app_certkey_get_int_ctx (ckpair, ctx->c_thread_index,
				 CRYPTO_ENGINE_PICOTLS);
  if (!cki || !cki->cert)
    {
      cki = quic_quicly_certkey_init_ctx (ckpair, ctx->c_thread_index);
      if (!cki)
	{
	  clib_warning ("unable to initialize certificate/key pair");
	  return -1;
	}
    }

  ptls_assign_private_key (quicly_ctx->tls, cki->key);
  ptls_assign_certificate_chain (quicly_ctx->tls, cki->cert);

  return 0;
}

void
quic_quicly_crypto_context_free (u32 crctx_ndx)
{
  quic_quicly_crypto_ctx_t *crctx;
  QUIC_DBG (3, "crctx_ndx 0x%x (%u)", crctx_ndx, crctx_ndx);
  crctx = quic_quicly_crypto_context_get (crctx_ndx);
  quic_quicly_crypto_context_free_if_needed (crctx);
}

quic_quicly_crypto_ctx_t *
quic_quicly_crypto_context_get_or_alloc (quic_ctx_t *ctx)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  quic_main_t *qm = qqcm->qqm->qm;
  quic_quicly_crypto_ctx_t *crctx;
  clib_bihash_kv_24_8_t kv;

  ctx->crypto_engine =
    (ctx->crypto_engine == CRYPTO_ENGINE_NONE) ? qm->default_crypto_engine : ctx->crypto_engine;

  /* Check for exisiting crypto ctx */
  quic_quicly_crypto_context_make_key_from_ctx (&kv, ctx);
  if (clib_bihash_search_24_8 (&qqcm->crypto_ctx_hash, &kv, &kv) == 0)
    {
      crctx = quic_quicly_crypto_context_get (kv.value);
      QUIC_DBG (2, "Found existing crypto context: crctx_ndx 0x%lx (%d), thread %u", kv.value,
		kv.value, ctx->c_thread_index);
      ctx->crypto_context_index = kv.value;
      clib_atomic_add_fetch (&crctx->ctx.n_subscribers, 1);
      return crctx;
    }

  crctx = quic_quicly_crypto_context_alloc ();
  ctx->crypto_context_index = crctx->ctx.ctx_index;
  kv.value = crctx->ctx.ctx_index;
  crctx->ctx.crypto_engine = ctx->crypto_engine;
  crctx->ctx.ckpair_index = ctx->ckpair_index;
  crctx->verify_cfg = ctx->verify_cfg;
  clib_bihash_add_del_24_8 (&qqcm->crypto_ctx_hash, &kv, 1 /* is_add */);
  quic_quicly_crypto_context_init_data (crctx, ctx);
  clib_atomic_add_fetch (&crctx->ctx.n_subscribers, 1);
  return crctx;
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

static uword
quic_quicly_crypto_set_key (vlib_main_t *vm, crypto_key_t *key)
{
  u8 thread_index = vlib_get_thread_index ();
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  vnet_crypto_key_t *vnet_key = qqcm->per_thread_crypto_keys[thread_index];

  ASSERT (key->algo);
  ASSERT (key->key_len);

  vnet_crypto_key_update (vnet_key, key->key);

  return vnet_crypto_get_key_data (vm, vnet_key, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
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
  aead_crctx->op.key_data = quic_quicly_crypto_set_key (vm, &aead_crctx->key);
  aead_crctx->op.src = (u8 *) input;
  aead_crctx->op.dst = output;
  aead_crctx->op.len = inlen;
  aead_crctx->op.tag_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag = aead_crctx->op.src + inlen;
  vnet_crypto_process_ops (&(aead_crctx->op), 1);
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
  hp_ctx->op.key_data = quic_quicly_crypto_set_key (vm, &hp_ctx->key);
  ;
  hp_ctx->op.src = (u8 *) supp.output;
  hp_ctx->op.dst = (u8 *) supp.output;
  hp_ctx->op.len = sizeof (supp.output);
  vnet_crypto_process_ops (&(hp_ctx->op), 1);
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
  aead_crctx->op.key_data = quic_quicly_crypto_set_key (vm, &aead_crctx->key);
  aead_crctx->op.len = inlen - aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.tag = aead_crctx->op.src + aead_crctx->op.len;

  vnet_crypto_process_ops (&(aead_crctx->op), 1);

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
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
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

  if (qqcm->vnet_crypto_enabled)
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
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
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

  if (qqcm->vnet_crypto_enabled)
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
      if (self->data.base)
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

X509 *
quic_quicly_crypto_get_peer_cert (quic_ctx_t *ctx)
{
  if (!ctx || !ctx->peer_cert)
    return NULL;

  /* Return the stored certificate - caller should NOT free it */
  return (X509 *) ctx->peer_cert;
}
