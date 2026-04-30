/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly.h>
#include <quic_quicly/quic_quicly_error.h>
#include <quic_quicly/quic_quicly_crypto.h>
#include <vnet/session/application.h>
#include <vnet/session/application_crypto.h>
#include <vnet/session/session.h>

#include <quic/quic_timer.h>
#include <quicly.h>
#include <picotls/openssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

  vec_validate (qqcm->quic_ciphers, type);
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
  quic_main_t *qm = qqm->qm;
  u8 seed[32];

  QUIC_DBG (2, "quic_quicly_crypto init");

  qqcm->qqm = qqm;

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    clib_warning ("getrandom() failed");
  RAND_seed (seed, sizeof (seed));

  clib_bihash_init_24_8 (&qqcm->crypto_ctx_hash, "quic (quicly engine) crypto ctx", 64, 128 << 10);
  quic_quicly_register_cipher_suite (CRYPTO_ENGINE_PICOTLS, ptls_openssl_cipher_suites);

  if (qm->enable_vnet_crypto)
    {
      if (vec_len (cm->engines) == 0)
	{
	  clib_warning ("No crypto engines available");
	  return;
	}
      if (quic_quicly_register_cipher_suite (CRYPTO_ENGINE_VPP, quic_quicly_crypto_cipher_suites))
	{
	  qqcm->vnet_crypto_enabled = 1;
	}
    }
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
  ASSERT (ctx->crypto_owner_app_wrk_id != SESSION_INVALID_INDEX);

  kv->key[0] = ((u64) ctx->ckpair_index) << 32 | (u64) (ctx->verify_cfg << 24) |
	       ((u64) (ctx->tls_profile_index & 0xFFFF)) << 8 | (u64) ctx->crypto_engine;
  kv->key[1] = ((u64) app->sm_properties.tx_fifo_size << 32) | app->sm_properties.rx_fifo_size;
  kv->key[2] = ((u64) ctx->crypto_owner_app_wrk_id << 32) | ctx->ca_trust_index;
}

static_always_inline void
quic_quicly_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
						quic_quicly_crypto_ctx_t *crctx)
{
  kv->key[0] = ((u64) crctx->ctx.ckpair_index) << 32 | (u64) (crctx->verify_cfg << 24) |
	       ((u64) (crctx->tls_profile_index & 0xFFFF)) << 8 | (u64) crctx->ctx.crypto_engine;
  kv->key[1] = ((u64) crctx->quicly_ctx.transport_params.max_stream_data.bidi_remote << 32) |
	       crctx->quicly_ctx.transport_params.max_stream_data.bidi_local;
  kv->key[2] = ((u64) crctx->crypto_owner_app_wrk_id << 32) | crctx->ca_trust_index;
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
  if (crctx->filtered_cipher_suites)
    {
      clib_mem_free (crctx->filtered_cipher_suites);
      crctx->filtered_cipher_suites = NULL;
    }
  if (crctx->filtered_key_exchanges)
    {
      clib_mem_free (crctx->filtered_key_exchanges);
      crctx->filtered_key_exchanges = NULL;
    }
  if (crctx->verify_cfg)
    {
      ptls_openssl_dispose_verify_certificate (&crctx->verify_cert.super);
      crctx->ptls_ctx.verify_certificate = NULL;
    }
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

static app_crypto_ca_trust_int_ctx_t *
quic_quicly_init_int_ca_trust_ctx (app_crypto_ca_trust_t *ca_trust,
				   clib_thread_index_t thread_index);

static void
quic_quicly_ca_trust_int_ctx_update (app_crypto_ca_trust_int_ctx_t *cti, app_crypto_ca_trust_t *ct,
				     app_crypto_ca_trust_update_type_t type)
{
  X509_STORE_free (cti->ca_store);
  cti->ca_store = 0;

  if (type == APP_CA_TRUST_UPDATE_TYPE_DEL)
    return;

  if (!quic_quicly_init_int_ca_trust_ctx (ct, cti->thread_index))
    clib_warning ("failed to rebuild ca trust ctx after CRL update");
}

static app_crypto_ca_trust_int_ctx_t *
quic_quicly_init_int_ca_trust_ctx (app_crypto_ca_trust_t *ca_trust,
				   clib_thread_index_t thread_index)
{
  app_crypto_ca_trust_int_ctx_t *cti;
  X509_STORE *store;
  X509 *cert;
  BIO *bio;

  cti = app_crypto_alloc_int_ca_trust (ca_trust, thread_index);
  store = X509_STORE_new ();
  if (!store)
    {
      clib_warning ("unable to create x509 store");
      return 0;
    }

  bio = BIO_new (BIO_s_mem ());
  BIO_write (bio, ca_trust->ca_chain, vec_len (ca_trust->ca_chain));
  while ((cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL)) != NULL)
    {
      if (X509_STORE_add_cert (store, cert) != 1)
	{
	  char err_buf[512];
	  ERR_error_string (ERR_get_error (), err_buf);
	  clib_warning ("unable to add certificate to store: %s", err_buf);
	  X509_free (cert);
	  BIO_free (bio);
	  X509_STORE_free (store);
	  return 0;
	}
      X509_free (cert);
    }
  BIO_free (bio);

  if (ca_trust->crl && vec_len (ca_trust->crl) > 0)
    {
      X509_CRL *crl;

      bio = BIO_new (BIO_s_mem ());
      BIO_write (bio, ca_trust->crl, vec_len (ca_trust->crl));
      while ((crl = PEM_read_bio_X509_CRL (bio, NULL, NULL, NULL)) != NULL)
	{
	  if (X509_STORE_add_crl (store, crl) != 1)
	    {
	      char err_buf[512];
	      ERR_error_string (ERR_get_error (), err_buf);
	      clib_warning ("unable to add CRL to store: %s", err_buf);
	      X509_CRL_free (crl);
	      BIO_free (bio);
	      X509_STORE_free (store);
	      return 0;
	    }
	  X509_CRL_free (crl);
	}
      BIO_free (bio);

      X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

  cti->ca_store = store;
  cti->update_cb = quic_quicly_ca_trust_int_ctx_update;
  return cti;
}

static app_crypto_ca_trust_int_ctx_t *
quic_quicly_get_int_ca_trust (quic_ctx_t *ctx)
{
  app_crypto_ca_trust_int_ctx_t *cti;
  app_crypto_ca_trust_t *ca_trust;
  ASSERT (ctx->crypto_owner_app_wrk_id != SESSION_INVALID_INDEX);
  ca_trust = app_crypto_get_wrk_ca_trust (ctx->crypto_owner_app_wrk_id, ctx->ca_trust_index);
  if (!ca_trust)
    return 0;

  cti = app_crypto_get_int_ca_trust (ca_trust, ctx->c_thread_index);
  if (!cti || !cti->ca_store)
    cti = quic_quicly_init_int_ca_trust_ctx (ca_trust, ctx->c_thread_index);

  return cti;
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
quic_quicly_group_name_matches (const char *ptls_name, const char *ossl_name)
{
  /* Case-insensitive match covers "x25519" vs "X25519", "secp256r1" vs
   * "secp256r1", etc. */
  if (strcasecmp (ptls_name, ossl_name) == 0)
    return 1;
  /* Handle OpenSSL short names: P-256, P-384, P-521 */
  if (strcmp (ptls_name, PTLS_GROUP_NAME_SECP256R1) == 0 &&
      (strcasecmp (ossl_name, "P-256") == 0 || strcasecmp (ossl_name, "prime256v1") == 0))
    return 1;
  if (strcmp (ptls_name, PTLS_GROUP_NAME_SECP384R1) == 0 && strcasecmp (ossl_name, "P-384") == 0)
    return 1;
  if (strcmp (ptls_name, PTLS_GROUP_NAME_SECP521R1) == 0 && strcasecmp (ossl_name, "P-521") == 0)
    return 1;
  return 0;
}

/* Returns 1 if the ptls group name appears anywhere in the colon-separated
 * OpenSSL-format groups list (e.g. "X25519:P-256"). */
static int
quic_quicly_group_in_list (const char *ptls_name, const u8 *groups_list)
{
  const char *p = (const char *) groups_list;
  const char *q;
  char name[64];
  uword len;

  while (*p)
    {
      q = p;
      while (*q && *q != ':')
	q++;
      len = q - p;
      if (len > 0 && len < sizeof (name))
	{
	  clib_memcpy (name, p, len);
	  name[len] = '\0';
	  if (quic_quicly_group_name_matches (ptls_name, name))
	    return 1;
	}
      p = *q ? q + 1 : q;
    }
  return 0;
}

static_always_inline app_tls_profile_t *
quic_quicly_get_tls_profile (quic_ctx_t *ctx)
{
  ASSERT (ctx->crypto_owner_app_wrk_id != SESSION_INVALID_INDEX);
  return app_crypto_get_tls_profile_if_valid (ctx->crypto_owner_app_wrk_id, ctx->tls_profile_index);
}

/* Apply a TLS profile's cipher suite and key exchange restrictions to the
 * picotls context.  Allocates NULL-terminated filtered arrays stored in
 * crctx->filtered_* and frees any previous ones. */
static void
quic_quicly_apply_tls_profile (quic_quicly_crypto_ctx_t *crctx, quic_ctx_t *ctx)
{
  quic_quicly_crypto_main_t *qqcm = &quic_quicly_crypto_main;
  ptls_context_t *ptls_ctx = &crctx->ptls_ctx;
  app_tls_profile_t *prof = NULL;
  int i, n;

  prof = quic_quicly_get_tls_profile (ctx);
  if (!prof)
    return;

  /* Filter TLS 1.3 cipher suites based on profile->ciphersuites.
   * Note: QUIC always requires TLS_AES_128_GCM_SHA256 for Initial packet
   * protection (quicly calls get_aes128gcmsha256() unconditionally); it is
   * always retained in the filtered list regardless of the profile. */
  if (prof->ciphersuites)
    {
      ptls_cipher_suite_t **all = qqcm->quic_ciphers[ctx->crypto_engine];
      ptls_cipher_suite_t **filtered;

      n = 0;
      for (i = 0; all[i]; i++)
	if (all[i]->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 ||
	    (all[i]->name && strstr ((char *) prof->ciphersuites, all[i]->name)))
	  n++;

      filtered = clib_mem_alloc ((n + 1) * sizeof (*filtered));
      n = 0;
      for (i = 0; all[i]; i++)
	if (all[i]->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 ||
	    (all[i]->name && strstr ((char *) prof->ciphersuites, all[i]->name)))
	  filtered[n++] = all[i];
      filtered[n] = NULL;

      if (crctx->filtered_cipher_suites)
	clib_mem_free (crctx->filtered_cipher_suites);
      crctx->filtered_cipher_suites = filtered;
      ptls_ctx->cipher_suites = filtered;
    }

  /* Filter key exchange groups based on profile->groups.
   * Filter from the full key exchange list (ptls_openssl_key_exchanges_all)
   * so that groups like x25519 that are absent from the minimal default list
   * (ptls_openssl_key_exchanges) are still reachable. */
  if (prof->groups)
    {
      ptls_key_exchange_algorithm_t **all = ptls_openssl_key_exchanges_all;
      ptls_key_exchange_algorithm_t **filtered;

      n = 0;
      for (i = 0; all[i]; i++)
	if (quic_quicly_group_in_list (all[i]->name, prof->groups))
	  n++;

      filtered = clib_mem_alloc ((n + 1) * sizeof (*filtered));
      n = 0;
      for (i = 0; all[i]; i++)
	if (quic_quicly_group_in_list (all[i]->name, prof->groups))
	  filtered[n++] = all[i];
      filtered[n] = NULL;

      if (crctx->filtered_key_exchanges)
	clib_mem_free (crctx->filtered_key_exchanges);
      crctx->filtered_key_exchanges = filtered;
      ptls_ctx->key_exchanges = filtered;
    }
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
  app_crypto_ca_trust_int_ctx_t *cti;
  app_certkey_int_ctx_t *cki;

  QUIC_DBG (2, "Init crctx: crctx_ndx 0x%08lx", crctx->ctx.ctx_index);

  quicly_ctx = &crctx->quicly_ctx;
  ptls_ctx = &crctx->ptls_ctx;

  crctx->client_hello_ctx.super.cb = quic_quicly_on_client_hello_ptls;
  crctx->client_hello_ctx.lctx_index = ctx->listener_ctx_id;

  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->get_time = &ptls_get_time;
  /* Use the full key exchange list so that x25519 and other modern groups are
   * available by default; a TLS profile can restrict to a subset. */
  ptls_ctx->key_exchanges = ptls_openssl_key_exchanges_all;
  ptls_ctx->cipher_suites = qqcm->quic_ciphers[ctx->crypto_engine];
  QUIC_DBG (2, "Init crctx: engine_type %U (%u), cipher_suites %p", format_crypto_engine,
	    ctx->crypto_engine, ctx->crypto_engine, ptls_ctx->cipher_suites);
  ptls_ctx->certificates.list = NULL;
  ptls_ctx->certificates.count = 0;
  ptls_ctx->on_client_hello = &crctx->client_hello_ctx.super;
  ptls_ctx->emit_certificate = NULL;
  ptls_ctx->sign_certificate = NULL;

  /* Apply TLS profile restrictions (cipher suites, key exchanges) */
  quic_quicly_apply_tls_profile (crctx, ctx);

  if (crctx->verify_cfg)
    {
      X509_STORE *ca_store = NULL;

      if (ctx->ca_trust_index)
	{
	  cti = quic_quicly_get_int_ca_trust (ctx);
	  if (!cti || !cti->ca_store)
	    {
	      clib_warning ("unable to initialize ca trust context");
	      return -1;
	    }
	  ca_store = cti->ca_store;
	}

      /* Set up custom verify certificate callback to capture peer certificates
       * Enable for both client and server (mutual TLS support) */
      /* Allocate verify certificate context (freed when crypto context is freed) */
      quic_quicly_verify_certificate_t *verify_cert = &crctx->verify_cert;
      if (ptls_openssl_init_verify_certificate (&verify_cert->super, ca_store))
	{
	  clib_warning ("unable to initialize verify certificate callback");
	  return -1;
	}
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
  quicly_ctx->enable_ratio.pacing = qm->enable_tx_pacing ? 255 : 0;

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
  quicly_ctx->transport_params.max_stream_data.bidi_local = app->sm_properties.rx_fifo_size;
  quicly_ctx->transport_params.max_stream_data.bidi_remote = app->sm_properties.tx_fifo_size;
  quicly_ctx->transport_params.max_stream_data.uni =
    clib_min (app->sm_properties.rx_fifo_size, app->sm_properties.tx_fifo_size);

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
  crctx->ca_trust_index = ctx->ca_trust_index;
  crctx->crypto_owner_app_wrk_id = ctx->crypto_owner_app_wrk_id;
  crctx->tls_profile_index = ctx->tls_profile_index;
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
  vnet_crypto_op_init (0, &aead_crctx->op);
  aead_crctx->op.type = aead_crctx->type;
  aead_crctx->op.aad = (u8 *) aad;
  aead_crctx->op.aad_len = aadlen;
  aead_crctx->op.iv = aead_crctx->iv;
  ptls_aead__build_iv (aead_crctx->super.algo, aead_crctx->op.iv,
		       aead_crctx->static_iv, packet_number);
  QUIC_DBG (3, "type %u, vnet_ctx %p", aead_crctx->type, aead_crctx->vnet_ctx);
  aead_crctx->op.ctx = aead_crctx->vnet_ctx;
  aead_crctx->op.src = (u8 *) input;
  aead_crctx->op.dst = output;
  aead_crctx->op.len = inlen;
  aead_crctx->op.auth_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.auth = aead_crctx->op.src + inlen;
  vnet_crypto_process_ops (vm, &(aead_crctx->op), 0, 1);
  assert (aead_crctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

  /* Build Header protection crypto operation */
  ptls_aead_supplementary_encryption_t supp = {
    .ctx = header_protect_ctx,
    .input =
      datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE
  };

  /* Build Header protection crypto operation */
  vnet_crypto_op_init (0, &hp_ctx->op);
  hp_ctx->op.type = hp_ctx->type;
  memset (supp.output, 0, sizeof (supp.output));
  hp_ctx->op.iv = (u8 *) supp.input;
  hp_ctx->op.ctx = hp_ctx->vnet_ctx;
  hp_ctx->op.src = (u8 *) supp.output;
  hp_ctx->op.dst = (u8 *) supp.output;
  hp_ctx->op.len = sizeof (supp.output);
  vnet_crypto_process_ops (vm, &(hp_ctx->op), 0, 1);
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

  vnet_crypto_op_init (0, &aead_crctx->op);
  aead_crctx->op.type = aead_crctx->type;
  aead_crctx->op.aad = (u8 *) aad;
  aead_crctx->op.aad_len = aadlen;
  aead_crctx->op.iv = aead_crctx->iv;
  ptls_aead__build_iv (aead_crctx->super.algo, aead_crctx->op.iv,
		       aead_crctx->static_iv, decrypted_pn);
  aead_crctx->op.src = (u8 *) input;
  aead_crctx->op.dst = _output;
  QUIC_DBG (3, "type %u, vnet_ctx %p", aead_crctx->type, aead_crctx->vnet_ctx);
  aead_crctx->op.ctx = aead_crctx->vnet_ctx;
  aead_crctx->op.len = inlen - aead_crctx->super.algo->tag_size;
  aead_crctx->op.auth_len = aead_crctx->super.algo->tag_size;
  aead_crctx->op.auth = aead_crctx->op.src + aead_crctx->op.len;

  vnet_crypto_process_ops (vm, &(aead_crctx->op), 0, 1);

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

static void
quic_quicly_cipher_do_dispose (ptls_cipher_context_t *_ctx)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;
  if (ctx->vnet_ctx)
    {
      vnet_crypto_ctx_destroy (vlib_get_main (), ctx->vnet_ctx);
      ctx->vnet_ctx = NULL;
    }
  if (ctx->orig_do_dispose)
    ctx->orig_do_dispose (_ctx);
}

static void
quic_quicly_aead_dispose_crypto (ptls_aead_context_t *_ctx)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;
  if (ctx->vnet_ctx)
    {
      vnet_crypto_ctx_destroy (vlib_get_main (), ctx->vnet_ctx);
      ctx->vnet_ctx = NULL;
    }
  if (ctx->orig_dispose_crypto)
    ctx->orig_dispose_crypto (_ctx);
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
      ctx->type = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
      ptls_openssl_aes128ctr.setup_crypto (_ctx, is_enc, key);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_CTR;
      ctx->type = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
      ptls_openssl_aes256ctr.setup_crypto (_ctx, is_enc, key);
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __func__, _ctx->algo->name);
      assert (0);
    }

  if (qqcm->vnet_crypto_enabled)
    {
      ctx->vnet_ctx = vnet_crypto_ctx_create (algo);
      vnet_crypto_ctx_set_cipher_key (ctx->vnet_ctx, key, _ctx->algo->key_size);
      ctx->orig_do_dispose = ctx->super.do_dispose;
      ctx->super.do_dispose = quic_quicly_cipher_do_dispose;
    }

  QUIC_DBG (2, "type %u, vnet_ctx %p", ctx->type, ctx->vnet_ctx);
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
      ctx->type = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
      ptls_openssl_aes128gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_GCM;
      ctx->type = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
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
      ctx->vnet_ctx = vnet_crypto_ctx_create (algo);
      vnet_crypto_ctx_set_cipher_key (ctx->vnet_ctx, key, _ctx->algo->key_size);
      ctx->orig_dispose_crypto = ctx->super.dispose_crypto;
      ctx->super.dispose_crypto = quic_quicly_aead_dispose_crypto;
    }

  QUIC_DBG (3, "type %u, vnet_ctx %p", ctx->type, ctx->vnet_ctx);
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
