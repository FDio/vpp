/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <quic/quic_inlines.h>
#include <quic_openssl/quic_openssl.h>
#include <quic_openssl/quic_openssl_crypto.h>
#include <vppinfra/pool.h>
#include <vnet/session/application_interface.h>
#include <vnet/tls/tls.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/quic.h>

static int
quic_openssl_alpn_select_cb (SSL *ssl, const unsigned char **out,
			     unsigned char *outlen, const unsigned char *in,
			     unsigned int inlen, void *arg)
{
  u8 *proto_list = arg;
  if (SSL_select_next_proto (
	(unsigned char **) out, outlen, (const unsigned char *) proto_list,
	vec_len (proto_list), in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
      QUIC_ERR ("No ALPN protocol match found");
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
  QUIC_DBG (2, "ALPN negotiated: %.*s", *outlen, *out);
  return SSL_TLSEXT_ERR_OK;
}

int
quic_openssl_init_ca_chain (void)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  tls_main_t *tm = vnet_tls_get_main ();
  BIO *cert_bio;
  X509 *testcert;
  int rv;

  /* TODO: is there a need for quic_openssl_reinit_ca_chain()??? */
  if (qom->cert_store)
    {
      QUIC_DBG (2, "ca chain already initialized");
      return 0;
    }
  if (access (tm->ca_cert_path, F_OK | R_OK) == -1)
    {
      clib_warning ("Could not initialize TLS CA certificates");
      return -1;
    }

  if (!(qom->cert_store = X509_STORE_new ()))
    {
      clib_warning ("failed to create cert store");
      return -1;
    }

  rv = X509_STORE_load_file (qom->cert_store, tm->ca_cert_path);
  if (rv < 0)
    {
      clib_warning ("failed to load ca certificate");
    }

  if (tm->use_test_cert_in_ca)
    {
      cert_bio = BIO_new (BIO_s_mem ());
      BIO_write (cert_bio, test_srv_crt_rsa, test_srv_crt_rsa_len);
      testcert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
      BIO_free (cert_bio);
      if (!testcert)
	{
	  clib_warning ("unable to parse certificate");
	  return -1;
	}
      X509_STORE_add_cert (qom->cert_store, testcert);
      X509_free (testcert);
      rv = 0;
    }
  return (rv < 0 ? -1 : 0);
}

static SSL_CTX *
quic_openssl_create_ssl_ctx (u8 is_server)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  SSL_CTX *ssl_ctx;

  ssl_ctx = is_server ? SSL_CTX_new (OSSL_QUIC_server_method ()) :
			SSL_CTX_new (OSSL_QUIC_client_method ());
  if (!ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context");
      return NULL;
    }

  SSL_CTX_set_min_proto_version (ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version (ssl_ctx, TLS1_3_VERSION);
  if (!SSL_CTX_set_ciphersuites (ssl_ctx, "TLS_AES_128_GCM_SHA256:"
					  "TLS_AES_256_GCM_SHA384:"
					  "TLS_CHACHA20_POLY1305_SHA256"))
    {
      QUIC_ERR ("Failed to set SSL server ciphersuites");
      SSL_CTX_free (ssl_ctx);
      return NULL;
    }

  if (is_server)
    {
      if (quic_openssl_init_ca_chain ())
	{
	  QUIC_ERR ("Failed to init ca chain");
	  SSL_CTX_free (ssl_ctx);
	  return NULL;
	}
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_NONE, NULL);
      SSL_CTX_set_alpn_select_cb (ssl_ctx, quic_openssl_alpn_select_cb, NULL);
    }
  else
    {
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

  if (SSL_CTX_set_alpn_protos (ssl_ctx, qom->alpn_protos,
			       vec_len (qom->alpn_protos)) != 0)
    {
      QUIC_ERR ("Failed to set ALPN protocols");
      SSL_CTX_free (ssl_ctx);
      return NULL;
    }

  return ssl_ctx;
}

void
quic_openssl_crypto_init_per_thread (quic_main_t *qm, u8 thread_index)
{
  clib_bihash_24_8_t *crctx_hash = quic_openssl_main.crypto_ctx_hash;

  clib_bihash_init_24_8 (&crctx_hash[thread_index], "quic crypto contexts", 64,
			 128 << 10);
  QUIC_DBG (2, "Initialized crctx_hash[%u] (buckets = 0x%lx)", thread_index,
	    crctx_hash[thread_index].buckets);

  QUIC_DBG (2, "Initialized OpenSSL crypto context pool for thread %u",
	    thread_index);
}

static crypto_context_t *
quic_openssl_crypto_context_alloc (quic_main_t *qm, u8 thread_index)
{
  quic_worker_ctx_t *wc = quic_wrk_ctx_get (qm, thread_index);
  crypto_context_t *crctx;
  u32 idx;

  pool_get_aligned_safe (wc->crypto_ctx_pool, crctx, CLIB_CACHE_LINE_BYTES);

  clib_memset (crctx, 0, sizeof (*crctx));
  idx = crctx - wc->crypto_ctx_pool;
  crctx->crctx_index = QUIC_CRCTX_CTX_INDEX_ENCODE (thread_index, idx);
  QUIC_DBG (2, "crctx %p, crctx_ndx 0x%08x thread %u", crctx,
	    crctx->crctx_index, thread_index);

  return crctx;
}

static void
quic_openssl_crypto_context_free (quic_main_t *qm, crypto_context_t *crctx)
{
  clib_thread_index_t thread_index =
    QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (crctx->crctx_index);
  quic_worker_ctx_t *wc = quic_wrk_ctx_get (qm, thread_index);

  quic_openssl_crypto_context_cleanup (crctx);

  QUIC_DBG (2,
	    "Freeing crypto context: crctx %p, "
	    "crctx_ndx 0x%08x, thread %u",
	    crctx, crctx->crctx_index, thread_index);
  pool_put (wc->crypto_ctx_pool, crctx);
}

int
quic_openssl_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  quic_main_t *qm = qom->qm;
  quic_openssl_crypto_context_data_t *data =
    (quic_openssl_crypto_context_data_t *) &crctx->data;
  u8 is_server = quic_ctx_is_listener (ctx) != 0;
  char *role = is_server ? "server" : "client";

  QUIC_DBG (2, "Initializing: %s, crctx_ndx 0x%08x, thread %u", role,
	    crctx->crctx_index, ctx->c_thread_index);

  u8 empty_key[32] = {};
  u64 i;
  vec_validate (qom->per_thread_crypto_key_indices, qm->num_threads);
  for (i = 0; i < qm->num_threads; i++)
    {
      qom->per_thread_crypto_key_indices[i] = vnet_crypto_key_add (
	vlib_get_main (), VNET_CRYPTO_ALG_AES_256_CTR, empty_key, 32);
    }

  data->is_server = is_server;

  data->ssl_ctx = quic_openssl_create_ssl_ctx (is_server);
  if (!data->ssl_ctx)
    {
      QUIC_ERR ("Failed create_ssl_ctx: %s, crctx_ndx 0x%08x, thread %u", role,
		crctx->crctx_index, ctx->c_thread_index);
      return -1;
    }

  data->ssl_conn = is_server ?
		     SSL_new_listener (data->ssl_ctx, data->listener_flags) :
		     SSL_new (data->ssl_ctx);
  ctx->conn = data->ssl_conn;
  data->rbio = BIO_new (BIO_s_datagram ());
  data->wbio = BIO_new (BIO_s_datagram ());

  if (!data->rbio || !data->wbio)
    {
      QUIC_ERR ("Failed SSL BIOs create: %s, crctx_ndx 0x%08x, thread %u",
		role, crctx->crctx_index, ctx->c_thread_index);
      if (data->rbio)
	BIO_free (data->rbio);
      if (data->wbio)
	BIO_free (data->wbio);
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      return -1;
    }

  BIO_set_nbio (data->rbio, 1);
  BIO_set_nbio (data->wbio, 1);

  // Set ALPN protocols on the connection
  if (!is_server && SSL_set_alpn_protos (data->ssl_conn, qom->alpn_protos,
					 vec_len (qom->alpn_protos)) != 0)
    {
      QUIC_ERR ("Failed SSL_set_alpn_protos: %s, crctx_ndx 0x%08x, thread %u",
		role, crctx->crctx_index, ctx->c_thread_index);
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      return -1;
    }

  // Generate connection ID key
  if (RAND_bytes ((unsigned char *) data->cid_key, QUIC_OPENSSL_IV_LEN) != 1)
    {
      QUIC_ERR ("Failed CID key gen: %s, crctx_ndx 0x%08x, thread %u", role,
		crctx->crctx_index, ctx->c_thread_index);
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      return -1;
    }

  data->is_initialized = 1;

  QUIC_DBG (2, "Complete: %s, crctx_ndx 0x%08x, thread %u", role,
	    crctx->crctx_index, ctx->c_thread_index);
  return 0;
}

int
quic_openssl_crypto_context_acquire (quic_ctx_t *ctx)
{
  /* import from src/vnet/session/application.c */
  extern u8 *format_crypto_engine (u8 * s, va_list * args);

  quic_openssl_main_t *qom = &quic_openssl_main;
  quic_main_t *qm = qom->qm;
  clib_bihash_24_8_t *crctx_hash = qom->crypto_ctx_hash;
  crypto_context_t *crctx = 0;
  clib_bihash_kv_24_8_t kv;
  quic_openssl_crypto_context_data_t *data;
  char *role = quic_ctx_is_listener (ctx) ? "server" : "client";

  QUIC_DBG (2, "Acquiring: %s, thread %u", role, ctx->c_thread_index);

  if (PREDICT_FALSE (ctx->crypto_engine == CRYPTO_ENGINE_NONE))
    {
      QUIC_DBG (2, "No crypto engine cfg, using %U: %s, thread %u",
		format_crypto_engine, qm->default_crypto_engine, role,
		ctx->c_thread_index);
      ctx->crypto_engine = qm->default_crypto_engine;
    }
  // TODO: FIXME available crypto engines
  // if (!clib_bitmap_get (qom->available_crypto_engines, ctx->crypto_engine))
  //   {
  //     QUIC_DBG (1, "Quic does not support crypto engine %U",
  // format_crypto_engine, ctx->crypto_engine);
  //     return SESSION_E_NOCRYPTOENG;
  //   }
  /* Check for exisiting crypto ctx */
  quic_crypto_context_make_key_from_ctx (&kv, ctx);
  if (clib_bihash_search_24_8 (&crctx_hash[ctx->c_thread_index], &kv, &kv) ==
      0)
    {
      crctx = quic_openssl_crypto_context_get (kv.value);
      QUIC_DBG (2, "Found existing crctx: %s, thread %u, kv.value 0x%08x",
		role, crctx->crctx_index, kv.value);
      ctx->crctx_index = kv.value;
      crctx->n_subscribers++;
      return 0;
    }

  crctx = quic_openssl_crypto_context_alloc (qm, ctx->c_thread_index);
  data = (quic_openssl_crypto_context_data_t *) &crctx->data;
  ctx->crctx_index = crctx->crctx_index;
  kv.value = crctx->crctx_index;
  if (quic_openssl_init_crypto_context (crctx, ctx))
    goto error;
  if (vnet_app_add_cert_key_interest (ctx->ckpair_index, qm->app_index))
    goto error;
  crctx->n_subscribers++;
  clib_memcpy_fast (data->crctx_key, kv.key, sizeof (data->crctx_key));
  clib_bihash_add_del_24_8 (&crctx_hash[ctx->c_thread_index], &kv,
			    1 /* is_add */);

  // Set app data to link back to VPP contextcrctx->data.
  // TODO: FIXME: this will access freed memory if the crctx pool is expanded
  // while SSL holds onto the pointer. The app data should be the crctx_index
  // which would then get the crctx pool element to access the data.
  SSL_set_app_data (data->ssl_conn, ctx);

  QUIC_DBG (3, "Acquired: %s, crctx_ndx 0x%08x, thread %u, kv.value 0x%08x",
	    role, crctx->crctx_index, ctx->c_thread_index, kv.value);
  return 0;

error:
  QUIC_ERR ("Failed acquire: %s, crctx_ndx 0x%08x, thread %u, kv.value 0x%llx",
	    role, crctx->crctx_index, ctx->c_thread_index, kv.value);
  if (ctx->conn)
    {
      SSL_free (ctx->conn);
      ctx->conn = NULL;
    }
  quic_openssl_crypto_context_free (qm, crctx);
  return SESSION_E_NOCRYPTOCKP;
}

void
quic_openssl_crypto_context_release (u32 crctx_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  crypto_context_t *crctx;

  crctx = quic_openssl_crypto_context_get (crctx_index);
  QUIC_DBG (2, "Releasing: crctx %p, crctx_ndx 0x%08x, thread %u", crctx,
	    crctx_index, QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (crctx_index));
  if (crctx)
    {
      quic_openssl_crypto_context_free (qom->qm, crctx);
    }
}

void
quic_openssl_crypto_context_cleanup (crypto_context_t *crctx)
{
  quic_openssl_crypto_context_data_t *data =
    (quic_openssl_crypto_context_data_t *) &crctx->data;

  QUIC_DBG (2, "Clean up: crctx %p, crctx_ndx 0x%08x, thread %u", crctx,
	    crctx->crctx_index,
	    QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (crctx->crctx_index));

  if (data->ssl_ctx)
    {
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      BIO_free_all (data->rbio);
      BIO_free_all (data->wbio);
      data->rbio = NULL;
      data->wbio = NULL;
    }

  data->is_initialized = 0;
}
