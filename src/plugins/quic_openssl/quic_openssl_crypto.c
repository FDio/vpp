/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <quic/quic_inlines.h>
#include <quic_openssl/quic_openssl.h>
#include <quic_openssl/quic_openssl_crypto.h>
#include <vppinfra/pool.h>
#include <vnet/session/application_interface.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/quic.h>

typedef struct quic_openssl_crypto_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  crypto_context_t *crypto_ctx_pool;
} quic_openssl_crypto_worker_ctx_t;

static quic_openssl_crypto_worker_ctx_t *quic_openssl_crypto_wrk_ctx;

static int
quic_openssl_alpn_select_cb (SSL *ssl, const unsigned char **out,
			     unsigned char *outlen, const unsigned char *in,
			     unsigned int inlen, void *arg)
{
  if (SSL_select_next_proto ((unsigned char **) out, outlen, alpn_protocols,
			     alpn_protocols_len, in,
			     inlen) == OPENSSL_NPN_NEGOTIATED)
    {
      QUIC_DBG (2, "ALPN negotiated: %.*s", *outlen, *out);
      return SSL_TLSEXT_ERR_OK;
    }

  QUIC_DBG (1, "No ALPN protocol match found");
  return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX *
quic_openssl_create_ssl_ctx (u8 is_server)
{
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

  if (is_server)
    {
      if (!SSL_CTX_set_ciphersuites (
	    ssl_ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"))
	{
	  QUIC_ERR ("Failed to set SSL server ciphersuites");
	  SSL_CTX_free (ssl_ctx);
	  return NULL;
	}
      // TODO: Load certificate and key
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_NONE, NULL);
      SSL_CTX_set_alpn_select_cb (ssl_ctx, quic_openssl_alpn_select_cb, NULL);
    }
  else
    {
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

  if (SSL_CTX_set_alpn_protos (ssl_ctx, alpn_protocols, alpn_protocols_len) !=
      0)
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
  quic_openssl_crypto_worker_ctx_t *cwctx;

  if (!quic_openssl_crypto_wrk_ctx)
    {
      vec_validate (quic_openssl_crypto_wrk_ctx, qm->num_threads - 1);
    }

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  pool_init_fixed (cwctx->crypto_ctx_pool,
		   QUIC_CRYPTO_CTX_POOL_PER_THREAD_SIZE);

  QUIC_DBG (2, "Initialized OpenSSL crypto context pool for thread %u",
	    thread_index);
}

static crypto_context_t *
quic_openssl_crypto_context_alloc (quic_main_t *qm, u8 thread_index)
{
  quic_openssl_crypto_worker_ctx_t *cwctx;
  crypto_context_t *crctx;
  u32 idx;

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  pool_get_aligned_safe (cwctx->crypto_ctx_pool, crctx, CLIB_CACHE_LINE_BYTES);

  clib_memset (crctx, 0, sizeof (*crctx));
  idx = crctx - cwctx->crypto_ctx_pool;
  crctx->ctx_index = ((u32) thread_index) << 24 | idx;
  QUIC_DBG (3, "Allocated OpenSSL crypto context %u on thread %u", idx,
	    thread_index);

  return crctx;
}

static void
quic_openssl_crypto_context_free (quic_main_t *qm, crypto_context_t *crctx)
{
  quic_openssl_crypto_worker_ctx_t *cwctx;
  u8 thread_index = vlib_get_thread_index ();

  QUIC_DBG (3, "Freeing OpenSSL crypto context %u on thread %u",
	    crctx->ctx_index, thread_index);

  // Cleanup any OpenSSL resources
  quic_openssl_crypto_context_cleanup (crctx);

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  if (CLIB_DEBUG)
    clib_memset (crctx, 0xfb, sizeof (*crctx));
  pool_put (cwctx->crypto_ctx_pool, crctx);
}

int
quic_openssl_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_openssl_crypto_context_data_t *data =
    (quic_openssl_crypto_context_data_t *) &crctx->data;
  u8 is_server = quic_ctx_is_listener (ctx);

  QUIC_DBG (3, "Initializing OpenSSL crypto context %u (server: %u)",
	    crctx->ctx_index, is_server);

  data->is_server = is_server;

  data->ssl_ctx = quic_openssl_create_ssl_ctx (is_server);
  if (!data->ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context for crypto context %u",
		crctx->ctx_index);
      return -1;
    }

  data->rbio = BIO_new (BIO_s_datagram ());
  data->wbio = BIO_new (BIO_s_datagram ());

  if (!data->rbio || !data->wbio)
    {
      QUIC_ERR ("Failed to create BIOs for crypto context %u",
		crctx->ctx_index);
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
  if (!is_server && SSL_set_alpn_protos (data->ssl_conn, alpn_protocols,
					 alpn_protocols_len) != 0)
    {
      QUIC_ERR (
	"Failed to set ALPN protocols on SSL connection for crypto context %u",
	crctx->ctx_index);
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      return -1;
    }

  // Generate connection ID key
  if (RAND_bytes ((unsigned char *) data->cid_key, QUIC_OPENSSL_IV_LEN) != 1)
    {
      QUIC_ERR ("Failed to generate CID key for crypto context %u",
		crctx->ctx_index);
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      return -1;
    }

  data->is_initialized = 1;

  QUIC_DBG (3, "Successfully initialized OpenSSL crypto context %u",
	    crctx->ctx_index);
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
  crypto_context_t *crctx;
  clib_bihash_kv_24_8_t kv;
  quic_openssl_crypto_context_data_t *data;
  u8 is_server = quic_ctx_is_listener (ctx);

  QUIC_DBG (3, "Acquiring crypto context for ctx %u (server: %u)",
	    ctx->c_c_index, is_server);

  if (PREDICT_FALSE (ctx->crypto_engine == CRYPTO_ENGINE_NONE))
    {
      QUIC_DBG (2, "No crypto engine specified, using %U",
		format_crypto_engine, qm->default_crypto_engine);
      ctx->crypto_engine = qm->default_crypto_engine;
    }
  if (!clib_bitmap_get (qom->available_crypto_engines, ctx->crypto_engine))
    {
      QUIC_DBG (1, "Quic does not support crypto engine %U",
		format_crypto_engine, ctx->crypto_engine);
      return SESSION_E_NOCRYPTOENG;
    }
  /* Check for exisiting crypto ctx */
  quic_crypto_context_make_key_from_ctx (&kv, ctx);
  if (clib_bihash_search_24_8 (&crctx_hash[ctx->c_thread_index], &kv, &kv) ==
      0)
    {
      crctx = quic_openssl_crypto_context_get (kv.value, ctx->c_thread_index);
      QUIC_DBG (2, "Found exisiting crypto context %d", kv.value);
      ctx->crctx_index = kv.value;
      crctx->n_subscribers++;
      return 0;
    }

  crctx = quic_openssl_crypto_context_alloc (qm, ctx->c_thread_index);
  data = (quic_openssl_crypto_context_data_t *) &crctx->data;
  ctx->crctx_index = crctx->ctx_index;
  kv.value = crctx->ctx_index;
  if (quic_openssl_init_crypto_context (crctx, ctx))
    goto error;
  if (vnet_app_add_cert_key_interest (ctx->ckpair_index, qm->app_index))
    goto error;
  crctx->n_subscribers++;
  clib_memcpy_fast (data->crctx_key, kv.key, sizeof (data->crctx_key));
  clib_bihash_add_del_24_8 (&crctx_hash[ctx->c_thread_index], &kv,
			    1 /* is_add */);

  data->ssl_conn = is_server ?
		     SSL_new_listener (data->ssl_ctx, data->listener_flags) :
		     SSL_new (data->ssl_ctx);
  ctx->conn = data->ssl_conn;

  // Set app data to link back to VPP contextcrctx->data.
  // TODO: FIXME: this will access freed memory if the crctx pool is expanded
  // while SSL holds onto the pointer. The app data should be the crctx_index
  // which would then get the crctx pool element to access the data.
  SSL_set_app_data (data->ssl_conn, ctx);

  QUIC_DBG (3, "Crypto context acquired successfully for ctx %u",
	    ctx->c_c_index);
  return 0;

error:
  QUIC_ERR ("Failed to initialize crypto context for ctx %u", ctx->c_c_index);
  quic_openssl_crypto_context_free (qm, crctx);
  return SESSION_E_NOCRYPTOCKP;
}

void
quic_openssl_crypto_context_release (u32 crctx_index, u8 thread_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  crypto_context_t *crctx;

  QUIC_DBG (3, "Releasing crypto context %u on thread %u", crctx_index,
	    thread_index);

  crctx = quic_openssl_crypto_context_get (crctx_index, thread_index);
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

  QUIC_DBG (3, "Cleaning up OpenSSL crypto context %u", crctx->ctx_index);

  if (data->ssl_ctx)
    {
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
      BIO_free_all (
	data->rbio); // TDOD: Verify if this is freed by SSL_CTX_free()
      BIO_free_all (data->wbio);
      data->rbio = NULL;
      data->wbio = NULL;
    }

  data->is_initialized = 0;
}
