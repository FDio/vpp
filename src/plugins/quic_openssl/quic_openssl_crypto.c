/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <quic_openssl/quic_openssl_crypto.h>
#include <quic_openssl/quic_openssl.h>
#include <vppinfra/pool.h>
#include <vnet/session/application_interface.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/quic.h>

typedef struct quic_openssl_crypto_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  quic_openssl_crypto_context_t *crypto_ctx_pool;
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

  if (is_server)
    ssl_ctx = SSL_CTX_new (OSSL_QUIC_server_method ());
  else
    ssl_ctx = SSL_CTX_new (OSSL_QUIC_client_method ());

  if (!ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context");
      return NULL;
    }

  SSL_CTX_set_min_proto_version (ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version (ssl_ctx, TLS1_3_VERSION);

  if (is_server)
    {
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

u32
quic_openssl_crypto_context_alloc (quic_main_t *qm, u8 thread_index)
{
  quic_openssl_crypto_worker_ctx_t *cwctx;
  quic_openssl_crypto_context_t *crctx;

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  pool_get_aligned_safe (cwctx->crypto_ctx_pool, crctx, CLIB_CACHE_LINE_BYTES);

  clib_memset (crctx, 0, sizeof (*crctx));
  crctx->ctx_index = crctx - cwctx->crypto_ctx_pool;
  crctx->thread_index = thread_index;

  QUIC_DBG (3, "Allocated OpenSSL crypto context %u on thread %u",
	    crctx->ctx_index, thread_index);

  return crctx->ctx_index;
}

void
quic_openssl_crypto_context_free (quic_main_t *qm,
				  quic_openssl_crypto_context_t *crctx)
{
  quic_openssl_crypto_worker_ctx_t *cwctx;
  u8 thread_index = crctx->thread_index;

  QUIC_DBG (3, "Freeing OpenSSL crypto context %u on thread %u",
	    crctx->ctx_index, thread_index);

  // Cleanup any OpenSSL resources
  quic_openssl_crypto_context_cleanup (crctx);

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  if (CLIB_DEBUG)
    clib_memset (crctx, 0xfb, sizeof (*crctx));
  pool_put (cwctx->crypto_ctx_pool, crctx);
}

quic_openssl_crypto_context_t *
quic_openssl_crypto_context_get_impl (u32 ctx_index, u8 thread_index)
{
  quic_openssl_crypto_worker_ctx_t *cwctx;

  cwctx = &quic_openssl_crypto_wrk_ctx[thread_index];
  return pool_elt_at_index (cwctx->crypto_ctx_pool, ctx_index);
}

int
quic_openssl_crypto_context_init (quic_openssl_crypto_context_t *crctx,
				  u8 is_server)
{
  quic_openssl_crypto_context_data_t *data = &crctx->data;

  QUIC_DBG (3, "Initializing OpenSSL crypto context %u (server: %u)",
	    crctx->ctx_index, is_server);

  data->is_server = is_server;

  // Create SSL context
  data->ssl_ctx = quic_openssl_create_ssl_ctx (is_server);
  if (!data->ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context for crypto context %u",
		crctx->ctx_index);
      return -1;
    }

  // Create SSL connection
  data->ssl_conn = SSL_new (data->ssl_ctx);
  if (!data->ssl_conn)
    {
      QUIC_ERR ("Failed to create SSL connection for crypto context %u",
		crctx->ctx_index);
      return -1;
    }

  // Create BIOs
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
      SSL_free (data->ssl_conn);
      data->ssl_conn = NULL;
      return -1;
    }

  SSL_set_bio (data->ssl_conn, data->rbio, data->wbio);

  // Configure non-blocking mode
  BIO_set_nbio (data->rbio, 1);
  BIO_set_nbio (data->wbio, 1);

  // Set ALPN protocols on the connection
  if (!is_server && SSL_set_alpn_protos (data->ssl_conn, alpn_protocols,
					 alpn_protocols_len) != 0)
    {
      QUIC_ERR (
	"Failed to set ALPN protocols on SSL connection for crypto context %u",
	crctx->ctx_index);
      SSL_free (data->ssl_conn);
      data->ssl_conn = NULL;
      return -1;
    }

  // Generate connection ID key
  if (RAND_bytes ((unsigned char *) data->cid_key, QUIC_OPENSSL_IV_LEN) != 1)
    {
      QUIC_ERR ("Failed to generate CID key for crypto context %u",
		crctx->ctx_index);
      SSL_free (data->ssl_conn);
      data->ssl_conn = NULL;
      return -1;
    }

  data->is_initialized = 1;

  QUIC_DBG (3, "Successfully initialized OpenSSL crypto context %u",
	    crctx->ctx_index);
  return 0;
}

void
quic_openssl_crypto_context_cleanup (quic_openssl_crypto_context_t *crctx)
{
  quic_openssl_crypto_context_data_t *data = &crctx->data;

  QUIC_DBG (3, "Cleaning up OpenSSL crypto context %u", crctx->ctx_index);

  if (data->ssl_conn)
    {
      SSL_free (data->ssl_conn); // This also frees the BIOs
      data->ssl_conn = NULL;
      data->rbio = NULL;
      data->wbio = NULL;
    }

  if (data->ssl_ctx)
    {
      SSL_CTX_free (data->ssl_ctx);
      data->ssl_ctx = NULL;
    }

  data->is_initialized = 0;
}
