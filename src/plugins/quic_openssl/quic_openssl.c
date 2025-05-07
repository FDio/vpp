/* SPDX-License-Identifier: Apache-2.0
Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <quic/quic.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

/* Main struct for openssl engine, if needed */
typedef struct
{
  quic_main_t *qm;
  SSL_CTX *ssl_ctx;
  SSL *ssl_conn;
  BIO *rbio;
  BIO *wbio;
  u32 num_threads;
  clib_bitmap_t *available_crypto_engines;
} quic_openssl_main_t;

quic_openssl_main_t quic_openssl_main;

static void
quic_openssl_engine_init (quic_main_t *qm)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  qom->qm = qm;

  // Initialize OpenSSL library
  SSL_library_init ();
  SSL_load_error_strings ();

  // Create SSL context using QUIC method
  qom->ssl_ctx = SSL_CTX_new (OSSL_QUIC_client_method ());
  if (!qom->ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context");
      return;
    }

  qom->num_threads = qm->num_threads;
  qom->available_crypto_engines =
    clib_bitmap_alloc (app_crypto_engine_n_types ());
}

static int
quic_openssl_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair)
{
  // Remove certificate and key from SSL context
  SSL_CTX_free (quic_openssl_main.ssl_ctx);
  return 0;
}

static int
quic_openssl_crypto_context_acquire (quic_ctx_t *ctx)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Create new SSL connection
  qom->ssl_conn = SSL_new (qom->ssl_ctx);
  if (!qom->ssl_conn)
    return -1;

  // Create datagram BIOs for network I/O
  qom->rbio = BIO_new (BIO_s_datagram ());
  qom->wbio = BIO_new (BIO_s_datagram ());

  if (!qom->rbio || !qom->wbio)
    {
      SSL_free (qom->ssl_conn);
      return -1;
    }

  // Set BIOs for SSL connection
  SSL_set_bio (qom->ssl_conn, qom->rbio, qom->wbio);

  // Configure non-blocking mode
  BIO_set_nbio (qom->rbio, 1);
  BIO_set_nbio (qom->wbio, 1);

  return 0;
}

static void
quic_openssl_crypto_context_release (u32 crypto_context_index, u8 thread_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  if (qom->ssl_conn)
    {
      SSL_free (qom->ssl_conn);
      qom->ssl_conn = NULL;
    }
}

static int
quic_openssl_connect (quic_ctx_t *ctx, u32 ctx_index,
		      clib_thread_index_t thread_index, struct sockaddr *sa)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  int ret;

  // Set initial peer address
  SSL_set1_initial_peer_addr (qom->ssl_conn, sa);

  // Start QUIC connection
  ret = SSL_connect (qom->ssl_conn);
  if (ret <= 0)
    {
      int err = SSL_get_error (qom->ssl_conn, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	{
	  return -1;
	}
    }

  return 0;
}

static int
quic_openssl_connect_stream (void *quic_conn, void **quic_stream,
			     quic_stream_data_t **quic_stream_data,
			     u8 is_unidir)
{
  SSL *ssl_conn = (SSL *) quic_conn;

  // Create new QUIC stream
  SSL *stream =
    SSL_new_stream (ssl_conn, is_unidir ? QUIC_STREAM_UNIDIRECTIONAL :
					  QUIC_STREAM_BIDIRECTIONAL);
  if (!stream)
    return -1;

  *quic_stream = stream;
  return 0;
}

static void
quic_openssl_connect_stream_error_reset (void *quic_stream)
{
  SSL *stream = (SSL *) quic_stream;
  SSL_stream_reset (stream, QUIC_ERR_INTERNAL_ERROR);
}

static int
quic_openssl_connection_receive (quic_ctx_t *ctx)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Handle QUIC events (timeouts, network I/O)
  return SSL_handle_events (qom->ssl_conn);
}

static int
quic_openssl_connection_get_stats (void *conn, u32 *stats)
{
  SSL *ssl_conn = (SSL *) conn;
  // Get connection stats from OpenSSL
  // TODO: Implement stats collection
  return 0;
}

static int
quic_openssl_udp_session_rx_packets (session_t *udp_session)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Process received UDP packets through QUIC
  return SSL_handle_events (qom->ssl_conn);
}

static void
quic_openssl_ack_rx_data (quic_ctx_t *ctx, session_t *stream_session)
{
  // ACK received data
  // No explicit ACK needed as OpenSSL QUIC handles this internally
}

static int
quic_openssl_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  u8 buf[QUIC_MAX_PACKET_SIZE];
  int ret;

  // Write data to QUIC stream
  ret = SSL_write (qom->ssl_conn, buf, sizeof (buf));
  if (ret <= 0)
    {
      int err = SSL_get_error (qom->ssl_conn, ret);
      if (err != SSL_ERROR_WANT_WRITE)
	return -1;
    }

  return ret;
}

static int
quic_openssl_send_packets (quic_ctx_t *ctx)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Trigger packet sending
  return SSL_handle_events (qom->ssl_conn);
}

static u8 *
quic_openssl_format_connection_stats (u8 *s, void *conn, int verbose)
{
  // Format connection statistics
  // TODO: Implement stats formatting
  return s;
}

static u8 *
quic_openssl_format_stream_connection (u8 *s, void *stream)
{
  SSL *ssl_stream = (SSL *) stream;
  u64 stream_id = SSL_get_stream_id (ssl_stream);
  s = format (s, "Stream ID: %lu", stream_id);
  return s;
}

static u8 *
quic_openssl_format_stream_ctx_stream_id (u8 *s, void *stream)
{
  SSL *ssl_stream = (SSL *) stream;
  u64 stream_id = SSL_get_stream_id (ssl_stream);
  s = format (s, "%lu", stream_id);
  return s;
}

static void
quic_openssl_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Close QUIC connection with normal shutdown
  if (qom->ssl_conn)
    {
      SSL_shutdown_ex (qom->ssl_conn, SSL_SHUTDOWN_FLAG_RAPID, 0, NULL);
      SSL_free (qom->ssl_conn);
      qom->ssl_conn = NULL;
    }
}

/* --- VFT Registration --- */

const static quic_engine_vft_t quic_openssl_engine_vft = {
  .engine_init = quic_openssl_engine_init,
  .app_cert_key_pair_delete = quic_openssl_app_cert_key_pair_delete,
  .crypto_context_acquire = quic_openssl_crypto_context_acquire,
  .crypto_context_release = quic_openssl_crypto_context_release,
  .connect = quic_openssl_connect,
  .connect_stream = quic_openssl_connect_stream,
  .connect_stream_error_reset = quic_openssl_connect_stream_error_reset,
  .connection_receive = quic_openssl_connection_receive,
  .connection_get_stats = quic_openssl_connection_get_stats,
  .udp_session_rx_packets = quic_openssl_udp_session_rx_packets,
  .ack_rx_data = quic_openssl_ack_rx_data,
  .stream_tx = quic_openssl_stream_tx,
  .send_packets = quic_openssl_send_packets,
  .format_connection_stats = quic_openssl_format_connection_stats,
  .format_stream_connection = quic_openssl_format_stream_connection,
  .format_stream_ctx_stream_id = quic_openssl_format_stream_ctx_stream_id,
  .proto_on_close = quic_openssl_proto_on_close,
};

static clib_error_t *
quic_openssl_init (vlib_main_t *vm)
{
  quic_register_engine_fn register_engine;

  register_engine =
    vlib_get_plugin_symbol ("quic_plugin.so", "quic_register_engine");
  if (register_engine == 0)
    {
      clib_warning ("quic_plugin.so not loaded...");
      return clib_error_return (0, "Unable to get plugin symbol: "
				   "'quic_register_engine'");
    }
  (*register_engine) (&quic_openssl_engine_vft, QUIC_ENGINE_OPENSSL);

  return 0;
}

VLIB_INIT_FUNCTION (quic_openssl_init) = {
  .runs_after = VLIB_INITS ("quic_init"),
};