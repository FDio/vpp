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
#include "quic_openssl.h"

quic_openssl_main_t quic_openssl_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Openssl QUIC Engine",
};

static void
quic_openssl_engine_init (quic_main_t *qm)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  qom->qm = qm;

  QUIC_DBG (2, "Initializing OpenSSL QUIC engine");

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
  qom->available_crypto_engines = clib_bitmap_alloc (
    qom->available_crypto_engines, app_crypto_engine_n_types ());
  QUIC_DBG (3, "OpenSSL QUIC engine initialized with %u threads", qom->num_threads);
}

static void
quic_openssl_debug_connection(quic_ctx_t *ctx)
{
  if (!ctx->conn)
    {
      QUIC_DBG(1, "No active connection in context %u", ctx->c_c_index);
      return;
    }

  SSL *ssl_conn = (SSL *)ctx->conn;
  char cipher_name[128];

  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl_conn);
  if (cipher)
    {
      SSL_CIPHER_description(cipher, cipher_name, sizeof(cipher_name));
    }
  else
    {
      snprintf(cipher_name, sizeof(cipher_name), "unknown");
    }

  QUIC_DBG(2, "QUIC Connection Details:");
  QUIC_DBG(2, "  Handle: %p", ssl_conn);
  QUIC_DBG(2, "  Context: %u (thread %u)", ctx->c_c_index, ctx->c_thread_index);
  QUIC_DBG(2, "  Cipher: %s", cipher_name);
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

  QUIC_DBG (3, "Acquiring crypto context for ctx %u", ctx->c_c_index);

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

  QUIC_DBG (3, "Releasing crypto context %u on thread %u", crypto_context_index, thread_index);

  if (qom->ssl_conn)
    {
      SSL_free (qom->ssl_conn);
      qom->ssl_conn = NULL;
    }
}

BIO_ADDR *
sockaddr_to_bio_addr (const struct sockaddr *sa)
{
  BIO_ADDR *bio_addr;
  const struct sockaddr_in *sin;
  const struct sockaddr_in6 *sin6;
  int ret;

  bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    return NULL;

  switch (sa->sa_family)
    {
    case AF_INET:
      sin = (const struct sockaddr_in *) sa;
      ret = BIO_ADDR_rawmake (bio_addr, AF_INET, &sin->sin_addr, sizeof (sin->sin_addr),
                            ntohs (sin->sin_port));
      if (ret != 1)
        {
          BIO_ADDR_free (bio_addr);
          return NULL;
        }
      break;

    case AF_INET6:
      sin6 = (const struct sockaddr_in6 *) sa;
      ret = BIO_ADDR_rawmake (bio_addr, AF_INET6, &sin6->sin6_addr, sizeof (sin6->sin6_addr),
                            ntohs (sin6->sin6_port));
      if (ret != 1)
        {
          BIO_ADDR_free (bio_addr);
          return NULL;
        }
      break;

    default:
      BIO_ADDR_free (bio_addr);
      return NULL;
    }

  return bio_addr;
}

static int
quic_openssl_connect (quic_ctx_t *ctx, u32 ctx_index,
		      clib_thread_index_t thread_index, struct sockaddr *sa)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  int ret;
  BIO_ADDR *bio_addr;

  QUIC_DBG (2, "Creating new QUIC connection for ctx %u on thread %u",
            ctx_index, thread_index);

  // Set initial peer address
  bio_addr = sockaddr_to_bio_addr (sa);
  if (!bio_addr) {
    QUIC_ERR ("Failed to convert sockaddr to BIO_ADDR");
    return -1;
  }

  SSL_set1_initial_peer_addr (qom->ssl_conn, bio_addr);
  BIO_ADDR_free (bio_addr);

  // Start QUIC connection
  ret = SSL_connect (qom->ssl_conn);
  if (ret <= 0)
    {
      int err = SSL_get_error (qom->ssl_conn, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	{
          QUIC_ERR ("SSL_connect failed with error %d", err);
	  return -1;
	}
    }

  // Store connection in context for future reference
  ctx->conn = qom->ssl_conn;

  QUIC_DBG (2, "QUIC connection handle=%p successfully created for ctx %u",
            ctx->conn, ctx_index);

  quic_openssl_debug_connection(ctx);
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
    SSL_new_stream (ssl_conn, is_unidir ? SSL_STREAM_TYPE_READ :
					  SSL_STREAM_TYPE_BIDI);
  if (!stream)
    return -1;

  *quic_stream = stream;
  return 0;
}

#define QUIC_ERR_INTERNAL_STREAM_ERROR 0x1

static void
quic_openssl_connect_stream_error_reset (void *quic_stream)
{
  SSL *stream = (SSL *) quic_stream;
  SSL_STREAM_RESET_ARGS args = {
    .quic_error_code = QUIC_ERR_INTERNAL_STREAM_ERROR
  };
  SSL_stream_reset (stream, &args, sizeof (args));
}


static void
quic_openssl_connection_get_stats (void *conn, quic_stats_t *stats)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  uint64_t rtt;

  if (SSL_get_handshake_rtt (qom->ssl_conn, &rtt) == 1)
    stats->rtt_smoothed = rtt;
  else
    stats->rtt_smoothed = 0;
}

static int
quic_openssl_udp_session_rx_packets (session_t *udp_session)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Process received UDP packets through QUIC
  return SSL_handle_events (qom->ssl_conn);
}

static void
quic_openssl_ack_rx_data (session_t *stream_session)
{
  // Implementation
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
quic_openssl_format_connection_stats (u8 *s, va_list *args)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  uint64_t rtt;

  s = format (s, "[OpenSSL QUIC]");
  if (SSL_get_handshake_rtt (qom->ssl_conn, &rtt) == 1)
    s = format (s, " RTT: %lu", rtt);
  else
    s = format (s, " RTT: N/A");

  return s;
}

static u8 *
quic_openssl_format_stream_connection (u8 *s, va_list *args)
{
  // Implementation
  return s;
}

static u8 *
quic_openssl_format_stream_ctx_stream_id (u8 *s, va_list *args)
{
  // Implementation
  return s;
}

static void
quic_openssl_proto_on_close (u32 ctx_index, clib_thread_index_t thread_index)
{
  // Implementation
}

static void
quic_openssl_connection_migrate (quic_ctx_t *ctx)
{
  /* Not implemented yet */
  return;
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
  .connection_migrate = quic_openssl_connection_migrate,
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