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

static int
quic_openssl_validate_alpn (SSL *ssl)
{
  const unsigned char *alpn_selected;
  unsigned int alpn_len;

  SSL_get0_alpn_selected (ssl, &alpn_selected, &alpn_len);

  if (alpn_selected && alpn_len > 0)
    {
      char alpn_str[32];
      clib_memcpy (alpn_str, alpn_selected,
		   clib_min (alpn_len, sizeof (alpn_str) - 1));
      alpn_str[clib_min (alpn_len, sizeof (alpn_str) - 1)] = '\0';

      QUIC_DBG (2, "ALPN negotiated protocol: %s (length: %u)", alpn_str,
		alpn_len);

      // Validate against known protocols
      if (alpn_len == 2 && clib_memcmp (alpn_selected, "h3", 2) == 0)
	{
	  QUIC_DBG (3, "HTTP/3 protocol selected");
	  return 0;
	}
      else if (alpn_len == 3 && clib_memcmp (alpn_selected, "h3e", 3) == 0)
	{
	  QUIC_DBG (3, "HTTP/3 experimental protocol selected");
	  return 0;
	}
      else if (alpn_len == 8 &&
	       clib_memcmp (alpn_selected, "hq-inter", 8) == 0)
	{
	  QUIC_DBG (3, "QUIC interop protocol selected");
	  return 0;
	}
      else
	{
	  QUIC_DBG (1, "Unknown ALPN protocol negotiated: %s", alpn_str);
	  return -1;
	}
    }

  QUIC_DBG (1, "No ALPN protocol negotiated");
  return -1;
}

static int
quic_openssl_alpn_select_cb (SSL *ssl, const unsigned char **out,
			     unsigned char *outlen, const unsigned char *in,
			     unsigned int inlen, void *arg)
{
  // Supported protocols in preference order
  static const unsigned char supported_alpn[] = {
    3, 'h', '3', 'e',			      // h3e (HTTP/3 experimental)
    2, 'h', '3',			      // h3 (HTTP/3)
    8, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r' // hq-interop
  };

  if (SSL_select_next_proto ((unsigned char **) out, outlen, supported_alpn,
			     sizeof (supported_alpn), in,
			     inlen) == OPENSSL_NPN_NEGOTIATED)
    {
      QUIC_DBG (2, "ALPN negotiated: %.*s", *outlen, *out);
      return SSL_TLSEXT_ERR_OK;
    }

  QUIC_DBG (1, "No ALPN protocol match found");
  return SSL_TLSEXT_ERR_NOACK;
}

static void
quic_openssl_engine_init (quic_main_t *qm)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  qom->qm = qm;

  QUIC_DBG (2, "Initializing OpenSSL QUIC engine");

  // OpenSSL 3.5.0 initialization
  OPENSSL_init_ssl (
    OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

  // Use the correct OpenSSL 3.5.0 QUIC method
  qom->ssl_ctx = SSL_CTX_new (OSSL_QUIC_client_method ());
  if (!qom->ssl_ctx)
    {
      QUIC_ERR ("Failed to create SSL context");
      return;
    }

  // Set TLS 1.3 as required for QUIC
  SSL_CTX_set_min_proto_version (qom->ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version (qom->ssl_ctx, TLS1_3_VERSION);

  // OpenSSL 3.5.0 handles QUIC transport internally - no custom callbacks
  // needed

  // Configure verification
  SSL_CTX_set_verify (qom->ssl_ctx, SSL_VERIFY_PEER, NULL);

  // Set ALPN selection callback for server-side
  SSL_CTX_set_alpn_select_cb (qom->ssl_ctx, quic_openssl_alpn_select_cb, NULL);

  // Set default ALPN protocols for client-side
  const unsigned char alpn_protocols[] = {
    3, 'h', '3', 'e',			      // h3e (HTTP/3 experimental)
    2, 'h', '3',			      // h3 (HTTP/3)
    8, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r' // hq-interop
  };

  if (SSL_CTX_set_alpn_protos (qom->ssl_ctx, alpn_protocols,
			       sizeof (alpn_protocols)) != 0)
    {
      QUIC_ERR ("Failed to set default ALPN protocols");
      SSL_CTX_free (qom->ssl_ctx);
      qom->ssl_ctx = NULL;
      return;
    }

  qom->num_threads = qm->num_threads;
  qom->available_crypto_engines = clib_bitmap_alloc (
    qom->available_crypto_engines, app_crypto_engine_n_types ());
  QUIC_DBG (3, "OpenSSL QUIC engine initialized with %u threads",
	    qom->num_threads);
}

static void
quic_openssl_debug_connection (quic_ctx_t *ctx)
{
  if (!ctx->conn)
    {
      QUIC_DBG (1, "No active connection in context %u", ctx->c_c_index);
      return;
    }

  SSL *ssl_conn = (SSL *) ctx->conn;
  char cipher_name[128];
  const unsigned char *alpn_selected;
  unsigned int alpn_len;

  const SSL_CIPHER *cipher = SSL_get_current_cipher (ssl_conn);
  if (cipher)
    {
      SSL_CIPHER_description (cipher, cipher_name, sizeof (cipher_name));
    }
  else
    {
      snprintf (cipher_name, sizeof (cipher_name), "unknown");
    }

  // Get ALPN information
  SSL_get0_alpn_selected (ssl_conn, &alpn_selected, &alpn_len);

  QUIC_DBG (2, "QUIC Connection Details:");
  QUIC_DBG (2, "  Handle: %p", ssl_conn);
  QUIC_DBG (2, "  Context: %u (thread %u)", ctx->c_c_index,
	    ctx->c_thread_index);
  QUIC_DBG (2, "  Cipher: %s", cipher_name);

  if (alpn_selected && alpn_len > 0)
    {
      char alpn_str[32];
      clib_memcpy (alpn_str, alpn_selected,
		   clib_min (alpn_len, sizeof (alpn_str) - 1));
      alpn_str[clib_min (alpn_len, sizeof (alpn_str) - 1)] = '\0';
      QUIC_DBG (2, "  ALPN: %s", alpn_str);
    }
  else
    {
      QUIC_DBG (2, "  ALPN: Not negotiated");
    }
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
    {
      QUIC_ERR ("Failed to create SSL connection");
      return -1;
    }

  // Set QUIC transport parameters
  SSL_set_app_data (qom->ssl_conn, ctx);

  // Enhanced ALPN configuration - support multiple protocols
  const unsigned char alpn_list[] = {
    3, 'h', '3', 'e',			      // h3e (HTTP/3 experimental)
    2, 'h', '3',			      // h3 (HTTP/3)
    8, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r' // hq-interop (QUIC interop)
  };

  if (SSL_set_alpn_protos (qom->ssl_conn, alpn_list, sizeof (alpn_list)) != 0)
    {
      QUIC_ERR ("Failed to set ALPN protocols");
      SSL_free (qom->ssl_conn);
      qom->ssl_conn = NULL;
      return -1;
    }

  QUIC_DBG (3, "ALPN protocols configured: h3e, h3, hq-interop");

  // Create and configure BIOs for datagram transport
  qom->rbio = BIO_new (BIO_s_datagram ());
  qom->wbio = BIO_new (BIO_s_datagram ());

  if (!qom->rbio || !qom->wbio)
    {
      QUIC_ERR ("Failed to create BIOs");
      SSL_free (qom->ssl_conn);
      qom->ssl_conn = NULL;
      return -1;
    }

  // Set BIOs for SSL connection
  SSL_set_bio (qom->ssl_conn, qom->rbio, qom->wbio);

  // Configure non-blocking mode
  BIO_set_nbio (qom->rbio, 1);
  BIO_set_nbio (qom->wbio, 1);

  // Store connection in context
  ctx->conn = qom->ssl_conn;

  QUIC_DBG (3, "Crypto context acquired successfully for ctx %u",
	    ctx->c_c_index);
  return 0;
}

static void
quic_openssl_crypto_context_release (u32 crypto_context_index, u8 thread_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  QUIC_DBG (3, "Releasing crypto context %u on thread %u",
	    crypto_context_index, thread_index);

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
      ret = BIO_ADDR_rawmake (bio_addr, AF_INET, &sin->sin_addr,
			      sizeof (sin->sin_addr), ntohs (sin->sin_port));
      if (ret != 1)
	{
	  BIO_ADDR_free (bio_addr);
	  return NULL;
	}
      break;

    case AF_INET6:
      sin6 = (const struct sockaddr_in6 *) sa;
      ret =
	BIO_ADDR_rawmake (bio_addr, AF_INET6, &sin6->sin6_addr,
			  sizeof (sin6->sin6_addr), ntohs (sin6->sin6_port));
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

  // Convert sockaddr to BIO_ADDR using the existing helper function
  bio_addr = sockaddr_to_bio_addr (sa);
  if (!bio_addr)
    {
      QUIC_ERR ("Failed to convert sockaddr to BIO_ADDR");
      return -1;
    }

  // Set initial peer address using OpenSSL 3.5.0 API
  if (!SSL_set1_initial_peer_addr (qom->ssl_conn, bio_addr))
    {
      QUIC_ERR ("Failed to set initial peer address");
      BIO_ADDR_free (bio_addr);
      return -1;
    }

  // Free the BIO_ADDR after use
  BIO_ADDR_free (bio_addr);

  // Start QUIC connection using OpenSSL 3.5.0 API
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

  // Validate ALPN negotiation after connection
  if (quic_openssl_validate_alpn (qom->ssl_conn) != 0)
    {
      QUIC_ERR ("ALPN validation failed for connection");
      return -1;
    }

  // Store connection in context for future reference
  ctx->conn = qom->ssl_conn;

  QUIC_DBG (2, "QUIC connection handle=%p successfully created for ctx %u",
	    ctx->conn, ctx_index);

  quic_openssl_debug_connection (ctx);
  return 0;
}

static int
quic_openssl_connect_stream (void *quic_conn, void **quic_stream,
			     quic_stream_data_t **quic_stream_data,
			     u8 is_unidir)
{
  SSL *ssl_conn = (SSL *) quic_conn;

  // Create new QUIC stream using OpenSSL 3.5.0 API
  SSL *stream = SSL_new_stream (ssl_conn, is_unidir ? SSL_STREAM_FLAG_UNI : 0);
  if (!stream)
    {
      QUIC_ERR ("Failed to create new QUIC stream");
      return -1;
    }

  *quic_stream = stream;
  QUIC_DBG (3, "Created new QUIC stream: %p (unidirectional: %u)", stream,
	    is_unidir);
  return 0;
}

#define QUIC_ERR_INTERNAL_STREAM_ERROR 0x1

static void
log_reset_args_details (const SSL_STREAM_RESET_ARGS *args, const char *when)
{
#if QUIC_DBG >= 1
  if (!args)
    {
      QUIC_DBG (4, "Reset args %s: NULL pointer", when);
      return;
    }

  QUIC_DBG (4, "Reset args %s:", when);
  QUIC_DBG (4, "  quic_error_code: 0x%llx",
	    (unsigned long long) args->quic_error_code);
  QUIC_DBG (4, "  struct_addr: %p", args);
  QUIC_DBG (4, "  struct_size: %zu bytes", sizeof (*args));

  // Log all potential fields by treating as array of uint64_t values
  const uint64_t *u64_fields = (const uint64_t *) args;
  size_t num_u64_fields = sizeof (*args) / sizeof (uint64_t);

  for (size_t i = 0; i < num_u64_fields; i++)
    {
      QUIC_DBG (4, "  u64_field[%zu]: 0x%016llx (%llu)", i,
		(unsigned long long) u64_fields[i],
		(unsigned long long) u64_fields[i]);
    }

  // Log remaining bytes if structure size is not multiple of uint64_t
  size_t remaining_bytes = sizeof (*args) % sizeof (uint64_t);
  if (remaining_bytes > 0)
    {
      const uint8_t *remaining =
	(const uint8_t *) args + (num_u64_fields * sizeof (uint64_t));
      char hex_str[32];
      char *p = hex_str;

      for (size_t i = 0;
	   i < remaining_bytes && (p - hex_str) < sizeof (hex_str) - 3; i++)
	{
	  p += snprintf (p, 4, "%02x ", remaining[i]);
	}
      *p = '\0';

      QUIC_DBG (4, "  remaining_bytes: %s", hex_str);
    }
#endif
}

static void
quic_openssl_connect_stream_error_reset (void *quic_stream)
{
  SSL *stream = (SSL *) quic_stream;

  SSL_STREAM_RESET_ARGS reset_args = {
    .quic_error_code = 0x01,
  };

  QUIC_DBG (3, "Resetting QUIC stream: %p with error code 0x%x", stream,
	    reset_args.quic_error_code);

  log_reset_args_details (&reset_args, "before reset");

  if (SSL_stream_reset (stream, &reset_args, sizeof (reset_args)) != 1)
    {
      QUIC_ERR ("Failed to reset QUIC stream: %p", stream);
      log_reset_args_details (&reset_args, "after failed reset");

      // Get additional SSL error information
      unsigned long ssl_err = ERR_get_error ();
      if (ssl_err != 0)
	{
	  char err_buf[256];
	  ERR_error_string_n (ssl_err, err_buf, sizeof (err_buf));
	  QUIC_ERR ("SSL error: %s", err_buf);
	}
    }
  else
    {
      QUIC_DBG (3, "Successfully reset QUIC stream: %p", stream);
      log_reset_args_details (&reset_args, "after successful reset");
    }
}

static void
quic_openssl_connection_get_stats (void *conn, quic_stats_t *stats)
{
  SSL *ssl_conn = (SSL *) conn;

  // OpenSSL 3.5.0 doesn't have SSL_get_params for QUIC stats
  // Use available OpenSSL QUIC APIs to get connection statistics

  // Initialize stats to default values
  stats->rtt_smoothed = 0;

  // Try to get RTT using SSL_get_handshake_rtt (if available)
  uint64_t rtt = 0;
  if (SSL_get_handshake_rtt (ssl_conn, &rtt) == 1)
    {
      stats->rtt_smoothed = rtt;
      QUIC_DBG (4, "Retrieved handshake RTT: %lu", rtt);
    }
  else
    {
      QUIC_DBG (4, "Handshake RTT not available");
    }

  // For other statistics, OpenSSL 3.5.0 QUIC may not expose them directly
  // You might need to use implementation-specific methods or wait for
  // future OpenSSL versions that expose more QUIC statistics

  QUIC_DBG (4, "Retrieved connection stats: RTT=%lu", stats->rtt_smoothed);
}

static int
quic_openssl_udp_session_rx_packets (session_t *udp_session)
{
  quic_openssl_main_t *qom = &quic_openssl_main;

  // Process received UDP packets through QUIC using OpenSSL 3.5.0 API
  int ret = SSL_handle_events (qom->ssl_conn);
  if (ret <= 0)
    {
      int err = SSL_get_error (qom->ssl_conn, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	{
	  QUIC_ERR ("SSL_handle_events failed with error %d", err);
	  return -1;
	}
    }

  return ret;
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