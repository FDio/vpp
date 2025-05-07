/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <quic/quic.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>
#include <vppinfra/pool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/quic.h>
#include <quic_openssl/quic_openssl.h>
#include <quic_openssl/quic_openssl_crypto.h>

quic_openssl_main_t quic_openssl_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Openssl QUIC Engine",
};

const unsigned char alpn_protocols[] = {
  3, 'h', '3', 'e',			    // h3e (HTTP/3 experimental)
  2, 'h', '3',				    // h3 (HTTP/3)
  8, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r' // hq-interop
};

const u32 alpn_protocols_len = sizeof (alpn_protocols);

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

static void
quic_openssl_engine_init (quic_main_t *qm)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, num_threads = 1 /* main thread */ + vtm->n_threads;

  qom->qm = qm;

  QUIC_DBG (2, "Initializing OpenSSL QUIC engine");

  OPENSSL_init_ssl (
    OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

  qom->num_threads = qm->num_threads;
  qom->available_crypto_engines = clib_bitmap_alloc (
    qom->available_crypto_engines, app_crypto_engine_n_types ());

  // Initialize crypto contexts for all threads
  for (i = 0; i < num_threads; i++)
    {
      quic_openssl_crypto_init_per_thread (qm, i);
    }

  QUIC_DBG (3, "OpenSSL QUIC engine initialized with %u threads",
        qom->num_threads);
}

static_always_inline void
quic_openssl_debug_connection (quic_ctx_t *ctx)
{
#if QUIC_DEBUG >= 1
  if (!ctx)
    {
      QUIC_DBG (1, "Context is NULL");
      return;
    }
  if (!ctx->conn)
    {
      QUIC_DBG (1, "No active connection in context %u", ctx->c_c_index);
      return;
    }

  SSL *ssl_conn = (SSL *) ctx->conn;
  const unsigned char *alpn_selected;
  unsigned int alpn_len;
  char cipher_name[128];

  if (!ssl_conn)
    {
      QUIC_DBG (1, "SSL connection is NULL in context %u", ctx->c_c_index);
      return;
    }
  const SSL_CIPHER *cipher = SSL_get_current_cipher (ssl_conn);
  if (cipher)
    {
      SSL_CIPHER_description (cipher, cipher_name, sizeof (cipher_name));
    }
  else
    {
      snprintf (cipher_name, sizeof (cipher_name), "unknown");
    }
  SSL_get0_alpn_selected (ssl_conn, &alpn_selected, &alpn_len);
  QUIC_DBG (1, "QUIC Connection Details:");
  QUIC_DBG (1, "  Handle: %p", ssl_conn);
  QUIC_DBG (1, "  Context: %u (thread %u)", ctx->c_c_index,
        ctx->c_thread_index);
  QUIC_DBG (1, "  Cipher: %s", cipher_name);

  if (alpn_selected && alpn_len > 0)
    {
      char alpn_str[32];
      clib_memcpy (alpn_str, alpn_selected,
           clib_min (alpn_len, sizeof (alpn_str) - 1));
      alpn_str[clib_min (alpn_len, sizeof (alpn_str) - 1)] = '\0';
      QUIC_DBG (1, "  ALPN: %s", alpn_str);
    }
  else
    {
      QUIC_DBG (1, "  ALPN: Not negotiated");
    }
#endif
}

static int
quic_openssl_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair)
{
  // OpenSSL certificate management is handled through SSL_CTX
  // This is primarily for cleanup notification
  QUIC_DBG (3, "Certificate key pair delete callback for ckpair %u",
            ckpair->cert_key_index);
  return 0;
}

static void
quic_openssl_connection_migrate (quic_ctx_t *ctx)
{
  // OpenSSL QUIC connection migration would be complex
  // For now, mark as not supported
  QUIC_ERR ("Connection migration not supported in OpenSSL engine");
}

static int
quic_openssl_crypto_context_acquire (quic_ctx_t *ctx)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  quic_openssl_crypto_context_t *crctx;
  u32 crctx_index;
  u8 is_server = quic_ctx_is_listener (ctx);

  QUIC_DBG (3, "Acquiring crypto context for ctx %u (server: %u)",
            ctx->c_c_index, is_server);

  // Allocate crypto context from the per-thread pool
  crctx_index = quic_openssl_crypto_context_alloc (qom->qm, ctx->c_thread_index);
  crctx = quic_openssl_crypto_context_get (crctx_index, ctx->c_thread_index);

  ctx->crypto_context_index = crctx_index;

  // Initialize the crypto context with server flag
  if (quic_openssl_crypto_context_init (crctx, is_server) != 0)
    {
      QUIC_ERR ("Failed to initialize crypto context for ctx %u", ctx->c_c_index);
      quic_openssl_crypto_context_free (qom->qm, crctx);
      return -1;
    }

  // Set the connection from crypto context
  ctx->conn = crctx->data.ssl_conn;

  // Set app data to link back to VPP context
  SSL_set_app_data (crctx->data.ssl_conn, ctx);

  QUIC_DBG (3, "Crypto context acquired successfully for ctx %u",
        ctx->c_c_index);
  return 0;
}

static void
quic_openssl_crypto_context_release (u32 crypto_context_index, u8 thread_index)
{
  quic_openssl_main_t *qom = &quic_openssl_main;
  quic_openssl_crypto_context_t *crctx;

  QUIC_DBG (3, "Releasing crypto context %u on thread %u",
        crypto_context_index, thread_index);

  crctx = quic_openssl_crypto_context_get (crypto_context_index, thread_index);
  if (crctx)
    {
      quic_openssl_crypto_context_free (qom->qm, crctx);
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
  quic_openssl_crypto_context_t *crctx;
  int ret;
  BIO_ADDR *bio_addr;

  QUIC_DBG (2, "Creating new QUIC connection for ctx %u on thread %u",
        ctx_index, thread_index);

  // First acquire crypto context
  if (quic_openssl_crypto_context_acquire (ctx) != 0)
    {
      QUIC_ERR ("Failed to acquire crypto context for connection");
      return -1;
    }

  crctx = quic_openssl_crypto_context_get (ctx->crypto_context_index,
                       ctx->c_thread_index);
  if (!crctx || !crctx->data.ssl_conn)
    {
      QUIC_ERR ("Invalid crypto context after acquisition");
      return -1;
    }

  bio_addr = sockaddr_to_bio_addr (sa);
  if (!bio_addr)
    {
      QUIC_ERR ("Failed to convert sockaddr to BIO_ADDR");
      return -1;
    }

  if (!SSL_set1_initial_peer_addr (crctx->data.ssl_conn, bio_addr))
    {
      QUIC_ERR ("Failed to set initial peer address");
      BIO_ADDR_free (bio_addr);
      return -1;
    }

  BIO_ADDR_free (bio_addr);

  ret = SSL_connect (crctx->data.ssl_conn);
  if (ret <= 0)
    {
      int err = SSL_get_error (crctx->data.ssl_conn, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
    {
      QUIC_ERR ("SSL_connect failed with error %d", err);
      return -1;
    }
    }

  if (quic_openssl_validate_alpn (crctx->data.ssl_conn) != 0)
    {
      QUIC_ERR ("ALPN validation failed for connection");
      return -1;
    }

  ctx->conn = crctx->data.ssl_conn;

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

  SSL *stream = SSL_new_stream (ssl_conn, is_unidir ? SSL_STREAM_FLAG_UNI : 0);
  if (!stream)
    {
      QUIC_ERR ("Failed to create new QUIC stream");
      return -1;
    }

  *quic_stream = stream;

  // Allocate stream data if requested
  if (quic_stream_data)
    {
      quic_stream_data_t *data = clib_mem_alloc (sizeof (quic_stream_data_t));
      clib_memset (data, 0, sizeof (quic_stream_data_t));
      *quic_stream_data = data;
    }

  QUIC_DBG (3, "Created new QUIC stream: %p (unidirectional: %u)", stream,
        is_unidir);
  return 0;
}

#define QUIC_ERR_INTERNAL_STREAM_ERROR 0x1

static_always_inline void
log_reset_args_details (const SSL_STREAM_RESET_ARGS *args, const char *when)
{
#if QUIC_DBG >= 1
  if (!args)
    {
      QUIC_DBG (3, "Reset args %s: NULL pointer", when);
      return;
    }

  QUIC_DBG (3, "Reset args %s:", when);
  QUIC_DBG (3, "  quic_error_code: 0x%llx",
           (unsigned long long) args->quic_error_code);
  QUIC_DBG (3, "  struct_addr: %p", args);
  QUIC_DBG (3, "  struct_size: %zu bytes", sizeof (*args));

  // Log all potential fields by treating as array of uint64_t values
  const uint64_t *u64_fields = (const uint64_t *) args;
  size_t num_u64_fields = sizeof (*args) / sizeof (uint64_t);

  for (size_t i = 0; i < num_u64_fields; i++)
    {
      QUIC_DBG (3, "  u64_field[%zu]: 0x%016llx (%llu)", i,
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

      QUIC_DBG (3, "  remaining_bytes: %s", hex_str);
    }
#endif
}

static void
quic_openssl_connect_stream_error_reset (void *quic_stream)
{
  SSL *stream = (SSL *) quic_stream;

  SSL_STREAM_RESET_ARGS reset_args = {
    .quic_error_code = QUIC_ERR_INTERNAL_STREAM_ERROR,
  };

  QUIC_DBG (3, "Resetting QUIC stream: %p with error code 0x%x", stream,
        reset_args.quic_error_code);

  log_reset_args_details (&reset_args, "before reset");

  if (SSL_stream_reset (stream, &reset_args, sizeof (reset_args)) != 1)
    {
      log_reset_args_details (&reset_args, "after failed reset");
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

static int
quic_openssl_send_packets (quic_ctx_t *ctx)
{
  quic_openssl_crypto_context_t *crctx;
  SSL *ssl_conn;
  session_t *udp_session;
  svm_fifo_t *f;
  u8 buf[QUIC_MAX_PACKET_SIZE];
  int bytes_read;
  int total_sent = 0;

  crctx = quic_openssl_crypto_context_get (ctx->crypto_context_index,
                       ctx->c_thread_index);
  if (!crctx || !crctx->data.ssl_conn)
    return -1;

  ssl_conn = crctx->data.ssl_conn;

  // Handle SSL events first
  SSL_handle_events (ssl_conn);

  // Get UDP session for sending
  udp_session = session_get_from_handle (ctx->udp_session_handle);
  if (!udp_session)
    return -1;

  f = udp_session->tx_fifo;

  // Read data from write BIO and send via UDP
  while ((bytes_read = BIO_read (crctx->data.wbio, buf, sizeof (buf))) > 0)
    {
      // Write to UDP session TX fifo
      session_dgram_hdr_t hdr;
      clib_memset (&hdr, 0, sizeof (hdr));
      hdr.data_length = bytes_read;
      hdr.data_offset = 0;

      if (svm_fifo_enqueue (f, sizeof (hdr), (u8 *) &hdr) != sizeof (hdr))
    break;

      if (svm_fifo_enqueue (f, bytes_read, buf) != bytes_read)
    break;

      total_sent += bytes_read;
    }

  if (total_sent > 0)
    {
      // Trigger TX event
      session_send_io_evt_to_thread (f, SESSION_IO_EVT_TX);
    }

  return total_sent;
}

static int
quic_openssl_udp_session_rx_packets (session_t *udp_session)
{
  svm_fifo_t *f = udp_session->rx_fifo;
  u32 max_deq;
  u32 cur_deq, fifo_offset = 0;
  session_dgram_hdr_t ph;
  u8 packet_data[QUIC_MAX_PACKET_SIZE];
  quic_ctx_t *ctx;
  quic_openssl_crypto_context_t *crctx;
  int rv = 0;

  if (udp_session->flags & SESSION_F_IS_MIGRATING)
    {
      QUIC_DBG (3, "RX on migrating udp session");
      return 0;
    }

  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq == 0)
    return 0;

  while (fifo_offset < max_deq)
    {
      cur_deq = max_deq - fifo_offset;
      if (cur_deq < SESSION_CONN_HDR_LEN)
    break;

      // Peek the packet header
      rv = svm_fifo_peek (f, fifo_offset, SESSION_CONN_HDR_LEN, (u8 *) &ph);
      if (rv != SESSION_CONN_HDR_LEN)
    break;

      u32 full_len = ph.data_length + SESSION_CONN_HDR_LEN;
      if (cur_deq < full_len)
    break;

      // Peek the packet data
      rv = svm_fifo_peek (f, fifo_offset + SESSION_CONN_HDR_LEN,
              ph.data_length, packet_data);
      if (rv != ph.data_length)
    break;

      // Get context from UDP session
      ctx = quic_openssl_get_quic_ctx (udp_session->opaque, udp_session->thread_index);
      if (!ctx || !ctx->conn)
    {
      fifo_offset += full_len;
      continue;
    }

      // Get crypto context
      crctx = quic_openssl_crypto_context_get (ctx->crypto_context_index,
                           ctx->c_thread_index);
      if (!crctx || !crctx->data.rbio)
    {
      fifo_offset += full_len;
      continue;
    }

      // Feed packet to OpenSSL QUIC
      BIO_write (crctx->data.rbio, packet_data, ph.data_length);

      // Process events
      SSL_handle_events ((SSL *)ctx->conn);

      fifo_offset += full_len;
    }

  // Dequeue processed data
  svm_fifo_dequeue_drop (f, fifo_offset);

  return 0;
}

static int
quic_openssl_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  SSL *stream = (SSL *)ctx->stream;
  svm_fifo_t *f;
  u8 buf[4096];
  int bytes_read, bytes_written;
  int total_written = 0;

  if (!stream)
    return -1;

  f = stream_session->tx_fifo;

  while ((bytes_read = svm_fifo_dequeue (f, sizeof(buf), buf)) > 0)
    {
      bytes_written = SSL_write (stream, buf, bytes_read);
      if (bytes_written <= 0)
        {
          int err = SSL_get_error (stream, bytes_written);
          if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
            {
              // Put data back in fifo and return
              svm_fifo_enqueue (f, bytes_read, buf);
              break;
            }
          else
            {
              QUIC_ERR ("SSL_write failed with error %d", err);
              return -1;
            }
        }
      total_written += bytes_written;
    }

  return total_written;
}

static void
quic_openssl_ack_rx_data (session_t *stream_session)
{
  // For OpenSSL QUIC, acknowledgments are handled internally
  // This function may need to update flow control if required
  QUIC_DBG (4, "ACK RX data for stream session %u", stream_session->session_index);
}

static u8 *
quic_openssl_format_stream_ctx_stream_id (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  SSL *stream = (SSL *)ctx->stream;

  if (stream)
    {
      uint64_t stream_id = SSL_get_stream_id (stream);
      s = format (s, "S%lx", stream_id);
    }
  else
    s = format (s, "S(null)");

  return s;
}

static u8 *
quic_openssl_format_stream_connection (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  SSL *stream = (SSL *)ctx->stream;

  if (stream)
    s = format (s, "OpenSSL Stream %p", stream);
  else
    s = format (s, "OpenSSL Stream (null)");

  return s;
}

static u8 *
quic_openssl_format_connection_stats (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quic_openssl_crypto_context_t *crctx;
  uint64_t rtt;

  s = format (s, "[OpenSSL QUIC]");

  crctx = quic_openssl_crypto_context_get (ctx->crypto_context_index,
                       ctx->c_thread_index);
  if (crctx && crctx->data.ssl_conn)
    {
      if (SSL_get_handshake_rtt (crctx->data.ssl_conn, &rtt) == 1)
    s = format (s, " RTT: %lu", rtt);
      else
    s = format (s, " RTT: N/A");
    }

  return s;
}

static void
quic_openssl_connection_get_stats (void *conn, quic_stats_t *stats)
{
  SSL *ssl_conn = (SSL *) conn;

  clib_memset (stats, 0, sizeof (*stats));

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

  // Additional stats can be added as OpenSSL QUIC API evolves
  QUIC_DBG (4, "Retrieved connection stats: RTT=%lu", stats->rtt_smoothed);
}

static_always_inline quic_ctx_t *
quic_openssl_get_quic_ctx_if_valid (u32 ctx_index,
				   clib_thread_index_t thread_index)
{
  quic_worker_ctx_t *wrk_ctx =
    quic_wrk_ctx_get (quic_openssl_main.qm, thread_index);

  if (pool_is_free_index (wrk_ctx->ctx_pool, ctx_index))
    return 0;
  return pool_elt_at_index (wrk_ctx->ctx_pool, ctx_index);
}

static void
quic_openssl_proto_on_close (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_ctx_t *ctx = quic_openssl_get_quic_ctx_if_valid (ctx_index, thread_index);

  if (!ctx)
    return;

  QUIC_DBG (2, "Proto on close for ctx %u (thread %u)", ctx_index, thread_index);

  if (quic_ctx_is_stream (ctx))
    {
      SSL *stream = (SSL *)ctx->stream;
      if (stream)
    {
      // Close the stream gracefully
      SSL_stream_conclude (stream, 0);
      SSL_free (stream);
      ctx->stream = NULL;
    }
    }
  else
    {
      SSL *conn = (SSL *)ctx->conn;
      if (conn)
    {
      // Close connection gracefully
      SSL_shutdown (conn);
    }

      // Release crypto context
      if (ctx->crypto_context_index != ~0)
    {
      quic_openssl_crypto_context_release (ctx->crypto_context_index,
                           thread_index);
      ctx->crypto_context_index = ~0;
    }
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