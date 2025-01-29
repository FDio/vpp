/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_quicly_h__
#define __included_quic_quicly_h__

#include <quic/quic.h>
#include <quic_quicly/ptls_certs.h>
#include <vnet/session/session.h>
#include <quicly.h>
#include <quicly/constants.h>
#include <quicly/defaults.h>
#include <picotls.h>
#include <picotls/openssl.h>

/* Taken from quicly.c */
#define QUICLY_QUIC_BIT 0x40

#define QUICLY_PACKET_TYPE_INITIAL                                            \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0)
#define QUICLY_PACKET_TYPE_0RTT                                               \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x10)
#define QUICLY_PACKET_TYPE_HANDSHAKE                                          \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x20)
#define QUICLY_PACKET_TYPE_RETRY                                              \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x30)
#define QUICLY_PACKET_TYPE_BITMASK 0xf0

typedef struct quic_quicly_rx_packet_ctx_
{
#define _(type, name) type name;
  foreach_quic_rx_pkt_ctx_field
#undef _
    quicly_decoded_packet_t packet;
  u8 data[QUIC_MAX_PACKET_SIZE];
  union
  {
    struct sockaddr sa;
    struct sockaddr_in6 sa6;
  };
  socklen_t salen;
  session_dgram_hdr_t ph;
} quic_quicly_rx_packet_ctx_t;

/* single-entry session cache */
typedef struct quic_quicly_session_cache_
{
  ptls_encrypt_ticket_t super;
  uint8_t id[32];
  ptls_iovec_t data;
} quic_quicly_session_cache_t;

typedef struct quic_quicly_main_
{
  quic_main_t *qm;
  ptls_cipher_suite_t **
    *quic_ciphers; /**< available ciphers by crypto engine */
  u32 *per_thread_crypto_key_indices;
  ptls_handshake_properties_t hs_properties;
  clib_bihash_16_8_t connection_hash; /**< quic connection id -> conn handle */
  quic_quicly_session_cache_t session_cache;
  quicly_cid_plaintext_t *next_cid;
  clib_bihash_24_8_t *crypto_ctx_hash;
  uword *available_crypto_engines; /**< Bitmap for registered engines */
  u8 vnet_crypto_enabled;
} quic_quicly_main_t;

extern quic_quicly_main_t quic_quicly_main;
extern const quicly_stream_callbacks_t quic_quicly_stream_callbacks;
extern quic_ctx_t *quic_quicly_get_conn_ctx (void *conn);
extern void quic_quicly_check_quic_session_connected (quic_ctx_t *ctx);

static_always_inline quic_ctx_t *
quic_quicly_get_quic_ctx (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (quic_quicly_main.qm->ctx_pool[thread_index],
			    ctx_index);
}

static_always_inline quic_session_connected_t
quic_quicly_is_session_connected (quic_ctx_t *ctx)
{
  quic_session_connected_t session_connected = QUIC_SESSION_CONNECTED_NONE;

  if (quicly_connection_is_ready (ctx->conn))
    {
      session_connected = quicly_is_client (ctx->conn) ?
			    QUIC_SESSION_CONNECTED_CLIENT :
			    QUIC_SESSION_CONNECTED_SERVER;
    }

  return (session_connected);
}

#endif /* __included_quic_quicly_h__ */
