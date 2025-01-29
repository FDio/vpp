/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quicly_impl_h__
#define __included_quicly_impl_h__

#include <quic/quic.h>
#include <quic_quicly/quic_quicly_crypto.h>
#include <quic/certs.h>
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

typedef struct quic_quicly_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_quic_wrk_ctx_field
#undef _
  quicly_cid_plaintext_t next_cid;
} quic_quicly_worker_ctx_t;

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
  
struct quic_quicly_ctx_ {
  struct
  {
    ptls_cipher_context_t *hp_ctx;
    ptls_aead_context_t *aead_ctx;
  } ingress_keys;

  int key_phase_ingress;
} quic_quicly_ctx_t;

typedef struct quic_quicly_main_
{
  quic_main_t *qm;
  ptls_cipher_suite_t ***quic_ciphers;	/**< available ciphers by crypto engine */
  uword *available_crypto_engines;	/**< Bitmap for registered engines */
  u32 crypto_engine;
  u8 default_crypto_engine;		/**< Used if you do connect with CRYPTO_ENGINE_NONE (0) */
  u8 default_quic_cc;
  u8 vnet_crypto_enabled;
  u32 *per_thread_crypto_key_indices;
  ptls_handshake_properties_t hs_properties;
  clib_bihash_16_8_t connection_hash;	/**< quic connection id -> conn handle */
  quic_quicly_worker_ctx_t *wrk_ctx;

  u64 max_packets_per_key;		/**< number of packets that can be sent without a key update */
} quic_quicly_main_t;

extern quic_quicly_main_t quic_quicly_main;
extern quicly_crypto_engine_t quic_quicly_crypto_engine;
extern const quicly_stream_callbacks_t quic_quicly_stream_callbacks;
extern quic_ctx_t * quic_quicly_get_conn_ctx (void *conn);

// TODO: make extern or ensure this header file is only included in 1 c-file.
static quicly_stream_open_t on_stream_open;
static quicly_closed_by_remote_t on_closed_by_remote;
static quicly_now_t quicly_vpp_now_cb;

#endif /* __included_quicly_impl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
