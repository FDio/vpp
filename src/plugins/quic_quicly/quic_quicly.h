/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quicly_impl_h__
#define __included_quicly_impl_h__

#include <quic/quic.h>
#include <quic/quic_crypto.h>
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

extern quicly_crypto_engine_t quic_crypto_engine;

// TODO: make extern or ensure this header file is only included in 1 c-file.
static quicly_stream_open_t on_stream_open;
static quicly_closed_by_remote_t on_closed_by_remote;
static quicly_now_t quicly_vpp_now_cb;

typedef struct quic_quicly_crypto_context_data_
{
  quicly_context_t quicly_ctx;
  char cid_key[QUIC_IV_LEN];
  ptls_context_t ptls_ctx;
} quic_quicly_crypto_context_data_t;

// TODO: rename to quicly_init_crypto_context() and register during
// quicly_impl_init()
extern int quic_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx);

#endif /* __included_quicly_impl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
