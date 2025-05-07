/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_openssl_h__
#define __included_quic_openssl_h__

#include <quic/quic.h>
#include <vnet/session/session.h>
#include <vnet/crypto/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef struct
{
  quic_main_t *qm;
  u32 num_threads;
  clib_bitmap_t *available_crypto_engines;
} quic_openssl_main_t;

extern quic_openssl_main_t quic_openssl_main;
extern const unsigned char alpn_protocols[];
extern const u32 alpn_protocols_len;

static_always_inline quic_ctx_t *
quic_openssl_get_quic_ctx (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (
    quic_wrk_ctx_get (quic_openssl_main.qm, thread_index)->ctx_pool,
    ctx_index);
}

#endif /* __included_quic_openssl_h__ */
