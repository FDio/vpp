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
  u32 *per_thread_crypto_key_indices;
  clib_bihash_16_8_t connection_hash; /**< quic connection id -> conn handle */
  clib_bihash_24_8_t *crypto_ctx_hash;
  clib_bitmap_t *available_crypto_engines;
  u8 vnet_crypto_enabled;
  u8 *alpn_protos;
} quic_openssl_main_t;

extern quic_openssl_main_t quic_openssl_main;

static_always_inline quic_ctx_t *
quic_openssl_get_quic_ctx (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (
    quic_wrk_ctx_get (quic_openssl_main.qm, thread_index)->ctx_pool,
    ctx_index);
}

#endif /* __included_quic_openssl_h__ */
