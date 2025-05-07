/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_openssl_crypto_h__
#define __included_quic_openssl_crypto_h__

#include <quic/quic.h>
#include <quic_openssl/quic_openssl.h>
#include <vnet/session/session.h>
#include <vnet/crypto/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define QUIC_OPENSSL_IV_LEN 17

typedef struct quic_openssl_crypto_key_
{
  vnet_crypto_alg_t algo;
  u8 key[32];
  u16 key_len;
} quic_openssl_crypto_key_t;

typedef struct quic_openssl_aead_crypto_context_
{
  EVP_CIPHER_CTX *evp_ctx;
  uint8_t static_iv[EVP_MAX_IV_LENGTH];
  vnet_crypto_op_t op;
  quic_openssl_crypto_key_t key;
  vnet_crypto_op_id_t id;
  uint8_t iv[EVP_MAX_IV_LENGTH];
} quic_openssl_aead_crypto_context_t;

typedef struct quic_openssl_cipher_context_
{
  vnet_crypto_op_t op;
  vnet_crypto_op_id_t id;
  quic_openssl_crypto_key_t key;
} quic_openssl_cipher_context_t;

#define QUIC_OPENSSL_CRYPTO_CONTEXT_KEY_LEN 3
typedef struct quic_openssl_crypto_context_data_
{
  SSL_CTX *ssl_ctx;
  SSL *ssl_conn;
  BIO *rbio;
  BIO *wbio;
  char cid_key[QUIC_OPENSSL_IV_LEN];
  u64 crctx_key[QUIC_OPENSSL_CRYPTO_CONTEXT_KEY_LEN];
  u8 is_initialized;
  u8 is_server;
  u64 listener_flags;
} quic_openssl_crypto_context_data_t;

static_always_inline crypto_context_t *
quic_openssl_crypto_context_get (u32 cr_index, u32 thread_index)
{
  ASSERT (cr_index >> 24 == thread_index);
  return pool_elt_at_index (
    quic_wrk_ctx_get (quic_openssl_main.qm, thread_index)->crypto_ctx_pool,
    cr_index & 0x00ffffff);
}

extern void quic_openssl_crypto_init_per_thread (quic_main_t *qm,
						 u8 thread_index);
extern int quic_openssl_crypto_context_acquire (quic_ctx_t *ctx);
extern void quic_openssl_crypto_context_release (u32 crctx_index,
						 u8 thread_index);
extern crypto_context_t *
quic_openssl_crypto_context_get_impl (u32 ctx_index, u8 thread_index);
extern void quic_openssl_crypto_context_cleanup (crypto_context_t *crctx);

#endif /* __included_quic_openssl_crypto_h__ */
