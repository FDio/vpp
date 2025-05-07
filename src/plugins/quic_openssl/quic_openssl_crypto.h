/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_openssl_crypto_h__
#define __included_quic_openssl_crypto_h__

#include <quic/quic.h>
#include <vnet/session/session.h>
#include <vnet/crypto/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define QUIC_OPENSSL_IV_LEN 17

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>

#define quic_openssl_load_openssl3_legacy_provider()                          \
  do                                                                          \
    {                                                                         \
      (void) OSSL_PROVIDER_load (NULL, "legacy");                             \
      (void) OSSL_PROVIDER_load (NULL, "default");                            \
    }                                                                         \
  while (0)
#else
#define quic_openssl_load_openssl3_legacy_provider()
#endif

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

typedef struct quic_openssl_crypto_context_data_
{
  SSL_CTX *ssl_ctx;
  SSL *ssl_conn;
  BIO *rbio;
  BIO *wbio;
  char cid_key[QUIC_OPENSSL_IV_LEN];
  u8 is_initialized;
  u8 is_server;
} quic_openssl_crypto_context_data_t;

typedef struct quic_openssl_crypto_context_
{
  quic_openssl_crypto_context_data_t data;
  u32 ctx_index;
  u8 thread_index;
} quic_openssl_crypto_context_t;

static_always_inline quic_openssl_crypto_context_t *
quic_openssl_crypto_context_get (u32 cr_index, u8 thread_index)
{
  extern quic_openssl_crypto_context_t *quic_openssl_crypto_context_get_impl (
    u32 ctx_index, u8 thread_index);
  return quic_openssl_crypto_context_get_impl (cr_index, thread_index);
}

static_always_inline void
quic_openssl_register_cipher_suite (crypto_engine_type_t type)
{
  // OpenSSL QUIC handles cipher suites internally
  // This is a no-op for compatibility with the quic engine interface
}

extern void quic_openssl_crypto_init_per_thread (quic_main_t *qm,
						 u8 thread_index);
extern u32 quic_openssl_crypto_context_alloc (quic_main_t *qm,
					      u8 thread_index);
extern void
quic_openssl_crypto_context_free (quic_main_t *qm,
				  quic_openssl_crypto_context_t *crctx);
extern quic_openssl_crypto_context_t *
quic_openssl_crypto_context_get_impl (u32 ctx_index, u8 thread_index);
extern int
quic_openssl_crypto_context_init (quic_openssl_crypto_context_t *crctx,
				  u8 is_server);
extern void
quic_openssl_crypto_context_cleanup (quic_openssl_crypto_context_t *crctx);

#endif /* __included_quic_openssl_crypto_h__ */