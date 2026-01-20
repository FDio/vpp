/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_quicly_crypto_h__
#define __included_quic_quicly_crypto_h__

#include <quic/quic.h>
#include <quicly.h>
#include <vnet/crypto/crypto.h>
#include <picotls/openssl.h>
#include <vppinfra/bihash_24_8.h>
#include <quic_quicly/quic_quicly.h>
#include <vnet/session/session.h>

static_always_inline quic_crypto_context_t *
quic_quicly_crypto_context_get (u32 cr_index, u32 thread_index)
{
  ASSERT (QUIC_CRCTX_CTX_INDEX_DECODE_THREAD (cr_index) == thread_index);
  return pool_elt_at_index (
    quic_wrk_ctx_get (quic_quicly_main.qm, thread_index)->crypto_ctx_pool,
    QUIC_CRCTX_CTX_INDEX_DECODE_INDEX (cr_index));
}

#define QUIC_IV_LEN 17

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>

#define quic_quicly_load_openssl3_legacy_provider()                           \
  do                                                                          \
    {                                                                         \
      (void) OSSL_PROVIDER_load (NULL, "legacy");                             \
    }                                                                         \
  while (0)
#else
#define quic_quicly_load_openssl3_legacy_provider()
#endif

typedef struct crypto_key_
{
  vnet_crypto_alg_t algo;
  u8 key[32];
  u16 key_len;
} crypto_key_t;

struct aead_crypto_context_t
{
  ptls_aead_context_t super;
  EVP_CIPHER_CTX *evp_ctx;
  uint8_t static_iv[PTLS_MAX_IV_SIZE];
  vnet_crypto_op_t op;
  crypto_key_t key;

  vnet_crypto_op_id_t id;
  uint8_t iv[PTLS_MAX_IV_SIZE];
};

struct cipher_context_t
{
  ptls_cipher_context_t super;
  vnet_crypto_op_t op;
  vnet_crypto_op_id_t id;
  crypto_key_t key;
};

typedef struct quic_quicly_on_client_hello_
{
  ptls_on_client_hello_t super;
  u32 lctx_index;
} quic_quicly_on_client_hello_t;

typedef struct quic_quicly_crypto_context_data_
{
  quicly_context_t quicly_ctx;
  char cid_key[QUIC_IV_LEN];
  ptls_context_t ptls_ctx;
  quic_quicly_on_client_hello_t client_hello_ctx;
  volatile u32 ref_count;
} quic_quicly_crypto_context_data_t;

static_always_inline u8
quic_quicly_register_cipher_suite (crypto_engine_type_t type,
				   ptls_cipher_suite_t **ciphers)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  u8 rv = 1;

  if (!qqm->quic_ciphers)
    {
      vec_validate (qqm->quic_ciphers, type);
    }
  if (!qqm->quic_ciphers[type])
    {
      QUIC_DBG (3,
		"Register cipher suite: engine_type %U (%u), cipher_suites %p",
		format_crypto_engine, type, type, ciphers);
      clib_bitmap_set (qqm->available_crypto_engines, type, 1);
      qqm->quic_ciphers[type] = ciphers;
    }
  else
    {
      QUIC_DBG (3,
		"Cipher suite already registered: engine_type %U (%u), "
		"cipher_suites %p",
		format_crypto_engine, type, type, ciphers);
      rv = 0;
    }
  return rv;
}

static_always_inline void
quic_quicly_crypto_context_reserve_data (quic_crypto_context_t *crctx)
{
  ASSERT (crctx->data);
  clib_atomic_add_fetch (&((quic_quicly_crypto_context_data_t *) crctx->data)->ref_count, 1);
}

extern quicly_crypto_engine_t quic_quicly_crypto_engine;
extern ptls_cipher_suite_t *quic_quicly_crypto_cipher_suites[];
int quic_quicly_crypto_context_init (quic_ctx_t *ctx);
quic_crypto_context_t *quic_quicly_crypto_context_get_or_alloc (quic_ctx_t *ctx);
int quic_quicly_crypto_context_init_data (quic_crypto_context_t *crctx, quic_ctx_t *ctx);
quic_quicly_crypto_context_data_t *quic_quicly_crypto_context_get_data (quic_ctx_t *ctx);
void quic_quicly_crypto_context_free (u32 crypto_context_index,
				      u8 thread_index);
extern int quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self,
					  ptls_t *tls, int is_encrypt,
					  ptls_buffer_t *dst,
					  ptls_iovec_t src);
extern void
quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx,
				   quic_quicly_rx_packet_ctx_t *pctx);
#endif /* __included_quic_quicly_crypto_h__ */
