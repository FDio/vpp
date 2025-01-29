/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_quicly_crypto_h__
#define __included_quic_quicly_crypto_h__

#include <quicly.h>
#include <vnet/crypto/crypto.h>
#include <picotls/openssl.h>
#include <vppinfra/bihash_24_8.h>
#include <quic_quicly/quic_quicly.h>
#include <vnet/session/session.h>

static_always_inline crypto_context_t *
quic_quicly_crypto_context_get (u32 cr_index, u32 thread_index)
{
  quic_worker_ctx_t *wrk_ctx = quic_quicly_main.qm->wrk_ctx;
  ASSERT (cr_index >> 24 == thread_index);
  return pool_elt_at_index (wrk_ctx[thread_index].crypto_ctx_pool,
			    cr_index & 0x00ffffff);
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

extern vnet_crypto_main_t *cm;

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

typedef struct quic_quicly_crypto_context_data_
{
  quicly_context_t quicly_ctx;
  char cid_key[QUIC_IV_LEN];
  ptls_context_t ptls_ctx;
} quic_quicly_crypto_context_data_t;

static_always_inline void
quic_quicly_register_cipher_suite (crypto_engine_type_t type,
				   ptls_cipher_suite_t **ciphers)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  vec_validate (qqm->quic_ciphers, type);
  clib_bitmap_set (qqm->available_crypto_engines, type, 1);
  qqm->quic_ciphers[type] = ciphers;
}

extern quicly_crypto_engine_t quic_quicly_crypto_engine;
extern ptls_cipher_suite_t *quic_quicly_crypto_cipher_suites[];
extern int quic_quicly_crypto_context_acquire (quic_ctx_t *ctx);
extern void quic_quicly_crypto_context_release (u32 crypto_context_index,
						u8 thread_index);
extern int quic_quicly_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair);
extern int quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self,
					  ptls_t *tls, int is_encrypt,
					  ptls_buffer_t *dst,
					  ptls_iovec_t src);
extern void
quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx,
				   quic_quicly_rx_packet_ctx_t *pctx);
#endif /* __included_quic_quicly_crypto_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
