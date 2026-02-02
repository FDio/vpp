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

#define QUIC_IV_LEN 17

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

/* Custom verify certificate callback that stores the peer certificate */
typedef struct st_quic_quicly_verify_certificate_t
{
  ptls_openssl_verify_certificate_t super;
  int (*orig_cb) (ptls_verify_certificate_t *, ptls_t *, const char *,
		  int (**) (void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **, ptls_iovec_t *,
		  size_t);
} quic_quicly_verify_certificate_t;

typedef struct quic_quicly_crypto_ctx_
{
  quic_crypto_context_t ctx; /* first */
  quicly_context_t quicly_ctx;
  char cid_key[QUIC_IV_LEN];
  ptls_context_t ptls_ctx;
  tls_verify_cfg_t verify_cfg;
  quic_quicly_verify_certificate_t verify_cert;
  quic_quicly_on_client_hello_t client_hello_ctx;
} quic_quicly_crypto_ctx_t;

typedef struct quic_quicly_crypto_main_
{
  quic_quicly_main_t *qqm;
  ptls_cipher_suite_t ***quic_ciphers;
  vnet_crypto_key_t **per_thread_crypto_keys;
  quic_quicly_crypto_ctx_t **crypto_ctx_pool;
  clib_bihash_24_8_t crypto_ctx_hash;
  uword *available_crypto_engines; /**< Bitmap for registered engines */
  u8 vnet_crypto_enabled;
} quic_quicly_crypto_main_t;

extern quic_quicly_crypto_main_t quic_quicly_crypto_main;

static_always_inline quic_quicly_crypto_ctx_t *
quic_quicly_crypto_context_get (u32 cr_index)
{
  quic_quicly_crypto_ctx_t **ctx;
  ctx = pool_elt_at_index (quic_quicly_crypto_main.crypto_ctx_pool,
			   QUIC_CRCTX_CTX_INDEX_DECODE_INDEX (cr_index));
  return *ctx;
}

static_always_inline void
quic_quicly_crypto_context_reserve_data (quic_quicly_crypto_ctx_t *crctx)
{
  clib_atomic_add_fetch (&crctx->ctx.n_subscribers, 1);
}

#define quic_quicly_crypto_engine_is_vpp()                                                         \
  (quic_quicly_crypto_main.vnet_crypto_enabled &&                                                  \
   quic_quicly_crypto_main.qqm->qm->default_crypto_engine)

extern quicly_crypto_engine_t quic_quicly_crypto_engine;
extern ptls_cipher_suite_t *quic_quicly_crypto_cipher_suites[];
void quic_quicly_crypto_init (quic_quicly_main_t *qqm);
void quic_quicly_crypto_context_list (vlib_main_t *vm);
quic_quicly_crypto_ctx_t *quic_quicly_crypto_context_get_or_alloc (quic_ctx_t *ctx);
void quic_quicly_crypto_context_free (u32 crypto_context_index);
extern int quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self,
					  ptls_t *tls, int is_encrypt,
					  ptls_buffer_t *dst,
					  ptls_iovec_t src);
extern void
quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx,
				   quic_quicly_rx_packet_ctx_t *pctx);
extern X509 *quic_quicly_crypto_get_peer_cert (quic_ctx_t *ctx);

#endif /* __included_quic_quicly_crypto_h__ */
