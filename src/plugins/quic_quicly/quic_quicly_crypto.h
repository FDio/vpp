/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_quic_quicly_crypto_h__
#define __included_quic_quicly_crypto_h__

#include <quicly.h>
#include <vnet/crypto/crypto.h>
#include <picotls/openssl.h>
#include <vppinfra/bihash_24_8.h>
#include <plugins/quic_quicly/quic_quicly.h>

#define QUIC_IV_LEN 17

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>

#define quic_quicly_load_openssl3_legacy_provider()                                  \
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

extern ptls_cipher_suite_t *quic_quicly_crypto_cipher_suites[];
extern void quic_quicly_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
					 crypto_context_t *crctx);
extern int quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t * _self,
          ptls_t * tls,
			    int is_encrypt, ptls_buffer_t * dst,
			    ptls_iovec_t src);
extern int quic_quicly_init_crypto_context (crypto_context_t *crctx,
                                            quic_ctx_t *ctx);
extern int
quic_quicly_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self, ptls_t *tls,
			int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src);
extern void
quic_quicly_crypto_encrypt_packet (struct st_quicly_crypto_engine_t *engine,
			    quicly_conn_t *conn,
			    ptls_cipher_context_t *header_protect_ctx,
			    ptls_aead_context_t *packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced);
extern void quic_quicly_crypto_decrypt_packet (quic_ctx_t *qctx,
                                               quic_rx_packet_ctx_t *pctx);

#endif /* __included_quic_quicly_crypto_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
