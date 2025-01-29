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

#ifndef __included_vpp_quic_crypto_h__
#define __included_vpp_quic_crypto_h__

#include <quicly.h>
#include <vnet/crypto/crypto.h>
#include <picotls/openssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>

#define quic_load_openssl3_legacy_provider()                                  \
  do                                                                          \
    {                                                                         \
      (void) OSSL_PROVIDER_load (NULL, "legacy");                             \
    }                                                                         \
  while (0)
#else
#define quic_load_openssl3_legacy_provider()
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

struct quic_ctx_t;

extern ptls_cipher_suite_t *quic_crypto_cipher_suites[];

int quic_encrypt_ticket_cb (ptls_encrypt_ticket_t * _self, ptls_t * tls,
			    int is_encrypt, ptls_buffer_t * dst,
			    ptls_iovec_t src);

#endif /* __included_vpp_quic_crypto_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
