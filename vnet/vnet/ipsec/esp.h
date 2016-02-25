/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#if DPDK==1
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

typedef struct {
  u32 spi;
  u32 seq;
  u8 data[0];
} esp_header_t;

typedef struct {
  u8 pad_length;
  u8 next_header;
} esp_footer_t;

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;

typedef struct {
  const EVP_CIPHER * type;
} esp_crypto_alg_t;

typedef struct {
  const EVP_MD * md;
  u8 trunc_size;
} esp_integ_alg_t;


typedef struct {
  esp_crypto_alg_t * esp_crypto_algs;
  esp_integ_alg_t * esp_integ_algs;
  EVP_CIPHER_CTX encrypt_ctx;
  EVP_CIPHER_CTX decrypt_ctx;
  HMAC_CTX hmac_ctx;
  ipsec_crypto_alg_t last_encrytp_alg;
  ipsec_crypto_alg_t last_decrytp_alg;
  ipsec_integ_alg_t last_integ_alg;
} esp_main_t;

esp_main_t esp_main;

always_inline void
esp_init()
{
  esp_main_t * em = &esp_main;

  memset (em, 0, sizeof (em[0]));

  vec_validate(em->esp_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].type = EVP_aes_128_cbc();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].type = EVP_aes_192_cbc();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].type = EVP_aes_256_cbc();

  vec_validate(em->esp_integ_algs, IPSEC_INTEG_N_ALG - 1);
  esp_integ_alg_t * i;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256();
  i->trunc_size = 16;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384();
  i->trunc_size = 24;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512();
  i->trunc_size = 32;

  EVP_CIPHER_CTX_init(&(em->encrypt_ctx));
  EVP_CIPHER_CTX_init(&(em->decrypt_ctx));
  HMAC_CTX_init(&(em->hmac_ctx));
}

always_inline unsigned int
hmac_calc(ipsec_integ_alg_t alg,
          u8 * key,
          int key_len,
          u8 * data,
          int data_len,
          u8 * signature,
          u8 use_esn,
          u32 seq_hi)
{
  esp_main_t * em = &esp_main;
  HMAC_CTX * ctx = &(em->hmac_ctx);
  const EVP_MD * md = NULL;
  unsigned int len;

  ASSERT(alg < IPSEC_INTEG_N_ALG);

  if (PREDICT_FALSE(em->esp_integ_algs[alg].md == 0))
    return 0;

  if (PREDICT_FALSE(alg != em->last_integ_alg)) {
    md = em->esp_integ_algs[alg].md;
    em->last_integ_alg = alg;
  }

  HMAC_Init(ctx, key, key_len, md);

  HMAC_Update(ctx, data, data_len);

  if (PREDICT_TRUE(use_esn))
    HMAC_Update(ctx, (u8 *) &seq_hi, sizeof(seq_hi));
  HMAC_Final(ctx, signature, &len);

  return em->esp_integ_algs[alg].trunc_size;
}

