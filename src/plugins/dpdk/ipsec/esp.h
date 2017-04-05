/*
 * Copyright (c) 2016 Intel and/or its affiliates.
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
#ifndef __DPDK_ESP_H__
#define __DPDK_ESP_H__

#include <dpdk/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

typedef struct
{
  enum rte_crypto_cipher_algorithm algo;
  u8 key_len;
  u8 iv_len;
} dpdk_esp_crypto_alg_t;

typedef struct
{
  enum rte_crypto_auth_algorithm algo;
  u8 trunc_size;
} dpdk_esp_integ_alg_t;

typedef struct
{
  dpdk_esp_crypto_alg_t *esp_crypto_algs;
  dpdk_esp_integ_alg_t *esp_integ_algs;
} dpdk_esp_main_t;

dpdk_esp_main_t dpdk_esp_main;

static_always_inline void
dpdk_esp_init ()
{
  dpdk_esp_main_t *em = &dpdk_esp_main;
  dpdk_esp_integ_alg_t *i;
  dpdk_esp_crypto_alg_t *c;

  vec_validate (em->esp_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);

  c = &em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128];
  c->algo = RTE_CRYPTO_CIPHER_AES_CBC;
  c->key_len = 16;
  c->iv_len = 16;

  c = &em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192];
  c->algo = RTE_CRYPTO_CIPHER_AES_CBC;
  c->key_len = 24;
  c->iv_len = 16;

  c = &em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256];
  c->algo = RTE_CRYPTO_CIPHER_AES_CBC;
  c->key_len = 32;
  c->iv_len = 16;

  c = &em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_GCM_128];
  c->algo = RTE_CRYPTO_CIPHER_AES_GCM;
  c->key_len = 16;
  c->iv_len = 8;

  vec_validate (em->esp_integ_algs, IPSEC_INTEG_N_ALG - 1);

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
  i->trunc_size = 16;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
  i->trunc_size = 24;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
  i->trunc_size = 32;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_AES_GCM_128];
  i->algo = RTE_CRYPTO_AUTH_AES_GCM;
  i->trunc_size = 16;
}

static_always_inline int
translate_crypto_algo (ipsec_crypto_alg_t crypto_algo,
		       struct rte_crypto_sym_xform *cipher_xform)
{
  switch (crypto_algo)
    {
    case IPSEC_CRYPTO_ALG_NONE:
      cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_NULL;
      break;
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
      cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
      cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_GCM;
      break;
    default:
      return -1;
    }

  cipher_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

  return 0;
}

static_always_inline int
translate_integ_algo (ipsec_integ_alg_t integ_alg,
		      struct rte_crypto_sym_xform *auth_xform, int use_esn)
{
  switch (integ_alg)
    {
    case IPSEC_INTEG_ALG_NONE:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_NULL;
      auth_xform->auth.digest_length = 0;
      break;
    case IPSEC_INTEG_ALG_SHA1_96:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
      auth_xform->auth.digest_length = 12;
      break;
    case IPSEC_INTEG_ALG_SHA_256_96:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
      auth_xform->auth.digest_length = 12;
      break;
    case IPSEC_INTEG_ALG_SHA_256_128:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
      auth_xform->auth.digest_length = 16;
      break;
    case IPSEC_INTEG_ALG_SHA_384_192:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
      auth_xform->auth.digest_length = 24;
      break;
    case IPSEC_INTEG_ALG_SHA_512_256:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
      auth_xform->auth.digest_length = 32;
      break;
    case IPSEC_INTEG_ALG_AES_GCM_128:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_GCM;
      auth_xform->auth.digest_length = 16;
      auth_xform->auth.add_auth_data_length = use_esn ? 12 : 8;
      break;
    default:
      return -1;
    }

  auth_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;

  return 0;
}

static_always_inline int
create_sym_sess (ipsec_sa_t * sa, crypto_sa_session_t * sa_sess,
		 u8 is_outbound)
{
  u32 thread_index = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
  struct rte_crypto_sym_xform cipher_xform = { 0 };
  struct rte_crypto_sym_xform auth_xform = { 0 };
  struct rte_crypto_sym_xform *xfs;
  uword key = 0, *data;
  crypto_worker_qp_key_t *p_key = (crypto_worker_qp_key_t *) & key;

  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
    {
      sa->crypto_key_len -= 4;
      clib_memcpy (&sa->salt, &sa->crypto_key[sa->crypto_key_len], 4);
    }
  else
    {
      u32 seed = (u32) clib_cpu_time_now ();
      sa->salt = random_u32 (&seed);
    }

  cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  cipher_xform.cipher.key.data = sa->crypto_key;
  cipher_xform.cipher.key.length = sa->crypto_key_len;

  auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
  auth_xform.auth.key.data = sa->integ_key;
  auth_xform.auth.key.length = sa->integ_key_len;

  if (translate_crypto_algo (sa->crypto_alg, &cipher_xform) < 0)
    return -1;
  p_key->cipher_algo = cipher_xform.cipher.algo;

  if (translate_integ_algo (sa->integ_alg, &auth_xform, sa->use_esn) < 0)
    return -1;
  p_key->auth_algo = auth_xform.auth.algo;

  if (is_outbound)
    {
      cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
      auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
      cipher_xform.next = &auth_xform;
      xfs = &cipher_xform;
    }
  else
    {
      cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
      auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
      auth_xform.next = &cipher_xform;
      xfs = &auth_xform;
    }

  p_key->is_outbound = is_outbound;

  data = hash_get (cwm->algo_qp_map, key);
  if (!data)
    return -1;

  sa_sess->sess =
    rte_cryptodev_sym_session_create (cwm->qp_data[*data].dev_id, xfs);

  if (!sa_sess->sess)
    return -1;

  sa_sess->qp_index = (u8) * data;

  return 0;
}

#endif /* __DPDK_ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
