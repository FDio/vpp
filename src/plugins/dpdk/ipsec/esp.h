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
#if ! DPDK_NO_AEAD
  enum rte_crypto_aead_algorithm aead_algo;
#endif
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
#if DPDK_NO_AEAD
  c->algo = RTE_CRYPTO_CIPHER_AES_GCM;
#else
  c->aead_algo = RTE_CRYPTO_AEAD_AES_GCM;
#endif
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
#if DPDK_NO_AEAD
  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_AES_GCM_128];
  i->algo = RTE_CRYPTO_AUTH_AES_GCM;
  i->trunc_size = 16;
#endif
}

static_always_inline int
translate_crypto_algo (ipsec_crypto_alg_t crypto_algo,
		       struct rte_crypto_sym_xform *xform, u8 use_esn)
{
#if ! DPDK_NO_AEAD
  const u16 iv_off =
    sizeof (struct rte_crypto_op) + sizeof (struct rte_crypto_sym_op) +
    offsetof (dpdk_cop_priv_t, cb);
#endif

  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

  switch (crypto_algo)
    {
    case IPSEC_CRYPTO_ALG_NONE:
#if ! DPDK_NO_AEAD
      xform->cipher.iv.offset = iv_off;
      xform->cipher.iv.length = 0;
#endif
      xform->cipher.algo = RTE_CRYPTO_CIPHER_NULL;
      break;
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
#if ! DPDK_NO_AEAD
      xform->cipher.iv.offset = iv_off;
      xform->cipher.iv.length = 16;
#endif
      xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
#if DPDK_NO_AEAD
      xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_GCM;
#else
      xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
      xform->aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
      xform->aead.iv.offset = iv_off;
      xform->aead.iv.length = 12;	/* GCM IV, not ESP IV */
      xform->aead.digest_length = 16;
      xform->aead.aad_length = use_esn ? 12 : 8;
#endif
      break;
    default:
      return -1;
    }

  return 0;
}

static_always_inline int
translate_integ_algo (ipsec_integ_alg_t integ_alg,
		      struct rte_crypto_sym_xform *auth_xform, u8 use_esn)
{
  auth_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;

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
#if DPDK_NO_AEAD
    case IPSEC_INTEG_ALG_AES_GCM_128:
      auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_GCM;
      auth_xform->auth.digest_length = 16;
      auth_xform->auth.add_auth_data_length = use_esn ? 12 : 8;
      break;
#endif
    default:
      return -1;
    }

  return 0;
}

static_always_inline i32
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
#if ! DPDK_NO_AEAD
  i32 socket_id = rte_socket_id ();
  i32 ret;
#endif

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

  if (translate_crypto_algo (sa->crypto_alg, &cipher_xform, sa->use_esn) < 0)
    return -1;
  p_key->cipher_algo = cipher_xform.cipher.algo;

  if (translate_integ_algo (sa->integ_alg, &auth_xform, sa->use_esn) < 0)
    return -1;
  p_key->auth_algo = auth_xform.auth.algo;

#if ! DPDK_NO_AEAD
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
    {
      cipher_xform.aead.key.data = sa->crypto_key;
      cipher_xform.aead.key.length = sa->crypto_key_len;

      if (is_outbound)
	cipher_xform.cipher.op =
	  (enum rte_crypto_cipher_operation) RTE_CRYPTO_AEAD_OP_ENCRYPT;
      else
	cipher_xform.cipher.op =
	  (enum rte_crypto_cipher_operation) RTE_CRYPTO_AEAD_OP_DECRYPT;
      cipher_xform.next = NULL;
      xfs = &cipher_xform;
      p_key->is_aead = 1;
    }
  else				/* Cipher + Auth */
#endif
    {
      cipher_xform.cipher.key.data = sa->crypto_key;
      cipher_xform.cipher.key.length = sa->crypto_key_len;

      auth_xform.auth.key.data = sa->integ_key;
      auth_xform.auth.key.length = sa->integ_key_len;

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
      p_key->is_aead = 0;
    }

  p_key->is_outbound = is_outbound;

  data = hash_get (cwm->algo_qp_map, key);
  if (!data)
    return -1;

#if DPDK_NO_AEAD
  sa_sess->sess =
    rte_cryptodev_sym_session_create (cwm->qp_data[*data].dev_id, xfs);
  if (!sa_sess->sess)
    return -1;
#else
  sa_sess->sess =
    rte_cryptodev_sym_session_create (dcm->sess_h_pools[socket_id]);
  if (!sa_sess->sess)
    return -1;

  ret =
    rte_cryptodev_sym_session_init (cwm->qp_data[*data].dev_id, sa_sess->sess,
				    xfs, dcm->sess_pools[socket_id]);
  if (ret)
    return -1;
#endif

  sa_sess->qp_index = (u8) * data;

  return 0;
}

static_always_inline void
crypto_set_icb (dpdk_gcm_cnt_blk * icb, u32 salt, u32 seq, u32 seq_hi)
{
  icb->salt = salt;
  icb->iv[0] = seq;
  icb->iv[1] = seq_hi;
#if DPDK_NO_AEAD
  icb->cnt = clib_host_to_net_u32 (1);
#endif
}

#define __unused __attribute__((unused))
static_always_inline void
crypto_op_setup (u8 is_aead, struct rte_mbuf *mb0,
		 struct rte_crypto_op *cop, void *session,
		 u32 cipher_off, u32 cipher_len,
		 u8 * icb __unused, u32 iv_size __unused,
		 u32 auth_off, u32 auth_len,
		 u8 * aad __unused, u32 aad_size __unused,
		 u8 * digest, u64 digest_paddr, u32 digest_size __unused)
{
  struct rte_crypto_sym_op *sym_cop;

  sym_cop = (struct rte_crypto_sym_op *) (cop + 1);

  sym_cop->m_src = mb0;
  rte_crypto_op_attach_sym_session (cop, session);

  if (!digest_paddr)
    digest_paddr =
      rte_pktmbuf_mtophys_offset (mb0, (uintptr_t) digest - (uintptr_t) mb0);

#if DPDK_NO_AEAD
  sym_cop->cipher.data.offset = cipher_off;
  sym_cop->cipher.data.length = cipher_len;

  sym_cop->cipher.iv.data = icb;
  sym_cop->cipher.iv.phys_addr =
    cop->phys_addr + (uintptr_t) icb - (uintptr_t) cop;
  sym_cop->cipher.iv.length = iv_size;

  if (is_aead)
    {
      sym_cop->auth.aad.data = aad;
      sym_cop->auth.aad.phys_addr =
	cop->phys_addr + (uintptr_t) aad - (uintptr_t) cop;
      sym_cop->auth.aad.length = aad_size;
    }
  else
    {
      sym_cop->auth.data.offset = auth_off;
      sym_cop->auth.data.length = auth_len;
    }

  sym_cop->auth.digest.data = digest;
  sym_cop->auth.digest.phys_addr = digest_paddr;
  sym_cop->auth.digest.length = digest_size;
#else /* ! DPDK_NO_AEAD */
  if (is_aead)
    {
      sym_cop->aead.data.offset = cipher_off;
      sym_cop->aead.data.length = cipher_len;

      sym_cop->aead.aad.data = aad;
      sym_cop->aead.aad.phys_addr =
	cop->phys_addr + (uintptr_t) aad - (uintptr_t) cop;

      sym_cop->aead.digest.data = digest;
      sym_cop->aead.digest.phys_addr = digest_paddr;
    }
  else
    {
      sym_cop->cipher.data.offset = cipher_off;
      sym_cop->cipher.data.length = cipher_len;

      sym_cop->auth.data.offset = auth_off;
      sym_cop->auth.data.length = auth_len;

      sym_cop->auth.digest.data = digest;
      sym_cop->auth.digest.phys_addr = digest_paddr;
    }
#endif /* DPDK_NO_AEAD */
}

#undef __unused

#endif /* __DPDK_ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
