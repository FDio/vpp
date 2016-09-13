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
#if DPDK_IPSEC==1
#include <vnet/ipsec/dpdk_ipsec.h>
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#endif
#endif

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

typedef struct
{
  u32 spi;
  u32 seq;
  u8 data[0];
} esp_header_t;

typedef struct
{
  u8 pad_length;
  u8 next_header;
} esp_footer_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;
/* *INDENT-ON* */

typedef struct {
  const EVP_CIPHER * type;
#if DPDK ==1 && DPDK_IPSEC==1
  enum rte_crypto_cipher_algorithm algo;
#endif
  u8 key_len;
  u8 iv_len;
} esp_crypto_alg_t;

typedef struct {
  const EVP_MD * md;
#if DPDK ==1 && DPDK_IPSEC==1
  enum rte_crypto_auth_algorithm algo;
  u8 aad_len;
#endif
  u8 trunc_size;
} esp_integ_alg_t;

#if DPDK==1 && DPDK_IPSEC==1
typedef struct
{
  u8 qp_index;
  void *sess;
} esp_sa_session_t;
#endif

typedef struct
{
#if DPDK==1 && DPDK_IPSEC==1
  esp_sa_session_t *sa_sess_d[2];
#endif
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  EVP_CIPHER_CTX encrypt_ctx;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  EVP_CIPHER_CTX decrypt_ctx;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  HMAC_CTX hmac_ctx;
  ipsec_crypto_alg_t last_encrypt_alg;
  ipsec_crypto_alg_t last_decrypt_alg;
  ipsec_integ_alg_t last_integ_alg;

} esp_main_per_thread_data_t;

typedef struct
{
  esp_crypto_alg_t *esp_crypto_algs;
  esp_integ_alg_t *esp_integ_algs;
  esp_main_per_thread_data_t *per_thread_data;
} esp_main_t;

esp_main_t esp_main;

/* XXX DPDK */
#if DPDK_IPSEC==1
always_inline void
dpdk_esp_init()
{
  esp_main_t * em = &esp_main;
  esp_integ_alg_t * i;
  esp_crypto_alg_t * c;

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
  c->iv_len = 16;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
  i->trunc_size = 12;

  /* XXX we shouldn't support this mode */
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
  i->aad_len = 8;
  i->trunc_size = 16;
}

always_inline int
add_del_sa_sess(u32 sa_index, u8 is_add)
{
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  u32 tid;

  for (tid = 1; tid < tm->n_vlib_mains; tid++)
    {
      u32 cpu_index = vlib_mains[tid]->cpu_index;
      esp_sa_session_t *sa_sess;
      esp_main_per_thread_data_t *ptd = &esp_main.per_thread_data[cpu_index];
      ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
      u8 outbound;

      for (outbound = 0; outbound < 2; outbound++)
	{
	  if (is_add)
	    {
	      pool_get (ptd->sa_sess_d[outbound], sa_sess);

	      sa_sess->qp_index = 0;
	      sa_sess->sess = NULL;
	    }
	  else
	    {
	      u8 cdev_id;

	      sa_sess = pool_elt_at_index (ptd->sa_sess_d[outbound], sa_index);
	      cdev_id = lcore_main->qp_data[sa_sess->qp_index].dev_id;

	      if (!sa_sess->sess)
		continue;

	      sa_sess->sess = rte_cryptodev_sym_session_free(cdev_id, sa_sess->sess);
	      if (sa_sess->sess)
		{
		  printf("failed to free session");
		  return -1;
		}
	      sa_sess->qp_index = 0;
	    }
	}
    }

   return 0;
}

always_inline int
create_sym_sess(ipsec_sa_t *sa, esp_sa_session_t *sa_sess, u8 outbound)
{
  u32 cpu_index = os_get_cpu_number();
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
  struct rte_crypto_sym_xform cipher_xform = {0};
  struct rte_crypto_sym_xform auth_xform = {0};
  struct rte_crypto_sym_xform *xfs;
  uword key = 0;
  ipsec_qp_data_t *p_data;
  ipsec_lcore_qp_key_t *p_key = (ipsec_lcore_qp_key_t *)&key;
  u8 i;

  cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  cipher_xform.cipher.key.data = sa->crypto_key;
  cipher_xform.cipher.key.length = sa->crypto_key_len;

  auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
  auth_xform.auth.key.data = sa->integ_key;
  auth_xform.auth.key.length = sa->integ_key_len;

  switch (sa->crypto_alg)
  {
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
      cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
      p_key->cipher_algo = cipher_xform.cipher.algo;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
      cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_GCM;
      p_key->cipher_algo = cipher_xform.cipher.algo;
      break;
    default:
      return -1;
  }

  switch (sa->integ_alg) {
    case IPSEC_INTEG_ALG_SHA1_96:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
      auth_xform.auth.digest_length = 12;
      p_key->auth_algo = auth_xform.auth.algo;
      break;
    case IPSEC_INTEG_ALG_SHA_256_96:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
      auth_xform.auth.digest_length = 12;
      p_key->auth_algo = auth_xform.auth.algo;
      break;
    case IPSEC_INTEG_ALG_SHA_256_128:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
      p_key->auth_algo = auth_xform.auth.algo;
      auth_xform.auth.digest_length = 16;
      break;
    case IPSEC_INTEG_ALG_SHA_384_192:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
      auth_xform.auth.digest_length = 24;
      p_key->auth_algo = auth_xform.auth.algo;
      break;
    case IPSEC_INTEG_ALG_SHA_512_256:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
      auth_xform.auth.digest_length = 32;
      p_key->auth_algo = auth_xform.auth.algo;
      break;
    case IPSEC_INTEG_ALG_AES_GCM_128:
      auth_xform.auth.algo = RTE_CRYPTO_AUTH_AES_GCM;
      auth_xform.auth.digest_length = 16;
      auth_xform.auth.add_auth_data_length = 8;
      p_key->auth_algo = auth_xform.auth.algo;
    default:
      return -1;
  }
  if (outbound)
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

  p_key->outbound = outbound;

  p_data = (ipsec_qp_data_t *)hash_get(lcore_main->algo_qp_map, key);
  if (!p_data)
    return -1;

  sa_sess->sess = rte_cryptodev_sym_session_create(p_data->dev_id, xfs);

  if (!sa_sess->sess)
      return -1;

  for (i = 0; i < lcore_main->n_qps; i++)
    if (p_data->dev_id == lcore_main->qp_data[i].dev_id &&
	p_data->qp_id == lcore_main->qp_data[i].qp_id)
      break;

  if (i == lcore_main->n_qps)
    return -1;

  sa_sess->qp_index = i;

  return 0;
}


#endif

always_inline void
esp_init ()
{
  esp_main_t *em = &esp_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (em, 0, sizeof (em[0]));

  vec_validate (em->esp_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].type = EVP_aes_128_cbc ();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].type = EVP_aes_192_cbc ();
  em->esp_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].type = EVP_aes_256_cbc ();

  vec_validate (em->esp_integ_algs, IPSEC_INTEG_N_ALG - 1);
  esp_integ_alg_t *i;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1 ();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();
  i->trunc_size = 12;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();
  i->trunc_size = 16;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();
  i->trunc_size = 24;

  i = &em->esp_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
  i->trunc_size = 32;

  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  int thread_id;

  for (thread_id = 0; thread_id < tm->n_vlib_mains - 1; thread_id++)
    {
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].encrypt_ctx));
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].decrypt_ctx));
      HMAC_CTX_init (&(em->per_thread_data[thread_id].hmac_ctx));
    }
}

always_inline unsigned int
hmac_calc (ipsec_integ_alg_t alg,
	   u8 * key,
	   int key_len,
	   u8 * data, int data_len, u8 * signature, u8 use_esn, u32 seq_hi)
{
  esp_main_t *em = &esp_main;
  u32 cpu_index = os_get_cpu_number ();
  HMAC_CTX *ctx = &(em->per_thread_data[cpu_index].hmac_ctx);
  const EVP_MD *md = NULL;
  unsigned int len;

  ASSERT (alg < IPSEC_INTEG_N_ALG);

  if (PREDICT_FALSE (em->esp_integ_algs[alg].md == 0))
    return 0;

  if (PREDICT_FALSE (alg != em->per_thread_data[cpu_index].last_integ_alg))
    {
      md = em->esp_integ_algs[alg].md;
      em->per_thread_data[cpu_index].last_integ_alg = alg;
    }

  HMAC_Init (ctx, key, key_len, md);

  HMAC_Update (ctx, data, data_len);

  if (PREDICT_TRUE (use_esn))
    HMAC_Update (ctx, (u8 *) & seq_hi, sizeof (seq_hi));
  HMAC_Final (ctx, signature, &len);

  return em->esp_integ_algs[alg].trunc_size;
}



