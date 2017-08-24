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
#ifndef __DPDK_IPSEC_H__
#define __DPDK_IPSEC_H__

#include <vnet/vnet.h>

#undef always_inline
#include <rte_config.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif


#define MAX_QP_PER_LCORE 16

typedef struct
{
  u32 salt;
  u32 iv[2];
  u32 cnt;
} dpdk_gcm_cnt_blk;

typedef struct
{
  dpdk_gcm_cnt_blk cb;
  union
  {
    u8 aad[12];
    u8 icv[64];
  };
} dpdk_cop_priv_t;

typedef struct
{
  u8 cipher_algo;
  u8 auth_algo;
  u8 is_outbound;
  u8 is_aead;
} crypto_worker_qp_key_t;

typedef struct
{
  u16 dev_id;
  u16 qp_id;
  u16 is_outbound;
  i16 inflights;
  u32 bi[VLIB_FRAME_SIZE];
  struct rte_crypto_op *cops[VLIB_FRAME_SIZE];
  struct rte_crypto_op **free_cops;
} crypto_qp_data_t;

typedef struct
{
  u8 qp_index;
  void *sess;
} crypto_sa_session_t;

typedef struct
{
  crypto_sa_session_t *sa_sess_d[2];
  crypto_qp_data_t *qp_data;
  uword *algo_qp_map;
} crypto_worker_main_t;

typedef struct
{
  struct rte_mempool **sess_h_pools;
  struct rte_mempool **sess_pools;
  struct rte_mempool **cop_pools;
  crypto_worker_main_t *workers_main;
  u8 enabled;
} dpdk_crypto_main_t;

dpdk_crypto_main_t dpdk_crypto_main;

extern vlib_node_registration_t dpdk_crypto_input_node;

#define CRYPTO_N_FREE_COPS (VLIB_FRAME_SIZE * 3)

static_always_inline void
crypto_alloc_cops ()
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  u32 thread_index = vlib_get_thread_index ();
  crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
  unsigned socket_id = rte_socket_id ();
  crypto_qp_data_t *qpd;

  /* *INDENT-OFF* */
  vec_foreach (qpd, cwm->qp_data)
    {
      u32 l = vec_len (qpd->free_cops);

      if (PREDICT_FALSE (l < VLIB_FRAME_SIZE))
	{
	  u32 n_alloc;

	  if (PREDICT_FALSE (!qpd->free_cops))
	    vec_alloc (qpd->free_cops, CRYPTO_N_FREE_COPS);

	  n_alloc = rte_crypto_op_bulk_alloc (dcm->cop_pools[socket_id],
					      RTE_CRYPTO_OP_TYPE_SYMMETRIC,
					      &qpd->free_cops[l],
					      CRYPTO_N_FREE_COPS - l - 1);

	  _vec_len (qpd->free_cops) = l + n_alloc;
	}
    }
  /* *INDENT-ON* */
}

static_always_inline void
crypto_free_cop (crypto_qp_data_t * qpd, struct rte_crypto_op **cops, u32 n)
{
  u32 l = vec_len (qpd->free_cops);

  if (l + n >= CRYPTO_N_FREE_COPS)
    {
      l -= VLIB_FRAME_SIZE;
      rte_mempool_put_bulk (cops[0]->mempool,
			    (void **) &qpd->free_cops[l], VLIB_FRAME_SIZE);
    }
  clib_memcpy (&qpd->free_cops[l], cops, sizeof (*cops) * n);

  _vec_len (qpd->free_cops) = l + n;
}

static_always_inline int
check_algo_is_supported (const struct rte_cryptodev_capabilities *cap,
			 char *name)
{
  struct
  {
    enum rte_crypto_sym_xform_type type;
    union
    {
      enum rte_crypto_auth_algorithm auth;
      enum rte_crypto_cipher_algorithm cipher;
#if ! DPDK_NO_AEAD
      enum rte_crypto_aead_algorithm aead;
#endif
    };
    char *name;
  } supported_algo[] =
  {
    {
    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,.cipher =
	RTE_CRYPTO_CIPHER_NULL,.name = "NULL"},
    {
    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,.cipher =
	RTE_CRYPTO_CIPHER_AES_CBC,.name = "AES_CBC"},
#if DPDK_NO_AEAD
    {
    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,.cipher =
	RTE_CRYPTO_CIPHER_AES_GCM,.name = "AES-GCM"},
#else
    {
    .type = RTE_CRYPTO_SYM_XFORM_AEAD,.aead =
	RTE_CRYPTO_AEAD_AES_GCM,.name = "AES-GCM"},
#endif
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_NULL,.name = "NULL"},
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_SHA1_HMAC,.name = "HMAC-SHA1"},
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_SHA256_HMAC,.name = "HMAC-SHA256"},
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_SHA384_HMAC,.name = "HMAC-SHA384"},
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_SHA512_HMAC,.name = "HMAC-SHA512"},
#if DPDK_NO_AEAD
    {
    .type = RTE_CRYPTO_SYM_XFORM_AUTH,.auth =
	RTE_CRYPTO_AUTH_AES_GCM,.name = "AES-GCM"},
#endif
    {
      /* tail */
    .type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED}
  };

  uint32_t i = 0;

  if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
    return -1;

  while (supported_algo[i].type != RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED)
    {
      if (cap->sym.xform_type == supported_algo[i].type)
	{
	  if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
	       cap->sym.cipher.algo == supported_algo[i].cipher) ||
#if ! DPDK_NO_AEAD
	      (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD &&
	       cap->sym.aead.algo == supported_algo[i].aead) ||
#endif
	      (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH &&
	       cap->sym.auth.algo == supported_algo[i].auth))
	    {
	      if (name)
		strcpy (name, supported_algo[i].name);
	      return 0;
	    }
	}

      i++;
    }

  return -1;
}

#endif /* __DPDK_IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
