/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vnet/ipsec/ipsec.h>
#include <vlib/node_funcs.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/ipsec/ipsec.h>

dpdk_crypto_main_t dpdk_crypto_main;

#define EMPTY_STRUCT {0}

static void
algos_init (u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *a;

  vec_validate_aligned (dcm->cipher_algs, IPSEC_CRYPTO_N_ALG - 1, 8);

  {
#define _(v,f,str) \
  dcm->cipher_algs[IPSEC_CRYPTO_ALG_##f].name = str; \
  dcm->cipher_algs[IPSEC_CRYPTO_ALG_##f].disabled = n_mains;
    foreach_ipsec_crypto_alg
#undef _
  }

  /* Minimum boundary for ciphers is 4B, required by ESP */
  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_NONE];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_NULL;
  a->boundary = 4;		/* 1 */
  a->key_len = 0;
  a->iv_len = 0;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_128];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 16;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_192];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 24;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_256];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 32;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_128];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 16;
  a->iv_len = 8;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_192];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 24;
  a->iv_len = 8;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_256];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 32;
  a->iv_len = 8;

#define AES_GCM_TYPE RTE_CRYPTO_SYM_XFORM_AEAD
#define AES_GCM_ALG RTE_CRYPTO_AEAD_AES_GCM

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_128];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 16;
  a->iv_len = 8;
  a->trunc_size = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_192];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 24;
  a->iv_len = 8;
  a->trunc_size = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_256];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 32;
  a->iv_len = 8;
  a->trunc_size = 16;

  vec_validate (dcm->auth_algs, IPSEC_INTEG_N_ALG - 1);

  {
#define _(v,f,str) \
  dcm->auth_algs[IPSEC_INTEG_ALG_##f].name = str; \
  dcm->auth_algs[IPSEC_INTEG_ALG_##f].disabled = n_mains;
    foreach_ipsec_integ_alg
#undef _
  }

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_NONE];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_NULL;
  a->key_len = 0;
  a->trunc_size = 0;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_MD5_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_MD5_HMAC;
  a->key_len = 16;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA1_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA1_HMAC;
  a->key_len = 20;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_256_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA256_HMAC;
  a->key_len = 32;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_256_128];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA256_HMAC;
  a->key_len = 32;
  a->trunc_size = 16;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_384_192];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA384_HMAC;
  a->key_len = 48;
  a->trunc_size = 24;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_512_256];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA512_HMAC;
  a->key_len = 64;
  a->trunc_size = 32;
}

static u8
cipher_alg_index (const crypto_alg_t * alg)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  return (alg - dcm->cipher_algs);
}

static u8
auth_alg_index (const crypto_alg_t * alg)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  return (alg - dcm->auth_algs);
}

static crypto_alg_t *
cipher_cap_to_alg (const struct rte_cryptodev_capabilities *cap, u8 key_len)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;

  if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
    return NULL;

  /* *INDENT-OFF* */
  vec_foreach (alg, dcm->cipher_algs)
    {
      if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
	  (alg->type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
	  (cap->sym.cipher.algo == alg->alg) &&
	  (alg->key_len == key_len))
	return alg;
      if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) &&
	  (alg->type == RTE_CRYPTO_SYM_XFORM_AEAD) &&
	  (cap->sym.aead.algo == alg->alg) &&
	  (alg->key_len == key_len))
	return alg;
    }
  /* *INDENT-ON* */

  return NULL;
}

static crypto_alg_t *
auth_cap_to_alg (const struct rte_cryptodev_capabilities *cap, u8 trunc_size)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;

  if ((cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC) ||
      (cap->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH))
    return NULL;

  /* *INDENT-OFF* */
  vec_foreach (alg, dcm->auth_algs)
    {
      if ((cap->sym.auth.algo == alg->alg) &&
	  (alg->trunc_size == trunc_size))
	return alg;
    }
  /* *INDENT-ON* */

  return NULL;
}

static void
crypto_set_aead_xform (struct rte_crypto_sym_xform *xform,
		       ipsec_sa_t * sa, u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *c;

  c = vec_elt_at_index (dcm->cipher_algs, sa->crypto_alg);

  ASSERT (c->type == RTE_CRYPTO_SYM_XFORM_AEAD);

  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  xform->aead.algo = c->alg;
  xform->aead.key.data = sa->crypto_key;
  xform->aead.key.length = c->key_len;
  xform->aead.iv.offset =
    crypto_op_get_priv_offset () + offsetof (dpdk_op_priv_t, cb);
  xform->aead.iv.length = 12;
  xform->aead.digest_length = c->trunc_size;
  xform->aead.aad_length = sa->use_esn ? 12 : 8;
  xform->next = NULL;

  if (is_outbound)
    xform->aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
  else
    xform->aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;
}

static void
crypto_set_cipher_xform (struct rte_crypto_sym_xform *xform,
			 ipsec_sa_t * sa, u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *c;

  c = vec_elt_at_index (dcm->cipher_algs, sa->crypto_alg);

  ASSERT (c->type == RTE_CRYPTO_SYM_XFORM_CIPHER);

  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  xform->cipher.algo = c->alg;
  xform->cipher.key.data = sa->crypto_key;
  xform->cipher.key.length = c->key_len;
  xform->cipher.iv.offset =
    crypto_op_get_priv_offset () + offsetof (dpdk_op_priv_t, cb);
  xform->cipher.iv.length = c->iv_len;
  xform->next = NULL;

  if (is_outbound)
    xform->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
  else
    xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
}

static void
crypto_set_auth_xform (struct rte_crypto_sym_xform *xform,
		       ipsec_sa_t * sa, u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *a;

  a = vec_elt_at_index (dcm->auth_algs, sa->integ_alg);

  ASSERT (a->type == RTE_CRYPTO_SYM_XFORM_AUTH);

  xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  xform->auth.algo = a->alg;
  xform->auth.key.data = sa->integ_key;
  xform->auth.key.length = a->key_len;
  xform->auth.digest_length = a->trunc_size;
  xform->next = NULL;

  if (is_outbound)
    xform->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
  else
    xform->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
}

clib_error_t *
create_sym_session (struct rte_cryptodev_sym_session **session,
		    u32 sa_idx,
		    crypto_resource_t * res,
		    crypto_worker_main_t * cwm, u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  ipsec_main_t *im = &ipsec_main;
  crypto_data_t *data;
  ipsec_sa_t *sa;
  struct rte_crypto_sym_xform cipher_xform = { 0 };
  struct rte_crypto_sym_xform auth_xform = { 0 };
  struct rte_crypto_sym_xform *xfs;
  crypto_session_key_t key = { 0 };

  key.drv_id = res->drv_id;
  key.sa_idx = sa_idx;

  sa = pool_elt_at_index (im->sad, sa_idx);

  if ((sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128) |
      (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_192) |
      (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_256))
    {
      crypto_set_aead_xform (&cipher_xform, sa, is_outbound);
      xfs = &cipher_xform;
    }
  else
    {
      crypto_set_cipher_xform (&cipher_xform, sa, is_outbound);
      crypto_set_auth_xform (&auth_xform, sa, is_outbound);

      if (is_outbound)
	{
	  cipher_xform.next = &auth_xform;
	  xfs = &cipher_xform;
	}
      else
	{
	  auth_xform.next = &cipher_xform;
	  xfs = &auth_xform;
	}
    }

  data = vec_elt_at_index (dcm->data, res->numa);

  /*
   * DPDK_VER >= 1708:
   *   Multiple worker/threads share the session for an SA
   *   Single session per SA, initialized for each device driver
   */
  session[0] = (void *) hash_get (data->session_by_sa_index, sa_idx);

  if (!session[0])
    {
      session[0] = rte_cryptodev_sym_session_create (data->session_h);
      if (!session[0])
	{
	  data->session_h_failed += 1;
	  return clib_error_return (0, "failed to create session header");
	}
      hash_set (data->session_by_sa_index, sa_idx, session[0]);
    }

  struct rte_mempool **mp;
  mp = vec_elt_at_index (data->session_drv, res->drv_id);
  ASSERT (mp[0] != NULL);

  i32 ret =
    rte_cryptodev_sym_session_init (res->dev_id, session[0], xfs, mp[0]);
  if (ret)
    {
      data->session_drv_failed[res->drv_id] += 1;
      return clib_error_return (0, "failed to init session for drv %u",
				res->drv_id);
    }

  hash_set (cwm->session_by_drv_id_and_sa_index, key.val, session[0]);

  return 0;
}

static void __attribute__ ((unused)) clear_and_free_obj (void *obj)
{
  struct rte_mempool *mp = rte_mempool_from_obj (obj);

  memset (obj, 0, mp->elt_size);

  rte_mempool_put (mp, obj);
}

/* This is from rte_cryptodev_pmd.h */
static inline void *
get_session_private_data (const struct rte_cryptodev_sym_session *sess,
			  uint8_t driver_id)
{
  return sess->sess_private_data[driver_id];
}

/* This is from rte_cryptodev_pmd.h */
static inline void
set_session_private_data (struct rte_cryptodev_sym_session *sess,
			  uint8_t driver_id, void *private_data)
{
  sess->sess_private_data[driver_id] = private_data;
}

static clib_error_t *
add_del_sa_session (u32 sa_index, u8 is_add)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm;
  struct rte_cryptodev_sym_session *s;
  crypto_session_key_t key = { 0 };
  uword *val;
  u32 drv_id;
  i32 ret;

  key.sa_idx = sa_index;

  if (is_add)
    {
#if 1
      ipsec_sa_t *sa = pool_elt_at_index (im->sad, sa_index);
      u32 seed;
      switch (sa->crypto_alg)
	{
	case IPSEC_CRYPTO_ALG_AES_GCM_128:
	case IPSEC_CRYPTO_ALG_AES_GCM_192:
	case IPSEC_CRYPTO_ALG_AES_GCM_256:
	  clib_memcpy (&sa->salt, &sa->crypto_key[sa->crypto_key_len - 4], 4);
	  break;
	default:
	  seed = (u32) clib_cpu_time_now ();
	  sa->salt = random_u32 (&seed);
	}
#endif
      return 0;
    }

  /* XXX Wait N cycles to be sure session is not in use OR
   * keep refcnt at SA level per worker/thread ? */
  unix_sleep (0.2);

  /* *INDENT-OFF* */
  vec_foreach (cwm, dcm->workers_main)
    {
      for (drv_id = 0; drv_id < dcm->max_drv_id; drv_id++)
	{
	  key.drv_id = drv_id;
	  val = hash_get (cwm->session_by_drv_id_and_sa_index, key.val);
	  s = (struct rte_cryptodev_sym_session *) val;

	  if (!s)
	    continue;

	  hash_unset (cwm->session_by_drv_id_and_sa_index, key.val);
	}
    }
  /* *INDENT-ON* */

  crypto_data_t *data;
  /* *INDENT-OFF* */
  vec_foreach (data, dcm->data)
    {
      val = hash_get (data->session_by_sa_index, sa_index);
      s = (struct rte_cryptodev_sym_session *) val;

      if (!s)
	continue;

      hash_unset (data->session_by_sa_index, sa_index);

      void *drv_session;
      vec_foreach_index (drv_id, dcm->drv)
	{
	  drv_session = get_session_private_data (s, drv_id);
	  if (!drv_session)
	    continue;

	  /*
	   * Custom clear to avoid finding a dev_id for drv_id:
	   *  ret = rte_cryptodev_sym_session_clear (dev_id, drv_session);
	   *  ASSERT (!ret);
	   */
	  clear_and_free_obj (drv_session);

	  set_session_private_data (s, drv_id, NULL);
	}

      ret = rte_cryptodev_sym_session_free(s);
      ASSERT (!ret);
    }
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
dpdk_ipsec_check_support (ipsec_sa_t * sa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    switch (sa->crypto_alg)
      {
      case IPSEC_CRYPTO_ALG_AES_GCM_128:
      case IPSEC_CRYPTO_ALG_AES_GCM_192:
      case IPSEC_CRYPTO_ALG_AES_GCM_256:
	break;
      default:
	return clib_error_return (0, "unsupported integ-alg %U crypto-alg %U",
				  format_ipsec_integ_alg, sa->integ_alg,
				  format_ipsec_crypto_alg, sa->crypto_alg);
      }

  /* XXX do we need the NONE check? */
  if (sa->crypto_alg != IPSEC_CRYPTO_ALG_NONE &&
      dcm->cipher_algs[sa->crypto_alg].disabled)
    return clib_error_return (0, "disabled crypto-alg %U",
			      format_ipsec_crypto_alg, sa->crypto_alg);

  /* XXX do we need the NONE check? */
  if (sa->integ_alg != IPSEC_INTEG_ALG_NONE &&
      dcm->auth_algs[sa->integ_alg].disabled)
    return clib_error_return (0, "disabled integ-alg %U",
			      format_ipsec_integ_alg, sa->integ_alg);
  return NULL;
}

static void
crypto_parse_capabilities (crypto_dev_t * dev,
			   const struct rte_cryptodev_capabilities *cap,
			   u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;
  u8 len, inc;

  for (; cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; cap++)
    {
      /* A single capability maps to multiple cipher/auth algorithms */
      switch (cap->sym.xform_type)
	{
	case RTE_CRYPTO_SYM_XFORM_AEAD:
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
	  inc = cap->sym.cipher.key_size.increment;
	  inc = inc ? inc : 1;
	  for (len = cap->sym.cipher.key_size.min;
	       len <= cap->sym.cipher.key_size.max; len += inc)
	    {
	      alg = cipher_cap_to_alg (cap, len);
	      if (!alg)
		continue;
	      dev->cipher_support[cipher_alg_index (alg)] = 1;
	      alg->resources += vec_len (dev->free_resources);
	      /* At least enough resources to support one algo */
	      dcm->enabled |= (alg->resources >= n_mains);
	    }
	  break;
	case RTE_CRYPTO_SYM_XFORM_AUTH:
	  inc = cap->sym.auth.digest_size.increment;
	  inc = inc ? inc : 1;
	  for (len = cap->sym.auth.digest_size.min;
	       len <= cap->sym.auth.digest_size.max; len += inc)
	    {
	      alg = auth_cap_to_alg (cap, len);
	      if (!alg)
		continue;
	      dev->auth_support[auth_alg_index (alg)] = 1;
	      alg->resources += vec_len (dev->free_resources);
	      /* At least enough resources to support one algo */
	      dcm->enabled |= (alg->resources >= n_mains);
	    }
	  break;
	default:
	  ;
	}
    }
}

#define DPDK_CRYPTO_N_QUEUE_DESC  2048
#define DPDK_CRYPTO_NB_SESS_OBJS  20000

static clib_error_t *
crypto_dev_conf (u8 dev, u16 n_qp, u8 numa)
{
  struct rte_cryptodev_config dev_conf;
  struct rte_cryptodev_qp_conf qp_conf;
  i32 ret;
  u16 qp;
  i8 *error_str;

  dev_conf.socket_id = numa;
  dev_conf.nb_queue_pairs = n_qp;

  error_str = "failed to configure crypto device %u";
  ret = rte_cryptodev_configure (dev, &dev_conf);
  if (ret < 0)
    return clib_error_return (0, error_str, dev);

  error_str = "failed to setup crypto device %u queue pair %u";
  qp_conf.nb_descriptors = DPDK_CRYPTO_N_QUEUE_DESC;
  for (qp = 0; qp < n_qp; qp++)
    {
      ret = rte_cryptodev_queue_pair_setup (dev, qp, &qp_conf, numa, NULL);
      if (ret < 0)
	return clib_error_return (0, error_str, dev, qp);
    }

  return 0;
}

static void
crypto_scan_devs (u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  struct rte_cryptodev *cryptodev;
  struct rte_cryptodev_info info;
  crypto_dev_t *dev;
  crypto_resource_t *res;
  clib_error_t *error;
  u32 i;
  u16 max_res_idx, res_idx, j;
  u8 drv_id;

  vec_validate_init_empty (dcm->dev, rte_cryptodev_count () - 1,
			   (crypto_dev_t) EMPTY_STRUCT);

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      dev = vec_elt_at_index (dcm->dev, i);

      cryptodev = &rte_cryptodevs[i];
      rte_cryptodev_info_get (i, &info);

      dev->id = i;
      dev->name = cryptodev->data->name;
      dev->numa = rte_cryptodev_socket_id (i);
      dev->features = info.feature_flags;
      dev->max_qp = info.max_nb_queue_pairs;
      drv_id = info.driver_id;
      if (drv_id >= vec_len (dcm->drv))
	vec_validate_init_empty (dcm->drv, drv_id,
				 (crypto_drv_t) EMPTY_STRUCT);
      vec_elt_at_index (dcm->drv, drv_id)->name = info.driver_name;
      dev->drv_id = drv_id;
      vec_add1 (vec_elt_at_index (dcm->drv, drv_id)->devs, i);

      if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      if ((error = crypto_dev_conf (i, dev->max_qp, dev->numa)))
	{
	  clib_error_report (error);
	  continue;
	}

      max_res_idx = (dev->max_qp / 2) - 1;

      vec_validate (dev->free_resources, max_res_idx);

      res_idx = vec_len (dcm->resource);
      vec_validate_init_empty_aligned (dcm->resource, res_idx + max_res_idx,
				       (crypto_resource_t) EMPTY_STRUCT,
				       CLIB_CACHE_LINE_BYTES);

      for (j = 0; j <= max_res_idx; j++, res_idx++)
	{
	  vec_elt (dev->free_resources, max_res_idx - j) = res_idx;
	  res = &dcm->resource[res_idx];
	  res->dev_id = i;
	  res->drv_id = drv_id;
	  res->qp_id = j * 2;
	  res->numa = dev->numa;
	  res->thread_idx = (u16) ~ 0;
	}

      crypto_parse_capabilities (dev, info.capabilities, n_mains);
    }
}

void
crypto_auto_placement (void)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res;
  crypto_worker_main_t *cwm;
  crypto_dev_t *dev;
  u32 thread_idx, skip_master;
  u16 res_idx, *idx;
  u8 used;
  u16 i;

  skip_master = vlib_num_workers () > 0;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
    {
      vec_foreach_index (thread_idx, dcm->workers_main)
	{
	  if (vec_len (dev->free_resources) == 0)
	    break;

	  if (thread_idx < skip_master)
	    continue;

	  /* Check thread is not already using the device */
	  vec_foreach (idx, dev->used_resources)
	    if (dcm->resource[idx[0]].thread_idx == thread_idx)
	      continue;

	  cwm = vec_elt_at_index (dcm->workers_main, thread_idx);

	  used = 0;
	  res_idx = vec_pop (dev->free_resources);

	  /* Set device only for supported algos */
	  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
	    if (dev->cipher_support[i] &&
		cwm->cipher_resource_idx[i] == (u16) ~0)
	      {
		dcm->cipher_algs[i].disabled--;
		cwm->cipher_resource_idx[i] = res_idx;
		used = 1;
	      }

	  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
	    if (dev->auth_support[i] &&
		cwm->auth_resource_idx[i] == (u16) ~0)
	      {
		dcm->auth_algs[i].disabled--;
		cwm->auth_resource_idx[i] = res_idx;
		used = 1;
	      }

	  if (!used)
	    {
	      vec_add1 (dev->free_resources, res_idx);
	      continue;
	    }

	  vec_add1 (dev->used_resources, res_idx);

	  res = vec_elt_at_index (dcm->resource, res_idx);

	  ASSERT (res->thread_idx == (u16) ~0);
	  res->thread_idx = thread_idx;

	  /* Add device to vector of polling resources */
	  vec_add1 (cwm->resource_idx, res_idx);
	}
    }
  /* *INDENT-ON* */
}

static void
crypto_op_init (struct rte_mempool *mempool,
		void *_arg __attribute__ ((unused)),
		void *_obj, unsigned i __attribute__ ((unused)))
{
  struct rte_crypto_op *op = _obj;

  op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
  op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->phys_addr = rte_mem_virt2phy (_obj);
  op->mempool = mempool;
}

static clib_error_t *
crypto_create_crypto_op_pool (vlib_main_t * vm, u8 numa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  dpdk_config_main_t *conf = &dpdk_config_main;
  crypto_data_t *data;
  u8 *pool_name;
  u32 pool_priv_size = sizeof (struct rte_crypto_op_pool_private);
  struct rte_crypto_op_pool_private *priv;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;

  data = vec_elt_at_index (dcm->data, numa);

  /* Already allocated */
  if (data->crypto_op)
    return NULL;

  pool_name = format (0, "crypto_pool_numa%u%c", numa, 0);

  error =
    dpdk_pool_create (vm, pool_name, crypto_op_len (), conf->num_mbufs,
		      pool_priv_size, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  /* Initialize mempool private data */
  priv = rte_mempool_get_priv (mp);
  priv->priv_size = pool_priv_size;
  priv->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;

  /* call the object initializers */
  rte_mempool_obj_iter (mp, crypto_op_init, 0);

  data->crypto_op = mp;

  return NULL;
}

static clib_error_t *
crypto_create_session_h_pool (vlib_main_t * vm, u8 numa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  u8 *pool_name;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;
  u32 elt_size;

  data = vec_elt_at_index (dcm->data, numa);

  if (data->session_h)
    return NULL;

  pool_name = format (0, "session_h_pool_numa%u%c", numa, 0);

  elt_size = rte_cryptodev_get_header_session_size ();

  error =
    dpdk_pool_create (vm, pool_name, elt_size, DPDK_CRYPTO_NB_SESS_OBJS,
		      0, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  data->session_h = mp;

  return NULL;
}

static clib_error_t *
crypto_create_session_drv_pool (vlib_main_t * vm, crypto_dev_t * dev)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  u8 *pool_name;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;
  u32 elt_size;
  u8 numa = dev->numa;

  data = vec_elt_at_index (dcm->data, numa);

  vec_validate (data->session_drv, dev->drv_id);
  vec_validate (data->session_drv_failed, dev->drv_id);

  if (data->session_drv[dev->drv_id])
    return NULL;

  pool_name = format (0, "session_drv%u_pool_numa%u%c", dev->drv_id, numa, 0);
  elt_size = rte_cryptodev_get_private_session_size (dev->id);

  error =
    dpdk_pool_create (vm, pool_name, elt_size, DPDK_CRYPTO_NB_SESS_OBJS,
		      0, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  data->session_drv[dev->drv_id] = mp;

  return NULL;
}

static clib_error_t *
crypto_create_pools (vlib_main_t * vm)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  clib_error_t *error = NULL;
  crypto_dev_t *dev;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
    {
      vec_validate_aligned (dcm->data, dev->numa, CLIB_CACHE_LINE_BYTES);

      error = crypto_create_crypto_op_pool (vm, dev->numa);
      if (error)
	return error;

      error = crypto_create_session_h_pool (vm, dev->numa);
      if (error)
	return error;

      error = crypto_create_session_drv_pool (vm, dev);
      if (error)
	return error;
    }
  /* *INDENT-ON* */

  return NULL;
}

static void
crypto_disable (void)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  u8 i;

  dcm->enabled = 0;

  /* *INDENT-OFF* */
  vec_foreach (data, dcm->data)
    {
      rte_mempool_free (data->crypto_op);
      rte_mempool_free (data->session_h);

      vec_foreach_index (i, data->session_drv)
	rte_mempool_free (data->session_drv[i]);

      vec_free (data->session_drv);
    }
  /* *INDENT-ON* */

  vec_free (dcm->data);
  vec_free (dcm->workers_main);
  vec_free (dcm->sa_session);
  vec_free (dcm->dev);
  vec_free (dcm->resource);
  vec_free (dcm->cipher_algs);
  vec_free (dcm->auth_algs);
}

static uword
dpdk_ipsec_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  crypto_worker_main_t *cwm;
  clib_error_t *error = NULL;
  u32 i, skip_master, n_mains;

  n_mains = tm->n_vlib_mains;
  skip_master = vlib_num_workers () > 0;

  algos_init (n_mains - skip_master);

  crypto_scan_devs (n_mains - skip_master);

  if (!(dcm->enabled))
    {
      clib_warning ("not enough DPDK crypto resources, default to OpenSSL");
      crypto_disable ();
      return 0;
    }

  vec_validate_init_empty_aligned (dcm->workers_main, n_mains - 1,
				   (crypto_worker_main_t) EMPTY_STRUCT,
				   CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  vec_foreach (cwm, dcm->workers_main)
    {
      vec_validate_init_empty_aligned (cwm->ops, VLIB_FRAME_SIZE - 1, 0,
				       CLIB_CACHE_LINE_BYTES);
      memset (cwm->cipher_resource_idx, ~0,
	      IPSEC_CRYPTO_N_ALG * sizeof(*cwm->cipher_resource_idx));
      memset (cwm->auth_resource_idx, ~0,
	      IPSEC_INTEG_N_ALG * sizeof(*cwm->auth_resource_idx));
    }
  /* *INDENT-ON* */

  crypto_auto_placement ();

  error = crypto_create_pools (vm);
  if (error)
    {
      clib_error_report (error);
      crypto_disable ();
      return 0;
    }

  /* Add new next node and set it as default */
  vlib_node_t *node, *next_node;

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-encrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-output-ip4");
  ASSERT (node);
  im->esp_encrypt_node_index = next_node->index;
  im->esp_encrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-decrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-input-ip4");
  ASSERT (node);
  im->esp_decrypt_node_index = next_node->index;
  im->esp_decrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  im->cb.check_support_cb = dpdk_ipsec_check_support;
  im->cb.add_del_sa_sess_cb = add_del_sa_session;

  node = vlib_get_node_by_name (vm, (u8 *) "dpdk-crypto-input");
  ASSERT (node);
  for (i = skip_master; i < n_mains; i++)
    vlib_node_set_state (vlib_mains[i], node->index, VLIB_NODE_STATE_POLLING);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_ipsec_process_node,static) = {
    .function = dpdk_ipsec_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-ipsec-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
