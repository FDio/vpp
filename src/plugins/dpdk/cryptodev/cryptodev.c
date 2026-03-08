/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Intel and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vnet/ipsec/ipsec.h>
#include <vpp/app/version.h>

#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#undef always_inline
#include <rte_bus_vdev.h>
#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>
#include <rte_crypto.h>
#include <rte_config.h>

#include "cryptodev.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

cryptodev_main_t cryptodev_main;

VLIB_REGISTER_LOG_CLASS (cryptodev_log, static) = {
  .class_name = "dpdk",
  .subclass_name = "cryptodev",
};

#define log_debug(...) vlib_log (VLIB_LOG_LEVEL_DEBUG, cryptodev_log.class, __VA_ARGS__)

static int
cryptodev_get_aead_algo (vnet_crypto_alg_family_t family, enum rte_crypto_aead_algorithm *algo)
{
  static const enum rte_crypto_aead_algorithm algs[] = {
    [VNET_CRYPTO_ALG_FAMILY_AES_GCM] = RTE_CRYPTO_AEAD_AES_GCM,
    [VNET_CRYPTO_ALG_FAMILY_CHACHA20_POLY1305] = RTE_CRYPTO_AEAD_CHACHA20_POLY1305,
  };

  if (family >= ARRAY_LEN (algs) || algs[family] == 0)
    return -1;

  *algo = algs[family];
  return 0;
}

static_always_inline u32
cryptodev_get_aead_iv_len (const vnet_crypto_alg_data_t *ad)
{
  if (ad->cipher_family == VNET_CRYPTO_ALG_FAMILY_AES_GCM ||
      ad->cipher_family == VNET_CRYPTO_ALG_FAMILY_CHACHA20_POLY1305)
    return 12;

  return 0;
}

static_always_inline u32
cryptodev_get_aead_iv_len_by_algo (enum rte_crypto_aead_algorithm algo)
{
  if (algo == RTE_CRYPTO_AEAD_AES_GCM || algo == RTE_CRYPTO_AEAD_CHACHA20_POLY1305)
    return 12;

  return 0;
}

static int
cryptodev_get_cipher_algo (vnet_crypto_alg_family_t family, enum rte_crypto_cipher_algorithm *algo)
{
  static const enum rte_crypto_cipher_algorithm algs[] = {
    [VNET_CRYPTO_ALG_FAMILY_DES_CBC] = RTE_CRYPTO_CIPHER_DES_CBC,
    [VNET_CRYPTO_ALG_FAMILY_TDES_CBC] = RTE_CRYPTO_CIPHER_3DES_CBC,
    [VNET_CRYPTO_ALG_FAMILY_AES_CBC] = RTE_CRYPTO_CIPHER_AES_CBC,
    [VNET_CRYPTO_ALG_FAMILY_AES_CTR] = RTE_CRYPTO_CIPHER_AES_CTR,
  };

  if (family >= ARRAY_LEN (algs) || algs[family] == 0)
    return -1;

  *algo = algs[family];
  return 0;
}

static_always_inline u8
cryptodev_alg_is_gmac (const vnet_crypto_alg_data_t *ad)
{
  return ad->cipher_family == VNET_CRYPTO_ALG_FAMILY_AES_NULL_GMAC;
}

static int
cryptodev_get_auth_algo (vnet_crypto_alg_family_t family, u32 digest_len,
			 enum rte_crypto_auth_algorithm *algo)
{
  switch (family)
    {
    case VNET_CRYPTO_ALG_FAMILY_MD5:
      *algo = RTE_CRYPTO_AUTH_MD5_HMAC;
      return 0;
    case VNET_CRYPTO_ALG_FAMILY_SHA1:
      *algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
      return 0;
    case VNET_CRYPTO_ALG_FAMILY_SHA2:
      switch (digest_len)
	{
	case 14:
	case 28:
	  *algo = RTE_CRYPTO_AUTH_SHA224_HMAC;
	  return 0;
	case 16:
	case 32:
	  *algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
	  return 0;
	case 24:
	case 48:
	  *algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
	  return 0;
	case 64:
	  *algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
	  return 0;
	default:
	  return -1;
	}
    case VNET_CRYPTO_ALG_FAMILY_AES_NULL_GMAC:
      *algo = RTE_CRYPTO_AUTH_AES_GMAC;
      return 0;
    default:
      return -1;
    }
}

static_always_inline u8
cryptodev_key_is_combined (const vnet_crypto_key_t *key)
{
  vnet_crypto_main_t *cm = &crypto_main;

  return cm->algs[key->alg].alg_type == VNET_CRYPTO_ALG_T_COMBINED;
}

static_always_inline int
prepare_auth_xform (struct rte_crypto_sym_xform *xform, cryptodev_op_type_t op_type,
		    const vnet_crypto_key_t *key, u32 digest_len)
{
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;
  struct rte_crypto_auth_xform *auth_xform = &xform->auth;
  enum rte_crypto_auth_algorithm auth_algo = ~0;
  u8 is_enc = op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT;

  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  xform->next = 0;

  if (cryptodev_get_auth_algo (ad->auth_family, ad->auth_len, &auth_algo))
    return -1;

  auth_xform->op = is_enc ? RTE_CRYPTO_AUTH_OP_GENERATE : RTE_CRYPTO_AUTH_OP_VERIFY;
  auth_xform->algo = auth_algo;
  auth_xform->digest_length = digest_len;
  auth_xform->iv.offset = CRYPTODEV_IV_OFFSET;
  auth_xform->iv.length = cryptodev_alg_is_gmac (ad) ? 12 : 0;
  auth_xform->key.data = (u8 *) vnet_crypto_get_cipher_key (key);
  auth_xform->key.length = key->cipher_key_sz;

  return 0;
}

static_always_inline int
prepare_cipher_xform (struct rte_crypto_sym_xform *xform, cryptodev_op_type_t op_type,
		      const vnet_crypto_key_t *key)
{
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;
  struct rte_crypto_cipher_xform *cipher_xform = &xform->cipher;
  enum rte_crypto_cipher_algorithm cipher_algo = ~0;
  u8 is_enc = op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT;

  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  xform->next = 0;

  if (cryptodev_get_cipher_algo (ad->cipher_family, &cipher_algo))
    return -1;

  cipher_xform->op = is_enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;
  cipher_xform->algo = cipher_algo;
  cipher_xform->key.data = (u8 *) vnet_crypto_get_cipher_key (key);
  cipher_xform->key.length = key->cipher_key_sz;
  cipher_xform->iv.length = 16;
  cipher_xform->iv.offset = CRYPTODEV_IV_OFFSET;

  return 0;
}

static_always_inline int
prepare_aead_xform (struct rte_crypto_sym_xform *xform, cryptodev_op_type_t op_type,
		    const vnet_crypto_key_t *key, u32 aad_len, u32 digest_len)
{
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;
  struct rte_crypto_aead_xform *aead_xform = &xform->aead;
  u8 is_enc = op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT;

  if (cryptodev_alg_is_gmac (ad))
    return prepare_auth_xform (xform, op_type, key, digest_len);

  memset (xform, 0, sizeof (*xform));
  xform->next = 0;

  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  if (cryptodev_get_aead_algo (ad->cipher_family, &aead_xform->algo))
    return -1;

  aead_xform->op = is_enc ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT;
  aead_xform->aad_length = aad_len;
  aead_xform->digest_length = digest_len;
  aead_xform->iv.offset = CRYPTODEV_IV_OFFSET;
  aead_xform->iv.length = cryptodev_get_aead_iv_len (ad);
  aead_xform->key.data = (u8 *) vnet_crypto_get_cipher_key (key);
  aead_xform->key.length = key->cipher_key_sz;

  return 0;
}

static_always_inline int
prepare_linked_xform (struct rte_crypto_sym_xform *xforms,
		      cryptodev_op_type_t op_type,
		      const vnet_crypto_key_t *key)
{
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;
  struct rte_crypto_sym_xform *xform_cipher, *xform_auth;
  enum rte_crypto_cipher_algorithm cipher_algo = ~0;
  enum rte_crypto_auth_algorithm auth_algo = ~0;
  u8 is_enc = op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT;

  if (cryptodev_alg_is_gmac (ad))
    return prepare_auth_xform (xforms, op_type, key, ad->auth_len);

  if (is_enc)
    {
      xform_cipher = xforms;
      xform_auth = xforms + 1;
      xform_cipher->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
      xform_auth->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
    }
  else
    {
      xform_cipher = xforms + 1;
      xform_auth = xforms;
      xform_cipher->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
      xform_auth->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
    }

  xform_cipher->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  xform_auth->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  xforms->next = xforms + 1;

  if (cryptodev_get_cipher_algo (ad->cipher_family, &cipher_algo) ||
      cryptodev_get_auth_algo (ad->auth_family, ad->auth_len, &auth_algo))
    return -1;

  xform_cipher->cipher.algo = cipher_algo;
  xform_cipher->cipher.key.data = (u8 *) vnet_crypto_get_cipher_key (key);
  xform_cipher->cipher.key.length = key->cipher_key_sz;
  xform_cipher->cipher.iv.length = 16;
  xform_cipher->cipher.iv.offset = CRYPTODEV_IV_OFFSET;

  xform_auth->auth.algo = auth_algo;
  xform_auth->auth.digest_length = ad->auth_len;
  xform_auth->auth.key.data = (u8 *) vnet_crypto_get_auth_key (key);
  xform_auth->auth.key.length = key->auth_key_sz;

  return 0;
}

static_always_inline int
cryptodev_prepare_sym_xform (struct rte_crypto_sym_xform *xform, cryptodev_op_type_t op_type,
			     const vnet_crypto_key_t *key, u32 aad_len, u32 digest_len)
{
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;

  if (cryptodev_key_is_combined (key))
    return prepare_linked_xform (xform, op_type, key);

  if (ad->alg_type == VNET_CRYPTO_ALG_T_CIPHER)
    return prepare_cipher_xform (xform, op_type, key);
  if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH)
    return prepare_auth_xform (xform, op_type, key, digest_len);

  return prepare_aead_xform (xform, op_type, key, aad_len, digest_len);
}

static_always_inline u32
cryptodev_session_opaque_data (const vnet_crypto_alg_data_t *ad, u32 aad_len, u32 digest_len)
{
  return ad->alg_type == VNET_CRYPTO_ALG_T_AUTH ? digest_len : aad_len;
}

static_always_inline void
cryptodev_session_del (cryptodev_session_t *sess)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;

  if (sess == NULL)
    return;

  if (vec_len (cmt->cryptodev_inst) == 0)
    return;

  dev_inst = vec_elt_at_index (cmt->cryptodev_inst, 0);
  rte_cryptodev_sym_session_free (dev_inst->dev_id, sess);
}

static_always_inline int
cryptodev_check_param_range (const struct rte_crypto_param_range *range, u32 size)
{
  if (size == (u32) ~0)
    return 1;

  if (size < range->min || size > range->max)
    return 0;

  if (range->increment && (size - range->min) % range->increment)
    return 0;

  return 1;
}

static int
cryptodev_check_cap_support (struct rte_cryptodev_sym_capability_idx *idx, u32 key_size,
			     u32 digest_size, u32 aad_size)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  u32 previous_dev_id = ~0;

  vec_foreach (dev_inst, cmt->cryptodev_inst)
    {
      const struct rte_cryptodev_symmetric_capability *cap;

      if (dev_inst->dev_id == previous_dev_id)
	continue;
      previous_dev_id = dev_inst->dev_id;

      cap = rte_cryptodev_sym_capability_get (dev_inst->dev_id, idx);
      if (cap == NULL)
	return 0;

      if (idx->type == RTE_CRYPTO_SYM_XFORM_AUTH)
	{
	  u32 iv_size = idx->algo.auth == RTE_CRYPTO_AUTH_AES_GMAC ? 12 : 0;
	  u32 cap_aad_size = aad_size;

	  if (idx->algo.auth == RTE_CRYPTO_AUTH_AES_GMAC)
	    cap_aad_size = (u32) ~0;

	  if (!cryptodev_check_param_range (&cap->auth.key_size, key_size) ||
	      !cryptodev_check_param_range (&cap->auth.digest_size, digest_size) ||
	      !cryptodev_check_param_range (&cap->auth.aad_size, cap_aad_size) ||
	      !cryptodev_check_param_range (&cap->auth.iv_size, iv_size))
	    return 0;
	}
      else if (idx->type == RTE_CRYPTO_SYM_XFORM_CIPHER)
	{
	  if (!cryptodev_check_param_range (&cap->cipher.key_size, key_size) ||
	      !cryptodev_check_param_range (&cap->cipher.iv_size, 16))
	    return 0;
	}
      else if (idx->type == RTE_CRYPTO_SYM_XFORM_AEAD)
	{
	  if (!cryptodev_check_param_range (&cap->aead.key_size, key_size) ||
	      !cryptodev_check_param_range (&cap->aead.digest_size, digest_size) ||
	      !cryptodev_check_param_range (&cap->aead.aad_size, aad_size) ||
	      !cryptodev_check_param_range (&cap->aead.iv_size,
					    cryptodev_get_aead_iv_len_by_algo (idx->algo.aead)))
	    return 0;
	}
    }

  return 1;
}

void
cryptodev_sess_handler (vlib_main_t *vm __clib_unused, vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  cryptodev_key_data_t *ckey = cryptodev_get_key_data (key);
  u32 i, j;
  cryptodev_main_t *cmt = &cryptodev_main;

  for (i = 0; i < cmt->n_numa_nodes; i++)
    {
      for (j = 0; j < VNET_CRYPTO_OP_N_TYPES; j++)
	{
	  cryptodev_session_del (cryptodev_session_get (ckey, i, j));
	  cryptodev_session_set (ckey, i, j, 0);
	}
    }
}

static void
cryptodev_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  if (args->action != VNET_CRYPTO_KEY_DATA_REMOVE)
    return;

  cryptodev_sess_handler (vlib_get_main (), key->index);
}

clib_error_t *
allocate_session_pools (u32 numa_node,
			cryptodev_session_pool_t *sess_pools_elt, u32 len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u8 *name;
  clib_error_t *error = NULL;

  name = format (0, "vcrypto_sess_pool_%u_%04x%c", numa_node, len, 0);
  sess_pools_elt->sess_pool = rte_cryptodev_sym_session_pool_create (
    (char *) name, CRYPTODEV_NB_SESSION, cmt->sess_sz, 0, 0, numa_node);

  if (!sess_pools_elt->sess_pool)
    {
      error = clib_error_return (0, "Not enough memory for mp %s", name);
      goto clear_mempools;
    }
  vec_free (name);

clear_mempools:
  if (error)
    {
      vec_free (name);
      if (sess_pools_elt->sess_pool)
	rte_mempool_free (sess_pools_elt->sess_pool);
      return error;
    }
  return 0;
}

int
cryptodev_session_create (vlib_main_t *vm, vnet_crypto_key_index_t idx, u32 aad_len, u32 digest_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  cryptodev_inst_t *dev_inst;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  vnet_crypto_alg_data_t *ad = crypto_main.algs + key->alg;
  cryptodev_key_data_t *ckey = cryptodev_get_key_data (key);
  struct rte_mempool *sess_pool;
  cryptodev_session_pool_t *sess_pools_elt;
  struct rte_crypto_sym_xform xforms_enc[2] = { { 0 } };
  struct rte_crypto_sym_xform xforms_dec[2] = { { 0 } };
  cryptodev_session_t *sessions[VNET_CRYPTO_OP_N_TYPES] = { 0 };
  u32 numa_node = vm->numa_node;
  clib_error_t *error;
  int ret = 0;
  u8 found = 0;

  numa_data = vec_elt_at_index (cmt->per_numa_data, numa_node);

  clib_spinlock_lock (&cmt->tlock);
  vec_foreach (sess_pools_elt, numa_data->sess_pools)
    {
      if (sess_pools_elt->sess_pool == NULL)
	{
	  error = allocate_session_pools (numa_node, sess_pools_elt,
					  vec_len (numa_data->sess_pools) - 1);
	  if (error)
	    {
	      ret = -1;
	      goto clear_key;
	    }
	}
      if (rte_mempool_avail_count (sess_pools_elt->sess_pool) >= 2)
	{
	  found = 1;
	  break;
	}
    }

  if (found == 0)
    {
      vec_add2 (numa_data->sess_pools, sess_pools_elt, 1);
      error = allocate_session_pools (numa_node, sess_pools_elt,
				      vec_len (numa_data->sess_pools) - 1);
      if (error)
	{
	  ret = -1;
	  goto clear_key;
	}
    }

  sess_pool = sess_pools_elt->sess_pool;

  ret =
    cryptodev_prepare_sym_xform (xforms_enc, VNET_CRYPTO_OP_TYPE_ENCRYPT, key, aad_len, digest_len);
  if (ret)
    {
      ret = -1;
      goto clear_key;
    }

  cryptodev_prepare_sym_xform (xforms_dec, VNET_CRYPTO_OP_TYPE_DECRYPT, key, aad_len, digest_len);

  dev_inst = vec_elt_at_index (cmt->cryptodev_inst, 0);
  u32 dev_id = dev_inst->dev_id;
  sessions[VNET_CRYPTO_OP_TYPE_ENCRYPT] =
    rte_cryptodev_sym_session_create (dev_id, xforms_enc, sess_pool);
  sessions[VNET_CRYPTO_OP_TYPE_DECRYPT] =
    rte_cryptodev_sym_session_create (dev_id, xforms_dec, sess_pool);
  if (!sessions[VNET_CRYPTO_OP_TYPE_ENCRYPT] || !sessions[VNET_CRYPTO_OP_TYPE_DECRYPT])
    {
      ret = -1;
      goto clear_key;
    }

  rte_cryptodev_sym_session_opaque_data_set (
    sessions[VNET_CRYPTO_OP_TYPE_ENCRYPT], cryptodev_session_opaque_data (ad, aad_len, digest_len));
  rte_cryptodev_sym_session_opaque_data_set (
    sessions[VNET_CRYPTO_OP_TYPE_DECRYPT], cryptodev_session_opaque_data (ad, aad_len, digest_len));

  cryptodev_session_set (ckey, numa_node, VNET_CRYPTO_OP_TYPE_ENCRYPT,
			 sessions[VNET_CRYPTO_OP_TYPE_ENCRYPT]);
  cryptodev_session_set (ckey, numa_node, VNET_CRYPTO_OP_TYPE_DECRYPT,
			 sessions[VNET_CRYPTO_OP_TYPE_DECRYPT]);

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (sessions[VNET_CRYPTO_OP_TYPE_ENCRYPT]);
      cryptodev_session_del (sessions[VNET_CRYPTO_OP_TYPE_DECRYPT]);
    }
  clib_spinlock_unlock (&cmt->tlock);
  return ret;
}

int
cryptodev_assign_resource_auto (cryptodev_engine_thread_t *cet)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *cinst = 0;
  uword idx;

  /* assign resource is only allowed when no inflight op is in the queue */
  if (cet->inflight)
    return -EBUSY;

  if (clib_bitmap_count_set_bits (cmt->active_cdev_inst_mask) >= vec_len (cmt->cryptodev_inst))
    return -1;

  clib_spinlock_lock (&cmt->tlock);
  idx = clib_bitmap_first_clear (cmt->active_cdev_inst_mask);
  clib_bitmap_set (cmt->active_cdev_inst_mask, idx, 1);
  cinst = vec_elt_at_index (cmt->cryptodev_inst, idx);
  cet->cryptodev_id = cinst->dev_id;
  cet->cryptodev_q = cinst->q_id;
  clib_spinlock_unlock (&cmt->tlock);

  return 0;
}

int
cryptodev_assign_resource_update (cryptodev_engine_thread_t *cet, u32 cryptodev_inst_index)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *cinst = 0;
  uword idx;

  /* assign resource is only allowed when no inflight op is in the queue */
  if (cet->inflight)
    return -EBUSY;

  /* assigning a used cryptodev resource is not allowed */
  if (clib_bitmap_get (cmt->active_cdev_inst_mask, cryptodev_inst_index) == 1)
    return -EBUSY;

  vec_foreach_index (idx, cmt->cryptodev_inst)
    {
      cinst = cmt->cryptodev_inst + idx;
      if (cinst->dev_id == cet->cryptodev_id && cinst->q_id == cet->cryptodev_q)
	break;
    }
  /* invalid existing worker resource assignment */
  if (idx >= vec_len (cmt->cryptodev_inst))
    return -EINVAL;

  clib_spinlock_lock (&cmt->tlock);
  clib_bitmap_set_no_check (cmt->active_cdev_inst_mask, idx, 0);
  clib_bitmap_set_no_check (cmt->active_cdev_inst_mask, cryptodev_inst_index, 1);
  cinst = cmt->cryptodev_inst + cryptodev_inst_index;
  cet->cryptodev_id = cinst->dev_id;
  cet->cryptodev_q = cinst->q_id;
  clib_spinlock_unlock (&cmt->tlock);

  return 0;
}

static_always_inline int
cryptodev_get_async_enc_dec (const vnet_crypto_alg_data_t *ad, cryptodev_get_enq_fn_t *get_fn,
			     vnet_crypto_op_id_t *enc_op, vnet_crypto_op_id_t *dec_op,
			     vnet_crypto_frame_enq_fn_t **enc_fn,
			     vnet_crypto_frame_enq_fn_t **dec_fn)
{
  *enc_op = ad->op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT];
  *dec_op = ad->op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT];
  if (*enc_op == VNET_CRYPTO_OP_NONE || *dec_op == VNET_CRYPTO_OP_NONE)
    return -1;

  *enc_fn = get_fn (ad, VNET_CRYPTO_OP_TYPE_ENCRYPT);
  *dec_fn = get_fn (ad, VNET_CRYPTO_OP_TYPE_DECRYPT);
  if (*enc_fn == 0 || *dec_fn == 0)
    return -1;

  return 0;
}

static_always_inline void
cryptodev_register_async_enc_dec (vlib_main_t *vm, u32 eidx, const char *backend_name,
				  const vnet_crypto_alg_data_t *ad, vnet_crypto_op_id_t enc_op,
				  vnet_crypto_op_id_t dec_op, vnet_crypto_frame_enq_fn_t *enc_fn,
				  vnet_crypto_frame_enq_fn_t *dec_fn)
{
  vnet_crypto_register_enqueue_handler (vm, eidx, enc_op, enc_fn);
  vnet_crypto_register_enqueue_handler (vm, eidx, dec_op, dec_fn);
  log_debug ("install %s alg=%s enc-op=%u dec-op=%u", backend_name, ad->name, enc_op, dec_op);
}

static u32
cryptodev_count_queue ()
{
  struct rte_cryptodev_info info;
  u32 n_cryptodev = rte_cryptodev_count ();
  u32 i, q_count = 0;

  for (i = 0; i < n_cryptodev; i++)
    {
      rte_cryptodev_info_get (i, &info);
      q_count += info.max_nb_queue_pairs;
    }

  return q_count;
}

static int
cryptodev_configure (u32 cryptodev_id)
{
  struct rte_cryptodev_config cfg;
  struct rte_cryptodev_info info;
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 i;
  int ret;

  rte_cryptodev_info_get (cryptodev_id, &info);

  /* Starting from DPDK 22.11, VPP does not allow heterogeneous crypto devices
     anymore. Only devices that have the same driver type as the first
     initialized device can be initialized.
   */
  if (cmt->drivers_cnt == 1 && cmt->driver_id != info.driver_id)
    return -1;

  if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO))
    return -1;

  cfg.socket_id = info.device->numa_node;
  cfg.nb_queue_pairs = info.max_nb_queue_pairs;

  rte_cryptodev_configure (cryptodev_id, &cfg);

  for (i = 0; i < info.max_nb_queue_pairs; i++)
    {
      struct rte_cryptodev_qp_conf qp_cfg;

      qp_cfg.mp_session = 0;
      qp_cfg.nb_descriptors = CRYPTODEV_NB_CRYPTO_OPS;

      ret = rte_cryptodev_queue_pair_setup (cryptodev_id, i, &qp_cfg,
					    info.device->numa_node);
      if (ret)
	{
	  clib_warning ("Cryptodev: Configure device %u queue %u failed %d",
			cryptodev_id, i, ret);
	  break;
	}
    }

  if (i != info.max_nb_queue_pairs)
    return -1;

  /* start the device */
  rte_cryptodev_start (cryptodev_id);

  if (cmt->drivers_cnt == 0)
    {
      cmt->drivers_cnt = 1;
      cmt->driver_id = info.driver_id;
      cmt->sess_sz = rte_cryptodev_sym_get_private_session_size (cryptodev_id);
    }

  for (i = 0; i < info.max_nb_queue_pairs; i++)
    {
      cryptodev_inst_t *cdev_inst;
      const char *dev_name = rte_dev_name (info.device);
      vec_add2(cmt->cryptodev_inst, cdev_inst, 1);
      cdev_inst->desc = vec_new (char, strlen (dev_name) + 10);
      cdev_inst->dev_id = cryptodev_id;
      cdev_inst->q_id = i;

      snprintf (cdev_inst->desc, strlen (dev_name) + 9, "%s_q%u", dev_name, i);
    }

  return 0;
}

static int
cryptodev_cmp (void *v1, void *v2)
{
  cryptodev_inst_t *a1 = v1;
  cryptodev_inst_t *a2 = v2;

  if (a1->q_id > a2->q_id)
    return 1;
  if (a1->q_id < a2->q_id)
    return -1;
  return 0;
}

u32
cryptodev_register_async_algs (vlib_main_t *vm, u32 eidx, cryptodev_get_enq_fn_t *get_fn,
			       const char *backend_name)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 ref_cnt = 0;
  u32 alg;

  for (alg = 1; alg < VNET_CRYPTO_N_ALGS; alg++)
    {
      vnet_crypto_alg_data_t *ad = cm->algs + alg;
      vnet_crypto_frame_enq_fn_t *enc_fn, *dec_fn, *hmac_fn;
      vnet_crypto_op_data_t *od;
      vnet_crypto_op_id_t enc_op, dec_op;
      vnet_crypto_op_id_t hmac_op = ad->op_by_type[VNET_CRYPTO_OP_TYPE_HMAC];

      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	{
	  enum rte_crypto_aead_algorithm aead_algo;
	  enum rte_crypto_auth_algorithm auth_algo;
	  struct rte_cryptodev_sym_capability_idx cap_idx = {
	    .type = RTE_CRYPTO_SYM_XFORM_AEAD,
	  };

	  if (cryptodev_alg_is_gmac (ad))
	    {
	      cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	      if (cryptodev_get_auth_algo (ad->auth_family, ad->auth_len, &auth_algo))
		continue;
	      cap_idx.algo.auth = auth_algo;
	    }
	  else if (cryptodev_get_aead_algo (ad->cipher_family, &aead_algo))
	    continue;
	  else
	    cap_idx.algo.aead = aead_algo;
	  if (cryptodev_get_async_enc_dec (ad, get_fn, &enc_op, &dec_op, &enc_fn, &dec_fn))
	    continue;

	  od = vnet_crypto_get_op_data (enc_op);
	  if (od->auth_len == 0)
	    continue;

	  if (!cryptodev_check_cap_support (&cap_idx, ad->key_len, od->auth_len, od->aad_len))
	    continue;

	  cryptodev_register_async_enc_dec (vm, eidx, backend_name, ad, enc_op, dec_op, enc_fn,
					    dec_fn);
	  ref_cnt++;
	}
      else if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
	{
	  enum rte_crypto_cipher_algorithm cipher_algo;
	  enum rte_crypto_auth_algorithm auth_algo;
	  struct rte_cryptodev_sym_capability_idx cap_cipher_idx = {
	    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  };
	  struct rte_cryptodev_sym_capability_idx cap_auth_idx = {
	    .type = RTE_CRYPTO_SYM_XFORM_AUTH,
	  };
	  if (cryptodev_get_async_enc_dec (ad, get_fn, &enc_op, &dec_op, &enc_fn, &dec_fn))
	    continue;

	  od = vnet_crypto_get_op_data (enc_op);
	  if (od->auth_len == 0 || cryptodev_get_cipher_algo (ad->cipher_family, &cipher_algo) ||
	      cryptodev_get_auth_algo (ad->auth_family, od->auth_len, &auth_algo))
	    continue;

	  cap_cipher_idx.algo.cipher = cipher_algo;
	  cap_auth_idx.algo.auth = auth_algo;
	  if (!cryptodev_check_cap_support (&cap_cipher_idx, ad->key_len, -1, -1) ||
	      !cryptodev_check_cap_support (&cap_auth_idx, -1, od->auth_len, -1))
	    continue;

	  cryptodev_register_async_enc_dec (vm, eidx, backend_name, ad, enc_op, dec_op, enc_fn,
					    dec_fn);
	  ref_cnt++;
	}
      else if (ad->alg_type == VNET_CRYPTO_ALG_T_CIPHER)
	{
	  enum rte_crypto_cipher_algorithm cipher_algo;
	  struct rte_cryptodev_sym_capability_idx cap_idx = {
	    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
	  };
	  if (cryptodev_get_async_enc_dec (ad, get_fn, &enc_op, &dec_op, &enc_fn, &dec_fn) ||
	      cryptodev_get_cipher_algo (ad->cipher_family, &cipher_algo))
	    continue;

	  cap_idx.algo.cipher = cipher_algo;
	  if (!cryptodev_check_cap_support (&cap_idx, ad->key_len, (u32) ~0, (u32) ~0))
	    continue;

	  cryptodev_register_async_enc_dec (vm, eidx, backend_name, ad, enc_op, dec_op, enc_fn,
					    dec_fn);
	  ref_cnt++;
	}
      else if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH)
	{
	  enum rte_crypto_auth_algorithm auth_algo;
	  struct rte_cryptodev_sym_capability_idx cap_idx = {
	    .type = RTE_CRYPTO_SYM_XFORM_AUTH,
	  };

	  if (ad->auth_family != VNET_CRYPTO_ALG_FAMILY_SHA2 ||
	      (ad->auth_len != 32 && ad->auth_len != 48 && ad->auth_len != 64) ||
	      hmac_op == VNET_CRYPTO_OP_NONE)
	    continue;

	  hmac_fn = get_fn (ad, VNET_CRYPTO_OP_TYPE_HMAC);
	  if (hmac_fn == 0 || cryptodev_get_auth_algo (ad->auth_family, ad->auth_len, &auth_algo))
	    continue;

	  cap_idx.algo.auth = auth_algo;
	  if (!cryptodev_check_cap_support (&cap_idx, ad->key_len, (u32) ~0, (u32) ~0))
	    continue;

	  vnet_crypto_register_enqueue_handler (vm, eidx, hmac_op, hmac_fn);
	  log_debug ("install %s alg=%s hmac-op=%u", backend_name, ad->name, hmac_op);
	  ref_cnt++;
	}
      else
	continue;
    }

  return ref_cnt;
}

static int
cryptodev_probe (u32 n_workers)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 n_queues = cryptodev_count_queue ();

  if (n_queues < n_workers)
    return -1;

  for (u32 i = 0; i < rte_cryptodev_count (); i++)
    cryptodev_configure (i);

  if (vec_len (cmt->cryptodev_inst) == 0)
    return -1;
  vec_sort_with_function (cmt->cryptodev_inst, cryptodev_cmp);

  /* if there is not enough device stop cryptodev */
  if (vec_len (cmt->cryptodev_inst) < n_workers)
    return -1;

  return 0;
}

static char *
dpdk_cryptodev_engine_init (vnet_crypto_engine_registration_t *r __clib_unused)
{
  vlib_main_t *vm = vlib_get_main ();
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cryptodev_engine_thread_t *cet;
  cryptodev_numa_data_t *numa_data;
  u32 node;
  u8 nodes = 0;
  u32 skip_master = vlib_num_workers () > 0;
  u32 n_workers = tm->n_vlib_mains - skip_master;
  u32 eidx;
  u32 i;
  clib_error_t *error = 0;

  cmt->iova_mode = rte_eal_iova_mode ();

  clib_bitmap_foreach (node, tm->cpu_socket_bitmap)
    {
      if (node >= nodes)
	nodes = node;
    }

  cmt->n_numa_nodes = nodes + 1;

  vec_validate (cmt->per_numa_data, nodes);
  vec_foreach (numa_data, cmt->per_numa_data)
    {
      vec_validate (numa_data->sess_pools, 0);
    }

  /* probe all cryptodev devices and get queue info */
  if (cryptodev_probe (n_workers) < 0)
    return 0;

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, n_workers);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, tm->n_vlib_mains - 1,
		       CLIB_CACHE_LINE_BYTES);
  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      cet = cmt->per_thread_data + i;

      if (cryptodev_assign_resource_auto (cet) < 0)
	{
	  error = clib_error_return (0, "Failed to configure cryptodev");
	  goto err_handling;
	}
    }

  /* register handler */
  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 100,
				      "DPDK Cryptodev Engine");

  if (vnet_crypto_register_async_key_change_handler (vm, eidx, cryptodev_key_change_handler,
						     sizeof (cryptodev_session_t *) *
						       VNET_CRYPTO_OP_N_TYPES * cmt->n_numa_nodes))
    {
      error = clib_error_return (0, "Failed to register cryptodev async key handler");
      goto err_handling;
    }

  error = cryptodev_register_raw_hdl (vm, eidx);

  if (error)
    goto err_handling;

  /* this engine is only enabled when cryptodev device(s) are presented in
   * startup.conf. Assume it is wanted to be used, turn on async mode here.
   */
  ipsec_set_async_mode (1);

  return 0;

err_handling:
  if (error == 0)
    return 0;

  return (char *) format (0, "%U%c", format_clib_error, error, 0);
}

VNET_CRYPTO_REG_ENGINE () = {
  .name = "dpdk_cryptodev",
  .desc = "DPDK Cryptodev Engine",
  .prio = 100,
  .init_fn = dpdk_cryptodev_engine_init,
};
