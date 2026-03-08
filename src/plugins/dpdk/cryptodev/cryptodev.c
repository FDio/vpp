/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Intel and/or its affiliates.
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
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

static void
cryptodev_key_add_handler (vnet_crypto_key_t *key)
{
  cryptodev_main_t *cmt = &cryptodev_main;

  vec_validate (cmt->keys, key->index);
}

static void
cryptodev_key_del_handler (vnet_crypto_key_t *key)
{
  cryptodev_sess_del (vlib_get_main (), key->index);
}

static_always_inline int
prepare_aead_xform (struct rte_crypto_sym_xform *xform,
		    cryptodev_op_type_t op_type, const vnet_crypto_key_t *key,
		    u32 aad_len)
{
  struct rte_crypto_aead_xform *aead_xform = &xform->aead;
  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  xform->next = 0;

#define _(a, b, c, d, e, f, g)                                                                     \
  if (key->alg == VNET_CRYPTO_ALG_##a)                                                             \
    aead_xform->algo = RTE_CRYPTO_AEAD_##c;                                                        \
  else
  foreach_vnet_aead_crypto_conversion
#undef _
    return -1;

  aead_xform->op = (op_type == CRYPTODEV_OP_TYPE_ENCRYPT) ?
    RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT;
  aead_xform->aad_length = aad_len;
  aead_xform->digest_length = 16;
  aead_xform->iv.offset = CRYPTODEV_IV_OFFSET;
  aead_xform->iv.length = 12;
  aead_xform->key.data = vnet_crypto_get_cypher_key (key);
  aead_xform->key.length = key->cipher_key_sz;

  return 0;
}

static_always_inline int
prepare_combined_xform (struct rte_crypto_sym_xform *xforms, cryptodev_op_type_t op_type,
			const vnet_crypto_key_t *key)
{
  struct rte_crypto_sym_xform *first_xform, *second_xform;
  struct rte_crypto_cipher_xform *cipher_xform;
  struct rte_crypto_auth_xform *auth_xform;

  memset (xforms, 0, 2 * sizeof (*xforms));

  if (op_type == CRYPTODEV_OP_TYPE_ENCRYPT)
    {
      first_xform = &xforms[0];
      second_xform = &xforms[1];
      cipher_xform = &first_xform->cipher;
      auth_xform = &second_xform->auth;
    }
  else
    {
      first_xform = &xforms[0];
      second_xform = &xforms[1];
      auth_xform = &first_xform->auth;
      cipher_xform = &second_xform->cipher;
    }

  first_xform->next = second_xform;
  second_xform->next = 0;
  cipher_xform->op = (op_type == CRYPTODEV_OP_TYPE_ENCRYPT) ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
							      RTE_CRYPTO_CIPHER_OP_DECRYPT;
  auth_xform->op = (op_type == CRYPTODEV_OP_TYPE_ENCRYPT) ? RTE_CRYPTO_AUTH_OP_GENERATE :
							    RTE_CRYPTO_AUTH_OP_VERIFY;
  cipher_xform->key.data = vnet_crypto_get_cypher_key (key);
  cipher_xform->key.length = key->cipher_key_sz;
  auth_xform->key.data = vnet_crypto_get_integ_key (key);
  auth_xform->key.length = key->integ_key_sz;

#define _(a, b, c, d, e, f)                                                                        \
  if (key->alg == VNET_CRYPTO_ALG_##a)                                                             \
    {                                                                                              \
      cipher_xform->algo = RTE_CRYPTO_CIPHER_##b;                                                  \
      cipher_xform->iv.offset = CRYPTODEV_IV_OFFSET;                                               \
      cipher_xform->iv.length = c;                                                                 \
      auth_xform->algo = RTE_CRYPTO_AUTH_##d;                                                      \
      auth_xform->digest_length = e;                                                               \
      first_xform->type = op_type == CRYPTODEV_OP_TYPE_ENCRYPT ? RTE_CRYPTO_SYM_XFORM_CIPHER :     \
								 RTE_CRYPTO_SYM_XFORM_AUTH;        \
      second_xform->type = op_type == CRYPTODEV_OP_TYPE_ENCRYPT ? RTE_CRYPTO_SYM_XFORM_AUTH :      \
								  RTE_CRYPTO_SYM_XFORM_CIPHER;     \
      return 0;                                                                                    \
    }                                                                                              \
  else
  foreach_vnet_combined_crypto_conversion
#undef _
    return -1;
}

static_always_inline void
cryptodev_session_del (u16 dev_id, cryptodev_session_t *sess)
{
  if (sess == NULL)
    return;

  rte_cryptodev_sym_session_free (dev_id, sess);
}

static_always_inline int
check_aead_support (enum rte_crypto_aead_algorithm algo, u32 key_size,
		    u32 digest_size, u32 aad_size)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_capability_t *vcap;
  u32 *s;
  u32 key_match = 0, digest_match = 0, aad_match = 0;

  vec_foreach (vcap, cmt->supported_caps)
    {
      if (vcap->xform_type != RTE_CRYPTO_SYM_XFORM_AEAD)
	continue;
      if (vcap->aead.algo != algo)
	continue;
      vec_foreach (s, vcap->aead.digest_sizes)
	if (*s == digest_size)
	  {
	    digest_match = 1;
	    break;
	  }
      vec_foreach (s, vcap->aead.key_sizes)
	if (*s == key_size)
	  {
	    key_match = 1;
	    break;
	  }
      vec_foreach (s, vcap->aead.aad_sizes)
	if (*s == aad_size)
	  {
	    aad_match = 1;
	    break;
	  }
    }

  if (key_match == 1 && digest_match == 1 && aad_match == 1)
    return 1;

  return 0;
}

static_always_inline int
cryptodev_check_supported_vnet_alg (vnet_crypto_key_t *key)
{
#define _(a, b, c, d, e, f, g)                                                                     \
  if (key->alg == VNET_CRYPTO_ALG_##a)                                                             \
    return check_aead_support (RTE_CRYPTO_AEAD_##c, g, e, f);
  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d, e, f)                                                                        \
  if (key->alg == VNET_CRYPTO_ALG_##a)                                                             \
    return cryptodev_check_feature_support (RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING) &&            \
	   cryptodev_check_cap_support (                                                           \
	     &(struct rte_cryptodev_sym_capability_idx){                                           \
	       .type = RTE_CRYPTO_SYM_XFORM_CIPHER,                                                \
	       .algo.cipher = RTE_CRYPTO_CIPHER_##b,                                               \
	     },                                                                                    \
	     f, 0, 0) &&                                                                           \
	   cryptodev_check_cap_support (                                                           \
	     &(struct rte_cryptodev_sym_capability_idx){                                           \
	       .type = RTE_CRYPTO_SYM_XFORM_AUTH,                                                  \
	       .algo.auth = RTE_CRYPTO_AUTH_##d,                                                   \
	     },                                                                                    \
	     0, e, 0);
    foreach_vnet_combined_crypto_conversion
#undef _

    return 0;
}

int
cryptodev_check_feature_support (u64 feature_flag)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  struct rte_cryptodev_info dev_info;
  u32 previous_dev_id = ~0;

  vec_foreach (dev_inst, cmt->cryptodev_inst)
    {
      if (dev_inst->dev_id == previous_dev_id)
	continue;

      rte_cryptodev_info_get (dev_inst->dev_id, &dev_info);
      if ((dev_info.feature_flags & feature_flag) == 0)
	return 0;
      previous_dev_id = dev_inst->dev_id;
    }

  return 1;
}

u8
cryptodev_get_iv_len (vnet_crypto_alg_t alg)
{
#define _(a, b, c, d, e, f, g)                                                                     \
  if (alg == VNET_CRYPTO_ALG_##a)                                                                  \
    return d;
  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d, e, f)                                                                        \
  if (alg == VNET_CRYPTO_ALG_##a)                                                                  \
    return c;
    foreach_vnet_combined_crypto_conversion
#undef _

    return 0;
}

void
cryptodev_sess_del (vlib_main_t *vm __clib_unused, vnet_crypto_key_index_t idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_key_t *ckey = 0;
  u32 i;

  if (idx >= vec_len (cmt->keys))
    return;

  ckey = vec_elt_at_index (cmt->keys, idx);
  vec_foreach_index (i, cmt->per_thread_data)
    {
      if (!ckey->keys)
	continue;
      if (!ckey->keys[i])
	continue;
      if (ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT])
	{
	  u16 dev_id = cmt->per_thread_data[i].cryptodev_id;

	  cryptodev_session_del (dev_id, ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT]);
	  cryptodev_session_del (dev_id, ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT]);

	  CLIB_MEMORY_STORE_BARRIER ();
	  ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT] = 0;
	  ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT] = 0;
	}
    }
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
cryptodev_session_create (vlib_main_t *vm, vnet_crypto_key_index_t idx,
			  u32 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  cryptodev_engine_thread_t *cet;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool;
  cryptodev_session_pool_t *sess_pools_elt;
  cryptodev_key_t *ckey;
  struct rte_crypto_sym_xform xforms_enc[2] = { { 0 } };
  struct rte_crypto_sym_xform xforms_dec[2] = { { 0 } };
  cryptodev_session_t *sessions[CRYPTODEV_N_OP_TYPES] = { 0 };
  u32 thread_index = vm->thread_index;
  u32 numa_node;
  u16 dev_id;
  u32 i;
  clib_error_t *error;
  int ret = 0;
  u8 found = 0;

  vec_validate (cmt->keys, idx);
  ckey = vec_elt_at_index (cmt->keys, idx);

  if (cryptodev_check_supported_vnet_alg (key) == 0)
    return -1;

  vec_validate (ckey->keys, vec_len (cmt->per_thread_data) - 1);
  vec_foreach_index (i, ckey->keys)
    vec_validate (ckey->keys[i], CRYPTODEV_N_OP_TYPES - 1);

  cet = vec_elt_at_index (cmt->per_thread_data, thread_index);
  numa_node = vm->numa_node;
  dev_id = cet->cryptodev_id;
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

  if (crypto_main.algs[key->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD)
    ret = prepare_aead_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key, aad_len);
  else
    ret = prepare_combined_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key);
  if (ret)
    {
      ret = -1;
      goto clear_key;
    }

  if (crypto_main.algs[key->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD)
    prepare_aead_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key, aad_len);
  else
    prepare_combined_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key);

  sessions[CRYPTODEV_OP_TYPE_ENCRYPT] =
    rte_cryptodev_sym_session_create (dev_id, xforms_enc, sess_pool);
  sessions[CRYPTODEV_OP_TYPE_DECRYPT] =
    rte_cryptodev_sym_session_create (dev_id, xforms_dec, sess_pool);
  if (!sessions[CRYPTODEV_OP_TYPE_ENCRYPT] ||
      !sessions[CRYPTODEV_OP_TYPE_DECRYPT])
    {
      ret = -1;
      goto clear_key;
    }

  rte_cryptodev_sym_session_opaque_data_set (
    sessions[CRYPTODEV_OP_TYPE_ENCRYPT],
    crypto_main.algs[key->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD ? aad_len : 0);
  rte_cryptodev_sym_session_opaque_data_set (
    sessions[CRYPTODEV_OP_TYPE_DECRYPT],
    crypto_main.algs[key->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD ? aad_len : 0);

  CLIB_MEMORY_STORE_BARRIER ();
  ckey->keys[thread_index][CRYPTODEV_OP_TYPE_ENCRYPT] = sessions[CRYPTODEV_OP_TYPE_ENCRYPT];
  ckey->keys[thread_index][CRYPTODEV_OP_TYPE_DECRYPT] = sessions[CRYPTODEV_OP_TYPE_DECRYPT];

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (dev_id, sessions[CRYPTODEV_OP_TYPE_ENCRYPT]);
      cryptodev_session_del (dev_id, sessions[CRYPTODEV_OP_TYPE_DECRYPT]);
    }
  clib_spinlock_unlock (&cmt->tlock);
  return ret;
}

/**
 *  assign a cryptodev resource to a worker.
 *  @param cet: the worker thread data
 *  @param cryptodev_inst_index: if op is "ASSIGN_AUTO" this param is ignored.
 *  @param op: the assignment method.
 *  @return: 0 if successfully, negative number otherwise.
 **/
int
cryptodev_assign_resource (cryptodev_engine_thread_t *cet, u32 cryptodev_inst_index,
			   cryptodev_resource_assign_op_t op)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *cinst = 0;
  uword idx;

  /* assign resource is only allowed when no inflight op is in the queue */
  if (cet->inflight)
    return -EBUSY;

  switch (op)
    {
    case CRYPTODEV_RESOURCE_ASSIGN_AUTO:
      if (clib_bitmap_count_set_bits (cmt->active_cdev_inst_mask) >=
	  vec_len (cmt->cryptodev_inst))
	return -1;

      clib_spinlock_lock (&cmt->tlock);
      idx = clib_bitmap_first_clear (cmt->active_cdev_inst_mask);
      clib_bitmap_set (cmt->active_cdev_inst_mask, idx, 1);
      cinst = vec_elt_at_index (cmt->cryptodev_inst, idx);
      cet->cryptodev_id = cinst->dev_id;
      cet->cryptodev_q = cinst->q_id;
      clib_spinlock_unlock (&cmt->tlock);
      break;
    case CRYPTODEV_RESOURCE_ASSIGN_UPDATE:
      /* assigning a used cryptodev resource is not allowed */
      if (clib_bitmap_get (cmt->active_cdev_inst_mask, cryptodev_inst_index)
	  == 1)
	return -EBUSY;

      vec_foreach_index (idx, cmt->cryptodev_inst)
	{
	  cinst = cmt->cryptodev_inst + idx;
	  if (cinst->dev_id == cet->cryptodev_id &&
	      cinst->q_id == cet->cryptodev_q)
	    break;
	}
      /* invalid existing worker resource assignment */
      if (idx >= vec_len (cmt->cryptodev_inst))
	return -EINVAL;
      clib_spinlock_lock (&cmt->tlock);
      clib_bitmap_set_no_check (cmt->active_cdev_inst_mask, idx, 0);
      clib_bitmap_set_no_check (cmt->active_cdev_inst_mask,
				cryptodev_inst_index, 1);
      cinst = cmt->cryptodev_inst + cryptodev_inst_index;
      cet->cryptodev_id = cinst->dev_id;
      cet->cryptodev_q = cinst->q_id;
      clib_spinlock_unlock (&cmt->tlock);
      break;
    default:
      return -EINVAL;
    }
  return 0;
};

static int
cryptodev_configure (vlib_main_t *vm, u32 cryptodev_id)
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

static int
cryptodev_supports_param_value (u32 *params, u32 param_value)
{
  u32 *value;
  vec_foreach (value, params)
    {
      if (*value == param_value)
	return 1;
    }
  return 0;
}

int
cryptodev_check_cap_support (struct rte_cryptodev_sym_capability_idx *idx,
			     u32 key_size, u32 digest_size, u32 aad_size)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_capability_t *cap;
  vec_foreach (cap, cmt->supported_caps)
    {

      if (cap->xform_type != idx->type)
	continue;

      if (idx->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
	  cap->auth.algo == idx->algo.auth &&
	  cryptodev_supports_param_value (cap->auth.digest_sizes, digest_size))
	return 1;

      if (idx->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
	  cap->cipher.algo == idx->algo.cipher &&
	  cryptodev_supports_param_value (cap->cipher.key_sizes, key_size))
	return 1;

      if (idx->type == RTE_CRYPTO_SYM_XFORM_AEAD &&
	  cap->aead.algo == idx->algo.aead &&
	  cryptodev_supports_param_value (cap->aead.key_sizes, key_size) &&
	  cryptodev_supports_param_value (cap->aead.digest_sizes,
					  digest_size) &&
	  cryptodev_supports_param_value (cap->aead.aad_sizes, aad_size))
	return 1;
    }
  return 0;
}

static void
remove_unsupported_param_size (u32 **param_sizes, u32 param_size_min,
			       u32 param_size_max, u32 increment)
{
  u32 i = 0;
  u32 cap_param_size;

  while (i < vec_len (*param_sizes))
    {
      u32 found_param = 0;
      for (cap_param_size = param_size_min; cap_param_size <= param_size_max;
	   cap_param_size += increment)
	{
	  if ((*param_sizes)[i] == cap_param_size)
	    {
	      found_param = 1;
	      break;
	    }
	  if (increment == 0)
	    break;
	}
      if (!found_param)
	/* no such param_size in cap so delete  this size in temp_cap params */
	vec_delete (*param_sizes, 1, i);
      else
	i++;
    }
}

static void
cryptodev_delete_cap (cryptodev_capability_t **temp_caps, u32 temp_cap_id)
{
  cryptodev_capability_t temp_cap = (*temp_caps)[temp_cap_id];

  switch (temp_cap.xform_type)
    {
    case RTE_CRYPTO_SYM_XFORM_AUTH:
      vec_free (temp_cap.auth.digest_sizes);
      break;
    case RTE_CRYPTO_SYM_XFORM_CIPHER:
      vec_free (temp_cap.cipher.key_sizes);
      break;
    case RTE_CRYPTO_SYM_XFORM_AEAD:
      vec_free (temp_cap.aead.key_sizes);
      vec_free (temp_cap.aead.aad_sizes);
      vec_free (temp_cap.aead.digest_sizes);
      break;
    default:
      break;
    }
  vec_delete (*temp_caps, 1, temp_cap_id);
}

static u32
cryptodev_remove_unsupported_param_sizes (
  cryptodev_capability_t *temp_cap,
  const struct rte_cryptodev_capabilities *dev_caps)
{
  u32 cap_found = 0;
  const struct rte_cryptodev_capabilities *cap = &dev_caps[0];

  while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED)
    {
      if (cap->sym.xform_type == temp_cap->xform_type)
	switch (cap->sym.xform_type)
	  {
	  case RTE_CRYPTO_SYM_XFORM_CIPHER:
	    if (cap->sym.cipher.algo == temp_cap->cipher.algo)
	      {
		remove_unsupported_param_size (
		  &temp_cap->cipher.key_sizes, cap->sym.cipher.key_size.min,
		  cap->sym.cipher.key_size.max,
		  cap->sym.cipher.key_size.increment);
		if (vec_len (temp_cap->cipher.key_sizes) > 0)
		  cap_found = 1;
	      }
	    break;
	  case RTE_CRYPTO_SYM_XFORM_AUTH:
	    if (cap->sym.auth.algo == temp_cap->auth.algo)
	      {
		remove_unsupported_param_size (
		  &temp_cap->auth.digest_sizes, cap->sym.auth.digest_size.min,
		  cap->sym.auth.digest_size.max,
		  cap->sym.auth.digest_size.increment);
		if (vec_len (temp_cap->auth.digest_sizes) > 0)
		  cap_found = 1;
	      }
	    break;
	  case RTE_CRYPTO_SYM_XFORM_AEAD:
	    if (cap->sym.aead.algo == temp_cap->aead.algo)
	      {
		remove_unsupported_param_size (
		  &temp_cap->aead.key_sizes, cap->sym.aead.key_size.min,
		  cap->sym.aead.key_size.max,
		  cap->sym.aead.key_size.increment);
		remove_unsupported_param_size (
		  &temp_cap->aead.aad_sizes, cap->sym.aead.aad_size.min,
		  cap->sym.aead.aad_size.max,
		  cap->sym.aead.aad_size.increment);
		remove_unsupported_param_size (
		  &temp_cap->aead.digest_sizes, cap->sym.aead.digest_size.min,
		  cap->sym.aead.digest_size.max,
		  cap->sym.aead.digest_size.increment);
		if (vec_len (temp_cap->aead.key_sizes) > 0 &&
		    vec_len (temp_cap->aead.aad_sizes) > 0 &&
		    vec_len (temp_cap->aead.digest_sizes) > 0)
		  cap_found = 1;
	      }
	    break;
	  default:
	    break;
	  }
      if (cap_found)
	break;
      cap++;
    }

  return cap_found;
}

static void
cryptodev_get_common_capabilities ()
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  struct rte_cryptodev_info dev_info;
  u32 previous_dev_id, dev_id;
  u32 cap_id = 0;
  u32 param;
  cryptodev_capability_t tmp_cap;
  const struct rte_cryptodev_capabilities *cap;
  const struct rte_cryptodev_capabilities *dev_caps;

  clib_memset (&tmp_cap, 0, sizeof (cryptodev_capability_t));
  if (vec_len (cmt->cryptodev_inst) == 0)
    return;
  dev_inst = vec_elt_at_index (cmt->cryptodev_inst, 0);
  rte_cryptodev_info_get (dev_inst->dev_id, &dev_info);
  cap = &dev_info.capabilities[0];

  /*init capabilities vector*/
  while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED)
    {
      if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
	{
	  cap++;
	  continue;
	}

      tmp_cap.xform_type = cap->sym.xform_type;
      switch (cap->sym.xform_type)
	{
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
	  tmp_cap.cipher.key_sizes = 0;
	  tmp_cap.cipher.algo = cap->sym.cipher.algo;
	  for (param = cap->sym.cipher.key_size.min;
	       param <= cap->sym.cipher.key_size.max;
	       param += cap->sym.cipher.key_size.increment)
	    {
	      vec_add1 (tmp_cap.cipher.key_sizes, param);
	      if (cap->sym.cipher.key_size.increment == 0)
		break;
	    }
	  break;
	case RTE_CRYPTO_SYM_XFORM_AUTH:
	  tmp_cap.auth.algo = cap->sym.auth.algo;
	  tmp_cap.auth.digest_sizes = 0;
	  for (param = cap->sym.auth.digest_size.min;
	       param <= cap->sym.auth.digest_size.max;
	       param += cap->sym.auth.digest_size.increment)
	    {
	      vec_add1 (tmp_cap.auth.digest_sizes, param);
	      if (cap->sym.auth.digest_size.increment == 0)
		break;
	    }
	  break;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
	  tmp_cap.aead.key_sizes = 0;
	  tmp_cap.aead.aad_sizes = 0;
	  tmp_cap.aead.digest_sizes = 0;
	  tmp_cap.aead.algo = cap->sym.aead.algo;
	  for (param = cap->sym.aead.key_size.min;
	       param <= cap->sym.aead.key_size.max;
	       param += cap->sym.aead.key_size.increment)
	    {
	      vec_add1 (tmp_cap.aead.key_sizes, param);
	      if (cap->sym.aead.key_size.increment == 0)
		break;
	    }
	  for (param = cap->sym.aead.aad_size.min;
	       param <= cap->sym.aead.aad_size.max;
	       param += cap->sym.aead.aad_size.increment)
	    {
	      vec_add1 (tmp_cap.aead.aad_sizes, param);
	      if (cap->sym.aead.aad_size.increment == 0)
		break;
	    }
	  for (param = cap->sym.aead.digest_size.min;
	       param <= cap->sym.aead.digest_size.max;
	       param += cap->sym.aead.digest_size.increment)
	    {
	      vec_add1 (tmp_cap.aead.digest_sizes, param);
	      if (cap->sym.aead.digest_size.increment == 0)
		break;
	    }
	  break;
	default:
	  break;
	}

      vec_add1 (cmt->supported_caps, tmp_cap);
      cap++;
    }

  while (cap_id < vec_len (cmt->supported_caps))
    {
      u32 cap_is_supported = 1;
      previous_dev_id = cmt->cryptodev_inst->dev_id;

      vec_foreach (dev_inst, cmt->cryptodev_inst)
	{
	  dev_id = dev_inst->dev_id;
	  if (previous_dev_id != dev_id)
	    {
	      previous_dev_id = dev_id;
	      rte_cryptodev_info_get (dev_id, &dev_info);
	      dev_caps = &dev_info.capabilities[0];
	      cap_is_supported = cryptodev_remove_unsupported_param_sizes (
		&cmt->supported_caps[cap_id], dev_caps);
	      if (!cap_is_supported)
		{
		  cryptodev_delete_cap (&cmt->supported_caps, cap_id);
		  /*no need to check other devices as this one doesn't support
		   * this temp_cap*/
		  break;
		}
	    }
	}
      if (cap_is_supported)
	cap_id++;
    }
}

clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  struct rte_cryptodev_info info;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cryptodev_engine_thread_t *cet;
  cryptodev_numa_data_t *numa_data;
  u32 n_queues = 0;
  u32 node;
  u8 nodes = 0;
  u32 skip_master = vlib_num_workers () > 0;
  u32 n_workers = tm->n_vlib_mains - skip_master;
  u32 eidx;
  u32 i;
  clib_error_t *error;

  cmt->iova_mode = rte_eal_iova_mode ();

  clib_bitmap_foreach (node, tm->cpu_socket_bitmap)
    {
      if (node >= nodes)
	nodes = node;
    }

  vec_validate (cmt->per_numa_data, nodes);
  vec_foreach (numa_data, cmt->per_numa_data)
    {
      vec_validate (numa_data->sess_pools, 0);
    }

  /* probe all cryptodev devices and get queue info */
  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      rte_cryptodev_info_get (i, &info);
      n_queues += info.max_nb_queue_pairs;
    }

  if (n_queues < n_workers)
    return 0;

  for (i = 0; i < rte_cryptodev_count (); i++)
    cryptodev_configure (vm, i);

  if (vec_len (cmt->cryptodev_inst) == 0)
    return 0;

  cryptodev_get_common_capabilities ();
  vec_sort_with_function (cmt->cryptodev_inst, cryptodev_cmp);

  /* if there is not enough device stop cryptodev */
  if (vec_len (cmt->cryptodev_inst) < n_workers)
    return 0;

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, n_workers);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, tm->n_vlib_mains - 1,
		       CLIB_CACHE_LINE_BYTES);
  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      cet = cmt->per_thread_data + i;

      if (cryptodev_assign_resource (cet, 0, CRYPTODEV_RESOURCE_ASSIGN_AUTO) < 0)
	{
	  error = clib_error_return (0, "Failed to configure cryptodev");
	  goto err_handling;
	}
    }

  /* register handler */
  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 100, "DPDK Cryptodev Engine");

  if (cryptodev_register_raw_hdl)
    error = cryptodev_register_raw_hdl (vm, eidx);
  else
    error = cryptodev_register_cop_hdl (vm, eidx);

  if (error)
    goto err_handling;

  vnet_crypto_register_async_key_add_handler (vm, eidx, cryptodev_key_add_handler);
  vnet_crypto_register_async_key_del_handler (vm, eidx, cryptodev_key_del_handler);

  /* this engine is only enabled when cryptodev device(s) are presented in
   * startup.conf. Assume it is wanted to be used, turn on async mode here.
   */
  ipsec_set_async_mode (1);

  return 0;

err_handling:
  return error;
}
