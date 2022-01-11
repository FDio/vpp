/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
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

static_always_inline int
prepare_aead_xform (struct rte_crypto_sym_xform *xform,
		    cryptodev_op_type_t op_type, const vnet_crypto_key_t *key,
		    u32 aad_len)
{
  struct rte_crypto_aead_xform *aead_xform = &xform->aead;
  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  xform->next = 0;

  if (key->alg != VNET_CRYPTO_ALG_AES_128_GCM &&
      key->alg != VNET_CRYPTO_ALG_AES_192_GCM &&
      key->alg != VNET_CRYPTO_ALG_AES_256_GCM)
    return -1;

  aead_xform->algo = RTE_CRYPTO_AEAD_AES_GCM;
  aead_xform->op = (op_type == CRYPTODEV_OP_TYPE_ENCRYPT) ?
    RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT;
  aead_xform->aad_length = aad_len;
  aead_xform->digest_length = 16;
  aead_xform->iv.offset = CRYPTODEV_IV_OFFSET;
  aead_xform->iv.length = 12;
  aead_xform->key.data = key->data;
  aead_xform->key.length = vec_len (key->data);

  return 0;
}

static_always_inline int
prepare_linked_xform (struct rte_crypto_sym_xform *xforms,
		      cryptodev_op_type_t op_type,
		      const vnet_crypto_key_t *key)
{
  struct rte_crypto_sym_xform *xform_cipher, *xform_auth;
  vnet_crypto_key_t *key_cipher, *key_auth;
  enum rte_crypto_cipher_algorithm cipher_algo = ~0;
  enum rte_crypto_auth_algorithm auth_algo = ~0;
  u32 digest_len = ~0;

  key_cipher = vnet_crypto_get_key (key->index_crypto);
  key_auth = vnet_crypto_get_key (key->index_integ);
  if (!key_cipher || !key_auth)
    return -1;

  if (op_type == CRYPTODEV_OP_TYPE_ENCRYPT)
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

  switch (key->async_alg)
    {
#define _(a, b, c, d, e)                                                      \
  case VNET_CRYPTO_ALG_##a##_##d##_TAG##e:                                    \
    cipher_algo = RTE_CRYPTO_CIPHER_##b;                                      \
    auth_algo = RTE_CRYPTO_AUTH_##d##_HMAC;                                   \
    digest_len = e;                                                           \
    break;

      foreach_cryptodev_link_async_alg
#undef _
    default:
      return -1;
    }

  xform_cipher->cipher.algo = cipher_algo;
  xform_cipher->cipher.key.data = key_cipher->data;
  xform_cipher->cipher.key.length = vec_len (key_cipher->data);
  xform_cipher->cipher.iv.length = 16;
  xform_cipher->cipher.iv.offset = CRYPTODEV_IV_OFFSET;

  xform_auth->auth.algo = auth_algo;
  xform_auth->auth.digest_length = digest_len;
  xform_auth->auth.key.data = key_auth->data;
  xform_auth->auth.key.length = vec_len (key_auth->data);

  return 0;
}

static_always_inline void
cryptodev_session_del (struct rte_cryptodev_sym_session *sess)
{
  u32 n_devs, i;

  if (sess == NULL)
    return;

  n_devs = rte_cryptodev_count ();

  for (i = 0; i < n_devs; i++)
    rte_cryptodev_sym_session_clear (i, sess);

  rte_cryptodev_sym_session_free (sess);
}

static int
check_cipher_support (enum rte_crypto_cipher_algorithm algo, u32 key_size)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_capability_t *vcap;
  u32 *s;

  vec_foreach (vcap, cmt->supported_caps)
    {
      if (vcap->xform_type != RTE_CRYPTO_SYM_XFORM_CIPHER)
	continue;
      if (vcap->cipher.algo != algo)
	continue;
      vec_foreach (s, vcap->cipher.key_sizes)
	if (*s == key_size)
	  return 1;
    }

  return 0;
}

static int
check_auth_support (enum rte_crypto_auth_algorithm algo, u32 digest_size)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_capability_t *vcap;
  u32 *s;

  vec_foreach (vcap, cmt->supported_caps)
    {
      if (vcap->xform_type != RTE_CRYPTO_SYM_XFORM_AUTH)
	continue;
      if (vcap->auth.algo != algo)
	continue;
      vec_foreach (s, vcap->auth.digest_sizes)
	if (*s == digest_size)
	  return 1;
    }

  return 0;
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
  u32 matched = 0;

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    {
      switch (key->async_alg)
	{
#define _(a, b, c, d, e)                                                      \
  case VNET_CRYPTO_ALG_##a##_##d##_TAG##e:                                    \
    if (check_cipher_support (RTE_CRYPTO_CIPHER_##b, c) &&                    \
	check_auth_support (RTE_CRYPTO_AUTH_##d##_HMAC, e))                   \
      return 1;
	  foreach_cryptodev_link_async_alg
#undef _
	    default : return 0;
	}
      return 0;
    }

#define _(a, b, c, d, e, f, g)                                                \
  if (key->alg == VNET_CRYPTO_ALG_##a)                                        \
    {                                                                         \
      if (check_aead_support (RTE_CRYPTO_AEAD_##c, g, e, f))                  \
	matched++;                                                            \
    }
  foreach_vnet_aead_crypto_conversion
#undef _

    if (matched < 2) return 0;

  return 1;
}

void
cryptodev_sess_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
			vnet_crypto_key_index_t idx, u32 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  cryptodev_key_t *ckey = 0;
  u32 i;

  vec_validate (cmt->keys, idx);
  ckey = vec_elt_at_index (cmt->keys, idx);

  if (kop == VNET_CRYPTO_KEY_OP_DEL || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      if (idx >= vec_len (cmt->keys))
	return;

      vec_foreach_index (i, cmt->per_numa_data)
	{
	  if (!ckey->keys)
	    continue;
	  if (!ckey->keys[i])
	    continue;
	  if (ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT])
	    {
	      cryptodev_session_del (ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT]);
	      cryptodev_session_del (ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT]);

	      CLIB_MEMORY_STORE_BARRIER ();
	      ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT] = 0;
	      ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT] = 0;
	    }
	}
      return;
    }

  /* create key */

  /* do not create session for unsupported alg */
  if (cryptodev_check_supported_vnet_alg (key) == 0)
    return;

  vec_validate (ckey->keys, vec_len (cmt->per_numa_data) - 1);
  vec_foreach_index (i, ckey->keys)
    vec_validate (ckey->keys[i], CRYPTODEV_N_OP_TYPES - 1);
}

/*static*/ void
cryptodev_key_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
		       vnet_crypto_key_index_t idx)
{
  cryptodev_sess_handler (vm, kop, idx, 8);
}

clib_error_t *
allocate_session_pools (u32 numa_node,
			cryptodev_session_pool_t *sess_pools_elt, u32 len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u8 *name;
  clib_error_t *error = NULL;

  name = format (0, "vcryptodev_sess_pool_%u_%c", numa_node, len);
  sess_pools_elt->sess_pool = rte_cryptodev_sym_session_pool_create (
    (char *) name, CRYPTODEV_NB_SESSION, 0, 0, 0, numa_node);

  if (!sess_pools_elt->sess_pool)
    {
      error = clib_error_return (0, "Not enough memory for mp %s", name);
      goto clear_mempools;
    }
  vec_free (name);

  name = format (0, "cryptodev_sess_pool_%u_%c", numa_node, len);
  sess_pools_elt->sess_priv_pool = rte_mempool_create (
    (char *) name, CRYPTODEV_NB_SESSION * (cmt->drivers_cnt), cmt->sess_sz, 0,
    0, NULL, NULL, NULL, NULL, numa_node, 0);

  if (!sess_pools_elt->sess_priv_pool)
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
      if (sess_pools_elt->sess_priv_pool)
	rte_mempool_free (sess_pools_elt->sess_priv_pool);
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
  cryptodev_inst_t *dev_inst;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  cryptodev_session_pool_t *sess_pools_elt;
  cryptodev_key_t *ckey = vec_elt_at_index (cmt->keys, idx);
  struct rte_crypto_sym_xform xforms_enc[2] = { { 0 } };
  struct rte_crypto_sym_xform xforms_dec[2] = { { 0 } };
  struct rte_cryptodev_sym_session *sessions[CRYPTODEV_N_OP_TYPES] = { 0 };
  struct rte_cryptodev_info dev_info;
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
  sess_priv_pool = sess_pools_elt->sess_priv_pool;

  sessions[CRYPTODEV_OP_TYPE_ENCRYPT] =
    rte_cryptodev_sym_session_create (sess_pool);

  sessions[CRYPTODEV_OP_TYPE_DECRYPT] =
    rte_cryptodev_sym_session_create (sess_pool);

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    ret = prepare_linked_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key);
  else
    ret =
      prepare_aead_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key, aad_len);
  if (ret)
    {
      ret = -1;
      goto clear_key;
    }

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    prepare_linked_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key);
  else
    prepare_aead_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key, aad_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
    {
      u32 dev_id = dev_inst->dev_id;
      rte_cryptodev_info_get (dev_id, &dev_info);
      u32 driver_id = dev_info.driver_id;

      /* if the session is already configured for the driver type, avoid
	 configuring it again to increase the session data's refcnt */
      if (sessions[CRYPTODEV_OP_TYPE_ENCRYPT]->sess_data[driver_id].data &&
	  sessions[CRYPTODEV_OP_TYPE_DECRYPT]->sess_data[driver_id].data)
	continue;

      ret = rte_cryptodev_sym_session_init (
	dev_id, sessions[CRYPTODEV_OP_TYPE_ENCRYPT], xforms_enc,
	sess_priv_pool);
      ret = rte_cryptodev_sym_session_init (
	dev_id, sessions[CRYPTODEV_OP_TYPE_DECRYPT], xforms_dec,
	sess_priv_pool);
      if (ret < 0)
	goto clear_key;
    }

  sessions[CRYPTODEV_OP_TYPE_ENCRYPT]->opaque_data = aad_len;
  sessions[CRYPTODEV_OP_TYPE_DECRYPT]->opaque_data = aad_len;

  CLIB_MEMORY_STORE_BARRIER ();
  ckey->keys[numa_node][CRYPTODEV_OP_TYPE_ENCRYPT] =
    sessions[CRYPTODEV_OP_TYPE_ENCRYPT];
  ckey->keys[numa_node][CRYPTODEV_OP_TYPE_DECRYPT] =
    sessions[CRYPTODEV_OP_TYPE_DECRYPT];

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (sessions[CRYPTODEV_OP_TYPE_ENCRYPT]);
      cryptodev_session_del (sessions[CRYPTODEV_OP_TYPE_DECRYPT]);
    }
  clib_spinlock_unlock (&cmt->tlock);
  return ret;
}

typedef enum
{
  CRYPTODEV_RESOURCE_ASSIGN_AUTO = 0,
  CRYPTODEV_RESOURCE_ASSIGN_UPDATE,
} cryptodev_resource_assign_op_t;

/**
 *  assign a cryptodev resource to a worker.
 *  @param cet: the worker thread data
 *  @param cryptodev_inst_index: if op is "ASSIGN_AUTO" this param is ignored.
 *  @param op: the assignment method.
 *  @return: 0 if successfully, negative number otherwise.
 **/
static_always_inline int
cryptodev_assign_resource (cryptodev_engine_thread_t * cet,
			   u32 cryptodev_inst_index,
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
      if (idx == vec_len (cmt->cryptodev_inst))
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
}

static u8 *
format_cryptodev_inst (u8 * s, va_list * args)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 inst = va_arg (*args, u32);
  cryptodev_inst_t *cit = cmt->cryptodev_inst + inst;
  u32 thread_index = 0;
  struct rte_cryptodev_info info;

  rte_cryptodev_info_get (cit->dev_id, &info);
  s = format (s, "%-25s%-10u", info.device->name, cit->q_id);

  vec_foreach_index (thread_index, cmt->per_thread_data)
  {
    cryptodev_engine_thread_t *cet = cmt->per_thread_data + thread_index;
    if (vlib_num_workers () > 0 && thread_index == 0)
      continue;

    if (cet->cryptodev_id == cit->dev_id && cet->cryptodev_q == cit->q_id)
      {
	s = format (s, "%u (%v)\n", thread_index,
		    vlib_worker_threads[thread_index].name);
	break;
      }
  }

  if (thread_index == vec_len (cmt->per_thread_data))
    s = format (s, "%s\n", "free");

  return s;
}

static clib_error_t *
cryptodev_show_assignment_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 inst;

  vlib_cli_output (vm, "%-5s%-25s%-10s%s\n", "No.", "Name", "Queue-id",
		   "Assigned-to");
  if (vec_len (cmt->cryptodev_inst) == 0)
    {
      vlib_cli_output (vm, "(nil)\n");
      return 0;
    }

  vec_foreach_index (inst, cmt->cryptodev_inst)
    vlib_cli_output (vm, "%-5u%U", inst, format_cryptodev_inst, inst);

  if (cmt->is_raw_api)
    vlib_cli_output (vm, "Cryptodev Data Path API used: RAW Data Path API");
  else
    vlib_cli_output (vm, "Cryptodev Data Path API used: crypto operation API");
  return 0;
}

VLIB_CLI_COMMAND (show_cryptodev_assignment, static) = {
    .path = "show cryptodev assignment",
    .short_help = "show cryptodev assignment",
    .function = cryptodev_show_assignment_fn,
};

static clib_error_t *
cryptodev_set_assignment_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 thread_index, inst_index;
  u32 thread_present = 0, inst_present = 0;
  clib_error_t *error = 0;
  int ret;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "thread %u", &thread_index))
	thread_present = 1;
      else if (unformat (line_input, "resource %u", &inst_index))
	inst_present = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  return error;
	}
    }

  if (!thread_present || !inst_present)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      return error;
    }

  if (thread_index == 0 && vlib_num_workers () > 0)
    {
      error =
	clib_error_return (0, "assign crypto resource for master thread");
      return error;
    }

  if (thread_index > vec_len (cmt->per_thread_data) ||
      inst_index > vec_len (cmt->cryptodev_inst))
    {
      error = clib_error_return (0, "wrong thread id or resource id");
      return error;
    }

  cet = cmt->per_thread_data + thread_index;
  ret = cryptodev_assign_resource (cet, inst_index,
				   CRYPTODEV_RESOURCE_ASSIGN_UPDATE);
  if (ret)
    {
      error =
	clib_error_return (0, "cryptodev_assign_resource returned %d", ret);
      return error;
    }

  return 0;
}

VLIB_CLI_COMMAND (set_cryptodev_assignment, static) = {
    .path = "set cryptodev assignment",
    .short_help = "set cryptodev assignment thread <thread_index> "
	"resource <inst_index>",
    .function = cryptodev_set_assignment_fn,
};

static u32
cryptodev_count_queue (u32 numa)
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
cryptodev_configure (vlib_main_t *vm, u32 cryptodev_id)
{
  struct rte_cryptodev_config cfg;
  struct rte_cryptodev_info info;
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 i;
  int ret;

  rte_cryptodev_info_get (cryptodev_id, &info);

  if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO))
    return -1;

  cfg.socket_id = info.device->numa_node;
  cfg.nb_queue_pairs = info.max_nb_queue_pairs;

  rte_cryptodev_configure (cryptodev_id, &cfg);

  for (i = 0; i < info.max_nb_queue_pairs; i++)
    {
      struct rte_cryptodev_qp_conf qp_cfg;

      qp_cfg.mp_session = 0;
      qp_cfg.mp_session_private = 0;
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

  for (i = 0; i < info.max_nb_queue_pairs; i++)
    {
      cryptodev_inst_t *cdev_inst;
      vec_add2(cmt->cryptodev_inst, cdev_inst, 1);
      cdev_inst->desc = vec_new (char, strlen (info.device->name) + 10);
      cdev_inst->dev_id = cryptodev_id;
      cdev_inst->q_id = i;

      snprintf (cdev_inst->desc, strlen (info.device->name) + 9,
		"%s_q%u", info.device->name, i);
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

static int
cryptodev_probe (vlib_main_t *vm, u32 n_workers)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 n_queues = cryptodev_count_queue (vm->numa_node);
  u32 i;

  if (n_queues < n_workers)
    return -1;

  for (i = 0; i < rte_cryptodev_count (); i++)
    cryptodev_configure (vm, i);

  if (vec_len (cmt->cryptodev_inst) == 0)
    return -1;
  cryptodev_get_common_capabilities ();
  vec_sort_with_function (cmt->cryptodev_inst, cryptodev_cmp);

  /* if there is not enough device stop cryptodev */
  if (vec_len (cmt->cryptodev_inst) < n_workers)
    return -1;

  return 0;
}

static void
is_drv_unique (u32 driver_id, u32 **unique_drivers)
{
  u32 *unique_elt;
  u8 found = 0;

  vec_foreach (unique_elt, *unique_drivers)
    {
      if (*unique_elt == driver_id)
	{
	  found = 1;
	  break;
	}
    }

  if (!found)
    vec_add1 (*unique_drivers, driver_id);
}

clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cryptodev_engine_thread_t *cet;
  cryptodev_numa_data_t *numa_data;
  cryptodev_inst_t *dev_inst;
  struct rte_cryptodev_info dev_info;
  u32 node;
  u8 nodes = 0;
  u32 skip_master = vlib_num_workers () > 0;
  u32 n_workers = tm->n_vlib_mains - skip_master;
  u32 eidx;
  u32 i;
  u32 *unique_drivers = 0;
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
  if (cryptodev_probe (vm, n_workers) < 0)
    {
      error = clib_error_return (0, "Not enough cryptodev resources");
      goto err_handling;
    }

  vec_foreach (dev_inst, cmt->cryptodev_inst)
    {
      u32 dev_id = dev_inst->dev_id;
      rte_cryptodev_info_get (dev_id, &dev_info);
      u32 driver_id = dev_info.driver_id;
      is_drv_unique (driver_id, &unique_drivers);

      u32 sess_sz =
	rte_cryptodev_sym_get_private_session_size (dev_inst->dev_id);
      cmt->sess_sz = clib_max (cmt->sess_sz, sess_sz);
    }

  cmt->drivers_cnt = vec_len (unique_drivers);
  vec_free (unique_drivers);

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, tm->n_vlib_mains);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, tm->n_vlib_mains - 1,
		       CLIB_CACHE_LINE_BYTES);
  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      cet = cmt->per_thread_data + i;

      if (cryptodev_assign_resource (cet, 0, CRYPTODEV_RESOURCE_ASSIGN_AUTO) <
	  0)
	{
	  error = clib_error_return (0, "Failed to configure cryptodev");
	  goto err_handling;
	}
    }

  /* register handler */
  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 100,
				      "DPDK Cryptodev Engine");

  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);

  if (cryptodev_register_raw_hdl)
    error = cryptodev_register_raw_hdl (vm, eidx);
  else
    error = cryptodev_register_cop_hdl (vm, eidx);

  if (error)
    goto err_handling;

  /* this engine is only enabled when cryptodev device(s) are presented in
   * startup.conf. Assume it is wanted to be used, turn on async mode here.
   */
  vnet_crypto_request_async_mode (1);
  ipsec_set_async_mode (1);

  return 0;

err_handling:
  return error;
}
