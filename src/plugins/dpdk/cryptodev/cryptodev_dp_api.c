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
#include <rte_cryptodev_pmd.h>
#include <rte_config.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define CRYPTODEV_NB_CRYPTO_OPS	1024
#define CRYPTODEV_MAX_INFLIGHT	(CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODEV_AAD_MASK	(CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODEV_DEQ_CACHE_SZ	32
#define CRYPTODEV_NB_SESSION	10240
#define CRYPTODEV_MAX_AAD_SIZE	16
#define CRYPTODEV_MAX_N_SGL	8 /**< maximum number of segments */

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN, TAG_LEN, AAD_LEN, KEY_LEN
 */
#define foreach_vnet_aead_crypto_conversion                                   \
  _ (AES_128_GCM, AEAD, AES_GCM, 12, 16, 8, 16)                               \
  _ (AES_128_GCM, AEAD, AES_GCM, 12, 16, 12, 16)                              \
  _ (AES_192_GCM, AEAD, AES_GCM, 12, 16, 8, 24)                               \
  _ (AES_192_GCM, AEAD, AES_GCM, 12, 16, 12, 24)                              \
  _ (AES_256_GCM, AEAD, AES_GCM, 12, 16, 8, 32)                               \
  _ (AES_256_GCM, AEAD, AES_GCM, 12, 16, 12, 32)

/**
 * crypto (alg, cryptodev_alg, key_size), hash (alg, digest-size)
 **/
#define foreach_cryptodev_link_async_alg                                      \
  _ (AES_128_CBC, AES_CBC, 16, SHA1, 12)                                      \
  _ (AES_192_CBC, AES_CBC, 24, SHA1, 12)                                      \
  _ (AES_256_CBC, AES_CBC, 32, SHA1, 12)                                      \
  _ (AES_128_CBC, AES_CBC, 16, SHA224, 14)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA224, 14)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA224, 14)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA256, 16)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA256, 16)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA256, 16)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA384, 24)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA384, 24)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA384, 24)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA512, 32)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA512, 32)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA512, 32)

typedef enum
{
  CRYPTODEV_OP_TYPE_ENCRYPT = 0,
  CRYPTODEV_OP_TYPE_DECRYPT,
  CRYPTODEV_N_OP_TYPES,
} cryptodev_op_type_t;

typedef struct
{
  union rte_cryptodev_session_ctx **keys;
} cryptodev_key_t;

/* Replicate DPDK rte_cryptodev_sym_capability structure with key size ranges
 * in favor of vpp vector */
typedef struct
{
  enum rte_crypto_sym_xform_type xform_type;
  union
  {
    struct
    {
      enum rte_crypto_auth_algorithm algo; /*auth algo */
      u32 *digest_sizes;		   /* vector of auth digest sizes */
    } auth;
    struct
    {
      enum rte_crypto_cipher_algorithm algo; /* cipher algo */
      u32 *key_sizes;			     /* vector of cipher key sizes */
    } cipher;
    struct
    {
      enum rte_crypto_aead_algorithm algo; /* aead algo */
      u32 *key_sizes;			   /*vector of aead key sizes */
      u32 *aad_sizes;			   /*vector of aad sizes */
      u32 *digest_sizes;		   /* vector of aead digest sizes */
    } aead;
  };
} cryptodev_capability_t;

typedef struct
{
  u32 dev_id;
  u32 q_id;
  char *desc;
} cryptodev_inst_t;

typedef struct
{
  struct rte_mempool *sess_pool;
  struct rte_mempool *sess_priv_pool;
} cryptodev_numa_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *b[VNET_CRYPTO_FRAME_SIZE];
  struct rte_crypto_raw_dp_ctx *ctx;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_ring *cached_frame;
  u16 aad_index;
  u8 *aad_buf;
  u64 aad_phy_addr;
  u16 cryptodev_id;
  u16 cryptodev_q;
  u16 inflight;
  union rte_cryptodev_session_ctx reset_sess; /* session data for reset ctx */
} cryptodev_engine_thread_t;

typedef struct
{
  cryptodev_numa_data_t *per_numa_data;
  cryptodev_key_t *keys;
  cryptodev_engine_thread_t *per_thread_data;
  enum rte_iova_mode iova_mode;
  cryptodev_inst_t *cryptodev_inst;
  clib_bitmap_t *active_cdev_inst_mask;
  clib_spinlock_t tlock;
  cryptodev_capability_t *supported_caps;
} cryptodev_main_t;

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
  aead_xform->iv.offset = 0;
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
  xform_cipher->cipher.iv.offset = 0;

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

static_always_inline int
cryptodev_session_create (vlib_main_t *vm, vnet_crypto_key_index_t idx,
			  u32 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  cryptodev_inst_t *dev_inst;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  cryptodev_key_t *ckey = vec_elt_at_index (cmt->keys, idx);
  struct rte_crypto_sym_xform xforms_enc[2] = { { 0 } };
  struct rte_crypto_sym_xform xforms_dec[2] = { { 0 } };
  struct rte_cryptodev_sym_session *sessions[CRYPTODEV_N_OP_TYPES] = { 0 };
  u32 numa_node = vm->numa_node;
  int ret;

  numa_data = vec_elt_at_index (cmt->per_numa_data, numa_node);
  sess_pool = numa_data->sess_pool;
  sess_priv_pool = numa_data->sess_priv_pool;

  sessions[CRYPTODEV_OP_TYPE_ENCRYPT] =
    rte_cryptodev_sym_session_create (sess_pool);
  if (!sessions[CRYPTODEV_OP_TYPE_ENCRYPT])
    {
      ret = -1;
      goto clear_key;
    }

  sessions[CRYPTODEV_OP_TYPE_DECRYPT] =
    rte_cryptodev_sym_session_create (sess_pool);
  if (!sessions[CRYPTODEV_OP_TYPE_DECRYPT])
    {
      ret = -1;
      goto clear_key;
    }

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    ret = prepare_linked_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key);
  else
    ret = prepare_aead_xform (xforms_enc, CRYPTODEV_OP_TYPE_ENCRYPT, key,
			      aad_len);
  if (ret)
    return 0;

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    prepare_linked_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key);
  else
    prepare_aead_xform (xforms_dec, CRYPTODEV_OP_TYPE_DECRYPT, key, aad_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
  {
    u32 dev_id = dev_inst->dev_id;
    struct rte_cryptodev *cdev = rte_cryptodev_pmd_get_dev (dev_id);

    /* if the session is already configured for the driver type, avoid
       configuring it again to increase the session data's refcnt */
    if (sessions[CRYPTODEV_OP_TYPE_ENCRYPT]->sess_data[cdev->driver_id].data &&
	sessions[CRYPTODEV_OP_TYPE_DECRYPT]->sess_data[cdev->driver_id].data)
      continue;

    ret = rte_cryptodev_sym_session_init (
      dev_id, sessions[CRYPTODEV_OP_TYPE_ENCRYPT], xforms_enc, sess_priv_pool);
    ret = rte_cryptodev_sym_session_init (
      dev_id, sessions[CRYPTODEV_OP_TYPE_DECRYPT], xforms_dec, sess_priv_pool);
    if (ret < 0)
      return ret;
  }

  sessions[CRYPTODEV_OP_TYPE_ENCRYPT]->opaque_data = aad_len;
  sessions[CRYPTODEV_OP_TYPE_DECRYPT]->opaque_data = aad_len;

  CLIB_MEMORY_STORE_BARRIER ();
  ckey->keys[numa_node][CRYPTODEV_OP_TYPE_ENCRYPT].crypto_sess =
    sessions[CRYPTODEV_OP_TYPE_ENCRYPT];
  ckey->keys[numa_node][CRYPTODEV_OP_TYPE_DECRYPT].crypto_sess =
    sessions[CRYPTODEV_OP_TYPE_DECRYPT];

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (sessions[CRYPTODEV_OP_TYPE_ENCRYPT]);
      cryptodev_session_del (sessions[CRYPTODEV_OP_TYPE_DECRYPT]);
    }
  return ret;
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

static int
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

static int
cryptodev_check_supported_vnet_alg (vnet_crypto_key_t * key)
{
  vnet_crypto_alg_t alg;
  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    return 0;

  alg = key->alg;

#define _(a, b, c, d, e, f, g)                                                \
  if (alg == VNET_CRYPTO_ALG_##a)                                             \
    return 0;

  foreach_vnet_aead_crypto_conversion
#undef _
    return -1;
}

static_always_inline void
cryptodev_sess_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
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
	  if (ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT].crypto_sess)
	    {
	      cryptodev_session_del (
		ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT].crypto_sess);
	      cryptodev_session_del (
		ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT].crypto_sess);

	      CLIB_MEMORY_STORE_BARRIER ();
	      ckey->keys[i][CRYPTODEV_OP_TYPE_ENCRYPT].crypto_sess = 0;
	      ckey->keys[i][CRYPTODEV_OP_TYPE_DECRYPT].crypto_sess = 0;
	    }
	}
      return;
    }

  /* create key */

  /* do not create session for unsupported alg */
  if (cryptodev_check_supported_vnet_alg (key))
    return;

  vec_validate (ckey->keys, vec_len (cmt->per_numa_data) - 1);
  vec_foreach_index (i, ckey->keys)
    vec_validate (ckey->keys[i], CRYPTODEV_N_OP_TYPES - 1);
}

/*static*/ void
cryptodev_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
		       vnet_crypto_key_index_t idx)
{
  cryptodev_sess_handler (vm, kop, idx, 8);
}

static_always_inline void
cryptodev_mark_frame_err_status (vnet_crypto_async_frame_t * f,
				 vnet_crypto_op_status_t s)
{
  u32 n_elts = f->n_elts, i;

  for (i = 0; i < n_elts; i++)
    f->elts[i].status = s;
  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
}

static_always_inline int
cryptodev_frame_build_sgl (vlib_main_t * vm, enum rte_iova_mode iova_mode,
			   struct rte_crypto_vec *data_vec,
			   u16 * n_seg, vlib_buffer_t * b, u32 size)
{
  struct rte_crypto_vec *vec = data_vec + 1;
  if (vlib_buffer_chain_linearize (vm, b) > CRYPTODEV_MAX_N_SGL)
    return -1;

  while ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && size)
    {
      u32 len;
      b = vlib_get_buffer (vm, b->next_buffer);
      len = clib_min (b->current_length, size);
      vec->base = (void *) vlib_buffer_get_current (b);
      if (iova_mode == RTE_IOVA_VA)
	vec->iova = pointer_to_uword (vec->base);
      else
	vec->iova = vlib_buffer_get_current_pa (vm, b);
      vec->len = len;
      size -= len;
      vec++;
      *n_seg += 1;
    }

  if (size)
    return -1;

  return 0;
}

static_always_inline u64
compute_ofs_linked_alg (vnet_crypto_async_frame_elt_t * fe, i16 * min_ofs,
			u32 * max_end)
{
  union rte_crypto_sym_ofs ofs;
  u32 crypto_end = fe->crypto_start_offset + fe->crypto_total_length;
  u32 integ_end = fe->integ_start_offset + fe->crypto_total_length +
    fe->integ_length_adj;

  *min_ofs = clib_min (fe->crypto_start_offset, fe->integ_start_offset);
  *max_end = clib_max (crypto_end, integ_end);

  ofs.ofs.cipher.head = fe->crypto_start_offset - *min_ofs;
  ofs.ofs.cipher.tail = *max_end - crypto_end;
  ofs.ofs.auth.head = fe->integ_start_offset - *min_ofs;
  ofs.ofs.auth.tail = *max_end - integ_end;

  return ofs.raw;
}

static_always_inline void
cryptodev_reset_ctx (cryptodev_engine_thread_t *cet)
{
  rte_cryptodev_configure_raw_dp_ctx (cet->cryptodev_id, cet->cryptodev_q,
				      cet->ctx, RTE_CRYPTO_OP_WITH_SESSION,
				      cet->reset_sess, 0);
}

static_always_inline int
cryptodev_frame_linked_algs_enqueue (vlib_main_t * vm,
				     vnet_crypto_async_frame_t * frame,
				     cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  struct rte_crypto_vec *vec;
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec;
  vlib_buffer_t **b;
  u32 n_elts;
  u32 last_key_index = ~0;
  i16 min_ofs;
  u32 max_end;
  int status;

  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_MAX_INFLIGHT - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  vec = cet->vec;
  b = cet->b;
  fe = frame->elts;

  while (n_elts)
    {
      union rte_crypto_sym_ofs cofs;
      u16 n_seg = 1;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (&fe[1], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&fe[2], CLIB_CACHE_LINE_BYTES, LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	  vlib_prefetch_buffer_header (b[2], LOAD);
	}

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);

	  if (PREDICT_FALSE (key->keys[vm->numa_node][op_type].crypto_sess ==
			     0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, 0);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  status = rte_cryptodev_configure_raw_dp_ctx (
	    cet->cryptodev_id, cet->cryptodev_q, cet->ctx,
	    RTE_CRYPTO_OP_WITH_SESSION, key->keys[vm->numa_node][op_type],
	    /*is_update */ 1);
	  if (PREDICT_FALSE (status < 0))
	    goto error_exit;

	  last_key_index = fe->key_index;
	}

      cofs.raw = compute_ofs_linked_alg (fe, &min_ofs, &max_end);

      vec->len = max_end - min_ofs;
      if (cmt->iova_mode == RTE_IOVA_VA)
	{
	  vec[0].base = (void *) (b[0]->data + min_ofs);
	  vec[0].iova = pointer_to_uword (b[0]->data) + min_ofs;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = pointer_to_uword (fe->iv);
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = pointer_to_uword (fe->tag);
	}
      else
	{
	  vec[0].base = (void *) (b[0]->data + min_ofs);
	  vec[0].iova = vlib_buffer_get_pa (vm, b[0]) + min_ofs;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = vlib_physmem_get_pa (vm, fe->iv);
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = vlib_physmem_get_pa (vm, fe->digest);
	}

      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	{
	  vec[0].len = b[0]->current_data + b[0]->current_length - min_ofs;
	  if (cryptodev_frame_build_sgl (vm, cmt->iova_mode, vec, &n_seg, b[0],
					 max_end - min_ofs - vec->len) < 0)
	    goto error_exit;
	}

      status = rte_cryptodev_raw_enqueue (cet->ctx, vec, n_seg, cofs, &iv_vec,
					  &digest_vec, 0, (void *) frame);
      if (PREDICT_FALSE (status < 0))
	goto error_exit;

      b++;
      fe++;
      n_elts--;
    }

  status = rte_cryptodev_raw_enqueue_done (cet->ctx, frame->n_elts);
  if (PREDICT_FALSE (status < 0))
    {
      cryptodev_reset_ctx (cet);
      return -1;
    }

  cet->inflight += frame->n_elts;
  return 0;

error_exit:
  cryptodev_mark_frame_err_status (frame,
				   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  cryptodev_reset_ctx (cet);
  return -1;
}

static_always_inline int
cryptodev_frame_gcm_enqueue (vlib_main_t * vm,
			     vnet_crypto_async_frame_t * frame,
			     cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  vlib_buffer_t **b;
  u32 n_elts;
  union rte_crypto_sym_ofs cofs;
  struct rte_crypto_vec *vec;
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec, aad_vec;
  u32 last_key_index = ~0;
  int status;

  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_MAX_INFLIGHT - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  vec = cet->vec;
  fe = frame->elts;
  b = cet->b;
  cofs.raw = 0;

  while (n_elts)
    {
      u32 aad_offset = ((cet->aad_index++) & CRYPTODEV_AAD_MASK) << 4;
      u16 n_seg = 1;

      if (n_elts > 1)
	{
	  CLIB_PREFETCH (&fe[1], CLIB_CACHE_LINE_BYTES, LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	}

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);

	  if (PREDICT_FALSE (key->keys[vm->numa_node][op_type].crypto_sess ==
			     0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  if (PREDICT_FALSE ((u8) key->keys[vm->numa_node][op_type]
			       .crypto_sess->opaque_data != aad_len))
	    {
	      cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_DEL,
				      fe->key_index, aad_len);
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  status = rte_cryptodev_configure_raw_dp_ctx (
	    cet->cryptodev_id, cet->cryptodev_q, cet->ctx,
	    RTE_CRYPTO_OP_WITH_SESSION, key->keys[vm->numa_node][op_type],
	    /*is_update */ 1);
	  if (PREDICT_FALSE (status < 0))
	    goto error_exit;

	  last_key_index = fe->key_index;
	}

      if (cmt->iova_mode == RTE_IOVA_VA)
	{
	  vec[0].base = (void *) (b[0]->data + fe->crypto_start_offset);
	  vec[0].iova = pointer_to_uword (vec[0].base);
	  vec[0].len = fe->crypto_total_length;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = pointer_to_uword (fe->iv);
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = pointer_to_uword (fe->tag);
	  aad_vec.va = (void *) (cet->aad_buf + aad_offset);
	  aad_vec.iova = cet->aad_phy_addr + aad_offset;
	}
      else
	{
	  vec[0].base = (void *) (b[0]->data + fe->crypto_start_offset);
	  vec[0].iova =
	    vlib_buffer_get_pa (vm, b[0]) + fe->crypto_start_offset;
	  vec[0].len = fe->crypto_total_length;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = vlib_physmem_get_pa (vm, fe->iv);
	  aad_vec.va = (void *) (cet->aad_buf + aad_offset);
	  aad_vec.iova = cet->aad_phy_addr + aad_offset;
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = vlib_physmem_get_pa (vm, fe->tag);
	}

      if (aad_len == 8)
	*(u64 *) (cet->aad_buf + aad_offset) = *(u64 *) fe->aad;
      else
	{
	  /* aad_len == 12 */
	  *(u64 *) (cet->aad_buf + aad_offset) = *(u64 *) fe->aad;
	  *(u32 *) (cet->aad_buf + aad_offset + 8) = *(u32 *) (fe->aad + 8);
	}

      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	{
	  vec[0].len = b[0]->current_data + b[0]->current_length -
		       fe->crypto_start_offset;
	  status =
	    cryptodev_frame_build_sgl (vm, cmt->iova_mode, vec, &n_seg, b[0],
				       fe->crypto_total_length - vec[0].len);
	  if (status < 0)
	    goto error_exit;
	}

      status =
	rte_cryptodev_raw_enqueue (cet->ctx, vec, n_seg, cofs, &iv_vec,
				   &digest_vec, &aad_vec, (void *) frame);
      if (PREDICT_FALSE (status < 0))
	goto error_exit;

      fe++;
      b++;
      n_elts--;
    }

  status = rte_cryptodev_raw_enqueue_done (cet->ctx, frame->n_elts);
  if (PREDICT_FALSE (status < 0))
    goto error_exit;

  cet->inflight += frame->n_elts;

  return 0;

error_exit:
  cryptodev_mark_frame_err_status (frame,
				   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  cryptodev_reset_ctx (cet);
  return -1;
}

static u32
cryptodev_get_frame_n_elts (void *frame)
{
  vnet_crypto_async_frame_t *f = (vnet_crypto_async_frame_t *) frame;
  return f->n_elts;
}

static void
cryptodev_post_dequeue (void *frame, u32 index, u8 is_op_success)
{
  vnet_crypto_async_frame_t *f = (vnet_crypto_async_frame_t *) frame;

  f->elts[index].status = is_op_success ? VNET_CRYPTO_OP_STATUS_COMPLETED :
    VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
}

#define GET_RING_OBJ(r, pos, f) do { \
	vnet_crypto_async_frame_t **ring = (void *)&r[1];     \
	f = ring[(r->cons.head + pos) & r->mask]; \
} while (0)

static_always_inline vnet_crypto_async_frame_t *
cryptodev_frame_dequeue (vlib_main_t * vm, u32 * nb_elts_processed,
			 u32 * enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_t *frame, *frame_ret = 0;
  u32 n_deq, n_success;
  u32 n_cached_frame = rte_ring_count (cet->cached_frame), n_room_left;
  u8 no_job_to_deq = 0;
  u16 inflight = cet->inflight;
  int dequeue_status;

  n_room_left = CRYPTODEV_DEQ_CACHE_SZ - n_cached_frame - 1;

  if (n_cached_frame)
    {
      u32 i;
      for (i = 0; i < n_cached_frame; i++)
	{
	  vnet_crypto_async_frame_t *f;
	  void *f_ret;
	  enum rte_crypto_op_status op_status;
	  u8 n_left, err, j;

	  GET_RING_OBJ (cet->cached_frame, i, f);

	  if (i < n_cached_frame - 2)
	    {
	      vnet_crypto_async_frame_t *f1, *f2;
	      GET_RING_OBJ (cet->cached_frame, i + 1, f1);
	      GET_RING_OBJ (cet->cached_frame, i + 2, f2);
	      CLIB_PREFETCH (f1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (f2, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  n_left = f->state & 0x7f;
	  err = f->state & 0x80;

	  for (j = f->n_elts - n_left; j < f->n_elts && inflight; j++)
	    {
	      int ret;
	      f_ret = rte_cryptodev_raw_dequeue (cet->ctx, &ret, &op_status);

	      if (!f_ret)
		break;

	      switch (op_status)
		{
		case RTE_CRYPTO_OP_STATUS_SUCCESS:
		  f->elts[j].status = VNET_CRYPTO_OP_STATUS_COMPLETED;
		  break;
		default:
		  f->elts[j].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
		  err |= 1 << 7;
		}

	      inflight--;
	    }

	  if (j == f->n_elts)
	    {
	      if (i == 0)
		{
		  frame_ret = f;
		  f->state = err ? VNET_CRYPTO_FRAME_STATE_ELT_ERROR :
		    VNET_CRYPTO_FRAME_STATE_SUCCESS;
		}
	      else
		{
		  f->state = f->n_elts - j;
		  f->state |= err;
		}
	      if (inflight)
		continue;
	    }

	  /* to here f is not completed dequeued and no more job can be
	   * dequeued
	   */
	  f->state = f->n_elts - j;
	  f->state |= err;
	  no_job_to_deq = 1;
	  break;
	}

      if (frame_ret)
	{
	  rte_ring_sc_dequeue (cet->cached_frame, (void **) &frame_ret);
	  n_room_left++;
	}
    }

  /* no point to dequeue further */
  if (!inflight || no_job_to_deq || !n_room_left)
    goto end_deq;

  n_deq = rte_cryptodev_raw_dequeue_burst (cet->ctx,
					   cryptodev_get_frame_n_elts,
					   cryptodev_post_dequeue,
					   (void **) &frame, 0, &n_success,
					   &dequeue_status);
  if (!n_deq)
    goto end_deq;

  inflight -= n_deq;
  no_job_to_deq = n_deq < frame->n_elts;
  /* we have to cache the frame */
  if (frame_ret || n_cached_frame || no_job_to_deq)
    {
      frame->state = frame->n_elts - n_deq;
      frame->state |= ((n_success < n_deq) << 7);
      rte_ring_sp_enqueue (cet->cached_frame, (void *) frame);
      n_room_left--;
    }
  else
    {
      frame->state = n_success == frame->n_elts ?
	VNET_CRYPTO_FRAME_STATE_SUCCESS : VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
      frame_ret = frame;
    }

  /* see if we can dequeue more */
  while (inflight && n_room_left && !no_job_to_deq)
    {
      n_deq = rte_cryptodev_raw_dequeue_burst (cet->ctx,
					       cryptodev_get_frame_n_elts,
					       cryptodev_post_dequeue,
					       (void **) &frame, 0,
					       &n_success, &dequeue_status);
      if (!n_deq)
	break;
      inflight -= n_deq;
      no_job_to_deq = n_deq < frame->n_elts;
      frame->state = frame->n_elts - n_deq;
      frame->state |= ((n_success < n_deq) << 7);
      rte_ring_sp_enqueue (cet->cached_frame, (void *) frame);
      n_room_left--;
    }

end_deq:
  if (inflight < cet->inflight)
    {
      int res =
	rte_cryptodev_raw_dequeue_done (cet->ctx, cet->inflight - inflight);
      ASSERT (res == 0);
      cet->inflight = inflight;
    }

  if (frame_ret)
    {
      *nb_elts_processed = frame_ret->n_elts;
      *enqueue_thread_idx = frame_ret->enqueue_thread_index;
    }

  return frame_ret;
}

/* *INDENT-OFF* */
static_always_inline int
cryptodev_enqueue_gcm_aad_8_enc (vlib_main_t * vm,
				 vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_gcm_enqueue (vm, frame,
				      CRYPTODEV_OP_TYPE_ENCRYPT, 8);
}
static_always_inline int
cryptodev_enqueue_gcm_aad_12_enc (vlib_main_t * vm,
				 vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_gcm_enqueue (vm, frame,
				      CRYPTODEV_OP_TYPE_ENCRYPT, 12);
}

static_always_inline int
cryptodev_enqueue_gcm_aad_8_dec (vlib_main_t * vm,
				 vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_gcm_enqueue (vm, frame,
				      CRYPTODEV_OP_TYPE_DECRYPT, 8);
}
static_always_inline int
cryptodev_enqueue_gcm_aad_12_dec (vlib_main_t * vm,
				 vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_gcm_enqueue (vm, frame,
				      CRYPTODEV_OP_TYPE_DECRYPT, 12);
}

static_always_inline int
cryptodev_enqueue_linked_alg_enc (vlib_main_t * vm,
				  vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_ENCRYPT);
}

static_always_inline int
cryptodev_enqueue_linked_alg_dec (vlib_main_t * vm,
				  vnet_crypto_async_frame_t * frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_DECRYPT);
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
      cryptodev_reset_ctx (cet);
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
      cryptodev_reset_ctx (cet);
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
      error = clib_error_return (0, "cryptodev_assign_resource returned %i",
				 ret);
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

  if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))
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

  if (vec_len (cmt->cryptodev_inst) == 0)
    return;
  dev_inst = vec_elt_at_index (cmt->cryptodev_inst, 0);
  rte_cryptodev_info_get (dev_inst->dev_id, &dev_info);
  cap = &dev_info.capabilities[0];

  /*init capabilities vector*/
  while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED)
    {
      ASSERT (cap->op == RTE_CRYPTO_OP_TYPE_SYMMETRIC);
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

  cryptodev_get_common_capabilities ();
  vec_sort_with_function(cmt->cryptodev_inst, cryptodev_cmp);

  /* if there is not enough device stop cryptodev */
  if (vec_len (cmt->cryptodev_inst) < n_workers)
    return -1;

  return 0;
}

static void
cryptodev_get_max_sz (u32 *max_sess_sz, u32 *max_dp_sz)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *cinst;
  u32 max_sess = 0, max_dp = 0;

  vec_foreach (cinst, cmt->cryptodev_inst)
    {
      u32 sess_sz = rte_cryptodev_sym_get_private_session_size (cinst->dev_id);
      u32 dp_sz = rte_cryptodev_get_raw_dp_ctx_size (cinst->dev_id);

      max_sess = clib_max (sess_sz, max_sess);
      max_dp = clib_max (dp_sz, max_dp);
    }

  *max_sess_sz = max_sess;
  *max_dp_sz = max_dp;
}

static void
dpdk_disable_cryptodev_engine (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  cryptodev_engine_thread_t *ptd;

  vec_validate (cmt->per_numa_data, vm->numa_node);
  numa_data = vec_elt_at_index (cmt->per_numa_data, vm->numa_node);

  if (numa_data->sess_pool)
    rte_mempool_free (numa_data->sess_pool);
  if (numa_data->sess_priv_pool)
    rte_mempool_free (numa_data->sess_priv_pool);

  vec_foreach (ptd, cmt->per_thread_data)
    {
      if (ptd->aad_buf)
	rte_free (ptd->aad_buf);
      if (ptd->cached_frame)
	rte_ring_free (ptd->cached_frame);
      if (ptd->reset_sess.crypto_sess)
	{
	  struct rte_mempool *mp =
	    rte_mempool_from_obj ((void *) ptd->reset_sess.crypto_sess);

	  rte_mempool_free (mp);
	  ptd->reset_sess.crypto_sess = 0;
	}
    }
}

static clib_error_t *
create_reset_sess (cryptodev_engine_thread_t *ptd, u32 lcore, u32 numa,
		   u32 sess_sz)
{
  struct rte_crypto_sym_xform xform = { 0 };
  struct rte_crypto_aead_xform *aead_xform = &xform.aead;
  struct rte_cryptodev_sym_session *sess;
  struct rte_mempool *mp = 0;
  u8 key[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  u8 *name = 0;
  clib_error_t *error = 0;

  /* create session pool for the numa node */
  name = format (0, "vcryptodev_s_reset_%u_%u", numa, lcore);
  mp = rte_cryptodev_sym_session_pool_create ((char *) name, 2, sess_sz, 0, 0,
					      numa);
  if (!mp)
    {
      error = clib_error_return (0, "Not enough memory for mp %s", name);
      goto error_exit;
    }
  vec_free (name);

  xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
  aead_xform->algo = RTE_CRYPTO_AEAD_AES_GCM;
  aead_xform->op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
  aead_xform->aad_length = 8;
  aead_xform->digest_length = 16;
  aead_xform->iv.offset = 0;
  aead_xform->iv.length = 12;
  aead_xform->key.data = key;
  aead_xform->key.length = 16;

  sess = rte_cryptodev_sym_session_create (mp);
  if (!sess)
    {
      error = clib_error_return (0, "failed to create session");
      goto error_exit;
    }

  if (rte_cryptodev_sym_session_init (ptd->cryptodev_id, sess, &xform, mp) < 0)
    {
      error = clib_error_return (0, "failed to create session private");
      goto error_exit;
    }

  ptd->reset_sess.crypto_sess = sess;

  return 0;

error_exit:
  if (mp)
    rte_mempool_free (mp);
  if (name)
    vec_free (name);

  return error;
}

clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cryptodev_engine_thread_t *ptd;
  cryptodev_numa_data_t *numa_data;
  struct rte_mempool *mp;
  u32 skip_master = vlib_num_workers () > 0;
  u32 n_workers = tm->n_vlib_mains - skip_master;
  u32 numa = vm->numa_node;
  u32 sess_sz, dp_sz;
  u32 eidx;
  u32 i;
  u8 *name = 0;
  clib_error_t *error;
  struct rte_cryptodev_sym_capability_idx cap_auth_idx;
  struct rte_cryptodev_sym_capability_idx cap_cipher_idx;
  struct rte_cryptodev_sym_capability_idx cap_aead_idx;

  cmt->iova_mode = rte_eal_iova_mode ();

  vec_validate (cmt->per_numa_data, vm->numa_node);

  /* probe all cryptodev devices and get queue info */
  if (cryptodev_probe (vm, n_workers) < 0)
    {
      error = clib_error_return (0, "Failed to configure cryptodev");
      goto err_handling;
    }

  cryptodev_get_max_sz (&sess_sz, &dp_sz);

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, tm->n_vlib_mains);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, tm->n_vlib_mains - 1,
		       CLIB_CACHE_LINE_BYTES);
  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      ptd = cmt->per_thread_data + i;
      numa = vlib_mains[i]->numa_node;

      ptd->aad_buf = rte_zmalloc_socket (0, CRYPTODEV_NB_CRYPTO_OPS *
					 CRYPTODEV_MAX_AAD_SIZE,
					 CLIB_CACHE_LINE_BYTES,
					 numa);

      if (ptd->aad_buf == 0)
	{
	  error = clib_error_return (0, "Failed to alloc aad buf");
	  goto err_handling;
	}

      ptd->aad_phy_addr = rte_malloc_virt2iova (ptd->aad_buf);

      ptd->ctx = rte_zmalloc_socket (0, dp_sz, CLIB_CACHE_LINE_BYTES, numa);
      if (!ptd->ctx)
	{
	  error = clib_error_return (0, "Failed to alloc raw dp ctx");
	  goto err_handling;
	}

      name = format (0, "cache_frame_ring_%u%u", numa, i);
      ptd->cached_frame = rte_ring_create ((char *)name,
					   CRYPTODEV_DEQ_CACHE_SZ, numa,
					   RING_F_SC_DEQ | RING_F_SP_ENQ);

      if (ptd->cached_frame == 0)
	{
	  error = clib_error_return (0, "Failed to alloc frame ring");
	  goto err_handling;
	}
      vec_free (name);

      vec_validate (cmt->per_numa_data, numa);
      numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

      if (!numa_data->sess_pool)
	{
	  /* create session pool for the numa node */
	  name = format (0, "vcryptodev_sess_pool_%u%c", numa, 0);
	  mp = rte_cryptodev_sym_session_pool_create (
	    (char *) name, CRYPTODEV_NB_SESSION, 0, 0, 0, numa);
	  if (!mp)
	    {
	      error =
		clib_error_return (0, "Not enough memory for mp %s", name);
	      goto err_handling;
	    }
	  vec_free (name);

	  numa_data->sess_pool = mp;

	  /* create session private pool for the numa node */
	  name = format (0, "cryptodev_sess_pool_%u%c", numa, 0);
	  mp =
	    rte_mempool_create ((char *) name, CRYPTODEV_NB_SESSION, sess_sz,
				0, 0, NULL, NULL, NULL, NULL, numa, 0);
	  if (!mp)
	    {
	      error =
		clib_error_return (0, "Not enough memory for mp %s", name);
	      vec_free (name);
	      goto err_handling;
	    }

	  vec_free (name);

	  numa_data->sess_priv_pool = mp;
	}

      error = create_reset_sess (ptd, i, numa, sess_sz);
      if (error)
	goto err_handling;

      cryptodev_assign_resource (ptd, 0, CRYPTODEV_RESOURCE_ASSIGN_AUTO);
    }

  /* register handler */
  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 100,
				      "DPDK Cryptodev Engine");

#define _(a, b, c, d, e, f, g)                                                \
  cap_aead_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;                              \
  cap_aead_idx.algo.aead = RTE_CRYPTO_##b##_##c;                              \
  if (cryptodev_check_cap_support (&cap_aead_idx, g, e, f))                   \
    {                                                                         \
      vnet_crypto_register_async_handler (                                    \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_ENC,                 \
	cryptodev_enqueue_gcm_aad_##f##_enc, cryptodev_frame_dequeue);        \
      vnet_crypto_register_async_handler (                                    \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_DEC,                 \
	cryptodev_enqueue_gcm_aad_##f##_dec, cryptodev_frame_dequeue);        \
    }

  foreach_vnet_aead_crypto_conversion
#undef _
/* clang-format off */
#define _(a, b, c, d, e)                                                      \
  cap_auth_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;                              \
  cap_auth_idx.algo.auth = RTE_CRYPTO_AUTH_##d##_HMAC;                        \
  cap_cipher_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;                          \
  cap_cipher_idx.algo.cipher = RTE_CRYPTO_CIPHER_##b;                         \
  if (cryptodev_check_cap_support (&cap_cipher_idx, c, -1, -1) &&             \
      cryptodev_check_cap_support (&cap_auth_idx, -1, e, -1))                 \
    {                                                                         \
      vnet_crypto_register_async_handler (                                    \
	vm, eidx, VNET_CRYPTO_OP_##a##_##d##_TAG##e##_ENC,                    \
	cryptodev_enqueue_linked_alg_enc, cryptodev_frame_dequeue);           \
      vnet_crypto_register_async_handler (                                    \
	vm, eidx, VNET_CRYPTO_OP_##a##_##d##_TAG##e##_DEC,                    \
	cryptodev_enqueue_linked_alg_dec, cryptodev_frame_dequeue);           \
    }

    foreach_cryptodev_link_async_alg
#undef _

  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);
  /* clang-format on */

  /* this engine is only enabled when cryptodev device(s) are presented in
   * startup.conf. Assume it is wanted to be used, turn on async mode here.
   */
  vnet_crypto_request_async_mode (1);
  ipsec_set_async_mode (1);

  return 0;

err_handling:
  dpdk_disable_cryptodev_engine (vm);

  return error;
}
/* *INDENT-On* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
