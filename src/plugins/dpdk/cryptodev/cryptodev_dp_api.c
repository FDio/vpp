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
#include <vnet/vnet.h>
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

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN, TAG_LEN, AAD_LEN */
#define foreach_vnet_aead_crypto_conversion \
  _(AES_128_GCM, AEAD, AES_GCM, 12, 16, 8)  \
  _(AES_128_GCM, AEAD, AES_GCM, 12, 16, 12) \
  _(AES_192_GCM, AEAD, AES_GCM, 12, 16, 8)  \
  _(AES_192_GCM, AEAD, AES_GCM, 12, 16, 12) \
  _(AES_256_GCM, AEAD, AES_GCM, 12, 16, 8)  \
  _(AES_256_GCM, AEAD, AES_GCM, 12, 16, 12)

/**
 * crypto (alg, cryptodev_alg), hash (alg, digest-size)
 **/
#define foreach_cryptodev_link_async_alg	\
  _ (AES_128_CBC, AES_CBC, SHA1, 12)		\
  _ (AES_192_CBC, AES_CBC, SHA1, 12)		\
  _ (AES_256_CBC, AES_CBC, SHA1, 12)		\
  _ (AES_128_CBC, AES_CBC, SHA224, 14)		\
  _ (AES_192_CBC, AES_CBC, SHA224, 14)		\
  _ (AES_256_CBC, AES_CBC, SHA224, 14)		\
  _ (AES_128_CBC, AES_CBC, SHA256, 16)		\
  _ (AES_192_CBC, AES_CBC, SHA256, 16)		\
  _ (AES_256_CBC, AES_CBC, SHA256, 16)		\
  _ (AES_128_CBC, AES_CBC, SHA384, 24)		\
  _ (AES_192_CBC, AES_CBC, SHA384, 24)		\
  _ (AES_256_CBC, AES_CBC, SHA384, 24)		\
  _ (AES_128_CBC, AES_CBC, SHA512, 32)		\
  _ (AES_192_CBC, AES_CBC, SHA512, 32)		\
  _ (AES_256_CBC, AES_CBC, SHA512, 32)

typedef enum
{
  CRYPTODEV_OP_TYPE_ENCRYPT = 0,
  CRYPTODEV_OP_TYPE_DECRYPT,
  CRYPTODEV_N_OP_TYPES,
} cryptodev_op_type_t;

typedef struct
{
  struct rte_cryptodev_sym_session *keys[CRYPTODEV_N_OP_TYPES];
} cryptodev_key_t;

typedef struct
{
  u32 dev_id;
  u32 q_id;
  u8 *dp_service_buffer;
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
  struct rte_crypto_dp_service_ctx *dp_service;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_ring *cached_frame;
  u16 aad_index;
  u8 *aad_buf;
  u64 aad_phy_addr;
  u16 cryptodev_id;
  u16 cryptodev_q;
  u16 inflight;
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
} cryptodev_main_t;

cryptodev_main_t cryptodev_main;

static int
prepare_aead_xform (struct rte_crypto_sym_xform *xform,
		    cryptodev_op_type_t op_type,
		    const vnet_crypto_key_t * key, u32 aad_len)
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

static int
prepare_linked_xform (struct rte_crypto_sym_xform *xforms,
		      cryptodev_op_type_t op_type,
		      const vnet_crypto_key_t * key)
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
#define _(a, b, c, d) \
  case VNET_CRYPTO_ALG_##a##_##c##_TAG##d:\
    cipher_algo = RTE_CRYPTO_CIPHER_##b; \
    auth_algo = RTE_CRYPTO_AUTH_##c##_HMAC; \
    digest_len = d; \
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

static int
cryptodev_session_create (vnet_crypto_key_t * const key,
			  struct rte_mempool *sess_priv_pool,
			  cryptodev_key_t * session_pair, u32 aad_len)
{
  struct rte_crypto_sym_xform xforms_enc[2] = { {0} };
  struct rte_crypto_sym_xform xforms_dec[2] = { {0} };
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  struct rte_cryptodev *cdev;
  int ret;
  uint8_t dev_id = 0;

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
    dev_id = dev_inst->dev_id;
    cdev = rte_cryptodev_pmd_get_dev (dev_id);

    /* if the session is already configured for the driver type, avoid
       configuring it again to increase the session data's refcnt */
    if (session_pair->keys[0]->sess_data[cdev->driver_id].data &&
	session_pair->keys[1]->sess_data[cdev->driver_id].data)
      continue;

    ret = rte_cryptodev_sym_session_init (dev_id, session_pair->keys[0],
					  xforms_enc, sess_priv_pool);
    ret = rte_cryptodev_sym_session_init (dev_id, session_pair->keys[1],
					  xforms_dec, sess_priv_pool);
    if (ret < 0)
      return ret;
  }
  session_pair->keys[0]->opaque_data = aad_len;
  session_pair->keys[1]->opaque_data = aad_len;

  return 0;
}

static void
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
cryptodev_check_supported_vnet_alg (vnet_crypto_key_t * key)
{
  vnet_crypto_alg_t alg;
  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    return 0;

  alg = key->alg;

#define _(a, b, c, d, e, f)	\
  if (alg == VNET_CRYPTO_ALG_##a) \
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
  cryptodev_numa_data_t *numa_data;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  cryptodev_key_t *ckey = 0;
  int ret = 0;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cmt->keys))
	return;

      ckey = pool_elt_at_index (cmt->keys, idx);
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
      pool_put (cmt->keys, ckey);
      return;
    }
  else if (kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      if (idx >= vec_len (cmt->keys))
	return;

      ckey = pool_elt_at_index (cmt->keys, idx);

      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
    }
  else				/* create key */
    pool_get_zero (cmt->keys, ckey);

  /* do not create session for unsupported alg */
  if (cryptodev_check_supported_vnet_alg (key))
    return;

  numa_data = vec_elt_at_index (cmt->per_numa_data, vm->numa_node);
  sess_pool = numa_data->sess_pool;
  sess_priv_pool = numa_data->sess_priv_pool;

  ckey->keys[0] = rte_cryptodev_sym_session_create (sess_pool);
  if (!ckey->keys[0])
    {
      ret = -1;
      goto clear_key;
    }

  ckey->keys[1] = rte_cryptodev_sym_session_create (sess_pool);
  if (!ckey->keys[1])
    {
      ret = -1;
      goto clear_key;
    }

  ret = cryptodev_session_create (key, sess_priv_pool, ckey, aad_len);

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      memset (ckey, 0, sizeof (*ckey));
      pool_put (cmt->keys, ckey);
    }
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

static_always_inline int
cryptodev_frame_linked_algs_enqueue (vlib_main_t * vm,
				     vnet_crypto_async_frame_t * frame,
				     cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  struct rte_crypto_vec *vec;
  struct rte_crypto_data iv_vec, digest_vec;
  vlib_buffer_t **b;
  u32 n_elts;
  cryptodev_key_t *key;
  u32 last_key_index;
  union rte_crypto_sym_ofs cofs;
  i16 min_ofs;
  u32 max_end;

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

  key = pool_elt_at_index (cmt->keys, fe->key_index);
  last_key_index = fe->key_index;

  if (PREDICT_FALSE
      (rte_cryptodev_dp_configure_service
       (cet->cryptodev_id, cet->cryptodev_q, RTE_CRYPTO_DP_SYM_CHAIN,
	RTE_CRYPTO_OP_WITH_SESSION,
	(union rte_cryptodev_session_ctx) key->keys[op_type], cet->dp_service,
	0) < 0))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  cofs.raw = compute_ofs_linked_alg (fe, &min_ofs, &max_end);

  while (n_elts)
    {
      u16 n_seg = 1;
      int status;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (&fe[1], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&fe[2], CLIB_CACHE_LINE_BYTES, LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	  vlib_prefetch_buffer_header (b[2], LOAD);
	}

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cofs.raw = compute_ofs_linked_alg (fe, &min_ofs, &max_end);

	  key = pool_elt_at_index (cmt->keys, fe->key_index);
	  last_key_index = fe->key_index;

	  if (PREDICT_FALSE
	      (rte_cryptodev_dp_configure_service
	       (cet->cryptodev_id, cet->cryptodev_q, RTE_CRYPTO_DP_SYM_CHAIN,
		RTE_CRYPTO_OP_WITH_SESSION,
		(union rte_cryptodev_session_ctx) key->keys[op_type],
		cet->dp_service, 1) < 0))
	    {
	      cryptodev_mark_frame_err_status (frame,
					       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}

      vec->len = max_end - min_ofs;
      if (cmt->iova_mode == RTE_IOVA_VA)
	{
	  vec->base = (void *) (b[0]->data + min_ofs);
	  vec->iova = pointer_to_uword (b[0]->data) + min_ofs;
	  iv_vec.base = (void *) fe->iv;
	  iv_vec.iova = pointer_to_uword (fe->iv);
	  digest_vec.base = (void *) fe->tag;
	  digest_vec.iova = pointer_to_uword (fe->tag);
	}
      else
	{
	  vec->base = (void *) (b[0]->data + min_ofs);
	  vec->iova = vlib_buffer_get_pa (vm, b[0]) + min_ofs;
	  iv_vec.base = (void *) fe->iv;
	  iv_vec.iova = vlib_physmem_get_pa (vm, fe->iv);
	  digest_vec.base = (void *) fe->tag;
	  digest_vec.iova = vlib_physmem_get_pa (vm, fe->digest);
	}

      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	{
	  vec->len = b[0]->current_data + b[0]->current_length - min_ofs;
	  if (cryptodev_frame_build_sgl
	      (vm, cmt->iova_mode, vec, &n_seg, b[0],
	       max_end - min_ofs - vec->len) < 0)
	    {
	      cryptodev_mark_frame_err_status (frame,
					       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}

      status = rte_cryptodev_dp_submit_single_job (cet->dp_service,
						   vec, n_seg, cofs, &iv_vec,
						   &digest_vec, 0,
						   (void *) frame);
      if (status < 0)
	{
	  cryptodev_mark_frame_err_status (frame,
					   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}

      b++;
      fe++;
      n_elts--;
    }

  rte_cryptodev_dp_submit_done (cet->dp_service, frame->n_elts);
  cet->inflight += frame->n_elts;

  return 0;
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
  cryptodev_key_t *key;
  u32 last_key_index;
  union rte_crypto_sym_ofs cofs;
  struct rte_crypto_vec *vec;
  struct rte_crypto_data iv_vec, digest_vec, aad_vec;
  u8 sess_aad_len;

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

  key = pool_elt_at_index (cmt->keys, fe->key_index);
  last_key_index = fe->key_index;
  sess_aad_len = (u8) key->keys[op_type]->opaque_data;
  if (PREDICT_FALSE (sess_aad_len != aad_len))
    cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_MODIFY,
			    fe->key_index, aad_len);

  if (PREDICT_FALSE
      (rte_cryptodev_dp_configure_service
       (cet->cryptodev_id, cet->cryptodev_q, RTE_CRYPTO_DP_SYM_AEAD,
	RTE_CRYPTO_OP_WITH_SESSION,
	(union rte_cryptodev_session_ctx) key->keys[op_type], cet->dp_service,
	0) < 0))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  while (n_elts)
    {
      u32 aad_offset = ((cet->aad_index++) & CRYPTODEV_AAD_MASK) << 4;
      int status;
      u16 n_seg = 1;

      if (n_elts > 1)
	{
	  CLIB_PREFETCH (&fe[1], CLIB_CACHE_LINE_BYTES, LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	}

      if (last_key_index != fe->key_index)
	{
	  key = pool_elt_at_index (cmt->keys, fe->key_index);
	  sess_aad_len = (u8) key->keys[op_type]->opaque_data;
	  if (PREDICT_FALSE (sess_aad_len != aad_len))
	    {
	      cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_MODIFY,
				      fe->key_index, aad_len);
	    }
	  last_key_index = fe->key_index;

	  if (PREDICT_FALSE
	      (rte_cryptodev_dp_configure_service
	       (cet->cryptodev_id, cet->cryptodev_q, RTE_CRYPTO_DP_SYM_AEAD,
		RTE_CRYPTO_OP_WITH_SESSION,
		(union rte_cryptodev_session_ctx) key->keys[op_type],
		cet->dp_service, 1) < 0))
	    {
	      cryptodev_mark_frame_err_status (frame,
					       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}

      if (cmt->iova_mode == RTE_IOVA_VA)
	{
	  vec[0].base = (void *) (b[0]->data + fe->crypto_start_offset);
	  vec[0].iova = pointer_to_uword (vec[0].base);
	  vec[0].len = fe->crypto_total_length;
	  iv_vec.base = (void *) fe->iv;
	  iv_vec.iova = pointer_to_uword (fe->iv);
	  digest_vec.base = (void *) fe->tag;
	  digest_vec.iova = pointer_to_uword (fe->tag);
	  aad_vec.base = (void *) (cet->aad_buf + aad_offset);
	  aad_vec.iova = cet->aad_phy_addr + aad_offset;
	}
      else
	{
	  vec[0].base = (void *) (b[0]->data + fe->crypto_start_offset);
	  vec[0].iova =
	    vlib_buffer_get_pa (vm, b[0]) + fe->crypto_start_offset;
	  vec[0].len = fe->crypto_total_length;
	  iv_vec.base = (void *) fe->iv;
	  iv_vec.iova = vlib_physmem_get_pa (vm, fe->iv);
	  aad_vec.base = (void *) (cet->aad_buf + aad_offset);
	  aad_vec.iova = cet->aad_phy_addr + aad_offset;
	  digest_vec.base = (void *) fe->tag;
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
	  vec[0].len = b[0]->current_data +
	    b[0]->current_length - fe->crypto_start_offset;
	  if (cryptodev_frame_build_sgl
	      (vm, cmt->iova_mode, vec, &n_seg, b[0],
	       fe->crypto_total_length - vec[0].len) < 0)
	    {
	      cryptodev_mark_frame_err_status (frame,
					       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}

      status =
	rte_cryptodev_dp_submit_single_job (cet->dp_service, vec, n_seg, cofs,
					    &iv_vec, &digest_vec, &aad_vec,
					    (void *) frame);
      if (PREDICT_FALSE (status < 0))
	{
	  cryptodev_mark_frame_err_status (frame,
					   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}
      fe++;
      b++;
      n_elts--;
    }

  rte_cryptodev_dp_submit_done (cet->dp_service, frame->n_elts);
  cet->inflight += frame->n_elts;

  return 0;
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

  n_room_left = CRYPTODEV_DEQ_CACHE_SZ - n_cached_frame - 1;

  if (n_cached_frame)
    {
      u32 i;
      for (i = 0; i < n_cached_frame; i++)
	{
	  vnet_crypto_async_frame_t *f;
	  void *f_ret;
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
	      int ret =
		rte_cryptodev_dp_sym_dequeue_single_job (cet->dp_service,
							 &f_ret);
	      if (ret < 0)
		break;
	      f->elts[j].status = ret == 1 ? VNET_CRYPTO_OP_STATUS_COMPLETED :
		VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	      err |= ret << 7;
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

  n_deq = rte_cryptodev_dp_sym_dequeue (cet->dp_service,
					cryptodev_get_frame_n_elts,
					cryptodev_post_dequeue,
					(void **) &frame, 0, &n_success);
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
      n_deq = rte_cryptodev_dp_sym_dequeue (cet->dp_service,
					    cryptodev_get_frame_n_elts,
					    cryptodev_post_dequeue,
					    (void **) &frame, 0, &n_success);
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
      rte_cryptodev_dp_dequeue_done (cet->dp_service,
				     cet->inflight - inflight);
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
      cet->dp_service = (struct rte_crypto_dp_service_ctx *)
	  cinst->dp_service_buffer;
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
      cet->dp_service = (struct rte_crypto_dp_service_ctx *)
	  cinst->dp_service_buffer;
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

static int
check_cryptodev_alg_support (u32 dev_id)
{
  const struct rte_cryptodev_symmetric_capability *cap;
  struct rte_cryptodev_sym_capability_idx cap_idx;

#define _(a, b, c, d, e, f) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##b; \
  cap_idx.algo.aead = RTE_CRYPTO_##b##_##c; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##b##_##c; \
  else \
    { \
      if (cap->aead.digest_size.min > e || cap->aead.digest_size.max < e) \
	return -RTE_CRYPTO_##b##_##c; \
      if (cap->aead.aad_size.min > f || cap->aead.aad_size.max < f) \
	return -RTE_CRYPTO_##b##_##c; \
      if (cap->aead.iv_size.min > d || cap->aead.iv_size.max < d) \
	return -RTE_CRYPTO_##b##_##c; \
    }

  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER; \
  cap_idx.algo.cipher = RTE_CRYPTO_CIPHER_##b; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_CIPHER_##b; \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH; \
  cap_idx.algo.auth = RTE_CRYPTO_AUTH_##c##_HMAC; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_AUTH_##c;

  foreach_cryptodev_link_async_alg
#undef _
    return 0;
}

static u32
cryptodev_count_queue (u32 numa)
{
  struct rte_cryptodev_info info;
  u32 n_cryptodev = rte_cryptodev_count ();
  u32 i, q_count = 0;

  for (i = 0; i < n_cryptodev; i++)
    {
      rte_cryptodev_info_get (i, &info);
      if (rte_cryptodev_socket_id (i) != numa)
	{
	  clib_warning ("DPDK crypto resource %s is in different numa node "
	      "as %u, ignored", info.device->name, numa);
	  continue;
	}
      q_count += info.max_nb_queue_pairs;
    }

  return q_count;
}

static int
cryptodev_configure (vlib_main_t *vm, u32 cryptodev_id)
{
  struct rte_cryptodev_info info;
  struct rte_cryptodev *cdev;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data = vec_elt_at_index (cmt->per_numa_data,
						       vm->numa_node);
  u32 dp_size = 0;
  u32 i;
  int ret;

  cdev = rte_cryptodev_pmd_get_dev (cryptodev_id);
  rte_cryptodev_info_get (cryptodev_id, &info);

  if (!(info.feature_flags & RTE_CRYPTODEV_FF_DATA_PLANE_SERVICE))
    return -1;

  ret = check_cryptodev_alg_support (cryptodev_id);
  if (ret != 0)
    return ret;



  /** If the device is already started, we reuse it, otherwise configure
   *  both the device and queue pair.
   **/
  if (!cdev->data->dev_started)
    {
      struct rte_cryptodev_config cfg;

      cfg.socket_id = vm->numa_node;
      cfg.nb_queue_pairs = info.max_nb_queue_pairs;

      rte_cryptodev_configure (cryptodev_id, &cfg);

      for (i = 0; i < info.max_nb_queue_pairs; i++)
	{
	  struct rte_cryptodev_qp_conf qp_cfg;

	  qp_cfg.mp_session = numa_data->sess_pool;
	  qp_cfg.mp_session_private = numa_data->sess_priv_pool;
	  qp_cfg.nb_descriptors = CRYPTODEV_NB_CRYPTO_OPS;

	  ret = rte_cryptodev_queue_pair_setup (cryptodev_id, i, &qp_cfg,
						vm->numa_node);
	  if (ret)
	    break;
	}
      if (i != info.max_nb_queue_pairs)
	return -1;

      /* start the device */
      rte_cryptodev_start (i);
    }

  ret = rte_cryptodev_get_dp_service_ctx_data_size (cryptodev_id);
  if (ret < 0)
    return -1;
  dp_size = ret;

  for (i = 0; i < info.max_nb_queue_pairs; i++)
    {
      cryptodev_inst_t *cdev_inst;
      vec_add2(cmt->cryptodev_inst, cdev_inst, 1);
      cdev_inst->desc = vec_new (char, strlen (info.device->name) + 10);
      cdev_inst->dev_id = cryptodev_id;
      cdev_inst->q_id = i;
      vec_validate_aligned(cdev_inst->dp_service_buffer, dp_size, 8);
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
cryptodev_probe (vlib_main_t *vm, u32 n_workers)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 n_queues = cryptodev_count_queue (vm->numa_node);
  u32 i;
  int ret;

  if (n_queues < n_workers)
    return -1;

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      ret = cryptodev_configure (vm, i);
      if (ret)
	continue;
    }

  vec_sort_with_function(cmt->cryptodev_inst, cryptodev_cmp);

  /* if there is not enough device stop cryptodev */
  if (vec_len (cmt->cryptodev_inst) < n_workers)
    return -1;

  return 0;
}

static int
cryptodev_get_session_sz (vlib_main_t *vm, u32 n_workers)
{
  u32 sess_data_sz = 0, i;

  if (rte_cryptodev_count () == 0)
    {
      clib_warning ("Failed");
      return -1;
    }

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      u32 dev_sess_sz = rte_cryptodev_sym_get_private_session_size (i);

      sess_data_sz = dev_sess_sz > sess_data_sz ? dev_sess_sz : sess_data_sz;
    }

  return sess_data_sz;
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
    }
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
  i32 sess_sz;
  u32 eidx;
  u32 i;
  u8 *name = 0;
  clib_error_t *error;

  cmt->iova_mode = rte_eal_iova_mode ();

  sess_sz = cryptodev_get_session_sz(vm, n_workers);
  if (sess_sz < 0)
    {
      error = clib_error_return (0, "Not enough cryptodevs");
      return error;
    }

  vec_validate (cmt->per_numa_data, vm->numa_node);
  numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

  /* create session pool for the numa node */
  name = format (0, "vcryptodev_sess_pool_%u%c", numa, 0);
  mp = rte_cryptodev_sym_session_pool_create ((char *) name,
					      CRYPTODEV_NB_SESSION,
					      0, 0, 0, numa);
  if (!mp)
    {
      error = clib_error_return (0, "Not enough memory for mp %s", name);
      goto err_handling;
    }
  vec_free (name);

  numa_data->sess_pool = mp;

  /* create session private pool for the numa node */
  name = format (0, "cryptodev_sess_pool_%u%c", numa, 0);
  mp = rte_mempool_create ((char *) name, CRYPTODEV_NB_SESSION, sess_sz, 0,
			   0, NULL, NULL, NULL, NULL, numa, 0);
  if (!mp)
    {
      error = clib_error_return (0, "Not enough memory for mp %s", name);
      vec_free (name);
      goto err_handling;
    }

  vec_free (name);

  numa_data->sess_priv_pool = mp;

  /* probe all cryptodev devices and get queue info */
  if (cryptodev_probe (vm, n_workers) < 0)
    {
      error = clib_error_return (0, "Failed to configure cryptodev");
      goto err_handling;
    }

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, tm->n_vlib_mains);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, tm->n_vlib_mains - 1,
		       CLIB_CACHE_LINE_BYTES);
  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      ptd = cmt->per_thread_data + i;
      cryptodev_assign_resource (ptd, 0, CRYPTODEV_RESOURCE_ASSIGN_AUTO);
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

      name = format (0, "cache_frame_ring_%u%u", numa, i);
      ptd->cached_frame = rte_ring_create ((char *)name,
					   CRYPTODEV_DEQ_CACHE_SZ, numa,
					   RING_F_SC_DEQ | RING_F_SP_ENQ);

      if (ptd->cached_frame == 0)
	{
	  error = clib_error_return (0, "Failed to frame ring");
	  goto err_handling;
	}
      vec_free (name);
    }

  /* register handler */
  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 79,
                                      "DPDK Cryptodev Engine");

#define _(a, b, c, d, e, f) \
  vnet_crypto_register_async_handler \
    (vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_ENC, \
	cryptodev_enqueue_gcm_aad_##f##_enc,\
	cryptodev_frame_dequeue); \
  vnet_crypto_register_async_handler \
    (vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_DEC, \
	cryptodev_enqueue_gcm_aad_##f##_dec, \
	cryptodev_frame_dequeue);

  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d) \
  vnet_crypto_register_async_handler \
    (vm, eidx, VNET_CRYPTO_OP_##a##_##c##_TAG##d##_ENC, \
	cryptodev_enqueue_linked_alg_enc, \
	cryptodev_frame_dequeue); \
  vnet_crypto_register_async_handler \
    (vm, eidx, VNET_CRYPTO_OP_##a##_##c##_TAG##d##_DEC, \
	cryptodev_enqueue_linked_alg_dec, \
	cryptodev_frame_dequeue);

    foreach_cryptodev_link_async_alg
#undef _

  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);

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
