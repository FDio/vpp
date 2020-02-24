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
#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>
#include <rte_crypto.h>
#include <rte_cryptodev_pmd.h>
#include <rte_bus_vdev.h>
#include <rte_config.h>

#define CRYPTODEV_NB_CRYPTO_OPS 4096
#define CRYPTODEV_NB_SESSION    10240

#define IV_OFF (offsetof (cryptodev_op_t, iv))
#define MAX_IV_SIZE 16

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN, DIGEST_LEN, AAD_LEN */
#define foreach_vnet_aead_crypto_conversion \
  _(AES_128_GCM, AEAD, AES_GCM, 12, 12, 12) \
  _(AES_192_GCM, AEAD, AES_GCM, 12, 12, 12) \
  _(AES_256_GCM, AEAD, AES_GCM, 12, 12, 12)

#define foreach_vnet_crypto_status_conversion \
  _(SUCCESS, COMPLETED) \
  _(NOT_PROCESSED, WORK_IN_PROGRESS) \
  _(AUTH_FAILED, FAIL_BAD_HMAC) \
  _(INVALID_SESSION, FAIL_ENGINE_ERR) \
  _(INVALID_ARGS, FAIL_ENGINE_ERR) \
  _(ERROR, FAIL_ENGINE_ERR)

static const vnet_crypto_op_status_t cryptodev_status_conversion[] = {
#define _(a, b) VNET_CRYPTO_OP_STATUS_##b,
  foreach_vnet_crypto_status_conversion
#undef _
};

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_crypto_op op;
  struct rte_crypto_sym_op sop;
  u8 iv[16];
  u32 buffer_index;
  u16 next_index;
} cryptodev_op_t;

typedef enum
{
  CRYPTODEV_OP_TYPE_ENC = 0,
  CRYPTODEV_OP_TYPE_DEC,
  CRYPTODEV_NO_OP_TYPES,
} cryptodev_op_type_t;

typedef struct
{
  struct rte_cryptodev_sym_session *keys[2];
  u32 iv_len;
  u32 aad_len;
  u32 digest_len;
} cryptodev_key_t;

typedef struct
{
  u32 dev_id;
  u32 q_id;
  char *desc;
} cryptodev_inst_t;

typedef struct
{
  struct rte_mempool *cop_pool;
  struct rte_mempool *sess_pool;
  struct rte_mempool *sess_priv_pool;
} cryptodev_numa_data_t;

typedef struct
{
  u16 cryptodev_id;
  u16 cryptodev_q;
  u32 inflight;
  cryptodev_op_t **cops;
} cryptodev_engine_thread_t;

typedef struct
{
  cryptodev_numa_data_t *per_numa_data;
  cryptodev_key_t *keys;
  cryptodev_engine_thread_t *per_thread_data;
  cryptodev_inst_t *cryptodev_inst;
  clib_bitmap_t *active_cdev_inst_mask;
  clib_spinlock_t tlock;
} cryptodev_main_t;

cryptodev_main_t cryptodev_main;

static int
prepare_aead_xform (struct rte_crypto_sym_xform *xform,
		    cryptodev_op_type_t op_type,
		    const vnet_crypto_key_t * key, u32 algo, u32 iv_len,
		    u32 aad_len, u32 digest_len)
{
  struct rte_crypto_aead_xform *aead_xform = &xform->aead;
  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;

  aead_xform->algo = algo;
  aead_xform->op = (op_type == CRYPTODEV_OP_TYPE_ENC) ?
    RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT;
  aead_xform->aad_length = aad_len;
  aead_xform->digest_length = digest_len;
  aead_xform->iv.offset = IV_OFF;
  aead_xform->iv.length = iv_len;
  aead_xform->key.data = key->data;
  aead_xform->key.length = vec_len (key->data);

  return 0;
}

/**
 * lookup the vnet_crypto_alg_t type and transform to dpdk xform type
 *
 *  @param vnet_alg: vnet_crypto_alg_t algo
 *  @param xform_type: the transformed xform type
 *
 *  @return: rte_crypto_cipher_algorithm / rte_crypto_auth_algorithm /
 *      rte_crypto_aead_algorithm enum type
 */
static int
transform_vnet_crypto_type (vnet_crypto_alg_t vnet_alg, u32 * cryptodev_algo,
			    enum rte_crypto_sym_xform_type *xform_type,
			    u32 * iv_len, u32 * digest_len, u32 * aad_len)
{
  switch (vnet_alg)
    {
#define _(v, t, c, i, d, a) \
    case VNET_CRYPTO_ALG_##v: \
      *xform_type = RTE_CRYPTO_SYM_XFORM_##t; \
      *cryptodev_algo = RTE_CRYPTO_##t##_##c; \
      *iv_len = i; \
      *digest_len = d; \
      *aad_len = a;\
      return 0;

      foreach_vnet_aead_crypto_conversion
#undef _
    default:
      *xform_type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED;
      return -1;
    }
}

static int
cryptodev_aead_session_create (vnet_crypto_key_t * const key,
			       struct rte_mempool *sess_pool,
			       struct rte_mempool *sess_priv_pool,
			       cryptodev_key_t * session_pair,
			       u32 iv_len, u32 aad_len, u32 digest_len,
			       u32 aead_cryptodev_algo,
			       enum rte_crypto_sym_xform_type xform_type)
{
  struct rte_crypto_sym_xform aead_xform;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  struct rte_cryptodev *cdev;
  int ret;
  uint8_t dev_id = 0;

  prepare_aead_xform (&aead_xform, CRYPTODEV_OP_TYPE_ENC, key,
		      aead_cryptodev_algo, iv_len, aad_len, digest_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
  {
    dev_id = dev_inst->dev_id;
    cdev = rte_cryptodev_pmd_get_dev (dev_id);

    /* if the session is already configured for the driver type, avoid
       configuring it again to increase the session data's refcnt */
    if (session_pair->keys[0]->sess_data[cdev->driver_id].data &&
	session_pair->keys[1]->sess_data[cdev->driver_id].data)
      continue;

    aead_xform.aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
    ret = rte_cryptodev_sym_session_init (dev_id, session_pair->keys[0],
					  &aead_xform, sess_priv_pool);
    if (ret < 0)
      return ret;

    aead_xform.aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;
    ret = rte_cryptodev_sym_session_init (dev_id, session_pair->keys[1],
					  &aead_xform, sess_priv_pool);
    if (ret < 0)
      return ret;
  }

  session_pair->aad_len = aad_len;
  session_pair->iv_len = iv_len;
  session_pair->digest_len = digest_len;

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

static_always_inline void
cryptodev_sess_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			vnet_crypto_key_index_t idx,
			u32 digest_len, u32 aad_len)
{
  cryptodev_main_t *cm = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  enum rte_crypto_sym_xform_type xform_type;
  cryptodev_key_t *ckey = 0;
  u32 numa;
  u32 cryptodev_algo;
  u32 iv_len, d_len = digest_len, a_len = aad_len;
  int ret = 0;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->keys))
	return;

      ckey = pool_elt_at_index (cm->keys, idx);
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
      pool_put (cm->keys, ckey);
      return;
    }

  ret = transform_vnet_crypto_type (key->alg, &cryptodev_algo,
				    &xform_type, &iv_len, &d_len, &a_len);
  /* unsupported algo will be ignored. */
  if (ret)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      if (idx >= vec_len (cm->keys))
	return;

      ckey = pool_elt_at_index (cm->keys, idx);

      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
      pool_put (cm->keys, ckey);
    }

  /* create key */
  pool_get_aligned_zero_numa (cm->keys, ckey, CLIB_CACHE_LINE_BYTES, 1,
			      vm->numa_node);
  numa = clib_get_current_numa_node ();
  numa_data = vec_elt_at_index (cm->per_numa_data, numa);
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

  switch (xform_type)
    {
    case RTE_CRYPTO_SYM_XFORM_AEAD:
      ret = cryptodev_aead_session_create (key, sess_pool, sess_priv_pool,
					   ckey, iv_len,
					   aad_len == ~0 ? a_len : aad_len,
					   digest_len == ~0 ?
					   d_len : digest_len,
					   cryptodev_algo, xform_type);
      break;
    default:
      ret = -1;
      goto clear_key;
    }

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      memset (ckey, 0, sizeof (*ckey));
      pool_put (cm->keys, ckey);
    }
}

/*static*/ void
cryptodev_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
		       vnet_crypto_key_index_t idx)
{
  cryptodev_sess_handler (vm, kop, idx, ~0, ~0);
}

/**
 * Duplicate of vlib_physmem_get_pa () with validity checking.
 **/
static_always_inline rte_iova_t
cryptodev_get_data_iova (clib_pmalloc_main_t * pm, void *data)
{
  uword index = (pointer_to_uword (data) - pointer_to_uword (pm->base)) >>
    pm->def_log2_page_sz;

  if (PREDICT_FALSE (index >= vec_len (pm->pages)))
    return 0;

  return pointer_to_uword (data) - pm->lookup_table[index];
}

static_always_inline void
fill_op_status (vnet_crypto_op_t ** ops, u32 n,
		vnet_crypto_op_status_t status)
{
  u32 i;
  for (i = 0; i < n; i++)
    ops[i]->status = status;
}

static_always_inline u32
cryptodev_aead_async_enqueue_handler (vlib_main_t * vm,
				      vnet_crypto_op_t * jobs[],
				      u32 n_jobs, cryptodev_op_type_t op_type)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa = cmt->per_numa_data + vm->numa_node;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_op_t **cop;
  vnet_crypto_op_t **job = jobs;
  cryptodev_key_t *key = 0;
  u32 n, n_enqueue = 0, n_to_enqueue;
  u32 last_key_index = ~0;

  n_to_enqueue = n =
    clib_min (CRYPTODEV_NB_CRYPTO_OPS - cet->inflight, n_jobs);
  if (n_to_enqueue == 0)
    return 0;

  vec_validate (cet->cops, n_jobs - 1);
  if (PREDICT_FALSE
      (rte_mempool_get_bulk
       (numa->cop_pool, (void **) cet->cops, n_to_enqueue) < 0))
    n = 0;

  cop = cet->cops;
  while (n)
    {
      vlib_buffer_t *b_src;
      struct rte_mbuf *m_src, *m_dst = 0;
      struct rte_crypto_op *op = &cop[0]->op;
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      rte_iova_t aad_iova, tag_iova;

      if (n > 2)
	{
	  CLIB_PREFETCH (cop[1], CLIB_CACHE_LINE_BYTES * 3, STORE);
	  CLIB_PREFETCH (job[1], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (cop[2], CLIB_CACHE_LINE_BYTES * 3, STORE);
	  CLIB_PREFETCH (job[2], CLIB_CACHE_LINE_BYTES, LOAD);
	}

      b_src = vlib_get_buffer (vm, job[0]->async_src.bi);

      if (last_key_index != job[0]->key_index)
	{
	  key = pool_elt_at_index (cmt->keys, job[0]->key_index);
	  last_key_index = job[0]->key_index;

	  if (PREDICT_FALSE ((key->digest_len != job[0]->tag_len) ||
			     (key->aad_len != job[0]->aad_len)))
	    cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_MODIFY,
				    job[0]->key_index, job[0]->tag_len,
				    job[0]->aad_len);
	  if (PREDICT_FALSE (key->keys[op_type] == 0))
	    {
	      job[0]->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	      goto next_job;
	    }
	}
      m_src = m_dst = rte_mbuf_from_vlib_buffer (b_src);
      /* oop operation */
      if (job[0]->asrc != job[0]->adst)
	{
	  vlib_buffer_t *b_dst = vlib_get_buffer (vm, job[0]->async_dst.bi);
	  m_dst = rte_mbuf_from_vlib_buffer (b_dst);
	}
      op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
      op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
      op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
      sop->m_src = m_src;
      sop->m_dst = m_dst;
      sop->aead.data.offset = job[0]->async_src.crypto_start_offset;
      cop[0]->buffer_index = job[0]->async_dst.bi;
      cop[0]->next_index = job[0]->async_dst.next;
      if (last_key_index != job[0]->key_index)
	{
	  key = pool_elt_at_index (cmt->keys, job[0]->key_index);
	  last_key_index = job[0]->key_index;

	  if (PREDICT_FALSE ((key->digest_len != job[0]->tag_len) ||
			     (key->aad_len != job[0]->aad_len)))
	    cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_MODIFY,
				    job[0]->key_index, job[0]->tag_len,
				    job[0]->aad_len);
	  if (PREDICT_FALSE (key->keys[op_type] == 0))
	    {
	      job[0]->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	      goto next_job;
	    }
	}
      sop->session = key->keys[op_type];
      sop->aead.data.length = job[0]->len;
      clib_memcpy_fast (cop[0]->iv, job[0]->iv, key->iv_len);
      /* discard jobs with failed iova computation */
      aad_iova = cryptodev_get_data_iova (pm, job[0]->aad);
      tag_iova = cryptodev_get_data_iova (pm, job[0]->tag);
      if (PREDICT_FALSE (aad_iova == 0 || tag_iova == 0))
	{
	  job[0]->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	  goto next_job;
	}
      sop->aead.aad.data = job[0]->aad;
      sop->aead.aad.phys_addr = aad_iova;
      sop->aead.digest.data = job[0]->tag;
      sop->aead.digest.phys_addr = tag_iova;
      cop++;
    next_job:
      job++;
      n--;
    }

  if (PREDICT_TRUE (cop - cet->cops))
    {
      n_enqueue = rte_cryptodev_enqueue_burst (cet->cryptodev_id,
					       cet->cryptodev_q,
					       (struct rte_crypto_op **)
					       cet->cops, cop - cet->cops);
      ASSERT (n_enqueue == (cop - cet->cops));
      cet->inflight += n_enqueue;
    }

  if (PREDICT_FALSE (n_enqueue < n_jobs))
    fill_op_status (jobs + n_enqueue, n_jobs - n_enqueue,
		    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);

  return n_enqueue;
}

static_always_inline u32
cryptodev_dequeue_handler (vlib_main_t * vm,
			   vnet_crypto_op_async_data_t post_jobs[],
			   u32 n_post_jobs)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa = cmt->per_numa_data + vm->numa_node;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_op_async_data_t *post_job = post_jobs;
  cryptodev_op_t **cop;
  u32 n, n_dequeue;

  if (n_post_jobs == 0)
    return 0;

  vec_validate (cet->cops, n_post_jobs);
  n_dequeue =
    rte_cryptodev_dequeue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cet->cops,
				 n_post_jobs);
  cet->inflight -= n_dequeue;
  n = n_dequeue;
  cop = cet->cops;

  while (n_dequeue >= 4)
    {
      post_job[0].status = cryptodev_status_conversion[cop[0]->op.status];
      post_job[0].bi = cop[0]->buffer_index;
      post_job[0].next = cop[0]->next_index;

      post_job[1].status = cryptodev_status_conversion[cop[1]->op.status];
      post_job[1].bi = cop[1]->buffer_index;
      post_job[1].next = cop[1]->next_index;

      post_job[2].status = cryptodev_status_conversion[cop[2]->op.status];
      post_job[2].bi = cop[2]->buffer_index;
      post_job[2].next = cop[2]->next_index;

      post_job[3].status = cryptodev_status_conversion[cop[3]->op.status];
      post_job[3].bi = cop[3]->buffer_index;
      post_job[3].next = cop[3]->next_index;

      post_job += 4;
      cop += 4;
      n_dequeue -= 4;
    }

  while (n_dequeue)
    {
      post_job[0].status = cryptodev_status_conversion[cop[0]->op.status];
      post_job[0].bi = cop[0]->buffer_index;
      post_job[0].next = cop[0]->next_index;

      post_job++;
      cop++;
      n_dequeue--;
    }

  rte_mempool_put_bulk (numa->cop_pool, (void **) cet->cops, n);
  return n;
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

#define _(v, t, c, i, d, a) \
static_always_inline u32 \
cryptodev_handler_##v##_enq_enc (vlib_main_t * vm, \
                                vnet_crypto_op_t * ops[], u32 n_ops) \
{ \
  return cryptodev_aead_async_enqueue_handler (vm, ops, n_ops, \
					       CRYPTODEV_OP_TYPE_ENC); \
} \
static_always_inline u32 \
cryptodev_handler_##v##_enq_dec (vlib_main_t * vm, \
                                vnet_crypto_op_t * ops[], u32 n_ops) \
{ \
  return cryptodev_aead_async_enqueue_handler (vm, ops, n_ops, \
					       CRYPTODEV_OP_TYPE_DEC); \
} \
static_always_inline u32 \
cryptodev_handler_##v##_deq (vlib_main_t * vm, \
				 vnet_crypto_op_async_data_t post_jobs[], \
				 u32 n_post_jobs) \
{ return cryptodev_dequeue_handler  (vm, post_jobs, n_post_jobs); }

foreach_vnet_aead_crypto_conversion
#undef _
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
		   "Assignment");
  if (vec_len (cmt->cryptodev_inst) == 0)
    {
      vlib_cli_output (vm, "(nil)\n");
      return 0;
    }

  vec_foreach_index (inst, cmt->cryptodev_inst)
    vlib_cli_output (vm, "%-5u%U\n", inst, format_cryptodev_inst, inst);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cryptodev_assignment, static) = {
    .path = "show cryptodev assignment",
    .short_help = "show cryptodev assignment",
    .function = cryptodev_show_assignment_fn,
};
/* *INDENT-ON* */

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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_cryptodev_assignment, static) = {
    .path = "set cryptodev assignment",
    .short_help = "set cryptodev assignment thread <thread_index> "
	"resource <inst_index>",
    .function = cryptodev_set_assignment_fn,
};
/* *INDENT-ON* */

static int
check_cryptodev_alg_support (u32 dev_id)
{
  const struct rte_cryptodev_symmetric_capability *cap;
  struct rte_cryptodev_sym_capability_idx cap_idx;

#define _(v, t, c, i, d, a) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##t; \
  cap_idx.algo.aead = RTE_CRYPTO_##t##_##c; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##t##_##c;

  foreach_vnet_aead_crypto_conversion
#undef _
    return 0;
}

static void
cryptodev_probe (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  u32 n_cryptodevs = rte_cryptodev_count ();
  u32 numa = vm->numa_node;
  u32 i;

  numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

  for (i = 0; i < n_cryptodevs; i++)
    {
      struct rte_cryptodev_info info;
      struct rte_cryptodev *cdev;
      i32 qp_setup_err = 0;
      u32 n_cdev_inst;
      u32 j;

      cdev = rte_cryptodev_pmd_get_dev (i);
      rte_cryptodev_info_get (i, &info);

      /**
       * Cryptodev is NUMA sensitive, for performance reason the device
       * lies in different numa node is not used.
       **/
      if (rte_cryptodev_socket_id (i) != numa)
	continue;

      if (check_cryptodev_alg_support (i) != 0)
	continue;

      n_cdev_inst = vec_len (cmt->cryptodev_inst);

      /** If the device is already started, we reuse it, otherwise configure
       *  both the device and queue pair.
       **/
      if (!cdev->data->dev_started)
	{
	  struct rte_cryptodev_config cfg;

	  cfg.socket_id = vm->numa_node;
	  cfg.nb_queue_pairs = info.max_nb_queue_pairs;

	  rte_cryptodev_configure (i, &cfg);

	  for (j = 0; j < info.max_nb_queue_pairs; j++)
	    {
	      struct rte_cryptodev_qp_conf qp_cfg;

	      int ret;

	      if (qp_setup_err)
		continue;

	      qp_cfg.mp_session = numa_data->sess_pool;
	      qp_cfg.mp_session_private = numa_data->sess_priv_pool;
	      qp_cfg.nb_descriptors = CRYPTODEV_NB_CRYPTO_OPS;

	      ret = rte_cryptodev_queue_pair_setup (i, j, &qp_cfg, numa);
	      if (ret)
		qp_setup_err = 1;
	    }

	  /* start the device */
	  rte_cryptodev_start (i);
	}

      if (qp_setup_err)
	continue;

      for (j = 0; j < info.max_nb_queue_pairs; j++)
	{
	  cryptodev_inst_t *cdev_inst;

	  vec_validate (cmt->cryptodev_inst, n_cdev_inst + j);
	  cdev_inst = vec_elt_at_index (cmt->cryptodev_inst, n_cdev_inst + j);
	  cdev_inst->desc = vec_new (char, strlen (info.device->name) + 10);
	  cdev_inst->dev_id = i;
	  cdev_inst->q_id = j;

	  snprintf (cdev_inst->desc, 128, "%s_q%u", info.device->name, j);
	}
    }
}

static i32
cryptodev_get_session_sz (void)
{
  u32 sess_data_sz = 0, i;

  if (rte_cryptodev_count () == 0)
    return -1;

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
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 numa;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
    {
      cryptodev_numa_data_t *numa_data;

      numa_data = vec_elt_at_index(cmt->per_numa_data, numa);

      if (numa_data->sess_pool)
        rte_mempool_free (numa_data->sess_pool);
      if (numa_data->sess_priv_pool)
        rte_mempool_free (numa_data->sess_priv_pool);
      if (numa_data->cop_pool)
        rte_mempool_free (numa_data->cop_pool);
    }));
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
  op->phys_addr = rte_mempool_virt2iova (_obj);
  op->mempool = mempool;
}


clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cryptodev_engine_thread_t *ptd;
  u32 skip_master = vlib_num_workers () > 0;
  u32 n_workers = vlib_thread_main.n_vlib_mains - skip_master;
  u32 n_numa, numa;
  i32 sess_sz, cop_priv_sz;
  u32 n_cop_elts;
  u32 eidx;
  u32 i;
  u8 *name = 0;
  clib_error_t *error;
  struct rte_crypto_op_pool_private *priv;

  n_numa = clib_bitmap_count_set_bits (tm->cpu_socket_bitmap);
  sess_sz = cryptodev_get_session_sz ();
  if (sess_sz < 0)
    {
      error = clib_error_return (0, "No Cryptodev available");
      return error;
    }
  cop_priv_sz = sizeof (cryptodev_op_t) - sizeof (struct rte_crypto_op) -
    sizeof (struct rte_crypto_sym_op);
  /* A total of 4 times n_worker threads * frame size as crypto ops */
  n_cop_elts = n_workers * VLIB_FRAME_SIZE * 4;

  vec_validate (cmt->per_numa_data, n_numa);

  /* *INDENT-OFF* */
  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
    {
      cryptodev_numa_data_t *numa_data;
      struct rte_mempool *mp;

      numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

      name = format (0, "vcryptodev_sess_pool_%u", numa);
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

      name = format (0, "cryptodev_sess_pool_%u", numa);
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

      name = format (0, "cryptodev_op_pool_%u", numa);
      mp = rte_mempool_create ((char *) name, n_cop_elts,
			   cop_priv_sz, VLIB_FRAME_SIZE * 2,
			   sizeof (struct rte_crypto_op_pool_private), NULL, NULL,
			   crypto_op_init, NULL, numa, 0);
      if (!mp)
        {
	  error = clib_error_return (0, "Not enough memory for mp %s", name);
	  vec_free (name);
	  goto err_handling;
        }

      priv = rte_mempool_get_priv (mp);
      priv->priv_size = sizeof (struct rte_crypto_op_pool_private);
      priv->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
      vec_free (name);
      numa_data->cop_pool = mp;
    }
  ));
  /* *INDENT-ON* */

  cryptodev_probe (vm);

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, tm->n_vlib_mains);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned (cmt->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      ptd = cmt->per_thread_data + i;
      cryptodev_assign_resource (ptd, 0, CRYPTODEV_RESOURCE_ASSIGN_AUTO);
    }

  eidx = vnet_crypto_register_engine (vm, "dpdk_cryptodev", 80,
				      "DPDK Cryptodev Engine");

#define _(v, t, c, i, d, a) \
  vnet_crypto_register_async_ops_handler (vm, eidx, VNET_CRYPTO_OP_##v##_ENC, \
					  cryptodev_handler_##v##_enq_enc, \
					  cryptodev_handler_##v##_deq); \
  vnet_crypto_register_async_ops_handler (vm, eidx, VNET_CRYPTO_OP_##v##_DEC, \
					  cryptodev_handler_##v##_enq_dec, \
					  cryptodev_handler_##v##_deq);

  foreach_vnet_aead_crypto_conversion;
#undef _
  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);

  return 0;

err_handling:
  dpdk_disable_cryptodev_engine (vm);

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
