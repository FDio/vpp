
/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 - 2021 Intel and/or its affiliates.
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
#include <vnet/crypto/crypto.h>

#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#undef always_inline
#include <rte_bus_vdev.h>
#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>
#include <rte_crypto.h>
#include <rte_ring_peek_zc.h>
#include <rte_config.h>

#include "cryptodev.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define CRYPTODEV_AAD_OFFSET (offsetof (cryptodev_op_t, aad))

#define foreach_vnet_crypto_status_conversion                                 \
  _ (SUCCESS, COMPLETED)                                                      \
  _ (NOT_PROCESSED, WORK_IN_PROGRESS)                                         \
  _ (AUTH_FAILED, FAIL_BAD_HMAC)                                              \
  _ (INVALID_SESSION, FAIL_ENGINE_ERR)                                        \
  _ (INVALID_ARGS, FAIL_ENGINE_ERR)                                           \
  _ (ERROR, FAIL_ENGINE_ERR)

static const vnet_crypto_op_status_t cryptodev_status_conversion[] = {
#define _(a, b) VNET_CRYPTO_OP_STATUS_##b,
  foreach_vnet_crypto_status_conversion
#undef _
};

static_always_inline rte_iova_t
cryptodev_get_iova (clib_pmalloc_main_t *pm, enum rte_iova_mode mode,
		    void *data)
{
  u64 index;
  if (mode == RTE_IOVA_VA)
    return (rte_iova_t) pointer_to_uword (data);

  index = clib_pmalloc_get_page_index (pm, data);
  return pointer_to_uword (data) - pm->lookup_table[index];
}

static_always_inline void
cryptodev_validate_mbuf_chain (vlib_main_t *vm, struct rte_mbuf *mb,
			       vlib_buffer_t *b)
{
  struct rte_mbuf *first_mb = mb, *last_mb = mb; /**< last mbuf */
  /* when input node is not dpdk, mbuf data len is not initialized, for
   * single buffer it is not a problem since the data length is written
   * into cryptodev operation. For chained buffer a reference data length
   * has to be computed through vlib_buffer.
   *
   * even when input node is dpdk, it is possible chained vlib_buffers
   * are updated (either added or removed a buffer) but not not mbuf fields.
   * we have to re-link every mbuf in the chain.
   */
  u16 data_len = b->current_length +
		 (b->data + b->current_data - rte_pktmbuf_mtod (mb, u8 *));

  first_mb->nb_segs = 1;
  first_mb->pkt_len = first_mb->data_len = data_len;

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (b);
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
	rte_pktmbuf_reset (mb);
      last_mb->next = mb;
      last_mb = mb;
      mb->data_len = b->current_length;
      mb->pkt_len = b->current_length;
      mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      first_mb->nb_segs++;
      if (PREDICT_FALSE (b->ref_count > 1))
	mb->pool =
	  dpdk_no_cache_mempool_by_buffer_pool_index[b->buffer_pool_index];
    }
}

static_always_inline void
crypto_op_init (struct rte_mempool *mempool,
		void *_arg __attribute__ ((unused)), void *_obj,
		unsigned i __attribute__ ((unused)))
{
  struct rte_crypto_op *op = _obj;

  op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
  op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->phys_addr = rte_mempool_virt2iova (_obj);
  op->mempool = mempool;
}

static_always_inline int
cryptodev_frame_linked_algs_enqueue (vlib_main_t *vm,
				     vnet_crypto_async_frame_t *frame,
				     cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  struct rte_cryptodev_sym_session *sess = 0;
  cryptodev_op_t **cop;
  u32 *bi;
  u32 n_enqueue, n_elts;
  u32 last_key_index = ~0;

  if (PREDICT_FALSE (frame == 0 || frame->n_elts == 0))
    return -1;
  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_NB_CRYPTO_OPS - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cet->cops, n_elts) < 0))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  cop = cet->cops;
  fe = frame->elts;
  bi = frame->buffer_indices;
  cop[0]->frame = frame;
  cop[0]->n_elts = n_elts;

  while (n_elts)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      i16 crypto_offset = fe->crypto_start_offset;
      i16 integ_offset = fe->integ_start_offset;
      u32 offset_diff = crypto_offset - integ_offset;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&fe[1]);
	  clib_prefetch_load (&fe[2]);
	}
      if (last_key_index != fe->key_index)
	{
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);
	  last_key_index = fe->key_index;

	  if (key->keys[vm->numa_node][op_type] == 0)
	    {
	      if (PREDICT_FALSE (
		    cryptodev_session_create (vm, last_key_index, 0) < 0))
		{
		  cryptodev_mark_frame_err_status (
		    frame, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  return -1;
		}
	    }
	  sess = key->keys[vm->numa_node][op_type];
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_TRUE (fe->integ_start_offset < 0))
	{
	  sop->m_src->data_off += fe->integ_start_offset;
	  integ_offset = 0;
	  crypto_offset = offset_diff;
	}
      sop->session = sess;
      sop->cipher.data.offset = crypto_offset;
      sop->cipher.data.length = fe->crypto_total_length;
      sop->auth.data.offset = integ_offset;
      sop->auth.data.length = fe->crypto_total_length + fe->integ_length_adj;
      sop->auth.digest.data = fe->digest;
      sop->auth.digest.phys_addr =
	cryptodev_get_iova (pm, cmt->iova_mode, fe->digest);
      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	cryptodev_validate_mbuf_chain (vm, sop->m_src, b);
      else
	/* for input nodes that are not dpdk-input, it is possible the mbuf
	 * was updated before as one of the chained mbufs. Setting nb_segs
	 * to 1 here to prevent the cryptodev PMD to access potentially
	 * invalid m_src->next pointers.
	 */
	sop->m_src->nb_segs = 1;
      clib_memcpy_fast (cop[0]->iv, fe->iv, 16);
      cop++;
      bi++;
      fe++;
      n_elts--;
    }

  n_enqueue = rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
					   (struct rte_crypto_op **) cet->cops,
					   frame->n_elts);
  ASSERT (n_enqueue == frame->n_elts);
  cet->inflight += n_enqueue;

  return 0;
}

static_always_inline int
cryptodev_frame_aead_enqueue (vlib_main_t *vm,
			      vnet_crypto_async_frame_t *frame,
			      cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  struct rte_cryptodev_sym_session *sess = 0;
  cryptodev_op_t **cop;
  u32 *bi;
  u32 n_enqueue = 0, n_elts;
  u32 last_key_index = ~0;

  if (PREDICT_FALSE (frame == 0 || frame->n_elts == 0))
    return -1;
  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_MAX_INFLIGHT - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cet->cops, n_elts) < 0))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  cop = cet->cops;
  fe = frame->elts;
  bi = frame->buffer_indices;
  cop[0]->frame = frame;
  cop[0]->n_elts = n_elts;

  while (n_elts)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      u16 crypto_offset = fe->crypto_start_offset;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&fe[1]);
	  clib_prefetch_load (&fe[2]);
	}
      if (last_key_index != fe->key_index)
	{
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);

	  last_key_index = fe->key_index;
	  if (key->keys[vm->numa_node][op_type] == 0)
	    {
	      if (PREDICT_FALSE (cryptodev_session_create (vm, last_key_index,
							   aad_len) < 0))
		{
		  cryptodev_mark_frame_err_status (
		    frame, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  return -1;
		}
	    }
	  else if (PREDICT_FALSE (
		     key->keys[vm->numa_node][op_type]->opaque_data !=
		     aad_len))
	    {
	      cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_DEL,
				      fe->key_index, aad_len);
	      if (PREDICT_FALSE (cryptodev_session_create (vm, last_key_index,
							   aad_len) < 0))
		{
		  cryptodev_mark_frame_err_status (
		    frame, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  return -1;
		}
	    }

	  sess = key->keys[vm->numa_node][op_type];
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_FALSE (fe->crypto_start_offset < 0))
	{
	  rte_pktmbuf_prepend (sop->m_src, -fe->crypto_start_offset);
	  crypto_offset = 0;
	}

      sop->session = sess;
      sop->aead.aad.data = cop[0]->aad;
      sop->aead.aad.phys_addr = cop[0]->op.phys_addr + CRYPTODEV_AAD_OFFSET;
      sop->aead.data.length = fe->crypto_total_length;
      sop->aead.data.offset = crypto_offset;
      sop->aead.digest.data = fe->tag;
      sop->aead.digest.phys_addr =
	cryptodev_get_iova (pm, cmt->iova_mode, fe->tag);
      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	cryptodev_validate_mbuf_chain (vm, sop->m_src, b);
      else
	/* for input nodes that are not dpdk-input, it is possible the mbuf
	 * was updated before as one of the chained mbufs. Setting nb_segs
	 * to 1 here to prevent the cryptodev PMD to access potentially
	 * invalid m_src->next pointers.
	 */
	sop->m_src->nb_segs = 1;
      clib_memcpy_fast (cop[0]->iv, fe->iv, 12);
      clib_memcpy_fast (cop[0]->aad, fe->aad, aad_len);
      cop++;
      bi++;
      fe++;
      n_elts--;
    }

  n_enqueue = rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
					   (struct rte_crypto_op **) cet->cops,
					   frame->n_elts);
  ASSERT (n_enqueue == frame->n_elts);
  cet->inflight += n_enqueue;

  return 0;
}

static_always_inline u16
cryptodev_ring_deq (struct rte_ring *r, cryptodev_op_t **cops)
{
  u16 n, n_elts = 0;

  n = rte_ring_dequeue_bulk_start (r, (void **) cops, 1, 0);
  rte_ring_dequeue_finish (r, 0);
  if (!n)
    return 0;

  n = cops[0]->n_elts;
  if (rte_ring_count (r) < n)
    return 0;

  n_elts = rte_ring_sc_dequeue_bulk (r, (void **) cops, n, 0);
  ASSERT (n_elts == n);

  return n_elts;
}

static_always_inline vnet_crypto_async_frame_t *
cryptodev_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			 u32 *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_op_t **cop = cet->cops;
  vnet_crypto_async_frame_elt_t *fe;
  vnet_crypto_async_frame_t *frame;
  u32 n_elts, n_completed_ops = rte_ring_count (cet->ring);
  u32 ss0 = 0, ss1 = 0, ss2 = 0, ss3 = 0; /* sum of status */

  if (cet->inflight)
    {
      n_elts = rte_cryptodev_dequeue_burst (
	cet->cryptodev_id, cet->cryptodev_q,
	(struct rte_crypto_op **) cet->cops, VNET_CRYPTO_FRAME_SIZE);

      if (n_elts)
	{
	  cet->inflight -= n_elts;
	  n_completed_ops += n_elts;

	  rte_ring_sp_enqueue_burst (cet->ring, (void **) cet->cops, n_elts,
				     NULL);
	}
    }

  if (PREDICT_FALSE (n_completed_ops == 0))
    return 0;

  n_elts = cryptodev_ring_deq (cet->ring, cop);
  if (!n_elts)
    return 0;

  frame = cop[0]->frame;
  fe = frame->elts;

  while (n_elts > 4)
    {
      ss0 |= fe[0].status = cryptodev_status_conversion[cop[0]->op.status];
      ss1 |= fe[1].status = cryptodev_status_conversion[cop[1]->op.status];
      ss2 |= fe[2].status = cryptodev_status_conversion[cop[2]->op.status];
      ss3 |= fe[3].status = cryptodev_status_conversion[cop[3]->op.status];

      cop += 4;
      fe += 4;
      n_elts -= 4;
    }

  while (n_elts)
    {
      ss0 |= fe[0].status = cryptodev_status_conversion[cop[0]->op.status];
      fe++;
      cop++;
      n_elts--;
    }

  frame->state = (ss0 | ss1 | ss2 | ss3) == VNET_CRYPTO_OP_STATUS_COMPLETED ?
		   VNET_CRYPTO_FRAME_STATE_SUCCESS :
		   VNET_CRYPTO_FRAME_STATE_ELT_ERROR;

  rte_mempool_put_bulk (cet->cop_pool, (void **) cet->cops, frame->n_elts);
  *nb_elts_processed = frame->n_elts;
  *enqueue_thread_idx = frame->enqueue_thread_index;
  return frame;
}

static_always_inline int
cryptodev_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT,
				       8);
}
static_always_inline int
cryptodev_enqueue_aead_aad_12_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT,
				       12);
}

static_always_inline int
cryptodev_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT,
				       8);
}
static_always_inline int
cryptodev_enqueue_aead_aad_12_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT,
				       12);
}

static_always_inline int
cryptodev_enqueue_linked_alg_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_ENCRYPT);
}

static_always_inline int
cryptodev_enqueue_linked_alg_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_DECRYPT);
}

clib_error_t *
cryptodev_register_cop_hdl (vlib_main_t *vm, u32 eidx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  struct rte_cryptodev_sym_capability_idx cap_auth_idx;
  struct rte_cryptodev_sym_capability_idx cap_cipher_idx;
  struct rte_cryptodev_sym_capability_idx cap_aead_idx;
  u8 *name;
  clib_error_t *error = 0;
  u32 ref_cnt = 0;

  vec_foreach (cet, cmt->per_thread_data)
    {
      u32 thread_index = cet - cmt->per_thread_data;
      u32 numa = vlib_get_main_by_index (thread_index)->numa_node;
      name = format (0, "vpp_cop_pool_%u_%u", numa, thread_index);
      cet->cop_pool = rte_mempool_create (
	(char *) name, CRYPTODEV_NB_CRYPTO_OPS, sizeof (cryptodev_op_t), 0,
	sizeof (struct rte_crypto_op_pool_private), NULL, NULL, crypto_op_init,
	NULL, vm->numa_node, 0);
      if (!cet->cop_pool)
	{
	  error = clib_error_return (
	    0, "Failed to create cryptodev op pool %s", name);

	  goto error_exit;
	}
      vec_free (name);

      name = format (0, "frames_ring_%u_%u", numa, thread_index);
      cet->ring =
	rte_ring_create ((char *) name, CRYPTODEV_NB_CRYPTO_OPS, vm->numa_node,
			 RING_F_SP_ENQ | RING_F_SC_DEQ);
      if (!cet->ring)
	{
	  error = clib_error_return (
	    0, "Failed to create cryptodev op pool %s", name);

	  goto error_exit;
	}
      vec_free (name);

      vec_validate (cet->cops, VNET_CRYPTO_FRAME_SIZE - 1);
    }

#define _(a, b, c, d, e, f, g)                                                \
  cap_aead_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;                              \
  cap_aead_idx.algo.aead = RTE_CRYPTO_##b##_##c;                              \
  if (cryptodev_check_cap_support (&cap_aead_idx, g, e, f))                   \
    {                                                                         \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_ENC,                 \
	cryptodev_enqueue_aead_aad_##f##_enc);                                \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_DEC,                 \
	cryptodev_enqueue_aead_aad_##f##_dec);                                \
      ref_cnt++;                                                              \
    }
  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d, e)                                                      \
  cap_auth_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;                              \
  cap_auth_idx.algo.auth = RTE_CRYPTO_AUTH_##d##_HMAC;                        \
  cap_cipher_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;                          \
  cap_cipher_idx.algo.cipher = RTE_CRYPTO_CIPHER_##b;                         \
  if (cryptodev_check_cap_support (&cap_cipher_idx, c, -1, -1) &&             \
      cryptodev_check_cap_support (&cap_auth_idx, -1, e, -1))                 \
    {                                                                         \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_##d##_TAG##e##_ENC,                    \
	cryptodev_enqueue_linked_alg_enc);                                    \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_##d##_TAG##e##_DEC,                    \
	cryptodev_enqueue_linked_alg_dec);                                    \
      ref_cnt++;                                                              \
    }
    foreach_cryptodev_link_async_alg
#undef _

    if (ref_cnt)
      vnet_crypto_register_dequeue_handler (vm, eidx, cryptodev_frame_dequeue);

    return 0;

error_exit:
  vec_foreach (cet, cmt->per_thread_data)
    {
      if (cet->ring)
	rte_ring_free (cet->ring);

      if (cet->cop_pool)
	rte_mempool_free (cet->cop_pool);
    }

  return error;
}
