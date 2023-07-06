
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
cryptodev_validate_mbuf (struct rte_mbuf *mb, vlib_buffer_t *b)
{
  /* on vnet side vlib_buffer current_length is updated by cipher padding and
   * icv_sh. mbuf needs to be sync with these changes */
  u16 data_len = b->current_length +
		 (b->data + b->current_data - rte_pktmbuf_mtod (mb, u8 *));

  /* for input nodes that are not dpdk-input, it is possible the mbuf
   * was updated before as one of the chained mbufs. Setting nb_segs
   * to 1 here to prevent the cryptodev PMD to access potentially
   * invalid m_src->next pointers.
   */
  mb->nb_segs = 1;
  mb->pkt_len = mb->data_len = data_len;
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
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  ERROR_ASSERT (frame != 0);
  ERROR_ASSERT (frame->n_elts > 0);
  cryptodev_cache_ring_elt_t *ring_elt =
    cryptodev_cache_ring_push (ring, frame);

  ring_elt->aad_len = 1;
  ring_elt->op_type = (u8) op_type;
  return 0;
}

static_always_inline void
cryptodev_frame_linked_algs_enqueue_internal (vlib_main_t *vm,
					      vnet_crypto_async_frame_t *frame,
					      cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const enq = &ring->enq_head;
  vnet_crypto_async_frame_elt_t *fe;
  cryptodev_session_t *sess = 0;
  cryptodev_op_t *cops[CRYPTODE_ENQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  u32 *bi = 0;
  u32 n_enqueue, n_elts;
  u32 last_key_index = ~0;
  u32 max_to_enq;

  if (PREDICT_FALSE (frame == 0 || frame->n_elts == 0))
    return;

  max_to_enq = clib_min (CRYPTODE_ENQ_MAX,
			 frame->n_elts - ring->frames[*enq].enq_elts_head);

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    return;

  n_elts = max_to_enq;

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cops, n_elts) < 0))
    {
      cryptodev_mark_frame_fill_err (
	frame, ring->frames[*enq].frame_elts_errs_mask,
	ring->frames[*enq].enq_elts_head, max_to_enq,
	VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      ring->frames[*enq].enq_elts_head += max_to_enq;
      ring->frames[*enq].deq_elts_tail += max_to_enq;
      cryptodev_cache_ring_update_enq_head (ring, frame);
      return;
    }

  fe = frame->elts + ring->frames[*enq].enq_elts_head;
  bi = frame->buffer_indices + ring->frames[*enq].enq_elts_head;

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
		  cryptodev_mark_frame_fill_err (
		    frame, ring->frames[*enq].frame_elts_errs_mask,
		    ring->frames[*enq].enq_elts_head, max_to_enq,
		    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
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
	cryptodev_validate_mbuf (sop->m_src, b);

      clib_memcpy_fast (cop[0]->iv, fe->iv, 16);
      ring->frames[*enq].enq_elts_head++;
      cop++;
      bi++;
      fe++;
      n_elts--;
    }

  n_enqueue =
    rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_enq);
  ERROR_ASSERT (n_enqueue == max_to_enq);
  cet->inflight += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  return;

error_exit:
  ring->frames[*enq].enq_elts_head += max_to_enq;
  ring->frames[*enq].deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, max_to_enq);
}

static_always_inline int
cryptodev_frame_aead_enqueue (vlib_main_t *vm,
			      vnet_crypto_async_frame_t *frame,
			      cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  ERROR_ASSERT (frame != 0);
  ERROR_ASSERT (frame->n_elts > 0);
  cryptodev_cache_ring_elt_t *ring_elt =
    cryptodev_cache_ring_push (ring, frame);
  ring_elt->aad_len = aad_len;
  ring_elt->op_type = (u8) op_type;
  return 0;
}

static_always_inline int
cryptodev_aead_enqueue_internal (vlib_main_t *vm,
				 vnet_crypto_async_frame_t *frame,
				 cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const enq = &ring->enq_head;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  vnet_crypto_async_frame_elt_t *fe;
  cryptodev_session_t *sess = 0;
  cryptodev_op_t *cops[CRYPTODE_ENQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  u32 *bi = 0;
  u32 n_enqueue = 0, n_elts;
  u32 last_key_index = ~0;
  u16 left_to_enq = frame->n_elts - ring->frames[*enq].enq_elts_head;
  const u16 max_to_enq = clib_min (CRYPTODE_ENQ_MAX, left_to_enq);

  if (PREDICT_FALSE (frame == 0 || frame->n_elts == 0))
    return -1;

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    return -1;

  n_elts = max_to_enq;

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cops, n_elts) < 0))
    {
      cryptodev_mark_frame_fill_err (
	frame, ring->frames[*enq].frame_elts_errs_mask,
	ring->frames[*enq].enq_elts_head, max_to_enq,
	VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      ring->frames[*enq].enq_elts_head += max_to_enq;
      ring->frames[*enq].deq_elts_tail += max_to_enq;
      cryptodev_cache_ring_update_enq_head (ring, frame);
      return -1;
    }

  fe = frame->elts + ring->frames[*enq].enq_elts_head;
  bi = frame->buffer_indices + ring->frames[*enq].enq_elts_head;

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
		  cryptodev_mark_frame_fill_err (
		    frame, ring->frames[*enq].frame_elts_errs_mask,
		    ring->frames[*enq].enq_elts_head, max_to_enq,
		    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
		}
	    }
	  else if (PREDICT_FALSE (
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
		     rte_cryptodev_sym_session_opaque_data_get (
		       key->keys[vm->numa_node][op_type]) != (u64) aad_len
#else
		     key->keys[vm->numa_node][op_type]->opaque_data != aad_len
#endif
		     ))
	    {
	      cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_DEL,
				      fe->key_index, aad_len);
	      if (PREDICT_FALSE (cryptodev_session_create (vm, last_key_index,
							   aad_len) < 0))
		{
		  cryptodev_mark_frame_fill_err (
		    frame, ring->frames[*enq].frame_elts_errs_mask,
		    ring->frames[*enq].enq_elts_head, max_to_enq,
		    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
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
	cryptodev_validate_mbuf (sop->m_src, b);

      clib_memcpy_fast (cop[0]->iv, fe->iv, 12);
      clib_memcpy_fast (cop[0]->aad, fe->aad, aad_len);

      cop++;
      bi++;
      fe++;
      n_elts--;
    }

  n_enqueue =
    rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_enq);
  ERROR_ASSERT (n_enqueue == max_to_enq);
  cet->inflight += max_to_enq;
  ring->frames[*enq].enq_elts_head += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);

  return 0;

error_exit:
  ring->frames[*enq].enq_elts_head += max_to_enq;
  ring->frames[*enq].deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, max_to_enq);

  return -1;
}

static_always_inline u8
cryptodev_frame_dequeue_internal (vlib_main_t *vm, u32 *nb_elts_processed,
				  u32 *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_t *frame = NULL;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const deq = &ring->deq_tail;
  u16 n_deq, idx, left_to_deq, i;
  u16 max_to_deq = 0;
  u16 inflight = cet->inflight;
  u8 dequeue_more = 0;
  cryptodev_op_t *cops[CRYPTODE_DEQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  vnet_crypto_async_frame_elt_t *fe;
  u32 n_elts, n;
  u64 err0 = 0, err1 = 0, err2 = 0, err3 = 0; /* partial errors mask */

  idx = ring->deq_tail;

  for (i = 0; i < VNET_CRYPTO_FRAME_POOL_SIZE; i++)
    {
      u32 frame_inflight =
	CRYPTODEV_CACHE_RING_GET_FRAME_ELTS_INFLIGHT (ring, idx);

      if (PREDICT_TRUE (frame_inflight > 0))
	break;
      idx++;
      idx &= (VNET_CRYPTO_FRAME_POOL_SIZE - 1);
    }

  ERROR_ASSERT (i != VNET_CRYPTO_FRAME_POOL_SIZE);
  ring->deq_tail = idx;

  left_to_deq =
    ring->frames[*deq].f->n_elts - ring->frames[*deq].deq_elts_tail;
  max_to_deq = clib_min (left_to_deq, CRYPTODE_DEQ_MAX);

  /* deq field can be used to track frame that is currently dequeued
   based on that you can specify the amount of elements to deq for the frame */

  n_deq =
    rte_cryptodev_dequeue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_deq);

  if (n_deq == 0)
    return dequeue_more;

  frame = ring->frames[*deq].f;
  fe = frame->elts + ring->frames[*deq].deq_elts_tail;

  n_elts = n_deq;
  n = ring->frames[*deq].deq_elts_tail;

  while (n_elts > 4)
    {
      fe[0].status = cryptodev_status_conversion[cop[0]->op.status];
      fe[1].status = cryptodev_status_conversion[cop[1]->op.status];
      fe[2].status = cryptodev_status_conversion[cop[2]->op.status];
      fe[3].status = cryptodev_status_conversion[cop[3]->op.status];

      err0 |= (fe[0].status == VNET_CRYPTO_OP_STATUS_COMPLETED) << n;
      err1 |= (fe[1].status == VNET_CRYPTO_OP_STATUS_COMPLETED) << (n + 1);
      err2 |= (fe[2].status == VNET_CRYPTO_OP_STATUS_COMPLETED) << (n + 2);
      err3 |= (fe[3].status == VNET_CRYPTO_OP_STATUS_COMPLETED) << (n + 3);

      cop += 4;
      fe += 4;
      n_elts -= 4;
      n += 4;
    }

  while (n_elts)
    {
      fe[0].status = cryptodev_status_conversion[cop[0]->op.status];
      err0 |= (fe[0].status == VNET_CRYPTO_OP_STATUS_COMPLETED) << n;
      n++;
      fe++;
      cop++;
      n_elts--;
    }

  ring->frames[*deq].frame_elts_errs_mask |= (err0 | err1 | err2 | err3);

  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, n_deq);

  inflight -= n_deq;
  ring->frames[*deq].deq_elts_tail += n_deq;
  if (cryptodev_cache_ring_update_deq_tail (ring, deq))
    {
      *nb_elts_processed = frame->n_elts;
      *enqueue_thread_idx = frame->enqueue_thread_index;
      dequeue_more = (max_to_deq < CRYPTODE_DEQ_MAX);
    }

  cet->inflight = inflight;
  return dequeue_more;
}

static_always_inline void
cryptodev_enqueue_frame (vlib_main_t *vm, cryptodev_cache_ring_elt_t *ring_elt)
{
  cryptodev_op_type_t op_type = (cryptodev_op_type_t) ring_elt->op_type;
  u8 linked_or_aad_len = ring_elt->aad_len;

  if (linked_or_aad_len == 1)
    cryptodev_frame_linked_algs_enqueue_internal (vm, ring_elt->f, op_type);
  else
    cryptodev_aead_enqueue_internal (vm, ring_elt->f, op_type,
				     linked_or_aad_len);
}

static_always_inline vnet_crypto_async_frame_t *
cryptodev_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			 u32 *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vnet_crypto_main_t *cm = &crypto_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  cryptodev_cache_ring_elt_t *ring_elt = &ring->frames[ring->tail];

  vnet_crypto_async_frame_t *ret_frame = 0;
  u8 dequeue_more = 1;

  while (cet->inflight > 0 && dequeue_more)
    {
      dequeue_more = cryptodev_frame_dequeue_internal (vm, nb_elts_processed,
						       enqueue_thread_idx);
    }

  if (PREDICT_TRUE (ring->frames[ring->enq_head].f != 0))
    cryptodev_enqueue_frame (vm, &ring->frames[ring->enq_head]);

  if (PREDICT_TRUE (ring_elt->f != 0))
    {
      if (ring_elt->enq_elts_head == ring_elt->deq_elts_tail)
	{
	  vlib_node_set_interrupt_pending (
	    vlib_get_main_by_index (vm->thread_index), cm->crypto_node_index);
	  ret_frame = cryptodev_cache_ring_pop (ring);
	  return ret_frame;
	}
    }

  return ret_frame;
}
static_always_inline int
cryptodev_enqueue_aead_aad_0_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT,
				       0);
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
cryptodev_enqueue_aead_aad_0_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT,
				       0);
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
      vec_free (name);
      if (!cet->cop_pool)
	{
	  error = clib_error_return (
	    0, "Failed to create cryptodev op pool %s", name);

	  goto error_exit;
	}
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
      if (cet->cop_pool)
	rte_mempool_free (cet->cop_pool);
    }

  return error;
}
