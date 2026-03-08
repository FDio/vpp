
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 - 2021 Intel and/or its affiliates.
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

static const u8 cryptodev_status_conversion[] = {
  [RTE_CRYPTO_OP_STATUS_SUCCESS] = VNET_CRYPTO_OP_STATUS_COMPLETED,
  [RTE_CRYPTO_OP_STATUS_NOT_PROCESSED] = VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS,
  [RTE_CRYPTO_OP_STATUS_AUTH_FAILED] = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC,
  [RTE_CRYPTO_OP_STATUS_INVALID_SESSION] = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR,
  [RTE_CRYPTO_OP_STATUS_INVALID_ARGS] = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR,
  [RTE_CRYPTO_OP_STATUS_ERROR] = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR,
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

  if (PREDICT_FALSE (ring_elt == NULL))
    return -1;

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
      ring->frames[*enq].frame_elts_errs_mask = cryptodev_mark_frame_fill_err (
	frame, ring->frames[*enq].frame_elts_errs_mask, ring->frames[*enq].enq_elts_head,
	max_to_enq, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
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
      vnet_crypto_alg_data_t *ad = crypto_main.algs + fe->key->alg;
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      i16 cipher_offset = fe->cipher_data_start_off;
      i16 auth_offset = fe->auth_data_start_off;
      u32 offset_diff = cipher_offset - auth_offset;
      u32 key_index = fe->key->index;
      cryptodev_op_type_t sess_op_type = op_type;
      u8 *digest = fe->icv;

      if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH)
	sess_op_type = fe->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK ? VNET_CRYPTO_OP_TYPE_DECRYPT :
								    VNET_CRYPTO_OP_TYPE_ENCRYPT;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&fe[1]);
	  clib_prefetch_load (&fe[2]);
	}
      if (last_key_index != key_index)
	{
	  cryptodev_key_data_t *key = cryptodev_get_key_data (fe->key);
	  cryptodev_session_t *key_sess;
	  last_key_index = key_index;
	  key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);

	  if (key_sess == 0)
	    {
	      if (PREDICT_FALSE (cryptodev_session_create (vm, last_key_index, 0, fe->icv_len) < 0))
		{
		  ring->frames[*enq].frame_elts_errs_mask =
		    cryptodev_mark_frame_fill_err (frame, ring->frames[*enq].frame_elts_errs_mask,
						   ring->frames[*enq].enq_elts_head, max_to_enq,
						   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
		}
	    }
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH &&
		   PREDICT_FALSE (rte_cryptodev_sym_session_opaque_data_get (key_sess) !=
				  (u64) fe->icv_len))
	    {
	      cryptodev_sess_handler (vm, key_index);
	      if (PREDICT_FALSE (cryptodev_session_create (vm, last_key_index, 0, fe->icv_len) < 0))
		{
		  ring->frames[*enq].frame_elts_errs_mask =
		    cryptodev_mark_frame_fill_err (frame, ring->frames[*enq].frame_elts_errs_mask,
						   ring->frames[*enq].enq_elts_head, max_to_enq,
						   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
		}
	      key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);
	    }
	  else
	    key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);
	  sess = key_sess;
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_TRUE (fe->auth_data_start_off < 0))
	{
	  sop->m_src->data_off += fe->auth_data_start_off;
	  auth_offset = 0;
	  cipher_offset = offset_diff;
	}
      sop->session = sess;
      sop->cipher.data.offset = cipher_offset;
      sop->cipher.data.length = fe->cipher_data_len;
      sop->auth.data.offset = auth_offset;
      sop->auth.data.length = fe->auth_data_len;
      sop->auth.digest.data = digest;
      sop->auth.digest.phys_addr = cryptodev_get_iova (pm, cmt->iova_mode, digest);
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

  if (PREDICT_FALSE (ring_elt == NULL))
    return -1;

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
      ring->frames[*enq].frame_elts_errs_mask = cryptodev_mark_frame_fill_err (
	frame, ring->frames[*enq].frame_elts_errs_mask, ring->frames[*enq].enq_elts_head,
	max_to_enq, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
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
      u16 cipher_offset = fe->cipher_data_start_off;
      u32 key_index = fe->key->index;
      u8 *tag = fe->icv;
      u8 *aad = fe->aad;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&fe[1]);
	  clib_prefetch_load (&fe[2]);
	}
      if (last_key_index != key_index)
	{
	  cryptodev_key_data_t *key = cryptodev_get_key_data (fe->key);

	  last_key_index = key_index;
	  if (cryptodev_session_get (key, vm->numa_node, op_type) == 0)
	    {
	      if (PREDICT_FALSE (
		    cryptodev_session_create (vm, last_key_index, aad_len, fe->icv_len) < 0))
		{
		  ring->frames[*enq].frame_elts_errs_mask =
		    cryptodev_mark_frame_fill_err (frame, ring->frames[*enq].frame_elts_errs_mask,
						   ring->frames[*enq].enq_elts_head, max_to_enq,
						   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
		}
	    }
	  else if (PREDICT_FALSE (rte_cryptodev_sym_session_opaque_data_get (cryptodev_session_get (
				    key, vm->numa_node, op_type)) != (u64) aad_len))
	    {
	      cryptodev_sess_handler (vm, key_index);
	      if (PREDICT_FALSE (
		    cryptodev_session_create (vm, last_key_index, aad_len, fe->icv_len) < 0))
		{
		  ring->frames[*enq].frame_elts_errs_mask =
		    cryptodev_mark_frame_fill_err (frame, ring->frames[*enq].frame_elts_errs_mask,
						   ring->frames[*enq].enq_elts_head, max_to_enq,
						   VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  goto error_exit;
		}
	    }

	  sess = cryptodev_session_get (key, vm->numa_node, op_type);
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_FALSE (fe->cipher_data_start_off < 0))
	{
	  rte_pktmbuf_prepend (sop->m_src, -fe->cipher_data_start_off);
	  cipher_offset = 0;
	}

      sop->session = sess;
      sop->aead.aad.data = cop[0]->aad;
      sop->aead.aad.phys_addr = cop[0]->op.phys_addr + CRYPTODEV_AAD_OFFSET;
      sop->aead.data.length = fe->cipher_data_len;
      sop->aead.data.offset = cipher_offset;
      sop->aead.digest.data = tag;
      sop->aead.digest.phys_addr = cryptodev_get_iova (pm, cmt->iova_mode, tag);
      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	cryptodev_validate_mbuf_chain (vm, sop->m_src, b);
      else
	cryptodev_validate_mbuf (sop->m_src, b);

      clib_memcpy_fast (cop[0]->iv, fe->iv, 12);
      clib_memset (cop[0]->aad, 0, 16);
      clib_memcpy_fast (cop[0]->aad, aad, aad_len);

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
cryptodev_frame_dequeue_internal (vlib_main_t *vm,
				  clib_thread_index_t *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_t *frame = NULL;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const deq = &ring->deq_tail;
  u16 n_deq, left_to_deq;
  u16 max_to_deq = 0;
  u16 inflight = cet->inflight;
  u8 dequeue_more = 0;
  cryptodev_op_t *cops[CRYPTODE_DEQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  u32 n_elts, n;
  u64 err0 = 0, err1 = 0, err2 = 0, err3 = 0; /* partial errors mask */

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
  n_elts = n_deq;
  n = ring->frames[*deq].deq_elts_tail;

  while (n_elts > 4)
    {
      u8 status0 = cryptodev_status_conversion[cop[0]->op.status];
      u8 status1 = cryptodev_status_conversion[cop[1]->op.status];
      u8 status2 = cryptodev_status_conversion[cop[2]->op.status];
      u8 status3 = cryptodev_status_conversion[cop[3]->op.status];

      if (status0 == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (frame, n);
      else if (status0 != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  vlib_crypto_async_frame_set_engine_error (frame, n);
	  err0 |= 1ULL << n;
	}

      if (status1 == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (frame, n + 1);
      else if (status1 != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  vlib_crypto_async_frame_set_engine_error (frame, n + 1);
	  err1 |= 1ULL << (n + 1);
	}

      if (status2 == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (frame, n + 2);
      else if (status2 != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  vlib_crypto_async_frame_set_engine_error (frame, n + 2);
	  err2 |= 1ULL << (n + 2);
	}

      if (status3 == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (frame, n + 3);
      else if (status3 != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  vlib_crypto_async_frame_set_engine_error (frame, n + 3);
	  err3 |= 1ULL << (n + 3);
	}

      cop += 4;
      n_elts -= 4;
      n += 4;
    }

  while (n_elts)
    {
      u8 status0 = cryptodev_status_conversion[cop[0]->op.status];

      if (status0 == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (frame, n);
      else if (status0 != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  vlib_crypto_async_frame_set_engine_error (frame, n);
	  err0 |= 1ULL << n;
	}

      n++;
      cop++;
      n_elts--;
    }

  ring->frames[*deq].frame_elts_errs_mask |= (err0 | err1 | err2 | err3);

  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, n_deq);

  inflight -= n_deq;
  ring->frames[*deq].deq_elts_tail += n_deq;
  if (cryptodev_cache_ring_update_deq_tail (ring, deq))
    {
      u32 fr_processed =
	(CRYPTODEV_CACHE_QUEUE_SIZE - ring->tail + ring->deq_tail) &
	CRYPTODEV_CACHE_QUEUE_MASK;

      *enqueue_thread_idx = frame->enqueue_thread_index;
      dequeue_more = (fr_processed < CRYPTODEV_MAX_PROCESED_IN_CACHE_QUEUE);
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
			 clib_thread_index_t *enqueue_thread_idx)
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
      dequeue_more = cryptodev_frame_dequeue_internal (vm, enqueue_thread_idx);
    }

  if (PREDICT_TRUE (ring->frames[ring->enq_head].f != 0))
    cryptodev_enqueue_frame (vm, &ring->frames[ring->enq_head]);

  if (PREDICT_TRUE (ring_elt->f != 0))
    {
      if (ring_elt->n_elts == ring_elt->deq_elts_tail)
	{
	  *nb_elts_processed = ring_elt->n_elts;
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
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_ENCRYPT, 0);
}
static_always_inline int
cryptodev_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_ENCRYPT, 8);
}
static_always_inline int
cryptodev_enqueue_aead_aad_12_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_ENCRYPT, 12);
}

static_always_inline int
cryptodev_enqueue_aead_aad_0_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_DECRYPT, 0);
}
static_always_inline int
cryptodev_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_DECRYPT, 8);
}
static_always_inline int
cryptodev_enqueue_aead_aad_12_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_aead_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_DECRYPT, 12);
}

static_always_inline int
cryptodev_enqueue_linked_alg_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_ENCRYPT);
}

static_always_inline int
cryptodev_enqueue_linked_alg_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_DECRYPT);
}

static_always_inline int
cryptodev_enqueue_hmac (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame, VNET_CRYPTO_OP_TYPE_HMAC);
}

static vnet_crypto_frame_enq_fn_t *
cryptodev_cop_get_enq_fn (const vnet_crypto_alg_data_t *ad, vnet_crypto_op_type_t op_type)
{
  u8 is_enc = op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    {
      if (ad->cipher_family == VNET_CRYPTO_ALG_FAMILY_AES_NULL_GMAC)
	return 0;

      switch (ad->aad_len)
	{
	case 0:
	  return is_enc ? cryptodev_enqueue_aead_aad_0_enc : cryptodev_enqueue_aead_aad_0_dec;
	case 8:
	  return is_enc ? cryptodev_enqueue_aead_aad_8_enc : cryptodev_enqueue_aead_aad_8_dec;
	case 12:
	  return is_enc ? cryptodev_enqueue_aead_aad_12_enc : cryptodev_enqueue_aead_aad_12_dec;
	default:
	  return 0;
	}
    }

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    return is_enc ? cryptodev_enqueue_linked_alg_enc : cryptodev_enqueue_linked_alg_dec;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_CIPHER)
    return is_enc ? cryptodev_enqueue_linked_alg_enc : cryptodev_enqueue_linked_alg_dec;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH && op_type == VNET_CRYPTO_OP_TYPE_HMAC)
    return cryptodev_enqueue_hmac;

  return 0;
}

clib_error_t *
cryptodev_register_cop_hdl (vlib_main_t *vm, u32 eidx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  u8 *name;
  clib_error_t *error = 0;
  u32 ref_cnt = 0;

  vec_foreach (cet, cmt->per_thread_data)
    {
      clib_thread_index_t thread_index = cet - cmt->per_thread_data;
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
  ref_cnt = cryptodev_register_async_algs (vm, eidx, cryptodev_cop_get_enq_fn, "cop");

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
