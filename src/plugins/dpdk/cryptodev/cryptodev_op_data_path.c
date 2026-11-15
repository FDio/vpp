
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

static_always_inline void
cryptodev_frame_linked_algs_enqueue_internal (vlib_main_t *vm, cryptodev_cache_ring_elt_t *ring_elt,
					      cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  vnet_crypto_ctx_t *ctx;
  vnet_crypto_ctx_t **ctxs;
  cryptodev_session_t *sess = 0;
  cryptodev_op_t *cops[CRYPTODE_ENQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  u32 *bi = 0;
  u32 n_enqueue, n_elts;
  u32 last_key_index = ~0;
  u32 max_to_enq;

  max_to_enq = clib_min (CRYPTODE_ENQ_MAX, ring_elt->n_elts - ring_elt->enq_elts_head);

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    return;

  n_elts = max_to_enq;

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cops, n_elts) < 0))
    {
      cryptodev_mark_frame_fill_err (ring_elt, ring_elt->enq_elts_head, max_to_enq,
				     VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      ring_elt->enq_elts_head += max_to_enq;
      ring_elt->deq_elts_tail += max_to_enq;
      cryptodev_cache_ring_update_enq_head (ring);
      return;
    }

  ctxs = cryptodev_frame_ctxs (ring_elt) + ring_elt->enq_elts_head;
  bi = cryptodev_frame_buffer_indices (ring_elt) + ring_elt->enq_elts_head;

  while (n_elts)
    {
      ctx = ctxs[0];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      vnet_crypto_buffer_metadata_t *md = vnet_crypto_buffer_get_metadata (b);
      vnet_crypto_alg_data_t *ad = crypto_main.algs + ctx->alg;
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      i16 cipher_offset = md->cipher_data_start_off;
      i16 auth_offset = md->auth_data_start_off;
      u32 offset_diff = cipher_offset - auth_offset;
      u32 key_index = ctx->index;
      cryptodev_op_type_t sess_op_type = op_type;
      u8 *digest = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);

      if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH)
	sess_op_type =
	  md->is_hmac_check ? VNET_CRYPTO_OP_TYPE_DECRYPT : VNET_CRYPTO_OP_TYPE_ENCRYPT;

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&ctxs[1]);
	  clib_prefetch_load (&ctxs[2]);
	}
      if (last_key_index != key_index)
	{
	  cryptodev_key_data_t *key = cryptodev_get_key_data (ctx);
	  cryptodev_session_t *key_sess;
	  last_key_index = key_index;
	  key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);

	  if (key_sess == 0)
	    {
	      if (PREDICT_FALSE (cryptodev_session_create (vm, ctx, 0, md->icv_len) < 0))
		goto error_exit;
	    }
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_AUTH &&
		   PREDICT_FALSE (rte_cryptodev_sym_session_opaque_data_get (key_sess) !=
				  (u64) md->icv_len))
	    {
	      cryptodev_sess_handler (vm, ctx);
	      if (PREDICT_FALSE (cryptodev_session_create (vm, ctx, 0, md->icv_len) < 0))
		goto error_exit;
	      key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);
	    }
	  else
	    key_sess = cryptodev_session_get (key, vm->numa_node, sess_op_type);
	  sess = key_sess;
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_TRUE (md->auth_data_start_off < 0))
	{
	  sop->m_src->data_off += md->auth_data_start_off;
	  auth_offset = 0;
	  cipher_offset = offset_diff;
	}
      sop->session = sess;
      sop->cipher.data.offset = cipher_offset;
      sop->cipher.data.length = md->cipher_data_len;
      sop->auth.data.offset = auth_offset;
      sop->auth.data.length = md->auth_data_len;
      sop->auth.digest.data = digest;
      sop->auth.digest.phys_addr = cryptodev_get_iova (pm, cmt->iova_mode, digest);
      if (PREDICT_FALSE (md->is_chained_buffers))
	cryptodev_validate_mbuf_chain (vm, sop->m_src, b);
      else
	cryptodev_validate_mbuf (sop->m_src, b);

      clib_memcpy_fast (cop[0]->iv, vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off), 16);
      cop++;
      bi++;
      ctxs++;
      n_elts--;
    }

  n_enqueue =
    rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_enq);
  ERROR_ASSERT (n_enqueue == max_to_enq);
  cet->inflight += max_to_enq;
  ring_elt->enq_elts_head += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring);
  return;

error_exit:
  cryptodev_mark_frame_fill_err (ring_elt, ring_elt->enq_elts_head, max_to_enq,
				 VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  ring_elt->enq_elts_head += max_to_enq;
  ring_elt->deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring);
  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, max_to_enq);
}

static_always_inline void
cryptodev_aead_enqueue_internal (vlib_main_t *vm, cryptodev_cache_ring_elt_t *ring_elt,
				 cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  vnet_crypto_ctx_t *ctx;
  vnet_crypto_ctx_t **ctxs;
  cryptodev_session_t *sess = 0;
  cryptodev_op_t *cops[CRYPTODE_ENQ_MAX] = {};
  cryptodev_op_t **cop = cops;
  u32 *bi = 0;
  u32 n_enqueue = 0, n_elts;
  u32 last_key_index = ~0;
  u16 left_to_enq = ring_elt->n_elts - ring_elt->enq_elts_head;
  const u16 max_to_enq = clib_min (CRYPTODE_ENQ_MAX, left_to_enq);

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    return;

  n_elts = max_to_enq;

  if (PREDICT_FALSE (
	rte_mempool_get_bulk (cet->cop_pool, (void **) cops, n_elts) < 0))
    {
      cryptodev_mark_frame_fill_err (ring_elt, ring_elt->enq_elts_head, max_to_enq,
				     VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      ring_elt->enq_elts_head += max_to_enq;
      ring_elt->deq_elts_tail += max_to_enq;
      cryptodev_cache_ring_update_enq_head (ring);
      return;
    }

  ctxs = cryptodev_frame_ctxs (ring_elt) + ring_elt->enq_elts_head;
  bi = cryptodev_frame_buffer_indices (ring_elt) + ring_elt->enq_elts_head;

  while (n_elts)
    {
      ctx = ctxs[0];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      vnet_crypto_buffer_metadata_t *md = vnet_crypto_buffer_get_metadata (b);
      struct rte_crypto_sym_op *sop = &cop[0]->sop;
      u16 cipher_offset = md->cipher_data_start_off;
      u32 key_index = ctx->index;
      u8 *tag = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
      u8 *aad = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->aad_off);

      if (n_elts > 2)
	{
	  CLIB_PREFETCH (cop[1], sizeof (*cop[1]), STORE);
	  CLIB_PREFETCH (cop[2], sizeof (*cop[2]), STORE);
	  clib_prefetch_load (&ctxs[1]);
	  clib_prefetch_load (&ctxs[2]);
	}
      if (last_key_index != key_index)
	{
	  cryptodev_key_data_t *key = cryptodev_get_key_data (ctx);

	  last_key_index = key_index;
	  if (cryptodev_session_get (key, vm->numa_node, op_type) == 0)
	    {
	      if (PREDICT_FALSE (cryptodev_session_create (vm, ctx, aad_len, md->icv_len) < 0))
		goto error_exit;
	    }
	  else if (PREDICT_FALSE (rte_cryptodev_sym_session_opaque_data_get (cryptodev_session_get (
				    key, vm->numa_node, op_type)) != (u64) aad_len))
	    {
	      cryptodev_sess_handler (vm, ctx);
	      if (PREDICT_FALSE (cryptodev_session_create (vm, ctx, aad_len, md->icv_len) < 0))
		goto error_exit;
	    }

	  sess = cryptodev_session_get (key, vm->numa_node, op_type);
	}

      sop->m_src = rte_mbuf_from_vlib_buffer (b);
      sop->m_src->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      sop->m_dst = 0;
      /* mbuf prepend happens in the tx, but vlib_buffer happens in the nodes,
       * so we have to manually adjust mbuf data_off here so cryptodev can
       * correctly compute the data pointer. The prepend here will be later
       * rewritten by tx. */
      if (PREDICT_FALSE (md->cipher_data_start_off < 0))
	{
	  rte_pktmbuf_prepend (sop->m_src, -md->cipher_data_start_off);
	  cipher_offset = 0;
	}

      sop->session = sess;
      sop->aead.aad.data = cop[0]->aad;
      sop->aead.aad.phys_addr = cop[0]->op.phys_addr + CRYPTODEV_AAD_OFFSET;
      sop->aead.data.length = md->cipher_data_len;
      sop->aead.data.offset = cipher_offset;
      sop->aead.digest.data = tag;
      sop->aead.digest.phys_addr = cryptodev_get_iova (pm, cmt->iova_mode, tag);
      if (PREDICT_FALSE (md->is_chained_buffers))
	cryptodev_validate_mbuf_chain (vm, sop->m_src, b);
      else
	cryptodev_validate_mbuf (sop->m_src, b);

      clib_memcpy_fast (cop[0]->iv, vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off), 12);
      clib_memset (cop[0]->aad, 0, 16);
      clib_memcpy_fast (cop[0]->aad, aad, aad_len);

      cop++;
      bi++;
      ctxs++;
      n_elts--;
    }

  n_enqueue =
    rte_cryptodev_enqueue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_enq);
  ERROR_ASSERT (n_enqueue == max_to_enq);
  cet->inflight += max_to_enq;
  ring_elt->enq_elts_head += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring);
  return;

error_exit:
  cryptodev_mark_frame_fill_err (ring_elt, ring_elt->enq_elts_head, max_to_enq,
				 VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  ring_elt->enq_elts_head += max_to_enq;
  ring_elt->deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring);
  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, max_to_enq);
}

static u8
cryptodev_frame_dequeue_internal (vlib_main_t *vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const deq = &ring->deq_tail;
  cryptodev_cache_ring_elt_t *ring_elt = ring->frames + *deq;
  u16 n_deq, left_to_deq, max_to_deq;
  u8 dequeue_more = 0;
  cryptodev_op_t *cops[CRYPTODE_DEQ_MAX] = {};

  left_to_deq = ring_elt->n_elts - ring_elt->deq_elts_tail;
  max_to_deq = clib_min (left_to_deq, CRYPTODE_DEQ_MAX);

  /* deq field can be used to track frame that is currently dequeued
   based on that you can specify the amount of elements to deq for the frame */
  n_deq =
    rte_cryptodev_dequeue_burst (cet->cryptodev_id, cet->cryptodev_q,
				 (struct rte_crypto_op **) cops, max_to_deq);

  if (n_deq == 0)
    return dequeue_more;

  for (u16 i = 0; i < n_deq; i++)
    {
      u8 status = cryptodev_status_conversion[cops[i]->op.status];

      if (status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	cryptodev_mark_frame_err (ring_elt, ring_elt->deq_elts_tail + i, status);
    }

  rte_mempool_put_bulk (cet->cop_pool, (void **) cops, n_deq);

  cet->inflight -= n_deq;
  ring_elt->deq_elts_tail += n_deq;
  if (cryptodev_cache_ring_update_deq_tail (ring, deq))
    {
      u32 fr_processed =
	(CRYPTODEV_CACHE_QUEUE_SIZE - ring->tail + ring->deq_tail) &
	CRYPTODEV_CACHE_QUEUE_MASK;

      dequeue_more = (fr_processed < CRYPTODEV_MAX_PROCESED_IN_CACHE_QUEUE);
    }

  return dequeue_more;
}

static void
cryptodev_enqueue_frame (vlib_main_t *vm, cryptodev_cache_ring_elt_t *ring_elt)
{
  cryptodev_op_type_t op_type = (cryptodev_op_type_t) ring_elt->op_type;
  u8 linked_or_aad_len = ring_elt->aad_len;

  if (linked_or_aad_len == 1)
    cryptodev_frame_linked_algs_enqueue_internal (vm, ring_elt, op_type);
  else
    cryptodev_aead_enqueue_internal (vm, ring_elt, op_type, linked_or_aad_len);
}

static int
cryptodev_cop_alg_supported (const vnet_crypto_alg_data_t *ad, vnet_crypto_op_type_t op_type)
{
  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    return ad->cipher_family != VNET_CRYPTO_ALG_FAMILY_AES_NULL_GMAC &&
	   (ad->aad_len == 0 || ad->aad_len == 8 || ad->aad_len == 12);

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED || ad->alg_type == VNET_CRYPTO_ALG_T_CIPHER)
    return 1;

  return ad->alg_type == VNET_CRYPTO_ALG_T_AUTH && op_type == VNET_CRYPTO_OP_TYPE_HMAC;
}

clib_error_t *
cryptodev_register_cop_hdl (vlib_main_t *vm, u32 eidx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  u8 *name;
  clib_error_t *error = 0;

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
  cmt->enqueue_frame = cryptodev_enqueue_frame;
  cmt->dequeue = cryptodev_frame_dequeue_internal;
  cryptodev_register_async_algs (vm, eidx, cryptodev_cop_alg_supported, "cop");

  return 0;

error_exit:
  vec_foreach (cet, cmt->per_thread_data)
    {
      if (cet->cop_pool)
	rte_mempool_free (cet->cop_pool);
    }

  return error;
}
