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
#include <rte_malloc.h>
#include <rte_config.h>

#include "cryptodev.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

static_always_inline int
cryptodev_frame_build_sgl (vlib_main_t *vm, enum rte_iova_mode iova_mode,
			   struct rte_crypto_vec *data_vec, u16 *n_seg,
			   vlib_buffer_t *b, u32 size)
{
  struct rte_crypto_vec *vec = data_vec + 1;

  while ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && size)
    {
      u32 len;

      if (PREDICT_FALSE (*n_seg >= CRYPTODEV_MAX_N_SGL))
	return -1;

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

static_always_inline void
cryptodev_reset_ctx (cryptodev_engine_thread_t *cet)
{
  union rte_cryptodev_session_ctx sess_ctx;

  ERROR_ASSERT (cet->reset_sess != 0);

  sess_ctx.crypto_sess = cet->reset_sess;

  rte_cryptodev_configure_raw_dp_ctx (cet->cryptodev_id, cet->cryptodev_q,
				      cet->ctx, RTE_CRYPTO_OP_WITH_SESSION,
				      sess_ctx, 0);
}

static_always_inline int
cryptodev_raw_aead_enqueue (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
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

static_always_inline void
cryptodev_raw_combined_enqueue_internal (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
					 cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  vnet_crypto_async_frame_elt_t *fe;
  vlib_buffer_t **b;
  u32 n_elts;
  union rte_crypto_sym_ofs cofs;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec;
  u32 last_key_index = ~0;
  u16 *const enq = &ring->enq_head;
  u16 left_to_enq = frame->n_elts - ring->frames[*enq].enq_elts_head;
  u16 max_to_enq = clib_min (CRYPTODE_ENQ_MAX, left_to_enq);
  u8 is_update = 0;
  int status;

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    return;

  n_elts = max_to_enq;

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  fe = frame->elts + ring->frames[*enq].enq_elts_head;
  b = cet->b + ring->frames[*enq].enq_elts_head;

  while (n_elts)
    {
      i32 auth_offset = fe->integ_start_offset;
      i32 auth_length = fe->crypto_total_length + fe->integ_length_adj;
      i32 cipher_offset = fe->crypto_start_offset;
      i32 start_offset = clib_min (auth_offset, cipher_offset);
      i32 end_offset =
	clib_max (auth_offset + auth_length, cipher_offset + (i32) fe->crypto_total_length);
      u32 total_length = end_offset - start_offset;
      u16 n_seg = 1;

      if (n_elts > 1)
	{
	  clib_prefetch_load (&fe[1]);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	}

      if (PREDICT_FALSE (auth_length <= 0 || start_offset < 0))
	goto error_exit;

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cryptodev_key_t *key;
	  union rte_cryptodev_session_ctx sess_ctx;
	  u32 thread_index = vm->thread_index;

	  if (PREDICT_FALSE (fe->key_index >= vec_len (cmt->keys)))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, 0);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  key = vec_elt_at_index (cmt->keys, fe->key_index);

	  if (PREDICT_FALSE (key->keys == 0 || thread_index >= vec_len (key->keys) ||
			     key->keys[thread_index] == 0 || key->keys[thread_index][op_type] == 0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, 0);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;

	      key = vec_elt_at_index (cmt->keys, fe->key_index);
	    }

	  if (PREDICT_FALSE (cet->reset_sess == 0))
	    cet->reset_sess = key->keys[thread_index][op_type];

	  sess_ctx.crypto_sess = key->keys[thread_index][op_type];

	  status =
	    rte_cryptodev_configure_raw_dp_ctx (cet->cryptodev_id, cet->cryptodev_q, cet->ctx,
						RTE_CRYPTO_OP_WITH_SESSION, sess_ctx, is_update);
	  if (PREDICT_FALSE (status < 0))
	    goto error_exit;

	  last_key_index = fe->key_index;
	  is_update = 1;
	}

      cofs.raw = 0;
      cofs.ofs.auth.head = auth_offset - start_offset;
      cofs.ofs.auth.tail = total_length - cofs.ofs.auth.head - auth_length;
      cofs.ofs.cipher.head = cipher_offset - start_offset;
      cofs.ofs.cipher.tail = total_length - cofs.ofs.cipher.head - fe->crypto_total_length;

      if (cmt->iova_mode == RTE_IOVA_VA)
	{
	  vec[0].base = (void *) (b[0]->data + start_offset);
	  vec[0].iova = pointer_to_uword (vec[0].base);
	  vec[0].len = total_length;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = pointer_to_uword (fe->iv);
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = pointer_to_uword (fe->tag);
	}
      else
	{
	  vec[0].base = (void *) (b[0]->data + start_offset);
	  vec[0].iova = vlib_buffer_get_pa (vm, b[0]) + start_offset;
	  vec[0].len = total_length;
	  iv_vec.va = (void *) fe->iv;
	  iv_vec.iova = vlib_physmem_get_pa (vm, fe->iv);
	  digest_vec.va = (void *) fe->tag;
	  digest_vec.iova = vlib_physmem_get_pa (vm, fe->tag);
	}

      if (PREDICT_FALSE (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS))
	{
	  vec[0].len = b[0]->current_data + b[0]->current_length - start_offset;
	  status = cryptodev_frame_build_sgl (vm, cmt->iova_mode, vec, &n_seg, b[0],
					      total_length - vec[0].len);
	  if (status < 0)
	    goto error_exit;
	}

      status = rte_cryptodev_raw_enqueue (cet->ctx, vec, n_seg, cofs, &iv_vec, &digest_vec, 0,
					  (void *) frame);
      if (PREDICT_FALSE (status < 0))
	goto error_exit;

      ring->frames[*enq].enq_elts_head += 1;
      fe++;
      b++;
      n_elts--;
    }

  status = rte_cryptodev_raw_enqueue_done (cet->ctx, max_to_enq);
  if (PREDICT_FALSE (status < 0))
    goto error_exit;

  cet->inflight += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  return;

error_exit:
  cryptodev_mark_frame_fill_err (frame, ring->frames[*enq].frame_elts_errs_mask,
				 ring->frames[*enq].enq_elts_head, max_to_enq,
				 VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  ring->frames[*enq].enq_elts_head += max_to_enq;
  ring->frames[*enq].deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  cryptodev_reset_ctx (cet);
  return;
}

static_always_inline void
cryptodev_raw_aead_enqueue_internal (vlib_main_t *vm,
				     vnet_crypto_async_frame_t *frame,
				     cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  vnet_crypto_async_frame_elt_t *fe;
  vlib_buffer_t **b;
  u32 n_elts;
  union rte_crypto_sym_ofs cofs;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec, aad_vec;
  u32 last_key_index = ~0;
  u16 *const enq = &ring->enq_head;
  u16 left_to_enq = frame->n_elts - ring->frames[*enq].enq_elts_head;
  u16 max_to_enq = clib_min (CRYPTODE_ENQ_MAX, left_to_enq);
  u8 is_update = 0;
  int status;

  if (cet->inflight + max_to_enq > CRYPTODEV_MAX_INFLIGHT)
    {
      return;
    }

  n_elts = max_to_enq;

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  fe = frame->elts + ring->frames[*enq].enq_elts_head;
  b = cet->b + ring->frames[*enq].enq_elts_head;
  cofs.raw = 0;

  while (n_elts)
    {
      u32 aad_offset = ((cet->aad_index++) & CRYPTODEV_AAD_MASK) << 4;
      u16 n_seg = 1;

      if (n_elts > 1)
	{
	  clib_prefetch_load (&fe[1]);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	}

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cryptodev_key_t *key;
	  union rte_cryptodev_session_ctx sess_ctx;
	  u32 thread_index = vm->thread_index;

	  if (PREDICT_FALSE (fe->key_index >= vec_len (cmt->keys)))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  key = vec_elt_at_index (cmt->keys, fe->key_index);

	  if (PREDICT_FALSE (key->keys == 0 || thread_index >= vec_len (key->keys) ||
			     key->keys[thread_index] == 0 || key->keys[thread_index][op_type] == 0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;

	      key = vec_elt_at_index (cmt->keys, fe->key_index);
	    }

	  if (PREDICT_FALSE (rte_cryptodev_sym_session_opaque_data_get (
			       key->keys[thread_index][op_type]) != (u64) aad_len))
	    {
	      cryptodev_sess_del (vm, fe->key_index);
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;

	      key = vec_elt_at_index (cmt->keys, fe->key_index);
	    }

	  /* Borrow a created session to reset session ctx, based on a valid
	   * assumption that the session reset won't happen until first valid
	   * packet is processed */

	  if (PREDICT_FALSE (cet->reset_sess == 0))
	    cet->reset_sess = key->keys[thread_index][op_type];

	  sess_ctx.crypto_sess = key->keys[thread_index][op_type];

	  status = rte_cryptodev_configure_raw_dp_ctx (
	    cet->cryptodev_id, cet->cryptodev_q, cet->ctx,
	    RTE_CRYPTO_OP_WITH_SESSION, sess_ctx, is_update);
	  if (PREDICT_FALSE (status < 0))
	    goto error_exit;

	  last_key_index = fe->key_index;
	  is_update = 1;
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
      else if (aad_len != 0)
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

      ring->frames[*enq].enq_elts_head += 1;
      fe++;
      b++;
      n_elts--;
    }

  status = rte_cryptodev_raw_enqueue_done (cet->ctx, max_to_enq);
  if (PREDICT_FALSE (status < 0))
    goto error_exit;

  cet->inflight += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  return;

error_exit:
  cryptodev_mark_frame_fill_err (frame,
				 ring->frames[*enq].frame_elts_errs_mask,
				 ring->frames[*enq].enq_elts_head, max_to_enq,
				 VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
  ring->frames[*enq].enq_elts_head += max_to_enq;
  ring->frames[*enq].deq_elts_tail += max_to_enq;
  cryptodev_cache_ring_update_enq_head (ring, frame);
  cryptodev_reset_ctx (cet);
  return;
}

static_always_inline void
cryptodev_post_dequeue (void *frame, u32 index, u8 is_op_success)
{
  vnet_crypto_async_frame_t *f = (vnet_crypto_async_frame_t *) frame;

  f->elts[index].status = is_op_success ? VNET_CRYPTO_OP_STATUS_COMPLETED :
					  VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
}

static_always_inline u8
cryptodev_raw_dequeue_internal (vlib_main_t *vm,
				clib_thread_index_t *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_t *frame;
  cryptodev_cache_ring_t *ring = &cet->cache_ring;
  u16 *const deq = &ring->deq_tail;
  u32 n_success;
  u16 n_deq, i, left_to_deq;
  u16 max_to_deq = 0;
  u16 inflight = cet->inflight;
  u8 dequeue_more = 0;
  int dequeue_status;

  left_to_deq = ring->frames[*deq].n_elts - ring->frames[*deq].deq_elts_tail;
  max_to_deq = clib_min (left_to_deq, CRYPTODE_DEQ_MAX);

  /* deq field can be used to track frame that is currently dequeued */
  /* based on thatthe amount of elements to deq for the frame can be specified
   */

  n_deq = rte_cryptodev_raw_dequeue_burst (
    cet->ctx, NULL, max_to_deq, cryptodev_post_dequeue, (void **) &frame, 0,
    &n_success, &dequeue_status);

  if (n_deq == 0)
    return dequeue_more;

  inflight -= n_deq;
  if (PREDICT_FALSE (n_success < n_deq))
    {
      u16 idx = ring->frames[*deq].deq_elts_tail;

      for (i = 0; i < n_deq; i++)
	{
	  if (frame->elts[idx + i].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    ring->frames[*deq].frame_elts_errs_mask |= 1 << (idx + i);
	}
    }
  ring->frames[*deq].deq_elts_tail += n_deq;

  if (cryptodev_cache_ring_update_deq_tail (ring, deq))
    {
      u32 fr_processed =
	(CRYPTODEV_CACHE_QUEUE_SIZE - ring->tail + ring->deq_tail) &
	CRYPTODEV_CACHE_QUEUE_MASK;

      *enqueue_thread_idx = frame->enqueue_thread_index;
      dequeue_more = (fr_processed < CRYPTODEV_MAX_PROCESED_IN_CACHE_QUEUE);
    }

  int res =
    rte_cryptodev_raw_dequeue_done (cet->ctx, cet->inflight - inflight);
  ERROR_ASSERT (res == 0);
  cet->inflight = inflight;
  return dequeue_more;
}

static_always_inline void
cryptodev_enqueue_frame_to_qat (vlib_main_t *vm,
				cryptodev_cache_ring_elt_t *ring_elt)
{
  cryptodev_op_type_t op_type = (cryptodev_op_type_t) ring_elt->op_type;
  if (crypto_main.algs[vnet_crypto_get_op_data (ring_elt->f->op)->alg].alg_type ==
      VNET_CRYPTO_ALG_T_COMBINED)
    cryptodev_raw_combined_enqueue_internal (vm, ring_elt->f, op_type);
  else
    cryptodev_raw_aead_enqueue_internal (vm, ring_elt->f, op_type, ring_elt->aad_len);
}

static_always_inline vnet_crypto_async_frame_t *
cryptodev_raw_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
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
    dequeue_more = cryptodev_raw_dequeue_internal (vm, enqueue_thread_idx);

  if (PREDICT_TRUE (ring->frames[ring->enq_head].f != 0))
    cryptodev_enqueue_frame_to_qat (vm, &ring->frames[ring->enq_head]);

  if (PREDICT_TRUE (ring_elt->f != 0) &&
      (ring_elt->n_elts == ring_elt->deq_elts_tail))
    {
      *nb_elts_processed = ring_elt->n_elts;
      vlib_node_set_interrupt_pending (
	vlib_get_main_by_index (vm->thread_index), cm->crypto_node_index);
      ret_frame = cryptodev_cache_ring_pop (ring);
    }

  return ret_frame;
}

static_always_inline int
cryptodev_raw_enq_aead_aad_0_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT, 0);
}

static_always_inline int
cryptodev_raw_enq_aead_aad_8_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT, 8);
}
static_always_inline int
cryptodev_raw_enq_aead_aad_12_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT, 12);
}

static_always_inline int
cryptodev_raw_enq_aead_aad_0_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT, 0);
}

static_always_inline int
cryptodev_raw_enq_aead_aad_8_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT, 8);
}
static_always_inline int
cryptodev_raw_enq_aead_aad_12_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT, 12);
}

static_always_inline int
cryptodev_raw_enq_combined_enc (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_ENCRYPT, 0);
}

static_always_inline int
cryptodev_raw_enq_combined_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return cryptodev_raw_aead_enqueue (vm, frame, CRYPTODEV_OP_TYPE_DECRYPT, 0);
}

clib_error_t *
cryptodev_register_raw_hdl (vlib_main_t *vm, u32 eidx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  cryptodev_inst_t *cinst;
  struct rte_cryptodev_info info;
  struct rte_cryptodev_sym_capability_idx cap_aead_idx;
  struct rte_cryptodev_sym_capability_idx cap_auth_idx;
  struct rte_cryptodev_sym_capability_idx cap_cipher_idx;
  u32 support_raw_api = 1, max_ctx_size = 0;
  clib_error_t *error = 0;
  u8 ref_cnt = 0;

  vec_foreach (cinst, cmt->cryptodev_inst)
    {
      u32 ctx_size;
      rte_cryptodev_info_get (cinst->dev_id, &info);
      if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP))
	{
	  support_raw_api = 0;
	  break;
	}

      ctx_size = rte_cryptodev_get_raw_dp_ctx_size (cinst->dev_id);
      max_ctx_size = clib_max (ctx_size, max_ctx_size);
    }

  if (!support_raw_api)
    return cryptodev_register_cop_hdl (vm, eidx);

  vec_foreach (cet, cmt->per_thread_data)
    {
      u32 thread_id = cet - cmt->per_thread_data;
      u32 numa = vlib_get_main_by_index (thread_id)->numa_node;
      u8 *name = format (0, "cache_cache_ring_%u_%u", numa, thread_id);

      cet->aad_buf = rte_zmalloc_socket (
	0, CRYPTODEV_NB_CRYPTO_OPS * CRYPTODEV_MAX_AAD_SIZE,
	CLIB_CACHE_LINE_BYTES, numa);
      if (cet->aad_buf == 0)
	{
	  error = clib_error_return (0, "Failed to alloc aad buf");
	  goto err_handling;
	}
      cet->aad_phy_addr = rte_malloc_virt2iova (cet->aad_buf);

      cet->ctx =
	rte_zmalloc_socket (0, max_ctx_size, CLIB_CACHE_LINE_BYTES, numa);
      if (!cet->ctx)
	{
	  error = clib_error_return (0, "Failed to alloc raw dp ctx");
	  goto err_handling;
	}
      vec_free (name);
    }

#define _(a, b, c, d, e, f, g)                                                                     \
  {                                                                                                \
    u8 supported;                                                                                  \
    cap_aead_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;                                                 \
    cap_aead_idx.algo.aead = RTE_CRYPTO_##b##_##c;                                                 \
    supported = cryptodev_check_cap_support (&cap_aead_idx, g, e, f);                              \
    if (supported)                                                                                 \
      {                                                                                            \
	log_debug ("cryptodev raw register alg=%s tag=%u aad=%u", #a, e, f);                       \
	vnet_crypto_register_enqueue_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC,                  \
					      cryptodev_raw_enq_aead_aad_##f##_enc);               \
	vnet_crypto_register_enqueue_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC,                  \
					      cryptodev_raw_enq_aead_aad_##f##_dec);               \
	ref_cnt++;                                                                                 \
      }                                                                                            \
    else                                                                                           \
      log_debug ("cryptodev raw skip alg=%s tag=%u aad=%u", #a, e, f);                             \
  }
  foreach_vnet_aead_crypto_conversion
#undef _

#define _(a, b, c, d, e, f)                                                                        \
  {                                                                                                \
    u8 chain_supported;                                                                            \
    u8 cipher_supported;                                                                           \
    u8 auth_supported;                                                                             \
    cap_cipher_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;                                             \
    cap_cipher_idx.algo.cipher = RTE_CRYPTO_CIPHER_##b;                                            \
    cap_auth_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;                                                 \
    cap_auth_idx.algo.auth = RTE_CRYPTO_AUTH_##d;                                                  \
    chain_supported = cryptodev_check_feature_support (RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING);   \
    cipher_supported = cryptodev_check_cap_support (&cap_cipher_idx, f, 0, 0);                     \
    auth_supported = cryptodev_check_cap_support (&cap_auth_idx, 0, e, 0);                         \
    if (chain_supported && cipher_supported && auth_supported)                                     \
      {                                                                                            \
	log_debug ("cryptodev raw register alg=%s tag=%u", #a, e);                                 \
	vnet_crypto_register_enqueue_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC,                  \
					      cryptodev_raw_enq_combined_enc);                     \
	vnet_crypto_register_enqueue_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC,                  \
					      cryptodev_raw_enq_combined_dec);                     \
	ref_cnt++;                                                                                 \
      }                                                                                            \
    else                                                                                           \
      log_debug ("cryptodev raw skip alg=%s tag=%u chain=%s cipher=%s auth=%s", #a, e,             \
		 chain_supported ? "yes" : "no", cipher_supported ? "yes" : "no",                  \
		 auth_supported ? "yes" : "no");                                                   \
  }
    foreach_vnet_combined_crypto_conversion
#undef _

    if (ref_cnt) vnet_crypto_register_dequeue_handler (vm, eidx, cryptodev_raw_dequeue);

  cmt->is_raw_api = 1;

  return 0;

err_handling:
  return error;
}
