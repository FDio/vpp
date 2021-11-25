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
#include <rte_malloc.h>
#include <rte_config.h>

#include "cryptodev.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

static_always_inline u64
compute_ofs_linked_alg (vnet_crypto_async_frame_elt_t *fe, i16 *min_ofs,
			u32 *max_end)
{
  union rte_crypto_sym_ofs ofs;
  u32 crypto_end = fe->crypto_start_offset + fe->crypto_total_length;
  u32 integ_end =
    fe->integ_start_offset + fe->crypto_total_length + fe->integ_length_adj;

  *min_ofs = clib_min (fe->crypto_start_offset, fe->integ_start_offset);
  *max_end = clib_max (crypto_end, integ_end);

  ofs.ofs.cipher.head = fe->crypto_start_offset - *min_ofs;
  ofs.ofs.cipher.tail = *max_end - crypto_end;
  ofs.ofs.auth.head = fe->integ_start_offset - *min_ofs;
  ofs.ofs.auth.tail = *max_end - integ_end;

  return ofs.raw;
}

static_always_inline int
cryptodev_frame_build_sgl (vlib_main_t *vm, enum rte_iova_mode iova_mode,
			   struct rte_crypto_vec *data_vec, u16 *n_seg,
			   vlib_buffer_t *b, u32 size)
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

static_always_inline void
cryptodev_reset_ctx (cryptodev_engine_thread_t *cet)
{
  union rte_cryptodev_session_ctx sess_ctx;

  ASSERT (cet->reset_sess != 0);

  sess_ctx.crypto_sess = cet->reset_sess;

  rte_cryptodev_configure_raw_dp_ctx (cet->cryptodev_id, cet->cryptodev_q,
				      cet->ctx, RTE_CRYPTO_OP_WITH_SESSION,
				      sess_ctx, 0);
}

static_always_inline int
cryptodev_frame_linked_algs_enqueue (vlib_main_t *vm,
				     vnet_crypto_async_frame_t *frame,
				     cryptodev_op_type_t op_type)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  vlib_buffer_t **b;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec;
  u32 n_elts;
  u32 last_key_index = ~0;
  i16 min_ofs;
  u32 max_end;
  u8 is_update = 0;
  int status;

  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_MAX_INFLIGHT - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  b = cet->b;
  fe = frame->elts;

  while (n_elts)
    {
      union rte_crypto_sym_ofs cofs;
      u16 n_seg = 1;

      if (n_elts > 2)
	{
	  clib_prefetch_load (&fe[1]);
	  clib_prefetch_load (&fe[2]);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	  vlib_prefetch_buffer_header (b[2], LOAD);
	}

      if (PREDICT_FALSE (last_key_index != fe->key_index))
	{
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);
	  union rte_cryptodev_session_ctx sess_ctx;

	  if (PREDICT_FALSE (key->keys[vm->numa_node][op_type] == 0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, 0);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  /* Borrow a created session to reset session ctx, based on a valid
	   * assumption that the session reset won't happen until first valid
	   * packet is processed */
	  if (PREDICT_FALSE (cet->reset_sess == 0))
	    cet->reset_sess = key->keys[vm->numa_node][op_type];

	  sess_ctx.crypto_sess = key->keys[vm->numa_node][op_type];

	  status = rte_cryptodev_configure_raw_dp_ctx (
	    cet->cryptodev_id, cet->cryptodev_q, cet->ctx,
	    RTE_CRYPTO_OP_WITH_SESSION, sess_ctx, is_update);
	  if (PREDICT_FALSE (status < 0))
	    goto error_exit;

	  last_key_index = fe->key_index;
	  is_update = 1;
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
cryptodev_raw_aead_enqueue (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
			    cryptodev_op_type_t op_type, u8 aad_len)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = cmt->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_elt_t *fe;
  vlib_buffer_t **b;
  u32 n_elts;
  union rte_crypto_sym_ofs cofs;
  struct rte_crypto_vec vec[CRYPTODEV_MAX_N_SGL];
  struct rte_crypto_va_iova_ptr iv_vec, digest_vec, aad_vec;
  u32 last_key_index = ~0;
  u8 is_update = 0;
  int status;

  n_elts = frame->n_elts;

  if (PREDICT_FALSE (CRYPTODEV_MAX_INFLIGHT - cet->inflight < n_elts))
    {
      cryptodev_mark_frame_err_status (frame,
				       VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  vlib_get_buffers (vm, frame->buffer_indices, cet->b, frame->n_elts);

  fe = frame->elts;
  b = cet->b;
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
	  cryptodev_key_t *key = vec_elt_at_index (cmt->keys, fe->key_index);
	  union rte_cryptodev_session_ctx sess_ctx;

	  if (PREDICT_FALSE (key->keys[vm->numa_node][op_type] == 0))
	    {
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  if (PREDICT_FALSE (
		(u8) key->keys[vm->numa_node][op_type]->opaque_data !=
		aad_len))
	    {
	      cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_DEL,
				      fe->key_index, aad_len);
	      status = cryptodev_session_create (vm, fe->key_index, aad_len);
	      if (PREDICT_FALSE (status < 0))
		goto error_exit;
	    }

	  /* Borrow a created session to reset session ctx, based on a valid
	   * assumption that the session reset won't happen until first valid
	   * packet is processed */

	  if (PREDICT_FALSE (cet->reset_sess == 0))
	    cet->reset_sess = key->keys[vm->numa_node][op_type];

	  sess_ctx.crypto_sess = key->keys[vm->numa_node][op_type];

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

static_always_inline u32
cryptodev_get_frame_n_elts (void *frame)
{
  vnet_crypto_async_frame_t *f = (vnet_crypto_async_frame_t *) frame;
  return f->n_elts;
}

static_always_inline void
cryptodev_post_dequeue (void *frame, u32 index, u8 is_op_success)
{
  vnet_crypto_async_frame_t *f = (vnet_crypto_async_frame_t *) frame;

  f->elts[index].status = is_op_success ? VNET_CRYPTO_OP_STATUS_COMPLETED :
					  VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
}

#define GET_RING_OBJ(r, pos, f)                                               \
  do                                                                          \
    {                                                                         \
      vnet_crypto_async_frame_t **ring = (void *) &r[1];                      \
      f = ring[(r->cons.head + pos) & r->mask];                               \
    }                                                                         \
  while (0)

static_always_inline vnet_crypto_async_frame_t *
cryptodev_raw_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
		       u32 *enqueue_thread_idx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vnet_crypto_main_t *cm = &crypto_main;
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
	      clib_prefetch_load (f1);
	      clib_prefetch_load (f2);
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

  if (cm->dispatch_mode == VNET_CRYPTO_ASYNC_DISPATCH_INTERRUPT &&
      inflight > 0)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (vm->thread_index),
				     cm->crypto_node_index);

  /* no point to dequeue further */
  if (!inflight || no_job_to_deq || !n_room_left)
    goto end_deq;

#if RTE_VERSION >= RTE_VERSION_NUM(21, 5, 0, 0)
  n_deq = rte_cryptodev_raw_dequeue_burst (
    cet->ctx, cryptodev_get_frame_n_elts, 0, cryptodev_post_dequeue,
    (void **) &frame, 0, &n_success, &dequeue_status);
#else
  n_deq = rte_cryptodev_raw_dequeue_burst (
    cet->ctx, cryptodev_get_frame_n_elts, cryptodev_post_dequeue,
    (void **) &frame, 0, &n_success, &dequeue_status);
#endif

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
		       VNET_CRYPTO_FRAME_STATE_SUCCESS :
		       VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
      frame_ret = frame;
    }

  /* see if we can dequeue more */
  while (inflight && n_room_left && !no_job_to_deq)
    {
#if RTE_VERSION >= RTE_VERSION_NUM(21, 5, 0, 0)
      n_deq = rte_cryptodev_raw_dequeue_burst (
	cet->ctx, cryptodev_get_frame_n_elts, 0, cryptodev_post_dequeue,
	(void **) &frame, 0, &n_success, &dequeue_status);
#else
      n_deq = rte_cryptodev_raw_dequeue_burst (
	cet->ctx, cryptodev_get_frame_n_elts, cryptodev_post_dequeue,
	(void **) &frame, 0, &n_success, &dequeue_status);
#endif
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
cryptodev_raw_enq_linked_alg_enc (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_ENCRYPT);
}

static_always_inline int
cryptodev_raw_enq_linked_alg_dec (vlib_main_t *vm,
				  vnet_crypto_async_frame_t *frame)
{
  return cryptodev_frame_linked_algs_enqueue (vm, frame,
					      CRYPTODEV_OP_TYPE_DECRYPT);
}

clib_error_t *
cryptodev_register_raw_hdl (vlib_main_t *vm, u32 eidx)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  cryptodev_inst_t *cinst;
  struct rte_cryptodev_info info;
  struct rte_cryptodev_sym_capability_idx cap_auth_idx;
  struct rte_cryptodev_sym_capability_idx cap_cipher_idx;
  struct rte_cryptodev_sym_capability_idx cap_aead_idx;
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
      u8 *name = format (0, "cache_frame_ring_%u_%u", numa, thread_id);

      cet->cached_frame =
	rte_ring_create ((char *) name, CRYPTODEV_DEQ_CACHE_SZ, numa,
			 RING_F_SC_DEQ | RING_F_SP_ENQ);

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

      if (cet->cached_frame == 0)
	{
	  error = clib_error_return (0, "Failed to alloc frame ring %s", name);
	  goto err_handling;
	}

      vec_free (name);
    }

#define _(a, b, c, d, e, f, g)                                                \
  cap_aead_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;                              \
  cap_aead_idx.algo.aead = RTE_CRYPTO_##b##_##c;                              \
  if (cryptodev_check_cap_support (&cap_aead_idx, g, e, f))                   \
    {                                                                         \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_ENC,                 \
	cryptodev_raw_enq_aead_aad_##f##_enc);                                \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_TAG##e##_AAD##f##_DEC,                 \
	cryptodev_raw_enq_aead_aad_##f##_dec);                                \
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
	cryptodev_raw_enq_linked_alg_enc);                                    \
      vnet_crypto_register_enqueue_handler (                                  \
	vm, eidx, VNET_CRYPTO_OP_##a##_##d##_TAG##e##_DEC,                    \
	cryptodev_raw_enq_linked_alg_dec);                                    \
      ref_cnt++;                                                              \
    }
    foreach_cryptodev_link_async_alg
#undef _

    if (ref_cnt)
      vnet_crypto_register_dequeue_handler (vm, eidx, cryptodev_raw_dequeue);

  cmt->is_raw_api = 1;

  return 0;

err_handling:
  vec_foreach (cet, cmt->per_thread_data)
    {
      if (cet->cached_frame)
	rte_ring_free (cet->cached_frame);
    }

  return error;
}
