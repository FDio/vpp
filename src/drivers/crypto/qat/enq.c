/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <qat.h>

static_always_inline u64
qat_dma_addr (vlib_main_t *vm, qat_queue_t *q, void *p)
{
  return q->va_dma ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static_always_inline int
qat_build_sgl (vlib_main_t *vm, qat_queue_t *q, qat_sgl_t *sgl, vlib_buffer_t *b, i32 off, u32 len)
{
  u32 n = 0;

  while (off >= b->current_length && (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      off -= b->current_length;
      b = vlib_get_buffer (vm, b->next_buffer);
    }

  while (len)
    {
      u32 seg_len = clib_min (b->current_length - off, len);

      if (n == QAT_SGL_MAX_BUFS)
	return -1;

      if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	{
	  /* ESN high bits follow the last buffer, not counted in its length */
	  if (len > seg_len && vlib_buffer_space_left_at_end (vm, b) < len - seg_len)
	    return -1;
	  seg_len = len;
	}

      sgl->bufs[n++] = (qat_flat_buf_t) {
	.len = seg_len,
	.addr = qat_dma_addr (vm, q, vlib_buffer_get_current (b) + off),
      };
      len -= seg_len;
      off = 0;

      if (len)
	b = vlib_get_buffer (vm, b->next_buffer);
    }

  sgl->num_bufs = n;
  return 0;
}

static_always_inline int
qat_build_req (vlib_main_t *vm, qat_queue_t *q, u32 slot, const qat_alg_t *a, const qat_key_t *k,
	       vlib_buffer_t *b, uword opaque, u8 is_enc, qat_alg_type_t type)
{
  qat_fw_la_req_t *req = q->tx_ring + slot;
  vnet_crypto_op_type_t t = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
  vnet_crypto_buffer_metadata_t *md = vnet_crypto_buffer_get_metadata (b);
  u8 *iv = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off);
  u8 *icv = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
  i32 start = md->cipher_data_start_off;
  u32 len = md->cipher_data_len;

  if (type != QAT_ALG_TYPE_AEAD && a->cipher_mode == QAT_HW_CIPHER_CBC_MODE && len % 16)
    return -1;

  *req = k->tmpl->req[t];
  req->cd_pars.content_desc_addr = k->cd_dma + t * QAT_CD_SIZE;
  req->mid.opaque = opaque;

  if (type == QAT_ALG_TYPE_AEAD)
    {
      req->ucs.cipher_length = len;
      clib_memcpy_fast (req->ucs.cipher_iv, iv, 12);
      if (a->aad_len)
	req->ucs.spc_aad_addr =
	  qat_dma_addr (vm, q, vnet_crypto_buffer_metadata_get_ptr (vm, b, md->aad_off));
      req->ucs.spc_auth_res_addr = qat_dma_addr (vm, q, icv);
    }
  else if (type == QAT_ALG_TYPE_CIPHER)
    {
      req->cipher_auth.cipher_length = len;
      clib_memcpy_fast (req->cipher_auth.cipher_iv, iv, 16);
    }
  else
    {
      i32 auth_start = md->auth_data_start_off;
      i32 auth_end = auth_start + md->auth_data_len;

      start = clib_min (start, auth_start);
      len = clib_max (md->cipher_data_start_off + md->cipher_data_len, auth_end) - start;
      req->cipher_auth.cipher_offset = md->cipher_data_start_off - start;
      req->cipher_auth.cipher_length = md->cipher_data_len;
      req->cipher_auth.auth_off = auth_start - start;
      req->cipher_auth.auth_len = md->auth_data_len;
      req->cipher_auth.auth_res_addr = qat_dma_addr (vm, q, icv);
      clib_memcpy_fast (req->cipher_auth.cipher_iv, iv, 16);

      if (is_enc == 0 && md->is_hmac_check == 0)
	{
	  req->hdr.la_flags.ret_auth_res = 1;
	  req->hdr.la_flags.cmp_auth_res = 0;
	}
    }

  if (PREDICT_FALSE (md->is_chained_buffers))
    {
      if (qat_build_sgl (vm, q, q->sgl + slot, b, start, len))
	return -1;
      req->hdr.ptr_type_sgl = 1;
      req->mid.src_data_addr = req->mid.dst_data_addr = q->sgl_dma + slot * sizeof (qat_sgl_t);
    }
  else
    req->mid.src_data_addr = req->mid.dst_data_addr =
      qat_dma_addr (vm, q, vlib_buffer_get_current (b) + start);

  req->mid.src_length = req->mid.dst_length = len;
  return 0;
}

/* builds the request of one element at ring slot tail, returns 1 if it was submitted */
static_always_inline u32
qat_enq_one (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq, qat_queue_t *q, qat_frame_entry_t *fe,
	     const qat_alg_t *a, vnet_crypto_ctx_t *ctx, vlib_buffer_t *b, u32 index, u32 tail,
	     u64 *n_bytes, u8 is_enc, qat_alg_type_t type)
{
  qat_key_t *k = (qat_key_t *) vnet_crypto_get_async_key_data (ctx);
  qat_session_cd_t *cd = __atomic_load_n (&k->cd, __ATOMIC_ACQUIRE);
  vnet_crypto_buffer_metadata_t *md = vnet_crypto_buffer_get_metadata (b);
  uword opaque = ((fe - q->fifo) << QAT_OPAQUE_ELT_BITS) | index;

  if (PREDICT_FALSE (cd == 0 ||
		     qat_build_req (vm, q, tail & q->mask, a, k, b, opaque, is_enc, type)))
    {
      qat_frame_set_status (fe, index, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      cq->enq_err++;
      return 0;
    }

  *n_bytes += clib_max (md->cipher_data_len, md->auth_data_len);
  return 1;
}

static_always_inline uword
qat_enq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f, u8 is_enc,
		     qat_alg_type_t type)
{
  vnet_dev_crypto_engine_t *e = vnet_dev_crypto_node_engine (node);
  vnet_dev_crypto_queue_t *cq = vnet_dev_crypto_get_least_loaded_queue (e, vm->thread_index);
  vnet_crypto_frame_scalar_data_t *sd = vlib_frame_scalar_args (f);
  vnet_crypto_ctx_t **ctxs = vlib_frame_aux_args (f);
  const qat_alg_t *a = qat_algs + sd->alg;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4], **b = bufs;
  u32 n_elts = f->n_vectors, n_sub, i;
  qat_frame_entry_t *fe;
  u64 n_bytes = 0;
  u32 tail;
  qat_queue_t *q;

  if (PREDICT_FALSE (cq == 0))
    return vnet_dev_crypto_frame_no_queue (vm, node, f);

  q = vnet_dev_get_crypto_queue_data (cq);
  if (PREDICT_FALSE (q->n_enq - q->n_deq + n_elts > q->max_inflight))
    {
      cq->enq_full += n_elts;
      return vnet_crypto_frame_to_consumer (vm, node, f, VNET_CRYPTO_OP_STATUS_FAIL_QUEUE_FULL);
    }

  vlib_get_buffers (vm, vlib_frame_vector_args (f), bufs, n_elts);
  b[n_elts] = b[n_elts + 1] = b[n_elts + 2] = b[n_elts + 3] = b[n_elts - 1];
  fe = q->fifo + (q->fifo_tail & q->mask);
  *fe = (qat_frame_entry_t) { .frame = f };
  tail = q->tx_tail;

  clib_prefetch_load (b[0]);
  clib_prefetch_load (b[1]);
  clib_prefetch_load (b[2]);
  clib_prefetch_load (b[3]);
  clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[0]));
  clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[1]));
  clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[2]));
  clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[3]));

  for (i = 0; i + 4 <= n_elts; i += 4, b += 4)
    {
      clib_prefetch_load (b[4]);
      clib_prefetch_load (b[5]);
      clib_prefetch_load (b[6]);
      clib_prefetch_load (b[7]);
      clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[4]));
      clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[5]));
      clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[6]));
      clib_prefetch_load (vnet_crypto_buffer_get_metadata (b[7]));

      tail += qat_enq_one (vm, cq, q, fe, a, ctxs[i], b[0], i, tail, &n_bytes, is_enc, type);
      tail +=
	qat_enq_one (vm, cq, q, fe, a, ctxs[i + 1], b[1], i + 1, tail, &n_bytes, is_enc, type);
      tail +=
	qat_enq_one (vm, cq, q, fe, a, ctxs[i + 2], b[2], i + 2, tail, &n_bytes, is_enc, type);
      tail +=
	qat_enq_one (vm, cq, q, fe, a, ctxs[i + 3], b[3], i + 3, tail, &n_bytes, is_enc, type);
    }

  for (; i < n_elts; i++, b++)
    tail += qat_enq_one (vm, cq, q, fe, a, ctxs[i], b[0], i, tail, &n_bytes, is_enc, type);

  n_sub = tail - q->tx_tail;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    for (u32 i = 0, slot = q->tx_tail; i < n_elts; i++)
      {
	u8 submitted = fe->status == 0 || fe->status[i] == VNET_CRYPTO_OP_STATUS_COMPLETED;
	qat_enq_trace_t *t;

	if (bufs[i]->flags & VLIB_BUFFER_IS_TRACED)
	  {
	    t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	    t->bank = q->rp.bank;
	    t->slot = submitted ? slot & q->mask : ~0;
	    if (submitted)
	      t->req = q->tx_ring[slot & q->mask];
	  }
	slot += submitted;
      }

  if (PREDICT_FALSE (n_sub == 0))
    {
      qat_frame_done (vm, node, fe);
      return n_elts;
    }

  fe->n_pending = n_sub;
  q->fifo_tail++;
  q->tx_tail = tail;
  q->n_enq += n_sub;
  cq->enq_req += n_sub;
  cq->enq_bytes += n_bytes;
  __atomic_store_n (q->tx_tail_csr, (tail & q->mask) * QAT_TX_MSG_SIZE, __ATOMIC_RELEASE);
  vlib_node_set_interrupt_pending (vm, e->deq_node_index);
  return n_elts;
}

#define _(n, s, is_enc, type)                                                                      \
  VNET_DEV_NODE_FN (qat_enq_##n##_node)                                                            \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)                             \
  {                                                                                                \
    return qat_enq_node_inline (vm, node, frame, is_enc, type);                                    \
  }
foreach_qat_enqueue_node
#undef _
