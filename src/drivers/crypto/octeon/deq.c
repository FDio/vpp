/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

VNET_DEV_NODE_FN (oct_crypto_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_crypto_engine_t *e = vnet_dev_crypto_node_engine (node);
  vnet_dev_crypto_queue_t *cq = vnet_dev_crypto_get_thread_queue (e, vm->thread_index);
  vnet_crypto_op_status_t status[VLIB_FRAME_SIZE];
  u16 frame_head, frame_tail, deq_next, deq_left, elt_head, mask;
  u32 n_completed = 0;
  oct_crypto_meta_t *meta;
  oct_crypto_queue_t *q;

  if (cq == 0)
    return 0;

  q = vnet_dev_get_crypto_queue_data (cq);
  meta = q->meta;
  mask = q->n_desc - 1;
  frame_head = q->frame_head;
  frame_tail = q->frame_tail;
  deq_next = q->deq_next;
  deq_left = q->deq_left;
  elt_head = q->elt_head;

  /* results are released only when the whole frame is done, so they can be traced */
  for (; frame_head != frame_tail; frame_head++)
    {
      vlib_frame_t *f = q->frames[frame_head & mask];
      u32 *bi = vlib_frame_vector_args (f);
      u16 n_elts = f->n_vectors;
      u8 has_fail = 0;

      if (deq_left == 0)
	deq_left = n_elts;

      for (; deq_left; deq_left--, deq_next++)
	{
	  cpt_res_t r = {
	    .u64[0] = __atomic_load_n (&meta[deq_next & mask].res.u64[0], __ATOMIC_ACQUIRE),
	  };

	  if (PREDICT_FALSE (r.cn10k.compcode == CPT_COMP_NOT_DONE))
	    break;
	}

      if (deq_left)
	break;

      /* dequeue nodes get no frames, so the node trace flag is never set */
      if (PREDICT_FALSE (vm->trace_main.trace_enable))
	for (u16 i = 0; i < n_elts; i++)
	  {
	    vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
	    u16 slot = (u16) (elt_head + i) & mask;
	    oct_crypto_deq_trace_t *t;

	    if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	      continue;

	    t = vlib_add_trace (vm, node, b, sizeof (*t));
	    t->lf_id = q->lf->lf_id;
	    t->slot = slot;
	    t->res = meta[slot].res;
	  }

      for (u16 i = 0; i < n_elts; i++)
	{
	  cpt_res_t *rp = &meta[(u16) (elt_head + i) & mask].res;
	  cpt_res_t r = { .u64[0] = rp->u64[0] };
	  u32 hw_good = (1 << r.cn10k.compcode) & CPT_COMP_HWGOOD_MASK;

	  rp->u64[0] = 0;
	  status[i] = VNET_CRYPTO_OP_STATUS_COMPLETED;

	  if (PREDICT_TRUE (hw_good && r.cn10k.uc_compcode == 0))
	    continue;

	  has_fail = 1;
	  if (hw_good && r.cn10k.uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
	    {
	      status[i] = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      cq->deq_auth_fail++;
	    }
	  else
	    {
	      status[i] = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	      cq->deq_err++;
	    }
	}

      elt_head = deq_next;
      cq->deq_req += n_elts;
      n_completed += n_elts;
      vnet_dev_crypto_frame_done (vm, node, f, has_fail ? status : 0);
    }

  q->frame_head = frame_head;
  q->deq_next = deq_next;
  q->deq_left = deq_left;
  q->elt_head = elt_head;

  if (frame_head != frame_tail)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_completed;
}
