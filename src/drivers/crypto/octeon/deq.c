/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

/* results are released only when the whole frame is done, so they can be traced */
static_always_inline u32
oct_crypto_dequeue_frame (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_crypto_queue_t *cq,
			  oct_crypto_queue_t *q)
{
  vnet_crypto_op_status_t status[VLIB_FRAME_SIZE];
  u16 deq_next, deq_left, elt_head, mask = q->n_desc - 1, n_elts;
  oct_crypto_meta_t *meta = q->meta;
  vlib_frame_t *frame;
  u8 has_fail = 0;
  u32 *bi;

  frame = q->frames[q->frame_head & mask];
  bi = vlib_frame_vector_args (frame);
  n_elts = frame->n_vectors;
  deq_next = q->deq_next;
  deq_left = q->deq_left ? q->deq_left : n_elts;

  for (; deq_left; deq_left--, deq_next++)
    {
      cpt_res_t r = {
	.u64[0] = __atomic_load_n (&meta[deq_next & mask].res.u64[0], __ATOMIC_ACQUIRE),
      };

      if (PREDICT_FALSE (r.cn10k.compcode == CPT_COMP_NOT_DONE))
	{
	  q->deq_next = deq_next;
	  q->deq_left = deq_left;
	  return 0;
	}
    }

  elt_head = q->elt_head;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
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

  q->elt_head = q->deq_next = deq_next;
  q->deq_left = 0;
  q->frame_head++;
  cq->deq_req += n_elts;

  vnet_dev_crypto_frame_done (vm, node, frame, has_fail ? status : 0);
  return n_elts;
}

static_always_inline u32
oct_crypto_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_crypto_queue_t *cq)
{
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  u32 n_completed = 0, n;

  while (q->frame_head != q->frame_tail && (n = oct_crypto_dequeue_frame (vm, node, cq, q)))
    n_completed += n;

  return n_completed;
}

VNET_DEV_NODE_FN (oct_crypto_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vnet_dev_crypto_deq_node_inline (vm, node, oct_crypto_dequeue);
}
