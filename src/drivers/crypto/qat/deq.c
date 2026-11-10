/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qat.h>

/* responses come back in request order */
static_always_inline u32
qat_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_crypto_queue_t *cq)
{
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  u32 head = q->rx_head, n_done = 0;

  while (q->fifo_head != q->fifo_tail)
    {
      u32 fe_index = q->fifo_head & q->mask;
      qat_frame_entry_t *fe = q->fifo + fe_index;
      vnet_crypto_deq_scalar_data_t *sd = vlib_frame_scalar_args (fe->frame);
      qat_fw_resp_t *r = q->rx_ring + (head & q->mask);
      qat_fw_resp_status_t st;
      u32 index;

      if (__atomic_load_n ((u32 *) r, __ATOMIC_ACQUIRE) == QAT_RING_EMPTY_SIG)
	break;

      ASSERT ((r->opaque >> QAT_OPAQUE_ELT_BITS) == fe_index);
      index = r->opaque & pow2_mask (QAT_OPAQUE_ELT_BITS);
      st = r->status;

      if (PREDICT_FALSE (st.crypto_error || st.invalid_param || st.unsupported_request))
	{
	  if (st.crypto_error && sd->op_type == VNET_CRYPTO_OP_TYPE_DECRYPT &&
	      qat_algs[sd->alg].type != QAT_ALG_TYPE_CIPHER)
	    {
	      qat_frame_set_status (fe, index, VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC);
	      cq->deq_auth_fail++;
	    }
	  else
	    {
	      qat_frame_set_status (fe, index, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      cq->deq_err++;
	    }
	}

      clib_memset_u8 (r, QAT_RING_EMPTY_SIG_BYTE, sizeof (*r));
      head++;

      if (--fe->n_pending == 0)
	{
	  n_done += fe->frame->n_vectors;
	  qat_frame_done (vm, node, fe);
	  q->fifo_head++;
	}
    }

  if (head != q->rx_head)
    {
      q->n_deq += head - q->rx_head;
      cq->deq_req += head - q->rx_head;
      q->rx_head = head;
      __atomic_store_n (q->rx_head_csr, (head & q->mask) * QAT_RX_MSG_SIZE, __ATOMIC_RELEASE);
    }

  return n_done;
}

VNET_DEV_NODE_FN (qat_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_crypto_engine_t *e = vnet_dev_crypto_node_engine (node);
  u32 n_done = 0, in_flight = 0;

  vec_foreach_pointer (cq, vnet_dev_crypto_get_thread_queues (e, vm->thread_index))
    {
      qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);

      n_done += qat_dequeue (vm, node, cq);
      in_flight |= q->fifo_head != q->fifo_tail;
    }

  if (in_flight)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_done;
}
