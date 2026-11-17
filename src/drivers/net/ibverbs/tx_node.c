/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <ibverbs.h>

static_always_inline void
ibv_txq_deq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 new_head = tq->head, mask = txq->size - 1;
  int n = ibv_poll_cq (tq->ibv_cq, VLIB_FRAME_SIZE, wc);

  if (PREDICT_FALSE (n < 0))
    vlib_error_count (vm, node->node_index, IBV_TX_NODE_CTR_IBV_POLL_CQ, 1);

  for (int i = 0; i < n; i++)
    {
      if (PREDICT_FALSE (wc[i].status != IBV_WC_SUCCESS))
	{
	  vlib_error_count (vm, node->node_index, IBV_TX_NODE_CTR_WC_STATUS, 1);
	  ibv_txq_recover (vm, txq, wc[i].status);
	  return;
	}
      new_head = wc[i].wr_id;
    }

  if (new_head != tq->head)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, new_head - tq->head);
  tq->head = new_head;
}

static_always_inline u32
ibv_txq_fill_sges (vlib_main_t *vm, vlib_buffer_t *b, struct ibv_sge *s, u32 max_sge, u32 skip)
{
  vlib_buffer_t *cb = b;
  u32 n = 1;

  while (cb->flags & VLIB_BUFFER_NEXT_PRESENT && n <= max_sge)
    {
      cb = vlib_get_buffer (vm, cb->next_buffer);
      n++;
    }

  if (PREDICT_FALSE (n > max_sge))
    {
      n = vlib_buffer_chain_linearize (vm, b);
      if (n == 0 || n > max_sge)
	return 0;
    }

  n = 0;
  if (b->current_length > skip)
    {
      s[n].addr = vlib_buffer_get_current_va (b) + skip;
      s[n].length = b->current_length - skip;
      n++;
    }

  for (cb = b; cb->flags & VLIB_BUFFER_NEXT_PRESENT; n++)
    {
      cb = vlib_get_buffer (vm, cb->next_buffer);
      s[n].addr = vlib_buffer_get_current_va (cb);
      s[n].length = cb->current_length;
    }

  return n;
}

static_always_inline void
ibv_txq_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq,
		   vlib_buffer_t *b, u32 bi, struct ibv_send_wr *w)
{
  u32 n_sge = w ? w->num_sge : 0;
  ibv_tx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr) + n_sge * sizeof (struct ibv_sge));

  *tr = (ibv_tx_trace_t) {
    .qid = txq->queue_id,
    .dropped = w == 0,
    .n_sge = n_sge,
    .hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq),
    .buffer_index = bi,
    .data_len = vlib_buffer_length_in_chain (vm, b),
  };
  if (w == 0)
    return;
  tr->wr_id = w->wr_id;
  tr->opcode = w->opcode;
  tr->send_flags = w->send_flags;
  if (w->opcode == IBV_WR_TSO)
    {
      tr->tso_hdr_sz = w->tso.hdr_sz;
      tr->tso_mss = w->tso.mss;
    }
  for (u32 i = 0; i < n_sge; i++)
    tr->sge[i] = w->sg_list[i];
}

static_always_inline void
ibv_txq_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	       u32 n, u16 *wr_idx, u32 n_posted)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	ibv_txq_trace_one (vm, node, txq, b, from[i],
			   wr_idx[i] < n_posted ? tq->wr_template + wr_idx[i] : 0);
    }
}

static_always_inline u32
ibv_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	     u32 n_left, u32 *drops, u32 *n_drops, u32 *n_chain)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_send_wr *wr = tq->wr_template, *w = wr, *bad_wr;
  u32 size = txq->size, mask = size - 1, tail = tq->tail, n_posted;
  u32 n = clib_min (n_left, size - (tq->tail - tq->head));
  u32 to_tx[VLIB_FRAME_SIZE], n_tx = 0;
  u16 wr_idx[VLIB_FRAME_SIZE];
  u8 trace = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;
  struct ibv_sge *s = tq->sge_template;
  u32 max_sge = tq->max_sge;

  if (n == 0)
    return 0;

  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u8 is_gso = (b->flags & VNET_BUFFER_F_GSO) != 0;
      u32 hdr_sz = 0, n_sge;

      if (PREDICT_FALSE (is_gso))
	hdr_sz = vnet_buffer (b)->l4_hdr_offset - b->current_data + vnet_buffer2 (b)->gso_l4_hdr_sz;

      n_sge = ibv_txq_fill_sges (vm, b, s, max_sge, hdr_sz);
      wr_idx[i] = n_sge ? n_tx : 0xffff;
      if (PREDICT_FALSE (n_sge == 0))
	{
	  drops[n_drops[0]++] = from[i];
	  n_chain[0]++;
	  continue;
	}

      w->num_sge = n_sge;
      w->opcode = IBV_WR_SEND;
      w->send_flags = 0;
      if (PREDICT_FALSE (is_gso))
	{
	  w->opcode = IBV_WR_TSO;
	  w->tso.hdr = vlib_buffer_get_current (b);
	  w->tso.hdr_sz = hdr_sz;
	  w->tso.mss = vnet_buffer2 (b)->gso_size;
	  w->send_flags = IBV_SEND_IP_CSUM;
	}
      else if ((b->flags & VNET_BUFFER_F_OFFLOAD) &&
	       (vnet_buffer (b)->oflags &
		(VNET_BUFFER_OFFLOAD_F_IP_CKSUM | VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
		 VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)))
	w->send_flags = IBV_SEND_IP_CSUM;
      to_tx[n_tx++] = from[i];
      w++;
      s += IBV_TXQ_MAX_SGE;
    }

  if (n_tx == 0)
    {
      if (PREDICT_FALSE (trace))
	ibv_txq_trace (vm, node, txq, from, n, wr_idx, 0);
      return n;
    }

  w[-1].wr_id = tail + n_tx;
  w[-1].next = 0;
  w[-1].send_flags |= IBV_SEND_SIGNALED;

  if (PREDICT_TRUE (ibv_post_send (tq->ibv_qp, wr, &bad_wr) == 0))
    n_posted = n_tx;
  else
    {
      vlib_error_count (vm, node->node_index, IBV_TX_NODE_CTR_IBV_POST_SEND, 1);
      n_posted = bad_wr ? bad_wr - wr : 0;
      for (u32 i = n_posted; i < n_tx; i++)
	drops[n_drops[0]++] = to_tx[i];
    }

  if (PREDICT_FALSE (trace))
    ibv_txq_trace (vm, node, txq, from, n, wr_idx, n_posted);

  w[-1].next = w;
  w[-1].send_flags = 0;
  vlib_buffer_copy_indices_to_ring (tq->buffers, to_tx, tail & mask, size, n_posted);
  tq->tail = tail + n_posted;
  return n;
}

VNET_DEV_NODE_FN (ibv_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors, n_enq = 0, n_drops = 0, n_chain = 0;
  u32 drops[VLIB_FRAME_SIZE];
  int n_retries = 2;

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_retries-- && n_enq < n_left)
    {
      u32 n;
      ibv_txq_deq (vm, node, txq);
      n = ibv_txq_enq (vm, node, txq, from + n_enq, n_left - n_enq, drops, &n_drops, &n_chain);
      n_enq += n;
      if (n == 0)
	break;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    for (u32 i = n_enq; i < n_left; i++)
      {
	vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	if (b->flags & VLIB_BUFFER_IS_TRACED)
	  ibv_txq_trace_one (vm, node, txq, b, from[i], 0);
      }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (PREDICT_FALSE (n_drops))
    {
      vlib_buffer_free (vm, drops, n_drops);
      if (n_chain)
	vlib_error_count (vm, node->node_index, IBV_TX_NODE_CTR_CHAIN_TOO_LONG, n_chain);
    }

  if (PREDICT_FALSE (n_enq < n_left))
    {
      vlib_buffer_free (vm, from + n_enq, n_left - n_enq);
      vlib_error_count (vm, node->node_index, IBV_TX_NODE_CTR_NO_FREE_SLOTS, n_left - n_enq);
    }

  return n_enq - n_drops;
}
