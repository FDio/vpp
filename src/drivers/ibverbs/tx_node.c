/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ibverbs.h>

static_always_inline void
ibv_txq_deq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 mask = txq->size - 1;
  u32 n_free;
  u32 tail;
  int n;

  n = ibv_poll_cq (tq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (n < 0)
    vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_IBV_POLL_CQ, 1);
  if (n <= 0)
    return;

  while (PREDICT_FALSE (wc[n - 1].status != IBV_WC_SUCCESS))
    {
      n--;
      if (n == 0)
	return;
    }

  tail = wc[n - 1].wr_id;
  n_free = tail - tq->head;
  if (n_free)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, n_free);
  tq->head = tail;
}

static_always_inline u32
ibv_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	     u32 n_left, u32 *n_bytes)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_send_wr wr[VLIB_FRAME_SIZE] = {};
  struct ibv_sge sge[VLIB_FRAME_SIZE] = {};
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  vlib_buffer_t **bp = b;
  struct ibv_send_wr *w = wr;
  struct ibv_sge *s = sge;
  u32 mask = txq->size - 1;
  u32 n;
  u32 n_posted;
  u32 tail;
  int rv;

  n = clib_min (n_left, txq->size - (tq->tail - tq->head));
  if (n == 0)
    return 0;

  tail = tq->tail;
  vlib_buffer_copy_indices_to_ring (tq->buffers, from, tail & mask, txq->size, n);
  vlib_get_buffers (vm, from, b, n);
  n_posted = n;

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  vlib_prefetch_buffer_header (bp[4], LOAD);
	  vlib_prefetch_buffer_header (bp[5], LOAD);
	  vlib_prefetch_buffer_header (bp[6], LOAD);
	  vlib_prefetch_buffer_header (bp[7], LOAD);
	}

      s[0].addr = vlib_buffer_get_current_va (bp[0]);
      s[0].length = bp[0]->current_length;
      s[1].addr = vlib_buffer_get_current_va (bp[1]);
      s[1].length = bp[1]->current_length;
      s[2].addr = vlib_buffer_get_current_va (bp[2]);
      s[2].length = bp[2]->current_length;
      s[3].addr = vlib_buffer_get_current_va (bp[3]);
      s[3].length = bp[3]->current_length;

      w[0].next = w + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      w[1].next = w + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;
      w[1].opcode = IBV_WR_SEND;

      w[2].next = w + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;
      w[2].opcode = IBV_WR_SEND;

      w[3].next = w + 1;
      w[3].sg_list = &s[3];
      w[3].num_sge = 1;
      w[3].opcode = IBV_WR_SEND;

      s += 4;
      w += 4;
      bp += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      s[0].addr = vlib_buffer_get_current_va (bp[0]);
      s[0].length = bp[0]->current_length;

      w[0].next = w + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;
      w[0].opcode = IBV_WR_SEND;

      s += 1;
      w += 1;
      bp += 1;
      n -= 1;
    }

  w[-1].wr_id = tail + n_posted;
  w[-1].next = 0;
  w[-1].send_flags = IBV_SEND_SIGNALED;

  rv = ibv_post_send (tq->ibv_qp, wr, &w);
  if (PREDICT_FALSE (rv != 0))
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_IBV_POST_SEND, 1);
      n_posted = w - wr;
    }

  tq->tail = tail + n_posted;

  if (n_posted)
    {
      u32 i;
      for (i = 0; i < n_posted; i++)
	*n_bytes += b[i]->current_length;
    }

  return n_posted;
}

VNET_DEV_NODE_FN (ibv_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_pkts = 0;
  u32 n_bytes = 0;
  int n_retries = 2;

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_retries-- && n_left)
    {
      u32 n;
      ibv_txq_deq (vm, node, txq);
      n = ibv_txq_enq (vm, node, txq, from, n_left, &n_bytes);
      from += n;
      n_left -= n;
      n_pkts += n;
      if (n == 0)
	break;
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n_left)
    vlib_buffer_free (vm, from, n_left);

  vlib_increment_combined_counter (vnet_get_main ()->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_TX,
				   vm->thread_index, rt->hw_if_index, n_pkts, n_bytes);

  return n_pkts;
}
