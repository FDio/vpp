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
  u32 new_head, n_free, n_bad = 0, mask = txq->size - 1;
  int n = ibv_poll_cq (tq->ibv_cq, VLIB_FRAME_SIZE, wc);

  if (n < 0)
    vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_IBV_POLL_CQ, 1);

  if (n <= 0)
    return;

  new_head = tq->head;
  for (u32 i = 0; i < n; i++)
    {
      if (wc[i].status != IBV_WC_SUCCESS)
	n_bad++;
      if ((i32) (wc[i].wr_id - new_head) > 0)
	new_head = wc[i].wr_id;
    }

  if (PREDICT_FALSE (n_bad))
    vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_WC_STATUS, n_bad);

  n_free = new_head - tq->head;

  if (n_free)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, n_free);

  tq->head = new_head;
}

static_always_inline u32
ibv_txq_enq_one_slow (vlib_main_t *vm, vlib_buffer_t *b0, struct ibv_sge *s, struct ibv_send_wr *w,
		      u8 cksum_off, u32 *n_bytes)
{
  u32 flags = b0->flags;
  u32 n_sge = 1;
  u32 tail_bytes = 0;
  vlib_buffer_t *pb;

  if (PREDICT_TRUE ((flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_OFFLOAD_F_IP_CKSUM)) == 0))
    return 1;

  if (cksum_off && (flags & VNET_BUFFER_F_OFFLOAD) &&
      (vnet_buffer (b0)->oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM))
    w->send_flags |= IBV_SEND_IP_CSUM;

  if ((flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
    return 1;

  pb = vlib_get_buffer (vm, b0->next_buffer);
  while (1)
    {
      if (n_sge == IBV_TXQ_MAX_CHAIN_SZ)
	return 0;
      s[n_sge].addr = vlib_buffer_get_current_va (pb);
      s[n_sge].length = pb->current_length;
      tail_bytes += pb->current_length;
      n_sge++;
      if ((pb->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	break;
      pb = vlib_get_buffer (vm, pb->next_buffer);
    }

  w->num_sge = n_sge;
  *n_bytes += tail_bytes;
  return 1;
}

static_always_inline u32
ibv_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	     u32 n_left, u32 *n_pkts, u32 *n_bytes)
{
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_send_wr *wr = tq->wr_template, *w = wr, *rw;
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  u32 to_tx[VLIB_FRAME_SIZE];
  u32 to_drop[VLIB_FRAME_SIZE];
  u32 *to = to_tx;
  u32 size = txq->size, mask = size - 1, n, n_queued, n_drop = 0, i, tail;
  u32 n_sent = 0;
  u8 cksum_off = txq->port->attr.tx_offloads.ip4_cksum;
  struct ibv_sge *s;
  int rv;

  n = clib_min (n_left, size - (tq->tail - tq->head));
  if (n == 0)
    return 0;

  vlib_get_buffers (vm, from, b, n);
  for (s = tq->sge_template, i = 0; i < n; i++)
    {
      u32 bi = from[i];
      s[0].addr = vlib_buffer_get_current_va (b[i]);
      s[0].length = b[i]->current_length;
      w->num_sge = 1;
      w->send_flags = 0;

      if (ibv_txq_enq_one_slow (vm, b[i], s, w, cksum_off, n_bytes) == 0)
	{
	  to_drop[n_drop++] = from[i];
	  continue;
	}

      *n_bytes += b[i]->current_length;
      to++[0] = bi;
      w++;
      s += IBV_TXQ_MAX_CHAIN_SZ;
    }

  if (n_drop)
    {
      vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_CHAIN_TOO_LONG, n_drop);
      vlib_buffer_free (vm, to_drop, n_drop);
    }

  n_queued = to - to_tx;

  if (n_queued == 0)
    return n;

  n_sent = n_queued;

  tail = tq->tail;
  vlib_buffer_copy_indices_to_ring (tq->buffers, to_tx, tail & mask, size, n_queued);
  w[-1].wr_id = tail + n_queued;
  w[-1].next = 0;
  w[-1].send_flags |= IBV_SEND_SIGNALED;

  rv = ibv_post_send (tq->ibv_qp, wr, &rw);

  /* reset template for next round */
  w[-1].next = w;
  w[-1].send_flags = 0;

  if (PREDICT_TRUE (rv == 0))
    {
      *n_pkts += n_sent;
      tq->tail = tail + n_sent;
      return n;
    }

  vlib_error_count (vm, node->node_index, RDMA_TX_NODE_CTR_IBV_POST_SEND, 1);

  if (rw == 0 || rw == wr)
    {
      n_sent = 0;
      vlib_buffer_free (vm, to_tx, n_queued);
      for (u32 j = 0; j < n_queued; j++)
	{
	  struct ibv_sge *sg = tq->sge_template + (j * IBV_TXQ_MAX_CHAIN_SZ);
	  for (u32 k = 0; k < wr[j].num_sge; k++)
	    *n_bytes -= sg[k].length;
	}
      return n;
    }

  n_sent = rw - wr;
  if (n_sent != n_queued)
    {
      u32 n_unposted = n_queued - n_sent;
      vlib_buffer_free (vm, to_tx + n_sent, n_unposted);
      for (u32 j = n_sent; j < n_queued; j++)
	{
	  struct ibv_sge *sg = tq->sge_template + (j * IBV_TXQ_MAX_CHAIN_SZ);
	  for (u32 k = 0; k < wr[j].num_sge; k++)
	    *n_bytes -= sg[k].length;
	}
    }
  *n_pkts += n_sent;

  if (n_sent)
    tq->tail = tail + n_sent;

  return n;
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
      u32 n_consumed;
      ibv_txq_deq (vm, node, txq);
      n_consumed = ibv_txq_enq (vm, node, txq, from, n_left, &n_pkts, &n_bytes);
      from += n_consumed;
      n_left -= n_consumed;
      if (n_consumed == 0)
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
