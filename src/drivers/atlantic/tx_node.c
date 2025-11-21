/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

static_always_inline u32
atl_tx_one_batch (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_t *dev,
		  vnet_dev_tx_queue_t *txq, u32 *bi_ring, u16 mask, u32 *from, u32 n_pkts,
		  u16 *tail_ptr, u32 *n_trace)
{
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  atl_tx_desc_t desc;
  u16 seg_len[8 * 32];
  void *seg_data[8 * 32];
  vlib_buffer_t *seg_buf[8 * 32];
  u32 seg_bi[8 * 32];
  u16 pkt_first_seg[32];
  u8 pkt_n_desc[32];
  u32 pkt_len[32];
  u32 drop_indices[32];
  u32 n_drop = 0;
  u32 n = 0;
  u16 tail = *tail_ptr;
  u16 n_free = txq->size - 1 - (tail - aq->head_index);
  u32 n_enq = 0;
  u32 n_seg = 0;

  for (u32 p = 0; p < n_pkts; p++)
    {
      u32 buffer_index = from[p];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffer_index);
      u32 total_len = 0;
      u32 n_desc = 0;

      if (n_free < ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? 8 : 1))
	break;

      pkt_first_seg[n_enq] = n_seg;

      for (;;)
	{
	  seg_bi[n_seg] = buffer_index;
	  seg_buf[n_seg] = b0;
	  seg_len[n_seg] = b0->current_length;
	  seg_data[n_seg] = vlib_buffer_get_current (b0);
	  total_len += b0->current_length;
	  n_seg++;
	  n_desc++;

	  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	    break;

	  if (PREDICT_FALSE (n_desc == 8))
	    {
	      drop_indices[n_drop++] = from[p];
	      n++;
	      goto next_pkt;
	    }

	  buffer_index = b0->next_buffer;
	  b0 = vlib_get_buffer (vm, buffer_index);
	}

      pkt_n_desc[n_enq] = n_desc;
      pkt_len[n_enq] = total_len;

      for (u32 i = 0; i < n_desc; i++)
	{
	  u32 seg_index = pkt_first_seg[n_enq] + i;
	  u8 is_last = (i + 1) == n_desc;
	  u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, seg_data[seg_index]);
	  u16 slot = tail & mask;
	  u32 bi = seg_bi[seg_index];
	  vlib_buffer_t *b = seg_buf[seg_index];

	  desc = (atl_tx_desc_t){
	    .addr = dma_addr,
	    .type_txd = 1,
	    .blen = seg_len[seg_index],
	    .eop = is_last,
	    .len = pkt_len[n_enq],
	  };

	  aq->descs[slot] = desc;
	  bi_ring[slot] = bi;
	  tail++;

	  if (*n_trace && vlib_trace_buffer (vm, node, VNET_INTERFACE_OUTPUT_NEXT_DROP, b, 0))
	    {
	      atl_tx_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	      t->buffer_index = bi;
	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	      t->queue_id = txq->queue_id;
	      t->desc = desc;
	      (*n_trace)--;
	    }
	}

      n_free -= n_desc;
      n_enq++;
      n++;

      if (n_free == 0)
	break;

    next_pkt:;
    }

  if (n_drop)
    {
      vlib_buffer_free (vm, drop_indices, n_drop);
      vlib_error_count (vm, node->node_index, ATL_TX_NODE_CTR_CHAIN_TOO_LONG, n_drop);
    }

  *tail_ptr = tail;
  return n;
}

VNET_DEV_NODE_FN (atl_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 *bi_ring = aq->buffer_indices;
  u32 n_left = frame->n_vectors;
  u32 n;
  u16 mask = txq->size - 1;
  u16 head;
  u16 tail;
  u16 old_tail;
  u16 n_used;
  u16 n_free;
  u32 n_trace = 0;

  vnet_dev_tx_queue_lock_if_needed (txq);
  head = atl_reg_rd_u32 (dev, ATL_REG_TX_DMA_DESC_HEAD_PTR (txq->queue_id));
  n_free = (head - aq->head_index) & mask;
  if (n_free)
    {
      vlib_buffer_free_from_ring_no_next (vm, bi_ring, aq->head_index & mask, txq->size, n_free);
      aq->head_index += n_free;
    }

  n_used = aq->tail_index - aq->head_index;
  n_free = txq->size - 1 - n_used;

  if (n_free == 0)
    goto no_space;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    n_trace = vlib_get_trace_count (vm, node);

  old_tail = aq->tail_index;
  tail = old_tail;
  while (n_left >= 32)
    {
      n = atl_tx_one_batch (vm, node, dev, txq, bi_ring, mask, from, 32, &tail, &n_trace);
      from += n;
      n_left -= n;
      if (n < 32)
	break;
    }

  if (n_left)
    {
      n = atl_tx_one_batch (vm, node, dev, txq, bi_ring, mask, from, n_left, &tail, &n_trace);
      from += n;
      n_left -= n;
    }

  aq->tail_index = tail;
  if (tail != old_tail)
    __atomic_store_n (aq->tail_reg, tail & mask, __ATOMIC_RELEASE);

  vlib_set_trace_count (vm, node, n_trace);

no_space:
  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, ATL_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
