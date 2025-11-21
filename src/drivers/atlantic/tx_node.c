/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

static_always_inline void
atl_txq_reclaim (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;
  u16 hw_head;
  u16 head_mod;
  u16 n_free;

  hw_head = atl_reg_rd_u32 (dev, ATL_REG_TX_DMA_DESC_HEAD_PTR (txq->queue_id));
  if (hw_head >= txq->size)
    return;

  head_mod = aq->head_index & mask;
  n_free = (hw_head - head_mod) & mask;
  if (n_free == 0)
    return;

  vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, head_mod, txq->size, n_free);
  aq->head_index += n_free;
}

VNET_DEV_NODE_FN (atl_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_sent = 0;
  u16 mask = txq->size - 1;
  u16 n_used;
  u16 n_free;
  u32 n_trace = 0;

  vnet_dev_tx_queue_lock_if_needed (txq);
  atl_txq_reclaim (vm, txq);

  n_used = aq->tail_index - aq->head_index;
  n_free = txq->size - 1 - n_used;
  if (n_free == 0)
    goto no_space;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    n_trace = vlib_get_trace_count (vm, node);

  while (n_left)
    {
      vlib_buffer_t *b;
      vlib_buffer_t *b0;
      atl_tx_desc_t desc;
      u32 pkt_len;
      u32 n_desc = 1;
      u16 slot = aq->tail_index & mask;
      u32 buffer_index = from[0];
      u32 i;

      b = vlib_get_buffer (vm, buffer_index);
      b0 = b;
      while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  b0 = vlib_get_buffer (vm, b0->next_buffer);
	  n_desc++;
	}

      if (n_desc > n_free)
	break;

      pkt_len = vlib_buffer_length_in_chain (vm, b);

      b0 = b;
      for (i = 0; i < n_desc; i++)
	{
	  u8 is_last;
	  u64 dma_addr;

	  is_last = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;
	  dma_addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (b0));
	  desc = (atl_tx_desc_t){
	    .addr = dma_addr,
	    .type_txd = 1,
	    .blen = b0->current_length,
	    .eop = is_last,
	    .wb = is_last,
	    .len = pkt_len,
	  };
	  aq->descs[slot] = desc;
	  aq->buffer_indices[slot] = buffer_index;

	  if (n_trace && vlib_trace_buffer (vm, node, VNET_INTERFACE_OUTPUT_NEXT_DROP, b0, 0))
	    {
	      atl_tx_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->buffer_index = buffer_index;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->queue_id = txq->queue_id;
	      t->desc = desc;
	      n_trace--;
	    }

	  slot = (slot + 1) & mask;
	  aq->tail_index++;
	  if (is_last)
	    break;

	  buffer_index = b0->next_buffer;
	  b0 = vlib_get_buffer (vm, buffer_index);
	}

      n_free -= n_desc;
      n_left--;
      n_sent++;
      from++;
      if (n_free == 0)
	break;
    }

  if (n_sent)
    __atomic_store_n (aq->tail_reg, aq->tail_index & mask, __ATOMIC_RELEASE);

  if (n_trace)
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
