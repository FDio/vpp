/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VNET_DEV_NODE_FN (ice_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 mask = txq->size - 1;

  vnet_dev_tx_queue_lock_if_needed (txq);
  u16 hw_head = ice_reg_read (dev, ICE_QTX_COMM_HEAD (id->txq_base + txq->queue_id)) & mask;
  u16 n_done = (hw_head - (iq->head & mask)) & mask;
  if (n_done)
    {
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & mask, txq->size,
					  n_done);
      iq->head += n_done;
    }

  u16 n_free = txq->size - 1 - (iq->tail - iq->head);
  while (n_left && n_free)
    {
      u32 bi = from[0];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  vlib_buffer_free_one (vm, bi);
	  vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_CHAIN_TOO_LONG, 1);
	  from++;
	  n_left--;
	  continue;
	}

      u16 slot = iq->tail & mask;
      ice_tx_desc_t d = {
        .buf_addr = vnet_dev_get_dma_addr (
          vm, dev, vlib_buffer_get_current (b)),
        .cmd = {
          .end_of_packet = 1,
          .report_status = 1,
          .buffer_size = b->current_length,
        },
      };
      iq->descs[slot] = d;
      iq->buffer_indices[slot] = bi;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) && vlib_get_trace_count (vm, node) &&
	  vlib_trace_buffer (vm, node, VNET_INTERFACE_OUTPUT_NEXT_DROP, b, 0))
	{
	  ice_tx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	  tr->buffer_index = bi;
	  tr->queue_id = txq->queue_id;
	  tr->desc = d;
	  vlib_set_trace_count (vm, node, vlib_get_trace_count (vm, node) - 1);
	}

      iq->tail++;
      n_free--;
      from++;
      n_left--;
    }

  if (iq->tail != iq->head)
    __atomic_store_n (iq->tail_reg, iq->tail & mask, __ATOMIC_RELEASE);
  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }
  vnet_dev_tx_queue_unlock_if_needed (txq);
  return frame->n_vectors - n_left;
}
