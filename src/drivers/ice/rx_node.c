/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/ethernet/ethernet.h>
#include <ice.h>

static_always_inline void
ice_rx_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  u16 mask = rxq->size - 1;
  u16 n = iq->head + rxq->size - iq->tail;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  if (n <= ICE_RX_REFILL_BATCH)
    return;
  n -= ICE_RX_REFILL_BATCH;
  while (n >= ICE_RX_REFILL_BATCH)
    {
      u16 slot = iq->tail & mask;
      u16 batch = clib_min ((u16) ICE_RX_REFILL_BATCH, (u16) (rxq->size - slot));
      u16 n_alloc = vlib_buffer_alloc_from_pool (vm, iq->buffer_indices + slot, batch, bpi);
      if (n_alloc != batch)
	{
	  if (n_alloc)
	    vlib_buffer_free (vm, iq->buffer_indices + slot, n_alloc);
	  break;
	}
      for (u16 i = 0; i < batch; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, iq->buffer_indices[slot + i]);
	  iq->descs[slot + i] = (ice_rx_desc_t) {
	    .read.pkt_addr = vnet_dev_get_dma_addr (vm, dev, b->data),
	  };
	}
      iq->tail += batch;
      n -= batch;
    }
  __atomic_store_n (iq->tail_reg, (iq->tail - 1) & mask, __ATOMIC_RELEASE);
}

static_always_inline uword
ice_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 bis[VLIB_FRAME_SIZE];
  u32 n_rx = 0, n_bytes = 0;
  u16 mask = rxq->size - 1;
  u16 head = iq->head;

  while (n_rx < VLIB_FRAME_SIZE)
    {
      u16 slot = head & mask;
      ice_rx_status_t status;
      status.as_u64 = __atomic_load_n (&iq->descs[slot].wb.status.as_u64, __ATOMIC_ACQUIRE);
      if (!status.done)
	break;
      if (!status.end_of_packet)
	{
	  vlib_buffer_free_one (vm, iq->buffer_indices[slot]);
	  vlib_error_count (vm, node->node_index, ICE_RX_NODE_CTR_DESC_ERROR, 1);
	  head++;
	  continue;
	}

      u32 bi = iq->buffer_indices[slot];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      vlib_buffer_copy_template (b, &bt);
      b->current_length = status.packet_length;
      bis[n_rx++] = bi;
      n_bytes += status.packet_length;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) && vlib_get_trace_count (vm, node) &&
	  vlib_trace_buffer (vm, node, vnet_dev_get_rx_queue_if_next_index (rxq), b, 0))
	{
	  ice_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
	  tr->buffer_index = bi;
	  tr->queue_id = rxq->queue_id;
	  tr->desc = iq->descs[slot];
	  vlib_set_trace_count (vm, node, vlib_get_trace_count (vm, node) - 1);
	}
      head++;
    }

  iq->head = head;
  ice_rx_refill (vm, rxq);
  if (n_rx == 0)
    return 0;

  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 *to_next;
  u32 n_left;
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left);
  ASSERT (n_left >= n_rx);
  vlib_buffer_copy_indices (to_next, bis, n_rx);
  to_next += n_rx;
  n_left -= n_rx;

  if (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT)
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef->sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
      ef->hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
    }
  vlib_put_next_frame (vm, node, next_index, n_left);
  vlib_increment_combined_counter (
    vnet_get_main ()->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, vnet_dev_get_rx_queue_if_sw_if_index (rxq), n_rx, n_bytes);
  return n_rx;
}

VNET_DEV_NODE_FN (ice_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uword n = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    n += ice_rx_one_queue (vm, node, rxq);
  return n;
}
