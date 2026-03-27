/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <cadence.h>

static_always_inline void
cdn_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 n_refill = crq->head + size - crq->tail;

  if (n_refill < 8)
    return;

  while (n_refill)
    {
      u16 off = crq->tail & mask;
      u16 n = clib_min ((u16) (size - off), n_refill);
      u32 n_alloc;

      n_alloc = vlib_buffer_alloc_from_pool (vm, crq->buffer_indices + off, n, bpi);
      if (n_alloc == 0)
	vlib_error_count (vm, node->node_index, CDN_RX_NODE_CTR_NO_BUFFER, n);
      for (u32 i = 0; i < n_alloc; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, crq->buffer_indices[off + i]);
	  u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, b->data);

	  u32 addr_lo = cdn_dma_addr_lo (dma_addr);

	  if (off + i == size - 1)
	    addr_lo |= 1 << 1;

	  crq->descs[off + i].ctrl.as_u32 = 0;
	  crq->descs[off + i].addrh = cdn_dma_addr_hi (dma_addr);
	  crq->descs[off + i].resvd = 0;
	  __atomic_store_n (&crq->descs[off + i].addr.as_u32, addr_lo, __ATOMIC_RELEASE);
	}

      crq->tail += n_alloc;
      if (n_alloc < n)
	break;
      n_refill -= n_alloc;
    }
}

static_always_inline u32
cdn_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_main_t *vnm = vnet_get_main ();
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 *to_next;
  uword n_left_to_next;
  u32 n_rx = 0;
  u32 n_rx_bytes = 0;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 head = crq->head;
  u16 slot = head & mask;
  cdn_rx_desc_t *d = crq->descs + slot;
  u32 addr;

  addr = __atomic_load_n (&d->addr.as_u32, __ATOMIC_ACQUIRE);
  if ((addr & 1) == 0)
    return 0;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  while (n_left_to_next)
    {
      vlib_buffer_t *b;
      u32 bi;

      d = crq->descs + slot;
      addr = __atomic_load_n (&d->addr.as_u32, __ATOMIC_ACQUIRE);
      if ((addr & 1) == 0)
	break;
      if (d->ctrl.eof == 0)
	{
	  vlib_error_count (vm, node->node_index, CDN_RX_NODE_CTR_INCOMPLETE_CHAIN, 1);
	  break;
	}

      bi = crq->buffer_indices[slot];
      b = vlib_get_buffer (vm, bi);
      b->template = bt;
      b->current_length = d->ctrl.frm_len;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cdn_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->desc = *d;
	  tr->buffer_index = bi;
	  tr->hw_if_index = hw_if_index;
	  tr->queue_id = rxq->queue_id;
	  tr->next_index = next_index;
	}

      to_next[0] = bi;
      to_next++;
      n_left_to_next--;
      n_rx++;
      n_rx_bytes += d->ctrl.frm_len;

      d->ctrl.as_u32 = 0;
      __atomic_store_n (&d->addr.as_u32, addr & ~1, __ATOMIC_RELEASE);

      head++;
      slot = head & mask;
    }

  crq->head = head;

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;

      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  if (n_rx)
    vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_RX,
				     vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  return n_rx;
}

VNET_DEV_NODE_FN (cdn_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 n_rx = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += cdn_rx_one_queue (vm, node, rxq);
      cdn_rxq_refill (vm, node, rxq);
    }

  return n_rx;
}
