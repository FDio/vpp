/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <cadence.h>

static_always_inline void
cdn_txq_complete (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;

  while (ctq->head != ctq->tail)
    {
      u16 first = ctq->head & mask;
      u16 n_free = 0;
      u32 ctrl;

      ctrl = __atomic_load_n (&ctq->descs[first].ctrl.as_u32, __ATOMIC_ACQUIRE);
      if ((ctrl >> 31) == 0)
	break;

      for (;;)
	{
	  u16 slot = (ctq->head + n_free) & mask;

	  ctrl = ctq->descs[slot].ctrl.as_u32;
	  ctq->descs[slot].addr = 0;
	  ctq->descs[slot].addrh = 0;
	  ctq->descs[slot].resvd = 0;
	  ctq->descs[slot].ctrl.as_u32 = (1u << 31) | (ctrl & (1u << 30));
	  n_free++;
	  if (ctrl & (1 << 15))
	    break;
	}

      vlib_buffer_free_from_ring_no_next (vm, ctq->buffer_indices, first, txq->size, n_free);
      ctq->head += n_free;
    }
}

static_always_inline u32
cdn_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_t *dev, vnet_dev_tx_queue_t *txq,
	     u32 *from, u32 n_left)
{
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vlib_buffer_t *seg_buf[8];
  u32 seg_bi[8];
  u32 n_pkts = 0;
  u16 mask = txq->size - 1;
  u16 head = ctq->head;
  u16 tail = ctq->tail;
  u16 n_free = txq->size - 1 - (tail - head);

  while (n_pkts < n_left)
    {
      vlib_buffer_t *b;
      u32 bi;
      u16 n_desc = 0;
      u16 first_slot;
      u16 i;
      u64 dma_addr;
      cdn_tx_desc_t first = {};

      bi = from[n_pkts];
      b = vlib_get_buffer (vm, bi);
      for (;;)
	{
	  if (n_desc == ARRAY_LEN (seg_buf))
	    {
	      vlib_error_count (vm, node->node_index, CDN_TX_NODE_CTR_CHAIN_TOO_LONG, 1);
	      vlib_buffer_free (vm, from + n_pkts, 1);
	      n_pkts++;
	      goto next_pkt;
	    }

	  seg_buf[n_desc] = b;
	  seg_bi[n_desc] = bi;
	  n_desc++;

	  if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	    break;

	  bi = b->next_buffer;
	  b = vlib_get_buffer (vm, bi);
	}

      if (n_desc > n_free)
	break;

      first_slot = tail & mask;

      for (i = n_desc - 1; i > 0; i--)
	{
	  u16 slot = (tail + i) & mask;
	  cdn_tx_desc_t *d = ctq->descs + slot;

	  dma_addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (seg_buf[i]));
	  d->addr = cdn_dma_addr_lo (dma_addr);
	  d->addrh = cdn_dma_addr_hi (dma_addr);
	  d->resvd = 0;
	  ctq->buffer_indices[slot] = seg_bi[i];
	  __atomic_store_n (&d->ctrl.as_u32,
			    seg_buf[i]->current_length | ((i + 1 == n_desc) << 15) |
			      ((slot == mask) << 30),
			    __ATOMIC_RELEASE);
	}

      dma_addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (seg_buf[0]));
      first.addr = cdn_dma_addr_lo (dma_addr);
      first.addrh = cdn_dma_addr_hi (dma_addr);
      first.resvd = 0;
      first.ctrl.frm_len = seg_buf[0]->current_length;
      first.ctrl.last = n_desc == 1;
      first.ctrl.wrap = first_slot == mask;
      ctq->buffer_indices[first_slot] = seg_bi[0];
      ctq->descs[first_slot].addr = first.addr;
      ctq->descs[first_slot].addrh = first.addrh;
      ctq->descs[first_slot].resvd = 0;
      __atomic_store_n (&ctq->descs[first_slot].ctrl.as_u32, first.ctrl.as_u32, __ATOMIC_RELEASE);

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (seg_buf[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cdn_tx_trace_t *t = vlib_add_trace (vm, node, seg_buf[0], sizeof (*t));
	  t->desc = ctq->descs[first_slot];
	  t->buffer_index = seg_bi[0];
	  t->hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
	  t->queue_id = txq->queue_id;
	}

      tail += n_desc;
      n_free -= n_desc;
      n_pkts++;

    next_pkt:;
    }

  if (tail != ctq->tail)
    {
      ctq->tail = tail;
      cdn_reg_wr (dev, cd, CDN_NCR, cdn_reg_rd (dev, cd, CDN_NCR) | (1 << 9));
    }

  return n_pkts;
}

VNET_DEV_NODE_FN (cdn_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n;

  vnet_dev_tx_queue_lock_if_needed (txq);

  cdn_txq_complete (vm, txq);
  n = cdn_txq_enq (vm, node, dev, txq, from, n_left);
  from += n;
  n_left -= n;

  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, CDN_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
