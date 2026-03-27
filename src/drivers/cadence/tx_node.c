/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <cadence.h>

static_always_inline int
cdn_txq_enq_tail (vlib_main_t *vm, vnet_dev_t *dev, u16 mask, cdn_tx_desc_t *descs,
		  u32 *buffer_indices, u32 bi0, u16 tail, u16 n_free)
{
  u32 bi = bi0;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u16 n_desc = 1;
  u16 slot;
  u64 dma_addr;
  cdn_tx_desc_ctrl_t ctrl;
  u64x2 d64;

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      if (n_desc == n_free)
	return 0;

      bi = b->next_buffer;
      b = vlib_get_buffer (vm, bi);
      slot = (tail + n_desc) & mask;
      dma_addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (b));
      ctrl.as_u32 = 0;
      ctrl.frm_len = b->current_length;
      ctrl.last = (b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;
      d64 = (u64x2){
	dma_addr,
	ctrl.as_u32,
      };
      descs[slot].as_u32x4 = u32x4_shuffle ((u32x4) d64, 0, 2, 1, 3);
      buffer_indices[slot] = bi;
      n_desc++;
    }

  return n_desc;
}

static_always_inline void
cdn_txq_complete (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u16 size = txq->size;
  u16 mask = size - 1;
  u32 head = ctq->head;
  u32 n_enq = ctq->tail - head;
  u16 first = head & mask;
  cdn_tx_desc_t *descs = ctq->descs;
  cdn_tx_desc_ctrl_t ctrl;

  if (n_enq == 0)
    return;

  for (; n_enq >= 32; head += 32, n_enq -= 32)
    {
      ctrl.as_u32 = __atomic_load_n (&descs[(head + 31) & mask].ctrl.as_u32, __ATOMIC_RELAXED);
      if (ctrl.used == 0)
	break;
    }

  for (; n_enq >= 8; head += 8, n_enq -= 8)
    {
      ctrl.as_u32 = __atomic_load_n (&descs[(head + 7) & mask].ctrl.as_u32, __ATOMIC_RELAXED);
      if (ctrl.used == 0)
	break;
    }

  for (; n_enq; head++, n_enq--)
    {
      ctrl.as_u32 = __atomic_load_n (&descs[head & mask].ctrl.as_u32, __ATOMIC_RELAXED);
      if (ctrl.used == 0)
	break;
    }

  if (head == ctq->head)
    return;

  vlib_buffer_free_from_ring_no_next (vm, ctq->buffer_indices, first, size, head - ctq->head);

  ctq->head = head;
}

static_always_inline void
cdn_txq_drop_too_long_chains (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq,
			      u32 or_flags, u32 *from, vlib_buffer_t **buffers, uword *dma_addrs,
			      cdn_tx_desc_ctrl_t *desc_ctrls, u32 *n_pkts)
{
  u32 drop[VLIB_FRAME_SIZE + 1];
  u32 n_drop = 0;
  u32 dst;

  if (PREDICT_TRUE ((or_flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    return;

  for (u32 i = 0; i < *n_pkts; i++)
    {
      vlib_buffer_t *tb = buffers[i];
      u8 n_bufs_in_chain = 1;

      if (desc_ctrls[i].last == 0)
	while (tb->flags & VLIB_BUFFER_NEXT_PRESENT)
	  {
	    n_bufs_in_chain++;
	    tb = vlib_get_buffer (vm, tb->next_buffer);
	  }
      if (n_bufs_in_chain > 8)
	drop[n_drop++] = i;
    }

  if (n_drop == 0)
    return;

  drop[n_drop] = *n_pkts;
  dst = 0;
  for (u32 src = 0, k = 0; k <= n_drop; k++)
    {
      u32 n_copy = drop[k] - src;
      if (n_copy)
	{
	  if (src != dst)
	    {
	      clib_memcpy_fast (from + dst, from + src, n_copy * sizeof (from[0]));
	      clib_memcpy_fast (buffers + dst, buffers + src, n_copy * sizeof (buffers[0]));
	      clib_memcpy_fast (dma_addrs + dst, dma_addrs + src, n_copy * sizeof (dma_addrs[0]));
	      clib_memcpy_fast (desc_ctrls + dst, desc_ctrls + src,
				n_copy * sizeof (desc_ctrls[0]));
	    }
	  dst += n_copy;
	}
      if (k < n_drop)
	{
	  src = drop[k];
	  drop[k] = from[src];
	  src++;
	}
    }
  *n_pkts = dst;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
      u16 queue_id = txq->queue_id;

      for (u32 i = 0; i < n_drop; i++)
	{
	  vlib_buffer_t *tb = vlib_get_buffer (vm, drop[i]);

	  if (tb->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cdn_tx_desc_t d = {};
	      cdn_tx_trace_t *t = vlib_add_trace (vm, node, tb, sizeof (*t));

	      t->word1 = d.ctrl;
	      t->buffer_index = drop[i];
	      t->hw_if_index = hw_if_index;
	      t->queue_id = queue_id;
	    }
	}
    }

  vlib_buffer_free (vm, drop, n_drop);
  vlib_error_count (vm, node->node_index, CDN_TX_NODE_CTR_CHAIN_TOO_LONG, n_drop);
}

static_always_inline void
cdn_txq_enq_rest (vlib_main_t *vm, vnet_dev_t *dev, cdn_tx_desc_t *descs, u32 *buffer_indices,
		  u32 *from, vlib_buffer_t **buffers, uword *dma_addrs,
		  cdn_tx_desc_ctrl_t *desc_ctrls, u32 n_pkts, u16 mask, u32 *tail, u16 *n_free,
		  u32 *n_enq, u8 maybe_chained)
{
  cdn_tx_desc_ctrl_t ctrl;
  u64x2 d64;
  u32x4 v;
  u16 slot;
  int rv;

  while (*n_enq < n_pkts)
    {
      if (*n_free == 0)
	break;
      slot = *tail & mask;
      ctrl = desc_ctrls[*n_enq];
      d64 = (u64x2){
	dma_addrs[*n_enq],
	ctrl.as_u32,
      };
      v = u32x4_shuffle ((u32x4) d64, 0, 2, 1, 3);
      buffer_indices[slot] = from[*n_enq];
      descs[slot].as_u32x4 = v;
      rv = 1;
      if (maybe_chained && (buffers[*n_enq]->flags & VLIB_BUFFER_NEXT_PRESENT))
	rv = cdn_txq_enq_tail (vm, dev, mask, descs, buffer_indices, from[*n_enq], *tail, *n_free);
      if (rv == 0)
	break;
      *tail += rv;
      *n_free -= rv;
      (*n_enq)++;
    }
}

static_always_inline u32
cdn_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_t *dev, vnet_dev_tx_queue_t *txq,
	     u32 *from, u32 n_pkts)
{
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u32 *buffer_indices = ctq->buffer_indices;
  cdn_tx_desc_t *descs = ctq->descs;
  uword dma_addrs[VLIB_FRAME_SIZE];
  cdn_tx_desc_ctrl_t desc_ctrls[VLIB_FRAME_SIZE];
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u32 n_enq = 0;
  u32 n_left;
  u32 or_flags = 0;
  u16 slot, mask = txq->size - 1;
  u32 head = ctq->head;
  u32 tail = ctq->tail;
  u32 start_tail = tail;
  u16 n_free = txq->size - 1 - (tail - head);
  u32 *first_desc_ctrl = 0;
  cdn_tx_desc_ctrl_t first_ctrl;
  vlib_buffer_t **bp;
  uword *dap;
  cdn_tx_desc_ctrl_t *dcp;
  u8 do_trace = node->flags & VLIB_NODE_FLAG_TRACE;

  if (!n_pkts || !n_free)
    return 0;

  vlib_get_buffers (vm, from, b, n_pkts);
  b[n_pkts] = b[n_pkts + 1] = b[n_pkts + 2] = b[n_pkts + 3] = b[n_pkts - 1];
  bp = buffers;
  dap = dma_addrs;
  dcp = desc_ctrls;

  for (n_left = n_pkts; n_left >= 4; bp += 4, dap += 4, dcp += 4, n_left -= 4)
    {
      clib_prefetch_load (bp[4]);
      clib_prefetch_load (bp[5]);
      clib_prefetch_load (bp[6]);
      clib_prefetch_load (bp[7]);

      dap[0] = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (bp[0]));
      dap[1] = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (bp[1]));
      dap[2] = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (bp[2]));
      dap[3] = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (bp[3]));
      dcp[0] = (cdn_tx_desc_ctrl_t){
	.frm_len = bp[0]->current_length,
	.last = (bp[0]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
      };
      dcp[1] = (cdn_tx_desc_ctrl_t){
	.frm_len = bp[1]->current_length,
	.last = (bp[1]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
      };
      dcp[2] = (cdn_tx_desc_ctrl_t){
	.frm_len = bp[2]->current_length,
	.last = (bp[2]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
      };
      dcp[3] = (cdn_tx_desc_ctrl_t){
	.frm_len = bp[3]->current_length,
	.last = (bp[3]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
      };
      or_flags |= bp[0]->flags;
      or_flags |= bp[1]->flags;
      or_flags |= bp[2]->flags;
      or_flags |= bp[3]->flags;
    }

  for (; n_left; bp++, dap++, dcp++, n_left--)
    {
      dap[0] = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (bp[0]));

      dcp[0] = (cdn_tx_desc_ctrl_t){
	.frm_len = bp[0]->current_length,
	.last = (bp[0]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0,
      };

      or_flags |= bp[0]->flags;
    }

  cdn_txq_drop_too_long_chains (vm, node, txq, or_flags, from, buffers, dma_addrs, desc_ctrls,
				&n_pkts);

  if (n_pkts == 0)
    return 0;

  /* The first descriptor is published last with a release store on word 1. */
  slot = tail & mask;
  first_desc_ctrl = &descs[slot].ctrl.as_u32;
  first_ctrl = desc_ctrls[n_enq];
  first_ctrl.wrap = slot == mask;
  buffer_indices[slot] = from[n_enq];
  descs[slot].addr = dma_addrs[n_enq];
  descs[slot].addrh = dma_addrs[n_enq] >> 32;
  descs[slot].resvd = 0;
  if ((or_flags & VLIB_BUFFER_NEXT_PRESENT) && (buffers[n_enq]->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      int rv = cdn_txq_enq_tail (vm, dev, mask, descs, buffer_indices, from[n_enq], tail, n_free);
      if (rv == 0)
	return 0;
      tail += rv;
      n_free -= rv;
    }
  else
    {
      tail += 1;
      n_free -= 1;
    }
  n_enq++;

  if (PREDICT_TRUE ((or_flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    cdn_txq_enq_rest (vm, dev, descs, buffer_indices, from, buffers, dma_addrs, desc_ctrls, n_pkts,
		      mask, &tail, &n_free, &n_enq, 0);
  else
    cdn_txq_enq_rest (vm, dev, descs, buffer_indices, from, buffers, dma_addrs, desc_ctrls, n_pkts,
		      mask, &tail, &n_free, &n_enq, 1);

  if (PREDICT_FALSE (do_trace))
    {
      u32 hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
      u16 queue_id = txq->queue_id;
      u32 trace_tail = start_tail;

      for (u32 i = 0; i < n_enq; i++)
	{
	  vlib_buffer_t *b;
	  cdn_tx_desc_t d;
	  u16 n_desc = 1;

	  b = vlib_get_buffer (vm, from[i]);

	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b = vlib_get_buffer (vm, b->next_buffer);
	      n_desc++;
	    }

	  b = vlib_get_buffer (vm, from[i]);
	  if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	    {
	      trace_tail += n_desc;
	      continue;
	    }

	  d = descs[trace_tail & mask];
	  if (trace_tail == start_tail)
	    d.ctrl = first_ctrl;

	  cdn_tx_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->word1 = d.ctrl;
	  t->buffer_index = from[i];
	  t->hw_if_index = hw_if_index;
	  t->queue_id = queue_id;

	  trace_tail += n_desc;
	}
    }

  if (first_desc_ctrl)
    {
      if (descs[txq->size - 1].ctrl.wrap == 0)
	descs[txq->size - 1].ctrl.wrap = 1;
      __atomic_store_n (first_desc_ctrl, first_ctrl.as_u32, __ATOMIC_RELEASE);

      u32 *ncr = (u32 *) ((u8 *) cd->regs + CDN_NCR);
      u32 val = __atomic_load_n (ncr, __ATOMIC_RELAXED);

      __atomic_store_n (ncr, val | (1 << 9), __ATOMIC_RELAXED);
      ctq->tail = tail;
    }

  return n_enq;
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
  n_left -= n;

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n_left)
    {
      vlib_buffer_free (vm, from + n, n_left);
      vlib_error_count (vm, node->node_index, CDN_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  return frame->n_vectors - n_left;
}
