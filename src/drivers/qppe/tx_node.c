/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>

/* tmpl is the queue's desc_template, loaded once by the caller instead of
 * being re-read from tq for every descriptor. Passed by value, so it's
 * just a pair of 128-bit register copies. */
static_always_inline void
qppe_tx_fill_desc (edma_tx_desc_t *d, vlib_main_t *vm, vnet_dev_t *dev, edma_tx_desc_t tmpl,
		   vlib_buffer_t *b, int last, u32 head_buffer_index)
{
  edma_tx_desc_t td = tmpl;

  qppe_dma_cache_clean (vlib_buffer_get_current (b), b->current_length);

  td.buffer_address = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (b));
  td.data_length = b->current_length;
  td.more = last ? 0 : 1;
  td.opaque_low = last ? head_buffer_index : 0;

  d->v128[0] = td.v128[0];
  d->v128[1] = td.v128[1];
}

/* number of additional (chained) buffers following 'b', i.e. the number of
 * extra TX descriptors its packet needs beyond the first. */
static_always_inline u32
qppe_tx_chain_len (vlib_main_t *vm, vlib_buffer_t *b)
{
  u32 n = 0;

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      n++;
    }

  return n;
}

/* final stage, only entered when tracing is active: re-walks the descriptors
 * just written (still intact in the ring) to add one trace record per
 * packet in from[0..n_tx), using each descriptor's 'more' bit (set on every
 * descriptor but a chain's last) to find packet boundaries, the same way the
 * RX node's trace stage uses it to find RX chain boundaries. */
static_always_inline void
qppe_tx_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq,
		     edma_tx_desc_t *desc_ring, u32 mask, u16 prod_start, u32 n_desc, u32 *from,
		     u32 n_tx)
{
  u32 hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
  u32 i = 0;
  u32 pkt = 0;

  while (i < n_desc && pkt < n_tx)
    {
      u32 slot = (prod_start + i) & mask;
      edma_tx_desc_t head_desc = desc_ring[slot];
      vlib_buffer_t *b = vlib_get_buffer (vm, from[pkt]);
      u16 n_pkt_descs = 1;

      i++;
      while (desc_ring[slot].more)
	{
	  slot = (prod_start + i) & mask;
	  i++;
	  n_pkt_descs++;
	}

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  qppe_tx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

	  *tr = (qppe_tx_trace_t) {
	    .hw_if_index = hw_if_index,
	    .buffer_index = from[pkt],
	    .queue_id = txq->queue_id,
	    .n_descs = n_pkt_descs,
	    .desc = head_desc,
	  };
	}

      pkt++;
    }
}

/* reaps completed TX descriptors from the completion ring and frees the
 * buffer chain each one carried. A completion entry with 'more' set is a
 * non-last fragment of a chain and carries no opaque value to free. */
static_always_inline void
qppe_tx_reap (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  const u32 mask = txq->size - 1;
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  edma_txcmpl_desc_t *cmpl_ring = tq->cmpl_descs;
  u16 cmpl_cons = tq->cmpl_cons;
  u32 hw_prod = qppe_mmio_read32 (qd, tq->txcmpl_prod_offset) & EDMA_TX_PROD_CONS_MASK;
  u32 n_avail = (hw_prod - cmpl_cons) & mask;
  u32 to_free[VLIB_FRAME_SIZE];
  u32 n_free = 0;
  u32 i;

  for (i = 0; i < n_avail; i++)
    {
      edma_txcmpl_desc_t c = cmpl_ring[cmpl_cons & mask];

      cmpl_cons++;
      if (c.more)
	continue;

      if (n_free == ARRAY_LEN (to_free))
	{
	  vlib_buffer_free (vm, to_free, n_free);
	  n_free = 0;
	}
      to_free[n_free++] = c.opaque_low;
    }

  if (n_free)
    vlib_buffer_free (vm, to_free, n_free);

  if (n_avail)
    {
      tq->cmpl_cons = cmpl_cons;
      qppe_mmio_write32 (qd, tq->txcmpl_cons_offset, cmpl_cons & mask);
    }
}

static_always_inline u32
qppe_tx_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
		 u32 n_left)
{
  const u32 mask = txq->size - 1;
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  edma_tx_desc_t *desc_ring = tq->descs;
  edma_tx_desc_t tmpl = tq->desc_template;
  u16 prod_start = tq->prod;
  u16 prod = prod_start;
  u32 avail_desc = tq->avail_desc;
  u32 drop[VLIB_FRAME_SIZE];
  u32 n_drop = 0;
  u32 n_tx = 0;

  while (n_tx < n_left)
    {
      u32 bi = from[n_tx];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      u32 n_frags = qppe_tx_chain_len (vm, b);
      u32 n_descs_needed = n_frags + 1;

      if (PREDICT_FALSE (n_frags >= QPPE_MAX_TX_CHAIN_LEN))
	{
	  drop[n_drop++] = bi;
	  n_tx++;
	  continue;
	}

      if (avail_desc < n_descs_needed)
	{
	  /* the hardware never lets the producer index catch up with the
	   * consumer index on a full ring, so one slot always stays empty. */
	  u32 hw_cons = qppe_mmio_read32 (qd, tq->txdesc_cons_offset) & EDMA_TX_PROD_CONS_MASK;
	  avail_desc = (hw_cons - 1 - prod) & mask;
	  if (avail_desc < n_descs_needed)
	    break;
	}

      {
	vlib_buffer_t *cur = b;
	u32 i;

	for (i = 0; i < n_descs_needed; i++)
	  {
	    int last = i == n_descs_needed - 1;

	    qppe_tx_fill_desc (&desc_ring[prod & mask], vm, dev, tmpl, cur, last, bi);
	    prod++;
	    if (!last)
	      cur = vlib_get_buffer (vm, cur->next_buffer);
	  }
      }

      avail_desc -= n_descs_needed;
      n_tx++;
    }

  if (n_drop)
    {
      vlib_error_count (vm, node->node_index, QPPE_TX_NODE_CTR_BUFFER_CHAIN_TOO_LONG, n_drop);
      vlib_buffer_free (vm, drop, n_drop);
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    qppe_tx_trace_frame (vm, node, txq, desc_ring, mask, prod_start, prod - prod_start, from, n_tx);

  tq->prod = prod;
  tq->avail_desc = avail_desc;

  if (prod != prod_start)
    {
      asm volatile ("dsb osh" : : : "memory");
      qppe_mmio_write32 (qd, tq->txdesc_prod_offset, prod & mask);
    }

  return n_tx;
}

VNET_DEV_NODE_FN (qppe_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  int n_retries = 2;

  vnet_dev_tx_queue_lock_if_needed (txq);

  qppe_tx_reap (vm, txq);

  while (n_retries--)
    {
      u32 n_tx = qppe_tx_enqueue (vm, node, txq, from, n_left);

      from += n_tx;
      n_left -= n_tx;

      if (n_tx == 0 || n_left == 0)
	break;

      qppe_tx_reap (vm, txq);
    }

  if (n_left)
    {
      vlib_error_count (vm, node->node_index, QPPE_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
      vlib_buffer_free (vm, from, n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
