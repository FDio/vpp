/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <ige.h>

static_always_inline void
ige_enq_txd (vlib_main_t *vm, vlib_node_runtime_t *n, vnet_dev_tx_queue_t *txq,
	     vlib_buffer_t *b, u32 bi, int first, int last,
	     ige_tx_desc_t *descs, u32 *buffer_indices, u16 *tail, u16 mask,
	     int use_va, int trace)
{
  u32 len = b->current_length;
  u32 slot = *tail & mask;
  ige_tx_desc_t d = {
    .eop = last ? 1 : 0,
    .rs = last ? 1 : 0,
    .ifcs = 1,
    .dtyp = 0b0011,
    .dtalen = len,
  };
  d.addr = use_va ? vlib_buffer_get_current_va (b) :
		    vlib_buffer_get_current_pa (vm, b);
  if (first)
    d.paylen = last ? len : len + b->total_length_not_including_first_buffer;

  if (trace && b->flags & VLIB_BUFFER_IS_TRACED)
    {
      ige_tx_trace_t *t = vlib_add_trace (vm, n, b, sizeof (*t));
      t->desc = d;
      t->hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
      t->queue_id = txq->queue_id;
      t->buffer_index = bi;
    }

  descs[slot] = d;
  buffer_indices[slot] = bi;
  (*tail)++;
}

static_always_inline void
ige_txq_complete (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);

  u16 head = itq->head;
  u16 tail = itq->tail;
  u16 n_free;

  if (head == tail)
    return;

  u32 new_head = __atomic_load_n (itq->wb, __ATOMIC_ACQUIRE);
  u16 mask = txq->size - 1;
  n_free = (new_head - head) & mask;
  n_free &= 0xfff0;

  if (!n_free)
    return;

  vlib_buffer_free_from_ring_no_next (vm, itq->buffer_indices, head & mask,
				      txq->size, n_free);

  itq->head = head + n_free;
}

static_always_inline u32
ige_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node,
	     vnet_dev_tx_queue_t *txq, u32 *from, u32 max_pkts, int va, int tr)
{
  ige_txq_t *const itq = vnet_dev_get_tx_queue_data (txq);
  ige_tx_desc_t *const d = itq->descs;
  u32 *const bi = itq->buffer_indices;
  const u16 size = txq->size;
  const u16 mask = size - 1;
  u16 n_pkts = 0;
  u32 drop_too_long[VLIB_FRAME_SIZE], n_drop_too_long = 0;

  ige_txq_complete (vm, txq);

  u16 head = itq->head;
  u16 tail = itq->tail;
  const u32 max_tail = head + size;

  while (n_pkts < max_pkts && tail < max_tail)
    {
      u32 hbi = from[n_pkts];
      vlib_buffer_t *b = vlib_get_buffer (vm, hbi);
      u32 i;

      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  u32 tbi[4] = {
	    [0] = b->next_buffer,
	  };
	  vlib_buffer_t *tb[4] = {
	    [0] = vlib_get_buffer (vm, b->next_buffer),
	  };
	  u32 n = 1;

	  while (tb[n - 1]->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      if (n >= ARRAY_LEN (tbi))
		{
		  drop_too_long[n_drop_too_long++] = hbi;
		  goto next;
		}

	      tbi[n] = tb[n - 1]->next_buffer;
	      tb[n] = vlib_get_buffer (vm, tbi[n]);
	      n++;
	    }

	  if (tail + n + 1 > max_tail)
	    break;

	  ige_enq_txd (vm, node, txq, b, hbi, 1, 0, d, bi, &tail, mask, va,
		       tr);
	  for (i = 0; i + 1 < n; i++)
	    ige_enq_txd (vm, node, txq, tb[i], tbi[i], 0, 0, d, bi, &tail,
			 mask, va, tr);
	  ige_enq_txd (vm, node, txq, tb[i], tbi[i], 0, 1, d, bi, &tail, mask,
		       va, tr);
	}
      else
	ige_enq_txd (vm, node, txq, b, hbi, 1, 1, d, bi, &tail, mask, va, tr);

    next:
      n_pkts++;
    }

  if (n_drop_too_long)
    {
      vlib_error_count (vm, node->node_index,
			IGE_TX_NODE_CTR_BUFFER_CHAIN_TOO_LONG,
			n_drop_too_long);
      vlib_buffer_free (vm, drop_too_long, n_drop_too_long);
    }

  if (itq->tail != tail)
    {
      __atomic_store_n (itq->reg_tdt, tail & mask, __ATOMIC_RELEASE);
      itq->tail = tail;
    }

  return n_pkts;
}

VNET_DEV_NODE_FN (ige_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  u32 *from = vlib_frame_vector_args (frame);
  u16 n, n_left;
  int n_reties = 2;

  n_left = frame->n_vectors;

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_reties--)
    {
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	n = ige_txq_enq (vm, node, txq, from, n_left, dev->va_dma != 0, 1);
      else if (dev->va_dma)
	n = ige_txq_enq (vm, node, txq, from, n_left, 1, 0);
      else
	n = ige_txq_enq (vm, node, txq, from, n_left, 0, 0);

      from += n;
      n_left -= n;

      if (n == 0 || n == n_left)
	break;
    }

  if (n_left)
    {
      fformat (stderr, "no_free_slots %u\n", n_left);
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_NO_FREE_SLOTS,
			n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
