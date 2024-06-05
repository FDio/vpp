/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
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

#include <dev_ige/ige.h>

static_always_inline void
ige_enq_tx_desc (vlib_main_t *vm, vlib_buffer_t *b, int first, int last,
		 ige_tx_desc_t *descs, u16 *tail, u16 mask, int use_va)
{
  u32 len = b->current_length;
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

  descs[*tail & mask] = d;
  (*tail)++;
}

static_always_inline u32
ige_txq_enq_no_wrap (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vnet_dev_tx_queue_t *txq, u32 *from, u32 max_pkts,
		     int use_va)
{
  ige_txq_t *const itq = vnet_dev_get_tx_queue_data (txq);
  ige_tx_desc_t *const descs = itq->descs;
  const u16 size = txq->size;
  const u16 mask = size - 1;
  const u16 max_tail = itq->head + size;
  u16 tail = itq->tail;
  u16 n_pkts = 0;
  u32 drop_too_long[VLIB_FRAME_SIZE], n_drop_too_long = 0;

  while (n_pkts < max_pkts && tail < max_tail)
    {
      u32 bi = from[n_pkts];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);

      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  u32 indices[5] = {
	    [0] = bi,
	    [1] = b->next_buffer,
	  };
	  vlib_buffer_t *bufs[5] = {
	    [0] = b,
	    [1] = vlib_get_buffer (vm, b->next_buffer),
	  };
	  u32 n = 1;

	  while (bufs[n]->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      n++;
	      if (n >= ARRAY_LEN (indices))
		{
		  drop_too_long[n_drop_too_long++] = bi;
		  goto next;
		}
	      indices[n] = bufs[n - 1]->next_buffer;
	      bufs[n] = vlib_get_buffer (vm, indices[n]);
	    }

	  if (tail + n + 1 > max_tail)
	    break;

	  ige_enq_tx_desc (vm, bufs[0], 1, 0, descs, &tail, mask, use_va);
	  for (int i = 1; i < n; i++)
	    ige_enq_tx_desc (vm, bufs[i], 0, 0, descs, &tail, mask, use_va);
	  ige_enq_tx_desc (vm, bufs[n], 0, 1, descs, &tail, mask, use_va);
	}
      else
	ige_enq_tx_desc (vm, b, 1, 1, descs, &tail, mask, use_va);

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
      if (dev->va_dma)
	n = ige_txq_enq_no_wrap (vm, node, txq, from, n_left, 1);
      else
	n = ige_txq_enq_no_wrap (vm, node, txq, from, n_left, 0);

      if (n == 0 || n == n_left)
	break;

      from += n;
      n_left -= n;
    }

  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_NO_FREE_SLOTS,
			n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
