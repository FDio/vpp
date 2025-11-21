/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

#define ATL_RX_REFILL_THRESHOLD 8

static_always_inline u16
atl_rxq_refill_no_wrap (vlib_main_t *vm, vnet_dev_t *dev, u32 *buffer_indices, atl_rx_desc_t *descs,
			u16 n, u8 bpi)
{
  u32 n_alloc, i;

  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, n, bpi);
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);

      descs[i] = (atl_rx_desc_t){
	.buf_addr = vnet_dev_get_dma_addr (vm, dev, b->data),
      };
    }

  return n_alloc;
}

static_always_inline void
atl_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  u16 n_refill;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 tail = aq->tail;
  u16 off = tail & mask;
  u16 n_before_wrap = size - off;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u16 n;

  n_refill = aq->head + size - tail;
  if (n_refill < ATL_RX_REFILL_THRESHOLD)
    return;

  n = clib_min (n_refill, n_before_wrap);
  n = atl_rxq_refill_no_wrap (vm, dev, aq->buffer_indices + off, aq->descs + off, n, bpi);
  tail += n;

  if (n == n_before_wrap)
    {
      n = atl_rxq_refill_no_wrap (vm, dev, aq->buffer_indices, aq->descs, n_refill - n_before_wrap,
				  bpi);
      tail += n;
    }

  if (aq->tail != tail)
    {
      aq->tail = tail;
      __atomic_store_n (aq->tail_reg, tail & mask, __ATOMIC_RELEASE);
    }
}

static_always_inline uword
atl_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_main_t *vnm = vnet_get_main ();
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 buffer_indices[VLIB_FRAME_SIZE];
  u32 head_indices[VLIB_FRAME_SIZE];
  atl_rx_desc_t dc[VLIB_FRAME_SIZE];
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE];
  u32 n_descs = 0, n_pkts = 0, n_rx_bytes = 0, n_trace, n_enq = 0;
  u32 next_index, sw_if_index;
  u16 head = aq->head;
  u16 mask = rxq->size - 1;
  u16 slot = head & mask;
  u32 *to_enqueue;
  atl_rx_desc_t *descs = aq->descs;
  atl_rx_desc_t *d = descs + slot;

  while (d->dd && n_descs < VLIB_FRAME_SIZE)
    {
      dc[n_descs] = *d;
      buffer_indices[n_descs] = aq->buffer_indices[slot];
      n_pkts += d->eop;
      n_descs++;
      slot = (slot + 1) & mask;
      d = descs + slot;
    }

  if (n_pkts == 0)
    return 0;

  while (dc[n_descs - 1].eop == 0)
    n_descs--;

  aq->head = head + n_descs;

  vlib_get_buffers (vm, buffer_indices, buffers, n_descs);

  fformat (stderr, "\n");
  for (u32 i = 0; i < n_descs; i++)
    {
      buffers[i]->template = bt;
      buffers[i]->current_length = dc[i].pkt_len;
      n_rx_bytes += dc[i].pkt_len;
      fformat (stderr, "[%u] %U\n", vm->thread_index, format_hexdump, buffers[i]->data, 34);
    }

  to_enqueue = buffer_indices;

  if (n_pkts < n_descs)
    {
      to_enqueue = head_indices;
      u32 hi = 0;
      u32 tlnif = 0;
      for (u32 i = 0; i < n_descs; i++)
	{
	  if (i > hi)
	    {
	      buffers[i - 1]->next_buffer = buffer_indices[i];
	      buffers[i - 1]->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      tlnif += dc[i].pkt_len;
	    }
	  if (dc[i].eop)
	    {
	      head_indices[n_enq++] = buffer_indices[hi];
	      if (tlnif)
		{
		  buffers[hi]->total_length_not_including_first_buffer = tlnif;
		  buffers[hi]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  tlnif = 0;
		}
	      hi = i + 1;
	    }
	}
    }
  else
    n_enq = n_pkts;

  next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);

  n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace))
    {
      for (u32 i = 0; i < n_descs && n_trace > 0; i++)
	{
	  vlib_buffer_t *b = buffers[i];

	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, 0)))
	    {
	      atl_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->sw_if_index = sw_if_index;
	      tr->queue_id = rxq->queue_id;
	      tr->buffer_index = buffer_indices[i];
	      tr->desc = dc[i];
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_buffer_enqueue_to_single_next (vm, node, to_enqueue, next_index, n_enq);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_enq, n_rx_bytes);

  aq->stats_rx_packets += n_enq;
  aq->stats_rx_bytes += n_rx_bytes;

  return n_enq;
}

VNET_DEV_NODE_FN (atl_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += atl_rx_one_queue (vm, node, rxq);
      atl_rxq_refill (vm, rxq);
    }

  return n_rx;
}
