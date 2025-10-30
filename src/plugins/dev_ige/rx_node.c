/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include "vppinfra/clib.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>

static_always_inline void
ige_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, int use_va_dma)
{
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 n, off, n_before_wrap, size, mask, n_refill, tail;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  tail = iq->tail;
  size = rxq->size;

  n_refill = iq->head + size - tail;

  if (n_refill < 8)
    return;

  mask = size - 1;
  off = tail & mask;
  n_before_wrap = size - off;
  n = clib_min (n_refill, n_before_wrap);

  n = ige_rxq_refill_no_wrap (vm, iq->buffer_indices + off, iq->descs + off, n,
			      buffer_pool_index, use_va_dma);
  tail += n;

  if (n == n_before_wrap)
    tail += ige_rxq_refill_no_wrap (vm, iq->buffer_indices, iq->descs,
				    n_refill - n_before_wrap,
				    buffer_pool_index, use_va_dma);

  if (iq->tail != tail)
    {
      __atomic_store_n (iq->reg_rdt, tail & mask, __ATOMIC_RELEASE);
      iq->tail = tail;
    }
}

static_always_inline u32
ige_rx_deq_64_desc (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vnet_dev_rx_queue_t *rxq, vlib_buffer_template_t bt,
		    u32 *to, u32 max_pkts, u32 *n_rx_bytes, u32 *n_trace)
{
  u16 mask = rxq->size - 1;
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 head = iq->head;
  u16 slot = head & mask;
  ige_rx_desc_t dc[64], *descs = iq->descs, *d = descs + slot;
  u32 bc[64], *buffer_indices = iq->buffer_indices,
	      *bi = buffer_indices + slot;
  vlib_buffer_t *buffers[64];
  u32 n_descs = 0, n_pkts = 0;

  while (d->dd && n_descs < ARRAY_LEN (dc) && n_pkts < max_pkts)
    {
      dc[n_descs] = *d;
      bc[n_descs] = *bi;
      n_pkts += d->eop;
      n_descs++;
      slot = (slot + 1) & mask;
      d = descs + slot;
      bi = buffer_indices + slot;
    }

  if (n_pkts == 0)
    return 0;

  /* remove descriptors from incomplete packets */
  while (dc[n_descs - 1].eop == 0)
    n_descs--;

  /* advance head */
  iq->head += n_descs;

  vlib_get_buffers (vm, bc, buffers, n_descs);

  for (int i = 0; i < n_descs; i++)
    {
      u32 len = dc[i].pkt_len;
      buffers[i]->template = bt;
      buffers[i]->current_length = len;
      *n_rx_bytes += len;
    }

  if (n_pkts < n_descs)
    {
      u32 hi = 0;    /* head index */
      u32 tlnif = 0; /* total length not including first buffer */

      for (int i = 0; i < n_descs; i++)
	{
	  if (i > hi)
	    {
	      buffers[i - 1]->next_buffer = bc[i];
	      buffers[i - 1]->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      tlnif += dc[i].pkt_len;
	    }
	  if (dc[i].eop)
	    {
	      to++[0] = bc[hi];
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
    vlib_buffer_copy_indices (to, bc, n_pkts);

  if (PREDICT_FALSE (*n_trace))
    for (u32 i = 0; i<n_descs && * n_trace> 0; i++)
      {
	vlib_buffer_t *b = buffers[i];
	u32 next_index, hw_if_index;

	if (b == 0)
	  continue;

	next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
	hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);

	if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, 0)))
	  {
	    ige_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	    tr->next_index = next_index;
	    tr->hw_if_index = hw_if_index;
	    tr->queue_id = rxq->queue_id;
	    tr->buffer_index = bc[i];
	    tr->desc = dc[i];
	    (*n_trace)--;
	  }
      }

  return n_pkts;
}

static_always_inline u32
ige_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vnet_dev_rx_queue_t *rxq)
{
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  vlib_buffer_template_t bt;
  vnet_main_t *vnm;
  u32 n_trace, sw_if_index, n_rx = 0, n_rx_bytes = 0, *to_next, n;
  uword n_left_to_next;
  u16 mask = rxq->size - 1;
  u16 slot = iq->head & mask;
  ige_rx_desc_t *d = iq->descs + slot;

  if (d->dd == 0)
    return 0;

  while (d->eop == 0)
    {
      slot = (slot + 1) & mask;
      d = iq->descs + slot;
      if (d->dd == 0)
	return 0;
    }

  bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  n_trace = vlib_get_trace_count (vm, node);

  while (n_left_to_next >= 64)
    {
      n = ige_rx_deq_64_desc (vm, node, rxq, bt, to_next, 64, &n_rx_bytes,
			      &n_trace);

      n_rx += n;

      to_next += n;
      n_left_to_next -= n;
      if (n < (64 - 3))
	goto rxq_empty;
    }

  if (n_left_to_next > 0)
    {
      n = ige_rx_deq_64_desc (vm, node, rxq, bt, to_next, n_left_to_next,
			      &n_rx_bytes, &n_trace);

      n_rx += n;

      to_next += n;
      n_left_to_next -= n;
    }

rxq_empty:

  vlib_set_trace_count (vm, node, n_trace);
  sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);

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
      ef->hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);

      // if ((or_qw1 & mask_ipe.as_u64) == 0) f->flags |=
      // ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vnm = vnet_get_main ();
  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  return n_rx;
}

VNET_DEV_NODE_FN (ige_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uint32_t rv = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_t *dev = rxq->port->dev;

      rv += ige_rx_one_queue (vm, node, rxq);

      /* refill RX queue */
      if (dev->va_dma)
	ige_rxq_refill (vm, rxq, /*use_va_dma */ 1);
      else
	ige_rxq_refill (vm, rxq, /*use_va_dma */ 0);
    }

  return rv;
}
