/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include "vppinfra/clib.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <ige.h>
#include <vnet/ethernet/ethernet.h>

static_always_inline void
ige_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		int use_va_dma)
{
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 n, n_want, off, n_before_wrap, size, mask, n_refill, tail;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  tail = iq->tail;
  size = rxq->size;

  n_refill = iq->head + size - tail;

  if (n_refill < 8)
    return;

  mask = size - 1;
  off = tail & mask;
  n_before_wrap = size - off;
  n_want = clib_min (n_refill, n_before_wrap);

  n = ige_rxq_refill_no_wrap (vm, iq->buffer_indices + off, iq->descs + off, n_want,
			      buffer_pool_index, use_va_dma);
  tail += n;

  if (PREDICT_FALSE (n != n_want))
    vlib_error_count (vm, node->node_index, IGE_RX_NODE_CTR_BUFFER_ALLOC, 1);
  else if (n == n_before_wrap)
    {
      n_want = n_refill - n_before_wrap;
      n = ige_rxq_refill_no_wrap (vm, iq->buffer_indices, iq->descs, n_want, buffer_pool_index,
				  use_va_dma);
      tail += n;

      if (PREDICT_FALSE (n != n_want))
	vlib_error_count (vm, node->node_index, IGE_RX_NODE_CTR_BUFFER_ALLOC, 1);
    }

  if (iq->tail != tail)
    {
      __atomic_store_n (iq->reg_rdt, tail & mask, __ATOMIC_RELEASE);
      iq->tail = tail;
    }
}

static_always_inline u32
ige_rx_deq_64_desc (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		    vlib_buffer_template_t bt, u32 *to, u32 max_pkts, u32 *n_rx_bytes, u32 *n_trace,
		    u32 *ip4_bad)
{
  u16 mask = rxq->size - 1;
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 head = iq->head;
  u16 slot = head & mask;
  ige_rx_desc_t dc[64], *descs = iq->descs, *d = descs + slot;
  u32 bc[64], *buffer_indices = iq->buffer_indices,
	      *bi = buffer_indices + slot;
  vlib_buffer_t *buffers[64];
  u32 n_descs = 0, n_pkts = 0, n_err = 0, n_drop = 0, n_drop_pkts = 0;
  u32 drop[ARRAY_LEN (dc)];

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
  while (n_descs && dc[n_descs - 1].eop == 0)
    n_descs--;

  /* advance head */
  iq->head += n_descs;

  vlib_get_buffers (vm, bc, buffers, n_descs);

  for (int i = 0; i < n_descs; i++)
    {
      u32 len = dc[i].pkt_len;
      vlib_buffer_copy_template (buffers[i], &bt);
      buffers[i]->current_length = len;
      *n_rx_bytes += len;
    }

  for (u32 i = 0, hi = 0; i < n_descs; i++)
    {
      u32 l4i = dc[i].l4i;

      if (dc[i].eop == 0)
	continue;

      buffers[hi]->flags |= l4i * VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
			    (l4i & !dc[i].l4e) * VNET_BUFFER_F_L4_CHECKSUM_CORRECT;
      *ip4_bad |= dc[i].ipv4 & (dc[i].ipcs == 0 || dc[i].ipe);
      n_err += dc[i].rxe;
      hi = i + 1;
    }

  if (n_pkts < n_descs || PREDICT_FALSE (n_err))
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
	      if (PREDICT_FALSE (dc[i].rxe))
		{
		  for (u32 j = hi; j <= i; j++)
		    drop[n_drop++] = bc[j];
		  n_drop_pkts++;
		  tlnif = 0;
		}
	      else
		{
		  to++[0] = bc[hi];
		  if (tlnif)
		    {
		      buffers[hi]->total_length_not_including_first_buffer = tlnif;
		      buffers[hi]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		      tlnif = 0;
		    }
		}
	      hi = i + 1;
	    }
	}
    }
  else
    vlib_buffer_copy_indices (to, bc, n_pkts);

  if (PREDICT_FALSE (*n_trace))
    {
      u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
      u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);

      for (u32 i = 0, n_desc; i < n_descs && *n_trace > 0; i += n_desc)
	{
	  u32 packet_length = 0;

	  n_desc = 0;
	  while (1)
	    {
	      packet_length += dc[i + n_desc].pkt_len;
	      if (dc[i + n_desc++].eop)
		break;
	    }

	  if (vlib_trace_buffer (vm, node, next_index, buffers[i], 0))
	    {
	      u32 size = sizeof (ige_rx_trace_t) + n_desc * sizeof (ige_rx_desc_t);
	      ige_rx_trace_t *tr = vlib_add_trace (vm, node, buffers[i], size);

	      tr->next_index = next_index;
	      tr->hw_if_index = hw_if_index;
	      tr->queue_id = rxq->queue_id;
	      tr->buffer_index = bc[i];
	      tr->n_desc = n_desc;
	      tr->packet_length = packet_length;
	      for (u32 j = 0; j < n_desc; j++)
		tr->desc[j] = dc[i + j];
	      (*n_trace)--;
	    }
	}
    }

  if (PREDICT_FALSE (n_drop))
    {
      vlib_buffer_free (vm, drop, n_drop);
      vlib_error_count (vm, node->node_index, IGE_RX_NODE_CTR_DESC_ERROR, n_drop_pkts);
    }

  return n_pkts - n_drop_pkts;
}

static_always_inline u32
ige_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vnet_dev_rx_queue_t *rxq)
{
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  vlib_buffer_template_t bt;
  vnet_main_t *vnm;
  u32 n_trace, sw_if_index, n_rx = 0, n_rx_bytes = 0, *to_next, n, ip4_bad = 0;
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
      n = ige_rx_deq_64_desc (vm, node, rxq, bt, to_next, 64, &n_rx_bytes, &n_trace, &ip4_bad);

      n_rx += n;

      to_next += n;
      n_left_to_next -= n;
      if (n < (64 - 3))
	goto rxq_empty;
    }

  if (n_left_to_next > 0)
    {
      n = ige_rx_deq_64_desc (vm, node, rxq, bt, to_next, n_left_to_next, &n_rx_bytes, &n_trace,
			      &ip4_bad);

      n_rx += n;

      to_next += n;
      n_left_to_next -= n;
    }

rxq_empty:

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
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
      if (ip4_bad == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);

      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vnm = vnet_get_main ();
  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  if (PREDICT_FALSE (rxq->interrupt_mode) && iq->descs[iq->head & mask].dd)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_rx;
}

VNET_DEV_NODE_FN (ige_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uint32_t rv = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_t *dev = rxq->port->dev;

      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      rv += ige_rx_one_queue (vm, node, rxq);

      /* refill RX queue */
      if (dev->va_dma)
	ige_rxq_refill (vm, node, rxq, /*use_va_dma */ 1);
      else
	ige_rxq_refill (vm, node, rxq, /*use_va_dma */ 0);

      if (PREDICT_FALSE (rxq->interrupt_mode) && iq->tail == iq->head)
	vlib_node_set_interrupt_pending (vm, node->node_index);
    }

  return rv;
}
