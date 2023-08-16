/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/clib.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>

static_always_inline u16
ige_rxq_refill_no_wrap (vlib_main_t *vm, u32 *buffer_indices,
			ige_rx_desc_t *descs, u16 n_refill,
			u8 buffer_pool_index, int use_va_dma)
{
  u16 n_alloc;
  vlib_buffer_t *b;
  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, n_refill,
					 buffer_pool_index);
  if (use_va_dma)
    for (u32 i = 0; i < n_alloc; i++)
      {
	b = vlib_get_buffer (vm, buffer_indices[i]);
	descs[i].pkt_addr = vlib_buffer_get_va (b);
	descs[i].hdr_addr = 0;
      }
  else
    for (u32 i = 0; i < n_alloc; i++)
      {
	b = vlib_get_buffer (vm, buffer_indices[i]);
	descs[i].pkt_addr = vlib_buffer_get_pa (vm, b);
	descs[i].hdr_addr = 0;
      }
  return n_alloc;
}
static_always_inline void
ige_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, int use_va_dma)
{
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 n, first, n_before_wrap, size, mask, n_refill, tail;
  u8 buffer_pool_index;

  tail = iq->tail;
  size = rxq->size;
  n_refill = size - (tail - iq->head);

  if (n_refill < 8)
    return;

  mask = size - 1;
  first = tail & mask;
  n_before_wrap = size - first;
  buffer_pool_index = rxq->buffer_pool_index;

  if (PREDICT_TRUE (n_refill <= n_before_wrap))
    {
      n = ige_rxq_refill_no_wrap (vm, iq->buffer_indices + first,
				  iq->descs + first, n_refill,
				  buffer_pool_index, use_va_dma);
      tail += n;
    }
  else
    {
      n = ige_rxq_refill_no_wrap (vm, iq->buffer_indices + first,
				  iq->descs + first, n_before_wrap,
				  buffer_pool_index, use_va_dma);

      tail += n;

      if (n == n_before_wrap)
	{
	  tail += ige_rxq_refill_no_wrap (vm, iq->buffer_indices, iq->descs,
					  n_refill - n_before_wrap,
					  buffer_pool_index, use_va_dma);
	}
    }

  if (iq->tail != tail)
    {
      __atomic_store_n (iq->reg_rdt, tail, __ATOMIC_RELEASE);
      iq->tail = tail;
    }
}

VNET_DEV_NODE_FN (ige_rx_node_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vnet_dev_t *dev = rxq->port->dev;
      ige_rx_desc_t *d = iq->descs + iq->head;

      if (d->hdr_addr)
	{
	  vlib_buffer_t *b =
	    vlib_get_buffer (vm, iq->buffer_indices[iq->head]);
	  if (0)
	    {
	      fformat (stderr,
		       "%u: queue_id %u head %u tail %u rss_type %u "
		       "packet_type %u pkt_len %u status %x err %x sph %u "
		       "hdr_len %u\n",
		       vm->thread_index, rxq->queue_id, iq->head, iq->tail,
		       d->rss_type, d->packet_type, d->pkt_len, d->ext_status,
		       d->ext_error, d->sph,
		       d->hdr_len_lo | d->hdr_len_hi << 10);
	      fformat (stderr, "%U\n", format_hexdump, b->data, d->pkt_len);
	    }
	  iq->head++;
	}

      /* refill RX queue */
      if (dev->va_dma)
	ige_rxq_refill (vm, rxq, /*use_va_dma */ 1);
      else
	ige_rxq_refill (vm, rxq, /*use_va_dma */ 0);
    }
  return 0;
}
