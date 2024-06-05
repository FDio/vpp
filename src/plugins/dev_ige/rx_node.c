/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/clib.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
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
      __atomic_store_n (iq->reg_rdt, tail, __ATOMIC_RELEASE);
      iq->tail = tail;
    }
}

VNET_DEV_NODE_FN (ige_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vnet_dev_t *dev = rxq->port->dev;
      u16 mask = rxq->size - 1;
      u16 slot = iq->head & mask;
      ige_rx_desc_t *d = iq->descs + slot;

      if (d->hdr_addr)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, iq->buffer_indices[slot]);
	  if (1)
	    {
	      fformat (stderr, "%u: queue_id %u head %u tail %u %U\n",
		       vm->thread_index, rxq->queue_id, iq->head, iq->tail,
		       format_ige_rx_desc, d);
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
