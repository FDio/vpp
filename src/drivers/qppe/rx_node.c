/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vlib/buffer_funcs.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "rx",
};

static_always_inline u32
qppe_rx_find_buffer_slot (qppe_rxq_t *qr, u32 ring_size, u32 buffer_index)
{
  u32 i;

  for (i = 0; i < ring_size; i++)
    if (qr->buffer_indices[i] == buffer_index)
      return i;

  return ~0;
}

static_always_inline u32
qppe_rx_dequeue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *packet_indices, u32 max_packets,
		 u32 *n_rx_bytes)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_PROD_IDX (qr->desc_ring_id);
  u32 hw_prod = qppe_mmio_read32 (qd, offset) & PPE_EDMA_RX_PROD_CONS_MASK;
  u32 n_rx = 0;

  while (qr->desc_cons != hw_prod && n_rx < max_packets)
    {
      u32 slot = qr->desc_cons & (rxq->size - 1);
      ppe_edma_rx_desc_t desc = qr->primary_descs[slot];
      u32 buffer_index = desc.opaque_low.fields.opaque_low;
      u32 buffer_slot;
      vlib_buffer_t *buffer;
      u32 len = desc.packet_length.fields.packet_length;
      vnet_dev_port_t *source_port;
      u32 sw_if_index;

      qr->desc_cons++;
      buffer_slot = qppe_rx_find_buffer_slot (qr, rxq->size, buffer_index);
      if (buffer_slot == ~0)
	{
	  log_warn (dev, "RX descriptor ring %u slot %u returned unknown buffer index %u",
		    qr->desc_ring_id, slot, buffer_index);
	  continue;
	}

      qr->buffer_indices[buffer_slot] = ~0;
      ASSERT (qr->n_buffers > 0);
      qr->n_buffers--;

      source_port =
	desc.source_destination_info.fields.source_type == PPE_EDMA_RX_SOURCE_TYPE_PORT_ID ?
	  vnet_dev_get_port_by_id (dev, desc.source_destination_info.fields.source_port_id) :
	  0;
      if (!source_port || !source_port->interfaces)
	{
	  log_warn (dev,
		    "dropping RX descriptor ring %u slot %u: invalid source port type %u id %u",
		    qr->desc_ring_id, slot, desc.source_destination_info.fields.source_type,
		    desc.source_destination_info.fields.source_port_id);
	  vlib_buffer_free (vm, &buffer_index, 1);
	  continue;
	}
      sw_if_index = source_port->interfaces->primary_interface.sw_if_index;

      if (desc.word1.fields.more || len == 0 || len > PPE_EDMA_RX_BUFFER_SIZE)
	{
	  log_warn (dev, "dropping RX descriptor ring %u slot %u: buffer %u, length %u, more %u",
		    qr->desc_ring_id, slot, buffer_index, len, desc.word1.fields.more);
	  vlib_buffer_free (vm, &buffer_index, 1);
	  continue;
	}

      buffer = vlib_get_buffer (vm, buffer_index);
      vlib_buffer_copy_template (buffer, &bt);
      buffer->current_data = desc.data_offset.fields.data_offset;
      buffer->current_length = len;
      vnet_buffer (buffer)->sw_if_index[VLIB_RX] = sw_if_index;
      packet_indices[n_rx++] = buffer_index;
      *n_rx_bytes += len;

      if (!qr->first_packet_received)
	{
	  qr->first_packet_received = 1;
	  fformat (stderr, "Packet received!!!!\n");
	}
    }

  if (qr->desc_cons)
    {
      offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CONS_IDX (qr->desc_ring_id);
      qppe_mmio_write32 (qd, offset, qr->desc_cons & PPE_EDMA_RX_PROD_CONS_MASK);
    }

  return n_rx;
}

static_always_inline void
qppe_rx_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 indices[64];
  u32 n_refill = 0;
  u32 shortage;

  ASSERT (qr->n_buffers <= rxq->size - 1);
  shortage = rxq->size - 1 - qr->n_buffers;

  while (shortage)
    {
      u32 n_alloc = clib_min (shortage, ARRAY_LEN (indices));
      u32 n_allocated = vlib_buffer_alloc_from_pool (vm, indices, n_alloc, qr->buffer_pool_index);
      u32 i, n_added = 0;

      if (n_allocated == 0)
	{
	  log_warn (dev, "RX queue %u refill short by %u buffers; will retry on next poll",
		    rxq->queue_id, shortage);
	  break;
	}

      for (i = 0; i < n_allocated; i++)
	{
	  u32 buffer_index = indices[i];
	  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
	  uword buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);
	  u32 tries;

	  if (buffer_dma > 0xffffffff)
	    {
	      log_err (dev, "RX refill buffer %u DMA address 0x%lx exceeds 32-bit EDMA address",
		       buffer_index, buffer_dma);
	      vlib_buffer_free (vm, &buffer_index, 1);
	      continue;
	    }

	  for (tries = 0; tries < rxq->size; tries++)
	    {
	      u32 buffer_slot = qr->fill_prod;
	      ppe_edma_rxfill_desc_t *desc;

	      qr->fill_prod = (qr->fill_prod + 1) & (rxq->size - 1);
	      if (qr->buffer_indices[buffer_slot] != ~0)
		continue;

	      qr->buffer_indices[buffer_slot] = buffer_index;
	      desc = &qr->fill_descs[buffer_slot];
	      desc->buffer_address.fields.buffer_address = buffer_dma;
	      desc->length.fields.buffer_size = PPE_EDMA_RX_BUFFER_SIZE;
	      desc->opaque_low = buffer_index;
	      desc->opaque_high = 0;
	      qr->n_buffers++;
	      shortage--;
	      n_refill++;
	      n_added++;
	      break;
	    }

	  if (tries == rxq->size)
	    {
	      log_err (dev, "RX queue %u has no empty fill descriptor slot", rxq->queue_id);
	      break;
	    }
	}

      if (i < n_allocated)
	vlib_buffer_free (vm, indices + i, n_allocated - i);

      if (n_added < n_allocated)
	break;

      if (n_allocated < n_alloc)
	{
	  log_warn (dev, "RX queue %u refill allocated %u of %u requested buffers", rxq->queue_id,
		    n_allocated, n_alloc);
	  break;
	}
    }

  if (n_refill)
    {
      u32 offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_PROD_IDX (qr->fill_ring_id);

      __atomic_thread_fence (__ATOMIC_RELEASE);
      qppe_mmio_write32 (qd, offset, qr->fill_prod);
      log_debug (dev, "refilled RX queue %u with %u buffers on fill ring %u; producer %u, %u owned",
		 rxq->queue_id, n_refill, qr->fill_ring_id, qr->fill_prod, qr->n_buffers);
    }
}

static_always_inline u32
qppe_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_rx_queue_t *ring_rxq = qd->rxq_owner;
  qppe_rxq_t *qr = ring_rxq ? vnet_dev_get_rx_queue_data (ring_rxq) : 0;
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 packet_indices[VLIB_FRAME_SIZE];
  u32 n_rx_bytes = 0;
  u32 n_rx;
  u32 *to_next;
  uword n_left_to_next;

  if (!ring_rxq || !qr || !qr->started)
    return 0;

  clib_spinlock_lock (&qd->rx_poll_lock);
  n_rx = qppe_rx_dequeue (vm, ring_rxq, packet_indices, ARRAY_LEN (packet_indices), &n_rx_bytes);
  qppe_rx_refill (vm, ring_rxq);
  clib_spinlock_unlock (&qd->rx_poll_lock);

  if (n_rx)
    {
      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
      ASSERT (n_left_to_next >= n_rx);
      clib_memcpy_fast (to_next, packet_indices, n_rx * sizeof (u32));

      if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
	{
	  vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
	  f->flags = 0;
	  vlib_frame_no_append (f);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx);
    }

  if (n_rx)
    log_debug (dev, "RX queue %u delivered %u packets and %u bytes from shared EDMA ring %u",
	       rxq->queue_id, n_rx, n_rx_bytes, qr->desc_ring_id);
  return n_rx;
}

VNET_DEV_NODE_FN (qppe_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    rv += qppe_rx_one_queue (vm, node, rxq);

  return rv;
}
