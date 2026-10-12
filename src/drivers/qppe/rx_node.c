/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vlib/buffer_funcs.h>
#include <qppe.h>

#define RX_REFILL_BATCH_SZ 32

static_always_inline u32
qppe_rx_dequeue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *packet_indices, u32 max_packets)
{
  const u32 ring_size = rxq->size;
  const u32 mask = ring_size - 1;
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 *buffer_indices = qr->buffer_indices;
  ppe_edma_rx_desc_t *desc_ring = qr->primary_descs;
  u16 desc_cons = qr->desc_cons;
  u32 n_buffers = qr->n_buffers;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 offset = qr->rxdesc_offset;
  u32 hw_prod = qppe_mmio_read32 (qd, offset) & PPE_EDMA_RX_PROD_CONS_MASK;
  u32 n_rx = 0;
  u32 n_desc = 0;
  u32 n_desc_available = (hw_prod - desc_cons) & mask;

  while (n_desc < n_desc_available && n_rx < max_packets)
    {
      u32 slot = desc_cons & mask;
      ppe_edma_rx_desc_t desc = desc_ring[slot];
      u32 buffer_index = desc.opaque_low;
      u32 buffer_slot = desc.opaque_high;
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
      u32 len = desc.packet_length;
      u32 data_offset = desc.data_offset;

      desc_cons++;
      n_desc++;

      ASSERT (buffer_slot < ring_size);
      ASSERT (buffer_indices[buffer_slot] == buffer_index);
      ASSERT (n_buffers > 0);
      n_buffers--;

      ASSERT (desc.source_type == PPE_EDMA_RX_SOURCE_TYPE_PORT_ID);
      ASSERT (desc.source_port_id == rxq->port->port_id);
      ASSERT (!desc.more);

      vlib_buffer_copy_template (b, &bt);
      b->current_data = data_offset;
      b->current_length = len;
      packet_indices[n_rx++] = buffer_index;
    }

  qr->desc_cons = desc_cons;
  qr->n_buffers = n_buffers;

  if (n_desc)
    qppe_mmio_write32 (qd, qr->rxdesc_cons_offset, desc_cons & mask);

  return n_rx;
}

static_always_inline void
qppe_rx_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 node_index)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 ring_size = rxq->size;
  u32 *buffer_indices = qr->buffer_indices;
  ppe_edma_rxfill_desc_t *fill_descs = qr->fill_descs;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u16 fill_prod = qr->fill_prod;
  u32 shortage = ring_size - qr->n_buffers;

  for (; shortage >= RX_REFILL_BATCH_SZ; shortage -= RX_REFILL_BATCH_SZ)
    {
      u32 fill_slot = fill_prod;

      if (!vlib_buffer_strict_alloc_from_pool (vm, buffer_indices + fill_slot, RX_REFILL_BATCH_SZ,
					       buffer_pool_index))
	{
	  vlib_error_count (vm, node_index, QPPE_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      for (u32 i = 0; i < RX_REFILL_BATCH_SZ; i++)
	{
	  u32 slot = fill_slot + i;
	  u32 buffer_index = buffer_indices[slot];
	  ppe_edma_rxfill_desc_t *desc = fill_descs + slot;
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
	  desc->buffer_address = vnet_dev_get_dma_addr (vm, dev, b->data);
	  desc->opaque_low = buffer_index;
	}

      fill_prod += RX_REFILL_BATCH_SZ;
      if (fill_prod == ring_size)
	fill_prod = 0;
    }

  if (fill_prod != qr->fill_prod)
    qppe_mmio_write32 (qd, qr->rxfill_prod_offset, fill_prod);

  qr->fill_prod = fill_prod;
  qr->n_buffers = ring_size - shortage;
}

static_always_inline u32
qppe_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 packet_indices[VLIB_FRAME_SIZE];
  u32 n_rx;
  u32 *to_next;
  uword n_left_to_next;

  n_rx = qppe_rx_dequeue (vm, rxq, packet_indices, ARRAY_LEN (packet_indices));
  qppe_rx_refill (vm, rxq, node->node_index);

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
