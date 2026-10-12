/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vlib/buffer_funcs.h>
#include <edma_hw.h>
#include <qppe.h>

#define QPPE_RX_REFILL_BATCH_SIZE 32

static_always_inline int
qppe_rx_cksum_ok (const edma_rx_desc_t *desc)
{
  if (desc->pid & ~0x3)
    return 1;

  return desc->l3_checksum_status;
}

static_always_inline u32
qppe_rx_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		 u8 maybe_multibuf)
{
  u32 max_packets = VLIB_FRAME_SIZE;
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_rx_bytes = 0;
  u32 *to_next;
  uword n_left_to_next;
  int ip4_cksum_ok = 1;
  const u32 ring_size = rxq->size;
  const u32 mask = ring_size - 1;
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  edma_rx_desc_t *desc_ring = qr->descs;
  u16 desc_cons_start = qr->desc_cons;
  u16 desc_cons;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u16 hw_prod = qppe_mmio_read32 (qd, qr->rxdesc_prod_mmio_off);
  u32 n_desc = (hw_prod - desc_cons_start) & mask;
  u32 n_rx = 0;
  u32 n_trace;
  u32 i, end;

  if (n_desc == 0)
    return 0;

  if (maybe_multibuf)
    {
      /* trim incomplete descriptor */
      end = desc_cons_start + n_desc;
      if (PREDICT_FALSE (desc_ring[(end - 1) & mask].more))
	{
	  while (end > desc_cons_start && desc_ring[(end - 1) & mask].more)
	    end--;
	  n_desc = end - desc_cons_start;
	  if (n_desc == 0)
	    return 0;
	}
    }

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  /* Consume descriptors and build packet buffers/chains. */
  for (i = desc_cons_start, end = i + n_desc; i < end && n_rx < max_packets; i++)
    {
      edma_rx_desc_t hd = desc_ring[i & mask];
      u32 head_buffer_index = hd.opaque_low;
      vlib_buffer_t *hb = vlib_get_buffer (vm, head_buffer_index);

      ASSERT (hd.source_type == EDMA_RX_SOURCE_TYPE_PORT_ID);
      ASSERT (hd.source_port_id == rxq->port->port_id);

      qppe_dma_cache_clean_invalidate (hb->data + hd.data_offset, hd.packet_length);
      vlib_buffer_copy_template (hb, &bt);
      hb->current_data = hd.data_offset;
      hb->current_length = hd.packet_length;
      n_rx_bytes += hd.packet_length;
      ip4_cksum_ok &= qppe_rx_cksum_ok (&hd);

      if (maybe_multibuf && hd.more)
	{
	  vlib_buffer_t *pb = hb;
	  u32 total_length = 0;
	  u8 more = hd.more;

	  while (more)
	    {
	      i++;
	      edma_rx_desc_t td = desc_ring[i & mask];
	      u32 frag_buffer_index = td.opaque_low;
	      vlib_buffer_t *tb = vlib_get_buffer (vm, frag_buffer_index);

	      qppe_dma_cache_clean_invalidate (tb->data + td.data_offset, td.packet_length);
	      tb->current_data = td.data_offset;
	      tb->current_length = td.packet_length;
	      pb->next_buffer = frag_buffer_index;
	      pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      total_length += td.packet_length;

	      pb = tb;
	      more = td.more;
	    }

	  hb->total_length_not_including_first_buffer = total_length;
	  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  n_rx_bytes += total_length;
	}
      else
	ASSERT (!hd.more);

      to_next[n_rx++] = head_buffer_index;
    }

  n_desc = i - desc_cons_start;
  desc_cons = i;
  qr->desc_cons = desc_cons;
  /* Each dequeued descriptor releases one fill slot, including chain tails. */
  qd->rxfill_rings[qr->fill_ring_index].n_refill += n_desc;

  /* Complete RX data invalidation before tracing or passing buffers onward. */
  asm volatile ("dsb osh" : : : "memory");

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      f->flags = ip4_cksum_ok ? ETH_INPUT_FRAME_F_IP4_CKSUM_OK : 0;
      vlib_frame_no_append (f);
    }

  n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace > 0))
    {
      edma_rx_sec_desc_t *sec_desc_ring = qr->preheader_descs;
      u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
      u8 more = 0;

      for (u32 i = 0; i < n_desc && n_trace > 0; i++)
	{
	  u32 slot = (desc_cons_start + i) & mask;
	  edma_rx_desc_t hd = desc_ring[slot];
	  u32 tail_start;
	  vlib_buffer_t *hb = vlib_get_buffer (vm, hd.opaque_low);
	  qppe_rx_trace_t *tr;
	  u16 n_tail = 0;

	  if (more)
	    {
	      more = hd.more;
	      continue;
	    }
	  more = hd.more;
	  if (!vlib_trace_buffer (vm, node, next_index, hb, /* follow_chain */ 0))
	    continue;

	  tail_start = i + 1;
	  for (; more; i++, n_tail++)
	    {
	      slot = (desc_cons_start + i + 1) & mask;
	      more = desc_ring[slot].more;
	    }

	  tr = vlib_add_trace (vm, node, hb, sizeof (*tr) + n_tail * sizeof (tr->tail[0]));

	  *tr = (qppe_rx_trace_t) {
            .sw_if_index = sw_if_index,
            .next_index = next_index,
            .n_tail = n_tail,
            .head = {
              .desc = hd,
              .sec_desc = sec_desc_ring[(desc_cons_start + tail_start - 1) & mask],
            },
          };

	  for (u32 j = 0; j < n_tail; j++)
	    {
	      slot = (desc_cons_start + tail_start + j) & mask;
	      tr->tail[j] = (qppe_rx_trace_descs_t) {
		.desc = desc_ring[slot],
		.sec_desc = sec_desc_ring[slot],
	      };
	    }
	  n_trace--;
	}

      vlib_set_trace_count (vm, node, n_trace);
    }

  qppe_mmio_write32 (qd, qr->rxdesc_cons_mmio_off, desc_cons & mask);
  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vlib_get_thread_index (), hw_if_index, n_rx, n_rx_bytes);

  return n_rx;
}

static_always_inline u32
qppe_rxfill_refill (vlib_main_t *vm, vnet_dev_t *dev)
{
  const u8 batch_sz = QPPE_RX_REFILL_BATCH_SIZE;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxfill_ring_t *rfr = &qd->rxfill_rings[vm->thread_index];
  edma_rxfill_desc_t *desc_ring = rfr->descs;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 mask = rfr->size - 1;
  u16 prod = rfr->prod;
  u32 shortage = rfr->n_refill;
  u8 buffer_pool_index = rfr->buffer_pool_index;

  while (shortage >= batch_sz)
    {
      u32 indices[QPPE_RX_REFILL_BATCH_SIZE];
      void *data[QPPE_RX_REFILL_BATCH_SIZE];
      edma_rxfill_desc_t *descs = desc_ring + (prod & mask);

      if (!vlib_buffer_strict_alloc_from_pool (vm, indices, batch_sz, buffer_pool_index))
	break;
      vlib_get_buffers_with_offset (vm, indices, data, batch_sz,
				    STRUCT_OFFSET_OF (vlib_buffer_t, data));
      for (u32 i = 0; i < batch_sz; i++)
	qppe_dma_cache_clean_invalidate (data[i], buffer_size);

      if (!dev->va_dma)
	vlib_physmem_convert_to_phys_addrs (vm, (uword *) data, batch_sz);

      for (u32 i = 0; i < batch_sz; i++)
	{
	  edma_rxfill_desc_t *desc = descs + i;
	  desc->buffer_address = pointer_to_uword (data[i]);
	  desc->buffer_size = buffer_size;
	  desc->opaque_low = indices[i];
	}
      prod += batch_sz;
      shortage -= batch_sz;
    }

  if (shortage != rfr->n_refill)
    {
      prod &= mask;
      asm volatile ("dsb osh" : : : "memory");
      qppe_mmio_write32 (qd, rfr->prod_mmio_off, prod);
      rfr->prod = prod;
      rfr->n_refill = shortage;
      rfr->buffers_posted = 1;
    }
  return shortage >= batch_sz;
}

VNET_DEV_NODE_FN (qppe_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_t *dev = 0;
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

      dev = rxq->port->dev;
      if (PREDICT_FALSE (qr->multibuf))
	rv += qppe_rx_dequeue (vm, node, rxq, 1);
      else
	rv += qppe_rx_dequeue (vm, node, rxq, 0);
    }

  if (dev)
    {
      if (qppe_rxfill_refill (vm, dev))
	vlib_error_count (vm, node->node_index, QPPE_RX_NODE_CTR_BUFFER_ALLOC, 1);
    }

  return rv;
}
