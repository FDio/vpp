/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vlib/buffer_funcs.h>
#include <edma_hw.h>
#include <qppe.h>

#define RX_REFILL_BATCH_SZ 32

/* Returns 1 if the packet's IPv4 header checksum can be trusted without a
 * software check: either it isn't IPv4 at all (pid 0x0-0x3 is some IPv4
 * variant; anything else, e.g. bit 2 set for IPv6, trivially passes an
 * IPv4-only check), or it is IPv4 and the PPE's own L3 checksum status says
 * good. */
static_always_inline int
qppe_rx_cksum_ok (const edma_rx_desc_t *desc)
{
  if (desc->pid & ~0x3)
    return 1;

  return desc->l3_checksum_status;
}

/* adds one trace record covering 'desc'/'sec_desc' (the packet's first
 * fragment) plus, for a scattered packet, the 'n_tail' chained fragments
 * following it. Returns 1 if a record was added, 0 if trace declined b. */
static_always_inline int
qppe_rx_trace_maybe_add (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
			 u16 next_index, u32 sw_if_index, const edma_rx_desc_t *desc,
			 const edma_rx_sec_desc_t *sec_desc, const qppe_rx_trace_frag_t *tail,
			 u16 n_tail)
{
  qppe_rx_trace_t *tr;

  if (!vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0))
    return 0;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr) + n_tail * sizeof (tr->tail[0]));
  *tr = (qppe_rx_trace_t) {
    .sw_if_index = sw_if_index,
    .next_index = next_index,
    .n_tail = n_tail,
    .head = {
      .desc = *desc,
      .sec_desc = *sec_desc,
    },
  };
  if (n_tail)
    clib_memcpy_fast (tr->tail, tail, n_tail * sizeof (tr->tail[0]));

  return 1;
}

/* final stage, only entered when tracing is active: re-walks the descriptors
 * just consumed (still intact in the ring) to add one trace record per
 * packet in packet_indices[0..n_rx). */
static_always_inline void
qppe_rx_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		     edma_rx_desc_t *desc_ring, edma_rx_sec_desc_t *sec_desc_ring, u32 mask,
		     u16 desc_cons_start, u32 n_desc, u32 *packet_indices, u32 n_rx)
{
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 i = 0;
  u32 pkt = 0;

  while (i < n_desc && pkt < n_rx && n_trace > 0)
    {
      u32 slot = (desc_cons_start + i) & mask;
      edma_rx_desc_t head_desc = desc_ring[slot];
      edma_rx_sec_desc_t head_sec_desc = sec_desc_ring[slot];
      vlib_buffer_t *head = vlib_get_buffer (vm, packet_indices[pkt]);
      qppe_rx_trace_frag_t tail[QPPE_MAX_RX_CHAIN_LEN];
      u16 n_tail = 0;
      u8 more = head_desc.more;

      i++;
      while (more)
	{
	  slot = (desc_cons_start + i) & mask;
	  edma_rx_desc_t frag_desc = desc_ring[slot];

	  ASSERT (n_tail < QPPE_MAX_RX_CHAIN_LEN);
	  tail[n_tail++] = (qppe_rx_trace_frag_t) {
	    .desc = frag_desc,
	    .sec_desc = sec_desc_ring[slot],
	  };
	  more = frag_desc.more;
	  i++;
	}

      if (qppe_rx_trace_maybe_add (vm, node, head, next_index, sw_if_index, &head_desc,
				   &head_sec_desc, tail, n_tail))
	n_trace--;
      pkt++;
    }

  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline u32
qppe_rx_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		 u32 *packet_indices, u32 max_packets, int *ip4_cksum_ok)
{
  const u32 ring_size = rxq->size;
  const u32 mask = ring_size - 1;
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 *buffer_indices = qr->buffer_indices;
  edma_rx_desc_t *desc_ring = qr->descs;
  edma_rx_sec_desc_t *sec_desc_ring = qr->preheader_descs;
  u16 desc_cons_start = qr->desc_cons;
  u16 desc_cons = desc_cons_start;
  u32 n_buffers = qr->n_buffers;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 offset = qr->rxdesc_offset;
  u32 hw_prod = qppe_mmio_read32 (qd, offset) & EDMA_RX_PROD_CONS_MASK;
  u32 n_rx = 0;
  u32 n_desc = 0;
  u32 n_desc_available = (hw_prod - desc_cons) & mask;

  /* stage 1: consume descriptors and build packet buffers; no tracing here */
  while (n_desc < n_desc_available && n_rx < max_packets)
    {
      u32 slot = desc_cons & mask;
      edma_rx_desc_t desc = desc_ring[slot];
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

      ASSERT (desc.source_type == EDMA_RX_SOURCE_TYPE_PORT_ID);
      ASSERT (desc.source_port_id == rxq->port->port_id);
      ASSERT (!desc.more);

      vlib_buffer_copy_template (b, &bt);
      b->current_data = data_offset;
      b->current_length = len;
      *ip4_cksum_ok &= qppe_rx_cksum_ok (&desc);
      packet_indices[n_rx++] = buffer_index;
    }

  qr->desc_cons = desc_cons;
  qr->n_buffers = n_buffers;

  if (n_desc)
    qppe_mmio_write32 (qd, qr->rxdesc_cons_offset, desc_cons & mask);

  /* stage 2: tracing, last and only entered when trace is active */
  if (PREDICT_FALSE (vlib_get_trace_count (vm, node) > 0))
    qppe_rx_trace_frame (vm, node, rxq, desc_ring, sec_desc_ring, mask, desc_cons_start, n_desc,
			 packet_indices, n_rx);

  return n_rx;
}

static_always_inline u32
qppe_rx_dequeue_multibuf (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
			  u32 *packet_indices, u32 max_packets, int *ip4_cksum_ok)
{
  const u32 ring_size = rxq->size;
  const u32 mask = ring_size - 1;
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 *buffer_indices = qr->buffer_indices;
  edma_rx_desc_t *desc_ring = qr->descs;
  edma_rx_sec_desc_t *sec_desc_ring = qr->preheader_descs;
  u16 desc_cons_start = qr->desc_cons;
  u16 desc_cons;
  u32 n_buffers = qr->n_buffers;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 hw_prod = qppe_mmio_read32 (qd, qr->rxdesc_offset) & EDMA_RX_PROD_CONS_MASK;
  u32 n_desc_available = (hw_prod - desc_cons_start) & mask;
  u32 n_desc = 0;
  u32 n_pkts = 0;
  u32 n_rx = 0;
  u32 i;

  /* Find how many descriptors from desc_cons_start form complete packets,
   * without consuming anything yet: a chain ('more' set) may still be
   * missing its last fragment, and that trailing, not-yet-complete chain
   * has to be left on the ring for a later call rather than processed now. */
  while (n_desc < n_desc_available && n_pkts < max_packets)
    {
      u32 slot = (desc_cons_start + n_desc) & mask;

      n_desc++;
      if (!desc_ring[slot].more)
	n_pkts++;
    }
  while (n_desc > 0 && desc_ring[(desc_cons_start + n_desc - 1) & mask].more)
    n_desc--;

  /* stage 1: consume descriptors and build packet buffers/chains; no tracing here */
  i = 0;
  while (i < n_desc)
    {
      u32 slot = (desc_cons_start + i) & mask;
      edma_rx_desc_t head_desc = desc_ring[slot];
      u32 head_buffer_index = head_desc.opaque_low;
      u32 head_buffer_slot = head_desc.opaque_high;
      vlib_buffer_t *head = vlib_get_buffer (vm, head_buffer_index);
      vlib_buffer_t *prev = head;
      u32 total_length = 0;
      u8 more = head_desc.more;

      ASSERT (head_buffer_slot < ring_size);
      ASSERT (buffer_indices[head_buffer_slot] == head_buffer_index);
      ASSERT (n_buffers > 0);
      n_buffers--;

      ASSERT (head_desc.source_type == EDMA_RX_SOURCE_TYPE_PORT_ID);
      ASSERT (head_desc.source_port_id == rxq->port->port_id);

      vlib_buffer_copy_template (head, &bt);
      head->current_data = head_desc.data_offset;
      head->current_length = head_desc.packet_length;
      *ip4_cksum_ok &= qppe_rx_cksum_ok (&head_desc);
      i++;

      while (more)
	{
	  slot = (desc_cons_start + i) & mask;
	  edma_rx_desc_t frag_desc = desc_ring[slot];
	  u32 frag_buffer_index = frag_desc.opaque_low;
	  u32 frag_buffer_slot = frag_desc.opaque_high;
	  vlib_buffer_t *frag = vlib_get_buffer (vm, frag_buffer_index);

	  ASSERT (frag_buffer_slot < ring_size);
	  ASSERT (buffer_indices[frag_buffer_slot] == frag_buffer_index);
	  ASSERT (n_buffers > 0);
	  n_buffers--;

	  frag->current_data = frag_desc.data_offset;
	  frag->current_length = frag_desc.packet_length;
	  prev->next_buffer = frag_buffer_index;
	  prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  total_length += frag_desc.packet_length;

	  prev = frag;
	  more = frag_desc.more;
	  i++;
	}

      if (total_length)
	{
	  head->total_length_not_including_first_buffer = total_length;
	  head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	}

      packet_indices[n_rx++] = head_buffer_index;
    }

  desc_cons = desc_cons_start + n_desc;
  qr->desc_cons = desc_cons;
  qr->n_buffers = n_buffers;

  if (n_desc)
    qppe_mmio_write32 (qd, qr->rxdesc_cons_offset, desc_cons & mask);

  /* stage 2: tracing, last and only entered when trace is active */
  if (PREDICT_FALSE (vlib_get_trace_count (vm, node) > 0))
    qppe_rx_trace_frame (vm, node, rxq, desc_ring, sec_desc_ring, mask, desc_cons_start, n_desc,
			 packet_indices, n_rx);

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
  edma_rxfill_desc_t *fill_descs = qr->fill_descs;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 buffer_size = vlib_get_buffer_pool (vm, buffer_pool_index)->data_size;
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
	  edma_rxfill_desc_t *desc = fill_descs + slot;
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
	  qppe_dma_cache_clean_invalidate (b->data, buffer_size);
	  desc->buffer_address = vnet_dev_get_dma_addr (vm, dev, b->data);
	  desc->opaque_low = buffer_index;
	}

      fill_prod += RX_REFILL_BATCH_SZ;
      if (fill_prod == ring_size)
	fill_prod = 0;
    }

  if (fill_prod != qr->fill_prod)
    {
      asm volatile ("dsb osh" : : : "memory");
      qppe_mmio_write32 (qd, qr->rxfill_prod_offset, fill_prod);
    }

  qr->fill_prod = fill_prod;
  qr->n_buffers = ring_size - shortage;
}

static_always_inline u32
qppe_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 packet_indices[VLIB_FRAME_SIZE];
  u32 n_rx;
  u32 *to_next;
  uword n_left_to_next;
  int ip4_cksum_ok = 1;

  n_rx = qr->multibuf ? qppe_rx_dequeue_multibuf (vm, node, rxq, packet_indices,
						  ARRAY_LEN (packet_indices), &ip4_cksum_ok) :
			qppe_rx_dequeue (vm, node, rxq, packet_indices, ARRAY_LEN (packet_indices),
					 &ip4_cksum_ok);
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
	  f->flags = ip4_cksum_ok ? ETH_INPUT_FRAME_F_IP4_CKSUM_OK : 0;
	  vlib_frame_no_append (f);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx);

      {
	vnet_main_t *vnm = vnet_get_main ();
	u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
	u32 n_rx_bytes = 0;
	u32 i;

	for (i = 0; i < n_rx; i++)
	  n_rx_bytes += vlib_buffer_length_in_chain (vm, vlib_get_buffer (vm, packet_indices[i]));

	vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
					   VNET_INTERFACE_COUNTER_RX,
					 vlib_get_thread_index (), hw_if_index, n_rx, n_rx_bytes);
      }
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
