/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/ethernet/ethernet.h>
#include <ice.h>

#define ICE_RX_REFILL_MAX 256

static_always_inline void
ice_rx_refill8 (ice_rx_desc_t *d, uword *a)
{
#if defined(CLIB_HAVE_VEC512)
  u64x8 *av = (u64x8 *) a;
  u64x8u *dv = (u64x8u *) d;

  dv[0] = u64x8_shuffle2 (av[0], (u64x8) {}, 0, 8, 1, 8, 2, 8, 3, 8);
  dv[1] = u64x8_shuffle2 (av[0], (u64x8) {}, 4, 8, 5, 8, 6, 8, 7, 8);
#elif defined(CLIB_HAVE_VEC256)
  u64x4 *av = (u64x4 *) a;
  u64x4u *dv = (u64x4u *) d;

  dv[0] = u64x4_shuffle2 (av[0], (u64x4) {}, 0, 4, 1, 4);
  dv[1] = u64x4_shuffle2 (av[0], (u64x4) {}, 2, 4, 3, 4);
  dv[2] = u64x4_shuffle2 (av[1], (u64x4) {}, 0, 4, 1, 4);
  dv[3] = u64x4_shuffle2 (av[1], (u64x4) {}, 2, 4, 3, 4);
#else
  ice_rx_desc_t dt[8] = {};

  dt[0].as_u64x2[0] = a[0];
  dt[1].as_u64x2[0] = a[1];
  dt[2].as_u64x2[0] = a[2];
  dt[3].as_u64x2[0] = a[3];
  dt[4].as_u64x2[0] = a[4];
  dt[5].as_u64x2[0] = a[5];
  dt[6].as_u64x2[0] = a[6];
  dt[7].as_u64x2[0] = a[7];

  d[0] = dt[0];
  d[1] = dt[1];
  d[2] = dt[2];
  d[3] = dt[3];
  d[4] = dt[4];
  d[5] = dt[5];
  d[6] = dt[6];
  d[7] = dt[7];
#endif
}

static_always_inline u16
ice_rx_refill_batch (vlib_main_t *vm, vnet_dev_t *dev, u32 *bi, ice_rx_desc_t *d, u16 n, u8 bpi)
{
  const i32 data_offset = STRUCT_OFFSET_OF (vlib_buffer_t, data);
  const u32 max_refill = ICE_RX_REFILL_MAX;
  uword addrs[ICE_RX_REFILL_MAX] __clib_aligned (64);
  ice_rx_desc_t desc = {};
  u16 n_alloc = 0;
  u16 rv;

  for (; n >= max_refill; n -= max_refill, bi += max_refill, d += max_refill)
    {
      rv = vlib_buffer_alloc_from_pool (vm, bi, max_refill, bpi);
      if (PREDICT_FALSE (rv < max_refill))
	goto last;

      vlib_get_buffers_with_offset (vm, bi, (void **) addrs, max_refill, data_offset);
      if (PREDICT_FALSE (!dev->va_dma))
	vlib_physmem_convert_to_phys_addrs (vm, addrs, max_refill);
      for (u16 i = 0; i < max_refill; i += 8)
	ice_rx_refill8 (d + i, addrs + i);
      n_alloc += max_refill;
    }

  if (n == 0)
    return n_alloc;

  rv = vlib_buffer_alloc_from_pool (vm, bi, n, bpi);

last:
  if (PREDICT_FALSE (rv == 0))
    return n_alloc;
  vlib_get_buffers_with_offset (vm, bi, (void **) addrs, rv, data_offset);
  if (PREDICT_FALSE (!dev->va_dma))
    vlib_physmem_convert_to_phys_addrs (vm, addrs, rv);
  for (u16 i = 0; i + 8 <= rv; i += 8)
    ice_rx_refill8 (d + i, addrs + i);
  for (u16 i = rv & ~7; i < rv; i++)
    {

      desc.as_u64x2[0] = addrs[i];
      d[i].as_u64x2 = desc.as_u64x2;
    }
  n_alloc += rv;

  return n_alloc;
}

static_always_inline void
ice_rx_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  ice_rx_desc_t *descs = iq->descs;
  u32 *bi = iq->buffer_indices, tail = iq->tail;
  u16 size = rxq->size, mask = size - 1;
  u16 n_avail = iq->head + size - tail, n_req, slot, batch, n_alloc;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  if (n_avail <= 1)
    return;
  n_req = n_avail - 1;
  slot = tail & mask;
  batch = clib_min (n_req, size - slot);
  n_alloc = ice_rx_refill_batch (vm, dev, bi + slot, descs + slot, batch, bpi);

  if (PREDICT_FALSE (batch < n_req) && n_alloc == batch)
    n_alloc += ice_rx_refill_batch (vm, dev, bi, descs, n_req - batch, bpi);

  if (PREDICT_FALSE (n_req > n_alloc))
    {
      vlib_error_count (vm, node->node_index, ICE_RX_NODE_CTR_BUFFER_ALLOC, 1);
      if (n_alloc == 0)
	return;
    }
  tail += n_alloc;
  iq->tail = tail;
  __atomic_store_n (iq->tail_reg, (tail - 1) & mask, __ATOMIC_RELEASE);
}

static_always_inline uword
ice_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  const ice_rx_flex_status_t error_mask = {
    .header_buffer_overflow = 1,
    .receive_error = 1,
  };
  ice_rx_flex_status_t eop_or_status = {};
  ice_rx_desc_t *hw_descs = iq->descs;
  ice_rx_desc_t descs[VLIB_FRAME_SIZE];
  u32 *buffer_indices = iq->buffer_indices;
  u32 *to_next;
  u32 n_rx = 0, n_bytes = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 node_index = node->node_index;
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_left;
  u32 first_head = iq->head;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u32 head = first_head;
  u16 n_descs;
  u16 n_eops = 0;
  u16 n_eop_descs = 0;
  u16 slot = head & mask;
  u16 queue_id = rxq->queue_id;
  u8 ip4_cksum_ok = 1;

  for (n_descs = 0; n_descs < VLIB_FRAME_SIZE; n_descs++)
    {
      ice_rx_desc_t *src = hw_descs + slot;
      ice_rx_flex_status_t status;

      status.as_u16 = __atomic_load_n (&src->wb.status.as_u16, __ATOMIC_ACQUIRE);
      if (!status.done)
	break;
      descs[n_descs] = src[0];
      if (status.end_of_packet)
	{
	  n_eops++;
	  n_eop_descs = n_descs + 1;
	  eop_or_status.as_u16 |= status.as_u16;
	}
      slot = (slot + 1) & mask;
    }

  if (PREDICT_FALSE (n_eop_descs != n_descs))
    n_descs = n_eop_descs;

  if (n_eops == 0)
    {
      ice_rx_refill (vm, node, rxq);
      return 0;
    }

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left);
  ASSERT (n_left >= n_eops);

  {
    u8 is_head = 1;

    slot = head & mask;
    for (u16 i = 0; i < n_descs; i++, slot = (slot + 1) & mask)
      {
	vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[slot]);

	vlib_buffer_copy_template (b, &bt);
	b->current_length = descs[i].wb.packet_length.length;
	if (is_head)
	  n_bytes += b->current_length;
	is_head = descs[i].wb.status.end_of_packet;
      }
  }

  if (PREDICT_FALSE (n_eops != n_descs || eop_or_status.ip_error ||
		     (eop_or_status.as_u16 & error_mask.as_u16)))
    {
      u16 i = 0;

      while (i < n_descs)
	{
	  ice_rx_flex_status_t status = {};
	  ice_rx_desc_t *first_desc = descs + i;
	  vlib_buffer_t *b;
	  vlib_buffer_t *last;
	  u32 tail_length = 0;
	  u32 bi;
	  u16 first_slot = head & mask;
	  u16 n_desc = 0;

	  while (!status.end_of_packet)
	    {
	      ice_rx_desc_t *desc = first_desc + n_desc;

	      status = desc->wb.status;
	      n_desc++;
	    }

	  if (PREDICT_FALSE (status.as_u16 & error_mask.as_u16))
	    {
	      n_bytes -= first_desc->wb.packet_length.length;
	      head += n_desc;
	      i += n_desc;
	      continue;
	    }

	  bi = buffer_indices[first_slot];
	  b = vlib_get_buffer (vm, bi);
	  last = b;

	  for (u16 j = 1; j < n_desc; j++)
	    {
	      u16 next_slot = (head + j) & mask;
	      u32 next_bi = buffer_indices[next_slot];
	      vlib_buffer_t *next = vlib_get_buffer (vm, next_bi);

	      last->next_buffer = next_bi;
	      last->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      tail_length += next->current_length;
	      last = next;
	    }
	  if (n_desc > 1)
	    {
	      b->total_length_not_including_first_buffer = tail_length;
	      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      n_bytes += tail_length;
	    }
	  to_next[n_rx++] = bi;
	  if (status.l3_l4_parsed && status.ip_error)
	    ip4_cksum_ok = 0;

	  head += n_desc;
	  i += n_desc;
	}
    }
  else
    {
      vlib_buffer_copy_indices_from_ring (to_next, buffer_indices, head & mask, size, n_descs);
      n_rx = n_eops;
      head += n_descs;
    }

  if (PREDICT_FALSE (n_trace))
    {
      u32 trace_head = first_head;
      u32 n_trace_packets = clib_min (n_eops, n_trace);

      for (u32 i = 0; i < n_trace_packets; i++)
	{
	  ice_rx_flex_status_t status = {};
	  u32 packet_length = 0;
	  u16 first_slot = trace_head & mask;
	  u32 bi = buffer_indices[first_slot];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u16 n_desc = 0;
	  u16 slot = first_slot;

	  while (!status.end_of_packet)
	    {
	      ice_rx_desc_t *desc = hw_descs + slot;

	      status = desc->wb.status;
	      packet_length += desc->wb.packet_length.length;
	      n_desc++;
	      slot = (slot + 1) & mask;
	    }

	  if (vlib_trace_buffer (vm, node, next_index, b, 0))
	    {
	      u32 trace_size = sizeof (ice_rx_trace_t) + n_desc * sizeof (ice_rx_desc_t);
	      ice_rx_trace_t *tr = vlib_add_trace (vm, node, b, trace_size);
	      u16 n_first = clib_min (n_desc, (u16) (size - first_slot));

	      tr->sw_if_index = sw_if_index;
	      tr->buffer_index = bi;
	      tr->queue_id = queue_id;
	      tr->n_desc = n_desc;
	      tr->packet_length = packet_length;
	      clib_memcpy_fast (tr->descs, hw_descs + first_slot, n_first * sizeof (tr->descs[0]));
	      if (n_first < n_desc)
		clib_memcpy_fast (tr->descs + n_first, hw_descs,
				  (n_desc - n_first) * sizeof (tr->descs[0]));
	      n_trace--;
	    }
	  trace_head += n_desc;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_FALSE (eop_or_status.as_u16 & error_mask.as_u16))
    {
      u32 drop_head = first_head;

      for (u16 i = 0; i < n_eops; i++)
	{
	  ice_rx_flex_status_t status = {};
	  u16 first_slot = drop_head & mask;
	  u16 n_desc = 0;

	  while (!status.end_of_packet)
	    {
	      ice_rx_desc_t *desc = hw_descs + ((drop_head + n_desc) & mask);

	      status = desc->wb.status;
	      n_desc++;
	    }
	  if (status.as_u16 & error_mask.as_u16)
	    {
	      vlib_buffer_free_from_ring_no_next (vm, buffer_indices, first_slot, size, n_desc);
	      vlib_error_count (vm, node_index, ICE_RX_NODE_CTR_DESC_ERROR, 1);
	    }
	  drop_head += n_desc;
	}
    }
  iq->head = head;
  ice_rx_refill (vm, node, rxq);
  to_next += n_rx;
  n_left -= n_rx;

  if (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT)
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);
      f->flags =
	ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX | (ip4_cksum_ok ? ETH_INPUT_FRAME_F_IP4_CKSUM_OK : 0);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
    }
  vlib_put_next_frame (vm, node, next_index, n_left);

  vlib_increment_combined_counter (vnet_get_main ()->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx, n_bytes);
  return n_rx;
}

VNET_DEV_NODE_FN (ice_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uword n = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    n += ice_rx_one_queue (vm, node, rxq);
  return n;
}
