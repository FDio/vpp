/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/ethernet/ethernet.h>
#include <ice.h>

static_always_inline void
ice_rx_refill32 (ice_rx_desc_t *d, uword *a)
{
#if defined(CLIB_HAVE_VEC512)
  u64x8 z = {};
  u64x8 *av = (u64x8 *) a;
  u64x8u *dv = (u64x8u *) d;

  dv[0] = u64x8_shuffle2 (av[0], z, 0, 8, 1, 8, 2, 8, 3, 8);
  dv[1] = u64x8_shuffle2 (av[0], z, 4, 8, 5, 8, 6, 8, 7, 8);
  dv[2] = u64x8_shuffle2 (av[1], z, 0, 8, 1, 8, 2, 8, 3, 8);
  dv[3] = u64x8_shuffle2 (av[1], z, 4, 8, 5, 8, 6, 8, 7, 8);
  dv[4] = u64x8_shuffle2 (av[2], z, 0, 8, 1, 8, 2, 8, 3, 8);
  dv[5] = u64x8_shuffle2 (av[2], z, 4, 8, 5, 8, 6, 8, 7, 8);
  dv[6] = u64x8_shuffle2 (av[3], z, 0, 8, 1, 8, 2, 8, 3, 8);
  dv[7] = u64x8_shuffle2 (av[3], z, 4, 8, 5, 8, 6, 8, 7, 8);
#elif defined(CLIB_HAVE_VEC256)
  u64x4 z = {};
  u64x4 *av = (u64x4 *) a;
  u64x4u *dv = (u64x4u *) d;

  dv[0] = u64x4_shuffle2 (av[0], z, 0, 4, 1, 4);
  dv[1] = u64x4_shuffle2 (av[0], z, 2, 4, 3, 4);
  dv[2] = u64x4_shuffle2 (av[1], z, 0, 4, 1, 4);
  dv[3] = u64x4_shuffle2 (av[1], z, 2, 4, 3, 4);
  dv[4] = u64x4_shuffle2 (av[2], z, 0, 4, 1, 4);
  dv[5] = u64x4_shuffle2 (av[2], z, 2, 4, 3, 4);
  dv[6] = u64x4_shuffle2 (av[3], z, 0, 4, 1, 4);
  dv[7] = u64x4_shuffle2 (av[3], z, 2, 4, 3, 4);
  dv[8] = u64x4_shuffle2 (av[4], z, 0, 4, 1, 4);
  dv[9] = u64x4_shuffle2 (av[4], z, 2, 4, 3, 4);
  dv[10] = u64x4_shuffle2 (av[5], z, 0, 4, 1, 4);
  dv[11] = u64x4_shuffle2 (av[5], z, 2, 4, 3, 4);
  dv[12] = u64x4_shuffle2 (av[6], z, 0, 4, 1, 4);
  dv[13] = u64x4_shuffle2 (av[6], z, 2, 4, 3, 4);
  dv[14] = u64x4_shuffle2 (av[7], z, 0, 4, 1, 4);
  dv[15] = u64x4_shuffle2 (av[7], z, 2, 4, 3, 4);
#else
  for (u16 i = 0; i < 32; i++)
    {
      ice_rx_desc_t desc = {};

      desc.as_u64x2[0] = a[i];
      d[i] = desc;
    }
#endif
}

static_always_inline void
ice_rx_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  ice_rx_desc_t *descs = iq->descs;
  u32 *bi = iq->buffer_indices, tail = iq->tail;
  u16 size = rxq->size, mask = size - 1;
  u16 n_refill = iq->head + size - tail;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 batch_size = ICE_RX_REFILL_BATCH_SIZE;
  const i32 data_offset = STRUCT_OFFSET_OF (vlib_buffer_t, data);
  uword addrs[batch_size] __clib_aligned (64);

  while (n_refill >= batch_size)
    {
      u16 slot = tail & mask;

      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, bi + slot, batch_size, bpi)))
	{
	  vlib_error_count (vm, node->node_index, ICE_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      vlib_get_buffers_with_offset (vm, bi + slot, (void **) addrs, batch_size, data_offset);
      if (PREDICT_FALSE (!dev->va_dma))
	vlib_physmem_convert_to_phys_addrs (vm, addrs, batch_size);
      ice_rx_refill32 (descs + slot, addrs);
      tail += batch_size;
      n_refill -= batch_size;
    }

  if (tail != iq->tail)
    {
      iq->tail = tail;
      __atomic_store_n (iq->tail_reg, (tail - 1) & mask, __ATOMIC_RELEASE);
    }
}

static_always_inline u16
ice_rx_descs_extract (ice_rx_desc_t *src, ice_rx_flex_status_t *statuses, u16 *packet_lengths,
		      ice_rx_flex_status_t *or_status, u16 n)
{
  u16 or_bits = or_status->as_u16, n_eops = 0;

#if defined(CLIB_HAVE_VEC512) || defined(CLIB_HAVE_VEC256)
  u16x8 or8 = {};

  for (; n >= 8; n -= 8, src += 8, statuses += 8, packet_lengths += 8)
    {
#if defined(CLIB_HAVE_VEC512)
      u16x32u *d = (u16x32u *) src;
      u16x32 fields = u16x32_shuffle2 (d[0], d[1], 2, 10, 18, 26, 34, 42, 50, 58, 4, 12, 20, 28, 36,
				       44, 52, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      u16x8 lengths = (u16x8) u8x64_extract_u8x16 (fields, 0);
      u16x8 st = (u16x8) u8x64_extract_u8x16 (fields, 1);
#else
      u16x16u *d = (u16x16u *) src;
      u16x16 fields0 =
	u16x16_shuffle2 (d[0], d[1], 2, 10, 18, 26, 4, 12, 20, 28, 0, 0, 0, 0, 0, 0, 0, 0);
      u16x16 fields1 =
	u16x16_shuffle2 (d[2], d[3], 2, 10, 18, 26, 4, 12, 20, 28, 0, 0, 0, 0, 0, 0, 0, 0);
      u16x8 lo = u16x16_extract_lo (fields0), hi = u16x16_extract_lo (fields1);
      u16x8 lengths = u16x8_shuffle2 (lo, hi, 0, 1, 2, 3, 8, 9, 10, 11);
      u16x8 st = u16x8_shuffle2 (lo, hi, 4, 5, 6, 7, 12, 13, 14, 15);
#endif
      u16x8 eops = (st >> 1) & u16x8_splat (1);

      *(u16x8u *) packet_lengths = lengths & u16x8_splat (0x3fff);
      *(u16x8u *) statuses = st;
      n_eops += u16x8_sum_elts (eops);
      or8 |= st & (u16x8) (eops != (u16x8) {});
    }
  or8 |= u16x8_word_shift_right (or8, 4);
  or8 |= u16x8_word_shift_right (or8, 2);
  or8 |= u16x8_word_shift_right (or8, 1);
  or_bits |= or8[0];
#endif

  for (u16 i = 0; i < n; i++, src++)
    {
      statuses[i] = src->wb.status;
      packet_lengths[i] = src->wb.packet_length.length;
      if (statuses[i].end_of_packet)
	{
	  or_bits |= statuses[i].as_u16;
	  n_eops++;
	}
    }
  or_status->as_u16 = or_bits;
  return n_eops;
}

static_always_inline uword
ice_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		  u32 maybe_chained)
{
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  const ice_rx_flex_status_t error_mask = { .receive_error = 1 };
  ice_rx_flex_status_t or_status = {};
  ice_rx_desc_t *hw_descs = iq->descs;
  ice_rx_flex_status_t statuses[VLIB_FRAME_SIZE] __clib_aligned (64);
  ice_rx_flex_status_t *sts = statuses;
  u16 packet_lengths[VLIB_FRAME_SIZE] __clib_aligned (64);
  u16 *pl = packet_lengths;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4], **b;
  u32 *buffer_indices = iq->buffer_indices;
  u32 *to_next;
  u32 drop_indices[VLIB_FRAME_SIZE];
  u32 n_drop = 0, n_drop_packets = 0;
  u32 n_rx = 0, n_bytes = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 node_index = node->node_index;
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_left_to_next;
  u32 first_head = iq->head;
  u16 size = rxq->size, mask = size - 1;
  u32 head = first_head;
  u16 n_descs = 0, n, n_left;
  u16 n_desc_limit = clib_min (VLIB_FRAME_SIZE, iq->tail - head);
  u16 n_eops;
  u16 slot = head & mask;
  u16 queue_id = rxq->queue_id;
  u8 ip4_cksum_ok = 1;
  ice_rx_desc_t *src;
  ice_rx_flex_status_t st = {};

  for (st.done = 1; n_descs + 64 <= n_desc_limit && st.done; n_descs += st.done << 6)
    {
      src = hw_descs + ((head + n_descs + 63) & mask);

      st.as_u16 = __atomic_load_n (&src->wb.status.as_u16, __ATOMIC_ACQUIRE);
    }

  for (st.done = 1; n_descs + 8 <= n_desc_limit && st.done; n_descs += st.done << 3)
    {
      src = hw_descs + ((head + n_descs + 7) & mask);

      st.as_u16 = __atomic_load_n (&src->wb.status.as_u16, __ATOMIC_ACQUIRE);
    }

  for (st.done = 1; n_descs < n_desc_limit && st.done; n_descs += st.done)
    {
      src = hw_descs + ((head + n_descs) & mask);

      st.as_u16 = __atomic_load_n (&src->wb.status.as_u16, __ATOMIC_ACQUIRE);
    }

  n = clib_min (n_descs, size - slot);
  n_eops = ice_rx_descs_extract (hw_descs + slot, sts, pl, &or_status, n);
  if (PREDICT_FALSE (n < n_descs))
    n_eops += ice_rx_descs_extract (hw_descs, sts + n, pl + n, &or_status, n_descs - n);

  /* walk back in case of incomplete descriptor chain */
  if (maybe_chained)
    while (n_descs && !statuses[n_descs - 1].end_of_packet)
      n_descs--;

  if (n_eops == 0)
    goto done;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  ASSERT (n_left_to_next >= n_eops);

  slot = head & mask;
  n = clib_min (n_descs, size - slot);
  vlib_get_buffers (vm, buffer_indices + slot, bufs, n);
  if (PREDICT_FALSE (n < n_descs))
    vlib_get_buffers (vm, buffer_indices, bufs + n, n_descs - n);
  bufs[n_descs] = bufs[n_descs + 1] = bufs[n_descs + 2] = bufs[n_descs + 3] = bufs[n_descs - 1];

  for (n_left = n_descs, b = bufs, pl = packet_lengths; n_left >= 4; n_left -= 4, b += 4, pl += 4)
    {

      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      vlib_buffer_copy_template (b[0], &bt);
      clib_prefetch_llc_load (b[0]->data);
      vlib_buffer_copy_template (b[1], &bt);
      clib_prefetch_llc_load (b[1]->data);
      vlib_buffer_copy_template (b[2], &bt);
      clib_prefetch_llc_load (b[2]->data);
      vlib_buffer_copy_template (b[3], &bt);
      clib_prefetch_llc_load (b[3]->data);

      n_bytes += b[0]->current_length = pl[0];
      n_bytes += b[1]->current_length = pl[1];
      n_bytes += b[2]->current_length = pl[2];
      n_bytes += b[3]->current_length = pl[3];
    }

  for (; n_left; n_left--, b++, pl++)
    {
      vlib_buffer_copy_template (b[0], &bt);
      clib_prefetch_llc_load (b[0]->data);
      n_bytes += b[0]->current_length = pl[0];
    }

  if (PREDICT_FALSE (or_status.ip_error))
    {
      const ice_rx_flex_status_t match = {
	.end_of_packet = 1,
	.l3_l4_parsed = 1,
	.ip_error = 1,
      };
      const ice_rx_flex_status_t mask = {
	.end_of_packet = 1,
	.l3_l4_parsed = 1,
	.ip_error = 1,
	.receive_error = 1,
      };

      for (u16 i = 0; i < n_descs; i++)
	{
	  st = statuses[i];
	  if ((st.as_u16 & mask.as_u16) == match.as_u16)
	    {
	      ip4_cksum_ok = 0;
	      break;
	    }
	}
    }

  if (PREDICT_FALSE ((n_eops != n_descs) || (or_status.as_u16 & error_mask.as_u16)))
    {
      u32 chain_indices[ICE_RX_DESC_MAX_CHAIN_LENGTH];
      u32 n_chain = 0, packet_length = 0;

      for (u32 i = 0; i < n_descs; i++, head++)
	{
	  u32 first = i - n_chain;
	  vlib_buffer_t *b = bufs[first], *last = b;

	  ASSERT (n_chain < ICE_RX_DESC_MAX_CHAIN_LENGTH);
	  chain_indices[n_chain++] = buffer_indices[head & mask];
	  packet_length += packet_lengths[i];
	  st = statuses[i];
	  if (!st.end_of_packet)
	    continue;

	  if (PREDICT_FALSE (st.receive_error))
	    {
	      vlib_buffer_copy_indices (drop_indices + n_drop, chain_indices, n_chain);
	      n_drop += n_chain;
	      n_drop_packets++;
	      n_bytes -= packet_length;
	      n_chain = 0;
	      packet_length = 0;
	      continue;
	    }

	  for (u32 j = 1; j < n_chain; j++)
	    {
	      last->next_buffer = chain_indices[j];
	      last->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      last = bufs[first + j];
	    }
	  if (n_chain > 1)
	    {
	      b->total_length_not_including_first_buffer = packet_length - packet_lengths[first];
	      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	    }

	  to_next[n_rx++] = chain_indices[0];
	  n_chain = 0;
	  packet_length = 0;
	}
      ASSERT (n_chain == 0);
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
	  ice_rx_flex_status_t st = {};
	  u32 packet_length = 0;
	  u16 first_slot = trace_head & mask;
	  u32 bi = buffer_indices[first_slot];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u16 n_desc = 0;

	  do
	    {
	      st = statuses[trace_head - first_head + n_desc];
	      packet_length += packet_lengths[trace_head - first_head + n_desc];
	      n_desc++;
	    }
	  while (!st.end_of_packet);

	  if (vlib_trace_buffer (vm, node, next_index, b, 0))
	    {
	      u32 trace_size = sizeof (ice_rx_trace_t) + n_desc * sizeof (ice_rx_desc_t);
	      ice_rx_trace_t *tr = vlib_add_trace (vm, node, b, trace_size);

	      tr->sw_if_index = sw_if_index;
	      tr->buffer_index = bi;
	      tr->queue_id = queue_id;
	      tr->n_desc = n_desc;
	      tr->packet_length = packet_length;
	      for (u16 j = 0; j < n_desc; j++)
		tr->descs[j] = hw_descs[(first_slot + j) & mask];
	      n_trace--;
	    }
	  trace_head += n_desc;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_FALSE (n_drop))
    {
      vlib_buffer_free_no_next (vm, drop_indices, n_drop);
      vlib_error_count (vm, node_index, ICE_RX_NODE_CTR_DESC_ERROR, n_drop_packets);
    }

  iq->head = head;
  to_next += n_rx;
  n_left_to_next -= n_rx;

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
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vnet_dev_increment_interface_counters (vm, rxq->port, n_rx, n_bytes);

done:
  ice_rx_refill (vm, node, rxq);
  return n_rx;
}

VNET_DEV_NODE_FN (ice_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uword n = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      uword n_rx;

      if (iq->maybe_chained)
	n_rx = ice_rx_one_queue (vm, node, rxq, 1);
      else
	n_rx = ice_rx_one_queue (vm, node, rxq, 0);
      n += n_rx;

      if (rxq->interrupt_mode && n_rx >= VLIB_FRAME_SIZE)
	vlib_node_set_interrupt_pending (vm, node->node_index);
    }
  return n;
}
