/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline u16
mvpp2_rx_append_buf_chain (vlib_main_t *vm, vlib_buffer_t *b, vlib_buffer_template_t *bt,
			   u64 *n_rx_bytes)
{
  vlib_buffer_t *prev = b;
  u16 n_buffers = 1;
  u32 total_length = 0;
  mvpp2_rx_buf_hdr_t *hdr = (mvpp2_rx_buf_hdr_t *) (b->data - MVPP2_RX_PACKET_OFFSET_BYTES);
  u16 first_length = hdr->byte_count - MV_MH_SIZE;

  fformat (
    stderr,
    "armada rx: buffer header %p next-phys 0x%08x next-virt 0x%08x bytes %u info 0x%04x last %u\n",
    hdr, hdr->next_phys_addr, hdr->next_dma_addr, hdr->byte_count, hdr->info.as_u16,
    hdr->info.last);

  while (!hdr->info.last)
    {
      u32 next_bi = hdr->next_dma_addr;
      vlib_buffer_t *next = vlib_get_buffer (vm, next_bi);
      mvpp2_rx_buf_hdr_t *next_hdr =
	(mvpp2_rx_buf_hdr_t *) (next->data - MVPP2_RX_PACKET_OFFSET_BYTES);

      fformat (stderr,
	       "armada rx: buffer header %p next-phys 0x%08x next-virt 0x%08x bytes %u info 0x%04x "
	       "last %u\n",
	       next_hdr, next_hdr->next_phys_addr, next_hdr->next_dma_addr, next_hdr->byte_count,
	       next_hdr->info.as_u16, next_hdr->info.last);

      next->template = *bt;
      next->current_data = -32;
      next->current_length = next_hdr->byte_count;
      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
      prev->next_buffer = next_bi;
      total_length += next->current_length;
      *n_rx_bytes += next->current_length;
      prev = next;
      hdr = next_hdr;
      n_buffers++;
    }

  if (total_length)
    {
      *n_rx_bytes -= b->current_length;
      b->current_length = first_length;
      *n_rx_bytes += b->current_length;
      b->total_length_not_including_first_buffer = total_length;
      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    }

  return n_buffers;
}

static_always_inline mvpp2_rx_desc_status_t
mvpp2_rx_extract_descs (mvpp2_rx_desc_t *desc, u32 n_left, u32 *bi, u16 *pl,
			mvpp2_rx_desc_status_hi_t *st)
{
  mvpp2_rx_desc_status_t sa = {};
  for (; n_left >= 4; n_left -= 4, bi += 4, pl += 4, desc += 4, st += 4)
    {
      st[0] = desc[0].status.hi;
      st[1] = desc[1].status.hi;
      st[2] = desc[2].status.hi;
      st[3] = desc[3].status.hi;
      sa.as_u32 |= desc[0].status.as_u32 | desc[1].status.as_u32 | desc[2].status.as_u32 |
		   desc[3].status.as_u32;

      if (PREDICT_TRUE (n_left > 6))
	{
	  clib_prefetch_load (desc + 4);
	  clib_prefetch_load (desc + 6);
	}

      bi[0] = desc[0].buf_virt_ptr_lo;
      pl[0] = desc[0].byte_count;
      bi[1] = desc[1].buf_virt_ptr_lo;
      pl[1] = desc[1].byte_count;
      bi[2] = desc[2].buf_virt_ptr_lo;
      pl[2] = desc[2].byte_count;
      bi[3] = desc[3].buf_virt_ptr_lo;
      pl[3] = desc[3].byte_count;
    }

  for (; n_left > 0; n_left--, bi++, pl++, desc++, st++)
    {
      st[0] = desc->status.hi;
      sa.as_u32 |= desc->status.as_u32;
      bi[0] = desc->buf_virt_ptr_lo;
      pl[0] = desc->byte_count;
    }
  return sa;
}

static_always_inline int
mvpp2_rx_frame_ip4_cksum_ok (mvpp2_rx_desc_status_hi_t *st, u16 n_desc)
{
  mvpp2_rx_desc_status_hi_t mask = {
    .ipv4_hdr_err = 1,
  };
  mvpp2_rx_desc_status_hi_t match = {
    .ipv4_hdr_err = 1,
  };
  u16x8 mask8 = u16x8_splat (mask.as_u16);
  u16x8 match8 = u16x8_splat (match.as_u16);

  for (; n_desc >= 8; n_desc -= 8, st += 8)
    {
      u16x8 st8 = u16x8_load_unaligned ((u16 *) st);
      u16x8 l3_info8 = st8 >> 12;
      u16x8 ip4 = (l3_info8 > u16x8_splat (0)) & (l3_info8 < u16x8_splat (4));

      if (!u16x8_is_all_zero (ip4 & ((st8 & mask8) == match8)))
	return 0;
    }

  for (; n_desc > 0; n_desc--, st++)
    if (st->l3_info >= 1 && st->l3_info <= 3 && (st->as_u16 & mask.as_u16) == match.as_u16)
      return 0;

  return 1;
}

static_always_inline uword
mrvl_pp2_rx_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rx_queue_if_rt_data_t *if_rt_data = vnet_dev_get_rx_queue_if_rt_data (rxq);
  vnet_main_t *vnm = vnet_get_main ();
  uintptr_t hif_base = md->threads[vm->thread_index].hif.base;
  mvpp2_rx_desc_status_hi_t statuses[VLIB_FRAME_SIZE];
  mvpp2_rx_desc_status_t sa = {};
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u16 packet_lengths[VLIB_FRAME_SIZE] __clib_aligned (16)
  , *pl = packet_lengths;
  vlib_buffer_template_t bt = if_rt_data->buffer_template;
  u32 next_index = if_rt_data->next_index;
  u32 sw_if_index = if_rt_data->sw_if_index;
  u64 n_rx_bytes = 0;
  u16 n_desc = VLIB_FRAME_SIZE;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 n_trace, n_left;
  u16 rxq_size = rxq->size;
  u32 next;
  u32 n_to_end;
  u32 *to_next;
  u32 n_left_to_next;

  /* Refresh cached RX descriptor count from hardware. */
  if (n_desc > mrq->desc_received)
    {
      mvpp22_rxq_status_reg_t status = {
	.as_u32 = mvpp2_reg_rd (hif_base, MVPP2_RXQ_STATUS_REG (mrq->hw_id)),
      };

      mrq->desc_received = status.occupied;
      n_desc = clib_min (n_desc, mrq->desc_received);
    }
  if (!n_desc)
    return 0;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  ASSERT (n_left_to_next >= n_desc);

  /* Extract buffer indices and packet lengths from RX descriptors. */
  next = mrq->desc_next_idx;
  n_to_end = rxq_size - next;
  n_to_end = n_desc < n_to_end ? n_desc : n_to_end;
  sa = mvpp2_rx_extract_descs (mrq->hw_descs + next, n_to_end, to_next, pl, statuses);
  if (n_to_end < n_desc)
    sa.as_u32 |= mvpp2_rx_extract_descs (mrq->hw_descs, n_desc - n_to_end, to_next + n_to_end,
					 pl + n_to_end, statuses + n_to_end)
		   .as_u32;

  mrq->desc_next_idx = next + n_desc;
  mrq->desc_next_idx =
    mrq->desc_next_idx < rxq_size ? mrq->desc_next_idx : mrq->desc_next_idx - rxq_size;

  /* Remove the hardware message header from packet lengths using SIMD */
  for (u16x8 *plv = (u16x8 *) packet_lengths, min = u16x8_splat (MV_MH_SIZE),
	     *end __clib_aligned (1) = (u16x8 *) (packet_lengths + n_desc);
       plv < end; plv++)
    plv[0] -= min;

  /* Resolve buffer indices once and pad the prefetch tail. */
  vlib_get_buffers (vm, to_next, b, n_desc);
  b[n_desc] = b[n_desc + 1] = b[n_desc + 2] = b[n_desc + 3] = b[n_desc - 1];

  /* Initialize received buffers four at a time. */
  bt.current_data = 2;
  for (n_left = n_desc, pl = packet_lengths; n_left >= 4; b += 4, pl += 4, n_left -= 4)
    {
      clib_prefetch_store (b[4]);
      clib_prefetch_store (b[5]);
      clib_prefetch_store (b[6]);
      clib_prefetch_store (b[7]);
      b0 = b[0];
      b1 = b[1];
      b2 = b[2];
      b3 = b[3];
      b0->template = bt;
      b1->template = bt;
      b2->template = bt;
      b3->template = bt;

      n_rx_bytes += b0->current_length = pl[0];
      clib_prefetch_slc_load (b0->data);
      n_rx_bytes += b1->current_length = pl[1];
      clib_prefetch_slc_load (b1->data);
      n_rx_bytes += b2->current_length = pl[2];
      clib_prefetch_slc_load (b2->data);
      n_rx_bytes += b3->current_length = pl[3];
      clib_prefetch_slc_load (b3->data);
    }

  /* Initialize the remaining received buffers. */
  for (; n_left; b++, pl++, n_left--)
    {
      b0 = b[0];
      b0->template = bt;

      n_rx_bytes += b0->current_length = pl[0];
      clib_prefetch_slc_load (b0->data);
    }

  /* Append additional VPP buffers for hardware buffer-header chains. */
  if (PREDICT_FALSE (sa.hi.buf_header == 1))
    for (u32 i = 0; i < n_desc; i++)
      if (statuses[i].buf_header)
	{
	  fformat (stderr, "armada rx: descriptor %u has buffer header, buffer index %u\n", i,
		   to_next[i]);
	  mrq->n_bpool_refill += mvpp2_rx_append_buf_chain (vm, buffers[i], &bt, &n_rx_bytes) - 1;
	}

  /* Add trace records for selected packets. */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node)) > 0))
    {
      for (u32 i = 0; i < n_desc && n_trace > 0; i++)
	{
	  mvpp2_rx_desc_t *desc = mrq->hw_descs + next;
	  vlib_buffer_t *b = buffers[i];

	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0)))
	    {
	      mvpp2_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

	      *tr = (mvpp2_rx_trace_t) {
		.desc = *desc,
		.next_index = next_index,
		.sw_if_index = sw_if_index,
	      };
	      n_trace--;
	    }
	  if (++next == rxq_size)
	    next = 0;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  /* Return consumed RX descriptors to hardware. */
  mvpp2_reg_wr (hif_base, MVPP2_RXQ_STATUS_UPDATE_REG (mrq->hw_id),
		(mvpp22_rxq_status_reg_t) {
		  .occupied = n_desc,
		  .available = n_desc,
		}
		  .as_u32);
  mrq->desc_received -= n_desc;
  mrq->n_bpool_refill += n_desc;

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);

      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
      if (sa.hi.ipv4_hdr_err == 0 || mvpp2_rx_frame_ip4_cksum_ok (statuses, n_desc))
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (f);
    }

  /* Enqueue packets to the next node and update interface counters. */
  to_next += n_desc;
  n_left_to_next -= n_desc;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_desc, n_rx_bytes);

  return n_desc;
}

static_always_inline u32
mrvl_pp2_bpool_put (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *n_alloc_fail)
{
  mvpp2_device_t *md = vnet_dev_get_data (rxq->port->dev);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  mvpp2_tx_desc_t desc = mrq->bpool_desc_template;
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  mvpp2_hif_t *hif = &thread->hif;
  u32 *desc_rsrvd = md->lbk_desc_rsrvd + vm->thread_index;
  uintptr_t hif_base = hif->base;
  const u32 batch_size = MRVL_PP2_BUFF_BATCH_SZ;
  u32 n_free = hif->n_free;
  u32 ring_size = hif->n_desc;
  u32 next = hif->next;
  u32 buffer_indices[batch_size];
  vlib_buffer_t *buffers[batch_size];
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n_desc;
  u32 i, n_put = 0;

  /* Wait until a full refill batch is needed. */
  if (mrq->n_bpool_refill < batch_size)
    return 0;

  /* Refresh cached HIF descriptor availability if needed. */
  if (n_free < mrq->n_bpool_refill)
    {
      u32 occ_desc = mvpp2_reg_rd (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (hif->id));
      n_free = ring_size - (occ_desc & MVPP2_AGGR_TXQ_PENDING_MASK);
    }

  n_desc = clib_min (mrq->n_bpool_refill, n_free);

  /* Reserve loopback TXQ descriptor credits. */
  if (n_desc >= batch_size && *desc_rsrvd < n_desc)
    {
      mvpp22_txq_rsvd_req_reg_t request = {
	.count = clib_max (n_desc - *desc_rsrvd, MVPP2_CPU_DESC_CHUNK),
	.queue = MVPP2_LOOPBACK_TXQ_ID,
      };
      u32 val;

      val =
	mvpp2_reg_wr_rd (hif_base, MVPP2_TXQ_RSVD_REQ_REG, request.as_u32, MVPP2_TXQ_RSVD_RSLT_REG);
      val &= MVPP2_TXQ_RSVD_RSLT_MASK;
      val += *desc_rsrvd;
      *desc_rsrvd = val;
      n_desc = clib_min (n_desc, val);
    }

  /* Allocate buffers and write loopback descriptors in batches. */
  for (; n_desc >= batch_size; n_desc -= batch_size)
    {
      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, buffer_indices, batch_size,
							      buffer_pool_index)))
	{
	  (*n_alloc_fail)++;
	  break;
	}

      vlib_get_buffers (vm, buffer_indices, buffers, batch_size);

      for (i = 0; i < batch_size; i++)
	{
	  u64 addr = vlib_buffer_get_pa (vm, buffers[i]) - MVPP2_RX_PACKET_OFFSET_BYTES;

	  desc.buf_phys_ptr_lo = addr;
	  desc.buf_phys_ptr_hi = addr >> 32;
	  desc.buf_virt_ptr_lo = buffer_indices[i];
	  hif->descs[next] = desc;
	  if (++next == ring_size)
	    next = 0;
	}
      n_put += batch_size;
    }

  /* Commit HIF descriptor state and notify hardware. */
  *desc_rsrvd -= n_put;
  hif->n_free = n_free - n_put;
  hif->next = next;

  if (n_put)
    mvpp2_reg_wr (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, n_put);

  /* Account completed buffer pool refill. */
  mrq->n_bpool_refill -= n_put;
  return n_put;
}

u32
mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  u32 n_alloc_fail = 0;

  return mrvl_pp2_bpool_put (vm, rxq, &n_alloc_fail);
}

VNET_DEV_NODE_FN (mvpp2_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  u32 n_alloc_fail = 0;
  u32 node_index = node->node_index;

  /* Poll RX queues and refill their buffer pools. */
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += mrvl_pp2_rx_inline (vm, node, rxq);
      mrvl_pp2_bpool_put (vm, rxq, &n_alloc_fail);
    }

  /* Report buffer allocation failures from refill. */
  if (n_alloc_fail)
    vlib_error_count (vm, node_index, MVPP2_RX_NODE_CTR_BUFFER_ALLOC, n_alloc_fail);
  return n_rx;
}
