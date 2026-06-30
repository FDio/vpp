/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline u16
mvpp2_tx_gather (vlib_main_t *vm, vlib_buffer_t **bufs, u32 *bi, u16 n_pkts, u16 n_slots,
		 uword *addrs, u32 *flags, u16 *lengths, u32 *buffer_indices, u16 *n_gathered_pkts,
		 u32 *or_flags)
{
  vlib_buffer_t *b, *b0, *b1, *b2, *b3;
  u16 n_desc = 0;
  u16 n_left = n_pkts;
  u16 first;
  u32 f0, f1, f2, f3, f = 0;

  n_slots = clib_min (n_slots, VLIB_FRAME_SIZE);

  *or_flags = 0;
  while (1)
    {
      /* Fast path: gather four complete single-buffer packets. */
      if (n_left < 4 || n_desc + 4 > n_slots)
	goto one_by_one;

      vlib_prefetch_buffer_header (bufs[4], LOAD);
      vlib_prefetch_buffer_header (bufs[5], LOAD);

      b0 = bufs[0], b1 = bufs[1], b2 = bufs[2], b3 = bufs[3];

      f = 0;
      f |= f0 = b0->flags;
      f |= f1 = b1->flags;
      f |= f2 = b2->flags;
      f |= f3 = b3->flags;

      vlib_prefetch_buffer_header (bufs[6], LOAD);
      vlib_prefetch_buffer_header (bufs[7], LOAD);

      if (PREDICT_FALSE (f & VLIB_BUFFER_NEXT_PRESENT))
	goto one_by_one;

      *or_flags |= f;

      addrs[n_desc] = (uword) (b0->data + b0->current_data);
      flags[n_desc] = f0;
      lengths[n_desc] = b0->current_length;

      addrs[n_desc + 1] = (uword) (b1->data + b1->current_data);
      flags[n_desc + 1] = f1;
      lengths[n_desc + 1] = b1->current_length;

      addrs[n_desc + 2] = (uword) (b2->data + b2->current_data);
      flags[n_desc + 2] = f2;
      lengths[n_desc + 2] = b2->current_length;

      addrs[n_desc + 3] = (uword) (b3->data + b3->current_data);
      flags[n_desc + 3] = f3;
      lengths[n_desc + 3] = b3->current_length;

      vlib_buffer_copy_indices (buffer_indices + n_desc, bi, 4);
      n_desc += 4;
      bufs += 4;
      bi += 4;
      n_left -= 4;
      continue;

    one_by_one:
      /* Gather one packet head. */
      if (n_left == 0)
	break;
      if (n_desc == n_slots)
	break;

      b = bufs[0];
      f = b->flags;

      addrs[n_desc] = (uword) (b->data + b->current_data);
      flags[n_desc] = f;
      lengths[n_desc] = b->current_length;
      buffer_indices[n_desc] = bi[0];
      n_desc++;

      /* Fast path for one remaining single-buffer packet. */
      if (PREDICT_TRUE (!(f & VLIB_BUFFER_NEXT_PRESENT)))
	{
	  *or_flags |= f;
	  bufs++;
	  bi++;
	  n_left--;
	  continue;
	}

      /* Slow path: gather every chained tail buffer. */
      first = n_desc - 1;
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  if (n_desc == n_slots)
	    {
	      n_desc = first;
	      break;
	    }
	  buffer_indices[n_desc] = b->next_buffer;
	  b = vlib_get_buffer (vm, buffer_indices[n_desc]);
	  addrs[n_desc] = (uword) (b->data + b->current_data);
	  flags[n_desc] = b->flags;
	  lengths[n_desc] = b->current_length;
	  n_desc++;
	}
      if (n_desc == first)
	break;
      *or_flags |= f;
      bufs++;
      bi++;
      n_left--;
    }
  *n_gathered_pkts = n_pkts - n_left;
  return n_desc;
}

static_always_inline void
mvpp2_tx_write_descs (mvpp2_txq_t *mpq, mvpp2_tx_desc_t *desc, uword *addrs,
		      mvpp2_tx_desc_cmd_t *cmds, u16 *lengths, u16 n_desc, int is_simple)
{
  vec128_t lo, hi, lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3;
  lo.as_u32x4 = mpq->desc_template.as_u32x4[0];
  hi.as_u32x4 = mpq->desc_template.as_u32x4[1];

  for (; n_desc >= 4; desc += 4, addrs += 4, lengths += 4, n_desc -= 4)
    {
      lo0 = lo1 = lo;
      hi0 = hi1 = hi;
      lo0.as_u16x8[3] = lengths[0];
      lo1.as_u16x8[3] = lengths[1];
      hi0.as_u64x2[0] = addrs[0];
      hi1.as_u64x2[0] = addrs[1];
      if (!is_simple)
	{
	  lo0.as_u32x4[0] = cmds[0].as_u32;
	  lo1.as_u32x4[0] = cmds[1].as_u32;
	}
      desc[0].as_u32x4[0] = lo0.as_u32x4;
      desc[0].as_u32x4[1] = hi0.as_u32x4;
      desc[1].as_u32x4[0] = lo1.as_u32x4;
      desc[1].as_u32x4[1] = hi1.as_u32x4;

      lo2 = lo3 = lo;
      hi2 = hi3 = hi;
      lo2.as_u16x8[3] = lengths[2];
      lo3.as_u16x8[3] = lengths[3];
      hi2.as_u64x2[0] = addrs[2];
      hi3.as_u64x2[0] = addrs[3];
      if (!is_simple)
	{
	  lo2.as_u32x4[0] = cmds[2].as_u32;
	  lo3.as_u32x4[0] = cmds[3].as_u32;
	}
      desc[2].as_u32x4[0] = lo2.as_u32x4;
      desc[2].as_u32x4[1] = hi2.as_u32x4;
      desc[3].as_u32x4[0] = lo3.as_u32x4;
      desc[3].as_u32x4[1] = hi3.as_u32x4;
      if (!is_simple)
	cmds += 4;
    }

  for (; n_desc; desc++, addrs++, lengths++, n_desc--)
    {
      lo.as_u16x8[3] = lengths[0];
      hi.as_u64x2[0] = addrs[0];
      if (!is_simple)
	lo.as_u32x4[0] = cmds[0].as_u32;

      desc[0].as_u32x4[0] = lo.as_u32x4;
      desc[0].as_u32x4[1] = hi.as_u32x4;
      if (!is_simple)
	cmds++;
    }
}

static_always_inline u16
mvpp2_txq_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *bi,
		   vlib_buffer_t **b, u16 n_pkts)
{
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_hif_t *hif = &md->threads[vm->thread_index].hif;
  mvpp2_tx_desc_t *hif_descs = hif->descs;
  uintptr_t hif_base = hif->base;
  u32 hif_id = hif->id;
  u32 hw_id = mtq->hw_id;
  u32 n_hif_desc = hif->n_desc;
  u32 hif_next = hif->next;
  uword addrs[VLIB_FRAME_SIZE];
  typeof (b[0]->flags) flags[VLIB_FRAME_SIZE], or_flags, prev_flags = 0;
  u32 buffer_indices[VLIB_FRAME_SIZE];
  u16 lengths[VLIB_FRAME_SIZE];
  u32 n;
  u16 n_desc;
  u16 n_to_end;
  u16 n_pkts_sent;
  u16 n_slots;
  u16 sz = txq->size;
  u16 mask = sz - 1;

  /* Reclaim each completed TX segment directly from the descriptor ring. */
  if (mtq->n_enq)
    {
      mvpp22_txq_sent_reg_t sent = {
	.as_u32 = mvpp2_hif_reg_rd (hif, MVPP22_TXQ_SENT_REG (hw_id)),
      };
      n = sent.count;
      if (n > mtq->n_enq)
	n = mtq->n_enq;
      if (n)
	{
	  u32 ring_index = (mtq->next - mtq->n_enq) & mask;
	  vlib_buffer_free_from_ring_no_next (vm, mtq->buffers, ring_index, sz, n);
	  mtq->n_enq -= n;
	}
    }

  n_slots = clib_min (sz - mtq->n_enq, VLIB_FRAME_SIZE);

  /* Refresh cached HIF descriptor availability when needed. */
  if (PREDICT_FALSE (hif->n_free < n_slots))
    {
      n = mvpp2_reg_rd_relax (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (hif_id));
      n &= MVPP2_AGGR_TXQ_PENDING_MASK;

      hif->n_free = n_hif_desc - n;
      n_slots = clib_min (n_slots, hif->n_free);
    }

  /* Reserve TXQ descriptor credits from hardware. */
  if (PREDICT_FALSE (mtq->desc_rsrvd < n_slots))
    {
      mvpp22_txq_rsvd_req_reg_t req = {
	.count = clib_max (n_slots - mtq->desc_rsrvd, MVPP2_CPU_DESC_CHUNK),
	.queue = hw_id,
      };

      n = mvpp2_reg_wr_rd (hif_base, MVPP2_TXQ_RSVD_REQ_REG, req.as_u32, MVPP2_TXQ_RSVD_RSLT_REG);
      n &= MVPP2_TXQ_RSVD_RSLT_MASK;
      mtq->desc_rsrvd += n;
      n_slots = clib_min (n_slots, mtq->desc_rsrvd);
    }

  n_desc = mvpp2_tx_gather (vm, b, bi, n_pkts, n_slots, addrs, flags, lengths, buffer_indices,
			    &n_pkts_sent, &or_flags);
  if (PREDICT_FALSE (!n_desc))
    goto done;

  /* Convert gathered virtual addresses to physical addresses. */
  vlib_physmem_convert_to_phys_addrs (vm, addrs, n_desc);

  n_to_end = n_hif_desc - hif_next;
  n = clib_min (n_desc, n_to_end);
  if (PREDICT_FALSE (or_flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD)))
    {
      /* Generate hardware flags for chained or checksum-offload batches. */

      mvpp2_tx_desc_cmd_t cmds[VLIB_FRAME_SIZE];

      for (u16 i = 0; i < n_desc; i++)
	{
	  typeof (flags[0]) next_flags = flags[i];
	  int first = !(prev_flags & VLIB_BUFFER_NEXT_PRESENT);
	  cmds[i] = (mvpp2_tx_desc_cmd_t) {
	    .l4_chk_disable = 2,
	    .ip_chk_disable = 1,
	    .first = first,
	    .last = !(next_flags & VLIB_BUFFER_NEXT_PRESENT),
	  };
	  if (first && (next_flags & VNET_BUFFER_F_OFFLOAD))
	    {
	      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffer_indices[i]);
	      vnet_buffer_oflags_t oflags = vnet_buffer (b0)->oflags;
	      i16 l3_off = vnet_buffer (b0)->l3_hdr_offset - b0->current_data;
	      i16 l4_off = vnet_buffer (b0)->l4_hdr_offset - b0->current_data;

	      cmds[i].l3_offset = l3_off;
	      cmds[i].ip_hdr_len = (l4_off - l3_off) >> 2;
	      cmds[i].l3_info = !!(next_flags & VNET_BUFFER_F_IS_IP6);
	      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
		cmds[i].ip_chk_disable = 0;
	    }
	  prev_flags = next_flags;
	}

      mvpp2_tx_write_descs (mtq, hif_descs + hif_next, addrs, cmds, lengths, n, 0);
      if (n < n_desc)
	mvpp2_tx_write_descs (mtq, hif_descs, addrs + n, cmds + n, lengths + n, n_desc - n, 0);
    }
  else
    {
      mvpp2_tx_write_descs (mtq, hif_descs + hif_next, addrs, 0, lengths, n, 1);
      if (n < n_desc)
	mvpp2_tx_write_descs (mtq, hif_descs, addrs + n, 0, lengths + n, n_desc - n, 1);
    }

  /* Trace packets from their completed hardware descriptors. */
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (or_flags & VLIB_BUFFER_IS_TRACED)))
    {
      u16 desc_index = hif_next;
      u16 hif_mask = n_hif_desc - 1;

      for (u16 i = 0; i < n_pkts_sent; i++)
	{
	  vlib_buffer_t *b0 = b[i];
	  vlib_buffer_t *seg = b0;
	  u16 n_pkt_desc = 1;

	  while (seg->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      seg = vlib_get_buffer (vm, seg->next_buffer);
	      n_pkt_desc++;
	    }

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      u32 trace_size = sizeof (mvpp2_tx_trace_t) + n_pkt_desc * sizeof (mvpp2_tx_desc_t);
	      mvpp2_tx_trace_t *tr = vlib_add_trace (vm, node, b0, trace_size);

	      *tr = (mvpp2_tx_trace_t) {
		.sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX],
		.buffer_index = bi[i],
		.queue_id = txq->queue_id,
		.n_desc = n_pkt_desc,
	      };
	      for (u16 j = 0; j < n_pkt_desc; j++)
		tr->desc[j] = hif_descs[(desc_index + j) & hif_mask];
	    }
	  desc_index = (desc_index + n_pkt_desc) & hif_mask;
	}
    }

  /* Publish descriptors and consume cached resources. */
  hif->next = (hif_next + n_desc) & (n_hif_desc - 1);
  mvpp2_reg_wr (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, n_desc);
  hif->n_free -= n_desc;
  mtq->desc_rsrvd -= n_desc;

  vlib_buffer_copy_indices_to_ring (mtq->buffers, buffer_indices, mtq->next & mask, sz, n_desc);
  mtq->next = (mtq->next + n_desc) & mask;
  mtq->n_enq += n_desc;

done:
  return n_pkts_sent;
}

VNET_DEV_NODE_FN (mvpp2_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *buffer_indices = vlib_frame_vector_args (frame), *bi = buffer_indices;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u16 n_pkts = frame->n_vectors;
  u16 n_left = n_pkts;
  u16 n;
  u8 n_retry = 5;

  vlib_get_buffers (vm, buffer_indices, b, n_pkts);
  b[n_pkts] = b[n_pkts + 1] = b[n_pkts + 2] = b[n_pkts + 3] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_left && n_retry--)
    {
      n = mvpp2_txq_enqueue (vm, node, txq, bi, b, n_left);
      b += n;
      bi += n;
      n_left -= n;
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  /* Free buffers not accepted for transmission. */
  if (PREDICT_FALSE (n_left))
    {
      vlib_buffer_free (vm, bi, n_left);
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  return n_pkts - n_left;
}
