/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

/* Write one contiguous block of TX descriptors. */
static_always_inline void
mvpp2_tx_write_descs (vlib_main_t *vm, mvpp2_tx_desc_t *desc, vlib_buffer_t **bufs, u16 n_desc,
		      u32 hw_id)
{
  u64 addr;
  mvpp2_tx_desc_t dt = {
    .l4_chk_disable = 2,
    .ip_chk_disable = 1,
    .first_last = 3,
    .dest_qid = hw_id,
  };

  for (; n_desc >= 4; n_desc -= 4, desc += 4, bufs += 4)
    {
      mvpp2_tx_desc_t dt0 = dt, dt1 = dt, dt2 = dt, dt3 = dt;
      vlib_buffer_t *b0 = bufs[0];
      vlib_buffer_t *b1 = bufs[1];
      vlib_buffer_t *b2 = bufs[2];
      vlib_buffer_t *b3 = bufs[3];

      vlib_prefetch_buffer_header (bufs[4], LOAD);
      dt0.byte_count = b0->current_length;
      vlib_prefetch_buffer_header (bufs[5], LOAD);
      dt1.byte_count = b1->current_length;
      vlib_prefetch_buffer_header (bufs[6], LOAD);
      dt2.byte_count = b2->current_length;
      vlib_prefetch_buffer_header (bufs[7], LOAD);
      dt3.byte_count = b3->current_length;

      addr = vlib_buffer_get_pa (vm, b0) + b0->current_data;
      dt0.buf_phys_ptr_lo = addr;
      dt0.buf_phys_ptr_hi = addr >> 32;
      desc[0] = dt0;

      addr = vlib_buffer_get_pa (vm, b1) + b1->current_data;
      dt1.buf_phys_ptr_lo = addr;
      dt1.buf_phys_ptr_hi = addr >> 32;
      desc[1] = dt1;

      addr = vlib_buffer_get_pa (vm, b2) + b2->current_data;
      dt2.buf_phys_ptr_lo = addr;
      dt2.buf_phys_ptr_hi = addr >> 32;
      desc[2] = dt2;

      addr = vlib_buffer_get_pa (vm, b3) + b3->current_data;
      dt3.buf_phys_ptr_lo = addr;
      dt3.buf_phys_ptr_hi = addr >> 32;
      desc[3] = dt3;
    }

  for (; n_desc > 0; n_desc--, desc++, bufs++)
    {
      vlib_buffer_t *b0 = bufs[0];
      u64 addr = vlib_buffer_get_pa (vm, b0) + b0->current_data;

      dt.byte_count = b0->current_length;
      dt.buf_phys_ptr_lo = addr;
      dt.buf_phys_ptr_hi = addr >> 32;
      desc[0] = dt;
    }
}

static_always_inline u16
mvpp2_txq_enqueue (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 *bi, vlib_buffer_t **b,
		   u16 n_pkts)
{
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_hif_t *hif = &md->threads[vm->thread_index].hif;
  uintptr_t hif_base = hif->base;
  u32 hif_id = hif->id;
  u32 hw_id = mtq->hw_id;
  u32 n_hif_desc = hif->n_desc;
  u32 hif_next = hif->next;
  u32 n;
  u16 n_desc;
  u16 sz = txq->size;
  u16 mask = sz - 1;

  /* Reclaim buffers for descriptors completed by hardware. */
  if (mtq->n_enq)
    {
      mvpp22_txq_sent_reg_t sent = {
	.as_u32 = mvpp2_hif_reg_rd (hif, MVPP22_TXQ_SENT_REG (hw_id)),
      };
      n = sent.count;

      if (n)
	{
	  vlib_buffer_free_from_ring (vm, mtq->buffers, (mtq->next - mtq->n_enq) & mask, sz, n);
	  mtq->n_enq -= n;
	}
    }

  /* Limit this burst to available software TX ring slots. */
  n_desc = clib_min (n_pkts, sz - mtq->n_enq);

  /* Refresh cached HIF descriptor availability when needed. */
  if (PREDICT_FALSE (hif->n_free < n_desc))
    {
      n = mvpp2_reg_rd_relax (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (hif_id));
      n &= MVPP2_AGGR_TXQ_PENDING_MASK;

      hif->n_free = n_hif_desc - n;
      n_desc = clib_min (n_desc, hif->n_free);
    }

  /* Reserve TXQ descriptor credits from hardware. */
  if (PREDICT_FALSE (mtq->desc_rsrvd < n_desc))
    {
      mvpp22_txq_rsvd_req_reg_t req = {
	.count = clib_max (n_desc - mtq->desc_rsrvd, MVPP2_CPU_DESC_CHUNK),
	.queue = hw_id,
      };

      n = mvpp2_reg_wr_rd (hif_base, MVPP2_TXQ_RSVD_REQ_REG, req.as_u32, MVPP2_TXQ_RSVD_RSLT_REG);
      n &= MVPP2_TXQ_RSVD_RSLT_MASK;
      mtq->desc_rsrvd += n;
      n_desc = clib_min (n_desc, mtq->desc_rsrvd);
    }

  /* Write descriptors to the HIF ring, splitting on wrap. */
  if (PREDICT_TRUE (n_desc))
    {
      u16 n_to_end = n_hif_desc - hif_next;
      n = clib_min (n_desc, n_to_end);
      mvpp2_tx_write_descs (vm, hif->descs + hif_next, b, n, hw_id);

      if (n < n_desc)
	{
	  n = n_desc - n;
	  mvpp2_tx_write_descs (vm, hif->descs, b + n_to_end, n, hw_id);
	  hif_next = n;
	}
      else
	{
	  hif_next += n;
	  if (hif_next == n_hif_desc)
	    hif_next = 0;
	}

      /* Publish descriptors and consume cached resources. */
      hif->next = hif_next;
      mvpp2_reg_wr (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, n_desc);
      hif->n_free -= n_desc;
      mtq->desc_rsrvd -= n_desc;

      /* Track buffers until hardware reports TX completion. */
      vlib_buffer_copy_indices_to_ring (mtq->buffers, bi, mtq->next & mask, sz, n_desc);
      mtq->next += n_desc;
      mtq->n_enq += n_desc;
    }

  return n_desc;
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
      n = mvpp2_txq_enqueue (vm, txq, bi, b, n_left);
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
