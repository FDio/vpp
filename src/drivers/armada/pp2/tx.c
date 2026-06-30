/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline vnet_dev_rv_t
mvpp2_txq_get_num_done (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u16 *num)
{
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  u32 count;

  count = mvpp2_reg_rd (thread->hif.base, MVPP22_TXQ_SENT_REG (mtq->hw_id));
  *num = (count & MVPP22_TRANSMITTED_COUNT_MASK) >> MVPP22_TRANSMITTED_COUNT_OFFSET;
  return VNET_DEV_OK;
}

static_always_inline void
mvpp2_tx_desc_reset (mvpp2_tx_desc_t *desc)
{
  *desc = (mvpp2_tx_desc_t) {
    .ip_chk_disable = 1,
    .l4_chk_disable = 2,
    .first_last = 3,
  };
}

static_always_inline void
mvpp2_tx_desc_set_phys_addr (mvpp2_tx_desc_t *desc, u64 addr)
{
  desc->buf_phys_ptr_lo = addr;
  desc->buf_phys_ptr_hi = addr >> 32;
}

static_always_inline void
mvpp2_tx_desc_set_pkt_offset (mvpp2_tx_desc_t *desc, u8 offset)
{
  desc->pkt_offset = offset;
}

static_always_inline void
mvpp2_tx_desc_set_pkt_len (mvpp2_tx_desc_t *desc, u16 len)
{
  desc->byte_count = len;
}

static_always_inline int
mvpp2_txq_send (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, mvpp2_tx_desc_t *descs, u16 *num)
{
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  mvpp2_hif_t *hif = &thread->hif;
  u32 *desc_rsrvd = mtq->desc_rsrvd + vm->thread_index;
  mvpp2_tx_desc_t *tx_desc;
  uintptr_t hif_base = hif->base;
  u16 num_txds = *num;
  u16 block_size;
  u16 index = 0;

  if (PREDICT_FALSE (mtq->disabled))
    goto no_descriptors;

  if (PREDICT_FALSE (hif->n_free < num_txds))
    {
      u32 occ_desc = mvpp2_reg_rd_relax (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (hif->id)) &
		     MVPP2_AGGR_TXQ_PENDING_MASK;

      hif->n_free = hif->n_desc - occ_desc;
      num_txds = clib_min (num_txds, hif->n_free);
    }

  if (PREDICT_FALSE (*desc_rsrvd < num_txds))
    {
      u32 needed = num_txds - *desc_rsrvd;
      mvpp22_txq_rsvd_req_reg_t request = {
	.count = clib_max (needed, MVPP2_CPU_DESC_CHUNK),
	.queue = mtq->hw_id,
      };

      *desc_rsrvd += mvpp2_reg_wr_rd (hif_base, MVPP2_TXQ_RSVD_REQ_REG, request.as_u32,
				      MVPP2_TXQ_RSVD_RSLT_REG) &
		     MVPP2_TXQ_RSVD_RSLT_MASK;
      num_txds = clib_min (num_txds, *desc_rsrvd);
    }

  if (!num_txds)
    goto no_descriptors;

  block_size = clib_min (num_txds, hif->n_desc - hif->next);
  tx_desc = hif->descs + hif->next;
  hif->next = block_size == hif->n_desc - hif->next ? 0 : hif->next + block_size;
  for (u16 i = 0; i < block_size; i++)
    {
      descs[i].dest_qid = mtq->hw_id;
      __builtin_memcpy (tx_desc + i, descs + i, sizeof (*tx_desc));
    }

  index = block_size;
  if (index < num_txds)
    {
      block_size = num_txds - index;
      tx_desc = hif->descs;
      hif->next = block_size;
      for (u16 i = 0; i < block_size; i++)
	{
	  descs[index + i].dest_qid = mtq->hw_id;
	  __builtin_memcpy (tx_desc + i, descs + index + i, sizeof (*tx_desc));
	}
    }

  mvpp2_reg_wr (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, num_txds);
  hif->n_free -= num_txds;
  *desc_rsrvd -= num_txds;
  *num = num_txds;
  return 0;

no_descriptors:
  *num = 0;

  return 0;
}

VNET_DEV_NODE_FN (mvpp2_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_vectors = frame->n_vectors, n_left;
  u16 n_sent;
  mvpp2_tx_desc_t descs[VLIB_FRAME_SIZE], *d = descs;
  u16 sz = txq->size;
  u16 mask = sz - 1;

  if (mtq->n_enq)
    {
      u16 n_done = 0;
      if (PREDICT_FALSE (mvpp2_txq_get_num_done (vm, txq, &n_done)))
	vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_GET_NUM_TX_DONE, 1);

      if (n_done)
	{
	  vlib_buffer_free_from_ring (
	    vm, mtq->buffers, (mtq->next - mtq->n_enq) & mask, sz, n_done);
	  mtq->n_enq -= n_done;
	}
    }

  n_sent = clib_min (n_vectors, sz - mtq->n_enq);

  for (d = descs, n_left = n_sent; n_left; d++, buffers++, n_left--)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffers[0]);
      u64 paddr = vlib_buffer_get_pa (vm, b0);

      mvpp2_tx_desc_reset (d);
      mvpp2_tx_desc_set_phys_addr (d, paddr + b0->current_data);
      mvpp2_tx_desc_set_pkt_offset (d, 0);
      mvpp2_tx_desc_set_pkt_len (d, b0->current_length);
    }

  buffers = vlib_frame_vector_args (frame);

  if (mvpp2_txq_send (vm, txq, descs, &n_sent))
    {
      n_sent = 0;
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_SEND, 1);
    }
  else if (n_sent)
    {
      vlib_buffer_copy_indices_to_ring (mtq->buffers, buffers,
					mtq->next & mask, sz, n_sent);
      mtq->next += n_sent;
      mtq->n_enq += n_sent;
    }

  /* free unsent buffers */
  if (PREDICT_FALSE (n_sent != n_vectors))
    {
      vlib_buffer_free (vm, buffers + n_sent, n_vectors - n_sent);
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_NO_FREE_SLOTS,
			n_vectors - n_sent);
    }

  return n_sent;
}
