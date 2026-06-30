/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline u32
pp2_tx_reg_read_relaxed (uintptr_t hif_base, u32 offset)
{
  uintptr_t addr = hif_base + offset;
  u32 value;

  asm volatile ("ldr %w0, [%1]" : "=r"(value) : "r"(addr));
  return value;
}

static_always_inline void
pp2_tx_reg_write_relaxed (uintptr_t hif_base, u32 offset, u32 value)
{
  uintptr_t addr = hif_base + offset;

  asm volatile ("str %w0, [%1]" : : "r"(value), "r"(addr));
}

static_always_inline void
pp2_tx_reg_write (uintptr_t hif_base, u32 offset, u32 value)
{
  asm volatile ("dsb st" : : : "memory");
  pp2_tx_reg_write_relaxed (hif_base, offset, value);
}

static_always_inline vnet_dev_rv_t
mvpp2_txq_get_num_done (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u16 *num)
{
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  u32 count;

  count = pp2_tx_reg_read_relaxed (thread->hif_base, MVPP22_TXQ_SENT_REG (mtq->hw_id));
  asm volatile ("dsb ld" : : : "memory");
  *num = (count & MVPP22_TRANSMITTED_COUNT_MASK) >> MVPP22_TRANSMITTED_COUNT_OFFSET;
  return VNET_DEV_OK;
}

static_always_inline void
mvpp2_tx_desc_reset (mvpp2_tx_desc_t *desc)
{
  desc->cmds[0] = desc->cmds[1] = desc->cmds[2] = desc->cmds[3] = desc->cmds[5] = desc->cmds[7] = 0;
  desc->cmds[0] =
    (desc->cmds[0] & ~TXD_GEN_IP_CHK_MASK) | (TXD_IP_CHK_DISABLE << 15 & TXD_GEN_IP_CHK_MASK);
  desc->cmds[0] =
    (desc->cmds[0] & ~TXD_GEN_L4_CHK_MASK) | (TXD_L4_CHK_DISABLE << 13 & TXD_GEN_L4_CHK_MASK);
  desc->cmds[0] = (desc->cmds[0] & ~TXD_FL_MASK) | (TXD_FIRST_LAST << 28 & TXD_FL_MASK);
}

static_always_inline void
mvpp2_tx_desc_set_phys_addr (mvpp2_tx_desc_t *desc, u64 addr)
{
  desc->cmds[4] = addr;
  desc->cmds[5] = (desc->cmds[5] & ~TXD_BUF_PHYS_HI_MASK) | (addr >> 32 & TXD_BUF_PHYS_HI_MASK);
}

static_always_inline void
mvpp2_tx_desc_set_pkt_offset (mvpp2_tx_desc_t *desc, u8 offset)
{
  desc->cmds[1] = offset;
}

static_always_inline void
mvpp2_tx_desc_set_pkt_len (mvpp2_tx_desc_t *desc, u16 len)
{
  desc->cmds[1] = (desc->cmds[1] & ~TXD_BYTE_COUNT_MASK) | (len << 16 & TXD_BYTE_COUNT_MASK);
}

static_always_inline int
mvpp2_txq_send (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, mvpp2_tx_desc_t *descs, u16 *num)
{
  mvpp2_device_t *md = vnet_dev_get_data (txq->port->dev);
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  mvpp2_dm_if_t *dm_if = &thread->dm_if;
  u32 *desc_rsrvd = mtq->desc_rsrvd + vm->thread_index;
  mvpp2_tx_desc_t *tx_desc;
  uintptr_t hif_base = thread->hif_base;
  u16 num_txds = *num;
  u16 block_size;
  u16 index = 0;

  if (PREDICT_FALSE (mtq->disabled))
    goto no_descriptors;

  if (PREDICT_FALSE (dm_if->free_count < num_txds))
    {
      u32 occ_desc =
	pp2_tx_reg_read_relaxed (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (thread->hif_id)) &
	MVPP2_AGGR_TXQ_PENDING_MASK;

      dm_if->free_count = dm_if->desc_total - occ_desc;
      num_txds = clib_min (num_txds, dm_if->free_count);
    }

  if (PREDICT_FALSE (*desc_rsrvd < num_txds))
    {
      u32 needed = num_txds - *desc_rsrvd;
      u32 res_req = clib_max (needed, MVPP2_CPU_DESC_CHUNK);
      u32 req_val = mtq->hw_id << MVPP2_TXQ_RSVD_REQ_Q_OFFSET | res_req;

      pp2_tx_reg_write_relaxed (hif_base, MVPP2_TXQ_RSVD_REQ_REG, req_val);
      asm volatile ("dsb sy" : : : "memory");
      *desc_rsrvd +=
	pp2_tx_reg_read_relaxed (hif_base, MVPP2_TXQ_RSVD_RSLT_REG) & MVPP2_TXQ_RSVD_RSLT_MASK;
      num_txds = clib_min (num_txds, *desc_rsrvd);
    }

  if (!num_txds)
    goto no_descriptors;

  block_size = clib_min (num_txds, dm_if->desc_total - dm_if->desc_next_idx);
  tx_desc = dm_if->descs + dm_if->desc_next_idx;
  dm_if->desc_next_idx =
    block_size == dm_if->desc_total - dm_if->desc_next_idx ? 0 : dm_if->desc_next_idx + block_size;
  for (u16 i = 0; i < block_size; i++)
    {
      descs[i].cmds[1] =
	(descs[i].cmds[1] & ~TXD_DEST_QID_MASK) | (mtq->hw_id << 8 & TXD_DEST_QID_MASK);
      __builtin_memcpy (tx_desc + i, descs + i, sizeof (*tx_desc));
    }

  index = block_size;
  if (index < num_txds)
    {
      block_size = num_txds - index;
      tx_desc = dm_if->descs;
      dm_if->desc_next_idx = block_size;
      for (u16 i = 0; i < block_size; i++)
	{
	  descs[index + i].cmds[1] =
	    (descs[index + i].cmds[1] & ~TXD_DEST_QID_MASK) | (mtq->hw_id << 8 & TXD_DEST_QID_MASK);
	  __builtin_memcpy (tx_desc + i, descs + index + i, sizeof (*tx_desc));
	}
    }

  pp2_tx_reg_write (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, num_txds);
  dm_if->free_count -= num_txds;
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
