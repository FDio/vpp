/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>
#include <pp2/pp2_regs.h>

#define TXD_DEST_QID_MASK 0x0000ff00

static_always_inline u32
pp2_tx_reg_read_relaxed (uintptr_t cpu_slot, u32 offset)
{
  uintptr_t addr = cpu_slot + offset;
  u32 value;

  asm volatile ("ldr %w0, [%1]" : "=r"(value) : "r"(addr));
  return value;
}

static_always_inline void
pp2_tx_reg_write_relaxed (uintptr_t cpu_slot, u32 offset, u32 value)
{
  uintptr_t addr = cpu_slot + offset;

  asm volatile ("str %w0, [%1]" : : "r"(value), "r"(addr));
}

static_always_inline void
pp2_tx_reg_write (uintptr_t cpu_slot, u32 offset, u32 value)
{
  asm volatile ("dsb st" : : : "memory");
  pp2_tx_reg_write_relaxed (cpu_slot, offset, value);
}

static_always_inline void
pp2_ppio_outq_desc_reset (struct pp2_ppio_desc *desc)
{
  desc->cmds[0] = desc->cmds[1] = desc->cmds[2] = desc->cmds[3] = desc->cmds[5] = desc->cmds[7] = 0;
  desc->cmds[0] =
    (desc->cmds[0] & ~TXD_GEN_IP_CHK_MASK) | (TXD_IP_CHK_DISABLE << 15 & TXD_GEN_IP_CHK_MASK);
  desc->cmds[0] =
    (desc->cmds[0] & ~TXD_GEN_L4_CHK_MASK) | (TXD_L4_CHK_DISABLE << 13 & TXD_GEN_L4_CHK_MASK);
  desc->cmds[0] = (desc->cmds[0] & ~TXD_FL_MASK) | (TXD_FIRST_LAST << 28 & TXD_FL_MASK);
}

static_always_inline void
pp2_ppio_outq_desc_set_phys_addr (struct pp2_ppio_desc *desc, dma_addr_t addr)
{
  desc->cmds[4] = addr;
  desc->cmds[5] = (desc->cmds[5] & ~TXD_BUF_PHYS_HI_MASK) | (addr >> 32 & TXD_BUF_PHYS_HI_MASK);
}

static_always_inline void
pp2_ppio_outq_desc_set_pkt_offset (struct pp2_ppio_desc *desc, u8 offset)
{
  desc->cmds[1] = offset;
}

static_always_inline void
pp2_ppio_outq_desc_set_pkt_len (struct pp2_ppio_desc *desc, u16 len)
{
  desc->cmds[1] = (desc->cmds[1] & ~TXD_BYTE_COUNT_MASK) | (len << 16 & TXD_BYTE_COUNT_MASK);
}

static_always_inline struct pp2_desc *
pp2_dm_if_next_desc_block_get (struct pp2_dm_if *dm_if, u16 num_desc, u16 *cont_desc)
{
  u32 tx_desc = dm_if->desc_next_idx;

  if (PREDICT_FALSE (num_desc >= (dm_if->desc_total - dm_if->desc_next_idx)))
    {
      *cont_desc = dm_if->desc_total - dm_if->desc_next_idx;
      dm_if->desc_next_idx = 0;
    }
  else
    {
      dm_if->desc_next_idx = tx_desc + num_desc;
      *cont_desc = num_desc;
    }

  return dm_if->desc_virt_arr + tx_desc;
}

u16
pp2_port_enqueue (struct pp2_port *port, struct pp2_dm_if *dm_if, u8 out_qid, u16 num_txds,
		  struct pp2_ppio_desc desc[], struct pp2_ppio_sg_pkts *pkts)
{
  struct pp2_tx_queue *txq = pp2_port_txq_get (port, out_qid);
  struct pp2_txq_dm_if *txq_dm_if;
  struct pp2_desc *tx_desc;
  uintptr_t cpu_slot = dm_if->cpu_slot;
  u16 block_size, to_send = num_txds;
  int i;

  if (PREDICT_FALSE (txq->disabled))
    goto error;

  if (PREDICT_FALSE (dm_if->free_count < num_txds))
    {
      u32 occ_desc =
	pp2_tx_reg_read_relaxed (dm_if->cpu_slot, MVPP2_AGGR_TXQ_STATUS_REG (dm_if->id)) &
	MVPP2_AGGR_TXQ_PENDING_MASK;

      dm_if->free_count = dm_if->desc_total - occ_desc;
      if (PREDICT_FALSE (dm_if->free_count < num_txds))
	num_txds = dm_if->free_count;
    }

  txq_dm_if = &txq->txq_dm_if[dm_if->id];
  if (PREDICT_FALSE (txq_dm_if->desc_rsrvd < num_txds))
    {
      u32 needed = num_txds - txq_dm_if->desc_rsrvd;
      u32 res_req = needed > MVPP2_CPU_DESC_CHUNK ? needed : MVPP2_CPU_DESC_CHUNK;
      u32 req_val = txq->id << MVPP2_TXQ_RSVD_REQ_Q_OFFSET | res_req;
      u32 result_val;

      pp2_tx_reg_write_relaxed (cpu_slot, MVPP2_TXQ_RSVD_REQ_REG, req_val);
      asm volatile ("dsb sy" : : : "memory");
      result_val =
	pp2_tx_reg_read_relaxed (cpu_slot, MVPP2_TXQ_RSVD_RSLT_REG) & MVPP2_TXQ_RSVD_RSLT_MASK;
      txq_dm_if->desc_rsrvd += result_val;

      if (PREDICT_FALSE (txq_dm_if->desc_rsrvd < num_txds))
	num_txds = txq_dm_if->desc_rsrvd;
    }

  if (pkts && to_send > num_txds)
    {
      u16 curr_txds = 0;

      for (i = 0; i < pkts->num; i++)
	{
	  if (curr_txds + pkts->frags[i] > num_txds)
	    break;
	  curr_txds += pkts->frags[i];
	}

      num_txds = curr_txds;
      pkts->num = i;
    }

  if (!num_txds)
    goto error;

  tx_desc = pp2_dm_if_next_desc_block_get (dm_if, num_txds, &block_size);
  for (i = 0; i < block_size; i++)
    {
      desc[i].cmds[1] = (desc[i].cmds[1] & ~TXD_DEST_QID_MASK) | (txq->id << 8 & TXD_DEST_QID_MASK);
      __builtin_memcpy (&tx_desc[i], &desc[i], sizeof (*tx_desc));
    }

  if (block_size < num_txds)
    {
      u16 index = block_size;
      u16 txds_remaining = num_txds - block_size;

      tx_desc = pp2_dm_if_next_desc_block_get (dm_if, txds_remaining, &block_size);
      if (PREDICT_FALSE (index + block_size != num_txds))
	num_txds = index + block_size;

      for (i = 0; i < block_size; i++)
	{
	  desc[index + i].cmds[1] =
	    (desc[index + i].cmds[1] & ~TXD_DEST_QID_MASK) | (txq->id << 8 & TXD_DEST_QID_MASK);
	  __builtin_memcpy (&tx_desc[i], &desc[index + i], sizeof (*tx_desc));
	}
    }

  pp2_tx_reg_write (cpu_slot, MVPP2_AGGR_TXQ_UPDATE_REG, num_txds);
  dm_if->free_count -= num_txds;
  txq_dm_if->desc_rsrvd -= num_txds;
  return num_txds;

error:
  if (pkts)
    pkts->num = 0;
  return 0;
}

static_always_inline int
pp2_ppio_send (vnet_dev_port_t *port, struct pp2_hif *hif, u8 qid, struct pp2_ppio_desc *descs,
	       u16 *num)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_port *pp_port = mp->pp_port;
  u16 desc_req = *num;
  u16 desc_sent;

  desc_sent = pp2_port_enqueue (pp_port, pp2_dm_if_get (pp_port, hif), qid, desc_req, descs, 0);
  if (PREDICT_FALSE (desc_sent < desc_req))
    *num = desc_sent;

  return 0;
}

VNET_DEV_NODE_FN (mvpp2_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_instance_t *ins = vnet_dev_get_dev_instance (rt->dev_instance);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u8 qid = txq->queue_id;
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_vectors = frame->n_vectors, n_left;
  u16 n_sent;
  struct pp2_hif *hif = md->hif[vm->thread_index];
  struct pp2_ppio_desc descs[VLIB_FRAME_SIZE], *d = descs;
  u16 sz = txq->size;
  u16 mask = sz - 1;
  i16 len_adj = 0;

  if (ins->is_primary_if == 0)
    {
      vnet_dev_port_interface_t *sif =
	vnet_dev_port_get_sec_if_by_index (port, ins->sec_if_index);

      mv_dsa_tag_t tag = { .as_u32 = sif->user_data };

      for (u32 i = 0; i < n_vectors; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
	  u8 *start = vlib_buffer_get_current (b);
	  clib_memmove (start - 4, start, 12);
	  mv_dsa_tag_write (start + 8, tag);
	}
      len_adj = 4;
    }

  if (mtq->n_enq)
    {
      u16 n_done = 0;
      if (PREDICT_FALSE (pp2_ppio_get_num_outq_done (port, hif, qid, &n_done)))
	vlib_error_count (vm, node->node_index,
			  MVPP2_TX_NODE_CTR_PPIO_GET_NUM_OUTQ_DONE, 1);

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

      pp2_ppio_outq_desc_reset (d);
      pp2_ppio_outq_desc_set_phys_addr (d, paddr + b0->current_data - len_adj);
      pp2_ppio_outq_desc_set_pkt_offset (d, 0);
      pp2_ppio_outq_desc_set_pkt_len (d, b0->current_length + len_adj);
    }

  buffers = vlib_frame_vector_args (frame);

  if (pp2_ppio_send (port, hif, qid, descs, &n_sent))
    {
      n_sent = 0;
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_PPIO_SEND, 1);
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
