/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <dev_armada/pp2/pp2.h>

VNET_DEV_NODE_FN (mvpp2_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_instance_t *ins = vnet_dev_get_dev_instance (rt->dev_instance);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u8 qid = txq->queue_id;
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_vectors = frame->n_vectors, n_left;
  u16 n_sent;
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_hif *hif = md->hif[vm->thread_index];
  struct pp2_ppio_desc descs[VLIB_FRAME_SIZE], *d = descs;
  u16 sz = txq->size;
  u16 mask = sz - 1;
  i16 len_adj = 0;

  if (ins->is_primary_if == 0)
    {
      u32 id = vnet_dev_port_get_sec_if_by_index (port, ins->sec_if_index)->id;
      mv_dsa_tag_t tag = {
	.tag_type = MV_DSA_TAG_TYPE_FROM_CPU,
	.src_port_or_lag = id,
      };
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
      if (PREDICT_FALSE (pp2_ppio_get_num_outq_done (ppio, hif, qid, &n_done)))
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

  if (pp2_ppio_send (ppio, hif, qid, descs, &n_sent))
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
