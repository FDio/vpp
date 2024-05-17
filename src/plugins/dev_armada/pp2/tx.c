/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <dev_armada/pp2/pp2.h>

uword
mrvl_pp2_interface_tx (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (txq);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  u8 qid = txq->queue_id;
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_desc = frame->n_vectors, n_left = n_desc, n_sent = n_desc;
  struct pp2_ppio *ppio = mp->ppio;
  struct pp2_hif *hif = md->hif[vm->thread_index];
  struct pp2_ppio_desc descs[VLIB_FRAME_SIZE], *d = descs;
  u16 sz = txq->size;
  u16 mask = sz - 1;

  if (mtq->n_enq)
    {
      u16 n_done = 0;
      if (PREDICT_FALSE (pp2_ppio_get_num_outq_done (ppio, hif, qid, &n_done)))
	vlib_error_count (vm, node->node_index,
			  MVPP2_TX_NODE_CTR_PPIO_GET_NUM_OUTQ_DONE, 1);

      if (n_done)
	{
	  vlib_buffer_free_from_ring (vm, mtq->buffers, mtq->next - mtq->n_enq,
				      sz, n_done);
	  mtq->n_enq -= n_done;
	}
    }

  d = descs;
  while (n_left)
    {
      u32 bi0 = buffers[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      u64 paddr = vlib_buffer_get_pa (vm, b0);

      pp2_ppio_outq_desc_reset (d);
      pp2_ppio_outq_desc_set_phys_addr (d, paddr + b0->current_data);
      pp2_ppio_outq_desc_set_pkt_offset (d, 0);
      pp2_ppio_outq_desc_set_pkt_len (d, b0->current_length);
      d++;
      buffers++;
      n_left--;
    }

  if (pp2_ppio_send (ppio, hif, qid, descs, &n_sent))
    {
      n_sent = 0;
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_PPIO_SEND, 1);
    }

  /* free unsent buffers */
  if (PREDICT_FALSE (n_sent != n_desc))
    {
      vlib_buffer_free (vm, vlib_frame_vector_args (frame) + n_sent,
			frame->n_vectors - n_sent);
      vlib_error_count (vm, node->node_index, MVPP2_TX_NODE_CTR_NO_FREE_SLOTS,
			frame->n_vectors - n_sent);
    }

  /* store buffer index for each enqueued packet into the ring
     so we can know what to free after packet is sent */
  if (n_sent)
    {
      u16 slot = mtq->next & mask;
      buffers = vlib_frame_vector_args (frame);
      vlib_buffer_copy_indices_to_ring (mtq->buffers, buffers, slot, sz,
					n_sent);
      mtq->next += n_sent;
    }

  return n_sent;
}
