/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <dev_ige/ige.h>

VNET_DEV_NODE_FN (ige_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_enq = 0, n_left;
  u16 n_retry = 2;

  n_left = frame->n_vectors;

  vnet_dev_tx_queue_lock_if_needed (txq);

retry:
#if 0
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;
  u16 next;
  next = atq->next;
  /* release consumed bufs */
  if (atq->n_enqueued)
    {
      i32 complete_slot = -1;
      while (1)
	{
	  u16 *slot = clib_ring_get_first (atq->rs_slots);

	  if (slot == 0)
	    break;

	  if (ige_tx_desc_get_dtyp (atq->descs + slot[0]) != 0x0F)
	    break;

	  complete_slot = slot[0];

	  clib_ring_deq (atq->rs_slots);
	}

      if (complete_slot >= 0)
	{
	  u16 first, mask, n_free;
	  mask = txq->size - 1;
	  first = (atq->next - atq->n_enqueued) & mask;
	  n_free = (complete_slot + 1 - first) & mask;

	  atq->n_enqueued -= n_free;
	  vlib_buffer_free_from_ring_no_next (vm, atq->buffer_indices, first,
					      txq->size, n_free);
	}
    }

  n_desc = 0;
  if (dev->va_dma)
    n_enq = ige_tx_prepare (vm, node, txq, buffers, n_left, &n_desc, 1);
  else
    n_enq = ige_tx_prepare (vm, node, txq, buffers, n_left, &n_desc, 0);

  if (n_desc)
    {
      if (PREDICT_TRUE (next + n_desc <= txq->size))
	{
	  /* no wrap */
	  ige_tx_copy_desc (atq->descs + next, atq->tmp_descs, n_desc);
	  vlib_buffer_copy_indices (atq->buffer_indices + next, atq->tmp_bufs,
				    n_desc);
	}
      else
	{
	  /* wrap */
	  u32 n_not_wrap = txq->size - next;
	  ige_tx_copy_desc (atq->descs + next, atq->tmp_descs, n_not_wrap);
	  ige_tx_copy_desc (atq->descs, atq->tmp_descs + n_not_wrap,
			     n_desc - n_not_wrap);
	  vlib_buffer_copy_indices (atq->buffer_indices + next, atq->tmp_bufs,
				    n_not_wrap);
	  vlib_buffer_copy_indices (atq->buffer_indices,
				    atq->tmp_bufs + n_not_wrap,
				    n_desc - n_not_wrap);
	}

      next += n_desc;
      if ((slot = clib_ring_enq (atq->rs_slots)))
	{
	  u16 rs_slot = slot[0] = (next - 1) & mask;
	  atq->descs[rs_slot].qword[1] |= IAVF_TXD_CMD_RS;
	}

      atq->next = next & mask;
      __atomic_store_n (atq->qtx_tail, atq->next, __ATOMIC_RELEASE);
      atq->n_enqueued += n_desc;
      n_left -= n_enq;
    }
#endif

  if (n_left)
    {
      buffers += n_enq;

      if (n_retry--)
	goto retry;

      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_NO_FREE_SLOTS,
			n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
