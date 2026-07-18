/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vnet/ip/ip4_packet.h>

static_always_inline void
ice_tx_prepare_ip4_checksum (vlib_buffer_t *b, ice_tx_cmd_t *cmd)
{
  ip4_header_t *ip4;
  u16 l2_length;
  u16 ip_length;

  if ((b->flags & VNET_BUFFER_F_OFFLOAD) == 0 ||
      (vnet_buffer (b)->oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM) == 0)
    return;

  ASSERT (b->flags & VNET_BUFFER_F_IS_IP4);
  ASSERT (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
  ASSERT (vnet_buffer (b)->l3_hdr_offset >= b->current_data);
  l2_length = vnet_buffer (b)->l3_hdr_offset - b->current_data;
  ASSERT (l2_length + sizeof (*ip4) <= b->current_length);
  ip4 = (void *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  ip_length = ip4_header_bytes (ip4);
  ASSERT (l2_length + ip_length <= b->current_length);
  ASSERT ((l2_length & 1) == 0 && l2_length <= 254);
  ASSERT ((ip_length & 3) == 0 && ip_length <= 508);

  ip4->checksum = 0;
  cmd->ip_type = ICE_TX_IP_TYPE_IPV4_CKSUM;
  cmd->mac_length = l2_length >> 1;
  cmd->ip_length = ip_length >> 2;
}

VNET_DEV_NODE_FN (ice_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 trace_count = n_trace;
  u16 mask = txq->size - 1;

  vnet_dev_tx_queue_lock_if_needed (txq);
  u16 n_done = 0;
  while (iq->head + n_done != iq->tail)
    {
      u16 slot = (iq->head + n_done) & mask;
      ice_tx_cmd_t cmd = {
	.as_u64 = __atomic_load_n (&iq->descs[slot].cmd.as_u64, __ATOMIC_ACQUIRE),
      };

      if (cmd.descriptor_type != ICE_TX_DESC_TYPE_DONE)
	break;
      n_done++;
    }
  if (n_done)
    {
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & mask, txq->size,
					  n_done);
      iq->head += n_done;
    }

  u16 n_free = txq->size - 1 - (iq->tail - iq->head);
  while (n_left && n_free)
    {
      u32 bi = from[0];
      u32 segment_bi = bi;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      vlib_buffer_t *segment = b;
      ice_tx_cmd_t cmd = {
	.report_status = 1,
	.reserved_command = 1,
      };
      u16 n_desc = 1;

      while (segment->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  n_desc++;
	  segment = vlib_get_buffer (vm, segment->next_buffer);
	}
      if (PREDICT_FALSE (n_desc >= txq->size))
	{
	  vlib_buffer_free_one (vm, bi);
	  vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_CHAIN_TOO_LONG, 1);
	  from++;
	  n_left--;
	  continue;
	}
      if (PREDICT_FALSE (n_desc > n_free))
	break;

      ice_tx_prepare_ip4_checksum (b, &cmd);
      segment = b;
      for (u16 i = 0; i < n_desc; i++)
	{
	  u16 slot = iq->tail & mask;
	  ice_tx_desc_t d = {
	    .buf_addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (segment)),
	    .cmd = cmd,
	  };

	  d.cmd.end_of_packet = (i == n_desc - 1);
	  d.cmd.buffer_size = segment->current_length;
	  iq->descs[slot] = d;
	  iq->buffer_indices[slot] = segment_bi;

	  if (i == 0)
	    {
	      u8 traced = (b->flags & VLIB_BUFFER_IS_TRACED) != 0;
	      if (PREDICT_FALSE (traced || n_trace) &&
		  (traced || vlib_trace_buffer (vm, node, VNET_INTERFACE_OUTPUT_NEXT_DROP, b, 0)))
		{
		  ice_tx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
		  tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
		  tr->buffer_index = bi;
		  tr->queue_id = txq->queue_id;
		  tr->n_desc = n_desc;
		  tr->desc = d;
		  if (!traced)
		    n_trace--;
		}
	    }

	  iq->tail++;
	  n_free--;
	  if (segment->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      segment_bi = segment->next_buffer;
	      segment = vlib_get_buffer (vm, segment_bi);
	    }
	}
      from++;
      n_left--;
    }

  if (iq->tail != iq->head)
    __atomic_store_n (iq->tail_reg, iq->tail & mask, __ATOMIC_RELEASE);
  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }
  if (trace_count)
    vlib_set_trace_count (vm, node, n_trace);
  vnet_dev_tx_queue_unlock_if_needed (txq);
  return frame->n_vectors - n_left;
}
