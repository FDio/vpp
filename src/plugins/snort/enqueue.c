/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip4_packet.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

static char *snort_enq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_enq_error
#undef _
};

static_always_inline uword
snort_enq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int with_trace, int is_output)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si = 0;
  snort_qpair_t *qp = 0;
  clib_thread_index_t thread_index = vm->thread_index;
  u32 n_left = frame->n_vectors;
  u32 n_trace = 0;
  u32 total_enq = 0, n_unprocessed = 0;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 unprocessed_bufs[VLIB_FRAME_SIZE];

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 next_index, n;
      /* fa_data is either SNORT_INPUT or SNORT_OUTPUT */
      vnet_feature_next (&next_index, b[0]);
      u32 l3_offset =
	is_output ? 0 : vnet_buffer (b[0])->ip.save_rewrite_length;
      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      si = pool_elt_at_index (sm->instances,
			      is_output ?
				sm->output_instance_by_interface[sw_if_index] :
				sm->input_instance_by_interface[sw_if_index]);
      qp = vec_elt_at_index (si->qpairs, thread_index);

      /* if client isn't connected skip enqueue and take default action */
      if (PREDICT_FALSE (qp->client_index == SNORT_INVALID_CLIENT_INDEX))
	{
	  if (si->drop_on_disconnect)
	    next[0] = SNORT_ENQ_NEXT_DROP;
	  else
	    next[0] = next_index;
	  next++;
	  unprocessed_bufs[n_unprocessed] = from[0];
	  n_unprocessed++;
	}
      else
	{
	  n = qp->n_pending++;
	  daq_vpp_desc_t *d = qp->pending_descs + n;

	  qp->pending_nexts[n] = next_index;
	  qp->pending_buffers[n] = from[0];

	  vlib_buffer_chain_linearize (vm, b[0]);

	  /* If this pkt is traced, snapshot the data */
	  if (with_trace && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    n_trace++;

	  /* fill descriptor */
	  d->buffer_pool = b[0]->buffer_pool_index;
	  d->length = b[0]->current_length;
	  d->offset = (u8 *) b[0]->data + b[0]->current_data + l3_offset -
		      sm->buffer_pool_base_addrs[d->buffer_pool];
	  d->address_space_id = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	}

      n_left--;
      from++;
      b++;
    }

  if (n_unprocessed)
    {
      vlib_node_increment_counter (vm, snort_enq_node.index,
				   SNORT_ENQ_ERROR_NO_INSTANCE, n_unprocessed);
      vlib_buffer_enqueue_to_next (vm, node, unprocessed_bufs, nexts,
				   n_unprocessed);
    }

  pool_foreach (si, sm->instances)
    {
      u32 head, n_pending, n_enq, mask;
      u16 n_freelist;
      u64 ctr = 1;
      qp = vec_elt_at_index (si->qpairs, thread_index);
      mask = pow2_mask (qp->log2_queue_size);
      n_pending = qp->n_pending;
      qp->n_pending = 0;

      if (n_pending == 0)
	continue;

      n_freelist = qp->n_freelist;

      if (n_freelist < n_pending)
	{
	  n_enq = n_freelist;
	  vlib_buffer_free (vm, qp->pending_buffers + n_enq,
			    n_pending - n_enq);
	  vlib_node_increment_counter (vm, snort_enq_node.index,
				       SNORT_ENQ_ERROR_NO_ENQ_SLOTS,
				       n_pending - n_enq);
	}
      else
	n_enq = n_pending;

      if (n_enq == 0)
	continue;

      total_enq += n_enq;
      head = *qp->enq_head;

      for (u32 i = 0; i < n_enq; i++)
	{
	  u32 desc_index = qp->freelist[--n_freelist];
	  qp->next_indices[desc_index] = qp->pending_nexts[i];
	  ASSERT (qp->buffer_indices[desc_index] == ~0);
	  qp->buffer_indices[desc_index] = qp->pending_buffers[i];
	  clib_memcpy_fast (qp->descriptors + desc_index,
			    qp->pending_descs + i, sizeof (daq_vpp_desc_t));
	  qp->enq_ring[head & mask] = desc_index;

	  /* trace */
	  if (with_trace && n_trace)
	    {
	      vlib_buffer_t *tb = vlib_get_buffer (vm, qp->pending_buffers[i]);
	      if (tb->flags & VLIB_BUFFER_IS_TRACED)
		{
		  snort_enq_trace_t *t =
		    vlib_add_trace (vm, node, tb, sizeof (*t));
		  t->sw_if_index = vnet_buffer (tb)->sw_if_index[VLIB_RX];
		  t->next_index = qp->pending_nexts[i];
		  t->instance = si->index;
		  t->qpair = qp - si->qpairs;
		  t->enq_slot = head & mask;
		  t->desc_index = desc_index;
		  clib_memcpy_fast (&t->desc, qp->pending_descs + i,
				    sizeof (daq_vpp_desc_t));
		}
	    }
	  head = head + 1;
	}

      __atomic_store_n (qp->enq_head, head, __ATOMIC_RELEASE);
      qp->n_freelist = n_freelist;
      if (sm->input_mode == VLIB_NODE_STATE_INTERRUPT)
	{
	  if (write (qp->enq_fd, &ctr, sizeof (ctr)) < 0)
	    vlib_node_increment_counter (vm, snort_enq_node.index,
					 SNORT_ENQ_ERROR_SOCKET_ERROR, 1);
	}
    }

  return total_enq;
}

VLIB_NODE_FN (snort_ip4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return snort_enq_node_inline (vm, node, frame, 1 /* is_trace*/,
				  0 /* is_output */);
  else
    return snort_enq_node_inline (vm, node, frame, 0 /* is_trace*/,
				  0 /* is_output */);
}

VLIB_REGISTER_NODE (snort_ip4_input_node) = {
  .name = "snort-ip4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_enq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SNORT_ENQ_N_NEXT_NODES,
  .next_nodes = SNORT_ENQ_NEXT_NODES,
  .n_errors = ARRAY_LEN (snort_enq_error_strings),
  .error_strings = snort_enq_error_strings,
};

VLIB_NODE_FN (snort_ip4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return snort_enq_node_inline (vm, node, frame, 1 /* is_trace*/,
				  1 /* is_output */);
  else
    return snort_enq_node_inline (vm, node, frame, 0 /* is_trace*/,
				  1 /* is_output */);
}

VLIB_REGISTER_NODE (snort_ip4_output_node) = {
  .name = "snort-ip4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_enq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SNORT_ENQ_N_NEXT_NODES,
  .next_nodes = SNORT_ENQ_NEXT_NODES,
  .n_errors = ARRAY_LEN (snort_enq_error_strings),
  .error_strings = snort_enq_error_strings,
};
