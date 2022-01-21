/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 instance;
  u16 qpair;
  u32 enq_slot;
  u32 desc_index;
  daq_vpp_desc_t desc;
} snort_enq_trace_t;

static u8 *
format_snort_enq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_enq_trace_t *t = va_arg (*args, snort_enq_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s,
	      "sw-if-index %u next-index %u\n"
	      "%Uinstance %u qpair %u desc-index %u slot %u\n"
	      "%Udesc: buffer-pool %u offset %u len %u address-space-id %u\n",
	      t->sw_if_index, t->next_index, format_white_space, indent,
	      t->instance, t->qpair, t->desc_index, t->enq_slot,
	      format_white_space, indent, t->desc.buffer_pool, t->desc.offset,
	      t->desc.length, t->desc.address_space_id);

  return s;
}

#define foreach_snort_enq_error                                               \
  _ (SOCKET_ERROR, "write socket error")                                      \
  _ (NO_INSTANCE, "no snort instance")                                        \
  _ (NO_ENQ_SLOTS, "no enqueue slots (packet dropped)")

typedef enum
{
#define _(sym, str) SNORT_ENQ_ERROR_##sym,
  foreach_snort_enq_error
#undef _
    SNORT_ENQ_N_ERROR,
} snort_enq_error_t;

static char *snort_enq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_enq_error
#undef _
};

static_always_inline uword
snort_enq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int with_trace)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si = 0;
  snort_qpair_t *qp = 0;
  u32 thread_index = vm->thread_index;
  u32 n_left = frame->n_vectors;
  u32 n_trace = 0;
  u32 total_enq = 0, n_processed = 0;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u64 fa_data;
      u32 instance_index, next_index, n;
      u32 l3_offset;

      fa_data =
	*(u64 *) vnet_feature_next_with_data (&next_index, b[0], sizeof (u64));

      instance_index = (u32) (fa_data & 0xffffffff);
      l3_offset =
	(fa_data >> 32) ? vnet_buffer (b[0])->ip.save_rewrite_length : 0;
      si = vec_elt_at_index (sm->instances, instance_index);

      /* if client isn't connected skip enqueue and take default action */
      if (PREDICT_FALSE (si->client_index == ~0))
	{
	  if (si->drop_on_disconnect)
	    next[0] = SNORT_ENQ_NEXT_DROP;
	  else
	    next[0] = next_index;
	  next++;
	  n_processed++;
	}
      else
	{
	  qp = vec_elt_at_index (si->qpairs, thread_index);
	  n = qp->n_pending++;
	  daq_vpp_desc_t *d = qp->pending_descs + n;

	  qp->pending_nexts[n] = next_index;
	  qp->pending_buffers[n] = from[0];

	  vlib_buffer_chain_linearize (vm, b[0]);

	  /* If this pkt is traced, snapshoot the data */
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

  if (n_processed)
    {
      vlib_node_increment_counter (vm, snort_enq_node.index,
				   SNORT_ENQ_ERROR_NO_INSTANCE, n_processed);
      vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
				   nexts, n_processed);
    }

  vec_foreach (si, sm->instances)
    {
      u32 head, freelist_len, n_pending, n_enq, mask;
      u64 ctr = 1;
      qp = vec_elt_at_index (si->qpairs, thread_index);
      mask = pow2_mask (qp->log2_queue_size);
      n_pending = qp->n_pending;
      qp->n_pending = 0;

      if (n_pending == 0)
	continue;

      freelist_len = vec_len (qp->freelist);

      if (freelist_len < n_pending)
	{
	  n_enq = freelist_len;
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
	  u32 desc_index = qp->freelist[--freelist_len];
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
      _vec_len (qp->freelist) = freelist_len;
      if (sm->input_mode == VLIB_NODE_STATE_INTERRUPT)
	{
	  if (write (qp->enq_fd, &ctr, sizeof (ctr)) < 0)
	    vlib_node_increment_counter (vm, snort_enq_node.index,
					 SNORT_ENQ_ERROR_SOCKET_ERROR, 1);
	}
    }

  return total_enq;
}

VLIB_NODE_FN (snort_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return snort_enq_node_inline (vm, node, frame, 1 /* is_trace*/);
  else
    return snort_enq_node_inline (vm, node, frame, 0 /* is_trace*/);
}

VLIB_REGISTER_NODE (snort_enq_node) = {
  .name = "snort-enq",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_enq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SNORT_ENQ_N_NEXT_NODES,
  .next_nodes = SNORT_ENQ_NEXT_NODES,
  .n_errors = ARRAY_LEN (snort_enq_error_strings),
  .error_strings = snort_enq_error_strings,
};
