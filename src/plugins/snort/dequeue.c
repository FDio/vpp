/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

static u32
snort_deq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       snort_instance_t *si, snort_qpair_t *qp)
{
  u32 buffer_indices[VLIB_FRAME_SIZE], *from;
  u16 next_indices[VLIB_FRAME_SIZE], *nexts;
  u32 n_left, n_deq, error = 0, n_total = 0;
  daq_vpp_head_tail_t head, tail, old_tail;
  daq_vpp_desc_index_t next_free, mask = pow2_mask (qp->log2_queue_size);
  u32 drop_bitmap = si->drop_bitmap;
  u16 n_verdicsts[DAQ_VPP_MAX_DAQ_VERDICT] = {};

  if (PREDICT_FALSE (qp->cleanup_needed))
    {
      u32 qsz = 1 << qp->log2_queue_size;
      if (qp->n_free_descs != qsz)
	{
	  u32 n_free = 0;
	  n_total = 0;
	  for (u32 i = 0; i < qsz; i++)
	    {
	      snort_qpair_entry_t *qpe = qp->entries + i;

	      if (qpe->buffer_index == ~0)
		continue;

	      buffer_indices[n_free++] = qpe->buffer_index;

	      if (n_free == VLIB_FRAME_SIZE)
		{
		  vlib_buffer_free (vm, buffer_indices, VLIB_FRAME_SIZE);
		  n_total += VLIB_FRAME_SIZE;
		  n_free = 0;
		}
	    }
	  if (n_free)
	    vlib_buffer_free (vm, buffer_indices, n_free);
	  n_total += n_free;

	  if (n_total)
	    vlib_node_increment_counter (
	      vm, node->node_index, SNORT_DEQ_ERROR_NO_CLIENT_FREE, n_total);
	}

      snort_qpair_init (qp);
      __atomic_store_n (&qp->cleanup_needed, 0, __ATOMIC_RELEASE);
      return 0;
    }

  tail = qp->deq_tail;
  head = __atomic_load_n (&qp->hdr->deq.head, __ATOMIC_ACQUIRE);
  next_free = qp->next_free_desc;

  if (head == tail)
    return 0;

  old_tail = tail;
more:

  n_left = clib_min (VLIB_FRAME_SIZE, head - tail);

  for (from = buffer_indices, nexts = next_indices; n_left;
       from++, nexts++, n_left--)
    {
      u32 desc_index = qp->deq_ring[tail & mask];
      snort_qpair_entry_t *qpe = qp->entries + desc_index;
      daq_vpp_desc_t *d = qp->hdr->descs + desc_index;
      vlib_buffer_t *b;
      u32 bi = qpe->buffer_index;
      u8 verdict;

      /* check if descriptor index taken from dequeue ring is valid */
      if (desc_index & ~mask)
	{
	  error = 1;
	  vlib_node_increment_counter (vm, node->node_index,
				       SNORT_DEQ_ERROR_BAD_DESC_INDEX, 1);
	  break;
	}

      /* check if descriptor index taken from dequeue ring is already
       * consumed by snort */
      if ((d->flags & DAQ_VPP_DESC_FLAG_USED) == 0)
	{
	  error = 1;
	  vlib_node_increment_counter (vm, node->node_index,
				       SNORT_DEQ_ERROR_BAD_DESC, 1);
	  break;
	}

      b = vlib_get_buffer (vm, bi);

      if (d->flags & DAQ_VPP_DESC_FLAG_INJECTED)
	{
	  qp->ebuf_tail++;
	  snort_qpair_entry_t *respective_qpe =
	    qp->entries + d->metadata.desc_index;
	  d->metadata.desc_index = 0;
	  u32 respective_bi = respective_qpe->buffer_index;
	  vlib_buffer_t *respective_b = vlib_get_buffer (vm, respective_bi);
	  b->current_config_index = respective_b->current_config_index;
	  vnet_buffer (b)->feature_arc_index =
	    vnet_buffer (respective_b)->feature_arc_index;
	  d->metadata.verdict = 0; // DAQ_VPP_VERDICT_PASS
	}

      verdict = d->metadata.verdict;
      from[0] = bi;
      if ((1U << verdict) & drop_bitmap)
	nexts[0] = SNORT_ENQ_NEXT_DROP;
      else
	nexts[0] = qpe->next_index;
      n_verdicsts[verdict]++;
      qpe->buffer_index = ~0;
      *snort_get_buffer_metadata (b) = d->metadata;

      /* put descriptor back to freelist */
      qpe->freelist_next = next_free;
      next_free = desc_index;
      d->flags = DAQ_VPP_DESC_FLAG_FREE;

      /* next */
      tail++;

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_deq_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  t->next_index = nexts[0];
	  t->buffer_index = bi;
	  t->verdict = verdict;
	}
    }

  n_deq = tail - old_tail;

  if (n_deq)
    {
      vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices,
				   n_deq);
      old_tail = tail;
      n_total += n_deq;

      if (!error && tail != head)
	goto more;
    }

  qp->deq_tail = tail;
  qp->n_free_descs += n_total;
  qp->next_free_desc = next_free;

  if (n_total)
    for (u32 i = 0; i < DAQ_VPP_MAX_DAQ_VERDICT; i++)
      qp->n_packets_by_verdict[i] += n_verdicsts[i];

  if (head != tail)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_total;
}

VLIB_NODE_FN (snort_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  snort_deq_runtime_data_t *rt =
    vlib_node_get_runtime_data (vm, node->node_index);
  snort_instance_t *si = pool_elt_at_index (sm->instances, rt->instance_index);
  u32 qpairs_per_thread = si->qpairs_per_thread;
  snort_qpair_t **qp = snort_get_qpairs (si, vm->thread_index);
  uword rv = 0;

  while (qpairs_per_thread--)
    rv += snort_deq_node_inline (vm, node, si, qp++[0]);

  return rv;
}

static_always_inline uword
snort_arc_next_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame)
{
  u32 *buffer_indices = vlib_frame_vector_args (frame), *bi = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *ni = next_indices;
  u32 n_pkts = frame->n_vectors, n_left = n_pkts;

  for (; n_left >= 8; n_left -= 4, bi += 4, ni += 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;

      clib_prefetch_load (vlib_get_buffer (vm, bi[4]));
      b0 = vlib_get_buffer (vm, bi[0]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[5]));
      b1 = vlib_get_buffer (vm, bi[1]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[6]));
      b2 = vlib_get_buffer (vm, bi[2]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[7]));
      b3 = vlib_get_buffer (vm, bi[3]);

      vnet_feature_next_u16 (ni + 0, b0);
      vnet_feature_next_u16 (ni + 1, b1);
      vnet_feature_next_u16 (ni + 2, b2);
      vnet_feature_next_u16 (ni + 3, b3);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_arc_next_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->buffer_index = bi[0];
	  t->next_index = ni[0];
	}

      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_arc_next_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->buffer_index = bi[1];
	  t->next_index = ni[1];
	}

      if (b2->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_arc_next_trace_t *t =
	    vlib_add_trace (vm, node, b2, sizeof (*t));
	  t->buffer_index = bi[2];
	  t->next_index = ni[2];
	}

      if (b3->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_arc_next_trace_t *t =
	    vlib_add_trace (vm, node, b3, sizeof (*t));
	  t->buffer_index = bi[3];
	  t->next_index = ni[3];
	}
    }

  for (; n_left > 0; n_left -= 1, bi += 1, ni += 1)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, bi[0]);
      vnet_feature_next_u16 (ni + 0, b0);
      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_arc_next_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->buffer_index = bi[0];
	  t->next_index = ni[0];
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices, n_pkts);
  return n_pkts;
}

VLIB_NODE_FN (snort_ip4_input_next_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return snort_arc_next_node_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (snort_ip4_input_next_node) = {
  .name = "snort-ip4-input-next",
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u16),
  .format_trace = format_snort_arc_next_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "snort-ip4-input",
};

VLIB_NODE_FN (snort_ip4_output_next_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return snort_arc_next_node_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (snort_ip4_output_next_node) = {
  .name = "snort-ip4-output-next",
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u16),
  .format_trace = format_snort_arc_next_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "snort-ip4-output",
};
