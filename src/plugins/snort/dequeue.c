/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

static u32
snort_deq_node_polling (vlib_main_t *vm, vlib_node_runtime_t *node,
			snort_instance_t *si)
{
  u32 buffer_indices[VLIB_FRAME_SIZE], *from = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *nexts = next_indices;
  snort_qpair_t *qp = *vec_elt_at_index (si->qpairs, vm->thread_index);
  u32 qsz = 1 << qp->log2_queue_size;
  u32 n_deq, error = 0, n_total = 0;
  daq_vpp_head_tail_t head, tail;
  daq_vpp_desc_index_t next_free, mask = pow2_mask (qp->log2_queue_size);

  tail = qp->deq_tail;
  next_free = qp->next_free_desc;

more:
  head = __atomic_load_n (&qp->hdr->deq_head, __ATOMIC_ACQUIRE);

  if (head == tail)
    goto nothing_enqueued;

  n_deq = 0;
  from = buffer_indices;
  nexts = next_indices;

  while (n_deq < VLIB_FRAME_SIZE)
    {
      u32 desc_index, bi;
      daq_vpp_desc_t *d;
      snort_qpair_entry_t *qpe;

      /* check if descriptor index taken from dequqe ring is valid */
      desc_index = qp->deq_ring[tail & mask];

      qpe = qp->entries + desc_index;
      if (desc_index & ~mask)
	{
	  error = 1;
	  vlib_node_increment_counter (vm, node->node_index,
				       SNORT_DEQ_ERROR_BAD_DESC_INDEX, 1);
	  goto done;
	}

      /* check if descriptor index taken from dequeue ring points to
       * enqueued buffer */
      bi = qpe->buffer_index;
      if (bi == ~0)
	{
	  error = 1;
	  vlib_node_increment_counter (vm, node->node_index,
				       SNORT_DEQ_ERROR_BAD_DESC, 1);
	  goto done;
	}

      /* put descriptor back to freelist */
      qpe->freelist_next = next_free;
      next_free = desc_index;

      d = qp->hdr->descs + desc_index;
      from++[0] = bi;
      if (d->action == DAQ_VPP_ACTION_FORWARD)
	nexts++[0] = qpe->next_index;
      else
	nexts++[0] = SNORT_ENQ_NEXT_DROP;
      qpe->buffer_index = ~0;

      /* next */
      tail++;
      n_deq++;
    }

done:
  if (n_deq)
    {
      vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices,
				   n_deq);
      n_total += n_deq;
    }

  if (!error && tail != head)
    goto more;

  qp->deq_tail = tail;
  qp->n_free_descs += n_total;
  qp->next_free_desc = next_free;

nothing_enqueued:
  if (qp->cleanup_needed)
    {
      if (qp->n_free_descs != qsz)
	{
	  u32 n_free = 0;
	  from = buffer_indices;
	  n_total = 0;
	  for (u32 i = 0; i < qsz; i++)
	    {
	      snort_qpair_entry_t *qpe = qp->entries + i;

	      if (qpe->buffer_index == ~0)
		continue;

	      from++[0] = qpe->buffer_index;
	      if (n_free == VLIB_FRAME_SIZE)
		{
		  vlib_buffer_free (vm, buffer_indices, VLIB_FRAME_SIZE);
		  from = buffer_indices;
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
    }

  return n_total;
}

VLIB_NODE_FN (snort_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  snort_deq_runtime_data_t *rt =
    vlib_node_get_runtime_data (vm, node->node_index);
  snort_instance_t *si = pool_elt_at_index (sm->instances, rt->instance_index);
  return snort_deq_node_polling (vm, node, si);
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
    }

  for (; n_left > 0; n_left -= 1, bi += 1, ni += 1)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, bi[0]);
      vnet_feature_next_u16 (ni + 0, b0);
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
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "snort-ip4-output",
};
