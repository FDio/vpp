/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

static char *snort_deq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_deq_error
#undef _
};

static_always_inline uword
snort_deq_instance (vlib_main_t *vm, u32 node_index, u32 instance_index,
		    snort_qpair_t *qp, u32 *buffer_indices, u16 *nexts,
		    u32 max_recv)
{
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u32 mask = pow2_mask (qp->log2_queue_size);
  u32 head, next, n_recv = 0, n_left;

  head = __atomic_load_n (qp->deq_head, __ATOMIC_ACQUIRE);
  next = qp->next_desc;

  n_left = head - next;

  if (n_left == 0)
    return 0;

  if (n_left > max_recv)
    {
      n_left = max_recv;
      clib_interrupt_set (ptd->interrupts, (int) instance_index);
      vlib_node_set_interrupt_pending (vm, node_index);
    }

  while (n_left)
    {
      u32 desc_index, bi;
      daq_vpp_desc_t *d;

      /* check if descriptor index taken from dequqe ring is valid */
      if ((desc_index = qp->deq_ring[next & mask]) & ~mask)
	{
	  vlib_node_increment_counter (vm, node_index,
				       SNORT_DEQ_ERROR_BAD_DESC_INDEX, 1);
	  goto next;
	}

      /* check if descriptor index taken from dequeue ring points to enqueued
       * buffer */
      if ((bi = qp->buffer_indices[desc_index]) == ~0)
	{
	  vlib_node_increment_counter (vm, node_index,
				       SNORT_DEQ_ERROR_BAD_DESC, 1);
	  goto next;
	}

      /* put descriptor back to freelist */
      qp->freelist[qp->n_freelist++] = desc_index;
      d = qp->descriptors + desc_index;
      buffer_indices++[0] = bi;
      if (d->action == DAQ_VPP_ACTION_FORWARD)
	nexts[0] = qp->next_indices[desc_index];
      else
	nexts[0] = SNORT_ENQ_NEXT_DROP;
      qp->buffer_indices[desc_index] = ~0;
      nexts++;
      n_recv++;

      /* next */
    next:
      next = next + 1;
      n_left--;
    }

  qp->next_desc = next;

  return n_recv;
}

static_always_inline u32
snort_process_all_buffer_indices (snort_qpair_t *qp, u32 *b, u16 *nexts,
				  u32 max_recv, u8 drop_on_disconnect)
{
  u32 *bi, n_processed = 0;
  u32 desc_index = 0;

  vec_foreach (bi, qp->buffer_indices)
    {
      if (n_processed >= max_recv)
	break;

      if (bi[0] == ~0)
	continue;

      desc_index = bi - qp->buffer_indices;

      b[0] = bi[0];
      if (drop_on_disconnect)
	nexts[0] = SNORT_ENQ_NEXT_DROP;
      else
	nexts[0] = qp->next_indices[desc_index];
      qp->buffer_indices[desc_index] = ~0;

      nexts += 1;
      b += 1;
      n_processed += 1;
    }
  return n_processed;
}

static_always_inline uword
snort_deq_instance_all_interrupt (vlib_main_t *vm, u32 node_index,
				  u32 instance_index, snort_qpair_t *qp,
				  u32 *buffer_indices, u16 *nexts,
				  u32 max_recv, u8 drop_on_disconnect)
{
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u32 n_processed;

  n_processed = snort_process_all_buffer_indices (
    qp, buffer_indices, nexts, max_recv, drop_on_disconnect);

  if (n_processed == max_recv)
    {
      clib_interrupt_set (ptd->interrupts, instance_index);
      vlib_node_set_interrupt_pending (vm, node_index);
    }
  else
    {
      *qp->enq_head = *qp->deq_head = qp->next_desc = 0;
      snort_freelist_init (qp);
      __atomic_store_n (&qp->ready, 1, __ATOMIC_RELEASE);
    }

  return n_processed;
}

static u32
snort_deq_node_interrupt (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *nexts = next_indices;
  u32 n_left = VLIB_FRAME_SIZE, n;
  snort_qpair_t *qp;
  snort_instance_t *si;
  int inst = -1;

  while ((inst = clib_interrupt_get_next_and_clear (ptd->interrupts, inst)) !=
	 -1)
    {
      si = vec_elt_at_index (sm->instances, inst);
      qp = vec_elt_at_index (si->qpairs, vm->thread_index);
      u32 ready = __atomic_load_n (&qp->ready, __ATOMIC_ACQUIRE);
      if (!ready)
	n = snort_deq_instance_all_interrupt (vm, node->node_index, inst, qp,
					      bi, nexts, n_left,
					      si->drop_on_disconnect);
      else
	n = snort_deq_instance (vm, node->node_index, inst, qp, bi, nexts,
				n_left);

      n_left -= n;
      bi += n;
      nexts += n;

      if (n_left == 0)
	goto enq;
    }

  if (n_left == VLIB_FRAME_SIZE)
    return 0;

enq:
  n = VLIB_FRAME_SIZE - n_left;
  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices, n);
  return n;
}

static_always_inline uword
snort_deq_instance_poll (vlib_main_t *vm, u32 node_index, snort_qpair_t *qp,
			 u32 *buffer_indices, u16 *nexts, u32 max_recv)
{
  u32 mask = pow2_mask (qp->log2_queue_size);
  u32 head, next, n_recv = 0, n_left;
  u32 n_bad_desc = 0, n_bad_desc_index = 0;

  head = __atomic_load_n (qp->deq_head, __ATOMIC_ACQUIRE);
  next = qp->next_desc;

  n_left = head - next;

  if (n_left == 0)
    return 0;

  if (n_left > max_recv)
    n_left = max_recv;

  while (n_left)
    {
      u32 desc_index, bi;
      daq_vpp_desc_t *d;

      /* check if descriptor index taken from dequqe ring is valid */
      desc_index = qp->deq_ring[next & mask];
      if (desc_index & ~mask)
	{
	  n_bad_desc_index++;
	  goto next;
	}

      /* check if descriptor index taken from dequeue ring points to enqueued
       * buffer */
      bi = qp->buffer_indices[desc_index];
      if (bi == ~0)
	{
	  n_bad_desc++;
	  goto next;
	}

      /* put descriptor back to freelist */
      qp->freelist[qp->n_freelist++] = desc_index;
      d = qp->descriptors + desc_index;
      buffer_indices++[0] = bi;
      if (d->action == DAQ_VPP_ACTION_FORWARD)
	nexts[0] = qp->next_indices[desc_index];
      else
	nexts[0] = SNORT_ENQ_NEXT_DROP;
      qp->buffer_indices[desc_index] = ~0;
      nexts++;
      n_recv++;

      /* next */
    next:
      next = next + 1;
      n_left--;
    }

  qp->next_desc = next;

  if (n_bad_desc)
    vlib_node_increment_counter (vm, node_index, SNORT_DEQ_ERROR_BAD_DESC,
				 n_bad_desc);
  if (n_bad_desc_index)
    vlib_node_increment_counter (
      vm, node_index, SNORT_DEQ_ERROR_BAD_DESC_INDEX, n_bad_desc_index);

  return n_recv;
}

static_always_inline uword
snort_deq_instance_all_poll (vlib_main_t *vm, snort_qpair_t *qp,
			     u32 *buffer_indices, u16 *nexts, u32 max_recv,
			     u8 drop_on_disconnect)
{
  u32 n_processed = snort_process_all_buffer_indices (
    qp, buffer_indices, nexts, max_recv, drop_on_disconnect);
  if (n_processed < max_recv)
    {
      *qp->enq_head = *qp->deq_head = qp->next_desc = 0;
      snort_freelist_init (qp);
      __atomic_store_n (&qp->ready, 1, __ATOMIC_RELEASE);
    }

  return n_processed;
}

static u32
snort_deq_node_polling (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  snort_main_t *sm = &snort_main;
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *nexts = next_indices;
  u32 n_left = VLIB_FRAME_SIZE, n, n_total = 0;
  snort_qpair_t *qp;
  snort_instance_t *si;

  pool_foreach (si, sm->instances)
    {
      qp = vec_elt_at_index (si->qpairs, vm->thread_index);
      u32 ready = __atomic_load_n (&qp->ready, __ATOMIC_ACQUIRE);
      if (!ready)
	n = snort_deq_instance_all_poll (vm, qp, bi, nexts, n_left,
					 si->drop_on_disconnect);
      else
	n = snort_deq_instance_poll (vm, node->node_index, qp, bi, nexts,
				     n_left);

      n_left -= n;
      bi += n;
      nexts += n;

      if (n_left == 0)
	{
	  n = VLIB_FRAME_SIZE - n_left;
	  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices,
				       n);
	  n_left = VLIB_FRAME_SIZE;
	  bi = buffer_indices;
	  nexts = next_indices;
	  n_total += n;
	}
    }

  if (n_left < VLIB_FRAME_SIZE)
    {
      n = VLIB_FRAME_SIZE - n_left;
      vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices, n);
      n_total += n;
    }
  return n_total;
}

VLIB_NODE_FN (snort_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  if (sm->input_mode == VLIB_NODE_STATE_POLLING)
    return snort_deq_node_polling (vm, node);
  return snort_deq_node_interrupt (vm, node);
}

VLIB_REGISTER_NODE (snort_deq_node) = {
  .name = "snort-deq",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_deq_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .n_errors = ARRAY_LEN (snort_deq_error_strings),
  .error_strings = snort_deq_error_strings,

  .n_next_nodes = 0,
};

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
