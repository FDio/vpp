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
} snort_enq_trace_t;

static u8 *
format_snort_enq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_enq_trace_t *t = va_arg (*args, snort_enq_trace_t *);

  s = format (s, "snort-enq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

#define foreach_snort_enq_error                                               \
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

VLIB_NODE_FN (snort_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si = 0;
  snort_qpair_t *qp = 0;
  u32 thread_index = vm->thread_index;
  u32 n_left = frame->n_vectors;
  u32 total_enq = 0;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 instance_index, next_index, n;
      instance_index =
	*(u32 *) vnet_feature_next_with_data (&next_index, b[0], sizeof (u32));
      si = vec_elt_at_index (sm->instances, instance_index);
      qp = vec_elt_at_index (si->qpairs, thread_index);
      n = qp->n_pending++;
      daq_vpp_desc_t *d = qp->pending_descs + n;

      qp->pending_nexts[n] = next_index;
      qp->pending_buffers[n] = from[0];

      vlib_buffer_chain_linearize (vm, b[0]);

      /* fill descriptor */
      d->buffer_pool = b[0]->buffer_pool_index;
      d->length = b[0]->current_length;
      d->offset = (u8 *) b[0]->data + b[0]->current_data -
		  sm->buffer_pool_base_addrs[d->buffer_pool];
      d->address_space_id = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      n_left--;
      from++;
      b++;
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
	  vlib_node_increment_counter (vm, snort_deq_node.index,
				       SNORT_ENQ_N_ERROR, n_pending - n_enq);
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
	  qp->enq_ring[head] = desc_index;
	  head = (head + 1) & mask;
	}

      __atomic_store_n (qp->enq_head, head, __ATOMIC_RELEASE);
      _vec_len (qp->freelist) = freelist_len;
      write (qp->enq_fd, &ctr, sizeof (ctr));
    }

  return total_enq;
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
