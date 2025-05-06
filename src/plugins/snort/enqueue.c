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

typedef struct
{
  u16 instance_index;
  u16 dequeue_node_next_index;
  u8 use_rewrite_length_offset;
} snort_enq_scalar_args_t;

static_always_inline uword
snort_enq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int with_trace)
{
  snort_main_t *sm = &snort_main;
  snort_qpair_t *qp;
  clib_thread_index_t thread_index = vm->thread_index;
  u32 n_enq = frame->n_vectors;
  u32 n_trace = with_trace ? vlib_get_trace_count (vm, node) : 0;
  u32 total_enq = 0;
  u32 *from = vlib_frame_vector_args (frame);
  const snort_enq_scalar_args_t *sa = vlib_frame_scalar_args (frame);
  snort_instance_t *si = pool_elt_at_index (sm->instances, sa->instance_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 next_index = sa->dequeue_node_next_index;
  daq_vpp_head_tail_t head;
  daq_vpp_desc_index_t mask;

  qp = *vec_elt_at_index (si->qpairs, thread_index);
  mask = (1 << qp->log2_queue_size) - 1;

  if (PREDICT_FALSE (qp->client_index == SNORT_INVALID_CLIENT_INDEX))
    {
      if (si->drop_on_disconnect)
	next_index = SNORT_ENQ_NEXT_DROP;
      vlib_buffer_enqueue_to_single_next (vm, node, from, next_index, n_enq);
      vlib_node_increment_counter (vm, node->node_index,
				   SNORT_ENQ_ERROR_NO_CLIENT, n_enq);
      return 0;
    }

  if (qp->n_free_descs < n_enq)
    {
      u32 n_free = qp->n_free_descs;
      vlib_buffer_free (vm, from + n_free, n_enq - n_free);
      vlib_node_increment_counter (
	vm, node->node_index, SNORT_ENQ_ERROR_NO_ENQ_SLOTS, n_enq - n_free);
      n_enq = n_free;
    }

  vlib_get_buffers (vm, from, bufs, n_enq);

  head = __atomic_load_n (&qp->hdr->enq_head, __ATOMIC_ACQUIRE);
  daq_vpp_desc_index_t next_free_desc = qp->next_free_desc;

  for (u32 n_left = n_enq; n_left; n_left--, from++, b++)
    {
      u32 desc_index, l3_offset;
      u8 buffer_pool_index;

      vlib_buffer_chain_linearize (vm, b[0]);

      desc_index = next_free_desc;
      snort_qpair_entry_t *qpe = qp->entries + desc_index;
      next_free_desc = qpe->freelist_next;
      daq_vpp_desc_t *d = qp->hdr->descs + desc_index;

      /* fill descriptor */
      l3_offset = sa->use_rewrite_length_offset ?
		    0 :
		    vnet_buffer (b[0])->ip.save_rewrite_length;
      buffer_pool_index = b[0]->buffer_pool_index;
      d->buffer_pool = buffer_pool_index;
      d->length = b[0]->current_length - l3_offset;
      d->offset = (u8 *) b[0]->data + b[0]->current_data + l3_offset -
		  sm->buffer_pool_base_addrs[buffer_pool_index];
      d->address_space_id = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      qpe->buffer_index = from[0];
      qpe->next_index = next_index;

      /* trace */
      if (n_trace && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  snort_enq_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->next_index = next_index;
	  t->instance = si->index;
	  t->qpair = qp->qpair_id.thread_id;
	  t->desc_index = desc_index;
	  t->desc = *d;
	  n_trace--;
	}

      /* enqueue */
      qp->enq_ring[head++ & mask] = desc_index;
    }

  __atomic_store_n (&qp->hdr->enq_head, head, __ATOMIC_RELEASE);
  qp->n_free_descs -= n_enq;
  qp->next_free_desc = next_free_desc;

  if (n_enq)
    {
      if (write (qp->enq_fd, &(u64){ 1 }, sizeof (u64)) < 0)
	vlib_node_increment_counter (vm, node->node_index,
				     SNORT_ENQ_ERROR_SOCKET_ERROR, 1);
    }

  if (with_trace)
    vlib_set_trace_count (vm, node, n_trace);

  return total_enq;
}

VLIB_NODE_FN (snort_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return snort_enq_node_inline (vm, node, frame, 1 /* is_trace */);
  else
    return snort_enq_node_inline (vm, node, frame, 0 /* is_trace */);
}

VLIB_REGISTER_NODE (snort_enq_node) = {
  .name = "snort-enq",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (snort_enq_scalar_args_t),
  .format_trace = format_snort_enq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SNORT_ENQ_N_NEXT_NODES,
  .next_nodes = SNORT_ENQ_NEXT_NODES,
  .n_errors = ARRAY_LEN (snort_enq_error_strings),
  .error_strings = snort_enq_error_strings,
};

static_always_inline uword
snort_arc_input (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, int is_output)
{
  snort_main_t *sm = &snort_main;
  u16 *instance_by_interface = is_output ? sm->output_instance_by_interface :
					   sm->input_instance_by_interface;
  u32 *buffer_indices = vlib_frame_vector_args (frame), *bi = buffer_indices;
  u32 n_pkts = frame->n_vectors, n_left = n_pkts, n_total_left = n_pkts;
  u16 instance_indices[VLIB_FRAME_SIZE], *ii = instance_indices;

  for (; n_left >= 8; n_left -= 4, bi += 4, ii += 4)
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

      ii[0] = instance_by_interface[vnet_buffer (b0)->sw_if_index[VLIB_RX]];
      ii[1] = instance_by_interface[vnet_buffer (b1)->sw_if_index[VLIB_RX]];
      ii[2] = instance_by_interface[vnet_buffer (b2)->sw_if_index[VLIB_RX]];
      ii[3] = instance_by_interface[vnet_buffer (b3)->sw_if_index[VLIB_RX]];
    }

  for (; n_left; n_left -= 1, bi += 1, ii += 1)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, bi[0]);
      ii[0] = instance_by_interface[vnet_buffer (b0)->sw_if_index[VLIB_RX]];
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 n_trace = vlib_get_trace_count (vm, node);
      for (u32 i = 0; n_trace && i < n_pkts; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  if (b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      snort_arc_input_trace_t *t =
		vlib_add_trace (vm, node, b, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      t->instance = instance_indices[i];
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  while (n_total_left)
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      snort_enq_scalar_args_t *sa;
      u32 *to_next, n_left_to_next, *not_now = buffer_indices;
      u16 next_index = 0; /* snort_enq */
      u16 instance_index = instance_indices[0];
      snort_instance_t *si = pool_elt_at_index (sm->instances, instance_index);
      u16 n_enq;

      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

      to_next++[0] = buffer_indices[0];
      n_enq = 1;

      for (u32 i = 1; i < n_total_left; i++)
	if (instance_indices[i] == instance_index)
	  {
	    to_next++[0] = buffer_indices[i];
	    n_enq++;
	  }
	else
	  not_now++[0] = buffer_indices[i];

      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      sa = vlib_frame_scalar_args (f);
      *sa = (snort_enq_scalar_args_t){
	.instance_index = instance_index,
	.dequeue_node_next_index = is_output ?
				     si->ip4_output_dequeue_node_next_index :
				     si->ip4_input_dequeue_node_next_index,
	.use_rewrite_length_offset = is_output ? 1 : 0,
      };
      vlib_frame_no_append (f);
      vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_enq);
      n_total_left -= n_enq;
    }

  return n_pkts;
}

VLIB_NODE_FN (snort_ip4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return snort_arc_input (vm, node, frame, 0 /* is_output */);
}

VLIB_REGISTER_NODE (snort_ip4_input_node) = {
  .name = "snort-ip4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_arc_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .next_nodes = {
      [0] = "snort-enq",
  },
  .n_next_nodes = 1,
};

VLIB_NODE_FN (snort_ip4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return snort_arc_input (vm, node, frame, 1 /* is_output */);
}

VLIB_REGISTER_NODE (snort_ip4_output_node) = {
  .name = "snort-ip4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_arc_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .next_nodes = {
      [0] = "snort-enq",
  },
  .n_next_nodes = 1,
};
