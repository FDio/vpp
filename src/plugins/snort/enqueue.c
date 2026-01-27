/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip4_packet.h>
#include <vlib/vlib.h>
#include <vppinfra/vector/array_mask.h>
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
  u8 use_flow_id_hash;
} snort_enq_scalar_args_t;

static_always_inline uword
snort_enq_qpair (vlib_main_t *vm, vlib_node_runtime_t *node,
		 snort_instance_t *si, snort_qpair_t *qp, u16 qpi, u32 *from,
		 daq_vpp_desc_t *descs, u32 *hashes, u32 n_enq, u16 next_index,
		 int single_qpair)
{
  u32 n_free_descs, old_n_free_descs;
  daq_vpp_desc_index_t mask = pow2_mask (qp->log2_queue_size);
  daq_vpp_head_tail_t head;
  u32 i, to_be_freed[VLIB_FRAME_SIZE], n_free = 0;

  if (PREDICT_FALSE (qp->client_index == SNORT_INVALID_CLIENT_INDEX))
    {
      u32 *f;
      if (si->drop_on_disconnect)
	next_index = SNORT_ENQ_NEXT_DROP;
      if (single_qpair)
	{
	  n_free = n_enq;
	  f = from;
	}
      else
	{
	  f = to_be_freed;
	  n_free = 0;

	  for (u32 i = 0; i < n_enq; i++)
	    if (hashes[i] == qpi)
	      to_be_freed[n_free++] = from[i];
	}

      vlib_buffer_enqueue_to_single_next (vm, node, f, next_index, n_free);
      vlib_node_increment_counter (vm, node->node_index,
				   SNORT_ENQ_ERROR_NO_CLIENT, n_free);
      return 0;
    }

  head = __atomic_load_n (&qp->hdr->enq.head, __ATOMIC_ACQUIRE);
  daq_vpp_desc_index_t next_free_desc = qp->next_free_desc;
  old_n_free_descs = n_free_descs = qp->n_free_descs;

  for (i = 0; i < n_enq; i++)
    if (single_qpair || hashes[i] == qpi)
      {
	u32 desc_index = next_free_desc;
	snort_qpair_entry_t *qpe = qp->entries + desc_index;
	daq_vpp_desc_t *d = qp->hdr->descs + desc_index;

	if (n_free_descs == 0)
	  break;

	/* take empty descriptor from freelist */
	next_free_desc = qpe->freelist_next;
	n_free_descs--;

	*d = descs[i];
	qpe->buffer_index = from[i];
	qpe->next_index = next_index;

	/* enqueue */
	qp->enq_ring[head++ & mask] = desc_index;
      }

  __atomic_store_n (&qp->hdr->enq.head, head, __ATOMIC_RELEASE);
  qp->n_free_descs = n_free_descs;
  qp->next_free_desc = next_free_desc;

  if (!__atomic_exchange_n (&qp->hdr->enq.interrupt_pending, 1,
			    __ATOMIC_RELAXED))
    {
      if (write (qp->enq_fd, &(u64){ 1 }, sizeof (u64)) < 0)
	vlib_node_increment_counter (vm, node->node_index,
				     SNORT_ENQ_ERROR_SOCKET_ERROR, 1);
    }

  for (; i < n_enq; i++)
    if (single_qpair || hashes[i] == qpi)
      to_be_freed[n_free++] = from[i];

  if (n_free)
    {
      vlib_buffer_free (vm, to_be_freed, n_free);
      vlib_node_increment_counter (vm, node->node_index,
				   SNORT_ENQ_ERROR_NO_ENQ_SLOTS, n_free);
      n_enq = n_free;
    }

  if (n_free_descs != 1U << qp->log2_queue_size)
    vlib_node_set_interrupt_pending (vm, si->dequeue_node_index);

  return old_n_free_descs - n_free_descs;
}

static_always_inline void
snort_enq_prepare_descs (vlib_main_t *vm, vlib_buffer_t **b, daq_vpp_desc_t *d, void **iph,
			 u32 n_left, int use_rewrite_length_offset, int with_hash)
{
  snort_main_t *sm = &snort_main;
  u8 bpi[4];
  u8 off[4] = { 0, 0, 0, 0 };
  u8 *p[4];

  for (; n_left >= 8; b += 4, d += 4, iph += 4, n_left -= 4)
    {
      clib_prefetch_load (b[4]);
      vlib_buffer_chain_linearize (vm, b[0]);
      vlib_buffer_chain_linearize (vm, b[1]);
      clib_prefetch_load (b[5]);
      vlib_buffer_chain_linearize (vm, b[2]);
      vlib_buffer_chain_linearize (vm, b[3]);

      clib_prefetch_load (b[6]);
      d[0].buffer_pool = bpi[0] = b[0]->buffer_pool_index;
      d[1].buffer_pool = bpi[1] = b[1]->buffer_pool_index;
      d[2].buffer_pool = bpi[2] = b[2]->buffer_pool_index;
      d[3].buffer_pool = bpi[3] = b[3]->buffer_pool_index;
      clib_prefetch_load (b[7]);

      if (use_rewrite_length_offset)
	{
	  off[0] = vnet_buffer (b[0])->ip.save_rewrite_length;
	  off[1] = vnet_buffer (b[1])->ip.save_rewrite_length;
	  off[2] = vnet_buffer (b[2])->ip.save_rewrite_length;
	  off[3] = vnet_buffer (b[3])->ip.save_rewrite_length;
	}

      d[0].length = b[0]->current_length - off[0];
      d[1].length = b[1]->current_length - off[1];
      d[2].length = b[2]->current_length - off[2];
      d[3].length = b[3]->current_length - off[3];

      p[0] = (u8 *) b[0]->data + b[0]->current_data;
      p[1] = (u8 *) b[1]->data + b[1]->current_data;
      p[2] = (u8 *) b[2]->data + b[2]->current_data;
      p[3] = (u8 *) b[3]->data + b[3]->current_data;

      d[0].offset = p[0] + off[0] - sm->buffer_pool_base_addrs[bpi[0]];
      d[1].offset = p[1] + off[1] - sm->buffer_pool_base_addrs[bpi[1]];
      d[2].offset = p[2] + off[2] - sm->buffer_pool_base_addrs[bpi[2]];
      d[3].offset = p[3] + off[3] - sm->buffer_pool_base_addrs[bpi[3]];

      if (with_hash)
	{
	  iph[0] = p[0];
	  iph[1] = p[1];
	  iph[2] = p[2];
	  iph[3] = p[3];
	}

      d[0].metadata = *snort_get_buffer_metadata (b[0]);
      d[1].metadata = *snort_get_buffer_metadata (b[1]);
      d[2].metadata = *snort_get_buffer_metadata (b[2]);
      d[3].metadata = *snort_get_buffer_metadata (b[3]);
    }

  for (; n_left; b++, d++, iph++, n_left--)
    {
      vlib_buffer_chain_linearize (vm, b[0]);
      d[0].buffer_pool = bpi[0] = b[0]->buffer_pool_index;

      if (use_rewrite_length_offset)
	off[0] = vnet_buffer (b[0])->ip.save_rewrite_length;

      d[0].length = b[0]->current_length - off[0];
      p[0] = (u8 *) b[0]->data + b[0]->current_data;
      d[0].offset = p[0] + off[0] - sm->buffer_pool_base_addrs[bpi[0]];

      if (with_hash)
	iph[0] = p[0];

      d[0].metadata = *snort_get_buffer_metadata (b[0]);
    }
}

static_always_inline void
snort_enq_prepare_flow_ids (vlib_buffer_t **b, u32 *flow_ids, u32 n_left)
{
  for (; n_left >= 4; b += 4, flow_ids += 4, n_left -= 4)
    {
      flow_ids[0] = b[0]->flow_id;
      flow_ids[1] = b[1]->flow_id;
      flow_ids[2] = b[2]->flow_id;
      flow_ids[3] = b[3]->flow_id;
    }

  for (; n_left; b++, flow_ids++, n_left--)
    flow_ids[0] = b[0]->flow_id;
}

static_always_inline void
clib_array_hash_to_index_u32 (u32 *src, u32 n_indices, u32 n_elts)
{
  if (count_set_bits (n_indices) == 1)
    {
      clib_array_mask_u32 (src, n_indices - 1, n_elts);
      return;
    }
  for (u32 i = 0; i < n_indices - 1; i++)
    src[i] = ((u64) src[i] * n_indices) >> 32;
}

VLIB_NODE_FN (snort_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_from);
  const snort_enq_scalar_args_t *sa = vlib_frame_scalar_args (frame);
  snort_instance_t *si = pool_elt_at_index (sm->instances, sa->instance_index);
  u16 qpairs_per_thread = si->qpairs_per_thread;
  u16 use_flow_id_hash = (sa->use_flow_id_hash == 1) ? 1 : 0;
  u16 with_hash = (qpairs_per_thread > 1 && use_flow_id_hash == 0) ? 1 : 0;
  snort_qpair_t **qp;
  u16 next_index = sa->dequeue_node_next_index;
  daq_vpp_desc_t descs[VLIB_FRAME_SIZE];
  void *ip_hdrs[VLIB_FRAME_SIZE];
  u32 hashes[VLIB_FRAME_SIZE];

  uword rv = 0;

  /* first qpair for this thread */
  qp = snort_get_qpairs (si, vm->thread_index);

  if (sa->use_rewrite_length_offset)
    {
      if (with_hash)
	snort_enq_prepare_descs (vm, bufs, descs, ip_hdrs, n_from, 1, 1);
      else
	snort_enq_prepare_descs (vm, bufs, descs, 0, n_from, 1, 0);
    }
  else
    {
      if (with_hash)
	snort_enq_prepare_descs (vm, bufs, descs, ip_hdrs, n_from, 0, 1);
      else
	snort_enq_prepare_descs (vm, bufs, descs, 0, n_from, 0, 0);
    }

  if (qpairs_per_thread > 1)
    {
      if (with_hash)
	{
	  /* calculate hash out of pointers to ip headers */
	  si->ip4_hash_fn (ip_hdrs, hashes, n_from);
	}
      else
	snort_enq_prepare_flow_ids (bufs, hashes, n_from);

      /* convert hash to qpair index */
      clib_array_hash_to_index_u32 (hashes, qpairs_per_thread, n_from);
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (u32 i = 0; i < n_from; i++)
	{
	  if (bufs[i]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      snort_enq_trace_t *t =
		vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	      t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	      t->next_index = next_index;
	      t->instance = si->index;
	      t->desc = descs[i];
	      t->qpair_id.thread_id = vm->thread_index;
	      t->qpair_id.queue_id = qpairs_per_thread > 1 ? hashes[i] : 0;
	    }
	}
    }

  if (qpairs_per_thread == 1)
    return snort_enq_qpair (vm, node, si, qp[0], 0, from, descs, 0, n_from,
			    next_index, /* single_qpair */ 1);

  for (u32 qpi = 0; qpi < qpairs_per_thread; qpi++)
    rv += snort_enq_qpair (vm, node, si, qp[qpi], qpi, from, descs, hashes,
			   n_from, next_index, /* single_qpair */ 0);
  return rv;
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
  daq_vpp_pkt_metadata_t metadata = {
    .flags = is_output ? 0 : DAQ_VPP_PKT_FLAG_PRE_ROUTING,
  };

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
      *snort_get_buffer_metadata (b0) = metadata;
      ii[1] = instance_by_interface[vnet_buffer (b1)->sw_if_index[VLIB_RX]];
      *snort_get_buffer_metadata (b1) = metadata;
      ii[2] = instance_by_interface[vnet_buffer (b2)->sw_if_index[VLIB_RX]];
      *snort_get_buffer_metadata (b2) = metadata;
      ii[3] = instance_by_interface[vnet_buffer (b3)->sw_if_index[VLIB_RX]];
      *snort_get_buffer_metadata (b3) = metadata;
    }

  for (; n_left; n_left -= 1, bi += 1, ii += 1)
    {
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, bi[0]);
      ii[0] = instance_by_interface[vnet_buffer (b0)->sw_if_index[VLIB_RX]];
      *snort_get_buffer_metadata (b0) = metadata;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (u32 i = 0; i < n_pkts; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  if (b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      snort_arc_input_trace_t *t =
		vlib_add_trace (vm, node, b, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      t->instance = instance_indices[i];
	    }
	}
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
	.dequeue_node_next_index = is_output ? si->ip4_output_dequeue_node_next_index :
					       si->ip4_input_dequeue_node_next_index,
	.use_rewrite_length_offset = is_output ? 1 : 0,
	.use_flow_id_hash = 0,
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
