/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

static_always_inline u32
vlib_handoff_slot_copy_indices (u32 *dst, vlib_handoff_queue_slot_t *slot, u32 first_bi)
{
  u32 n;

  dst[0] = first_bi;
  for (n = 1; n < VLIB_HANDOFF_QUEUE_SLOT_SIZE; n++)
    {
      if (slot->buffer_indices[n] == VLIB_BUFFER_INVALID_INDEX)
	break;
      dst[n] = slot->buffer_indices[n];
    }

  return n;
}

static_always_inline u32
vlib_handoff_queue_dequeue_inline (vlib_main_t *vm, vlib_handoff_queue_main_t *hqm, u8 with_aux)
{
  u32 thread_id = vm->thread_index;
  vlib_handoff_queue_t *hq = hqm->vlib_handoff_queues[thread_id];
  u32 mask = hq->size - 1;
  u32 dequeue_vector_limit = hq->dequeue_vector_limit;
  vlib_handoff_queue_slot_t *bi_slots = vlib_handoff_queue_buffer_index_slots (hq);
  vlib_handoff_queue_slot_t *aux_slots = vlib_handoff_queue_aux_slots (hq);
  u32 n_free, n_copy, *to = 0, *to_aux = 0, n_deq = 0;
  u64 trace_stop;
  vlib_frame_t *f = 0;

  ASSERT (hq);

  while (1)
    {
      u64 head = __atomic_load_n (&hq->head, __ATOMIC_RELAXED);
      u32 slot_index = head & mask;
      vlib_handoff_queue_slot_t *slot = bi_slots + slot_index;
      u32 first_bi = __atomic_load_n (&slot->buffer_indices[0], __ATOMIC_ACQUIRE);

      if (first_bi == VLIB_BUFFER_INVALID_INDEX)
	break;

      if (n_deq + VLIB_HANDOFF_QUEUE_SLOT_SIZE > dequeue_vector_limit)
	break;

      if (f && VLIB_HANDOFF_QUEUE_SLOT_SIZE > n_free)
	{
	  f->n_vectors = VLIB_FRAME_SIZE - n_free;
	  vlib_put_frame_to_node (vm, hqm->node_index, f);
	  f = 0;
	}

      if (f == 0)
	{
	  f = vlib_get_frame_to_node (vm, hqm->node_index);
	  to = vlib_frame_vector_args (f);
	  if (with_aux)
	    to_aux = vlib_frame_aux_args (f);
	  n_free = VLIB_FRAME_SIZE;
	}

      trace_stop = __atomic_load_n (&hq->trace_stop, __ATOMIC_RELAXED);
      if (trace_stop > head)
	f->frame_flags |= VLIB_NODE_FLAG_TRACE;

      n_copy = vlib_handoff_slot_copy_indices (to, slot, first_bi);
      ASSERT (n_copy);
      to += n_copy;
      if (with_aux)
	{
	  vlib_buffer_copy_indices (to_aux, aux_slots[slot_index].buffer_indices, n_copy);
	  to_aux += n_copy;
	}

      n_free -= n_copy;

      if (n_free == 0)
	{
	  f->n_vectors = VLIB_FRAME_SIZE;
	  vlib_put_frame_to_node (vm, hqm->node_index, f);
	  f = 0;
	}

      __atomic_store_n (&slot->buffer_indices[0], VLIB_BUFFER_INVALID_INDEX, __ATOMIC_RELEASE);
      head++;
      __atomic_store_n (&hq->head, head, __ATOMIC_RELAXED);
      n_deq += n_copy;

      /* Limit the number of packets pushed into the graph */
      if (n_deq >= dequeue_vector_limit)
	break;
    }

  if (f)
    {
      f->n_vectors = VLIB_FRAME_SIZE - n_free;
      vlib_put_frame_to_node (vm, hqm->node_index, f);
    }

  return n_deq;
}

u32 __clib_section (".vlib_handoff_queues_dequeue_fn")
CLIB_MULTIARCH_FN (vlib_handoff_queues_dequeue_fn)
(vlib_main_t *vm)
{
  vlib_handoff_queue_main_t *hqm;
  u32 n_deq = 0;

  vec_foreach (hqm, vm->handoff_queue_mains)
    {
      if (PREDICT_FALSE (hqm->with_aux))
	n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 1 /* with_aux */);
      else
	n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 0 /* with_aux */);
    }

  return n_deq;
}

CLIB_MARCH_FN_REGISTRATION (vlib_handoff_queues_dequeue_fn);

static_always_inline void
vlib_handoff_queue_update_trace_stop (vlib_handoff_queue_t *hq, u64 stop)
{
  u64 old = __atomic_load_n (&hq->trace_stop, __ATOMIC_RELAXED);

  while (stop > old && !__atomic_compare_exchange_n (&hq->trace_stop, &old, stop, 0 /* weak */,
						     __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    ;
}

static_always_inline u32
vlib_handoff_queue_get_slots (vlib_handoff_queue_t *hq, u32 n_slots_requested, u64 *first_slot,
			      u8 *do_wakeup)
{
  u64 tail, new_tail, head, n_avail;
  u32 n_slots;

retry:
  tail = __atomic_load_n (&hq->tail, __ATOMIC_RELAXED);
  head = __atomic_load_n (&hq->head, __ATOMIC_ACQUIRE);
  n_avail = head + hq->size - tail;
  n_slots = clib_min (n_slots_requested, n_avail);

  if (n_slots == 0)
    return 0;

  new_tail = tail + n_slots;
  if (!__atomic_compare_exchange_n (&hq->tail, &tail, new_tail, 0 /* weak */, __ATOMIC_RELAXED,
				    __ATOMIC_RELAXED))
    goto retry;

  *first_slot = tail;
  *do_wakeup |= tail == head;

  return n_slots;
}

static_always_inline void
vlib_handoff_queue_copy_to_slots (vlib_handoff_queue_slot_t *slots, u32 mask, u64 start, u32 *src,
				  u32 n_vectors)
{
  u32 n_left = n_vectors;
  u32 slot_index = start & mask;

  while (n_left)
    {
      vlib_handoff_queue_slot_t *slot = slots + slot_index;
      u32 n_copy = clib_min (n_left, VLIB_HANDOFF_QUEUE_SLOT_SIZE);

      if (n_copy > 1)
	vlib_buffer_copy_indices (slot->buffer_indices + 1, src + 1, n_copy - 1);
      if (n_copy < VLIB_HANDOFF_QUEUE_SLOT_SIZE)
	clib_memset_u32 (slot->buffer_indices + n_copy, VLIB_BUFFER_INVALID_INDEX,
			 VLIB_HANDOFF_QUEUE_SLOT_SIZE - n_copy);
      slot->buffer_indices[0] = src[0];

      src += n_copy;
      n_left -= n_copy;
      slot_index = (slot_index + 1) & mask;
    }
}

static_always_inline void
vlib_handoff_queue_copy_indices_to_slots (vlib_handoff_queue_slot_t *slots, u32 mask, u64 start,
					  u32 *src, u32 n_vectors)
{
  u32 n_left = n_vectors;
  u32 slot_index = start & mask;

  while (n_left)
    {
      vlib_handoff_queue_slot_t *slot = slots + slot_index;
      u32 n_copy = clib_min (n_left, VLIB_HANDOFF_QUEUE_SLOT_SIZE);

      if (n_copy > 1)
	vlib_buffer_copy_indices (slot->buffer_indices + 1, src + 1, n_copy - 1);
      if (n_copy < VLIB_HANDOFF_QUEUE_SLOT_SIZE)
	clib_memset_u32 (slot->buffer_indices + n_copy, VLIB_BUFFER_INVALID_INDEX,
			 VLIB_HANDOFF_QUEUE_SLOT_SIZE - n_copy);

      src += n_copy;
      n_left -= n_copy;
      slot_index = (slot_index + 1) & mask;
    }
}

static_always_inline void
vlib_handoff_queue_publish_slots (vlib_handoff_queue_slot_t *slots, u32 mask, u64 start, u32 *src,
				  u32 n_vectors)
{
  u32 n_left = n_vectors;
  u32 n_copy;
  u32 slot_index = start & mask;
  vlib_handoff_queue_slot_t *first_slot = slots + slot_index;
  u32 first_bi = src[0];

  n_copy = clib_min (n_left, VLIB_HANDOFF_QUEUE_SLOT_SIZE);
  src += n_copy;
  n_left -= n_copy;
  slot_index = (slot_index + 1) & mask;

  while (n_left)
    {
      vlib_handoff_queue_slot_t *slot = slots + slot_index;
      n_copy = clib_min (n_left, VLIB_HANDOFF_QUEUE_SLOT_SIZE);

      slot->buffer_indices[0] = src[0];

      src += n_copy;
      n_left -= n_copy;
      slot_index = (slot_index + 1) & mask;
    }

  __atomic_store_n (first_slot->buffer_indices, first_bi, __ATOMIC_RELEASE);
}

static_always_inline u32
vlib_buffer_enqueue_to_thread_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				      vlib_handoff_queue_main_t *hqm, u32 *buffer_indices,
				      u16 *thread_indices, u32 n_packets, int with_aux,
				      u32 *aux_data)
{
  u32 enqueue_list[VLIB_FRAME_SIZE], enqueue_aux[VLIB_FRAME_SIZE];
  vlib_frame_bitmap_t mask, used_elts = {};
  vlib_handoff_queue_t *hq;
  clib_thread_index_t thread_index;
  vlib_handoff_queue_slot_t *buffer_index_slots, *aux_slots;
  u8 do_wakeup = 0;
  u64 size, start;
  u32 *drop;
  u32 n_comp, n_drop, n_drop_total = 0, n_enq, n_slots, off = 0, n_left = n_packets;
  u32 ring_mask;
  u32 maybe_trace;

  thread_index = thread_indices[0];
  maybe_trace = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;

more:
  clib_mask_compare_u16 (thread_index, thread_indices, mask, n_packets);
  hq = vec_elt (hqm->vlib_handoff_queues, thread_index);
  ASSERT (hq);
  size = hq->size;
  ring_mask = size - 1;
  buffer_index_slots = vlib_handoff_queue_buffer_index_slots (hq);
  aux_slots = vlib_handoff_queue_aux_slots (hq);
  n_comp = clib_compress_u32 (enqueue_list, buffer_indices, mask, n_packets);
  if (with_aux)
    clib_compress_u32 (enqueue_aux, aux_data, mask, n_packets);
  n_drop = 0;

  do_wakeup = 0;
  n_slots = round_pow2 (n_comp, VLIB_HANDOFF_QUEUE_SLOT_SIZE) / VLIB_HANDOFF_QUEUE_SLOT_SIZE;
  n_slots = vlib_handoff_queue_get_slots (hq, n_slots, &start, &do_wakeup);
  if (n_slots == 0)
    {
      drop = enqueue_list;
      n_drop = n_comp;
      goto next;
    }

  n_enq = clib_min (n_comp, n_slots * VLIB_HANDOFF_QUEUE_SLOT_SIZE);

  if (with_aux)
    vlib_handoff_queue_copy_to_slots (aux_slots, ring_mask, start, enqueue_aux, n_enq);

  if (maybe_trace)
    vlib_handoff_queue_update_trace_stop (hq, start + n_slots);
  vlib_handoff_queue_copy_indices_to_slots (buffer_index_slots, ring_mask, start, enqueue_list,
					    n_enq);
  vlib_handoff_queue_publish_slots (buffer_index_slots, ring_mask, start, enqueue_list, n_enq);
  __atomic_store_n (&vlib_get_main_by_index (thread_index)->check_handoff_queues, 1,
		    __ATOMIC_RELAXED);
  if (do_wakeup)
    vlib_thread_wakeup (thread_index);

  if (n_enq < n_comp)
    {
      drop = enqueue_list + n_enq;
      n_drop = n_comp - n_enq;
    }

next:
  if (n_drop)
    {
      vlib_buffer_free (vm, drop, n_drop);
      n_drop_total += n_drop;
    }

  n_left -= n_comp;

  if (n_left)
    {
      vlib_frame_bitmap_or (used_elts, mask);

      while (PREDICT_FALSE (used_elts[off] == ~0))
	{
	  off++;
	  ASSERT (off < ARRAY_LEN (used_elts));
	}

      thread_index = thread_indices[off * 64 + count_trailing_zeros (~used_elts[off])];
      goto more;
    }

  return n_packets - n_drop_total;
}

static_always_inline u32
vlib_buffer_enqueue_to_single_thread_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
					     vlib_handoff_queue_main_t *hqm, u32 *buffer_indices,
					     clib_thread_index_t thread_index, u32 n_packets,
					     int with_aux, u32 *aux_data)
{
  u8 do_wakeup = 0;
  u64 start;
  u32 *drop;
  u32 n_drop = 0, n_enq, n_slots, maybe_trace;
  vlib_handoff_queue_t *hq = vec_elt (hqm->vlib_handoff_queues, thread_index);
  u64 size = hq->size;
  u32 ring_mask = size - 1;
  vlib_handoff_queue_slot_t *bi_slots = vlib_handoff_queue_buffer_index_slots (hq);
  vlib_handoff_queue_slot_t *aux_slots = vlib_handoff_queue_aux_slots (hq);
  maybe_trace = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;

  n_slots = round_pow2 (n_packets, VLIB_HANDOFF_QUEUE_SLOT_SIZE) / VLIB_HANDOFF_QUEUE_SLOT_SIZE;
  n_slots = vlib_handoff_queue_get_slots (hq, n_slots, &start, &do_wakeup);
  if (n_slots == 0)
    {
      drop = buffer_indices;
      n_drop = n_packets;
      goto done;
    }

  n_enq = clib_min (n_packets, n_slots * VLIB_HANDOFF_QUEUE_SLOT_SIZE);

  if (with_aux)
    vlib_handoff_queue_copy_to_slots (aux_slots, ring_mask, start, aux_data, n_enq);

  if (maybe_trace)
    vlib_handoff_queue_update_trace_stop (hq, start + n_slots);
  vlib_handoff_queue_copy_indices_to_slots (bi_slots, ring_mask, start, buffer_indices, n_enq);
  vlib_handoff_queue_publish_slots (bi_slots, ring_mask, start, buffer_indices, n_enq);

  if (n_enq < n_packets)
    {
      drop = buffer_indices + n_enq;
      n_drop = n_packets - n_enq;
    }

done:
  if (n_drop)
    vlib_buffer_free (vm, drop, n_drop);

  if (n_slots)
    {
      __atomic_store_n (&vlib_get_main_by_index (thread_index)->check_handoff_queues, 1,
			__ATOMIC_RELAXED);
      if (do_wakeup)
	vlib_thread_wakeup (thread_index);
    }

  return n_packets - n_drop;
}

u32 __clib_section (".vlib_buffer_enqueue_to_thread_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 handoff_queue_index, u32 *buffer_indices,
 u16 *thread_indices, u32 n_packets, int drop_on_congestion __clib_unused)
{
  vlib_handoff_queue_main_t *hqm;
  u32 n_enq = 0;

  hqm = vec_elt_at_index (vm->handoff_queue_mains, handoff_queue_index);

  while (n_packets >= VLIB_FRAME_SIZE)
    {
      n_enq += vlib_buffer_enqueue_to_thread_inline (vm, node, hqm, buffer_indices, thread_indices,
						     VLIB_FRAME_SIZE, 0 /* with_aux */, NULL);
      buffer_indices += VLIB_FRAME_SIZE;
      thread_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_buffer_enqueue_to_thread_inline (vm, node, hqm, buffer_indices, thread_indices,
						 n_packets, 0 /* with_aux */, NULL);

  return n_enq;
}

u32 __clib_section (".vlib_buffer_enqueue_to_single_thread_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_thread_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 handoff_queue_index, u32 *buffer_indices,
 clib_thread_index_t thread_index, u32 n_packets)
{
  vlib_handoff_queue_main_t *hqm;
  u32 n_enq = 0;

  hqm = vec_elt_at_index (vm->handoff_queue_mains, handoff_queue_index);

  while (n_packets >= VLIB_FRAME_SIZE)
    {
      n_enq += vlib_buffer_enqueue_to_single_thread_inline (
	vm, node, hqm, buffer_indices, thread_index, VLIB_FRAME_SIZE, 0 /* with_aux */, NULL);
      buffer_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_buffer_enqueue_to_single_thread_inline (vm, node, hqm, buffer_indices, thread_index,
							n_packets, 0 /* with_aux */, NULL);

  return n_enq;
}

u32 __clib_section (".vlib_buffer_enqueue_to_thread_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_with_aux_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 handoff_queue_index, u32 *buffer_indices, u32 *aux,
 u16 *thread_indices, u32 n_packets, int drop_on_congestion __clib_unused)
{
  u32 n_enq = 0;
  vlib_handoff_queue_main_t *hqm = vec_elt_at_index (vm->handoff_queue_mains, handoff_queue_index);

  while (n_packets >= VLIB_FRAME_SIZE)
    {
      n_enq += vlib_buffer_enqueue_to_thread_inline (vm, node, hqm, buffer_indices, thread_indices,
						     VLIB_FRAME_SIZE, 1 /* with_aux */, aux);
      buffer_indices += VLIB_FRAME_SIZE;
      thread_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_buffer_enqueue_to_thread_inline (vm, node, hqm, buffer_indices, thread_indices,
						 n_packets, 1 /* with_aux */, aux);

  return n_enq;
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_thread_fn);
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_thread_fn);
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_thread_with_aux_fn);

#ifndef CLIB_MARCH_VARIANT
static vlib_handoff_queue_t *
vlib_handoff_queue_alloc (u32 size)
{
  vlib_handoff_queue_t *hq;
  uword alloc_sz;

  ASSERT (size >= VLIB_FRAME_SIZE);
  ASSERT ((size & (size - 1)) == 0);

  alloc_sz = sizeof (*hq) + 2 * sizeof (hq->data[0]) * size;
  hq = clib_mem_alloc_aligned (alloc_sz, __alignof (vlib_handoff_queue_slot_t));
  clib_memset (hq, 0, alloc_sz);
  hq->size = size;
  hq->dequeue_vector_limit = 2 * VLIB_FRAME_SIZE;
  clib_memset_u32 (vlib_handoff_queue_buffer_index_slots (hq)->buffer_indices,
		   VLIB_BUFFER_INVALID_INDEX, size * VLIB_HANDOFF_QUEUE_SLOT_SIZE);

  return (hq);
}

u32
vlib_handoff_alloc_queues (vlib_handoff_alloc_queues_args_t *a)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_main_t *vm = vlib_get_main ();
  vlib_handoff_queue_main_t *hqm;
  vlib_handoff_queue_t *hq;
  vlib_node_t *node;
  u32 qsz = a->queue_size ? a->queue_size : VLIB_HANDOFF_QUEUE_DEFAULT_SIZE;

  ASSERT (qsz >= VLIB_FRAME_SIZE);
  ASSERT ((qsz & (qsz - 1)) == 0);

  vec_add2 (vm->handoff_queue_mains, hqm, 1);

  node = vlib_get_node (vm, a->node_index);
  ASSERT (node);
  hqm->node_index = a->node_index;
  hqm->size = qsz;
  hqm->with_aux = node->aux_offset != 0;

  vec_validate (hqm->vlib_handoff_queues, tm->n_vlib_mains - 1);
  vec_set_len (hqm->vlib_handoff_queues, 0);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      hq = vlib_handoff_queue_alloc (qsz);
      vec_add1 (hqm->vlib_handoff_queues, hq);
    }

  return (hqm - vm->handoff_queue_mains);
}
#endif
