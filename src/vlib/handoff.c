/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

/*
 * Handoff queues are MPSC rings: multiple producer threads reserve slots by
 * advancing tail, and one consumer thread drains slots in head order.
 *
 * The ring stores fixed-size slots instead of single buffer indices.
 * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS is currently sized to 128 bytes, i.e. two standard cachelines
 * worth of buffer indices. Each slot is aligned to that size to avoid producer cacheline bouncing
 * when multiple producers reserve adjacent slots. Optional aux slots are stored in a parallel ring
 * after the buffer-index ring.
 *
 * VLIB_BUFFER_INVALID_INDEX terminates the valid buffer indices inside a slot.
 * In buffer_indices[0], it also means that the slot is available to producers.
 * Producers fill the whole reserved batch first, publish non-first slot markers with plain
 * stores, then publish the first slot by writing buffer_indices[0] with release semantics. The
 * consumer uses an acquire load of the first slot to observe the complete batch and then consumes
 * slots in order.
 */

STATIC_ASSERT (VLIB_HANDOFF_QUEUE_SLOT_N_ELTS == 32,
	       "VLIB_HANDOFF_QUEUE_SLOT_N_ELTS must be 32 for SIMD code to work");

static_always_inline u32
vlib_handoff_copy_indices_from_slot (u32 *dst, vlib_handoff_queue_slot_t *slot)
{
  u32 n = 0;

#if defined(CLIB_HAVE_VEC512) && defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  const u32x16 match = u32x16_splat (VLIB_BUFFER_INVALID_INDEX);
  u32x16u *dv = (u32x16u *) dst;
  u32x16 v0 = slot->as_u32x16[0];
  u32x16 v1 = slot->as_u32x16[1];
  u16 mask;

  if (PREDICT_TRUE (u32x16_is_all_zero (v1 == match)))
    {
      dv[0] = v0;
      dv[1] = v1;
      return 32;
    }
  if (PREDICT_TRUE (u32x16_is_all_zero (v0 == match)))
    {
      mask = u32x16_is_equal_mask (v1, match);

      dv[0] = v0;
      u32x16_mask_store (v1, dv + 1, ~mask);
      return 16 + count_trailing_zeros (mask);
    }

  mask = u32x16_is_equal_mask (v0, match);
  u32x16_mask_store (v0, dv, ~mask);
  return count_trailing_zeros (mask);

#elif defined(CLIB_HAVE_VEC256)
  const u32x8 match = u32x8_splat (VLIB_BUFFER_INVALID_INDEX);
  u32x8u *dv = (u32x8u *) dst;
  u32x8 v = slot->as_u32x8[3];

  if (PREDICT_TRUE (u32x8_is_all_zero (v == match)))
    {
      dv[0] = slot->as_u32x8[0];
      dv[1] = slot->as_u32x8[1];
      dv[2] = slot->as_u32x8[2];
      dv[3] = v;
      return 32;
    }

  for (u32 i = 0;; i++, n += 8)
    {
      v = slot->as_u32x8[i];
      if (PREDICT_TRUE (!u32x8_is_all_zero (v == match)))
	break;

      dv++[0] = v;
    }

#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u8 mask;

  mask = u32x8_is_equal_mask (v, match);
  if (mask)
    {
      u32x8_mask_store (v, dv, ~mask);
      n += count_trailing_zeros (mask);
    }
  return n;
#endif

#elif defined(CLIB_HAVE_VEC128)
  const u32x4 match = u32x4_splat (VLIB_BUFFER_INVALID_INDEX);
  u32x4u *dv = (u32x4u *) dst;
  u32x4 v = slot->as_u32x4[7];

  if (PREDICT_TRUE (u32x4_is_all_zero (v == match)))
    {
      dv[0] = slot->as_u32x4[0];
      dv[1] = slot->as_u32x4[1];
      dv[2] = slot->as_u32x4[2];
      dv[3] = slot->as_u32x4[3];
      dv[4] = slot->as_u32x4[4];
      dv[5] = slot->as_u32x4[5];
      dv[6] = slot->as_u32x4[6];
      dv[7] = v;
      return 32;
    }

  for (u32 i = 0;; i++, n += 4)
    {
      v = slot->as_u32x4[i];
      if (PREDICT_TRUE (!u32x4_is_all_zero (v == match)))
	break;

      dv++[0] = v;
    }

#endif

  for (; slot->buffer_indices[n] != VLIB_BUFFER_INVALID_INDEX; n++)
    dst[n] = slot->buffer_indices[n];

  return n;
}

static_always_inline u32
vlib_handoff_queue_dequeue_inline (vlib_main_t *vm, vlib_handoff_queue_main_t *hqm, u8 with_aux)
{
  vlib_handoff_queue_t *hq = hqm->vlib_handoff_queues[vm->thread_index];
  vlib_handoff_queue_slot_t *bi_slots = vlib_handoff_queue_buffer_index_slots (hq);
  vlib_handoff_queue_slot_t *aux_slots = vlib_handoff_queue_aux_slots (hq);
  u32 dequeue_vector_limit = hq->dequeue_vector_limit;
  u32 mask = hq->size - 1;
  u32 n_free = 0, n_copy, *to = 0, *to_aux = 0, n_deq = 0;
  u64 trace_stop;
  vlib_frame_t *f = 0;
  u64 head = __atomic_load_n (&hq->head, __ATOMIC_RELAXED);

  while (n_deq < dequeue_vector_limit)
    {
      u32 slot_index = head & mask;
      vlib_handoff_queue_slot_t *slot = bi_slots + slot_index;
      u32 first_bi = __atomic_load_n (slot->buffer_indices, __ATOMIC_ACQUIRE);

      if (first_bi == VLIB_BUFFER_INVALID_INDEX)
	break;

      if (PREDICT_FALSE (f && VLIB_HANDOFF_QUEUE_SLOT_N_ELTS > n_free))
	{
	  f->n_vectors = VLIB_FRAME_SIZE - n_free;
	  vlib_put_frame_to_node (vm, hqm->node_index, f);
	  f = 0;
	}

      if (PREDICT_FALSE (f == 0))
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

      n_copy = vlib_handoff_copy_indices_from_slot (to, slot);
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

      __atomic_store_n (slot->buffer_indices, VLIB_BUFFER_INVALID_INDEX, __ATOMIC_RELAXED);
      head++;
      n_deq += n_copy;
    }

  if (n_deq)
    {
      hq->n_vectors += n_deq;
      __atomic_store_n (&hq->head, head, __ATOMIC_RELAXED);
      if (n_deq >= dequeue_vector_limit)
	__atomic_fetch_or (&vm->handoff_queue_pending_bmp, hqm->queue_bit, __ATOMIC_RELAXED);
    }

  if (f)
    {
      f->n_vectors = VLIB_FRAME_SIZE - n_free;
      vlib_put_frame_to_node (vm, hqm->node_index, f);
    }

  return n_deq;
}

void __clib_section (".vlib_handoff_queues_dequeue_fn")
CLIB_MULTIARCH_FN (vlib_handoff_queues_dequeue_fn)
(vlib_main_t *vm)
{
  vlib_handoff_queue_main_t *hqm;
  u64 queues_bitmap;
  u32 n_deq = 0;

  queues_bitmap = __atomic_exchange_n (&vm->handoff_queue_pending_bmp, 0, __ATOMIC_RELAXED);

  if (PREDICT_FALSE (queues_bitmap == CLIB_U64_MAX))
    {
      vec_foreach (hqm, vm->handoff_queue_mains)
	{
	  if (PREDICT_FALSE (hqm->with_aux))
	    n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 1 /* with_aux */);
	  else
	    n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 0 /* with_aux */);
	}

      if (PREDICT_TRUE (n_deq))
	vm->file_poll_no_sleep_epolls = 512;

      return;
    }

  while (queues_bitmap)
    {
      u32 hqm_index = count_trailing_zeros (queues_bitmap);

      queues_bitmap = clear_lowest_set_bit (queues_bitmap);

      ASSERT (hqm_index < vec_len (vm->handoff_queue_mains));

      hqm = vec_elt_at_index (vm->handoff_queue_mains, hqm_index);
      if (PREDICT_FALSE (hqm->with_aux))
	n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 1 /* with_aux */);
      else
	n_deq += vlib_handoff_queue_dequeue_inline (vm, hqm, 0 /* with_aux */);
    }

  if (PREDICT_TRUE (n_deq))
    vm->file_poll_no_sleep_epolls = 512;
}

CLIB_MARCH_FN_REGISTRATION (vlib_handoff_queues_dequeue_fn);

static_always_inline void
vlib_handoff_queue_copy_and_publish_indices_to_slots (vlib_handoff_queue_slot_t *slots, u32 mask,
						      u64 start, u32 *src, u32 n_vectors)
{
  const u32 slot_elts = VLIB_HANDOFF_QUEUE_SLOT_N_ELTS;
  u32 n_left = n_vectors;
  u32 slot_index = start & mask;
  u32 *first_slot = slots[slot_index].buffer_indices;
  u32 first_bi = src[0];

  if (PREDICT_FALSE (n_left < slot_elts))
    {
      clib_memset_u32 (first_slot, VLIB_BUFFER_INVALID_INDEX, slot_elts);
      vlib_buffer_copy_indices (first_slot + 1, src + 1, n_left - 1);
      goto done;
    }

#if defined(CLIB_HAVE_VEC512)
  u32x16u *sv = (u32x16u *) src;
  u32x16u *dv = (u32x16u *) first_slot;
  u32x16 v = sv[0];

  v[0] = VLIB_BUFFER_INVALID_INDEX;
  dv[0] = v;
  dv[1] = sv[1];
#elif defined(CLIB_HAVE_VEC256)
  u32x8u *sv = (u32x8u *) src;
  u32x8u *dv = (u32x8u *) first_slot;
  u32x8 v = sv[0];

  v[0] = VLIB_BUFFER_INVALID_INDEX;
  dv[0] = v;
  dv[1] = sv[1], dv[2] = sv[2], dv[3] = sv[3];
#elif defined(CLIB_HAVE_VEC128)
  u32x4u *sv = (u32x4u *) src;
  u32x4u *dv = (u32x4u *) first_slot;
  u32x4 v = sv[0];

  v[0] = VLIB_BUFFER_INVALID_INDEX;
  dv[0] = v;
  dv[1] = sv[1], dv[2] = sv[2], dv[3] = sv[3], dv[4] = sv[4];
  dv[5] = sv[5], dv[6] = sv[6], dv[7] = sv[7];
#else
  first_slot[0] = VLIB_BUFFER_INVALID_INDEX;
  vlib_buffer_copy_indices (first_slot + 1, src + 1, slot_elts - 1);
#endif

  src += slot_elts;
  n_left -= slot_elts;
  slot_index = (slot_index + 1) & mask;

  while (n_left >= slot_elts)
    {
      vlib_buffer_copy_indices (slots[slot_index].buffer_indices, src, slot_elts);
      src += slot_elts;
      n_left -= slot_elts;
      slot_index = (slot_index + 1) & mask;
    }

  if (n_left)
    {
      vlib_handoff_queue_slot_t *slot = slots + slot_index;
      clib_memset_u32 (slot->buffer_indices, VLIB_BUFFER_INVALID_INDEX, slot_elts);
      vlib_buffer_copy_indices (slot->buffer_indices, src, n_left);
    }

done:
  /* Publish the first buffer index last with release ordering, making all slots visible. */
  __atomic_store_n (first_slot, first_bi, __ATOMIC_RELEASE);
}

static_always_inline u32
vlib_handoff_enqueue_one_thread (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vlib_handoff_queue_main_t *hqm, u32 *buffer_indices,
				 clib_thread_index_t thread_index, u32 n_packets, int with_aux,
				 u32 *aux_data)
{
  u8 do_wakeup = 0;
  u64 head, start, tail, n_avail;
  u32 n_drop = 0, n_enq, n_req, n_slots, *drop;
  vlib_handoff_queue_t *hq = vec_elt (hqm->vlib_handoff_queues, thread_index);
  u64 size = hq->size;
  u32 ring_mask = size - 1;
  vlib_handoff_queue_slot_t *bi_slots = vlib_handoff_queue_buffer_index_slots (hq);
  vlib_handoff_queue_slot_t *aux_slots = vlib_handoff_queue_aux_slots (hq);
  u32 maybe_trace = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;
  n_req = round_pow2 (n_packets, VLIB_HANDOFF_QUEUE_SLOT_N_ELTS) / VLIB_HANDOFF_QUEUE_SLOT_N_ELTS;

retry:
  tail = __atomic_load_n (&hq->tail, __ATOMIC_RELAXED);
  head = __atomic_load_n (&hq->head, __ATOMIC_ACQUIRE);
  n_avail = head + size - tail;

  if (n_avail < n_req)
    {
      n_slots = n_avail;
      n_enq = n_slots * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS;
      drop = buffer_indices + n_enq;
      n_drop = n_packets - n_enq;
      if (n_slots == 0)
	goto done;
    }
  else
    {
      n_enq = n_packets;
      n_slots = n_req;
      n_drop = 0;
    }

  if (!__atomic_compare_exchange_n (&hq->tail, &tail, tail + n_slots, 0 /* weak */,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    goto retry;

  start = tail;
  do_wakeup = tail == head;

  if (with_aux)
    vlib_buffer_copy_indices_to_ring (aux_slots[0].buffer_indices, aux_data,
				      (start & ring_mask) * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS,
				      size * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS, n_enq);

  if (PREDICT_FALSE (maybe_trace))
    {
      u64 stop = start + n_slots;
      u64 trace_stop = __atomic_load_n (&hq->trace_stop, __ATOMIC_RELAXED);

      while (1)
	{
	  if (stop <= trace_stop)
	    break;

	  if (__atomic_compare_exchange_n (&hq->trace_stop, &trace_stop, stop, 0 /* weak */,
					   __ATOMIC_RELAXED, __ATOMIC_RELAXED))
	    break;

	  CLIB_PAUSE ();
	}
    }
  vlib_handoff_queue_copy_and_publish_indices_to_slots (bi_slots, ring_mask, start, buffer_indices,
							n_enq);

done:
  if (PREDICT_FALSE (n_drop))
    {
      __atomic_fetch_add (&hq->n_dropped, n_drop, __ATOMIC_RELAXED);
      vlib_buffer_free (vm, drop, n_drop);
    }

  if (PREDICT_TRUE (n_slots))
    {
      vlib_main_t *target_vm = vlib_get_main_by_index (thread_index);

      __atomic_fetch_or (&target_vm->handoff_queue_pending_bmp, hqm->queue_bit, __ATOMIC_RELAXED);
      if (do_wakeup && __atomic_load_n (&target_vm->thread_sleeps, __ATOMIC_RELAXED))
	vlib_thread_wakeup (thread_index);
    }

  return n_enq;
}

static_always_inline u32
vlib_buffer_enqueue_to_thread_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				      vlib_handoff_queue_main_t *hqm, u32 *buffer_indices,
				      u16 *thread_indices, u32 n_packets, int with_aux,
				      u32 *aux_data)
{
  u32 enqueue_list[VLIB_FRAME_SIZE], enqueue_aux[VLIB_FRAME_SIZE];
  vlib_frame_bitmap_t mask, used_elts = {};
  clib_thread_index_t thread_index;
  u32 n_comp, n_enq, n_drop_total = 0, off = 0, n_left = n_packets;

  thread_index = thread_indices[0];

more:
  clib_mask_compare_u16 (thread_index, thread_indices, mask, n_packets);
  n_comp = clib_compress_u32 (enqueue_list, buffer_indices, mask, n_packets);
  if (with_aux)
    clib_compress_u32 (enqueue_aux, aux_data, mask, n_packets);
  n_enq = vlib_handoff_enqueue_one_thread (vm, node, hqm, enqueue_list, thread_index, n_comp,
					   with_aux, enqueue_aux);
  n_drop_total += n_comp - n_enq;

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

u32 __clib_section (".vlib_buffer_enqueue_to_thread_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 handoff_queue_index, u32 *buffer_indices,
 u16 *thread_indices, u32 n_packets)
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
      n_enq += vlib_handoff_enqueue_one_thread (vm, node, hqm, buffer_indices, thread_index,
						VLIB_FRAME_SIZE, 0 /* with_aux */, 0);
      buffer_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_handoff_enqueue_one_thread (vm, node, hqm, buffer_indices, thread_index, n_packets,
					    0 /* with_aux */, 0);

  return n_enq;
}

u32 __clib_section (".vlib_buffer_enqueue_to_thread_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_with_aux_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 handoff_queue_index, u32 *buffer_indices, u32 *aux,
 u16 *thread_indices, u32 n_packets)
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

  ASSERT (size > 0);
  ASSERT ((size & (size - 1)) == 0);

  alloc_sz = sizeof (*hq) + 2 * sizeof (hq->data[0]) * size;
  hq = clib_mem_alloc_aligned (alloc_sz, __alignof (vlib_handoff_queue_slot_t));
  clib_memset (hq, 0, alloc_sz);
  hq->size = size;
  hq->dequeue_vector_limit = 2 * VLIB_FRAME_SIZE;
  clib_memset_u32 (vlib_handoff_queue_buffer_index_slots (hq)->buffer_indices,
		   VLIB_BUFFER_INVALID_INDEX, size * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);

  return (hq);
}

static u32
vlib_handoff_queue_n_pending_slots (vlib_handoff_queue_t *hq)
{
  vlib_handoff_queue_slot_t *slots = vlib_handoff_queue_buffer_index_slots (hq);
  u64 head = __atomic_load_n (&hq->head, __ATOMIC_RELAXED);
  u64 tail = __atomic_load_n (&hq->tail, __ATOMIC_RELAXED);
  u32 mask = hq->size - 1;
  u32 n_pending = 0;
  u64 i;

  for (i = head; i < tail; i++)
    {
      u32 slot_index = i & mask;

      if (slots[slot_index].buffer_indices[0] == VLIB_BUFFER_INVALID_INDEX)
	break;
      n_pending++;
    }

  return n_pending;
}

static void
vlib_handoff_queue_copy_pending_slots (vlib_handoff_queue_main_t *hqm, vlib_handoff_queue_t *old_hq,
				       vlib_handoff_queue_t *new_hq, u32 n_pending)
{
  vlib_handoff_queue_slot_t *old_bi_slots = vlib_handoff_queue_buffer_index_slots (old_hq);
  vlib_handoff_queue_slot_t *new_bi_slots = vlib_handoff_queue_buffer_index_slots (new_hq);
  vlib_handoff_queue_slot_t *old_aux_slots = vlib_handoff_queue_aux_slots (old_hq);
  vlib_handoff_queue_slot_t *new_aux_slots = vlib_handoff_queue_aux_slots (new_hq);
  u64 head = __atomic_load_n (&old_hq->head, __ATOMIC_RELAXED);
  u64 trace_stop = __atomic_load_n (&old_hq->trace_stop, __ATOMIC_RELAXED);
  u32 old_mask = old_hq->size - 1;
  u32 new_mask = new_hq->size - 1;
  u32 i;

  new_hq->dequeue_vector_limit = old_hq->dequeue_vector_limit;
  new_hq->head = head;
  new_hq->tail = head + n_pending;
  new_hq->trace_stop = clib_min (trace_stop, new_hq->tail);
  new_hq->n_dropped = old_hq->n_dropped;
  new_hq->n_vectors = old_hq->n_vectors;

  for (i = 0; i < n_pending; i++)
    {
      u32 old_slot = (head + i) & old_mask;
      u32 new_slot = (head + i) & new_mask;

      new_bi_slots[new_slot] = old_bi_slots[old_slot];
      if (hqm->with_aux)
	new_aux_slots[new_slot] = old_aux_slots[old_slot];
    }
}

clib_error_t *
vlib_handoff_queue_resize (u32 index, u32 queue_size)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_main_t *vm = vlib_get_main ();
  vlib_main_t *this_vm = vm;
  vlib_handoff_queue_main_t *hqm;
  vlib_handoff_queue_t **new_queues = 0;
  u32 thread_index;
  u32 size;

  if (index >= vec_len (vm->handoff_queue_mains))
    return clib_error_return (0, "expecting valid handoff queue index");

  if (queue_size < VLIB_HANDOFF_QUEUE_SLOT_N_ELTS || (queue_size & (queue_size - 1)))
    return clib_error_return (0, "size must be a power of 2 and at least %u",
			      VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);

  size = queue_size / VLIB_HANDOFF_QUEUE_SLOT_N_ELTS;

  hqm = vec_elt_at_index (vm->handoff_queue_mains, index);

  vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
    {
      vlib_handoff_queue_t *old_hq = hqm->vlib_handoff_queues[thread_index];
      vlib_handoff_queue_t *new_hq;
      u32 n_pending = vlib_handoff_queue_n_pending_slots (old_hq);

      if (n_pending > size)
	{
	  vlib_handoff_queue_t **q;

	  vec_foreach (q, new_queues)
	    clib_mem_free (q[0]);
	  vec_free (new_queues);
	  return clib_error_return (0,
				    "queue has pending buffers using %u elements, "
				    "size %u is too small",
				    n_pending * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS, queue_size);
	}

      new_hq = vlib_handoff_queue_alloc (size);
      vlib_handoff_queue_copy_pending_slots (hqm, old_hq, new_hq, n_pending);
      vec_add1 (new_queues, new_hq);
    }

  vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
    clib_mem_free (hqm->vlib_handoff_queues[thread_index]);

  vec_free (hqm->vlib_handoff_queues);
  hqm->vlib_handoff_queues = new_queues;
  hqm->size = size;

  for (int i = 0; i < vec_len (vgm->vlib_mains); i++)
    {
      vm = vlib_get_main_by_index (i);
      if (vm != this_vm)
	vm->handoff_queue_mains = this_vm->handoff_queue_mains;
    }

  return 0;
}

u32
vlib_handoff_alloc_queues (vlib_handoff_alloc_queues_args_t *a)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_main_t *vm = vlib_get_main ();
  vlib_main_t *this_vm = vm;
  vlib_handoff_queue_main_t hqm = {};
  vlib_handoff_queue_main_t *hqm_at_index;
  vlib_handoff_queue_t *hq;
  vlib_node_t *node;
  u32 hqm_index;
  u32 queue_size = a->queue_size ? a->queue_size : VLIB_HANDOFF_QUEUE_DEFAULT_SIZE;
  u32 qsz;

  ASSERT (queue_size >= VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);
  ASSERT ((queue_size & (queue_size - 1)) == 0);
  qsz = queue_size / VLIB_HANDOFF_QUEUE_SLOT_N_ELTS;

  node = vlib_get_node (vm, a->node_index);
  ASSERT (node);
  hqm.index = vec_len (vm->handoff_queue_mains);
  hqm.queue_bit = hqm.index < 64 ? 1ULL << hqm.index : CLIB_U64_MAX;
  hqm.node_index = a->node_index;
  hqm.size = qsz;
  hqm.with_aux = node->aux_offset != 0;

  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      hq = vlib_handoff_queue_alloc (qsz);
      vec_add1 (hqm.vlib_handoff_queues, hq);
    }

  hqm_index = vec_len (vm->handoff_queue_mains);
  vec_add2 (vm->handoff_queue_mains, hqm_at_index, 1);
  hqm_at_index[0] = hqm;

  for (int i = 0; i < vec_len (vgm->vlib_mains); i++)
    {
      vm = vlib_get_main_by_index (i);
      if (vm != this_vm)
	vm->handoff_queue_mains = this_vm->handoff_queue_mains;
    }

  return hqm_index;
}
#endif
