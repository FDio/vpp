/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

static_always_inline u32
enqueue_one (vlib_main_t *vm, vlib_node_runtime_t *node,
	     vlib_frame_bitmap_t used_elt_bmp, u16 next_index, u32 *buffers,
	     u16 *nexts, u32 n_buffers, u32 n_left, u32 *tmp, u8 maybe_aux,
	     u32 *aux_data, u32 *tmp_aux)
{
  vlib_frame_bitmap_t match_bmp;
  vlib_frame_t *f;
  u32 n_extracted, n_free;
  u32 *to, *to_aux;

  f = vlib_get_next_frame_internal (vm, node, next_index, 0);

  maybe_aux = maybe_aux && f->aux_offset;

  n_free = VLIB_FRAME_SIZE - f->n_vectors;

  /* if frame contains enough space for worst case scenario, we can avoid
   * use of tmp */
  if (n_free >= n_left)
    {
      to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
      if (maybe_aux)
	to_aux = (u32 *) vlib_frame_aux_args (f) + f->n_vectors;
    }
  else
    {
      to = tmp;
      if (maybe_aux)
	to_aux = tmp_aux;
    }
  clib_mask_compare_u16 (next_index, nexts, match_bmp, n_buffers);
  n_extracted = clib_compress_u32 (to, buffers, match_bmp, n_buffers);
  if (maybe_aux)
    clib_compress_u32 (to_aux, aux_data, match_bmp, n_buffers);
  vlib_frame_bitmap_or (used_elt_bmp, match_bmp);

  if (to != tmp)
    {
      /* indices already written to frame, just close it */
      vlib_put_next_frame (vm, node, next_index, n_free - n_extracted);
    }
  else if (n_free >= n_extracted)
    {
      /* enough space in the existing frame */
      to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
      vlib_buffer_copy_indices (to, tmp, n_extracted);
      if (maybe_aux)
	{
	  to_aux = (u32 *) vlib_frame_aux_args (f) + f->n_vectors;
	  vlib_buffer_copy_indices (to_aux, tmp_aux, n_extracted);
	}
      vlib_put_next_frame (vm, node, next_index, n_free - n_extracted);
    }
  else
    {
      /* full frame */
      to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
      vlib_buffer_copy_indices (to, tmp, n_free);
      if (maybe_aux)
	{
	  to_aux = (u32 *) vlib_frame_aux_args (f) + f->n_vectors;
	  vlib_buffer_copy_indices (to_aux, tmp_aux, n_free);
	}
      vlib_put_next_frame (vm, node, next_index, 0);

      /* second frame */
      u32 n_2nd_frame = n_extracted - n_free;
      f = vlib_get_next_frame_internal (vm, node, next_index, 1);
      to = vlib_frame_vector_args (f);
      vlib_buffer_copy_indices (to, tmp + n_free, n_2nd_frame);
      if (maybe_aux)
	{
	  to_aux = vlib_frame_aux_args (f);
	  vlib_buffer_copy_indices (to_aux, tmp_aux + n_free, n_2nd_frame);
	}
      vlib_put_next_frame (vm, node, next_index,
			   VLIB_FRAME_SIZE - n_2nd_frame);
    }

  return n_left - n_extracted;
}

static_always_inline void
vlib_buffer_enqueue_to_next_fn_inline (vlib_main_t *vm,
				       vlib_node_runtime_t *node, u32 *buffers,
				       u32 *aux_data, u16 *nexts, uword count,
				       u8 maybe_aux)
{
  u32 tmp[VLIB_FRAME_SIZE];
  u32 tmp_aux[VLIB_FRAME_SIZE];
  u32 n_left;
  u16 next_index;

  while (count >= VLIB_FRAME_SIZE)
    {
      vlib_frame_bitmap_t used_elt_bmp = {};
      n_left = VLIB_FRAME_SIZE;
      u32 off = 0;

      next_index = nexts[0];
      n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers, nexts,
			    VLIB_FRAME_SIZE, n_left, tmp, maybe_aux, aux_data,
			    tmp_aux);

      while (n_left)
	{
	  while (PREDICT_FALSE (used_elt_bmp[off] == ~0))
	    {
	      off++;
	      ASSERT (off < ARRAY_LEN (used_elt_bmp));
	    }

	  next_index =
	    nexts[off * 64 + count_trailing_zeros (~used_elt_bmp[off])];
	  n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers,
				nexts, VLIB_FRAME_SIZE, n_left, tmp, maybe_aux,
				aux_data, tmp_aux);
	}

      buffers += VLIB_FRAME_SIZE;
      if (maybe_aux)
	aux_data += VLIB_FRAME_SIZE;
      nexts += VLIB_FRAME_SIZE;
      count -= VLIB_FRAME_SIZE;
    }

  if (count)
    {
      vlib_frame_bitmap_t used_elt_bmp = {};
      next_index = nexts[0];
      n_left = count;
      u32 off = 0;

      n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers, nexts,
			    count, n_left, tmp, maybe_aux, aux_data, tmp_aux);

      while (n_left)
	{
	  while (PREDICT_FALSE (used_elt_bmp[off] == ~0))
	    {
	      off++;
	      ASSERT (off < ARRAY_LEN (used_elt_bmp));
	    }

	  next_index =
	    nexts[off * 64 + count_trailing_zeros (~used_elt_bmp[off])];
	  n_left =
	    enqueue_one (vm, node, used_elt_bmp, next_index, buffers, nexts,
			 count, n_left, tmp, maybe_aux, aux_data, tmp_aux);
	}
    }
}

void __clib_section (".vlib_buffer_enqueue_to_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts,
 uword count)
{
  vlib_buffer_enqueue_to_next_fn_inline (vm, node, buffers, NULL, nexts, count,
					 0 /* maybe_aux */);
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_next_fn);

void __clib_section (".vlib_buffer_enqueue_to_next_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_next_with_aux_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u32 *aux_data,
 u16 *nexts, uword count)
{
  vlib_buffer_enqueue_to_next_fn_inline (vm, node, buffers, aux_data, nexts,
					 count, 1 /* maybe_aux */);
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_next_with_aux_fn);

static_always_inline void
vlib_buffer_enqueue_to_single_next_fn_inline (vlib_main_t *vm,
					      vlib_node_runtime_t *node,
					      u32 *buffers, u32 *aux_data,
					      u16 next_index, u32 count,
					      u8 with_aux)
{
  u32 *to_next, *to_next_aux, n_left_to_next, n_enq;

  if (with_aux)
    vlib_get_next_frame_with_aux (vm, node, next_index, to_next, to_next_aux,
				  n_left_to_next);
  else
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (PREDICT_TRUE (n_left_to_next >= count))
    {
      vlib_buffer_copy_indices (to_next, buffers, count);
      if (with_aux)
	vlib_buffer_copy_indices (to_next_aux, aux_data, count);
      n_left_to_next -= count;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return;
    }

  n_enq = n_left_to_next;
next:
  vlib_buffer_copy_indices (to_next, buffers, n_enq);
  if (with_aux)
    vlib_buffer_copy_indices (to_next_aux, aux_data, n_enq);
  n_left_to_next -= n_enq;

  if (PREDICT_FALSE (count > n_enq))
    {
      count -= n_enq;
      buffers += n_enq;
      if (with_aux)
	aux_data += n_enq;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      if (with_aux)
	vlib_get_next_frame_with_aux (vm, node, next_index, to_next,
				      to_next_aux, n_left_to_next);
      else
	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      n_enq = clib_min (n_left_to_next, count);
      goto next;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
}

void __clib_section (".vlib_buffer_enqueue_to_single_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 next_index,
 u32 count)
{
  vlib_buffer_enqueue_to_single_next_fn_inline (
    vm, node, buffers, NULL, next_index, count, 0 /* with_aux */);
}
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_next_fn);

void __clib_section (".vlib_buffer_enqueue_to_single_next_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_next_with_aux_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u32 *aux_data,
 u16 next_index, u32 count)
{
  vlib_buffer_enqueue_to_single_next_fn_inline (
    vm, node, buffers, aux_data, next_index, count, 1 /* with_aux */);
}
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_next_with_aux_fn);

static inline vlib_frame_queue_elt_t *
vlib_get_frame_queue_elt (vlib_frame_queue_main_t *fqm, u32 index,
			  int dont_wait)
{
  vlib_frame_queue_t *fq;
  u64 nelts, tail, new_tail;

  fq = vec_elt (fqm->vlib_frame_queues, index);
  ASSERT (fq);
  nelts = fq->nelts;

retry:
  tail = __atomic_load_n (&fq->tail, __ATOMIC_ACQUIRE);
  new_tail = tail + 1;

  if (new_tail >= fq->head + nelts)
    {
      if (dont_wait)
	return 0;

      /* Wait until a ring slot is available */
      while (new_tail >= fq->head + nelts)
	vlib_worker_thread_barrier_check ();
    }

  if (!__atomic_compare_exchange_n (&fq->tail, &tail, new_tail, 0 /* weak */,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    goto retry;

  return fq->elts + (new_tail & (nelts - 1));
}

static_always_inline u32
vlib_buffer_enqueue_to_thread_inline (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_queue_main_t *fqm,
				      u32 *buffer_indices, u16 *thread_indices,
				      u32 n_packets, int drop_on_congestion,
				      int with_aux, u32 *aux_data)
{
  u32 drop_list[VLIB_FRAME_SIZE], n_drop = 0;
  vlib_frame_bitmap_t mask, used_elts = {};
  vlib_frame_queue_elt_t *hf = 0;
  u16 thread_index;
  u32 n_comp, off = 0, n_left = n_packets;

  thread_index = thread_indices[0];

more:
  clib_mask_compare_u16 (thread_index, thread_indices, mask, n_packets);
  hf = vlib_get_frame_queue_elt (fqm, thread_index, drop_on_congestion);

  n_comp = clib_compress_u32 (hf ? hf->buffer_index : drop_list + n_drop,
			      buffer_indices, mask, n_packets);
  if (with_aux)
    clib_compress_u32 (hf ? hf->aux_data : drop_list + n_drop, aux_data, mask,
		       n_packets);

  if (hf)
    {
      if (node->flags & VLIB_NODE_FLAG_TRACE)
	hf->maybe_trace = 1;
      hf->n_vectors = n_comp;
      __atomic_store_n (&hf->valid, 1, __ATOMIC_RELEASE);
      vlib_get_main_by_index (thread_index)->check_frame_queues = 1;
    }
  else
    n_drop += n_comp;

  n_left -= n_comp;

  if (n_left)
    {
      vlib_frame_bitmap_or (used_elts, mask);

      while (PREDICT_FALSE (used_elts[off] == ~0))
	{
	  off++;
	  ASSERT (off < ARRAY_LEN (used_elts));
	}

      thread_index =
	thread_indices[off * 64 + count_trailing_zeros (~used_elts[off])];
      goto more;
    }

  if (drop_on_congestion && n_drop)
    vlib_buffer_free (vm, drop_list, n_drop);

  return n_packets - n_drop;
}

u32 __clib_section (".vlib_buffer_enqueue_to_thread_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 frame_queue_index,
 u32 *buffer_indices, u16 *thread_indices, u32 n_packets,
 int drop_on_congestion)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  u32 n_enq = 0;

  fqm = vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);

  while (n_packets >= VLIB_FRAME_SIZE)
    {
      n_enq += vlib_buffer_enqueue_to_thread_inline (
	vm, node, fqm, buffer_indices, thread_indices, VLIB_FRAME_SIZE,
	drop_on_congestion, 0 /* with_aux */, NULL);
      buffer_indices += VLIB_FRAME_SIZE;
      thread_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_buffer_enqueue_to_thread_inline (
    vm, node, fqm, buffer_indices, thread_indices, n_packets,
    drop_on_congestion, 0 /* with_aux */, NULL);

  return n_enq;
}

u32 __clib_section (".vlib_buffer_enqueue_to_thread_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_with_aux_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 frame_queue_index,
 u32 *buffer_indices, u32 *aux, u16 *thread_indices, u32 n_packets,
 int drop_on_congestion)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  u32 n_enq = 0;

  fqm = vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);

  while (n_packets >= VLIB_FRAME_SIZE)
    {
      n_enq += vlib_buffer_enqueue_to_thread_inline (
	vm, node, fqm, buffer_indices, thread_indices, VLIB_FRAME_SIZE,
	drop_on_congestion, 1 /* with_aux */, aux);
      buffer_indices += VLIB_FRAME_SIZE;
      thread_indices += VLIB_FRAME_SIZE;
      n_packets -= VLIB_FRAME_SIZE;
    }

  if (n_packets == 0)
    return n_enq;

  n_enq += vlib_buffer_enqueue_to_thread_inline (
    vm, node, fqm, buffer_indices, thread_indices, n_packets,
    drop_on_congestion, 1 /* with_aux */, aux);

  return n_enq;
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_thread_fn);
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_thread_with_aux_fn);

static_always_inline u32
vlib_frame_queue_dequeue_inline (vlib_main_t *vm, vlib_frame_queue_main_t *fqm,
				 u8 with_aux)
{
  u32 thread_id = vm->thread_index;
  vlib_frame_queue_t *fq = fqm->vlib_frame_queues[thread_id];
  u32 mask = fq->nelts - 1;
  vlib_frame_queue_elt_t *elt;
  u32 n_free, n_copy, *from, *from_aux, *to = 0, *to_aux = 0, processed = 0,
					vectors = 0;
  vlib_frame_t *f = 0;

  ASSERT (fq);
  ASSERT (vm == vlib_global_main.vlib_mains[thread_id]);

  if (PREDICT_FALSE (fqm->node_index == ~0))
    return 0;
  /*
   * Gather trace data for frame queues
   */
  if (PREDICT_FALSE (fq->trace))
    {
      frame_queue_trace_t *fqt;
      frame_queue_nelt_counter_t *fqh;
      u32 elix;

      fqt = &fqm->frame_queue_traces[thread_id];

      fqt->nelts = fq->nelts;
      fqt->head = fq->head;
      fqt->tail = fq->tail;
      fqt->threshold = fq->vector_threshold;
      fqt->n_in_use = fqt->tail - fqt->head;
      if (fqt->n_in_use >= fqt->nelts)
	{
	  // if beyond max then use max
	  fqt->n_in_use = fqt->nelts - 1;
	}

      /* Record the number of elements in use in the histogram */
      fqh = &fqm->frame_queue_histogram[thread_id];
      fqh->count[fqt->n_in_use]++;

      /* Record a snapshot of the elements in use */
      for (elix = 0; elix < fqt->nelts; elix++)
	{
	  elt = fq->elts + ((fq->head + 1 + elix) & (mask));
	  if (1 || elt->valid)
	    {
	      fqt->n_vectors[elix] = elt->n_vectors;
	    }
	}
      fqt->written = 1;
    }

  while (1)
    {
      if (fq->head == fq->tail)
	break;

      elt = fq->elts + ((fq->head + 1) & mask);

      if (!__atomic_load_n (&elt->valid, __ATOMIC_ACQUIRE))
	break;

      from = elt->buffer_index + elt->offset;
      if (with_aux)
	from_aux = elt->aux_data + elt->offset;
      ASSERT (elt->offset + elt->n_vectors <= VLIB_FRAME_SIZE);

      if (f == 0)
	{
	  f = vlib_get_frame_to_node (vm, fqm->node_index);
	  to = vlib_frame_vector_args (f);
	  if (with_aux)
	    to_aux = vlib_frame_aux_args (f);
	  n_free = VLIB_FRAME_SIZE;
	}

      if (elt->maybe_trace)
	f->frame_flags |= VLIB_NODE_FLAG_TRACE;

      n_copy = clib_min (n_free, elt->n_vectors);

      vlib_buffer_copy_indices (to, from, n_copy);
      to += n_copy;
      if (with_aux)
	{
	  vlib_buffer_copy_indices (to_aux, from_aux, n_copy);
	  to_aux += n_copy;
	}

      n_free -= n_copy;
      vectors += n_copy;

      if (n_free == 0)
	{
	  f->n_vectors = VLIB_FRAME_SIZE;
	  vlib_put_frame_to_node (vm, fqm->node_index, f);
	  f = 0;
	}

      if (n_copy < elt->n_vectors)
	{
	  /* not empty - leave it on the ring */
	  elt->n_vectors -= n_copy;
	  elt->offset += n_copy;
	}
      else
	{
	  /* empty - reset and bump head */
	  u32 sz = STRUCT_OFFSET_OF (vlib_frame_queue_elt_t, end_of_reset);
	  clib_memset (elt, 0, sz);
	  __atomic_store_n (&fq->head, fq->head + 1, __ATOMIC_RELEASE);
	  processed++;
	}

      /* Limit the number of packets pushed into the graph */
      if (vectors >= fq->vector_threshold)
	break;
    }

  if (f)
    {
      f->n_vectors = VLIB_FRAME_SIZE - n_free;
      vlib_put_frame_to_node (vm, fqm->node_index, f);
    }

  return processed;
}

u32 __clib_section (".vlib_frame_queue_dequeue_fn")
CLIB_MULTIARCH_FN (vlib_frame_queue_dequeue_fn)
(vlib_main_t *vm, vlib_frame_queue_main_t *fqm)
{
  return vlib_frame_queue_dequeue_inline (vm, fqm, 0 /* with_aux */);
}

CLIB_MARCH_FN_REGISTRATION (vlib_frame_queue_dequeue_fn);

u32 __clib_section (".vlib_frame_queue_dequeue_with_aux_fn")
CLIB_MULTIARCH_FN (vlib_frame_queue_dequeue_with_aux_fn)
(vlib_main_t *vm, vlib_frame_queue_main_t *fqm)
{
  return vlib_frame_queue_dequeue_inline (vm, fqm, 1 /* with_aux */);
}

CLIB_MARCH_FN_REGISTRATION (vlib_frame_queue_dequeue_with_aux_fn);

#ifndef CLIB_MARCH_VARIANT
vlib_buffer_func_main_t vlib_buffer_func_main;

static clib_error_t *
vlib_buffer_funcs_init (vlib_main_t *vm)
{
  vlib_buffer_func_main_t *bfm = &vlib_buffer_func_main;
  bfm->buffer_enqueue_to_next_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_next_fn);
  bfm->buffer_enqueue_to_next_with_aux_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_next_with_aux_fn);
  bfm->buffer_enqueue_to_single_next_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_next_fn);
  bfm->buffer_enqueue_to_single_next_with_aux_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_next_with_aux_fn);
  bfm->buffer_enqueue_to_thread_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_thread_fn);
  bfm->buffer_enqueue_to_thread_with_aux_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_thread_with_aux_fn);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_buffer_funcs_init);
#endif
