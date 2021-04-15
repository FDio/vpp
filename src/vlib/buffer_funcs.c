/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vppinfra/vector_funcs.h>

static_always_inline u32
enqueue_one (vlib_main_t *vm, vlib_node_runtime_t *node, u64 *used_elt_bmp,
	     u16 next_index, u32 *buffers, u16 *nexts, u32 n_buffers,
	     u32 n_left, u32 *tmp)
{
  u64 match_bmp[VLIB_FRAME_SIZE / 64];
  vlib_frame_t *f;
  u32 n_extracted, n_free;
  u32 *to;

  f = vlib_get_next_frame_internal (vm, node, next_index, 0);

  n_free = VLIB_FRAME_SIZE - f->n_vectors;

  /* if frame contains enough space for worst case scenario, we can avoid
   * use of tmp */
  if (n_free >= n_left)
    to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
  else
    to = tmp;

  clib_mask_compare_u16 (next_index, nexts, match_bmp, n_buffers);

  n_extracted = clib_compress_u32 (to, buffers, match_bmp, n_buffers);

  for (int i = 0; i < ARRAY_LEN (match_bmp); i++)
    used_elt_bmp[i] |= match_bmp[i];

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
      vlib_put_next_frame (vm, node, next_index, n_free - n_extracted);
    }
  else
    {
      /* full frame */
      to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
      vlib_buffer_copy_indices (to, tmp, n_free);
      vlib_put_next_frame (vm, node, next_index, 0);

      /* second frame */
      u32 n_2nd_frame = n_extracted - n_free;
      f = vlib_get_next_frame_internal (vm, node, next_index, 1);
      to = vlib_frame_vector_args (f);
      vlib_buffer_copy_indices (to, tmp + n_free, n_2nd_frame);
      vlib_put_next_frame (vm, node, next_index,
			   VLIB_FRAME_SIZE - n_2nd_frame);
    }

  return n_left - n_extracted;
}

void __clib_section (".vlib_buffer_enqueue_to_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts,
 uword count)
{
  u32 tmp[VLIB_FRAME_SIZE];
  u32 n_left;
  u16 next_index;

  while (count >= VLIB_FRAME_SIZE)
    {
      u64 used_elt_bmp[VLIB_FRAME_SIZE / 64] = {};
      n_left = VLIB_FRAME_SIZE;

      next_index = nexts[0];
      n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers, nexts,
			    VLIB_FRAME_SIZE, n_left, tmp);

      while (n_left)
	{
	  next_index = nexts[find_first_unused_elt (used_elt_bmp)];
	  n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers,
				nexts, VLIB_FRAME_SIZE, n_left, tmp);
	}

      buffers += VLIB_FRAME_SIZE;
      nexts += VLIB_FRAME_SIZE;
      count -= VLIB_FRAME_SIZE;
    }

  if (count)
    {
      u64 used_elt_bmp[VLIB_FRAME_SIZE / 64] = {};
      next_index = nexts[0];
      n_left = count;

      n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers, nexts,
			    count, n_left, tmp);

      while (n_left)
	{
	  next_index = nexts[find_first_unused_elt (used_elt_bmp)];
	  n_left = enqueue_one (vm, node, used_elt_bmp, next_index, buffers,
				nexts, count, n_left, tmp);
	}
    }
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_next_fn);

void __clib_section (".vlib_buffer_enqueue_to_single_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 next_index,
 u32 count)
{
  u32 *to_next, n_left_to_next, n_enq;

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (PREDICT_TRUE (n_left_to_next >= count))
    {
      vlib_buffer_copy_indices (to_next, buffers, count);
      n_left_to_next -= count;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return;
    }

  n_enq = n_left_to_next;
next:
  vlib_buffer_copy_indices (to_next, buffers, n_enq);
  n_left_to_next -= n_enq;

  if (PREDICT_FALSE (count > n_enq))
    {
      count -= n_enq;
      buffers += n_enq;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      n_enq = clib_min (n_left_to_next, count);
      goto next;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
}
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_next_fn);

u32 __clib_section (".vlib_buffer_enqueue_to_thread_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_thread_fn)
(vlib_main_t *vm, u32 frame_queue_index, u32 *buffer_indices,
 u16 *thread_indices, u32 n_packets, int drop_on_congestion)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  vlib_frame_queue_per_thread_data_t *ptd;
  u32 n_left = n_packets;
  u32 drop_list[VLIB_FRAME_SIZE], *dbi = drop_list, n_drop = 0;
  vlib_frame_queue_elt_t *hf = 0;
  u32 n_left_to_next_thread = 0, *to_next_thread = 0;
  u32 next_thread_index, current_thread_index = ~0;
  int i;

  fqm = vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);
  ptd = vec_elt_at_index (fqm->per_thread_data, vm->thread_index);

  while (n_left)
    {
      next_thread_index = thread_indices[0];

      if (next_thread_index != current_thread_index)
	{
	  if (drop_on_congestion &&
	      is_vlib_frame_queue_congested (
		frame_queue_index, next_thread_index, fqm->queue_hi_thresh,
		ptd->congested_handoff_queue_by_thread_index))
	    {
	      dbi[0] = buffer_indices[0];
	      dbi++;
	      n_drop++;
	      goto next;
	    }

	  if (hf)
	    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_thread;

	  hf = vlib_get_worker_handoff_queue_elt (
	    frame_queue_index, next_thread_index,
	    ptd->handoff_queue_elt_by_thread_index);

	  n_left_to_next_thread = VLIB_FRAME_SIZE - hf->n_vectors;
	  to_next_thread = &hf->buffer_index[hf->n_vectors];
	  current_thread_index = next_thread_index;
	}

      to_next_thread[0] = buffer_indices[0];
      to_next_thread++;
      n_left_to_next_thread--;

      if (n_left_to_next_thread == 0)
	{
	  hf->n_vectors = VLIB_FRAME_SIZE;
	  vlib_put_frame_queue_elt (hf);
	  vlib_get_main_by_index (current_thread_index)->check_frame_queues =
	    1;
	  current_thread_index = ~0;
	  ptd->handoff_queue_elt_by_thread_index[next_thread_index] = 0;
	  hf = 0;
	}

      /* next */
    next:
      thread_indices += 1;
      buffer_indices += 1;
      n_left -= 1;
    }

  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_thread;

  /* Ship frames to the thread nodes */
  for (i = 0; i < vec_len (ptd->handoff_queue_elt_by_thread_index); i++)
    {
      if (ptd->handoff_queue_elt_by_thread_index[i])
	{
	  hf = ptd->handoff_queue_elt_by_thread_index[i];
	  /*
	   * It works better to let the handoff node
	   * rate-adapt, always ship the handoff queue element.
	   */
	  if (1 || hf->n_vectors == hf->last_n_vectors)
	    {
	      vlib_put_frame_queue_elt (hf);
	      vlib_get_main_by_index (i)->check_frame_queues = 1;
	      ptd->handoff_queue_elt_by_thread_index[i] = 0;
	    }
	  else
	    hf->last_n_vectors = hf->n_vectors;
	}
      ptd->congested_handoff_queue_by_thread_index[i] =
	(vlib_frame_queue_t *) (~0);
    }

  if (drop_on_congestion && n_drop)
    vlib_buffer_free (vm, drop_list, n_drop);

  return n_packets - n_drop;
}

CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_thread_fn);

/*
 * Check the frame queue to see if any frames are available.
 * If so, pull the packets off the frames and put them to
 * the handoff node.
 */
u32 __clib_section (".vlib_frame_queue_dequeue_fn")
CLIB_MULTIARCH_FN (vlib_frame_queue_dequeue_fn)
(vlib_main_t *vm, vlib_frame_queue_main_t *fqm)
{
  u32 thread_id = vm->thread_index;
  vlib_frame_queue_t *fq = fqm->vlib_frame_queues[thread_id];
  vlib_frame_queue_elt_t *elt;
  u32 *from, *to;
  vlib_frame_t *f;
  int msg_type;
  int processed = 0;
  u32 vectors = 0;

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
      fqt->head_hint = fq->head_hint;
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
	  elt = fq->elts + ((fq->head + 1 + elix) & (fq->nelts - 1));
	  if (1 || elt->valid)
	    {
	      fqt->n_vectors[elix] = elt->n_vectors;
	    }
	}
      fqt->written = 1;
    }

  while (1)
    {
      vlib_buffer_t *b;
      if (fq->head == fq->tail)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}

      elt = fq->elts + ((fq->head + 1) & (fq->nelts - 1));

      if (!elt->valid)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}

      from = elt->buffer_index;
      msg_type = elt->msg_type;

      ASSERT (msg_type == VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME);
      ASSERT (elt->n_vectors <= VLIB_FRAME_SIZE);

      f = vlib_get_frame_to_node (vm, fqm->node_index);

      /* If the first vector is traced, set the frame trace flag */
      b = vlib_get_buffer (vm, from[0]);
      if (b->flags & VLIB_BUFFER_IS_TRACED)
	f->frame_flags |= VLIB_NODE_FLAG_TRACE;

      to = vlib_frame_vector_args (f);

      vlib_buffer_copy_indices (to, from, elt->n_vectors);

      vectors += elt->n_vectors;
      f->n_vectors = elt->n_vectors;
      vlib_put_frame_to_node (vm, fqm->node_index, f);

      elt->valid = 0;
      elt->n_vectors = 0;
      elt->msg_type = 0xfefefefe;
      CLIB_MEMORY_BARRIER ();
      fq->head++;
      processed++;

      /*
       * Limit the number of packets pushed into the graph
       */
      if (vectors >= fq->vector_threshold)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}
    }
  ASSERT (0);
  return processed;
}
CLIB_MARCH_FN_REGISTRATION (vlib_frame_queue_dequeue_fn);

#ifndef CLIB_MARCH_VARIANT
vlib_buffer_func_main_t vlib_buffer_func_main;

static clib_error_t *
vlib_buffer_funcs_init (vlib_main_t *vm)
{
  vlib_buffer_func_main_t *bfm = &vlib_buffer_func_main;
  bfm->buffer_enqueue_to_next_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_next_fn);
  bfm->buffer_enqueue_to_single_next_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_next_fn);
  bfm->buffer_enqueue_to_thread_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_thread_fn);
  bfm->frame_queue_dequeue_fn =
    CLIB_MARCH_FN_POINTER (vlib_frame_queue_dequeue_fn);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_buffer_funcs_init);
#endif
