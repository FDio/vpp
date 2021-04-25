/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

void __clib_section (".vlib_buffer_enqueue_to_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts,
 uword count)
{
  u32 *to_next, n_left_to_next, max;
  u16 next_index;

  next_index = nexts[0];
  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
  max = clib_min (n_left_to_next, count);

  while (count)
    {
      u32 n_enqueued;
      if ((nexts[0] != next_index) || n_left_to_next == 0)
	{
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	  next_index = nexts[0];
	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	  max = clib_min (n_left_to_next, count);
	}
#if defined(CLIB_HAVE_VEC512)
      u16x32 next32 = CLIB_MEM_OVERFLOW_LOAD (u16x32_load_unaligned, nexts);
      next32 = (next32 == u16x32_splat (next32[0]));
      u64 bitmap = u16x32_msb_mask (next32);
      n_enqueued = count_trailing_zeros (~bitmap);
#elif defined(CLIB_HAVE_VEC256)
      u16x16 next16 = CLIB_MEM_OVERFLOW_LOAD (u16x16_load_unaligned, nexts);
      next16 = (next16 == u16x16_splat (next16[0]));
      u64 bitmap = u8x32_msb_mask ((u8x32) next16);
      n_enqueued = count_trailing_zeros (~bitmap) / 2;
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
      u16x8 next8 = CLIB_MEM_OVERFLOW_LOAD (u16x8_load_unaligned, nexts);
      next8 = (next8 == u16x8_splat (next8[0]));
      u64 bitmap = u8x16_msb_mask ((u8x16) next8);
      n_enqueued = count_trailing_zeros (~bitmap) / 2;
#else
      u16 x = 0;
      if (count + 3 < max)
	{
	  x |= next_index ^ nexts[1];
	  x |= next_index ^ nexts[2];
	  x |= next_index ^ nexts[3];
	  n_enqueued = (x == 0) ? 4 : 1;
	}
      else
	n_enqueued = 1;
#endif

      if (PREDICT_FALSE (n_enqueued > max))
	n_enqueued = max;

#ifdef CLIB_HAVE_VEC512
      if (n_enqueued >= 32)
	{
	  vlib_buffer_copy_indices (to_next, buffers, 32);
	  nexts += 32;
	  to_next += 32;
	  buffers += 32;
	  n_left_to_next -= 32;
	  count -= 32;
	  max -= 32;
	  continue;
	}
#endif

#ifdef CLIB_HAVE_VEC256
      if (n_enqueued >= 16)
	{
	  vlib_buffer_copy_indices (to_next, buffers, 16);
	  nexts += 16;
	  to_next += 16;
	  buffers += 16;
	  n_left_to_next -= 16;
	  count -= 16;
	  max -= 16;
	  continue;
	}
#endif

#ifdef CLIB_HAVE_VEC128
      if (n_enqueued >= 8)
	{
	  vlib_buffer_copy_indices (to_next, buffers, 8);
	  nexts += 8;
	  to_next += 8;
	  buffers += 8;
	  n_left_to_next -= 8;
	  count -= 8;
	  max -= 8;
	  continue;
	}
#endif

      if (n_enqueued >= 4)
	{
	  vlib_buffer_copy_indices (to_next, buffers, 4);
	  nexts += 4;
	  to_next += 4;
	  buffers += 4;
	  n_left_to_next -= 4;
	  count -= 4;
	  max -= 4;
	  continue;
	}

      /* copy */
      to_next[0] = buffers[0];

      /* next */
      nexts += 1;
      to_next += 1;
      buffers += 1;
      n_left_to_next -= 1;
      count -= 1;
      max -= 1;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
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
  return 0;
}

VLIB_INIT_FUNCTION (vlib_buffer_funcs_init);
#endif
