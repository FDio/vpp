/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#ifdef CLIB_HAVE_VEC512_COMPRESS
static_always_inline u16
compress_and_store16 (u32x16 fv, u16x16 nv, u16 n_elts, u16 mask, u32 *sp,
		      u32 *dp, u16 *np)
{
  u16 rv = _popcnt32 (mask);

  /* store matched */
  *(u32x16u *) dp = u32x16_compress (fv, mask);

  /* inverse mask */
  mask = ~mask & pow2_mask (n_elts);

  /* remaining indices */
  *(u32x16u *) sp = u32x16_compress (fv, mask);

  /* remaining nexts */
  *(u16x16u *) np = u16x16_compress (nv, mask);
  return rv;
}
#elif defined CLIB_HAVE_VEC256_COMPRESS
static_always_inline u8
compress_and_store8 (u32x8 fv, u16x8 nv, u16 n_elts, u8 mask, u32 *sp, u32 *dp,
		     u16 *np)
{
  u16 rv = _popcnt32 (mask);

  /* store matched */
  *(u32x8u *) dp = u32x8_compress (fv, mask);

  /* inverse mask */
  mask = ~mask & pow2_mask (n_elts);

  /* remaining indices */
  *(u32x8u *) sp = u32x8_compress (fv, mask);

  /* remaining nexts */
  *(u16x8u *) np = u16x8_compress (nv, mask);
  return rv;
}
#endif

static_always_inline u32
vlib_buffer_extract_indices_by_next (u32 *from, u16 *nexts, u16 next_index,
				     int n_left, u32 *extracted,
				     u32 *remaining, u16 *remainining_nexts)
{
  u32 *tp = extracted;	       /* extracted inidice write pointer */
  u32 *fp = remaining;	       /* remaining indices write pointer */
  u16 *np = remainining_nexts; /* remaining nexts write pointer */

#ifdef CLIB_HAVE_VEC512_COMPRESS
  u16x32 next0x32 = u16x32_splat (next_index);
  u16x16 next0x16 = u16x32_extract_lo (next0x32);
  u32x16 f;
  u16x16 n;
  u16 mask, cnt;

  while (n_left >= 32)
    {
      u32 mask32;
      u16x32 next32 = *(u16x32u *) nexts;
      mask32 = u16x32_is_equal_mask (next32, next0x32);
      u32x16u *fv = (u32x16u *) from;

      if (PREDICT_TRUE (mask32 == pow2_mask (32)))
	{
	  u32x16u *tv = (u32x16u *) tp;
	  tv[0] = fv[0];
	  tv[1] = fv[1];
	  tp += 32;
	}
      else
	{
	  n = u16x32_extract_lo (next32);
	  cnt = compress_and_store16 (fv[0], n, 16, mask32, fp, tp, np);
	  tp += cnt;
	  cnt = 16 - cnt;
	  fp += cnt;
	  np += cnt;

	  n = u16x32_extract_hi (next32);
	  cnt = compress_and_store16 (fv[1], n, 16, mask32 >> 16, fp, tp, np);
	  tp += cnt;
	  cnt = 16 - cnt;
	  fp += cnt;
	  np += cnt;
	}

      /* next */
      nexts += 32;
      from += 32;
      n_left -= 32;
    }

  if (n_left >= 16)
    {
      n = *(u16x16u *) nexts;
      u32x16u *fv = (u32x16u *) from;
      mask = u16x16_is_equal_mask (n, next0x16);

      if (PREDICT_TRUE (mask == pow2_mask (16)))
	{
	  u32x16u *tv = (u32x16u *) tp;
	  tv[0] = fv[0];
	  tp += 16;
	}
      else
	{
	  cnt = compress_and_store16 (fv[0], n, 16, mask, fp, tp, np);
	  tp += cnt;
	  fp += 16 - cnt;
	  np += 16 - cnt;
	}

      /* next */
      nexts += 16;
      from += 16;
      n_left -= 16;
    }

  if (n_left > 0)
    {
      n = *(u16x16u *) nexts;
      f = *(u32x16u *) from;
      mask = u16x16_is_equal_mask (n, next0x16) & pow2_mask (n_left);
      tp += compress_and_store16 (f, n, n_left, mask, fp, tp, np);
    }
#elif defined CLIB_HAVE_VEC256_COMPRESS
  u16x16 next0x16 = u16x16_splat (next_index);
  u16x8 next0x8 = u16x16_extract_lo (next0x16);
  u32x8 f;
  u16x8 n;
  u16 cnt;
  u8 mask;

  while (n_left >= 16)
    {
      u16 mask16;
      u16x16 next16 = *(u16x16u *) nexts;
      mask16 = u16x16_is_equal_mask (next16, next0x16);
      u32x8u *fv = (u32x8u *) from;

      if (PREDICT_TRUE (mask16 == pow2_mask (16)))
	{
	  u32x8u *tv = (u32x8u *) tp;
	  tv[0] = fv[0];
	  tv[1] = fv[1];
	  tp += 16;
	}
      else
	{
	  n = u16x16_extract_lo (next16);
	  cnt = compress_and_store8 (fv[0], n, 8, mask16, fp, tp, np);
	  tp += cnt;
	  cnt = 8 - cnt;
	  fp += cnt;
	  np += cnt;

	  n = u16x16_extract_hi (next16);
	  cnt = compress_and_store8 (fv[1], n, 8, mask16 >> 8, fp, tp, np);
	  tp += cnt;
	  cnt = 8 - cnt;
	  fp += cnt;
	  np += cnt;
	}

      /* next */
      nexts += 16;
      from += 16;
      n_left -= 16;
    }

  while (n_left >= 8)
    {
      n = *(u16x8u *) nexts;
      u32x8u *fv = (u32x8u *) from;
      mask = u16x8_is_equal_mask (n, next0x8);

      if (PREDICT_TRUE (mask == pow2_mask (8)))
	{
	  u32x8u *tv = (u32x8u *) tp;
	  tv[0] = fv[0];
	  tp += 8;
	}
      else
	{
	  cnt = compress_and_store8 (fv[0], n, 8, mask, fp, tp, np);
	  tp += cnt;
	  fp += 8 - cnt;
	  np += 8 - cnt;
	}

      /* next */
      nexts += 8;
      from += 8;
      n_left -= 8;
    }

  if (n_left > 0)
    {
      n = *(u16x8u *) nexts;
      f = *(u32x8u *) from;
      mask = u16x8_is_equal_mask (n, next0x8) & pow2_mask (n_left);
      tp += compress_and_store8 (f, n, n_left, mask, fp, tp, np);
    }
#else
#ifdef CLIB_HAVE_VEC256
  u16x16 n16, next0x16 = u16x16_splat (next_index);
#elif defined CLIB_HAVE_VEC128
  u16x8 n8, next0x8 = u16x8_splat (next_index);
#endif

  while (n_left)
    {
#ifdef CLIB_HAVE_VEC256
      n16 = *(u16x16u *) nexts;
      if (n_left >= 16 && u16x16_is_equal (n16, next0x16))
	{
	  u32x8u *fv = (u32x8u *) from;
	  u32x8u *tv = (u32x8u *) tp;

	  tv[0] = fv[0];
	  tv[1] = fv[1];
	  tp += 16;
	  from += 16;
	  nexts += 16;
	  n_left -= 16;
	  continue;
	}
#elif defined CLIB_HAVE_VEC128
      n8 = *(u16x8u *) nexts;
      if (n_left >= 8 && u16x8_is_equal (n8, next0x8))
	{
	  u32x4u *fv = (u32x4u *) from;
	  u32x4u *tv = (u32x4u *) tp;

	  tv[0] = fv[0];
	  tv[1] = fv[1];
	  tp += 8;
	  from += 8;
	  nexts += 8;
	  n_left -= 8;
	  continue;
	}
#endif
      if (nexts[0] == next_index)
	{
	  tp++[0] = from[0];
	}
      else
	{
	  fp++[0] = from[0];
	  np++[0] = nexts[0];
	}

      from++;
      nexts++;
      n_left--;
    }
#endif
  return tp - extracted;
}

static_always_inline u32
enqueue_one (vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers,
	     u16 *nexts, u32 n_buffers, u32 *remaining_buffers,
	     u16 *remaining_nexts, u32 *tmp)
{
  vlib_frame_t *f;
  u16 next_index;
  u32 n_extracted, n_free;
  u32 *to;

  next_index = nexts[0];
  f = vlib_get_next_frame_internal (vm, node, next_index, 0);

  n_free = VLIB_FRAME_SIZE - f->n_vectors;

  /* if frame contains enough space for worst case scenario, we can avoid
   * use of tmp */
  if (n_free >= n_buffers)
    to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
  else
    to = tmp;

  n_extracted = vlib_buffer_extract_indices_by_next (
    buffers, nexts, next_index, n_buffers, to, remaining_buffers,
    remaining_nexts);

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
      n_free = n_extracted - n_free;
      f = vlib_get_next_frame_internal (vm, node, next_index, 1);
      to = vlib_frame_vector_args (f);
      vlib_buffer_copy_indices (to, tmp + n_free, n_free);
      vlib_put_next_frame (vm, node, next_index, VLIB_FRAME_SIZE - n_free);
    }

  return n_buffers - n_extracted;
}

void __clib_section (".vlib_buffer_enqueue_to_next_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_next_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts,
 uword count)
{
  u32 remaining_buffers[VLIB_FRAME_SIZE];
  u32 tmp[VLIB_FRAME_SIZE];
  u16 remaining_nexts[VLIB_FRAME_SIZE];
  u32 n_left;

  while (count >= VLIB_FRAME_SIZE)
    {
      n_left = enqueue_one (vm, node, buffers, nexts, VLIB_FRAME_SIZE,
			    remaining_buffers, remaining_nexts, tmp);

      while (n_left)
	n_left = enqueue_one (vm, node, remaining_buffers, remaining_nexts,
			      n_left, remaining_buffers, remaining_nexts, tmp);

      buffers += VLIB_FRAME_SIZE;
      nexts += VLIB_FRAME_SIZE;
      count -= VLIB_FRAME_SIZE;
    }

  if (count)
    {
      n_left = enqueue_one (vm, node, buffers, nexts, count, remaining_buffers,
			    remaining_nexts, tmp);

      while (n_left)
	n_left = enqueue_one (vm, node, remaining_buffers, remaining_nexts,
			      n_left, remaining_buffers, remaining_nexts, tmp);
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
