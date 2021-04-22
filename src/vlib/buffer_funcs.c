/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

typedef struct
{
  uword used_elts[VLIB_FRAME_SIZE / 64];
  u32 uword_offset;
} extract_data_t;

static_always_inline u32 *
extract_unused_elts_x64 (u32 *elts, u16 *indices, u16 index, int n_left,
			 u64 *bmp, u32 *dst)
{
  u64 mask = 0;
#if defined CLIB_HAVE_VEC512
  u16x32 idx32 = u16x32_splat (index);
  u16x32u *iv = (u16x32u *) indices;
#elif defined CLIB_HAVE_VEC256
  u16x16 idx16 = u16x16_splat (index);
  u16x16u *iv = (u16x16u *) indices;
#elif defined CLIB_HAVE_VEC128
  u16x8 idx8 = u16x8_splat (index);
  u16x8u *iv = (u16x8u *) indices;
#endif

#ifdef CLIB_HAVE_VEC512_COMPRESS
  u32x16u *ev = (u32x16u *) elts;
  mask = (u64) u16x32_is_equal_mask (iv[0], idx32);
  mask |= (u64) u16x32_is_equal_mask (iv[1], idx32) << 32;

  if (n_left == 64)
    {
      if (mask == ~0ULL)
	{
	  clib_memcpy_u32 (dst, elts, 64);
	  *bmp |= ~0ULL;
	  return dst + 64;
	}
    }
  else
    mask &= pow2_mask (n_left);

  *bmp |= mask;
  for (int i = 0; i < 4; i++)
    {
      int cnt = _popcnt32 ((u16) mask);
      u32x16_compress_store (ev[i], mask, dst);
      dst += cnt;
      mask >>= 16;
    }

#elif defined CLIB_HAVE_VEC256_COMPRESS
  u32x8u *ev = (u32x8u *) elts;
  mask = (u64) u16x16_is_equal_mask (iv[0], idx16);
  mask |= (u64) u16x16_is_equal_mask (iv[1], idx16) << 16;
  mask |= (u64) u16x16_is_equal_mask (iv[2], idx16) << 32;
  mask |= (u64) u16x16_is_equal_mask (iv[3], idx16) << 48;

  if (n_left == 64)
    {
      if (mask == ~0ULL)
	{
	  clib_memcpy_u32 (dst, elts, 64);
	  *bmp |= ~0ULL;
	  return dst + 64;
	}
    }
  else
    mask &= pow2_mask (n_left);

  *bmp |= mask;
  for (int i = 0; i < 8; i++)
    {
      int cnt = _popcnt32 ((u8) mask);
      u32x8_compress_store (ev[i], mask, dst);
      dst += cnt;
      mask >>= 8;
    }
#elif defined(CLIB_HAVE_VEC256)
  u64 b0, b1, b2, b3;
  const u64 pext_mask = 0x5555555555555555;
  b0 = u8x32_msb_mask (idx16 == iv[0]);
  b1 = u8x32_msb_mask (idx16 == iv[1]);
  b2 = u8x32_msb_mask (idx16 == iv[2]);
  b3 = u8x32_msb_mask (idx16 == iv[3]);

  if (n_left == 64)
    {
      if (PREDICT_TRUE ((b0 & b1 & b2 & b3) == 0xFFFFFFFF))
	{
	  clib_memcpy_u32 (dst, elts, 64);
	  *bmp |= ~0ULL;
	  return dst + 64;
	}
      mask = ~0ULL;
    }
  else
    mask = pow2_mask (n_left);

  mask &= (_pext_u64 (b0 | (b1 << 32), pext_mask) |
	   _pext_u64 (b2 | (b3 << 32), pext_mask) << 32);
  *bmp |= mask;

  while (mask)
    {
      u16 bit = count_trailing_zeros (mask);
      mask = clear_lowest_set_bit (mask);
      dst++[0] = elts[bit];
    }

#else
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u16 b0, b1;
  b0 = u8x16_msb_mask (idx8 == iv[0]) & u8x16_msb_mask (idx8 == iv[1]);
  b1 = u8x16_msb_mask (idx8 == iv[2]) & u8x16_msb_mask (idx8 == iv[3]);
  if (n_left == 64 && (b0 & b1) == 0xFFFF)
    {
      clib_memcpy_u32 (dst, elts, 64);
      *bmp |= ~0ULL;
      return dst + 64;
    }
#endif
  for (int i = 0; i < n_left; i++)
    {
      if (indices[i] == index)
	{
	  dst++[0] = elts[i];
	  mask |= 1ULL << i;
	}
    }
  *bmp |= mask;
#endif
  return dst;
}

static_always_inline u32
extract_unused_elts_by_index (extract_data_t *d, u32 *elts, u16 *indices,
			      u16 index, int n_left, u32 *dst)
{
  u32 *dst0 = dst;
  u64 *bmp = d->used_elts;
  while (n_left >= 64)
    {
      dst = extract_unused_elts_x64 (elts, indices, index, 64, bmp, dst);

      /* next */
      indices += 64;
      elts += 64;
      bmp++;
      n_left -= 64;
    }

  if (n_left)
    dst = extract_unused_elts_x64 (elts, indices, index, n_left, bmp, dst);

  return dst - dst0;
}

static_always_inline u32
find_first_unused_elt (extract_data_t *d)
{
  u64 *ue = d->used_elts + d->uword_offset;

  while (PREDICT_FALSE (ue[0] == ~0))
    {
      ue++;
      d->uword_offset++;
    }

  return d->uword_offset * 64 + count_trailing_zeros (~ue[0]);
}

static_always_inline u32
enqueue_one (vlib_main_t *vm, vlib_node_runtime_t *node, extract_data_t *d,
	     u16 next_index, u32 *buffers, u16 *nexts, u32 n_buffers,
	     u32 n_left, u32 *tmp)
{
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

  n_extracted = extract_unused_elts_by_index (d, buffers, nexts, next_index,
					      n_buffers, to);

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
      extract_data_t d = {};
      n_left = VLIB_FRAME_SIZE;

      next_index = nexts[0];
      n_left = enqueue_one (vm, node, &d, next_index, buffers, nexts,
			    VLIB_FRAME_SIZE, n_left, tmp);

      while (n_left)
	{
	  next_index = nexts[find_first_unused_elt (&d)];
	  n_left = enqueue_one (vm, node, &d, next_index, buffers, nexts,
				VLIB_FRAME_SIZE, n_left, tmp);
	}

      buffers += VLIB_FRAME_SIZE;
      nexts += VLIB_FRAME_SIZE;
      count -= VLIB_FRAME_SIZE;
    }

  if (count)
    {
      extract_data_t d = {};
      next_index = nexts[0];
      n_left = count;

      n_left = enqueue_one (vm, node, &d, next_index, buffers, nexts, count,
			    n_left, tmp);

      while (n_left)
	{
	  next_index = nexts[find_first_unused_elt (&d)];
	  n_left = enqueue_one (vm, node, &d, next_index, buffers, nexts,
				count, n_left, tmp);
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
