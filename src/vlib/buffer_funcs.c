/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021-2026 Cisco Systems, Inc.
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
  u32 *to, *to_aux = 0;

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

static_always_inline void
vlib_buffer_enqueue_to_single_next_aux64_fn_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
						    u32 *buffers, u64 *aux_data, u16 next_index,
						    u32 count)
{
  u32 *to_next, n_left_to_next, n_enq;
  u64 *to_next_aux;

  vlib_get_new_next_frame_with_aux (vm, node, next_index, to_next, to_next_aux, n_left_to_next);

  if (PREDICT_TRUE (n_left_to_next >= count))
    {
      vlib_buffer_copy_indices (to_next, buffers, count);
      clib_memcpy_fast (to_next_aux, aux_data, count * sizeof (aux_data[0]));
      n_left_to_next -= count;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return;
    }

  n_enq = n_left_to_next;
next:
  vlib_buffer_copy_indices (to_next, buffers, n_enq);
  clib_memcpy_fast (to_next_aux, aux_data, n_enq * sizeof (aux_data[0]));
  n_left_to_next -= n_enq;

  if (PREDICT_FALSE (count > n_enq))
    {
      count -= n_enq;
      buffers += n_enq;
      aux_data += n_enq;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      vlib_get_new_next_frame_with_aux (vm, node, next_index, to_next, to_next_aux, n_left_to_next);
      n_enq = clib_min (n_left_to_next, count);
      goto next;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
}

static_always_inline void
vlib_buffer_enqueue_to_single_next_aux64_and_scalar_fn_inline (vlib_main_t *vm,
							       vlib_node_runtime_t *node,
							       u32 *buffers, u64 *aux_data,
							       void *scalar_data, u16 scalar_size,
							       u16 next_index, u32 count)
{
  u32 *to_next, n_left_to_next, n_enq;
  u64 *to_next_aux;
  vlib_next_frame_t *nf;

  vlib_get_next_frame_with_aux (vm, node, next_index, to_next, to_next_aux, n_left_to_next);
  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
  clib_memcpy_fast (vlib_frame_scalar_args (nf->frame), scalar_data, scalar_size);

  if (PREDICT_TRUE (n_left_to_next >= count))
    {
      vlib_buffer_copy_indices (to_next, buffers, count);
      clib_memcpy_fast (to_next_aux, aux_data, count * sizeof (aux_data[0]));
      n_left_to_next -= count;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return;
    }

  n_enq = n_left_to_next;
next:
  vlib_buffer_copy_indices (to_next, buffers, n_enq);
  clib_memcpy_fast (to_next_aux, aux_data, n_enq * sizeof (aux_data[0]));
  n_left_to_next -= n_enq;

  if (PREDICT_FALSE (count > n_enq))
    {
      count -= n_enq;
      buffers += n_enq;
      aux_data += n_enq;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      vlib_get_next_frame_with_aux (vm, node, next_index, to_next, to_next_aux, n_left_to_next);
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      clib_memcpy_fast (vlib_frame_scalar_args (nf->frame), scalar_data, scalar_size);
      n_enq = clib_min (n_left_to_next, count);
      goto next;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
}

void __clib_section (".vlib_buffer_enqueue_to_single_next_with_aux64_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_next_with_aux64_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u64 *aux_data, u16 next_index, u32 count)
{
  vlib_buffer_enqueue_to_single_next_aux64_fn_inline (vm, node, buffers, aux_data, next_index,
						      count);
}
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_next_with_aux64_fn);

void __clib_section (".vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar_fn")
CLIB_MULTIARCH_FN (vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u64 *aux_data, void *scalar_data,
 u16 scalar_size, u16 next_index, u32 count)
{
  vlib_buffer_enqueue_to_single_next_aux64_and_scalar_fn_inline (
    vm, node, buffers, aux_data, scalar_data, scalar_size, next_index, count);
}
CLIB_MARCH_FN_REGISTRATION (vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar_fn);

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
  bfm->buffer_enqueue_to_single_next_with_aux64_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_next_with_aux64_fn);
  bfm->buffer_enqueue_to_single_next_with_aux64_and_scalar_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar_fn);
  bfm->buffer_enqueue_to_thread_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_thread_fn);
  bfm->buffer_enqueue_to_single_thread_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_single_thread_fn);
  bfm->buffer_enqueue_to_thread_with_aux_fn =
    CLIB_MARCH_FN_POINTER (vlib_buffer_enqueue_to_thread_with_aux_fn);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_buffer_funcs_init);
#endif
