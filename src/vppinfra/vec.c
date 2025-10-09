/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/vec.h>
#include <vppinfra/mem.h>

#ifndef CLIB_VECTOR_GROW_BY_ONE
#define CLIB_VECTOR_GROW_BY_ONE 0
#endif

__clib_export uword
vec_mem_size (void *v)
{
  return v ? clib_mem_size (v - vec_get_header_size (v)) : 0;
}

__clib_export void *
_vec_alloc_internal (uword n_elts, const vec_attr_t *const attr)
{
  uword req_size, alloc_size, data_offset, align;
  uword elt_sz = attr->elt_sz;
  void *p, *v, *heap = attr->heap;

  /* alignment must be power of 2 */
  align = clib_max (attr->align, VEC_MIN_ALIGN);
  ASSERT (count_set_bits (align) == 1);

  /* calc offset where vector data starts */
  data_offset = attr->hdr_sz + sizeof (vec_header_t);
  data_offset += heap ? sizeof (void *) : 0;
  data_offset = round_pow2 (data_offset, align);

  req_size = data_offset + n_elts * elt_sz;
  p = clib_mem_heap_alloc_aligned (heap, req_size, align);

  /* zero out whole alocation */
  alloc_size = clib_mem_size (p);
  clib_mem_unpoison (p, alloc_size);
  clib_memset_u8 (p, 0, alloc_size);

  /* fill vector header */
  v = p + data_offset;
  _vec_find (v)->len = n_elts;
  _vec_find (v)->hdr_size = data_offset / VEC_MIN_ALIGN;
  _vec_find (v)->log2_align = min_log2 (align);
  if (heap)
    {
      _vec_find (v)->default_heap = 0;
      _vec_heap (v) = heap;
    }
  else
    _vec_find (v)->default_heap = 1;

  /* poison extra space given by allocator */
  clib_mem_poison (p + req_size, alloc_size - req_size);
  _vec_set_grow_elts (v, (alloc_size - req_size) / elt_sz);
  return v;
}

__clib_export void
_vec_update_len (void *v, uword n_elts, uword elt_sz, uword n_data_bytes,
		 uword unused_bytes)
{
  _vec_find (v)->len = n_elts;
  _vec_set_grow_elts (v, unused_bytes / elt_sz);
  clib_mem_unpoison (v, n_data_bytes);
  clib_mem_poison (v + n_data_bytes, unused_bytes);
}

__clib_export void *
_vec_realloc_internal (void *v, uword n_elts, const vec_attr_t *const attr)
{
  uword old_alloc_sz, new_alloc_sz, new_data_size, n_data_bytes, data_offset;
  uword elt_sz;

  if (PREDICT_FALSE (v == 0))
    return _vec_alloc_internal (n_elts, attr);

  elt_sz = attr->elt_sz;
  n_data_bytes = n_elts * elt_sz;
  data_offset = vec_get_header_size (v);
  new_data_size = data_offset + n_data_bytes;
  new_alloc_sz = old_alloc_sz = clib_mem_size (vec_header (v));

  /* realloc if new size cannot fit into existing allocation */
  if (old_alloc_sz < new_data_size)
    {
      uword n_bytes, req_size = new_data_size;
      void *p = v - data_offset;

      req_size += CLIB_VECTOR_GROW_BY_ONE ? 0 : n_data_bytes / 2;

      p = clib_mem_heap_realloc_aligned (vec_get_heap (v), p, req_size,
					 vec_get_align (v));
      new_alloc_sz = clib_mem_size (p);
      v = p + data_offset;

      /* zero out new allocation */
      n_bytes = new_alloc_sz - old_alloc_sz;
      clib_mem_unpoison (p + old_alloc_sz, n_bytes);
      clib_memset_u8 (p + old_alloc_sz, 0, n_bytes);
    }

  _vec_update_len (v, n_elts, elt_sz, n_data_bytes,
		   new_alloc_sz - new_data_size);
  return v;
}

__clib_export void *
_vec_resize_internal (void *v, uword n_elts, const vec_attr_t *const attr)
{
  uword elt_sz = attr->elt_sz;
  if (PREDICT_TRUE (v != 0))
    {
      uword hs = _vec_find (v)->hdr_size * VEC_MIN_ALIGN;
      uword alloc_sz = clib_mem_size (v - hs);
      uword n_data_bytes = elt_sz * n_elts;
      word unused_bytes = alloc_sz - (n_data_bytes + hs);

      if (PREDICT_TRUE (unused_bytes >= 0))
	{
	  _vec_update_len (v, n_elts, elt_sz, n_data_bytes, unused_bytes);
	  return v;
	}
    }

  /* this shouled emit tail jump and likely avoid stack usasge inside this
   * function */
  return _vec_realloc_internal (v, n_elts, attr);
}

__clib_export u32
vec_len_not_inline (void *v)
{
  return vec_len (v);
}

__clib_export void
vec_free_not_inline (void *v)
{
  vec_free (v);
}
