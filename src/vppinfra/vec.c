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
_vec_realloc (void *v, uword n_elts, uword elt_sz, uword hdr_sz, uword align,
	      void *heap)
{
  uword n_data_bytes, alloc_size, new_data_size;
  void *p;

  /* alignment must be power of 2 */
  align = clib_max (align, VEC_MIN_ALIGN);
  ASSERT (count_set_bits (align) == 1);

  /* mumber of bytes needed to store vector data */
  n_data_bytes = n_elts * elt_sz;

  if (v)
    {
      uword data_offset = vec_get_header_size (v);
      uword old_data_size = data_offset + _vec_len (v) * elt_sz;
      new_data_size = data_offset + n_data_bytes;
      heap = _vec_find (v)->default_heap ? 0 : _vec_heap (v);
      p = vec_header (v);
      alloc_size = clib_mem_size (p);

      /* check that we are still dealing with the same vector type */
      ASSERT (_vec_find (v)->hdr_size * VEC_MIN_ALIGN == data_offset);
      ASSERT (_vec_find (v)->log2_align == min_log2 (align));

      /* realloc if new size cannot fit into existing allocation */
      if (alloc_size < new_data_size)
	{
	  if (CLIB_VECTOR_GROW_BY_ONE)
	    alloc_size = n_data_bytes + data_offset;
	  else
	    alloc_size = (n_data_bytes * 3) / 2 + data_offset;

	  p = clib_mem_heap_realloc_aligned (heap, p, alloc_size, align);
	  alloc_size = clib_mem_size (p);
	  v = p + data_offset;
	}

      CLIB_MEM_UNPOISON (p, alloc_size);
      clib_memset_u8 (p + old_data_size, 0, alloc_size - old_data_size);
    }
  else
    {
      /* new allocation */
      uword data_offset = hdr_sz + sizeof (vec_header_t);
      data_offset += heap ? sizeof (void *) : 0;
      data_offset = round_pow2 (data_offset, align);

      new_data_size = data_offset + n_data_bytes;
      p = clib_mem_heap_alloc_aligned (heap, new_data_size, align);
      alloc_size = clib_mem_size (p);
      CLIB_MEM_UNPOISON (p, alloc_size);
      clib_memset_u8 (p, 0, alloc_size);
      v = p + data_offset;
      _vec_find (v)->hdr_size = data_offset / VEC_MIN_ALIGN;
      _vec_find (v)->log2_align = min_log2 (align);
      if (heap)
	{
	  _vec_find (v)->default_heap = 0;
	  _vec_heap (v) = heap;
	}
      else
	_vec_find (v)->default_heap = 1;
    }

  CLIB_MEM_POISON (p + new_data_size, alloc_size - new_data_size);
  _vec_len (v) = n_elts;
  return v;
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
