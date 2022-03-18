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

__clib_export void
_vec_free (void *v)
{
  clib_mem_free (vec_header (v));
}

__clib_export void *
_vec_realloc (void *old, uword n_elts, uword elt_size, uword hdr_size,
	      uword align, void *heap)
{
  void *mspace_memalign (void *msp, size_t alignment, size_t bytes);
  size_t mspace_usable_size (const void *mem);

  void *v = old;
  vec_header_t *vh = _vec_find (v);
  uword old_alloc_bytes, new_alloc_bytes;
  void *new;

  align = clib_max (align, VEC_MIN_ALIGN);
  hdr_size = round_pow2 (hdr_size + sizeof (vec_header_t), align);
  uword data_bytes = n_elts * elt_size;

  data_bytes += hdr_size;

  /* alignment must be power of 2 */
  ASSERT (count_set_bits (align) == 1);

  if (!v)
    {
      new = clib_mem_alloc_aligned (data_bytes, align);
      new_alloc_bytes = clib_mem_size (new);
      CLIB_MEM_UNPOISON (new + data_bytes, new_alloc_bytes - data_bytes);
      clib_memset (new, 0, new_alloc_bytes);
      CLIB_MEM_POISON (new + data_bytes, new_alloc_bytes - data_bytes);
      v = new + hdr_size;
      _vec_len (v) = n_elts;
      ASSERT (hdr_size / VEC_MIN_ALIGN <= 255);
      _vec_find (v)->hdr_size = hdr_size / VEC_MIN_ALIGN;
      _vec_find (v)->log2_align = min_log2 (align);
      return v;
    }

  ASSERT (_vec_find (v)->hdr_size * VEC_MIN_ALIGN == hdr_size);
  hdr_size = _vec_find (v)->hdr_size * VEC_MIN_ALIGN;

  ASSERT (align == (1 << _vec_find (v)->log2_align));
  align = 1 << _vec_find (v)->log2_align;

  vh->len = n_elts;
  old = v - hdr_size;

  /* Vector header must start heap object. */
  ASSERT (clib_mem_is_heap_object (old));

  old_alloc_bytes = clib_mem_size (old);

  /* Need to resize? */
  if (data_bytes <= old_alloc_bytes)
    {
      CLIB_MEM_UNPOISON (v, data_bytes);
      return v;
    }

#if CLIB_VECTOR_GROW_BY_ONE > 0
  new_alloc_bytes = data_bytes;
#else
  new_alloc_bytes = (old_alloc_bytes * 3) / 2;
  if (new_alloc_bytes < data_bytes)
    new_alloc_bytes = data_bytes;
#endif

  new = clib_mem_alloc_aligned (new_alloc_bytes, align);

  /* FIXME fail gracefully. */
  if (!new)
    clib_panic ("vec_resize fails, n_elts %d, elt_size %d, alignment %d",
		n_elts, elt_size, align);

  CLIB_MEM_UNPOISON (old, old_alloc_bytes);
  clib_memcpy_fast (new, old, old_alloc_bytes);
  clib_mem_free (old);

  /* Allocator may give a bit of extra room. */
  new_alloc_bytes = clib_mem_size (new);
  v = new;

  /* Zero new memory. */
  CLIB_MEM_UNPOISON (new + data_bytes, new_alloc_bytes - data_bytes);
  memset (v + old_alloc_bytes, 0, new_alloc_bytes - old_alloc_bytes);
  CLIB_MEM_POISON (new + data_bytes, new_alloc_bytes - data_bytes);

  return v + hdr_size;
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
