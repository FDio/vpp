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
_vec_realloc (void *v, uword n_elts, uword elt_size, uword hdr_size,
	      uword align, void *heap)
{
  uword n_alloc, data_offset, old_alloc_size = 0;
  void *p;

  /* alignment must be power of 2 */
  align = clib_max (align, VEC_MIN_ALIGN);
  ASSERT (count_set_bits (align) == 1);

  data_offset = round_pow2 (hdr_size + sizeof (vec_header_t), align);

  if (v)
    {
      p = vec_header (v);
      old_alloc_size = clib_mem_size (p);
      n_alloc = n_elts * elt_size;
#if CLIB_VECTOR_GROW_BY_ONE == 0
      n_alloc = (n_alloc * 3) / 2;
#endif
      n_alloc += data_offset;

      if (old_alloc_size >= n_alloc)
	goto done;

      p = clib_mem_realloc_aligned (p, n_alloc, align);
    }
  else
    {
      n_alloc = n_elts * elt_size + data_offset;
      p = clib_mem_alloc_aligned (n_alloc, align);
    }

  clib_memset_u8 (p + old_alloc_size, 0, clib_mem_size (p) - old_alloc_size);
  v = p + data_offset;

done:
  _vec_find (v)->hdr_size = data_offset / VEC_MIN_ALIGN;
  _vec_find (v)->log2_align = min_log2 (align);
  _vec_len (v) = n_elts;
  _vec_mem_poison_unpoison (v, elt_size);
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
