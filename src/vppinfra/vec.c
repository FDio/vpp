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

/* Vector resize operator.  Called as needed by various macros such as
   vec_add1() when we need to allocate memory. */
__clib_export void *
_vec_realloc (void *v, uword n_elts, uword elt_size, uword header_bytes,
	      uword data_align, void *heap)
{
  vec_header_t *vh = _vec_find (v);
  uword old_alloc_bytes, new_alloc_bytes;
  void *old, *new;

  header_bytes = vec_header_bytes (header_bytes);
  data_align = data_align == 0 ? 1 : data_align;
  uword data_bytes = n_elts * elt_size;

  data_bytes += header_bytes;

  uword inc = n_elts - vec_len (v);

  /* alignment must be power of 2 */
  ASSERT (count_set_bits (data_align) == 1);

  if (!v)
    {
      new = clib_mem_alloc_aligned_at_offset (data_bytes, data_align, header_bytes, 1	/* yes, call os_out_of_memory */
	);
      new_alloc_bytes = clib_mem_size (new);
      CLIB_MEM_UNPOISON (new + data_bytes, new_alloc_bytes - data_bytes);
      clib_memset (new, 0, new_alloc_bytes);
      CLIB_MEM_POISON (new + data_bytes, new_alloc_bytes - data_bytes);
      v = new + header_bytes;
      _vec_len (v) = inc;
      ASSERT (header_bytes / VEC_MIN_ALIGN <= 255);
      _vec_find (v)->hdr_size = header_bytes / VEC_MIN_ALIGN;
      _vec_find (v)->log2_align = min_log2 (data_align);
      return v;
    }

  ASSERT (_vec_find (v)->hdr_size * VEC_MIN_ALIGN == header_bytes);
  header_bytes = _vec_find (v)->hdr_size * VEC_MIN_ALIGN;

  ASSERT (data_align == (1 << _vec_find (v)->log2_align));
  data_align = 1 << _vec_find (v)->log2_align;

  vh->len += inc;
  old = v - header_bytes;

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

  new =
    clib_mem_alloc_aligned_at_offset (new_alloc_bytes, data_align,
				      header_bytes,
				      1 /* yes, call os_out_of_memory */ );

  /* FIXME fail gracefully. */
  if (!new)
    clib_panic (
      "vec_resize fails, length increment %d, data bytes %d, alignment %d",
      inc, data_bytes, data_align);

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

  return v + header_bytes;
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

