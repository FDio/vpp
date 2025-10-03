/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>

#include <vlib/delayed_free.h>
#include <vlib/vlib.h>

__clib_export void
clib_mem_heap_free_mt_safe (void *heap, void *p)
{
  clib_mem_heap_t *h;
  clib_delayed_free_entry_t *e;
  vlib_main_t *vm = vlib_get_main ();

  /* For now, only the main thread can perform mt-safe reallocations. */
  ASSERT (vlib_get_thread_index () == 0);

  /* If no workers, no need for delayed free. */
  if (vlib_num_workers () == 0)
    {
      clib_mem_heap_free (heap, p);
      return;
    }

  if (heap == 0)
    h = clib_mem_get_per_cpu_heap ();
  else
    h = heap;

  /* Allocate the element in the vector. */
  vec_add2 (vm->pending_frees, e, 1);
  e->ptr_to_free = p;
  e->heap = h;
  e->type = CLIB_DELAYED_FREE_DLMALLOC;
}

__clib_export void
clib_mem_free_mt_safe (void *p)
{
  clib_mem_heap_free_mt_safe (0, p);
}

/* TODO: Deduplicate with vppinfra/mem_dlmalloc.c if without perf impact. */

__clib_export void *
clib_mem_heap_realloc_aligned_mt_safe (void *heap, void *p, uword new_size,
				       uword align)
{
  uword old_alloc_size;
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();
  void *new;

  ASSERT (count_set_bits (align) == 1);

  old_alloc_size = p ? mspace_usable_size (p) : 0;

  if (new_size == old_alloc_size)
    return p;

  if (p && pointer_is_aligned (p, align) &&
      mspace_realloc_in_place (h->mspace, p, new_size))
    {
      clib_mem_unpoison (p, new_size);
      if (PREDICT_FALSE (h->flags & CLIB_MEM_HEAP_F_TRACED))
	{
	  mheap_put_trace_internal (h, pointer_to_uword (p), old_alloc_size);
	  mheap_get_trace_internal (h, pointer_to_uword (p),
				    clib_mem_size (p));
	}
    }
  else
    {
      new = clib_mem_heap_alloc_inline (h, new_size, align, 1);

      clib_mem_unpoison (new, new_size);
      if (old_alloc_size)
	{
	  clib_mem_unpoison (p, old_alloc_size);
	  clib_memcpy_fast (new, p, clib_min (new_size, old_alloc_size));
	  clib_mem_heap_free_mt_safe (h, p);
	}
      p = new;
    }

  return p;
}

__clib_export void *
clib_mem_heap_realloc_mt_safe (void *heap, void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned_mt_safe (heap, p, new_size,
						CLIB_MEM_MIN_ALIGN);
}

__clib_export void *
clib_mem_realloc_aligned_mt_safe (void *p, uword new_size, uword align)
{
  return clib_mem_heap_realloc_aligned_mt_safe (0, p, new_size, align);
}

__clib_export void *
clib_mem_realloc_mt_safe (void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned_mt_safe (0, p, new_size,
						CLIB_MEM_MIN_ALIGN);
}

__clib_export void *
_vec_realloc_internal_mt_safe (void *v, uword n_elts,
			       const vec_attr_t *const attr)
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

      p = clib_mem_heap_realloc_aligned_mt_safe (vec_get_heap (v), p, req_size,
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
_vec_resize_internal_mt_safe (void *v, uword n_elts,
			      const vec_attr_t *const attr)
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
  return _vec_realloc_internal_mt_safe (v, n_elts, attr);
}

/* The following function move elements in inherently unsafe way:
 * _ ver prepend, _vec_insert_elts, _vec insert,
 */

__clib_export void
_vec_resize_mt_safe (void **vp, uword n_add, uword hdr_sz, uword align,
		     uword elt_sz)
{
  void *v = *vp;
  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = _vec_alloc_internal (n_add, &va);
      return;
    }

  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal_mt_safe (v, _vec_len (v) + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, _vec_len (v) + n_add, elt_sz);
}

__clib_export void
_vec_validate_mt_safe (void **vp, uword index, uword header_size, uword align,
		       void *heap, uword elt_sz)
{
  void *v = *vp;
  uword vl, n_elts = index + 1;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = header_size };
      *vp = _vec_alloc_internal (n_elts, &va);
      return;
    }

  vl = _vec_len (v);

  if (PREDICT_FALSE (index < vl))
    return;

  if (PREDICT_FALSE (index >= _vec_find (v)->grow_elts + vl))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = header_size };
      v = _vec_resize_internal_mt_safe (v, n_elts, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, n_elts, elt_sz);

  _vec_zero_elts (v, vl, n_elts - vl, elt_sz);
}

__clib_export void
_vec_append_mt_safe (void **v1p, void *v2, uword v1_elt_sz, uword v2_elt_sz,
		     uword align)
{
  void *v1 = v1p[0];
  uword len1 = vec_len (v1);
  uword len2 = vec_len (v2);

  if (PREDICT_TRUE (len2 > 0))
    {
      const vec_attr_t va = { .elt_sz = v2_elt_sz, .align = align };
      v1 = _vec_resize_internal_mt_safe (v1, len1 + len2, &va);
      clib_memcpy_fast (v1 + len1 * v1_elt_sz, v2, len2 * v2_elt_sz);
      _vec_update_pointer (v1p, v1);
    }
}

__clib_export void
_vec_add_mt_safe (void **vp, void *e, word n_add, uword hdr_sz, uword align,
		  uword elt_sz)
{
  void *v = *vp;
  uword len;

  ASSERT (n_add >= 0);

  if (n_add < 1)
    return;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = v = _vec_alloc_internal (n_add, &va);
      clib_memcpy_fast (v, e, n_add * elt_sz);
      return;
    }

  len = _vec_len (v);

  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal_mt_safe (v, len + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + n_add, elt_sz);

  clib_memcpy_fast (v + len * elt_sz, e, n_add * elt_sz);
}

__clib_export void *
_vec_add1_mt_safe (void **vp, uword hdr_sz, uword align, uword elt_sz)
{
  void *v = vp[0];
  uword len;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      return *vp = _vec_alloc_internal (1, &va);
    }

  len = _vec_len (v);

  if (PREDICT_FALSE (_vec_find (v)->grow_elts == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal_mt_safe (v, len + 1, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + 1, elt_sz);

  return v + len * elt_sz;
}

__clib_export void
_vec_add2_mt_safe (void **vp, void **pp, uword n_add, uword hdr_sz,
		   uword align, uword elt_sz)
{
  void *v = *vp;
  uword len;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = *pp = _vec_alloc_internal (n_add, &va);
      return;
    }

  len = _vec_len (v);
  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal_mt_safe (v, len + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + n_add, elt_sz);

  *pp = v + len * elt_sz;
}

__clib_export void
_vec_free_mt_safe (void **vp)
{
  if (vp[0] == 0)
    return;
  clib_mem_heap_free_mt_safe (vec_get_heap (vp[0]), vec_header (vp[0]));
  vp[0] = 0;
}

/* TODO: Divide into multiple files depending on which vppinfra file is
 * mirrored? */

/* _hash_create is inherently safe */
/* TODO: format_hash? */

__clib_export hash_pair_union_t *
set_indirect_mt_safe (void *v, hash_pair_indirect_t *pi, uword key,
		      uword *found_key)
{
  hash_t *h = hash_header (v);
  hash_pair_t *new_pair;
  hash_pair_union_t *q;

  q = get_indirect (v, pi, key);
  if (q)
    {
      *found_key = 1;
      return q;
    }

  if (h->log2_pair_size == 0)
    vec_add2_mt_safe (pi->pairs, new_pair, 1);
  else
    {
      uword len, new_len, log2_bytes;

      len = indirect_pair_get_len (pi);
      log2_bytes = indirect_pair_get_log2_bytes (pi);

      new_len = len + 1;
      if (new_len * hash_pair_bytes (h) > (1ULL << log2_bytes))
	{
	  pi->pairs =
	    clib_mem_realloc_mt_safe (pi->pairs, 1ULL << (log2_bytes + 1));
	  log2_bytes++;
	}

      indirect_pair_set (pi, log2_bytes, new_len);
      new_pair = pi->pairs + (len << h->log2_pair_size);
    }
  new_pair->key = key;
  init_pair (h, new_pair);
  *found_key = 0;
  return (hash_pair_union_t *) new_pair;
}

__clib_export clib_error_t *
hash_validate_mt_safe (void *v)
{
  hash_t *h = hash_header (v);
  uword i, j;
  uword *keys = 0;
  clib_error_t *error = 0;

#define CHECK(x)                                                              \
  if ((error = ERROR_ASSERT (x)))                                             \
    goto done;

  for (i = 0; i < hash_capacity (v); i++)
    {
      hash_pair_union_t *pu = get_pair (v, i);

      if (hash_is_user (v, i))
	{
	  CHECK (pu->direct.key != 0);
	  vec_add1_mt_safe (keys, pu->direct.key);
	}
      else
	{
	  hash_pair_t *p;
	  hash_pair_indirect_t *pi = &pu->indirect;
	  uword n;

	  n = h->log2_pair_size > 0 ? indirect_pair_get_len (pi) :
				      vec_len (pi->pairs);

	  for (p = pi->pairs; n-- > 0; p = hash_forward1 (h, p))
	    {
	      /* Assert key uniqueness. */
	      for (j = 0; j < vec_len (keys); j++)
		CHECK (keys[j] != p->key);
	      vec_add1_mt_safe (keys, p->key);
	    }
	}
    }

  CHECK (vec_len (keys) == h->elts);

  vec_free (keys);
done:
  return error;
}

__clib_export hash_pair_t *
lookup_mt_safe (void *v, uword key, enum lookup_opcode op, void *new_value,
		void *old_value)
{
  hash_t *h = hash_header (v);
  hash_pair_union_t *p = 0;
  uword found_key = 0;
  uword value_bytes;
  uword i;

  if (!v)
    return 0;

  i = key_sum (h, key) & (_vec_len (v) - 1);
  p = get_pair (v, i);
  value_bytes = hash_value_bytes (h);

  if (hash_is_user (v, i))
    {
      found_key = key_equal (h, p->direct.key, key);
      if (found_key)
	{
	  if (op == UNSET)
	    {
	      set_is_user (v, i, 0);
	      if (old_value && value_bytes)
		clib_memcpy_fast (old_value, p->direct.value, value_bytes);
	      zero_pair (h, &p->direct);
	    }
	}
      else
	{
	  if (op == SET)
	    p = set_indirect_is_user (v, i, p, key);
	  else
	    p = 0;
	}
    }
  else
    {
      hash_pair_indirect_t *pi = &p->indirect;

      if (op == SET)
	{
	  if (!pi->pairs)
	    {
	      p->direct.key = key;
	      set_is_user (v, i, 1);
	    }
	  else
	    p = set_indirect_mt_safe (v, pi, key, &found_key);
	}
      else
	{
	  p = get_indirect (v, pi, key);
	  found_key = p != 0;
	  if (found_key && op == UNSET)
	    {
	      if (old_value && value_bytes)
		clib_memcpy_fast (old_value, &p->direct.value, value_bytes);

	      unset_indirect (v, i, &p->direct);

	      /* Nullify p (since it's just been deleted).
		 Otherwise we might be tempted to play with it. */
	      p = 0;
	    }
	}
    }

  if (op == SET && p != 0 && value_bytes)
    {
      /* Save away old value for caller. */
      if (old_value && found_key)
	clib_memcpy_fast (old_value, &p->direct.value, value_bytes);
      clib_memcpy_fast (&p->direct.value, new_value, value_bytes);
    }

  if (op == SET)
    h->elts += !found_key;
  if (op == UNSET)
    h->elts -= found_key;

  return &p->direct;
}

/* hash_get functions are already safe. */

__clib_export void *
_hash_set3_mt_safe (void *v, uword key, void *value, void *old_value)
{
  hash_t *h;

  if (!v)
    v = hash_create (0, sizeof (uword));

  h = hash_header (v);
  (void) lookup_mt_safe (v, key, SET, value, old_value);

  if (!(h->flags & HASH_FLAG_NO_AUTO_GROW))
    {
      /* Resize when 3/4 full. */
      if (4 * (h->elts + 1) > 3 * vec_len (v))
	v = hash_resize_mt_safe (v, 2 * vec_len (v));
    }

  return v;
}

__clib_export void
hash_set_mem_alloc_mt_safe (uword **h, const void *key, uword v)
{
  int objsize = __builtin_object_size (key, 0);
  size_t ksz = hash_header (*h)->user;
  void *copy;
  if (objsize > 0)
    {
      ASSERT (objsize == ksz);
      copy = clib_mem_alloc (objsize);
      clib_memcpy_fast (copy, key, objsize);
    }
  else
    {
      copy = clib_mem_alloc (ksz);
      clib_memcpy_fast (copy, key, ksz);
    }
  hash_set_mem_mt_safe (*h, copy, v);
}

__clib_export void *
_hash_unset_mt_safe (void *v, uword key, void *old_value)
{
  hash_t *h;

  if (!v)
    return v;

  (void) lookup_mt_safe (v, key, UNSET, 0, old_value);

  h = hash_header (v);
  if (!(h->flags & HASH_FLAG_NO_AUTO_SHRINK))
    {
      /* Resize when 1/4 full. */
      if (h->elts > 32 && 4 * (h->elts + 1) < vec_len (v))
	v = hash_resize_mt_safe (v, vec_len (v) / 2);
    }

  return v;
}

__clib_export void
hash_unset_mem_free_mt_safe (uword **h, const void *key)
{
  hash_pair_t *hp = hash_get_pair_mem (*h, key);
  if (PREDICT_TRUE (hp != NULL))
    {
      void *_k = uword_to_pointer (hp->key, void *);
      hash_unset_mem_mt_safe (*h, _k);
      clib_mem_free_mt_safe (_k);
    }
}

__clib_export void *
_hash_free_mt_safe (void *v)
{
  hash_t *h = hash_header (v);
  hash_pair_union_t *p;
  uword i;

  if (!v)
    return v;

  /* We zero all freed memory in case user would be tempted to use it. */
  for (i = 0; i < hash_capacity (v); i++)
    {
      if (hash_is_user (v, i))
	continue;
      p = get_pair (v, i);
      if (h->log2_pair_size == 0)
	vec_free_mt_safe (p->indirect.pairs);
      else if (p->indirect.pairs)
	clib_mem_free_mt_safe (p->indirect.pairs);
    }

  vec_free_mt_safe (h->is_user);
  vec_free_header_mt_safe (h);

  return 0;
}

__clib_export void *
hash_resize_internal_mt_safe (void *old, uword new_size, uword free_old)
{
  void *new;
  hash_pair_t *p;

  new = 0;
  if (new_size > 0)
    {
      hash_t *h = old ? hash_header (old) : 0;
      new = _hash_create (new_size, h);
      hash_foreach_pair (
	p, old, { new = _hash_set3_mt_safe (new, p->key, &p->value[0], 0); });
    }

  if (free_old)
    hash_free_mt_safe (old);
  return new;
}

__clib_export void *
hash_resize_mt_safe (void *old, uword new_size)
{
  return hash_resize_internal_mt_safe (old, new_size, 1);
}

/* Safe version of hash_dup is hardly needed. */

/* clib_bitmap_random does not seem to need thread safety. */

/* clib_bitmap_set_no_check is intentionally unsafe. */

__clib_export uword *
clib_bitmap_set_region_mt_safe (uword *bitmap, uword i, uword value,
				uword n_bits)
{
  uword a0, a1, b0, b1;
  uword i_end, mask;

  a0 = i / BITS (bitmap[0]);
  a1 = i % BITS (bitmap[0]);

  i_end = i + n_bits - 1;
  b0 = i_end / BITS (bitmap[0]);
  b1 = i_end % BITS (bitmap[0]);

  clib_bitmap_vec_validate_mt_safe (bitmap, b0);

  /* First word. */
  mask = n_bits < BITS (bitmap[0]) ? pow2_mask (n_bits) : ~0;
  mask <<= a1;

  if (value)
    bitmap[a0] |= mask;
  else
    bitmap[a0] &= ~mask;

  for (a0++; a0 < b0; a0++)
    bitmap[a0] = value ? ~0 : 0;

  if (a0 == b0)
    {
      mask = (uword) ~0 >> (BITS (bitmap[0]) - b1 - 1);
      if (value)
	bitmap[a0] |= mask;
      else
	bitmap[a0] &= ~mask;
    }

  return bitmap;
}

__clib_export uword *
clib_bitmap_set_multiple_mt_safe (uword *bitmap, uword i, uword value,
				  uword n_bits)
{
  uword i0, i1, l, t, m;

  ASSERT (n_bits <= BITS (value));

  i0 = i / BITS (bitmap[0]);
  i1 = i % BITS (bitmap[0]);

  /* Allocate bitmap. */
  clib_bitmap_vec_validate_mt_safe (bitmap,
				    (i + n_bits - 1) / BITS (bitmap[0]));
  l = vec_len (bitmap);

  m = ~0;
  if (n_bits < BITS (value))
    m = (((uword) 1 << n_bits) - 1);
  value &= m;

  /* Insert into first word. */
  t = bitmap[i0];
  t &= ~(m << i1);
  t |= value << i1;
  bitmap[i0] = t;

  /* Insert into second word. */
  i0++;
  if (i1 + n_bits > BITS (bitmap[0]) && i0 < l)
    {
      t = BITS (bitmap[0]) - i1;
      value >>= t;
      n_bits -= t;
      t = bitmap[i0];
      m = ((uword) 1 << n_bits) - 1;
      t &= ~m;
      t |= value;
      bitmap[i0] = t;
    }

  return bitmap;
}

__clib_export uword *
clib_bitmap_set_mt_safe (uword *ai, uword i, uword value)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  uword a;

  /* Check for writing a zero to beyond end of bitmap. */
  if (value == 0 && i0 >= vec_len (ai))
    return ai; /* Implied trailing zeros. */

  clib_bitmap_vec_validate_mt_safe (ai, i0);

  a = ai[i0];
  a &= ~((uword) 1 << i1);
  a |= ((uword) (value != 0)) << i1;
  ai[i0] = a;

  /* If bits have been cleared, test for zero. */
  if (a == 0)
    ai = _clib_bitmap_remove_trailing_zeros (ai);

  return ai;
}

__clib_export void
clib_bitmap_copy_mt_safe (clib_bitmap_t **dst, const clib_bitmap_t *src)
{
  if (vec_len (src))
    {
      clib_bitmap_vec_validate_mt_safe (*dst, vec_len (src) - 1);
      vec_copy (*dst, src);
    }
  else
    {
      vec_reset_length (*dst);
    }
}

/* _pool_init_fixed is inherently safe. */

__clib_export void
_pool_get_mt_safe (void **pp, void **ep, uword align, int zero, uword elt_sz)
{
  uword len = 0;
  void *p = pp[0];
  void *e;
  vec_attr_t va = { .hdr_sz = sizeof (pool_header_t),
		    .elt_sz = elt_sz,
		    .align = align };

  if (p)
    {
      pool_header_t *ph = pool_header (p);
      uword n_free = vec_len (ph->free_indices);

      if (n_free)
	{
	  uword index = ph->free_indices[n_free - 1];
	  e = p + index * elt_sz;
	  ph->free_bitmap =
	    clib_bitmap_andnoti_notrim_mt_safe (ph->free_bitmap, index);
	  vec_set_len (ph->free_indices, n_free - 1);
	  clib_mem_unpoison (e, elt_sz);
	  goto done;
	}

      if (ph->max_elts)
	{
	  clib_warning ("can't expand fixed-size pool");
	  os_out_of_memory ();
	}
    }

  len = vec_len (p);

  /* Nothing on free list, make a new element and return it. */
  p = _vec_realloc_internal_mt_safe (p, len + 1, &va);
  e = p + len * elt_sz;

  _vec_update_pointer (pp, p);

done:
  ep[0] = e;
  if (zero)
    clib_memset_u8 (e, 0, elt_sz);
}

__clib_export void
_pool_alloc_mt_safe (void **pp, uword n_elts, uword align, void *heap,
		     uword elt_sz)
{
  pool_header_t *ph = pool_header (pp[0]);
  uword len = vec_len (pp[0]);
  const vec_attr_t va = { .hdr_sz = sizeof (pool_header_t),
			  .elt_sz = elt_sz,
			  .align = align,
			  .heap = heap };

  if (ph && ph->max_elts)
    {
      clib_warning ("Can't expand fixed-size pool");
      os_out_of_memory ();
    }

  pp[0] = _vec_resize_internal_mt_safe (pp[0], len + n_elts, &va);
  _vec_set_len (pp[0], len, elt_sz);
  clib_mem_poison (pp[0] + len * elt_sz, n_elts * elt_sz);

  ph = pool_header (pp[0]);
  vec_resize_mt_safe (ph->free_indices, n_elts);
  vec_dec_len (ph->free_indices, n_elts);
  clib_bitmap_validate_mt_safe (ph->free_bitmap, (len + n_elts) ?: 1);
}

__clib_export void
_pool_put_index_mt_safe (void *p, uword index, uword elt_sz)
{
  pool_header_t *ph = pool_header (p);

  ASSERT (index < ph->max_elts ? ph->max_elts : vec_len (p));
  ASSERT (!pool_is_free_index (p, index));

  /* Add element to free bitmap and to free list. */
  ph->free_bitmap = clib_bitmap_ori_notrim_mt_safe (ph->free_bitmap, index);

  /* Preallocated pool? */
  if (ph->max_elts)
    {
      u32 len = _vec_len (ph->free_indices);
      vec_set_len (ph->free_indices, len + 1);
      ph->free_indices[len] = index;
    }
  else
    vec_add1_mt_safe (ph->free_indices, index);

  clib_mem_poison (p + index * elt_sz, elt_sz);
}

__clib_export void
_pool_free_mt_safe (void **v)
{
  pool_header_t *p = pool_header (v[0]);
  if (!p)
    return;

  clib_bitmap_free_mt_safe (p->free_bitmap);

  vec_free_mt_safe (p->free_indices);
  _vec_free_mt_safe (v);
}
