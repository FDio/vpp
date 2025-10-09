/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __vlib_delayed_free_h__
#define __vlib_delayed_free_h__

#include <vppinfra/bitmap.h>
#include <vppinfra/dlmalloc.h>
#include <vppinfra/fifo.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

typedef enum
{
  CLIB_DELAYED_FREE_DLMALLOC,
} clib_delayed_free_type_t;

typedef struct
{
  void *ptr_to_free;
  clib_mem_heap_t *heap;
  clib_delayed_free_type_t type;
} clib_delayed_free_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** FIFO of free lists */
  clib_delayed_free_entry_t **frees_by_epoch_fifo;
  /** Last seen epoch for each worker thread */
  u64 *worker_last_seen_epochs;
  /** Last safe epoch across all workers, to avoid redundant checks */
  u64 last_known_safe_epoch;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /** The current epoch - written by main thread, read by workers */
  u64 current_epoch;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
} clib_delayed_free_main_t;

/* FIXME: mt_safe or mp_safe? Or something else? */

void clib_mem_heap_free_mt_safe (void *heap, void *p);
/* Implemented in .c file as the implementation needs main.h which needs this.
 */

void clib_mem_free_mt_safe (void *p);

#define vec_free_header_mt_safe(h) clib_mem_free_mt_safe (h)

/* TODO: Deduplicate with vppinfra/mem_dlmalloc.c if without perf impact. */

void *clib_mem_heap_realloc_aligned_mt_safe (void *heap, void *p,
					     uword new_size, uword align);

void *clib_mem_heap_realloc_mt_safe (void *heap, void *p, uword new_size);

void *clib_mem_realloc_aligned_mt_safe (void *p, uword new_size, uword align);

void *clib_mem_realloc_mt_safe (void *p, uword new_size);

void *_vec_realloc_internal_mt_safe (void *v, uword n_elts,
				     const vec_attr_t *const attr);

void *_vec_resize_internal_mt_safe (void *v, uword n_elts,
				    const vec_attr_t *const attr);

/* The following function move elements in inherently unsafe way:
 * _ ver prepend, _vec_insert_elts, _vec insert,
 */

void _vec_resize_mt_safe (void **vp, uword n_add, uword hdr_sz, uword align,
			  uword elt_sz);

#define vec_resize_ha_mt_safe(V, N, H, A)                                     \
  _vec_resize_mt_safe ((void **) &(V), N, H, _vec_align (V, A),               \
		       _vec_elt_sz (V))

#define vec_resize_aligned_mt_safe(V, N, A) vec_resize_ha_mt_safe (V, N, 0, A)

#define vec_resize_mt_safe(V, N) vec_resize_ha_mt_safe (V, N, 0, 0)

void _vec_validate_mt_safe (void **vp, uword index, uword header_size,
			    uword align, void *heap, uword elt_sz);

#define vec_validate_hap_mt_safe(V, I, H, A, P)                               \
  _vec_validate_mt_safe ((void **) &(V), I, H, _vec_align (V, A), 0,          \
			 _vec_elt_sz (V))

#define vec_validate_aligned_mt_safe(V, I, A)                                 \
  vec_validate_hap_mt_safe (V, I, 0, A, 0)

#define vec_validate_heap_mt_safe(V, I, P)                                    \
  vec_validate_hap_mt_safe (V, I, 0, 0, P)

#define vec_validate_mt_safe(V, I) vec_validate_hap_mt_safe (V, I, 0, 0, 0)

#define vec_validate_init_empty_ha_mt_safe(V, I, INIT, H, A)                  \
  do                                                                          \
    {                                                                         \
      word _v (i) = (I);                                                      \
      word _v (l) = vec_len (V);                                              \
      if (_v (i) >= _v (l))                                                   \
	{                                                                     \
	  vec_resize_ha_mt_safe (V, 1 + (_v (i) - _v (l)), H, A);             \
	  while (_v (l) <= _v (i))                                            \
	    {                                                                 \
	      (V)[_v (l)] = (INIT);                                           \
	      _v (l)++;                                                       \
	    }                                                                 \
	}                                                                     \
    }                                                                         \
  while (0)

#define vec_validate_init_empty_aligned_mt_safe(V, I, INIT, A)                \
  vec_validate_init_empty_ha_mt_safe (V, I, INIT, 0, A)

#define vec_validate_init_empty_mt_safe(V, I, INIT)                           \
  vec_validate_init_empty_ha_mt_safe (V, I, INIT, 0, 0)

#define vec_alloc_ha_mt_safe(V, N, H, A)                                      \
  do                                                                          \
    {                                                                         \
      uword _v (l) = vec_len (V);                                             \
      vec_resize_ha_mt_safe (V, N, H, A);                                     \
      vec_set_len (V, _v (l));                                                \
    }                                                                         \
  while (0)

#define vec_alloc_aligned_mt_safe(V, N, A) vec_alloc_ha_mt_safe (V, N, 0, A)

#define vec_alloc_mt_safe(V, N) vec_alloc_ha_mt_safe (V, N, 0, 0)

void _vec_append_mt_safe (void **v1p, void *v2, uword v1_elt_sz,
			  uword v2_elt_sz, uword align);

#define vec_append_aligned_mt_safe(v1, v2, align)                             \
  _vec_append_mt_safe ((void **) &(v1), (void *) (v2), _vec_elt_sz (v1),      \
		       _vec_elt_sz (v2), _vec_align (v1, align))

#define vec_append_mt_safe(v1, v2) vec_append_aligned_mt_safe (v1, v2, 0)

void _vec_add_mt_safe (void **vp, void *e, word n_add, uword hdr_sz,
		       uword align, uword elt_sz);

#define vec_add_ha_mt_safe(V, E, N, H, A)                                     \
  _vec_add_mt_safe ((void **) &(V), (void *) (E), N, H, _vec_align (V, A),    \
		    _vec_elt_sz (V))

#define vec_add_aligned_mt_safe(V, E, N, A) vec_add_ha_mt_safe (V, E, N, 0, A)

#define vec_add_mt_safe(V, E, N) vec_add_ha_mt_safe (V, E, N, 0, 0)

void *_vec_add1_mt_safe (void **vp, uword hdr_sz, uword align, uword elt_sz);

#define vec_add1_ha_mt_safe(V, E, H, A)                                       \
  ((__typeof__ ((V)[0]) *) _vec_add1_mt_safe (                                \
    (void **) &(V), H, _vec_align (V, A), _vec_elt_sz (V)))[0] = (E)

#define vec_add1_aligned_mt_safe(V, E, A) vec_add1_ha_mt_safe (V, E, 0, A)
#define vec_add1_mt_safe(V, E)		  vec_add1_ha_mt_safe (V, E, 0, 0)

void _vec_add2_mt_safe (void **vp, void **pp, uword n_add, uword hdr_sz,
			uword align, uword elt_sz);

#define vec_add2_ha_mt_safe(V, P, N, H, A)                                    \
  _vec_add2_mt_safe ((void **) &(V), (void **) &(P), N, H, _vec_align (V, A), \
		     _vec_elt_sz (V))

#define vec_add2_aligned_mt_safe(V, P, N, A)                                  \
  vec_add2_ha_mt_safe (V, P, N, 0, A)
#define vec_add2_mt_safe(V, P, N) vec_add2_ha_mt_safe (V, P, N, 0, 0)

void _vec_free_mt_safe (void **vp);

#define vec_free_mt_safe(V) _vec_free_mt_safe ((void **) &(V))

/* TODO: Divide into multiple files depending on which vppinfra file is
 * mirrored? */

/* _hash_create is inherently safe */
/* TODO: format_hash? */

/* Declared to enable recursion. */
void *hash_resize_mt_safe (void *old, uword new_size);

hash_pair_union_t *set_indirect_mt_safe (void *v, hash_pair_indirect_t *pi,
					 uword key, uword *found_key);

clib_error_t *hash_validate_mt_safe (void *v);

hash_pair_t *lookup_mt_safe (void *v, uword key, enum lookup_opcode op,
			     void *new_value, void *old_value);

/* hash_get functions are already safe. */

void *_hash_set3_mt_safe (void *v, uword key, void *value, void *old_value);

#define hash_set3_mt_safe(h, key, value, old_value)                           \
  ({                                                                          \
    uword _v = (uword) (value);                                               \
    (h) = _hash_set3_mt_safe ((h), (uword) (key), (void *) &_v, (old_value)); \
  })

#define hash_set_mt_safe(h, key, value) hash_set3_mt_safe (h, key, value, 0)
#define hash_set1_mt_safe(h, key)                                             \
  (h) = _hash_set3_mt_safe (h, (uword) (key), 0, 0)
#define hash_set_mem_mt_safe(h, key, value)                                   \
  hash_set3_mt_safe (h, pointer_to_uword (key), (value), 0)
#define hash_set1_mem_mt_safe(h, key)                                         \
  hash_set3_mt_safe ((h), pointer_to_uword (key), 0, 0)

void hash_set_mem_alloc_mt_safe (uword **h, const void *key, uword v);

void *_hash_unset_mt_safe (void *v, uword key, void *old_value);

#define hash_unset3_mt_safe(h, key, old_value)                                \
  ((h) = _hash_unset_mt_safe ((h), (uword) (key), (void *) (old_value)))
#define hash_unset_mem_mt_safe(h, key)                                        \
  ((h) = _hash_unset_mt_safe ((h), pointer_to_uword (key), 0))
#define hash_unset_mt_safe(h, key)                                            \
  ((h) = _hash_unset_mt_safe ((h), (uword) (key), 0))

void hash_unset_mem_free_mt_safe (uword **h, const void *key);

void *_hash_free_mt_safe (void *v);

#define hash_free_mt_safe(h) (h) = _hash_free_mt_safe ((h))

void *hash_resize_internal_mt_safe (void *old, uword new_size, uword free_old);

void *hash_resize_mt_safe (void *old, uword new_size);

/* Safe version of hash_dup is hardly needed. */

/* clib_bitmap_random does not seem to need thread safety. */

#define clib_bitmap_vec_validate_mt_safe(v, i)                                \
  vec_validate_aligned_mt_safe ((v), (i), sizeof (uword))

#define clib_bitmap_validate_mt_safe(v, n_bits)                               \
  clib_bitmap_vec_validate_mt_safe ((v), ((n_bits) -1) / BITS (uword))

#define _(name, body)                                                         \
  always_inline uword *clib_bitmap_##name##_notrim_mt_safe (uword *ai,        \
							    uword i)          \
  {                                                                           \
    uword i0 = i / BITS (ai[0]);                                              \
    uword i1 = i % BITS (ai[0]);                                              \
    uword a, b;                                                               \
    clib_bitmap_vec_validate_mt_safe (ai, i0);                                \
    a = ai[i0];                                                               \
    b = (uword) 1 << i1;                                                      \
    do                                                                        \
      {                                                                       \
	body;                                                                 \
      }                                                                       \
    while (0);                                                                \
    ai[i0] = a;                                                               \
    return ai;                                                                \
  }

_ (andi, a = a & b)
_ (andnoti, a = a & ~b)
_ (ori, a = a | b)
_ (xori, a = a ^ b)
#undef _

#define _(name, body, check_zero)                                             \
  always_inline uword *clib_bitmap_##name##_mt_safe (uword *ai, uword i)      \
  {                                                                           \
    uword i0 = i / BITS (ai[0]);                                              \
    uword i1 = i % BITS (ai[0]);                                              \
    uword a, b;                                                               \
    clib_bitmap_vec_validate_mt_safe (ai, i0);                                \
    a = ai[i0];                                                               \
    b = (uword) 1 << i1;                                                      \
    do                                                                        \
      {                                                                       \
	body;                                                                 \
      }                                                                       \
    while (0);                                                                \
    ai[i0] = a;                                                               \
    if (check_zero && a == 0)                                                 \
      ai = _clib_bitmap_remove_trailing_zeros (ai);                           \
    return ai;                                                                \
  }

/* ALU functions immediate: */
_ (andi, a = a & b, 1)
_ (andnoti, a = a & ~b, 1)
_ (ori, a = a | b, 0)
_ (xori, a = a ^ b, 1)
#undef _

#define _(name, body, check_zero)                                             \
  always_inline uword *clib_bitmap_##name##_mt_safe (uword *ai, uword *bi)    \
  {                                                                           \
    uword i, a, b, bi_len, n_trailing_zeros;                                  \
                                                                              \
    n_trailing_zeros = 0;                                                     \
    bi_len = vec_len (bi);                                                    \
    if (bi_len > 0)                                                           \
      clib_bitmap_vec_validate_mt_safe (ai, bi_len - 1);                      \
    for (i = 0; i < vec_len (ai); i++)                                        \
      {                                                                       \
	a = ai[i];                                                            \
	b = i < bi_len ? bi[i] : 0;                                           \
	do                                                                    \
	  {                                                                   \
	    body;                                                             \
	  }                                                                   \
	while (0);                                                            \
	ai[i] = a;                                                            \
	if (check_zero)                                                       \
	  n_trailing_zeros = a ? 0 : (n_trailing_zeros + 1);                  \
      }                                                                       \
    if (check_zero)                                                           \
      vec_dec_len (ai, n_trailing_zeros);                                     \
    return ai;                                                                \
  }

/* ALU functions: */
_ (and, a = a & b, 1)
_ (andnot, a = a & ~b, 1)
_ (or, a = a | b, 0)
_ (xor, a = a ^ b, 1)
#undef _

/* clib_bitmap_set_no_check is intentionally unsafe. */

uword *clib_bitmap_set_region_mt_safe (uword *bitmap, uword i, uword value,
				       uword n_bits);

uword *clib_bitmap_set_multiple_mt_safe (uword *bitmap, uword i, uword value,
					 uword n_bits);

uword *clib_bitmap_set_mt_safe (uword *ai, uword i, uword value);

void clib_bitmap_copy_mt_safe (clib_bitmap_t **dst, const clib_bitmap_t *src);

#define clib_bitmap_free_mt_safe(v) vec_free_mt_safe (v)

/* _pool_init_fixed is inherently safe. */

void _pool_get_mt_safe (void **pp, void **ep, uword align, int zero,
			uword elt_sz);

#define _pool_get_aligned_internal_mt_safe(P, E, A, Z)                        \
  _pool_get_mt_safe ((void **) &(P), (void **) &(E), _vec_align (P, A), Z,    \
		     _vec_elt_sz (P))

#define pool_get_aligned_mt_safe(P, E, A)                                     \
  _pool_get_aligned_internal_mt_safe (P, E, A, 0)
#define pool_get_aligned_zero_mt_safe(P, E, A)                                \
  _pool_get_aligned_internal_mt_safe (P, E, A, 1)
#define pool_get_mt_safe(P, E)	    pool_get_aligned_mt_safe (P, E, 0)
#define pool_get_zero_mt_safe(P, E) pool_get_aligned_zero_mt_safe (P, E, 0)

void _pool_alloc_mt_safe (void **pp, uword n_elts, uword align, void *heap,
			  uword elt_sz);

void _pool_put_index_mt_safe (void *p, uword index, uword elt_sz);

#define pool_put_index_mt_safe(P, I)                                          \
  _pool_put_index_mt_safe ((void *) (P), I, _vec_elt_sz (P))
#define pool_put_mt_safe(P, E) pool_put_index_mt_safe (P, (E) - (P))

#define pool_flush_mt_safe(VAR, POOL, BODY)                                   \
  {                                                                           \
    uword *_pool_var (ii), *_pool_var (dv) = NULL;                            \
                                                                              \
    pool_foreach ((VAR), (POOL))                                              \
      {                                                                       \
	vec_add1 (_pool_var (dv), (VAR) - (POOL));                            \
      }                                                                       \
    vec_foreach (_pool_var (ii), _pool_var (dv))                              \
      {                                                                       \
	(VAR) = pool_elt_at_index ((POOL), *_pool_var (ii));                  \
	do                                                                    \
	  {                                                                   \
	    BODY;                                                             \
	  }                                                                   \
	while (0);                                                            \
	pool_put_mt_safe ((POOL), (VAR));                                     \
      }                                                                       \
    vec_free (_pool_var (dv));                                                \
  }

void _pool_free_mt_safe (void **v);

#define pool_free_mt_safe(p) _pool_free_mt_safe ((void **) &(p))

/* TODO: Offer ml_safe functions for rb_tree and clib_llist. */

/* heap.h and heap.c do not seem friendly for thread-safe usage. */
/* heap is used by mhash, so */
/* TODO: mhash is used maybe without worker readers? Investigate. */

/* TODO: Support also sparse_vec? */
/* TODO: timing_wheel? */
/* TODO: pmalloc? */
/* TODO: valloc.c? */

/* TODO: fifo? */
/* TODO: bihash!! */

#endif /* __vlib_delayed_free_h__ */
