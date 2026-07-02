/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * vlib_pool_cache: per-thread caches of stable element indices.
 *
 * Backing storage is split into fixed-size chunks. A returned u32 ID encodes
 * the backing-chunk index in the high bits and the element slot in the low
 * log2_subpool_size bits. Published chunks never move, so pointers returned by
 * pool_cache_elt_at_index() remain stable when the cache grows. An element
 * pointer remains valid only until its index is passed to
 * pool_cache_put_index(); callers must synchronize pool_cache_put_index()
 * against concurrent readers.
 *
 * Free IDs live in exactly one of two intrusive linked lists: the
 * lock-protected global list, or the cache of one VPP thread. A get pops
 * locally and refills a full batch from the global list when empty. A put
 * pushes locally; once a thread cache exceeds twice the configured batch size
 * it flushes back to one batch. The backing chunks themselves have no thread
 * owner.
 *
 * Usage:
 *
 *   vlib_pool_cache_t flows;
 *   pool_cache_init_with_batch (&flows, "flow-instance", format_vnet_flow, 0,
 *                               CLIB_CACHE_LINE_BYTES, 128, vnet_flow_t);
 *   vnet_flow_t *f;
 *   u32 idx = pool_cache_get (&flows, f);
 *   pool_cache_put_index (&flows, idx);
 *   pool_cache_free (&flows);
 *
 * pool_cache_init() selects a transfer batch of 256.
 * pool_cache_init_with_batch() accepts an explicit batch size; zero also
 * selects the default. log2_subpool_size controls only backing-storage/index
 * geometry and is independent of the per-thread cache batch size.
 *
 * pool_cache_free() requires complete quiescence: no worker may still get,
 * put, look up, or format this cache while it is destroyed.
 */

#ifndef included_vlib_pool_cache_h
#define included_vlib_pool_cache_h

#include <vlib/vlib.h>
#include <vppinfra/atomics.h>
#include <vppinfra/cache.h>
#include <vppinfra/lock.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

#define VLIB_POOL_CACHE_DEFAULT_LOG2_SUBPOOL_SIZE   12
#define VLIB_POOL_CACHE_DEFAULT_BATCH_SIZE	    256
#define VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE 12
#define VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE	    (1U << VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE)
#define VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK	    (VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1)
#define VLIB_POOL_CACHE_INVALID_INDEX		    ((u32) ~0)
#define VLIB_POOL_CACHE_ALLOCATED_INDEX		    ((u32) (~0) - 1)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 refills;
  u64 flushes;
  u32 n_cached;
  u32 free_list;
} vlib_pool_cache_thread_t;

typedef struct
{
  /* Type-erased stable payload chunks; element access returns void pointers. */
  u8 *pool;
  u32 *next_free;
} vlib_pool_cache_subpool_t;

typedef struct vlib_pool_cache_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (hot);
  /* Indexed by vlib_get_thread_index(); only that thread mutates its cache. */
  vlib_pool_cache_thread_t *per_thread;
  /* Stable chunked metadata table, parallel to the payload table. */
  vlib_pool_cache_subpool_t **subpool_chunks;

  uword elt_size;
  u32 log2_subpool_size;
  u32 subpool_size;
  u32 subpool_mask;
  u32 max_subpools;
  u32 max_subpool_chunks;
  u32 n_subpools;
  u32 batch_size;
  u32 align;

  CLIB_CACHE_LINE_ALIGN_MARK (slow);
  /* Protects the global free-index list and backing-chunk growth. */
  clib_spinlock_t lock;
  u32 global_free_list;
  /* Writers hold lock; atomic publication permits lock-free diagnostics. */
  u32 n_global_free;
  /* Slow-path observability. */
  u64 global_lock_acquisitions;
  u64 growths;

  char *name;
  format_function_t *format_element;
  struct vlib_pool_cache_t_ *next_instance;
} vlib_pool_cache_t;

typedef struct
{
  vlib_pool_cache_t *instances;
} vlib_pool_cache_main_t;

extern vlib_pool_cache_main_t pool_cache_main;

void _pool_cache_init_with_batch (vlib_pool_cache_t *c, char *name,
				  format_function_t *format_element, u32 log2_subpool_size,
				  u32 align, u32 batch_size, uword elt_size, uword elt_align);
#define pool_cache_init_with_batch(C, N, F, L, A, B, T)                                            \
  _pool_cache_init_with_batch ((C), (N), (F), (L), (A), (B), sizeof (T), __alignof__ (T))
#define pool_cache_init(C, N, F, L, A, T)                                                          \
  _pool_cache_init_with_batch ((C), (N), (F), (L), (A), 0, sizeof (T), __alignof__ (T))
void pool_cache_free (vlib_pool_cache_t *c);
void _pool_cache_refill (vlib_pool_cache_t *c, vlib_pool_cache_thread_t *pt);
void _pool_cache_flush (vlib_pool_cache_t *c, vlib_pool_cache_thread_t *pt, u32 n_cached);
u8 *pool_cache_format_element (u8 *s, vlib_pool_cache_t *c, u32 index);
u8 *format_vlib_pool_cache (u8 *s, va_list *args);

static_always_inline u32
_pool_cache_encode_index (const vlib_pool_cache_t *c, u32 subpool_index, u32 elt_index)
{
  ASSERT (subpool_index < c->max_subpools);
  ASSERT (elt_index < c->subpool_size);
  return (u32) (((u64) subpool_index << c->log2_subpool_size) | elt_index);
}

#define _pool_cache_subpool_chunk_index(P)                                                         \
  ((u32) (P) >> VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE)
#define _pool_cache_subpool_chunk_subpool_index(P)                                                 \
  ((u32) (P) & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK)
#define _pool_cache_subpool_index(C, I) ((u32) (I) >> (C)->log2_subpool_size)
#define _pool_cache_elt_index(C, I)	((u32) (I) & (C)->subpool_mask)

static_always_inline vlib_pool_cache_subpool_t *
_pool_cache_subpool_at (vlib_pool_cache_t *c, u32 pidx)
{
  vlib_pool_cache_subpool_t *chunk;

  ASSERT (pidx < clib_atomic_load_acq_n (&c->n_subpools));
  chunk = c->subpool_chunks[_pool_cache_subpool_chunk_index (pidx)];
  ASSERT (chunk != 0);
  return vec_elt_at_index (chunk, _pool_cache_subpool_chunk_subpool_index (pidx));
}

static_always_inline u32
_pool_cache_next_free (vlib_pool_cache_t *c, u32 index)
{
  u32 pidx = _pool_cache_subpool_index (c, index);
  u32 eidx = _pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, pidx);

  ASSERT (index != VLIB_POOL_CACHE_INVALID_INDEX);
  return clib_atomic_load_relax_n (vec_elt_at_index (sp->next_free, eidx));
}

static_always_inline void
_pool_cache_set_next_free (vlib_pool_cache_t *c, u32 index, u32 next)
{
  u32 pidx = _pool_cache_subpool_index (c, index);
  u32 eidx = _pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, pidx);

  ASSERT (index != VLIB_POOL_CACHE_INVALID_INDEX);
  clib_atomic_store_relax_n (vec_elt_at_index (sp->next_free, eidx), next);
}

static_always_inline void *
_pool_cache_elt_at_indices (vlib_pool_cache_t *c, u32 pidx, u32 eidx)
{
  vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, pidx);
  ASSERT (sp->pool != 0);
  return sp->pool + (uword) eidx * c->elt_size;
}

static_always_inline void *
pool_cache_elt_at_index (vlib_pool_cache_t *c, u32 index)
{
  u32 pidx = _pool_cache_subpool_index (c, index);
  u32 eidx = _pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, pidx);
  ASSERT (clib_atomic_load_acq_n (vec_elt_at_index (sp->next_free, eidx)) ==
	  VLIB_POOL_CACHE_ALLOCATED_INDEX);
  return _pool_cache_elt_at_indices (c, pidx, eidx);
}

static_always_inline int
pool_cache_is_free_index (vlib_pool_cache_t *c, u32 index)
{
  u32 pidx = _pool_cache_subpool_index (c, index);
  u32 eidx = _pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_t *sp;

  if (PREDICT_FALSE (index == VLIB_POOL_CACHE_INVALID_INDEX ||
		     pidx >= clib_atomic_load_acq_n (&c->n_subpools)))
    return 1;
  sp = _pool_cache_subpool_at (c, pidx);
  return clib_atomic_load_relax_n (vec_elt_at_index (sp->next_free, eidx)) !=
	 VLIB_POOL_CACHE_ALLOCATED_INDEX;
}

static_always_inline u32
_pool_cache_get (vlib_pool_cache_t *c, void **elt)
{
  u32 ti = vlib_get_thread_index ();
  vlib_pool_cache_thread_t *pt = vec_elt_at_index (c->per_thread, ti);
  vlib_pool_cache_subpool_t *sp;
  void *e;
  u32 n = clib_atomic_load_relax_n (&pt->n_cached);
  u32 index, pidx, eidx;

  if (PREDICT_FALSE (n == 0))
    {
      /* Refill is an out-of-line locked slow path. */
      _pool_cache_refill (c, pt);
      n = c->batch_size;
    }

  /* Pop the caller's private list and make the payload accessible. */
  index = pt->free_list;
  ASSERT (index != VLIB_POOL_CACHE_INVALID_INDEX);
  pidx = _pool_cache_subpool_index (c, index);
  eidx = _pool_cache_elt_index (c, index);
  sp = _pool_cache_subpool_at (c, pidx);
  pt->free_list = clib_atomic_load_relax_n (vec_elt_at_index (sp->next_free, eidx));
  clib_atomic_store_relax_n (&pt->n_cached, --n);
  clib_atomic_store_relax_n (vec_elt_at_index (sp->next_free, eidx),
			     VLIB_POOL_CACHE_ALLOCATED_INDEX);
  e = _pool_cache_elt_at_indices (c, pidx, eidx);
  if (elt)
    *elt = e;
  clib_mem_unpoison (e, c->elt_size);
  return index;
}

#define pool_cache_get(C, E)	_pool_cache_get (C, (void **) &(E))
#define pool_cache_get_index(C) _pool_cache_get (C, 0)

static_always_inline void
_pool_cache_publish_free (vlib_pool_cache_t *c, u32 index, u32 pidx, u32 eidx,
			  vlib_pool_cache_subpool_t *sp)
{
  u32 ti = vlib_get_thread_index ();
  vlib_pool_cache_thread_t *pt = vec_elt_at_index (c->per_thread, ti);
  u32 n = clib_atomic_load_relax_n (&pt->n_cached);

  /* Poison before publishing the token to the caller's private list. */
  clib_mem_poison (_pool_cache_elt_at_indices (c, pidx, eidx), c->elt_size);
  clib_atomic_store_relax_n (vec_elt_at_index (sp->next_free, eidx), pt->free_list);
  pt->free_list = index;
  clib_atomic_store_relax_n (&pt->n_cached, ++n);
  /* Flush is an out-of-line locked slow path. */
  if (PREDICT_FALSE (n > 2 * c->batch_size))
    _pool_cache_flush (c, pt, n);
}

static_always_inline void
pool_cache_put_index (vlib_pool_cache_t *c, u32 index)
{
  u32 pidx = _pool_cache_subpool_index (c, index);
  u32 eidx = _pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_t *sp;
  u32 expected = VLIB_POOL_CACHE_ALLOCATED_INDEX;

  if (PREDICT_FALSE (index == VLIB_POOL_CACHE_INVALID_INDEX ||
		     pidx >= clib_atomic_load_acq_n (&c->n_subpools)))
    {
      ASSERT (0);
      return;
    }
  sp = _pool_cache_subpool_at (c, pidx);
  /* Claim the sole release; this rejects double-free - debug only. */
  ASSERT (clib_atomic_cmp_and_swap_acq_relax_n (vec_elt_at_index (sp->next_free, eidx), &expected,
						VLIB_POOL_CACHE_INVALID_INDEX, 0));
  if (!CLIB_DEBUG)
    clib_atomic_store_relax_n (vec_elt_at_index (sp->next_free, eidx),
			       VLIB_POOL_CACHE_INVALID_INDEX);
  _pool_cache_publish_free (c, index, pidx, eidx, sp);
}

#endif /* included_vlib_pool_cache_h */
