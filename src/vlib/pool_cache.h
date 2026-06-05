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
 * elt_at_index remain stable when the cache grows.
 *
 * Free IDs live in exactly one of two intrusive linked lists: the
 * lock-protected global list, or the cache of one VPP thread. Allocation pops
 * locally and refills a full batch from the global list when empty. Freeing
 * pushes locally; once a thread cache exceeds twice the configured batch size
 * it flushes back to one batch. The backing chunks themselves have no thread
 * owner.
 *
 * Usage:
 *
 *   VLIB_POOL_CACHE_DEFINE (flow, vnet_flow_t) = {
 *     .name = "flow",
 *   };
 *
 *   flow_pool_cache_t flows;
 *   flow_pool_cache_init_with_batch (&flows, "flow-instance", 0,
 *                                    CLIB_CACHE_LINE_BYTES, 128);
 *   u32 idx = flow_pool_cache_alloc (&flows);
 *   vnet_flow_t *f = flow_pool_cache_elt_at_index (&flows, idx);
 *   flow_pool_cache_free (&flows, idx);
 *
 * NAME_pool_cache_init() retains the original four-argument API and selects a
 * transfer batch of 256. NAME_pool_cache_init_with_batch() accepts a fifth
 * batch-size argument; zero also selects the default. log2_subpool_size
 * controls only backing-storage/index geometry and is independent of the
 * per-thread cache batch size.
 *
 * free_resources() requires complete quiescence: no worker may still allocate,
 * free, look up, or format this cache while it is being destroyed.
 *
 * Readers which can outlive removal use get_if_live(). The owner first calls
 * retire(), completes its own grace-period mechanism, and then calls
 * reclaim(). Retirement prevents new live lookups but deliberately leaves the
 * element readable for readers which obtained its pointer before retirement.
 * The pool cache does not provide or infer the grace period.
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

typedef enum
{
  VLIB_POOL_CACHE_SLOT_FREE = 0,
  VLIB_POOL_CACHE_SLOT_ALLOCATED = 1,
  VLIB_POOL_CACHE_SLOT_RETIRED = 2,
} vlib_pool_cache_slot_state_t;

/*
 * A free-list token is owned by exactly one local cache or by the locked
 * global list, so allocation does not need an atomic read-modify-write to
 * claim the slot. Keep the CAS in debug builds to catch token duplication;
 * production builds avoid the locked instruction on the local hot path.
 */
static_always_inline int
vlib_pool_cache_mark_allocated (u8 *slot_state)
{
#ifdef CLIB_DEBUG
  u8 expected = VLIB_POOL_CACHE_SLOT_FREE;

  return clib_atomic_cmp_and_swap_acq_relax_n (slot_state, &expected,
					       VLIB_POOL_CACHE_SLOT_ALLOCATED, 0);
#else
  clib_atomic_store_relax_n (slot_state, VLIB_POOL_CACHE_SLOT_ALLOCATED);
  return 1;
#endif
}

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 free_list;
  u32 n_cached;
  u64 refills;
  u64 flushes;
} vlib_pool_cache_thread_t;

typedef struct
{
  u8 *slot_state;
  u32 *next_free;
} vlib_pool_cache_subpool_meta_t;

typedef struct vlib_pool_cache_registration_t_ vlib_pool_cache_registration_t;

typedef struct vlib_pool_cache_t_
{
  char *name;
  vlib_pool_cache_registration_t *registration;
  struct vlib_pool_cache_t_ *next_instance;

  /* Protects the global free-index list and backing-chunk growth. */
  clib_spinlock_t lock;
  u32 global_free_list;
  /* Writers hold lock; atomic publication permits lock-free diagnostics. */
  u32 n_global_free;

  /* Successful retire/reclaim transitions maintain this diagnostic gauge. */
  u64 n_retired;

  /* Indexed by vlib_get_thread_index(); only that thread mutates its cache. */
  vlib_pool_cache_thread_t *per_thread;

  /* Stable chunked metadata table, parallel to the generated typed table. */
  vlib_pool_cache_subpool_meta_t **subpool_meta_chunks;

  u32 log2_subpool_size;
  u32 subpool_size;
  u32 subpool_mask;
  u32 max_subpools;
  u32 max_subpool_chunks;
  u32 n_subpools;
  u32 batch_size;
  u32 align;

  /* Slow-path observability. */
  u64 global_lock_acquisitions;
  u64 growths;
} vlib_pool_cache_t;

struct vlib_pool_cache_registration_t_
{
  char *name;
  format_function_t *format_element;
  struct vlib_pool_cache_registration_t_ *next_registration;
};

typedef struct
{
  vlib_pool_cache_registration_t *registrations;
  vlib_pool_cache_t *instances;
} vlib_pool_cache_main_t;

extern vlib_pool_cache_main_t pool_cache_main;

void vlib_pool_cache_init_state (vlib_pool_cache_t *c, u32 log2_subpool_size, u32 align);
void vlib_pool_cache_init_state_with_batch (vlib_pool_cache_t *c, u32 log2_subpool_size, u32 align,
					    u32 batch_size);
void vlib_pool_cache_free_state (vlib_pool_cache_t *c);
void vlib_pool_cache_register_instance (vlib_pool_cache_t *c,
					vlib_pool_cache_registration_t *registration, char *name);
void vlib_pool_cache_unregister_instance (vlib_pool_cache_t *c);
u8 *format_vlib_pool_cache (u8 *s, va_list *args);

static_always_inline u32
vlib_pool_cache_encode_index (const vlib_pool_cache_t *c, u32 subpool_index, u32 elt_index)
{
  ASSERT (subpool_index < c->max_subpools);
  ASSERT (elt_index < c->subpool_size);
  return (u32) (((u64) subpool_index << c->log2_subpool_size) | elt_index);
}

static_always_inline u32
vlib_pool_cache_subpool_index (const vlib_pool_cache_t *c, u32 index)
{
  return index >> c->log2_subpool_size;
}

static_always_inline u32
vlib_pool_cache_elt_index (const vlib_pool_cache_t *c, u32 index)
{
  return index & c->subpool_mask;
}

static_always_inline vlib_pool_cache_subpool_meta_t *
vlib_pool_cache_get_subpool_meta_chunk (vlib_pool_cache_t *c, u32 pidx)
{
  u32 chunk_index = pidx >> VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE;
  vlib_pool_cache_subpool_meta_t *chunk = c->subpool_meta_chunks[chunk_index];

  if (PREDICT_FALSE (chunk == 0))
    {
      vec_validate_aligned (chunk, VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1,
			    CLIB_CACHE_LINE_BYTES);
      c->subpool_meta_chunks[chunk_index] = chunk;
    }
  return chunk;
}

static_always_inline vlib_pool_cache_subpool_meta_t *
vlib_pool_cache_subpool_meta_at (vlib_pool_cache_t *c, u32 pidx)
{
  vlib_pool_cache_subpool_meta_t *chunk;

  ASSERT (pidx < clib_atomic_load_acq_n (&c->n_subpools));
  chunk = c->subpool_meta_chunks[pidx >> VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE];
  ASSERT (chunk != 0);
  return chunk + (pidx & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK);
}

static_always_inline u32
vlib_pool_cache_next_free (vlib_pool_cache_t *c, u32 index)
{
  u32 pidx = vlib_pool_cache_subpool_index (c, index);
  u32 eidx = vlib_pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, pidx);

  ASSERT (index != VLIB_POOL_CACHE_INVALID_INDEX);
  return sp->next_free[eidx];
}

static_always_inline void
vlib_pool_cache_set_next_free (vlib_pool_cache_t *c, u32 index, u32 next)
{
  u32 pidx = vlib_pool_cache_subpool_index (c, index);
  u32 eidx = vlib_pool_cache_elt_index (c, index);
  vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, pidx);

  ASSERT (index != VLIB_POOL_CACHE_INVALID_INDEX);
  sp->next_free[eidx] = next;
}

/*
 * Generate a typed wrapper around fixed backing chunks of T.
 *
 * Public generated functions:
 *   NAME##_pool_cache_init (c, name, log2_subpool_size, align)
 *   NAME##_pool_cache_init_with_batch (c, name, log2_subpool_size, align,
 *                                      batch_size)
 *   NAME##_pool_cache_free_resources (c)
 *   NAME##_pool_cache_alloc (c)
 *   NAME##_pool_cache_free (c, idx)
 *   NAME##_pool_cache_elt_at_index (c, idx)
 *   NAME##_pool_cache_get_if_live (c, idx)
 *   NAME##_pool_cache_retire (c, idx)
 *   NAME##_pool_cache_reclaim (c, idx)
 *   NAME##_pool_cache_is_free_index (c, idx)
 *   NAME##_pool_cache_format_element (s, c, idx)
 */
#define VLIB_POOL_CACHE_DEFINE(NAME, T)                                                            \
                                                                                                   \
  static vlib_pool_cache_registration_t NAME##_pool_cache_registration;                            \
                                                                                                   \
  static void __vlib_add_pool_cache_registration_##NAME (void) __attribute__ ((__constructor__));  \
  static void __vlib_add_pool_cache_registration_##NAME (void)                                     \
  {                                                                                                \
    vlib_pool_cache_main_t *_pcm_ = &pool_cache_main;                                              \
    NAME##_pool_cache_registration.next_registration = _pcm_->registrations;                       \
    _pcm_->registrations = &NAME##_pool_cache_registration;                                        \
  }                                                                                                \
                                                                                                   \
  static void __vlib_rm_pool_cache_registration_##NAME (void) __attribute__ ((__destructor__));    \
  static void __vlib_rm_pool_cache_registration_##NAME (void)                                      \
  {                                                                                                \
    vlib_pool_cache_main_t *_pcm_ = &pool_cache_main;                                              \
    VLIB_REMOVE_FROM_LINKED_LIST (_pcm_->registrations, &NAME##_pool_cache_registration,           \
				  next_registration);                                              \
  }                                                                                                \
                                                                                                   \
  typedef struct                                                                                   \
  {                                                                                                \
    T ***_pool_chunks;                                                                             \
    vlib_pool_cache_t state;                                                                       \
  } NAME##_pool_cache_t;                                                                           \
                                                                                                   \
  static_always_inline T **NAME##_pool_cache_get_pool_chunk_ (NAME##_pool_cache_t *_c_,            \
							      u32 _pidx_)                          \
  {                                                                                                \
    u32 _ci_ = _pidx_ >> VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE;                              \
    T **_chunk_ = _c_->_pool_chunks[_ci_];                                                         \
    if (PREDICT_FALSE (_chunk_ == 0))                                                              \
      {                                                                                            \
	vec_validate_aligned (_chunk_, VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1,                 \
			      CLIB_CACHE_LINE_BYTES);                                              \
	_c_->_pool_chunks[_ci_] = _chunk_;                                                         \
      }                                                                                            \
    return _chunk_;                                                                                \
  }                                                                                                \
                                                                                                   \
  static_always_inline T *NAME##_pool_cache_pool_at_ (NAME##_pool_cache_t *_c_, u32 _pidx_)        \
  {                                                                                                \
    T **_chunk_;                                                                                   \
    ASSERT (_pidx_ < clib_atomic_load_acq_n (&_c_->state.n_subpools));                             \
    _chunk_ = _c_->_pool_chunks[_pidx_ >> VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE];            \
    ASSERT (_chunk_ != 0);                                                                         \
    ASSERT (_chunk_[_pidx_ & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK] != 0);                        \
    return _chunk_[_pidx_ & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK];                               \
  }                                                                                                \
                                                                                                   \
  /* Caller holds state.lock. */                                                                   \
  static_always_inline void NAME##_pool_cache_add_subpool_locked_ (NAME##_pool_cache_t *_c_)       \
  {                                                                                                \
    T *_pool_ = 0;                                                                                 \
    T **_pool_chunk_;                                                                              \
    vlib_pool_cache_subpool_meta_t *_meta_chunk_, *_sp_;                                           \
    u32 _i_, _n_global_, _pidx_ = _c_->state.n_subpools;                                           \
    u32 _old_global_head_ = _c_->state.global_free_list;                                           \
    if (PREDICT_FALSE (_pidx_ >= _c_->state.max_subpools))                                         \
      clib_panic ("pool cache '%s' exhausted u32 index space",                                     \
		  _c_->state.name ? _c_->state.name : NAME##_pool_cache_registration.name);        \
    /* Allocate stable payload storage and its parallel per-slot metadata. */                      \
    vec_validate_aligned (_pool_, _c_->state.subpool_size - 1, _c_->state.align);                  \
    clib_mem_poison (_pool_, (uword) _c_->state.subpool_size * sizeof (_pool_[0]));                \
    _pool_chunk_ = NAME##_pool_cache_get_pool_chunk_ (_c_, _pidx_);                                \
    _pool_chunk_[_pidx_ & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK] = _pool_;                        \
    _meta_chunk_ = vlib_pool_cache_get_subpool_meta_chunk (&_c_->state, _pidx_);                   \
    _sp_ = &_meta_chunk_[_pidx_ & VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_MASK];                         \
    clib_memset (_sp_, 0, sizeof (*_sp_));                                                         \
    vec_validate_aligned (_sp_->slot_state, _c_->state.subpool_size - 1, CLIB_CACHE_LINE_BYTES);   \
    vec_validate_aligned (_sp_->next_free, _c_->state.subpool_size - 1, CLIB_CACHE_LINE_BYTES);    \
    /* Form one free chain whose tail points at the previous global head. */                       \
    for (_i_ = 0; _i_ < _c_->state.subpool_size; _i_++)                                            \
      {                                                                                            \
	_sp_->slot_state[_i_] = VLIB_POOL_CACHE_SLOT_FREE;                                         \
	_sp_->next_free[_i_] = _i_ + 1 < _c_->state.subpool_size ?                                 \
				 vlib_pool_cache_encode_index (&_c_->state, _pidx_, _i_ + 1) :     \
				 _old_global_head_;                                                \
      }                                                                                            \
    /* Publish storage before exposing its first index through the global list. */                 \
    clib_atomic_store_rel_n (&_c_->state.n_subpools, _pidx_ + 1);                                  \
    _c_->state.global_free_list = vlib_pool_cache_encode_index (&_c_->state, _pidx_, 0);           \
    _n_global_ = clib_atomic_load_relax_n (&_c_->state.n_global_free);                             \
    clib_atomic_store_relax_n (&_c_->state.n_global_free,                                          \
			       _n_global_ + _c_->state.subpool_size);                               \
    clib_atomic_fetch_add_rel (&_c_->state.growths, 1);                                            \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_refill_ (NAME##_pool_cache_t *_c_,                   \
						       vlib_pool_cache_thread_t *_pt_)             \
  {                                                                                                \
    u32 _batch_ = _c_->state.batch_size;                                                           \
    u32 _head_, _tail_, _i_, _n_global_;                                                           \
    ASSERT (clib_atomic_load_relax_n (&_pt_->n_cached) == 0);                                      \
    ASSERT (_pt_->free_list == VLIB_POOL_CACHE_INVALID_INDEX);                                     \
    clib_spinlock_lock (&_c_->state.lock);                                                         \
    clib_atomic_fetch_add_rel (&_c_->state.global_lock_acquisitions, 1);                           \
    /* Grow until a complete transfer batch can be detached. */                                    \
    while (clib_atomic_load_relax_n (&_c_->state.n_global_free) < _batch_)                         \
      NAME##_pool_cache_add_subpool_locked_ (_c_);                                                 \
    /* Locate the batch tail, then cut that prefix from the global chain. */                       \
    _head_ = _tail_ = _c_->state.global_free_list;                                                 \
    for (_i_ = 1; _i_ < _batch_; _i_++)                                                            \
      _tail_ = vlib_pool_cache_next_free (&_c_->state, _tail_);                                    \
    _c_->state.global_free_list = vlib_pool_cache_next_free (&_c_->state, _tail_);                 \
    vlib_pool_cache_set_next_free (&_c_->state, _tail_, VLIB_POOL_CACHE_INVALID_INDEX);            \
    _n_global_ = clib_atomic_load_relax_n (&_c_->state.n_global_free);                             \
    ASSERT (_n_global_ >= _batch_);                                                                \
    clib_atomic_store_relax_n (&_c_->state.n_global_free, _n_global_ - _batch_);                   \
    /* The detached chain is now owned exclusively by this thread. */                              \
    _pt_->free_list = _head_;                                                                      \
    clib_atomic_store_rel_n (&_pt_->n_cached, _batch_);                                            \
    clib_atomic_fetch_add_rel (&_pt_->refills, 1);                                                 \
    clib_spinlock_unlock (&_c_->state.lock);                                                       \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_flush_ (NAME##_pool_cache_t *_c_,                    \
						      vlib_pool_cache_thread_t *_pt_, u32 _n_)     \
  {                                                                                                \
    u32 _batch_ = _c_->state.batch_size;                                                           \
    u32 _n_flush_ = _n_ - _batch_;                                                                 \
    u32 _head_ = _pt_->free_list;                                                                  \
    u32 _tail_ = _head_;                                                                           \
    u32 _new_local_head_, _i_, _n_global_;                                                         \
    ASSERT (_n_ > 2 * _batch_);                                                                    \
    ASSERT (_head_ != VLIB_POOL_CACHE_INVALID_INDEX);                                              \
    /* Split off the newest n-batch entries and retain one batch locally. */                       \
    for (_i_ = 1; _i_ < _n_flush_; _i_++)                                                          \
      _tail_ = vlib_pool_cache_next_free (&_c_->state, _tail_);                                    \
    _new_local_head_ = vlib_pool_cache_next_free (&_c_->state, _tail_);                            \
    ASSERT (_new_local_head_ != VLIB_POOL_CACHE_INVALID_INDEX);                                    \
    /* Prepend the detached chain to the global list while holding its lock. */                    \
    clib_spinlock_lock (&_c_->state.lock);                                                         \
    clib_atomic_fetch_add_rel (&_c_->state.global_lock_acquisitions, 1);                           \
    vlib_pool_cache_set_next_free (&_c_->state, _tail_, _c_->state.global_free_list);              \
    _c_->state.global_free_list = _head_;                                                          \
    _n_global_ = clib_atomic_load_relax_n (&_c_->state.n_global_free);                             \
    clib_atomic_store_relax_n (&_c_->state.n_global_free, _n_global_ + _n_flush_);                 \
    _pt_->free_list = _new_local_head_;                                                            \
    clib_atomic_store_rel_n (&_pt_->n_cached, _batch_);                                            \
    clib_atomic_fetch_add_rel (&_pt_->flushes, 1);                                                 \
    clib_spinlock_unlock (&_c_->state.lock);                                                       \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_init_with_batch (                                    \
    NAME##_pool_cache_t *_c_, char *_name_, u32 _log2_subpool_size_, u32 _align_,                  \
    u32 _batch_size_)                                                                              \
  {                                                                                                \
    _c_->_pool_chunks = 0;                                                                         \
    /* Initialize the generic list and metadata state used by this typed wrapper. */               \
    vlib_pool_cache_init_state_with_batch (&_c_->state, _log2_subpool_size_, _align_,              \
					   _batch_size_);                                          \
    vlib_pool_cache_register_instance (&_c_->state, &NAME##_pool_cache_registration, _name_);      \
    vec_validate_aligned (_c_->_pool_chunks, _c_->state.max_subpool_chunks - 1,                    \
			  CLIB_CACHE_LINE_BYTES);                                                  \
  }                                                                                                \
                                                                                                   \
  static_always_inline __clib_unused void NAME##_pool_cache_init (                                 \
    NAME##_pool_cache_t *_c_, char *_name_, u32 _log2_subpool_size_, u32 _align_)                  \
  {                                                                                                \
    NAME##_pool_cache_init_with_batch (_c_, _name_, _log2_subpool_size_, _align_, 0);              \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_free_resources (NAME##_pool_cache_t *_c_)            \
  {                                                                                                \
    u32 _i_;                                                                                       \
    vlib_pool_cache_unregister_instance (&_c_->state);                                             \
    /* Free payload slots may be poisoned, so expose each whole chunk first. */                    \
    for (_i_ = 0; _i_ < _c_->state.n_subpools; _i_++)                                              \
      {                                                                                            \
	T *_pool_ = NAME##_pool_cache_pool_at_ (_c_, _i_);                                         \
	clib_mem_unpoison (_pool_, (uword) _c_->state.subpool_size * sizeof (_pool_[0]));          \
	vec_free (_pool_);                                                                         \
      }                                                                                            \
    for (_i_ = 0; _i_ < vec_len (_c_->_pool_chunks); _i_++)                                        \
      vec_free (_c_->_pool_chunks[_i_]);                                                           \
    vec_free (_c_->_pool_chunks);                                                                  \
    /* Release slot-state/link metadata and per-thread/global list state. */                       \
    vlib_pool_cache_free_state (&_c_->state);                                                      \
  }                                                                                                \
                                                                                                   \
  static_always_inline T *NAME##_pool_cache_elt_at_index (NAME##_pool_cache_t *_c_, u32 _idx_)     \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    T *_pool_;                                                                                     \
    ASSERT (_pidx_ < clib_atomic_load_acq_n (&_c_->state.n_subpools));                             \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    ASSERT (clib_atomic_load_acq_n (&_sp_->slot_state[_eidx_]) == VLIB_POOL_CACHE_SLOT_ALLOCATED); \
    _pool_ = NAME##_pool_cache_pool_at_ (_c_, _pidx_);                                             \
    return _pool_ + _eidx_;                                                                        \
  }                                                                                                \
                                                                                                   \
  /* A successful lookup is protected only until the caller's retirement grace period ends. */     \
  /* Callers with concurrent readers must use retire/reclaim instead of immediate free. */         \
  static_always_inline __clib_unused T *NAME##_pool_cache_get_if_live (NAME##_pool_cache_t *_c_,   \
								       u32 _idx_)                  \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    if (PREDICT_FALSE (_idx_ == VLIB_POOL_CACHE_INVALID_INDEX ||                                   \
		       _pidx_ >= clib_atomic_load_acq_n (&_c_->state.n_subpools)))                 \
      return 0;                                                                                    \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    /* RETIRED and FREE reject new readers; success does not pin the element. */                   \
    if (clib_atomic_load_acq_n (&_sp_->slot_state[_eidx_]) != VLIB_POOL_CACHE_SLOT_ALLOCATED)      \
      return 0;                                                                                    \
    return NAME##_pool_cache_pool_at_ (_c_, _pidx_) + _eidx_;                                      \
  }                                                                                                \
                                                                                                   \
  static_always_inline __clib_unused u8 *NAME##_pool_cache_format_element (                        \
    u8 *s, NAME##_pool_cache_t *_c_, u32 _idx_)                                                    \
  {                                                                                                \
    format_function_t *_f_ = NAME##_pool_cache_registration.format_element;                        \
    if (_f_ == 0)                                                                                  \
      return s;                                                                                    \
    return format (s, "%U", _f_, NAME##_pool_cache_elt_at_index (_c_, _idx_));                     \
  }                                                                                                \
                                                                                                   \
  static_always_inline int NAME##_pool_cache_is_free_index (NAME##_pool_cache_t *_c_, u32 _idx_)   \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    if (PREDICT_FALSE (_idx_ == VLIB_POOL_CACHE_INVALID_INDEX ||                                   \
		       _pidx_ >= clib_atomic_load_acq_n (&_c_->state.n_subpools)))                 \
      return 1;                                                                                    \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    /* Retired slots are quarantined, not free or allocatable. */                                  \
    return clib_atomic_load_acq_n (&_sp_->slot_state[_eidx_]) == VLIB_POOL_CACHE_SLOT_FREE;        \
  }                                                                                                \
                                                                                                   \
  static_always_inline u32 NAME##_pool_cache_alloc (NAME##_pool_cache_t *_c_)                      \
  {                                                                                                \
    u32 _ti_ = vlib_get_thread_index ();                                                           \
    vlib_pool_cache_thread_t *_pt_ = vec_elt_at_index (_c_->state.per_thread, _ti_);               \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    u32 _n_ = clib_atomic_load_relax_n (&_pt_->n_cached);                                          \
    u32 _idx_, _pidx_, _eidx_;                                                                     \
    T *_pool_;                                                                                     \
    /* Empty local lists acquire a detached batch from the locked global list. */                  \
    if (PREDICT_FALSE (_n_ == 0))                                                                  \
      {                                                                                            \
	NAME##_pool_cache_refill_ (_c_, _pt_);                                                     \
	_n_ = clib_atomic_load_relax_n (&_pt_->n_cached);                                          \
      }                                                                                            \
    /* Pop the local head and remove its link before marking the slot allocated. */                \
    _idx_ = _pt_->free_list;                                                                       \
    ASSERT (_idx_ != VLIB_POOL_CACHE_INVALID_INDEX);                                               \
    _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                                   \
    _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                       \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    _pt_->free_list = _sp_->next_free[_eidx_];                                                     \
    _sp_->next_free[_eidx_] = VLIB_POOL_CACHE_INVALID_INDEX;                                       \
    clib_atomic_store_rel_n (&_pt_->n_cached, --_n_);                                              \
    if (PREDICT_FALSE (!vlib_pool_cache_mark_allocated (&_sp_->slot_state[_eidx_])))               \
      clib_panic ("pool cache '%s' free-index corruption at %u", _c_->state.name, _idx_);          \
    /* A free slot is poisoned until its token has been claimed successfully. */                   \
    _pool_ = NAME##_pool_cache_pool_at_ (_c_, _pidx_);                                             \
    clib_mem_unpoison (_pool_ + _eidx_, sizeof (_pool_[0]));                                       \
    return _idx_;                                                                                  \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_publish_free_ (NAME##_pool_cache_t *_c_, u32 _idx_,  \
							     u32 _pidx_, u32 _eidx_,               \
							     vlib_pool_cache_subpool_meta_t *_sp_) \
  {                                                                                                \
    u32 _ti_ = vlib_get_thread_index ();                                                           \
    vlib_pool_cache_thread_t *_pt_;                                                                \
    T *_pool_ = NAME##_pool_cache_pool_at_ (_c_, _pidx_);                                          \
    u32 _n_;                                                                                       \
    /* Poison before publishing the token so a later allocation must unpoison it. */               \
    clib_mem_poison (_pool_ + _eidx_, sizeof (_pool_[0]));                                         \
    _pt_ = vec_elt_at_index (_c_->state.per_thread, _ti_);                                         \
    _n_ = clib_atomic_load_relax_n (&_pt_->n_cached);                                              \
    /* Push onto the caller's private list; no global lock is needed here. */                      \
    _sp_->next_free[_eidx_] = _pt_->free_list;                                                     \
    _pt_->free_list = _idx_;                                                                       \
    _n_++;                                                                                         \
    clib_atomic_store_rel_n (&_pt_->n_cached, _n_);                                                \
    /* Return excess entries to the global list in one batched splice. */                          \
    if (PREDICT_FALSE (_n_ > 2 * _c_->state.batch_size))                                           \
      NAME##_pool_cache_flush_ (_c_, _pt_, _n_);                                                   \
  }                                                                                                \
                                                                                                   \
  /* Immediate release; callers with concurrent readers must use retire/reclaim. */                \
  static_always_inline int NAME##_pool_cache_free_internal_ (NAME##_pool_cache_t *_c_, u32 _idx_)  \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    u8 _expected_ = VLIB_POOL_CACHE_SLOT_ALLOCATED;                                                \
    if (PREDICT_FALSE (_idx_ == VLIB_POOL_CACHE_INVALID_INDEX ||                                   \
		       _pidx_ >= clib_atomic_load_acq_n (&_c_->state.n_subpools)))                 \
      return 0;                                                                                    \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    /* Claim the sole release; this also rejects double-free and RETIRED slots. */                 \
    if (!clib_atomic_cmp_and_swap_acq_relax_n (&_sp_->slot_state[_eidx_], &_expected_,             \
					       VLIB_POOL_CACHE_SLOT_FREE, 0))                      \
      return 0;                                                                                    \
    NAME##_pool_cache_publish_free_ (_c_, _idx_, _pidx_, _eidx_, _sp_);                            \
    return 1;                                                                                      \
  }                                                                                                \
                                                                                                   \
  /* Stop new get_if_live lookups without poisoning or making the index allocatable. */            \
  static_always_inline __clib_unused int NAME##_pool_cache_retire (NAME##_pool_cache_t *_c_,       \
								   u32 _idx_)                      \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    u8 _expected_ = VLIB_POOL_CACHE_SLOT_ALLOCATED;                                                \
    if (PREDICT_FALSE (_idx_ == VLIB_POOL_CACHE_INVALID_INDEX ||                                   \
		       _pidx_ >= clib_atomic_load_acq_n (&_c_->state.n_subpools)))                 \
      return 0;                                                                                    \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    /* Close the lookup gate without poisoning or publishing a free token. */                      \
    if (!clib_atomic_cmp_and_swap_acq_relax_n (&_sp_->slot_state[_eidx_], &_expected_,             \
					       VLIB_POOL_CACHE_SLOT_RETIRED, 0))                   \
      return 0;                                                                                    \
    clib_atomic_fetch_add_relax (&_c_->state.n_retired, 1);                                        \
    return 1;                                                                                      \
  }                                                                                                \
                                                                                                   \
  /* Call only after the user-provided grace period has completed. */                              \
  static_always_inline __clib_unused int NAME##_pool_cache_reclaim (NAME##_pool_cache_t *_c_,      \
								    u32 _idx_)                     \
  {                                                                                                \
    u32 _pidx_ = vlib_pool_cache_subpool_index (&_c_->state, _idx_);                               \
    u32 _eidx_ = vlib_pool_cache_elt_index (&_c_->state, _idx_);                                   \
    vlib_pool_cache_subpool_meta_t *_sp_;                                                          \
    u64 _n_retired_;                                                                               \
    u8 _expected_ = VLIB_POOL_CACHE_SLOT_RETIRED;                                                  \
    if (PREDICT_FALSE (_idx_ == VLIB_POOL_CACHE_INVALID_INDEX ||                                   \
		       _pidx_ >= clib_atomic_load_acq_n (&_c_->state.n_subpools)))                 \
      return 0;                                                                                    \
    _sp_ = vlib_pool_cache_subpool_meta_at (&_c_->state, _pidx_);                                  \
    /* Only a retired slot may cross back to FREE after the caller's grace period. */              \
    if (!clib_atomic_cmp_and_swap_acq_relax_n (&_sp_->slot_state[_eidx_], &_expected_,             \
					       VLIB_POOL_CACHE_SLOT_FREE, 0))                      \
      return 0;                                                                                    \
    _n_retired_ = clib_atomic_fetch_sub_relax (&_c_->state.n_retired, 1);                          \
    ASSERT (_n_retired_ > 0);                                                                      \
    /* Poison the payload and publish its token to this thread's free list. */                     \
    NAME##_pool_cache_publish_free_ (_c_, _idx_, _pidx_, _eidx_, _sp_);                            \
    return 1;                                                                                      \
  }                                                                                                \
                                                                                                   \
  static_always_inline void NAME##_pool_cache_free (NAME##_pool_cache_t *_c_, u32 _idx_)           \
  {                                                                                                \
    int _ok_ = NAME##_pool_cache_free_internal_ (_c_, _idx_);                                      \
    ASSERT (_ok_);                                                                                 \
  }                                                                                                \
                                                                                                   \
  static vlib_pool_cache_registration_t NAME##_pool_cache_registration

#endif /* included_vlib_pool_cache_h */
