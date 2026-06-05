/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>

void
vlib_pool_cache_init_state (vlib_pool_cache_t *c, char *name, u32 log2_subpool_size, u32 align)
{
  vlib_pool_cache_thread_t *pt;
  u32 n_threads;

  clib_memset (c, 0, sizeof (*c));
  c->name = name;
  c->empty_subpools = VLIB_POOL_CACHE_INVALID_INDEX;
  /* log2_subpool_size controls the public ID layout: high bits select the
   * subpool, low bits select the slot inside that fixed-size subpool. */
  c->log2_subpool_size =
    log2_subpool_size ? log2_subpool_size : VLIB_POOL_CACHE_DEFAULT_LOG2_SUBPOOL_SIZE;
  ASSERT (c->log2_subpool_size > 0 && c->log2_subpool_size < 32);
  if (PREDICT_FALSE (c->log2_subpool_size == 0 || c->log2_subpool_size >= 32))
    c->log2_subpool_size = VLIB_POOL_CACHE_DEFAULT_LOG2_SUBPOOL_SIZE;
  c->subpool_size = 1U << c->log2_subpool_size;
  c->subpool_mask = c->subpool_size - 1;
  /* A public ID is u32. Reserve the all-ones value for the internal invalid
   * sentinel, so the final encodable subpool/slot pair is not usable. */
  c->max_subpools = (1ULL << (32 - c->log2_subpool_size)) - 1;
  c->max_subpool_chunks = ((u64) c->max_subpools + VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1) >>
			  VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE;
  c->align = align;

  clib_spinlock_init (&c->lock);

  /* Thread 0 can use this allocator in single-worker configurations, so keep
   * one per-thread entry even when vlib has no worker threads. */
  n_threads = clib_max (vlib_thread_main.n_vlib_mains, 1);
  vec_validate_aligned (c->per_thread, n_threads - 1, CLIB_CACHE_LINE_BYTES);
  vec_foreach (pt, c->per_thread)
    {
      pt->current_subpool = VLIB_POOL_CACHE_INVALID_INDEX;
      pt->remote_pending_subpools = VLIB_POOL_CACHE_INVALID_INDEX;
    }

  /* The typed backing pools are chunked separately in each generated wrapper;
   * this table is only the generic ownership and remote-free metadata. The
   * outer vector is pre-sized so later helper code can index it without
   * growing the vector on the allocation/free fast path. */
  vec_validate_aligned (c->subpool_meta_chunks, c->max_subpool_chunks - 1, CLIB_CACHE_LINE_BYTES);
}

void
vlib_pool_cache_free_state (vlib_pool_cache_t *c)
{
  u32 i;

  /* Metadata owns the per-slot remote_next side arrays. The generated typed
   * wrapper frees the actual fixed-size backing pools before calling here. */
  for (i = 0; i < c->n_subpools; i++)
    {
      vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, i);
      vec_free (sp->remote_next);
      vec_free (sp->slot_state);
    }

  for (i = 0; i < vec_len (c->subpool_meta_chunks); i++)
    {
      /* Individual metadata chunks were allocated lazily as subpools were
       * created, so unused outer-vector entries are still NULL here. */
      vec_free (c->subpool_meta_chunks[i]);
    }

  vec_free (c->subpool_meta_chunks);
  vec_free (c->per_thread);
  clib_spinlock_free (&c->lock);
}
