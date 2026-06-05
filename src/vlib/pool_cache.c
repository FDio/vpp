/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>

void
vlib_pool_cache_init_state (vlib_pool_cache_t *c, char *name, u32 cache_size, u32 align)
{
  clib_memset (c, 0, sizeof (*c));
  c->name = name;
  c->cache_size = cache_size ? cache_size : VLIB_POOL_CACHE_DEFAULT_SIZE;
  c->drain_threshold = 2 * c->cache_size;
  c->align = align;

  /* Single-thread mode: leave per_thread = NULL and lock uninitialized.
   * The fast-path generated code special-cases this to a direct
   * pool_get_aligned / pool_put_index, no allocation, no spinlock cost. */
  if (vlib_num_workers () == 0)
    return;

  clib_spinlock_init (&c->lock);
  vec_validate (c->per_thread, vlib_thread_main.n_vlib_mains - 1);
}

void
vlib_pool_cache_free_state (vlib_pool_cache_t *c)
{
  if (c->per_thread)
    {
      vlib_pool_cache_thread_t *pt;
      vec_foreach (pt, c->per_thread)
	vec_free (pt->cache);
      vec_free (c->per_thread);
    }
  clib_spinlock_free (&c->lock);
}
