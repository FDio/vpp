/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>
#include <vppinfra/format_table.h>

vlib_pool_cache_main_t pool_cache_main;

static_always_inline void
_pool_cache_lock (vlib_pool_cache_t *c)
{
  clib_spinlock_lock (&c->lock);
  u64 global_lock_acquisitions = clib_atomic_load_relax_n (&c->global_lock_acquisitions);
  clib_atomic_store_relax_n (&c->global_lock_acquisitions, global_lock_acquisitions + 1);
}

static_always_inline void
_pool_cache_unlock (vlib_pool_cache_t *c)
{
  clib_spinlock_unlock (&c->lock);
}

static u64
_pool_cache_count_cached (vlib_pool_cache_t *c)
{
  vlib_pool_cache_thread_t *pt;
  u64 cached = 0;

  vec_foreach (pt, c->per_thread)
    cached += clib_atomic_load_relax_n (&pt->n_cached);
  return cached;
}

static u32
_pool_cache_count_global (vlib_pool_cache_t *c)
{
  return clib_atomic_load_relax_n (&c->n_global_free);
}

static void
_pool_cache_format_summary_row (table_t *t, int row, vlib_pool_cache_t *c)
{
  u64 allocated, free, cached, total;
  u32 n_subpools, global;
  int col = 0;

  n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  cached = _pool_cache_count_cached (c);
  global = _pool_cache_count_global (c);
  total = (u64) n_subpools * c->subpool_size;
  free = cached + global;
  /* Concurrent transitions can make this diagnostic snapshot momentarily skewed. */
  allocated = free < total ? total - free : 0;

  table_format_cell (t, row, col++, "%s", c->name);
  table_format_cell (t, row, col++, "%p", c);
  table_format_cell (t, row, col++, "%u", n_subpools);
  table_format_cell (t, row, col++, "%u", c->subpool_size);
  table_format_cell (t, row, col++, "%u", c->batch_size);
  table_format_cell (t, row, col++, "%llu", allocated);
  table_format_cell (t, row, col++, "%u", global);
  table_format_cell (t, row, col++, "%llu", cached);
  table_format_cell (t, row, col++, "%llu", free);
  table_format_cell (t, row, col++, "%llu",
		     clib_atomic_load_relax_n (&c->global_lock_acquisitions));
  table_format_cell (t, row, col++, "%llu", clib_atomic_load_relax_n (&c->growths));
}

static u8 *
_pool_cache_format_threads (u8 *s, vlib_pool_cache_t *c)
{
  table_t table = {}, *t = &table;
  vlib_pool_cache_thread_t *pt;
  int row = 0;

  table_add_hdr_row (t, 4, "thread", "cached", "refills", "flushes");
  vec_foreach (pt, c->per_thread)
    {
      int col = 0;
      table_format_cell (t, row, col++, "%u", pt - c->per_thread);
      table_format_cell (t, row, col++, "%u", clib_atomic_load_relax_n (&pt->n_cached));
      table_format_cell (t, row, col++, "%llu", clib_atomic_load_relax_n (&pt->refills));
      table_format_cell (t, row, col++, "%llu", clib_atomic_load_relax_n (&pt->flushes));
      row++;
    }

  s = format (s, "\n%U", format_table, t);
  table_free (t);
  return s;
}

u8 *
format_vlib_pool_cache (u8 *s, va_list *args)
{
  vlib_pool_cache_t *c = va_arg (*args, vlib_pool_cache_t *);
  uword verbose = va_arg (*args, uword);
  table_t table = {}, *t = &table;

  table_add_hdr_row (t, 11, "Name", "Address", "Chunks", "ChunkSize", "Batch", "Allocated",
		     "GlobalFree", "CachedFree", "Free", "GlobalLocks", "Growths");
  _pool_cache_format_summary_row (t, 0, c);
  s = format (s, "%U", format_table, t);
  table_free (t);

  if (verbose)
    s = _pool_cache_format_threads (s, c);
  return s;
}

static void
_pool_cache_add_instance (vlib_pool_cache_t *c, char *name, format_function_t *format_element)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;

  ASSERT (name != 0);
  ASSERT (c->name == 0);
  c->name = name;
  c->format_element = format_element;
  c->next_instance = pcm->instances;
  pcm->instances = c;
}

static void
_pool_cache_remove_instance (vlib_pool_cache_t *c)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;

  if (c->name == 0)
    return;
  VLIB_REMOVE_FROM_LINKED_LIST (pcm->instances, c, next_instance);
  c->name = 0;
  c->format_element = 0;
  c->next_instance = 0;
}

static vlib_pool_cache_subpool_t *
_pool_cache_subpool_at_maybe_chunk (vlib_pool_cache_t *c, u32 pidx)
{
  u32 chunk_index = _pool_cache_subpool_chunk_index (pidx);
  ASSERT (chunk_index < c->max_subpool_chunks);
  vlib_pool_cache_subpool_t *chunk = c->subpool_chunks[chunk_index];

  if (!chunk)
    {
      vec_validate_aligned (chunk, VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1,
			    CLIB_CACHE_LINE_BYTES);
      c->subpool_chunks[chunk_index] = chunk;
    }

  return vec_elt_at_index (chunk, _pool_cache_subpool_chunk_subpool_index (pidx));
}

/* Caller holds c->lock. */
static void
_pool_cache_add_subpool_locked (vlib_pool_cache_t *c)
{
  vlib_pool_cache_subpool_t *sp;
  u32 pidx = clib_atomic_load_acq_n (&c->n_subpools);
  u64 growths = clib_atomic_load_relax_n (&c->growths);
  u32 n_global, i;
  uword n_bytes;
  u8 *pool = 0;

  if (PREDICT_FALSE (pidx >= c->max_subpools))
    clib_panic ("pool cache '%s' exhausted u32 index space", c->name);

  /* Allocate stable payload storage and its parallel per-slot metadata. */
  n_bytes = (uword) c->subpool_size * c->elt_size;
  vec_validate_aligned (pool, n_bytes - 1, c->align);
  clib_mem_poison (pool, n_bytes);

  sp = _pool_cache_subpool_at_maybe_chunk (c, pidx);
  clib_memset (sp, 0, sizeof (*sp));
  sp->pool = pool;
  vec_validate_aligned (sp->next_free, c->subpool_size - 1, CLIB_CACHE_LINE_BYTES);

  /* push next indices on top of the global free list, no need for atomic there as the pool elements
   * cannot be yet accessed */
  vec_elt (sp->next_free, 0) = c->global_free_list;
  for (i = 1; i < c->subpool_size; i++)
    vec_elt (sp->next_free, i) = _pool_cache_encode_index (c, pidx, i - 1);

  /* Publish storage before exposing its first index through the global list. */
  clib_atomic_store_rel_n (&c->n_subpools, pidx + 1);
  c->global_free_list = _pool_cache_encode_index (c, pidx, c->subpool_size - 1);
  n_global = clib_atomic_load_relax_n (&c->n_global_free);
  clib_atomic_store_relax_n (&c->n_global_free, n_global + c->subpool_size);
  clib_atomic_store_relax_n (&c->growths, growths + 1);
}

void
_pool_cache_refill (vlib_pool_cache_t *c, vlib_pool_cache_thread_t *pt)
{
  u32 batch = c->batch_size;
  u64 refills = clib_atomic_load_relax_n (&pt->refills);
  u32 head, tail, i, n_global;

  ASSERT (clib_atomic_load_relax_n (&pt->n_cached) == 0);
  ASSERT (pt->free_list == VLIB_POOL_CACHE_INVALID_INDEX);

  _pool_cache_lock (c);

  /* Grow until a complete transfer batch can be detached. */
  while (clib_atomic_load_relax_n (&c->n_global_free) < batch)
    _pool_cache_add_subpool_locked (c);

  /* Cut one batch from the global chain and transfer it to this thread. */
  head = tail = c->global_free_list;
  for (i = 1; i < batch; i++)
    tail = _pool_cache_next_free (c, tail);

  c->global_free_list = _pool_cache_next_free (c, tail);
  _pool_cache_set_next_free (c, tail, VLIB_POOL_CACHE_INVALID_INDEX);
  n_global = clib_atomic_load_relax_n (&c->n_global_free);
  ASSERT (n_global >= batch);
  clib_atomic_store_relax_n (&c->n_global_free, n_global - batch);

  pt->free_list = head;
  clib_atomic_store_relax_n (&pt->n_cached, batch);
  clib_atomic_store_relax_n (&pt->refills, refills + 1);

  _pool_cache_unlock (c);
}

void
_pool_cache_flush (vlib_pool_cache_t *c, vlib_pool_cache_thread_t *pt, u32 n_cached)
{
  u32 batch = c->batch_size;
  u32 n_flush = n_cached - batch;
  u32 head = pt->free_list;
  u32 tail = head;
  u64 flushes = clib_atomic_load_relax_n (&pt->flushes);
  u32 new_local_head, i, n_global;

  ASSERT (n_cached > 2 * batch);
  ASSERT (head != VLIB_POOL_CACHE_INVALID_INDEX);

  /* Split off the newest entries and retain one complete batch locally. */
  for (i = 1; i < n_flush; i++)
    tail = _pool_cache_next_free (c, tail);

  new_local_head = _pool_cache_next_free (c, tail);
  ASSERT (new_local_head != VLIB_POOL_CACHE_INVALID_INDEX);

  /* Prepend the detached chain to the global list under its lock. */
  _pool_cache_lock (c);

  _pool_cache_set_next_free (c, tail, c->global_free_list);
  c->global_free_list = head;
  n_global = clib_atomic_load_relax_n (&c->n_global_free);
  clib_atomic_store_relax_n (&c->n_global_free, n_global + n_flush);

  pt->free_list = new_local_head;
  clib_atomic_store_relax_n (&pt->n_cached, batch);
  clib_atomic_store_relax_n (&pt->flushes, flushes + 1);

  _pool_cache_unlock (c);
}

void
_pool_cache_init_with_batch (vlib_pool_cache_t *c, char *name, format_function_t *format_element,
			     u32 log2_subpool_size, u32 align, u32 batch_size, uword elt_size,
			     uword elt_align)
{
  vlib_pool_cache_thread_t *pt;
  u32 n_threads;
  u64 max_cached;

  ASSERT (name != 0);
  ASSERT (elt_size > 0);
  clib_memset (c, 0, sizeof (*c));
  c->elt_size = elt_size;
  c->log2_subpool_size =
    log2_subpool_size ? log2_subpool_size : VLIB_POOL_CACHE_DEFAULT_LOG2_SUBPOOL_SIZE;
  ASSERT (c->log2_subpool_size > 0 && c->log2_subpool_size < 32);
  if (PREDICT_FALSE (c->log2_subpool_size == 0 || c->log2_subpool_size >= 32))
    c->log2_subpool_size = VLIB_POOL_CACHE_DEFAULT_LOG2_SUBPOOL_SIZE;

  c->batch_size = batch_size ? batch_size : VLIB_POOL_CACHE_DEFAULT_BATCH_SIZE;
  max_cached = 2ULL * c->batch_size + 1;
  if (PREDICT_FALSE (max_cached > (u64) (u32) ~0))
    clib_panic ("pool cache batch size %u is too large", c->batch_size);

  c->subpool_size = 1U << c->log2_subpool_size;
  if (PREDICT_FALSE (c->elt_size > (uword) ~0 / c->subpool_size))
    clib_panic ("pool cache element storage size overflow");
  c->subpool_mask = c->subpool_size - 1;
  c->max_subpools = (1ULL << (32 - c->log2_subpool_size)) - 1;
  c->max_subpool_chunks = ((u64) c->max_subpools + VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1) >>
			  VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE;
  /* Match typed-vector semantics: never weaken T's natural alignment. */
  c->align = __vec_align (elt_align, align);
  /* INVALID is the empty-list sentinel; encoded element indices never use it. */
  c->global_free_list = VLIB_POOL_CACHE_INVALID_INDEX;

  clib_spinlock_init (&c->lock);
  n_threads = clib_max (vlib_thread_main.n_vlib_mains, 1);
  vec_validate_aligned (c->per_thread, n_threads - 1, CLIB_CACHE_LINE_BYTES);
  /* Each VPP thread is the sole writer of its own local free-list head. */
  vec_foreach (pt, c->per_thread)
    {
      pt->free_list = VLIB_POOL_CACHE_INVALID_INDEX;
      pt->n_cached = 0;
      pt->refills = 0;
      pt->flushes = 0;
    }

  vec_validate_aligned (c->subpool_chunks, c->max_subpool_chunks - 1, CLIB_CACHE_LINE_BYTES);
  _pool_cache_add_instance (c, name, format_element);
}

void
pool_cache_free (vlib_pool_cache_t *c)
{
  u32 i;

  _pool_cache_remove_instance (c);
  /* Payload and metadata chunks are stable until complete quiescence here. */
  for (i = 0; i < c->n_subpools; i++)
    {
      vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, i);

      clib_mem_unpoison (sp->pool, (uword) c->subpool_size * c->elt_size);
      vec_free (sp->pool);
      vec_free (sp->next_free);
    }
  for (i = 0; i < vec_len (c->subpool_chunks); i++)
    vec_free (c->subpool_chunks[i]);
  vec_free (c->subpool_chunks);
  vec_free (c->per_thread);
  clib_spinlock_free (&c->lock);
}

u8 *
pool_cache_format_element (u8 *s, vlib_pool_cache_t *c, u32 index)
{
  format_function_t *f = c->format_element;

  if (f == 0)
    return s;
  return format (s, "%U", f, pool_cache_elt_at_index (c, index));
}

static clib_error_t *
show_pool_cache_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;
  vlib_pool_cache_t *c;
  vlib_pool_cache_t **verbose_caches = 0;
  char *name = 0, *parsed_name = 0;
  clib_error_t *error = 0;
  u8 *s = 0;
  uword verbose = 0;
  u8 found = 0;
  int row = 0;
  table_t table = {}, *t = &table;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "name %s", &parsed_name) || unformat (input, "%s", &parsed_name))
	{
	  if (name)
	    {
	      vec_free (name);
	      vec_free (parsed_name);
	      return clib_error_return (0, "pool-cache name specified more than once");
	    }
	  name = parsed_name;
	  parsed_name = 0;
	}
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (verbose && name == 0)
    return clib_error_return (0, "verbose requires a pool-cache name");
  if (pcm->instances == 0)
    {
      vlib_cli_output (vm, "No pool caches initialized");
      vec_free (name);
      return 0;
    }

  table_add_hdr_row (t, 11, "Name", "Address", "Chunks", "ChunkSize", "Batch", "Allocated",
		     "GlobalFree", "CachedFree", "Free", "GlobalLocks", "Growths");
  for (c = pcm->instances; c; c = c->next_instance)
    {
      if (name && strcmp (c->name, name))
	continue;
      found = 1;
      _pool_cache_format_summary_row (t, row++, c);
      if (verbose)
	vec_add1 (verbose_caches, c);
    }

  if (name && !found)
    {
      table_free (t);
      error = clib_error_return (0, "pool-cache `%s' not found", name);
      vec_free (name);
      return error;
    }

  s = format (s, "%U", format_table, t);
  table_free (t);
  if (verbose)
    {
      vlib_pool_cache_t **cp;
      vec_foreach (cp, verbose_caches)
	{
	  if (vec_len (verbose_caches) > 1)
	    s = format (s, "\n%s %p", (*cp)->name, *cp);
	  s = _pool_cache_format_threads (s, *cp);
	}
    }

  vlib_cli_output (vm, "%v", s);
  vlib_cli_output (vm, "Counts are a non-atomic diagnostic snapshot.");
  vec_free (s);
  vec_free (verbose_caches);
  vec_free (name);
  return 0;
}

VLIB_CLI_COMMAND (show_pool_cache_command, static) = {
  .path = "show pool-cache",
  .short_help = "show pool-cache [<name> | name <name>] [verbose]",
  .function = show_pool_cache_command_fn,
  .is_mp_safe = 1,
};
