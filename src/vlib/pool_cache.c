/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>
#include <vppinfra/format_table.h>

vlib_pool_cache_main_t pool_cache_main;

static u64
vlib_pool_cache_count_cached (vlib_pool_cache_t *c)
{
  vlib_pool_cache_thread_t *pt;
  u64 cached = 0;

  vec_foreach (pt, c->per_thread)
    cached += clib_atomic_load_acq_n (&pt->n_cached);
  return cached;
}

static u32
vlib_pool_cache_count_global (vlib_pool_cache_t *c)
{
  return clib_atomic_load_relax_n (&c->n_global_free);
}

static void
vlib_pool_cache_format_summary_row (table_t *t, int row, vlib_pool_cache_t *c)
{
  u64 allocated, retired, free, cached, total;
  u32 n_subpools, global;
  int col = 0;

  n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  cached = vlib_pool_cache_count_cached (c);
  global = vlib_pool_cache_count_global (c);
  retired = clib_atomic_load_relax_n (&c->n_retired);
  total = (u64) n_subpools * c->subpool_size;
  free = cached + global;
  /* Concurrent transitions can make this diagnostic snapshot momentarily skewed. */
  allocated = free + retired < total ? total - free - retired : 0;

  table_format_cell (t, row, col++, "%s", c->name);
  table_format_cell (t, row, col++, "%p", c);
  table_format_cell (t, row, col++, "%u", n_subpools);
  table_format_cell (t, row, col++, "%u", c->subpool_size);
  table_format_cell (t, row, col++, "%u", c->batch_size);
  table_format_cell (t, row, col++, "%llu", allocated);
  table_format_cell (t, row, col++, "%llu", retired);
  table_format_cell (t, row, col++, "%u", global);
  table_format_cell (t, row, col++, "%llu", cached);
  table_format_cell (t, row, col++, "%llu", free);
  table_format_cell (t, row, col++, "%llu", clib_atomic_load_acq_n (&c->global_lock_acquisitions));
  table_format_cell (t, row, col++, "%llu", clib_atomic_load_acq_n (&c->growths));
}

static u8 *
format_vlib_pool_cache_threads (u8 *s, vlib_pool_cache_t *c)
{
  table_t table = {}, *t = &table;
  vlib_pool_cache_thread_t *pt;
  int row = 0;

  table_add_hdr_row (t, 4, "thread", "cached", "refills", "flushes");
  vec_foreach (pt, c->per_thread)
    {
      int col = 0;
      table_format_cell (t, row, col++, "%u", pt - c->per_thread);
      table_format_cell (t, row, col++, "%u", clib_atomic_load_acq_n (&pt->n_cached));
      table_format_cell (t, row, col++, "%llu", clib_atomic_load_acq_n (&pt->refills));
      table_format_cell (t, row, col++, "%llu", clib_atomic_load_acq_n (&pt->flushes));
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

  table_add_hdr_row (t, 12, "Name", "Address", "Chunks", "ChunkSize", "Batch", "Allocated",
		     "Retired", "GlobalFree", "CachedFree", "Free", "GlobalLocks", "Growths");
  vlib_pool_cache_format_summary_row (t, 0, c);
  s = format (s, "%U", format_table, t);
  table_free (t);

  if (verbose)
    s = format_vlib_pool_cache_threads (s, c);
  return s;
}

void
vlib_pool_cache_register_instance (vlib_pool_cache_t *c,
				   vlib_pool_cache_registration_t *registration, char *name)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;

  ASSERT (registration != 0);
  ASSERT (c->registration == 0);
  c->registration = registration;
  c->name = name ? name : registration->name;
  c->next_instance = pcm->instances;
  pcm->instances = c;
}

void
vlib_pool_cache_unregister_instance (vlib_pool_cache_t *c)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;

  if (c->registration == 0)
    return;
  VLIB_REMOVE_FROM_LINKED_LIST (pcm->instances, c, next_instance);
  c->registration = 0;
  c->name = 0;
  c->next_instance = 0;
}

void
vlib_pool_cache_init_state_with_batch (vlib_pool_cache_t *c, u32 log2_subpool_size, u32 align,
				       u32 batch_size)
{
  vlib_pool_cache_thread_t *pt;
  u32 n_threads;
  u64 max_cached;

  clib_memset (c, 0, sizeof (*c));
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
  c->subpool_mask = c->subpool_size - 1;
  c->max_subpools = (1ULL << (32 - c->log2_subpool_size)) - 1;
  c->max_subpool_chunks = ((u64) c->max_subpools + VLIB_POOL_CACHE_SUBPOOL_PTR_CHUNK_SIZE - 1) >>
			  VLIB_POOL_CACHE_LOG2_SUBPOOL_PTR_CHUNK_SIZE;
  c->align = align;
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

  vec_validate_aligned (c->subpool_meta_chunks, c->max_subpool_chunks - 1, CLIB_CACHE_LINE_BYTES);
}

void
vlib_pool_cache_init_state (vlib_pool_cache_t *c, u32 log2_subpool_size, u32 align)
{
  vlib_pool_cache_init_state_with_batch (c, log2_subpool_size, align, 0);
}

void
vlib_pool_cache_free_state (vlib_pool_cache_t *c)
{
  u32 i;

  for (i = 0; i < c->n_subpools; i++)
    {
      vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, i);
      /* State and intrusive links are parallel arrays owned by this chunk. */
      vec_free (sp->slot_state);
      vec_free (sp->next_free);
    }
  for (i = 0; i < vec_len (c->subpool_meta_chunks); i++)
    vec_free (c->subpool_meta_chunks[i]);
  vec_free (c->subpool_meta_chunks);
  vec_free (c->per_thread);
  clib_spinlock_free (&c->lock);
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

  table_add_hdr_row (t, 12, "Name", "Address", "Chunks", "ChunkSize", "Batch", "Allocated",
		     "Retired", "GlobalFree", "CachedFree", "Free", "GlobalLocks", "Growths");
  for (c = pcm->instances; c; c = c->next_instance)
    {
      if (name && strcmp (c->name, name))
	continue;
      found = 1;
      vlib_pool_cache_format_summary_row (t, row++, c);
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
	  s = format_vlib_pool_cache_threads (s, *cp);
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
