/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>
#include <vppinfra/format_table.h>

vlib_pool_cache_main_t vlib_pool_cache_main;

static void
vlib_pool_cache_count_slots (vlib_pool_cache_t *c, u64 *allocated, u64 *remote_pending, u64 *free)
{
  u32 i, j, n_subpools;

  *allocated = 0;
  *remote_pending = 0;
  *free = 0;

  n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  for (i = 0; i < n_subpools; i++)
    {
      vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, i);

      for (j = 0; j < c->subpool_size; j++)
	{
	  switch (clib_atomic_load_acq_n (&sp->slot_state[j]))
	    {
	    case VLIB_POOL_CACHE_SLOT_ALLOCATED:
	      (*allocated)++;
	      break;
	    case VLIB_POOL_CACHE_SLOT_REMOTE_PENDING:
	      (*remote_pending)++;
	      break;
	    case VLIB_POOL_CACHE_SLOT_FREE:
	    default:
	      (*free)++;
	      break;
	    }
	}
    }
}

static u32
vlib_pool_cache_count_remote_free_pending (vlib_pool_cache_t *c, vlib_pool_cache_subpool_meta_t *sp)
{
  u32 head, n = 0;

  head = clib_atomic_load_acq_n (&sp->remote_head);
  while (head != VLIB_POOL_CACHE_INVALID_INDEX && head < c->subpool_size && n < c->subpool_size)
    {
      n++;
      head = clib_atomic_load_acq_n (&sp->remote_next[head]);
    }

  return n;
}

static void
vlib_pool_cache_format_summary_row (table_t *t, int row, vlib_pool_cache_t *c)
{
  u64 allocated, remote_pending, free;
  u32 n_subpools;
  int col = 0;

  n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  vlib_pool_cache_count_slots (c, &allocated, &remote_pending, &free);

  table_format_cell (t, row, col++, "%s", c->name);
  table_format_cell (t, row, col++, "%p", c);
  table_format_cell (t, row, col++, "%u", n_subpools);
  table_format_cell (t, row, col++, "%u", c->subpool_size);
  table_format_cell (t, row, col++, "%llu", allocated);
  table_format_cell (t, row, col++, "%llu", remote_pending);
  table_format_cell (t, row, col++, "%llu", free);
}

static u8 *
format_vlib_pool_cache_subpools (u8 *s, vlib_pool_cache_t *c)
{
  table_t table = {}, *t = &table;
  u32 i, n_subpools;

  if (c == 0)
    return s;

  n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  table_add_hdr_row (t, 4, "subpool", "owner", "has-free-entries", "remote-pending");
  for (i = 0; i < n_subpools; i++)
    {
      vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (c, i);
      u32 owner = clib_atomic_load_acq_n (&sp->owner_thread_index);
      u32 n_remote_pending = vlib_pool_cache_count_remote_free_pending (c, sp);
      u8 on_owner_free_list = clib_atomic_load_acq_n (&sp->on_owner_free_list);
      int col = 0;

      table_format_cell (t, i, col++, "%u", i);
      table_format_cell (t, i, col++, "%u", owner);
      table_format_cell (t, i, col++, on_owner_free_list ? "yes" : "no");
      table_format_cell (t, i, col++, "%u", n_remote_pending);
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

  table_add_hdr_row (t, 7, "Name", "Address", "Subpools", "SubpoolSize", "Allocated",
		     "RemotePending", "Free");
  vlib_pool_cache_format_summary_row (t, 0, c);
  s = format (s, "%U", format_table, t);
  table_free (t);

  if (verbose)
    s = format_vlib_pool_cache_subpools (s, c);

  return s;
}

void
vlib_pool_cache_register_instance (vlib_pool_cache_t *c,
				   vlib_pool_cache_registration_t *registration, char *name)
{
  vlib_pool_cache_main_t *pcm = &vlib_pool_cache_main;

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
  vlib_pool_cache_main_t *pcm = &vlib_pool_cache_main;

  if (c->registration == 0)
    return;

  VLIB_REMOVE_FROM_LINKED_LIST (pcm->instances, c, next_instance);
  c->registration = 0;
  c->name = 0;
  c->next_instance = 0;
}

void
vlib_pool_cache_init_state (vlib_pool_cache_t *c, u32 log2_subpool_size, u32 align)
{
  vlib_pool_cache_thread_t *pt;
  u32 n_threads;

  clib_memset (c, 0, sizeof (*c));
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

static clib_error_t *
show_pool_cache_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_pool_cache_main_t *pcm = &vlib_pool_cache_main;
  vlib_pool_cache_t *c;
  vlib_pool_cache_t **verbose_caches = 0;
  char *name = 0;
  char *parsed_name = 0;
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
      else if (unformat (input, "name %s", &parsed_name))
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
      else if (unformat (input, "%s", &parsed_name))
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

  table_add_hdr_row (t, 7, "Name", "Address", "Subpools", "SubpoolSize", "Allocated",
		     "RemotePending", "Free");
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
	  s = format_vlib_pool_cache_subpools (s, *cp);
	}
    }

  vlib_cli_output (vm, "%v", s);
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
