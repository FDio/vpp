/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

static void
vlib_delayed_free_enqueue (clib_mem_heap_t *heap, void *p)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_delayed_free_entry_t *e;
  vlib_main_t *vm;

  /* With the barrier held all workers are parked at an iteration
   * boundary, so nobody can hold a stale reference and an immediate
   * free is safe (and avoids queue growth in barrier-heavy phases). */
  if (vlib_worker_thread_barrier_held ())
    {
      clib_mem_heap_free (heap, p);
      return;
    }

  /* Without the barrier, only the main thread may mutate mt-safe
   * structures. */
  ASSERT (vlib_get_thread_index () == 0);
  if (PREDICT_FALSE (vlib_get_thread_index () != 0))
    {
      /* Misuse; freeing immediately is no worse than pre-delayed-free
       * behavior. */
      clib_mem_heap_free (heap, p);
      return;
    }

  vm = vlib_get_main ();
  vec_add2 (vm->pending_frees, e, 1);
  e->ptr = p;
  e->heap = heap;
  vgm->delayed_free_main.n_enqueued += 1;
}

void
vlib_delayed_free_enable (vlib_main_t *vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_delayed_free_main_t *dfm = &vgm->delayed_free_main;

  vec_validate_init_empty (dfm->worker_last_seen_epochs, vlib_get_n_threads () - 1, 0);
  clib_mem_set_delayed_free_cb (vlib_delayed_free_enqueue);
}

void
vlib_delayed_free_process (vlib_main_t *vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_delayed_free_main_t *dfm = &vgm->delayed_free_main;
  u64 epoch, min_worker_epoch, reclaimed_epoch;
  u32 worker_index;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  /* Frees generated since the last iteration open a new epoch. */
  if (vec_len (vm->pending_frees))
    {
      clib_fifo_add1 (dfm->frees_by_epoch_fifo, vm->pending_frees);
      vm->pending_frees = 0;
      /* Release: pointer updates that made the parked memory
       * unreachable must be visible before workers see this epoch. */
      __atomic_store_n (&dfm->current_epoch, dfm->current_epoch + 1, __ATOMIC_RELEASE);
    }

  if (clib_fifo_elts (dfm->frees_by_epoch_fifo) == 0)
    return;

  /* Sample one worker per iteration, round-robin. */
  worker_index = (vm->main_loop_count % vlib_num_workers ()) + 1;
  epoch = __atomic_load_n (&vlib_get_main_by_index (worker_index)->local_epoch, __ATOMIC_ACQUIRE);
  dfm->worker_last_seen_epochs[worker_index] = epoch;
  min_worker_epoch = epoch;

  if (min_worker_epoch == dfm->last_known_safe_epoch)
    return;

  /* Minimum acknowledged epoch across all workers. */
  for (i = 1; i < vec_len (dfm->worker_last_seen_epochs); i++)
    {
      epoch = dfm->worker_last_seen_epochs[i];
      if ((i64) (min_worker_epoch - epoch) > 0)
	min_worker_epoch = epoch;
    }

  if (min_worker_epoch == dfm->last_known_safe_epoch)
    return;
  dfm->last_known_safe_epoch = min_worker_epoch;

  /* Free all epochs every worker has moved past. */
  reclaimed_epoch = dfm->current_epoch - clib_fifo_elts (dfm->frees_by_epoch_fifo);
  while ((i64) (min_worker_epoch - reclaimed_epoch) > 0)
    {
      vlib_delayed_free_entry_t *free_list, *e;

      clib_fifo_sub1 (dfm->frees_by_epoch_fifo, free_list);
      vec_foreach (e, free_list)
	clib_mem_heap_free (e->heap, e->ptr);
      dfm->n_freed += vec_len (free_list);
      vec_free (free_list);
      reclaimed_epoch += 1;
    }
}

static clib_error_t *
show_delayed_free_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_delayed_free_main_t *dfm = &vgm->delayed_free_main;
  vlib_delayed_free_entry_t **free_list;
  u64 n_pending = vec_len (vlib_get_main_by_index (0)->pending_frees);
  int i;

  clib_fifo_foreach (free_list, dfm->frees_by_epoch_fifo, { n_pending += vec_len (free_list[0]); });

  vlib_cli_output (vm, "current epoch: %lu", dfm->current_epoch);
  vlib_cli_output (vm, "last known safe epoch: %lu", dfm->last_known_safe_epoch);
  for (i = 1; i < vec_len (dfm->worker_last_seen_epochs); i++)
    vlib_cli_output (vm, "worker %d last seen epoch: %lu", i, dfm->worker_last_seen_epochs[i]);
  vlib_cli_output (vm, "pending frees: %lu (in %lu epochs)", n_pending,
		   clib_fifo_elts (dfm->frees_by_epoch_fifo));
  vlib_cli_output (vm, "total enqueued: %lu, total freed: %lu", dfm->n_enqueued, dfm->n_freed);
  return 0;
}

VLIB_CLI_COMMAND (show_delayed_free_command, static) = {
  .path = "show delayed-free",
  .short_help = "show delayed-free",
  .function = show_delayed_free_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
