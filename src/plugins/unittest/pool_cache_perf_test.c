/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define POOL_CACHE_PERF_DEFAULT_ROUNDS		  100000
#define POOL_CACHE_PERF_DEFAULT_BATCH_SIZE	  256
#define POOL_CACHE_PERF_DEFAULT_WARMUP_ROUNDS	  1000
#define POOL_CACHE_PERF_DEFAULT_SAMPLES		  5
#define POOL_CACHE_PERF_DEFAULT_LOG2_SUBPOOL_SIZE 12
#define POOL_CACHE_PERF_WORKER_TIMEOUT		  30.0
#define POOL_CACHE_PERF_MAIN_TIMEOUT		  600.0

typedef enum
{
  POOL_CACHE_PERF_MODE_LOCAL = 1 << 0,
  POOL_CACHE_PERF_MODE_REFILL = 1 << 1,
  POOL_CACHE_PERF_MODE_RING = 1 << 2,
  POOL_CACHE_PERF_MODE_MANY_TO_ONE = 1 << 3,
  POOL_CACHE_PERF_MODE_OVERLAP = 1 << 4,
  POOL_CACHE_PERF_MODE_ALL = POOL_CACHE_PERF_MODE_LOCAL | POOL_CACHE_PERF_MODE_REFILL |
			     POOL_CACHE_PERF_MODE_RING | POOL_CACHE_PERF_MODE_MANY_TO_ONE |
			     POOL_CACHE_PERF_MODE_OVERLAP,
} pool_cache_perf_mode_t;

typedef struct
{
  u64 opaque;
} pool_cache_perf_elt_t;

VLIB_POOL_CACHE_DEFINE (test_perf, pool_cache_perf_elt_t);

typedef struct
{
  test_perf_pool_cache_t pool;
  u32 active_mode;
  u32 rounds;
  u32 batch_size;
  u32 warmup_rounds;
  u32 samples;
  u32 log2_subpool_size;
  u32 n_workers;
  u64 run_id;
  int csv_fd;
  u8 *csv_filename;
  u32 *indices;
  u64 *sample_ticks;
  u64 *sample_ops;
  volatile u32 workers_done;
  volatile u32 phase_alloc_done;
  volatile u32 phase_free_done;
  volatile u32 phase_drain_done;
  volatile u32 overlap_round;
  volatile u32 errors;
} pool_cache_perf_main_t;

static pool_cache_perf_main_t pool_cache_perf_main;
static u64 pool_cache_perf_next_run_id;

static clib_error_t *
pool_cache_perf_write_all (int fd, u8 *s)
{
  uword n_left = vec_len (s);
  u8 *p = s;

  while (n_left > 0)
    {
      ssize_t n_written = write (fd, p, n_left);

      if (n_written < 0)
	{
	  if (errno == EINTR)
	    continue;
	  return clib_error_return_unix (0, "write pool-cache perf csv");
	}

      if (n_written == 0)
	return clib_error_return (0, "short write to pool-cache perf csv");

      p += n_written;
      n_left -= n_written;
    }

  return 0;
}

static clib_error_t *
pool_cache_perf_open_csv (pool_cache_perf_main_t *ptm)
{
  static const char csv_header[] =
    "run_id,pid,mode,workers,rounds,batch_size,warmup_rounds,samples,"
    "log2_subpool_size,sample,cpu_hz,total_ticks,max_ticks,total_ops,"
    "cycles_per_op,mops\n";
  clib_error_t *error;
  struct stat st;
  u8 *header = 0;

  ptm->csv_fd =
    open ((char *) ptm->csv_filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (ptm->csv_fd < 0)
    return clib_error_return_unix (0, "open `%s'", ptm->csv_filename);

  if (fstat (ptm->csv_fd, &st) < 0)
    return clib_error_return_unix (0, "stat `%s'", ptm->csv_filename);

  if (st.st_size != 0)
    return 0;

  vec_add (header, csv_header, sizeof (csv_header) - 1);
  error = pool_cache_perf_write_all (ptm->csv_fd, header);
  vec_free (header);
  return error;
}

static const char *
pool_cache_perf_mode_name (u32 mode)
{
  switch (mode)
    {
    case POOL_CACHE_PERF_MODE_LOCAL:
      return "local";
    case POOL_CACHE_PERF_MODE_REFILL:
      return "refill";
    case POOL_CACHE_PERF_MODE_RING:
      return "ring";
    case POOL_CACHE_PERF_MODE_MANY_TO_ONE:
      return "many-to-one";
    case POOL_CACHE_PERF_MODE_OVERLAP:
      return "overlap";
    default:
      return "unknown";
    }
}

static_always_inline void
pool_cache_perf_error (pool_cache_perf_main_t *ptm)
{
  clib_atomic_fetch_add_rel (&ptm->errors, 1);
}

static_always_inline int
pool_cache_perf_wait_for_phase (vlib_main_t *vm, pool_cache_perf_main_t *ptm, volatile u32 *counter,
				u32 target)
{
  f64 deadline = vlib_time_now (vm) + POOL_CACHE_PERF_WORKER_TIMEOUT;

  while (clib_atomic_load_acq_n (counter) < target)
    {
      if (PREDICT_FALSE (vlib_time_now (vm) > deadline))
	{
	  pool_cache_perf_error (ptm);
	  return 0;
	}
      CLIB_PAUSE ();
    }
  return 1;
}

static_always_inline void
pool_cache_perf_drain_remote (pool_cache_perf_main_t *ptm, u32 thread_index)
{
  vlib_pool_cache_thread_t *pt = vec_elt_at_index (ptm->pool.state.per_thread, thread_index);

  test_perf_pool_cache_drain_remote_ (&ptm->pool, pt, thread_index);
}

static_always_inline void
pool_cache_perf_alloc_batch (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_elts)
{
  u32 i;

  for (i = 0; i < n_elts; i++)
    indices[i] = test_perf_pool_cache_alloc (&ptm->pool);
}

static_always_inline void
pool_cache_perf_free_batch (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_elts)
{
  u32 i;

  for (i = 0; i < n_elts; i++)
    test_perf_pool_cache_free (&ptm->pool, indices[i]);
}

static_always_inline void
pool_cache_perf_free_range (pool_cache_perf_main_t *ptm, u32 *indices, u32 start, u32 end)
{
  u32 i;

  for (i = start; i < end; i++)
    test_perf_pool_cache_free (&ptm->pool, indices[i]);
}

static clib_error_t *
pool_cache_perf_probe_generated_api (pool_cache_perf_main_t *ptm)
{
  pool_cache_perf_elt_t *e;
  u32 idx;

  idx = test_perf_pool_cache_alloc (&ptm->pool);
  e = test_perf_pool_cache_elt_at_index (&ptm->pool, idx);
  e->opaque = idx;

  if (test_perf_pool_cache_is_free_index (&ptm->pool, idx))
    return clib_error_return (0, "allocated probe index reports free");

  test_perf_pool_cache_free (&ptm->pool, idx);

  if (!test_perf_pool_cache_is_free_index (&ptm->pool, idx))
    return clib_error_return (0, "freed probe index reports allocated");

  return 0;
}

static_always_inline u64
pool_cache_perf_local_or_refill_loop (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_rounds)
{
  u32 i;

  for (i = 0; i < n_rounds; i++)
    {
      pool_cache_perf_alloc_batch (ptm, indices, ptm->batch_size);
      pool_cache_perf_free_batch (ptm, indices, ptm->batch_size);
    }

  return (u64) n_rounds * ptm->batch_size * 2;
}

static_always_inline void
pool_cache_perf_run_local_or_refill_sample (pool_cache_perf_main_t *ptm, u32 worker_index,
					    int keep_anchor)
{
  u32 *indices = ptm->indices + worker_index * ptm->batch_size;
  u32 anchor = 0;
  u64 t0, t1;

  /* The local hot-path benchmark keeps one owned element live so each round
   * does not empty the subpool and measure empty-depot lock traffic instead. */
  if (keep_anchor)
    anchor = test_perf_pool_cache_alloc (&ptm->pool);

  pool_cache_perf_local_or_refill_loop (ptm, indices, ptm->warmup_rounds);

  t0 = clib_cpu_time_now ();
  ptm->sample_ops[worker_index] = pool_cache_perf_local_or_refill_loop (ptm, indices, ptm->rounds);
  t1 = clib_cpu_time_now ();

  ptm->sample_ticks[worker_index] = t1 - t0;

  if (keep_anchor)
    test_perf_pool_cache_free (&ptm->pool, anchor);
}

static_always_inline int
pool_cache_perf_ring_iteration (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index,
				u32 source_worker_index, u32 *alloc_target, u32 *free_target,
				u32 *drain_target)
{
  u32 *own_indices = ptm->indices + worker_index * ptm->batch_size;
  u32 *source_indices = ptm->indices + source_worker_index * ptm->batch_size;
  u32 thread_index = vlib_get_thread_index ();

  pool_cache_perf_alloc_batch (ptm, own_indices, ptm->batch_size);
  *alloc_target += ptm->n_workers;
  clib_atomic_fetch_add_rel (&ptm->phase_alloc_done, 1);
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_alloc_done, *alloc_target))
    return 0;

  pool_cache_perf_free_batch (ptm, source_indices, ptm->batch_size);
  *free_target += ptm->n_workers;
  clib_atomic_fetch_add_rel (&ptm->phase_free_done, 1);
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_free_done, *free_target))
    return 0;

  pool_cache_perf_drain_remote (ptm, thread_index);
  *drain_target += ptm->n_workers;
  clib_atomic_fetch_add_rel (&ptm->phase_drain_done, 1);
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_drain_done, *drain_target))
    return 0;

  return 1;
}

static void
pool_cache_perf_run_ring_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index)
{
  u32 source_worker_index = worker_index ? worker_index - 1 : ptm->n_workers - 1;
  u32 alloc_target = 0, free_target = 0, drain_target = 0;
  u32 anchor, i;
  u64 t0, t1;

  anchor = test_perf_pool_cache_alloc (&ptm->pool);

  for (i = 0; i < ptm->warmup_rounds; i++)
    if (!pool_cache_perf_ring_iteration (vm, ptm, worker_index, source_worker_index, &alloc_target,
					 &free_target, &drain_target))
      goto done;

  t0 = clib_cpu_time_now ();
  for (i = 0; i < ptm->rounds; i++)
    if (!pool_cache_perf_ring_iteration (vm, ptm, worker_index, source_worker_index, &alloc_target,
					 &free_target, &drain_target))
      goto done;
  t1 = clib_cpu_time_now ();

  ptm->sample_ticks[worker_index] = t1 - t0;
  ptm->sample_ops[worker_index] = (u64) ptm->rounds * ptm->batch_size * 2;

done:
  test_perf_pool_cache_free (&ptm->pool, anchor);
}

static_always_inline int
pool_cache_perf_many_iteration (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index,
				u32 *alloc_target, u32 *free_target, u32 *drain_target)
{
  u32 total_elts = ptm->batch_size * ptm->n_workers;
  u32 *worker_indices = ptm->indices + worker_index * ptm->batch_size;

  if (worker_index == 0)
    {
      pool_cache_perf_alloc_batch (ptm, ptm->indices, total_elts);
      clib_atomic_fetch_add_rel (&ptm->phase_alloc_done, 1);
    }

  *alloc_target += 1;
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_alloc_done, *alloc_target))
    return 0;

  pool_cache_perf_free_batch (ptm, worker_indices, ptm->batch_size);
  *free_target += ptm->n_workers;
  clib_atomic_fetch_add_rel (&ptm->phase_free_done, 1);
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_free_done, *free_target))
    return 0;

  if (worker_index == 0)
    {
      pool_cache_perf_drain_remote (ptm, vlib_get_thread_index ());
      clib_atomic_fetch_add_rel (&ptm->phase_drain_done, 1);
    }

  *drain_target += 1;
  if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->phase_drain_done, *drain_target))
    return 0;

  return 1;
}

static void
pool_cache_perf_run_many_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index)
{
  u32 alloc_target = 0, free_target = 0, drain_target = 0;
  u32 total_elts = ptm->batch_size * ptm->n_workers;
  u32 anchor = 0, i;
  u64 t0, t1;

  if (worker_index == 0)
    anchor = test_perf_pool_cache_alloc (&ptm->pool);

  for (i = 0; i < ptm->warmup_rounds; i++)
    if (!pool_cache_perf_many_iteration (vm, ptm, worker_index, &alloc_target, &free_target,
					 &drain_target))
      goto done;

  t0 = clib_cpu_time_now ();
  for (i = 0; i < ptm->rounds; i++)
    if (!pool_cache_perf_many_iteration (vm, ptm, worker_index, &alloc_target, &free_target,
					 &drain_target))
      goto done;
  t1 = clib_cpu_time_now ();

  ptm->sample_ticks[worker_index] = t1 - t0;
  if (worker_index == 0)
    ptm->sample_ops[worker_index] = (u64) ptm->rounds * (total_elts + ptm->batch_size);
  else
    ptm->sample_ops[worker_index] = (u64) ptm->rounds * ptm->batch_size;

done:
  if (worker_index == 0)
    test_perf_pool_cache_free (&ptm->pool, anchor);
}

static_always_inline u64
pool_cache_perf_overlap_iteration (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index,
				   u32 *round_target, u32 *free_target)
{
  u32 *owner_indices = ptm->indices;
  u32 *scratch_indices = ptm->indices + (ptm->n_workers * ptm->batch_size);
  f64 deadline;
  u64 ops = 0;

  *round_target += 1;

  if (worker_index == 0)
    {
      pool_cache_perf_alloc_batch (ptm, owner_indices, ptm->batch_size);
      ops += ptm->batch_size;

      *free_target += ptm->n_workers - 1;
      clib_atomic_store_rel_n (&ptm->overlap_round, *round_target);

      deadline = vlib_time_now (vm) + POOL_CACHE_PERF_WORKER_TIMEOUT;
      while (clib_atomic_load_acq_n (&ptm->phase_free_done) < *free_target)
	{
	  if (PREDICT_FALSE (vlib_time_now (vm) > deadline))
	    {
	      pool_cache_perf_error (ptm);
	      return 0;
	    }

	  pool_cache_perf_alloc_batch (ptm, scratch_indices, ptm->batch_size);
	  pool_cache_perf_free_batch (ptm, scratch_indices, ptm->batch_size);
	  ops += (u64) ptm->batch_size * 2;
	}

      /* Drive any late pending remote frees through the public alloc path. */
      pool_cache_perf_alloc_batch (ptm, scratch_indices, ptm->batch_size);
      pool_cache_perf_free_batch (ptm, scratch_indices, ptm->batch_size);
      ops += (u64) ptm->batch_size * 2;
    }
  else
    {
      u32 start, end;

      if (!pool_cache_perf_wait_for_phase (vm, ptm, &ptm->overlap_round, *round_target))
	return 0;

      start = (ptm->batch_size * (worker_index - 1)) / (ptm->n_workers - 1);
      end = (ptm->batch_size * worker_index) / (ptm->n_workers - 1);
      pool_cache_perf_free_range (ptm, owner_indices, start, end);
      ops += end - start;

      clib_atomic_fetch_add_rel (&ptm->phase_free_done, 1);
    }

  return ops;
}

static void
pool_cache_perf_run_overlap_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 worker_index)
{
  u32 free_target = 0, round_target = 0, i;
  u64 ops = 0, t0, t1;

  for (i = 0; i < ptm->warmup_rounds; i++)
    if (!pool_cache_perf_overlap_iteration (vm, ptm, worker_index, &round_target, &free_target))
      goto done;

  t0 = clib_cpu_time_now ();
  for (i = 0; i < ptm->rounds; i++)
    {
      ops += pool_cache_perf_overlap_iteration (vm, ptm, worker_index, &round_target, &free_target);
      if (PREDICT_FALSE (clib_atomic_load_acq_n (&ptm->errors)))
	goto done;
    }
  t1 = clib_cpu_time_now ();

  ptm->sample_ticks[worker_index] = t1 - t0;
  ptm->sample_ops[worker_index] = ops;

done:
  return;
}

static uword
pool_cache_perf_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  CLIB_UNUSED (vlib_frame_t *frame))
{
  pool_cache_perf_main_t *ptm = &pool_cache_perf_main;
  u32 worker_index;

  if (vm->thread_index == 0)
    return 0;

  worker_index = vlib_get_current_worker_index ();

  switch (ptm->active_mode)
    {
    case POOL_CACHE_PERF_MODE_LOCAL:
      pool_cache_perf_run_local_or_refill_sample (ptm, worker_index, 1);
      break;
    case POOL_CACHE_PERF_MODE_REFILL:
      pool_cache_perf_run_local_or_refill_sample (ptm, worker_index, 0);
      break;
    case POOL_CACHE_PERF_MODE_RING:
      pool_cache_perf_run_ring_sample (vm, ptm, worker_index);
      break;
    case POOL_CACHE_PERF_MODE_MANY_TO_ONE:
      pool_cache_perf_run_many_sample (vm, ptm, worker_index);
      break;
    case POOL_CACHE_PERF_MODE_OVERLAP:
      pool_cache_perf_run_overlap_sample (vm, ptm, worker_index);
      break;
    default:
      pool_cache_perf_error (ptm);
      break;
    }

  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  clib_atomic_fetch_add_rel (&ptm->workers_done, 1);
  return 0;
}

VLIB_REGISTER_NODE (pool_cache_perf_input_node) = {
  .function = pool_cache_perf_input_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "pool-cache-perf-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
pool_cache_perf_report_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 sample,
			       u32 n_participants, u32 mode)
{
  u64 total_ticks = 0, max_ticks = 0, total_ops = 0;
  f64 cycles_per_op, mops;
  clib_error_t *error;
  u8 *line = 0;
  u32 i;

  for (i = 0; i < n_participants; i++)
    {
      total_ticks += ptm->sample_ticks[i];
      max_ticks = clib_max (max_ticks, ptm->sample_ticks[i]);
      total_ops += ptm->sample_ops[i];
    }

  cycles_per_op = total_ops ? (f64) total_ticks / (f64) total_ops : 0;
  mops =
    max_ticks ? ((f64) total_ops * vm->clib_time.clocks_per_second) / ((f64) max_ticks * 1e6) : 0;

  vlib_cli_output (vm, "  sample %u: %.03f cycles/op, %.03f Mops", sample + 1, cycles_per_op, mops);

  if (ptm->csv_fd < 0)
    return 0;

  line = format (line, "%llu,%u,%s,%u,%u,%u,%u,%u,%u,%u,%.0f,%llu,%llu,%llu,%.6f,%.6f\n",
		 (unsigned long long) ptm->run_id, (u32) getpid (),
		 pool_cache_perf_mode_name (mode), ptm->n_workers, ptm->rounds,
		 ptm->batch_size, ptm->warmup_rounds, ptm->samples, ptm->log2_subpool_size,
		 sample + 1, vm->clib_time.clocks_per_second,
		 (unsigned long long) total_ticks, (unsigned long long) max_ticks,
		 (unsigned long long) total_ops, cycles_per_op, mops);
  error = pool_cache_perf_write_all (ptm->csv_fd, line);
  vec_free (line);
  return error;
}

static clib_error_t *
pool_cache_perf_prepare_storage (pool_cache_perf_main_t *ptm, u32 n_participants,
				 u32 n_index_batches)
{
  u64 n_indices = (u64) n_index_batches * ptm->batch_size;

  if (n_indices > (u64) (u32) ~0)
    return clib_error_return (0, "too many benchmark indices");

  vec_validate_aligned (ptm->indices, n_indices - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ptm->sample_ticks, n_participants - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ptm->sample_ops, n_participants - 1, CLIB_CACHE_LINE_BYTES);
  return 0;
}

static clib_error_t *
pool_cache_perf_run_worker_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 mode)
{
  clib_error_t *error = 0;
  f64 deadline;
  u32 i;

  ptm->active_mode = mode;
  clib_atomic_store_rel_n (&ptm->workers_done, 0);
  clib_atomic_store_rel_n (&ptm->phase_alloc_done, 0);
  clib_atomic_store_rel_n (&ptm->phase_free_done, 0);
  clib_atomic_store_rel_n (&ptm->phase_drain_done, 0);
  clib_atomic_store_rel_n (&ptm->overlap_round, 0);
  clib_atomic_store_rel_n (&ptm->errors, 0);
  clib_memset (ptm->sample_ticks, 0, vec_len (ptm->sample_ticks) * sizeof (ptm->sample_ticks[0]));
  clib_memset (ptm->sample_ops, 0, vec_len (ptm->sample_ops) * sizeof (ptm->sample_ops[0]));

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index != 0)
	vlib_node_set_state (this_vlib_main, pool_cache_perf_input_node.index,
			     VLIB_NODE_STATE_INTERRUPT);
    }
  vlib_worker_thread_barrier_release (vm);

  for (i = 1; i <= ptm->n_workers; i++)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), pool_cache_perf_input_node.index);

  deadline = vlib_time_now (vm) + POOL_CACHE_PERF_MAIN_TIMEOUT;
  while (clib_atomic_load_acq_n (&ptm->workers_done) < ptm->n_workers)
    {
      if (vlib_time_now (vm) > deadline)
	{
	  error = clib_error_return (0, "pool-cache perf worker timeout");
	  break;
	}
      vlib_process_suspend (vm, 1e-4);
    }

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index == 0)
	continue;
      vlib_node_set_state (this_vlib_main, pool_cache_perf_input_node.index,
			   VLIB_NODE_STATE_DISABLED);
    }
  vlib_worker_thread_barrier_release (vm);

  if (error == 0 && clib_atomic_load_acq_n (&ptm->errors))
    error = clib_error_return (0, "pool-cache perf saw %u worker errors", ptm->errors);

  return error;
}

static void
pool_cache_perf_run_main_sample (pool_cache_perf_main_t *ptm, u32 mode)
{
  clib_memset (ptm->sample_ticks, 0, vec_len (ptm->sample_ticks) * sizeof (ptm->sample_ticks[0]));
  clib_memset (ptm->sample_ops, 0, vec_len (ptm->sample_ops) * sizeof (ptm->sample_ops[0]));

  pool_cache_perf_run_local_or_refill_sample (ptm, 0, mode == POOL_CACHE_PERF_MODE_LOCAL);
}

static clib_error_t *
pool_cache_perf_run_mode (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 mode)
{
  clib_error_t *error = 0;
  u32 n_participants, sample;

  if ((mode == POOL_CACHE_PERF_MODE_RING || mode == POOL_CACHE_PERF_MODE_MANY_TO_ONE ||
       mode == POOL_CACHE_PERF_MODE_OVERLAP) &&
      ptm->n_workers < 2)
    return clib_error_return (0, "mode %s requires at least two workers",
			      pool_cache_perf_mode_name (mode));

  n_participants = ptm->n_workers ? ptm->n_workers : 1;
  if ((error = pool_cache_perf_prepare_storage (
	 ptm, n_participants,
	 n_participants + (mode == POOL_CACHE_PERF_MODE_OVERLAP ? 1 : 0))))
    return error;

  test_perf_pool_cache_init (&ptm->pool, "pool-cache-perf", ptm->log2_subpool_size,
			     CLIB_CACHE_LINE_BYTES);
  if ((error = pool_cache_perf_probe_generated_api (ptm)))
    goto done;
  test_perf_pool_cache_free_resources (&ptm->pool);
  test_perf_pool_cache_init (&ptm->pool, "pool-cache-perf", ptm->log2_subpool_size,
			     CLIB_CACHE_LINE_BYTES);

  vlib_cli_output (vm,
		   "pool-cache perf: mode %s workers %u rounds %u batch-size %u "
		   "warmup-rounds %u samples %u log2-subpool-size %u",
		   pool_cache_perf_mode_name (mode), ptm->n_workers, ptm->rounds, ptm->batch_size,
		   ptm->warmup_rounds, ptm->samples, ptm->log2_subpool_size);
  vlib_cli_output (vm, "  cpu-freq %.02f GHz", (f64) vm->clib_time.clocks_per_second * 1e-9);

  for (sample = 0; sample < ptm->samples; sample++)
    {
      if (ptm->n_workers)
	error = pool_cache_perf_run_worker_sample (vm, ptm, mode);
      else
	pool_cache_perf_run_main_sample (ptm, mode);

      if (error)
	break;

      error = pool_cache_perf_report_sample (vm, ptm, sample, n_participants, mode);
      if (error)
	break;
    }

done:
  test_perf_pool_cache_free_resources (&ptm->pool);
  return error;
}

static clib_error_t *
pool_cache_perf_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    CLIB_UNUSED (vlib_cli_command_t *cmd))
{
  pool_cache_perf_main_t *ptm = &pool_cache_perf_main;
  clib_error_t *error = 0;
  u32 mode_flags = POOL_CACHE_PERF_MODE_ALL;
  u32 modes[] = {
    POOL_CACHE_PERF_MODE_LOCAL,
    POOL_CACHE_PERF_MODE_REFILL,
    POOL_CACHE_PERF_MODE_RING,
    POOL_CACHE_PERF_MODE_MANY_TO_ONE,
    POOL_CACHE_PERF_MODE_OVERLAP,
  };
  u32 i;

  clib_memset (ptm, 0, sizeof (*ptm));
  ptm->csv_fd = -1;
  ptm->run_id = ++pool_cache_perf_next_run_id;
  ptm->rounds = POOL_CACHE_PERF_DEFAULT_ROUNDS;
  ptm->batch_size = POOL_CACHE_PERF_DEFAULT_BATCH_SIZE;
  ptm->warmup_rounds = POOL_CACHE_PERF_DEFAULT_WARMUP_ROUNDS;
  ptm->samples = POOL_CACHE_PERF_DEFAULT_SAMPLES;
  ptm->log2_subpool_size = POOL_CACHE_PERF_DEFAULT_LOG2_SUBPOOL_SIZE;
  ptm->n_workers = vlib_num_workers ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mode local"))
	mode_flags = POOL_CACHE_PERF_MODE_LOCAL;
      else if (unformat (input, "mode refill"))
	mode_flags = POOL_CACHE_PERF_MODE_REFILL;
      else if (unformat (input, "mode ring"))
	mode_flags = POOL_CACHE_PERF_MODE_RING;
      else if (unformat (input, "mode many-to-one"))
	mode_flags = POOL_CACHE_PERF_MODE_MANY_TO_ONE;
      else if (unformat (input, "mode overlap"))
	mode_flags = POOL_CACHE_PERF_MODE_OVERLAP;
      else if (unformat (input, "mode all"))
	mode_flags = POOL_CACHE_PERF_MODE_ALL;
      else if (unformat (input, "rounds %u", &ptm->rounds))
	;
      else if (unformat (input, "batch-size %u", &ptm->batch_size))
	;
      else if (unformat (input, "warmup-rounds %u", &ptm->warmup_rounds))
	;
      else if (unformat (input, "samples %u", &ptm->samples))
	;
      else if (unformat (input, "log2-subpool-size %u", &ptm->log2_subpool_size))
	;
      else if (unformat (input, "csv %s", &ptm->csv_filename))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
	  goto done;
	}
    }

  if (ptm->rounds == 0 || ptm->batch_size == 0 || ptm->samples == 0)
    {
      error = clib_error_return (0, "rounds, batch-size, and samples must be non-zero");
      goto done;
    }

  if (ptm->log2_subpool_size == 0 || ptm->log2_subpool_size >= 32)
    {
      error = clib_error_return (0, "log2-subpool-size must be in the range 1..31");
      goto done;
    }

  if ((u64) clib_max (ptm->n_workers, 1) * ptm->batch_size > (u64) (u32) ~0)
    {
      error = clib_error_return (0, "too many benchmark indices");
      goto done;
    }

  if (ptm->csv_filename)
    {
      error = pool_cache_perf_open_csv (ptm);
      if (error)
	goto done;

      vlib_cli_output (vm, "pool-cache perf csv: %s", ptm->csv_filename);
    }

  for (i = 0; i < ARRAY_LEN (modes); i++)
    {
      if ((mode_flags & modes[i]) == 0)
	continue;

      error = pool_cache_perf_run_mode (vm, ptm, modes[i]);
      if (error)
	goto done;
    }

done:
  if (ptm->csv_fd >= 0)
    close (ptm->csv_fd);
  vec_free (ptm->indices);
  vec_free (ptm->sample_ticks);
  vec_free (ptm->sample_ops);
  vec_free (ptm->csv_filename);
  return error;
}

VLIB_CLI_COMMAND (pool_cache_perf_command, static) = {
  .path = "test pool-cache perf",
  .short_help = "test pool-cache perf [mode local|refill|ring|many-to-one|overlap|all] "
		"[rounds <n>] [batch-size <n>] [warmup-rounds <n>] "
		"[samples <n>] [log2-subpool-size <n>] [csv <filename>]",
  .function = pool_cache_perf_command_fn,
  .is_mp_safe = 1,
};
