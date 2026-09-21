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
#define POOL_CACHE_PERF_DEFAULT_CACHE_BATCH_SIZE  256
#define POOL_CACHE_PERF_DEFAULT_WARMUP_ROUNDS	  1000
#define POOL_CACHE_PERF_DEFAULT_SAMPLES		  5
#define POOL_CACHE_PERF_DEFAULT_LOG2_SUBPOOL_SIZE 12
#define POOL_CACHE_PERF_MAIN_TIMEOUT		  600.0

/*
 * local
 *   Every participant repeatedly allocates one element and immediately frees
 *   it. After a non-zero warmup this measures only the per-thread linked-list
 *   push/pop path; the test fails if the measured loop refills or flushes.
 *
 * refill
 *   A single participant (the main thread without workers, worker 0 otherwise)
 *   allocates a complete batch and then frees it. This measures batched local
 *   list use and any global-list refill/flush it causes. A batch-size greater
 *   than twice cache-batch-size guarantees slow-path transfers every round.
 *
 * contended
 *   Every worker runs the refill workload concurrently, without per-round
 *   barriers. It measures global-list lock contention when the selected batch
 *   and cache-batch sizes cause refill/flush transfers. At least two workers
 *   are required.
 *
 * growth
 *   Starting from an empty cache, every participant allocates and frees one
 *   batch. It includes backing-chunk allocation, slot/link metadata setup, and
 *   publication of the new chain on the global free list. Each sample uses a
 *   newly initialized cache and has no warmup.
 *
 * all
 *   Runs local, refill, contended, and growth in that order. Each mode gets a
 *   newly initialized cache.
 */
typedef enum
{
  POOL_CACHE_PERF_MODE_LOCAL = 1 << 0,
  POOL_CACHE_PERF_MODE_REFILL = 1 << 1,
  POOL_CACHE_PERF_MODE_CONTENDED = 1 << 2,
  POOL_CACHE_PERF_MODE_GROWTH = 1 << 3,
  POOL_CACHE_PERF_MODE_ALL = POOL_CACHE_PERF_MODE_LOCAL | POOL_CACHE_PERF_MODE_REFILL |
			     POOL_CACHE_PERF_MODE_CONTENDED | POOL_CACHE_PERF_MODE_GROWTH,
} pool_cache_perf_mode_t;

typedef struct
{
  u64 opaque;
} pool_cache_perf_elt_t;

typedef struct
{
  vlib_pool_cache_t pool;
  u32 active_mode;
  u32 rounds;
  u32 batch_size;
  u32 cache_batch_size;
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
  volatile u32 errors;
} pool_cache_perf_main_t;

static pool_cache_perf_main_t pool_cache_perf_main;
static volatile u32 pool_cache_perf_test_command_active;
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
    "run_id,pid,mode,workers,rounds,batch_size,cache_batch_size,"
    "warmup_rounds,samples,log2_subpool_size,sample,cpu_hz,total_ticks,"
    "max_ticks,total_ops,cycles_per_op,mops,refills,flushes,global_locks,growths\n";
  clib_error_t *error;
  struct stat st;
  u8 *header = 0;
  char existing_header[sizeof (csv_header) - 1];
  ssize_t n_read;

  ptm->csv_fd = open ((char *) ptm->csv_filename, O_RDWR | O_CREAT | O_APPEND, 0644);
  if (ptm->csv_fd < 0)
    return clib_error_return_unix (0, "open `%s'", ptm->csv_filename);

  if (fstat (ptm->csv_fd, &st) < 0)
    {
      error = clib_error_return_unix (0, "stat `%s'", ptm->csv_filename);
      close (ptm->csv_fd);
      ptm->csv_fd = -1;
      return error;
    }

  if (st.st_size != 0)
    {
      n_read = pread (ptm->csv_fd, existing_header, sizeof (existing_header), 0);
      if (n_read != sizeof (existing_header) ||
	  memcmp (existing_header, csv_header, sizeof (existing_header)) != 0)
	{
	  close (ptm->csv_fd);
	  ptm->csv_fd = -1;
	  return clib_error_return (0,
				    "refusing to append pool-cache results to `%s': "
				    "incompatible CSV header",
				    ptm->csv_filename);
	}
      return 0;
    }

  vec_add (header, csv_header, sizeof (csv_header) - 1);
  error = pool_cache_perf_write_all (ptm->csv_fd, header);
  vec_free (header);
  if (error)
    {
      close (ptm->csv_fd);
      ptm->csv_fd = -1;
    }
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
    case POOL_CACHE_PERF_MODE_CONTENDED:
      return "contended";
    case POOL_CACHE_PERF_MODE_GROWTH:
      return "growth";
    default:
      return "unknown";
    }
}

static_always_inline void
pool_cache_perf_error (pool_cache_perf_main_t *ptm)
{
  clib_atomic_fetch_add_rel (&ptm->errors, 1);
}

static_always_inline void
pool_cache_perf_alloc_batch (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_elts)
{
  u32 i;

  for (i = 0; i < n_elts; i++)
    indices[i] = pool_cache_get_index (&ptm->pool);
}

static_always_inline void
pool_cache_perf_free_batch (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_elts)
{
  u32 i;

  for (i = 0; i < n_elts; i++)
    pool_cache_put_index (&ptm->pool, indices[i]);
}

static clib_error_t *
pool_cache_perf_probe_api (pool_cache_perf_main_t *ptm)
{
  pool_cache_perf_elt_t *e;
  u32 idx;

  idx = pool_cache_get (&ptm->pool, e);
  e->opaque = idx;

  if (pool_cache_is_free_index (&ptm->pool, idx))
    return clib_error_return (0, "allocated probe index reports free");

  pool_cache_put_index (&ptm->pool, idx);

  if (!pool_cache_is_free_index (&ptm->pool, idx))
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

static_always_inline u64
pool_cache_perf_local_loop (pool_cache_perf_main_t *ptm, u32 *indices, u32 n_rounds)
{
  u32 i, j;

  for (i = 0; i < n_rounds; i++)
    for (j = 0; j < ptm->batch_size; j++)
      {
	indices[j] = pool_cache_get_index (&ptm->pool);
	pool_cache_put_index (&ptm->pool, indices[j]);
      }

  return (u64) n_rounds * ptm->batch_size * 2;
}

static_always_inline void
pool_cache_perf_run_local_or_refill_sample (pool_cache_perf_main_t *ptm, u32 worker_index,
					    int local_only)
{
  u32 *indices = ptm->indices + worker_index * ptm->batch_size;
  vlib_pool_cache_thread_t *cache =
    vec_elt_at_index (ptm->pool.per_thread, vlib_get_thread_index ());
  u64 refills_before, flushes_before;
  u64 t0, t1;

  if (local_only)
    pool_cache_perf_local_loop (ptm, indices, ptm->warmup_rounds);
  else
    pool_cache_perf_local_or_refill_loop (ptm, indices, ptm->warmup_rounds);

  refills_before = clib_atomic_load_acq_n (&cache->refills);
  flushes_before = clib_atomic_load_acq_n (&cache->flushes);

  t0 = clib_cpu_time_now ();
  if (local_only)
    ptm->sample_ops[worker_index] = pool_cache_perf_local_loop (ptm, indices, ptm->rounds);
  else
    ptm->sample_ops[worker_index] =
      pool_cache_perf_local_or_refill_loop (ptm, indices, ptm->rounds);
  t1 = clib_cpu_time_now ();

  ptm->sample_ticks[worker_index] = t1 - t0;
  if (local_only && (refills_before != clib_atomic_load_acq_n (&cache->refills) ||
		     flushes_before != clib_atomic_load_acq_n (&cache->flushes)))
    pool_cache_perf_error (ptm);
}

static void
pool_cache_perf_run_growth_sample (pool_cache_perf_main_t *ptm, u32 worker_index)
{
  u32 *indices = ptm->indices + worker_index * ptm->batch_size;
  u64 t0, t1;

  t0 = clib_cpu_time_now ();
  pool_cache_perf_alloc_batch (ptm, indices, ptm->batch_size);
  pool_cache_perf_free_batch (ptm, indices, ptm->batch_size);
  t1 = clib_cpu_time_now ();
  ptm->sample_ticks[worker_index] = t1 - t0;
  ptm->sample_ops[worker_index] = (u64) ptm->batch_size * 2;
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
      if (worker_index == 0)
	pool_cache_perf_run_local_or_refill_sample (ptm, worker_index, 0);
      break;
    case POOL_CACHE_PERF_MODE_CONTENDED:
      pool_cache_perf_run_local_or_refill_sample (ptm, worker_index, 0);
      break;
    case POOL_CACHE_PERF_MODE_GROWTH:
      pool_cache_perf_run_growth_sample (ptm, worker_index);
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

static void
pool_cache_perf_reset_sample_counters (pool_cache_perf_main_t *ptm)
{
  vlib_pool_cache_thread_t *pt;

  vec_foreach (pt, ptm->pool.per_thread)
    {
      clib_atomic_store_rel_n (&pt->refills, 0);
      clib_atomic_store_rel_n (&pt->flushes, 0);
    }
  clib_atomic_store_rel_n (&ptm->pool.global_lock_acquisitions, 0);
  clib_atomic_store_rel_n (&ptm->pool.growths, 0);
}

static clib_error_t *
pool_cache_perf_report_sample (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 sample,
			       u32 n_participants, u32 mode)
{
  u64 total_ticks = 0, max_ticks = 0, total_ops = 0;
  u64 refills = 0, flushes = 0;
  vlib_pool_cache_thread_t *pt;
  f64 cycles_per_op, mops;
  clib_error_t *error;
  u8 *line = 0;
  u32 csv_rounds = mode == POOL_CACHE_PERF_MODE_GROWTH ? 1 : ptm->rounds;
  u32 csv_warmup = mode == POOL_CACHE_PERF_MODE_GROWTH ? 0 : ptm->warmup_rounds;
  u32 i;

  for (i = 0; i < n_participants; i++)
    {
      total_ticks += ptm->sample_ticks[i];
      max_ticks = clib_max (max_ticks, ptm->sample_ticks[i]);
      total_ops += ptm->sample_ops[i];
    }

  vec_foreach (pt, ptm->pool.per_thread)
    {
      refills += clib_atomic_load_acq_n (&pt->refills);
      flushes += clib_atomic_load_acq_n (&pt->flushes);
    }

  cycles_per_op = total_ops ? (f64) total_ticks / (f64) total_ops : 0;
  mops =
    max_ticks ? ((f64) total_ops * vm->clib_time.clocks_per_second) / ((f64) max_ticks * 1e6) : 0;

  vlib_cli_output (vm, "  sample %u: %.03f cycles/op, %.03f Mops", sample + 1, cycles_per_op, mops);

  if (ptm->csv_fd < 0)
    return 0;

  line = format (
    line, "%llu,%u,%s,%u,%u,%u,%u,%u,%u,%u,%u,%.0f,%llu,%llu,%llu,%.6f,%.6f,%llu,%llu,%llu,%llu\n",
    (unsigned long long) ptm->run_id, (u32) getpid (), pool_cache_perf_mode_name (mode),
    ptm->n_workers, csv_rounds, ptm->batch_size, ptm->cache_batch_size, csv_warmup, ptm->samples,
    ptm->log2_subpool_size, sample + 1, vm->clib_time.clocks_per_second,
    (unsigned long long) total_ticks, (unsigned long long) max_ticks,
    (unsigned long long) total_ops, cycles_per_op, mops, (unsigned long long) refills,
    (unsigned long long) flushes,
    (unsigned long long) clib_atomic_load_acq_n (&ptm->pool.global_lock_acquisitions),
    (unsigned long long) clib_atomic_load_acq_n (&ptm->pool.growths));
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

static clib_error_t *
pool_cache_perf_run_main_sample (pool_cache_perf_main_t *ptm, u32 mode)
{
  u32 errors;

  clib_atomic_store_rel_n (&ptm->errors, 0);
  clib_memset (ptm->sample_ticks, 0, vec_len (ptm->sample_ticks) * sizeof (ptm->sample_ticks[0]));
  clib_memset (ptm->sample_ops, 0, vec_len (ptm->sample_ops) * sizeof (ptm->sample_ops[0]));

  if (mode == POOL_CACHE_PERF_MODE_GROWTH)
    pool_cache_perf_run_growth_sample (ptm, 0);
  else
    pool_cache_perf_run_local_or_refill_sample (ptm, 0, mode == POOL_CACHE_PERF_MODE_LOCAL);

  errors = clib_atomic_load_acq_n (&ptm->errors);
  if (errors)
    return clib_error_return (0, "pool-cache perf saw %u main-thread errors", errors);

  return 0;
}

static clib_error_t *
pool_cache_perf_run_mode (vlib_main_t *vm, pool_cache_perf_main_t *ptm, u32 mode)
{
  clib_error_t *error = 0;
  u32 n_participants, sample;

  if (mode == POOL_CACHE_PERF_MODE_CONTENDED && ptm->n_workers < 2)
    return clib_error_return (0, "mode %s requires at least two workers",
			      pool_cache_perf_mode_name (mode));

  n_participants = ptm->n_workers ? ptm->n_workers : 1;
  if (mode == POOL_CACHE_PERF_MODE_REFILL)
    n_participants = 1;
  if ((error = pool_cache_perf_prepare_storage (ptm, n_participants, n_participants)))
    return error;

  pool_cache_init_with_batch (&ptm->pool, "pool-cache-perf", 0, ptm->log2_subpool_size,
			      CLIB_CACHE_LINE_BYTES, ptm->cache_batch_size, pool_cache_perf_elt_t);
  if ((error = pool_cache_perf_probe_api (ptm)))
    goto done;
  pool_cache_free (&ptm->pool);
  pool_cache_init_with_batch (&ptm->pool, "pool-cache-perf", 0, ptm->log2_subpool_size,
			      CLIB_CACHE_LINE_BYTES, ptm->cache_batch_size, pool_cache_perf_elt_t);

  vlib_cli_output (vm,
		   "pool-cache perf: mode %s workers %u rounds %u batch-size %u "
		   "cache-batch-size %u warmup-rounds %u samples %u log2-subpool-size %u",
		   pool_cache_perf_mode_name (mode), ptm->n_workers, ptm->rounds, ptm->batch_size,
		   ptm->cache_batch_size, ptm->warmup_rounds, ptm->samples, ptm->log2_subpool_size);
  vlib_cli_output (vm, "  cpu-freq %.02f GHz", (f64) vm->clib_time.clocks_per_second * 1e-9);

  for (sample = 0; sample < ptm->samples; sample++)
    {
      /* The reported slow-path counters belong to this sample (including its
	 warmup), rather than accumulating across the full command. */
      pool_cache_perf_reset_sample_counters (ptm);

      if (ptm->n_workers)
	error = pool_cache_perf_run_worker_sample (vm, ptm, mode);
      else
	error = pool_cache_perf_run_main_sample (ptm, mode);

      if (error)
	break;

      error = pool_cache_perf_report_sample (vm, ptm, sample, n_participants, mode);
      if (error)
	break;

      if (mode == POOL_CACHE_PERF_MODE_GROWTH && sample + 1 < ptm->samples)
	{
	  pool_cache_free (&ptm->pool);
	  pool_cache_init_with_batch (&ptm->pool, "pool-cache-perf", 0, ptm->log2_subpool_size,
				      CLIB_CACHE_LINE_BYTES, ptm->cache_batch_size,
				      pool_cache_perf_elt_t);
	}
    }

done:
  pool_cache_free (&ptm->pool);
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
    POOL_CACHE_PERF_MODE_CONTENDED,
    POOL_CACHE_PERF_MODE_GROWTH,
  };
  u32 i;

  if (!clib_atomic_bool_cmp_and_swap (&pool_cache_perf_test_command_active, 0, 1))
    return clib_error_return (0, "pool cache perf test already running");

  clib_memset (ptm, 0, sizeof (*ptm));
  ptm->csv_fd = -1;
  ptm->run_id = ++pool_cache_perf_next_run_id;
  ptm->rounds = POOL_CACHE_PERF_DEFAULT_ROUNDS;
  ptm->batch_size = POOL_CACHE_PERF_DEFAULT_BATCH_SIZE;
  ptm->cache_batch_size = POOL_CACHE_PERF_DEFAULT_CACHE_BATCH_SIZE;
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
      else if (unformat (input, "mode contended"))
	mode_flags = POOL_CACHE_PERF_MODE_CONTENDED;
      else if (unformat (input, "mode growth"))
	mode_flags = POOL_CACHE_PERF_MODE_GROWTH;
      else if (unformat (input, "mode all"))
	mode_flags = POOL_CACHE_PERF_MODE_ALL;
      else if (unformat (input, "rounds %u", &ptm->rounds))
	;
      else if (unformat (input, "batch-size %u", &ptm->batch_size))
	;
      else if (unformat (input, "cache-batch-size %u", &ptm->cache_batch_size))
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

  if (ptm->rounds == 0 || ptm->batch_size == 0 || ptm->cache_batch_size == 0 || ptm->samples == 0)
    {
      error =
	clib_error_return (0, "rounds, batch-size, cache-batch-size, and samples must be non-zero");
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
  clib_atomic_store_rel_n (&pool_cache_perf_test_command_active, 0);
  return error;
}

VLIB_CLI_COMMAND (pool_cache_perf_command, static) = {
  .path = "test pool-cache-perf",
  .short_help = "test pool-cache-perf [mode local|refill|contended|growth|all] "
		"[rounds <n>] [batch-size <n>] [cache-batch-size <n>] [warmup-rounds <n>] "
		"[samples <n>] [log2-subpool-size <n>] [csv <filename>]",
  .function = pool_cache_perf_command_fn,
  .is_mp_safe = 1,
};
