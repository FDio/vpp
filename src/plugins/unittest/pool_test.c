/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Dave Barach
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>

#define POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE 5
#define POOL_CACHE_TEST_SUBPOOL_SIZE	  (1 << POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE)
/* Keep this intentionally off a subpool boundary so partial-list transitions
 * are exercised, not only full-subpool alloc/free cycles. */
#define POOL_CACHE_TEST_BATCH_SIZE (3 * POOL_CACHE_TEST_SUBPOOL_SIZE - 5)
#define POOL_CACHE_TEST_ROUNDS	   128
/* The overlap phase keeps worker 0 allocating while other workers publish
 * remote frees into worker 0's subpools. This stresses the public alloc-side
 * remote-drain path and the drain/requeue race, not just explicit drains. */
#define POOL_CACHE_TEST_OVERLAP_ROUNDS 64
#define POOL_CACHE_TEST_DRAIN_ATTEMPTS 64
#define POOL_CACHE_TEST_OVERLAP_BASE   0xfffe0000
#define POOL_CACHE_TEST_MANY_ROUND     0xfffffffd
#define POOL_CACHE_TEST_CROSS_ROUND    0xfffffffe
#define POOL_CACHE_TEST_DRAIN_ROUND    0xffffffff
#define POOL_CACHE_TEST_MAGIC	       0x51ced00d
#define POOL_CACHE_TEST_WORKER_TIMEOUT 5.0
#define POOL_CACHE_TEST_MAIN_TIMEOUT   15.0

typedef struct
{
  u32 thread_index;
  u32 round;
  u32 slot;
  u32 magic;
} pool_cache_test_elt_t;

VLIB_POOL_CACHE_DEFINE (test_mw, pool_cache_test_elt_t);

typedef struct
{
  test_mw_pool_cache_t pool;
  u32 *in_use_by_index;
  u32 *handoff_indices;
  u32 *many_to_one_indices;
  u32 *overlap_indices;
  volatile u32 workers_done;
  volatile u32 cross_alloc_done;
  volatile u32 cross_free_done;
  volatile u32 cross_drain_done;
  volatile u32 many_alloc_done;
  volatile u32 many_free_done;
  volatile u32 many_drain_done;
  volatile u32 overlap_round;
  volatile u32 overlap_free_done;
  volatile u32 overlap_owner_done;
  volatile u32 first_error_line;
  volatile u32 errors;
} pool_cache_test_main_t;

static pool_cache_test_main_t pool_cache_test_main;

static_always_inline void
pool_cache_test_error_at (pool_cache_test_main_t *ptm, u32 line)
{
  u32 expected = 0;
  clib_atomic_cmp_and_swap (&ptm->first_error_line, expected, line);
  clib_atomic_fetch_add_rel (&ptm->errors, 1);
}

#define pool_cache_test_error(ptm) pool_cache_test_error_at ((ptm), __LINE__)

static_always_inline int
pool_cache_test_wait_for_workers (vlib_main_t *vm, pool_cache_test_main_t *ptm,
				  volatile u32 *counter, u32 target)
{
  f64 deadline = vlib_time_now (vm) + POOL_CACHE_TEST_WORKER_TIMEOUT;

  /* Worker nodes cannot rely on the main test timeout while they are spinning
   * here, so each rendezvous has its own bounded wait. */
  while (clib_atomic_load_acq_n (counter) < target)
    {
      if (PREDICT_FALSE (vlib_time_now (vm) > deadline))
	{
	  pool_cache_test_error (ptm);
	  return 0;
	}
      CLIB_PAUSE ();
    }
  return 1;
}

static_always_inline u8
pool_cache_test_slot_state (pool_cache_test_main_t *ptm, u32 idx)
{
  u32 pidx = vlib_pool_cache_subpool_index (&ptm->pool.state, idx);
  u32 elt_index = vlib_pool_cache_elt_index (&ptm->pool.state, idx);
  vlib_pool_cache_subpool_meta_t *sp = vlib_pool_cache_subpool_meta_at (&ptm->pool.state, pidx);

  return clib_atomic_load_acq_n (&sp->slot_state[elt_index]);
}

static_always_inline void
pool_cache_test_drain_remote (pool_cache_test_main_t *ptm, u32 thread_index)
{
  vlib_pool_cache_thread_t *pt = vec_elt_at_index (ptm->pool.state.per_thread, thread_index);

  test_mw_pool_cache_drain_remote_ (&ptm->pool, pt, thread_index);
}

static_always_inline void
pool_cache_test_verify_state (pool_cache_test_main_t *ptm, u32 *indices, u32 start, u32 end,
			      u8 expected)
{
  u32 i;

  for (i = start; i < end; i++)
    if (PREDICT_FALSE (pool_cache_test_slot_state (ptm, indices[i]) != expected))
      pool_cache_test_error (ptm);
}

static_always_inline int
pool_cache_test_range_state_is (pool_cache_test_main_t *ptm, u32 *indices, u32 start, u32 end,
				u8 expected)
{
  u32 i;

  for (i = start; i < end; i++)
    if (pool_cache_test_slot_state (ptm, indices[i]) != expected)
      return 0;
  return 1;
}

static_always_inline void
pool_cache_test_alloc_batch (pool_cache_test_main_t *ptm, u32 thread_index, u32 round, u32 *indices)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  for (i = 0; i < POOL_CACHE_TEST_BATCH_SIZE; i++)
    {
      idx = test_mw_pool_cache_alloc (&ptm->pool);
      indices[i] = idx;

      if (PREDICT_FALSE (idx >= vec_len (ptm->in_use_by_index)))
	{
	  pool_cache_test_error (ptm);
	  continue;
	}

      /* This external bitmap catches duplicate live indices independently from
       * the allocator's internal slot-state checks. */
      if (PREDICT_FALSE (clib_atomic_bool_cmp_and_swap (&ptm->in_use_by_index[idx], 0, 1) == 0))
	pool_cache_test_error (ptm);

      if (PREDICT_FALSE (test_mw_pool_cache_is_free_index (&ptm->pool, idx)))
	pool_cache_test_error (ptm);

      e = test_mw_pool_cache_elt_at_index (&ptm->pool, idx);
      e->thread_index = thread_index;
      e->round = round;
      e->slot = i;
      e->magic = POOL_CACHE_TEST_MAGIC;
    }
}

static_always_inline void
pool_cache_test_free_range (pool_cache_test_main_t *ptm, u32 expected_thread_index, u32 round,
			    u32 *indices, u32 start, u32 end, int duplicate_first,
			    int clear_before_free)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  for (i = start; i < end; i++)
    {
      idx = indices[i];
      e = test_mw_pool_cache_elt_at_index (&ptm->pool, idx);

      if (PREDICT_FALSE (e->thread_index != expected_thread_index || e->round != round ||
			 e->slot != i || e->magic != POOL_CACHE_TEST_MAGIC))
	pool_cache_test_error (ptm);

      if (clear_before_free && idx < vec_len (ptm->in_use_by_index))
	clib_atomic_store_rel_n (&ptm->in_use_by_index[idx], 0);

      /* duplicate_first probes the checked free path without tripping the
       * public free wrapper's ASSERT on the intentional second free. */
      if (duplicate_first && i == start)
	{
	  if (PREDICT_FALSE (!test_mw_pool_cache_free_internal_ (&ptm->pool, idx)))
	    {
	      pool_cache_test_error (ptm);
	      continue;
	    }

	  if (PREDICT_FALSE (test_mw_pool_cache_free_internal_ (&ptm->pool, idx)))
	    pool_cache_test_error (ptm);
	}
      else
	test_mw_pool_cache_free (&ptm->pool, idx);

      if (!clear_before_free && idx < vec_len (ptm->in_use_by_index))
	clib_atomic_store_rel_n (&ptm->in_use_by_index[idx], 0);
    }
}

static_always_inline void
pool_cache_test_free_batch (pool_cache_test_main_t *ptm, u32 expected_thread_index, u32 round,
			    u32 *indices, int duplicate_first)
{
  pool_cache_test_free_range (ptm, expected_thread_index, round, indices, 0,
			      POOL_CACHE_TEST_BATCH_SIZE, duplicate_first, 0);
}

static uword
pool_cache_test_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  CLIB_UNUSED (vlib_frame_t *frame))
{
  pool_cache_test_main_t *ptm = &pool_cache_test_main;
  u32 *indices = 0;
  u32 round, thread_index, worker_index, source_worker_index;
  u32 source_thread_index, many_owner_thread_index, n_workers;
  u32 i, start, end;

  if (vm->thread_index == 0)
    return 0;

  thread_index = vlib_get_thread_index ();
  worker_index = vlib_get_current_worker_index ();
  n_workers = vlib_num_workers ();
  source_worker_index = worker_index ? worker_index - 1 : n_workers - 1;
  source_thread_index = vlib_get_worker_thread_index (source_worker_index);
  vec_validate (indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  /* Same-owner churn keeps the hot path busy and validates partial subpool
   * reuse before cross-thread frees are introduced. */
  for (round = 0; round < POOL_CACHE_TEST_ROUNDS; round++)
    {
      pool_cache_test_alloc_batch (ptm, thread_index, round, indices);
      pool_cache_test_free_batch (ptm, thread_index, round, indices, 0);
    }

  pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_CROSS_ROUND,
			       ptm->handoff_indices + worker_index * POOL_CACHE_TEST_BATCH_SIZE);
  clib_atomic_fetch_add_rel (&ptm->cross_alloc_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_alloc_done, n_workers))
    goto done;

  /* Ring handoff: each worker frees the previous worker's allocations. The
   * first free in each range also verifies duplicate remote frees are rejected. */
  pool_cache_test_free_batch (
    ptm, source_thread_index, POOL_CACHE_TEST_CROSS_ROUND,
    ptm->handoff_indices + source_worker_index * POOL_CACHE_TEST_BATCH_SIZE, 1);
  clib_atomic_fetch_add_rel (&ptm->cross_free_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_free_done, n_workers))
    goto done;

  /* Draining must make the exact handed-off indices free again. This prevents
   * the test from passing just because later allocation created new subpools. */
  pool_cache_test_drain_remote (ptm, thread_index);
  pool_cache_test_verify_state (ptm,
				ptm->handoff_indices + worker_index * POOL_CACHE_TEST_BATCH_SIZE, 0,
				POOL_CACHE_TEST_BATCH_SIZE, VLIB_POOL_CACHE_SLOT_FREE);
  clib_atomic_fetch_add_rel (&ptm->cross_drain_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_drain_done, n_workers))
    goto done;

  /* Many-to-one remote frees concentrate all workers on one owner's remote
   * stack, covering a different contention shape from the ring handoff. */
  if (worker_index == 0)
    {
      pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_MANY_ROUND,
				   ptm->many_to_one_indices);
      clib_atomic_fetch_add_rel (&ptm->many_alloc_done, 1);
    }

  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->many_alloc_done, 1))
    goto done;

  start = (POOL_CACHE_TEST_BATCH_SIZE * worker_index) / n_workers;
  end = (POOL_CACHE_TEST_BATCH_SIZE * (worker_index + 1)) / n_workers;
  /* The many-to-one owner is worker 0; derive its VPP thread index instead of
   * assuming a literal value. */
  many_owner_thread_index = vlib_get_worker_thread_index (0);
  pool_cache_test_free_range (ptm, many_owner_thread_index, POOL_CACHE_TEST_MANY_ROUND,
			      ptm->many_to_one_indices, start, end, 0, 0);
  clib_atomic_fetch_add_rel (&ptm->many_free_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->many_free_done, n_workers))
    goto done;

  if (worker_index == 0)
    {
      pool_cache_test_drain_remote (ptm, thread_index);
      pool_cache_test_verify_state (ptm, ptm->many_to_one_indices, 0, POOL_CACHE_TEST_BATCH_SIZE,
				    VLIB_POOL_CACHE_SLOT_FREE);
      clib_atomic_fetch_add_rel (&ptm->many_drain_done, 1);
    }

  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->many_drain_done, 1))
    goto done;

  if (n_workers == 1)
    goto final_cycle;

  /* Sustained-overlap remote-free test:
   *
   * Worker 0 owns the published batch. All other workers free disjoint slices
   * of that batch back to worker 0 while worker 0 keeps using the normal public
   * alloc/free API. That overlap is deliberate: alloc() must notice
   * remote_pending_subpools and drain remote frees, including the case where a
   * remote free arrives while the owner is already draining and must requeue the
   * subpool. Calling the internal drain helper here would miss that contract.
   */
  if (worker_index == 0)
    {
      u32 target;

      for (round = 0; round < POOL_CACHE_TEST_OVERLAP_ROUNDS; round++)
	{
	  pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
				       ptm->overlap_indices);
	  /* Release this round's owner batch to the remote freeing workers. */
	  clib_atomic_store_rel_n (&ptm->overlap_round, round + 1);
	  target = (round + 1) * (n_workers - 1);

	  /* Keep owner-side allocation active while remote workers are publishing
	   * frees into the same owner's subpools. */
	  while (clib_atomic_load_acq_n (&ptm->overlap_free_done) < target)
	    {
	      pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
					   indices);
	      pool_cache_test_free_batch (ptm, thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
					  indices, 0);
	    }

	  for (i = 0; i < POOL_CACHE_TEST_DRAIN_ATTEMPTS; i++)
	    {
	      if (pool_cache_test_range_state_is (ptm, ptm->overlap_indices, 0,
						  POOL_CACHE_TEST_BATCH_SIZE,
						  VLIB_POOL_CACHE_SLOT_FREE))
		break;

	      /* Drive any pending remote frees through public alloc(). The
	       * bound makes a lost notification show up as a test failure. */
	      pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
					   indices);
	      pool_cache_test_free_batch (ptm, thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
					  indices, 0);
	    }
	  pool_cache_test_verify_state (ptm, ptm->overlap_indices, 0, POOL_CACHE_TEST_BATCH_SIZE,
					VLIB_POOL_CACHE_SLOT_FREE);
	}
      clib_atomic_store_rel_n (&ptm->overlap_owner_done, 1);
    }
  else
    {
      u32 owner_thread_index = vlib_get_worker_thread_index (0);

      for (round = 0; round < POOL_CACHE_TEST_OVERLAP_ROUNDS; round++)
	{
	  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->overlap_round, round + 1))
	    goto done;

	  /* Split worker 0's published batch across all non-owner workers.
	   * clear_before_free drops the test bitmap before the remote free,
	   * so owner-side drain/reuse can legitimately race after publish. */
	  start = (POOL_CACHE_TEST_BATCH_SIZE * (worker_index - 1)) / (n_workers - 1);
	  end = (POOL_CACHE_TEST_BATCH_SIZE * worker_index) / (n_workers - 1);
	  pool_cache_test_free_range (ptm, owner_thread_index, POOL_CACHE_TEST_OVERLAP_BASE + round,
				      ptm->overlap_indices, start, end, 0, 1);
	  clib_atomic_fetch_add_rel (&ptm->overlap_free_done, 1);
	}

      if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->overlap_owner_done, 1))
	goto done;
    }

  /* Final local cycle proves that drained remote frees left the allocator in a
   * reusable state for the owner. */
final_cycle:
  pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_DRAIN_ROUND, indices);
  pool_cache_test_free_batch (ptm, thread_index, POOL_CACHE_TEST_DRAIN_ROUND, indices, 0);

done:
  vec_free (indices);
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  clib_atomic_fetch_add_rel (&ptm->workers_done, 1);
  return 0;
}

static clib_error_t *
pool_cache_test_single_thread (vlib_main_t *vm)
{
  pool_cache_test_main_t *ptm = &pool_cache_test_main;
  clib_error_t *error = 0;
  u32 *indices = 0;
  u32 i, max_indices;

  clib_memset (ptm, 0, sizeof (*ptm));
  test_mw_pool_cache_init (&ptm->pool, "test-single-thread-pool", POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE,
			   CLIB_CACHE_LINE_BYTES);

  if (PREDICT_FALSE (test_mw_pool_cache_free_internal_ (&ptm->pool, VLIB_POOL_CACHE_INVALID_INDEX)))
    pool_cache_test_error (ptm);

  max_indices = round_pow2 ((POOL_CACHE_TEST_ROUNDS + 1) * POOL_CACHE_TEST_BATCH_SIZE,
			    POOL_CACHE_TEST_SUBPOOL_SIZE);
  vec_validate (ptm->in_use_by_index, max_indices - 1);
  vec_validate (indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  /* The CLI intentionally runs a real thread-0 path when VPP has no workers;
   * it should not silently skip coverage in single-thread configurations. */
  for (i = 0; i < POOL_CACHE_TEST_ROUNDS; i++)
    {
      pool_cache_test_alloc_batch (ptm, vlib_get_thread_index (), i, indices);
      pool_cache_test_free_batch (ptm, vlib_get_thread_index (), i, indices, i == 0);
      pool_cache_test_verify_state (ptm, indices, 0, POOL_CACHE_TEST_BATCH_SIZE,
				    VLIB_POOL_CACHE_SLOT_FREE);
    }

  if (clib_atomic_load_acq_n (&ptm->errors))
    error = clib_error_return (0, "single-thread pool cache test saw %u errors, first at line %u",
			       ptm->errors, ptm->first_error_line);

  if (error == 0)
    {
      for (i = 0; i < vec_len (ptm->in_use_by_index); i++)
	if (clib_atomic_load_acq_n (&ptm->in_use_by_index[i]) != 0)
	  {
	    error = clib_error_return (0, "pool cache index %u still in use", i);
	    break;
	  }
    }

  if (error == 0)
    vlib_cli_output (vm, "Single-thread pool cache test passed: %u rounds", POOL_CACHE_TEST_ROUNDS);

  vec_free (indices);
  test_mw_pool_cache_free_resources (&ptm->pool);
  vec_free (ptm->in_use_by_index);
  return error;
}

VLIB_REGISTER_NODE (pool_cache_test_input_node) = {
  .function = pool_cache_test_input_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "pool-cache-test-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
test_multi_worker_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  pool_cache_test_main_t *ptm = &pool_cache_test_main;
  clib_error_t *error = 0;
  u32 i, max_indices, n_workers = vlib_num_workers ();
  f64 deadline;

  if (n_workers == 0)
    return pool_cache_test_single_thread (vm);

  /* Workers execute the test inside an input node so allocations and frees run
   * with real worker thread indices instead of simulated callers. */
  clib_memset (ptm, 0, sizeof (*ptm));
  test_mw_pool_cache_init (&ptm->pool, "test-multi-worker-pool", POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE,
			   CLIB_CACHE_LINE_BYTES);

  if (PREDICT_FALSE (test_mw_pool_cache_free_internal_ (&ptm->pool, VLIB_POOL_CACHE_INVALID_INDEX)))
    {
      error = clib_error_return (0, "pool cache invalid free returned success");
      goto done;
    }

  max_indices =
    round_pow2 (n_workers * (POOL_CACHE_TEST_ROUNDS + POOL_CACHE_TEST_OVERLAP_ROUNDS + 4) *
		  POOL_CACHE_TEST_BATCH_SIZE,
		POOL_CACHE_TEST_SUBPOOL_SIZE);
  vec_validate (ptm->in_use_by_index, max_indices - 1);
  vec_validate (ptm->handoff_indices, n_workers * POOL_CACHE_TEST_BATCH_SIZE - 1);
  vec_validate (ptm->many_to_one_indices, POOL_CACHE_TEST_BATCH_SIZE - 1);
  vec_validate (ptm->overlap_indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index != 0)
	vlib_node_set_state (this_vlib_main, pool_cache_test_input_node.index,
			     VLIB_NODE_STATE_INTERRUPT);
    }
  vlib_worker_thread_barrier_release (vm);

  for (i = 1; i <= n_workers; i++)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), pool_cache_test_input_node.index);

  deadline = vlib_time_now (vm) + POOL_CACHE_TEST_MAIN_TIMEOUT;
  while (clib_atomic_load_acq_n (&ptm->workers_done) < n_workers)
    {
      if (vlib_time_now (vm) > deadline)
	{
	  error = clib_error_return (0, "timeout waiting for pool cache workers: done %u of %u",
				     ptm->workers_done, n_workers);
	  goto done;
	}
      vlib_process_suspend (vm, 1e-4);
    }

  if (clib_atomic_load_acq_n (&ptm->errors))
    {
      error = clib_error_return (0, "pool cache worker test saw %u errors, first at line %u",
				 ptm->errors, ptm->first_error_line);
      goto done;
    }

  for (i = 0; i < vec_len (ptm->in_use_by_index); i++)
    {
      if (clib_atomic_load_acq_n (&ptm->in_use_by_index[i]) != 0)
	{
	  error = clib_error_return (0, "pool cache index %u still in use", i);
	  goto done;
	}
    }

  vlib_cli_output (vm,
		   "Multi-worker pool cache test passed: %u workers, "
		   "%u alloc/free operations each",
		   n_workers, (POOL_CACHE_TEST_ROUNDS + 2) * POOL_CACHE_TEST_BATCH_SIZE);

done:
  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index != 0)
	vlib_node_set_state (this_vlib_main, pool_cache_test_input_node.index,
			     VLIB_NODE_STATE_DISABLED);
    }
  vlib_worker_thread_barrier_release (vm);

  test_mw_pool_cache_free_resources (&ptm->pool);
  vec_free (ptm->in_use_by_index);
  vec_free (ptm->handoff_indices);
  vec_free (ptm->many_to_one_indices);
  vec_free (ptm->overlap_indices);
  return error;
}

VLIB_CLI_COMMAND (test_multi_worker_pool_command, static) = {
  .path = "test pool-cache",
  .short_help = "vlib pool cache multi-worker test",
  .function = test_multi_worker_pool_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
test_pool_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  static int sizes[] = { 3, 31, 2042, 2048 };

  int i, j;
  u64 *pool;
  uword this_size;

  for (j = 0; j < ARRAY_LEN (sizes); j++)
    {
      this_size = sizes[j];

      pool_init_fixed (pool, this_size);

      i = 0;

      while (pool_free_elts (pool) > 0)
	{
	  u64 *p __attribute__ ((unused));

	  pool_get (pool, p);
	  i++;
	}

      vlib_cli_output (vm, "allocated %d elts\n", i);

      for (--i; i >= 0; i--)
	{
	  pool_put_index (pool, i);
	}

      ALWAYS_ASSERT (pool_free_elts (pool) == this_size);
    }

  vlib_cli_output (vm, "Test succeeded...\n");
  return 0;
}

VLIB_CLI_COMMAND (test_pool_command, static) = {
  .path = "test pool",
  .short_help = "vppinfra pool.h tests",
  .function = test_pool_command_fn,
};
