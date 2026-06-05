/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Dave Barach
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>

#define POOL_CACHE_TEST_CACHE_SIZE 8
#define POOL_CACHE_TEST_BATCH_SIZE 31
#define POOL_CACHE_TEST_ROUNDS	   256
#define POOL_CACHE_TEST_MAGIC	   0x51ced00d

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
  u32 prealloc_size;
  volatile u32 workers_done;
  volatile u32 errors;
} pool_cache_test_main_t;

static pool_cache_test_main_t pool_cache_test_main;

static_always_inline void
pool_cache_test_error (pool_cache_test_main_t *ptm)
{
  clib_atomic_fetch_add_rel (&ptm->errors, 1);
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
pool_cache_test_free_batch (pool_cache_test_main_t *ptm, u32 thread_index, u32 round, u32 *indices)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  for (i = 0; i < POOL_CACHE_TEST_BATCH_SIZE; i++)
    {
      idx = indices[i];
      e = test_mw_pool_cache_elt_at_index (&ptm->pool, idx);

      if (PREDICT_FALSE (e->thread_index != thread_index || e->round != round || e->slot != i ||
			 e->magic != POOL_CACHE_TEST_MAGIC))
	pool_cache_test_error (ptm);

      if (idx < vec_len (ptm->in_use_by_index))
	clib_atomic_store_rel_n (&ptm->in_use_by_index[idx], 0);

      test_mw_pool_cache_free (&ptm->pool, idx);
    }
}

static uword
pool_cache_test_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  CLIB_UNUSED (vlib_frame_t *frame))
{
  pool_cache_test_main_t *ptm = &pool_cache_test_main;
  u32 *indices = 0;
  u32 round, thread_index;

  if (vm->thread_index == 0)
    return 0;

  thread_index = vlib_get_thread_index ();
  vec_validate (indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  for (round = 0; round < POOL_CACHE_TEST_ROUNDS; round++)
    {
      pool_cache_test_alloc_batch (ptm, thread_index, round, indices);
      pool_cache_test_free_batch (ptm, thread_index, round, indices);
    }

  vec_free (indices);
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  clib_atomic_fetch_add_rel (&ptm->workers_done, 1);
  return 0;
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
  u32 i, n_workers = vlib_num_workers ();
  f64 deadline;

  if (n_workers == 0)
    {
      vlib_cli_output (vm, "Test requires workers, skipping");
      return 0;
    }

  clib_memset (ptm, 0, sizeof (*ptm));
  test_mw_pool_cache_init (&ptm->pool, "test-multi-worker-pool", POOL_CACHE_TEST_CACHE_SIZE,
			   CLIB_CACHE_LINE_BYTES);

  ptm->prealloc_size = n_workers * POOL_CACHE_TEST_BATCH_SIZE * POOL_CACHE_TEST_CACHE_SIZE;
  test_mw_pool_cache_pre_alloc (&ptm->pool, ptm->prealloc_size);
  vec_validate (ptm->in_use_by_index, ptm->prealloc_size - 1);

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

  deadline = vlib_time_now (vm) + 10.0;
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
      error = clib_error_return (0, "pool cache worker test saw %u errors", ptm->errors);
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
		   n_workers, POOL_CACHE_TEST_ROUNDS * POOL_CACHE_TEST_BATCH_SIZE);

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
  return error;
}

VLIB_CLI_COMMAND (test_multi_worker_pool_command, static) = {
  .path = "test pool-cache",
  .short_help = "vlib pool cache multi-worker test",
  .function = test_multi_worker_pool_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
test_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
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
