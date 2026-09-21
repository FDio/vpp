/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Dave Barach
 */

#include <vlib/vlib.h>
#include <vlib/pool_cache.h>

#define POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE 5
#define POOL_CACHE_TEST_SUBPOOL_SIZE	  (1 << POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE)
/* Small transfer batches force refill and flush boundaries in every round. */
#define POOL_CACHE_TEST_CACHE_BATCH_SIZE 8
/* Keep this intentionally off a backing-chunk boundary. */
#define POOL_CACHE_TEST_BATCH_SIZE     (POOL_CACHE_TEST_SUBPOOL_SIZE + 1)
#define POOL_CACHE_TEST_ROUNDS	       32
#define POOL_CACHE_TEST_CROSS_ROUND    0xfffffffe
#define POOL_CACHE_TEST_FINAL_ROUND    0xffffffff
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

typedef struct
{
  u8 data[64];
} pool_cache_aligned_elt_t __clib_aligned (64);

static u8 *
format_pool_cache_test_element (u8 *s, va_list *args)
{
  pool_cache_test_elt_t *e = va_arg (*args, pool_cache_test_elt_t *);
  return format (s, "thread %u round %u slot %u magic 0x%08x", e->thread_index, e->round, e->slot,
		 e->magic);
}

typedef struct
{
  vlib_pool_cache_t pool;
  u32 *in_use_by_index;
  u32 *handoff_indices;
  volatile u32 running;
  volatile u32 workers_done;
  volatile u32 cross_alloc_done;
  volatile u32 cross_free_done;
  volatile u32 cross_verify_done;
  volatile u32 first_error_line;
  volatile u32 first_error_caller_line;
  volatile u32 first_error_thread_index;
  volatile u32 first_error_index;
  volatile u32 first_error_slot;
  volatile u32 first_error_expected_state;
  volatile u32 first_error_actual_state;
  volatile u32 first_error_has_state;
  const char *first_error_func;
  const char *first_error_caller_func;
  volatile u32 errors;
} pool_cache_test_main_t;

static pool_cache_test_main_t pool_cache_test_main;
static volatile u32 pool_cache_test_command_active;

typedef struct
{
  vlib_pool_cache_t pool;
  u32 *indices;
  u8 active;
} pool_cache_cli_test_main_t;

static pool_cache_cli_test_main_t pool_cache_cli_test_main;

static clib_error_t *pool_cache_test_verify_conservation (vlib_pool_cache_t *c);

static u8
pool_cache_test_cache_is_initialized (vlib_pool_cache_t *c)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;
  vlib_pool_cache_t *instance;

  for (instance = pcm->instances; instance; instance = instance->next_instance)
    if (instance == c)
      return 1;

  return 0;
}

static clib_error_t *
pool_cache_test_verify_registry (pool_cache_test_main_t *ptm, const char *test_name)
{
  vlib_pool_cache_main_t *pcm = &pool_cache_main;
  vlib_pool_cache_t *c;
  u8 *s = 0;
  u8 found = 0;

  for (c = pcm->instances; c; c = c->next_instance)
    {
      if (c == &ptm->pool)
	{
	  found = 1;
	  s = format (s, "%U", format_vlib_pool_cache, c, 0);
	  break;
	}
    }

  if (!found)
    return clib_error_return (0, "%s pool cache not initialized", test_name);

  if (vec_len (s) == 0)
    {
      vec_free (s);
      return clib_error_return (0, "%s pool cache formatter returned empty output", test_name);
    }

  vec_free (s);
  return 0;
}

static clib_error_t *
pool_cache_test_multiple_instances (void)
{
  vlib_pool_cache_t pool_a, pool_b;
  vlib_pool_cache_main_t *pcm = &pool_cache_main;
  vlib_pool_cache_t *c;
  clib_error_t *error = 0;
  u8 found_a = 0, found_b = 0;
  u32 idx;
  u8 *formatted = 0;
  pool_cache_test_elt_t *e;

  clib_memset (&pool_a, 0, sizeof (pool_a));
  clib_memset (&pool_b, 0, sizeof (pool_b));

  pool_cache_init_with_batch (&pool_a, "pool-cache-instance-a", format_pool_cache_test_element,
			      POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE, CLIB_CACHE_LINE_BYTES,
			      POOL_CACHE_TEST_CACHE_BATCH_SIZE, pool_cache_test_elt_t);
  pool_cache_init (&pool_b, "pool-cache-instance-b", format_pool_cache_test_element,
		   POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE, CLIB_CACHE_LINE_BYTES, pool_cache_test_elt_t);

  if (pool_a.batch_size != POOL_CACHE_TEST_CACHE_BATCH_SIZE ||
      pool_b.batch_size != VLIB_POOL_CACHE_DEFAULT_BATCH_SIZE)
    error = clib_error_return (0, "pool-cache batch-size initialization mismatch");

  idx = pool_cache_get (&pool_a, e);
  e->thread_index = 0;
  e->round = 1;
  e->slot = 2;
  e->magic = POOL_CACHE_TEST_MAGIC;
  formatted = pool_cache_format_element (formatted, &pool_a, idx);
  if (vec_len (formatted) == 0)
    error = clib_error_return (0, "pool-cache element formatter returned empty output");
  vec_free (formatted);

  if (error == 0 && pool_cache_is_free_index (&pool_a, idx))
    error = clib_error_return (0, "pool-cache allocated index reported free");
  pool_cache_put_index (&pool_a, idx);
  if (error == 0 && !pool_cache_is_free_index (&pool_a, idx))
    error = clib_error_return (0, "pool-cache freed index reported allocated");
  if (error == 0)
    error = pool_cache_test_verify_conservation (&pool_a);

  idx = pool_cache_get (&pool_b, e);
  pool_cache_put_index (&pool_b, idx);

  for (c = pcm->instances; c; c = c->next_instance)
    {
      if (c == &pool_a)
	{
	  found_a = 1;
	  if (c->format_element != format_pool_cache_test_element ||
	      strcmp (c->name, "pool-cache-instance-a"))
	    error = clib_error_return (0, "pool-cache instance-a metadata mismatch");
	}
      else if (c == &pool_b)
	{
	  found_b = 1;
	  if (c->format_element != format_pool_cache_test_element ||
	      strcmp (c->name, "pool-cache-instance-b"))
	    error = clib_error_return (0, "pool-cache instance-b metadata mismatch");
	}
    }

  if (error == 0 && (!found_a || !found_b))
    error = clib_error_return (0, "pool-cache instances not found");

  pool_cache_free (&pool_a);
  pool_cache_free (&pool_b);

  if (error == 0 && (pool_cache_test_cache_is_initialized (&pool_a) ||
		     pool_cache_test_cache_is_initialized (&pool_b)))
    error = clib_error_return (0, "pool-cache instance still initialized");

  return error;
}

static clib_error_t *
pool_cache_test_natural_alignment (void)
{
  vlib_pool_cache_t pool = {};
  u32 *indices = 0;
  clib_error_t *error = 0;
  pool_cache_aligned_elt_t *e;
  u32 idx;
  u32 i;

  /* A zero requested alignment must retain the element type's alignment. */
  pool_cache_init (&pool, "pool-cache-aligned", 0, POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE, 0,
		   pool_cache_aligned_elt_t);

  for (i = 0; i < POOL_CACHE_TEST_SUBPOOL_SIZE + 1; i++)
    {
      idx = pool_cache_get (&pool, e);

      vec_add1 (indices, idx);
      if ((uword) e & (__alignof__ (pool_cache_aligned_elt_t) - 1))
	{
	  error = clib_error_return (0, "pool-cache element %u is not naturally aligned", idx);
	  break;
	}
    }

  vec_foreach_index (i, indices)
    pool_cache_put_index (&pool, indices[i]);
  vec_free (indices);
  pool_cache_free (&pool);
  return error;
}

static void
pool_cache_cli_test_free_all (pool_cache_cli_test_main_t *ptm)
{
  u32 i;

  for (i = 0; i < vec_len (ptm->indices); i++)
    pool_cache_put_index (&ptm->pool, ptm->indices[i]);
  vec_reset_length (ptm->indices);
}

static clib_error_t *
pool_cache_cli_test_init (pool_cache_cli_test_main_t *ptm, u32 log2_subpool_size,
			  u32 cache_batch_size)
{
  if (ptm->active)
    return clib_error_return (0, "pool-cache-cli already active");

  pool_cache_init_with_batch (&ptm->pool, "pool-cache-cli", format_pool_cache_test_element,
			      log2_subpool_size, CLIB_CACHE_LINE_BYTES, cache_batch_size,
			      pool_cache_test_elt_t);
  ptm->active = 1;
  return 0;
}

static clib_error_t *
pool_cache_cli_test_alloc (pool_cache_cli_test_main_t *ptm, u32 count)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  if (!ptm->active)
    return clib_error_return (0, "pool-cache-cli is not active; run `test pool-cache cli init`");

  for (i = 0; i < count; i++)
    {
      idx = pool_cache_get (&ptm->pool, e);
      vec_add1 (ptm->indices, idx);
      if (PREDICT_FALSE (pool_cache_is_free_index (&ptm->pool, idx)))
	return clib_error_return (0, "pool-cache-cli allocated index %u reports free", idx);
      e->thread_index = vlib_get_thread_index ();
      e->round = 0;
      e->slot = vec_len (ptm->indices) - 1;
      e->magic = POOL_CACHE_TEST_MAGIC;
    }

  return 0;
}

static clib_error_t *
pool_cache_cli_test_free (pool_cache_cli_test_main_t *ptm, u32 count)
{
  u32 i, idx;

  if (!ptm->active)
    return clib_error_return (0, "pool-cache-cli is not active; run `test pool-cache cli init`");

  if (count > vec_len (ptm->indices))
    return clib_error_return (0, "pool-cache-cli tracks only %u allocated indices",
			      vec_len (ptm->indices));

  for (i = 0; i < count; i++)
    {
      idx = ptm->indices[vec_len (ptm->indices) - 1];
      vec_dec_len (ptm->indices, 1);
      pool_cache_put_index (&ptm->pool, idx);
      if (PREDICT_FALSE (!pool_cache_is_free_index (&ptm->pool, idx)))
	return clib_error_return (0, "pool-cache-cli freed index %u reports allocated", idx);
    }

  return 0;
}

static void
pool_cache_cli_test_cleanup (pool_cache_cli_test_main_t *ptm)
{
  if (!ptm->active)
    return;

  pool_cache_cli_test_free_all (ptm);
  pool_cache_free (&ptm->pool);
  ptm->active = 0;
}

static_always_inline void
pool_cache_test_error_at (pool_cache_test_main_t *ptm, const char *func, u32 line,
			  const char *caller_func, u32 caller_line, u32 has_state, u32 idx,
			  u32 slot, u32 expected_state, u32 actual_state)
{
  if (clib_atomic_cmp_and_swap (&ptm->first_error_line, 0, line) == 0)
    {
      ptm->first_error_func = func;
      ptm->first_error_caller_func = caller_func;
      ptm->first_error_caller_line = caller_line;
      ptm->first_error_thread_index = vlib_get_thread_index ();
      ptm->first_error_has_state = has_state;
      ptm->first_error_index = idx;
      ptm->first_error_slot = slot;
      ptm->first_error_expected_state = expected_state;
      ptm->first_error_actual_state = actual_state;
    }
  clib_atomic_fetch_add_rel (&ptm->errors, 1);
}

#define pool_cache_test_error(ptm)                                                                 \
  pool_cache_test_error_at ((ptm), __func__, __LINE__, 0, 0, 0, 0, 0, 0, 0)

#define pool_cache_test_error_from(ptm, caller_func, caller_line)                                  \
  pool_cache_test_error_at ((ptm), __func__, __LINE__, (caller_func), (caller_line), 0, 0, 0, 0, 0)

#define pool_cache_test_state_error_from(ptm, caller_func, caller_line, idx, slot, expected,       \
					 actual)                                                   \
  pool_cache_test_error_at ((ptm), __func__, __LINE__, (caller_func), (caller_line), 1, (idx),     \
			    (slot), (expected), (actual))

static_always_inline int
pool_cache_test_wait_for_workers_at (vlib_main_t *vm, pool_cache_test_main_t *ptm,
				     volatile u32 *counter, u32 target, const char *caller_func,
				     u32 caller_line)
{
  f64 deadline = vlib_time_now (vm) + POOL_CACHE_TEST_WORKER_TIMEOUT;

  /* Worker nodes cannot rely on the main test timeout while they are spinning
   * here, so each rendezvous has its own bounded wait. */
  while (clib_atomic_load_acq_n (counter) < target)
    {
      if (PREDICT_FALSE (vlib_time_now (vm) > deadline))
	{
	  pool_cache_test_error_from (ptm, caller_func, caller_line);
	  return 0;
	}
      CLIB_PAUSE ();
    }
  return 1;
}

#define pool_cache_test_wait_for_workers(vm, ptm, counter, target)                                 \
  pool_cache_test_wait_for_workers_at ((vm), (ptm), (counter), (target), __func__, __LINE__)

static_always_inline void
pool_cache_test_verify_is_free_at (pool_cache_test_main_t *ptm, u32 *indices, u32 start, u32 end,
				   int expected_free, const char *caller_func, u32 caller_line)
{
  u32 i;
  expected_free = !!expected_free;

  for (i = start; i < end; i++)
    {
      int actual = pool_cache_is_free_index (&ptm->pool, indices[i]);
      if (PREDICT_FALSE (actual != expected_free))
	pool_cache_test_state_error_from (ptm, caller_func, caller_line, indices[i], i,
					  expected_free, actual);
    }
}

#define pool_cache_test_verify_is_free(ptm, indices, start, end, expected)                         \
  pool_cache_test_verify_is_free_at ((ptm), (indices), (start), (end), (expected), __func__,       \
				     __LINE__)

static clib_error_t *
pool_cache_test_error_report (pool_cache_test_main_t *ptm, const char *test_name)
{
  const char *func = ptm->first_error_func ? ptm->first_error_func : "unknown";
  u8 *state_detail = 0;
  clib_error_t *error;

  if (ptm->first_error_caller_func)
    error = clib_error_return (
      0, "%s pool cache test saw %u errors, first at %s:%u called from %s:%u on thread %u",
      test_name, ptm->errors, func, ptm->first_error_line, ptm->first_error_caller_func,
      ptm->first_error_caller_line, ptm->first_error_thread_index);
  else
    error = clib_error_return (0, "%s pool cache test saw %u errors, first at %s:%u on thread %u",
			       test_name, ptm->errors, func, ptm->first_error_line,
			       ptm->first_error_thread_index);

  if (ptm->first_error_has_state)
    {
      u32 pidx = _pool_cache_subpool_index (&ptm->pool, ptm->first_error_index);
      u32 elt_index = _pool_cache_elt_index (&ptm->pool, ptm->first_error_index);

      state_detail = format (
	state_detail, ", index %u slot %u subpool %u elt %u expected state %u actual state %u%c",
	ptm->first_error_index, ptm->first_error_slot, pidx, elt_index,
	ptm->first_error_expected_state, ptm->first_error_actual_state, 0);
      vec_add (error->what, state_detail, vec_len (state_detail) - 1);
      vec_free (state_detail);
    }

  return error;
}

static clib_error_t *
pool_cache_test_verify_conservation (vlib_pool_cache_t *c)
{
  vlib_pool_cache_thread_t *pt;
  u8 *seen = 0;
  u64 allocated = 0, cached = 0, global, total;
  u32 i, j, n_subpools = clib_atomic_load_acq_n (&c->n_subpools);
  clib_error_t *error = 0;

  total = (u64) n_subpools * c->subpool_size;
  vec_validate (seen, total ? total - 1 : 0);

  clib_spinlock_lock (&c->lock);
  global = clib_atomic_load_relax_n (&c->n_global_free);
  i = c->global_free_list;
  for (u64 n = 0; n < global; n++)
    {
      u32 idx = i;
      if (idx >= total || seen[idx])
	{
	  error = clib_error_return (0, "invalid or duplicate global free index %u", idx);
	  goto unlock;
	}
      if (!pool_cache_is_free_index (c, idx))
	{
	  error = clib_error_return (0, "non-free global index %u", idx);
	  goto unlock;
	}
      seen[idx] = 1;
      i = _pool_cache_next_free (c, idx);
    }
  if (i != VLIB_POOL_CACHE_INVALID_INDEX)
    {
      error = clib_error_return (0, "global free-list count is shorter than its chain");
      goto unlock;
    }

  vec_foreach (pt, c->per_thread)
    {
      u32 n = clib_atomic_load_acq_n (&pt->n_cached);
      u32 idx = pt->free_list;
      cached += n;
      for (i = 0; i < n; i++)
	{
	  if (idx >= total || seen[idx])
	    {
	      error = clib_error_return (0, "invalid or duplicate cached free index %u", idx);
	      goto unlock;
	    }
	  if (!pool_cache_is_free_index (c, idx))
	    {
	      error = clib_error_return (0, "non-free cached index %u", idx);
	      goto unlock;
	    }
	  seen[idx] = 1;
	  idx = _pool_cache_next_free (c, idx);
	}
      if (idx != VLIB_POOL_CACHE_INVALID_INDEX)
	{
	  error = clib_error_return (0, "thread %u free-list count is shorter than its chain",
				     pt - c->per_thread);
	  goto unlock;
	}
    }

  for (i = 0; i < n_subpools; i++)
    {
      vlib_pool_cache_subpool_t *sp = _pool_cache_subpool_at (c, i);
      for (j = 0; j < c->subpool_size; j++)
	{
	  u32 idx = _pool_cache_encode_index (c, i, j);
	  u32 next_free = clib_atomic_load_relax_n (&sp->next_free[j]);
	  if (next_free == VLIB_POOL_CACHE_ALLOCATED_INDEX)
	    {
	      allocated++;
	      if (seen[idx])
		{
		  error = clib_error_return (0, "allocated index %u appears on a free list", idx);
		  goto unlock;
		}
	    }
	  else if (!seen[idx])
	    {
	      error = clib_error_return (0, "free index %u appears on no free list", idx);
	      goto unlock;
	    }
	}
    }

  if (allocated + cached + global != total)
    error = clib_error_return (
      0, "pool cache conservation failed: allocated %llu cached %llu global %llu total %llu",
      allocated, cached, global, total);

unlock:
  clib_spinlock_unlock (&c->lock);
  vec_free (seen);
  return error;
}

static_always_inline void
pool_cache_test_alloc_batch (pool_cache_test_main_t *ptm, u32 thread_index, u32 round, u32 *indices)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  for (i = 0; i < POOL_CACHE_TEST_BATCH_SIZE; i++)
    {
      idx = pool_cache_get (&ptm->pool, e);
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

      if (PREDICT_FALSE (pool_cache_is_free_index (&ptm->pool, idx)))
	pool_cache_test_error (ptm);

      e->thread_index = thread_index;
      e->round = round;
      e->slot = i;
      e->magic = POOL_CACHE_TEST_MAGIC;
    }
}

static_always_inline void
pool_cache_test_free_range (pool_cache_test_main_t *ptm, u32 expected_thread_index, u32 round,
			    u32 *indices, u32 start, u32 end)
{
  pool_cache_test_elt_t *e;
  u32 i, idx;

  for (i = start; i < end; i++)
    {
      idx = indices[i];
      e = pool_cache_elt_at_index (&ptm->pool, idx);

      if (PREDICT_FALSE (e->thread_index != expected_thread_index || e->round != round ||
			 e->slot != i || e->magic != POOL_CACHE_TEST_MAGIC))
	pool_cache_test_error (ptm);

      if (idx < vec_len (ptm->in_use_by_index))
	clib_atomic_store_rel_n (&ptm->in_use_by_index[idx], 0);

      pool_cache_put_index (&ptm->pool, idx);
    }
}

static_always_inline void
pool_cache_test_free_batch (pool_cache_test_main_t *ptm, u32 expected_thread_index, u32 round,
			    u32 *indices)
{
  pool_cache_test_free_range (ptm, expected_thread_index, round, indices, 0,
			      POOL_CACHE_TEST_BATCH_SIZE);
}

static uword
pool_cache_test_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  CLIB_UNUSED (vlib_frame_t *frame))
{
  pool_cache_test_main_t *ptm = &pool_cache_test_main;
  u32 *indices = 0;
  u32 round, thread_index, worker_index, source_worker_index;
  u32 source_thread_index, n_workers;

  if (vm->thread_index == 0)
    return 0;

  if (PREDICT_FALSE (clib_atomic_load_acq_n (&ptm->running) == 0))
    return 0;

  thread_index = vlib_get_thread_index ();
  worker_index = vlib_get_current_worker_index ();
  n_workers = vlib_num_workers ();
  source_worker_index = worker_index ? worker_index - 1 : n_workers - 1;
  source_thread_index = vlib_get_worker_thread_index (source_worker_index);
  vec_validate (indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  /* Same-thread churn exercises repeated exact-batch refill and flush. */
  for (round = 0; round < POOL_CACHE_TEST_ROUNDS; round++)
    {
      pool_cache_test_alloc_batch (ptm, thread_index, round, indices);
      pool_cache_test_free_batch (ptm, thread_index, round, indices);
    }

  pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_CROSS_ROUND,
			       ptm->handoff_indices + worker_index * POOL_CACHE_TEST_BATCH_SIZE);
  clib_atomic_fetch_add_rel (&ptm->cross_alloc_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_alloc_done, n_workers))
    goto done;

  /* Ring handoff: each worker frees the previous worker's allocations. */
  pool_cache_test_free_batch (ptm, source_thread_index, POOL_CACHE_TEST_CROSS_ROUND,
			      ptm->handoff_indices +
				source_worker_index * POOL_CACHE_TEST_BATCH_SIZE);
  clib_atomic_fetch_add_rel (&ptm->cross_free_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_free_done, n_workers))
    goto done;

  /* A successful free is immediately reusable state; no owner drain exists. */
  pool_cache_test_verify_is_free (
    ptm, ptm->handoff_indices + source_worker_index * POOL_CACHE_TEST_BATCH_SIZE, 0,
    POOL_CACHE_TEST_BATCH_SIZE, 1);
  clib_atomic_fetch_add_rel (&ptm->cross_verify_done, 1);
  if (!pool_cache_test_wait_for_workers (vm, ptm, &ptm->cross_verify_done, n_workers))
    goto done;

  /* Final local cycle proves that concurrent refill/flush left reusable state. */
  pool_cache_test_alloc_batch (ptm, thread_index, POOL_CACHE_TEST_FINAL_ROUND, indices);
  pool_cache_test_free_batch (ptm, thread_index, POOL_CACHE_TEST_FINAL_ROUND, indices);

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
  u32 i, max_indices, anchor, n_subpools_before;
  pool_cache_test_elt_t *anchor_elt;

  clib_memset (ptm, 0, sizeof (*ptm));

  pool_cache_init_with_batch (&ptm->pool, "test-single-thread-pool", format_pool_cache_test_element,
			      POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE, CLIB_CACHE_LINE_BYTES,
			      POOL_CACHE_TEST_CACHE_BATCH_SIZE, pool_cache_test_elt_t);

  error = pool_cache_test_verify_registry (ptm, "single-thread");
  if (error)
    goto done;

  max_indices =
    round_pow2 (POOL_CACHE_TEST_BATCH_SIZE + 1 +
		  2 * POOL_CACHE_TEST_CACHE_BATCH_SIZE * vec_len (ptm->pool.per_thread) +
		  POOL_CACHE_TEST_SUBPOOL_SIZE,
		POOL_CACHE_TEST_SUBPOOL_SIZE);
  vec_validate (ptm->in_use_by_index, max_indices - 1);
  vec_validate (indices, POOL_CACHE_TEST_BATCH_SIZE - 1);

  anchor = pool_cache_get (&ptm->pool, anchor_elt);
  anchor_elt->magic = POOL_CACHE_TEST_MAGIC;
  n_subpools_before = ptm->pool.n_subpools;
  pool_cache_test_alloc_batch (ptm, vlib_get_thread_index (), POOL_CACHE_TEST_FINAL_ROUND, indices);
  if (pool_cache_elt_at_index (&ptm->pool, anchor) != anchor_elt ||
      anchor_elt->magic != POOL_CACHE_TEST_MAGIC || ptm->pool.n_subpools <= n_subpools_before)
    pool_cache_test_error (ptm);
  pool_cache_test_free_batch (ptm, vlib_get_thread_index (), POOL_CACHE_TEST_FINAL_ROUND, indices);
  pool_cache_put_index (&ptm->pool, anchor);

  /* The CLI intentionally runs a real thread-0 path when VPP has no workers;
   * it should not silently skip coverage in single-thread configurations. */
  for (i = 0; i < POOL_CACHE_TEST_ROUNDS; i++)
    {
      pool_cache_test_alloc_batch (ptm, vlib_get_thread_index (), i, indices);
      pool_cache_test_free_batch (ptm, vlib_get_thread_index (), i, indices);
      pool_cache_test_verify_is_free (ptm, indices, 0, POOL_CACHE_TEST_BATCH_SIZE, 1);
    }

  if (clib_atomic_load_acq_n (&ptm->errors))
    error = pool_cache_test_error_report (ptm, "single-thread");

  if (error == 0)
    error = pool_cache_test_verify_conservation (&ptm->pool);

  if (error == 0)
    {
      vlib_pool_cache_thread_t *pt =
	vec_elt_at_index (ptm->pool.per_thread, vlib_get_thread_index ());
      if (clib_atomic_load_acq_n (&pt->n_cached) > 2 * POOL_CACHE_TEST_CACHE_BATCH_SIZE ||
	  clib_atomic_load_acq_n (&pt->refills) == 0 || clib_atomic_load_acq_n (&pt->flushes) == 0)
	error = clib_error_return (0, "single-thread refill/flush watermark validation failed");
    }

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

done:
  vec_free (indices);
  pool_cache_free (&ptm->pool);
  if (error == 0 && pool_cache_test_cache_is_initialized (&ptm->pool))
    error = clib_error_return (0, "single-thread pool cache still initialized after free");
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
  u64 max_expected;
  f64 deadline;

  if (!clib_atomic_bool_cmp_and_swap (&pool_cache_test_command_active, 0, 1))
    return clib_error_return (0, "pool cache test already running");

  error = pool_cache_test_natural_alignment ();
  if (error)
    goto unlock;

  error = pool_cache_test_multiple_instances ();
  if (error)
    goto unlock;

  if (n_workers == 0)
    {
      error = pool_cache_test_single_thread (vm);
      goto unlock;
    }

  /* Workers execute the test inside an input node so allocations and frees run
   * with real worker thread indices instead of simulated callers. */
  clib_memset (ptm, 0, sizeof (*ptm));

  pool_cache_init_with_batch (&ptm->pool, "test-multi-worker-pool", format_pool_cache_test_element,
			      POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE, CLIB_CACHE_LINE_BYTES,
			      POOL_CACHE_TEST_CACHE_BATCH_SIZE, pool_cache_test_elt_t);

  error = pool_cache_test_verify_registry (ptm, "multi-worker");
  if (error)
    goto done;

  max_expected = (u64) n_workers * POOL_CACHE_TEST_BATCH_SIZE +
		 (u64) 2 * POOL_CACHE_TEST_CACHE_BATCH_SIZE * vec_len (ptm->pool.per_thread) +
		 POOL_CACHE_TEST_SUBPOOL_SIZE;
  max_indices = round_pow2 (max_expected, POOL_CACHE_TEST_SUBPOOL_SIZE);
  vec_validate (ptm->in_use_by_index, max_indices - 1);
  vec_validate (ptm->handoff_indices, n_workers * POOL_CACHE_TEST_BATCH_SIZE - 1);

  vlib_worker_thread_barrier_sync (vm);
  clib_atomic_store_rel_n (&ptm->running, 1);
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
      error = pool_cache_test_error_report (ptm, "worker");
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

  error = pool_cache_test_verify_conservation (&ptm->pool);
  if (error)
    goto done;

  for (i = 1; i <= n_workers; i++)
    {
      vlib_pool_cache_thread_t *pt = vec_elt_at_index (ptm->pool.per_thread, i);
      if (clib_atomic_load_acq_n (&pt->n_cached) > 2 * POOL_CACHE_TEST_CACHE_BATCH_SIZE ||
	  clib_atomic_load_acq_n (&pt->refills) == 0 || clib_atomic_load_acq_n (&pt->flushes) == 0)
	{
	  error =
	    clib_error_return (0, "worker %u did not exercise bounded refill/flush caching", i);
	  goto done;
	}
    }

  if ((u64) ptm->pool.n_subpools * ptm->pool.subpool_size > max_expected)
    {
      error = clib_error_return (0, "pool cache grew beyond expected bound %llu", max_expected);
      goto done;
    }

  vlib_cli_output (vm,
		   "Multi-worker pool cache test passed: %u workers, "
		   "%u alloc/free operations each",
		   n_workers, (POOL_CACHE_TEST_ROUNDS + 2) * POOL_CACHE_TEST_BATCH_SIZE);

done:
  vlib_worker_thread_barrier_sync (vm);
  clib_atomic_store_rel_n (&ptm->running, 0);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index != 0)
	vlib_node_set_state (this_vlib_main, pool_cache_test_input_node.index,
			     VLIB_NODE_STATE_DISABLED);
    }
  vlib_worker_thread_barrier_release (vm);

  pool_cache_free (&ptm->pool);
  if (error == 0 && pool_cache_test_cache_is_initialized (&ptm->pool))
    error = clib_error_return (0, "multi-worker pool cache still initialized after free");
  vec_free (ptm->in_use_by_index);
  vec_free (ptm->handoff_indices);
unlock:
  clib_atomic_store_rel_n (&pool_cache_test_command_active, 0);
  return error;
}

VLIB_CLI_COMMAND (test_multi_worker_pool_command, static) = {
  .path = "test pool-cache",
  .short_help = "vlib pool cache multi-worker test",
  .function = test_multi_worker_pool_command_fn,
  .is_mp_safe = 1,
};

typedef enum
{
  POOL_CACHE_CLI_TEST_STATUS,
  POOL_CACHE_CLI_TEST_INIT,
  POOL_CACHE_CLI_TEST_ALLOC,
  POOL_CACHE_CLI_TEST_FREE,
  POOL_CACHE_CLI_TEST_FREE_ALL,
  POOL_CACHE_CLI_TEST_CLEANUP,
} pool_cache_cli_test_action_t;

static clib_error_t *
test_pool_cache_cli_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pool_cache_cli_test_main_t *ptm = &pool_cache_cli_test_main;
  pool_cache_cli_test_action_t action = POOL_CACHE_CLI_TEST_STATUS;
  clib_error_t *error = 0;
  u32 count = 1;
  u32 init_alloc = 0;
  u32 log2_subpool_size = POOL_CACHE_TEST_LOG2_SUBPOOL_SIZE;
  u32 cache_batch_size = POOL_CACHE_TEST_CACHE_BATCH_SIZE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "init"))
	action = POOL_CACHE_CLI_TEST_INIT;
      else if (unformat (input, "alloc %u", &count))
	{
	  if (action == POOL_CACHE_CLI_TEST_INIT)
	    init_alloc = count;
	  else
	    action = POOL_CACHE_CLI_TEST_ALLOC;
	}
      else if (unformat (input, "alloc"))
	{
	  if (action == POOL_CACHE_CLI_TEST_INIT)
	    init_alloc = count;
	  else
	    action = POOL_CACHE_CLI_TEST_ALLOC;
	}
      else if (unformat (input, "free %u", &count))
	action = POOL_CACHE_CLI_TEST_FREE;
      else if (unformat (input, "free-all"))
	action = POOL_CACHE_CLI_TEST_FREE_ALL;
      else if (unformat (input, "free"))
	action = POOL_CACHE_CLI_TEST_FREE;
      else if (unformat (input, "cleanup"))
	action = POOL_CACHE_CLI_TEST_CLEANUP;
      else if (unformat (input, "status"))
	action = POOL_CACHE_CLI_TEST_STATUS;
      else if (unformat (input, "log2-subpool-size %u", &log2_subpool_size))
	;
      else if (unformat (input, "cache-batch-size %u", &cache_batch_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  switch (action)
    {
    case POOL_CACHE_CLI_TEST_INIT:
      error = pool_cache_cli_test_init (ptm, log2_subpool_size, cache_batch_size);
      if (error == 0 && init_alloc)
	error = pool_cache_cli_test_alloc (ptm, init_alloc);
      break;
    case POOL_CACHE_CLI_TEST_ALLOC:
      error = pool_cache_cli_test_alloc (ptm, count);
      break;
    case POOL_CACHE_CLI_TEST_FREE:
      error = pool_cache_cli_test_free (ptm, count);
      break;
    case POOL_CACHE_CLI_TEST_FREE_ALL:
      if (!ptm->active)
	error =
	  clib_error_return (0, "pool-cache-cli is not active; run `test pool-cache cli init`");
      else
	pool_cache_cli_test_free_all (ptm);
      break;
    case POOL_CACHE_CLI_TEST_CLEANUP:
      pool_cache_cli_test_cleanup (ptm);
      break;
    case POOL_CACHE_CLI_TEST_STATUS:
      break;
    }

  if (error)
    return error;

  vlib_cli_output (vm, "pool-cache-cli: %s, tracked allocations %u",
		   ptm->active ? "active" : "inactive", vec_len (ptm->indices));
  return 0;
}

VLIB_CLI_COMMAND (test_pool_cache_cli_command, static) = {
  .path = "test pool-cache cli",
  .short_help = "test pool-cache cli init [log2-subpool-size <n>] [cache-batch-size <n>] "
		"[alloc <n>] | alloc [n] | "
		"free [n] | free-all | cleanup | status",
  .function = test_pool_cache_cli_command_fn,
};
