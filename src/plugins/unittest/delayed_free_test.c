/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

/* Tests for the delayed free mechanics: VEC_FLAG_MT_SAFE routing of
 * vector/pool/hash stale memory through the registered delayed free
 * callback. The vlib epoch engine itself is exercised by the python
 * test (test_delayed_free.py) which runs VPP with workers. */

#include <vlib/vlib.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>

typedef struct
{
  void *ptr;
  clib_mem_heap_t *heap;
} df_test_capture_t;

static df_test_capture_t *df_test_captured;

static void
df_test_capture_cb (clib_mem_heap_t *heap, void *p)
{
  df_test_capture_t *c;
  vec_add2 (df_test_captured, c, 1);
  c->ptr = p;
  c->heap = heap;
}

static void
df_test_execute_captured_frees (void)
{
  df_test_capture_t *c;
  vec_foreach (c, df_test_captured)
    clib_mem_heap_free (c->heap, c->ptr);
  vec_free (df_test_captured);
}

/* Growing a vector only produces stale memory when dlmalloc cannot
 * extend the allocation in place. Plug the space right behind the
 * growing allocation with small blocker allocations so a grow is
 * forced to relocate sooner or later. */

static void **df_test_blockers;

static void
df_test_add_blocker (void)
{
  vec_add1 (df_test_blockers, clib_mem_alloc (64));
}

static void
df_test_free_blockers (void)
{
  void **b;
  vec_foreach (b, df_test_blockers)
    clib_mem_free (b[0]);
  vec_free (df_test_blockers);
}

static clib_error_t *
df_test_vec (void)
{
  u32 *v = 0, i;
  uword n_before;

  vec_mark_mt_safe (v);
  if (v == 0)
    return clib_error_return (0, "mark did not allocate NULL vector");
  if (!vec_is_mt_safe (v))
    return clib_error_return (0, "vector not marked");
  if (vec_len (v) != 0)
    return clib_error_return (0, "marked NULL vector not empty");

  /* grow until at least one reallocation was forced to relocate */
  for (i = 0; i < 100000 && vec_len (df_test_captured) == 0; i++)
    {
      vec_add1 (v, i);
      df_test_add_blocker ();
    }

  if (!vec_is_mt_safe (v))
    return clib_error_return (0, "mark lost across reallocations");
  if (vec_len (df_test_captured) == 0)
    return clib_error_return (0, "no stale vector memory captured");

  for (i = 0; i < vec_len (v); i++)
    if (v[i] != i)
      return clib_error_return (0, "vector content corrupted at %u", i);

  n_before = vec_len (df_test_captured);
  vec_free (v);
  if (v != 0)
    return clib_error_return (0, "vec_free did not clear pointer");
  if (vec_len (df_test_captured) != n_before + 1)
    return clib_error_return (0, "vec_free not routed to delayed free");

  return 0;
}

static clib_error_t *
df_test_vec_unmarked (void)
{
  u32 *v = 0, i;

  for (i = 0; i < 10000; i++)
    vec_add1 (v, i);
  vec_free (v);

  if (vec_len (df_test_captured) != 0)
    return clib_error_return (0, "unmarked vector went to delayed free");

  return 0;
}

typedef struct
{
  u64 a;
  u64 b;
} df_test_elt_t;

static clib_error_t *
df_test_pool (void)
{
  df_test_elt_t *pool = 0, *e;
  u32 i;

  pool_mark_mt_safe (pool);
  if (!vec_is_mt_safe (pool))
    return clib_error_return (0, "pool not marked");

  u32 n_elts = 0;
  for (i = 0; i < 100000 && vec_len (df_test_captured) == 0; i++)
    {
      pool_get (pool, e);
      e->a = e->b = i;
      df_test_add_blocker ();
      n_elts++;
    }
  if (!vec_is_mt_safe (pool))
    return clib_error_return (0, "pool mark lost across growth");
  if (vec_len (df_test_captured) == 0)
    return clib_error_return (0, "no stale pool memory captured");

  /* free bitmap / free indices grow on put and are marked as well */
  for (i = 0; i < n_elts; i += 2)
    pool_put_index (pool, i);
  for (i = 1; i < n_elts; i += 2)
    {
      e = pool_elt_at_index (pool, i);
      if (e->a != i || e->b != i)
	return clib_error_return (0, "pool content corrupted at %u", i);
    }

  pool_free (pool);

  return 0;
}

static clib_error_t *
df_test_hash (void)
{
  uword *h, *p;
  u32 i;
  const u32 n_elts = 5000;

  h = hash_create (4, sizeof (uword));
  hash_mark_mt_safe (h);
  if (!vec_is_mt_safe (h))
    return clib_error_return (0, "hash not marked");

  /* force multiple resizes and indirect pair churn; use a sparse key
   * pattern so buckets collide and indirect pairs are created */
  for (i = 0; i < n_elts; i++)
    hash_set (h, i * 7, i);

  if (!vec_is_mt_safe (h))
    return clib_error_return (0, "hash mark lost across resize");
  if (vec_len (df_test_captured) == 0)
    return clib_error_return (0, "no stale hash memory captured");

  for (i = 0; i < n_elts; i++)
    {
      p = hash_get (h, i * 7);
      if (!p || p[0] != i)
	return clib_error_return (0, "hash content corrupted at %u", i);
    }

  for (i = 0; i < n_elts; i += 2)
    hash_unset (h, i * 7);
  for (i = 1; i < n_elts; i += 2)
    {
      p = hash_get (h, i * 7);
      if (!p || p[0] != i)
	return clib_error_return (0, "hash content corrupted after unset");
    }

  hash_free (h);

  return 0;
}

static clib_error_t *
test_delayed_free_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  struct
  {
    const char *name;
    clib_error_t *(*fn) (void);
  } tests[] = {
    { "vec", df_test_vec },
    { "vec-unmarked", df_test_vec_unmarked },
    { "pool", df_test_pool },
    { "hash", df_test_hash },
  };
  int i;

  for (i = 0; i < ARRAY_LEN (tests); i++)
    {
      /* capture delayed frees instead of executing them */
      df_test_captured = 0;
      clib_mem_set_delayed_free_cb (df_test_capture_cb);

      error = tests[i].fn ();

      /* restore normal operation before doing anything else */
      if (vlib_num_workers () > 0)
	vlib_delayed_free_enable (vm);
      else
	clib_mem_set_delayed_free_cb (0);

      /* nothing references the stale memory here, free it for real */
      df_test_execute_captured_frees ();
      df_test_free_blockers ();

      if (error)
	return error;
      vlib_cli_output (vm, "delayed-free %s test OK", tests[i].name);
    }

  return 0;
}

VLIB_CLI_COMMAND (test_delayed_free_command, static) = {
  .path = "test delayed-free",
  .short_help = "test delayed-free",
  .function = test_delayed_free_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
