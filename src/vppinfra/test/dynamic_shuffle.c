/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#pragma GCC diagnostic ignored "-Wpsabi"
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector.h>

#include <string.h>

#define NUM_TEST_ITERS	256
#define PERF_BATCH_SIZE 256

#define TEST_INSERT_FUNCTION_DEFINE(type, scalar_t)                           \
  static_always_inline type type##_local_insert (type x, scalar_t y, int pos) \
  {                                                                           \
    x[pos] = y;                                                               \
    return x;                                                                 \
  }

#define TEST_SHUFFLE_MASK(func, type, scalar_t, lanes, select_mask)           \
  do                                                                          \
    {                                                                         \
      const scalar_t select_mask_local = (scalar_t) (select_mask);            \
      const scalar_t invalid_mask_local = (scalar_t) (~select_mask_local);    \
                                                                              \
      for (u32 iter = 0; iter < NUM_TEST_ITERS; ++iter)                       \
	{                                                                     \
	  type data = { 0 };                                                  \
	  type index = { 0 };                                                 \
                                                                              \
	  for (u32 lane = 0; lane < (lanes); ++lane)                          \
	    {                                                                 \
	      data[lane] = (scalar_t) random_u32 (&seed);                     \
                                                                              \
	      scalar_t base =                                                 \
		(scalar_t) (random_u32 (&seed) & select_mask_local);          \
	      if (random_u32 (&seed) & 1)                                     \
		index[lane] = base;                                           \
	      else                                                            \
		index[lane] = (scalar_t) ~0;                                  \
	    }                                                                 \
                                                                              \
	  type actual = func (data, index);                                   \
	  type expected = actual;                                             \
                                                                              \
	  for (u32 lane = 0; lane < (lanes); ++lane)                          \
	    {                                                                 \
	      scalar_t idx_val = index[lane];                                 \
	      expected =                                                      \
		type##_local_insert (expected,                                \
				     (idx_val & invalid_mask_local) ?         \
				       (scalar_t) 0 :                         \
				       data[idx_val & select_mask_local],     \
				     lane);                                   \
	    }                                                                 \
                                                                              \
	  if (memcmp (&expected, &actual, sizeof (expected)) != 0)            \
	    {                                                                 \
	      for (u32 lane = 0; lane < (lanes); ++lane)                      \
		{                                                             \
		  if (expected[lane] != actual[lane])                         \
		    return clib_error_return (                                \
		      err,                                                    \
		      "%s mismatch iter %u lane %u index=0x%llx "             \
		      "expected=0x%llx actual=0x%llx",                        \
		      #func, iter, lane, (unsigned long long) index[lane],    \
		      (unsigned long long) expected[lane],                    \
		      (unsigned long long) actual[lane]);                     \
		}                                                             \
	    }                                                                 \
	}                                                                     \
    }                                                                         \
  while (0)

TEST_INSERT_FUNCTION_DEFINE (u8x8, u8);
TEST_INSERT_FUNCTION_DEFINE (u16x4, u16);
TEST_INSERT_FUNCTION_DEFINE (u8x16, u8);
TEST_INSERT_FUNCTION_DEFINE (u16x8, u16);
TEST_INSERT_FUNCTION_DEFINE (u32x4, u32);
TEST_INSERT_FUNCTION_DEFINE (u8x32, u8);
TEST_INSERT_FUNCTION_DEFINE (u16x16, u16);
TEST_INSERT_FUNCTION_DEFINE (u32x8, u32);

static clib_error_t *
test_clib_dynamic_shuffle (clib_error_t *err)
{
  u32 seed = 0x9e3779b9;

  TEST_SHUFFLE_MASK (u8x8_shuffle_dynamic, u8x8, u8, 8, 0x7);
  TEST_SHUFFLE_MASK (u16x4_shuffle_dynamic, u16x4, u16, 4, 0x3);
  TEST_SHUFFLE_MASK (u8x16_shuffle_dynamic, u8x16, u8, 16, 0x0f);
  TEST_SHUFFLE_MASK (u16x8_shuffle_dynamic, u16x8, u16, 8, 0x7);
  TEST_SHUFFLE_MASK (u32x4_shuffle_dynamic, u32x4, u32, 4, 0x3);
  TEST_SHUFFLE_MASK (u8x32_shuffle_dynamic, u8x32, u8, 32, 0x1f);
  TEST_SHUFFLE_MASK (u16x16_shuffle_dynamic, u16x16, u16, 16, 0x0f);
  TEST_SHUFFLE_MASK (u32x8_shuffle_dynamic, u32x8, u32, 8, 0x7);

  return err;
}

#undef TEST_SHUFFLE_MASK

#define foreach_dynamic_shuffle_perf_case(_)                                  \
  _ (u8x8, u8, 8, 0x7, 0x12345678)                                            \
  _ (u16x4, u16, 4, 0x3, 0x2468ace0)                                          \
  _ (u8x16, u8, 16, 0x0f, 0xf00dcafe)                                         \
  _ (u16x8, u16, 8, 0x7, 0xdeadbeef)                                          \
  _ (u32x4, u32, 4, 0x3, 0x13579bdf)                                          \
  _ (u32x8, u32, 8, 0x7, 0x0badf00d)                                          \
  _ (u8x32, u8, 32, 0x1f, 0xc001c0de)                                         \
  _ (u16x16, u16, 16, 0x0f, 0x42424242)

#define _(vec_t, scalar_t, lanes, select_mask, seed_init)                     \
  void __test_perf_fn perftest_shuffle_##vec_t (test_perf_t *tp)              \
  {                                                                           \
    vec_t *data = test_mem_alloc (sizeof (*data) * PERF_BATCH_SIZE);          \
    vec_t *indices = test_mem_alloc (sizeof (*indices) * PERF_BATCH_SIZE);    \
    u32 seed = seed_init;                                                     \
    const scalar_t select_mask_local = (scalar_t) (select_mask);              \
    const scalar_t invalid_value = (scalar_t) ~0;                             \
                                                                              \
    for (u32 i = 0; i < PERF_BATCH_SIZE; ++i)                                 \
      {                                                                       \
	for (u32 lane = 0; lane < (lanes); ++lane)                            \
	  {                                                                   \
	    data[i][lane] = (scalar_t) random_u32 (&seed);                    \
	    scalar_t base =                                                   \
	      (scalar_t) (random_u32 (&seed) & select_mask_local);            \
	    if (random_u32 (&seed) & 1)                                       \
	      indices[i][lane] = base;                                        \
	    else                                                              \
	      indices[i][lane] = invalid_value;                               \
	  }                                                                   \
      }                                                                       \
                                                                              \
    test_perf_event_enable (tp);                                              \
    for (u32 i = 0; i < tp->n_ops; ++i)                                       \
      {                                                                       \
	u32 pos = i & (PERF_BATCH_SIZE - 1);                                  \
	vec_t res = vec_t##_shuffle_dynamic (data[pos], indices[pos]);        \
	data[pos] = res;                                                      \
      }                                                                       \
    test_perf_event_disable (tp);                                             \
                                                                              \
    tp->arg0 = 0;                                                             \
  }
foreach_dynamic_shuffle_perf_case (_)
#undef _

#define _(vec_t, scalar_t, lanes, select_mask, seed_init)                     \
  { .name = #vec_t " shuffle (per op)",                                       \
    .n_ops = 32768,                                                           \
    .fn = perftest_shuffle_##vec_t },

  REGISTER_TEST (clib_dynamic_shuffle) = {
    .name = "clib_dynamic_shuffle",
    .fn = test_clib_dynamic_shuffle,
    .perf_tests = (test_perf_t[]){ foreach_dynamic_shuffle_perf_case (_){} },
  };

#undef _
#undef foreach_dynamic_shuffle_perf_case
