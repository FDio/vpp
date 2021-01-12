/*
 * Copyright (c) 2021 EMnify.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>

#include <vlib/counter.h>
#include <vpp/stats/stat_segment.h>

enum
{
  type_simple = 0,
  type_combined,
};

enum
{
  test_expand = 0,
};

/*
 * Return the stats segment epoch value.
 */
static uint64_t
get_stats_epoch ()
{
  stat_segment_main_t *sm = &stat_segment_main;
  return sm->shared_header->epoch;
}

/*
 * Return the maximum element count of the vector based on its allocated
 * memory.
 */
static int
get_vec_mem_size (void *v, uword data_size)
{
  stat_segment_main_t *sm = &stat_segment_main;

  if (v == 0)
    return 0;

  uword aligned_header_bytes = vec_header_bytes (0);
  void *p = v - aligned_header_bytes;
  void *oldheap = clib_mem_set_heap (sm->heap);
  int mem_size = (clib_mem_size (p) - aligned_header_bytes) / data_size;
  clib_mem_set_heap (oldheap);

  return mem_size;
}

/* number of times to repeat the counter expand tests */
#define EXPAND_TEST_ROUNDS 3

/*
 * Let a simple counter vector grow and verify that
 * the stats epoch is increased only when the vector
 * is expanded.
 */
static clib_error_t *
test_simple_counter_expand (vlib_main_t *vm)
{
  vlib_simple_counter_main_t counter = {
    .name = "test-simple-counter-expand",
    .stat_segment_name = "/vlib/test-simple-counter-expand",
  };
  int i, index;
  uint64_t epoch, new_epoch;

  // Create one counter to allocate the vector.
  vlib_validate_simple_counter (&counter, 0);
  epoch = get_stats_epoch ();

  for (i = 0; i < EXPAND_TEST_ROUNDS; i++)
    {
      // Check how many elements fit into the counter vector without expanding
      // that. The next validate calls should not increase the stats segment
      // epoch.
      int mem_size = get_vec_mem_size (counter.counters[0],
				       sizeof ((counter.counters[0])[0]));
      for (index = 1; index <= mem_size - 1; index++)
	{
	  vlib_validate_simple_counter (&counter, index);
	  new_epoch = get_stats_epoch ();
	  if (new_epoch != epoch)
	    return clib_error_return (
	      0, "Stats segment epoch should not increase");
	}

      // The next counter index does not fit and it will extend the vector.
      // The stats segment epoch should increase.
      vlib_validate_simple_counter (&counter, index + 1);
      new_epoch = get_stats_epoch ();
      if (new_epoch == epoch)
	return clib_error_return (0,
				  "Stats segment epoch should have increased");
      epoch = new_epoch;
    }

  return 0;
}

/*
 * Let a combined counter vector grow and verify that
 * the stats epoch is increased only when the vector
 * is expanded.
 */
static clib_error_t *
test_combined_counter_expand (vlib_main_t *vm)
{
  vlib_combined_counter_main_t counter = {
    .name = "test-combined-counter-expand",
    .stat_segment_name = "/vlib/test-combined-counter-expand",
  };
  int i, index;
  uint64_t epoch, new_epoch;

  // Create one counter to allocate the vector.
  vlib_validate_combined_counter (&counter, 0);
  epoch = get_stats_epoch ();

  for (i = 0; i < EXPAND_TEST_ROUNDS; i++)
    {
      // Check how many elements fit into the counter vector without expanding
      // that. The next validate calls should not increase the stats segment
      // epoch.
      int mem_size = get_vec_mem_size (counter.counters[0],
				       sizeof ((counter.counters[0])[0]));
      for (index = 1; index <= mem_size - 1; index++)
	{
	  vlib_validate_combined_counter (&counter, index);
	  new_epoch = get_stats_epoch ();
	  if (new_epoch != epoch)
	    return clib_error_return (
	      0, "Stats segment epoch should not increase");
	}

      // The next counter index does not fit and it will extend the vector.
      // The stats segment epoch should increase.
      vlib_validate_combined_counter (&counter, index + 1);
      new_epoch = get_stats_epoch ();
      if (new_epoch == epoch)
	return clib_error_return (0,
				  "Stats segment epoch should have increased");
      epoch = new_epoch;
    }

  return 0;
}

static clib_error_t *
test_simple_counter (vlib_main_t *vm, int test_case)
{
  clib_error_t *error;

  switch (test_case)
    {
    case test_expand:
      error = test_simple_counter_expand (vm);
      break;

    default:
      return clib_error_return (0, "no such test");
    }

  return error;
}

static clib_error_t *
test_combined_counter (vlib_main_t *vm, int test_case)
{
  clib_error_t *error;

  switch (test_case)
    {
    case test_expand:
      error = test_combined_counter_expand (vm);
      break;

    default:
      return clib_error_return (0, "no such test");
    }

  return error;
}

static clib_error_t *
test_counter_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  clib_error_t *error;
  int counter_type = -1;
  int test_case = -1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "simple"))
	counter_type = type_simple;
      else if (unformat (input, "combined"))
	counter_type = type_combined;
      else if (unformat (input, "expand"))
	test_case = test_expand;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (test_case == -1)
    return clib_error_return (0, "no such test");

  switch (counter_type)
    {
    case type_simple:
      error = test_simple_counter (vm, test_case);
      break;

    case type_combined:
      error = test_combined_counter (vm, test_case);
      break;

    default:
      return clib_error_return (0, "no such test");
    }

  return error;
}

VLIB_CLI_COMMAND (test_counter_command, static) = {
  .path = "test counter",
  .short_help = "test counter [simple | combined] expand",
  .function = test_counter_command_fn,
};

static clib_error_t *
test_counter_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (test_counter_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
