/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vppinfra/mem.h>
#include <vlib/vlib.h>

#define MB_TEST_I(_cond, _comment, _args...)                                  \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    _evald;                                                                   \
  })

#define MB_TEST(_cond, _comment, _args...)                                    \
  {                                                                           \
    if (!MB_TEST_I (_cond, _comment, ##_args))                                \
      {                                                                       \
	return 1;                                                             \
      }                                                                       \
  }

typedef struct test_struct_
{
  u32 data;
} test_struct_t;

static int
mem_bulk_test_basic (vlib_main_t *vm, unformat_input_t *input)
{
  int __clib_unused verbose, i, rv, n_iter = 1000;
  test_struct_t *elt, **elts = 0;
  clib_mem_bulk_handle_t mb;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  mb = clib_mem_bulk_init (sizeof (test_struct_t), 0, 0);

  for (i = 0; i < n_iter; i++)
    {
      elt = clib_mem_bulk_alloc (mb);
      vec_add1 (elts, elt);
    }

  for (i = 0; i < n_iter; i++)
    elts[i]->data = i;

  for (i = 0; i < n_iter; i++)
    if (elts[i]->data != i)
      MB_TEST (0, "data corrupted");

  for (i = 0; i < n_iter; i++)
    clib_mem_bulk_free (mb, elts[i]);

  /*
   * realloc all
   */
  for (i = 0; i < n_iter; i++)
    {
      elt = clib_mem_bulk_alloc (mb);
      vec_add1 (elts, elt);
    }

  for (i = n_iter - 1; i >= 0; i--)
    elts[i]->data = i;

  for (i = n_iter - 1; i >= 0; i--)
    if (elts[i]->data != i)
      MB_TEST (0, "data corrupted");

  for (i = 0; i < n_iter; i++)
    clib_mem_bulk_free (mb, elts[i]);

  clib_mem_bulk_destroy (mb);
  vec_free (elts);

  return 0;
}

static clib_error_t *
mem_bulk_test (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd_arg)
{
  int res = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	{
	  res = mem_bulk_test_basic (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = mem_bulk_test_basic (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "llist unit test failed");
  return 0;
}

VLIB_CLI_COMMAND (mem_bulk_test_command, static) = {
  .path = "test membulk",
  .short_help = "internal membulk unit tests",
  .function = mem_bulk_test,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
