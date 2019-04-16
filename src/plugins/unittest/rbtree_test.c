/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vppinfra/rbtree.h>
#include <vlib/vlib.h>

#define RBTREE_TEST_I(_cond, _comment, _args...)		\
({								\
  int _evald = (_cond);						\
  if (!(_evald)) {						\
    fformat(stderr, "FAIL:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  } else {							\
    fformat(stderr, "PASS:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  }								\
  _evald;							\
})

#define RBTREE_TEST(_cond, _comment, _args...)			\
{								\
    if (!RBTREE_TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

static int
rbtree_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  int __clib_unused verbose, n_keys = 10e3, i;
  rb_tree_t _rt, *rt = &_rt;
  u32 *test_keys = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "nkeys %u", &n_keys))
	;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  rb_tree_init (rt);
  RBTREE_TEST (rb_tree_n_nodes (rt) == 1, "tnil created");

  vec_validate (test_keys, n_keys - 1);
  for (i = 0; i < n_keys; i++)
    {
      test_keys[i] = i;
      rb_tree_add (rt, i);
    }

  RBTREE_TEST (rb_tree_n_nodes (rt) == n_keys + 1, "all nodes added");
  return 0;
}

static clib_error_t *
rbtree_test (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	{
	  res = rbtree_test_basic (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = rbtree_test_basic (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "rbtree unit test failed");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (rbtree_test_command, static) =
{
  .path = "test rbtree",
  .short_help = "internal tcp unit tests",
  .function = rbtree_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
