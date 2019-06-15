/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
  int __clib_unused verbose, n_keys = 1e3, i;
  u32 *test_keys = 0, search_key;
  rb_tree_t _rt, *rt = &_rt;
  rb_node_t *n, *aux;

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

  /*
   * Add keys
   */
  vec_validate (test_keys, n_keys - 1);
  for (i = n_keys - 1; i >= 0; i--)
    {
      test_keys[i] = i;
      rb_tree_add (rt, i);
    }

  RBTREE_TEST (rb_tree_n_nodes (rt) == n_keys + 1, "all nodes added");

  n = rb_tree_max_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == n_keys - 1, "max should be %u", n_keys - 1);

  n = rb_tree_min_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == 0, "min should be %u", 0);

  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), n_keys / 2);
  RBTREE_TEST (n->key == n_keys / 2, "search result should be %u",
	       n_keys / 2);

  aux = rb_tree_successor (rt, n);
  RBTREE_TEST (aux->key == n_keys / 2 + 1, "successor should be %u is %u",
	       n_keys / 2 + 1, aux->key);

  aux = rb_tree_predecessor (rt, n);
  RBTREE_TEST (aux->key == n_keys / 2 - 1, "predecessor should be %u is %u",
	       n_keys / 2 - 1, aux->key);

  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), n_keys);
  RBTREE_TEST (rb_node_is_tnil (rt, n), "search result should be tnil");

  /*
   * Delete even keys
   */
  for (i = 0; i < n_keys; i += 2)
    rb_tree_del (rt, i);

  n = rb_tree_max_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == n_keys - 1, "max should be %u", n_keys - 1);

  n = rb_tree_min_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == 1, "min should be %u and is %u", 1, n->key);

  search_key = 2 * ((n_keys - 1) / 4);
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (rb_node_is_tnil (rt, n), "search result for %u should be tnil",
	       search_key);

  search_key += 1;
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (n->key == search_key, "search result should be %u",
	       search_key);

  aux = rb_tree_successor (rt, n);
  RBTREE_TEST (aux->key == search_key + 2, "successor should be %u is %u",
	       search_key + 2, aux->key);

  aux = rb_tree_predecessor (rt, n);
  RBTREE_TEST (aux->key == search_key - 2, "predecessor should be %u is %u",
	       search_key - 2, aux->key);

  /*
   * Re-add even keys
   */
  for (i = 0; i < n_keys; i += 2)
    rb_tree_add (rt, i);

  RBTREE_TEST (rb_tree_n_nodes (rt) == n_keys + 1, "number nodes %u is %u",
	       n_keys + 1, rb_tree_n_nodes (rt));

  n = rb_tree_max_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == n_keys - 1, "max should be %u", n_keys - 1);

  n = rb_tree_min_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (n->key == 0, "min should be %u", 0);

  search_key = 2 * ((n_keys - 1) / 4);
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (n->key == search_key, "search result should be %u",
	       search_key);

  search_key += 1;
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (n->key == search_key, "search result should be %u",
	       search_key);

  aux = rb_tree_successor (rt, n);
  RBTREE_TEST (aux->key == search_key + 1, "successor should be %u is %u",
	       search_key + 1, aux->key);

  aux = rb_tree_predecessor (rt, n);
  RBTREE_TEST (aux->key == search_key - 1, "predecessor should be %u is %u",
	       search_key - 1, aux->key);

  /*
   * Delete all keys
   */
  for (i = 0; i < n_keys; i++)
    rb_tree_del (rt, i);

  RBTREE_TEST (rb_tree_n_nodes (rt) == 1, "number nodes %u is %u",
	       1, rb_tree_n_nodes (rt));

  n = rb_tree_min_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (rb_node_is_tnil (rt, n), "min should be tnil");

  n = rb_tree_max_subtree (rt, rb_node (rt, rt->root));
  RBTREE_TEST (rb_node_is_tnil (rt, n), "max should be tnil");

  search_key = 2 * ((n_keys - 1) / 4);
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (rb_node_is_tnil (rt, n), "search result should be tnil");

  /*
   * Test successor/predecessor
   */
  u8 test_vals[] = { 2, 3, 4, 6, 7, 9, 13, 15, 17, 18, 20 };
  for (i = 0; i < sizeof (test_vals) / sizeof (u8); i++)
    rb_tree_add (rt, test_vals[i]);

  search_key = 13;
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), search_key);
  RBTREE_TEST (n->key == search_key, "search result should be %u",
	       search_key);

  aux = rb_tree_successor (rt, n);
  RBTREE_TEST (aux->key == 15, "successor should be %u is %u", 15, aux->key);

  aux = rb_tree_predecessor (rt, n);
  RBTREE_TEST (aux->key == 9, "predecessor should be %u is %u", 9, aux->key);

  n = aux;
  aux = rb_tree_predecessor (rt, n);
  RBTREE_TEST (aux->key == 7, "predecessor should be %u is %u", 7, aux->key);

  /*
   * Cleanup
   */
  rb_tree_free_nodes (rt);
  RBTREE_TEST (rb_tree_n_nodes (rt) == 0, "number nodes %u is %u",
	       0, rb_tree_n_nodes (rt));

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
  .short_help = "internal rbtree unit tests",
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
