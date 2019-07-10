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
#include <vppinfra/llist.h>
#include <vlib/vlib.h>

#define LLIST_TEST_I(_cond, _comment, _args...)			\
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

#define LLIST_TEST(_cond, _comment, _args...)			\
{								\
    if (!LLIST_TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

typedef struct list_elt
{
  llist_elt_t ll_test;
  llist_elt_t ll_test2;
  u32 data;
} list_elt_t;

static int
llist_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  list_elt_t *pelts = 0, *head_entry, *head_entry2, *e, *next;
  int __clib_unused verbose, i;
  llist_index_t head, head2;

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

  head = llist_make_head (pelts, ll_test);

  /*
   * Add head elements and test insertion
   */
  for (i = 0; i < 100; i++)
    {
      pool_get (pelts, e);
      e->data = i;
      head_entry = llist_pool_entry (pelts, head);
      llist_add (pelts, ll_test, e, head_entry);
    }

  i--;
  e = head_entry = llist_pool_entry (pelts, head);
  while (((e = llist_next (pelts, ll_test, e)) != head_entry))
    {
      if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
      i--;
    }

  LLIST_TEST (1, "head insertion works");

  /*
   * Remove head elements
   */
  i = 99;
  e = llist_next (pelts, ll_test, head_entry);
  while (e != head_entry)
    {
      next = llist_next (pelts, ll_test, e);

      if (e->data != i)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);

      llist_remove (pelts, ll_test, e);
      pool_put (pelts, e);
      i--;
      e = next;
    }

  e = llist_pool_entry (pelts, head);
  LLIST_TEST (e == llist_next (pelts, ll_test, e), "list should be empty");
  LLIST_TEST (pool_elts (pelts) == 1, "pool should have only 1 element");

  /*
   * Add tail elements to ll_test2 and test
   */
  head2 = llist_make_head (pelts, ll_test2);
  for (i = 0; i < 100; i++)
    {
      pool_get (pelts, e);
      e->data = i;
      head_entry2 = llist_pool_entry (pelts, head2);
      llist_add_tail (pelts, ll_test2, e, head_entry2);
    }

  i--;
  e = head_entry2 = llist_pool_entry (pelts, head2);
  while (((e = llist_prev (pelts, ll_test2, e)) != head_entry2))
    {
      if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
      i--;
    }
  LLIST_TEST (1, "tail insertion works");

  /*
   * Remove in from ll_test2 and add to ll_test
   */
  i = 0;
  head_entry = llist_pool_entry (pelts, head);
  e = llist_next (pelts, ll_test2, head_entry2);
  while (e != head_entry2)
    {
      next = llist_next (pelts, ll_test2, e);

      if (e->data != i)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);

      llist_remove (pelts, ll_test2, e);
      llist_add_tail (pelts, ll_test, e, head_entry);
      i++;
      e = next;
    }

  i = 0;
  e = head_entry = llist_pool_entry (pelts, head);
  while (((e = llist_prev (pelts, ll_test, e)) != head_entry))
    {
      if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
      i++;
    }
  LLIST_TEST (1, "move from ll_test2 to ll_test worked");

  e = llist_pool_entry (pelts, head2);
  LLIST_TEST (e == llist_next (pelts, ll_test2, e),
	      "ll_test2 should be empty");

  return 0;
}

static clib_error_t *
llist_test (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	{
	  res = llist_test_basic (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = llist_test_basic (vm, input)))
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (llist_test_command, static) =
{
  .path = "test llist",
  .short_help = "internal llist unit tests",
  .function = llist_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
