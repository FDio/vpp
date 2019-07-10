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
  llist_anchor_t ll_test;
  llist_anchor_t ll_test2;
  u32 data;
} list_elt_t;

#define list_elt_is_sane(pl,name,E,P,N)					\
 (E->name.next == (N) - pl 						\
  && E->name.prev == (P) - pl 						\
  && P->name.next == (E) - pl 						\
  && N->name.prev == (E) - pl)

#define list_test_is_sane(pl,name,h)					\
do {									\
  typeof (pl) e;							\
  int rv;								\
  llist_foreach (pl, name, h, e, ({					\
    rv = list_elt_is_sane ((pl), name, (e),				\
			   llist_prev (pl,name,e),			\
                           llist_next (pl,name,e));			\
    if (!rv)								\
      LLIST_TEST (0, "invalid elt %u prev %u/%u next %u/%u", e - pl, 	\
                  e->name.prev, llist_prev (pl,name,e) - pl,		\
                  e->name.next, llist_next (pl,name,e) - pl);		\
  }));									\
} while (0)

static int
llist_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  list_elt_t *pelts = 0, *he, *he2, *e, *next, *nnext;
  int __clib_unused verbose, i, rv;
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
  he = llist_pool_entry (pelts, head);

  LLIST_TEST (he->ll_test.next == head, "head next points to itself");
  LLIST_TEST (he->ll_test.prev == head, "head prev points to itself");
  LLIST_TEST (he == llist_next (pelts, ll_test, he), "should be the same");
  LLIST_TEST (he == llist_prev (pelts, ll_test, he), "should be the same");

  /*
   * Add and remove one element
   */
  pool_get (pelts, e);
  e->data = 1;
  he = llist_pool_entry (pelts, head);
  llist_add (pelts, ll_test, e, he);

  LLIST_TEST (e->ll_test.next == head, "next should be head");
  LLIST_TEST (e->ll_test.prev == head, "prev should be head");
  LLIST_TEST (he->ll_test.prev == e - pelts, "prev should be new");
  LLIST_TEST (he->ll_test.next == e - pelts, "prev should be new");

  llist_remove (pelts, ll_test, e);
  pool_put (pelts, e);
  LLIST_TEST (he->ll_test.prev == head, "prev should be head");
  LLIST_TEST (he->ll_test.prev == head, "next should be head");
  LLIST_TEST (he == llist_next (pelts, ll_test, he), "should be the same");
  LLIST_TEST (he == llist_prev (pelts, ll_test, he), "should be the same");

  /*
   * Add multiple head elements and test insertion
   */
  for (i = 0; i < 100; i++)
    {
      pool_get (pelts, e);
      e->data = i;
      he = llist_pool_entry (pelts, head);
      llist_add (pelts, ll_test, e, he);
    }

  e = he = llist_pool_entry (pelts, head);
  LLIST_TEST (e != llist_next (pelts, ll_test, e), "shoud not be empty");
  list_test_is_sane (pelts, ll_test, he);

  i--;
  /* *INDENT-OFF* */
  llist_foreach (pelts, ll_test, he, e, ({
    if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
    i--;
  }));
  /* *INDENT-ON* */

  LLIST_TEST (i == -1, "head insertion works i = %d", i);

  /*
   * Remove elements from head
   */
  i = 99;
  e = llist_next (pelts, ll_test, he);
  while (e != he)
    {
      next = llist_next (pelts, ll_test, e);
      llist_remove (pelts, ll_test, e);
      pool_put (pelts, e);
      i--;
      e = next;
    }

  he = llist_pool_entry (pelts, head);
  list_test_is_sane (pelts, ll_test, he);
  LLIST_TEST (llist_is_empty (pelts, ll_test, he), "list should be empty");
  LLIST_TEST (pool_elts (pelts) == 1, "pool should have only 1 element");

  /*
   * Add tail elements to ll_test2 and test
   */
  head2 = llist_make_head (pelts, ll_test2);
  for (i = 0; i < 100; i++)
    {
      pool_get (pelts, e);
      e->data = i;
      he2 = llist_pool_entry (pelts, head2);
      llist_add_tail (pelts, ll_test2, e, he2);
    }

  he2 = llist_pool_entry (pelts, head2);
  list_test_is_sane (pelts, ll_test2, he2);
  LLIST_TEST (!llist_is_empty (pelts, ll_test2, he2), "list should not be empty");

  i--;
  e = llist_prev (pelts, ll_test2, he2);
  while (e != he2)
    {
      if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
      i--;
      e = llist_prev (pelts, ll_test2, e);
    }
  LLIST_TEST (1, "tail insertion works");

  /*
   * Remove in from ll_test2 and add to ll_test
   */
  i = 0;
  he = llist_pool_entry (pelts, head);
  e = llist_next (pelts, ll_test2, he2);
  while (e != he2)
    {
      next = llist_next (pelts, ll_test2, e);

      if (e->data != i)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);

      llist_remove (pelts, ll_test2, e);
      llist_add_tail (pelts, ll_test, e, he);
      i++;
      e = next;
    }

  he = llist_pool_entry (pelts, head);
  he2 = llist_pool_entry (pelts, head2);
  list_test_is_sane (pelts, ll_test, he);
  LLIST_TEST (!llist_is_empty (pelts, ll_test, he), "shoud not be empty");
  LLIST_TEST (llist_is_empty (pelts, ll_test2, he2), "shoud be empty");

  i = 0;

  /* *INDENT-OFF* */
  llist_foreach (pelts, ll_test, he, e, ({
    if (i != e->data)
	LLIST_TEST (0, "incorrect element i = %u data = %u", i, e->data);
    i++;
  }));
  /* *INDENT-ON* */

  LLIST_TEST (i == 100, "move from ll_test2 to ll_test worked i %u", i);

  e = llist_pool_entry (pelts, head2);
  LLIST_TEST (e == llist_next (pelts, ll_test2, e),
	      "ll_test2 should be empty");

  /*
   * Delete and insert at random position
   */
  e = llist_pool_entry (pelts, head);
  for (i = 0; i < 10; i++)
    e = llist_next (pelts, ll_test, e);

  next = llist_next (pelts, ll_test, e);
  nnext = llist_next (pelts, ll_test, next);

  LLIST_TEST (e->data == 9, "data should be 9 is %u", e->data);
  LLIST_TEST (next->data == 10, "data should be 10");
  LLIST_TEST (nnext->data == 11, "data should be 11");

  llist_remove (pelts, ll_test, next);
  pool_put (pelts, next);
  memset (next, 0xfc, sizeof (*next));

  next = llist_next (pelts, ll_test, e);
  LLIST_TEST (next->data == 11, "data should be 11");
  LLIST_TEST (next == nnext, "should be nnext");

  pool_get (pelts, next);
  next->data = 10;
  llist_insert (pelts, ll_test, next, e);

  next = llist_next (pelts, ll_test, e);
  LLIST_TEST (next->data == 10, "new next data should be 10");
  next = llist_next (pelts, ll_test, next);
  LLIST_TEST (nnext == next, "next should be linked to old nnext");

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
