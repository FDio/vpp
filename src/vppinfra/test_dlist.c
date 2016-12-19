/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vppinfra/dlist.h>

typedef struct
{
  dlist_elt_t *test_pool;
  u32 head_index;
} test_main_t;

test_main_t test_main;

int
test_dlist_main (unformat_input_t * input)
{
  test_main_t *tm = &test_main;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 value;
  int i;

  pool_get (tm->test_pool, head);
  head_index = head - tm->test_pool;
  clib_dlist_init (tm->test_pool, head - tm->test_pool);

  for (i = 1; i <= 3; i++)
    {
      pool_get (tm->test_pool, elt);
      elt_index = elt - tm->test_pool;

      clib_dlist_init (tm->test_pool, elt_index);
      elt->value = i;
      clib_dlist_addtail (tm->test_pool, head_index, elt_index);
    }

  head = pool_elt_at_index (tm->test_pool, head_index);

  fformat (stdout, "Dump forward links\n");
  elt_index = head->next;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->next;
      value = elt->value;
    }

  fformat (stdout, "Dump reverse links\n");
  elt_index = head->prev;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->prev;
      value = elt->value;
    }

  fformat (stdout, "remove first element\n");

  elt_index = clib_dlist_remove_head (tm->test_pool, head_index);
  elt = pool_elt_at_index (tm->test_pool, elt_index);

  fformat (stdout, "removed index %d value %d\n", elt_index, elt->value);

  head = pool_elt_at_index (tm->test_pool, head_index);

  fformat (stdout, "Dump forward links\n");
  elt_index = head->next;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->next;
      value = elt->value;
    }

  fformat (stdout, "Dump reverse links\n");
  elt_index = head->prev;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->prev;
      value = elt->value;
    }

  fformat (stdout, "re-insert index %d value %d at head\n", 1, 1);

  clib_dlist_addhead (tm->test_pool, head_index, 1);

  fformat (stdout, "Dump forward links\n");
  elt_index = head->next;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->next;
      value = elt->value;
    }

  fformat (stdout, "Dump reverse links\n");
  elt_index = head->prev;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->prev;
      value = elt->value;
    }

  fformat (stdout, "Remove middle element\n");

  clib_dlist_remove (tm->test_pool, 2);
  elt = pool_elt_at_index (tm->test_pool, 2);

  fformat (stdout, "removed index %d value %d\n", elt_index, elt->value);

  fformat (stdout, "Dump forward links\n");
  elt_index = head->next;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->next;
      value = elt->value;
    }

  fformat (stdout, "Dump reverse links\n");
  elt_index = head->prev;
  i = 1;
  value = 0;
  while (value != ~0)
    {
      elt = pool_elt_at_index (tm->test_pool, elt_index);
      fformat (stdout, "elt %d value %d\n", i++, elt->value);
      elt_index = elt->prev;
      value = elt->value;
    }

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  ret = test_dlist_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
