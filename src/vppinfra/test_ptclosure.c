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

#include <vppinfra/ptclosure.h>
#include <vppinfra/hash.h>

typedef struct
{
  uword *index_by_name;
  u8 *items;
} test_main_t;

test_main_t test_main;

static char *items[] = {
  "d",
  "a",
  "b",
  "c",
};

char *constraints[] = {
  "a,b",
  "b,c",
  "d,b",
  //    "c,a", /* no partial order possible */
};

u32
vl (void *p)
{
  return vec_len (p);
}

static void
dump_closure (test_main_t * tm, char *s, u8 ** orig)
{
  int i, j;

  fformat (stdout, "--------- %s --------------\n", s);
  for (i = 0; i < vec_len (orig); i++)
    {
      for (j = 0; j < vec_len (orig); j++)
	if (orig[i][j])
	  {
	    fformat (stdout, "%s <before> %s\n", items[i], items[j]);
	  }
    }
}

int
comma_split (u8 * s, u8 ** a, u8 ** b)
{
  *a = s;

  while (*s && *s != ',')
    s++;

  if (*s == ',')
    *s = 0;
  else
    return 1;

  *b = (u8 *) (s + 1);
  return 0;
}

int
test_ptclosure_main (unformat_input_t * input)
{
  test_main_t *tm = &test_main;
  u8 *item_name;
  int i, j;
  u8 **orig;
  u8 **closure;
  u8 *a_name, *b_name;
  int a_index, b_index;
  uword *p;
  u8 *this_constraint;
  int n;
  u32 *result = 0;

  tm->index_by_name = hash_create_string (0, sizeof (uword));

  n = ARRAY_LEN (items);

  for (i = 0; i < n; i++)
    {
      item_name = (u8 *) items[i];
      hash_set_mem (tm->index_by_name, item_name, i);
    }

  orig = clib_ptclosure_alloc (n);

  for (i = 0; i < ARRAY_LEN (constraints); i++)
    {
      this_constraint = format (0, "%s%c", constraints[i], 0);

      if (comma_split (this_constraint, &a_name, &b_name))
	{
	  clib_warning ("couldn't split '%s'", constraints[i]);
	  return 1;
	}

      p = hash_get_mem (tm->index_by_name, a_name);
      if (p == 0)
	{
	  clib_warning ("couldn't find '%s'", a_name);
	  return 1;
	}
      a_index = p[0];

      p = hash_get_mem (tm->index_by_name, b_name);
      if (p == 0)
	{
	  clib_warning ("couldn't find '%s'", b_name);
	  return 1;
	}
      b_index = p[0];

      orig[a_index][b_index] = 1;
      vec_free (this_constraint);
    }

  dump_closure (tm, "original relation", orig);

  closure = clib_ptclosure (orig);

  dump_closure (tm, "closure", closure);

  /*
   * Output partial order
   */

again:
  for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
	{
	  if (closure[i][j])
	    goto item_constrained;
	}
      /* Item i can be output */
      vec_add1 (result, i);
      {
	int k;
	for (k = 0; k < n; k++)
	  closure[k][i] = 0;
	/* "Magic" a before a, to keep from ever outputting it again */
	closure[i][i] = 1;
	goto again;
      }
    item_constrained:
      ;
    }

  if (vec_len (result) != n)
    {
      clib_warning ("no partial order exists");
      exit (1);
    }

  fformat (stdout, "Partial order:\n");

  for (i = vec_len (result) - 1; i >= 0; i--)
    {
      fformat (stdout, "%s\n", items[result[i]]);
    }

  vec_free (result);
  clib_ptclosure_free (orig);
  clib_ptclosure_free (closure);

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
  ret = test_ptclosure_main (&i);
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
