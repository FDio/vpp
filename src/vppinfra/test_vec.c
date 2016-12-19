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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
  Written by Fred Delley <fdelley@cisco.com> .

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifdef CLIB_LINUX_KERNEL
#include <linux/unistd.h>
#endif

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#include <vppinfra/clib.h>
#include <vppinfra/mheap.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>

#include "test_vec.h"

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

#define MAX_CHANGE 100


typedef enum
{
  /* Values have to be sequential and start with 0. */
  OP_IS_VEC_RESIZE = 0,
  OP_IS_VEC_ADD1,
  OP_IS_VEC_ADD2,
  OP_IS_VEC_ADD,
  OP_IS_VEC_INSERT,
  OP_IS_VEC_INSERT_ELTS,
  OP_IS_VEC_DELETE,
  OP_IS_VEC_DUP,
  OP_IS_VEC_IS_EQUAL,
  OP_IS_VEC_ZERO,
  OP_IS_VEC_SET,
  OP_IS_VEC_VALIDATE,
  OP_IS_VEC_FREE,
  OP_IS_VEC_INIT,
  OP_IS_VEC_CLONE,
  OP_IS_VEC_APPEND,
  OP_IS_VEC_PREPEND,
  /* Operations on vectors with custom headers. */
  OP_IS_VEC_INIT_H,
  OP_IS_VEC_RESIZE_H,
  OP_IS_VEC_FREE_H,
  OP_MAX,
} op_t;

#define FIRST_VEC_OP		OP_IS_VEC_RESIZE
#define LAST_VEC_OP		OP_IS_VEC_PREPEND
#define FIRST_VEC_HDR_OP	OP_IS_VEC_INIT_H
#define LAST_VEC_HDR_OP		OP_IS_VEC_FREE_H

uword g_prob_ratio[] = {
  [OP_IS_VEC_RESIZE] = 5,
  [OP_IS_VEC_ADD1] = 5,
  [OP_IS_VEC_ADD2] = 5,
  [OP_IS_VEC_ADD] = 5,
  [OP_IS_VEC_INSERT] = 5,
  [OP_IS_VEC_INSERT_ELTS] = 5,
  [OP_IS_VEC_DELETE] = 30,
  [OP_IS_VEC_DUP] = 5,
  [OP_IS_VEC_IS_EQUAL] = 5,
  [OP_IS_VEC_ZERO] = 2,
  [OP_IS_VEC_SET] = 3,
  [OP_IS_VEC_VALIDATE] = 5,
  [OP_IS_VEC_FREE] = 5,
  [OP_IS_VEC_INIT] = 5,
  [OP_IS_VEC_CLONE] = 5,
  [OP_IS_VEC_APPEND] = 5,
  [OP_IS_VEC_PREPEND] = 5,
  /* Operations on vectors with custom headers. */
  [OP_IS_VEC_INIT_H] = 5,
  [OP_IS_VEC_RESIZE_H] = 5,
  [OP_IS_VEC_FREE_H] = 5,
};

op_t *g_prob;
op_t *g_prob_wh;

uword g_call_stats[OP_MAX];


/* A structure for both vector headers and vector elements might be useful to
   uncover potential alignement issues. */

typedef struct
{
  u8 field1[4];
    CLIB_PACKED (u32 field2);
} hdr_t;

typedef struct
{
  u8 field1[3];
    CLIB_PACKED (u32 field2);
} elt_t;

#ifdef CLIB_UNIX
u32 g_seed = 0xdeadbabe;
uword g_verbose = 1;
#endif

op_t *g_op_prob;
uword g_set_verbose_at = ~0;
uword g_dump_period = ~0;


static u8 *
format_vec_op_type (u8 * s, va_list * args)
{
  op_t op = va_arg (*args, int);

  switch (op)
    {
#define _(n)					\
      case OP_IS_##n:				\
	s = format (s, "OP_IS_" #n);		\
	break;

      _(VEC_RESIZE);
      _(VEC_ADD1);
      _(VEC_ADD2);
      _(VEC_ADD);
      _(VEC_INSERT);
      _(VEC_INSERT_ELTS);
      _(VEC_DELETE);
      _(VEC_DUP);
      _(VEC_IS_EQUAL);
      _(VEC_ZERO);
      _(VEC_SET);
      _(VEC_VALIDATE);
      _(VEC_FREE);
      _(VEC_INIT);
      _(VEC_CLONE);
      _(VEC_APPEND);
      _(VEC_PREPEND);
      _(VEC_INIT_H);
      _(VEC_RESIZE_H);
      _(VEC_FREE_H);

    default:
      s = format (s, "Unknown vec op (%d)", op);
      break;
    }

#undef _

  return s;
}

static void
dump_call_stats (uword * stats)
{
  uword i;

  fformat (stdout, "Call Stats\n----------\n");

  for (i = 0; i < OP_MAX; i++)
    fformat (stdout, "%-8d %U\n", stats[i], format_vec_op_type, i);
}


/* XXX - Purposely low value for debugging the validator. Will be set it to a
   more sensible value later. */
#define MAX_VEC_LEN 10

#define create_random_vec_wh(elt_type, len, hdr_bytes, seed)			\
({										\
  elt_type * _v(v) = NULL;							\
  uword _v(l) = (len);								\
  uword _v(h) = (hdr_bytes);							\
  u8 * _v(hdr);									\
										\
  if (_v(l) == 0)								\
    goto __done__;								\
										\
  /* ~0 means select random length between 0 and MAX_VEC_LEN. */		\
  if (_v(l) == ~0)								\
    _v(l) = bounded_random_u32 (&(seed), 0, MAX_VEC_LEN);			\
										\
  _v(v) = _vec_resize (NULL, _v(l), _v(l) * sizeof (elt_type), _v(h), 0);	\
  fill_with_random_data (_v(v), vec_bytes (_v(v)), (seed));			\
										\
  /* Fill header with random data as well. */					\
  if (_v(h) > 0)								\
    {										\
      _v(hdr) = vec_header (_v(v), _v(h));					\
      fill_with_random_data (_v(hdr), _v(h), (seed));				\
    }										\
										\
__done__:									\
  _v(v);									\
})

#define create_random_vec(elt_type, len, seed) \
create_random_vec_wh (elt_type, len, 0, seed)

#define compute_vec_hash(hash, vec)			\
({							\
  u8 * _v(v) = (u8 *) (vec);				\
  uword _v(n) = vec_len (vec) * sizeof ((vec)[0]);	\
  u8 _v(hh) = (u8) (hash);				\
							\
  compute_mem_hash (_v(hh), _v(v), _v(n));		\
})

static elt_t *
validate_vec_free (elt_t * vec)
{
  vec_free (vec);
  ASSERT (vec == NULL);
  return vec;
}

static elt_t *
validate_vec_free_h (elt_t * vec, uword hdr_bytes)
{
  vec_free_h (vec, hdr_bytes);
  ASSERT (vec == NULL);
  return vec;
}

static void
validate_vec_hdr (elt_t * vec, uword hdr_bytes)
{
  u8 *hdr;
  u8 *hdr_end;
  vec_header_t *vh;

  if (!vec)
    return;

  vh = _vec_find (vec);
  hdr = vec_header (vec, hdr_bytes);
  hdr_end = vec_header_end (hdr, hdr_bytes);

  ASSERT (hdr_end == (u8 *) vec);
  ASSERT ((u8 *) vh - (u8 *) hdr >= hdr_bytes);
}

static void
validate_vec_len (elt_t * vec)
{
  u8 *ptr;
  u8 *end;
  uword len;
  uword bytes;
  uword i;
  elt_t *elt;

  if (!vec)
    return;

  ptr = (u8 *) vec;
  end = (u8 *) vec_end (vec);
  len = vec_len (vec);
  bytes = sizeof (vec[0]) * len;

  ASSERT (bytes == vec_bytes (vec));
  ASSERT ((ptr + bytes) == end);

  i = 0;

  /* XXX - TODO: confirm that auto-incrementing in vec_is_member() would not
     have the expected result. */
  while (vec_is_member (vec, (__typeof__ (vec[0]) *) ptr))
    {
      ptr++;
      i++;
    }

  ASSERT (ptr == end);
  ASSERT (i == bytes);

  i = 0;

  vec_foreach (elt, vec) i++;

  ASSERT (i == len);
}

static void
validate_vec (elt_t * vec, uword hdr_bytes)
{
  validate_vec_hdr (vec, hdr_bytes);
  validate_vec_len (vec);

  if (!vec || vec_len (vec) == 0)
    {
      VERBOSE3 ("Vector at %p has zero elements.\n\n", vec);
    }
  else
    {
      if (hdr_bytes > 0)
	VERBOSE3 ("Header: %U\n",
		  format_hex_bytes, vec_header (vec, sizeof (vec[0])),
		  sizeof (vec[0]));

      VERBOSE3 ("%U\n\n",
		format_hex_bytes, vec, vec_len (vec) * sizeof (vec[0]));
    }
}

static elt_t *
validate_vec_resize (elt_t * vec, uword num_elts)
{
  uword len1 = vec_len (vec);
  uword len2;
  u8 hash = compute_vec_hash (0, vec);

  vec_resize (vec, num_elts);
  len2 = vec_len (vec);

  ASSERT (len2 == len1 + num_elts);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_resize_h (elt_t * vec, uword num_elts, uword hdr_bytes)
{
  uword len1, len2;
  u8 *end1, *end2;
  u8 *hdr = NULL;
  u8 hash, hdr_hash;

  len1 = vec_len (vec);

  if (vec)
    hdr = vec_header (vec, hdr_bytes);

  hash = compute_vec_hash (0, vec);
  hdr_hash = compute_mem_hash (0, hdr, hdr_bytes);

  vec_resize_ha (vec, num_elts, hdr_bytes, 0);
  len2 = vec_len (vec);

  ASSERT (len2 == len1 + num_elts);

  end1 = (u8 *) (vec + len1);
  end2 = (u8 *) vec_end (vec);

  while (end1 != end2)
    {
      ASSERT (*end1 == 0);
      end1++;
    }

  if (vec)
    hdr = vec_header (vec, hdr_bytes);

  ASSERT (compute_vec_hash (hash, vec) == 0);
  ASSERT (compute_mem_hash (hdr_hash, hdr, hdr_bytes) == 0);
  validate_vec (vec, 1);
  return vec;
}

static elt_t *
generic_validate_vec_add (elt_t * vec, uword num_elts, uword is_add2)
{
  uword len1 = vec_len (vec);
  uword len2;
  u8 hash = compute_vec_hash (0, vec);
  elt_t *new;

  if (is_add2)
    {
      vec_add2 (vec, new, num_elts);
    }
  else
    {
      new = create_random_vec (elt_t, num_elts, g_seed);

      VERBOSE3 ("%U\n", format_hex_bytes, new,
		vec_len (new) * sizeof (new[0]));

      /* Add the hash value of the new elements to that of the old vector. */
      hash = compute_vec_hash (hash, new);

      if (num_elts == 1)
	vec_add1 (vec, new[0]);
      else if (num_elts > 1)
	vec_add (vec, new, num_elts);

      vec_free (new);
    }

  len2 = vec_len (vec);
  ASSERT (len2 == len1 + num_elts);

  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_add1 (elt_t * vec)
{
  return generic_validate_vec_add (vec, 1, 0);
}

static elt_t *
validate_vec_add2 (elt_t * vec, uword num_elts)
{
  return generic_validate_vec_add (vec, num_elts, 1);
}

static elt_t *
validate_vec_add (elt_t * vec, uword num_elts)
{
  return generic_validate_vec_add (vec, num_elts, 0);
}

static elt_t *
validate_vec_insert (elt_t * vec, uword num_elts, uword start_elt)
{
  uword len1 = vec_len (vec);
  uword len2;
  u8 hash;

  /* vec_insert() would not handle it properly. */
  if (start_elt > len1 || num_elts == 0)
    return vec;

  hash = compute_vec_hash (0, vec);
  vec_insert (vec, num_elts, start_elt);
  len2 = vec_len (vec);

  ASSERT (len2 == len1 + num_elts);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_insert_elts (elt_t * vec, uword num_elts, uword start_elt)
{
  uword len1 = vec_len (vec);
  uword len2;
  elt_t *new;
  u8 hash;

  /* vec_insert_elts() would not handle it properly. */
  if (start_elt > len1 || num_elts == 0)
    return vec;

  new = create_random_vec (elt_t, num_elts, g_seed);

  VERBOSE3 ("%U\n", format_hex_bytes, new, vec_len (new) * sizeof (new[0]));

  /* Add the hash value of the new elements to that of the old vector. */
  hash = compute_vec_hash (0, vec);
  hash = compute_vec_hash (hash, new);

  vec_insert_elts (vec, new, num_elts, start_elt);
  len2 = vec_len (vec);

  vec_free (new);

  ASSERT (len2 == len1 + num_elts);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_delete (elt_t * vec, uword num_elts, uword start_elt)
{
  uword len1 = vec_len (vec);
  uword len2;
  u8 *start;
  u8 hash;
  u8 hash_del;

  /* vec_delete() would not handle it properly. */
  if (start_elt + num_elts > len1)
    return vec;

  start = (u8 *) vec + (start_elt * sizeof (vec[0]));

  hash = compute_vec_hash (0, vec);
  hash_del = compute_mem_hash (0, start, num_elts * sizeof (vec[0]));
  hash ^= hash_del;

  vec_delete (vec, num_elts, start_elt);
  len2 = vec_len (vec);

  ASSERT (len2 == len1 - num_elts);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_dup (elt_t * vec)
{
  elt_t *new;
  u8 hash;

  hash = compute_vec_hash (0, vec);
  new = vec_dup (vec);

  ASSERT (compute_vec_hash (hash, new) == 0);

  validate_vec (new, 0);
  return new;
}

static elt_t *
validate_vec_zero (elt_t * vec)
{
  u8 *ptr;
  u8 *end;

  vec_zero (vec);

  ptr = (u8 *) vec;
  end = (u8 *) (vec + vec_len (vec));

  while (ptr != end)
    {
      ASSERT (ptr < (u8 *) vec_end (vec));
      ASSERT (ptr[0] == 0);
      ptr++;
    }

  validate_vec (vec, 0);
  return vec;
}

static void
validate_vec_is_equal (elt_t * vec)
{
  elt_t *new = NULL;

  if (vec_len (vec) <= 0)
    return;

  new = vec_dup (vec);
  ASSERT (vec_is_equal (new, vec));
  vec_free (new);
}

static elt_t *
validate_vec_set (elt_t * vec)
{
  uword i;
  uword len = vec_len (vec);
  elt_t *new;

  if (!vec)
    return NULL;

  new = create_random_vec (elt_t, 1, g_seed);

  VERBOSE3 ("%U\n", format_hex_bytes, new, vec_len (new) * sizeof (new[0]));

  vec_set (vec, new[0]);

  for (i = 0; i < len; i++)
    ASSERT (memcmp (&vec[i], &new[0], sizeof (vec[0])) == 0);

  vec_free (new);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_validate (elt_t * vec, uword index)
{
  uword len = vec_len (vec);
  word num_new = index - len + 1;
  u8 *ptr;
  u8 *end;
  u8 hash = compute_vec_hash (0, vec);

  if (num_new < 0)
    num_new = 0;

  vec_validate (vec, index);

  /* Old len but new vec pointer! */
  ptr = (u8 *) (vec + len);
  end = (u8 *) (vec + len + num_new);

  ASSERT (len + num_new == vec_len (vec));
  ASSERT (compute_vec_hash (hash, vec) == 0);

  while (ptr != end)
    {
      ASSERT (ptr < (u8 *) vec_end (vec));
      ASSERT (ptr[0] == 0);
      ptr++;
    }

  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_init (uword num_elts)
{
  u8 *ptr;
  u8 *end;
  uword len;
  elt_t *new;

  new = vec_new (elt_t, num_elts);
  len = vec_len (new);

  ASSERT (len == num_elts);

  ptr = (u8 *) new;
  end = (u8 *) (new + len);

  while (ptr != end)
    {
      ASSERT (ptr < (u8 *) vec_end (new));
      ASSERT (ptr[0] == 0);
      ptr++;
    }

  validate_vec (new, 0);
  return new;
}

static elt_t *
validate_vec_init_h (uword num_elts, uword hdr_bytes)
{
  uword i = 0;
  u8 *ptr;
  u8 *end;
  uword len;
  elt_t *new;

  new = vec_new_ha (elt_t, num_elts, hdr_bytes, 0);
  len = vec_len (new);

  ASSERT (len == num_elts);

  /* We have 2 zero-regions to check: header & vec data (skip _VEC struct). */
  for (i = 0; i < 2; i++)
    {
      if (i == 0)
	{
	  ptr = (u8 *) vec_header (new, hdr_bytes);
	  end = ptr + hdr_bytes;
	}
      else
	{
	  ptr = (u8 *) new;
	  end = (u8 *) (new + len);
	}

      while (ptr != end)
	{
	  ASSERT (ptr < (u8 *) vec_end (new));
	  ASSERT (ptr[0] == 0);
	  ptr++;
	}
    }

  validate_vec (new, 1);
  return new;
}

/* XXX - I don't understand the purpose of the vec_clone() call. */
static elt_t *
validate_vec_clone (elt_t * vec)
{
  elt_t *new;

  vec_clone (new, vec);

  ASSERT (vec_len (new) == vec_len (vec));
  ASSERT (compute_vec_hash (0, new) == 0);
  validate_vec (new, 0);
  return new;
}

static elt_t *
validate_vec_append (elt_t * vec)
{
  elt_t *new;
  uword num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
  uword len;
  u8 hash = 0;

  new = create_random_vec (elt_t, num_elts, g_seed);

  len = vec_len (vec) + vec_len (new);
  hash = compute_vec_hash (0, vec);
  hash = compute_vec_hash (hash, new);

  vec_append (vec, new);
  vec_free (new);

  ASSERT (vec_len (vec) == len);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static elt_t *
validate_vec_prepend (elt_t * vec)
{
  elt_t *new;
  uword num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
  uword len;
  u8 hash = 0;

  new = create_random_vec (elt_t, num_elts, g_seed);

  len = vec_len (vec) + vec_len (new);
  hash = compute_vec_hash (0, vec);
  hash = compute_vec_hash (hash, new);

  vec_prepend (vec, new);
  vec_free (new);

  ASSERT (vec_len (vec) == len);
  ASSERT (compute_vec_hash (hash, vec) == 0);
  validate_vec (vec, 0);
  return vec;
}

static void
run_validator_wh (uword iter)
{
  elt_t *vec;
  uword i;
  uword op;
  uword num_elts;
  uword len;
  uword dump_time;
  f64 time[3];			/* [0]: start, [1]: last, [2]: current */

  vec = create_random_vec_wh (elt_t, ~0, sizeof (hdr_t), g_seed);
  validate_vec (vec, 0);
  VERBOSE2 ("Start with len %d\n", vec_len (vec));

  time[0] = unix_time_now ();
  time[1] = time[0];
  dump_time = g_dump_period;

  for (i = 1; i <= iter; i++)
    {
      if (i >= g_set_verbose_at)
	g_verbose = 2;

      op = bounded_random_u32 (&g_seed, 0, vec_len (g_prob_wh) - 1);
      op = g_prob_wh[op];

      switch (op)
	{
	case OP_IS_VEC_INIT_H:
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  vec_free_h (vec, sizeof (hdr_t));
	  VERBOSE2 ("vec_init_h(), new elts %d\n", num_elts);
	  vec = validate_vec_init_h (num_elts, sizeof (hdr_t));
	  break;

	case OP_IS_VEC_RESIZE_H:
	  len = vec_len (vec);
	  num_elts = bounded_random_u32 (&g_seed, len, len + MAX_CHANGE);
	  VERBOSE2 ("vec_resize_h(), %d new elts.\n", num_elts);
	  vec = validate_vec_resize_h (vec, num_elts, sizeof (hdr_t));
	  break;

	case OP_IS_VEC_FREE_H:
	  VERBOSE2 ("vec_free_h()\n");
	  vec = validate_vec_free_h (vec, sizeof (hdr_t));
	  break;

	default:
	  ASSERT (0);
	  break;
	}

      g_call_stats[op]++;

      if (i == dump_time)
	{
	  time[2] = unix_time_now ();
	  VERBOSE1 ("%d vec ops in %f secs. (last %d in %f secs.).\n",
		    i, time[2] - time[0], g_dump_period, time[2] - time[1]);
	  time[1] = time[2];
	  dump_time += g_dump_period;

	  VERBOSE1 ("vec len %d\n", vec_len (vec));
	  VERBOSE2 ("%U\n\n",
		    format_hex_bytes, vec, vec_len (vec) * sizeof (vec[0]));
	}

      VERBOSE2 ("len %d\n", vec_len (vec));
    }

  validate_vec (vec, sizeof (hdr_t));
  vec_free_h (vec, sizeof (hdr_t));
}

static void
run_validator (uword iter)
{
  elt_t *vec;
  elt_t *new;
  uword i;
  uword op;
  uword num_elts;
  uword index;
  uword len;
  uword dump_time;
  f64 time[3];			/* [0]: start, [1]: last, [2]: current */

  vec = create_random_vec (elt_t, ~0, g_seed);
  validate_vec (vec, 0);
  VERBOSE2 ("Start with len %d\n", vec_len (vec));

  time[0] = unix_time_now ();
  time[1] = time[0];
  dump_time = g_dump_period;

  for (i = 1; i <= iter; i++)
    {
      if (i >= g_set_verbose_at)
	g_verbose = 2;

      op = bounded_random_u32 (&g_seed, 0, vec_len (g_prob) - 1);
      op = g_prob[op];

      switch (op)
	{
	case OP_IS_VEC_RESIZE:
	  len = vec_len (vec);
	  num_elts = bounded_random_u32 (&g_seed, len, len + MAX_CHANGE);
	  VERBOSE2 ("vec_resize(), %d new elts.\n", num_elts);
	  vec = validate_vec_resize (vec, num_elts);
	  break;

	case OP_IS_VEC_ADD1:
	  VERBOSE2 ("vec_add1()\n");
	  vec = validate_vec_add1 (vec);
	  break;

	case OP_IS_VEC_ADD2:
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  VERBOSE2 ("vec_add2(), %d new elts.\n", num_elts);
	  vec = validate_vec_add2 (vec, num_elts);
	  break;

	case OP_IS_VEC_ADD:
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  VERBOSE2 ("vec_add(), %d new elts.\n", num_elts);
	  vec = validate_vec_add (vec, num_elts);
	  break;

	case OP_IS_VEC_INSERT:
	  len = vec_len (vec);
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  index = bounded_random_u32 (&g_seed, 0,
				      (len > 0) ? (len - 1) : (0));
	  VERBOSE2 ("vec_insert(), %d new elts, index %d.\n", num_elts,
		    index);
	  vec = validate_vec_insert (vec, num_elts, index);
	  break;

	case OP_IS_VEC_INSERT_ELTS:
	  len = vec_len (vec);
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  index = bounded_random_u32 (&g_seed, 0,
				      (len > 0) ? (len - 1) : (0));
	  VERBOSE2 ("vec_insert_elts(), %d new elts, index %d.\n",
		    num_elts, index);
	  vec = validate_vec_insert_elts (vec, num_elts, index);
	  break;

	case OP_IS_VEC_DELETE:
	  len = vec_len (vec);
	  index = bounded_random_u32 (&g_seed, 0, len - 1);
	  num_elts = bounded_random_u32 (&g_seed, 0,
					 (len > index) ? (len - index) : (0));
	  VERBOSE2 ("vec_delete(), %d elts, index %d.\n", num_elts, index);
	  vec = validate_vec_delete (vec, num_elts, index);
	  break;

	case OP_IS_VEC_DUP:
	  VERBOSE2 ("vec_dup()\n");
	  new = validate_vec_dup (vec);
	  vec_free (new);
	  break;

	case OP_IS_VEC_IS_EQUAL:
	  VERBOSE2 ("vec_is_equal()\n");
	  validate_vec_is_equal (vec);
	  break;

	case OP_IS_VEC_ZERO:
	  VERBOSE2 ("vec_zero()\n");
	  vec = validate_vec_zero (vec);
	  break;

	case OP_IS_VEC_SET:
	  VERBOSE2 ("vec_set()\n");
	  vec = validate_vec_set (vec);
	  break;

	case OP_IS_VEC_VALIDATE:
	  len = vec_len (vec);
	  index = bounded_random_u32 (&g_seed, 0, len - 1 + MAX_CHANGE);
	  VERBOSE2 ("vec_validate(), index %d\n", index);
	  vec = validate_vec_validate (vec, index);
	  break;

	case OP_IS_VEC_FREE:
	  VERBOSE2 ("vec_free()\n");
	  vec = validate_vec_free (vec);
	  break;

	case OP_IS_VEC_INIT:
	  num_elts = bounded_random_u32 (&g_seed, 0, MAX_CHANGE);
	  vec_free (vec);
	  VERBOSE2 ("vec_init(), new elts %d\n", num_elts);
	  vec = validate_vec_init (num_elts);
	  break;

	case OP_IS_VEC_CLONE:
	  VERBOSE2 ("vec_clone()\n");
	  new = validate_vec_clone (vec);
	  vec_free (new);
	  break;

	case OP_IS_VEC_APPEND:
	  VERBOSE2 ("vec_append()\n");
	  vec = validate_vec_append (vec);
	  break;

	case OP_IS_VEC_PREPEND:
	  VERBOSE2 ("vec_prepend()\n");
	  vec = validate_vec_prepend (vec);
	  break;

	default:
	  ASSERT (0);
	  break;
	}

      g_call_stats[op]++;

      if (i == dump_time)
	{
	  time[2] = unix_time_now ();
	  VERBOSE1 ("%d vec ops in %f secs. (last %d in %f secs.).\n",
		    i, time[2] - time[0], g_dump_period, time[2] - time[1]);
	  time[1] = time[2];
	  dump_time += g_dump_period;

	  VERBOSE1 ("vec len %d\n", vec_len (vec));
	  VERBOSE2 ("%U\n\n",
		    format_hex_bytes, vec, vec_len (vec) * sizeof (vec[0]));
	}

      VERBOSE2 ("len %d\n", vec_len (vec));
    }

  validate_vec (vec, 0);
  vec_free (vec);
}

static void
prob_init (void)
{
  uword i, j, ratio, len, index;

  /* Create the vector to implement the statistical profile:
     vec [ op1 op1 op1 op2 op3 op3 op3 op4 op4 .... ] */
  for (i = FIRST_VEC_OP; i <= LAST_VEC_OP; i++)
    {
      ratio = g_prob_ratio[i];
      if (ratio <= 0)
	continue;

      len = vec_len (g_prob);
      index = len - 1 + ratio;
      ASSERT (index >= 0);

      /* Pre-allocate new elements. */
      vec_validate (g_prob, index);

      for (j = len; j <= index; j++)
	g_prob[j] = i;
    }

  /* Operations on vectors with headers. */
  for (i = FIRST_VEC_HDR_OP; i <= LAST_VEC_HDR_OP; i++)
    {
      ratio = g_prob_ratio[i];
      if (ratio <= 0)
	continue;

      len = vec_len (g_prob_wh);
      index = len - 1 + ratio;
      ASSERT (index >= 0);

      /* Pre-allocate new elements. */
      vec_validate (g_prob_wh, index);

      for (j = len; j <= index; j++)
	g_prob_wh[j] = i;
    }

  VERBOSE3 ("prob_vec, len %d\n%U\n", vec_len (g_prob),
	    format_hex_bytes, g_prob, vec_len (g_prob) * sizeof (g_prob[0]));
  VERBOSE3 ("prob_vec_wh, len %d\n%U\n", vec_len (g_prob_wh),
	    format_hex_bytes, g_prob_wh,
	    vec_len (g_prob_wh) * sizeof (g_prob_wh[0]));
}

static void
prob_free (void)
{
  vec_free (g_prob);
  vec_free (g_prob_wh);
}

int
test_vec_main (unformat_input_t * input)
{
  uword iter = 1000;
  uword help = 0;
  uword big = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &iter)
	  && 0 == unformat (input, "seed %d", &g_seed)
	  && 0 == unformat (input, "verbose %d", &g_verbose)
	  && 0 == unformat (input, "set %d", &g_set_verbose_at)
	  && 0 == unformat (input, "dump %d", &g_dump_period)
	  && 0 == unformat (input, "help %=", &help, 1)
	  && 0 == unformat (input, "big %=", &big, 1))
	{
	  clib_error ("unknown input `%U'", format_unformat_error, input);
	  goto usage;
	}
    }

  if (big)
    {
      u8 *bigboy = 0;
      u64 one_gig = (1 << 30);
      u64 size;
      u64 index;

      fformat (stdout, "giant vector test...");
      size = 5ULL * one_gig;

      vec_validate (bigboy, size);

      for (index = size; index >= 0; index--)
	bigboy[index] = index & 0xff;
      return 0;
    }


  if (help)
    goto usage;

  prob_init ();
  run_validator (iter);
  run_validator_wh (iter);
  if (verbose)
    dump_call_stats (g_call_stats);
  prob_free ();

  if (verbose)
    {
      memory_snap ();
    }
  return 0;

usage:
  fformat (stdout, "Usage: test_vec iter <N> seed <N> verbose <N> "
	   "set <N> dump <N>\n");
  if (help)
    return 0;

  return -1;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  mheap_alloc (0, (uword) 10ULL << 30);

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_vec_main (&i);
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
