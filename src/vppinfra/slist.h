/*
  Copyright (c) 2012 Cisco and/or its affiliates.

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

#ifndef included_slist_h
#define included_slist_h

#include <stdarg.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/cache.h>

typedef word (clib_slist_key_compare_function_t)
  (void *key, u32 elt_pool_index);

typedef enum
{
  CLIB_SLIST_MATCH = 0,
  CLIB_SLIST_NO_MATCH
} clib_slist_search_result_t;

typedef struct
{
  /* Vector of next elements. Every valid instance has at least one */
  union
  {
    u32 next0[2];
    u32 *nexts;
  } n;

  /* Index of item in user's pool */
  u32 user_pool_index;
  /* $$$ pad to even divisor of cache line */
} clib_slist_elt_t;

static inline u32
clib_slist_get_next_at_level (clib_slist_elt_t * elt, int level)
{
  if (elt->n.next0[0] & 1)
    {
      ASSERT (level < 2);
      if (level == 1)
	return elt->n.next0[1];
      /* preserve ~0 (end of list) */
      return (elt->n.next0[0] == (u32) ~ 0) ? elt->n.next0[0] :
	(elt->n.next0[0] >> 1);
    }
  else
    {
      ASSERT (level < vec_len (elt->n.nexts));
      return elt->n.nexts[level];
    }
}

static inline void
clib_slist_set_next_at_level (clib_slist_elt_t * elt, u32 index, int level)
{
  u32 old_level0_value[2];
  /* level0 and not a vector */
  if (level < 2 && (elt->n.next0[0] == 0 || elt->n.next0[0] & 1))
    {
      if (level == 0)
	{
	  elt->n.next0[0] = (index << 1) | 1;
	  return;
	}
      elt->n.next0[1] = index;
      return;
    }
  /* have to save old level0 values? */
  if (elt->n.next0[0] & 1)
    {
      old_level0_value[0] = (elt->n.next0[0] == (u32) ~ 0) ?
	elt->n.next0[0] : elt->n.next0[0] >> 1;
      old_level0_value[1] = elt->n.next0[1];
      elt->n.nexts = 0;
      vec_add1 (elt->n.nexts, old_level0_value[0]);
      vec_add1 (elt->n.nexts, old_level0_value[1]);
    }
  vec_validate (elt->n.nexts, level);
  elt->n.nexts[level] = index;
}


typedef struct
{
  /* pool of skip-list elements */
  clib_slist_elt_t *elts;

  /* last search path */
  u32 *path;

  /* last search number of compares */
  u32 ncompares;

  /* occupancy stats */
  u32 *occupancy;

  /* Comparison function */
  clib_slist_key_compare_function_t *compare;

  /* Format function */
  format_function_t *format_user_element;

  /* items appear in successive plies with Pr (1 / branching_factor) */
  f64 branching_factor;

  /* random seed */
  u32 seed;
} clib_slist_t;

clib_error_t *clib_slist_init (clib_slist_t * sp, f64 branching_factor,
			       clib_slist_key_compare_function_t compare,
			       format_function_t format_user_element);

format_function_t format_slist;

void clib_slist_add (clib_slist_t * sp, void *key, u32 user_pool_index);
clib_slist_search_result_t clib_slist_del (clib_slist_t * sp, void *key);
u32 clib_slist_search (clib_slist_t * sp, void *key, u32 * ncompares);

#endif /* included_slist_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
