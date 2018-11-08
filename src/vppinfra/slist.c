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

#include <vppinfra/slist.h>

/*
 * skip-list implementation
 *
 * Good news / bad news. As balanced binary tree schemes go,
 * this one seems pretty fast and is reasonably simple. There's a very
 * limited amount that can be done to mitigate sdram read latency.
 *
 * Each active clib_slist_elt_t is on from 1 to N lists. Each active element
 * is always on the "level-0" list. Since most elements are *only* on
 * level 0, we keep the level 0 (and level 1) in the element. For those
 * elements on more than two lists, we switch to a vector. Hence, the
 * "n" union in slib_slist_elt_t.
 *
 * The low-order bit of elt->n.next0[0] is 1 for inlined next indices,
 * 0 for vector indices (since the allocator always aligns to at least
 * a 4-byte boundary). We can only represent 2e9 items, but since the
 * practical performance limit is O(1e7), it doesn't matter.
 *
 * We create a "head" element which (by construction) is always
 * lexically lighter than any other element. This makes a large number
 * of irritating special cases go away.
 *
 * User code is in charge of comparing a supplied key with
 * the key component of a user pool element. The user tells this code
 * to add or delete (opaque key, 32-bit integer) pairs to the skip-list.
 *
 * The algorithm adds new elements to one or more lists.
 * For levels greater than zero, the probability of a new element landing on
 * a list is branching_factor**N. Branching_factor = 0.2 seems to work
 * OK, yielding about 50 compares per search at O(1e7) items.
 */

clib_error_t *
clib_slist_init (clib_slist_t * sp, f64 branching_factor,
		 clib_slist_key_compare_function_t compare,
		 format_function_t format_user_element)
{
  clib_slist_elt_t *head;
  clib_memset (sp, 0, sizeof (sp[0]));
  sp->branching_factor = branching_factor;
  sp->format_user_element = format_user_element;
  sp->compare = compare;
  sp->seed = 0xdeaddabe;
  pool_get (sp->elts, head);
  vec_add1 (head->n.nexts, (u32) ~ 0);
  head->user_pool_index = (u32) ~ 0;
  vec_validate (sp->path, 1);
  vec_validate (sp->occupancy, 0);

  return 0;
}

/*
 * slist_search_internal
 */
static inline clib_slist_search_result_t
slist_search_internal (clib_slist_t * sp, void *key, int need_full_path)
{
  int level, comp_result;
  clib_slist_elt_t *search_elt, *head_elt;

  sp->ncompares = 0;
  /*
   * index 0 is the magic listhead element which is
   * lexically lighter than / to the left of every element
   */
  search_elt = head_elt = pool_elt_at_index (sp->elts, 0);

  /*
   * Initial negotiating position, only the head_elt is
   * lighter than the supplied key
   */
  clib_memset (sp->path, 0, vec_len (head_elt->n.nexts) * sizeof (u32));

  /* Walk the fastest lane first */
  level = vec_len (head_elt->n.nexts) - 1;
  _vec_len (sp->path) = level + 1;

  while (1)
    {
      u32 next_index_this_level;
      clib_slist_elt_t *prefetch_elt;

      /*
       * Prefetching the next element at this level makes a measurable
       * difference, but doesn't fix the dependent read stall problem
       */
      prefetch_elt = sp->elts +
	clib_slist_get_next_at_level (search_elt, level);

      CLIB_PREFETCH (prefetch_elt, CLIB_CACHE_LINE_BYTES, READ);

      /* Compare the key with the current element */
      comp_result = (search_elt == head_elt) ? 1 :
	sp->compare (key, search_elt->user_pool_index);

      sp->ncompares++;
      /* key "lighter" than this element */
      if (comp_result < 0)
	{
	  /*
	   * Back up to previous item on this list
	   * and search the next finer-grained list
	   * starting there.
	   */
	  search_elt = pool_elt_at_index (sp->elts, sp->path[level]);
	next_list:
	  if (level > 0)
	    {
	      level--;
	      continue;
	    }
	  else
	    {
	      return CLIB_SLIST_NO_MATCH;
	    }
	}
      /* Match */
      if (comp_result == 0)
	{
	  /*
	   * If we're trying to delete an element, we need to
	   * track down all of the elements which point at it.
	   * Otherwise, don't bother with it
	   */
	  if (need_full_path && level > 0)
	    {
	      search_elt = pool_elt_at_index (sp->elts, sp->path[level]);
	      level--;
	      continue;
	    }
	  level = vec_len (head_elt->n.nexts);
	  sp->path[level] = search_elt - sp->elts;
	  _vec_len (sp->path) = level + 1;
	  return CLIB_SLIST_MATCH;
	}
      /*
       * comp_result positive, key is to the right of
       * this element
       */
      sp->path[level] = search_elt - sp->elts;

      /* Out of list at this level? */
      next_index_this_level =
	clib_slist_get_next_at_level (search_elt, level);
      if (next_index_this_level == (u32) ~ 0)
	goto next_list;

      /* No, try the next element */
      search_elt = pool_elt_at_index (sp->elts, next_index_this_level);
    }
  return 0;			/* notreached */
}

u32
clib_slist_search (clib_slist_t * sp, void *key, u32 * ncompares)
{
  clib_slist_search_result_t rv;

  rv = slist_search_internal (sp, key, 0 /* dont need full path */ );
  if (rv == CLIB_SLIST_MATCH)
    {
      clib_slist_elt_t *elt;
      elt = pool_elt_at_index (sp->elts, sp->path[vec_len (sp->path) - 1]);
      if (ncompares)
	*ncompares = sp->ncompares;
      return elt->user_pool_index;
    }
  return (u32) ~ 0;
}

void
clib_slist_add (clib_slist_t * sp, void *key, u32 user_pool_index)
{
  clib_slist_elt_t *new_elt;
  clib_slist_search_result_t search_result;
  int level;

  search_result = slist_search_internal (sp, key,
					 0 /* don't need full path */ );

  /* Special case: key exists, just replace user_pool_index */
  if (PREDICT_FALSE (search_result == CLIB_SLIST_MATCH))
    {
      clib_slist_elt_t *elt;
      elt = pool_elt_at_index (sp->elts, sp->path[0]);
      elt->user_pool_index = user_pool_index;
      return;
    }

  pool_get (sp->elts, new_elt);
  new_elt->n.nexts = 0;
  new_elt->user_pool_index = user_pool_index;

  /* sp->path lists elements to the left of key, by level */
  for (level = 0; level < vec_len (sp->path); level++)
    {
      clib_slist_elt_t *prev_elt_this_level;
      u32 prev_elt_next_index_this_level;

      /* Add to list at the current level */
      prev_elt_this_level = pool_elt_at_index (sp->elts, sp->path[level]);
      prev_elt_next_index_this_level = clib_slist_get_next_at_level
	(prev_elt_this_level, level);

      clib_slist_set_next_at_level (new_elt, prev_elt_next_index_this_level,
				    level);

      clib_slist_set_next_at_level (prev_elt_this_level, new_elt - sp->elts,
				    level);
      sp->occupancy[level]++;

      /* Randomly add to the next-higher level */
      if (random_f64 (&sp->seed) > sp->branching_factor)
	break;
    }
  {
    /* Time to add a new ply? */
    clib_slist_elt_t *head_elt = pool_elt_at_index (sp->elts, 0);
    int top_level = vec_len (head_elt->n.nexts) - 1;
    if (((f64) sp->occupancy[top_level]) * sp->branching_factor > 1.0)
      {
	vec_add1 (sp->occupancy, 0);
	vec_add1 (head_elt->n.nexts, (u32) ~ 0);
	/* full match case returns n+1 items */
	vec_validate (sp->path, vec_len (head_elt->n.nexts));
      }
  }
}

clib_slist_search_result_t
clib_slist_del (clib_slist_t * sp, void *key)
{
  clib_slist_search_result_t search_result;
  clib_slist_elt_t *del_elt;
  int level;

  search_result = slist_search_internal (sp, key, 1 /* need full path */ );

  if (PREDICT_FALSE (search_result == CLIB_SLIST_NO_MATCH))
    return search_result;

  del_elt = pool_elt_at_index (sp->elts, sp->path[vec_len (sp->path) - 1]);
  ASSERT (vec_len (sp->path) > 1);

  for (level = 0; level < vec_len (sp->path) - 1; level++)
    {
      clib_slist_elt_t *path_elt;
      u32 path_elt_next_index;

      path_elt = pool_elt_at_index (sp->elts, sp->path[level]);
      path_elt_next_index = clib_slist_get_next_at_level (path_elt, level);

      /* Splice the item out of the list if it's adjacent to the victim */
      if (path_elt_next_index == del_elt - sp->elts)
	{
	  sp->occupancy[level]--;
	  path_elt_next_index = clib_slist_get_next_at_level (del_elt, level);
	  clib_slist_set_next_at_level (path_elt, path_elt_next_index, level);
	}
    }

  /* If this element is on more than two lists it has a vector of nexts */
  if (!(del_elt->n.next0[0] & 1))
    vec_free (del_elt->n.nexts);
  pool_put (sp->elts, del_elt);
  return CLIB_SLIST_MATCH;
}

u8 *
format_slist (u8 * s, va_list * args)
{
  clib_slist_t *sl = va_arg (*args, clib_slist_t *);
  int verbose = va_arg (*args, int);
  int i;
  clib_slist_elt_t *head_elt, *elt;

  s = format (s, "slist 0x%x, %u items, branching_factor %.2f\n", sl,
	      sl->occupancy ? sl->occupancy[0] : 0, sl->branching_factor);

  if (pool_elts (sl->elts) == 0)
    return s;

  head_elt = pool_elt_at_index (sl->elts, 0);

  for (i = 0; i < vec_len (head_elt->n.nexts); i++)
    {
      s = format (s, "level %d: %d elts\n", i,
		  sl->occupancy ? sl->occupancy[i] : 0);

      if (verbose && head_elt->n.nexts[i] != (u32) ~ 0)
	{
	  elt = pool_elt_at_index (sl->elts, head_elt->n.nexts[i]);
	  while (elt)
	    {
	      u32 next_index;
	      s = format (s, "%U(%d) ", sl->format_user_element,
			  elt->user_pool_index, elt - sl->elts);
	      next_index = clib_slist_get_next_at_level (elt, i);
	      ASSERT (next_index != 0x7fffffff);
	      if (next_index == (u32) ~ 0)
		break;
	      else
		elt = pool_elt_at_index (sl->elts, next_index);
	    }
	}
      s = format (s, "\n");
    }
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
