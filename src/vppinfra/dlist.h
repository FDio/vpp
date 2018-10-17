/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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

#ifndef included_dlist_h
#define included_dlist_h

#include <stdarg.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/cache.h>

typedef struct
{
  u32 next;
  u32 prev;
  u32 value;
} dlist_elt_t;

static inline void
clib_dlist_init (dlist_elt_t * pool, u32 index)
{
  dlist_elt_t *head = pool_elt_at_index (pool, index);
  clib_memset (head, 0xFF, sizeof (*head));
}

static inline void
clib_dlist_addtail (dlist_elt_t * pool, u32 head_index, u32 new_index)
{
  dlist_elt_t *head = pool_elt_at_index (pool, head_index);
  u32 old_last_index;
  dlist_elt_t *old_last;
  dlist_elt_t *new;

  ASSERT (head->value == ~0);

  new = pool_elt_at_index (pool, new_index);

  if (PREDICT_FALSE (head->next == ~0))
    {
      head->next = head->prev = new_index;
      new->next = new->prev = head_index;
      return;
    }

  old_last_index = head->prev;
  old_last = pool_elt_at_index (pool, old_last_index);

  new->next = old_last->next;
  new->prev = old_last_index;
  old_last->next = new_index;
  head->prev = new_index;
}

static inline void
clib_dlist_addhead (dlist_elt_t * pool, u32 head_index, u32 new_index)
{
  dlist_elt_t *head = pool_elt_at_index (pool, head_index);
  dlist_elt_t *old_first;
  u32 old_first_index;
  dlist_elt_t *new;

  ASSERT (head->value == ~0);

  new = pool_elt_at_index (pool, new_index);

  if (PREDICT_FALSE (head->next == ~0))
    {
      head->next = head->prev = new_index;
      new->next = new->prev = head_index;
      return;
    }

  old_first_index = head->next;
  old_first = pool_elt_at_index (pool, old_first_index);

  new->next = old_first_index;
  new->prev = old_first->prev;
  old_first->prev = new_index;
  head->next = new_index;
}

static inline void
clib_dlist_remove (dlist_elt_t * pool, u32 index)
{
  dlist_elt_t *elt = pool_elt_at_index (pool, index);
  dlist_elt_t *next_elt, *prev_elt;

  /* listhead, not so much */
  ASSERT (elt->value != ~0);

  next_elt = pool_elt_at_index (pool, elt->next);
  prev_elt = pool_elt_at_index (pool, elt->prev);

  next_elt->prev = elt->prev;
  prev_elt->next = elt->next;

  elt->prev = elt->next = ~0;
}

static inline u32
clib_dlist_remove_head (dlist_elt_t * pool, u32 head_index)
{
  dlist_elt_t *head = pool_elt_at_index (pool, head_index);
  u32 rv;

  ASSERT (head->value == ~0);

  if (head->next == ~0 || (head->next == head_index))
    return ~0;

  rv = head->next;
  clib_dlist_remove (pool, rv);
  return rv;
}

static inline u32
clib_dlist_remove_tail (dlist_elt_t * pool, u32 head_index)
{
  dlist_elt_t *head = pool_elt_at_index (pool, head_index);
  u32 rv;

  ASSERT (head->value == ~0);

  if (head->prev == ~0)
    return ~0;

  rv = head->prev;
  clib_dlist_remove (pool, rv);
  return rv;
}

#endif /* included_dlist_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
