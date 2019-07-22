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
 *
 * @file
 * @brief Circular doubly linked list with head sentinel.
 * List entries are allocated out of a "supporting" pool and all pool entries
 * must contain a list anchor struct for each list they pertain to.
 */

#ifndef SRC_VPPINFRA_CLIB_LLIST_H_
#define SRC_VPPINFRA_CLIB_LLIST_H_

#include <vppinfra/types.h>
#include <vppinfra/pool.h>

typedef u32 clib_llist_index_t;

typedef struct clib_llist_anchor
{
  clib_llist_index_t prev;
  clib_llist_index_t next;
} clib_llist_anchor_t;

#define CLIB_LLIST_INVALID_INDEX ((u32)~0)

/**
 * Local variable naming macro.
 */
#define _ll_var(v) _llist_##v
/**
 * Local macros to grab llist anchor next and prev from pool entry
 */
#define _lnext(E,name) ((E)->name).next
#define _lprev(E,name) ((E)->name).prev
/**
 * Get list entry index
 *
 * @param LP	linked list pool
 * @param E	pool entry
 * @return	pool entry index
 */
#define clib_llist_entry_index(LP,E) ((E) - (LP))
/**
 * Get prev list entry index
 *
 * @param E	pool entry
 * @name	list anchor name
 * @return	previous index
 */
#define clib_llist_prev_index(E,name) _lprev(E,name)
/**
 * Get next list entry index
 *
 * @param E	pool entry
 * @name	list anchor name
 * @return	next index
 */
#define clib_llist_next_index(E,name) _lnext(E,name)
/**
 * Get next pool entry
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	pool entry
 * @return	next pool entry
 */
#define clib_llist_next(LP,name,E) pool_elt_at_index((LP),_lnext((E),name))
/**
 * Get previous pool entry
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	pool entry
 * @return	previous pool entry
 */
#define clib_llist_prev(LP,name,E) pool_elt_at_index((LP),_lprev((E),name))
/**
 * Initialize element in llist for entry
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	entry whose ll anchor is to be initialized
 */
#define clib_llist_anchor_init(LP,name,E)				\
do {									\
  _lprev ((E),name) = clib_llist_entry_index ((LP), (E));		\
  _lnext ((E),name) = _lprev ((E),name);				\
} while (0)
/**
 * Initialize llist head
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 */
#define clib_llist_make_head(LP,name)					\
({									\
  typeof (LP) _ll_var (head);						\
  pool_get_zero ((LP), _ll_var (head));					\
  clib_llist_anchor_init ((LP),name,_ll_var (head));			\
  clib_llist_entry_index ((LP), _ll_var (head));			\
})
/**
 * Check is list is empty
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param H	list head
 * @return	1 if sentinel is the only node part of the list, 0 otherwise
 */
#define clib_llist_is_empty(LP,name,H) 					\
  (clib_llist_entry_index (LP,H) == (H)->name.next)
/**
 * Check if element is linked in a list
 *
 * @param E	list element
 * @param name	list anchor name
 */
#define clib_llist_elt_is_linked(E,name)				\
  ((E)->name.next != CLIB_LLIST_INVALID_INDEX				\
   && (E)->name.prev != CLIB_LLIST_INVALID_INDEX)
/**
 * Insert entry between previous and next
 *
 * Internal use.
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	new entry
 * @param P	previous in list
 * @param N	next in list
 */
#define _llist_insert(LP,name,E,P,N)					\
do {									\
  _lprev (E,name) = _lprev(N,name);					\
  _lnext (E,name) = _lnext(P,name);					\
  _lprev ((N),name) = clib_llist_entry_index ((LP),(E));		\
  _lnext ((P),name) = clib_llist_entry_index ((LP),(E));		\
} while (0)
/**
 * Insert entry after previous
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	new entry
 * @param P	previous in list
 */
#define clib_llist_insert(LP,name,E,P) 					\
do {									\
  typeof (LP) _ll_var (N) = clib_llist_next (LP,name,P);		\
  _llist_insert ((LP),name,(E),(P), _ll_var (N));			\
} while (0)

/**
 * Add entry after head
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	new entry
 * @param H	list head
 */
#define clib_llist_add(LP,name,E,H) clib_llist_insert ((LP),name,(E),(H))
/**
 * Add entry after tail
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	new entry
 * @param H	list head
 */
#define clib_llist_add_tail(LP,name,E,H)				\
do {									\
  typeof (LP) _ll_var (P) = clib_llist_prev ((LP),name,(H));		\
  _llist_insert ((LP),name,(E),_ll_var (P),(H));			\
} while (0)
/**
 * Remove entry from list
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	entry to be removed
 */
#define clib_llist_remove(LP,name,E)					\
do {									\
  ASSERT ((E) != clib_llist_next (LP,name,E));/* don't remove sentinel */\
  ASSERT (_lnext (E,name) != CLIB_LLIST_INVALID_INDEX);			\
  ASSERT (_lprev (E,name) != CLIB_LLIST_INVALID_INDEX);			\
  typeof (LP) _ll_var (P) = clib_llist_prev ((LP),name,E);		\
  typeof (LP) _ll_var (N) = clib_llist_next ((LP),name,E);		\
  _lnext (_ll_var (P),name) = _lnext (E,name);				\
  _lprev (_ll_var (N),name) = _lprev (E,name);				\
  _lnext (E,name) = _lprev (E,name) = CLIB_LLIST_INVALID_INDEX;		\
}while (0)
/**
 * Removes and returns the first element in the list.
 *
 * The element is not freed. It's the responsability of the caller to
 * free it.
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param E	storage the first entry
 * @param H	list head entry
 */
#define clib_llist_pop_first(LP,name,E,H)				\
do {									\
  E = clib_llist_next (LP,name,H);					\
  clib_llist_remove (LP,name,E);					\
} while (0)
/**
 * Splice two lists at a given position
 *
 * List spliced into destination list is left with 0 entries, i.e., head
 * is made to point to itself.
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param P	position in destination where source list is spliced
 * @param H	head of source list that will be spliced into destination
 */
#define clib_llist_splice(LP,name,P,H)					\
do {									\
  typeof (LP) _ll_var (fe) = clib_llist_next (LP,name,H);		\
  if (_ll_var (fe) != (H))						\
    {									\
      typeof (LP) _ll_var (le) = clib_llist_prev (LP,name,H);		\
      typeof (LP) _ll_var (ne) = clib_llist_next (LP,name,P);		\
      _lprev (_ll_var (fe),name) = clib_llist_entry_index(LP,P);	\
      _lnext (_ll_var (le),name) = clib_llist_entry_index(LP,_ll_var (ne));\
      _lnext (P,name) = clib_llist_entry_index (LP,_ll_var (fe));	\
      _lprev (_ll_var (ne),name) = clib_llist_entry_index(LP,_ll_var (le));\
      _lnext (H,name) = clib_llist_entry_index(LP,H);			\
      _lprev (H,name) = _lnext (H,name);				\
    }									\
} while (0)
/**
 * Walk list starting at head
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param H	head entry
 * @param E	entry iterator
 * @param body	code to be executed
 */
#define clib_llist_foreach(LP,name,H,E,body)				\
do {									\
  typeof (LP) _ll_var (n);						\
  (E) = clib_llist_next (LP,name,H);					\
  while (E != H)							\
    { 									\
      _ll_var (n) = clib_llist_next (LP,name,E);			\
      do { body; } while (0);						\
      (E) = _ll_var (n);						\
    }									\
} while (0)
/**
 * Walk list starting at head safe
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param HI	head index
 * @param EI	entry index iterator
 * @param body	code to be executed
 */
#define clib_llist_foreach_safe(LP,name,H,E,body)			\
do {									\
  clib_llist_index_t _ll_var (HI) = clib_llist_entry_index (LP, H);	\
  clib_llist_index_t _ll_var (EI), _ll_var (NI);			\
  _ll_var (EI) = _lnext ((H),name);					\
  while (_ll_var (EI) != _ll_var (HI))					\
    { 									\
      (E) = pool_elt_at_index (LP, _ll_var (EI));			\
      _ll_var (NI) = _lnext ((E),name);					\
      do { body; } while (0);						\
      _ll_var (EI) = _ll_var (NI);					\
    }									\
} while (0)
/**
 * Walk list starting at head in reverse order
 *
 * @param LP	linked list pool
 * @param name	list anchor name
 * @param H	head entry
 * @param E	entry iterator
 * @param body	code to be executed
 */
#define clib_llist_foreach_reverse(LP,name,H,E,body)			\
do {									\
  typeof (LP) _ll_var (p);						\
  (E) = clib_llist_prev (LP,name,H);					\
  while (E != H)							\
    { 									\
      _ll_var (p) = clib_llist_prev (LP,name,E);			\
      do { body; } while (0);						\
      (E) = _ll_var (p);						\
    }									\
} while (0)

#endif /* SRC_VPPINFRA_CLIB_LLIST_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
