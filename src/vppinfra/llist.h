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
 * Doubly linked list for elements allocated out of a pool.
 */

#ifndef SRC_VPPINFRA_LLIST_H_
#define SRC_VPPINFRA_LLIST_H_

#include <vppinfra/types.h>
#include <vppinfra/pool.h>

typedef u32 llist_index_t;

typedef struct llist_elt
{
  llist_index_t prev;
  llist_index_t next;
} llist_elt_t;

#define LLIST_INVALID_INDEX ((u32)~0)

/**
 * Local variable naming macro.
 */
#define _ll_var(v) _llist_##v
/**
 * Local macro to cast pool entry to llist element
 */
#define _lle(E,name) ((E)->name)
/**
 * Get list entry from pool for given index
 *
 * @param LP	linked list pool
 * @param EI	entry index
 */
#define llist_pool_entry(LP,EI) pool_elt_at_index((LP), (EI))
/**
 * Get list entry index
 *
 * @param LP	linked list pool
 * @param E	pool entry
 * @return	pool entry index
 */
#define llist_entry_index(LP,E) ((E) - (LP))

/**
 * Get next pool entry
 *
 * @param LP	linked list pool
 * @param E	pool entry
 * @return	next pool entry
 */
#define llist_next(LP,name,E) llist_pool_entry((LP),_lle((E),name).next)
/**
 * Get previous pool entry
 *
 * @param LP	linked list pool
 * @param E	pool entry
 * @return	previous pool entry
 */
#define llist_prev(LP,name,E) llist_pool_entry((LP),_lle((E),name).prev)
/**
 * Initialize element in llist for entry
 *
 * @param LP	linked list pool
 * @param E	entry whose ll element is to be initialized
 */
#define llist_entry_init(LP,name,E)				\
do {								\
  _lle ((E),name).prev = llist_entry_index ((LP), (E));		\
  _lle ((E),name).next = _lle ((E),name).prev;			\
} while (0)
/**
 * Initialize llist head
 *
 * @param LP	linked list pool
 * @param name	name of llist element field in pool struct
 */
#define llist_make_head(LP,name)				\
({								\
  typeof (LP) _ll_var (head);					\
  pool_get_zero ((LP), _ll_var (head));				\
  llist_entry_init ((LP),name,_ll_var (head));			\
  llist_entry_index ((LP), _ll_var (head));			\
})
/**
 * Insert entry between previous and next
 *
 * Internal use.
 *
 * @param LP	linked list pool
 * @param E	new element
 * @param P	previous in list
 * @param N	next in list
 */
#define _llist_insert(LP,name,E,P,N)				\
do {								\
  _lle ((E),name).prev = _lle((N),name).prev;			\
  _lle ((N),name).prev = llist_entry_index ((LP),(E));		\
  _lle ((E),name).next = _lle((P),name).next;			\
  _lle ((P),name).next = llist_entry_index ((LP),(E));		\
} while (0)
/**
 * Insert entry after previous
 *
 * @param LP	linked list pool
 * @param E	new element
 * @param P	previous in list
 */
#define llist_insert(LP,name,E,P) 				\
  _llist_insert ((LP),name,(E),(P),llist_next ((LP),name,(P)))
/**
 * Add entry after head
 *
 * @param LP	linked list pool
 * @param E	new element
 * @param H	list head
 */
#define llist_add(LP,name,E,H) llist_insert ((LP),name,(E),(H))
/**
 * Add entry after tail
 *
 * @param LP	linked list poool
 * @param E	new element
 * @param H	list head
 */
#define llist_add_tail(LP,name,E,H)				\
  _llist_insert ((LP),name,(E),llist_prev ((LP),name,(H)),(H))
/**
 * Remove entry from list
 *
 * @param LP	linked list poool
 * @param E	element to be removed
 */
#define llist_remove(LP,name,E)						\
do {									\
  typeof (LP) _ll_var (p) = llist_prev ((LP),name,(E));			\
  typeof (LP) _ll_var (n) = llist_next ((LP),name,(E));			\
  ASSERT ((E) != _ll_var (n));	/* don't remove head */			\
  _lle (_ll_var (p),name).next = llist_entry_index ((LP), _ll_var (n));	\
  _lle (_ll_var (n),name).prev = llist_entry_index ((LP), _ll_var (p));	\
  _lle ((E),name).next = _lle ((E),name).prev = LLIST_INVALID_INDEX;	\
}while (0)

#endif /* SRC_VPPINFRA_LLIST_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
