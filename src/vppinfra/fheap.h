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
#ifndef included_clib_fheap_h
#define included_clib_fheap_h

/* Fibonacci Heaps Fredman, M. L.; Tarjan (1987).
   "Fibonacci heaps and their uses in improved network optimization algorithms" */

#include <vppinfra/vec.h>

typedef struct
{
  /* Node index of parent. */
  u32 parent;

  /* Node index of first child. */
  u32 first_child;

  /* Next and previous nodes in doubly linked list of siblings. */
  u32 next_sibling, prev_sibling;

  /* Key (distance) for this node.  Parent always has key
     <= than keys of children. */
  u32 key;

  /* Number of children (as opposed to descendents). */
  u32 rank;

  u32 is_marked;

  /* Set to one when node is inserted; zero when deleted. */
  u32 is_valid;
} fheap_node_t;

#define foreach_fheap_node_sibling(f,ni,first_ni,body)			\
do {									\
  u32 __fheap_foreach_first_ni = (first_ni);				\
  u32 __fheap_foreach_ni = __fheap_foreach_first_ni;			\
  u32 __fheap_foreach_next_ni;						\
  fheap_node_t * __fheap_foreach_n;					\
  if (__fheap_foreach_ni != ~0)						\
    while (1)								\
      {									\
	__fheap_foreach_n = fheap_get_node ((f), __fheap_foreach_ni);	\
	__fheap_foreach_next_ni = __fheap_foreach_n -> next_sibling;	\
	(ni) = __fheap_foreach_ni;					\
									\
	body;								\
									\
	/* End of circular list? */					\
	if (__fheap_foreach_next_ni == __fheap_foreach_first_ni)	\
	  break;							\
									\
	__fheap_foreach_ni = __fheap_foreach_next_ni;			\
									\
      }									\
} while (0)

typedef struct
{
  u32 min_root;

  /* Vector of nodes. */
  fheap_node_t *nodes;

  u32 *root_list_by_rank;

  u32 enable_validate;

  u32 validate_serial;
} fheap_t;

/* Initialize empty heap. */
always_inline void
fheap_init (fheap_t * f, u32 n_nodes)
{
  fheap_node_t *save_nodes = f->nodes;
  u32 *save_root_list = f->root_list_by_rank;

  clib_memset (f, 0, sizeof (f[0]));

  f->nodes = save_nodes;
  f->root_list_by_rank = save_root_list;

  vec_validate (f->nodes, n_nodes - 1);
  vec_reset_length (f->root_list_by_rank);

  f->min_root = ~0;
}

always_inline void
fheap_free (fheap_t * f)
{
  vec_free (f->nodes);
  vec_free (f->root_list_by_rank);
}

always_inline u32
fheap_find_min (fheap_t * f)
{
  return f->min_root;
}

always_inline u32
fheap_is_empty (fheap_t * f)
{
  return f->min_root == ~0;
}

/* Add/delete nodes. */
void fheap_add (fheap_t * f, u32 ni, u32 key);
void fheap_del (fheap_t * f, u32 ni);

/* Delete and return minimum. */
u32 fheap_del_min (fheap_t * f, u32 * min_key);

/* Change key value. */
void fheap_decrease_key (fheap_t * f, u32 ni, u32 new_key);

#endif /* included_clib_fheap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
