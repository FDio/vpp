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

#ifndef SRC_VPPINFRA_RBTREE_H_
#define SRC_VPPINFRA_RBTREE_H_

#include <vppinfra/types.h>

typedef u32 rb_node_index_t;

typedef enum rb_tree_color_
{
  RBTREE_RED,
  RBTREE_BLACK
} rb_node_color_t;

typedef struct rb_node_ {
  u8 color;			/**< node color */
  rb_node_index_t parent;	/**< parent index */
  rb_node_index_t left;		/**< left child index */
  rb_node_index_t right;	/**< right child index */
  u32 key;			/**< node key */
} rb_node_t;

typedef struct rb_tree_ {
  rb_node_t *nodes;		/**< pool of nodes */
  rb_node_index_t root;		/**< root index */
} rb_tree_t;

void rb_tree_init (rb_tree_t *rt);
rb_node_index_t rb_tree_add (rb_tree_t *rt, u32 key);
void rb_tree_del (rb_tree_t *rt, u32 key);
u32 rb_tree_n_nodes (rb_tree_t *rt);

#endif /* SRC_VPPINFRA_RBTREE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
