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
#ifndef included_clib_graph_h
#define included_clib_graph_h

#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>

/* Generic graphs. */
typedef struct
{
  /* Next node along this link. */
  u32 node_index;

  /* Other direction link index to reach back to current node. */
  u32 link_to_self_index;

  /* Distance to next node. */
  u32 distance;
} graph_link_t;

/* Direction on graph: either next or previous. */
typedef struct
{
  /* Vector of links. */
  graph_link_t *links;

  /* Hash mapping node index to link which visits this node. */
  uword *link_index_by_node_index;
} graph_dir_t;

always_inline void
graph_dir_free (graph_dir_t * d)
{
  vec_free (d->links);
  hash_free (d->link_index_by_node_index);
}

always_inline graph_link_t *
graph_dir_get_link_to_node (graph_dir_t * d, u32 node_index)
{
  uword *p = hash_get (d->link_index_by_node_index, node_index);
  return p ? vec_elt_at_index (d->links, p[0]) : 0;
}

always_inline uword
graph_dir_add_link (graph_dir_t * d, u32 node_index, u32 distance)
{
  graph_link_t *l;
  ASSERT (!graph_dir_get_link_to_node (d, node_index));
  vec_add2 (d->links, l, 1);
  l->node_index = node_index;
  l->distance = distance;
  hash_set (d->link_index_by_node_index, node_index, l - d->links);
  return l - d->links;
}

always_inline void
graph_dir_del_link (graph_dir_t * d, u32 node_index)
{
  graph_link_t *l = graph_dir_get_link_to_node (d, node_index);
  uword li = l - d->links;
  uword n_links = vec_len (d->links);

  ASSERT (l != 0);
  hash_unset (d->link_index_by_node_index, node_index);
  n_links -= 1;
  if (li < n_links)
    d->links[li] = d->links[n_links];
  _vec_len (d->links) = n_links;
}

typedef struct
{
  /* Nodes we are connected to plus distances. */
  graph_dir_t next, prev;
} graph_node_t;

typedef struct
{
  /* Pool of nodes. */
  graph_node_t *nodes;

  void *opaque;

  format_function_t *format_node;
} graph_t;

/* Set link distance, creating link if not found. */
u32 graph_set_link (graph_t * g, u32 src, u32 dst, u32 distance);

always_inline void
graph_set_bidirectional_link (graph_t * g, u32 src, u32 dst, u32 distance)
{
  graph_set_link (g, src, dst, distance);
  graph_set_link (g, dst, src, distance);
}

void graph_del_link (graph_t * g, u32 src, u32 dst);
uword graph_del_node (graph_t * g, u32 src);

unformat_function_t unformat_graph;
format_function_t format_graph;
format_function_t format_graph_node;

#endif /* included_clib_graph_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
