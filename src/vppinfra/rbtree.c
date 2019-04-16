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
#include <vppinfra/rbtree.h>

#define RBTREE_TNIL_INDEX 0

static inline rb_tree_index_t
rb_node_index (rb_tree_t *rt, rb_node_t *n)
{
  return n - rt->nodes;
}

static inline rb_node_t *
rb_node_right (rb_tree_t *rt, rb_node_t *n)
{
  return pool_elt_at_index (rt->nodes, n->right);
}

static inline rb_node_t *
rb_node_left (rb_tree_t *rt, rb_node_t *n)
{
  return pool_elt_at_index (rt->nodes, n->left);
}

static inline rb_node_t *
rb_node_parent (rb_tree_t *rt, rb_node_t *n)
{
  return pool_elt_at_index (rt->nodes, n->parent);
}

static inline void
rb_tree_rotate_left (rb_tree_t *rt, rb_node_t *x)
{
  rb_node_t *y, *tmp, *xp;
  rb_tree_index_t xi, yi;

  xi = rb_node_index (rt, x);
  yi = x->right;
  y = rb_node_right (rt, x);
  x->right = y->left;
  if (y->left)
    {
      tmp = rb_node_left (rt, y);
      tmp->parent = xi;
    }
  xp = rb_node_parent (rt, x);
  y->parent = x->parent;
  if (!x->parent)
    rt->root = rb_node_index (rt, y);
  else if (xp->left == xi)
    xp->left = yi;
  else
    xp->right = yi;
  y->left = xi;
  x->parent = yi;
}

static inline void
rb_tree_rotate_right (rb_tree_t *rt, rb_node_t *y)
{
  rb_node_t *x, *tmp, *yp;
  rb_tree_index_t yi, xi;

  yi = rb_node_index (rt, y);
  xi = y->left;
  x = rb_node_left (rt, y);
  y->left = x->right;
  if (x->right)
    {
      tmp = rb_node_right (rt, x);
      tmp->parent = yi;
    }
  yp = rb_node_parent (rt, y);
  x->parent = y->parent;
  if (!y->parent)
    rt->root = rb_node_index (rt, x);
  else if (yp->right == yi)
    yp->right = xi;
  else
    yp->left = xi;
  x->right = yi;
  y->parent = xi;
}

static void
rb_tree_insert (rb_tree_t *rt, rb_node_t *z)
{
  u32 yi = 0, xi = rt->root, zi;
  rb_node_t *y, *zpp, *sy, *x, *zp;

  y = pool_elt_at_index (rt->nodes, RBTREE_TNIL_INDEX);
  while (xi)
    {
      x = pool_elt_at_index (rt->nodes, xi);
      yi = xi;
      y = x;
      if (z->key < x->key)
	xi = x->left;
      else
	xi = x->right;
    }
  z->parent = yi;
  if (yi == RBTREE_TNIL_INDEX)
    rt->root = rb_node_index (rt, z);
  else if (z->key < y->key)
    y->left = rb_node_index (rt, z);
  else
    y->right = rb_node_index (rt, z);

  /* Tree fixup stage */
  while (y->color == RBTREE_RED)
    {
      zi = rb_node_index (rt, z);
      zp = pool_elt_at_index (rt->nodes, z->parent);
      zpp = pool_elt_at_index (rt->nodes, zp->parent);
      if (z->parent == zpp->left)
	{
	  y = pool_elt_at_index (rt->nodes, zpp->right);
	  if (y->color == RBTREE_RED)
	    {
	      zp->color = RBTREE_BLACK;
	      y->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      z = zpp;
	    }
	  else
	    {
	      if (zi == zp->right)
		{
		  z = zp;
		  rb_tree_rotate_left (rt, z);
		  zp = pool_elt_at_index (rt->nodes, z->parent);
		  zpp = pool_elt_at_index (rt->nodes, zp->parent);
		}
	      zp->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      rb_tree_rotate_right (rt, zpp);
	    }
	}
      else
	{
	  y = pool_elt_at_index (rt->nodes, zpp->left);
	  if (y->color == RBTREE_RED)
	    {
	      zp->color = RBTREE_BLACK;
	      y->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      z = zpp;
	    }
	  else
	    {
	      if (zi == zp->left)
		{
		  z = zp;
		  rb_tree_rotate_right (rt, z);
		  zp = pool_elt_at_index (rt->nodes, z->parent);
		  zpp = pool_elt_at_index (rt->nodes, zp->parent);
		}
	      zp->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      rb_tree_rotate_left (rt, zpp);
	    }
	}
    }
}

rb_tree_index_t
rb_tree_add (rb_tree_t *rt, u32 key)
{
  rb_node_t *n;

  pool_get_zero (rt->nodes, n);
  n->key = key;
  n->color = RBTREE_RED;
  rb_tree_insert (rt, n);
  return n - rt->nodes;
}

rb_tree_index_t
rb_tree_del (rb_tree_t *rt, u32 key)
{

}

void
rb_tree_init (rb_tree_t *rt)
{
  rb_node_t *tnil;

  /* By convention first node, index 0, is the T.nil sentinel */
  pool_get_zero (rt->nodes, tnil);
  tnil->color = RBTREE_BLACK;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
